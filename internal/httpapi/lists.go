package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/pandops/flowai-admin-panel/internal/cursor"
)

const maxRawQuery = 2048

// list describes one paginated admin projection.
type list struct {
	endpoint, subject, ordering string
	filters                     []string // query names; *_id values are identifiers
	project                     func(json.RawMessage) (any, error)
	flowNeedsTeam               bool
}

var (
	tagsList = list{
		endpoint: "GET /admin/tags", subject: "flow-registry.admin.tags.pub",
		ordering: "team_id_asc,execution_tag_asc,flow_id_asc",
		filters:  []string{"team_id", "tag"},
		project:  projectAs[tagEntry],
	}
	tasksList = list{
		endpoint: "GET /admin/tasks", subject: "task-manager.admin.list-tasks.pub",
		ordering: "ingested_at_desc,team_id_desc,task_id_desc",
		filters:  []string{"team_id", "state", "tag", "flow_id"}, flowNeedsTeam: true,
		project: projectAs[taskEntry],
	}
)

// tagEntry and taskEntry fix the exact fields and their order.
type tagEntry struct {
	TeamID       int64  `json:"team_id"`
	FlowID       int64  `json:"flow_id"`
	ExecutionTag string `json:"execution_tag"`
}

type taskEntry struct {
	TaskID         int64   `json:"task_id"`
	TeamID         int64   `json:"team_id"`
	FlowID         int64   `json:"flow_id"`
	SourceID       int64   `json:"source_id"`
	ExternalID     string  `json:"external_id"`
	RequiredTag    string  `json:"required_tag"`
	CurrentState   string  `json:"current_state"`
	OwnerCommandID *int64  `json:"owner_command_id"`
	ExecutorID     *int64  `json:"executor_id"`
	IngestedAt     string  `json:"ingested_at"`
	ClaimedAt      *string `json:"claimed_at"`
}

func projectAs[T any](raw json.RawMessage) (any, error) {
	var v T
	err := json.Unmarshal(raw, &v)
	return v, err
}

var limitPattern = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)

type pageInfo struct {
	NextCursor *string `json:"next_cursor"`
	Count      int     `json:"count"`
}

type pageReply struct {
	Items []any    `json:"items"`
	Page  pageInfo `json:"page"`
}

func (s *server) listRoute(l list) func(*call) *rejection {
	return func(c *call) *rejection {
		bad := func(code string, team *int64) *rejection {
			return &rejection{status: http.StatusBadRequest, code: code, resourceID: team}
		}
		allowed := map[string]bool{"limit": true, "cursor": true}
		for _, f := range l.filters {
			allowed[f] = true
		}
		if len(c.r.URL.RawQuery) > maxRawQuery {
			return bad("invalid_pagination", nil)
		}
		q, err := url.ParseQuery(c.r.URL.RawQuery)
		if err != nil {
			return bad("invalid_pagination", nil)
		}
		for k, v := range q {
			if !allowed[k] || len(v) != 1 {
				return bad("invalid_pagination", pathTeam(c.r))
			}
		}
		params := map[string]any{}
		binding := map[string]string{}
		var team *int64
		for _, f := range l.filters {
			v, present := q[f]
			if !present {
				continue
			}
			binding[f] = v[0]
			if f == "team_id" || f == "flow_id" {
				id, ok := parseID(v[0])
				if !ok {
					return bad("invalid_request", team)
				}
				if f == "team_id" {
					team = &id
				}
				params[f] = id
				continue
			}
			params[f] = v[0]
		}
		if l.flowNeedsTeam && params["flow_id"] != nil && params["team_id"] == nil {
			return bad("invalid_request", nil)
		}
		limit := int64(50)
		if v, present := q["limit"]; present {
			n, err := strconv.ParseInt(v[0], 10, 64)
			if !limitPattern.MatchString(v[0]) || err != nil || n > 200 {
				return bad("invalid_pagination", team)
			}
			limit = n
		}
		params["limit"] = limit
		b := cursor.Binding{Endpoint: l.endpoint, Filters: binding, Ordering: l.ordering}
		req := request{Params: params}
		if v, present := q["cursor"]; present {
			after, err := cursor.Decode(s.Keys, b, v[0])
			if err != nil {
				return bad("invalid_pagination", team)
			}
			req.Body = map[string]json.RawMessage{"after": after}
		}
		rep, ok := s.forward(c, l.subject, req)
		if !ok {
			return nil
		}
		if status(rep) != http.StatusOK {
			relay(c.w, rep)
			return nil
		}
		var owner struct {
			Items []json.RawMessage `json:"items"`
			Next  json.RawMessage   `json:"next"`
		}
		if err := json.Unmarshal(rep.Body, &owner); err != nil {
			s.badReply(c, l.subject)
			return nil
		}
		out := pageReply{Items: make([]any, 0, len(owner.Items))}
		for _, raw := range owner.Items {
			item, err := l.project(raw)
			if err != nil {
				s.badReply(c, l.subject)
				return nil
			}
			out.Items = append(out.Items, item)
		}
		out.Page.Count = len(out.Items)
		if len(owner.Next) > 0 && string(owner.Next) != "null" {
			token, err := cursor.Encode(s.Keys, b, owner.Next)
			if err != nil {
				s.badReply(c, l.subject)
				return nil
			}
			out.Page.NextCursor = &token
		}
		writeJSON(c.w, http.StatusOK, out)
		return nil
	}
}

func (s *server) badReply(c *call, subject string) {
	s.Logger.Warn("owner reply is malformed", "request_id", c.requestID, "subject", subject)
	s.writeError(c, http.StatusServiceUnavailable, "service_unavailable")
}
