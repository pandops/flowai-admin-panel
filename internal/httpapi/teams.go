package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// teamRoute forwards one /admin/teams* route to team-registry.admin.<op>.
// admin-panel checks only identifiers; team-registry validates the rest.
func (s *server) teamRoute(op string, namesTeam bool) func(*call) *rejection {
	return func(c *call) *rejection {
		req := request{Params: map[string]any{}}
		var teamID int64
		if namesTeam {
			id, ok := parseID(chi.URLParam(c.r, "team_id"))
			if !ok {
				return &rejection{status: http.StatusBadRequest, code: "invalid_request"}
			}
			teamID = id
			req.Params["team_id"] = id
		}
		if op == "create" || op == "update" {
			raw, ok := readBody(c.r)
			if !ok {
				return &rejection{status: http.StatusBadRequest, code: "invalid_request", resourceID: optional(teamID)}
			}
			if raw != nil {
				if !bodyIDsValid(raw, teamID) {
					return &rejection{status: http.StatusBadRequest, code: "invalid_request", resourceID: optional(teamID)}
				}
				req.Body = raw
			}
		}
		rep, ok := s.forward(c, "team-registry.admin."+op+".pub", req)
		if ok {
			relay(c.w, rep)
		}
		return nil
	}
}

func optional(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

// readBody returns the JSON body unchanged, nil when there is none, and
// ok=false when it is too large or not one JSON value.
func readBody(r *http.Request) (json.RawMessage, bool) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(data) > maxBodyBytes {
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, true
	}
	if !json.Valid(data) {
		return nil, false
	}
	return json.RawMessage(data), true
}

// bodyIDsValid checks every top-level FlowAI identifier of a JSON object
// body (a key ending in _id other than external_id): it must be a JSON
// number holding a positive int64, and team_id must equal the path team.
func bodyIDsValid(raw json.RawMessage, pathTeam int64) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return true // not an object: team-registry decides
	}
	for k, v := range fields {
		if !strings.HasSuffix(k, "_id") || k == "external_id" {
			continue
		}
		id, ok := parseID(string(v))
		if !ok {
			return false
		}
		if k == "team_id" && pathTeam != 0 && id != pathTeam {
			return false
		}
	}
	return true
}
