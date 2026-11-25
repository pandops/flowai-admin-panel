package test

// In-process fakes of flow-registry.admin.tags and
// task-manager.admin.list-tasks that filter, order and page like the
// owners do, so admin-panel's cursor wrapping is exercised end to end.

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
)

type flowRow struct {
	Team, Flow int64
	Tag        string
}

type taskRow struct {
	Team, Task, Flow int64
	State, Tag       string
	Ingested         string
}

// ownerParams returns params with the continuation position of
// body.after merged in as "after"; ok is false when raw is not JSON.
func ownerParams(raw []byte) (map[string]any, bool) {
	var m struct {
		Params map[string]any `json:"params"`
		Body   *struct {
			After map[string]any `json:"after"`
		} `json:"body"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&m) != nil {
		return nil, false
	}
	if m.Params == nil {
		m.Params = map[string]any{}
	}
	if m.Body != nil && m.Body.After != nil {
		m.Params["after"] = m.Body.After
	}
	return m.Params, true
}

func pInt(p map[string]any, k string) (int64, bool) {
	n, ok := p[k].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	return v, err == nil
}

// serveTags installs a flow-registry fake over rows. Every reply entry
// also carries default_image, which admin-panel must drop.
func serveTags(fb *fakeBroker, rows []flowRow) {
	sorted := append([]flowRow(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Team != b.Team {
			return a.Team < b.Team
		}
		if a.Tag != b.Tag {
			return a.Tag < b.Tag
		}
		return a.Flow < b.Flow
	})
	fb.on("flow-registry.admin.tags.pub", func(_ string, _ map[string]string, body []byte) (reply, error) {
		p, ok := ownerParams(body)
		if !ok {
			return replyOf(400, map[string]any{"code": "invalid_request", "message": "bad", "request_id": 1}), nil
		}
		limit, ok := pInt(p, "limit")
		if !ok {
			return replyOf(400, map[string]any{"code": "invalid_pagination", "message": "limit missing", "request_id": 1}), nil
		}
		team, hasTeam := pInt(p, "team_id")
		tag, hasTag := p["tag"].(string)
		var after *flowRow
		if a, ok := p["after"].(map[string]any); ok {
			at, _ := pInt(a, "team_id")
			af, _ := pInt(a, "flow_id")
			after = &flowRow{Team: at, Flow: af, Tag: a["execution_tag"].(string)}
		}
		var items []any
		var next any
		for _, r := range sorted {
			if hasTeam && r.Team != team || hasTag && r.Tag != tag {
				continue
			}
			if after != nil && r.Team <= after.Team && (r.Team != after.Team || r.Tag <= after.Tag && (r.Tag != after.Tag || r.Flow <= after.Flow)) {
				continue
			}
			if int64(len(items)) == limit {
				last := items[len(items)-1].(map[string]any)
				next = map[string]any{"team_id": last["team_id"], "execution_tag": last["execution_tag"], "flow_id": last["flow_id"]}
				break
			}
			items = append(items, map[string]any{"default_image": "img@sha256:x", "execution_tag": r.Tag, "flow_id": r.Flow, "team_id": r.Team})
		}
		if items == nil {
			items = []any{}
		}
		return replyOf(200, map[string]any{"items": items, "next": next}), nil
	})
}

func serveTasks(fb *fakeBroker, rows []taskRow) {
	sorted := append([]taskRow(nil), rows...)
	less := func(a, b taskRow) bool { // DESC order: a before b
		if a.Ingested != b.Ingested {
			return a.Ingested > b.Ingested
		}
		if a.Team != b.Team {
			return a.Team > b.Team
		}
		return a.Task > b.Task
	}
	sort.Slice(sorted, func(i, j int) bool { return less(sorted[i], sorted[j]) })
	fb.on("task-manager.admin.list-tasks.pub", func(_ string, _ map[string]string, body []byte) (reply, error) {
		p, _ := ownerParams(body)
		limit, ok := pInt(p, "limit")
		if !ok {
			return replyOf(400, map[string]any{"code": "invalid_pagination", "message": "limit missing", "request_id": 1}), nil
		}
		team, hasTeam := pInt(p, "team_id")
		flow, hasFlow := pInt(p, "flow_id")
		state, hasState := p["state"].(string)
		tag, hasTag := p["tag"].(string)
		var after *taskRow
		if a, ok := p["after"].(map[string]any); ok {
			at, _ := pInt(a, "team_id")
			ak, _ := pInt(a, "task_id")
			after = &taskRow{Team: at, Task: ak, Ingested: a["ingested_at"].(string)}
		}
		var items []any
		var next any
		for _, r := range sorted {
			if hasTeam && r.Team != team || hasFlow && r.Flow != flow || hasState && r.State != state || hasTag && r.Tag != tag {
				continue
			}
			if after != nil && !less(*after, r) {
				continue
			}
			if int64(len(items)) == limit {
				last := items[len(items)-1].(map[string]any)
				next = map[string]any{"ingested_at": last["ingested_at"], "team_id": last["team_id"], "task_id": last["task_id"]}
				break
			}
			items = append(items, map[string]any{
				"image": "img@sha256:x", "payload": map[string]any{"secret": "s"},
				"task_id": r.Task, "team_id": r.Team, "flow_id": r.Flow, "source_id": 4, "external_id": "EXT-1",
				"required_tag": r.Tag, "current_state": r.State, "owner_command_id": nil, "executor_id": 7,
				"ingested_at": r.Ingested, "claimed_at": nil, "environment_id": 2,
			})
		}
		if items == nil {
			items = []any{}
		}
		return replyOf(200, map[string]any{"items": items, "next": next}), nil
	})
}

// objectKeys returns the keys of a JSON object in document order.
func objectKeys(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	var keys []string
	for dec.More() {
		tok, _ := dec.Token()
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

type page struct {
	Items []json.RawMessage `json:"items"`
	Page  struct {
		Count      *int    `json:"count"`
		NextCursor *string `json:"next_cursor"`
	} `json:"page"`
}

func decodePage(t *testing.T, r response) page {
	t.Helper()
	if r.Status != 200 {
		t.Fatalf("got %d %s", r.Status, r.Raw)
	}
	var p page
	if err := json.Unmarshal(r.Raw, &p); err != nil || p.Items == nil || p.Page.Count == nil {
		t.Fatalf("not a page {items, page{count,next_cursor}}: %s", r.Raw)
	}
	if *p.Page.Count != len(p.Items) {
		t.Fatalf("count %d != %d items", *p.Page.Count, len(p.Items))
	}
	return p
}

func entry(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// walk follows next_cursor from the first page of path (which must carry
// its own query) and returns all pages.
func (e *env) walk(t *testing.T, path string) []page {
	t.Helper()
	var pages []page
	next := ""
	for i := 0; i < 100; i++ {
		p := path
		if next != "" {
			sep := "?"
			if containsQuery(path) {
				sep = "&"
			}
			p += sep + "cursor=" + next
		}
		pg := decodePage(t, e.do("GET", p, e.is.adminToken("admin-1"), nil))
		pages = append(pages, pg)
		if pg.Page.NextCursor == nil {
			return pages
		}
		next = *pg.Page.NextCursor
	}
	t.Fatal("cursor never ended")
	return nil
}

func containsQuery(p string) bool { return bytes.ContainsRune([]byte(p), '?') }
