package test

// Requirement: admin-panel binds admin cursors to endpoint, role, filters, and order.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pandops/flowai-admin-panel/internal/cursor"
)

// Scenario: Forward page advances via next_cursor.
func TestV0048AdminPanelForwardPageAdvancesViaNextCursor(t *testing.T) {
	e := newEnv(t)
	serveTasks(e.broker, taskRows())
	path := "/admin/tasks?team_id=3&limit=10"
	first := decodePage(t, e.do(http.MethodGet, path, e.is.adminToken("a"), nil))
	if first.Page.NextCursor == nil {
		t.Fatal("first page has no next_cursor")
	}
	second := decodePage(t, e.do(http.MethodGet, path+"&cursor="+url.QueryEscape(*first.Page.NextCursor), e.is.adminToken("a"), nil))
	ids := map[int64]bool{}
	for _, raw := range first.Items {
		ids[num(t, entry(t, raw)["task_id"])] = true
	}
	for _, raw := range second.Items {
		m := entry(t, raw)
		if ids[num(t, m["task_id"])] {
			t.Fatalf("task %v appears on both pages", m["task_id"])
		}
		if num(t, m["team_id"]) != 3 {
			t.Fatal("second page left the filter tuple")
		}
	}
	reqs := e.broker.requestList()
	p := params(t, reqs[len(reqs)-1].Body)
	b, _ := decodeBody(t, reqs[len(reqs)-1].Body)["body"].(map[string]any)
	after, ok := b["after"].(map[string]any)
	if !ok || num(t, p["team_id"]) != 3 || num(t, p["limit"]) != 10 {
		t.Fatalf("second request params %v: want the same filters plus the owner's after position", p)
	}
	last := entry(t, first.Items[len(first.Items)-1])
	if num(t, after["task_id"]) != num(t, last["task_id"]) || after["ingested_at"] != last["ingested_at"] {
		t.Fatalf("after %v is not the owner's continuation position of the last entry %v", after, last)
	}
	if _, has := decodeBody(t, reqs[0].Body)["body"]; has {
		t.Fatal("first page request carries a body with an after position")
	}
	// The cursor is opaque: the owner's position is not readable in it.
	if strings.Contains(*first.Page.NextCursor, "ingested_at") {
		t.Fatal("cursor exposes the continuation position in clear text")
	}
}

// Scenario: Tampered, cross-endpoint, or changed-filter cursor.
func TestV0048AdminPanelTamperedCrossEndpointOrChangedFilterCursor(t *testing.T) {
	e := newEnv(t)
	serveTasks(e.broker, taskRows())
	serveTags(e.broker, tagRows())
	tasksCursor := *decodePage(t, e.do(http.MethodGet, "/admin/tasks?team_id=3&state=pending&limit=1", e.is.adminToken("a"), nil)).Page.NextCursor
	tagsCursor := *decodePage(t, e.do(http.MethodGet, "/admin/tags?limit=1", e.is.adminToken("a"), nil)).Page.NextCursor

	flip := func(tok string, i int) string {
		b := []byte(tok)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	foreignKey := cursor.Keyring{ActiveKeyID: 2, Keys: map[int64][]byte{2: bytes.Repeat([]byte{0x22}, 32)}}
	forged, err := cursor.Encode(foreignKey, cursor.Binding{Endpoint: "GET /admin/tasks", Filters: map[string]string{"team_id": "3", "state": "pending"}, Ordering: "ingested_at_desc,team_id_desc,task_id_desc"}, json.RawMessage(`{"ingested_at":"2026-11-07T10:10:00.000Z","team_id":3,"task_id":10}`))
	if err != nil {
		t.Fatalf("cursor.Encode: %v", err)
	}
	parts := strings.SplitN(tasksCursor, ".", 2)
	cases := map[string]string{
		"one changed character in the MAC":     flip(tasksCursor, len(tasksCursor)-3),
		"one changed character in the payload": flip(tasksCursor, len(parts[0])+3),
		"truncated":                            tasksCursor[:len(tasksCursor)/2],
		"garbage":                              "not-a-cursor",
		"non-integer key_id":                   "abc." + parts[1],
		"zero key_id":                          "0." + parts[1],
		"unknown key_id":                       "2." + parts[1],
		"signed under an unconfigured key":     forged,
		"tags cursor on /admin/tasks":          tagsCursor,
		"changed filter value":                 "",
		"filter removed":                       "",
		"filter added":                         "",
	}
	type try struct{ path, token string }
	tries := map[string]try{}
	for name, tok := range cases {
		tries[name] = try{"/admin/tasks?team_id=3&state=pending&limit=1", tok}
	}
	tries["changed filter value"] = try{"/admin/tasks?team_id=4&state=pending&limit=1", tasksCursor}
	tries["filter removed"] = try{"/admin/tasks?team_id=3&limit=1", tasksCursor}
	tries["filter added"] = try{"/admin/tasks?team_id=3&state=pending&tag=openhands&limit=1", tasksCursor}
	tries["tasks cursor on /admin/tags"] = try{"/admin/tags?limit=1", tasksCursor}

	var bodies []string
	for name, tr := range tries {
		before := len(e.broker.requestList())
		pubBefore := len(e.broker.publishedList())
		res := e.do(http.MethodGet, tr.path+"&cursor="+url.QueryEscape(tr.token), e.is.adminToken("a"), nil)
		expectError(t, res, http.StatusBadRequest, "invalid_pagination")
		if len(e.broker.requestList()) != before {
			t.Fatalf("%s: a downstream request was sent", name)
		}
		if len(e.broker.publishedList()) != pubBefore+1 {
			t.Fatalf("%s: want exactly one rejection audit", name)
		}
		var shape map[string]any
		_ = json.Unmarshal(res.Raw, &shape)
		delete(shape, "request_id")
		b, _ := json.Marshal(shape)
		bodies = append(bodies, string(b))
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("rejections are distinguishable: %s vs %s", b, bodies[0])
		}
	}
	// Positive control: the untouched cursor works with its own filters.
	if res := e.do(http.MethodGet, "/admin/tasks?team_id=3&state=pending&limit=1&cursor="+url.QueryEscape(tasksCursor), e.is.adminToken("a"), nil); res.Status != 200 {
		t.Fatalf("valid cursor rejected: %d %s", res.Status, res.Raw)
	}
}
