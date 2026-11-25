package test

// Requirement: admin-panel serves the global task projection through task-manager.

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

var taskFields = []string{"task_id", "team_id", "flow_id", "source_id", "external_id", "required_tag", "current_state", "owner_command_id", "executor_id", "ingested_at", "claimed_at"}

func taskRows() []taskRow {
	var rows []taskRow
	states := []string{"queued", "pending", "running", "finished", "failed"}
	for _, team := range []int64{3, 4} {
		for task := int64(1); task <= 60; task++ {
			tag := "openhands"
			if task%4 == 0 {
				tag = "k8s-gpu"
			}
			rows = append(rows, taskRow{
				Team: team, Task: task, Flow: 10 + task%3, State: states[task%5], Tag: tag,
				// equal timestamps across teams force the team_id tie-break
				Ingested: fmt.Sprintf("2026-11-07T10:%02d:00.000Z", task%50),
			})
		}
	}
	return rows
}

// Scenario: System administrator lists tasks across every team.
func TestV0048AdminPanelSystemAdministratorListsTasksAcrossEveryTeam(t *testing.T) {
	e := newEnv(t)
	rows := taskRows()
	serveTasks(e.broker, rows)
	pages := e.walk(t, "/admin/tasks")
	seen := map[[2]int64]bool{}
	var prev []any
	for _, pg := range pages {
		if len(pg.Items) > 50 {
			t.Fatalf("page of %d entries exceeds the default 50", len(pg.Items))
		}
		for _, raw := range pg.Items {
			if keys := objectKeys(t, raw); !reflect.DeepEqual(keys, taskFields) {
				t.Fatalf("entry keys %v, want exactly %v", keys, taskFields)
			}
			if s := string(raw); strings.Contains(s, "image") || strings.Contains(s, "payload") || strings.Contains(s, "environment_id") || strings.Contains(s, "secret") {
				t.Fatalf("entry leaks a forbidden field: %s", s)
			}
			m := entry(t, raw)
			k := [2]int64{num(t, m["team_id"]), num(t, m["task_id"])}
			if seen[k] {
				t.Fatalf("(team, task) %v repeated", k)
			}
			seen[k] = true
			cur := []any{m["ingested_at"].(string), k[0], k[1]}
			if prev != nil && !taskBefore(prev, cur) {
				t.Fatalf("order (ingested_at DESC, team_id DESC, task_id DESC) broken: %v then %v", prev, cur)
			}
			prev = cur
		}
	}
	if len(seen) != len(rows) {
		t.Fatalf("%d entries, want %d", len(seen), len(rows))
	}
	if !seen[[2]int64{3, 1}] || !seen[[2]int64{4, 1}] {
		t.Fatal("tasks numbered 1 in teams 3 and 4 must be distinct entries")
	}
	if len(e.broker.publishedList()) != 0 {
		t.Fatal("admin-panel published a message for a forwarded read")
	}
	for _, bad := range []string{"0", "201", "x"} {
		before := len(e.broker.requestList())
		expectError(t, e.do(http.MethodGet, "/admin/tasks?limit="+bad, e.is.adminToken("a"), nil), http.StatusBadRequest, "invalid_pagination")
		if len(e.broker.requestList()) != before {
			t.Fatalf("limit=%s reached task-manager", bad)
		}
	}
}

func taskBefore(a, b []any) bool {
	if a[0].(string) != b[0].(string) {
		return a[0].(string) > b[0].(string)
	}
	if a[1].(int64) != b[1].(int64) {
		return a[1].(int64) > b[1].(int64)
	}
	return a[2].(int64) > b[2].(int64)
}

// Scenario: Optional filters narrow the global collection.
func TestV0048AdminPanelOptionalFiltersNarrowTheGlobalCollection(t *testing.T) {
	e := newEnv(t)
	serveTasks(e.broker, taskRows())
	pages := e.walk(t, "/admin/tasks?team_id=3&state=pending&tag=openhands&flow_id=12&limit=2")
	n := 0
	for _, pg := range pages {
		for _, raw := range pg.Items {
			m := entry(t, raw)
			if num(t, m["team_id"]) != 3 || m["current_state"] != "pending" || m["required_tag"] != "openhands" || num(t, m["flow_id"]) != 12 {
				t.Fatalf("entry does not match all filters: %v", m)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("the filtered collection is empty; the fixture must match")
	}
	p := params(t, e.broker.requestList()[0].Body)
	if num(t, p["team_id"]) != 3 || num(t, p["flow_id"]) != 12 || p["state"] != "pending" || p["tag"] != "openhands" || num(t, p["limit"]) != 2 {
		t.Fatalf("filters not forwarded as typed params: %v", p)
	}
	// flow_id only together with team_id.
	before := len(e.broker.requestList())
	expectError(t, e.do(http.MethodGet, "/admin/tasks?flow_id=12", e.is.adminToken("a"), nil), http.StatusBadRequest, "invalid_request")
	if len(e.broker.requestList()) != before {
		t.Fatal("flow_id without team_id reached task-manager")
	}
	// No match returns an empty bounded page.
	pg := decodePage(t, e.do(http.MethodGet, "/admin/tasks?team_id=9", e.is.adminToken("a"), nil))
	if len(pg.Items) != 0 || pg.Page.NextCursor != nil {
		t.Fatalf("no match must be an empty page: %+v", pg)
	}
}

// Scenario: Admin reads perform no mutation.
func TestV0048AdminPanelAdminReadsPerformNoMutation(t *testing.T) {
	e := newEnv(t)
	serveTags(e.broker, tagRows())
	serveTasks(e.broker, taskRows())
	first := map[string]string{}
	for i := 0; i < 3; i++ {
		for _, p := range []string{"/admin/tags", "/admin/tasks"} {
			res := e.do(http.MethodGet, p, e.is.adminToken("admin-1"), nil)
			if res.Status != 200 {
				t.Fatalf("%s: %d", p, res.Status)
			}
			items := string(res.Raw)
			if i == 0 {
				first[p] = items
			}
			// cursors may differ in nothing but are opaque; items must not
			if strings.Split(items, `"page"`)[0] != strings.Split(first[p], `"page"`)[0] {
				t.Fatalf("%s changed between identical reads", p)
			}
		}
	}
	reqs := e.broker.requestList()
	if len(reqs) != 6 {
		t.Fatalf("%d downstream requests, want exactly one per read", len(reqs))
	}
	for _, r := range reqs {
		if r.Subject != "flow-registry.admin.tags.pub" && r.Subject != "task-manager.admin.list-tasks.pub" {
			t.Fatalf("read sent %s", r.Subject)
		}
	}
	if n := len(e.broker.attemptList()); n != 0 {
		t.Fatalf("admin-panel published %d messages for reads; the owners audit them", n)
	}
}
