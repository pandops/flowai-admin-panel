package test

// Requirement: admin-panel serves the global tag projection through flow-registry.

import (
	"net/http"
	"reflect"
	"strconv"
	"testing"
)

func tagRows() []flowRow {
	var rows []flowRow
	for team := int64(1); team <= 4; team++ {
		for flow := int64(1); flow <= 30; flow++ {
			tag := "openhands"
			if flow%3 == 0 {
				tag = "k8s-gpu"
			}
			rows = append(rows, flowRow{Team: team, Flow: flow, Tag: tag})
		}
	}
	return rows
}

// Scenario: System administrator lists configured tags across teams.
func TestV0048AdminPanelSystemAdministratorListsConfiguredTagsAcrossTeams(t *testing.T) {
	e := newEnv(t)
	rows := tagRows()
	serveTags(e.broker, rows)
	pages := e.walk(t, "/admin/tags")
	if len(pages) != 3 { // 120 rows, default limit 50
		t.Fatalf("%d pages, want 3 with the default limit 50", len(pages))
	}
	seen := map[[2]int64]bool{}
	var prev []any
	for _, pg := range pages {
		for _, raw := range pg.Items {
			if keys := objectKeys(t, raw); !reflect.DeepEqual(keys, []string{"team_id", "flow_id", "execution_tag"}) {
				t.Fatalf("entry keys %v, want exactly team_id, flow_id, execution_tag", keys)
			}
			m := entry(t, raw)
			k := [2]int64{num(t, m["team_id"]), num(t, m["flow_id"])}
			if seen[k] {
				t.Fatalf("entry %v repeated across pages", k)
			}
			seen[k] = true
			cur := []any{k[0], m["execution_tag"].(string), k[1]}
			if prev != nil && !tagLess(prev, cur) {
				t.Fatalf("order broken: %v then %v", prev, cur)
			}
			prev = cur
		}
	}
	if len(seen) != len(rows) {
		t.Fatalf("%d entries, want %d", len(seen), len(rows))
	}
	for _, r := range e.broker.requestList() {
		if r.Subject != "flow-registry.admin.tags.pub" || r.Header["team"] != "admin" {
			t.Fatalf("unexpected request %s %v", r.Subject, r.Header)
		}
	}
	if n := num(t, params(t, e.broker.requestList()[0].Body)["limit"]); n != 50 {
		t.Fatalf("default limit %d, want 50", n)
	}
	if len(e.broker.publishedList()) != 0 {
		t.Fatal("a read published a message from admin-panel")
	}
	// limit 200 is the maximum.
	if pg := decodePage(t, e.do(http.MethodGet, "/admin/tags?limit=200", e.is.adminToken("a"), nil)); len(pg.Items) != 120 {
		t.Fatalf("limit=200 returned %d items", len(pg.Items))
	}
	for _, bad := range []string{"0", "201", "-1", "abc", "1.5", ""} {
		before := len(e.broker.requestList())
		expectError(t, e.do(http.MethodGet, "/admin/tags?limit="+bad, e.is.adminToken("a"), nil), http.StatusBadRequest, "invalid_pagination")
		if len(e.broker.requestList()) != before {
			t.Fatalf("limit=%q reached flow-registry", bad)
		}
	}
}

func tagLess(a, b []any) bool {
	if a[0].(int64) != b[0].(int64) {
		return a[0].(int64) < b[0].(int64)
	}
	if a[1].(string) != b[1].(string) {
		return a[1].(string) < b[1].(string)
	}
	return a[2].(int64) < b[2].(int64)
}

// Scenario: Tag filter restricts results to one tag.
func TestV0048AdminPanelTagFilterRestrictsResultsToOneTag(t *testing.T) {
	e := newEnv(t)
	serveTags(e.broker, tagRows())
	pages := e.walk(t, "/admin/tags?tag=openhands&limit=25")
	total := 0
	var prev [2]int64
	for _, pg := range pages {
		for _, raw := range pg.Items {
			m := entry(t, raw)
			if m["execution_tag"] != "openhands" {
				t.Fatalf("entry with tag %v", m["execution_tag"])
			}
			cur := [2]int64{num(t, m["team_id"]), num(t, m["flow_id"])}
			if total > 0 && cur[0] <= prev[0] && (cur[0] != prev[0] || cur[1] <= prev[1]) {
				t.Fatalf("order (team_id, flow_id) broken: %v then %v", prev, cur)
			}
			prev = cur
			total++
		}
	}
	if total != 80 {
		t.Fatalf("%d openhands entries, want 80", total)
	}
	for _, r := range e.broker.requestList() {
		if params(t, r.Body)["tag"] != "openhands" {
			t.Fatalf("tag filter not forwarded: %s", r.Body)
		}
	}
	if pg := decodePage(t, e.do(http.MethodGet, "/admin/tags?tag=missing", e.is.adminToken("a"), nil)); len(pg.Items) != 0 || pg.Page.NextCursor != nil {
		t.Fatalf("a tag with no Flow must return an empty page: %+v", pg)
	}
}

// Scenario: Team filter restricts results to one team.
func TestV0048AdminPanelTeamFilterRestrictsResultsToOneTeam(t *testing.T) {
	e := newEnv(t)
	serveTags(e.broker, tagRows())
	pages := e.walk(t, "/admin/tags?team_id=3&limit=7")
	total := 0
	var prev []any
	for _, pg := range pages {
		for _, raw := range pg.Items {
			m := entry(t, raw)
			if num(t, m["team_id"]) != 3 {
				t.Fatalf("entry of team %v", m["team_id"])
			}
			cur := []any{int64(3), m["execution_tag"].(string), num(t, m["flow_id"])}
			if prev != nil && !tagLess(prev, cur) {
				t.Fatalf("order (execution_tag, flow_id) broken: %v then %v", prev, cur)
			}
			prev = cur
			total++
		}
	}
	if total != 30 {
		t.Fatalf("%d entries for team 3, want 30", total)
	}
	for _, r := range e.broker.requestList() {
		if num(t, params(t, r.Body)["team_id"]) != 3 {
			t.Fatalf("team filter not a JSON number: %s", r.Body)
		}
	}
	if pg := decodePage(t, e.do(http.MethodGet, "/admin/tags?team_id="+strconv.Itoa(99), e.is.adminToken("a"), nil)); len(pg.Items) != 0 {
		t.Fatalf("a team with no Flow must return an empty page")
	}
}
