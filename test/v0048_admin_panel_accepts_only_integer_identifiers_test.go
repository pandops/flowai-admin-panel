package test

// Requirement: admin-panel accepts only integer identifiers.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

var invalidIDs = []string{"team-a", "0", "-3", "1.5", "+3", "03", "9223372036854775808", "3f2c9a1e-8d4b-4c11-9a7e-2b6f0d5c1a90"}

// Scenario: Administrator names a team by a non-integer identifier.
func TestV0048AdminPanelAdministratorNamesATeamByANonIntegerIdentifier(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	type probe struct {
		method, path, action string
		body                 any
	}
	var probes []probe
	for _, id := range invalidIDs {
		probes = append(probes,
			probe{http.MethodGet, "/admin/teams/" + id, "team-get", nil},
			probe{http.MethodPatch, "/admin/teams/" + id, "team-update", map[string]any{"default_image": validImage}},
			probe{http.MethodPost, "/admin/teams/" + id + "/archive", "team-archive", nil},
			probe{http.MethodGet, "/admin/tags?team_id=" + id, "tags-list", nil},
			probe{http.MethodGet, "/admin/tasks?team_id=" + id, "tasks-list", nil},
			probe{http.MethodGet, "/admin/tasks?team_id=3&flow_id=" + id, "tasks-list", nil},
		)
	}
	// A body identifier must be a JSON number equal to the path team.
	probes = append(probes,
		probe{http.MethodPatch, "/admin/teams/3", "team-update", map[string]any{"team_id": 4, "default_image": validImage}},
		probe{http.MethodPatch, "/admin/teams/3", "team-update", map[string]any{"team_id": "3", "default_image": validImage}},
		probe{http.MethodPatch, "/admin/teams/3", "team-update", map[string]any{"team_id": 3.5}},
		probe{http.MethodPost, "/admin/teams", "team-create", map[string]any{"team_id": "abc", "team_name": "x"}},
	)
	for _, p := range probes {
		before := len(e.broker.publishedList())
		reqs := len(e.broker.requestList())
		res := e.do(p.method, p.path, e.is.adminToken("admin-1"), p.body)
		expectError(t, res, http.StatusBadRequest, "invalid_request")
		if len(e.broker.requestList()) != reqs {
			t.Fatalf("%s %s sent a downstream request", p.method, p.path)
		}
		pub := e.broker.publishedList()
		if len(pub) != before+1 {
			t.Fatalf("%s %s published %d audit messages, want 1", p.method, p.path, len(pub)-before)
		}
		last := pub[len(pub)-1]
		if last.Subject != "admin-panel.audit."+p.action+".pub" {
			t.Fatalf("%s %s audit subject %s", p.method, p.path, last.Subject)
		}
		a := auditBody(t, last)
		if a["reason"] != "invalid_request" || a["outcome"] != "rejected" || a["action"] != p.action {
			t.Fatalf("audit %v", a)
		}
	}
}

// Scenario: Administrator reads a team by its integer identifier.
func TestV0048AdminPanelAdministratorReadsATeamByItsIntegerIdentifier(t *testing.T) {
	e := newEnv(t)
	team := map[string]any{"team_id": 3, "team_name": "alpha", "default_image": validImage, "ingested_at": "2026-11-07T10:00:00.000Z", "archived_at": nil}
	e.broker.on("team-registry.admin.get.pub", func(string, map[string]string, []byte) (reply, error) {
		r := replyOf(200, team)
		r.Header["ETag"] = `"7"`
		return r, nil
	})
	res := e.do(http.MethodGet, "/admin/teams/3", e.is.adminToken("admin-1"), nil)
	want, _ := json.Marshal(team)
	if res.Status != 200 || strings.TrimSpace(string(res.Raw)) != string(want) || res.Header.Get("ETag") != `"7"` {
		t.Fatalf("got %d %s etag=%q", res.Status, res.Raw, res.Header.Get("ETag"))
	}
	reqs := e.broker.requestList()
	if len(reqs) != 1 || reqs[0].Subject != "team-registry.admin.get.pub" {
		t.Fatalf("requests %+v", reqs)
	}
	if !strings.Contains(string(reqs[0].Body), `"team_id":3`) {
		t.Fatalf("team_id is not the JSON number 3: %s", reqs[0].Body)
	}
	if num(t, params(t, reqs[0].Body)["team_id"]) != 3 {
		t.Fatalf("params %s", reqs[0].Body)
	}
	if len(e.broker.publishedList()) != 0 {
		t.Fatal("admin-panel audited a forwarded read")
	}
	// The largest int64 is a valid identifier.
	e.do(http.MethodGet, "/admin/teams/9223372036854775807", e.is.adminToken("admin-1"), nil)
	if last := e.broker.requestList(); len(last) != 2 || !strings.Contains(string(last[1].Body), `"team_id":9223372036854775807`) {
		t.Fatalf("max int64 not forwarded exactly: %+v", last)
	}
}
