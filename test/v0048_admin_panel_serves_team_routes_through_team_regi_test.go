package test

// Requirement: admin-panel serves team routes through team-registry.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

var validImage = "registry.test/flowai/runtime@sha256:" + strings.Repeat("b", 64)

// Scenario: Administrator creates a team.
func TestV0048AdminPanelAdministratorCreatesATeam(t *testing.T) {
	e := newEnv(t)
	created := map[string]any{"team_id": 3, "team_name": "alpha", "default_image": validImage, "ingested_at": "2026-11-07T10:00:00.000Z", "archived_at": nil}
	e.broker.on("team-registry.admin.create.pub", func(string, map[string]string, []byte) (reply, error) {
		r := replyOf(201, created)
		r.Header["Location"] = "/admin/teams/3"
		r.Header["X-Internal"] = "not-copied"
		return r, nil
	})
	body := `{"team_name":"alpha","default_image":"` + validImage + `"}`
	res := e.do(http.MethodPost, "/admin/teams", e.is.adminToken("admin-1"), body)
	if res.Status != http.StatusCreated {
		t.Fatalf("got %d %s", res.Status, res.Raw)
	}
	want, _ := json.Marshal(created)
	if strings.TrimSpace(string(res.Raw)) != string(want) {
		t.Fatalf("body changed: got %s want %s", res.Raw, want)
	}
	if res.Header.Get("Location") != "/admin/teams/3" || res.Header.Get("X-Internal") != "" {
		t.Fatalf("reply headers: Location=%q X-Internal=%q", res.Header.Get("Location"), res.Header.Get("X-Internal"))
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type %q", ct)
	}
	reqs := e.broker.requestList()
	if len(reqs) != 1 || reqs[0].Subject != "team-registry.admin.create.pub" {
		t.Fatalf("requests: %+v", reqs)
	}
	sent := decodeBody(t, reqs[0].Body)
	var raw struct {
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(reqs[0].Body, &raw); err != nil || string(raw.Body) != body {
		t.Fatalf("body not forwarded unchanged: %s", raw.Body)
	}
	if p, _ := sent["params"].(map[string]any); len(p) != 0 {
		t.Fatalf("create carries params %v, want none (no team_id)", p)
	}
	h := reqs[0].Header
	if h["team"] != "admin" || h["admin_subject"] != "admin-1" {
		t.Fatalf("headers %v", h)
	}
	id, err := strconv.ParseInt(h["request_id"], 10, 64)
	if err != nil || id <= 0 || h["request_id"] != strconv.FormatInt(id, 10) {
		t.Fatalf("request_id %q is not a positive decimal int64", h["request_id"])
	}
	// No domain validation in admin-panel: an invalid image is still forwarded.
	e.broker.on("team-registry.admin.create.pub", func(string, map[string]string, []byte) (reply, error) {
		return replyOf(400, map[string]any{"code": "invalid_request", "message": "default_image is invalid", "request_id": 9}), nil
	})
	res = e.do(http.MethodPost, "/admin/teams", e.is.adminToken("admin-1"), map[string]any{"team_name": "beta", "default_image": "not-an-image"})
	if res.Status != 400 || res.code() != "invalid_request" || len(e.broker.requestList()) != 2 {
		t.Fatalf("domain validation must be team-registry's: got %d %s", res.Status, res.Raw)
	}
	// Distinct requests carry distinct request_id values.
	reqs = e.broker.requestList()
	if reqs[0].Header["request_id"] == reqs[1].Header["request_id"] {
		t.Fatal("request_id repeated across requests")
	}
}

// Scenario: team-registry rejects the request.
func TestV0048AdminPanelTeamRegistryRejectsTheRequest(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		method, path, subject string
		body                  any
		status                int
		code                  string
	}{
		// A team name is fixed at create: team-registry rejects any update
		// carrying team_name, alone or with default_image.
		{http.MethodPatch, "/admin/teams/3", "team-registry.admin.update.pub", map[string]any{"team_name": "beta"}, 400, "team_name_immutable"},
		{http.MethodPatch, "/admin/teams/3", "team-registry.admin.update.pub", map[string]any{"team_name": "beta", "default_image": validImage}, 400, "team_name_immutable"},
		// A duplicate name is rejected at create.
		{http.MethodPost, "/admin/teams", "team-registry.admin.create.pub", map[string]any{"team_name": "taken", "default_image": validImage}, 409, "team_conflict"},
		{http.MethodGet, "/admin/teams/99", "team-registry.admin.get.pub", nil, 404, "canonical_team_not_found"},
		{http.MethodPatch, "/admin/teams/3", "team-registry.admin.update.pub", map[string]any{"default_image": ""}, 400, "invalid_request"},
		{http.MethodPost, "/admin/teams/99/archive", "team-registry.admin.archive.pub", nil, 404, "canonical_team_not_found"},
	}
	for _, c := range cases {
		errBody := map[string]any{"code": c.code, "message": "owner says no", "request_id": 12345}
		e.broker.on(c.subject, func(string, map[string]string, []byte) (reply, error) { return replyOf(c.status, errBody), nil })
		before := len(e.broker.requestList())
		res := e.do(c.method, c.path, e.is.adminToken("admin-1"), c.body)
		want, _ := json.Marshal(errBody)
		if res.Status != c.status || res.code() != c.code || strings.TrimSpace(string(res.Raw)) != string(want) {
			t.Fatalf("%s %s: got %d %s, want %d %s unchanged", c.method, c.path, res.Status, res.Raw, c.status, want)
		}
		// Exactly one forwarded request, to the owner, with the REST body
		// unchanged: admin-panel neither strips team_name nor answers itself.
		reqs := e.broker.requestList()
		if len(reqs) != before+1 || reqs[before].Subject != c.subject {
			t.Fatalf("%s %s: forwarded %d requests, last %v", c.method, c.path, len(reqs)-before, reqs[len(reqs)-1].Subject)
		}
		if c.body != nil {
			wantBody, _ := json.Marshal(c.body)
			var raw struct {
				Body json.RawMessage `json:"body"`
			}
			if err := json.Unmarshal(reqs[before].Body, &raw); err != nil || string(raw.Body) != string(wantBody) {
				t.Fatalf("%s %s: body not forwarded unchanged: %s want %s", c.method, c.path, raw.Body, wantBody)
			}
		}
	}
	// The update carries the target team only as params.team_id and the
	// REST body unchanged as body.
	var update recorded
	for _, r := range e.broker.requestList() {
		if r.Subject == "team-registry.admin.update.pub" {
			update = r
			break
		}
	}
	sent := decodeBody(t, update.Body)
	if num(t, sent["params"].(map[string]any)["team_id"]) != 3 {
		t.Fatalf("params %v", sent["params"])
	}
	if b, _ := sent["body"].(map[string]any); b["team_name"] != "beta" || len(b) != 1 {
		t.Fatalf("body %v", sent["body"])
	}
	// The create carries no target team.
	for _, r := range e.broker.requestList() {
		if r.Subject == "team-registry.admin.create.pub" {
			if p, _ := decodeBody(t, r.Body)["params"].(map[string]any); len(p) != 0 {
				t.Fatalf("create carries params %v, want none", p)
			}
		}
	}
	// No partial change is possible in admin-panel: it published nothing.
	if n := len(e.broker.publishedList()); n != 0 {
		t.Fatalf("admin-panel published %d messages for forwarded requests", n)
	}
}
