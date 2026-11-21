package test

// Requirement: admin-panel audits only its own rejections of authenticated administrators.

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Scenario: Forwarded team update is audited by team-registry.
func TestV0048AdminPanelForwardedTeamUpdateIsAuditedByTeamRegistry(t *testing.T) {
	e := newEnv(t)
	newImage := "registry.test/flowai/runtime@sha256:" + strings.Repeat("c", 64)
	e.broker.on("team-registry.admin.update.pub", func(string, map[string]string, []byte) (reply, error) {
		return replyOf(200, map[string]any{"team_id": 3, "team_name": "alpha", "default_image": newImage, "ingested_at": "2026-11-07T10:00:00.000Z", "archived_at": nil}), nil
	})
	res := e.do(http.MethodPatch, "/admin/teams/3", e.is.adminToken("admin-7"), map[string]any{"default_image": newImage})
	if res.Status != 200 || res.JSON["default_image"] != newImage {
		t.Fatalf("got %d %s", res.Status, res.Raw)
	}
	// admin-panel writes no audit of its own for a forwarded update: the
	// owner, team-registry, audits it.
	if n := len(e.broker.attemptList()); n != 0 {
		t.Fatalf("admin-panel published %d messages for a forwarded update", n)
	}
	reqs := e.broker.requestList()
	if len(reqs) != 1 || reqs[0].Subject != "team-registry.admin.update.pub" {
		t.Fatalf("requests %+v", reqs)
	}
	r := reqs[0]
	if r.Header["team"] != "admin" || r.Header["admin_subject"] != "admin-7" || r.Header["request_id"] == "" {
		t.Fatalf("team-registry cannot audit without team/admin_subject/request_id headers: %v", r.Header)
	}
	if b, _ := decodeBody(t, r.Body)["body"].(map[string]any); b["default_image"] != newImage || len(b) != 1 {
		t.Fatalf("update body %v, want only default_image", b)
	}
}

// Scenario: Global read is audited by its owner.
func TestV0048AdminPanelGlobalReadIsAuditedByItsOwner(t *testing.T) {
	e := newEnv(t)
	serveTasks(e.broker, taskRows())
	if res := e.do(http.MethodGet, "/admin/tasks", e.is.adminToken("admin-7"), nil); res.Status != 200 {
		t.Fatalf("got %d", res.Status)
	}
	if n := len(e.broker.attemptList()); n != 0 {
		t.Fatalf("admin-panel published %d messages for a global read", n)
	}
	r := e.broker.requestList()[0]
	if r.Subject != "task-manager.admin.list-tasks.pub" || r.Header["admin_subject"] != "admin-7" || r.Header["team"] != "admin" {
		t.Fatalf("request %s %v", r.Subject, r.Header)
	}
}

// Scenario: Administrator without the role is audited by admin-panel.
func TestV0048AdminPanelAdministratorWithoutTheRoleIsAuditedByAdminPanel(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	token := e.is.sign(e.is.claims("ops-user", "flowai-operator"))
	res := e.do(http.MethodGet, "/admin/teams/3", token, nil)
	expectError(t, res, http.StatusForbidden, "insufficient_admin_role")
	if n := len(e.broker.requestList()); n != 0 {
		t.Fatalf("%d downstream requests", n)
	}
	pub := e.broker.publishedList()
	if len(pub) != 1 {
		t.Fatalf("%d audit messages, want 1", len(pub))
	}
	m := pub[0]
	if m.Subject != "admin-panel.audit.team-get.pub" {
		t.Fatalf("subject %s", m.Subject)
	}
	a := auditBody(t, m)
	seqN := num(t, a["publisher_seq"])
	if m.Header["team"] != "admin" || m.Header["Nats-Msg-Id"] != "admin-panel-"+strconv.FormatInt(seqN, 10) {
		t.Fatalf("headers %v", m.Header)
	}
	if m.Header["request_id"] != strconv.FormatInt(num(t, a["request_id"]), 10) {
		t.Fatalf("request_id header %q != body %v", m.Header["request_id"], a["request_id"])
	}
	if num(t, res.JSON["request_id"]) != num(t, a["request_id"]) {
		t.Fatal("HTTP error request_id differs from the audited request_id")
	}
	want := map[string]any{"publisher": "admin-panel", "source_service": "admin-panel", "actor_type": "administrator", "actor_subject": "ops-user", "action": "team-get", "resource_type": "team", "outcome": "rejected", "reason": "insufficient_admin_role"}
	for k, v := range want {
		if a[k] != v {
			t.Fatalf("%s = %v, want %v", k, a[k], v)
		}
	}
	if num(t, a["resource_id"]) != 3 {
		t.Fatalf("resource_id %v, want 3", a["resource_id"])
	}
	if _, has := a["team_id"]; has {
		t.Fatal("a team: admin record carries team_id")
	}
	if strings.Contains(string(m.Body), token) || strings.Contains(string(m.Body), "eyJ") {
		t.Fatal("audit message carries the JWT")
	}
	// Every route audits a role-less administrator on its own action subject.
	actions := map[string]string{"/admin/teams": "team-create", "/admin/teams/3": "team-update", "/admin/teams/3/archive": "team-archive", "/admin/tags": "tags-list", "/admin/tasks": "tasks-list"}
	for _, r := range adminRoutes {
		if r.method == http.MethodGet && r.path == "/admin/teams/3" {
			continue
		}
		before := len(e.broker.publishedList())
		expectError(t, e.do(r.method, r.path, token, r.body), http.StatusForbidden, "insufficient_admin_role")
		pub := e.broker.publishedList()
		if len(pub) != before+1 || pub[len(pub)-1].Subject != "admin-panel.audit."+actions[r.path]+".pub" {
			t.Fatalf("%s %s: audit %v", r.method, r.path, pub[len(pub)-1].Subject)
		}
		auditBody(t, pub[len(pub)-1])
	}
	for _, p := range e.broker.attemptList() {
		if !strings.HasPrefix(p.Subject, "admin-panel.audit.") || p.Header["team"] != "admin" {
			t.Fatalf("published %s with team %q", p.Subject, p.Header["team"])
		}
	}
	if n := len(e.broker.requestList()); n != 0 {
		t.Fatalf("%d downstream requests for role-less tokens", n)
	}
}

// Scenario: Rejection audit is not acknowledged.
func TestV0048AdminPanelRejectionAuditIsNotAcknowledged(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	token := e.is.sign(e.is.claims("ops-user", "flowai-operator"))

	t.Run("no acknowledgement within the request timeout", func(t *testing.T) {
		e.broker.ackNever = true
		start := time.Now()
		res := e.do(http.MethodGet, "/admin/teams/3", token, nil)
		e.broker.ackNever = false
		expectError(t, res, http.StatusServiceUnavailable, "service_unavailable")
		if d := time.Since(start); d > testTimeout+time.Second {
			t.Fatalf("waited %v, longer than the request timeout", d)
		}
		if _, has := res.JSON["team_id"]; has {
			t.Fatal("503 carries team data")
		}
		if n := len(e.broker.requestList()); n != 0 {
			t.Fatalf("%d downstream requests", n)
		}
	})
	t.Run("republished with the same publisher_seq until acknowledged", func(t *testing.T) {
		before := len(e.broker.attemptList())
		e.broker.ackFailures = 2
		expectError(t, e.do(http.MethodGet, "/admin/teams/3", token, nil), http.StatusForbidden, "insufficient_admin_role")
		attempts := e.broker.attemptList()[before:]
		if len(attempts) != 3 {
			t.Fatalf("%d publish attempts, want 3", len(attempts))
		}
		for _, a := range attempts[1:] {
			if a.Header["Nats-Msg-Id"] != attempts[0].Header["Nats-Msg-Id"] || string(a.Body) != string(attempts[0].Body) {
				t.Fatal("a republish changed the message or its Nats-Msg-Id")
			}
		}
	})
}

// Scenario: Unauthenticated request is not audited.
func TestV0048AdminPanelUnauthenticatedRequestIsNotAudited(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	expectError(t, e.do(http.MethodGet, "/admin/teams/3", "", nil), http.StatusUnauthorized, "invalid_admin_token")
	expectError(t, e.do(http.MethodGet, "/admin/teams/3", "garbage", nil), http.StatusUnauthorized, "invalid_admin_token")
	e.is.setMode("fail")
	expectError(t, e.do(http.MethodGet, "/admin/teams/3", e.is.signWith(e.is.key, "k9", "RS256", e.is.claims("a")), nil), http.StatusBadGateway, "admin_identity_provider_unavailable")
	if n := len(e.broker.attemptList()); n != 0 {
		t.Fatalf("%d audit publishes for 401/502", n)
	}
	if n := len(e.broker.requestList()); n != 0 {
		t.Fatalf("%d downstream requests", n)
	}
}
