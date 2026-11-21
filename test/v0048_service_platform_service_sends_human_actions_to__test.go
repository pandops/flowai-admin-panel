package test

// Requirement: service-platform service sends human actions to audit and
// others to journal (admin-panel's part). "Operator cancels a task" and
// "Executor event goes to journal" are not applicable to admin-panel.

import (
	"net/http"
	"strings"
	"testing"
)

// Scenario: Forwarded administrator action is audited by its owner.
func TestV0048AdminPanelForwardedAdministratorActionIsAuditedByItsOwner(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	if res := e.do(http.MethodPost, "/admin/teams/3/archive", e.is.adminToken("admin-9"), nil); res.Status != 200 {
		t.Fatalf("archive: %d", res.Status)
	}
	if n := len(e.broker.attemptList()); n != 0 {
		t.Fatalf("admin-panel published %d messages for a forwarded archive", n)
	}
	r := e.broker.requestList()[0]
	if r.Subject != "team-registry.admin.archive.pub" || r.Header["admin_subject"] != "admin-9" || r.Header["team"] != "admin" {
		t.Fatalf("request %s %v", r.Subject, r.Header)
	}
}

// Scenario: Rejected human action is audited.
func TestV0048AdminPanelRejectedHumanActionIsAudited(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	cases := []struct {
		path, reason, action string
	}{
		{"/admin/teams/abc", "invalid_request", "team-get"},
		{"/admin/tags?limit=500", "invalid_pagination", "tags-list"},
		{"/admin/tasks?flow_id=2", "invalid_request", "tasks-list"},
	}
	for _, c := range cases {
		before := len(e.broker.publishedList())
		e.do(http.MethodGet, c.path, e.is.adminToken("admin-9"), nil)
		pub := e.broker.publishedList()
		if len(pub) != before+1 {
			t.Fatalf("%s: %d audit messages", c.path, len(pub)-before)
		}
		a := auditBody(t, pub[len(pub)-1])
		if a["reason"] != c.reason || a["action"] != c.action || a["actor_subject"] != "admin-9" || a["outcome"] != "rejected" {
			t.Fatalf("%s: audit %v", c.path, a)
		}
		if !strings.HasPrefix(pub[len(pub)-1].Subject, "admin-panel.audit.") {
			t.Fatalf("subject %s", pub[len(pub)-1].Subject)
		}
	}
	if n := len(e.broker.requestList()); n != 0 {
		t.Fatalf("%d downstream requests for rejected requests", n)
	}
}
