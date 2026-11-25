package test

// Requirement: message-broker carries the team in the team header —
// Administrator action carries team admin (admin-panel's part).

import (
	"net/http"
	"testing"
)

func TestV0048AdminPanelAdministratorActionCarriesTeamAdmin(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	res := e.do(http.MethodPatch, "/admin/teams/3", e.is.adminToken("admin-1"), map[string]any{"default_image": validImage},
		"team", "3", "X-FlowAI-Team-Id", "4")
	if res.Status != 200 {
		t.Fatalf("got %d", res.Status)
	}
	r := e.broker.requestList()[0]
	if r.Subject != "team-registry.admin.update.pub" || r.Header["team"] != "admin" {
		t.Fatalf("subject %s team %q, want team: admin", r.Subject, r.Header["team"])
	}
	if num(t, params(t, r.Body)["team_id"]) != 3 {
		t.Fatalf("target team not in the body: %s", r.Body)
	}
	for k := range r.Header {
		switch k {
		case "team", "admin_subject", "request_id", "If-Match":
		default:
			t.Fatalf("unexpected request header %q (caller headers must not be forwarded)", k)
		}
	}
	// Every request and every rejection audit carries team: admin.
	for _, rr := range adminRoutes {
		e.do(rr.method, rr.path, e.is.adminToken("admin-1"), rr.body)
		e.do(rr.method, rr.path, e.is.sign(e.is.claims("x", "none")), rr.body)
	}
	for _, rec := range append(e.broker.requestList(), e.broker.attemptList()...) {
		if rec.Header["team"] != "admin" {
			t.Fatalf("%s carries team %q", rec.Subject, rec.Header["team"])
		}
	}
	// If-Match travels as the NATS request header of the same name.
	e.do(http.MethodPatch, "/admin/teams/3", e.is.adminToken("admin-1"), map[string]any{"default_image": validImage}, "If-Match", `"5"`)
	reqs := e.broker.requestList()
	if reqs[len(reqs)-1].Header["If-Match"] != `"5"` {
		t.Fatal("If-Match not forwarded")
	}
}
