package test

// Requirement: message-broker allows HTTP only on the named edges —
// Service offers no internal HTTP API (admin-panel serves only /admin/*
// and its probes).

import (
	"net/http"
	"testing"
)

func TestV0048AdminPanelServiceOffersNoInternalHTTPAPI(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	for _, p := range []string{"/", "/internal/v1/teams/3", "/v1/teams/3", "/ui/v1/teams", "/v1/_test/decrypt-ops", "/admin", "/admin/v1/oidc-team-mappings", "/metrics", "/debug/pprof/"} {
		for _, token := range []string{"", e.is.adminToken("a")} {
			if res := e.do(http.MethodGet, p, token, nil); res.Status != http.StatusNotFound {
				t.Fatalf("GET %s: %d, want 404", p, res.Status)
			}
		}
	}
	if n := len(e.broker.requestList()); n != 0 {
		t.Fatalf("%d downstream requests from unknown routes", n)
	}
	for _, p := range []string{"/v1/livez", "/v1/readyz"} {
		res := e.do(http.MethodGet, p, "", nil)
		if res.Status != 200 {
			t.Fatalf("%s: %d", p, res.Status)
		}
		if _, has := res.JSON["items"]; has {
			t.Fatalf("%s carries data", p)
		}
	}
}
