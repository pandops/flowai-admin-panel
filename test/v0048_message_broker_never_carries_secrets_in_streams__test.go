package test

// Requirement: message-broker never carries secrets in streams or logs —
// Stream content inspection (admin-panel's ALL_AUDIT messages and logs).

import (
	"net/http"
	"strings"
	"testing"
)

func TestV0048AdminPanelStreamContentInspection(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	roleless := e.is.sign(e.is.claims("ops", "none"))
	e.do(http.MethodGet, "/admin/teams/3", roleless, nil)
	e.do(http.MethodGet, "/admin/tags?limit=0", e.is.adminToken("a"), nil)
	e.do(http.MethodGet, "/admin/tasks?cursor=forged", e.is.adminToken("a"), nil)
	e.do(http.MethodPatch, "/admin/teams/x", e.is.adminToken("a"), map[string]any{"default_image": "secret-looking"})
	e.do(http.MethodGet, "/admin/teams/3", "invalid.token.value", nil)
	pub := e.broker.publishedList()
	if len(pub) != 4 {
		t.Fatalf("%d audit messages, want 4", len(pub))
	}
	for _, m := range pub {
		auditBody(t, m)
		blob := string(m.Body)
		for k, v := range m.Header {
			blob += k + v
		}
		for _, bad := range []string{roleless, "eyJ", "Bearer", "secret-looking", "forged", strings.Repeat("\x11", 4)} {
			if strings.Contains(blob, bad) {
				t.Fatalf("audit message carries %q: %s", bad, blob)
			}
		}
	}
	logs := e.logs.String()
	for _, bad := range []string{roleless, "invalid.token.value", "Bearer "} {
		if strings.Contains(logs, bad) {
			t.Fatalf("log carries a credential %q", bad)
		}
	}
}
