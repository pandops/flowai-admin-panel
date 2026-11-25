package test

// Requirement: service-platform services use integer identifiers.
// Scenario: Invalid identifier is rejected (admin-panel's routes). The
// scenarios about per-team counters, sequences and consumer deduplication
// are not applicable: admin-panel assigns no identifier and consumes no
// stream.

import (
	"net/http"
	"testing"
)

func TestV0048AdminPanelInvalidIdentifierIsRejected(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	for _, id := range []string{"abc", "0", "-1", "1.5", "9223372036854775808", "3f2c8a10-6b1e-4d2a-9c3e-5a7b8c9d0e1f"} {
		for _, p := range []string{"/admin/teams/" + id, "/admin/tasks?team_id=" + id, "/admin/tags?team_id=" + id} {
			before := len(e.broker.requestList())
			expectError(t, e.do(http.MethodGet, p, e.is.adminToken("a"), nil), http.StatusBadRequest, "invalid_request")
			if len(e.broker.requestList()) != before {
				t.Fatalf("%s reached an owner", p)
			}
		}
	}
	// A team-owned identifier is meaningful only with its team.
	expectError(t, e.do(http.MethodGet, "/admin/tasks?flow_id=1", e.is.adminToken("a"), nil), http.StatusBadRequest, "invalid_request")
	if res := e.do(http.MethodGet, "/admin/tasks?team_id=3&flow_id=1", e.is.adminToken("a"), nil); res.Status != 200 {
		t.Fatalf("flow_id with team_id: %d", res.Status)
	}
}
