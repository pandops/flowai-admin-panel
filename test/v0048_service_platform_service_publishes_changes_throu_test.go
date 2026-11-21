package test

// Requirement: service-platform service publishes changes through an outbox.
// admin-panel's form is the exception "Synchronous publications without an
// outbox"; "Service stops after commit" and "Rolled-back change publishes
// nothing" are not applicable (admin-panel has no database and no outbox).

import (
	"net/http"
	"testing"
)

// Scenario: Synchronous publications without an outbox.
func TestV0048AdminPanelSynchronousPublicationsWithoutAnOutbox(t *testing.T) {
	e := newEnv(t)
	token := e.is.sign(e.is.claims("ops", "none"))
	e.broker.ackNever = true
	expectError(t, e.do(http.MethodGet, "/admin/teams/3", token, nil), http.StatusServiceUnavailable, "service_unavailable")
	e.broker.ackNever = false
	if n := len(e.broker.attemptList()); n == 0 {
		t.Fatal("no synchronous JetStream publish was attempted")
	}
	if n := len(e.broker.publishedList()); n != 0 {
		t.Fatalf("%d acknowledged messages", n)
	}
	// Acknowledged: the HTTP rejection follows the acknowledgement.
	expectError(t, e.do(http.MethodGet, "/admin/teams/3", token, nil), http.StatusForbidden, "insufficient_admin_role")
	if n := len(e.broker.publishedList()); n != 1 {
		t.Fatalf("%d acknowledged messages, want 1", n)
	}
}
