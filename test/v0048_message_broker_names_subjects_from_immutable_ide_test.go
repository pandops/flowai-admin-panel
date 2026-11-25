package test

// Requirement: message-broker names subjects from immutable identifiers —
// Team appears as a subject token only in the task queue and Source intake
// (admin-panel's subjects).

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var subjectToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func TestV0048AdminPanelTeamAppearsAsASubjectTokenOnlyInTheTaskQueueAndSourceIntake(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	for _, r := range adminRoutes {
		path := strings.Replace(r.path, "/3", "/987654", 1)
		if res := e.do(r.method, path, e.is.adminToken("a"), r.body); res.Status != 200 {
			t.Fatalf("%s %s: %d", r.method, path, res.Status)
		}
		e.do(r.method, path, e.is.sign(e.is.claims("a", "none")), r.body) // rejection audit
	}
	e.do(http.MethodGet, "/admin/tags?team_id=987654", e.is.adminToken("a"), nil)
	e.do(http.MethodGet, "/admin/tasks?team_id=987654&flow_id=55", e.is.adminToken("a"), nil)
	all := append(e.broker.requestList(), e.broker.attemptList()...)
	if len(all) < 2*len(adminRoutes) {
		t.Fatalf("only %d subjects recorded", len(all))
	}
	for _, rec := range all {
		s := rec.Subject
		if strings.HasPrefix(s, "flowai.") || !strings.HasSuffix(s, ".pub") {
			t.Fatalf("subject %s does not follow <svc>.<item>...<pub>", s)
		}
		for _, tok := range strings.Split(s, ".") {
			if !subjectToken.MatchString(tok) {
				t.Fatalf("subject %s has an invalid token %q", s, tok)
			}
			if tok == "987654" || tok == "55" {
				t.Fatalf("subject %s carries a team or Flow identifier", s)
			}
		}
		if !strings.Contains(s, ".admin.") && !strings.HasPrefix(s, "admin-panel.audit.") {
			t.Fatalf("admin-panel published %s, outside <svc>.admin.*.pub and admin-panel.audit.*.pub", s)
		}
	}
}
