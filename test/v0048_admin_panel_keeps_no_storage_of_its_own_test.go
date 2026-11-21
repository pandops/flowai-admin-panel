package test

// Requirement: admin-panel keeps no storage of its own.

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-admin-panel/internal/seq"
)

// Scenario: admin-panel restarts.
func TestV0048AdminPanelAdminPanelRestarts(t *testing.T) {
	is := newIssuer(t)
	fb := newFakeBroker()
	serveTasks(fb, taskRows())
	before := newEnvWith(t, is, fb, testKeys(), seq.New(time.Now))
	pg := decodePage(t, before.do(http.MethodGet, "/admin/tasks?limit=5", is.adminToken("a"), nil))
	if pg.Page.NextCursor == nil {
		t.Fatal("no cursor issued")
	}
	// A new process with the same configuration (same integer key_id 1).
	after := newEnvWith(t, is, fb, testKeys(), seq.New(time.Now))
	res := after.do(http.MethodGet, "/admin/tasks?limit=5&cursor="+url.QueryEscape(*pg.Page.NextCursor), is.adminToken("a"), nil)
	if res.Status != 200 {
		t.Fatalf("cursor issued before the restart rejected: %d %s", res.Status, res.Raw)
	}
	for _, r := range adminRoutes[:4] {
		fb.on(r.subject, func(string, map[string]string, []byte) (reply, error) { return replyOf(200, map[string]any{}), nil })
		if res := after.do(r.method, r.path, is.adminToken("a"), r.body); res.Status != 200 {
			t.Fatalf("%s %s after restart: %d", r.method, r.path, res.Status)
		}
	}
}

// Scenario: Rejection audit sequence increases across a restart.
func TestV0048AdminPanelRejectionAuditSequenceIncreasesAcrossARestart(t *testing.T) {
	t.Run("counter rule", func(t *testing.T) {
		var mu sync.Mutex
		now := time.UnixMicro(1_000_000)
		clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
		c := seq.New(clock)
		if a, b := c.Next(), c.Next(); a != 1_000_001 || b != 1_000_002 {
			t.Fatalf("frozen clock: got %d, %d; want start+1, start+2", a, b)
		}
		mu.Lock()
		now = time.UnixMicro(5_000_000)
		mu.Unlock()
		if v := c.Next(); v != 5_000_000 {
			t.Fatalf("advanced clock: got %d, want the current time 5000000", v)
		}
		// Concurrent callers never get the same value.
		seen := sync.Map{}
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, dup := seen.LoadOrStore(c.Next(), true); dup {
					t.Error("duplicate publisher_seq")
				}
			}()
		}
		wg.Wait()
	})
	t.Run("restart", func(t *testing.T) {
		is := newIssuer(t)
		fb := newFakeBroker()
		token := is.sign(is.claims("ops", "none"))
		first := newEnvWith(t, is, fb, testKeys(), seq.New(time.Now))
		expectError(t, first.do(http.MethodGet, "/admin/teams/3", token, nil), http.StatusForbidden, "insufficient_admin_role")
		time.Sleep(2 * time.Millisecond)
		second := newEnvWith(t, is, fb, testKeys(), seq.New(time.Now))
		expectError(t, second.do(http.MethodGet, "/admin/teams/3", token, nil), http.StatusForbidden, "insufficient_admin_role")
		pub := fb.publishedList()
		if len(pub) != 2 {
			t.Fatalf("%d audit messages", len(pub))
		}
		s1, s2 := num(t, auditBody(t, pub[0])["publisher_seq"]), num(t, auditBody(t, pub[1])["publisher_seq"])
		if s2 <= s1 {
			t.Fatalf("publisher_seq %d after restart is not greater than %d", s2, s1)
		}
		if pub[0].Header["Nats-Msg-Id"] == pub[1].Header["Nats-Msg-Id"] {
			t.Fatal("Nats-Msg-Id repeated across a restart")
		}
		if s1 < time.Now().Add(-time.Minute).UnixMicro() {
			t.Fatalf("publisher_seq %d does not start at the start time in Unix microseconds", s1)
		}
	})
}
