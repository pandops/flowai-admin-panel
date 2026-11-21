package test

// Requirement: admin-panel authenticates administrators by external admin JWT.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pandops/flowai-admin-panel/internal/config"
)

// adminRoutes lists every admin route with a representative valid request.
var adminRoutes = []struct {
	method, path string
	body         any
	subject      string
}{
	{http.MethodPost, "/admin/teams", map[string]any{"team_name": "alpha", "default_image": "registry.test/img@sha256:" + strings.Repeat("a", 64)}, "team-registry.admin.create.pub"},
	{http.MethodGet, "/admin/teams/3", nil, "team-registry.admin.get.pub"},
	{http.MethodPatch, "/admin/teams/3", map[string]any{"default_image": "registry.test/img@sha256:" + strings.Repeat("b", 64)}, "team-registry.admin.update.pub"},
	{http.MethodPost, "/admin/teams/3/archive", nil, "team-registry.admin.archive.pub"},
	{http.MethodGet, "/admin/tags", nil, "flow-registry.admin.tags.pub"},
	{http.MethodGet, "/admin/tasks", nil, "task-manager.admin.list-tasks.pub"},
}

// answerAll makes every owner answer 200 with an empty object or page;
// team-registry answers an update carrying team_name 400 team_name_immutable.
func answerAll(fb *fakeBroker) {
	for _, r := range adminRoutes {
		subject := r.subject
		fb.on(subject, func(_ string, _ map[string]string, raw []byte) (reply, error) {
			if strings.HasSuffix(subject, "tags.pub") || strings.HasSuffix(subject, "list-tasks.pub") {
				return replyOf(200, map[string]any{"items": []any{}, "next": nil}), nil
			}
			// A team name is fixed at create, as in team-registry.
			if subject == "team-registry.admin.update.pub" {
				var req struct {
					Body map[string]any `json:"body"`
				}
				if json.Unmarshal(raw, &req) == nil {
					if _, has := req.Body["team_name"]; has {
						return replyOf(400, map[string]any{"code": "team_name_immutable", "message": "team_name cannot be changed", "request_id": 1}), nil
					}
				}
			}
			return replyOf(200, map[string]any{"team_id": 3, "team_name": "alpha"}), nil
		})
	}
}

// Scenario: External role provisions team administration.
func TestV0048AdminPanelExternalRoleProvisionsTeamAdministration(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)

	t.Run("token with the signed role is authorized on every route", func(t *testing.T) {
		for _, r := range adminRoutes {
			res := e.do(r.method, r.path, e.is.adminToken("admin-1"), r.body)
			if res.Status != http.StatusOK {
				t.Fatalf("%s %s: got %d %s", r.method, r.path, res.Status, res.Raw)
			}
		}
	})
	t.Run("a new token after the role is removed is refused", func(t *testing.T) {
		before := len(e.broker.requestList())
		token := e.is.sign(e.is.claims("admin-1", "flowai-operator"))
		expectError(t, e.do(http.MethodGet, "/admin/teams/3", token, nil), http.StatusForbidden, "insufficient_admin_role")
		if len(e.broker.requestList()) != before {
			t.Fatal("a downstream request was sent for a role-less token")
		}
	})
	t.Run("an earlier token is bounded by exp and admin_token_max_age", func(t *testing.T) {
		expired := e.is.claims("admin-1")
		expired["iat"] = time.Now().Add(-20 * time.Minute).Unix()
		expired["exp"] = time.Now().Add(-10 * time.Minute).Unix()
		expectError(t, e.do(http.MethodGet, "/admin/teams/3", e.is.sign(expired), nil), http.StatusUnauthorized, "invalid_admin_token")

		old := e.is.claims("admin-1")
		old["iat"] = time.Now().Add(-10 * time.Minute).Unix() // older than max age 5m + skew
		old["exp"] = time.Now().Add(time.Hour).Unix()
		expectError(t, e.do(http.MethodGet, "/admin/teams/3", e.is.sign(old), nil), http.StatusUnauthorized, "invalid_admin_token")
	})
	t.Run("no local administrator or role API exists", func(t *testing.T) {
		for _, p := range []string{"/admin/administrators", "/admin/roles", "/admin/teams/3/members", "/admin/users"} {
			if res := e.do(http.MethodGet, p, e.is.adminToken("admin-1"), nil); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
				t.Fatalf("GET %s: got %d, want 404", p, res.Status)
			}
		}
	})
}

// Scenario: Operator or malformed admin token calls an admin route.
func TestV0048AdminPanelOperatorOrMalformedAdminTokenCallsAnAdminRoute(t *testing.T) {
	e := newEnv(t)
	answerAll(e.broker)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(map[string]any)) string {
		c := e.is.claims("admin-1")
		f(c)
		return e.is.sign(c)
	}
	unauthorized := map[string]string{
		"operator working token": mut(func(c map[string]any) { c["aud"] = "flowai-gateway"; c["iss"] = "https://idp.test/realms/operators" }),
		"wrong issuer":           mut(func(c map[string]any) { c["iss"] = "https://evil.test" }),
		"wrong audience":         mut(func(c map[string]any) { c["aud"] = "other" }),
		"algorithm none":         e.is.unsigned(e.is.claims("admin-1")),
		"algorithm not allowed":  e.is.signWith(e.is.key, e.is.kid, "RS512", e.is.claims("admin-1")),
		"bad signature":          e.is.signWith(otherKey, e.is.kid, "RS256", e.is.claims("admin-1")),
		// The JWKS answers but does not publish k9: an invalid key, not an
		// unavailable identity provider.
		"unknown key": e.is.signWith(otherKey, "k9", "RS256", e.is.claims("admin-1")),
		"expired":     mut(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"too old":     mut(func(c map[string]any) { c["iat"] = time.Now().Add(-time.Hour).Unix() }),
		"no iat":      mut(func(c map[string]any) { delete(c, "iat") }),
		"no exp":      mut(func(c map[string]any) { delete(c, "exp") }),
		"garbage":     "not-a-jwt",
	}
	before := len(e.broker.requestList())
	for name, token := range unauthorized {
		for _, r := range adminRoutes {
			res := e.do(r.method, r.path, token, r.body)
			if res.Status != http.StatusUnauthorized || res.code() != "invalid_admin_token" {
				t.Fatalf("%s on %s %s: got %d %s, want 401 invalid_admin_token", name, r.method, r.path, res.Status, res.Raw)
			}
		}
	}
	if n := len(e.broker.attemptList()); n != 0 {
		t.Fatalf("%d audit publish attempts for unauthenticated requests", n)
	}
	for _, r := range adminRoutes {
		expectError(t, e.do(r.method, r.path, "", r.body), http.StatusUnauthorized, "invalid_admin_token")
		expectError(t, e.do(r.method, r.path, e.is.sign(e.is.claims("admin-1", "flowai-system-admins")), r.body), http.StatusForbidden, "insufficient_admin_role")
	}
	if got := len(e.broker.requestList()); got != before {
		t.Fatalf("%d downstream requests were sent for rejected tokens", got-before)
	}
	// Positive control: the valid token reaches the owner.
	if res := e.do(http.MethodGet, "/admin/teams/3", e.is.adminToken("admin-1"), nil); res.Status != http.StatusOK {
		t.Fatalf("valid token: got %d %s", res.Status, res.Raw)
	}
}

// Scenario: Admin signing key cannot be refreshed.
func TestV0048AdminPanelAdminSigningKeyCannotBeRefreshed(t *testing.T) {
	for _, mode := range []string{"fail", "slow"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			answerAll(e.broker)
			// Warm the cache with k1, then present an unknown kid.
			if res := e.do(http.MethodGet, "/admin/teams/3", e.is.adminToken("admin-1"), nil); res.Status != http.StatusOK {
				t.Fatalf("warm-up: %d %s", res.Status, res.Raw)
			}
			before := len(e.broker.requestList())
			e.is.setMode(mode)
			unknown := e.is.signWith(e.is.key, "k2", "RS256", e.is.claims("admin-1"))
			start := time.Now()
			for _, r := range adminRoutes {
				expectError(t, e.do(r.method, r.path, unknown, r.body), http.StatusBadGateway, "admin_identity_provider_unavailable")
			}
			if mode == "slow" && time.Since(start) > time.Duration(len(adminRoutes))*1500*time.Millisecond {
				t.Fatalf("JWKS refresh did not respect admin_jwks_timeout")
			}
			if got := len(e.broker.requestList()); got != before {
				t.Fatalf("%d downstream requests were sent while the JWKS was unavailable", got-before)
			}
		})
	}
}

// Scenario: Header identities are ignored.
func TestV0048AdminPanelHeaderIdentitiesAreIgnored(t *testing.T) {
	e := newEnv(t)
	e.broker.on("flow-registry.admin.tags.pub", func(string, map[string]string, []byte) (reply, error) {
		return replyOf(200, map[string]any{"items": []any{map[string]any{"team_id": 3, "flow_id": 1, "execution_tag": "openhands"}}, "next": nil}), nil
	})
	e.broker.on("task-manager.admin.list-tasks.pub", func(string, map[string]string, []byte) (reply, error) {
		return replyOf(200, map[string]any{"items": []any{taskItem(3, 1)}, "next": nil}), nil
	})
	for _, p := range []string{"/admin/tags", "/admin/tasks"} {
		res := e.do(http.MethodGet, p, "", nil, "X-FlowAI-Role", "admin", "X-FlowAI-Admin-Subject", "root")
		expectError(t, res, http.StatusUnauthorized, "invalid_admin_token")
		if _, has := res.JSON["items"]; has {
			t.Fatalf("%s returned projection data without a JWT", p)
		}
	}
	if n := len(e.broker.requestList()); n != 0 {
		t.Fatalf("%d downstream requests for header-only identities", n)
	}
	for _, p := range []string{"/admin/tags", "/admin/tasks"} {
		res := e.do(http.MethodGet, p, e.is.adminToken("admin-1"), nil, "X-FlowAI-Role", "admin", "X-FlowAI-Admin-Subject", "root")
		items, _ := res.JSON["items"].([]any)
		if res.Status != http.StatusOK || len(items) != 1 {
			t.Fatalf("%s with a valid JWT: got %d %s", p, res.Status, res.Raw)
		}
	}
	for _, rec := range e.broker.requestList() {
		if rec.Header["admin_subject"] != "admin-1" {
			t.Fatalf("admin_subject %q on %s, want the JWT subject admin-1", rec.Header["admin_subject"], rec.Subject)
		}
	}
}

// Scenario: Unsafe trust configuration.
func TestV0048AdminPanelUnsafeTrustConfiguration(t *testing.T) {
	if _, err := config.Load(configFixture(t, nil)); err != nil {
		t.Fatalf("the complete configuration must load: %v", err)
	}
	cases := map[string]func(map[string]any){
		"missing issuer":              func(d map[string]any) { delete(section(d, "admin"), "issuer") },
		"missing audience":            func(d map[string]any) { delete(section(d, "admin"), "audience") },
		"missing jwks_url":            func(d map[string]any) { delete(section(d, "admin"), "jwks_url") },
		"missing role pointer":        func(d map[string]any) { delete(section(d, "admin"), "role_claim_pointer") },
		"role pointer not RFC 6901":   func(d map[string]any) { section(d, "admin")["role_claim_pointer"] = "realm_access.roles" },
		"missing algorithms":          func(d map[string]any) { delete(section(d, "admin"), "algorithms") },
		"HS256 allowed":               func(d map[string]any) { section(d, "admin")["algorithms"] = []any{"RS256", "HS256"} },
		"none allowed":                func(d map[string]any) { section(d, "admin")["algorithms"] = []any{"none"} },
		"zero admin_jwks_timeout":     func(d map[string]any) { section(d, "admin")["admin_jwks_timeout"] = "0s" },
		"negative admin_jwks_timeout": func(d map[string]any) { section(d, "admin")["admin_jwks_timeout"] = "-1s" },
		"missing admin_jwks_timeout":  func(d map[string]any) { delete(section(d, "admin"), "admin_jwks_timeout") },
		"zero admin_token_max_age":    func(d map[string]any) { section(d, "admin")["admin_token_max_age"] = "0s" },
		"missing admin_token_max_age": func(d map[string]any) { delete(section(d, "admin"), "admin_token_max_age") },
		"negative clock skew":         func(d map[string]any) { section(d, "admin")["clock_skew"] = "-5s" },
		"unbounded clock skew":        func(d map[string]any) { section(d, "admin")["clock_skew"] = "1h" },
	}
	for name, mutate := range cases {
		if _, err := config.Load(configFixture(t, mutate)); err == nil {
			t.Fatalf("%s: configuration loaded, want a startup refusal", name)
		}
	}
}

// taskItem is one owner reply entry with every field the owner may send.
func taskItem(team, task int) map[string]any {
	return map[string]any{
		"task_id": task, "team_id": team, "flow_id": 12, "source_id": 4, "external_id": "ISSUE-1",
		"required_tag": "openhands", "current_state": "pending", "owner_command_id": nil,
		"executor_id": 7, "ingested_at": "2026-11-07T10:00:00.000Z", "claimed_at": nil,
	}
}
