package test

// Survivors of deleted State Registry admin tests (ledger M32, M39, M48,
// M53/M76 admin part, M126, M127), translated to admin-panel's v0048 edge.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pandops/flowai-admin-panel/internal/broker"
	"github.com/pandops/flowai-admin-panel/internal/cursor"
)

// TestV0048AdminPanelRehomedStateRegistryCases groups the re-homed cases;
// each subtest names its ledger row.
func TestV0048AdminPanelRehomedStateRegistryCases(t *testing.T) {
	// M32: a token without the role claim is an authenticated identity
	// without the role (403, audited); a role claim that is not an array is
	// an invalid token (401). Neither reaches an owner.
	t.Run("M32 missing role claim and non-array role claim differ", func(t *testing.T) {
		e := newEnv(t)
		e.broker.on("team-registry.admin.get.pub", func(string, broker.Header, []byte) (reply, error) {
			return replyOf(200, map[string]any{"team_id": 3}), nil
		})
		missing := e.is.claims("no-role-claim")
		delete(missing, "realm_access")
		expectError(t, e.do(http.MethodGet, "/admin/teams/3", e.is.sign(missing), nil), http.StatusForbidden, "insufficient_admin_role")
		missingLeaf := e.is.claims("no-roles-leaf")
		missingLeaf["realm_access"] = map[string]any{}
		expectError(t, e.do(http.MethodGet, "/admin/teams/3", e.is.sign(missingLeaf), nil), http.StatusForbidden, "insufficient_admin_role")
		notArray := e.is.claims("string-role")
		notArray["realm_access"] = map[string]any{"roles": adminRole}
		expectError(t, e.do(http.MethodGet, "/admin/teams/3", e.is.sign(notArray), nil), http.StatusUnauthorized, "invalid_admin_token")
		if n := len(e.broker.requestList()); n != 0 {
			t.Fatalf("role-claim rejections sent %d downstream requests", n)
		}
		// Only the two 403s are admin-panel's own audited rejections.
		pub := e.broker.publishedList()
		if len(pub) != 2 {
			t.Fatalf("published %d audit messages, want 2 (the two 403s only)", len(pub))
		}
		for i, subject := range []string{"no-role-claim", "no-roles-leaf"} {
			m := auditBody(t, pub[i])
			if m["actor_subject"] != subject || m["reason"] != "insufficient_admin_role" || m["outcome"] != "rejected" {
				t.Fatalf("audit %d = %v, want rejected insufficient_admin_role for %s", i, m, subject)
			}
		}
	})

	// M39: the cursor of the maximum schema-valid admin tag tuple (largest
	// team_id and flow_id, 128-character tag filter and position) fits the
	// token bound and is accepted again with the same filters.
	t.Run("M39 maximum admin tag tuple cursor fits the bound", func(t *testing.T) {
		e := newEnv(t)
		const maxID = int64(9223372036854775807)
		tag := strings.Repeat("x", 128)
		var afters []json.RawMessage
		e.broker.on("flow-registry.admin.tags.pub", func(_ string, _ broker.Header, body []byte) (reply, error) {
			var req struct {
				Body struct {
					After json.RawMessage `json:"after"`
				} `json:"body"`
			}
			_ = json.Unmarshal(body, &req)
			afters = append(afters, req.Body.After)
			item := map[string]any{"team_id": maxID, "flow_id": maxID, "execution_tag": tag}
			return replyOf(200, map[string]any{"items": []any{item}, "next": map[string]any{"team_id": maxID, "execution_tag": tag, "flow_id": maxID}}), nil
		})
		path := "/admin/tags?team_id=9223372036854775807&tag=" + tag + "&limit=200"
		first := decodePage(t, e.do(http.MethodGet, path, e.is.adminToken("a"), nil))
		if first.Page.NextCursor == nil {
			t.Fatal("no next_cursor for the maximum tuple")
		}
		if n := len(*first.Page.NextCursor); n > cursor.MaxTokenLength {
			t.Fatalf("cursor length %d exceeds bound %d", n, cursor.MaxTokenLength)
		}
		second := decodePage(t, e.do(http.MethodGet, path+"&cursor="+url.QueryEscape(*first.Page.NextCursor), e.is.adminToken("a"), nil))
		if len(second.Items) != 1 || len(afters) != 2 {
			t.Fatalf("replay of the maximum cursor: items=%d owner calls=%d", len(second.Items), len(afters))
		}
		var after struct {
			TeamID       json.Number `json:"team_id"`
			ExecutionTag string      `json:"execution_tag"`
			FlowID       json.Number `json:"flow_id"`
		}
		if err := json.Unmarshal(afters[1], &after); err != nil {
			t.Fatalf("after position %s: %v", afters[1], err)
		}
		if after.TeamID.String() != "9223372036854775807" || after.FlowID.String() != "9223372036854775807" || after.ExecutionTag != tag {
			t.Fatalf("owner after position %s is not the maximum tuple", afters[1])
		}
	})

	// M48: the cursor scope is the role only; a cursor issued to one
	// administrator continues under another administrator's token.
	t.Run("M48 admin cursor scope is the role not the subject", func(t *testing.T) {
		e := newEnv(t)
		serveTasks(e.broker, taskRows())
		path := "/admin/tasks?team_id=3&limit=2"
		first := decodePage(t, e.do(http.MethodGet, path, e.is.adminToken("admin-one"), nil))
		if first.Page.NextCursor == nil {
			t.Fatal("first page has no next_cursor")
		}
		res := e.do(http.MethodGet, path+"&cursor="+url.QueryEscape(*first.Page.NextCursor), e.is.adminToken("admin-two"), nil)
		second := decodePage(t, res)
		if len(second.Items) == 0 || string(second.Items[0]) == string(first.Items[0]) {
			t.Fatalf("another administrator could not continue the page: %s", res.Raw)
		}
	})

	// M53 / M76 (admin part): every malformed limit shape is 400
	// invalid_pagination before any owner request on both admin lists.
	t.Run("M53 M76 malformed limit shapes rejected before the owner", func(t *testing.T) {
		e := newEnv(t)
		serveTasks(e.broker, taskRows())
		serveTags(e.broker, tagRows())
		token := e.is.adminToken("a")
		shapes := []string{"", " ", "abc", " 50", "50 ", "01", "010", "+1", "-1", "1.5", "0x1", "0o1", "1e2", "0", "201"}
		for _, route := range []string{"/admin/tasks", "/admin/tags"} {
			for _, raw := range shapes {
				q := url.Values{"limit": {raw}}
				expectError(t, e.do(http.MethodGet, route+"?"+q.Encode(), token, nil), http.StatusBadRequest, "invalid_pagination")
			}
		}
		if n := len(e.broker.requestList()); n != 0 {
			t.Fatalf("malformed limits sent %d owner requests", n)
		}
		// The boundaries themselves are accepted.
		for _, raw := range []string{"1", "200"} {
			if res := e.do(http.MethodGet, "/admin/tasks?limit="+raw, token, nil); res.Status != http.StatusOK {
				t.Fatalf("limit=%s: %d %s", raw, res.Status, res.Raw)
			}
		}
	})

	// M126: PUT and DELETE on a team answer 405 and reach no owner; PATCH
	// changes the team and keeps its team_id.
	t.Run("M126 team replace and delete are not allowed", func(t *testing.T) {
		e := newEnv(t)
		var updates int
		e.broker.on("team-registry.admin.update.pub", func(_ string, _ broker.Header, body []byte) (reply, error) {
			updates++
			return replyOf(200, map[string]any{"team_id": num(t, params(t, body)["team_id"]), "team_name": "alpha", "default_image": validImage, "ingested_at": "2026-11-07T10:00:00.000Z", "archived_at": nil}), nil
		})
		body := `{"default_image":"` + validImage + `"}`
		token := e.is.adminToken("admin-64")
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			if res := e.do(method, "/admin/teams/64", token, body); res.Status != http.StatusMethodNotAllowed {
				t.Fatalf("%s /admin/teams/64: %d %s, want 405", method, res.Status, res.Raw)
			}
		}
		if n := len(e.broker.requestList()); n != 0 {
			t.Fatalf("PUT/DELETE sent %d owner requests", n)
		}
		res := e.do(http.MethodPatch, "/admin/teams/64", token, body)
		if res.Status != http.StatusOK || num(t, res.JSON["team_id"]) != 64 || updates != 1 {
			t.Fatalf("PATCH: %d %s updates=%d, want 200 with team_id 64", res.Status, res.Raw, updates)
		}
	})

	// M127: the retired admin Source and Flow onboarding routes answer 404
	// to a verified administrator and reach no owner.
	t.Run("M127 retired admin onboarding routes are absent", func(t *testing.T) {
		e := newEnv(t)
		token := e.is.adminToken("admin-retired")
		for path, body := range map[string]string{
			"/admin/source-systems": `{"team_id":3,"name":"legacy"}`,
			"/admin/flows":          `{"team_id":3,"name":"openhands","execution_tag":"openhands"}`,
		} {
			if res := e.do(http.MethodPost, path, token, body); res.Status != http.StatusNotFound {
				t.Fatalf("authenticated POST %s: %d %s, want 404", path, res.Status, res.Raw)
			}
		}
		if n := len(e.broker.requestList()) + len(e.broker.publishedList()); n != 0 {
			t.Fatalf("retired routes produced %d broker messages", n)
		}
	})
}
