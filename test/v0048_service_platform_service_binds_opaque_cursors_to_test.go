package test

// Requirement: service-platform service binds opaque cursors to their read
// (admin-panel's admin cursors).

import (
	"net/http"
	"net/url"
	"testing"
)

// Scenarios: Forward page advances; Tampered cursor; Cursor reused for
// another operation or team; Changed filter; Limit out of range.
func TestV0048AdminPanelServiceBindsOpaqueCursorsToTheirRead(t *testing.T) {
	e := newEnv(t)
	serveTasks(e.broker, taskRows())
	serveTags(e.broker, tagRows())
	token := e.is.adminToken("a")
	first := decodePage(t, e.do(http.MethodGet, "/admin/tasks?state=pending&limit=3", token, nil))
	c := url.QueryEscape(*first.Page.NextCursor)

	t.Run("forward page advances", func(t *testing.T) {
		second := decodePage(t, e.do(http.MethodGet, "/admin/tasks?state=pending&limit=3&cursor="+c, token, nil))
		if len(second.Items) != 3 || string(second.Items[0]) == string(first.Items[0]) {
			t.Fatal("second page does not advance")
		}
	})
	reject := func(t *testing.T, path string) {
		t.Helper()
		before := len(e.broker.requestList())
		expectError(t, e.do(http.MethodGet, path, token, nil), http.StatusBadRequest, "invalid_pagination")
		if len(e.broker.requestList()) != before {
			t.Fatalf("%s reached the owner", path)
		}
	}
	t.Run("tampered cursor", func(t *testing.T) {
		b := []byte(*first.Page.NextCursor)
		b[len(b)/2] ^= 1
		reject(t, "/admin/tasks?state=pending&limit=3&cursor="+url.QueryEscape(string(b)))
	})
	t.Run("cursor reused for another operation", func(t *testing.T) {
		reject(t, "/admin/tags?limit=3&cursor="+c)
	})
	t.Run("changed filter", func(t *testing.T) {
		reject(t, "/admin/tasks?state=running&limit=3&cursor="+c)
		reject(t, "/admin/tasks?limit=3&cursor="+c)
		reject(t, "/admin/tasks?state=pending&team_id=3&limit=3&cursor="+c)
	})
	t.Run("limit out of range", func(t *testing.T) {
		for _, l := range []string{"0", "201", "x", "1e2"} {
			reject(t, "/admin/tasks?limit="+l)
			reject(t, "/admin/tags?limit="+l)
		}
	})
	t.Run("repeated or unknown query parameters", func(t *testing.T) {
		reject(t, "/admin/tasks?limit=3&limit=4")
		reject(t, "/admin/tasks?cursor=a&cursor=b")
	})
}
