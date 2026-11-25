package httpapi

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"
)

var decimalID = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

// parseID accepts a positive int64 written in decimal without sign or
// leading zeros.
func parseID(s string) (int64, bool) {
	if !decimalID.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// pathTeam returns the valid team_id the route path names, if any.
func pathTeam(r *http.Request) *int64 {
	if n, ok := parseID(chi.URLParam(r, "team_id")); ok {
		return &n
	}
	if n, ok := parseID(r.URL.Query().Get("team_id")); ok {
		return &n
	}
	return nil
}
