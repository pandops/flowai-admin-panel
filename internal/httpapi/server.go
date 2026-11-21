// Package httpapi serves admin-panel's /admin/* edge and its probes.
//
// Every admin request is authenticated by the admin JWT first. A request
// that admin-panel itself rejects after authentication (missing role,
// invalid identifier or request, invalid pagination) is audited directly to
// ALL_AUDIT and answered only after the JetStream acknowledgement; every
// other request is forwarded to its owning service over core NATS
// request/reply with team: admin, admin_subject and request_id, and the
// owner's status and body are returned unchanged.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pandops/flowai-admin-panel/internal/adminauth"
	"github.com/pandops/flowai-admin-panel/internal/broker"
	"github.com/pandops/flowai-admin-panel/internal/cursor"
	"github.com/pandops/flowai-admin-panel/internal/seq"
)

// Authenticator verifies the admin JWT (adminauth.Authenticator).
type Authenticator interface {
	Authenticate(ctx context.Context, authorization string) (string, error)
}

// Deps wires the handler.
type Deps struct {
	Auth           Authenticator
	Broker         broker.Broker
	Keys           cursor.Keyring
	Seq            *seq.Counter
	RequestTimeout time.Duration
	Logger         *slog.Logger
	Now            func() time.Time
}

const (
	maxBodyBytes      = 64 << 10
	auditRetryBackoff = 50 * time.Millisecond
)

type server struct{ Deps }

// New returns the HTTP handler.
func New(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.RequestTimeout <= 0 {
		d.RequestTimeout = 5 * time.Second
	}
	s := &server{d}
	r := chi.NewRouter()
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": "not_found", "message": "route not found"})
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": "method_not_allowed", "message": "method not allowed"})
	})
	r.Get("/v1/livez", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	r.Get("/v1/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Broker.Connected() {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready"})
	})
	r.Post("/admin/teams", s.admin(actionTeamCreate, s.teamRoute("create", false)))
	r.Get("/admin/teams/{team_id}", s.admin(actionTeamGet, s.teamRoute("get", true)))
	r.Patch("/admin/teams/{team_id}", s.admin(actionTeamUpdate, s.teamRoute("update", true)))
	r.Post("/admin/teams/{team_id}/archive", s.admin(actionTeamArchive, s.teamRoute("archive", true)))
	r.Get("/admin/tags", s.admin(actionTagsList, s.listRoute(tagsList)))
	r.Get("/admin/tasks", s.admin(actionTasksList, s.listRoute(tasksList)))
	return r
}

type action struct{ name, resourceType string }

var (
	actionTeamCreate  = action{"team-create", "team"}
	actionTeamGet     = action{"team-get", "team"}
	actionTeamUpdate  = action{"team-update", "team"}
	actionTeamArchive = action{"team-archive", "team"}
	actionTagsList    = action{"tags-list", "execution_tags"}
	actionTasksList   = action{"tasks-list", "tasks"}
)

// call is one authenticated admin request.
type call struct {
	w         http.ResponseWriter
	r         *http.Request
	action    action
	subject   string
	requestID int64
}

// rejection is a decision admin-panel makes itself after authentication.
type rejection struct {
	status     int
	code       string
	resourceID *int64
}

func (s *server) admin(a action, handle func(*call) *rejection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &call{w: w, r: r, action: a, requestID: newRequestID()}
		subject, err := s.Auth.Authenticate(r.Context(), r.Header.Get("Authorization"))
		switch {
		case errors.Is(err, adminauth.ErrUnavailable):
			s.Logger.Warn("admin identity provider unavailable", "request_id", c.requestID, "action", a.name)
			s.writeError(c, http.StatusBadGateway, "admin_identity_provider_unavailable")
			return
		case errors.Is(err, adminauth.ErrRole):
			c.subject = subject
			s.reject(c, &rejection{status: http.StatusForbidden, code: "insufficient_admin_role", resourceID: pathTeam(r)})
			return
		case err != nil:
			s.writeError(c, http.StatusUnauthorized, "invalid_admin_token")
			return
		}
		c.subject = subject
		if rej := handle(c); rej != nil {
			s.reject(c, rej)
		}
	}
}

var messages = map[string]string{
	"invalid_admin_token":                 "administrator token is invalid",
	"insufficient_admin_role":             "system administrator role is required",
	"admin_identity_provider_unavailable": "administrator identity provider is unavailable",
	"invalid_request":                     "request is invalid",
	"invalid_pagination":                  "the pagination request is invalid",
	"service_unavailable":                 "the owning service is unavailable",
	"broker_unavailable":                  "the message broker is unavailable",
}

func (s *server) writeError(c *call, status int, code string) {
	writeJSON(c.w, status, map[string]any{"code": code, "message": messages[code], "request_id": c.requestID})
}

// reject audits admin-panel's own rejection and then answers it, or
// answers 503 when JetStream does not acknowledge within the timeout.
func (s *server) reject(c *call, rej *rejection) {
	seqN := s.Seq.Next()
	body, err := json.Marshal(auditMessage{
		Publisher: broker.Name, PublisherSeq: seqN,
		OccurredAt:    s.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		SourceService: broker.Name, ActorType: "administrator", ActorSubject: c.subject,
		Action: c.action.name, ResourceType: c.action.resourceType, ResourceID: rej.resourceID,
		RequestID: c.requestID, Outcome: "rejected", Reason: rej.code,
	})
	if err != nil {
		s.writeError(c, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	header := broker.Header{
		"team":        "admin",
		"Nats-Msg-Id": broker.Name + "-" + strconv.FormatInt(seqN, 10),
		"request_id":  strconv.FormatInt(c.requestID, 10),
	}
	subject := "admin-panel.audit." + c.action.name + ".pub"
	ctx, cancel := context.WithTimeout(c.r.Context(), s.RequestTimeout)
	defer cancel()
	for {
		err := s.Broker.PublishJetStream(ctx, subject, header, body)
		if err == nil {
			s.Logger.Info("admin request rejected", "request_id", c.requestID, "action", c.action.name, "code", rej.code, "publisher_seq", seqN)
			s.writeError(c, rej.status, rej.code)
			return
		}
		select {
		case <-ctx.Done():
			s.Logger.Warn("rejection audit not acknowledged", "request_id", c.requestID, "action", c.action.name, "publisher_seq", seqN, "error", err.Error())
			s.writeError(c, http.StatusServiceUnavailable, "service_unavailable")
			return
		case <-time.After(auditRetryBackoff):
		}
	}
}

type auditMessage struct {
	Publisher     string `json:"publisher"`
	PublisherSeq  int64  `json:"publisher_seq"`
	OccurredAt    string `json:"occurred_at"`
	SourceService string `json:"source_service"`
	ActorType     string `json:"actor_type"`
	ActorSubject  string `json:"actor_subject"`
	Action        string `json:"action"`
	ResourceType  string `json:"resource_type"`
	ResourceID    *int64 `json:"resource_id"`
	RequestID     int64  `json:"request_id"`
	Outcome       string `json:"outcome"`
	Reason        string `json:"reason"`
}

// request is the rule-9 request body.
type request struct {
	Params map[string]any `json:"params"`
	Body   any            `json:"body,omitempty"`
}

// forward sends the request and returns the reply, or writes the 503
// and returns ok=false.
func (s *server) forward(c *call, subject string, req request) (broker.Reply, bool) {
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	data, err := json.Marshal(req)
	if err != nil {
		s.writeError(c, http.StatusServiceUnavailable, "service_unavailable")
		return broker.Reply{}, false
	}
	header := broker.Header{"team": "admin", "admin_subject": c.subject, "request_id": strconv.FormatInt(c.requestID, 10)}
	if m := c.r.Header.Get("If-Match"); m != "" {
		header["If-Match"] = m
	}
	ctx, cancel := context.WithTimeout(c.r.Context(), s.RequestTimeout)
	defer cancel()
	rep, err := s.Broker.Request(ctx, subject, header, data)
	if err != nil {
		code := "service_unavailable"
		if errors.Is(err, broker.ErrUnavailable) {
			code = "broker_unavailable"
		}
		s.Logger.Warn("owner request failed", "request_id", c.requestID, "subject", subject, "error", err.Error())
		s.writeError(c, http.StatusServiceUnavailable, code)
		return broker.Reply{}, false
	}
	if status(rep) == 0 {
		s.Logger.Warn("owner reply without status", "request_id", c.requestID, "subject", subject)
		s.writeError(c, http.StatusServiceUnavailable, "service_unavailable")
		return broker.Reply{}, false
	}
	return rep, true
}

func status(rep broker.Reply) int {
	n, err := strconv.Atoi(rep.Header["status"])
	if err != nil || n < 100 || n > 599 {
		return 0
	}
	return n
}

// relay returns the owner's status, body and copied headers unchanged.
func relay(w http.ResponseWriter, rep broker.Reply) {
	for _, h := range []string{"ETag", "Location", "Retry-After"} {
		if v := rep.Header[h]; v != "" {
			w.Header().Set(h, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status(rep))
	_, _ = w.Write(rep.Body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// newRequestID draws a random positive 63-bit integer.
func newRequestID() int64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		if n := int64(binary.BigEndian.Uint64(b[:]) >> 1); n > 0 {
			return n
		}
	}
}
