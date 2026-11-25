// Package test holds admin-panel's unit tests. Every external dependency
// is faked in process: the identity provider's JWKS endpoint is an
// httptest server, the broker is fakeBroker at admin-panel's messaging
// boundary (internal/broker.Broker), and time comes from the real clock
// or an injected function.
package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/pandops/flowai-admin-panel/internal/adminauth"
	"github.com/pandops/flowai-admin-panel/internal/broker"
	"github.com/pandops/flowai-admin-panel/internal/cursor"
	"github.com/pandops/flowai-admin-panel/internal/httpapi"
	"github.com/pandops/flowai-admin-panel/internal/seq"
)

const (
	testIssuer   = "https://idp.test/realms/flowai"
	testAudience = "flowai-admin"
	testPointer  = "/realm_access/roles"
	adminRole    = "flowai-system-admin"
	testTimeout  = 300 * time.Millisecond
)

// ---------------------------------------------------------------- JWT issuer

type issuer struct {
	t      *testing.T
	key    *rsa.PrivateKey
	kid    string
	mu     sync.Mutex
	mode   string // "ok", "fail", "slow"
	hits   int
	server *httptest.Server
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{t: t, key: key, kid: "k1", mode: "ok"}
	is.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.mu.Lock()
		mode := is.mode
		is.hits++
		is.mu.Unlock()
		switch mode {
		case "fail":
			http.Error(w, "down", http.StatusInternalServerError)
			return
		case "slow":
			time.Sleep(2 * time.Second)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{is.jwk(is.key, is.kid)}})
	}))
	t.Cleanup(is.server.Close)
	return is
}

func (is *issuer) jwk(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func (is *issuer) setMode(mode string) {
	is.mu.Lock()
	is.mode = mode
	is.mu.Unlock()
}

func (is *issuer) jwksHits() int {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.hits
}

func (is *issuer) authConfig() adminauth.Config {
	return adminauth.Config{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: is.server.URL,
		RolePointer: testPointer, Algorithms: []string{"RS256"},
		ClockSkew: 30 * time.Second, TokenMaxAge: 5 * time.Minute, JWKSTimeout: 500 * time.Millisecond,
	}
}

// claims returns valid administrator claims for subject.
func (is *issuer) claims(subject string, roles ...string) map[string]any {
	now := time.Now().Unix()
	if roles == nil {
		roles = []string{adminRole}
	}
	return map[string]any{
		"iss": testIssuer, "aud": testAudience, "sub": subject,
		"iat": now, "exp": now + 300,
		"realm_access": map[string]any{"roles": roles},
	}
}

// sign signs claims as RS256 with kid.
func (is *issuer) signWith(key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": alg, "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, 5 /* crypto.SHA256 */, digest[:])
	if err != nil {
		is.t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (is *issuer) sign(claims map[string]any) string {
	return is.signWith(is.key, is.kid, "RS256", claims)
}

func (is *issuer) adminToken(subject string) string { return is.sign(is.claims(subject)) }

// unsigned returns an alg=none token with the given claims.
func (is *issuer) unsigned(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "none", "kid": is.kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// ---------------------------------------------------------------- fake broker

type recorded struct {
	Subject string
	Header  broker.Header
	Body    []byte
}

// responder answers one request.
type responder func(subject string, header broker.Header, body []byte) (broker.Reply, error)

type fakeBroker struct {
	mu          sync.Mutex
	responders  map[string]responder
	requests    []recorded
	published   []recorded
	attempts    []recorded
	ackFailures int  // fail the first N JetStream publishes with ErrTimeout
	ackNever    bool // never acknowledge (wait for the deadline)
}

func newFakeBroker() *fakeBroker {
	return &fakeBroker{responders: map[string]responder{}}
}

func (f *fakeBroker) on(subject string, r responder) {
	f.mu.Lock()
	f.responders[subject] = r
	f.mu.Unlock()
}

func copyHeader(h broker.Header) broker.Header {
	out := broker.Header{}
	for k, v := range h {
		out[k] = v
	}
	return out
}

func (f *fakeBroker) Request(ctx context.Context, subject string, header broker.Header, body []byte) (broker.Reply, error) {
	f.mu.Lock()
	f.requests = append(f.requests, recorded{subject, copyHeader(header), append([]byte(nil), body...)})
	r := f.responders[subject]
	f.mu.Unlock()
	if r == nil {
		return broker.Reply{}, broker.ErrNoResponder
	}
	return r(subject, header, body)
}

func (f *fakeBroker) PublishJetStream(ctx context.Context, subject string, header broker.Header, body []byte) error {
	f.mu.Lock()
	rec := recorded{subject, copyHeader(header), append([]byte(nil), body...)}
	f.attempts = append(f.attempts, rec)
	if f.ackNever {
		f.mu.Unlock()
		<-ctx.Done()
		return broker.ErrTimeout
	}
	if f.ackFailures > 0 {
		f.ackFailures--
		f.mu.Unlock()
		return broker.ErrTimeout
	}
	f.published = append(f.published, rec)
	f.mu.Unlock()
	return nil
}

func (f *fakeBroker) Connected() bool { return true }

func (f *fakeBroker) requestList() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func (f *fakeBroker) publishedList() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.published...)
}

func (f *fakeBroker) attemptList() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.attempts...)
}

type reply = broker.Reply

// replyOf builds a broker reply with the status header and a JSON body.
func replyOf(status int, body any) broker.Reply {
	data, _ := json.Marshal(body)
	return broker.Reply{Header: broker.Header{"status": itoa(status)}, Body: data}
}

func itoa(v int) string { return strconv.Itoa(v) }

// ---------------------------------------------------------------- server

type env struct {
	t      *testing.T
	is     *issuer
	broker *fakeBroker
	keys   cursor.Keyring
	h      http.Handler
	logs   *bytes.Buffer
	seq    *seq.Counter
}

func testKeys() cursor.Keyring {
	return cursor.Keyring{ActiveKeyID: 1, Keys: map[int64][]byte{1: bytes.Repeat([]byte{0x11}, 32)}}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	is := newIssuer(t)
	return newEnvWith(t, is, newFakeBroker(), testKeys(), seq.New(time.Now))
}

func newEnvWith(t *testing.T, is *issuer, fb *fakeBroker, keys cursor.Keyring, counter *seq.Counter) *env {
	t.Helper()
	auth, err := adminauth.New(is.authConfig())
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	logs := &bytes.Buffer{}
	e := &env{t: t, is: is, broker: fb, keys: keys, logs: logs, seq: counter}
	e.h = httpapi.New(httpapi.Deps{
		Auth: auth, Broker: fb, Keys: keys, Seq: counter,
		RequestTimeout: testTimeout,
		Logger:         slog.New(slog.NewJSONHandler(&lockedWriter{w: logs}, nil)),
		Now:            time.Now,
	})
	return e
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type response struct {
	Status int
	Header http.Header
	Raw    []byte
	JSON   map[string]any
}

// do sends one request. token "" sends no Authorization header.
func (e *env) do(method, path, token string, body any, headers ...string) response {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			reader = strings.NewReader(b)
		default:
			data, _ := json.Marshal(b)
			reader = bytes.NewReader(data)
		}
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	res := response{Status: rec.Code, Header: rec.Header(), Raw: rec.Body.Bytes()}
	dec := json.NewDecoder(bytes.NewReader(res.Raw))
	dec.UseNumber()
	_ = dec.Decode(&res.JSON)
	return res
}

func (r response) code() string {
	c, _ := r.JSON["code"].(string)
	return c
}

func expectError(t *testing.T, r response, status int, code string) {
	t.Helper()
	if r.Status != status || r.code() != code {
		t.Fatalf("got %d %q (%s), want %d %q", r.Status, r.code(), r.Raw, status, code)
	}
	id, ok := r.JSON["request_id"].(json.Number)
	if !ok {
		t.Fatalf("error body has no integer request_id: %s", r.Raw)
	}
	if n, err := id.Int64(); err != nil || n <= 0 {
		t.Fatalf("request_id %v is not a positive int64", id)
	}
}

// decodeBody decodes a broker request body {params, body}.
func decodeBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("request body is not a JSON object: %v (%s)", err, raw)
	}
	return m
}

func params(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	p, _ := decodeBody(t, raw)["params"].(map[string]any)
	if p == nil {
		t.Fatalf("request body has no params object: %s", raw)
	}
	return p
}

// ---------------------------------------------------------------- schema

// auditActions are admin-panel's published audit actions; each has its own
// schemas/audit.<action>.schema.json (rule 17).
var auditActions = []string{"team-create", "team-get", "team-update", "team-archive", "tags-list", "tasks-list"}

var (
	schemaMu    sync.Mutex
	schemaCache = map[string]*jsonschema.Schema{}
)

func schemaPath(action string) string {
	return filepath.Join("..", "schemas", "audit."+action+".schema.json")
}

func auditSchema(t *testing.T, action string) *jsonschema.Schema {
	t.Helper()
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if s, ok := schemaCache[action]; ok {
		return s
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	s, err := c.Compile(schemaPath(action))
	if err != nil {
		t.Fatalf("compile schema for %s: %v", action, err)
	}
	schemaCache[action] = s
	return s
}

// validateAuditAs validates raw against the schema of one action.
func validateAuditAs(t *testing.T, action string, raw []byte) error {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return auditSchema(t, action).Validate(v)
}

// validateAudit validates raw against the schema named by its action field;
// a message without a published action is invalid.
func validateAudit(t *testing.T, raw []byte) error {
	t.Helper()
	var m struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	for _, a := range auditActions {
		if a == m.Action {
			return validateAuditAs(t, a, raw)
		}
	}
	return fmt.Errorf("action %q has no admin-panel audit schema", m.Action)
}

// auditBody decodes one published audit message.
func auditBody(t *testing.T, rec recorded) map[string]any {
	t.Helper()
	if err := validateAudit(t, rec.Body); err != nil {
		t.Fatalf("audit message does not validate against its schema: %v\n%s", err, rec.Body)
	}
	m := decodeBody(t, rec.Body)
	if want := "admin-panel.audit." + m["action"].(string) + ".pub"; rec.Subject != want {
		t.Fatalf("audit for action %v published on %s, want %s", m["action"], rec.Subject, want)
	}
	return m
}

func num(t *testing.T, v any) int64 {
	t.Helper()
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("%v (%T) is not a JSON number", v, v)
	}
	i, err := n.Int64()
	if err != nil {
		t.Fatalf("%v is not an int64", v)
	}
	return i
}

// ---------------------------------------------------------------- config files

// configFixture writes a complete valid configuration and its referenced
// files into a temp dir. mutate edits the YAML document before writing.
func configFixture(t *testing.T, mutate func(doc map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	creds := testCreds(t)
	doc := map[string]any{
		"http": map[string]any{"bind_host": "0.0.0.0", "bind_port": 8080},
		"nats": map[string]any{
			"url":              "tls://nats.flowai.svc:4222",
			"ca_file":          write("ca.pem", testCAPEM(t)),
			"credentials_file": write("user.creds", creds),
		},
		"admin": map[string]any{
			"issuer":              testIssuer,
			"audience":            testAudience,
			"jwks_url":            "https://idp.test/realms/flowai/protocol/openid-connect/certs",
			"role_claim_pointer":  testPointer,
			"algorithms":          []any{"RS256"},
			"admin_jwks_timeout":  "2s",
			"admin_token_max_age": "5m",
			"clock_skew":          "30s",
		},
		"cursor_keys":          []any{map[string]any{"id": 1, "secret_file": write("cursor-1.key", bytes.Repeat([]byte("k"), 32))}},
		"cursor_active_key_id": 1,
	}
	if mutate != nil {
		mutate(doc)
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return write("admin-panel.yaml", data)
}

// testCreds returns a NATS .creds file (decorated user JWT and seed).
func testCreds(t *testing.T) []byte {
	t.Helper()
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	pub, _ := user.PublicKey()
	claims := natsjwt.NewUserClaims(pub)
	claims.Name = "admin-panel"
	token, err := claims.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := natsjwt.FormatUserConfig(token, seed)
	if err != nil {
		t.Fatal(err)
	}
	return creds
}

func section(doc map[string]any, name string) map[string]any { return doc[name].(map[string]any) }

var (
	caOnce sync.Once
	caPEM  []byte
)

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	caOnce.Do(func() {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "flowai-test-ca"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	})
	return caPEM
}

// serviceDir returns the standalone service root.
func serviceDir() string { return ".." }
