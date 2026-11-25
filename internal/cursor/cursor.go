// Package cursor issues and verifies admin-panel's opaque admin cursors.
//
// A cursor is "<key_id>.<payload>.<mac>": key_id is the decimal integer of
// a configured key, payload the base64url JSON envelope (endpoint, the
// flowai-system-admin scope, the complete filter tuple, the ordering, the
// forward direction and the owner's continuation position), and mac the
// base64url HMAC-SHA-256 of "<key_id>.<payload>" under that key. Every
// failure is the same ErrInvalid.
package cursor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalid is the single non-revealing rejection.
var ErrInvalid = errors.New("invalid cursor")

const (
	scope     = "flowai-system-admin"
	direction = "forward"
	// MaxTokenLength bounds the work done on caller input.
	MaxTokenLength = 2048
)

var keyIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

// Keyring holds the configured keys by integer key_id.
type Keyring struct {
	ActiveKeyID int64
	Keys        map[int64][]byte
}

// Binding is everything a cursor is bound to besides scope and direction.
type Binding struct {
	Endpoint string
	Filters  map[string]string
	Ordering string
}

type envelope struct {
	Endpoint  string            `json:"ep"`
	Scope     string            `json:"sc"`
	Filters   map[string]string `json:"ft"`
	Ordering  string            `json:"or"`
	Direction string            `json:"dr"`
	After     json.RawMessage   `json:"af"`
}

// Encode issues a cursor wrapping the owner's continuation position after.
func Encode(k Keyring, b Binding, after json.RawMessage) (string, error) {
	key, ok := k.Keys[k.ActiveKeyID]
	if !ok || len(key) == 0 {
		return "", errors.New("active cursor key is not configured")
	}
	filters := b.Filters
	if filters == nil {
		filters = map[string]string{}
	}
	payload, err := json.Marshal(envelope{Endpoint: b.Endpoint, Scope: scope, Filters: filters, Ordering: b.Ordering, Direction: direction, After: after})
	if err != nil {
		return "", err
	}
	head := strconv.FormatInt(k.ActiveKeyID, 10) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return head + "." + base64.RawURLEncoding.EncodeToString(sign(key, head)), nil
}

// Decode verifies token against the binding and returns the position.
func Decode(k Keyring, b Binding, token string) (json.RawMessage, error) {
	if len(token) == 0 || len(token) > MaxTokenLength {
		return nil, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || !keyIDPattern.MatchString(parts[0]) {
		return nil, ErrInvalid
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := k.Keys[id]
	if !ok {
		return nil, ErrInvalid
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(mac, sign(key, parts[0]+"."+parts[1])) {
		return nil, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalid
	}
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, ErrInvalid
	}
	filters := b.Filters
	if filters == nil {
		filters = map[string]string{}
	}
	if env.Endpoint != b.Endpoint || env.Scope != scope || env.Ordering != b.Ordering || env.Direction != direction ||
		!maps.Equal(env.Filters, filters) || len(env.After) == 0 || env.After[0] != '{' {
		return nil, ErrInvalid
	}
	return env.After, nil
}

func sign(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
