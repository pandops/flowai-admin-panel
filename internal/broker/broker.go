// Package broker is admin-panel's messaging boundary: core NATS
// request/reply to the owning services and synchronous JetStream
// publishes of its own rejection audits.
package broker

import (
	"context"
	"errors"
)

var (
	// ErrNoResponder: nobody serves the subject.
	ErrNoResponder = errors.New("no responder")
	// ErrTimeout: no reply or acknowledgement within the deadline.
	ErrTimeout = errors.New("timeout")
	// ErrUnavailable: admin-panel's own broker connection is down.
	ErrUnavailable = errors.New("broker unavailable")
)

// Header is a single-valued set of NATS headers.
type Header = map[string]string

// Reply is a request/reply answer.
type Reply struct {
	Header Header
	Body   []byte
}

// Broker is implemented by the NATS client and by test fakes.
type Broker interface {
	Request(ctx context.Context, subject string, header Header, body []byte) (Reply, error)
	// PublishJetStream publishes one message and waits for the
	// JetStream acknowledgement.
	PublishJetStream(ctx context.Context, subject string, header Header, body []byte) error
	Connected() bool
}
