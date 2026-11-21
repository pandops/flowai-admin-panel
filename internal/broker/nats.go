package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

// Name is admin-panel's NATS identity; its reply inbox is _INBOX.<Name>.
const Name = "admin-panel"

// Settings are the connection settings taken from configuration.
type Settings struct {
	URL     string
	CAFile  string
	UserJWT string
	Seed    []byte
}

// Options builds the connection options: TLS against the configured CA,
// the static user JWT and seed, admin-panel's own inbox prefix, and
// endless reconnects with no publish buffering while disconnected.
func Options(s Settings) ([]nats.Option, error) {
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" {
		return nil, errors.New("broker URL must be a tls:// URL")
	}
	if s.CAFile == "" || s.UserJWT == "" || len(s.Seed) == 0 {
		return nil, errors.New("broker CA, user JWT and seed are required")
	}
	pem, err := os.ReadFile(s.CAFile)
	if err != nil {
		return nil, errors.New("broker CA file cannot be read")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("broker CA file holds no PEM certificate")
	}
	return []nats.Option{
		nats.Name(Name),
		nats.CustomInboxPrefix("_INBOX." + Name),
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}),
		nats.UserJWTAndSeed(s.UserJWT, string(s.Seed)),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.ReconnectBufSize(-1),
	}, nil
}

// NATS is the production Broker.
type NATS struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

// Connect opens the connection; it keeps retrying in the background when
// the server is unreachable, and Connected reports false until it is up.
func Connect(s Settings) (*NATS, error) {
	opts, err := Options(s)
	if err != nil {
		return nil, err
	}
	nc, err := nats.Connect(s.URL, opts...)
	if err != nil {
		return nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &NATS{nc: nc, js: js}, nil
}

// Close drains nothing and closes the connection.
func (n *NATS) Close() { n.nc.Close() }

// Connected reports whether the connection is up.
func (n *NATS) Connected() bool { return n.nc.IsConnected() }

func message(subject string, header Header, body []byte) *nats.Msg {
	m := nats.NewMsg(subject)
	for k, v := range header {
		m.Header.Set(k, v)
	}
	m.Data = body
	return m
}

// Request sends a core NATS request and waits for its reply.
func (n *NATS) Request(ctx context.Context, subject string, header Header, body []byte) (Reply, error) {
	if !n.nc.IsConnected() {
		return Reply{}, ErrUnavailable
	}
	msg, err := n.nc.RequestMsgWithContext(ctx, message(subject, header, body))
	if err != nil {
		return Reply{}, classify(err)
	}
	h := Header{}
	for k := range msg.Header {
		h[k] = msg.Header.Get(k)
	}
	return Reply{Header: h, Body: msg.Data}, nil
}

// PublishJetStream publishes one stream message and waits for its
// acknowledgement. header must carry Nats-Msg-Id.
func (n *NATS) PublishJetStream(ctx context.Context, subject string, header Header, body []byte) error {
	if !n.nc.IsConnected() {
		return ErrUnavailable
	}
	if _, err := n.js.PublishMsg(message(subject, header, body), nats.Context(ctx)); err != nil {
		return classify(err)
	}
	return nil
}

func classify(err error) error {
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		return ErrNoResponder
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout), errors.Is(err, context.Canceled):
		return ErrTimeout
	case errors.Is(err, nats.ErrConnectionClosed), errors.Is(err, nats.ErrDisconnected), errors.Is(err, nats.ErrConnectionReconnecting), errors.Is(err, nats.ErrReconnectBufExceeded):
		return ErrUnavailable
	}
	return err
}
