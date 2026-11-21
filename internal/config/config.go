// Package config loads and validates admin-panel's YAML configuration.
//
// admin-panel has no database, so the file has no db section; unknown
// keys (db, test switches, password users) are rejected. Every trust
// setting is required and checked before the service listens.
package config

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	"gopkg.in/yaml.v3"
)

// Config is the resolved admin-panel configuration.
type Config struct {
	BindHost string
	BindPort int

	NATSURL        string
	NATSCAFile     string
	NATSUserJWT    string
	NATSSeed       []byte
	RequestTimeout time.Duration

	AdminIssuer      string
	AdminAudience    string
	AdminJWKSURL     string
	AdminRolePointer string
	AdminAlgorithms  []string
	AdminJWKSTimeout time.Duration
	AdminTokenMaxAge time.Duration
	AdminClockSkew   time.Duration

	CursorActiveKeyID int64
	CursorKeys        map[int64][]byte
}

const (
	defaultRequestTimeout = 5 * time.Second
	defaultClockSkew      = 30 * time.Second
	maxClockSkew          = 5 * time.Minute
	minCursorKeyBytes     = 32
)

// allowedAlgorithms are the asymmetric algorithms the authenticator
// verifies. Symmetric (HS*) and none are never allowed.
var allowedAlgorithms = map[string]bool{"RS256": true, "RS384": true, "RS512": true}

type document struct {
	HTTP struct {
		BindHost string `yaml:"bind_host"`
		BindPort int    `yaml:"bind_port"`
	} `yaml:"http"`
	NATS struct {
		URL             string `yaml:"url"`
		CAFile          string `yaml:"ca_file"`
		CredentialsFile string `yaml:"credentials_file"`
		RequestTimeout  string `yaml:"request_timeout"`
	} `yaml:"nats"`
	Admin *struct {
		Issuer           string   `yaml:"issuer"`
		Audience         string   `yaml:"audience"`
		JWKSURL          string   `yaml:"jwks_url"`
		RoleClaimPointer string   `yaml:"role_claim_pointer"`
		Algorithms       []string `yaml:"algorithms"`
		JWKSTimeout      string   `yaml:"admin_jwks_timeout"`
		TokenMaxAge      string   `yaml:"admin_token_max_age"`
		ClockSkew        string   `yaml:"clock_skew"`
	} `yaml:"admin"`
	CursorKeys []struct {
		ID         int64  `yaml:"id"`
		SecretFile string `yaml:"secret_file"`
	} `yaml:"cursor_keys"`
	CursorActiveKeyID int64 `yaml:"cursor_active_key_id"`
}

// Load reads the YAML file at path and every file it references.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	var doc document
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}
	cfg := Config{BindHost: doc.HTTP.BindHost, BindPort: doc.HTTP.BindPort}
	if cfg.BindHost == "" {
		cfg.BindHost = "0.0.0.0"
	}
	if cfg.BindPort == 0 {
		cfg.BindPort = 8080
	}
	if cfg.BindPort < 1 || cfg.BindPort > 65535 {
		return Config{}, errors.New("http.bind_port is out of range")
	}
	if err := loadNATS(&cfg, &doc); err != nil {
		return Config{}, err
	}
	if err := loadAdmin(&cfg, &doc); err != nil {
		return Config{}, err
	}
	if err := loadCursorKeys(&cfg, &doc); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadNATS(cfg *Config, doc *document) error {
	u, err := url.Parse(doc.NATS.URL)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" {
		return errors.New("nats.url must be a tls:// URL")
	}
	cfg.NATSURL = doc.NATS.URL
	if doc.NATS.CAFile == "" {
		return errors.New("nats.ca_file is required")
	}
	ca, err := os.ReadFile(doc.NATS.CAFile)
	if err != nil || !x509.NewCertPool().AppendCertsFromPEM(ca) {
		return errors.New("nats.ca_file must hold a PEM CA certificate")
	}
	cfg.NATSCAFile = doc.NATS.CAFile
	if doc.NATS.CredentialsFile == "" {
		return errors.New("nats.credentials_file is required")
	}
	creds, err := os.ReadFile(doc.NATS.CredentialsFile)
	if err != nil {
		return errors.New("nats.credentials_file cannot be read")
	}
	userJWT, err := natsjwt.ParseDecoratedJWT(creds)
	if err != nil {
		return errors.New("nats.credentials_file holds no user JWT")
	}
	if _, err := natsjwt.DecodeUserClaims(userJWT); err != nil {
		return errors.New("nats.credentials_file holds no valid user JWT")
	}
	kp, err := natsjwt.ParseDecoratedNKey(creds)
	if err != nil {
		return errors.New("nats.credentials_file holds no user seed")
	}
	seed, err := kp.Seed()
	if err != nil || len(seed) == 0 {
		return errors.New("nats.credentials_file holds no user seed")
	}
	cfg.NATSUserJWT, cfg.NATSSeed = userJWT, seed
	cfg.RequestTimeout = defaultRequestTimeout
	if doc.NATS.RequestTimeout != "" {
		d, err := time.ParseDuration(doc.NATS.RequestTimeout)
		if err != nil || d <= 0 {
			return errors.New("nats.request_timeout must be a positive duration")
		}
		cfg.RequestTimeout = d
	}
	return nil
}

func loadAdmin(cfg *Config, doc *document) error {
	a := doc.Admin
	if a == nil {
		return errors.New("admin trust configuration is required")
	}
	for name, v := range map[string]string{"admin.issuer": a.Issuer, "admin.jwks_url": a.JWKSURL} {
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%s must be an absolute URL", name)
		}
	}
	if strings.TrimSpace(a.Audience) == "" {
		return errors.New("admin.audience is required")
	}
	if !strings.HasPrefix(a.RoleClaimPointer, "/") {
		return errors.New("admin.role_claim_pointer must be an RFC 6901 pointer")
	}
	if len(a.Algorithms) == 0 {
		return errors.New("admin.algorithms is required")
	}
	for _, alg := range a.Algorithms {
		if !allowedAlgorithms[alg] {
			return fmt.Errorf("admin algorithm %q is not an allowed asymmetric algorithm", alg)
		}
	}
	var err error
	if cfg.AdminJWKSTimeout, err = positive("admin.admin_jwks_timeout", a.JWKSTimeout); err != nil {
		return err
	}
	if cfg.AdminTokenMaxAge, err = positive("admin.admin_token_max_age", a.TokenMaxAge); err != nil {
		return err
	}
	cfg.AdminClockSkew = defaultClockSkew
	if a.ClockSkew != "" {
		d, err := time.ParseDuration(a.ClockSkew)
		if err != nil || d < 0 || d > maxClockSkew {
			return errors.New("admin.clock_skew must be between 0 and 5m")
		}
		cfg.AdminClockSkew = d
	}
	cfg.AdminIssuer, cfg.AdminAudience, cfg.AdminJWKSURL = a.Issuer, a.Audience, a.JWKSURL
	cfg.AdminRolePointer, cfg.AdminAlgorithms = a.RoleClaimPointer, a.Algorithms
	return nil
}

func positive(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return d, nil
}

func loadCursorKeys(cfg *Config, doc *document) error {
	if len(doc.CursorKeys) == 0 {
		return errors.New("cursor_keys is required")
	}
	cfg.CursorKeys = map[int64][]byte{}
	for _, k := range doc.CursorKeys {
		if k.ID <= 0 {
			return errors.New("cursor key id must be a positive integer")
		}
		if _, dup := cfg.CursorKeys[k.ID]; dup {
			return fmt.Errorf("cursor key id %d is repeated", k.ID)
		}
		secret, err := os.ReadFile(k.SecretFile)
		if err != nil || len(secret) < minCursorKeyBytes {
			return fmt.Errorf("cursor key %d needs a secret_file of at least %d bytes", k.ID, minCursorKeyBytes)
		}
		cfg.CursorKeys[k.ID] = secret
	}
	if _, ok := cfg.CursorKeys[doc.CursorActiveKeyID]; !ok {
		return errors.New("cursor_active_key_id must name a configured cursor key")
	}
	cfg.CursorActiveKeyID = doc.CursorActiveKeyID
	return nil
}
