// Command admin-panel serves the /admin/* HTTP backend: it verifies the
// external admin JWT and calls the owning services over NATS.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/pandops/flowai-admin-panel/internal/adminauth"
	"github.com/pandops/flowai-admin-panel/internal/broker"
	"github.com/pandops/flowai-admin-panel/internal/config"
	"github.com/pandops/flowai-admin-panel/internal/cursor"
	"github.com/pandops/flowai-admin-panel/internal/httpapi"
	"github.com/pandops/flowai-admin-panel/internal/seq"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", broker.Name)
	if err := run(logger); err != nil {
		logger.Error("admin-panel stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	configPath := flag.String("config", "/etc/flowai/config.yaml", "path of the YAML configuration")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	auth, err := adminauth.New(adminauth.Config{
		Issuer: cfg.AdminIssuer, Audience: cfg.AdminAudience, JWKSURL: cfg.AdminJWKSURL,
		RolePointer: cfg.AdminRolePointer, Algorithms: cfg.AdminAlgorithms,
		ClockSkew: cfg.AdminClockSkew, TokenMaxAge: cfg.AdminTokenMaxAge, JWKSTimeout: cfg.AdminJWKSTimeout,
	})
	if err != nil {
		return err
	}
	nc, err := broker.Connect(broker.Settings{URL: cfg.NATSURL, CAFile: cfg.NATSCAFile, UserJWT: cfg.NATSUserJWT, Seed: cfg.NATSSeed})
	if err != nil {
		return err
	}
	defer nc.Close()

	handler := httpapi.New(httpapi.Deps{
		Auth: auth, Broker: nc,
		Keys:           cursor.Keyring{ActiveKeyID: cfg.CursorActiveKeyID, Keys: cfg.CursorKeys},
		Seq:            seq.New(time.Now),
		RequestTimeout: cfg.RequestTimeout,
		Logger:         logger,
		Now:            time.Now,
	})
	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.BindPort)),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		logger.Info("admin-panel listening", "addr", srv.Addr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
