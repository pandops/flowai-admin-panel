package test

// Requirement: service-platform service owns one PostgreSQL schema and role
// — admin-panel's form: "admin-panel SHALL store no data of its own beyond
// configuration and SHALL need no schema". The scenarios Default schema
// name, Configured schema and host are used, and Access to a foreign schema
// is denied are not applicable to admin-panel.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pandops/flowai-admin-panel/internal/config"
)

// The configuration has no database section and the service links no
// database driver, migration tool or migrations directory.
func TestV0048AdminPanelOwnsNoDatabase(t *testing.T) {
	if _, err := config.Load(configFixture(t, nil)); err != nil {
		t.Fatalf("valid configuration: %v", err)
	}
	withDB := configFixture(t, func(d map[string]any) {
		d["db"] = map[string]any{"host": "pg", "port": 5432, "user": "admin_panel", "password": "x", "schema": "admin_panel_schema"}
	})
	if _, err := config.Load(withDB); err == nil {
		t.Fatal("a db section was accepted; admin-panel owns no schema")
	}
	for _, d := range []string{"migrations", "internal/migrations", "internal/store"} {
		if _, err := os.Stat(filepath.Join(serviceDir(), d)); err == nil {
			t.Fatalf("%s exists; admin-panel has no storage", d)
		}
	}
	cmd := exec.Command("go", "list", "-mod=readonly", "-deps", "./cmd/admin-panel")
	cmd.Dir = serviceDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "database/sql" || strings.HasPrefix(dep, "github.com/jackc/") || strings.HasPrefix(dep, "github.com/pressly/goose") || strings.HasPrefix(dep, "go.etcd.io/bbolt") {
			t.Fatalf("admin-panel links storage package %s", dep)
		}
	}
}
