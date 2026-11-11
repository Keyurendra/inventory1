package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAIAgentCatalogUsesLocalPathWhenProvided(t *testing.T) {
	dbDir := t.TempDir()
	defaultCatalogPath := filepath.Join(dbDir, "aiagent", "aiagentscan.json")
	if err := os.MkdirAll(filepath.Dir(defaultCatalogPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultCatalogPath, []byte(`{"version":1,"agents":[{"id":"db","name":"DB"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	localCatalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(localCatalogPath, []byte(`{"version":1,"agents":[{"id":"local","name":"Local"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	j := Job{opts: opts{
		vulnDBDirectory:    dbDir,
		aiAgentCatalogPath: localCatalogPath,
	}}
	catalog, err := j.loadAIAgentCatalog(context.Background())
	if err != nil {
		t.Fatalf("loadAIAgentCatalog() error = %v", err)
	}
	if len(catalog.Agents) != 1 || catalog.Agents[0].ID != "local" {
		t.Fatalf("loaded catalog = %+v, want local catalog", catalog)
	}
}

func TestLoadAIAgentCatalogUsesDatabaseCatalogWhenLocalPathOmitted(t *testing.T) {
	dbDir := t.TempDir()
	catalogPath := filepath.Join(dbDir, "aiagent", "aiagentscan.json")
	if err := os.MkdirAll(filepath.Dir(catalogPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, []byte(`{"version":1,"agents":[{"id":"db","name":"DB"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	j := Job{opts: opts{vulnDBDirectory: dbDir}}
	catalog, err := j.loadAIAgentCatalog(context.Background())
	if err != nil {
		t.Fatalf("loadAIAgentCatalog() error = %v", err)
	}
	if len(catalog.Agents) != 1 || catalog.Agents[0].ID != "db" {
		t.Fatalf("loaded catalog = %+v, want database catalog", catalog)
	}
}

func TestLoadAIAgentCatalogReportsInvalidExplicitPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	j := Job{opts: opts{aiAgentCatalogPath: path}}

	if catalog, err := j.loadAIAgentCatalog(context.Background()); err == nil {
		t.Fatalf("loadAIAgentCatalog() = (%v, nil), want an error", catalog)
	}
}

func TestPackageInventoryRequiresLocalAIAgentCatalog(t *testing.T) {
	rootfs := t.TempDir()
	for _, directory := range []string{"etc", "bin", "usr"} {
		if err := os.MkdirAll(filepath.Join(rootfs, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "os-release"), []byte("ID=ubuntu\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	j := Job{opts: opts{
		packageInventory: true,
		vulnDBDirectory:  filepath.Join(t.TempDir(), "missing-vuln-db"),
		logger:           slog.Default(),
	}}
	if _, err := j.scanMountPoint(context.Background(), rootfs, "vm://inventory"); err == nil {
		t.Fatal("scanMountPoint() error = nil, want local catalog requirement")
	}
}
