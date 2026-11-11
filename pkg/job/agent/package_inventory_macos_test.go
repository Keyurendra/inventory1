package agent

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/accuknox/omniscan/pkg/publisher/file"
	trivyScanner "github.com/accuknox/omniscan/pkg/scanner/trivy"
)

func TestMacOSPackageInventoryJobLoadsLocalCatalogAndPublishesCombinedTR(t *testing.T) {
	rootfs := t.TempDir()
	appDir := filepath.Join(rootfs, "Applications", "Inventory Agent.app")
	writeMacInventoryFixture(t, filepath.Join(rootfs, "System", "Library", "CoreServices", "SystemVersion.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>ProductName</key><string>macOS</string>
<key>ProductVersion</key><string>15.0</string>
<key>ProductBuildVersion</key><string>24A1</string>
</dict></plist>`)
	writeMacInventoryFixture(t, filepath.Join(appDir, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Inventory Agent</string>
<key>CFBundleIdentifier</key><string>com.example.inventory-agent</string>
<key>CFBundleShortVersionString</key><string>3.2.1</string>
<key>CFBundleExecutable</key><string>inventory-agent</string>
</dict></plist>`)
	writeMacInventoryFixture(t, filepath.Join(appDir, "Contents", "MacOS", "inventory-agent"), "agent fixture")
	writeMacInventoryFixture(
		t,
		filepath.Join(rootfs, "Volumes", "External", "node_modules", "external-only", "package.json"),
		`{"name":"external-only","version":"9.9.9"}`,
	)

	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`{
		"version": 1,
		"agents": [{
			"id": "inventory-agent",
			"name": "Inventory Agent",
			"platforms": ["macos"],
			"installations": [{
				"signals": {
					"packages": ["Inventory Agent"],
					"executables": ["inventory-agent"],
					"paths": ["**/Inventory Agent.app/**"]
				}
			}]
		}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	outputDir := t.TempDir()
	vulnDBDir := filepath.Join(t.TempDir(), "missing-vulnerability-database")
	publisher := file.NewPublisher(outputDir)
	scanJob, err := NewJob(
		publisher,
		WithPackageInventory(),
		WithAIAgentCatalogPath(catalogPath),
		WithVulnDBDirectory(vulnDBDir),
		WithOverrideHostname("mac-inventory-test"),
		WithVMURIPrefix("vm://"),
	)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := scanJob.Run(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("running macOS inventory job: %v", err)
	}
	if result := summary["mac-inventory-test"]; result.OS != "macos" ||
		result.OrchestrationError != nil || result.ArtifactAPIError != nil ||
		result.VulnScanError != nil || result.MalwareScanError != nil {
		t.Fatalf("agent job summary = %+v, want successful macOS inventory", result)
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "-TR.json") {
		t.Fatalf("published files = %v, want exactly one TR artifact", entries)
	}
	data, err := os.ReadFile(filepath.Join(outputDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var report trivyScanner.Result
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.AIAgentDetections == nil || len(*report.AIAgentDetections) != 1 ||
		(*report.AIAgentDetections)[0].AgentID != "inventory-agent" {
		t.Fatalf("local catalog detection missing from TR artifact: %+v", report.AIAgentDetections)
	}
	detectionTypes := make(map[string]bool)
	for _, detection := range (*report.AIAgentDetections)[0].Detections {
		detectionTypes[detection.Type] = true
	}
	for _, kind := range []string{"package", "executable", "path"} {
		if !detectionTypes[kind] {
			t.Errorf("missing %s detection: %+v", kind, (*report.AIAgentDetections)[0].Detections)
		}
	}
	var appPackageFound bool
	var mountedVolumePackageFound bool
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			if pkg.Name == "Inventory Agent" && pkg.Version == "3.2.1" {
				appPackageFound = true
			}
			if pkg.Name == "external-only" {
				mountedVolumePackageFound = true
			}
		}
	}
	if !appPackageFound {
		t.Fatal("TR artifact does not contain the general macOS application package")
	}
	if mountedVolumePackageFound {
		t.Fatal("TR artifact unexpectedly included a package from a mounted volume")
	}
	for _, dbDir := range []string{"db", "java-db"} {
		if _, err := os.Stat(filepath.Join(vulnDBDir, dbDir)); !os.IsNotExist(err) {
			t.Errorf("inventory unexpectedly initialized %s: %v", dbDir, err)
		}
	}
}

func writeMacInventoryFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatalf("writing fixture file %q: %v", path, err)
	}
}
