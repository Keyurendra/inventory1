//go:build linux

package job

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/accuknox/omniscan/pkg/publisher/file"
	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/aiagent"
	trivyScanner "github.com/accuknox/omniscan/pkg/scanner/trivy"
)

func TestLinuxPackageInventoryPublishesPackagesAndAIAgentsInOneTR(t *testing.T) {
	rootfs := t.TempDir()
	files := map[string]string{
		"etc/os-release": "ID=ubuntu\nVERSION_ID=22.04\n",
		"var/lib/dpkg/status": "Package: inventory-test-os\n" +
			"Status: install ok installed\n" +
			"Version: 1.2.3\n" +
			"Architecture: amd64\n" +
			"Description: package inventory test fixture\n\n",
		"usr/local/lib/node_modules/inventory-test-lib/package.json": `{"name":"inventory-test-lib","version":"4.5.6"}`,
	}
	for name, contents := range files {
		path := filepath.Join(rootfs, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("writing fixture file %q: %v", name, err)
		}
	}

	catalog := &aiagent.Catalog{Agents: []aiagent.Agent{{
		ID:        "inventory-test-agent",
		Name:      "Inventory Test Agent",
		Platforms: []string{"linux"},
		Installations: []aiagent.Installation{{Signals: aiagent.Signals{
			Packages: []string{"inventory-test-lib"},
		}}},
	}}}

	outputDir := t.TempDir()
	publisher := file.NewPublisher(outputDir)
	run := NewRun(RunConfig{
		PackageInventory:  true,
		AIAgentCatalog:    catalog,
		VulnScan:          true,
		ContainerVulnScan: true,
		MalwareScan:       true,
		VulnScanDBDir:     filepath.Join(t.TempDir(), "no-vulnerability-database"),
	})
	_, err := run.ScanMountPoint(
		context.Background(),
		"linux",
		rootfs,
		"vm://inventory-test",
		"agent",
		func(ctx context.Context, finding scanner.Findings) error {
			return publisher.Publish(ctx, finding)
		},
	)
	if err != nil {
		t.Fatalf("ScanMountPoint() error = %v", err)
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("reading published output: %v", err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "-TR.json") {
		t.Fatalf("published files = %v, want exactly one TR JSON artifact", entries)
	}
	data, err := os.ReadFile(filepath.Join(outputDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("reading published TR artifact: %v", err)
	}
	var report trivyScanner.Result
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decoding published TR artifact: %v", err)
	}
	if report.DataType() != "TR" || report.AIAgentDetections == nil {
		t.Fatalf("published finding = %+v, want TR with AI-agent detections", report)
	}
	if len(*report.AIAgentDetections) != 1 ||
		(*report.AIAgentDetections)[0].AgentID != "inventory-test-agent" {
		t.Fatalf("AI-agent detections = %+v, want inventory-test-agent", *report.AIAgentDetections)
	}

	var osPackageFound, libraryPackageFound bool
	for _, result := range report.Results {
		if len(result.Vulnerabilities) > 0 {
			t.Fatalf("inventory result %q contains vulnerability findings", result.Target)
		}
		for _, pkg := range result.Packages {
			switch pkg.Name {
			case "inventory-test-os":
				osPackageFound = pkg.Version == "1.2.3"
			case "inventory-test-lib":
				libraryPackageFound = pkg.Version == "4.5.6"
			}
		}
	}
	if !osPackageFound || !libraryPackageFound {
		t.Fatalf("package inventory missing fixture packages: OS=%t library=%t", osPackageFound, libraryPackageFound)
	}
}

func TestPackageInventoryRejectsNonLinuxWithoutPublishing(t *testing.T) {
	run := NewRun(RunConfig{PackageInventory: true})
	if _, err := run.ScanMountPoint(
		context.Background(),
		"windows",
		t.TempDir(),
		"vm://unsupported",
		"agent",
		func(context.Context, scanner.Findings) error {
			t.Fatal("publisher called for unsupported inventory platform")
			return nil
		},
	); err == nil {
		t.Fatal("ScanMountPoint() error = nil, want unsupported platform error")
	}
}
