//go:build linux

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

func TestPackageInventoryJobLoadsLocalCatalogAndPublishesTR(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "bin"), 0o755); err != nil {
		t.Fatalf("creating fixture directory: %v", err)
	}
	files := map[string]string{
		"etc/os-release": "ID=ubuntu\nVERSION_ID=22.04\n",
		"var/lib/dpkg/status": "Package: inventory-job-test-os\n" +
			"Status: install ok installed\n" +
			"Version: 1.2.3\n" +
			"Architecture: amd64\n" +
			"Description: package inventory job test fixture\n\n",
		"usr/local/lib/node_modules/inventory-job-test-lib/package.json": `{"name":"inventory-job-test-lib","version":"4.5.6"}`,
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

	localCatalogPath := filepath.Join(t.TempDir(), "catalog.json")
	catalog := `{"version":1,"agents":[{"id":"inventory-job-test-agent","name":"Inventory Job Test Agent","platforms":["linux"],"installations":[{"signals":{"packages":["inventory-job-test-lib"]}}]}]}`
	if err := os.WriteFile(localCatalogPath, []byte(catalog), 0o600); err != nil {
		t.Fatalf("writing local catalog: %v", err)
	}

	outputDir := t.TempDir()
	vulnDBDir := filepath.Join(t.TempDir(), "missing-vulnerability-database")
	publisher := file.NewPublisher(outputDir)
	scanJob, err := NewJob(
		publisher,
		WithPackageInventory(),
		WithAIAgentCatalogPath(localCatalogPath),
		WithVulnDBDirectory(vulnDBDir),
		WithOverrideHostname("inventory-job-test"),
		WithVMURIPrefix("vm://"),
	)
	if err != nil {
		t.Fatalf("creating agent job: %v", err)
	}

	summary, err := scanJob.Run(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("running agent job: %v", err)
	}
	if result := summary["inventory-job-test"]; result.OS != "linux" ||
		result.OrchestrationError != nil || result.ArtifactAPIError != nil ||
		result.VulnScanError != nil || result.MalwareScanError != nil {
		t.Fatalf("agent job summary = %+v, want successful Linux inventory", result)
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
		(*report.AIAgentDetections)[0].AgentID != "inventory-job-test-agent" {
		t.Fatalf("AI-agent detections = %+v, want inventory-job-test-agent", *report.AIAgentDetections)
	}

	var packageFound bool
	for _, result := range report.Results {
		if len(result.Vulnerabilities) > 0 {
			t.Fatalf("inventory result %q contains vulnerability findings", result.Target)
		}
		for _, pkg := range result.Packages {
			if pkg.Name == "inventory-job-test-lib" && pkg.Version == "4.5.6" {
				packageFound = true
			}
		}
	}
	if !packageFound {
		t.Fatal("published TR artifact does not contain the fixture package")
	}

	if _, err := os.Stat(filepath.Join(vulnDBDir, "trivy.db")); !os.IsNotExist(err) {
		t.Fatalf("vulnerability database unexpectedly exists or could not be checked: %v", err)
	}
}
