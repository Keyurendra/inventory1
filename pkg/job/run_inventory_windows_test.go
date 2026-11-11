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
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

type windowsInventoryScannerStub struct {
	finding scanner.Findings
	calls   int
}

func (s *windowsInventoryScannerStub) Scan(context.Context, string, string, string, string) (scanner.Findings, error) {
	s.calls++
	return s.finding, nil
}

func TestWindowsPackageInventoryPublishesPackagesAndAgentSignalsInOneTR(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "CODEX.EXE")
	if err := os.WriteFile(executable, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	extensionDir := filepath.Join(root, ".vscode", "extensions", "openai.chatgpt-1.0")
	if err := os.MkdirAll(extensionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	finding := &trivyScanner.Result{
		ArtifactType: "rootfs",
		Results: trivyTypes.Results{{Packages: types.Packages{{
			Name:    "@openai/codex",
			Version: "0.4.0",
		}}}},
	}
	inventoryScanner := &windowsInventoryScannerStub{finding: finding}
	catalog := &aiagent.Catalog{Agents: []aiagent.Agent{{
		ID:        "codex",
		Name:      "Codex",
		Platforms: []string{"windows"},
		Installations: []aiagent.Installation{{Signals: aiagent.Signals{
			Packages:    []string{"@openai/codex"},
			Executables: []string{"codex"},
			Paths:       []string{"**/.vscode/extensions/openai.chatgpt-*"},
		}}},
	}}}

	outputDir := t.TempDir()
	publisher := file.NewPublisher(outputDir)
	run := NewRun(RunConfig{
		PackageInventory:        true,
		AIAgentCatalog:          catalog,
		VulnScan:                true,
		ContainerVulnScan:       true,
		MalwareScan:             true,
		VulnScanDBDir:           filepath.Join(t.TempDir(), "no-vulnerability-database"),
		windowsInventoryScanner: inventoryScanner,
		aiAgentRoots:            []string{root},
	})
	_, err := run.ScanMountPoint(
		context.Background(),
		"windows",
		root,
		"vm://windows-inventory",
		"agent",
		func(ctx context.Context, finding scanner.Findings) error {
			return publisher.Publish(ctx, finding)
		},
	)
	if err != nil {
		t.Fatalf("ScanMountPoint() error = %v", err)
	}
	if inventoryScanner.calls != 1 {
		t.Fatalf("inventory scanner calls = %d, want one", inventoryScanner.calls)
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("reading published output: %v", err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "-TR.json") {
		t.Fatalf("published files = %v, want exactly one TR artifact", entries)
	}
	data, err := os.ReadFile(filepath.Join(outputDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("reading TR artifact: %v", err)
	}
	var report trivyScanner.Result
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decoding TR artifact: %v", err)
	}
	if report.AIAgentDetections == nil || len(*report.AIAgentDetections) != 1 {
		t.Fatalf("AI-agent detections missing from TR artifact: %+v", report.AIAgentDetections)
	}
	detectionTypes := make(map[string]bool)
	for _, detection := range (*report.AIAgentDetections)[0].Detections {
		detectionTypes[detection.Type] = true
	}
	for _, kind := range []string{"package", "executable", "path"} {
		if !detectionTypes[kind] {
			t.Errorf("missing %s detector signal: %+v", kind, (*report.AIAgentDetections)[0].Detections)
		}
	}
	if len(report.Results) != 1 || len(report.Results[0].Packages) != 1 ||
		report.Results[0].Packages[0].Name != "@openai/codex" {
		t.Fatalf("general package inventory was not retained: %+v", report.Results)
	}
}

func TestWindowsWithoutPackageInventoryDoesNotInvokeInventoryScanner(t *testing.T) {
	inventoryScanner := &windowsInventoryScannerStub{}
	run := NewRun(RunConfig{
		VulnScan:                true,
		OfflineWinVulnScan:      true,
		windowsInventoryScanner: inventoryScanner,
	})
	result, err := run.ScanMountPoint(
		context.Background(),
		"windows",
		t.TempDir(),
		"vm://normal-scan",
		"agent",
		func(context.Context, scanner.Findings) error { return nil },
	)
	if err != nil {
		t.Fatalf("ScanMountPoint() error = %v", err)
	}
	if inventoryScanner.calls != 0 {
		t.Fatalf("inventory scanner calls = %d without inventory flag, want zero", inventoryScanner.calls)
	}
	if result == nil || result.VulnScanError == nil {
		t.Fatal("normal Windows vulnerability scanner was not reached when package inventory was omitted")
	}
}
