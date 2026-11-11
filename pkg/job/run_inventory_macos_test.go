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

type macOSInventoryScannerStub struct {
	finding scanner.Findings
	calls   int
}

func (s *macOSInventoryScannerStub) Scan(context.Context, string, string, string, string) (scanner.Findings, error) {
	s.calls++
	return s.finding, nil
}

func TestMacOSPackageInventoryPublishesPackagesAndAgentDetectionsInOneTR(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "Applications", "Example.app", "Contents", "MacOS", "example-agent")
	if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	finding := &trivyScanner.Result{
		ArtifactType: "rootfs",
		Results: trivyTypes.Results{{Packages: types.Packages{{
			Name:           "Example Agent",
			Version:        "1.2.3",
			FilePath:       filepath.Join(root, "Applications", "Example.app"),
			InstalledFiles: []string{executable},
		}}}},
	}
	inventoryScanner := &macOSInventoryScannerStub{finding: finding}
	catalog := &aiagent.Catalog{Agents: []aiagent.Agent{{
		ID:        "example-agent",
		Name:      "Example Agent",
		Platforms: []string{"macos"},
		Installations: []aiagent.Installation{{Signals: aiagent.Signals{
			Packages:    []string{"Example Agent"},
			Executables: []string{"example-agent"},
			Paths:       []string{"**/Example.app/**"},
		}}},
	}}}

	outputDir := t.TempDir()
	publisher := file.NewPublisher(outputDir)
	run := NewRun(RunConfig{
		PackageInventory:      true,
		AIAgentCatalog:        catalog,
		VulnScan:              true,
		MalwareScan:           true,
		macOSInventoryScanner: inventoryScanner,
		aiAgentRoots:          []string{root},
	})
	_, err := run.ScanMountPoint(
		context.Background(),
		"macos",
		root,
		"vm://macos-inventory",
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
		report.Results[0].Packages[0].Name != "Example Agent" {
		t.Fatalf("general package inventory was not retained: %+v", report.Results)
	}
}
