package winfs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	wintypes "github.com/accuknox/accuknox-windows-scanner/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/accuknox/omniscan/pkg/scanner/trivy"
	"github.com/accuknox/omniscan/pkg/scanner/winvuln"
)

type updateCase struct {
	kind string
	kb   string
}

func TestCollectCombinesMSRCAndTwoDrives(t *testing.T) {
	windows := &winvuln.Result{ScanResult: &wintypes.ScanResult{
		WindowsVersion: "10.0",
		MissingSoftwareUpdates: []wintypes.MissingSoftwareUpdate{{
			Name: "Example", Version: "1.0", KB: "KB123", CVEs: []wintypes.CVE{{ID: "CVE-2026-1", Severity: "high", CVSS: 7.5}},
		}},
		MissingKBs: []string{"KB456", "KB789"},
		MissingKBDetails: []wintypes.MissingKB{
			{KB: "KB456", CVEs: []wintypes.CVE{{ID: "CVE-2026-2"}}},
			{KB: "KB789"},
		},
	}}
	s := Scanner{
		listDrives: func() ([]string, error) { return []string{`C:\`, `D:\`}, nil },
		scanDrive: func(_ context.Context, drive, _ string) (types.Report, error) {
			return types.Report{Results: types.Results{{Target: "path/package-lock.json", Class: types.ClassLangPkg}}}, nil
		},
	}
	result, err := s.Collect(context.Background(), "vm://one", "aws", windows)
	if err != nil {
		t.Fatal(err)
	}
	if result.DataType() != "TR" || result.ArtifactName != "vm://one" || result.Metadata.Windows == nil || result.Metadata.Windows.WindowsVersion != "10.0" {
		t.Fatalf("combined artifact metadata lost: %+v", result)
	}
	if len(result.Metadata.Windows.MissingKBs) != 0 || len(result.Metadata.Windows.MissingKBDetails) != 0 {
		t.Fatalf("missing KB lists leaked into metadata: %+v", result.Metadata.Windows)
	}
	if len(windows.MissingKBs) != 2 || len(windows.MissingKBDetails) != 2 {
		t.Fatalf("source Windows scan was modified: %+v", windows.ScanResult)
	}
	if len(result.Results) != 4 {
		t.Fatalf("got %d results, want 4", len(result.Results))
	}
	if result.Results[0].Target != "Example@1.0" || string(result.Results[0].Type) != "windows-msrc" || result.Results[1].Target != "Windows Security Update (KB456)" {
		t.Fatalf("MSRC locations changed: %+v", result.Results[:2])
	}
	msrc := result.Results[0].Vulnerabilities[0]
	if msrc.PkgName != "Example" || msrc.InstalledVersion != "1.0" || msrc.FixedVersion != "KB123" || msrc.VulnerabilityID != "CVE-2026-1" {
		t.Fatalf("MSRC package identity changed: %+v", msrc)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"missingKBs"`) || strings.Contains(string(data), `"missingKBDetails"`) {
		t.Fatalf("combined artifact still contains missing KB metadata: %s", data)
	}
	var serialized trivy.Result
	if err := json.Unmarshal(data, &serialized); err != nil {
		t.Fatal(err)
	}
	wants := []updateCase{
		{kind: "software", kb: "KB123"},
		{kind: "kb", kb: "KB456"},
	}
	for i, want := range wants {
		custom, ok := serialized.Results[i].Vulnerabilities[0].Custom.(map[string]any)
		if !ok {
			t.Fatalf("MSRC result %d has invalid Custom metadata", i)
		}
		if custom["updateKind"] != want.kind || custom["kb"] != want.kb {
			t.Errorf("MSRC result %d serialized Custom = %v", i, custom)
		}
	}
	for i, drive := range []string{"C", "D"} {
		if got := result.Results[i+2].Target; got != drive+`:\path\package-lock.json` {
			t.Errorf("drive %s target = %q", drive, got)
		}
	}
}

func TestCollectFailureDiscardsAllResults(t *testing.T) {
	s := Scanner{
		listDrives: func() ([]string, error) { return []string{`C:\`, `D:\`}, nil },
		scanDrive: func(_ context.Context, drive, _ string) (types.Report, error) {
			if strings.HasPrefix(drive, "D") {
				return types.Report{}, errors.New("unreadable")
			}
			return types.Report{Results: types.Results{{Target: "one"}}}, nil
		},
	}
	result, err := s.Collect(context.Background(), "vm://one", "aws", &winvuln.Result{ScanResult: &wintypes.ScanResult{}})
	if result != nil || err == nil || !strings.Contains(err.Error(), "drive D:") {
		t.Fatalf("result=%v err=%v", result, err)
	}
}

func TestCollectEmptyScanStillProducesArtifact(t *testing.T) {
	s := Scanner{
		listDrives: func() ([]string, error) { return []string{`C:\`}, nil },
		scanDrive:  func(context.Context, string, string) (types.Report, error) { return types.Report{}, nil },
	}
	result, err := s.Collect(context.Background(), "vm://one", "aws", &winvuln.Result{ScanResult: &wintypes.ScanResult{}})
	if err != nil || result == nil || len(result.Results) != 0 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	data, err := json.Marshal(result)
	if err != nil || !strings.Contains(string(data), `"Windows":{}`) {
		t.Fatalf("empty successful scan lost Windows marker: %s, %v", data, err)
	}
}
