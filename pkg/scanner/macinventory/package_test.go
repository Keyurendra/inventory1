package macinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/accuknox/omniscan/pkg/scanner"
	trivyScanner "github.com/accuknox/omniscan/pkg/scanner/trivy"
)

func TestScannerCollectsMacOSApplicationsReceiptsAndPackageDirectories(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "Applications", "Example.app")
	writeInventoryFile(t, filepath.Join(appDir, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Example</string>
<key>CFBundleIdentifier</key><string>com.example.desktop</string>
<key>CFBundleShortVersionString</key><string>2.3.4</string>
<key>CFBundleExecutable</key><string>example</string>
</dict></plist>`)
	writeInventoryFile(t, filepath.Join(appDir, "Contents", "MacOS", "example"), "")

	receipt := filepath.Join(root, "var", "db", "receipts", "com.example.tool.plist")
	writeInventoryFile(t, receipt, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PackageIdentifier</key><string>com.example.tool</string>
<key>PackageVersion</key><string>1.5</string>
<key>InstallPrefixPath</key><string>/usr/local</string>
</dict></plist>`)

	formula := filepath.Join(root, "opt", "homebrew", "Cellar", "example-formula", "1.0")
	cask := filepath.Join(root, "usr", "local", "Caskroom", "example-cask", "4.0")
	macport := filepath.Join(root, "opt", "local", "var", "macports", "software", "example-port", "2.0_1")
	for _, path := range []string{formula, cask, macport} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("creating package directory %q: %v", path, err)
		}
	}

	s := NewScanner()
	s.scanRoot = func(context.Context, string, string, string, string, string) (scanner.Findings, error) {
		return &trivyScanner.Result{
			ArtifactType: "rootfs",
			Results: trivyTypes.Results{{Target: "manifest.json", Packages: ftypes.Packages{{
				Name: "manifest-package",
			}}}},
		}, nil
	}
	finding, err := s.Scan(context.Background(), root, "vm://macos-inventory", "agent", "macos")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	report := finding.(*trivyScanner.Result)
	var found = map[string]bool{"manifest-package": false}
	for _, result := range report.Results {
		if len(result.Vulnerabilities) != 0 {
			t.Fatalf("inventory result %q contains vulnerability data", result.Target)
		}
		for _, pkg := range result.Packages {
			found[pkg.Name] = true
			if pkg.Name == "Example" {
				if pkg.Version != "2.3.4" || pkg.FilePath != appDir ||
					len(pkg.InstalledFiles) != 1 ||
					pkg.InstalledFiles[0] != filepath.Join(appDir, "Contents", "MacOS", "example") {
					t.Errorf("unexpected app bundle package metadata: %+v", pkg)
				}
			}
			if pkg.Name == "com.example.tool" &&
				(pkg.Version != "1.5" || pkg.FilePath != filepath.Join(root, "usr", "local")) {
				t.Errorf("unexpected installer receipt metadata: %+v", pkg)
			}
		}
	}
	for _, name := range []string{"manifest-package", "Example", "com.example.tool", "example-formula", "example-cask", "example-port"} {
		if !found[name] {
			t.Errorf("inventory package %q was not collected", name)
		}
	}
}

func writeInventoryFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatalf("writing fixture file %q: %v", path, err)
	}
}
