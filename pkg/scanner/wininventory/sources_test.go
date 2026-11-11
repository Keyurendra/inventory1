package wininventory

import (
	"strings"
	"testing"
)

func TestParseRegistryEntriesIncludesBothViewsAndMetadata(t *testing.T) {
	packages := ParseRegistryEntries([]RegistrySoftwareEntry{
		{
			Name:            "Example IDE",
			Version:         "1.2.3",
			Vendor:          "Example Corp",
			InstallLocation: `C:\Program Files\Example IDE`,
			InstallDate:     "20261001",
			View:            "machine-64-bit",
		},
		{
			Name:            "Example IDE",
			Version:         "1.2.3",
			Vendor:          "Example Corp",
			InstallLocation: `C:\Program Files\Example IDE`,
			View:            "machine-32-bit",
		},
	})
	if len(packages) != 1 {
		t.Fatalf("got %d packages, want one deduplicated entry: %+v", len(packages), packages)
	}
	pkg := packages[0]
	if pkg.Name != "Example IDE" || pkg.Version != "1.2.3" ||
		pkg.Vendor != "Example Corp" || pkg.InstallDate != "20261001" {
		t.Fatalf("registry metadata was not preserved: %+v", pkg)
	}
	if !strings.Contains(pkg.Source, "machine-64-bit") || !strings.Contains(pkg.Source, "machine-32-bit") {
		t.Fatalf("registry views were not retained: %+v", pkg)
	}
}

func TestParseAppxMSIXAndPackageManagerOutput(t *testing.T) {
	appx, err := ParseAppxJSON([]byte(`[
		{"Name":"Microsoft.Example","Version":"2.3.4.0","Publisher":"CN=Example","InstallLocation":"C:\\Program Files\\WindowsApps\\Example","PackageFullName":"Microsoft.Example_2.3.4.0_x64"}
	]`))
	if err != nil {
		t.Fatalf("ParseAppxJSON() error = %v", err)
	}
	if len(appx) != 1 || appx[0].Name != "Microsoft.Example" || appx[0].Vendor != "CN=Example" ||
		appx[0].InstallLocation != `C:\Program Files\WindowsApps\Example` {
		t.Fatalf("unexpected AppX/MSIX result: %+v", appx)
	}

	winget, err := ParsePackageManagerJSON([]byte(`{
		"Sources":[{"Packages":[{"PackageIdentifier":"OpenAI.Codex","Version":"1.0.0"}]}]
	}`), "winget")
	if err != nil {
		t.Fatalf("ParsePackageManagerJSON(winget) error = %v", err)
	}
	if len(winget) != 1 || winget[0].Name != "OpenAI.Codex" || winget[0].Source != "winget" {
		t.Fatalf("unexpected winget result: %+v", winget)
	}

	chocolatey := ParseChocolateyList([]byte("git|2.45.0\nchocolatey|2.3.0\nnot an entry\n"))
	if len(chocolatey) != 2 || chocolatey[0].Name != "chocolatey" || chocolatey[1].Name != "git" {
		t.Fatalf("unexpected Chocolatey result: %+v", chocolatey)
	}

	scoop, err := ParsePackageManagerJSON([]byte(`{
		"apps":[{"Name":"go","Version":"1.24.0","Source":"main"}]
	}`), "scoop")
	if err != nil {
		t.Fatalf("ParsePackageManagerJSON(scoop) error = %v", err)
	}
	if len(scoop) != 1 || scoop[0].Name != "go" || scoop[0].Version != "1.24.0" {
		t.Fatalf("unexpected Scoop result: %+v", scoop)
	}
}

func TestParseGlobalLanguagePackageOutput(t *testing.T) {
	npm, err := ParsePackageManagerJSON([]byte(`{
		"name":"global","dependencies":{"@openai/codex":{"version":"0.1.0"}}
	}`), "npm-global")
	if err != nil {
		t.Fatalf("ParsePackageManagerJSON(npm) error = %v", err)
	}
	if len(npm) != 1 || npm[0].Name != "@openai/codex" || npm[0].Version != "0.1.0" {
		t.Fatalf("unexpected npm package result: %+v", npm)
	}

	python, err := ParsePackageManagerJSON([]byte(`[{"name":"transformers","version":"4.50.0"}]`), "pip-global")
	if err != nil {
		t.Fatalf("ParsePackageManagerJSON(pip) error = %v", err)
	}
	if len(python) != 1 || python[0].Name != "transformers" || python[0].Version != "4.50.0" {
		t.Fatalf("unexpected Python package result: %+v", python)
	}
}

func TestNormalizePackagesMergesDuplicateMetadata(t *testing.T) {
	packages := NormalizePackages([]SoftwarePackage{
		{Name: "Example", Version: "1.0", Source: "winget", Identifier: "Example.ID"},
		{Name: " example ", Version: "1.0", Vendor: "Vendor", InstallLocation: `C:\Apps\Example`, Source: "registry-64-bit"},
		{Name: "", Source: "invalid"},
	})
	if len(packages) != 1 {
		t.Fatalf("got %d normalized packages, want one: %+v", len(packages), packages)
	}
	pkg := packages[0]
	if pkg.Vendor != "Vendor" || pkg.InstallLocation != `C:\Apps\Example` ||
		!strings.Contains(pkg.Source, "winget") || !strings.Contains(pkg.Source, "registry-64-bit") {
		t.Fatalf("duplicate metadata was not merged: %+v", pkg)
	}
}
