package aiagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectWindowsPackageExecutableAndPath(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "CODEX.EXE")
	if err := os.WriteFile(executable, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, ".codex")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	catalog := &Catalog{Agents: []Agent{{
		ID:        "codex",
		Name:      "Codex",
		Version:   "2.0",
		Platforms: []string{"Windows"},
		Installations: []Installation{{Signals: Signals{
			Packages:    []string{"@openai/codex"},
			Executables: []string{"codex"},
			Paths:       []string{"**/.codex"},
		}}},
	}}}
	packages := []PackageSignal{{Name: "@openai/codex", Version: "1.0"}}

	results := Detect(catalog, []string{root}, packages, "windows")
	if len(results) != 1 || results[0].AgentID != "codex" {
		t.Fatalf("unexpected Windows detections: %+v", results)
	}
	detected := make(map[string]string)
	for _, detection := range results[0].Detections {
		detected[detection.Type] = detection.Value
		if detection.Type == "package" && detection.Version != "1.0" {
			t.Fatalf("catalog version replaced installed version: %+v", detection)
		}
	}
	want := map[string]string{
		"package":    "@openai/codex",
		"executable": executable,
		"path":       configDir,
	}
	for kind, value := range want {
		if detected[kind] != value {
			t.Fatalf("missing %s signal: %+v", kind, results[0].Detections)
		}
	}
	if got := Detect(catalog, []string{root}, packages, "linux"); len(got) != 0 {
		t.Fatalf("Windows-only catalog entry detected on Linux: %+v", got)
	}
	matches := matchesPathPattern(
		"C:\\Users\\Jane\\AppData\\Local\\Programs\\Cursor\\Resources",
		"**/appdata/local/programs/CURSOR/*",
		"windows",
	)
	if !matches {
		t.Fatal("Windows path matching ignored case or drive separators")
	}
}

func TestDetectLinuxExcludesContainerStorage(t *testing.T) {
	root := t.TempDir()
	hostBinary := filepath.Join(root, "root", ".local", "bin", "codex")
	containerBinary := filepath.Join(root, "var", "lib", "containerd", "snapshots", "8", "fs", "root", ".local", "bin", "codex")
	dockerBinary := filepath.Join(root, "var", "lib", "docker", "volumes", "codex-config", "_data", "bin", "codex")
	for _, executable := range []string{hostBinary, containerBinary, dockerBinary} {
		if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(executable, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	catalog := &Catalog{Agents: []Agent{{
		ID: "codex-cli", Platforms: []string{"linux"},
		Installations: []Installation{{Signals: Signals{Executables: []string{"codex"}}}},
	}}}
	results := Detect(catalog, []string{root}, nil, "linux")
	if len(results) != 1 || len(results[0].Detections) != 1 || results[0].Detections[0].Value != hostBinary {
		t.Fatalf("container storage was attributed to the host: %+v", results)
	}
}

func TestDetectMacOSSkipsShellFunctionsAndMountedVolumes(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		"usr/share/zsh/5.9/functions/zed",
		"System/Volumes/Data/usr/share/zsh/5.9/functions/zed",
		"Volumes/InternalDisk/usr/local/bin/zed",
		"System/Volumes/Data/Volumes/InternalDisk/usr/local/bin/zed",
		"Applications/Zed.app/Contents/MacOS/zed",
	}
	for _, path := range paths {
		fullPath := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	catalog := &Catalog{Agents: []Agent{{
		ID: "zed", Platforms: []string{"macos"},
		Installations: []Installation{{Signals: Signals{
			Executables: []string{"zed"},
			Paths:       []string{"**/zed.app/**"},
		}}},
	}}}
	results := Detect(catalog, []string{root}, nil, "macos")
	if len(results) != 1 || results[0].AgentID != "zed" {
		t.Fatalf("expected installed Zed app: %+v", results)
	}
	for _, detection := range results[0].Detections {
		shell := strings.Contains(detection.Value, "share/zsh")
		volume := strings.Contains(detection.Value, "Volumes/InternalDisk")
		if shell || volume {
			t.Fatalf("non-host file detected as Zed: %+v", detection)
		}
	}
	if len(results[0].Detections) < 2 {
		t.Fatalf("expected executable and case-insensitive app path: %+v", results[0].Detections)
	}
}
