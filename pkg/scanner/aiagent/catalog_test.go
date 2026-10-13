package aiagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExtendedCatalogMetadataAppearsInAgentResult(t *testing.T) {
	const catalogJSON = `{
		"version": 1,
		"agents": [{
			"id": "codex-cli",
			"name": "Codex CLI",
			"description": "Local coding agent",
			"homepageUrl": "https://example.com/codex",
			"repositoryUrl": "https://example.com/codex/repo",
			"publishedAt": "2026-10-09",
			"version": "0.162.0",
			"language": "Rust",
			"license": "Apache-2.0",
			"category": "AI Agent",
			"platforms": ["windows"],
			"installations": [{"signals": {"packages": ["@openai/codex"]}}]
		}]
	}`
	path := filepath.Join(t.TempDir(), "aiagentscan.json")
	if err := os.WriteFile(path, []byte(catalogJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog, err := LoadCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	results := Detect(catalog, nil, []PackageSignal{{Name: "@openai/codex", Version: "0.161.0"}}, "windows")
	if len(results) != 1 {
		t.Fatalf("expected one agent result, got %+v", results)
	}
	result := results[0]
	if result.Description != "Local coding agent" ||
		result.HomepageURL != "https://example.com/codex" ||
		result.RepositoryURL != "https://example.com/codex/repo" ||
		result.PublishedAt != "2026-10-09" ||
		result.Version != "0.162.0" ||
		result.Language != "Rust" ||
		result.License != "Apache-2.0" {
		t.Fatalf("catalog metadata missing from result: %+v", result)
	}
	if len(result.Detections) != 1 || result.Detections[0].Version != "0.161.0" {
		t.Fatalf("installed package version was overwritten by catalog version: %+v", result.Detections)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"Description", "HomepageURL", "RepositoryURL", "PublishedAt", "Version", "Language", "License",
	} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing %s in JSON: %s", key, data)
		}
	}
}

func TestEmptyCatalogMetadataRemainsPresentInResult(t *testing.T) {
	catalog := &Catalog{Agents: []Agent{{
		ID: "claude-code", Name: "Claude Code", Platforms: []string{"linux"},
		Installations: []Installation{{Signals: Signals{Packages: []string{"@anthropic-ai/claude-code"}}}},
	}}}
	results := Detect(catalog, nil, []PackageSignal{{Name: "@anthropic-ai/claude-code"}}, "linux")
	if len(results) != 1 {
		t.Fatalf("expected one agent result, got %+v", results)
	}
	data, err := json.Marshal(results[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"Description", "HomepageURL", "RepositoryURL", "PublishedAt", "Version", "Language", "License",
	} {
		if got, exists := fields[key]; !exists || got != "" {
			t.Fatalf("expected %s to be present as an empty string, got %v in %s", key, got, data)
		}
	}
}
