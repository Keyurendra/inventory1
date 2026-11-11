package wininventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type RegistrySoftwareEntry struct {
	Name            string
	Identifier      string
	Version         string
	Vendor          string
	InstallLocation string
	InstallDate     string
	UninstallString string
	View            string
}

func ParseRegistryEntries(entries []RegistrySoftwareEntry) []SoftwarePackage {
	packages := make([]SoftwarePackage, 0, len(entries))
	for _, entry := range entries {
		packages = append(packages, SoftwarePackage{
			Name:            entry.Name,
			Version:         entry.Version,
			Vendor:          entry.Vendor,
			InstallLocation: entry.InstallLocation,
			InstallDate:     entry.InstallDate,
			UninstallString: entry.UninstallString,
			Source:          "windows-registry-" + normalizedSource(entry.View),
			Identifier:      firstNonEmpty(strings.TrimSpace(entry.Identifier), strings.TrimSpace(entry.Name)),
		})
	}
	return NormalizePackages(packages)
}

func ParseAppxJSON(data []byte) ([]SoftwarePackage, error) {
	packages, err := ParsePackageManagerJSON(data, "appx")
	if err != nil {
		return nil, fmt.Errorf("parsing AppX/MSIX package output: %w", err)
	}
	return packages, nil
}

func ParsePackageManagerJSON(data []byte, source string) ([]SoftwarePackage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	var packages []SoftwarePackage
	collectJSONPackages(raw, source, &packages)
	return NormalizePackages(packages), nil
}

func collectJSONPackages(value any, source string, packages *[]SoftwarePackage) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			collectJSONPackages(item, source, packages)
		}
	case map[string]any:
		name := firstString(typed, "Name", "name", "PackageIdentifier", "Id", "id", "PackageName")
		version := firstString(typed, "Version", "version", "DisplayVersion")
		_, hasDependencies := typed["dependencies"]
		if name != "" && (version != "" || !hasDependencies) {
			*packages = append(*packages, SoftwarePackage{
				Name:            name,
				Version:         version,
				Vendor:          firstString(typed, "Publisher", "publisher", "Vendor"),
				InstallLocation: firstString(typed, "InstallLocation", "InstallPath", "Path"),
				Source:          source,
				Identifier:      firstString(typed, "PackageFullName", "PackageIdentifier", "Id", "id", "Name", "name"),
			})
		}
		for key, child := range typed {
			if strings.EqualFold(key, "dependencies") {
				if dependencies, ok := child.(map[string]any); ok {
					for dependencyName, dependency := range dependencies {
						if metadata, ok := dependency.(map[string]any); ok {
							version := firstString(metadata, "Version", "version")
							*packages = append(*packages, SoftwarePackage{
								Name:       dependencyName,
								Version:    version,
								Source:     source,
								Identifier: dependencyName,
							})
						}
					}
				}
			}
			if strings.EqualFold(key, "Name") || strings.EqualFold(key, "Version") {
				continue
			}
			collectJSONPackages(child, source, packages)
		}
	}
}

func ParseChocolateyList(data []byte) []SoftwarePackage {
	var packages []SoftwarePackage
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "|", 2)
		if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
			continue
		}
		packages = append(packages, SoftwarePackage{
			Name:       strings.TrimSpace(fields[0]),
			Version:    strings.TrimSpace(fields[1]),
			Source:     "chocolatey",
			Identifier: strings.TrimSpace(fields[0]),
		})
	}
	return NormalizePackages(packages)
}

func executablePackage(path string) SoftwarePackage {
	return SoftwarePackage{
		Name:            strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		InstallLocation: filepath.Dir(path),
		Source:          "filesystem-executable",
		Identifier:      path,
		ExecutablePath:  path,
	}
}

func NormalizePackages(packages []SoftwarePackage) []SoftwarePackage {
	byKey := make(map[string]SoftwarePackage, len(packages))
	for _, pkg := range packages {
		pkg.Name = strings.TrimSpace(pkg.Name)
		pkg.Version = strings.TrimSpace(pkg.Version)
		pkg.Vendor = strings.TrimSpace(pkg.Vendor)
		pkg.InstallLocation = strings.TrimSpace(pkg.InstallLocation)
		pkg.Source = normalizedSource(pkg.Source)
		pkg.Identifier = strings.TrimSpace(pkg.Identifier)
		if pkg.Name == "" {
			continue
		}
		key := strings.ToLower(pkg.Name) + "\x00" + strings.ToLower(pkg.Version)
		location := strings.ToLower(strings.TrimRight(strings.ReplaceAll(pkg.InstallLocation, "/", `\`), `\`))
		existing, ok := byKey[key]
		if ok && location != "" && existing.InstallLocation != "" &&
			!strings.EqualFold(strings.TrimRight(strings.ReplaceAll(existing.InstallLocation, "/", `\`), `\`), location) {
			key += "\x00" + location
			existing, ok = byKey[key]
		}
		if !ok {
			if pkg.Identifier == "" {
				pkg.Identifier = pkg.Name
			}
			byKey[key] = pkg
			continue
		}
		existing.Vendor = firstNonEmpty(existing.Vendor, pkg.Vendor)
		existing.InstallLocation = firstNonEmpty(existing.InstallLocation, pkg.InstallLocation)
		existing.InstallDate = firstNonEmpty(existing.InstallDate, pkg.InstallDate)
		existing.UninstallString = firstNonEmpty(existing.UninstallString, pkg.UninstallString)
		existing.Identifier = mergeValue(existing.Identifier, pkg.Identifier)
		existing.Source = mergeValue(existing.Source, pkg.Source)
		byKey[key] = existing
	}

	result := make([]SoftwarePackage, 0, len(byKey))
	for _, pkg := range byKey {
		result = append(result, pkg)
	}
	sort.Slice(result, func(i, j int) bool {
		if !strings.EqualFold(result[i].Name, result[j].Name) {
			return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
		}
		if result[i].Version != result[j].Version {
			return result[i].Version < result[j].Version
		}
		return result[i].InstallLocation < result[j].InstallLocation
	})
	return result
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case json.Number:
			return typed.String()
		}
	}
	return ""
}

func normalizedSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	source = strings.ReplaceAll(source, " ", "-")
	if source == "" {
		return "unknown"
	}
	return source
}

func mergeValue(existing, incoming string) string {
	if incoming == "" || strings.EqualFold(existing, incoming) {
		return existing
	}
	if existing == "" {
		return incoming
	}
	return existing + "," + incoming
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
