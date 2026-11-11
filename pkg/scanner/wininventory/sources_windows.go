//go:build windows

package wininventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func discoverWindowsPackages(ctx context.Context) ([]SoftwarePackage, error) {
	packages, registryErr := discoverRegistryPackages()
	if registryErr != nil {
		return nil, registryErr
	}

	packages = append(packages, discoverAppxPackages(ctx)...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packages = append(packages, discoverPackageManagers(ctx)...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packages = append(packages, discoverGlobalLanguagePackages(ctx)...)
	executables, err := discoverExecutablePackages(ctx)
	if err != nil {
		return nil, err
	}
	packages = append(packages, executables...)
	return NormalizePackages(packages), nil
}

func discoverRegistryPackages() ([]SoftwarePackage, error) {
	var entries []RegistrySoftwareEntry
	paths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	hives := []struct {
		root registry.Key
		name string
	}{
		{registry.LOCAL_MACHINE, "machine"},
		{registry.CURRENT_USER, "user"},
	}
	views := []struct {
		access uint32
		name   string
	}{
		{registry.WOW64_64KEY, "64-bit"},
		{registry.WOW64_32KEY, "32-bit"},
	}

	var failures []error
	for _, hive := range hives {
		for _, view := range views {
			for _, path := range paths {
				key, err := registry.OpenKey(hive.root, path, registry.READ|view.access)
				if err != nil {
					if !errors.Is(err, registry.ErrNotExist) {
						failures = append(failures, fmt.Errorf("opening %s %s uninstall key: %w", hive.name, view.name, err))
					}
					continue
				}
				subkeys, err := key.ReadSubKeyNames(-1)
				_ = key.Close()
				if err != nil {
					failures = append(failures, fmt.Errorf("listing %s %s uninstall entries: %w", hive.name, view.name, err))
					continue
				}
				for _, subkey := range subkeys {
					appKey, err := registry.OpenKey(hive.root, path+`\`+subkey, registry.READ|view.access)
					if err != nil {
						continue
					}
					entry := RegistrySoftwareEntry{
						Name:            registryString(appKey, "DisplayName"),
						Identifier:      subkey,
						Version:         registryString(appKey, "DisplayVersion"),
						Vendor:          registryString(appKey, "Publisher"),
						InstallLocation: registryString(appKey, "InstallLocation"),
						InstallDate:     registryString(appKey, "InstallDate"),
						UninstallString: registryString(appKey, "UninstallString"),
						View:            hive.name + "-" + view.name,
					}
					_ = appKey.Close()
					if entry.Name != "" {
						entries = append(entries, entry)
					}
				}
			}
		}
	}
	if len(entries) == 0 && len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	return ParseRegistryEntries(entries), nil
}

func registryString(key registry.Key, name string) string {
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func discoverAppxPackages(ctx context.Context) []SoftwarePackage {
	script := `Get-AppxPackage -AllUsers | Select-Object Name,Version,Publisher,InstallLocation,PackageFullName | ConvertTo-Json -Compress`
	output, err := runPowerShell(ctx, script)
	if err != nil {
		slog.WarnContext(ctx, "unable to enumerate AppX/MSIX packages for all users; trying current user", "error", err)
		output, err = runPowerShell(ctx, `Get-AppxPackage | Select-Object Name,Version,Publisher,InstallLocation,PackageFullName | ConvertTo-Json -Compress`)
		if err != nil {
			slog.WarnContext(ctx, "unable to enumerate current-user AppX/MSIX packages", "error", err)
			return nil
		}
	}
	packages, err := ParseAppxJSON(output)
	if err != nil {
		slog.WarnContext(ctx, "unable to parse AppX/MSIX package inventory", "error", err)
		return nil
	}
	return packages
}

func discoverPackageManagers(ctx context.Context) []SoftwarePackage {
	var packages []SoftwarePackage
	if output, ok := runWingetExport(ctx); ok {
		parsed, err := ParsePackageManagerJSON(output, "winget")
		if err != nil {
			slog.WarnContext(ctx, "unable to parse winget export", "error", err)
		} else {
			packages = append(packages, parsed...)
		}
	}
	if output, ok := runOptionalCommand(ctx, "choco", "list", "--limit-output", "--no-color"); ok {
		packages = append(packages, ParseChocolateyList(output)...)
	}
	if output, ok := runOptionalCommand(ctx, "scoop", "export"); ok {
		parsed, err := ParsePackageManagerJSON(output, "scoop")
		if err != nil {
			slog.WarnContext(ctx, "unable to parse Scoop inventory", "error", err)
		} else {
			packages = append(packages, parsed...)
		}
	}
	return packages
}

func runWingetExport(ctx context.Context) ([]byte, bool) {
	path, err := exec.LookPath("winget")
	if err != nil {
		return nil, false
	}
	outputFile, err := os.CreateTemp("", "omniscan-winget-*.json")
	if err != nil {
		slog.WarnContext(ctx, "unable to create temporary winget export file", "error", err)
		return nil, false
	}
	outputPath := outputFile.Name()
	if err := outputFile.Close(); err != nil {
		_ = os.Remove(outputPath)
		slog.WarnContext(ctx, "unable to close temporary winget export file", "error", err)
		return nil, false
	}
	defer func() {
		if err := os.Remove(outputPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.WarnContext(ctx, "unable to remove temporary winget export file", "path", outputPath, "error", err)
		}
	}()

	command, args := executableCommand(path,
		"export",
		"--output", outputPath,
		"--include-versions",
		"--ignore-unavailable",
	)
	if output, err := exec.CommandContext(ctx, command, args...).CombinedOutput(); err != nil {
		slog.WarnContext(ctx, "winget export failed", "error", err, "output", strings.TrimSpace(string(output)))
		return nil, false
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		slog.WarnContext(ctx, "unable to read winget export file", "path", outputPath, "error", err)
		return nil, false
	}
	return data, true
}

func discoverGlobalLanguagePackages(ctx context.Context) []SoftwarePackage {
	var packages []SoftwarePackage
	if output, ok := runOptionalCommand(ctx, "npm", "ls", "--global", "--json", "--depth=0"); ok {
		parsed, err := ParsePackageManagerJSON(output, "npm-global")
		if err != nil {
			slog.WarnContext(ctx, "unable to parse global npm package inventory", "error", err)
		} else {
			packages = append(packages, parsed...)
		}
	}
	if output, ok := runOptionalCommand(ctx, "python", "-m", "pip", "list", "--format=json"); ok {
		parsed, err := ParsePackageManagerJSON(output, "pip-global")
		if err != nil {
			slog.WarnContext(ctx, "unable to parse global Python package inventory", "error", err)
		} else {
			packages = append(packages, parsed...)
		}
	}
	return packages
}

func discoverExecutablePackages(ctx context.Context) ([]SoftwarePackage, error) {
	var roots []string
	for _, name := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA"} {
		if value := os.Getenv(name); value != "" {
			roots = append(roots, value)
		}
	}

	if systemDrive := os.Getenv("SystemDrive"); systemDrive != "" {
		usersRoot := filepath.Join(systemDrive+`\`, "Users")
		if users, err := os.ReadDir(usersRoot); err == nil {
			for _, user := range users {
				if !user.IsDir() {
					continue
				}
				profile := filepath.Join(usersRoot, user.Name())
				roots = append(roots,
					filepath.Join(profile, "AppData", "Local", "Programs"),
					filepath.Join(profile, "AppData", "Roaming", "npm"),
					filepath.Join(profile, ".vscode", "extensions"),
					filepath.Join(profile, "scoop", "apps"),
					filepath.Join(profile, "AppData", "Local", "Microsoft", "WinGet", "Packages"),
				)
			}
		}
	}

	seen := make(map[string]struct{})
	var packages []SoftwarePackage
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				slog.WarnContext(ctx, "unable to inspect Windows application directory", "path", root, "error", err)
			}
			continue
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err != nil {
				slog.WarnContext(ctx, "unable to enumerate Windows executable path", "path", path, "error", err)
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			extension := strings.ToLower(filepath.Ext(entry.Name()))
			switch extension {
			case ".exe", ".com", ".cmd", ".bat", ".ps1":
			default:
				return nil
			}
			key := strings.ToLower(path)
			if _, ok := seen[key]; ok {
				return nil
			}
			seen[key] = struct{}{}
			packages = append(packages, executablePackage(path))
			return nil
		})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			slog.WarnContext(ctx, "Windows executable traversal was incomplete", "path", root, "error", err)
		}
	}
	return NormalizePackages(packages), nil
}

func runOptionalCommand(ctx context.Context, name string, args ...string) ([]byte, bool) {
	path, err := exec.LookPath(name)
	if err != nil {
		if !errors.Is(err, exec.ErrNotFound) {
			slog.WarnContext(ctx, "unable to locate optional Windows package source", "source", name, "error", err)
		}
		return nil, false
	}
	command, commandArgs := executableCommand(path, args...)
	output, err := exec.CommandContext(ctx, command, commandArgs...).CombinedOutput()
	if err != nil {
		slog.WarnContext(ctx, "optional Windows package source failed", "source", name, "error", err, "output", strings.TrimSpace(string(output)))
		return nil, false
	}
	return output, true
}

func executableCommand(path string, args ...string) (string, []string) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cmd", ".bat":
		return "cmd.exe", append([]string{"/C", path}, args...)
	default:
		return path, args
	}
}

func runPowerShell(ctx context.Context, script string) ([]byte, error) {
	for _, name := range []string{"pwsh.exe", "powershell.exe"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		output, err := exec.CommandContext(ctx, path, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
		}
		return output, nil
	}
	return nil, errors.New("PowerShell executable is not available")
}
