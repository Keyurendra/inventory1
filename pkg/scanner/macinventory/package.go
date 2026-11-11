package macinventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
	"howett.net/plist"

	"github.com/accuknox/omniscan/pkg/scanner"
	trivyScanner "github.com/accuknox/omniscan/pkg/scanner/trivy"
	"github.com/accuknox/omniscan/pkg/scanner/trivy/rootfs"
)

type SoftwarePackage struct {
	Name            string
	Version         string
	Vendor          string
	InstallLocation string
	Source          string
	Identifier      string
	ExecutablePath  string
}

type scanRootFunc func(context.Context, string, string, string, string, string) (scanner.Findings, error)
type discoverPackagesFunc func(context.Context, string) ([]SoftwarePackage, error)

type Scanner struct {
	cacheDir         string
	scanRoot         scanRootFunc
	discoverPackages discoverPackagesFunc
}

type OptFunc func(*Scanner)

func WithCacheDirectory(path string) OptFunc {
	return func(s *Scanner) {
		s.cacheDir = path
	}
}

func NewScanner(opts ...OptFunc) *Scanner {
	s := &Scanner{
		scanRoot:         scanTrivyRoot,
		discoverPackages: discoverFilesystemPackages,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Scan(ctx context.Context, mount, vmURI, platform, osType string) (scanner.Findings, error) {
	if osType != "macos" {
		return nil, fmt.Errorf("macOS package inventory cannot scan %q", osType)
	}
	finding, err := s.scanRoot(ctx, mount, vmURI, platform, osType, s.cacheDir)
	if err != nil {
		return nil, fmt.Errorf("scanning macOS filesystem for package inventory: %w", err)
	}
	result, ok := finding.(*trivyScanner.Result)
	if !ok {
		return nil, fmt.Errorf("unexpected package inventory result %T", finding)
	}
	packages, err := s.discoverPackages(ctx, mount)
	if err != nil {
		return nil, fmt.Errorf("discovering macOS installed software: %w", err)
	}
	if len(packages) == 0 {
		return result, nil
	}

	inventoryPackages := make(ftypes.Packages, 0, len(packages))
	for _, item := range normalizePackages(packages) {
		pkg := ftypes.Package{
			Name:       item.Name,
			Version:    item.Version,
			Maintainer: item.Vendor,
			FilePath:   item.InstallLocation,
			AnalyzedBy: ftypes.AnalyzerType(item.Source),
			ID:         item.Source + ":" + item.Identifier + "@" + item.Version,
			Identifier: ftypes.PkgIdentifier{
				PURL: packageurl.NewPackageURL(
					packageurl.TypeGeneric,
					"macos",
					item.Name,
					item.Version,
					packageurl.Qualifiers{{Key: "source", Value: item.Source}},
					"",
				),
			},
		}
		if item.ExecutablePath != "" {
			pkg.InstalledFiles = []string{item.ExecutablePath}
		}
		inventoryPackages = append(inventoryPackages, pkg)
	}
	result.Results = append(result.Results, types.Result{
		Target:   "macOS installed software",
		Class:    types.ClassOSPkg,
		Type:     ftypes.TargetType("macos-software"),
		Packages: inventoryPackages,
	})
	return result, nil
}

func scanTrivyRoot(ctx context.Context, mount, vmURI, platform, osType, cacheDir string) (scanner.Findings, error) {
	opts := []rootfs.OptFunc{
		rootfs.WithPackageInventory(),
		rootfs.WithSkipDirectories(
			filepath.Join(mount, "Volumes"),
			filepath.Join(mount, "System", "Volumes", "Data", "Volumes"),
		),
	}
	if cacheDir != "" {
		opts = append(opts, rootfs.WithCacheDirectory(cacheDir))
	}
	s, err := rootfs.NewScanner(opts...)
	if err != nil {
		return nil, err
	}
	return s.Scan(ctx, mount, vmURI, platform, osType)
}

func discoverFilesystemPackages(ctx context.Context, root string) ([]SoftwarePackage, error) {
	type inventoryRoot struct {
		path   string
		source string
	}
	var packages []SoftwarePackage
	roots := []inventoryRoot{
		{filepath.Join(root, "Applications"), "macos-app"},
		{filepath.Join(root, "System", "Applications"), "macos-app"},
		{filepath.Join(root, "System", "Library", "CoreServices", "Applications"), "macos-app"},
		{filepath.Join(root, "opt", "homebrew", "Cellar"), "homebrew-formula"},
		{filepath.Join(root, "opt", "homebrew", "Caskroom"), "homebrew-cask"},
		{filepath.Join(root, "usr", "local", "Cellar"), "homebrew-formula"},
		{filepath.Join(root, "usr", "local", "Caskroom"), "homebrew-cask"},
		{filepath.Join(root, "opt", "local", "var", "macports", "software"), "macports"},
		{filepath.Join(root, "var", "db", "receipts"), "apple-installer-receipt"},
	}
	usersRoot := filepath.Join(root, "Users")
	users, err := os.ReadDir(usersRoot)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.WarnContext(ctx, "unable to enumerate macOS user profiles", "path", usersRoot, "error", err)
	}
	for _, user := range users {
		if user.IsDir() {
			profile := filepath.Join(usersRoot, user.Name())
			roots = append(roots,
				inventoryRoot{filepath.Join(profile, "Applications"), "macos-app"},
				inventoryRoot{filepath.Join(profile, ".homebrew", "Cellar"), "homebrew-formula"},
				inventoryRoot{filepath.Join(profile, ".homebrew", "Caskroom"), "homebrew-cask"},
				inventoryRoot{filepath.Join(profile, "homebrew", "Cellar"), "homebrew-formula"})
		}
	}

	for _, sourceRoot := range roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Stat(sourceRoot.path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				slog.WarnContext(ctx, "unable to inspect macOS inventory source", "path", sourceRoot.path, "error", err)
			}
			continue
		}
		if !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(sourceRoot.path, func(path string, entry fs.DirEntry, walkErr error) error {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if walkErr != nil {
				slog.WarnContext(ctx, "unable to enumerate macOS inventory source", "path", path, "error", walkErr)
				return nil
			}
			if sourceRoot.source == "macos-app" && strings.HasSuffix(strings.ToLower(entry.Name()), ".app") {
				if pkg, ok := readAppBundle(path); ok {
					packages = append(packages, pkg)
				}
				if entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if sourceRoot.source == "apple-installer-receipt" && strings.HasSuffix(strings.ToLower(entry.Name()), ".plist") {
				if pkg, ok := readInstallerReceipt(path, root); ok {
					packages = append(packages, pkg)
				}
				return nil
			}
			if sourceRoot.source == "homebrew-formula" || sourceRoot.source == "homebrew-cask" || sourceRoot.source == "macports" {
				relative, err := filepath.Rel(sourceRoot.path, path)
				if err != nil {
					return nil
				}
				if entry.IsDir() && len(strings.Split(relative, string(filepath.Separator))) == 2 {
					if pkg, ok := readVersionedPackage(path, sourceRoot.source); ok {
						packages = append(packages, pkg)
					}
				}
			}
			return nil
		})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			slog.WarnContext(ctx, "macOS inventory traversal was incomplete", "path", sourceRoot.path, "error", err)
		}
	}
	return normalizePackages(packages), nil
}

func readAppBundle(path string) (SoftwarePackage, bool) {
	data, err := os.ReadFile(filepath.Join(path, "Contents", "Info.plist"))
	if err != nil {
		return SoftwarePackage{}, false
	}
	var metadata map[string]any
	if _, err := plist.Unmarshal(data, &metadata); err != nil {
		return SoftwarePackage{}, false
	}
	name := plistString(metadata, "CFBundleDisplayName", "CFBundleName")
	identifier := plistString(metadata, "CFBundleIdentifier")
	version := plistString(metadata, "CFBundleShortVersionString", "CFBundleVersion")
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if identifier == "" {
		identifier = name
	}
	pkg := SoftwarePackage{
		Name:            name,
		Version:         version,
		Vendor:          plistString(metadata, "NSHumanReadableCopyright", "TeamIdentifier"),
		InstallLocation: path,
		Source:          "macos-app",
		Identifier:      identifier,
	}
	if executable := plistString(metadata, "CFBundleExecutable"); executable != "" {
		executablePath := filepath.Join(path, "Contents", "MacOS", executable)
		if _, err := os.Stat(executablePath); err == nil {
			pkg.ExecutablePath = executablePath
		}
	}
	return pkg, true
}

func readInstallerReceipt(path, root string) (SoftwarePackage, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SoftwarePackage{}, false
	}
	var metadata map[string]any
	if _, err := plist.Unmarshal(data, &metadata); err != nil {
		return SoftwarePackage{}, false
	}
	identifier := plistString(metadata, "PackageIdentifier")
	if identifier == "" {
		identifier = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	name := plistString(metadata, "DisplayName", "PackageName")
	if name == "" {
		name = identifier
	}
	version := plistString(metadata, "PackageVersion")
	if name == "" {
		return SoftwarePackage{}, false
	}
	installPrefix := plistString(metadata, "InstallPrefixPath")
	if installPrefix != "" && filepath.IsAbs(installPrefix) {
		installPrefix = filepath.Join(root, strings.TrimLeft(installPrefix, string(filepath.Separator)))
	}
	return SoftwarePackage{
		Name:            name,
		Version:         version,
		InstallLocation: installPrefix,
		Source:          "apple-installer-receipt",
		Identifier:      identifier,
	}, true
}

func readVersionedPackage(path, source string) (SoftwarePackage, bool) {
	version := filepath.Base(path)
	name := filepath.Base(filepath.Dir(path))
	if name == "." || name == string(filepath.Separator) || version == "" {
		return SoftwarePackage{}, false
	}
	return SoftwarePackage{
		Name:            name,
		Version:         version,
		InstallLocation: path,
		Source:          source,
		Identifier:      name,
	}, true
}

func plistString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func normalizePackages(packages []SoftwarePackage) []SoftwarePackage {
	byKey := make(map[string]SoftwarePackage, len(packages))
	for _, pkg := range packages {
		pkg.Name = strings.TrimSpace(pkg.Name)
		pkg.Version = strings.TrimSpace(pkg.Version)
		if pkg.Name == "" {
			continue
		}
		key := strings.ToLower(pkg.Name) + "\x00" + strings.ToLower(pkg.Version) + "\x00" + filepath.Clean(pkg.InstallLocation)
		if _, ok := byKey[key]; !ok {
			byKey[key] = pkg
		}
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

var _ scanner.Scanner = (*Scanner)(nil)
