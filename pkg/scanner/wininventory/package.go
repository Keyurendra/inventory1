package wininventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	wintypes "github.com/accuknox/accuknox-windows-scanner/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
	"github.com/accuknox/omniscan/pkg/scanner/trivy/rootfs"
	"github.com/accuknox/omniscan/pkg/scanner/winfs"
)

type SoftwarePackage struct {
	Name            string
	Version         string
	Vendor          string
	InstallLocation string
	Source          string
	Identifier      string
	ExecutablePath  string
	InstallDate     string
	UninstallString string
}

type scanRootFunc func(context.Context, string, string, string, string, string) (scanner.Findings, error)
type listDrivesFunc func() ([]string, error)
type discoverPackagesFunc func(context.Context) ([]SoftwarePackage, error)

type Scanner struct {
	cacheDir         string
	listDrives       listDrivesFunc
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
		listDrives:       winfs.FixedDrives,
		discoverPackages: discoverWindowsPackages,
		scanRoot:         scanTrivyRoot,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Scan(ctx context.Context, _ string, vmURI, platform, osType string) (scanner.Findings, error) {
	if osType != "windows" {
		return nil, fmt.Errorf("Windows package inventory cannot scan %q", osType)
	}

	drives, err := s.listDrives()
	if err != nil {
		return nil, fmt.Errorf("listing fixed Windows drives: %w", err)
	}
	if len(drives) == 0 {
		return nil, errors.New("no fixed Windows drives found")
	}

	result := &trivy.Result{
		SchemaVersion: 2,
		CreatedAt:     time.Now().UTC(),
		ArtifactName:  vmURI,
		ArtifactType:  "rootfs",
		Metadata: trivy.Metadata{
			OS: &ftypes.OS{Family: ftypes.OSType("windows")},
			VM: trivy.VMMetadata{URI: vmURI, Platform: platform, OS: osType},
		},
	}

	for _, drive := range drives {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		finding, err := s.scanRoot(ctx, drive, vmURI, platform, osType, s.cacheDir)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			slog.WarnContext(ctx, "unable to scan Windows drive for package inventory", "drive", drive, "error", err)
			continue
		}
		rootfsResult, ok := finding.(*trivy.Result)
		if !ok {
			slog.WarnContext(ctx, "unexpected Windows drive package inventory result", "drive", drive, "result_type", fmt.Sprintf("%T", finding))
			continue
		}
		result.Metadata.Size += rootfsResult.Metadata.Size
		if result.Metadata.OS == nil {
			result.Metadata.OS = rootfsResult.Metadata.OS
		}
		for _, trivyResult := range rootfsResult.Results {
			trivyResult.Target = absoluteTarget(drive, trivyResult.Target)
			for i := range trivyResult.Packages {
				trivyResult.Packages[i].FilePath = absoluteTarget(drive, trivyResult.Packages[i].FilePath)
			}
			result.Results = append(result.Results, trivyResult)
		}
	}

	softwarePackages, err := s.discoverPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("discovering Windows installed software: %w", err)
	}
	softwarePackages = NormalizePackages(softwarePackages)
	result.Metadata.Windows = &wintypes.ScanResult{
		Source:            "windows-package-inventory",
		InstalledSoftware: make([]wintypes.InstalledSoftware, 0, len(softwarePackages)),
	}
	packages := make(ftypes.Packages, 0, len(softwarePackages))
	for _, item := range softwarePackages {
		result.Metadata.Windows.InstalledSoftware = append(
			result.Metadata.Windows.InstalledSoftware,
			wintypes.InstalledSoftware{
				Name:            item.Name,
				Version:         item.Version,
				Publisher:       item.Vendor,
				InstallDate:     item.InstallDate,
				InstallLocation: item.InstallLocation,
				UninstallString: item.UninstallString,
			},
		)
		pkg := ftypes.Package{
			Name:       item.Name,
			Version:    item.Version,
			Maintainer: item.Vendor,
			FilePath:   item.InstallLocation,
			AnalyzedBy: ftypes.AnalyzerType(item.Source),
			ID:         packageID(item),
		}
		if item.ExecutablePath != "" {
			pkg.InstalledFiles = []string{item.ExecutablePath}
		}
		purl := softwarePackageURL(item)
		pkg.Identifier.PURL = purl
		packages = append(packages, pkg)
	}
	if len(packages) > 0 {
		result.Results = append(result.Results, types.Result{
			Target:   "Windows installed software",
			Class:    types.ClassOSPkg,
			Type:     ftypes.TargetType("windows-software"),
			Packages: packages,
		})
	}

	deduplicatePackages(result)
	return result, nil
}

func packageID(item SoftwarePackage) string {
	return item.Source + ":" + item.Identifier + "@" + item.Version
}

func softwarePackageURL(item SoftwarePackage) *packageurl.PackageURL {
	purlType := packageURLType(item.Source)
	namespace := ""
	name := item.Name
	if purlType == packageurl.TypeNPM && strings.HasPrefix(name, "@") {
		if separator := strings.IndexByte(name, '/'); separator > 1 {
			namespace = name[:separator]
			name = name[separator+1:]
		}
	}
	return packageurl.NewPackageURL(
		purlType,
		namespace,
		name,
		item.Version,
		packageurl.Qualifiers{{Key: "source", Value: item.Source}},
		"",
	)
}

func packageURLType(source string) string {
	switch {
	case strings.Contains(source, "chocolatey"):
		return packageurl.TypeChocolatey
	case strings.Contains(source, "npm"):
		return packageurl.TypeNPM
	case strings.Contains(source, "pip"):
		return packageurl.TypePyPi
	case strings.Contains(source, "nuget"):
		return packageurl.TypeNuget
	case strings.Contains(source, "cargo"):
		return packageurl.TypeCargo
	case strings.Contains(source, "golang"), strings.Contains(source, "go-module"):
		return packageurl.TypeGolang
	default:
		return packageurl.TypeGeneric
	}
}

func scanTrivyRoot(ctx context.Context, root, vmURI, platform, osType, cacheDir string) (scanner.Findings, error) {
	opts := []rootfs.OptFunc{rootfs.WithPackageInventory()}
	if cacheDir != "" {
		opts = append(opts, rootfs.WithCacheDirectory(cacheDir))
	}
	s, err := rootfs.NewScanner(opts...)
	if err != nil {
		return nil, err
	}
	return s.Scan(ctx, root, vmURI, platform, osType)
}

func absoluteTarget(root, target string) string {
	if target == "" || filepath.IsAbs(target) || (len(target) > 2 && target[1] == ':') {
		if len(target) >= 3 && target[1] == ':' {
			return strings.ReplaceAll(target, "/", `\`)
		}
		if target == "" {
			return root
		}
		return filepath.Join(root, target)
	}
	return filepath.Join(root, target)
}

func deduplicatePackages(result *trivy.Result) {
	type location struct {
		resultIndex  int
		packageIndex int
	}
	seen := make(map[string]location)
	var results types.Results
	for _, current := range result.Results {
		packages := current.Packages
		current.Packages = nil
		results = append(results, current)
		resultIndex := len(results) - 1
		for _, pkg := range packages {
			key := strings.ToLower(pkg.Name) + "\x00" + strings.ToLower(pkg.Version) + "\x00" +
				strings.ToLower(filepath.Clean(pkg.FilePath))
			if existing, ok := seen[key]; ok {
				mergePackage(&results[existing.resultIndex].Packages[existing.packageIndex], pkg)
				continue
			}
			seen[key] = location{resultIndex: resultIndex, packageIndex: len(results[resultIndex].Packages)}
			results[resultIndex].Packages = append(results[resultIndex].Packages, pkg)
		}
	}
	result.Results = results
}

func mergePackage(dst *ftypes.Package, src ftypes.Package) {
	if dst.Maintainer == "" {
		dst.Maintainer = src.Maintainer
	}
	if dst.FilePath == "" {
		dst.FilePath = src.FilePath
	}
	if src.AnalyzedBy != "" && !strings.Contains(string(dst.AnalyzedBy), string(src.AnalyzedBy)) {
		dst.AnalyzedBy = ftypes.AnalyzerType(mergeValue(string(dst.AnalyzedBy), string(src.AnalyzedBy)))
	}
	if dst.ID == "" {
		dst.ID = src.ID
	} else if src.ID != "" && dst.ID != src.ID {
		dst.ID = mergeValue(dst.ID, src.ID)
	}
	dst.InstalledFiles = mergeStrings(dst.InstalledFiles, src.InstalledFiles)
	if dst.Identifier.PURL == nil {
		dst.Identifier.PURL = src.Identifier.PURL
	}
}

func mergeStrings(existing, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	merged := make([]string, 0, len(existing)+len(incoming))
	for _, value := range append(existing, incoming...) {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	return merged
}

var _ scanner.Scanner = (*Scanner)(nil)
