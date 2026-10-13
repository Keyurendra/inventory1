package filesystem

import (
	"context"
	"fmt"
	"os"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scan reports vulnerabilities in application dependencies found on a filesystem.
// Callers add OS and installed software vulnerabilities from their OS-specific scanner.
func Scan(ctx context.Context, target, cacheDir string) (types.Report, error) {
	return scan(ctx, target, cacheDir, false, nil)
}

// ScanRootfs scans installed libraries without resolving parent POMs in source trees.
func ScanRootfs(ctx context.Context, target, cacheDir string, skipDirs ...string) (types.Report, error) {
	return scan(ctx, target, cacheDir, true, skipDirs)
}

func scan(ctx context.Context, target, cacheDir string, rootfs bool, skipDirs []string) (types.Report, error) {
	if cacheDir == "" {
		var err error
		cacheDir, err = os.UserCacheDir()
		if err != nil {
			return types.Report{}, fmt.Errorf("getting user cache directory: %w", err)
		}
	}

	opts := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  12 * time.Hour,
			CacheDir: cacheDir,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: string(cache.TypeMemory),
		},
		ScanOptions: flag.ScanOptions{
			Scanners:          types.Scanners{types.VulnerabilityScanner},
			SkipDirs:          skipDirs,
			DisableTelemetry:  true,
			OfflineScan:       true,
			Target:            target,
			DetectionPriority: ftypes.PriorityPrecise,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbTypes.SourceID{"auto"},
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes: []string{types.PkgTypeLibrary},
			PkgRelationships: []ftypes.Relationship{
				ftypes.RelationshipUnknown,
				ftypes.RelationshipRoot,
				ftypes.RelationshipWorkspace,
				ftypes.RelationshipDirect,
				ftypes.RelationshipIndirect,
			},
		},
		ReportOptions: flag.ReportOptions{
			Format:      types.FormatJSON,
			ListAllPkgs: true,
			Severities: []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			},
		},
	}

	targetType := artifact.TargetFilesystem
	if rootfs {
		targetType = artifact.TargetRootfs
	}
	runner, err := artifact.NewRunner(ctx, opts, targetType)
	if err != nil {
		return types.Report{}, fmt.Errorf("initializing filesystem scanner: %w", err)
	}
	defer runner.Close(ctx)

	scan := runner.ScanFilesystem
	if rootfs {
		scan = runner.ScanRootfs
	}
	report, err := scan(ctx, opts)
	if err != nil {
		return types.Report{}, fmt.Errorf("scanning filesystem %q: %w", target, err)
	}
	return report, nil
}
