package rootfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	flanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
)

type s struct {
	opts
}

func NewScanner(fns ...OptFunc) (scanner.Scanner, error) {
	o, err := defaultOpts()
	if err != nil {
		return nil, fmt.Errorf("initializing opts: %w", err)
	}
	for _, fn := range fns {
		fn(o)
	}
	return &s{
		opts: *o,
	}, nil
}

func (s s) Scan(ctx context.Context, mountpoint, vmURI, platform, osType string) (scanner.Findings, error) {
	if s.packageInventory {
		if s.useExternalTrivy {
			return nil, fmt.Errorf("package inventory requires embedded Trivy")
		}
		return s.embeddedInventoryScan(ctx, mountpoint, vmURI, platform, osType)
	}
	if s.useExternalTrivy {
		return s.externalScan(ctx, mountpoint, vmURI, platform, osType)
	}
	return s.embeddedScan(ctx, mountpoint, vmURI, platform, osType)
}

func (s s) embeddedInventoryScan(ctx context.Context, mountpoint, vmURI, platform, osType string) (scanner.Findings, error) {
	opts := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  s.timeout,
			CacheDir: s.cacheDir,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: "fs",
		},
		ScanOptions: flag.ScanOptions{
			Scanners:          types.Scanners{types.SBOMScanner},
			SkipDirs:          s.skipDirs,
			DisableTelemetry:  true,
			OfflineScan:       true,
			SkipVersionCheck:  true,
			Target:            mountpoint,
			DetectionPriority: flanalTypes.PriorityPrecise,
			Parallel:          0,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			SkipVEXRepoUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes: []string{"os", "library"},
			PkgRelationships: []flanalTypes.Relationship{
				flanalTypes.RelationshipUnknown,
				flanalTypes.RelationshipRoot,
				flanalTypes.RelationshipWorkspace,
				flanalTypes.RelationshipDirect,
				flanalTypes.RelationshipIndirect,
			},
		},
		ReportOptions: flag.ReportOptions{
			Format:      types.FormatJSON,
			ListAllPkgs: true,
		},
	}

	runner, err := artifact.NewRunner(ctx, opts, artifact.TargetRootfs)
	if err != nil {
		return nil, fmt.Errorf("initializing package inventory scanner: %w", err)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanRootfs(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("scanning rootfs %s for package inventory: %w", mountpoint, err)
	}

	return &trivy.Result{
		SchemaVersion: report.SchemaVersion,
		CreatedAt:     report.CreatedAt,
		ArtifactName:  report.ArtifactName,
		ArtifactType:  "rootfs",
		Results:       report.Results,
		Metadata: trivy.Metadata{
			Size:        report.Metadata.Size,
			OS:          report.Metadata.OS,
			ImageID:     report.Metadata.ImageID,
			DiffIDs:     report.Metadata.DiffIDs,
			RepoTags:    report.Metadata.RepoTags,
			RepoDigests: report.Metadata.RepoDigests,
			ImageConfig: report.Metadata.ImageConfig,
			Layers:      report.Metadata.Layers,
			VM: trivy.VMMetadata{
				URI:      vmURI,
				Platform: platform,
				OS:       osType,
			},
		},
	}, nil
}

func (s s) externalScan(ctx context.Context, mountpoint, vmURI, platform, osType string) (scanner.Findings, error) {
	path, err := exec.LookPath("trivy")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("`trivy` executable not found in PATH")
		}
		return nil, fmt.Errorf("looking up trivy in PATH: %w", err)
	}

	var stdout, stderr bytes.Buffer

	cmd := exec.CommandContext(
		ctx,
		path,
		"rootfs",
		mountpoint,
		"--quiet",
		"--format=json",
		"--scanners=vuln",
		"--offline-scan",
		"--skip-db-update",
		"--skip-java-db-update",
		"--timeout="+s.timeout.String(),
		"--cache-dir="+s.cacheDir,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("executing trivy: %w: %s", err, stderr.String())
	}

	report := new(types.Report)
	if err := json.NewDecoder(&stdout).Decode(report); err != nil {
		return nil, fmt.Errorf("decoding trivy report: %w", err)
	}

	return &trivy.Result{
		SchemaVersion: report.SchemaVersion,
		CreatedAt:     report.CreatedAt,
		ArtifactName:  report.ArtifactName,
		ArtifactType:  "rootfs",
		Results:       report.Results,
		Metadata: trivy.Metadata{
			Size:        report.Metadata.Size,
			OS:          report.Metadata.OS,
			ImageID:     report.Metadata.ImageID,
			DiffIDs:     report.Metadata.DiffIDs,
			RepoTags:    report.Metadata.RepoTags,
			RepoDigests: report.Metadata.RepoDigests,
			ImageConfig: report.Metadata.ImageConfig,
			Layers:      report.Metadata.Layers,
			VM: trivy.VMMetadata{
				URI:      vmURI,
				Platform: platform,
				OS:       osType,
			},
		},
	}, nil
}

func (s s) embeddedScan(ctx context.Context, mountpoint, vmURI, platform, osType string) (scanner.Findings, error) {
	opts := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  s.timeout,
			CacheDir: s.cacheDir,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: "fs",
		},
		ScanOptions: flag.ScanOptions{
			Scanners:          []types.Scanner{types.VulnerabilityScanner},
			DisableTelemetry:  true,
			OfflineScan:       true,
			Target:            mountpoint,
			DetectionPriority: flanalTypes.PriorityPrecise,
			Parallel:          0,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbTypes.SourceID{"auto"},
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes: []string{"os", "library"},
			PkgRelationships: []flanalTypes.Relationship{
				flanalTypes.RelationshipUnknown,
				flanalTypes.RelationshipRoot,
				flanalTypes.RelationshipWorkspace,
				flanalTypes.RelationshipDirect,
				flanalTypes.RelationshipIndirect,
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

	runner, err := artifact.NewRunner(ctx, opts, artifact.TargetRootfs)
	if err != nil {
		return nil, fmt.Errorf("initializing scanner: %w", err)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanRootfs(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("scanning rootfs %s: %w", mountpoint, err)
	}

	return &trivy.Result{
		SchemaVersion: report.SchemaVersion,
		CreatedAt:     report.CreatedAt,
		ArtifactName:  report.ArtifactName,
		ArtifactType:  "rootfs",
		Results:       report.Results,
		Metadata: trivy.Metadata{
			Size:        report.Metadata.Size,
			OS:          report.Metadata.OS,
			ImageID:     report.Metadata.ImageID,
			DiffIDs:     report.Metadata.DiffIDs,
			RepoTags:    report.Metadata.RepoTags,
			RepoDigests: report.Metadata.RepoDigests,
			ImageConfig: report.Metadata.ImageConfig,
			Layers:      report.Metadata.Layers,
			VM: trivy.VMMetadata{
				URI:      vmURI,
				Platform: platform,
				OS:       osType,
			},
		},
	}, nil
}
