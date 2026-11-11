package agent

import (
	"context"
	"log/slog"

	"github.com/accuknox/omniscan/pkg/util"
)

type OptFunc func(*opts)

type opts struct {
	vulnDBDirectory                  string
	aiAgentCatalogPath               string
	packageInventory                 bool
	macOSFeedURL                     string
	vulnScanEnabled                  bool
	containerVulnScanEnabled         bool
	containerImageScanRemoteFallback bool
	clusterID                        *int
	clusterName                      string
	malwareScanEnabled               bool
	clamavDBDirectory                string
	malwareScanTargetDirectory       string
	criSockets                       []string
	overrideHostname                 string
	vmURIPrefix                      string
	platform                         string
	logger                           *slog.Logger
}

func WithMalwareScanDisabled() OptFunc {
	return func(o *opts) {
		o.malwareScanEnabled = false
	}
}

func WithVulnScanDisabled() OptFunc {
	return func(o *opts) {
		o.vulnScanEnabled = false
	}
}

func WithContainerVulnScanDisabled() OptFunc {
	return func(o *opts) {
		o.containerVulnScanEnabled = false
	}
}

func WithContainerVulnScanEnabled() OptFunc {
	return func(o *opts) {
		o.containerVulnScanEnabled = true
	}
}

func WithContainerImageScanRemoteFallback(enabled bool) OptFunc {
	return func(o *opts) {
		o.containerImageScanRemoteFallback = enabled
	}
}

func WithClusterID(clusterID int) OptFunc {
	return func(o *opts) {
		o.clusterID = &clusterID
	}
}

func WithClusterName(clusterName string) OptFunc {
	return func(o *opts) {
		o.clusterName = clusterName
	}
}

func WithVulnDBDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.vulnDBDirectory = dir
	}
}

func WithAIAgentCatalogPath(path string) OptFunc {
	return func(o *opts) {
		o.aiAgentCatalogPath = path
	}
}

func WithPackageInventory() OptFunc {
	return func(o *opts) {
		o.packageInventory = true
	}
}

func WithMacOSFeedURL(url string) OptFunc {
	return func(o *opts) {
		o.macOSFeedURL = url
	}
}

func WithClamAVDBDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.clamavDBDirectory = dir
	}
}

func WithMalwareScanTargetDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.malwareScanTargetDirectory = dir
	}
}

func WithCRISockets(sockets ...string) OptFunc {
	return func(o *opts) {
		o.criSockets = append(o.criSockets, sockets...)
	}
}

func WithOverrideHostname(hostname string) OptFunc {
	return func(o *opts) {
		o.overrideHostname = hostname
	}
}

func WithPlatform(platform string) OptFunc {
	return func(o *opts) {
		o.platform = platform
	}
}

func WithVMURIPrefix(prefix string) OptFunc {
	return func(o *opts) {
		o.vmURIPrefix = prefix
	}
}

func WithLogger(l *slog.Logger) OptFunc {
	return func(o *opts) {
		if l == nil {
			return
		}
		o.logger = l
	}
}

func defaultOpts() opts {
	rootfs, err := util.FindRootFS()
	if err != nil {
		slog.LogAttrs(
			context.TODO(),
			slog.LevelWarn,
			"failed to determine rootfs",
			slog.String("error", err.Error()),
		)
	}
	return opts{
		vulnDBDirectory:            "/var/lib/accuknox-omni/",
		clamavDBDirectory:          "/var/lib/clamav",
		malwareScanEnabled:         true,
		vulnScanEnabled:            true,
		containerVulnScanEnabled:   false,
		malwareScanTargetDirectory: rootfs,
		platform:                   "agent",
		logger:                     slog.Default(),
	}
}
