package util

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/publisher/cspm"
)

func CloudScanCmdFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "local-publisher",
			Usage: "Store artifacts locally only",
		},
		&cli.StringFlag{
			Name:      "local-publisher-store-path",
			Usage:     "Path to local publisher's store directory",
			TakesFile: true,
			Value:     "/var/lib/accuknox-omni/",
		},
		&cli.StringFlag{
			Name:  "artifact-endpoint",
			Usage: "AccuKnox artifact API endpoint",
			Value: "https://cspm.accuknox.com/api/v1/artifact/",
		},
		&cli.UintFlag{
			Name:        "tenant-id",
			Usage:       "AccuKnox tenant ID",
			HideDefault: true,
		},
		&cli.StringFlag{
			Name:  "artifact-label",
			Usage: "Label to associate with the artifact",
		},
		&cli.StringFlag{
			Name:      "artifact-token-file",
			Usage:     "Path to AccuKnox artifact API JWT auth token",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "skip-malware-scan",
			Usage: "Scan only for vulnerabilities",
		},
		&cli.BoolFlag{
			Name:  "multi-az-support",
			Usage: "Authorizes Pulling VMs from all Availability Zones in the Region",
		},
		&cli.StringFlag{
			Name:      "vuln-db-directory",
			Usage:     "Path to vulnerability scanner's database directory",
			Value:     "/var/lib/accuknox-omni",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:  "vm-name-regex",
			Usage: "Filter VMs by name using regex",
		},
		&cli.StringMapFlag{
			Name:  "vm-label-regex",
			Usage: "Filter VMs by label using regex",
		},
		&cli.UintFlag{
			Name:  "concurrency",
			Usage: "Number of concurrent scans",
			Value: uint(runtime.NumCPU()),
		},
		&cli.BoolFlag{
			Name:  "enable-container-image-scan",
			Usage: "Enable container image scan",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "container-image-scan-remote-fallback",
			Usage: "Retry failed local container image scan via remote registry",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "use-external-trivy",
			Usage: "Use external trivy. Must be in PATH",
			Value: true,
		},
		&cli.IntFlag{
			Name:  "cluster-id",
			Usage: "Cluster ID to include in Trivy artifact",
		},
		&cli.StringFlag{
			Name:  "cluster-name",
			Usage: "Cluster name to include in Trivy artifact",
		},
	}
}

func CloudScheduleCmdFlags() []cli.Flag {
	return append([]cli.Flag{
		&cli.StringFlag{
			Name:  "crontab",
			Value: "@daily",
			Usage: "Cron expression for scheduling",
		},
		&cli.BoolFlag{
			Name:  "trigger-immediately",
			Value: false,
			Usage: "Trigger the first scan right after scheduling",
		},
		&cli.BoolFlag{
			Name:  "enable-prometheus-metrics",
			Value: false,
			Usage: "Enable prometheus metrics endpoint",
		},
		&cli.Uint16Flag{
			Name:  "prometheus-metrics-port",
			Value: 9100,
			Usage: "Port for prometheus metrics",
		},
	}, CloudScanCmdFlags()...)
}

func AgentScanCmdFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "override-hostname",
			Usage: "Override system hostname",
		},
		&cli.StringFlag{
			Name:      "ai-agent-catalog-path",
			Usage:     "Path to AI-agent detection catalog",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "package-inventory",
			Usage: "Run package inventory only",
		},
		&cli.StringFlag{
			Name:  "platform",
			Usage: "Platform name",
			Value: "agent",
		},
		&cli.StringFlag{
			Name:  "vm-uri-prefix",
			Usage: "Prefix to prepend to the node's hostname",
		},
		&cli.BoolFlag{
			Name:  "local-publisher",
			Usage: "Store artifacts locally only",
		},
		&cli.StringFlag{
			Name:      "local-publisher-store-path",
			Usage:     "Path to local publisher's store directory",
			TakesFile: true,
			Value:     "/var/lib/accuknox-omni/",
		},
		&cli.StringFlag{
			Name:  "artifact-endpoint",
			Usage: "AccuKnox artifact API endpoint",
			Value: "https://cspm.accuknox.com/api/v1/artifact/",
		},
		&cli.BoolFlag{
			Name:  "skip-tls-verification",
			Usage: "Skip TLS verification for artifact API",
			Value: false,
		},
		&cli.UintFlag{
			Name:        "tenant-id",
			Usage:       "AccuKnox tenant ID",
			HideDefault: true,
		},
		&cli.StringFlag{
			Name:  "artifact-label",
			Usage: "Label to associate with the artifact",
		},
		&cli.StringFlag{
			Name:      "artifact-token-file",
			Usage:     "Path to AccuKnox artifact API JWT auth token",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "skip-malware-scan",
			Usage: "Scan only for vulnerabilities",
		},
		&cli.BoolFlag{
			Name:  "skip-vuln-scan",
			Usage: "Scan only for malware",
		},
		&cli.BoolFlag{
			Name:  "enable-container-image-scan",
			Usage: "Enable container image scan. Supported runtimes: docker, podman, containerd, crio",
			Value: false,
		},
		&cli.StringSliceFlag{
			Name:        "cri-sockets",
			Usage:       "Comma-separated container runtime sockets",
			DefaultText: "docker: /var/run/docker.sock,/run/docker.sock; podman: /run/podman/podman.sock,/var/run/podman/podman.sock; containerd: /run/containerd/containerd.sock,/var/run/containerd/containerd.sock; crio: /var/run/crio/crio.sock,/run/crio/crio.sock",
			TakesFile:   true,
		},
		&cli.BoolFlag{
			Name:  "container-image-scan-remote-fallback",
			Usage: "Retry failed local container image scan via remote registry",
			Value: false,
		},
		&cli.StringFlag{
			Name:      "vuln-db-directory",
			Usage:     "Path to vulnerability scanner's database directory",
			Value:     "/var/lib/accuknox-omni/",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:  "macos-feed-url",
			Usage: "MacAdmins SOFA macOS vulnerability feed URL",
			Value: "https://sofafeed.macadmins.io/v1/macos_data_feed.json",
		},
		&cli.StringFlag{
			Name:      "clamav-db-directory",
			Usage:     "Path to ClamAV database directory",
			Value:     "/var/lib/clamav",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:      "malware-scan-target-directory",
			Usage:     "Limit malware scan to a specific directory",
			Value:     "",
			TakesFile: true,
		},
		&cli.IntFlag{
			Name:  "cluster-id",
			Usage: "Cluster ID to include in Trivy artifact",
		},
		&cli.StringFlag{
			Name:  "cluster-name",
			Usage: "Cluster name to include in Trivy artifact",
		},
	}
}

func AgentScheduleCmdFlags() []cli.Flag {
	return append([]cli.Flag{
		&cli.StringFlag{
			Name:  "crontab",
			Value: "@daily",
			Usage: "Cron expression for scheduling",
		},
		&cli.BoolFlag{
			Name:  "trigger-immediately",
			Value: false,
			Usage: "Trigger the first scan right after scheduling",
		},
	}, AgentScanCmdFlags()...)
}

func AgentScanCmdArgs() []cli.Argument {
	return []cli.Argument{
		&cli.StringArg{
			Name:      "rootfs",
			UsageText: "[MOUNTPOINT]",
		},
	}
}

func AgentScheduleCmdArgs() []cli.Argument {
	return AgentScanCmdArgs()
}

func CreateCSPMPublisher(c *cli.Command) (publisher.Publisher, error) {
	endpoint := c.String("artifact-endpoint")
	if endpoint == "" {
		return nil, fmt.Errorf("missing `--artifact-endpoint`")
	}

	tenantID := c.Uint("tenant-id")
	if tenantID == 0 {
		return nil, fmt.Errorf("missing `--tenant-id`")
	}

	label := c.String("artifact-label")
	if label == "" {
		return nil, fmt.Errorf("missing `--artifact-label`")
	}

	tokenFile := c.String("artifact-token-file")
	if tokenFile == "" {
		return nil, fmt.Errorf("missing `--artifact-token-file`")
	}

	tkn, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token file %q: %w", tokenFile, err)
	}

	return cspm.NewPublisher(cspm.Config{
		Endpoint:            endpoint,
		TenantID:            tenantID,
		LabelID:             label,
		Token:               strings.TrimSpace(string(tkn)),
		SkipTLSVerification: c.Bool("skip-tls-verification"),
	}, nil)
}
