package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/urfave/cli/v3"

	cmdUtil "github.com/accuknox/omniscan/cmd/omni/util"
	"github.com/accuknox/omniscan/pkg/job/agent"
	"github.com/accuknox/omniscan/pkg/publisher/file"
	"github.com/accuknox/omniscan/pkg/util"
)

var scanCmd = &cli.Command{
	Name:      "scan",
	Flags:     cmdUtil.AgentScanCmdFlags(),
	Arguments: cmdUtil.AgentScanCmdArgs(),
	Action: func(ctx context.Context, c *cli.Command) error {
		packageInventory := c.Bool("package-inventory")
		publisher := file.NewPublisher(c.String("local-publisher-store-path"))
		if !packageInventory && !c.Bool("local-publisher") {
			var err error
			publisher, err = cmdUtil.CreateCSPMPublisher(c)
			if err != nil {
				return err
			}
		}

		skipMalwareScan := c.Bool("skip-malware-scan")
		skipVulnScan := c.Bool("skip-vuln-scan")
		enableContainerImageScan := c.Bool("enable-container-image-scan")
		if !packageInventory && skipVulnScan && skipMalwareScan && !enableContainerImageScan {
			return fmt.Errorf("atleast one scaner should be enabled")
		}

		opts := []agent.OptFunc{
			agent.WithVulnDBDirectory(c.String("vuln-db-directory")),
			agent.WithMacOSFeedURL(c.String("macos-feed-url")),
			agent.WithClamAVDBDirectory(c.String("clamav-db-directory")),
			agent.WithMalwareScanTargetDirectory(c.String("malware-scan-target-directory")),
			agent.WithCRISockets(c.StringSlice("cri-sockets")...),
			agent.WithContainerImageScanRemoteFallback(c.Bool("container-image-scan-remote-fallback")),
			agent.WithOverrideHostname(c.String("override-hostname")),
			agent.WithAIAgentCatalogPath(c.String("ai-agent-catalog-path")),
			agent.WithPlatform(c.String("platform")),
			agent.WithVMURIPrefix(c.String("vm-uri-prefix")),
		}
		if packageInventory {
			opts = append(opts, agent.WithPackageInventory())
		}
		if c.IsSet("cluster-id") {
			opts = append(opts, agent.WithClusterID(c.Int("cluster-id")))
		}
		if c.IsSet("cluster-name") {
			opts = append(opts, agent.WithClusterName(c.String("cluster-name")))
		}
		if skipMalwareScan {
			opts = append(opts, agent.WithMalwareScanDisabled())
		}
		if skipVulnScan {
			opts = append(opts, agent.WithVulnScanDisabled())
		}
		if enableContainerImageScan {
			opts = append(opts, agent.WithContainerVulnScanEnabled())
		}

		job, err := agent.NewJob(publisher, opts...)
		if err != nil {
			return fmt.Errorf("creating job: %w", err)
		}

		rootfs := c.StringArg("rootfs")
		if rootfs == "" {
			rootfs, err = util.FindRootFS()
			if err != nil {
				return fmt.Errorf("determining rootfs: %w", err)
			}
		}

		summary, err := job.Run(ctx, rootfs)
		if err != nil {
			return fmt.Errorf("executing scan job: %w", err)
		}

		output, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling execution summary to json: %w", err)
		}

		fmt.Println(string(output))

		return nil
	},
}
