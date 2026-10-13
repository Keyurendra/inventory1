//go:build windows

package winvuln

import (
	"context"

	winsc "github.com/accuknox/accuknox-windows-scanner/pkg/scanner"

	"github.com/accuknox/omniscan/pkg/scanner"
)

func (s s) scanLive(ctx context.Context, vmURI, platform string) (scanner.Findings, error) {
	opts := winsc.ScanOptions{
		ShowKBs:                 true,
		ShowSoftware:            true,
		ShowMissingKBs:          true,
		ShowMissingSoftwareKBs:  true,
		ShowSystemInfo:          true,
		ShowUSBDevices:          true,
		ShowNetworkInterfaces:   true,
		ShowWindowsFeatures:     true,
		ShowRecentPrograms:      true,
		ShowFirewallConfig:      true,
		ShowRemoteDesktopConfig: true,
		ShowEventLogConfig:      true,
		ShowBootConfig:          true,
	}

	scanResult, err := winsc.ScanLive(ctx, s.dbPath, opts)
	if err != nil {
		return nil, err
	}

	return &Result{
		Platform:   platform,
		VMUri:      vmURI,
		OS:         "windows",
		ScanResult: scanResult,
	}, nil
}
