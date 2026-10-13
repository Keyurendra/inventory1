package winvuln

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	winsc "github.com/accuknox/accuknox-windows-scanner/pkg/scanner"

	"github.com/accuknox/omniscan/pkg/scanner"
)

const (
	softwareHivePath = "Windows/System32/config/SOFTWARE"
	systemHivePath   = "Windows/System32/config/SYSTEM"
)

type s struct {
	opts
}

func NewScanner(fns ...OptFunc) scanner.Scanner {
	o := defaultOpts()
	for _, fn := range fns {
		fn(&o)
	}
	return &s{
		opts: o,
	}
}

func (s s) Scan(ctx context.Context, mountpoint, vmURI, platform, osType string) (scanner.Findings, error) {
	if !s.useOfflineMode {
		return s.scanLive(ctx, vmURI, platform)
	}
	return s.scanOffline(ctx, mountpoint, vmURI, platform)
}

func (s s) scanOffline(ctx context.Context, mountpoint, vmURI, platform string) (scanner.Findings, error) {
	fullSoftwareHivePath := filepath.Join(mountpoint, softwareHivePath)
	fullSystemHivePath := filepath.Join(mountpoint, systemHivePath)
	if _, err := os.Stat(fullSoftwareHivePath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("path %s does not exist", fullSoftwareHivePath)
		}
	}
	if _, err := os.Stat(fullSystemHivePath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("path %s does not exist", fullSystemHivePath)
		}
	}

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

	scanResult, err := winsc.ScanHive(
		ctx,
		mountpoint,
		s.dbPath,
		fullSoftwareHivePath,
		fullSystemHivePath,
		opts,
	)
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
