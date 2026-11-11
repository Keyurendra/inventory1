package rootfs

import (
	"fmt"
	"os"
	"time"
)

type OptFunc func(*opts)

type opts struct {
	timeout          time.Duration
	cacheDir         string
	useExternalTrivy bool
	packageInventory bool
	skipDirs         []string
}

func WithTimeout(timeout time.Duration) OptFunc {
	return func(o *opts) {
		o.timeout = timeout
	}
}

func WithCacheDirectory(cacheDir string) OptFunc {
	return func(o *opts) {
		o.cacheDir = cacheDir
	}
}

func WithExternalTrivy() OptFunc {
	return func(o *opts) {
		o.useExternalTrivy = true
	}
}

func WithPackageInventory() OptFunc {
	return func(o *opts) {
		o.packageInventory = true
	}
}

func WithSkipDirectories(paths ...string) OptFunc {
	return func(o *opts) {
		o.skipDirs = append(o.skipDirs, paths...)
	}
}

func defaultOpts() (*opts, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("get user cache directory: %w", err)
	}
	return &opts{
		timeout:          time.Hour * 12,
		cacheDir:         cacheDir,
		useExternalTrivy: false,
	}, nil
}
