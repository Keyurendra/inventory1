//go:build !windows

package wininventory

import (
	"context"
	"errors"
)

func discoverWindowsPackages(context.Context) ([]SoftwarePackage, error) {
	return nil, errors.New("native Windows package sources are only available on Windows")
}
