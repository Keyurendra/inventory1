//go:build !windows

package winvuln

import (
	"context"
	"errors"

	"github.com/accuknox/omniscan/pkg/scanner"
)

func (s s) scanLive(_ context.Context, _, _ string) (scanner.Findings, error) {
	return nil, errors.New("live Windows scanning only supported on Windows OS")
}
