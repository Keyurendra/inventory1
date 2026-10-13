package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type osCase struct {
	name    string
	markers []string
	want    string
}

func TestDetectOS(t *testing.T) {
	tests := []osCase{
		{
			name: "macOS",
			markers: []string{
				"System/Library/CoreServices/SystemVersion.plist",
			},
			want: "macos",
		},
		{
			name:    "Linux",
			markers: []string{"etc", "bin", "sys"},
			want:    "linux",
		},
		{
			name:    "Windows",
			markers: []string{"Windows", "Program Files"},
			want:    "windows",
		},
		{
			name: "unknown",
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			for _, marker := range tt.markers {
				path := filepath.Join(root, marker)
				if filepath.Ext(path) == ".plist" {
					require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
					require.NoError(t, os.WriteFile(path, nil, 0o600))
					continue
				}
				require.NoError(t, os.MkdirAll(path, 0o755))
			}

			require.Equal(t, tt.want, DetectOS(root))
		})
	}
}
