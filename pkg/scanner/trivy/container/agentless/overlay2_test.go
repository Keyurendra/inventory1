package agentless

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOverlay2LowerDirsOrder(t *testing.T) {
	t.Parallel()

	dataRoot := t.TempDir()
	imageID := "1111111111111111111111111111111111111111111111111111111111111111"
	diffA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	diffB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cfg := v1.ConfigFile{
		RootFS: v1.RootFS{
			Type: "layers",
			DiffIDs: []v1.Hash{
				{Algorithm: "sha256", Hex: diffA},
				{Algorithm: "sha256", Hex: diffB},
			},
		},
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)

	cfgPath := filepath.Join(
		dataRoot,
		"image",
		"overlay2",
		"imagedb",
		"content",
		"sha256",
		imageID,
	)
	require.NoError(t, os.MkdirAll(filepath.Dir(cfgPath), 0o755))
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o644))

	writeCache := func(key, cacheID string) {
		p := filepath.Join(
			dataRoot,
			"image",
			"overlay2",
			"layerdb",
			"sha256",
			key,
			"cache-id",
		)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(cacheID), 0o644))
		require.NoError(t, os.MkdirAll(filepath.Join(
			dataRoot,
			"overlay2",
			cacheID,
			"diff",
		), 0o755))
	}
	dA := digest.Digest("sha256:" + diffA)
	dB := digest.Digest("sha256:" + diffB)
	cA := identity.ChainID([]digest.Digest{dA}).Encoded()
	cB := identity.ChainID([]digest.Digest{dA, dB}).Encoded()
	writeCache(cA, "cache-a")
	writeCache(cB, "cache-b")

	lower, cfgOut, err := overlay2LowerDirs(dataRoot, "sha256:"+imageID)
	require.NoError(t, err)
	require.Len(t, lower, 2)
	assert.Equal(t, filepath.Join(dataRoot, "overlay2", "cache-b", "diff"), lower[0])
	assert.Equal(t, filepath.Join(dataRoot, "overlay2", "cache-a", "diff"), lower[1])
	require.Len(t, cfgOut.RootFS.DiffIDs, 2)
}
