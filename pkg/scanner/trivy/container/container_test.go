package container

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type nsCase struct {
	name  string
	input []string
	want  []string
}

func TestRetryRemote(t *testing.T) {
	t.Parallel()
	err := errors.New("failed to get reader: content digest sha256:abc: not found")
	assert.True(t, retryRemote("containerd", err))
	assert.False(t, retryRemote("docker", err))
	assert.False(t, retryRemote("containerd", nil))
	assert.False(t, retryRemote("containerd", errors.New("image not found in containerd store")))
}

func TestDedupByDigestAcrossRuntimes(t *testing.T) {
	t.Parallel()

	d := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cts := []containerInfo{
		{
			ID:          "ctr-1",
			Image:       "repo/app:v1",
			ImageID:     d,
			Runtime:     "docker",
			RuntimeHost: "unix:///run/docker.sock",
		},
		{
			ID:          "ctr-2",
			Image:       "repo/app:v1",
			ImageID:     d,
			Runtime:     "containerd",
			RuntimeHost: "unix:///run/containerd/containerd.sock",
		},
	}

	targets := dedup(cts)
	if assert.Len(t, targets, 1) {
		assert.Equal(t, "digest:"+d, targets[0].key)
		assert.Equal(t, 2, targets[0].n)
		assert.Len(t, targets[0].srcs, 2)
	}
}

func TestDedupUsesRefFallbackWhenDigestMissing(t *testing.T) {
	t.Parallel()

	cts := []containerInfo{
		{
			ID:          "ctr-1",
			Image:       "repo/app:v1",
			Runtime:     "docker",
			RuntimeHost: "unix:///run/docker.sock",
		},
		{
			ID:          "ctr-2",
			Image:       "repo/app:v1",
			Runtime:     "docker",
			RuntimeHost: "unix:///run/docker.sock",
		},
	}

	targets := dedup(cts)
	if assert.Len(t, targets, 1) {
		assert.Equal(t, "ref:repo/app:v1", targets[0].key)
		assert.Equal(t, 2, targets[0].n)
		assert.Len(t, targets[0].srcs, 1)
	}
}

func TestKeyOfPrefersImageIDDigest(t *testing.T) {
	t.Parallel()

	c := containerInfo{
		ID:      "ctr-1",
		Image:   "repo/a:v1",
		ImageID: "docker-pullable://repo/a@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	k := keyOf(c)
	assert.Equal(
		t,
		"digest:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		k,
	)
}

func TestKeyOfPrefersImageRefDigestOverImageID(t *testing.T) {
	t.Parallel()

	c := containerInfo{
		ID:      "ctr-1",
		Image:   "docker.io/library/nginx@sha256:9ff236ed47fe39cf1f0acf349d0e5137f8b8a6fd0b46e5117a401010e56222e1",
		ImageID: "sha256:c613f16b664244b150d1c3644cbc387ec1fe8376377f9419992280eb4a82ff3b",
	}

	k := keyOf(c)
	assert.Equal(
		t,
		"digest:sha256:9ff236ed47fe39cf1f0acf349d0e5137f8b8a6fd0b46e5117a401010e56222e1",
		k,
	)
}

func TestUniqNS(t *testing.T) {
	t.Parallel()

	cases := []nsCase{
		{
			name:  "dedups with stable order",
			input: []string{"default", "k8s.io", "default"},
			want:  []string{"default", "k8s.io"},
		},
		{
			name:  "keeps order",
			input: []string{"default", "moby"},
			want:  []string{"default", "moby"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := uniqNS(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
