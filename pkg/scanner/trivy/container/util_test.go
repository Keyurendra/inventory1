package container

import (
	"os"
	"testing"

	namespaceapi "github.com/containerd/containerd/api/services/namespaces/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type runtimeCase struct {
	name    string
	socket  string
	runtime string
	cri     bool
}

func TestDetectRuntimeWithSocket(t *testing.T) {
	t.Parallel()

	tests := []runtimeCase{
		{
			name:    "docker",
			socket:  "/run/docker.sock",
			runtime: "docker",
		},
		{
			name:    "podman",
			socket:  "/run/podman/podman.sock",
			runtime: "podman",
		},
		{
			name:    "containerd",
			socket:  "/run/containerd/containerd.sock",
			runtime: "containerd",
			cri:     true,
		},
		{
			name:    "crio",
			socket:  "/run/crio/crio.sock",
			runtime: "crio",
			cri:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := s{opts: opts{criSockets: []string{tt.socket}}}
			cfgs, err := scanner.detectWithStat(fakeStat(tt.socket), runtimeHosts)
			require.NoError(t, err)
			require.Len(t, cfgs, 1)
			assert.Equal(t, tt.runtime, cfgs[0].name)
			assert.Equal(t, "unix://"+tt.socket, cfgs[0].host)
			assert.Equal(t, tt.cri, cfgs[0].cri)
		})
	}
}

func TestDetectRuntimeUnknownSocket(t *testing.T) {
	t.Parallel()

	scanner := s{opts: opts{criSockets: []string{"/tmp/custom.sock"}}}
	cfgs, err := scanner.detectWithStat(fakeStat("/tmp/custom.sock"), runtimeHosts)
	require.Empty(t, cfgs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supported runtimes")
}

func TestDetectRuntimeCustomSocketPathByToken(t *testing.T) {
	t.Parallel()

	tests := []runtimeCase{
		{
			name:    "rootless podman",
			socket:  "/run/user/1001/podman/podman.sock",
			runtime: "podman",
		},
		{
			name:    "custom mounted containerd",
			socket:  "/mnt/custom/runtime/containerd.sock",
			runtime: "containerd",
			cri:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := s{opts: opts{criSockets: []string{tt.socket}}}
			cfgs, err := scanner.detectWithStat(
				fakeStat(tt.socket),
				runtimeHosts,
			)
			require.NoError(t, err)
			require.Len(t, cfgs, 1)
			assert.Equal(t, tt.runtime, cfgs[0].name)
			assert.Equal(t, tt.cri, cfgs[0].cri)
			assert.Equal(t, "unix://"+tt.socket, cfgs[0].host)
		})
	}
}

func TestDetectRuntimePriority(t *testing.T) {
	t.Parallel()

	hosts := []runtimeHost{
		{name: "docker", hosts: []string{"unix:///run/docker.sock"}},
		{
			name:  "containerd",
			cri:   true,
			hosts: []string{"unix:///run/containerd.sock"},
		},
	}
	scanner := s{}
	cfgs, err := scanner.detectWithStat(
		fakeStat("/run/docker.sock", "/run/containerd.sock"),
		hosts,
	)
	require.NoError(t, err)
	require.Len(t, cfgs, 2)
	assert.Equal(t, "docker", cfgs[0].name)
	assert.False(t, cfgs[0].cri)
	assert.Equal(t, "containerd", cfgs[1].name)
	assert.True(t, cfgs[1].cri)
}

func TestDetectRuntimeAllSocketsPerRuntime(t *testing.T) {
	t.Parallel()

	hosts := []runtimeHost{
		{
			name: "docker",
			hosts: []string{
				"unix:///run/docker.sock",
				"unix:///run/docker-alt.sock",
			},
		},
		{
			name: "containerd",
			cri:  true,
			hosts: []string{
				"unix:///run/containerd.sock",
				"unix:///run/containerd-alt.sock",
			},
		},
	}

	scanner := s{}
	cfgs, err := scanner.detectWithStat(
		fakeStat(
			"/run/docker.sock",
			"/run/docker-alt.sock",
			"/run/containerd.sock",
			"/run/containerd-alt.sock",
		),
		hosts,
	)
	require.NoError(t, err)
	require.Len(t, cfgs, 4)
	assert.Equal(t, "unix:///run/docker.sock", cfgs[0].host)
	assert.Equal(t, "unix:///run/docker-alt.sock", cfgs[1].host)
	assert.Equal(t, "unix:///run/containerd.sock", cfgs[2].host)
	assert.Equal(t, "unix:///run/containerd-alt.sock", cfgs[3].host)
}

func TestDetectRuntimeNoneFound(t *testing.T) {
	t.Parallel()

	scanner := s{}
	_, err := scanner.detectWithStat(fakeStat(), runtimeHosts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no supported container runtime")
}

func TestDetectRuntimeWithSocketPartialFailure(t *testing.T) {
	t.Parallel()

	scanner := s{
		opts: opts{
			criSockets: []string{
				"/run/containerd/containerd.sock",
				"/tmp/missing.sock",
			},
		},
	}
	cfgs, err := scanner.detectWithStat(
		fakeStat("/run/containerd/containerd.sock"),
		runtimeHosts,
	)
	require.Error(t, err)
	require.Len(t, cfgs, 1)
	assert.Equal(t, "containerd", cfgs[0].name)
	assert.Contains(t, err.Error(), `stat socket "/tmp/missing.sock"`)
}

func TestDetectRuntimeWithSocketVarRunAlias(t *testing.T) {
	t.Parallel()

	scanner := s{opts: opts{criSockets: []string{"/var/run/docker.sock"}}}
	cfgs, err := scanner.detectWithStat(fakeStat("/var/run/docker.sock"), runtimeHosts)
	require.NoError(t, err)
	require.Len(t, cfgs, 1)
	assert.Equal(t, "docker", cfgs[0].name)
	assert.Equal(t, "unix:///var/run/docker.sock", cfgs[0].host)
}

func fakeStat(paths ...string) func(string) (os.FileInfo, error) {
	found := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		found[path] = struct{}{}
	}
	return func(path string) (os.FileInfo, error) {
		if _, ok := found[path]; ok {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
}

func TestNSExtract(t *testing.T) {
	t.Parallel()

	items := []*namespaceapi.Namespace{
		{Name: "k8s.io"},
		{Name: "default"},
		{Name: "k8s.io"},
		{Name: " "},
		nil,
	}
	ns := nsExtract(items)
	assert.Equal(t, []string{"default", "k8s.io"}, ns)
}

func TestPickRef(t *testing.T) {
	t.Parallel()

	assert.Equal(
		t,
		"repo@sha256:abc",
		pickRef([]string{"repo@sha256:abc"}, []string{"repo:latest"}, "fallback"),
	)
	assert.Equal(
		t,
		"repo:latest",
		pickRef(nil, []string{"repo:latest"}, "fallback"),
	)
	assert.Equal(t, "fallback", pickRef(nil, nil, "fallback"))
}
