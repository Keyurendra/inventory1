package agentless

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Resolver struct {
	kind       StoreKind
	dataRoot   string
	mountpoint string
	cache      *mountCache
	containerd *offlineContainerdStore
}

func NewResolver(rootfs, mountpoint, dataRoot string, containers []Container) (*Resolver, error) {
	kind, containerd, err := detectStore(rootfs, dataRoot, containers)
	if err != nil {
		return nil, err
	}
	return &Resolver{
		kind:       kind,
		dataRoot:   dataRoot,
		mountpoint: mountpoint,
		cache:      newMountCache(),
		containerd: containerd,
	}, nil
}

func (r *Resolver) Kind() StoreKind {
	return r.kind
}

func (r *Resolver) Cleanup() error {
	if r.cache == nil {
		return nil
	}
	return r.cache.cleanup()
}

func (r *Resolver) Reconstruct(c Container) (string, ImageMeta, error) {
	switch r.kind {
	case StoreOverlay2:
		id := strings.TrimSpace(c.ImageID)
		if id == "" {
			id = digestOf(c.Image)
		}
		if strings.TrimSpace(id) == "" {
			return "", ImageMeta{}, errors.New("overlay2 image id is missing")
		}
		lower, cfg, err := overlay2LowerDirs(r.dataRoot, id)
		if err != nil {
			return "", ImageMeta{}, err
		}
		key := sanitizeImageKey(id)
		at, err := r.cache.ensure(key, func() (*overlayMount, error) {
			return mountOverlayLowerDirs(r.mountpoint, key, lower)
		})
		if err != nil {
			return "", ImageMeta{}, err
		}
		meta := ImageMeta{
			ImageRef:    imageRef(c),
			ImageID:     id,
			HasConfig:   true,
			ImageConfig: cfg,
		}
		for _, d := range cfg.RootFS.DiffIDs {
			meta.DiffIDs = append(meta.DiffIDs, d.String())
		}
		meta.RepoTags, meta.RepoDigests = refsFromImage(meta.ImageRef)
		return at, meta, nil
	case StoreDockerContainer, StoreSystemContainer:
		return r.containerd.reconstruct(r.mountpoint, c, r.cache)
	default:
		return "", ImageMeta{}, fmt.Errorf("unsupported store %q", r.kind)
	}
}

type storeCandidate struct {
	kind       StoreKind
	containerd *offlineContainerdStore
}

type scoredStoreCandidate struct {
	candidate storeCandidate
	count     int
}

func detectStore(rootfs, dataRoot string, cts []Container) (StoreKind, *offlineContainerdStore, error) {
	drivers := make(map[string]struct{})
	for _, c := range cts {
		name := strings.TrimSpace(c.GraphDriver)
		if name == "" {
			continue
		}
		drivers[name] = struct{}{}
	}

	if len(drivers) > 0 {
		if len(drivers) > 1 {
			return "", nil, errors.New("ambiguous storage driver; mixed GraphDriver values")
		}
		var d string
		for k := range drivers {
			d = k
		}
		layerdb := filepath.Join(dataRoot, "image", d, "layerdb")
		if !isDir(layerdb) {
			return "", nil, errors.New("GraphDriver specified but layerdb missing")
		}
		if d != "overlay2" {
			return "", nil, fmt.Errorf("unsupported GraphDriver %q in agentless mode", d)
		}
		return StoreOverlay2, nil, nil
	}

	var candidates []storeCandidate
	layerdb := filepath.Join(dataRoot, "image", "overlay2", "layerdb")
	if isDir(layerdb) && isDir(filepath.Join(dataRoot, "overlay2")) {
		candidates = append(candidates, storeCandidate{kind: StoreOverlay2})
	}

	dMeta := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.metadata.v1.bolt", "meta.db")
	dContent := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.content.v1.content")
	dSnapDB := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.snapshotter.v1.overlayfs", "metadata.db")
	dSnaps := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	if isFile(dMeta) && isDir(dContent) {
		st, err := newOfflineContainerdStore(dMeta, dContent, dSnapDB, dSnaps)
		if err == nil {
			candidates = append(candidates, storeCandidate{
				kind:       StoreDockerContainer,
				containerd: st,
			})
		}
	}

	sMeta := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.metadata.v1.bolt", "meta.db")
	sContent := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.content.v1.content")
	sSnapDB := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.snapshotter.v1.overlayfs", "metadata.db")
	sSnaps := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	if isFile(sMeta) && isDir(sContent) {
		st, err := newOfflineContainerdStore(sMeta, sContent, sSnapDB, sSnaps)
		if err == nil {
			candidates = append(candidates, storeCandidate{
				kind:       StoreSystemContainer,
				containerd: st,
			})
		}
	}

	if len(candidates) == 0 {
		return "", nil, errors.New("no container image store evidence")
	}

	var ranked []scoredStoreCandidate
	var scoreParts []string
	for _, candidate := range candidates {
		n := 0
		switch candidate.kind {
		case StoreOverlay2:
			n = overlay2ResolutionCount(dataRoot, cts)
		case StoreDockerContainer, StoreSystemContainer:
			n = candidate.containerd.resolutionCount(cts)
		}
		scoreParts = append(scoreParts, fmt.Sprintf("%s=%d", candidate.kind, n))
		if n > 0 {
			ranked = append(ranked, scoredStoreCandidate{
				candidate: candidate,
				count:     n,
			})
		}
	}

	if len(ranked) == 0 {
		return "", nil, fmt.Errorf(
			"no image store can resolve running images (%s)",
			strings.Join(scoreParts, ", "),
		)
	}

	best := ranked[0]
	ties := 1
	for _, item := range ranked[1:] {
		if item.count > best.count {
			best = item
			ties = 1
			continue
		}
		if item.count == best.count {
			ties++
		}
	}
	if ties > 1 {
		return "", nil, errors.New("ambiguous storage driver; multiple stores match running images")
	}
	return best.candidate.kind, best.candidate.containerd, nil
}

func overlay2ResolutionCount(dataRoot string, cts []Container) int {
	var count int
	seen := make(map[string]struct{})
	for _, c := range cts {
		k := keyOf(c)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}

		id := strings.TrimSpace(c.ImageID)
		if id == "" {
			id = digestOf(c.Image)
		}
		if _, err := overlay2ConfigPath(dataRoot, id); err == nil {
			count++
		}
	}
	return count
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.IsDir()
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}
