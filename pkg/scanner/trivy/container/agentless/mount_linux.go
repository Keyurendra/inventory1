//go:build linux

package agentless

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func cleanupOverlayMount(m *overlayMount) error {
	if m == nil {
		return nil
	}
	err := unix.Unmount(m.merged, unix.MNT_DETACH)
	ignored := errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM)
	ignored = ignored || errors.Is(err, unix.ENOENT)
	if err != nil && !ignored {
		return fmt.Errorf("unmount %q: %w", m.merged, err)
	}
	if err := os.RemoveAll(m.root); err != nil {
		return fmt.Errorf("remove temp root %q: %w", m.root, err)
	}
	return nil
}

func mountOverlayLowerDirs(mountpoint, imageKey string, lower []string) (*overlayMount, error) {
	if len(lower) == 0 {
		return nil, errors.New("overlay lowerdir list is empty")
	}

	root := filepath.Join("/tmp", mountKeyFromPath(mountpoint), imageKey)
	upper := filepath.Join(root, "upper")
	work := filepath.Join(root, "work")
	merged := filepath.Join(root, "merged")

	if err := os.MkdirAll(upper, 0o755); err != nil {
		return nil, fmt.Errorf("create upperdir: %w", err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}
	if err := os.MkdirAll(merged, 0o755); err != nil {
		return nil, fmt.Errorf("create mergeddir: %w", err)
	}

	opts := strings.Join([]string{
		"lowerdir=" + strings.Join(lower, ":"),
		"upperdir=" + upper,
		"workdir=" + work,
	}, ",")
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("mount overlay for image %q: %w", imageKey, err)
	}
	return &overlayMount{root: root, merged: merged}, nil
}
