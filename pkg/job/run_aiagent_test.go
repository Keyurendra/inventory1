package job

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/accuknox/omniscan/pkg/scanner/aiagent"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
)

func TestAIAgentDetectionsBelongToVMRootfsOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "codex.exe"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	catalog := &aiagent.Catalog{Agents: []aiagent.Agent{{
		ID:        "codex",
		Platforms: []string{"windows"},
		Installations: []aiagent.Installation{{Signals: aiagent.Signals{
			Executables: []string{"codex"},
		}}},
	}}}

	image := &trivy.Result{ArtifactType: "container_image"}
	enrichAIAgentDetections(image, catalog, []string{root}, "windows")
	if image.AIAgentDetections != nil {
		t.Fatalf("host detections attached to a container image: %+v", image.AIAgentDetections)
	}

	rootfs := &trivy.Result{ArtifactType: "rootfs"}
	enrichAIAgentDetections(rootfs, catalog, []string{root}, "windows")
	if rootfs.AIAgentDetections == nil || len(*rootfs.AIAgentDetections) != 1 {
		t.Fatalf("VM rootfs detection missing: %+v", rootfs.AIAgentDetections)
	}

	empty := &trivy.Result{ArtifactType: "rootfs"}
	enrichAIAgentDetections(empty, &aiagent.Catalog{}, []string{root}, "windows")
	if empty.AIAgentDetections == nil || len(*empty.AIAgentDetections) != 0 {
		t.Fatalf("successful empty discovery is not explicit: %+v", empty)
	}
}
