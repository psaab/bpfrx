package dataplane

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	legacyBPFManifestRepoRoot = "../.."
	legacyBPFManifestPath     = "../../docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md"
)

var retainedUserspaceShimManifestPaths = []string{
	"userspace-xdp/",
	"pkg/dataplane/userspace_xdp_bpfel.o",
	"pkg/dataplane/userspace_xdp_rust.go",
	"pkg/dataplane/build-userspace-xdp.sh",
	"test/xsk-repro/",
}

func TestLegacyBPFRemovalManifestCoversTrackedGeneratedArtifacts(t *testing.T) {
	t.Parallel()

	manifest := readLegacyBPFManifest(t)
	generated := gitTrackedFilesForLegacyBPFManifest(t,
		"pkg/dataplane/*_bpfel.go",
		"pkg/dataplane/*_bpfel.o",
		"pkg/dataplane/*_bpfeb.go",
		"pkg/dataplane/*_bpfeb.o",
	)

	var missing []string
	for _, rel := range generated {
		if isRetainedUserspaceShimManifestPath(rel) {
			continue
		}
		if !strings.Contains(manifest, "`"+rel+"`") {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("legacy generated artifacts missing from #1476 manifest: %v", missing)
	}
}

func TestLegacyBPFRemovalManifestKeepsRetainedShimOutOfDeleteScope(t *testing.T) {
	t.Parallel()

	manifest := readLegacyBPFManifest(t)
	deleteSection := markdownSectionForLegacyBPFManifest(t, manifest, "## Delete Manifest")
	retainSection := markdownSectionForLegacyBPFManifest(t, manifest, "## Retain Manifest")

	var deleteViolations []string
	var missingRetained []string
	for _, rel := range retainedUserspaceShimManifestPaths {
		if strings.Contains(deleteSection, rel) {
			deleteViolations = append(deleteViolations, rel)
		}
		if !strings.Contains(retainSection, "`"+rel+"`") {
			missingRetained = append(missingRetained, rel)
		}
	}
	if len(deleteViolations) > 0 || len(missingRetained) > 0 {
		sort.Strings(deleteViolations)
		sort.Strings(missingRetained)
		t.Fatalf(
			"retained userspace shim manifest drift\ndelete-scope violations: %v\nmissing retain entries: %v",
			deleteViolations,
			missingRetained,
		)
	}
}

func TestLegacyBPFRemovalManifestDocumentsDependencyOrder(t *testing.T) {
	t.Parallel()

	manifest := readLegacyBPFManifest(t)
	section := markdownSectionForLegacyBPFManifest(t, manifest, "## Dependency Order")
	wantOrder := []string{
		"#1494 canary",
		"#1493 loader split",
		"#1451 surface shrink",
		"#1476 deletion",
		"#1477 final evidence",
	}

	last := -1
	for _, token := range wantOrder {
		idx := strings.Index(section, token)
		if idx < 0 {
			t.Fatalf("#1476 manifest dependency order missing %q", token)
		}
		if idx <= last {
			t.Fatalf("#1476 manifest dependency order has %q out of order", token)
		}
		last = idx
	}
}

func readLegacyBPFManifest(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(legacyBPFManifestPath)
	if err != nil {
		t.Fatalf("read #1476 source-removal manifest: %v", err)
	}
	return string(data)
}

func gitTrackedFilesForLegacyBPFManifest(t *testing.T, patterns ...string) []string {
	t.Helper()

	args := append([]string{"ls-files", "--"}, patterns...)
	cmd := exec.Command("git", args...)
	cmd.Dir = legacyBPFManifestRepoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git ls-files %v: %v\n%s", patterns, err, out)
	}

	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		rel := strings.TrimSpace(line)
		if rel == "" {
			continue
		}
		files = append(files, filepath.ToSlash(rel))
	}
	sort.Strings(files)
	return files
}

func isRetainedUserspaceShimManifestPath(rel string) bool {
	for _, retained := range retainedUserspaceShimManifestPaths {
		if rel == strings.TrimSuffix(retained, "/") || strings.HasPrefix(rel, retained) {
			return true
		}
	}
	return false
}

func markdownSectionForLegacyBPFManifest(t *testing.T, text, heading string) string {
	t.Helper()

	lines := strings.Split(text, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == heading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("manifest section %q not found", heading)
	}

	end := len(lines)
	for i := start; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "## ") && line != heading {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}
