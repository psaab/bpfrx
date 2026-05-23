package dataplane

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

var legacyBPFManifestCodeSpanRE = regexp.MustCompile("`([^`]+)`")

func TestLegacyBPFRemovalManifestCoversTrackedGeneratedArtifacts(t *testing.T) {
	t.Parallel()

	manifest := readLegacyBPFManifest(t)
	deletePaths := markdownPathSetForLegacyBPFManifest(
		t,
		markdownSectionForLegacyBPFManifest(t, manifest, "## Delete Manifest"),
	)
	retainPaths := markdownPathSetForLegacyBPFManifest(
		t,
		markdownSectionForLegacyBPFManifest(t, manifest, "## Retain Manifest"),
	)
	generated := gitTrackedFilesForLegacyBPFManifest(t,
		"pkg/dataplane/*_bpfel.go",
		"pkg/dataplane/*_bpfel.o",
		"pkg/dataplane/*_bpfeb.go",
		"pkg/dataplane/*_bpfeb.o",
	)

	var missing []string
	var wronglyRetained []string
	for _, rel := range generated {
		if isRetainedUserspaceShimManifestPath(rel) {
			continue
		}
		if !deletePaths[rel] {
			missing = append(missing, rel)
		}
		if retainPaths[rel] {
			wronglyRetained = append(wronglyRetained, rel)
		}
	}
	if len(missing) > 0 || len(wronglyRetained) > 0 {
		sort.Strings(missing)
		sort.Strings(wronglyRetained)
		t.Fatalf(
			"legacy generated artifact manifest drift\nmissing from delete section: %v\nwrongly retained: %v",
			missing,
			wronglyRetained,
		)
	}
}

func TestLegacyBPFRemovalManifestCoversTrackedBPFSourceTree(t *testing.T) {
	t.Parallel()

	manifest := readLegacyBPFManifest(t)
	deletePaths := markdownPathSetForLegacyBPFManifest(
		t,
		markdownSectionForLegacyBPFManifest(t, manifest, "## Delete Manifest"),
	)
	retainPaths := markdownPathSetForLegacyBPFManifest(
		t,
		markdownSectionForLegacyBPFManifest(t, manifest, "## Retain Manifest"),
	)
	tracked := gitTrackedFilesForLegacyBPFManifest(t, "bpf/**")

	var missing []string
	var doubleListed []string
	for _, rel := range tracked {
		inDelete := deletePaths[rel]
		inRetain := retainPaths[rel]
		switch {
		case !inDelete && !inRetain:
			missing = append(missing, rel)
		case inDelete && inRetain:
			doubleListed = append(doubleListed, rel)
		}
	}
	if len(missing) > 0 || len(doubleListed) > 0 {
		sort.Strings(missing)
		sort.Strings(doubleListed)
		t.Fatalf(
			"tracked bpf/ source tree manifest drift\nmissing entries: %v\ndouble-listed entries: %v",
			missing,
			doubleListed,
		)
	}
}

func TestLegacyBPFRemovalManifestEntriesResolveToTrackedFiles(t *testing.T) {
	t.Parallel()

	manifest := readLegacyBPFManifest(t)
	tracked := stringSet(gitTrackedFilesForLegacyBPFManifest(t))

	sections := map[string]string{
		"delete": markdownSectionForLegacyBPFManifest(t, manifest, "## Delete Manifest"),
		"retain": markdownSectionForLegacyBPFManifest(t, manifest, "## Retain Manifest"),
	}

	var missing []string
	for name, section := range sections {
		for rel := range markdownPathSetForLegacyBPFManifest(t, section) {
			if !manifestPathExistsInTrackedFiles(rel, tracked) {
				missing = append(missing, name+":"+rel)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("#1476 manifest references paths not tracked at HEAD: %v", missing)
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
		"#1494",
		"#1493",
		"#1451",
		"#1476",
		"#1477",
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

	requireGitForLegacyBPFManifest(t)
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

func requireGitForLegacyBPFManifest(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not available; skipping #1476 manifest canary: %v", err)
	}
	if _, err := os.Stat(filepath.Join(legacyBPFManifestRepoRoot, ".git")); err != nil {
		t.Skipf("not a git checkout; skipping #1476 manifest canary: %v", err)
	}
}

func markdownPathSetForLegacyBPFManifest(t *testing.T, section string) map[string]bool {
	t.Helper()

	paths := map[string]bool{}
	for _, match := range legacyBPFManifestCodeSpanRE.FindAllStringSubmatch(section, -1) {
		value := strings.TrimSpace(match[1])
		if legacyBPFManifestPathCandidate(value) {
			paths[value] = true
		}
	}
	return paths
}

func legacyBPFManifestPathCandidate(value string) bool {
	if value == "" || strings.ContainsAny(value, "* ") {
		return false
	}
	switch {
	case value == "Makefile":
		return true
	case strings.HasPrefix(value, "bpf/"):
		return true
	case strings.HasPrefix(value, "pkg/dataplane/"):
		return true
	case strings.HasPrefix(value, "userspace-xdp/"):
		return true
	case strings.HasPrefix(value, "test/xsk-repro/"):
		return true
	default:
		return false
	}
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func manifestPathExistsInTrackedFiles(rel string, tracked map[string]bool) bool {
	if strings.HasSuffix(rel, "/") {
		for path := range tracked {
			if strings.HasPrefix(path, rel) {
				return true
			}
		}
		return false
	}
	return tracked[rel]
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
