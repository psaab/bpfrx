package cluster

import (
	"os"
	"strings"
	"testing"
)

func mustReadClusterFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// sourceContainsFlat searches with all whitespace collapsed, so a needle still
// matches when gofmt has wrapped the call across lines. A line-oriented search
// here would silently stop seeing the very statements these guards exist to
// pin the moment the surrounding code grows an indent level.
func sourceContainsFlat(src, needle string) bool {
	flat := strings.Join(strings.Fields(src), "")
	return strings.Contains(flat, strings.Join(strings.Fields(needle), ""))
}
