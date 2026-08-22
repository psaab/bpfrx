package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
)

// readGoFiles returns the contents of every non-test .go file directly under
// dir, keyed by base name.
func readGoFiles(dir string) (map[string]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out[n] = string(b)
	}
	return out, nil
}
