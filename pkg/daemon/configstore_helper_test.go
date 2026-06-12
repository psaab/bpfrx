package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// newConfigStore constructs a configstore.Store for tests, failing the
// test when the fail-closed constructor (#1893) reports an unusable
// config db.
func newConfigStore(t *testing.T, path string) *configstore.Store {
	t.Helper()
	s, err := configstore.New(path)
	if err != nil {
		t.Fatalf("configstore.New(%s): %v", path, err)
	}
	return s
}
