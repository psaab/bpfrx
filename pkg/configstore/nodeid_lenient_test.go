package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestLenientNodeIDMismatchWarnsNotRejects pins #4191-review Finding 2: the
// tolerant Load/SyncApply path must NOT hard-reject a node-id mismatch (that
// would blackout-boot the node / alarm-loop HA config sync, the #1960
// doctrine), but it MUST warn — a silent literal `chassis cluster node 0`
// reaching a node-1 box via config-sync causes a heartbeat-id collision +
// wrong FPC naming with no diagnostic. RED-on-revert: without the lenient
// warn, no "node identity mismatch" line is logged.
func TestLenientNodeIDMismatchWarnsNotRejects(t *testing.T) {
	// captureWarnLogs installs a mutex-guarded slog sink (syncBuffer): a
	// persistRetryLoop goroutine leaked from an earlier test races the read
	// of a raw buffer otherwise (#6446).
	buf := captureWarnLogs(t)

	s, err := New(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetNodeID(1) // this node is node 1

	// A config whose literal leaf says node 0 (as if copied from node 0's
	// config and pushed to node 1 by config-sync).
	conf := "chassis { cluster { cluster-id 1; node 0; } }\nsystem { host-name box; }"
	tree, errs := config.NewParser(conf).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}

	cfg, err := s.compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile MUST NOT reject a node-id mismatch (would brick the standby): %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a compiled config on the tolerant path")
	}
	if !strings.Contains(buf.String(), "node identity mismatch") {
		t.Errorf("expected a node-identity-mismatch warning on the lenient path, log = %q", buf.String())
	}
}
