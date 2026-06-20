package config

import "testing"

// #2008 M9: `set security flow tcp-session no-sequence-check` must compile into
// TCPSessionConfig.NoSequenceCheck, mirroring the sibling no-syn-check /
// rst-invalidate-session presence flags. Uses the production ParseSetCommand +
// SetPath path (buildTree), never NewParser (flat-set gotcha in CLAUDE.md).
func TestCompileTCPSessionNoSequenceCheck(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow tcp-session no-sequence-check",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Security.Flow.TCPSession == nil {
		t.Fatal("TCPSession is nil")
	}
	if !cfg.Security.Flow.TCPSession.NoSequenceCheck {
		t.Fatal("NoSequenceCheck should be true")
	}
	// Default (flag absent) must stay false, and the sibling flags must be
	// independent of it.
	tree2 := buildTree(t, []string{
		"set security flow tcp-session no-syn-check",
	})
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig(default): %v", err)
	}
	if cfg2.Security.Flow.TCPSession.NoSequenceCheck {
		t.Fatal("NoSequenceCheck should be false when only no-syn-check is set")
	}
	if !cfg2.Security.Flow.TCPSession.NoSynCheck {
		t.Fatal("NoSynCheck should remain true (sibling flag unaffected)")
	}
}
