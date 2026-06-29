package config

import (
	"strings"
	"testing"
)

// Tests for #3374: a flat-set `then deny session-init` (or `session-close`)
// with NO accompanying `log` token collapses onto the deny node as
// Keys=["deny","session-init"]. recognizedCollapsedDenyToken accepts the bare
// sub-token positionally, so before this fix the collapsed form committed and
// applyCollapsedDenyModifiers silently wired session-init/session-close
// logging — syntax Junos rejects (session-init/session-close are sub-options
// of `log` only). #3374 rejects an orphaned session sub-token at commit
// (lenient-warn on the load/peer-sync path) while keeping the legitimate
// `then deny log session-init` (and the standalone `then log session-init`)
// forms working.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser. buildPolicyThenTree / findZonePairPolicy / findGlobalPolicy are
// shared with the #3141/#3114 tests in this package.

// TestPolicyThenDenyOrphanLogSubRejectedAtCommit is the fail-on-revert proof:
// a collapsed `then deny session-init`/`session-close` (no `log`) is
// hard-rejected at commit for both zone-pair and global scopes. Reverting the
// #3374 emitOrphanLogSub gate makes CompileConfig ACCEPT these (the bug), so
// every case here goes RED.
func TestPolicyThenDenyOrphanLogSubRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "zone-pair deny session-init (no log)",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web match source-address any",
				"set security policies from-zone trust to-zone untrust policy web match destination-address any",
				"set security policies from-zone trust to-zone untrust policy web match application any",
				"set security policies from-zone trust to-zone untrust policy web then deny session-init",
			},
			want: `from-zone trust to-zone untrust policy "web" then deny "session-init"`,
		},
		{
			name: "zone-pair deny session-close (no log)",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web match source-address any",
				"set security policies from-zone trust to-zone untrust policy web match destination-address any",
				"set security policies from-zone trust to-zone untrust policy web match application any",
				"set security policies from-zone trust to-zone untrust policy web then deny session-close",
			},
			want: `from-zone trust to-zone untrust policy "web" then deny "session-close"`,
		},
		{
			name: "zone-pair deny session-init session-close (no log)",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web match source-address any",
				"set security policies from-zone trust to-zone untrust policy web match destination-address any",
				"set security policies from-zone trust to-zone untrust policy web match application any",
				"set security policies from-zone trust to-zone untrust policy web then deny session-init session-close",
			},
			want: `from-zone trust to-zone untrust policy "web" then deny "session-init"`,
		},
		{
			name: "global deny session-init (no log)",
			cmds: []string{
				"set security policies global policy gd match source-address any",
				"set security policies global policy gd match destination-address any",
				"set security policies global policy gd match application any",
				"set security policies global policy gd then deny session-init",
			},
			want: `global policy "gd" then deny "session-init"`,
		},
		{
			// count LEADS, orphaned session-init TRAILS — the whole collapsed
			// tail is inspected and the orphan sub-token still fires even when a
			// legitimate `count` modifier precedes it.
			name: "zone-pair deny count session-init (no log)",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy web match source-address any",
				"set security policies from-zone trust to-zone untrust policy web match destination-address any",
				"set security policies from-zone trust to-zone untrust policy web match application any",
				"set security policies from-zone trust to-zone untrust policy web then deny count session-init",
			},
			want: `from-zone trust to-zone untrust policy "web" then deny "session-init"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildPolicyThenTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted orphaned then-deny log sub-token; want commit rejection (#3374)")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "#3374") {
				t.Fatalf("CompileConfig error = %q, want #3374 reference", err.Error())
			}
		})
	}
}

// TestPolicyThenDenyOrphanLogSubLenientWarns proves the tolerant
// load/peer-sync path (CompileConfigLenient) does NOT fail on an orphaned
// session sub-token — it compiles and records a #3374 warning so an
// already-persisted config still boots (#1960 fail-closed-on-load doctrine).
func TestPolicyThenDenyOrphanLogSubLenientWarns(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security policies from-zone trust to-zone untrust policy web then deny session-init",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on orphaned then-deny sub-token; want warn-and-boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3374") && strings.Contains(w, "session-init") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient warnings = %v, want a #3374 orphan-log-sub warning", cfg.Warnings)
	}
}

// TestPolicyThenDenyLogWithSessionSubStillCommits proves the #3374 gate does
// NOT regress the legitimate forms: a collapsed `then deny log session-init`
// (and session-close, and both) and the canonical separate-node
// `then deny` + `then log session-init` still commit and wire the log flags.
func TestPolicyThenDenyLogWithSessionSubStillCommits(t *testing.T) {
	t.Run("collapsed deny log session-init session-close", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy web match source-address any",
			"set security policies from-zone trust to-zone untrust policy web match destination-address any",
			"set security policies from-zone trust to-zone untrust policy web match application any",
			"set security policies from-zone trust to-zone untrust policy web then deny log session-init session-close",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected then deny log session-init session-close: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
		if p.Action != PolicyDeny {
			t.Fatalf("Action = %v, want PolicyDeny", p.Action)
		}
		if p.Log == nil || !p.Log.SessionInit || !p.Log.SessionClose {
			t.Fatalf("pol.Log both flags not wired: %+v (#3374 must not regress #3141)", p.Log)
		}
	})

	t.Run("separate-node deny + log session-init", func(t *testing.T) {
		tree := buildPolicyThenTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy web match source-address any",
			"set security policies from-zone trust to-zone untrust policy web match destination-address any",
			"set security policies from-zone trust to-zone untrust policy web match application any",
			"set security policies from-zone trust to-zone untrust policy web then deny",
			"set security policies from-zone trust to-zone untrust policy web then log session-init",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected separate-node deny + log session-init: %v", err)
		}
		p := findZonePairPolicy(t, cfg, "trust", "untrust", "web")
		if p.Log == nil || !p.Log.SessionInit {
			t.Fatalf("separate-node deny + log session-init not wired: %+v", p.Log)
		}
	})
}
