// #5819: a source-NAT pool could configure BOTH `persistent-nat` and `port
// no-translation`, but the userspace dataplane's address-only (no-translation)
// branch BYPASSES the persistent-lease machinery. It selects a pool address by
// round-robin / global-hash and records each flow with no persistent lease — no
// permit-scope reuse, no inactivity timer. With global `source address-
// persistent` off, two flows that the configured persistent binding should pin
// to one public address can leave through DIFFERENT public addresses, and
// status reports no lease. A strict-valid config that CLAIMS persistence
// silently degrades to ordinary per-flow address-only NAT.
//
// Until address-only persistent leases are implemented (option 1 of #5819,
// deferred), the fix REJECTS the unsupported combination at strict commit and
// FAILS CLOSED on the tolerant/lenient load path (downgraded to a warning; the
// SNAT snapshot builder independently marks the pool unusable). This mirrors the
// #5859 static-nat `then inet` fail-closed pattern.
//
// RED-on-revert:
//   - remove validateSourceNATPersistentNoTranslationStrict (or its dispatch):
//     the combo compiles clean at strict commit and the lenient path emits no
//     warning — both RED.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath (snatPoolTree),
// never NewParser.
package config

import (
	"strings"
	"testing"
)

// TestSourceNATPersistentNoTranslationRejectedAtCommit_5819: a pool configuring
// both `persistent-nat` and `port no-translation` hard-rejects at strict commit
// with an error naming the pool and the unsupported combination. RED-on-revert
// (validator/dispatch removed): CompileConfig accepts it.
func TestSourceNATPersistentNoTranslationRejectedAtCommit_5819(t *testing.T) {
	cases := []struct {
		name string
		pool []string
	}{
		{"permit-any-remote-host", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat permit any-remote-host"}},
		{"permit-target-host", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat permit target-host"}},
		{"inactivity-timeout-only", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat inactivity-timeout 600"}},
		{"ipv6-pool", []string{
			"set security nat source pool p1 address 2001:db8::5/128",
			"set security nat source pool p1 address 2001:db8::6/128",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat permit any-remote-host"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := snatPoolTree(t, tc.pool...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted persistent-nat + port no-translation pool (want reject)")
			}
			msg := err.Error()
			for _, want := range []string{"p1", "persistent-nat", "no-translation"} {
				if !strings.Contains(msg, want) {
					t.Fatalf("reject error missing %q: %v", want, msg)
				}
			}
		})
	}
}

// TestSourceNATPersistentNoTranslationLenientFailClosed_5819: on the tolerant /
// lenient load path the combo does NOT hard-reject the whole config (a config
// persisted before this gate existed still boots — #1960), but the error is
// SURFACED as a warning rather than silently accepted. RED-on-revert: no
// warning is produced (the rule ships silently as address-only). The dataplane
// snapshot builder independently marks the pool unusable (fail closed); that is
// asserted in the pkg/dataplane/userspace suite.
func TestSourceNATPersistentNoTranslationLenientFailClosed_5819(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 address 203.0.113.6/32",
		"set security nat source pool p1 port no-translation",
		"set security nat source pool p1 persistent-nat permit any-remote-host")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-rejected the combo (want warn-and-compile): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no-translation") && strings.Contains(w, "persistent-nat") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient produced no persistent-nat + no-translation warning; warnings=%v", cfg.Warnings)
	}
	// The pool is still materialized (lenient load keeps the config), but its
	// unsupported nature is now surfaced, not silent.
	if cfg.Security.NAT.SourcePools["p1"] == nil {
		t.Fatalf("pool p1 missing from leniently-compiled config")
	}
}

// TestSourceNATPersistentNoTranslationNoFalseReject_5819: the gate must fire
// ONLY when BOTH modifiers are present. persistent-nat alone, port
// no-translation alone, and a plain pool must all still compile clean.
func TestSourceNATPersistentNoTranslationNoFalseReject_5819(t *testing.T) {
	t.Run("persistent-nat-without-no-translation", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 persistent-nat permit any-remote-host")
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected persistent-nat pool WITHOUT no-translation: %v", err)
		}
		pool := cfg.Security.NAT.SourcePools["p1"]
		if pool.PersistentNAT == nil {
			t.Fatalf("PersistentNAT lost")
		}
		if pool.PortNoTranslation {
			t.Fatalf("PortNoTranslation set unexpectedly")
		}
	})
	t.Run("no-translation-without-persistent-nat", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation")
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected no-translation pool WITHOUT persistent-nat: %v", err)
		}
		pool := cfg.Security.NAT.SourcePools["p1"]
		if !pool.PortNoTranslation {
			t.Fatalf("PortNoTranslation lost")
		}
		if pool.PersistentNAT != nil {
			t.Fatalf("PersistentNAT set unexpectedly")
		}
	})
	t.Run("plain-pool", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32")
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected plain pool: %v", err)
		}
	})
}
