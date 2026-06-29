package config

import (
	"strings"
	"testing"
)

// #3422: `security flow traceoptions` copied both `flag <name>` tokens and
// `packet-filter <n> { source-prefix / destination-prefix <prefix> }` values
// verbatim with no validation, and the runtime then failed silently in two
// directions — an unparseable filter prefix was dropped (every-filter-invalid
// -> trace EVERYTHING, M01), and an unimplemented flag suppressed the defaults
// (matchFlags never matches -> trace NOTHING while reporting enabled, M02).
// validateFlowTraceFlagsAndFiltersAST now hard-rejects both at strict commit /
// commit-check.
//
// FAIL-ON-REVERT: delete the validateFlowTraceFlagsAndFiltersAST call in
// compiler.go (or neuter the validator) and every reject subtest below goes
// GREEN, which is exactly the regression this guards.
func TestFlowTraceFilterFailsCommit(t *testing.T) {
	cases := []struct {
		name string
		set  []string
		want string // substring the error must name
	}{
		{
			name: "invalid-source-prefix",
			set: []string{
				"set security flow traceoptions packet-filter pf1 source-prefix 10.0.0.999/32",
			},
			want: "10.0.0.999/32",
		},
		{
			name: "invalid-destination-prefix",
			set: []string{
				"set security flow traceoptions packet-filter pf1 destination-prefix 10.0.0.0/40",
			},
			want: "10.0.0.0/40",
		},
		{
			name: "bare-address-not-prefix",
			set: []string{
				"set security flow traceoptions packet-filter pf1 source-prefix 10.0.0.1",
			},
			want: "10.0.0.1",
		},
		{
			name: "empty-source-prefix",
			set: []string{
				`set security flow traceoptions packet-filter pf1 source-prefix ""`,
			},
			want: "source-prefix",
		},
		{
			name: "empty-destination-prefix",
			set: []string{
				`set security flow traceoptions packet-filter pf1 destination-prefix ""`,
			},
			want: "destination-prefix",
		},
		{
			name: "one-valid-one-invalid",
			set: []string{
				"set security flow traceoptions packet-filter pf1 source-prefix 10.0.1.0/24",
				"set security flow traceoptions packet-filter pf2 source-prefix bogus/24",
			},
			want: "bogus/24",
		},
		{
			name: "unknown-flag",
			set: []string{
				"set security flow traceoptions flag sesson",
			},
			want: "sesson",
		},
		{
			name: "mixed-valid-and-unknown-flag",
			set: []string{
				"set security flow traceoptions flag session",
				"set security flow traceoptions flag bogus-flag",
			},
			want: "bogus-flag",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.set)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected strict commit to reject the traceoptions filter/flag, got nil error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the offending value %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "traceoptions") {
				t.Fatalf("error %q does not name the traceoptions path", err.Error())
			}
		})
	}
}

// TestFlowTraceFilterValidCommits is the anti-over-reject guard: a legitimate
// filter (parseable prefixes, recognized protocol) and the implemented flags
// must still commit cleanly.
func TestFlowTraceFilterValidCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions file rt-flow.log",
		"set security flow traceoptions flag basic-datapath",
		"set security flow traceoptions packet-filter pf1 source-prefix 10.0.1.0/24",
		"set security flow traceoptions packet-filter pf1 destination-prefix 2001:db8::/32",
		"set security flow traceoptions packet-filter pf1 protocol tcp",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a valid traceoptions filter: %v", err)
	}
	to := cfg.Security.Flow.Traceoptions
	if to == nil {
		t.Fatalf("traceoptions not compiled")
	}
	if len(to.PacketFilters) != 1 || to.PacketFilters[0].SourcePrefix != "10.0.1.0/24" {
		t.Fatalf("packet filters = %+v, want one pf1 with source 10.0.1.0/24", to.PacketFilters)
	}
	if to.PacketFilters[0].DestinationPrefix != "2001:db8::/32" {
		t.Fatalf("dest prefix = %q, want 2001:db8::/32", to.PacketFilters[0].DestinationPrefix)
	}
	if len(to.Flags) != 1 || to.Flags[0] != "basic-datapath" {
		t.Fatalf("flags = %v, want [basic-datapath]", to.Flags)
	}
}

// TestFlowTraceFilterProtocolOnlyCommits is the #3422 BLOCKER anti-over-reject
// guard: a filter that legitimately OMITS its prefixes (protocol-only) must
// still commit on the strict path. The empty-prefix rejection is for a
// present-but-empty node only — an absent prefix is fine.
//
// FAIL-ON-REVERT: reject a filter with no prefix and this test fails.
func TestFlowTraceFilterProtocolOnlyCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions file rt-flow.log",
		"set security flow traceoptions packet-filter pf1 protocol tcp",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a protocol-only filter: %v", err)
	}
	to := cfg.Security.Flow.Traceoptions
	if to == nil || len(to.PacketFilters) != 1 {
		t.Fatalf("traceoptions filters = %+v, want one pf1", to)
	}
	if to.PacketFilters[0].InvalidPrefix {
		t.Fatalf("protocol-only filter wrongly marked InvalidPrefix (over-rejection)")
	}
	if to.PacketFilters[0].Protocol != "tcp" {
		t.Fatalf("protocol = %q, want tcp", to.PacketFilters[0].Protocol)
	}
}

// TestFlowTraceFilterEmptyPrefixLenient is the #3422 BLOCKER lenient backstop:
// a persisted / peer-synced `source-prefix ""` must NOT fail the boot (downgrade
// to a warning) but must compile to a filter marked InvalidPrefix so the runtime
// fails it closed (match-none) rather than tracing everything.
//
// FAIL-ON-REVERT: restore the `v == ""` skip in the validator and no warning is
// recorded; drop the compiler InvalidPrefix marking and the filter compiles as a
// match-everything filter.
func TestFlowTraceFilterEmptyPrefixLenient(t *testing.T) {
	tree := buildTree(t, []string{
		`set security flow traceoptions packet-filter pf1 source-prefix ""`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail on a persisted empty prefix: %v", err)
	}
	gotWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "source-prefix") && strings.Contains(w, "traceoptions") &&
			strings.Contains(w, "empty") {
			gotWarn = true
		}
	}
	if !gotWarn {
		t.Fatalf("lenient load did not warn about the empty prefix; warnings=%v", cfg.Warnings)
	}
	to := cfg.Security.Flow.Traceoptions
	if to == nil || len(to.PacketFilters) != 1 {
		t.Fatalf("traceoptions filters = %+v, want one pf1", to)
	}
	if !to.PacketFilters[0].InvalidPrefix {
		t.Fatalf("empty-prefix filter not marked InvalidPrefix; runtime would trace everything (#3422 BLOCKER)")
	}
}

// TestFlowTraceFilterSessionFlagCommits verifies the second implemented flag
// (session) is also accepted by the strict gate.
func TestFlowTraceFilterSessionFlagCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions flag session",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected the session flag: %v", err)
	}
}

// TestFlowTraceFilterLenientDowngrade verifies the load / peer-sync path
// downgrades a persisted invalid prefix / unknown flag to a warning instead of
// failing the boot (#1960 fail-closed-on-load class) — NewTraceWriter
// independently fails safe at runtime (invalid filter -> match-none, unknown
// flag -> dropped so defaults apply).
func TestFlowTraceFilterLenientDowngrade(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions packet-filter pf1 source-prefix 10.0.0.999/32",
		"set security flow traceoptions flag sesson",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail on persisted invalid filter/flag: %v", err)
	}
	wantPrefix, wantFlag := false, false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "10.0.0.999/32") && strings.Contains(w, "traceoptions") {
			wantPrefix = true
		}
		if strings.Contains(w, "sesson") && strings.Contains(w, "traceoptions") {
			wantFlag = true
		}
	}
	if !wantPrefix {
		t.Fatalf("lenient load did not record an invalid-prefix warning; warnings=%v", cfg.Warnings)
	}
	if !wantFlag {
		t.Fatalf("lenient load did not record an unknown-flag warning; warnings=%v", cfg.Warnings)
	}
}
