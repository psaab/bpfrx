// #4422 (NAT reversed-range slice): a source- or destination-NAT rule's
// `match destination-port <low> to <high>` with high < low (a REVERSED range,
// e.g. `4000 to 3000`) was silently accepted at commit and MISCOMPILED. The
// parser (parseDNATPortList) required `high >= low` on the range branch and
// otherwise fell through, splitting the range into its two discrete endpoints:
// `4000 to 3000` matched ONLY ports {4000, 3000}, not the contiguous range the
// operator wrote — with no error and no warning. Both endpoints are valid ports
// (1..65535) so the #3446 out-of-range/non-numeric gate never fired.
//
// parseDNATPortList now records a reversed range on
// NATMatch.ReversedDestinationPortRanges and validateNATMatchDestinationPortStrict
// hard-rejects it at commit (naming the rule-set, rule, and the `low to high`
// token), downgrading to a warning on the tolerant load / peer-sync path
// (#1960 no-brick — the two endpoints still flow through so a config persisted
// before this gate installs exactly what it did before, just flagged).
//
// This file also PINS the sibling reversed-range rejections that were already
// handled, so a future regression that drops any of them fails:
//   - source-NAT pool `port range <low> to <high>` reversed
//     (validateSourceNATPoolStrict, #3906) — see also
//     compiler_nat_source_pool_port_3906_test.go.
//   - source-NAT pool `address <low> to <high>` reversed (expandAddressRange).
//
// RED-on-revert (the new fix): restore the `high >= low` guard fall-through in
// parseDNATPortList (drop the addReversed branches) and the reversed range
// splits into two ports, ReversedDestinationPortRanges stays empty, and the
// strict gate has nothing to reject — the reject cases compile clean.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.
package config

import (
	"strings"
	"testing"
)

// TestDNATMatchDestPortReversedRejected_4422 is the core RED-on-revert case for
// destination NAT: a reversed range hard-rejects at commit and warns on the
// lenient path.
func TestDNATMatchDestPortReversedRejected_4422(t *testing.T) {
	tree := dnatTree(t, "set security nat destination rule-set RS rule R1 match destination-port 4000 to 3000")
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted reversed DNAT destination-port range 4000 to 3000 (want reject)")
	}
	if !strings.Contains(err.Error(), "reversed range") {
		t.Fatalf("reject error %q does not name the reversed range", err.Error())
	}
	// Lenient path must NOT brick (downgrade to warning) and must compile.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("CompileConfigLenient rejected reversed range (want warn-and-compile): %v", lerr)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatalf("CompileConfigLenient produced no warning for reversed DNAT destination-port range")
	}
	// The reversed range must be recorded so the gate can see it (RED-on-revert:
	// without addReversed this list is empty and the range splits to two ports).
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if len(rule.Match.ReversedDestinationPortRanges) == 0 {
		t.Fatalf("ReversedDestinationPortRanges is empty — reversed range was not recorded")
	}
}

// TestSNATMatchDestPortReversedRejected_4422: the same gap and fix for a source
// NAT rule (parseDNATPortList feeds both the source and destination match path).
func TestSNATMatchDestPortReversedRejected_4422(t *testing.T) {
	tree := snatTree(t, "set security nat source rule-set RS rule R1 match destination-port 4000 to 3000")
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted reversed SNAT destination-port range 4000 to 3000 (want reject)")
	}
	if _, err := CompileConfigLenient(tree); err != nil {
		t.Fatalf("CompileConfigLenient rejected reversed SNAT range (want warn-and-compile): %v", err)
	}
}

// TestNATMatchDestPortReversedValidStillCompiles_4422 is the over-rejection
// guard: a forward range, a single-value range (low == high), a bracket list of
// discrete descending ports, and no range at all must all commit clean. Only a
// genuinely reversed `low to high` range is rejected.
func TestNATMatchDestPortReversedValidStillCompiles_4422(t *testing.T) {
	valid := []struct {
		name string
		cmd  string
	}{
		{"forward-range", "set security nat destination rule-set RS rule R1 match destination-port 3000 to 4000"},
		{"single-value-range", "set security nat destination rule-set RS rule R1 match destination-port 5000 to 5000"},
		// A bracket list of two descending discrete ports is NOT a range — it is
		// two explicit ports and must stay valid (the `to` keyword is what marks a
		// range, and there is none here).
		{"descending-bracket-list", "set security nat destination rule-set RS rule R1 match destination-port [ 4000 3000 ]"},
		{"single-port", "set security nat destination rule-set RS rule R1 match destination-port 8080"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			tree := dnatTree(t, tc.cmd)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig rejected VALID destination-port %q: %v", tc.cmd, err)
			}
		})
	}
}

// TestSNATPoolReversedRangesRejected_4422 pins the sibling reversed-range
// rejections that share the #4422 malformed-range class and were ALREADY
// handled — so a regression that drops either check fails here too. The
// source-NAT pool `port range` reversed reject is additionally covered by
// TestSourceNATPoolPortRangeRejectedAtCommit_3906.
func TestSNATPoolReversedRangesRejected_4422(t *testing.T) {
	cases := []struct {
		name string
		pool []string
	}{
		{"pool-address-reversed", []string{
			"set security nat source pool p1 address 10.0.0.20/32 to 10.0.0.10/32"}},
		{"pool-port-reversed", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 port range 6000 to 5000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := snatPoolTree(t, tc.pool...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted reversed SNAT pool range %q (want reject)", tc.name)
			}
		})
	}
}

// TestSNATPoolAddressForwardRangeStillCompiles_4422 is the over-rejection guard
// for the pool address range: a valid forward range (low <= high) still
// expands and compiles clean.
func TestSNATPoolAddressForwardRangeStillCompiles_4422(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 10.0.0.10/32 to 10.0.0.20/32")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected VALID forward pool address range: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil || len(pool.Addresses) != 11 {
		t.Fatalf("pool addresses = %v, want the 11 expanded IPs 10.0.0.10..20", pool)
	}
}
