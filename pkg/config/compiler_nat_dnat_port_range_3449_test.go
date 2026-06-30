package config

import "testing"

// #3449: parseDNATPortList expanded a `destination-port low to high` range with
// an unbounded `for p := low; p <= high` over operator-supplied endpoints. A
// huge/garbage range (e.g. `destination-port 1 to 1000000`) allocated a million
// ints at COMPILE time — a control-plane OOM that fired BEFORE the strict commit
// gate (#3446) could reject the out-of-range endpoint. appendDNATPortRange now
// bounds the expansion to the valid 1..65535 port space: an out-of-range
// endpoint is NOT expanded, both endpoints are recorded verbatim, and the strict
// gate still rejects the bad value (fail-closed).
//
// RED-on-revert: restore the unbounded `for p := low; p <= high` loop and the
// DestinationPorts list balloons to ~1e6 entries, failing the bound assert.

func TestParseDNATPortRangeOverLargeNotExpanded_3449(t *testing.T) {
	// 1000000 is out of the 1..65535 port space, so the range must NOT expand.
	tree := dnatTree(t, "set security nat destination rule-set RS rule R1 match destination-port 1 to 1000000")

	// Strict commit must still reject the out-of-range endpoint (#3446 preserved).
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted destination-port 1 to 1000000 (want reject)")
	}

	// Lenient load must not brick and must keep the port list BOUNDED — the
	// out-of-range range is recorded as its two endpoints, not expanded.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected over-large range (want warn-and-compile): %v", err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if len(rule.Match.DestinationPorts) > 2 {
		t.Fatalf("DestinationPorts has %d entries — the over-large range was expanded per port (want <= 2, the bounded endpoints)", len(rule.Match.DestinationPorts))
	}
	// The out-of-range value must survive so the strict gate can see it.
	found := false
	for _, p := range rule.Match.DestinationPorts {
		if p == 1000000 {
			found = true
		}
	}
	if !found {
		t.Fatalf("DestinationPorts = %v, want it to contain the out-of-range endpoint 1000000 for the strict gate", rule.Match.DestinationPorts)
	}
}

func TestParseDNATPortRangeInRangeStillExpands_3449(t *testing.T) {
	// A valid in-range range expands to its concrete ports (bounded <= 65535)
	// and commits clean — the bound must not break legitimate ranges.
	tree := dnatTree(t, "set security nat destination rule-set RS rule R1 match destination-port 20000 to 20003")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid in-range range: %v", err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if len(rule.Match.DestinationPorts) != 4 {
		t.Fatalf("DestinationPorts = %v, want the 4 ports 20000..20003", rule.Match.DestinationPorts)
	}
}
