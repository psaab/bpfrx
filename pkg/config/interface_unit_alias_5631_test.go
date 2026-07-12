package config

import (
	"strings"
	"testing"
)

// #5631 (codex-review-181 M23): the interface compiler parsed the raw unit
// tokens `unit 00` and `unit 0` as two SEPARATE named instances and only
// canonicalized each spelling through strconv.Atoi AFTER — so the two aliases
// collided on the same `ifc.Units[0]` key. The later spelling REPLACED the
// prior unit (last-writer-wins for the firewall filter and the unit addresses),
// but the interface-level tunnel-address collection was append-only and
// ACCUMULATED the addresses of BOTH spellings. The observable filter + address
// ownership therefore flipped with config order, and a stale tunnel address
// from the spelling that lost the filter race survived — a fail-open on the
// interface's firewall filter. These tests pin the strict reject at commit
// (CompileConfig) and the lenient downgrade-to-warning on the tolerant load /
// peer-sync path (CompileConfigLenient).

// buildTreeFromSet (shared, ipsec_proposal_ref_test.go) builds a candidate
// ConfigTree from flat `set` commands the way configstore does — ParseSetCommand
// + SetPath, NOT NewParser (per CLAUDE.md the parser merges newlines and would
// collapse separate set lines into one node).

// unitAlias5631Base defines the two firewall filters and the interface-level
// tunnel used by the collision cases below.
func unitAlias5631Base() []string {
	return []string{
		"set firewall family inet filter F1 term t1 then accept",
		"set firewall family inet filter F2 term t1 then accept",
		"set interfaces gr-0/0/0 tunnel source 1.1.1.1",
		"set interfaces gr-0/0/0 tunnel destination 2.2.2.2",
	}
}

// unit "00" carries filter F1 + address 10.0.0.1/24; unit "0" carries filter F2
// + address 10.0.0.2/24. The two spellings name the SAME logical unit 0, so a
// correct compiler must resolve them identically regardless of the order the
// two set-line groups appear in.
func unitAlias5631Order(unit00First bool) []string {
	cmds := unitAlias5631Base()
	u00 := []string{
		"set interfaces gr-0/0/0 unit 00 family inet address 10.0.0.1/24",
		"set interfaces gr-0/0/0 unit 00 family inet filter input F1",
	}
	u0 := []string{
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.2/24",
		"set interfaces gr-0/0/0 unit 0 family inet filter input F2",
	}
	if unit00First {
		return append(cmds, append(u00, u0...)...)
	}
	return append(cmds, append(u0, u00...)...)
}

// RED-on-revert: on the pre-fix compiler BOTH orders compile WITHOUT error and
// yield DIFFERENT results — order `00,0` resolves the unit filter to F2 with
// tunnel addresses [10.0.0.1/24, 10.0.0.2/24]; the reverse resolves it to F1
// with the addresses in the opposite order. This test asserts the fixed
// behavior: both orders are REJECTED at strict commit with the SAME error
// (an order-independent, deterministic outcome). Reverting
// validateInterfaceUnitAliasCollisionsAST makes CompileConfig return nil here,
// so the `err == nil` guards fire — the test goes RED.
func TestInterfaceUnitAliasRejectedBothOrders_5631(t *testing.T) {
	treeA := buildTreeFromSet(t, unitAlias5631Order(true))  // 00 then 0
	treeB := buildTreeFromSet(t, unitAlias5631Order(false)) // 0 then 00

	_, errA := CompileConfig(treeA)
	_, errB := CompileConfig(treeB)

	if errA == nil {
		t.Fatal("CompileConfig(00,0): expected rejection of numeric unit-alias collision, got nil (order-dependent fail-open)")
	}
	if errB == nil {
		t.Fatal("CompileConfig(0,00): expected rejection of numeric unit-alias collision, got nil (order-dependent fail-open)")
	}

	// Deterministic / order-independent: the SAME rejection regardless of the
	// order the aliased spellings appear in.
	if errA.Error() != errB.Error() {
		t.Fatalf("rejection is order-dependent:\n 00,0: %v\n 0,00: %v", errA, errB)
	}

	for _, want := range []string{"gr-0/0/0", "#5631", "`unit 0`", "`unit 00`", "unit 0"} {
		if !strings.Contains(errA.Error(), want) {
			t.Fatalf("error missing %q: %v", want, errA)
		}
	}
}

// The lenient load / peer-sync path must NOT hard-fail — an already-persisted
// or peer-synced config an older binary silently accepted still has to boot —
// but it surfaces the collision as a warning (#1960 fail-closed-on-load class).
func TestInterfaceUnitAliasLenientWarns_5631(t *testing.T) {
	tree := buildTreeFromSet(t, unitAlias5631Order(true))

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: numeric unit-alias collision must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5631") && strings.Contains(w, "gr-0/0/0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #5631 unit-alias warning on the lenient path, got: %v", cfg.Warnings)
	}
}

// Common case guard: distinct logical units (0 and 1) under one interface are
// NOT aliases and must commit cleanly with their per-unit filters/addresses
// intact and both units' addresses collected onto the interface-level tunnel.
// This proves the gate does not false-positive and that non-colliding behavior
// is unchanged.
func TestInterfaceUnitAliasDistinctUnitsCommit_5631(t *testing.T) {
	cmds := append(unitAlias5631Base(),
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.2/24",
		"set interfaces gr-0/0/0 unit 0 family inet filter input F2",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.0.1.2/24",
		"set interfaces gr-0/0/0 unit 1 family inet filter input F1",
	)
	tree := buildTreeFromSet(t, cmds)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: distinct units must commit cleanly, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5631") {
			t.Fatalf("unexpected #5631 warning on a non-aliased config: %q", w)
		}
	}

	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		t.Fatal("interface gr-0/0/0 not compiled")
	}
	u0, u1 := ifc.Units[0], ifc.Units[1]
	if u0 == nil || u1 == nil {
		t.Fatalf("expected units 0 and 1, got units=%v", ifc.Units)
	}
	if u0.FilterInputV4 != "F2" {
		t.Fatalf("unit 0 filter = %q, want F2", u0.FilterInputV4)
	}
	if u1.FilterInputV4 != "F1" {
		t.Fatalf("unit 1 filter = %q, want F1", u1.FilterInputV4)
	}
	// Both units' addresses are collected onto the shared interface-level
	// tunnel (existing, unchanged behavior for non-colliding units).
	if ifc.Tunnel == nil {
		t.Fatal("expected interface-level tunnel")
	}
	joined := strings.Join(ifc.Tunnel.Addresses, ",")
	if !strings.Contains(joined, "10.0.0.2/24") || !strings.Contains(joined, "10.0.1.2/24") {
		t.Fatalf("tunnel addresses = %v, want both unit addresses", ifc.Tunnel.Addresses)
	}
}
