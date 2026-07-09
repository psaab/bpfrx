package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #4813: renderHostInboundMatches' outer loop only advances `i` from WITHIN
// each switch case body, and the ICMP/ICMPv6 case's inner accumulation loop
// only advances `i` when ms[i].ICMPType != nil. If the FIRST unconsumed
// entry has an ICMP/ICMPv6 Proto but a nil ICMPType, the inner loop runs
// zero iterations, `i` is never incremented for that outer iteration, and
// the outer loop spins forever on the same index. The documented SSOT
// invariant (config.L4Match doc comment: "nil ICMPType is not emitted for
// an ICMP proto") means no reachable caller hits this today — this test
// constructs the degenerate input directly, bypassing the invariant, to pin
// the defensive fix.
//
// FAIL-ON-REVERT: drop the `if len(types) == 0 { i++; continue }` guard in
// renderHostInboundMatches (daemon_nft.go) and this test hangs forever
// (verified via a bounded goroutine + timeout so the suite fails loudly
// with a diagnostic instead of hanging CI).

// renderWithTimeout runs renderHostInboundMatches on a separate goroutine
// and fails the test if it does not return within the deadline, rather than
// hanging the whole test binary on a genuine infinite loop.
func renderWithTimeout(t *testing.T, ms []config.L4Match, family string) []string {
	t.Helper()
	done := make(chan []string, 1)
	go func() {
		done <- renderHostInboundMatches(ms, family)
	}()
	select {
	case out := <-done:
		return out
	case <-time.After(2 * time.Second):
		t.Fatal("renderHostInboundMatches did not terminate within 2s " +
			"(infinite loop on a degenerate ICMP L4Match with a nil ICMPType, #4813)")
		return nil
	}
}

// TestRenderHostInboundMatches_DegenerateICMPTerminates is the primary
// regression: a single ICMP entry with a nil ICMPType as the very first
// (and only) unconsumed match must not hang the render.
func TestRenderHostInboundMatches_DegenerateICMPTerminates(t *testing.T) {
	ms := []config.L4Match{
		{Proto: config.HostInboundProtoICMP, ICMPType: nil},
	}
	out := renderWithTimeout(t, ms, "ip")
	// No valid ICMP type to render — the degenerate entry contributes
	// nothing rather than a malformed empty nft set ("icmp type {  }").
	if len(out) != 0 {
		t.Fatalf("degenerate-only input: got %v, want no rendered fragments", out)
	}
}

// TestRenderHostInboundMatches_DegenerateICMPv6Terminates is the ICMPv6
// sibling of the primary regression.
func TestRenderHostInboundMatches_DegenerateICMPv6Terminates(t *testing.T) {
	ms := []config.L4Match{
		{Proto: config.HostInboundProtoICMPv6, ICMPType: nil},
	}
	out := renderWithTimeout(t, ms, "ip6")
	if len(out) != 0 {
		t.Fatalf("degenerate-only input: got %v, want no rendered fragments", out)
	}
}

// TestRenderHostInboundMatches_DegenerateFollowedByValid pins that the
// guard both terminates AND does not corrupt a later, VALID entry: after
// skipping the degenerate first ICMP entry, a following TCP match still
// renders correctly.
func TestRenderHostInboundMatches_DegenerateFollowedByValid(t *testing.T) {
	tcpPort := uint16(22)
	ms := []config.L4Match{
		{Proto: config.HostInboundProtoICMP, ICMPType: nil},
		{Proto: config.HostInboundProtoTCP, Ports: []config.PortRange{{Lo: tcpPort, Hi: tcpPort}}},
	}
	out := renderWithTimeout(t, ms, "ip")
	if len(out) != 1 || out[0] != "tcp dport 22" {
		t.Fatalf("got %v, want exactly [\"tcp dport 22\"] (degenerate ICMP entry "+
			"skipped, valid TCP entry still rendered)", out)
	}
}

// TestRenderHostInboundMatches_ValidICMPTypesUnaffected is the positive
// control: a well-formed ICMP match list (every ICMPType non-nil, matching
// the config.HostInboundServiceMatch/hiICMP SSOT invariant) renders exactly
// as before the fix.
func TestRenderHostInboundMatches_ValidICMPTypesUnaffected(t *testing.T) {
	t8 := uint8(8)
	t3 := uint8(3)
	ms := []config.L4Match{
		{Proto: config.HostInboundProtoICMP, ICMPType: &t8},
		{Proto: config.HostInboundProtoICMP, ICMPType: &t3},
	}
	out := renderWithTimeout(t, ms, "ip")
	want := "icmp type { 8, 3 }"
	if len(out) != 1 || out[0] != want {
		t.Fatalf("got %v, want [%q]", out, want)
	}
}
