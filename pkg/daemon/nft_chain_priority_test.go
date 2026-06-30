package daemon

import (
	"regexp"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// hookInputPriorityRe extracts the integer priority from a base-chain
// definition line of the form `type filter hook input priority <N>; ...`.
var hookInputPriorityRe = regexp.MustCompile(`type filter hook input priority (-?\d+);`)

// nftHookInputPriority parses the single `type filter hook input priority <N>`
// line out of an nft `-f -` payload and returns N. It fails the test if the
// chain is not a `hook input` filter base chain or the priority is missing —
// both are part of the #3364 invariant (the chains must stay base chains on the
// SAME hook, differing only in priority).
func nftHookInputPriority(t *testing.T, label, payload string) int {
	t.Helper()
	m := hookInputPriorityRe.FindStringSubmatch(payload)
	if m == nil {
		t.Fatalf("%s payload has no `type filter hook input priority <N>` base-chain line:\n%s", label, payload)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s payload priority %q is not an integer: %v", label, m[1], err)
	}
	return n
}

// TestNftLocalDeliveryChainsDistinctPriority is the #3364 RED-on-revert proof:
// the two daemon-generated local-delivery base chains (inet xpf_lo0 and inet
// xpf_hostinbound) both register at `type filter hook input`, so they MUST carry
// DISTINCT priorities or netfilter's inter-chain evaluation order between them is
// implementation-defined (which chain's reject/log/counter fires for a packet
// both match becomes order-dependent and can vary silently across nft/kernel
// versions). The ordering is also load-bearing: the operator's explicit lo0
// input filter (xpf_lo0) must evaluate BEFORE the zone host-inbound default-deny
// backstop (xpf_hostinbound) — the Junos lo0-filter-then-zone semantics — so
// lo0's priority must be STRICTLY LESS THAN host-inbound's.
//
// This goes RED the instant the two priorities are made equal again (the
// strictly-less-than assertion fails), or if either chain is moved off
// `hook input` (the parse fails), restoring the #3364 invariant as a test.
func TestNftLocalDeliveryChainsDistinctPriority(t *testing.T) {
	// lo0 payload: the chain header is emitted unconditionally, so a config with
	// no resolvable filter still renders the base-chain line.
	lo0Payload := buildLo0FilterPayload(&config.Config{}, "", "")
	lo0Pri := nftHookInputPriority(t, "lo0", lo0Payload)

	// host-inbound payload: likewise emits the base-chain header regardless of
	// views. Use a representative enforced config so the rendered table is the
	// real commit-time shape.
	views := buildAndCheckViews(t, hostInboundTestConfig())
	hiPayload := buildHostInboundFilterPayload(views)
	hiPri := nftHookInputPriority(t, "host-inbound", hiPayload)

	if lo0Pri == hiPri {
		t.Fatalf("xpf_lo0 and xpf_hostinbound share hook-input priority %d — #3364 "+
			"requires DISTINCT priorities so inter-chain evaluation order is "+
			"deterministic (equal priority => implementation-defined ordering)", lo0Pri)
	}
	if lo0Pri >= hiPri {
		t.Fatalf("xpf_lo0 priority %d must be STRICTLY LESS THAN xpf_hostinbound "+
			"priority %d (#3364): the explicit lo0 input filter must evaluate "+
			"BEFORE the zone host-inbound default-deny backstop "+
			"(Junos lo0-filter-then-zone ordering)", lo0Pri, hiPri)
	}

	// The rendered payload priorities must match the named constants that
	// document the invariant, so a future edit cannot silently desync the code
	// from the constants.
	if lo0Pri != nftLo0FilterPriority {
		t.Errorf("lo0 payload priority %d != nftLo0FilterPriority %d", lo0Pri, nftLo0FilterPriority)
	}
	if hiPri != nftHostInboundPriority {
		t.Errorf("host-inbound payload priority %d != nftHostInboundPriority %d", hiPri, nftHostInboundPriority)
	}
}

// TestNftLocalDeliveryPriorityConstantsOrdered guards the invariant at the
// constant level (independent of payload rendering): nftLo0FilterPriority must be
// strictly less than nftHostInboundPriority (#3364). Equalizing the two
// constants — the simplest way to reintroduce the bug — turns this RED directly.
func TestNftLocalDeliveryPriorityConstantsOrdered(t *testing.T) {
	if nftLo0FilterPriority >= nftHostInboundPriority {
		t.Fatalf("nftLo0FilterPriority (%d) must be < nftHostInboundPriority (%d): "+
			"the lo0 input filter must evaluate before the host-inbound backstop "+
			"and the two base chains must carry distinct hook-input priorities (#3364)",
			nftLo0FilterPriority, nftHostInboundPriority)
	}
}
