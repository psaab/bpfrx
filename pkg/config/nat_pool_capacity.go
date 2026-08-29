package config

import (
	"net/netip"
)

// Reportable source-NAT pool capacity (#7000).
//
// THE DEFECT THIS REPLACES. Six operator-facing surfaces each derived a pool's
// address cardinality as `len(pool.Addresses)` and multiplied it by the port
// range. That single expression is wrong in THREE directions at once:
//
//  1. It reports capacity for a pool the dataplane REFUSED. A pool whose member
//     the Rust expander cannot honour installs no allocator at all, so any
//     non-zero figure is confidently wrong — including on the
//     `natPoolTotalPorts` Prometheus gauge, where it becomes the denominator of
//     a utilisation alert for a pool that can allocate nothing.
//  2. It UNDER-reports a prefix member. The expander enumerates every address
//     in the prefix (`for i in 0..count` in `expand_pool_address`, network and
//     broadcast included), so a healthy `203.0.113.0/24` installs 256 addresses
//     and was reported as 1.
//  3. It MISSES the singular `address` field entirely. `SourceNATPoolMembers`
//     — the one answer to "what is in this pool", shared by the snapshot
//     builder and the unusable verdict — is `pool.Address` PLUS
//     `pool.Addresses`, so a pool configured with only the singular form
//     reported 0.
//
// WHY A SINGLE SOURCE RATHER THAN AN AGREEMENT TEST. Two derivations of "how
// many addresses does this pool have" can never legitimately differ: there is
// one pool and one expander. So the divergence is always a bug, and the fix is
// to remove the second derivation rather than to bind the two. `NATPoolTotalPorts`
// already single-sources the MULTIPLICATION; this single-sources the
// CARDINALITY that was being fed into it.
//
// WHAT ZERO MEANS, AND WHY THE REASON COMES BACK WITH IT. A capacity of 0 is
// ambiguous on its own — no such pool, a pool with no members, a pool whose
// member is malformed, and a pool refused by the #6812 aggregate budget all
// produce it, and they have different operator remedies. Returning the count
// ALONE would collapse them, so this returns the reason alongside it and
// callers that can render it do. That is the same three-states discipline
// #6982 applied to the NAT64 budget, one layer out.

// SourceNATPoolReportableAddresses returns the address cardinality an operator
// surface should report for a source-NAT pool, and the reason it is zero.
//
// A non-empty reason means the dataplane installs NO allocator for this pool,
// so the reportable capacity is 0 whatever its members say. An empty reason
// means the count is the EXPANDED cardinality the dataplane actually installs.
//
// `overBudget` is `SourceNATAggregateOverBudgetPools(cfg)`; pass nil when the
// caller has no config-wide view, which degrades to the definition verdict
// alone rather than silently reporting an over-budget pool as healthy.
func SourceNATPoolReportableAddresses(pool *NATPool, poolName string, overBudget map[string]bool) (int, string) {
	if reason := SourceNATPoolDisarmedReason(pool, poolName, overBudget); reason != "" {
		return 0, reason
	}
	total := 0
	for _, m := range SourceNATPoolMembers(pool) {
		total += sourceNATPoolMemberHosts(m)
	}
	return total, ""
}

// SourceNATPoolReportablePorts is the port-capacity form of the same verdict:
// the reportable address count multiplied through the shared
// `NATPoolTotalPorts` arithmetic, plus the reason it is zero.
//
// Callers used to compute `NATPoolTotalPorts(low, high, len(pool.Addresses))`.
// The multiplication was never the wrong part.
func SourceNATPoolReportablePorts(pool *NATPool, poolName string, portLow, portHigh int, overBudget map[string]bool) (int64, string) {
	addrs, reason := SourceNATPoolReportableAddresses(pool, poolName, overBudget)
	if reason != "" {
		return 0, reason
	}
	return NATPoolTotalPorts(portLow, portHigh, addrs), ""
}

// sourceNATPoolMemberHosts is the host count one pool member expands to,
// mirroring the Rust `expand_pool_address` exactly.
//
// A bare address is 1. A CIDR enumerates `1 << host_bits` addresses — the
// network and broadcast addresses INCLUDED, because the expander pushes every
// value in the range and the allocator indexes all of them. A member the
// expander would refuse returns 0, but callers reach this only after
// SourceNATPoolDisarmedReason has cleared the pool, so that is a backstop
// rather than a live path: an unhonourable member makes the WHOLE pool
// unusable (`invalid_pool`), never a silently narrowed one.
func sourceNATPoolMemberHosts(addr string) int {
	p, err := netip.ParsePrefix(addr)
	if err != nil {
		// Not CIDR: a bare address counts once (and only if it parses).
		if _, aerr := netip.ParseAddr(addr); aerr != nil {
			return 0
		}
		return 1
	}
	addrBits := 32
	if p.Addr().Is6() {
		addrBits = 128
	}
	hostBits := addrBits - p.Bits()
	// BEHAVIOURALLY REDUNDANT, AND SAID SO RATHER THAN CLAIMED OTHERWISE.
	//
	// This guard mirrors the Rust early-out, but unlike the Rust one it changes
	// no output here. Go DEFINES an over-wide shift as 0 (it is not UB and does
	// not wrap), and 0 fails the `count > MaxSourceNATPoolPrefixHosts` check
	// below exactly as a huge value does, so both paths return 0 for every
	// hostBits >= 64. Measured at 63 / 64 / 65 / 128.
	//
	// An earlier revision of this comment said the guard "prevents an over-wide
	// shift ... which would UNDER-count". That was FALSE: under-counting to 0 is
	// precisely the right answer for an over-cap prefix, which is why the cap
	// check already produces it. #7000's mutation cell M5 relaxed this bound to
	// `>= 1024` and the whole suite stayed GREEN — an unbound guard, correctly
	// reported as an escape rather than dressed up as a red.
	//
	// It is kept as a structural guard for a refactor that moves or widens the
	// cap check, and for parity with the Rust expander it mirrors — not because
	// it is load-bearing today. Do not write a test claiming it is; there is no
	// input that distinguishes the two.
	if hostBits < 0 || hostBits >= 64 {
		return 0
	}
	count := uint64(1) << uint(hostBits)
	if count > MaxSourceNATPoolPrefixHosts {
		return 0
	}
	return int(count)
}
