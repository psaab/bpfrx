package userspace

import (
	"log/slog"
	"sync/atomic"

	"github.com/vishvananda/netlink"
)

// napiProbeTargetSkips counts interfaces the NAPI bootstrap could not derive a
// probe target for, and therefore did NOT probe (#9019).
//
// The skip used to be entirely silent: no log, no counter, no status field, and
// `bootstrapNAPIQueuesLocked` simply `continue`d. That made it
// indistinguishable from "bootstrap succeeded on this interface", which is the
// property that made it expensive — this module's own header records that the
// three plausible self-heal paths (a poll(POLLIN) wake, the bind-time fill
// prime, SO_BUSY_POLL) were MEASURED not to cover a queue that never got a
// synthetic HW RX event, so a missed probe is not benign here.
//
// Exposed so the condition is visible to something other than the log, matching
// LearnedRouteCapHits.
var napiProbeTargetSkips atomic.Uint64

// NAPIProbeTargetSkips reports how many interface-probe attempts have been
// skipped for want of a derivable target since process start.
func NAPIProbeTargetSkips() uint64 { return napiProbeTargetSkips.Load() }

// deriveNAPIProbeTarget picks the address the NAPI bootstrap probes on one
// interface, from that link's routes and neighbours.
//
// #9019: both lookups used to be IPv4-ONLY — `netlink.RouteList(link,
// FAMILY_V4)` and `netlink.NeighList(idx, FAMILY_V4)`, each additionally
// filtered through `.To4() != nil`. An interface with no v4 gateway route and
// no v4 neighbour was skipped unconditionally, which is a v6-only segment
// ALWAYS, and plausibly a cold-boot LAN segment where the firewall itself is
// the gateway (no gateway route on that link, empty neighbour table).
//
// ORDER IS PART OF THE CONTRACT. IPv4 is still consulted first, and within a
// family a gateway still outranks a neighbour, so an interface that derived a
// target before this change derives the SAME target now. The v6 arms are
// reached only where the old code had already given up and returned nothing —
// this widens the set of interfaces that get probed and changes the target for
// none of them.
//
// Pure by construction: the netlink calls stay at the call site and their
// results are passed in. That is what lets a cell drive the v6-only case and
// the v4 case in the SAME run, so "the v6 path does not fire" is observed
// against a v4 path that demonstrably does — rather than against a harness that
// was never wired up.
func deriveNAPIProbeTarget(routes []netlink.Route, neighs []netlink.Neigh) string {
	// 1. IPv4 gateway (the pre-#9019 first choice).
	for _, r := range routes {
		if r.Gw != nil && r.Gw.To4() != nil {
			return r.Gw.String()
		}
	}
	// 2. IPv4 neighbour (the pre-#9019 second choice).
	for _, n := range neighs {
		if n.IP != nil && n.IP.To4() != nil && n.HardwareAddr != nil &&
			n.State != netlink.NUD_FAILED {
			return n.IP.String()
		}
	}
	// 3. IPv6 gateway.
	//
	//    `To4() == nil` here is DEFENSIVE REDUNDANCY, not a load-bearing
	//    guard, and saying so is the honest version. Arm 1 already returns for
	//    any gateway with `To4() != nil`, so this loop cannot see a v4 gateway
	//    however it is written — a mutation dropping the `To4() == nil` clause
	//    SURVIVES the test suite, and that survival is correct rather than a
	//    coverage gap. What the clause actually buys is that the arm stays
	//    correct if the ordering above it ever changes; the ordering is what
	//    the #9019 table pins, and a mutation hoisting these v6 arms above the
	//    v4 ones DOES red it.
	//
	//    It is spelled `To4() == nil` rather than a length check because Go
	//    stores a v4 address in a 16-byte net.IP, so `len(ip) == 16` is true
	//    for v4-in-v6 as well — a length check would be wrong on the day the
	//    ordering changed, which is the only day either spelling matters.
	for _, r := range routes {
		if r.Gw != nil && r.Gw.To4() == nil && r.Gw.To16() != nil {
			return r.Gw.String()
		}
	}
	// 4. IPv6 neighbour. Same NUD_FAILED exclusion as the v4 arm: a failed
	//    entry names an address that did not answer, so probing it re-probes a
	//    known-dead neighbour.
	for _, n := range neighs {
		if n.IP != nil && n.IP.To4() == nil && n.IP.To16() != nil &&
			n.HardwareAddr != nil && n.State != netlink.NUD_FAILED {
			return n.IP.String()
		}
	}
	return ""
}

// noteNAPIProbeTargetSkip records that an interface could not be probed.
//
// Deliberately NOT a silent `continue`. The counter is the durable half — a log
// line is lost to rotation and cannot be asserted on — and the log names the
// interface so an operator has somewhere to look.
func noteNAPIProbeTargetSkip(linuxName, reason string) {
	napiProbeTargetSkips.Add(1)
	slog.Warn("napi bootstrap: interface NOT probed; its queues may stay cold "+
		"(no synthetic HW RX event). The XSK liveness gate is box-wide, so a live "+
		"queue elsewhere still reports this box healthy",
		"interface", linuxName, "reason", reason,
		"skips_total", napiProbeTargetSkips.Load())
}
