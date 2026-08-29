package upgrade

import (
	"fmt"
	"strings"
)

// kernel_beacon_target_7157.go — Gate 4's beacon TARGET ELIGIBILITY check
// (#7157, the #1930 remainder).
//
// THE DEFECT THIS CLOSES
//
// ForwardBeacon proves the candidate kernel forwards by pinging a target and
// treating a reply as proof. A reply proves that SOMETHING answered. It does
// not prove the packet ever left the box, and the gate had no way to tell the
// two apart.
//
// Measured on loss:xpf-userspace-fw0:
//
//	# ip route get 172.16.50.8          <- the box's OWN dataplane address
//	local 172.16.50.8 dev lo table local src 172.16.50.8
//	# ping -c 1 172.16.50.8
//	1 packets transmitted, 1 received, 0% packet loss, rtt 0.055 ms
//
// A ping to the box's own address is answered by the local stack over `lo` in
// 55 microseconds, with the dataplane in any state whatsoever. So
// XPF_KERNEL_BEACON_TARGET set to the box's own dataplane address makes Gate 4
// pass UNCONDITIONALLY — and ForwardBeacon's own guidance ("set
// XPF_KERNEL_BEACON_TARGET to a DATAPLANE-side target") is exactly what leads
// an operator to type it. The gate then promotes any candidate kernel that
// reaches the promote verb, which is the whole failure #1930's Gate 4 exists to
// prevent.
//
// The same hole admits the issue's original scenario: a target whose egress is
// the out-of-band MANAGEMENT interface proves the management path answered, not
// that the security dataplane forwards.
//
// THE CHECK
//
// Before pinging, resolve the target's EGRESS INTERFACE (`ip route get`) and
// require it to be one a transit packet could actually leave by. Three classes
// are refused, each with a named reason that reaches the durable last-roll
// record (KernelRunner.revert stamps the error text into KernelRollOutcome):
//
//	no route          the target is unreachable from this box. Measured on the
//	                  HA SECONDARY, where main's only default is
//	                  `blackhole default` and `ip route get` returns EINVAL for
//	                  every address — so this is not a hypothetical branch, it
//	                  is the steady state of the node an HA operator upgrades
//	                  FIRST.
//	dev lo            the target is local. The ping never leaves the box and
//	                  cannot fail, so a pass carries no information at all.
//	management iface  the probe would traverse the OOB management path, which a
//	                  candidate kernel can keep working while the dataplane
//	                  cannot forward a transit packet.
//
// This is an ELIGIBILITY check, not a transit witness. It cannot show that a
// packet crossed ingress AF_XDP -> filter/PBR -> policy -> session/NAT ->
// egress; that needs an external observer and stays open on #7157. What it does
// is remove the cases where the ping's success is guaranteed regardless of
// dataplane health, so that a pass is at least CAPABLE of being a failure.

// beaconRouteGet is the egress-interface resolver. A package var for the same
// reason as beaconPing and beaconDefaultGateway (#6607): it is the only other
// thing in the eligibility path that reaches outside the process, so without a
// seam every assertion about the code AFTER it is decided by the routing table
// of whatever machine runs the suite.
//
// `ip route get` selects the family from the address, so one form covers IPv4
// and IPv6 (verified against both on the loss cluster).
var beaconRouteGet = func(target string) (string, error) {
	return captureCmd("ip", "route", "get", target)
}

// parseDefaultRoute extracts the next-hop and egress device from
// `ip -4 route show default` output.
//
// SINGLE-SOURCED deliberately. This logic used to live inline in
// defaultGateway(), which shells out — so TestDefaultGatewayParseLogic pinned a
// COPY of the scan written inside the test, and a change to the production
// parse would have left it green. A test that re-implements its subject is not
// testing it. Both the production resolver and the test now call this.
//
// Parsed PER LINE, and the device is taken from the SAME line as the via. The
// old flattened `strings.Fields(out)` scan could pair a `via` from one default
// route with a `dev` from another, which matters as soon as the caller wants
// the device: measured output on this platform includes a lone
// `blackhole default proto static metric 20` (no via, no dev) and an FRR
// nexthop-group form `default nhid 115 via 172.16.50.1 dev ge-0-0-2.50 proto
// static metric 20`. Returns ("", "") when no line carries a via.
func parseDefaultRoute(out string) (gw, dev string) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		var lineGW, lineDev string
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				if lineGW == "" {
					lineGW = fields[i+1]
				}
			case "dev":
				if lineDev == "" {
					lineDev = fields[i+1]
				}
			}
		}
		if lineGW != "" {
			return lineGW, lineDev
		}
	}
	return "", ""
}

// parseRouteGetDev extracts the egress device from `ip route get` output.
//
// Measured shapes, all four of which the selftest carries verbatim:
//
//	172.16.50.1 dev ge-0-0-2.50 src 172.16.50.8 uid 0        (on-link v4)
//	10.136.126.1 via 172.16.50.1 dev ge-0-0-2.50 src ...     (via a gateway)
//	2001:...::1 from :: dev ge-0-0-2.50 proto kernel src ... (v6)
//	local 172.16.50.8 dev lo table local src 172.16.50.8     (the box itself)
//
// Returns "" when the output carries no `dev` field. The caller treats that as
// UNRESOLVED — never as eligible: an absent device is "I could not tell where
// this packet would go", which is the one answer that must not permit a probe
// whose whole purpose is to establish where the packet went.
func parseRouteGetDev(out string) string {
	// Only the FIRST line describes the route; `cache`/`cache <local>`
	// continuation lines carry no dev but must not be scanned for one either.
	line := out
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		line = out[:i]
	}
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1]
		}
	}
	return ""
}

// beaconTargetEligible reports whether a ping to target could carry any
// information about dataplane forwarding.
//
// TOTAL: returns nil (eligible) or a non-nil error naming exactly which class
// refused it. The error text is what reaches the operator, through
// KernelRunner.revert -> KernelRollOutcome.Detail, so each one says what to do
// rather than only what happened.
//
// isManagement may be nil, which means THIS CALLER CANNOT CLASSIFY interfaces.
// That is treated as "no information", not "ineligible" — the same contract
// ForwardBeacon's nil-HelperStatus branch documents, and for the same reason:
// failing closed on a missing seam reverts every embedder's promotion. Both
// production constructors wire it, and TestBothProductionCallersWireIsManagement_7157
// binds that claim so "production always wires it" is asserted rather than
// asserted-in-a-comment.
func beaconTargetEligible(target string, isManagement func(string) bool) error {
	out, err := beaconRouteGet(target)
	if err != nil {
		return fmt.Errorf("beacon target %s has no route from this box (%v) — a ping to it "+
			"cannot leave, so a pass would carry no information. On an HA SECONDARY this is "+
			"expected: the RETH default is a blackhole while the peer holds the VIP. Set "+
			"XPF_KERNEL_BEACON_TARGET to an address reachable over a dataplane interface on "+
			"THIS node", target, err)
	}
	dev := parseRouteGetDev(out)
	if dev == "" {
		return fmt.Errorf("beacon target %s: could not determine the egress interface from "+
			"%q — refusing to probe a target whose path is unknown", target, strings.TrimSpace(out))
	}
	if dev == "lo" {
		return fmt.Errorf("beacon target %s is LOCAL to this box (egress dev lo) — the ping is "+
			"answered by the host stack without a packet ever leaving, so it succeeds with the "+
			"dataplane in ANY state and proves nothing. Set XPF_KERNEL_BEACON_TARGET to an "+
			"OFF-BOX address reachable over a dataplane interface", target)
	}
	if isManagement != nil && isManagement(dev) {
		return fmt.Errorf("beacon target %s egresses the MANAGEMENT interface %s — a candidate "+
			"kernel can keep management reachable while the security dataplane cannot forward "+
			"transit traffic, so this probe cannot substantiate a promotion. Set "+
			"XPF_KERNEL_BEACON_TARGET to an address reachable over a dataplane interface",
			target, dev)
	}
	return nil
}
