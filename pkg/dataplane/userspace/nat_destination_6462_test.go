// #6462: a DNAT rule with `match destination-port` but NO `match protocol`
// matches BOTH TCP and UDP, exactly as Junos does for a bare destination-port.
// buildDestinationNATSnapshots must emit one snapshot per protocol so a UDP
// packet to the VIP:port is translated. Before #6462 such a rule defaulted to a
// single TCP-keyed entry; a UDP (proto 17) packet hit none of the TCP-keyed
// entries and was silently NOT translated — a silent UDP-service outage (DNS,
// SIP, VPN) plus an observability lie (`show security nat destination` still
// listed the rule as installed).
//
// The fix emits an explicit tcp AND udp row, never a single PROTO_ANY+port row:
// the Rust DnatTable lookup probes (protocol,dst_ip,dst_port) →
// (protocol,dst_ip,0) → (PROTO_ANY,dst_ip,0) and never
// (PROTO_ANY,dst_ip,dst_port), so a PROTO_ANY+port row would be unreachable for
// UDP; and PROTO_ANY would also wrongly translate ICMP/other (ports exist only
// for TCP/UDP). Two explicit rows is the only correct, non-over-matching fix.
//
// RED-on-revert: restore the tcp-only default (`proto = "tcp"` with a single
// emit) and TestBuildDNATBareDestPortEmitsTCPAndUDP_6462 fails its "want a
// udp-keyed entry" assertion (the udp row is absent).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// dnatCounterIDs returns a counter map keyed for the single rule dnatPortConfig
// builds (ruleset "rs", rule "r1"), so the shared-CounterID assertion below
// exercises a real non-zero id rather than the nil-map zero default.
func dnatCounterIDs(id uint32) map[string]uint32 {
	return map[string]uint32{
		dataplane.NATCounterKey(dataplane.NATCounterTypeDest, "rs", "r1"): id,
	}
}

func TestBuildDNATBareDestPortEmitsTCPAndUDP_6462(t *testing.T) {
	// `match destination-address 198.51.100.10; match destination-port 53` with
	// NO `match protocol` — the exact trace from the issue.
	cfg := dnatPortConfig(config.NATMatch{
		DestinationAddress: "198.51.100.10",
		DestinationPorts:   []int{53},
		DestinationPort:    53,
	})
	snaps := buildDestinationNATSnapshots(cfg, dnatCounterIDs(42))

	byProto := map[string]DestinationNATRuleSnapshot{}
	for _, s := range snaps {
		if s.DestinationAddress != "198.51.100.10" || s.DestinationPort != 53 {
			t.Fatalf("unexpected entry %+v", s)
		}
		if _, dup := byProto[s.Protocol]; dup {
			t.Fatalf("duplicate entry for protocol %q: %+v", s.Protocol, snaps)
		}
		byProto[s.Protocol] = s
	}

	tcp, hasTCP := byProto["tcp"]
	udp, hasUDP := byProto["udp"]
	if !hasTCP {
		t.Fatalf("no tcp-keyed entry for 198.51.100.10:53; got %+v", snaps)
	}
	if !hasUDP {
		// The #6462 bug: a bare destination-port defaulted to tcp-only, so a UDP
		// packet to the VIP:53 matched no entry and was left untranslated.
		t.Fatalf("no udp-keyed entry for 198.51.100.10:53 (the #6462 bug); got %+v", snaps)
	}
	// Exactly two rows: tcp + udp, with no PROTO_ANY / icmp / empty-protocol
	// over-match (ports exist only for TCP and UDP).
	if len(snaps) != 2 {
		t.Fatalf("len(snaps) = %d, want exactly 2 (tcp + udp): %+v", len(snaps), snaps)
	}
	// Both rows are identical except the protocol key: same pool VIP and the
	// SAME CounterID, exactly like an explicit `match protocol [ tcp udp ]`
	// (#3431). A packet is TCP or UDP, so it hits exactly one row and the shared
	// rule counter increments once — no double-count.
	if tcp.PoolAddress != "192.168.1.10" || udp.PoolAddress != "192.168.1.10" {
		t.Fatalf("pool mismatch: tcp=%q udp=%q, want both 192.168.1.10", tcp.PoolAddress, udp.PoolAddress)
	}
	if tcp.CounterID != 42 || udp.CounterID != 42 {
		t.Fatalf("CounterID: tcp=%d udp=%d, want both 42 (shared rule counter)", tcp.CounterID, udp.CounterID)
	}
}

func TestBuildDNATBareDestPortRangeEmitsBothProtos_6462(t *testing.T) {
	// The range branch of the gate: a bare `destination-port 5060 to 5061` (no
	// protocol) coalesces to one wildcard-port entry with a MatchDestinationPorts
	// range — it must ALSO dual-emit tcp + udp, not default to tcp only.
	cfg := dnatPortConfig(config.NATMatch{
		DestinationPorts: expandPorts(5060, 5061),
		DestinationPort:  5060,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 2 {
		t.Fatalf("len(snaps) = %d, want 2 (tcp + udp, range not per-port expanded): %+v", len(snaps), snaps)
	}
	seen := map[string]bool{}
	for _, s := range snaps {
		seen[s.Protocol] = true
		if s.DestinationPort != 0 {
			t.Fatalf("range entry DestinationPort = %d, want 0 (wildcard key)", s.DestinationPort)
		}
		if len(s.MatchDestinationPorts) != 1 || s.MatchDestinationPorts[0].Low != 5060 || s.MatchDestinationPorts[0].High != 5061 {
			t.Fatalf("MatchDestinationPorts = %+v, want [{5060 5061}]", s.MatchDestinationPorts)
		}
	}
	if !seen["tcp"] || !seen["udp"] {
		t.Fatalf("protocols = %v, want both tcp and udp", seen)
	}
}

func TestBuildDNATExplicitProtoNotDualEmitted_6462(t *testing.T) {
	// When a protocol IS pinned, honor it verbatim: `match protocol udp;
	// destination-port 53` emits ONLY a udp entry — the fix must not also add a
	// tcp row, and must not widen to match-any.
	cfg := dnatPortConfig(config.NATMatch{
		Protocol:         "udp",
		DestinationPorts: []int{53},
		DestinationPort:  53,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (explicit protocol udp): %+v", len(snaps), snaps)
	}
	if snaps[0].Protocol != "udp" {
		t.Fatalf("Protocol = %q, want \"udp\"", snaps[0].Protocol)
	}
}

func TestBuildDNATNoPortStaysMatchAny_6462(t *testing.T) {
	// A protocol-less rule with NO destination-port must NOT change: it stays a
	// single match-any (empty-protocol) entry — it neither defaults to tcp nor
	// dual-emits tcp+udp. Guards against the fix broadening the no-port path.
	cfg := dnatPortConfig(config.NATMatch{DestinationAddress: "198.51.100.10"})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (match-any, no port): %+v", len(snaps), snaps)
	}
	if snaps[0].Protocol != "" {
		t.Fatalf("Protocol = %q, want \"\" (match any protocol, not tcp)", snaps[0].Protocol)
	}
	if snaps[0].DestinationPort != 0 {
		t.Fatalf("DestinationPort = %d, want 0 (no port constraint)", snaps[0].DestinationPort)
	}
}
