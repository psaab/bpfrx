// #3449: a DNAT `match destination-port low to high` range must NOT expand into
// one snapshot/table entry per port (a control-plane memory/apply-time
// amplification: `destination-port 1 to 65535` produced 65 535 entries).
// buildDestinationNATSnapshots coalesces the (parser-expanded) port list into
// inclusive [Low,High] wire ranges: a single port keeps the exact-port O(1)
// fast path (DestinationPort set, MatchDestinationPorts empty); a multi-port
// range rides ONE wildcard-port entry (DestinationPort=0) whose
// MatchDestinationPorts the Rust l4_extra_matches AND-checks against the flow's
// destination port.
//
// RED-on-revert: restore the per-port `for _, dstPort := range dstPorts` emit
// and a 10 001-port range yields 10 001 snapshots, failing the len==1 assert.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func expandPorts(lo, hi int) []int {
	ports := make([]int, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		ports = append(ports, p)
	}
	return ports
}

func TestBuildDNATSnapshotWideRangeNotExpanded_3449(t *testing.T) {
	// `destination-port 20000 to 30000` — the parser hands the builder the
	// expanded 10 001-port list; the builder must collapse it to ONE entry.
	cfg := dnatPortConfig(config.NATMatch{DestinationPorts: expandPorts(20000, 30000), DestinationPort: 20000})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("a 10 001-port range expanded into %d snapshots, want 1 (range, not per-port)", len(snaps))
	}
	s := snaps[0]
	if s.DestinationPort != 0 {
		t.Fatalf("DestinationPort = %d, want 0 (wildcard key for a multi-port range)", s.DestinationPort)
	}
	if len(s.MatchDestinationPorts) != 1 || s.MatchDestinationPorts[0].Low != 20000 || s.MatchDestinationPorts[0].High != 30000 {
		t.Fatalf("MatchDestinationPorts = %+v, want [{20000 30000}]", s.MatchDestinationPorts)
	}
	if s.Protocol != "tcp" {
		t.Fatalf("Protocol = %q, want \"tcp\" (port-based DNAT default)", s.Protocol)
	}
}

func TestBuildDNATSnapshotFullPortSpaceNotExpanded_3449(t *testing.T) {
	// The worst case from the issue: `destination-port 1 to 65535`. Must be ONE
	// entry, never 65 535.
	cfg := dnatPortConfig(config.NATMatch{DestinationPorts: expandPorts(1, 65535), DestinationPort: 1})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("a 65 535-port range expanded into %d snapshots, want 1", len(snaps))
	}
	if r := snaps[0].MatchDestinationPorts; len(r) != 1 || r[0].Low != 1 || r[0].High != 65535 {
		t.Fatalf("MatchDestinationPorts = %+v, want [{1 65535}]", r)
	}
}

func TestBuildDNATSnapshotSinglePortKeepsExactFastPath_3449(t *testing.T) {
	// A single port must NOT regress to the wildcard+range form — it keeps the
	// exact-port key with no range constraint (the O(1) DnatKey fast path).
	cfg := dnatPortConfig(config.NATMatch{DestinationPorts: []int{8080}, DestinationPort: 8080})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].DestinationPort != 8080 {
		t.Fatalf("DestinationPort = %d, want 8080 (exact fast path)", snaps[0].DestinationPort)
	}
	if len(snaps[0].MatchDestinationPorts) != 0 {
		t.Fatalf("MatchDestinationPorts = %+v, want empty for a single port", snaps[0].MatchDestinationPorts)
	}
}

func TestBuildDNATSnapshotDiscreteAndRangeMix_3449(t *testing.T) {
	// `destination-port [ 80 443 20000 to 20002 ]` coalesces to two exact ports
	// (80, 443) plus one range (20000-20002) — three entries, not 80/443 + 3
	// per-port entries.
	ports := append([]int{80, 443}, expandPorts(20000, 20002)...)
	cfg := dnatPortConfig(config.NATMatch{DestinationPorts: ports, DestinationPort: 80})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 3 {
		t.Fatalf("len(snaps) = %d, want 3 (80, 443, [20000-20002])", len(snaps))
	}
	var exact, ranged int
	for _, s := range snaps {
		if len(s.MatchDestinationPorts) > 0 {
			ranged++
			if s.DestinationPort != 0 {
				t.Fatalf("range entry has DestinationPort %d, want 0", s.DestinationPort)
			}
		} else {
			exact++
		}
	}
	if exact != 2 || ranged != 1 {
		t.Fatalf("got %d exact + %d range entries, want 2 + 1", exact, ranged)
	}
}
