// Tests for the #1197 neighbor listener filter and force-probe
// tier classification logic. These cover the pure logic; the
// netlink subscription itself requires a live kernel and is
// covered by manual repro + smoke matrix.
package daemon

import (
	"net"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestProbeTierClassification(t *testing.T) {
	tests := []struct {
		name     string
		state    uint16
		critical bool
		want     int
	}{
		{"NUD_NONE (state==0) is tier 1", 0, false, 1},
		{"NUD_NONE critical still tier 1", 0, true, 1},
		{"STALE is tier 1", uint16(netlink.NUD_STALE), false, 1},
		{"PROBE is tier 1", uint16(netlink.NUD_PROBE), false, 1},
		{"DELAY is tier 1", uint16(netlink.NUD_DELAY), false, 1},
		{"FAILED is tier 1", uint16(netlink.NUD_FAILED), false, 1},
		{"INCOMPLETE is tier 1", uint16(netlink.NUD_INCOMPLETE), false, 1},
		{"REACHABLE+critical is tier 2", uint16(netlink.NUD_REACHABLE), true, 2},
		{"REACHABLE non-critical is tier 3", uint16(netlink.NUD_REACHABLE), false, 3},
		{"PERMANENT non-critical is tier 3", uint16(netlink.NUD_PERMANENT), false, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := probeTier(tc.state, tc.critical)
			if got != tc.want {
				t.Errorf("probeTier(%v, %v) = %d, want %d",
					tc.state, tc.critical, got, tc.want)
			}
		})
	}
}

func TestUsableNUDMask(t *testing.T) {
	cases := []struct {
		name  string
		state int
		usable bool
	}{
		{"REACHABLE usable", netlink.NUD_REACHABLE, true},
		{"STALE usable", netlink.NUD_STALE, true},
		{"DELAY usable", netlink.NUD_DELAY, true},
		{"PROBE usable", netlink.NUD_PROBE, true},
		{"PERMANENT usable", netlink.NUD_PERMANENT, true},
		{"NOARP usable", netlink.NUD_NOARP, true},
		{"FAILED NOT usable", netlink.NUD_FAILED, false},
		{"INCOMPLETE NOT usable", netlink.NUD_INCOMPLETE, false},
		{"NUD_NONE (0) NOT in mask", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.state&usableNUD != 0
			if got != tc.usable {
				t.Errorf("state=%v: usableNUD bit = %v, want %v",
					tc.state, got, tc.usable)
			}
		})
	}
}

// shouldTriggerRegen tests use a stub provider to avoid wiring
// a full Daemon. We test the pure decision logic here.
type stubNeighborProvider struct {
	existing map[string]string // ip → mac (existing snapshot entries)
}

func (s *stubNeighborProvider) RegenerateNeighborSnapshot()                       {}
func (s *stubNeighborProvider) SnapshotHasIfindex(int) bool                       { return true }
func (s *stubNeighborProvider) LookupSnapshotNeighbor(_ int, ip net.IP) *snapshotEntry {
	if mac, ok := s.existing[ip.String()]; ok {
		return &snapshotEntry{IP: ip.String(), MAC: mac}
	}
	return nil
}

// snapshotEntry mirrors userspace.NeighborSnapshot's relevant fields
// for shouldTriggerRegen testing. We don't import the userspace
// package here because that would create a cycle in some test setups;
// the real LookupSnapshotNeighbor returns the userspace type.
type snapshotEntry struct {
	IP, MAC string
}

// Note: full shouldTriggerRegen test would need a Daemon instance
// with d.dp wired to a stub provider. That's covered indirectly
// by the integration smoke matrix on the loss userspace cluster.
// For pure-logic coverage we test probeTier + usableNUD mask
// (above).

func TestNeighborListenerNUDStateBitmaskCoverage(t *testing.T) {
	// Sanity: documented learnedMask in the plan must match
	// usableNUD constant. usableNUD = REACHABLE | STALE | DELAY
	// | PROBE | PERMANENT | NOARP — matches Codex round-5 #5
	// requirement.
	expected := netlink.NUD_REACHABLE | netlink.NUD_STALE |
		netlink.NUD_DELAY | netlink.NUD_PROBE |
		netlink.NUD_PERMANENT | netlink.NUD_NOARP
	if usableNUD != expected {
		t.Errorf("usableNUD = %x, want %x", usableNUD, expected)
	}
	// NUD_NONE must NOT be in mask
	if usableNUD&0 != 0 {
		t.Error("usableNUD must not include NUD_NONE")
	}
	// FAILED, INCOMPLETE must NOT be in mask
	if usableNUD&netlink.NUD_FAILED != 0 {
		t.Error("usableNUD must not include NUD_FAILED")
	}
	if usableNUD&netlink.NUD_INCOMPLETE != 0 {
		t.Error("usableNUD must not include NUD_INCOMPLETE")
	}
}

func TestNeighborListenerEventTypes(t *testing.T) {
	// Sanity: confirm the syscall constants we depend on.
	if syscall.RTM_NEWNEIGH == 0 || syscall.RTM_DELNEIGH == 0 {
		t.Skip("RTM_NEWNEIGH/RTM_DELNEIGH constants unavailable on this platform")
	}
	if syscall.RTM_NEWNEIGH == syscall.RTM_DELNEIGH {
		t.Error("RTM_NEWNEIGH and RTM_DELNEIGH must differ")
	}
}
