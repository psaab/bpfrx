package upgrade

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// TestParsers_AgainstRealFormatInformation feeds REAL
// cluster.Manager.FormatInformation() output through the drain-predicate
// parsers so a status-format change is caught here (Codex r1 Critical#7:
// the old parser keyed on "Remote node:" text that the WRONG command —
// FormatStatus — never emits; this asserts we parse the RIGHT command's
// output). A freshly-constructed Manager with a configured RG renders the
// "Remote node:" and per-RG "Local state:" lines the parsers depend on.
func TestParsers_AgainstRealFormatInformation(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID: 1,
		NodeID:    0,
		RedundancyGroups: []*config.RedundancyGroup{
			{
				ID:      0,
				Preempt: true,
				NodePriorities: map[int]int{
					0: 200,
					1: 100,
				},
			},
		},
	})

	info := m.FormatInformation()

	// The parsers depend on these exact field tokens — assert they exist in
	// real output so a format rename breaks this test, not production.
	if !strings.Contains(info, "Remote node:") {
		t.Fatalf("FormatInformation() lacks 'Remote node:' line the parsers key on:\n%s", info)
	}
	if !strings.Contains(info, "Local state:") {
		t.Fatalf("FormatInformation() lacks 'Local state:' line the parsers key on:\n%s", info)
	}

	// No peer configured => remote lost => peer not alive.
	if parsePeerAlive(info) {
		t.Errorf("parsePeerAlive true with no peer (remote should be lost):\n%s", info)
	}

	// parseDrainComplete consumes the STATUS topic (node rows). A real
	// FormatStatus with no peer must NOT read as drained (no peer-primary).
	st := m.FormatStatus()
	if !strings.Contains(st, "Node name:") {
		t.Fatalf("FormatStatus lacks 'Node name:' header parseLocalNodeID keys on:\n%s", st)
	}
	if parseDrainComplete(st) {
		t.Errorf("parseDrainComplete true with no peer — would cut with no peer owning RGs:\n%s", st)
	}
}

// TestDrainParser_Fixtures exercises parseDrainComplete against
// FormatStatus-grammar fixtures (status.go node rows). Drain is complete
// ONLY when the LOCAL node row is secondary AND the PEER node row is
// primary (the peer actually took ownership).
func TestDrainParser_Fixtures(t *testing.T) {
	// FormatStatus row: "node<id>  <prio>  <state>  <preempt> <manual> <mon>".
	drained := strings.Join([]string{
		"Node name: node0",
		"",
		"Redundancy group: 0 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
		"",
	}, "\n")
	localStillPrimary := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   200      primary        yes      no       None",
		"node1   100      secondary      yes      no       None",
	}, "\n")
	bothSecondary := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   100      secondary      yes      no       None",
		"node1   100      secondary      yes      no       None",
	}, "\n")
	localSecondaryNoPeer := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   100      secondary      yes      no       None",
	}, "\n")
	// Multi-RG (Codex r3): RG0 fully handed off, RG1 peer still secondary —
	// NOT drained (per-RG pairing, not global any-peer-primary).
	multiRGPartial := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
		"Redundancy group: 1 , Failover count: 0",
		"node0   100      secondary      yes      no       None",
		"node1   100      secondary      yes      no       None",
	}, "\n")
	multiRGDrained := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
		"Redundancy group: 1 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
	}, "\n")

	if !parseDrainComplete(drained) {
		t.Error("local secondary + peer primary should be drain-complete")
	}
	if parseDrainComplete(localStillPrimary) {
		t.Error("local primary must NOT be drain-complete")
	}
	if parseDrainComplete(bothSecondary) {
		t.Error("both-secondary must NOT be drain-complete (peer has not taken ownership — VIP stranding)")
	}
	if parseDrainComplete(localSecondaryNoPeer) {
		t.Error("local secondary with no peer-primary row must NOT be drain-complete")
	}
	if parseDrainComplete(multiRGPartial) {
		t.Error("multi-RG with one RG peer-secondary must NOT be drain-complete (per-RG pairing)")
	}
	if !parseDrainComplete(multiRGDrained) {
		t.Error("multi-RG all-handed-off should be drain-complete")
	}
	if parseDrainComplete("garbage\nno node rows") {
		t.Error("garbled output read as drained")
	}
}

// TestPeerTakeoverReady_Fixtures covers the real not-ready tokens
// FormatInformation emits (Codex r4 High).
func TestPeerTakeoverReady_Fixtures(t *testing.T) {
	ready := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"  Takeover ready: yes (since 12:00:00)",
		"  Transfer ready: yes",
		"  Monitor failures: none",
	}, "\n")
	takeoverNo := strings.ReplaceAll(ready, "Takeover ready: yes (since 12:00:00)", "Takeover ready: no (interface ge-0-0-1 down)")
	transferNo := strings.ReplaceAll(ready, "Transfer ready: yes", "Transfer ready: no")
	monFail := strings.ReplaceAll(ready, "Monitor failures: none", "Monitor failures: ge-0-0-1")

	if !parsePeerTakeoverReady(ready) {
		t.Error("all-green should be takeover-ready")
	}
	if parsePeerTakeoverReady(takeoverNo) {
		t.Error("'Takeover ready: no' must block (VIP stranding risk)")
	}
	if parsePeerTakeoverReady(transferNo) {
		t.Error("'Transfer ready: no' must block")
	}
	if parsePeerTakeoverReady(monFail) {
		t.Error("'Monitor failures: <iface>' must block")
	}
}

// TestDrainComplete_MalformedHeaderNoBleed proves a malformed RG header
// does not let following node rows bleed into the previous RG (Codex r4
// Medium): the rows after the bad header are dropped (curRG reset to -1),
// so the previous RG keeps only its own (incomplete) rows and the result
// is NOT drained.
func TestDrainComplete_MalformedHeaderNoBleed(t *testing.T) {
	// RG0 local-primary (not drained); then a MALFORMED header; then rows
	// that, if they bled into RG0, would look secondary/primary. The
	// malformed header must prevent the bleed so RG0 stays primary => not
	// drained.
	s := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   200      primary        yes      no       None",
		"node1   100      secondary      yes      no       None",
		"Redundancy group: XYZ , Failover count: 0", // malformed number
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
	}, "\n")
	if parseDrainComplete(s) {
		t.Error("malformed header let node rows bleed into the previous RG — must NOT read drained")
	}
}

// TestSyncParser_Fixtures covers the Status: Up/Down sync gate.
func TestSyncParser_Fixtures(t *testing.T) {
	up := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"Sync link statistics (control-link):",
		"  Status: Up",
	}, "\n")
	down := strings.ReplaceAll(up, "Status: Up", "Status: Down")
	noStatus := "  Remote node: healthy (node1)\n"

	if !parseSyncEstablished(up) {
		t.Error("Status: Up should read as sync established")
	}
	if parseSyncEstablished(down) {
		t.Error("Status: Down must NOT read as sync established (would drop sessions on cut)")
	}
	if parseSyncEstablished(noStatus) {
		t.Error("missing Status line must fail closed")
	}
}

func TestParseHAProtocolCompatible(t *testing.T) {
	match := "HA protocol version: 1\nPeer HA protocol version: 1\n"
	mismatch := "HA protocol version: 1\nPeer HA protocol version: 2\n"
	noPeer := "HA protocol version: 1\n"

	if !parseHAProtocolCompatible(match) {
		t.Error("equal protocol versions should be compatible")
	}
	if parseHAProtocolCompatible(mismatch) {
		t.Error("mismatched protocol versions must be incompatible (not rolling-upgradable)")
	}
	if parseHAProtocolCompatible(noPeer) {
		t.Error("missing peer protocol line must fail closed")
	}
}

// TestStatusEmitsProtocolLines guards that FormatStatus still emits the HA
// protocol version lines parseHAProtocolCompatible keys on.
func TestStatusEmitsProtocolLines(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID:        1,
		NodeID:           0,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}}},
	})
	st := m.FormatStatus()
	if !strings.Contains(st, "HA protocol version:") {
		t.Fatalf("FormatStatus lacks 'HA protocol version:' the parser keys on:\n%s", st)
	}
}
