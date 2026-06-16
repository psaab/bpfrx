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

	// No peer configured => remote lost => peer not alive, not drained.
	if parsePeerAlive(info) {
		t.Errorf("parsePeerAlive true with no peer (remote should be lost):\n%s", info)
	}
	if parseDrainComplete(info) {
		t.Errorf("parseDrainComplete true with no healthy peer — would cut with no peer to own RGs")
	}
}

// TestParsers_Fixtures exercises the parsers against fixtures matching the
// FormatInformation grammar (status.go) for states a live Manager is
// awkward to drive to from an external test.
func TestParsers_Fixtures(t *testing.T) {
	healthyPeerSecondary := strings.Join([]string{
		"Node health:",
		"  Local node: healthy",
		"  Remote node: healthy (node1)",
		"",
		"Redundancy group 0:",
		"  Local priority: 100",
		"  Local state: Secondary",
		"  Takeover ready: yes (since 12:00:00)",
		"",
	}, "\n")
	healthyPeerPrimary := strings.ReplaceAll(healthyPeerSecondary, "Local state: Secondary", "Local state: Primary")
	remoteLost := strings.ReplaceAll(healthyPeerSecondary, "Remote node: healthy (node1)", "Remote node: lost")

	if !parsePeerAlive(healthyPeerSecondary) {
		t.Error("healthy peer not detected as alive")
	}
	if parsePeerAlive(remoteLost) {
		t.Error("lost remote read as alive")
	}
	if !parseDrainComplete(healthyPeerSecondary) {
		t.Error("local Secondary + healthy peer should be drain-complete")
	}
	if parseDrainComplete(healthyPeerPrimary) {
		t.Error("local Primary must NOT be drain-complete (node still owns an RG)")
	}
	if parseDrainComplete(remoteLost) {
		t.Error("drain-complete with a lost remote — no peer to own the RGs")
	}
	if !parsePeerTakeoverReady(healthyPeerSecondary) {
		t.Error("healthy peer should be takeover-ready")
	}
	if parsePeerTakeoverReady(remoteLost) {
		t.Error("lost remote must not be takeover-ready")
	}
	// Empty / garbled output must never read as drained.
	if parseDrainComplete("garbage\nno fields here") {
		t.Error("garbled output read as drained")
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
