package cluster

import (
	"fmt"
	"strings"
	"testing"
)

// #72 acceptance criterion 3: "Operators can observe fence attempts/results in
// runtime status." The fence mechanism itself (config leaf -> peerFencing ->
// handlePeerTimeout -> SendFence) has been wired since #3917, and FenceStatus
// has always returned the configured action plus the EventFence history — but
// nothing rendered it, so a fence attempt was visible only in journald. These
// tests bind FenceStatus to the `show chassis cluster information` render
// (Manager.FormatInformation, which serves BOTH the local CLI
// pkg/cli/cli_show_cluster.go and the gRPC remote CLI
// pkg/grpcapi/server_show_cluster_text.go).

// fenceInfoManager returns a manager with one RG, optionally with peer fencing
// configured, primed so handlePeerTimeout will run its fence branch.
func fenceInfoManager(t *testing.T, action string) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.PeerFencing = action
	m.UpdateConfig(cfg)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.mu.Unlock()
	return m
}

// A configured fence action is reported even before any fence has fired, so an
// operator can confirm the policy is armed rather than inferring it from the
// absence of events.
func TestFormatInformation_PeerFencingArmedNoAttempts(t *testing.T) {
	m := fenceInfoManager(t, "disable-rg")

	out := m.FormatInformation()
	if !strings.Contains(out, "Peer fencing:") {
		t.Fatalf("FormatInformation() lacks the 'Peer fencing:' section:\n%s", out)
	}
	if !strings.Contains(out, "Action: disable-rg") {
		t.Errorf("FormatInformation() lacks 'Action: disable-rg':\n%s", out)
	}
	if !strings.Contains(out, "Attempts: none") {
		t.Errorf("FormatInformation() lacks 'Attempts: none':\n%s", out)
	}
}

// The result of each fence attempt — sent, failed, or skipped — reaches the
// operator surface. This drives the REAL handlePeerTimeout path rather than
// recording history directly, so the test also binds the fence call site.
func TestFormatInformation_PeerFencingAttemptResults(t *testing.T) {
	tests := []struct {
		name    string
		fenceFn func() error
		want    string
	}{
		{"sent", func() error { return nil }, "Fence disable-rg sent to peer"},
		{"failed", func() error { return fmt.Errorf("connection refused") }, "Fence failed: connection refused"},
		{"skipped", nil, "Fence skipped: sync not available"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := fenceInfoManager(t, "disable-rg")
			if tt.fenceFn != nil {
				m.SetPeerFenceFunc(tt.fenceFn)
			}

			m.handlePeerTimeout()

			out := m.FormatInformation()
			if !strings.Contains(out, "Peer fencing:") {
				t.Fatalf("FormatInformation() lacks the 'Peer fencing:' section:\n%s", out)
			}
			if !strings.Contains(out, "Attempts:") {
				t.Fatalf("FormatInformation() lacks the 'Attempts:' list:\n%s", out)
			}
			if !strings.Contains(out, tt.want) {
				t.Errorf("FormatInformation() lacks fence attempt %q:\n%s", tt.want, out)
			}
		})
	}
}

// A cluster that never configured fencing and never fenced must not grow a
// section: the render stays quiet, matching the conditional style of the
// "Install fence" / "Interface monitoring events" sections around it. Without
// this the first assertion above would pass on an unconditional section that
// tells the operator nothing.
func TestFormatInformation_PeerFencingUnconfiguredIsQuiet(t *testing.T) {
	m := fenceInfoManager(t, "")

	m.handlePeerTimeout() // no fence branch: peerFencing is empty

	out := m.FormatInformation()
	if strings.Contains(out, "Peer fencing:") {
		t.Errorf("FormatInformation() emits a 'Peer fencing:' section with fencing "+
			"unconfigured and no fence history:\n%s", out)
	}
}

// History outlives the config. After the operator removes `peer-fencing`, past
// attempts stay visible but the action reported is the CURRENT one, so the
// surface never implies fencing is still armed.
func TestFormatInformation_PeerFencingDisarmedKeepsHistory(t *testing.T) {
	m := fenceInfoManager(t, "disable-rg")
	m.SetPeerFenceFunc(func() error { return nil })
	m.handlePeerTimeout()

	// Operator removes the leaf and re-commits.
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.PeerFencing = ""
	m.UpdateConfig(cfg)

	out := m.FormatInformation()
	if !strings.Contains(out, "Peer fencing:") {
		t.Fatalf("FormatInformation() dropped the fence history after disarm:\n%s", out)
	}
	if !strings.Contains(out, "Action: disabled") {
		t.Errorf("FormatInformation() lacks 'Action: disabled' after disarm:\n%s", out)
	}
	if !strings.Contains(out, "Fence disable-rg sent to peer") {
		t.Errorf("FormatInformation() dropped the recorded attempt after disarm:\n%s", out)
	}
}
