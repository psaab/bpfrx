package userspace

import (
	"strings"
	"testing"
	"time"
)

func wgFmtFixture() ProcessStatus {
	return ProcessStatus{
		WgTunnels: []WgTunnelStatus{{
			Tunnel:                 "wg0",
			TunnelEndpointID:       3,
			ListenPort:             51820,
			PeerPubkeyHex:          strings.Repeat("ab", 32),
			PeerEndpoint:           "192.0.2.10:51820",
			SessionConfirmed:       true,
			LastHandshakeUnixSecs:  1_770_000_000,
			HsCompletionsInitiator: 2,
			HsResponsesCreated:     1,
			HsInitiationsCreated:   4,
			HsSendErrors:           1,
			DecapPackets:           100,
			DecapBytes:             5000,
			EncapPackets:           90,
			EncapBytes:             4500,
			DecapKeepalives:        7,
			DecapDropsReplay:       2,
			EncapMtuDrops:          3,
			HsRxDropsMac1Mismatch:  5,
		}},
	}
}

func TestFormatWireguardStatusSummary(t *testing.T) {
	now := time.Unix(1_770_000_090, 0) // 90s after the handshake
	out := FormatWireguardStatus(wgFmtFixture(), false, now)
	for _, want := range []string{
		"Tunnel: wg0 (endpoint id 3)",
		"Listen port:        51820",
		"Peer public key:    " + strings.Repeat("ab", 32),
		"Peer endpoint:      192.0.2.10:51820",
		"Session:            session confirmed",
		"Latest handshake:   1m30s ago",
		"Handshakes:         2 initiator, 1 responder (initiations created 4, send errors 1)",
		"Transfer:           100 pkts / 5000 bytes received, 90 pkts / 4500 bytes sent (inner IP)",
		"Keepalives:         7 received",
		"Drops:              2 receive, 3 transmit, 5 handshake, 1 I/O errors",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "by reason") {
		t.Errorf("summary must not include the detail reason tables:\n%s", out)
	}
}

func TestFormatWireguardStatusDetailReasonTables(t *testing.T) {
	now := time.Unix(1_770_000_090, 0)
	out := FormatWireguardStatus(wgFmtFixture(), true, now)
	for _, want := range []string{
		"Receive drops by reason:",
		"replay                   2",
		"Transmit drops by reason:",
		"mtu-exceeded             3",
		"Handshake drops by reason:",
		"mac1-mismatch            5",
		"I/O errors:",
		"handshake-send           1",
		"Handshake activity: 4 initiations created, 0 build failures, 0 requests armed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail missing %q in:\n%s", want, out)
		}
	}
}

func TestFormatWireguardStatusNeverAndEmpty(t *testing.T) {
	out := FormatWireguardStatus(ProcessStatus{}, false, time.Now())
	if !strings.Contains(out, "No WireGuard tunnels configured") {
		t.Errorf("empty status rendering = %q", out)
	}
	status := ProcessStatus{WgTunnels: []WgTunnelStatus{{Tunnel: "wg1"}}}
	out = FormatWireguardStatus(status, false, time.Now())
	if !strings.Contains(out, "Latest handshake:   never") {
		t.Errorf("never-handshaked tunnel must render 'never':\n%s", out)
	}
	if !strings.Contains(out, "Session:            no session") {
		t.Errorf("no-session state missing:\n%s", out)
	}
	if !strings.Contains(out, "(responder-only; learned at runtime)") {
		t.Errorf("empty endpoint placeholder missing:\n%s", out)
	}
}

// A future timestamp (clock step between the helper's conversion and
// this render) clamps to "0 seconds ago", never negative.
func TestFormatHandshakeAgeClamps(t *testing.T) {
	if got := formatHandshakeAge(2_000_000_000, time.Unix(1_900_000_000, 0)); got != "0 seconds ago" {
		t.Errorf("future stamp = %q, want clamp to 0 seconds ago", got)
	}
	if got := formatHandshakeAge(0, time.Now()); got != "never" {
		t.Errorf("zero stamp = %q, want never", got)
	}
}
