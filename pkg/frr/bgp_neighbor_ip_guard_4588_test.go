package frr

import (
	"context"
	"strings"
	"testing"
)

// TestBGPNeighborReceivedRoutesRejectsUnvalidatedIP proves the #4588 belt:
// GetBGPNeighborReceivedRoutes must reject a neighbor "IP" that carries a
// space or embedded newline (raw vtysh CLI injection payload) BEFORE it
// builds and runs the vtysh command. The show path is reachable over the
// unauthenticated local gRPC channel (GetBGPStatus), and unlike the config
// path it is not sanitized — so a newline-bearing token must never reach
// `vtysh -c` (FRR historically splits its -c argument on newlines).
//
// On revert (drop the net.ParseIP guard, restore `if ip == ""`), the raw
// ip is concatenated into the command and Vtysh is invoked — the
// vtyshCalls==0 and lastVtyshCmd assertions go RED.
func TestBGPNeighborReceivedRoutesRejectsUnvalidatedIP(t *testing.T) {
	badIPs := []string{
		"1.1.1.1\nconfigure terminal",
		"1.1.1.1 received-routes\nconfigure terminal\nno router bgp 65000",
		"1.1.1.1 all",  // trailing token — not a bare IP
		"not-an-ip",    // pure garbage
		"",             // empty must still error
		"1.1.1.1/24",   // prefix, not a host address
		"1.1.1.1\t x ", // tab/space bearing
	}
	for _, bad := range badIPs {
		fake := &fakeExecutor{}
		m := &Manager{exec: fake}
		out, err := m.GetBGPNeighborReceivedRoutes(context.Background(), bad)
		if err == nil {
			t.Errorf("GetBGPNeighborReceivedRoutes(%q): expected error, got nil (out=%q)", bad, out)
		}
		if fake.vtyshCalls != 0 {
			t.Errorf("GetBGPNeighborReceivedRoutes(%q): Vtysh was invoked (%d calls, cmd=%q) — the raw IP reached the command line",
				bad, fake.vtyshCalls, fake.lastVtyshCmd)
		}
	}
}

// TestBGPNeighborAdvertisedRoutesRejectsUnvalidatedIP is the advertised-routes
// twin of the received-routes belt test (#4588).
func TestBGPNeighborAdvertisedRoutesRejectsUnvalidatedIP(t *testing.T) {
	fake := &fakeExecutor{}
	m := &Manager{exec: fake}
	bad := "2001:db8::1\nconfigure terminal"
	if _, err := m.GetBGPNeighborAdvertisedRoutes(context.Background(), bad); err == nil {
		t.Errorf("GetBGPNeighborAdvertisedRoutes(%q): expected error, got nil", bad)
	}
	if fake.vtyshCalls != 0 {
		t.Errorf("GetBGPNeighborAdvertisedRoutes(%q): Vtysh invoked (%d, cmd=%q)", bad, fake.vtyshCalls, fake.lastVtyshCmd)
	}
}

// TestBGPNeighborDetailRejectsUnvalidatedIP verifies the detail wrapper
// rejects a non-empty malformed ip but STILL allows the empty ip (which
// selects every neighbor — a legitimate operation) (#4588).
func TestBGPNeighborDetailRejectsUnvalidatedIP(t *testing.T) {
	// Malformed non-empty ip -> error, no vtysh call.
	fake := &fakeExecutor{}
	m := &Manager{exec: fake}
	bad := "1.1.1.1\nno router bgp 65000"
	if _, err := m.GetBGPNeighborDetail(context.Background(), bad); err == nil {
		t.Errorf("GetBGPNeighborDetail(%q): expected error, got nil", bad)
	}
	if fake.vtyshCalls != 0 {
		t.Errorf("GetBGPNeighborDetail(%q): Vtysh invoked (%d, cmd=%q)", bad, fake.vtyshCalls, fake.lastVtyshCmd)
	}

	// Empty ip is legal: selects all neighbors, DOES call vtysh.
	fakeAll := &fakeExecutor{
		vtyshResp: map[string]string{"show bgp neighbor": "all neighbors output"},
	}
	mAll := &Manager{exec: fakeAll}
	out, err := mAll.GetBGPNeighborDetail(context.Background(), "")
	if err != nil {
		t.Fatalf("GetBGPNeighborDetail(\"\"): unexpected error: %v", err)
	}
	if out != "all neighbors output" {
		t.Errorf("GetBGPNeighborDetail(\"\"): got %q, want all-neighbors output", out)
	}
	if fakeAll.lastVtyshCmd != "show bgp neighbor" {
		t.Errorf("GetBGPNeighborDetail(\"\"): cmd = %q, want %q", fakeAll.lastVtyshCmd, "show bgp neighbor")
	}
}

// TestBGPNeighborValidIPsPass proves a syntactically valid neighbor IP —
// both IPv4 and IPv6 — passes the guard and builds the expected vtysh
// command verbatim (#4588 must not regress the happy path).
func TestBGPNeighborValidIPsPass(t *testing.T) {
	cases := []struct {
		name    string
		call    func(m *Manager, ctx context.Context, ip string) (string, error)
		ip      string
		wantCmd string
	}{
		{"received-v4", (*Manager).GetBGPNeighborReceivedRoutes, "10.0.0.1", "show bgp neighbor 10.0.0.1 received-routes"},
		{"received-v6", (*Manager).GetBGPNeighborReceivedRoutes, "2001:db8::1", "show bgp neighbor 2001:db8::1 received-routes"},
		{"advertised-v4", (*Manager).GetBGPNeighborAdvertisedRoutes, "10.0.0.1", "show bgp neighbor 10.0.0.1 advertised-routes"},
		{"advertised-v6", (*Manager).GetBGPNeighborAdvertisedRoutes, "2001:db8::1", "show bgp neighbor 2001:db8::1 advertised-routes"},
		{"detail-v4", (*Manager).GetBGPNeighborDetail, "10.0.0.1", "show bgp neighbor 10.0.0.1"},
		{"detail-v6", (*Manager).GetBGPNeighborDetail, "2001:db8::1", "show bgp neighbor 2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeExecutor{
				vtyshResp: map[string]string{tc.wantCmd: "ok"},
			}
			m := &Manager{exec: fake}
			out, err := tc.call(m, context.Background(), tc.ip)
			if err != nil {
				t.Fatalf("%s(%q): unexpected error: %v", tc.name, tc.ip, err)
			}
			if out != "ok" {
				t.Errorf("%s(%q): got %q, want %q", tc.name, tc.ip, out, "ok")
			}
			if fake.vtyshCalls != 1 {
				t.Errorf("%s(%q): Vtysh calls = %d, want 1", tc.name, tc.ip, fake.vtyshCalls)
			}
			if fake.lastVtyshCmd != tc.wantCmd {
				t.Errorf("%s(%q): cmd = %q, want %q", tc.name, tc.ip, fake.lastVtyshCmd, tc.wantCmd)
			}
			if strings.Contains(fake.lastVtyshCmd, "\n") {
				t.Errorf("%s(%q): built command contains a newline: %q", tc.name, tc.ip, fake.lastVtyshCmd)
			}
		})
	}
}
