package vrrp

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #5695 (codex-182 M16): the configured GARP/NA burst count was used verbatim
// as the per-VIP send budget on failover, with NO upper clamp — an unbounded
// count fans the full burst (1 immediate frame + (count-1) 50ms follow-ups) per
// VIP, a self-inflicted CPU/socket-exhaustion vector. sendGARP now clamps the
// effective count to config.GratuitousARPBurstClamp.
//
// These tests capture the COUNT sendGARP passes to the burst senders via the
// garpBurstFn / naBurstFn seams — no AF_PACKET I/O — and assert it is clamped.
//
// FAIL-ON-REVERT: delete the `else if clamped, was := ...` clamp branch in
// sendGARP (leaving `count := vi.cfg.GARPCount; if count <= 0 { count = 3 }`)
// and the clamp assertions below observe the raw 100000 and go RED.

// captureBurstCounts swaps the burst/probe seams to record the count sendGARP
// passes, restoring them when the returned cleanup runs. The recorded value is
// the LAST count observed on each family.
func captureBurstCounts(t *testing.T, v4count, v6count *int) func() {
	t.Helper()
	origGARP, origNA, origProbe := garpBurstFn, naBurstFn, arpProbeFn
	garpBurstFn = func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error {
		*v4count = count
		return nil
	}
	naBurstFn = func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error {
		*v6count = count
		return nil
	}
	arpProbeFn = func(iface string, senderIP, targetIP net.IP) error { return nil }
	return func() { garpBurstFn, naBurstFn, arpProbeFn = origGARP, origNA, origProbe }
}

func instanceWithGARPCount(t *testing.T, garpCount int, vips ...string) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:        "xpf-test-nonexistent0",
		GroupID:          102,
		Priority:         200,
		GARPCount:        garpCount,
		VirtualAddresses: vips,
	}, &net.Interface{Name: "xpf-test-nonexistent0"}, make(chan VRRPEvent, 8), nil)
	vi.setState(StateMaster)
	return vi
}

func TestSendGARPClampsBurstCount_5695(t *testing.T) {
	cases := []struct {
		name      string
		garpCount int
		wantV4    int
		wantV6    int
	}{
		{"unset defaults to 3", 0, 3, 3},
		{"deployed value unclamped", 8, 8, 8},
		{"junos max unclamped", 16, 16, 16},
		{"one over clamp", config.GratuitousARPBurstClamp + 1, config.GratuitousARPBurstClamp, config.GratuitousARPBurstClamp},
		{"pathological clamped", 100000, config.GratuitousARPBurstClamp, config.GratuitousARPBurstClamp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v4, v6 int
			cleanup := captureBurstCounts(t, &v4, &v6)
			defer cleanup()

			vi := instanceWithGARPCount(t, tc.garpCount, "10.0.0.100/24", "fd00::100/64")
			vi.sendGARP(true) // force: bypass the time dampener

			if v4 != tc.wantV4 {
				t.Errorf("IPv4 GARP burst count = %d, want %d (GARPCount=%d, clamp=%d)",
					v4, tc.wantV4, tc.garpCount, config.GratuitousARPBurstClamp)
			}
			if v6 != tc.wantV6 {
				t.Errorf("IPv6 NA burst count = %d, want %d (GARPCount=%d, clamp=%d)",
					v6, tc.wantV6, tc.garpCount, config.GratuitousARPBurstClamp)
			}
		})
	}
}

// TestSendGARPClampNeverExceedsBudget is the security invariant in one line:
// no matter how large the configured count, the effective per-VIP burst budget
// never exceeds the runtime clamp.
func TestSendGARPClampNeverExceedsBudget_5695(t *testing.T) {
	var v4, v6 int
	cleanup := captureBurstCounts(t, &v4, &v6)
	defer cleanup()

	vi := instanceWithGARPCount(t, 1<<30, "10.0.0.100/24", "fd00::100/64")
	vi.sendGARP(true)

	if v4 > config.GratuitousARPBurstClamp || v6 > config.GratuitousARPBurstClamp {
		t.Fatalf("burst budget escaped the clamp: v4=%d v6=%d, clamp=%d (M16 exhaustion vector)",
			v4, v6, config.GratuitousARPBurstClamp)
	}
}
