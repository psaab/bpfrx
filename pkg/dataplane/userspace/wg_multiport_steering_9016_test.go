package userspace

import "testing"

// #9016: the multi-port WireGuard advisory in pkg/config asserts a specific
// dataplane fact — that only the FIRST configured listen-port is steered onto
// the AF_XDP path. This cell pins that fact HERE, at the mechanism, so the two
// cannot drift: if multi-port steering lands (#1434 Increment 2), this reds and
// whoever lands it is sent to the advisory text that describes it.
//
// The advisory's previous text went further and said the unsteered tunnel was
// "dead ... no handshake ever completes". Nothing bound that claim, which is
// how it survived while being false: the host-inbound filter admits every
// configured port and each tunnel binds its own socket, so the unsteered port
// is served by the KERNEL path, not by nothing.
func TestOnlyFirstWireGuardListenPortIsSteered9016(t *testing.T) {
	snap := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{ID: 1, Mode: "wireguard", WgListenPort: 51820},
			{ID: 2, Mode: "wireguard", WgListenPort: 51821},
		},
	}
	got := snapshotWgListenPort(snap)
	if got != 51820 {
		t.Fatalf("snapshotWgListenPort = %d, want 51820 (the FIRST wireguard endpoint). "+
			"If multi-port steering has landed, the pkg/config multi-port advisory "+
			"(compiler_validate_wireguard_multiport.go) still tells the operator only "+
			"one port is steered — update it in the same change.", got)
	}

	// Order is what selects the steered port, so a reversed list must steer the
	// other one. Without this, a hard-coded 51820 would satisfy the assertion
	// above and the cell would prove nothing about "first".
	rev := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{ID: 2, Mode: "wireguard", WgListenPort: 51821},
			{ID: 1, Mode: "wireguard", WgListenPort: 51820},
		},
	}
	if got := snapshotWgListenPort(rev); got != 51821 {
		t.Fatalf("snapshotWgListenPort with the order reversed = %d, want 51821", got)
	}

	// A single tunnel is the ordinary case and must be steered.
	one := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{{ID: 1, Mode: "wireguard", WgListenPort: 51820}},
	}
	if got := snapshotWgListenPort(one); got != 51820 {
		t.Fatalf("single-tunnel snapshotWgListenPort = %d, want 51820", got)
	}

	// A non-wireguard endpoint must not be mistaken for one.
	none := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{{ID: 1, Mode: "gre", WgListenPort: 51820}},
	}
	if got := snapshotWgListenPort(none); got != 0 {
		t.Fatalf("a gre endpoint yielded a steered WG port %d; want 0", got)
	}
}
