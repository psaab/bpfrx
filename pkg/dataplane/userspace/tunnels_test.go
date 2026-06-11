package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1866: a config commit that removes the wgN stanza must produce a
// snapshot WITHOUT the WG tunnel endpoint — the prune signal the Rust
// coordinator's teardown keys on.
func TestBuildTunnelEndpointSnapshotsDropsRemovedWireguard(t *testing.T) {
	withWg := &config.Config{}
	withWg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Name: "wg0",
			Tunnel: &config.TunnelConfig{
				Name:              "wg0",
				Mode:              "wireguard",
				WgListenPort:      51820,
				WgLocalPrivkeyHex: "a01010101010101010101010101010101010101010101010101010101010101a",
				WgPeerPubkeyHex:   "b02020202020202020202020202020202020202020202020202020202020202b",
				WgAllowedIPs:      []string{"10.77.0.0/24"},
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "wg0", LinuxName: "wg0", Ifindex: 42},
	}
	endpoints := buildTunnelEndpointSnapshots(withWg, interfaces)
	if len(endpoints) != 1 || endpoints[0].Mode != "wireguard" {
		t.Fatalf("pre-removal endpoints = %+v, want one wireguard endpoint", endpoints)
	}

	// The removal commit: wg0 gone from the compiled config. The
	// kernel TUN may still exist (documented S2a leak) — the snapshot
	// must NOT resurrect the endpoint from it.
	removed := &config.Config{}
	removed.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1"},
	}
	endpoints = buildTunnelEndpointSnapshots(removed, interfaces)
	if len(endpoints) != 0 {
		t.Fatalf("post-removal endpoints = %+v, want none", endpoints)
	}
}

// #1866 D3: the publish-boundary transition summary must change when
// the WG endpoint set changes and ignore non-WG endpoints.
func TestWgEndpointSetSummaryTransitions(t *testing.T) {
	empty := wgEndpointSetSummary(&ConfigSnapshot{})
	if empty != "" {
		t.Fatalf("empty snapshot summary = %q, want empty", empty)
	}
	if got := wgEndpointSetSummary(nil); got != "" {
		t.Fatalf("nil snapshot summary = %q, want empty", got)
	}
	withWg := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{ID: 2, Interface: "gr-0/0/0", Mode: "gre"},
			{ID: 1, Interface: "wg0", Mode: "wireguard", WgListenPort: 51820, Ifindex: 42},
		},
	}
	got := wgEndpointSetSummary(withWg)
	want := "1:wg0:51820@42"
	if got != want {
		t.Fatalf("summary = %q, want %q (GRE rows excluded)", got, want)
	}
	renamed := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{ID: 1, Interface: "wg1", Mode: "wireguard", WgListenPort: 51820, Ifindex: 43},
		},
	}
	if wgEndpointSetSummary(renamed) == got {
		t.Fatal("rename/ifindex change must change the summary")
	}

	m := &Manager{}
	m.logWgEndpointSetTransitionLocked(withWg, "test")
	if m.lastPublishedWgEndpoints != want {
		t.Fatalf("lastPublishedWgEndpoints = %q, want %q", m.lastPublishedWgEndpoints, want)
	}
	m.logWgEndpointSetTransitionLocked(withWg, "test")
	if m.lastPublishedWgEndpoints != want {
		t.Fatal("unchanged set must keep the recorded summary")
	}
	m.logWgEndpointSetTransitionLocked(&ConfigSnapshot{}, "test")
	if m.lastPublishedWgEndpoints != "" {
		t.Fatalf("removal must record the empty set, got %q", m.lastPublishedWgEndpoints)
	}
}
