package userspace

import (
	"fmt"
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

// #1873 helpers: build a config + interface snapshot set for N GRE
// tunnels by name. Each tunnel gets a unit-0 endpoint.
func tunnelTestConfig(names ...string) (*config.Config, []InterfaceSnapshot) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	interfaces := make([]InterfaceSnapshot, 0, len(names))
	for i, name := range names {
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			Tunnel: &config.TunnelConfig{
				Name:        name,
				Mode:        "gre",
				Source:      "10.0.0.1",
				Destination: fmt.Sprintf("10.0.1.%d", i+1),
			},
		}
		interfaces = append(interfaces, InterfaceSnapshot{
			Name:    name + ".0",
			Ifindex: 100 + i,
		})
	}
	return cfg, interfaces
}

func endpointIDsByInterface(endpoints []TunnelEndpointSnapshot) map[string]uint16 {
	out := make(map[string]uint16, len(endpoints))
	for _, ep := range endpoints {
		out[ep.Interface] = ep.ID
	}
	return out
}

// #1873 core pin: adding or removing one tunnel must not renumber any
// other tunnel. Under the retired positional allocator, removing
// gr-a renumbered gr-b and gr-c; under stable ids they are invariant.
func TestBuildTunnelEndpointSnapshotsStableAcrossAddRemove(t *testing.T) {
	cfgAll, ifAll := tunnelTestConfig("gr-a", "gr-b", "gr-c")
	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAll, ifAll))
	if len(idsAll) != 3 {
		t.Fatalf("baseline endpoints = %v, want 3", idsAll)
	}

	// Remove the FIRST-sorting tunnel — the positional scheme's worst
	// case (every later tunnel shifted).
	cfgRm, ifRm := tunnelTestConfig("gr-b", "gr-c")
	idsRm := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgRm, ifRm))
	for _, name := range []string{"gr-b.0", "gr-c.0"} {
		if idsRm[name] != idsAll[name] {
			t.Fatalf("%s id changed on unrelated removal: %d -> %d", name, idsAll[name], idsRm[name])
		}
	}

	// Add a new tunnel — existing ids invariant again.
	cfgAdd, ifAdd := tunnelTestConfig("gr-a", "gr-b", "gr-c", "gr-d")
	idsAdd := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAdd, ifAdd))
	for name, id := range idsAll {
		if idsAdd[name] != id {
			t.Fatalf("%s id changed on unrelated add: %d -> %d", name, id, idsAdd[name])
		}
	}
	// And ids are the pure hash of the name (HA agreement by
	// construction — no history input).
	for name, id := range idsAdd {
		if want := config.StableTunnelEndpointID(name); id != want {
			t.Fatalf("%s id = %d, want pure hash %d", name, id, want)
		}
	}
}

// #1873 eligibility-flap pin (Codex plan r1 M2 / AGY plan r1): an
// interface absent from the runtime snapshot must remove ONLY its own
// row — every other tunnel's id is identical in both builds.
func TestBuildTunnelEndpointSnapshotsEligibilityFlapDoesNotShiftIDs(t *testing.T) {
	cfg, ifAll := tunnelTestConfig("gr-a", "gr-b", "gr-c")
	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifAll))

	// gr-a's netdev is transiently absent (link flap at build time).
	ifFlap := make([]InterfaceSnapshot, 0, 2)
	for _, snap := range ifAll {
		if snap.Name == "gr-a.0" {
			continue
		}
		ifFlap = append(ifFlap, snap)
	}
	idsFlap := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifFlap))
	if _, present := idsFlap["gr-a.0"]; present {
		t.Fatalf("flapped tunnel still has a row: %v", idsFlap)
	}
	for _, name := range []string{"gr-b.0", "gr-c.0"} {
		if idsFlap[name] != idsAll[name] {
			t.Fatalf("%s id shifted on gr-a flap: %d -> %d", name, idsAll[name], idsFlap[name])
		}
	}
}

// #1873 R-B belt-and-braces: if a colliding pair somehow reaches the
// snapshot builder (commit gate bypassed — e.g. pre-existing lenient
// config), the later-sorting collider is dropped, never double-keyed.
func TestBuildTunnelEndpointSnapshotsDropsLaterSortingCollider(t *testing.T) {
	// wg1408.0 / wg78.0 both fold to 824 (frozen pin in pkg/config).
	cfg, ifAll := tunnelTestConfig("wg1408", "wg78")
	endpoints := buildTunnelEndpointSnapshots(cfg, ifAll)
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want exactly one (collider dropped)", endpoints)
	}
	// Sorted iteration: "wg1408" sorts before "wg78", so wg1408.0 wins.
	if endpoints[0].Interface != "wg1408.0" {
		t.Fatalf("kept %q, want earlier-sorting wg1408.0", endpoints[0].Interface)
	}
	if endpoints[0].ID != config.StableTunnelEndpointID("wg1408.0") {
		t.Fatalf("kept id %d, want %d", endpoints[0].ID, config.StableTunnelEndpointID("wg1408.0"))
	}
}
