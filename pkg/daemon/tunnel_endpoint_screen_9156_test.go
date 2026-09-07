package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9156: collectAppliedTunnels decides which tunnels the ROUTING side creates.
//
// It screened on `Source != "" || Mode == "wireguard"` at the interface level
// and on NOTHING AT ALL in its per-unit loop, while EmitTunnelEndpointNames —
// which decides what the dataplane learns — requires BOTH endpoints. A tunnel
// with a source and no destination therefore passed here and failed there: the
// TUN was created, brought up and given its configured addresses, and every
// packet routed into it disappeared.
//
// The routing package HAS a correct endpoint guard and it is dead code
// (pkg/routing/tunnel.go: the daemon always sets AnchorOnly, so Apply always
// dispatches to applyAnchorLocked, which has no endpoint check at all), which
// is why the loss reached the wire.
func TestTunnelWithoutBothEndpointsIsNotApplied9156(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// CONTROL: complete, must be applied. Without it a cell asserting
		// "nothing was applied" passes on an empty result.
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &config.TunnelConfig{
			Name: "gr-0-0-0", Mode: "gre", Source: "10.0.0.1", Destination: "10.0.0.2",
		}},
		// The blackhole shape: source, no destination.
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: &config.TunnelConfig{
			Name: "gr-0-0-1", Mode: "gre", Source: "10.0.0.1",
		}},
		// WireGuard carries its peer in WgEndpoint and must NOT be screened
		// (#1736 S2b: screening it left the persistent wgN TUN uncreated while
		// the helper's control thread waited to open it).
		"wg0": {Name: "wg0", Tunnel: &config.TunnelConfig{Name: "wg0", Mode: "wireguard"}},
		// A per-UNIT tunnel with no endpoints at all — the loop that screened
		// nothing.
		"gr-0/0/2": {Name: "gr-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Tunnel: &config.TunnelConfig{Name: "gr-0-0-2", Mode: "gre"}},
		}},
		// A per-unit tunnel that IS complete, so the unit loop is not simply
		// disabled.
		"gr-0/0/3": {Name: "gr-0/0/3", Units: map[int]*config.InterfaceUnit{
			0: {Tunnel: &config.TunnelConfig{
				Name: "gr-0-0-3", Mode: "gre", Source: "10.0.0.5", Destination: "10.0.0.6",
			}},
		}},
	}

	got := map[string]bool{}
	for _, tc := range collectAppliedTunnels(cfg) {
		got[tc.Name] = true
	}
	want := map[string]bool{"gr-0-0-0": true, "wg0": true, "gr-0-0-3": true}
	for name := range want {
		if !got[name] {
			t.Errorf("%s must be applied; it is complete (or WireGuard). If nothing is "+
				"applied the negative assertions below are vacuous", name)
		}
	}
	if got["gr-0-0-1"] {
		t.Errorf("gr-0-0-1 has a source and NO destination and was applied. " +
			"EmitTunnelEndpointNames gives the dataplane no endpoint for it, so the " +
			"device is created, brought up and addressed while every packet routed " +
			"into it disappears")
	}
	if got["gr-0-0-2"] {
		t.Errorf("the per-UNIT tunnel with no endpoints at all was applied — that loop " +
			"screened nothing before #9156")
	}
	if len(got) != len(want) {
		t.Errorf("applied %v, want exactly %v", got, want)
	}

	// AGREEMENT with the emitter, in the same run. The two used to disagree,
	// and asserting each side separately is what let them.
	emitted := map[string]bool{}
	for _, e := range config.EmitTunnelEndpointNames(cfg) {
		emitted[e.Tunnel.Name] = true
	}
	for name := range got {
		if !emitted[name] {
			t.Errorf("%s is APPLIED by the routing side but the dataplane emitter gives "+
				"it no endpoint — that disagreement is exactly the #9156 blackhole", name)
		}
	}
}
