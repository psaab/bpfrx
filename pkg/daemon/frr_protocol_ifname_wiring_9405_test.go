package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAssembleFRRConfigWiresProtocolIfNameResolver9405 binds the WIRING, not
// the resolver.
//
// pkg/frr can resolve protocol interface operands correctly and the box still
// renders `interface ge-0/0/1.0` if assembleFRRConfig — the sole production
// FullConfig constructor (TestFRRFullConfigConstructedOnlyByAssembler) — never
// hands it a resolver, because a nil IfNameResolver is deliberately IDENTITY
// so direct generateProtocols callers keep byte-identical output. That default
// is exactly what makes the missing wire silent: nothing errors, nothing warns,
// the managed section just goes back to naming devices the kernel does not
// have. Severing the field assignment in daemon_ipmon.go must fail HERE.
//
// It asserts a CONFIG-DEPENDENT resolution rather than `!= nil`: a resolver
// bound to the wrong config — or a stray identity closure — passes a nil check
// and still renders an unbindable operand. reth0 resolves only through THIS
// config's RethToPhysical map, so the assertion cannot be satisfied by any
// resolver that is not this cfg's.
func TestAssembleFRRConfigWiresProtocolIfNameResolver9405(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {
			Name:            "ge-0/0/2",
			RedundantParent: "reth0",
			Units:           map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"reth0": {
			Name: "reth0",
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0},
				80: {Number: 80, VlanID: 180},
			},
		},
	}

	fc := d.assembleFRRConfig(cfg, nil)
	if fc.IfNameResolver == nil {
		t.Fatal("assembleFRRConfig left IfNameResolver nil: pkg/frr then falls back " +
			"to identity and the managed section renders the AUTHORED Junos " +
			"reference, which Linux dev_valid_name() rejects — no IGP attaches, " +
			"silently (#9405)")
	}

	for _, tc := range []struct{ ref, want string }{
		{"ge-0/0/2.0", "ge-0-0-2"},   // slash rewrite + unit-0 collapse
		{"reth0.0", "ge-0-0-2"},      // RETH -> local physical member
		{"reth0.80", "ge-0-0-2.180"}, // the .<vlan-id> arm (#5107), not .80
	} {
		if got := fc.IfNameResolver(tc.ref); got != tc.want {
			t.Errorf("IfNameResolver(%q) = %q, want %q — the assembler must wire "+
				"Config.ResolveKernelIfName for THIS config, not an identity or a "+
				"partial resolver", tc.ref, got, tc.want)
		}
	}
}
