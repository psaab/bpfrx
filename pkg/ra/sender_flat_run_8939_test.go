package ra

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8939, the WIRE consequence, asserted where it is observable.
//
// The compiler-side cell (pkg/config/ra_interface_flat_run_8939_test.go)
// asserts that `DefaultLifetimeSet` survives a flat run. This one asserts what
// losing it DID, because "a boolean stayed false" and "the router advertises
// itself as a default router when the operator said it is not" are not
// obviously the same statement — and the second is the reason this row
// outranked every other on the board.
//
// It is the SAME defect #4119 fixed, reached by a different route. #4119
// removed a `lifetime <= 0` coercion in buildRA; #8939 never sets the flag in
// the first place, and buildRA's fallback does the rest. The cells next door
// (sender_marshal_4119_test.go) pin the sender's half; this pins that the
// COMPILER still hands it a set flag when the operator used the flat spelling.
//
//	set … interface trust0 managed-configuration default-lifetime 0
//	  before: RouterLifetime 1800  ("I am a default router")
//	  after:  RouterLifetime 0     ("I am NOT a default router")
func TestBuildRA_FlatRunPreservesExplicitZero8939(t *testing.T) {
	compile := func(t *testing.T, cmds ...string) *config.RAInterfaceConfig {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, c := range cmds {
			p, err := config.ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		for _, i := range cfg.Protocols.RouterAdvertisement {
			if i != nil && i.Interface == "trust0" {
				return i
			}
		}
		t.Fatal("no RA interface trust0 (#8939)")
		return nil
	}
	b := "set protocols router-advertisement interface trust0 "

	// REFERENCE ARM: the spelling that always worked must reach the wire as 0.
	// Without this, a buildRA that stopped honouring the flag entirely would
	// make the comparison below pass with both arms wrong.
	split := newTestSender3895(compile(t, b+"managed-configuration",
		b+"default-lifetime 0")).buildRA()
	if split.RouterLifetime != 0 {
		t.Fatalf("the SPLIT spelling no longer reaches the wire as RouterLifetime "+
			"0 (got %v); #4119 has regressed and the comparison below is "+
			"meaningless (#8939)", split.RouterLifetime)
	}

	packed := newTestSender3895(compile(t,
		b+"managed-configuration default-lifetime 0")).buildRA()
	if packed.RouterLifetime != split.RouterLifetime {
		t.Errorf("packed spelling marshals RouterLifetime %v, split marshals %v.\n"+
			"An explicit `default-lifetime 0` means \"this router is NOT a default "+
			"router\" (RFC 4861 §6.2.1). Advertising %v instead hijacks host "+
			"default-route selection on a multi-router LAN — #4119's defect, "+
			"reached by dropping the leaf rather than by coercing it (#8939)",
			packed.RouterLifetime, split.RouterLifetime, packed.RouterLifetime)
	}
}
