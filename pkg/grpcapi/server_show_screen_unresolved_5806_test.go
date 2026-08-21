package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestShowScreenReportsUnresolvedReferenceWithNoProfilesDefined is the #5806
// fail-on-revert guard for the WORST case of the status surface.
//
// `showScreen` early-returns "No screen profiles configured" when
// cfg.Security.Screen is empty. That is precisely the tolerant-load / HA-sync
// shape that strands a reference: the profile definitions are gone, the zone
// still claims one, and the dataplane enforces nothing — yet the operator was
// told, in as many words, that nothing was configured. The unresolved-reference
// block must therefore be emitted BEFORE that early return.
//
// RED on revert, measured at three placements rather than asserted (#6839
// round 2 — the round-1 claim held for two of them and the third was rc=0):
//
//   - DELETE the loop → rc=1, but from the COMPILER, not from here:
//     `dpuserspace` becomes an unused import. Worth naming, because a build
//     failure is not this guard firing, and if any other reference to that
//     package is ever added the deletion becomes invisible to it.
//   - MOVE it INTO the `else` branch (so the empty-Screen case skips it) →
//     rc=1 here, on the zone/profile assertion. This is the placement the
//     original claim described.
//   - MOVE it AFTER the whole if/else, to the end of showScreen → rc=0 before
//     this round. Every assertion below was `strings.Contains`, which cannot
//     see position, so the block still appeared — just last — and the guard
//     stayed green while the stated property ("emitted BEFORE that early
//     return") was violated. The ordering assertion at the end of this test
//     closes that third placement.
func TestShowScreenReportsUnresolvedReferenceWithNoProfilesDefined(t *testing.T) {
	cfg := &config.Config{}
	// No cfg.Security.Screen entries at all — the stranding shape.
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "gone"},
	}

	s := &Server{}
	var buf strings.Builder
	s.showScreen(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "trust") || !strings.Contains(out, "gone") {
		t.Fatalf("status must name the zone and the undefined profile it references; got:\n%s", out)
	}
	// The status must state the enforcement disposition, not merely that a
	// reference dangles: "unresolved" alone cannot tell an operator whether they
	// are currently exposed or currently over-blocked, and those demand opposite
	// responses. It must be the SHARED string, so the metric HELP and this block
	// cannot drift into describing the behaviour differently.
	if !strings.Contains(out, dpuserspace.ScreenUnresolvedDisposition) {
		t.Fatalf("status must carry the shared disposition string; got:\n%s", out)
	}
	// The wording must NOT read as a permit. "forwarded unscreened" invites an
	// operator to think the firewall is passing traffic it would otherwise deny;
	// policy evaluation is in fact unaffected.
	if !strings.Contains(out, "policy evaluation is unaffected") {
		t.Errorf("disposition must say policy evaluation is unaffected, so it is not "+
			"read as a permit; got:\n%s", out)
	}
	if !strings.Contains(out, "No screen profiles configured") {
		t.Errorf("the pre-existing empty-inventory line must still be rendered; got:\n%s", out)
	}

	// ORDER, not just presence (#6839 round 2). Every assertion above is
	// containment, and containment is position-blind: moving the emit to the end
	// of showScreen keeps all of them green while the operator reads
	// "No screen profiles configured" FIRST — the exact misreading this guard
	// exists to prevent, since that line says "nothing was asked for" and the
	// correction arrives after it.
	//
	// The check itself is SHARED with the local-CLI guard (#6839 round 3) rather
	// than hand-written here. Both renderers ship one contract, so a divergence
	// between two copies of its assertion is always a bug; round 2 wrote this
	// check here only, and the CLI peer stayed position-blind.
	if err := dpuserspace.CheckScreenUnresolvedRenderOrder(out); err != nil {
		t.Errorf("gRPC showScreen: %v", err)
	}
}

// TestShowScreenSilentWhenReferencesResolve is the negative control: a healthy
// config must not grow an unresolved-reference block, so the guard above cannot
// pass by the renderer emitting the block unconditionally.
func TestShowScreenSilentWhenReferencesResolve(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Screen = map[string]*config.ScreenProfile{"alpha": {}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "alpha"},
	}

	s := &Server{}
	var buf strings.Builder
	s.showScreen(cfg, &buf)
	if out := buf.String(); strings.Contains(out, "Unresolved screen profile references") {
		t.Fatalf("a resolved reference must not render the unresolved block; got:\n%s", out)
	}
}
