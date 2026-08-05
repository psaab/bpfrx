package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
// RED on revert: move the ScreenUnresolvedProfileLines loop below the
// empty-Screen branch (or delete it) and the output is the bare
// "No screen profiles configured", failing every assertion here.
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
	if !strings.Contains(out, "UNSCREENED") {
		t.Fatalf("status must state the enforcement disposition, not just that a "+
			"reference dangles; got:\n%s", out)
	}
	if !strings.Contains(out, "No screen profiles configured") {
		t.Errorf("the pre-existing empty-inventory line must still be rendered; got:\n%s", out)
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
