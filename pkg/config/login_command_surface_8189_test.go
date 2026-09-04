package config

import (
	"strings"
	"testing"
)

// #8189. Measured BEFORE this change, on the real commit path: an
// unenforceable `deny-commands` committed clean with exactly one warning — the
// generic "recognized (custom RBAC)" line — and no advisory of any kind. The
// enforceable pattern produced the identical output, so nothing distinguished
// them. That silence is what these cells replace.

func loginClassCfg(t *testing.T, pattern string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range []string{
		"set system login class limited permissions view",
		`set system login class limited deny-commands "` + pattern + `"`,
	} {
		p, q, err := ParseSetCommandQuoted(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		if err := tree.SetPathQuoted(p, q); err != nil {
			t.Fatalf("setpath %q: %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func withSurface(t *testing.T, name string, cmds []string) {
	t.Helper()
	saved := registeredCommandSurfaces
	registeredCommandSurfaces = nil
	if name != "" {
		RegisterCommandSurface(name, func() []string { return cmds })
	}
	t.Cleanup(func() { registeredCommandSurfaces = saved })
}

func advisoryFor(cfg *Config) (string, bool) {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "REGISTERED command set") {
			return w, true
		}
	}
	return "", false
}

// A pattern that matches nothing in the registered set warns, and the wording
// carries what an operator needs to act: the class, the pattern, the surface,
// and that the restriction still applies on the box.
func TestUnenforceableDenyWarnsAtCommit_8189(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show interfaces"})
	cfg := loginClassCfg(t, "^zzz-not-a-real-command")

	w, ok := advisoryFor(cfg)
	if !ok {
		t.Fatalf("no commit advisory for an unenforceable deny pattern; warnings: %q", cfg.Warnings)
	}
	for _, want := range []string{`"limited"`, "^zzz-not-a-real-command", "the gRPC surface", "on-box CLI"} {
		if !strings.Contains(w, want) {
			t.Errorf("advisory does not carry %q: %s", want, w)
		}
	}
}

// THE LOAD-BEARING CONTROL. A false advisory here is worse than no advisory:
// it tells an operator at commit that a restriction which DOES work does
// nothing, and the operator then removes it or broadens it. So a pattern that
// IS enforceable must produce no advisory at all.
//
// RED on over-reach: invert the `matched` test in UnenforceableDenySurfaces and
// every enforceable pattern starts warning — which is exactly the shape that
// would degrade a real posture.
func TestEnforceableDenyDoesNotWarn_8189(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show interfaces"})
	cfg := loginClassCfg(t, "^show route")

	if w, ok := advisoryFor(cfg); ok {
		t.Errorf("an ENFORCEABLE deny pattern produced an unenforceability advisory: %s\n"+
			"Telling an operator that a working restriction does nothing is worse than "+
			"the silence this replaces — they remove it or widen it.", w)
	}
}

// Silence is the resolution for every ambiguous case. With no surface
// registered — a build that does not link one, or a unit test — an empty
// population makes EVERY pattern vacuously unmatched, and declaring them all
// unenforceable would be the false advisory on every config in the field.
func TestNoRegisteredSurfaceIsSilent_8189(t *testing.T) {
	withSurface(t, "", nil)
	if w, ok := advisoryFor(loginClassCfg(t, "^zzz-not-a-real-command")); ok {
		t.Errorf("advisory emitted with NO registered surface: %s", w)
	}
}

// Same for a surface that registers but reports nothing — the drift case where
// a table is empty or a derivation returns nothing.
func TestEmptyRegisteredSetIsSilent_8189(t *testing.T) {
	withSurface(t, "the gRPC surface", nil)
	if w, ok := advisoryFor(loginClassCfg(t, "^zzz-not-a-real-command")); ok {
		t.Errorf("advisory emitted for a surface reporting ZERO commands: %s\n"+
			"An empty set makes every pattern vacuously unmatched.", w)
	}
}

// Spelling independence, carried over from #7172's
// TestUnenforceableDenyDetectionIsSpellingIndependent7172: the check must ask
// whether the pattern MATCHES a command, never inspect the pattern's shape.
// regexp.LiteralPrefix returns "" for an anchored pattern, so a literal-prefix
// heuristic would cover the unanchored spelling and miss the anchored one --
// the spelling Juniper's guidance tells operators to use for anything complex.
func TestAdvisoryIsSpellingIndependent_8189(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show interfaces"})
	for _, pat := range []string{`show route`, `^show route`} {
		if _, ok := advisoryFor(loginClassCfg(t, pat)); ok {
			t.Errorf("pattern %q is enforceable in both spellings but warned", pat)
		}
	}
	for _, pat := range []string{`zzz-nope`, `^zzz-nope`} {
		if _, ok := advisoryFor(loginClassCfg(t, pat)); !ok {
			t.Errorf("pattern %q is unenforceable in both spellings but did not warn", pat)
		}
	}
}
