package config

import (
	"strings"
	"testing"
)

// #2078: the `security flow tcp-session` presence flags (no-syn-check,
// no-syn-check-in-tunnel, rst-invalidate-session, no-sequence-check) are typed
// and committed but the userspace AF_XDP dataplane enforces none of them (it
// has no TCP state machine). Research #2078 converged PLAN-KILL on enforcement
// and recommended C2: emit a commit-time advisory so an operator who sets one
// is not silently misled into believing it has runtime effect. These tests
// pin that the advisory fires for each knob and folds them into one warning.

// findTCPSessionAdvisory returns the single #2078 tcp-session advisory warning,
// or "" if none was emitted. It is keyed on the stable substrings the warning
// is built from, NOT on the per-knob token list (which the per-knob tests below
// assert separately), so the helper stays valid as knobs are added.
func findTCPSessionAdvisory(cfg *Config) string {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow tcp-session") &&
			strings.Contains(w, "accepted-only") &&
			strings.Contains(w, "#2078") {
			return w
		}
	}
	return ""
}

// Each knob, set in isolation, must produce the advisory AND the advisory must
// name that specific knob (so the warning is not a generic catch-all that would
// pass even if the knob were silently dropped). Driven through the production
// ParseSetCommand + SetPath + CompileConfig path (compileSetLines).
func TestTCPSessionAdvisory_PerKnob(t *testing.T) {
	cases := []struct {
		setLine string
		token   string // the exact knob name that must appear in the advisory
	}{
		{"set security flow tcp-session no-syn-check", "no-syn-check"},
		{"set security flow tcp-session no-syn-check-in-tunnel", "no-syn-check-in-tunnel"},
		{"set security flow tcp-session rst-invalidate-session", "rst-invalidate-session"},
		{"set security flow tcp-session no-sequence-check", "no-sequence-check"},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			cfg := compileSetLines(t, []string{tc.setLine})
			adv := findTCPSessionAdvisory(cfg)
			if adv == "" {
				t.Fatalf("%q did not emit the #2078 tcp-session advisory; warnings=%v",
					tc.setLine, cfg.Warnings)
			}
			if !strings.Contains(adv, tc.token) {
				t.Fatalf("advisory does not name knob %q: %q", tc.token, adv)
			}
			// Guard against a substring false-positive: no-syn-check is a
			// prefix of no-syn-check-in-tunnel. When ONLY no-syn-check is set,
			// the advisory must not also claim the longer in-tunnel knob.
			if tc.token == "no-syn-check" && strings.Contains(adv, "no-syn-check-in-tunnel") {
				t.Fatalf("advisory wrongly names no-syn-check-in-tunnel when only no-syn-check set: %q", adv)
			}
		})
	}
}

// All four knobs set together must fold into a SINGLE advisory that names all
// four (the C2 plan calls for one folded warning across the whole family, not
// four separate lines).
func TestTCPSessionAdvisory_FoldsAllKnobs(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session no-syn-check",
		"set security flow tcp-session no-syn-check-in-tunnel",
		"set security flow tcp-session rst-invalidate-session",
		"set security flow tcp-session no-sequence-check",
	})

	// Exactly one advisory line, not one per knob.
	count := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security flow tcp-session") &&
			strings.Contains(w, "accepted-only") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one folded tcp-session advisory, got %d; warnings=%v",
			count, cfg.Warnings)
	}

	adv := findTCPSessionAdvisory(cfg)
	for _, token := range []string{
		"no-syn-check", "no-syn-check-in-tunnel",
		"rst-invalidate-session", "no-sequence-check",
	} {
		if !strings.Contains(adv, token) {
			t.Fatalf("folded advisory missing knob %q: %q", token, adv)
		}
	}
}

// A tcp-session stanza with ONLY enforced/typed fields (timeouts) and none of
// the unenforced presence flags must NOT emit the advisory — proves the warning
// is gated on the actual knobs, not on the presence of the tcp-session node.
func TestTCPSessionAdvisory_TimeoutsOnlyNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session established-timeout 600",
	})
	if cfg.Security.Flow.TCPSession == nil {
		t.Fatal("TCPSession is nil; established-timeout did not compile")
	}
	if adv := findTCPSessionAdvisory(cfg); adv != "" {
		t.Fatalf("unexpected tcp-session advisory with only a timeout set: %q", adv)
	}
}

// No tcp-session stanza at all: no advisory, no nil-deref.
func TestTCPSessionAdvisory_AbsentNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone trust",
	})
	if adv := findTCPSessionAdvisory(cfg); adv != "" {
		t.Fatalf("unexpected tcp-session advisory with no tcp-session stanza: %q", adv)
	}
}
