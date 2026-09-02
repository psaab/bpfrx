package config

import "testing"

// #7422 row 13: the default-policy-log flags are inert under a default
// DENY/REJECT, and the surfaces that report them must say so.
//
// WHY THE ROW LOOKS CLOSED AND IS NOT. The flags are threaded end to end —
// `builder.go` -> `default_log_session_init` on the wire ->
// `forwarding_build/mod.rs` -> `policy.rs` — so a reader tracing the plumbing
// concludes they are live and strikes the row. The inertness is one level away,
// in the runtime CONDITION rather than the wiring: session-init/session-close
// RT_FLOW records fire only for a default-PERMIT verdict, because that is the
// only one that installs a session. #3534 established this at commit time and
// warns about it; the renderers surfaced the raw flags unconditionally.
//
// THE FIXTURE MUST EXERCISE BOTH DEFAULT VERDICTS. A permit-only cell cannot see
// the gate at all — the flags pass through unchanged there — and a deny-only
// cell passes on the UNFIXED code only if it asserts the wrong direction. The
// pair is what makes the assertion mean something.
func TestDefaultPolicyLogFlagsInertUnderDenyDefault7422(t *testing.T) {
	mk := func(def PolicyAction, init, close bool) *Config {
		return &Config{Security: SecurityConfig{
			DefaultPolicy:                def,
			DefaultPolicyLogSessionInit:  init,
			DefaultPolicyLogSessionClose: close,
		}}
	}

	for _, tc := range []struct {
		name      string
		cfg       *Config
		wantInert bool
		wantInit  bool
		wantClose bool
	}{
		// LIVE — a session is installed, so the records fire.
		{"permit-all with both flags", mk(PolicyPermit, true, true), false, true, true},
		{"permit-all with session-init only", mk(PolicyPermit, true, false), false, true, false},

		// INERT — no session is installed for the records to fire on.
		{"deny-all with both flags", mk(PolicyDeny, true, true), true, false, false},
		{"reject-all with both flags", mk(PolicyReject, true, true), true, false, false},
		{"deny-all with session-close only", mk(PolicyDeny, false, true), true, false, false},

		// Nothing configured: there is nothing to be inert, and the renderers'
		// behaviour must be unchanged for the overwhelmingly common config.
		{"deny-all, no flags", mk(PolicyDeny, false, false), false, false, false},
		{"permit-all, no flags", mk(PolicyPermit, false, false), false, false, false},

		{"nil config", nil, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DefaultPolicyLogFlagsInert(tc.cfg); got != tc.wantInert {
				t.Errorf("DefaultPolicyLogFlagsInert = %v, want %v", got, tc.wantInert)
			}
			gotInit, gotClose := EffectiveDefaultPolicyLogFlags(tc.cfg)
			if gotInit != tc.wantInit || gotClose != tc.wantClose {
				t.Errorf("EffectiveDefaultPolicyLogFlags = (%v,%v), want (%v,%v)",
					gotInit, gotClose, tc.wantInit, tc.wantClose)
			}
		})
	}
}

// The advisory and the renderers must agree about WHICH configs are inert,
// because they now share one predicate. This asserts the agreement rather than
// re-deriving the condition: if the advisory ever warns about a config the
// renderers still report as live (or vice versa), an operator is told two
// different things about one setting.
func TestDefaultPolicyLogAdvisoryAgreesWithRenderers7422(t *testing.T) {
	for _, def := range []PolicyAction{PolicyPermit, PolicyDeny, PolicyReject} {
		for _, init := range []bool{false, true} {
			for _, cl := range []bool{false, true} {
				cfg := &Config{Security: SecurityConfig{
					DefaultPolicy:                def,
					DefaultPolicyLogSessionInit:  init,
					DefaultPolicyLogSessionClose: cl,
				}}
				warned := len(validateDefaultPolicyLogWarnings(cfg)) > 0
				inert := DefaultPolicyLogFlagsInert(cfg)
				if warned != inert {
					t.Errorf("default=%v init=%v close=%v: advisory warned=%v but "+
						"renderers treat inert=%v — the two must not disagree about "+
						"one setting", def, init, cl, warned, inert)
				}
				gotInit, gotClose := EffectiveDefaultPolicyLogFlags(cfg)
				if inert && (gotInit || gotClose) {
					t.Errorf("default=%v init=%v close=%v: inert but renderers would "+
						"still report (%v,%v)", def, init, cl, gotInit, gotClose)
				}
				if !inert && (gotInit != init || gotClose != cl) {
					t.Errorf("default=%v init=%v close=%v: LIVE flags must pass through "+
						"unchanged, got (%v,%v)", def, init, cl, gotInit, gotClose)
				}
			}
		}
	}
}
