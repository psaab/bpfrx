package config

// default_policy_log_inert_7422.go is the SINGLE decision behind "do the
// `security policies default-policy-log session-init/session-close` flags
// actually do anything?"
//
// #3534 established the answer at COMMIT time: the session-init/session-close
// RT_FLOW records fire only for a default-PERMIT verdict, which installs a
// session. A default-DENY or default-REJECT installs no session for the records
// to fire on and is already logged by the policy-deny record, so the flags are
// accepted-but-inert. `validateDefaultPolicyLogWarnings` warns about exactly
// that.
//
// #7422 row 13: three RENDERERS surfaced the raw flags UNCONDITIONALLY, so an
// audit surface reported `LogSessionInit: true` on a deny-all box where nothing
// logs. That is the #6534 shape — a value the box reports as in effect while it
// deliberately is not — and it is the reverse of the rationale that added them
// (#3670 wanted audit tooling not to read the boundary as unlogged while the
// dataplane IS emitting; the inverse error is just as misleading).
//
// The flags are threaded end to end (`builder.go` -> `default_log_session_init`
// on the wire -> `forwarding_build/mod.rs` -> `policy.rs`), which reads as
// "not inert, nothing to fix here". The inertness is one level away, in the
// runtime CONDITION rather than the plumbing, which is why the row survived.
//
// Both the advisory and the renderers route through this file so they cannot
// disagree about which case is which — the house pattern for this issue's
// other rows.

// DefaultPolicyLogFlagsInert reports whether configured default-policy-log
// flags are accepted but will never fire.
//
// False when no flag is configured: there is nothing to be inert. That matches
// the advisory's own early return, and it keeps the renderers' behaviour
// unchanged for the overwhelmingly common config.
func DefaultPolicyLogFlagsInert(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	if !cfg.Security.DefaultPolicyLogSessionInit && !cfg.Security.DefaultPolicyLogSessionClose {
		return false
	}
	// Live for permit-all (a session is installed). deny-all / reject-all
	// install no session, so the session-init/close records never fire.
	return cfg.Security.DefaultPolicy != PolicyPermit
}

// EffectiveDefaultPolicyLogFlags returns the default-policy log flags as they
// will actually BEHAVE at runtime, which is what an audit surface should
// report.
//
// Renderers must use this rather than reading
// `Security.DefaultPolicyLogSessionInit/Close` directly; reading the raw fields
// is what produced #7422 row 13.
func EffectiveDefaultPolicyLogFlags(cfg *Config) (sessionInit, sessionClose bool) {
	if cfg == nil || DefaultPolicyLogFlagsInert(cfg) {
		return false, false
	}
	return cfg.Security.DefaultPolicyLogSessionInit, cfg.Security.DefaultPolicyLogSessionClose
}
