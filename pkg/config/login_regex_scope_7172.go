package config

// login_regex_scope_7172.go answers "which command regexes apply to this login
// class", for BOTH enforcement surfaces.
//
// It lives here rather than in pkg/cli because #7172 has two gates — the on-box
// CLI (cut 3) and the gRPC listener (cut 5b) — and the question they must not
// disagree about is not the MATCHING (that is CompiledLoginRegexes.Evaluate,
// already shared) but the ADMISSION: whose regexes are in force, and whether a
// leaf counts as present. A second copy of that decision is how one surface
// comes to enforce a class the other treats as unrestricted, which is a
// bypass rather than a cosmetic drift.
//
// pkg/cli.loginRegexesFrom is now a one-line delegation to this, so the cut-3
// tests keep exercising the same code they always did.

// OperationalDenyRegexesFor compiles the operational command regexes in force
// for class, and reports whether the class has any at all.
//
// ok=false is the overwhelmingly common case — a class with no fine-grained
// rules — and callers MUST skip evaluation entirely rather than evaluate an
// empty ruleset, because an empty ruleset is not the same object as no
// ruleset: #7172's fail-closed arms (an unresolvable command, an unmappable
// RPC) apply ONLY to a class that configured regexes.
//
// DENY ONLY, deliberately, and this is not an oversight for a later reader to
// "complete". `allow-commands` commits today and is documented as inert
// (compiler_system.go files it under "Neutral not-enforced knobs"). An allow
// regex is an ALLOWLIST, so enforcing it here would be a LOCKOUT on upgrade: a
// live class carrying `allow-commands "show interfaces"` would abruptly lose
// `show version`, `configure`, and everything else — a restriction its author
// was explicitly told was inert. Allow enforcement lands in cut 6 alongside the
// #6838 retirement, so both leaves go live in one step with one release note.
func OperationalDenyRegexesFor(cfg *Config, class string) (CompiledLoginRegexes, bool, error) {
	return loginDenyRegexesFor(cfg, class, LoginRegexPlainFamily, "deny-commands", func(lc *LoginClass) string {
		return lc.DenyCommands
	})
}

// loginDenyRegexesFor is the shared body: find the class, decide leaf PRESENCE,
// compile.
//
// PRESENCE, NOT VALUE, for the deny leaf, and the two are opposite. Both
// `deny-commands ""` and a valueless `deny-commands` flatten to the empty
// string, and an empty POSIX regex matches EVERY command — so an empty deny
// denies everything, the most restrictive thing an operator can write, while an
// ABSENT deny denies nothing. Only DenyLeavesPresent separates them, which is
// why #6838's classification table has to outlive #6838's gate.
func loginDenyRegexesFor(
	cfg *Config,
	class string,
	family LoginRegexFamily,
	leaf string,
	pattern func(*LoginClass) string,
) (CompiledLoginRegexes, bool, error) {
	if cfg == nil || cfg.System.Login == nil || class == "" {
		return CompiledLoginRegexes{}, false, nil
	}
	for _, lc := range cfg.System.Login.Classes {
		if lc == nil || lc.Name != class {
			continue
		}
		denySet := false
		for _, present := range lc.DenyLeavesPresent {
			if present == leaf {
				denySet = true
				break
			}
		}
		if !denySet {
			return CompiledLoginRegexes{}, false, nil
		}
		compiled, err := CompileLoginRegexes(family, "", false, pattern(lc), true)
		if err != nil {
			return CompiledLoginRegexes{}, false, err
		}
		return compiled, true, nil
	}
	return CompiledLoginRegexes{}, false, nil
}

// DenySource returns the deny pattern as the operator AUTHORED it, and whether
// a deny leaf was present at all.
//
// The authored text rather than the compiled form: it is what an operator can
// search their config for, and #7172's audit rule keeps operator ARGUMENT
// values out of log lines — a pattern is config the operator wrote, not data a
// caller supplied, so it is safe to echo where a matched command is not.
func (c CompiledLoginRegexes) DenySource() (string, bool) {
	return c.denySrc, c.denySet
}
