package cli

import (
	"github.com/psaab/xpf/pkg/config"
)

// Fine-grained configuration-mutation enforcement for `system login class`
// deny-configuration (#7172 cut 4).
//
// THIS IS THE FIRST PER-COMMAND AUTHORIZATION THAT HAS EVER EXISTED ON THIS
// PATH, and a reviewer should read it that way rather than as a filter added to
// an existing gate. Until now `configure` was all-or-nothing: once
// checkPermission admitted the `configure` verb, every mutation inside config
// mode ran unchecked. That was deliberate and is documented as such in
// pkg/config/compiler_login_deny.go. So there is no prior art here to be
// consistent with, and nothing upstream of this narrowing the input.
//
// ── THE EDIT-PATH BYPASS, WHICH IS THE POINT OF THIS FILE ────────────────
//
// Junos config mode is hierarchical: `edit system` moves the cursor, and every
// later `set`/`delete` is relative to it. dispatchConfig reflects that —
// each mutating case builds `append(store.GetEditPath(), parts[1:]...)`.
//
// So an operator under `deny-configuration "system root-authentication"` who
// types
//
//	edit system
//	set root-authentication plain-text-password hunter2
//
// hands the gate the line `set root-authentication ...`, which does NOT match
// the deny. This is the configuration twin of the abbreviation bypass
// canonicalization closes on the operational side, and it is worse: an
// abbreviation is a deliberate short form, while navigating with `edit` is the
// ordinary way operators work. The gate therefore matches the RESOLVED path —
// edit path plus typed remainder — and never the typed fragment.

// checkConfigRegex enforces deny-configuration against a config-mode line.
//
// Mirrors checkCommandRegex's posture exactly, and deliberately so: fail closed
// on a class whose regex does not compile, and scope every refusal to classes
// that actually configured regexes so an unrestricted operator's typo still
// gets its ordinary error rather than a permission denial.
//
// It does NOT canonicalize. Configuration paths are not abbreviated the way
// operational commands are — the config grammar's prefix handling lives in the
// store's parser, and a path is matched as written against a regex the operator
// wrote against the same grammar. The edit-path resolution above is the
// normalization this side needs.
func (c *CLI) checkConfigRegex(line string) error {
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	var editPath []string
	if c.store != nil {
		editPath = c.store.GetEditPath()
	}
	return checkConfigRegexWith(cfg, c.userClass, editPath, line)
}

// checkConfigRegexWith is the store-free whole decision.
//
// Split out for the same reason cut 3's equivalent is: driving the decision
// directly is what keeps its error branches tested.
//
// #8597: this doc used to say "no supported path puts a `deny-configuration`
// class into ActiveConfig until cut 6 retires #6838's gate, so every branch
// here is unreachable through a store". That is STALE. #7172 cut 6 landed and
// retired the #5831/#6838 admission gate — `pkg/config/compiler_tailgates.go`
// records it in as many words — so such a config commits now AND takes effect,
// and this path IS reachable by an ordinary operator config.
//
// The identical sentence in permissions_regex.go was corrected by #8289 for the
// deny-COMMANDS half. The deny-CONFIGURATION half was not brought along, and
// the cost was exactly what the stale rationale licensed: every cell in
// permissions_config_regex_7172_test.go drove this function directly and NOT
// ONE went through a store, so the wiring from ActiveConfig through the
// session's class and edit path was untested for a deny-bypass-critical gate.
// TestDenyConfigurationIsReachableThroughAStore_8597 closes that.
//
// A rationale asserting unreachability outlives the change that makes the thing
// reachable, because nothing re-checks a comment. This is the second time the
// same sentence has done it in this package.
// checkConfigRegexWith delegates to config.AuthorizeConfigMutation.
//
// #9154: THE DECISION MOVED TO pkg/config so the gRPC and REST surfaces can
// reach it. They could not before, and neither called it — the regexes were
// enforced on the console alone, while the shipped remote `cli` and the REST
// API mutated configuration with no restriction at all. #7172 cut 6 had already
// moved the RESOLUTION there for exactly this reason ("so this gate, the
// operational gate and the gRPC gate all read one implementation"); the
// decision stayed behind, where the other two surfaces could not call it.
func checkConfigRegexWith(cfg *config.Config, class string, editPath []string, line string) error {
	return config.AuthorizeConfigMutation(cfg, class, editPath, line)
}

// configRegexesFrom resolves the `*-configuration` allow/deny pair in force for
// class.
//
// #7172 cut 6 turned the ALLOW half on and moved the whole decision into
// pkg/config, so this gate, the operational gate and the gRPC gate all read one
// implementation. The deny-only scoping comment that used to live here is gone
// with the scoping.
func configRegexesFrom(cfg *config.Config, class string) (config.CompiledLoginRegexes, bool, error) {
	return config.ConfigurationLoginRegexesFor(cfg, class)
}
