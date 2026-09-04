package cli

import (
	"fmt"
	"strings"

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

// configMutationVerbs are the dispatchConfig verbs that CHANGE the candidate
// configuration and therefore carry a path to match.
//
// `edit`, `top` and `up` are deliberately absent: they move the cursor and
// change nothing. Entering a denied subtree is harmless because every mutation
// inside it is denied on its own, and gating navigation would also stop an
// operator merely LOOKING at a subtree they cannot edit.
//
// `commit`, `rollback` and `load` are absent for a different reason and are NOT
// covered by this gate — see configMutationPath.
var configMutationVerbs = map[string]bool{
	"set":        true,
	"delete":     true,
	"deactivate": true,
	"activate":   true,
	"copy":       true,
	"rename":     true,
	"insert":     true,
	"annotate":   true,
}

// configMutationPath returns the configuration path a verb will act on,
// resolved against the current edit path, and whether this verb is gated here.
//
// NOT GATED, and each for a stated reason rather than by omission:
//
//   - `edit`/`top`/`up` — navigation, no change (see configMutationVerbs).
//   - `commit`/`rollback` — they act on the candidate as a whole, not on a
//     path, so there is nothing for a path regex to match. A deny that stopped
//     `commit` would be denying the operator's own already-authorized edits.
//   - `load` — applies arbitrary config whose content is not known until it is
//     parsed, so enforcing deny-configuration against it means matching every
//     path the loaded content touches, which is a different mechanism from a
//     verb gate. Explicitly a REMAINING GAP rather than something this gate
//     quietly covers.
func configMutationPath(editPath, parts []string) (string, bool) {
	if len(parts) == 0 {
		return "", false
	}
	if !configMutationVerbs[parts[0]] {
		return "", false
	}
	if len(parts) < 2 {
		// The verb's own arity error is a better message than a permission
		// denial, and an empty path cannot match a meaningful deny anyway.
		return "", false
	}
	// THE RESOLVED PATH, not the typed remainder. See the edit-path bypass note
	// above: matching parts[1:] alone lets `edit system` walk a deny.
	full := make([]string, 0, len(editPath)+len(parts)-1)
	full = append(full, editPath...)
	full = append(full, parts[1:]...)
	return strings.Join(full, " "), true
}

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
func checkConfigRegexWith(cfg *config.Config, class string, editPath []string, line string) error {
	if class == "" {
		return nil
	}
	parts := strings.Fields(line)
	path, gated := configMutationPath(editPath, parts)
	if !gated {
		return nil
	}
	rules, ok, err := configRegexesFrom(cfg, class)
	if err != nil {
		return fmt.Errorf(
			"permission denied: login class %q has an invalid configuration regex: %w",
			class, err)
	}
	if !ok {
		return nil
	}
	decision := rules.Evaluate(path)
	if decision.Allowed {
		return nil
	}
	// AUDIT: the VERB and the resolved path's leading element only. A config
	// path's trailing tokens are operator data — `set system root-authentication
	// plain-text-password <secret>` puts the secret in the path itself — so the
	// full path must never reach a log line. Cut 3's canonicalPrefix cannot be
	// reused: it walks the operational cmdtree, which config paths do not use.
	return fmt.Errorf("permission denied: login class %q denies %s under %q (%s)",
		class, parts[0], configAuditRoot(path), decision.Reason)
}

// configAuditRoot renders only the first element of a configuration path.
//
// One element is a deliberate floor rather than a tuned depth: any deeper and
// the rendering depends on knowing which level of which hierarchy holds a
// secret, and that knowledge does not exist here. `system` tells an operator
// which tree they were denied in without revealing what they set.
func configAuditRoot(path string) string {
	fields := strings.Fields(path)
	if len(fields) == 0 {
		return "<empty>"
	}
	return fields[0]
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
