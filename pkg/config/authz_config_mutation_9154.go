package config

import (
	"fmt"
	"strings"
)

// #9154: THE CONFIGURATION REGEXES WERE ENFORCED ON EXACTLY ONE OF THREE
// DISPATCH SURFACES.
//
// `allow-configuration` / `deny-configuration` were evaluated only by the on-box
// CLI. The gRPC listener the shipped `cli` binary speaks to, and the REST API,
// both performed config mutations without ever consulting them -- so an operator
// who withheld configuration authority from a class saw it withheld only if that
// person happened to log in at the console. The documented way to administer the
// box bypassed it.
//
// Measured, with the control that makes it a finding rather than a guess:
//
//	deny-configuration-only : authorizeRPCCommand(Set) -> nil       ALLOWED
//	deny-commands-only      : authorizeRPCCommand(Set) -> denied    the gate IS live
//
// The second row is what proves the machinery works and simply was not asked
// this question.
//
// SO THE DECISION LIVES HERE, in pkg/config, beside
// ConfigurationLoginRegexesFor. #7172 cut 6 moved the RESOLUTION here for
// exactly this reason -- "so this gate, the operational gate and the gRPC gate
// all read one implementation" -- and the decision stayed behind in pkg/cli,
// where the other two surfaces cannot reach it. A rule enforced by whichever
// caller remembers to call it is the shape that produced this defect.

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

// AuthorizeConfigMutation adjudicates one config-mode line against a class's
// `*-configuration` regexes, returning nil when the mutation is permitted.
//
// editPath is the operator's current `edit` cursor, or nil where the caller has
// already resolved it -- the remote CLI prepends its own edit path before
// sending, so the gRPC and REST surfaces pass nil and gate the line they will
// actually act on.
func AuthorizeConfigMutation(cfg *Config, class string, editPath []string, line string) error {
	if class == "" {
		return nil
	}
	parts := strings.Fields(line)
	path, gated := configMutationPath(editPath, parts)
	if !gated {
		return nil
	}
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
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
