package config

import (
	"fmt"
	"sort"
	"strings"
)

// #5831: a custom `system login class <name>` may carry four fine-grained
// regex sub-statements. xpf's runtime RBAC gate (pkg/cli/permissions.go
// checkPermission) is COARSE — it matches a required permission against the
// class's mapped bucket set and consults NONE of the four regexes. Before
// #5831 all four were "recognized, not enforced": the config committed and the
// regex configured nothing.
//
// That is fail-open for the RESTRICTIVE half. An operator writing
//
//	set system login class limited permissions all
//	set system login class limited deny-commands "request system zeroize"
//
// got a class that committed cleanly and could still zeroize the box. A
// security restriction was accepted as inert state, which is strictly worse
// than refusing it: the operator has a config that says the verb is denied and
// a box on which it is not.
//
// DIRECTIONALITY (the two halves are NOT symmetric — do not "simplify" this
// into one list):
//
//   - deny-commands / deny-configuration SUBTRACT from the permission bits.
//     Dropping them leaves the denied verbs ALLOWED — the class ends up MORE
//     permissive than the config says. Fail-OPEN. Hard-rejected here.
//   - allow-commands / allow-configuration ADD to the permission bits (Junos:
//     commands usable "in addition to" those the permission bits allow).
//     Dropping them leaves the class with a SUBSET of what the operator wrote
//     — less access, never more. Fail-CLOSED. They keep the #4304
//     accept-with-advisory treatment, and rejecting them would break configs
//     that are already safe.
//
// Note the Junos precedence rule cuts the same way: allow-commands WINS over
// deny-commands when both match a command. So a class pairing them is a
// deny-with-exceptions, and rejecting on deny-presence alone still catches it
// — there is no shape where an allow leaf makes a deny leaf safe to drop.

// loginClassDenyRejection describes one class whose restrictive regexes xpf
// cannot honor. Split out from the gate so the strict error and the tolerant
// warning render from the identical data and cannot drift apart.
type loginClassDenyRejection struct {
	class  string
	leaves []string
}

// collectLoginClassDenyRejections returns, in deterministic config order, every
// custom login class carrying a restrictive regex the coarse gate will not
// enforce. Reads LoginClass.DenyLeavesPresent (presence, recorded at parse) —
// NOT DenyCommands/DenyConfiguration, whose empty string cannot distinguish
// "absent" from the maximally-restrictive `deny-commands ""`.
func collectLoginClassDenyRejections(cfg *Config) []loginClassDenyRejection {
	if cfg == nil || cfg.System.Login == nil {
		return nil
	}
	var out []loginClassDenyRejection
	for _, lc := range cfg.System.Login.Classes {
		if lc == nil || len(lc.DenyLeavesPresent) == 0 {
			continue
		}
		// Deduplicate: the same leaf can be written twice (two set lines, or a
		// hierarchical block repeating it). Sorted so the message is stable
		// regardless of the order the operator wrote them in.
		seen := map[string]bool{}
		leaves := make([]string, 0, len(lc.DenyLeavesPresent))
		for _, l := range lc.DenyLeavesPresent {
			if !seen[l] {
				seen[l] = true
				leaves = append(leaves, l)
			}
		}
		sort.Strings(leaves)
		out = append(out, loginClassDenyRejection{class: lc.Name, leaves: leaves})
	}
	return out
}

// validateLoginClassDenyStrict is the strict commit / commit-check gate: it
// hard-rejects a custom login class carrying deny-commands or
// deny-configuration, so a restriction xpf will not enforce can never be
// accepted as inert state (#5831).
//
// This is the fail-closed HALF of #5831. It does not implement the regexes;
// enforcing them across every operational-command and configuration dispatch
// point needs a matching-semantics decision and stays on #5831. Refusing a
// control we do not implement is strictly safer than pretending to accept it,
// and it is reversible: when enforcement lands, this gate goes away.
func validateLoginClassDenyStrict(cfg *Config) error {
	rejections := collectLoginClassDenyRejections(cfg)
	if len(rejections) == 0 {
		return nil
	}
	r := rejections[0] // first-failing-gate-wins: report one, deterministically
	return fmt.Errorf(
		"system login class %q: %s is NOT enforced by xpf's coarse RBAC model, "+
			"so accepting it would leave the denied commands/configuration ALLOWED "+
			"while the config says otherwise; remove it and express the restriction "+
			"with a narrower `permissions` set instead (per-command deny enforcement "+
			"is tracked separately)",
		r.class, strings.Join(r.leaves, " / "))
}

// foldLoginClassDenyToViewOnly is the tolerant load / peer-sync counterpart of
// validateLoginClassDenyStrict (#5831). It returns one warning per affected
// class and mutates cfg.
//
// Why this path does MORE than warn. The #1960 no-brick rule says an
// already-persisted or peer-synced config must still boot, so the strict
// rejection above cannot simply be re-run here. But a bare warning would leave
// the runtime fail-open exactly where it started: a config persisted before
// this gate existed (or synced from a peer running older code) would still
// reach pkg/cli/permissions.go with its full permission set and the deny
// silently dropped. Warning about a hole is not closing it.
//
// So the tolerant path resolves the ambiguity in the RESTRICTIVE direction:
// the operator asked for strictly less than `permissions` grants, we cannot
// compute how much less, so the class collapses to view-only. That is the same
// least-privilege fold mapJunosPermissions already applies to Junos permission
// tokens with no precise coarse equivalent, so it is the established reading of
// "we cannot model this exactly" in this file, not a new policy.
//
// It cannot brick the box: resolveClassPerms consults the BUILT-IN classes
// (super-user/operator/read-only/config-viewer) FIRST and this fold only ever
// touches a custom class, so console super-user access is untouched and an
// operator can always log in and remove the offending stanza.
func foldLoginClassDenyToViewOnly(cfg *Config) []string {
	rejections := collectLoginClassDenyRejections(cfg)
	if len(rejections) == 0 {
		return nil
	}
	byName := map[string]*LoginClass{}
	for _, lc := range cfg.System.Login.Classes {
		if lc != nil {
			byName[lc.Name] = lc
		}
	}
	warnings := make([]string, 0, len(rejections))
	for _, r := range rejections {
		lc := byName[r.class]
		if lc == nil {
			continue
		}
		before := lc.MappedPermissions
		lc.MappedPermissions = viewOnlyFold(before)
		warnings = append(warnings, fmt.Sprintf(
			"system login class %q: %s is NOT enforced by xpf's coarse RBAC model "+
				"(downgraded to warning on tolerant path); the class is folded to "+
				"%s so it cannot be MORE permissive than the config states — "+
				"remove the statement and re-express the restriction as a narrower "+
				"`permissions` set",
			r.class, strings.Join(r.leaves, " / "), describePerms(lc.MappedPermissions)))
	}
	return warnings
}

// viewOnlyFold reduces a coarse permission set to view-only WITHOUT ever
// widening it (#5831).
//
// The non-widening argument, case by case:
//   - contains PermAll — PermAll matches every required permission, so it
//     strictly subsumes PermView. all -> view is a reduction.
//   - contains PermView — view is retained, every other bucket is dropped.
//     Identity or reduction.
//   - contains NEITHER (an empty set from `permissions unauthorized`, or a
//     hypothetical set with no view bucket) — returns nil, NOT PermView.
//
// That last case is the whole reason this is not a one-line assignment to
// []LoginClassPermission{PermView}: a class that today grants NOTHING would be
// handed view access by such an assignment, which is a widening — the precise
// fail-open direction this gate exists to prevent.
func viewOnlyFold(perms []LoginClassPermission) []LoginClassPermission {
	for _, p := range perms {
		if p == PermView || p == PermAll {
			return []LoginClassPermission{PermView}
		}
	}
	return nil
}

// describePerms renders a coarse permission set for an operator-facing
// warning; the empty set is spelled out rather than shown as "{}".
func describePerms(perms []LoginClassPermission) string {
	if len(perms) == 0 {
		return "no permissions at all"
	}
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, loginClassPermName(p))
	}
	sort.Strings(names)
	return "{" + strings.Join(names, ",") + "}"
}
