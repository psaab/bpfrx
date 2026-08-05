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

// foldLoginClassDenyToRepairableFloor is the tolerant load / peer-sync
// counterpart of validateLoginClassDenyStrict (#5831). It returns one warning
// per affected class and mutates cfg.
//
// Why this path does MORE than warn. The #1960 no-brick rule says an
// already-persisted or peer-synced config must still boot, so the strict
// rejection above cannot simply be re-run here. But a bare warning would leave
// the runtime fail-open exactly where it started: a config persisted before
// this gate existed (or synced from a peer running older code) would still
// reach pkg/cli/permissions.go with its full permission set and the deny
// silently dropped. Warning about a hole is not closing it.
//
// So the tolerant path resolves the ambiguity in the RESTRICTIVE direction —
// the operator asked for strictly less than `permissions` grants and we cannot
// compute how much less — BOUNDED BY REPAIRABILITY.
//
// Read that as blast-radius reduction, NOT as enforcement: the statement is
// still honored at NO granularity, and every bucket the floor retains is a
// bucket where it does nothing (see repairableFloorFold's LIMIT section, and
// loginClassDenyFoldWarning, which states this to the operator per class).
//
// The repairability bound is the whole reason this is not a collapse to
// view-only, and it is not a stylistic preference; a view-only collapse
// strands the box:
//
//	set system login class noc-admin permissions [ view configure ]
//	set system login class noc-admin deny-configuration "security policies"
//	set system login user root class noc-admin
//
// pkg/daemon/daemon_run.go assigns the CONFIGURED class to any OS user whose
// name matches a `system login user` (`if u.Name == osUser {
// shell.SetUserClass(u.Class) }`), and `root` is a name the username validator
// accepts. Account PROVISIONING skips root (daemon_system.go); the CLI class
// assignment does not. So the console operator above runs as `noc-admin`, and
// a view-only collapse takes `configure` away from the only login that could
// delete the offending stanza — while validateLoginClassDenyStrict rejects
// every commit until it IS deleted. A configure-only class collapses to the
// empty set, which is worse. Recovery would need an out-of-band shell.
//
// "The built-ins are consulted first" does NOT rescue that case: built-ins-first
// lookup only decides which table answers for a class NAME, it does not
// guarantee that any actual login is bound to a built-in.
//
// #1960's no-brick rule is therefore read as covering this: a config that
// LOADS but revokes the access needed to repair itself is the same failure with
// extra steps.
//
// RECOVERY PATH for an operator who already committed such a config: log in
// (the class keeps `view` if it had it), run `configure`, `delete system login
// class <name> deny-configuration` (and/or `deny-commands`), `commit`. That
// commit is the FIRST one the strict gate lets through, which is exactly the
// forcing function — nothing else about the box can be changed until the
// unenforceable statement is gone.
func foldLoginClassDenyToRepairableFloor(cfg *Config) []string {
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
		after := repairableFloorFold(before)
		lc.MappedPermissions = after
		warnings = append(warnings, loginClassDenyFoldWarning(r, before, after))
	}
	return warnings
}

// loginClassDenyFoldWarning renders the operator-facing warning for one folded
// class (#6838 review).
//
// The message is derived MECHANICALLY from the RETAINED set rather than
// written as prose, because the two must never drift: every permission level
// the fold keeps is, by construction, a level at which the deny statement is
// still completely unenforced. An earlier revision hard-coded a carve-out for
// `deny-configuration` alone and so claimed more than the behaviour delivered
// — a `deny-commands "show interfaces"` targets PermView, which the floor also
// retains, and that shape was silently described as restricted when it was
// not. Naming the retained set makes the claim exactly as wide as the fold.
func loginClassDenyFoldWarning(r loginClassDenyRejection, before, after []LoginClassPermission) string {
	leaves := strings.Join(r.leaves, " / ")
	if len(after) == 0 {
		return fmt.Sprintf(
			"system login class %q: %s is NOT enforced by xpf's coarse RBAC model "+
				"(downgraded to a warning on the tolerant load / peer-sync path). The "+
				"class is folded from %s to no permissions at all, so it can run "+
				"nothing and the statement has no remaining effect to enforce. Remove "+
				"it and re-express the restriction as a narrower `permissions` set; "+
				"every commit is rejected until you do.",
			r.class, leaves, describePerms(before))
	}
	return fmt.Sprintf(
		"system login class %q: %s is NOT enforced by xpf's coarse RBAC model "+
			"(downgraded to a warning on the tolerant load / peer-sync path). The "+
			"class is folded from %s to %s. That REDUCES BLAST RADIUS; it does NOT "+
			"enforce the statement — xpf cannot honor a per-command or "+
			"per-configuration deny at any granularity. Anything gated at %s is "+
			"therefore still COMPLETELY UNRESTRICTED for this class, including any "+
			"command or configuration this statement names: those levels are kept "+
			"only because they are what an operator needs to delete it. Remove the "+
			"statement and re-express the restriction as a narrower `permissions` "+
			"set; every commit is rejected until you do.",
		r.class, leaves, describePerms(before), describePerms(after), describePerms(after))
}

// repairableFloorFold reduces a coarse permission set to the smallest set that
// is BOTH never wider than the original AND still able to repair the config
// that triggered the fold (#5831): the intersection of the original with
// {PermView, PermConfig}.
//
// TWO properties, and the file's whole design tension lives between them.
//
// Never widens. PermView and PermConfig are emitted only when the input
// already held that bucket, or held PermAll — and PermAll subsumes both
// (pkg/cli/permissions.go checkPermission returns nil on `p == PermAll` for
// EVERY required permission). An input with neither returns nil, NOT
// PermView: a class that grants nothing today must not be handed view access
// by a restriction gate. That is why this is not an assignment to a literal.
//
// Never folds below the repair floor. PermConfig is exactly what
// requiredPermission demands for `configure` (permissions.go), and config mode
// applies no further per-command permission gate — checkPermission runs only
// on the operational dispatch path — so PermConfig IS the self-repair channel
// in xpf's coarse model. Dropping it is the one reduction that cannot be
// undone from the box. PermView rides along so the operator can read the
// config to find the statement.
//
// The buckets that DO get dropped — PermClear, PermControl, PermMaint, and
// PermAll itself — are the operational-verb buckets `deny-commands` targets.
// The motivating #5831 example (`permissions all` + `deny-commands "request
// system zeroize"`) therefore still loses PermAll and PermMaint, so zeroize is
// genuinely denied after the fold. The fold keeps its teeth on that half.
//
// THE LIMIT — general, not a `deny-configuration` special case (#6838 review).
// This fold is a BLAST-RADIUS REDUCTION, not enforcement. A retained bucket is
// a bucket where the deny statement does nothing at all, and the floor retains
// two of them:
//
//   - PermConfig gates `configure`, so `deny-configuration <anything>` is a
//     complete no-op.
//   - PermView gates `show` / `ping` / `traceroute` / `monitor`
//     (requiredPermission), so a `deny-commands` naming any of those — e.g.
//     `deny-commands "show interfaces"` — is equally a complete no-op.
//
// An earlier revision named only the first and so claimed more than it
// delivered. The operator warning is now generated FROM the retained set
// (loginClassDenyFoldWarning) precisely so this claim cannot drift wider than
// the behaviour again.
//
// Tightening the floor to `{PermConfig}` would make view-level denies bite,
// and is technically safe for repair — config mode applies no per-statement
// gate, so `configure` alone completes the fix. It is rejected because the
// cost lands on the wrong configs: a class whose deny targets `request` would
// lose ALL of `show`/`ping`/`monitor`, and a view-only class would fold to
// nothing. Trading a large, silent operational downgrade for partial
// enforcement of a control xpf cannot honor anyway is the worse deal. The
// enforcement that DOES exist is validateLoginClassDenyStrict refusing the
// commit; per-command/per-path RBAC — what Junos implements, and what would
// let these be honored properly — stays on #5831.
//
// Dropping Clear/Control/Maint even when only `deny-configuration` is present
// is deliberate over-restriction in a dimension the operator did not restrict:
// one rule that always errs restrictive is easier to reason about than a
// per-leaf branch, and unlike the configure bucket, losing those verbs is
// fully recoverable from the CLI.
func repairableFloorFold(perms []LoginClassPermission) []LoginClassPermission {
	var keepView, keepConfig bool
	for _, p := range perms {
		switch p {
		case PermAll:
			keepView, keepConfig = true, true
		case PermView:
			keepView = true
		case PermConfig:
			keepConfig = true
		}
	}
	var out []LoginClassPermission
	if keepView {
		out = append(out, PermView)
	}
	if keepConfig {
		out = append(out, PermConfig)
	}
	return out
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
