package cli

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// identity.go maps an OS credential onto an xpf RBAC login class (#6701).
//
// Before this, the in-process CLI shell decided WHICH configured user you are
// from `os.Getenv("USER")` and, on no match, handed out `super-user`:
//
//	osUser := os.Getenv("USER")
//	for _, u := range cfg.System.Login.Users { if u.Name == osUser { ... } }
//	if !found { shell.SetUserClass("super-user") }
//
// Both halves are broken and each is sufficient on its own. `$USER` is set by
// the caller — per #5278 every login-class user has a real shell account, so a
// `class read-only` operator ran `USER=nobody cli` (or unset it) and was handed
// super-user. And even with a trustworthy identity, the `!found` default
// PROMOTES: an OS account that exists on the box but is absent from `system
// login` got the highest class rather than the lowest.
//
// The replacement takes the identity from the kernel (pkg/osident, real uid ->
// passwd) and defaults DOWN.

// ClassUnidentified is the login class given to a caller that RBAC cannot
// place: an unresolvable OS identity, or a resolved account absent from
// `system login`.
//
// It is `unauthorized`, a real system-defined class (config.LoginClassPermissions)
// whose permission set is EMPTY. That matters mechanically, not just
// cosmetically: the empty STRING is pkg/cli's deliberate legacy
// "no RBAC configured" shortcut, which checkPermission treats as allow-anything
// and showConfigRedacted treats as privileged-read-cleartext. Failing closed
// therefore has to name a class, never leave one unset. With `unauthorized`,
// resolveClassPerms returns an empty-but-present permission set, so
// checkPermission denies every command by name and showConfigRedacted redacts.
const ClassUnidentified = "unauthorized"

// ClassRootDefault is the class a uid-0 caller gets when `system login` does
// not configure an account matching its name.
//
// Junos parity: root is the super-user account and is not demoted by omission.
// It is also not a boundary xpf could enforce anyway — uid 0 owns the config
// database, the daemon process and the on-disk secrets, and pkg/cli's own
// #4057/#4099 redaction rationale already treats "the console root operator"
// as the privileged reader. This default applies ONLY when nothing in `system
// login` matches; an explicit `system login user root class <c>` wins, because
// a configured restriction silently ignored is the exact defect class this
// change exists to remove, and honoring it can only narrow privilege.
const ClassRootDefault = "super-user"

// ResolveLoginClass returns the RBAC login class for an OS identity against the
// active `system login` configuration, plus a human-readable reason for the
// decision (for the daemon's log line — the CLI never prints it).
//
// The caller is responsible for only invoking this when RBAC is actually
// configured (login != nil). With no `system login` stanza at all the CLI keeps
// its legacy unset-class allow-everything mode; that is a deliberate
// backward-compatibility contract (permissions.go) and is NOT what this
// function is for. Called with a nil login it does not assert: every non-root
// uid resolves to ClassUnidentified, and uid 0 takes ClassRootDefault by
// decision 2 below — a nil login is "nothing is configured about root", which
// is precisely the omission case the root default exists for. So it is
// fail-closed for every identity xpf can meaningfully contain, and unchanged
// for the one it cannot.
//
// Order of decision:
//
//  1. an EXPLICIT class on a matching `system login user` wins. An explicit
//     class is an instruction, and honouring it can only narrow privilege.
//
//     "MATCHING" IS BY NAME, so this cannot win when the caller has no name.
//     An earlier revision of this list said an explicit class wins "for any uid
//     including 0", which is false in exactly one reachable case: uid 0 shared
//     by two passwd accounts (the classic root/toor alias). osident then
//     reports ReasonAmbiguousUID with an empty Name, configuredClass matches
//     nothing, and decision 2 hands back ClassRootDefault — so
//     `system login user toor class read-only` is NOT applied and the caller
//     gets super-user (#6706 MINOR-5).
//
//     This is left as-is rather than fixed, and the reason is the same one
//     stated above: uid 0 already owns the config database, the daemon process
//     and the on-disk secrets, so it is not a boundary xpf can enforce — the
//     alternative would be locking the console out over a passwd alias. What is
//     NOT acceptable is misreporting it, so the reason string below names the
//     ambiguity instead of claiming root is unconfigured.
//
//  2. uid 0 otherwise gets ClassRootDefault — whether root is absent from
//     `system login` or is LISTED WITH NO CLASS. See rootOmittedClass below for
//     why the omission case must not fail closed.
//
//  3. a non-root account listed with an EMPTY class -> ClassUnidentified. RBAC
//     is configured and this account is listed but says nothing about what it
//     may do; falling through to the empty-string legacy mode would grant it
//     everything. (Pre-#6662 a packed `user alice class ops;` compiled exactly
//     this shape from a config that READS as restrictive, which is how the two
//     defects compounded.)
//
//  4. anything else — unresolvable identity, or an OS account absent from
//     `system login` -> ClassUnidentified.
func ResolveLoginClass(login *config.LoginConfig, id osident.Identity) (string, string) {
	class, listed := configuredClass(login, id)
	if class != "" {
		return class, fmt.Sprintf("login user %q class %q", configuredName(login, id), class)
	}
	if id.IsRoot() {
		if listed {
			return ClassRootDefault, fmt.Sprintf(
				"uid 0 (%s) is listed under `system login` with no class; applying the root "+
					"default rather than locking the console out on an omission", id)
		}
		// Do not claim uid 0 is unconfigured when we simply could not tell. With
		// an ambiguous or unreadable passwd the caller may well BE configured
		// under a name we failed to resolve, and saying otherwise sends the
		// operator to add a stanza that already exists (#6706 MINOR-5).
		if !id.Resolved() {
			return ClassRootDefault, fmt.Sprintf(
				"uid 0 could not be named (%s), so no `system login user` stanza could be "+
					"matched; applying the root default. Any explicit class configured for "+
					"this account was NOT applied", unidentifiedReason(id))
		}
		return ClassRootDefault, fmt.Sprintf(
			"uid 0 (%s) is not configured under `system login`; applying the root default", id)
	}
	if listed {
		return ClassUnidentified, fmt.Sprintf(
			"login user %q is configured with no class; refusing to fall back to the "+
				"unrestricted legacy mode", id.Name)
	}
	if !id.Resolved() {
		return ClassUnidentified, unidentifiedReason(id)
	}
	return ClassUnidentified, fmt.Sprintf(
		"OS account %q (uid %d) is not configured under `system login`", id.Name, id.UID)
}

// unidentifiedReason renders WHY the caller could not be named, from the
// category osident recorded.
//
// The distinction is operator-facing, not cosmetic. All three states deny
// identically — that is the point of failing closed — but they send the
// operator to three different places: create the account, fix the duplicate
// uid, or repair the passwd database. Reporting a read failure or a duplicate
// uid as "has no passwd entry" (which is what a single hardcoded message did)
// sends them to look for a missing account that is in fact present.
func unidentifiedReason(id osident.Identity) string {
	switch id.Reason {
	case osident.ReasonAmbiguousUID:
		return fmt.Sprintf(
			"uid %d is shared by more than one passwd account, so the kernel credential does "+
				"not name a single `system login user` — refusing to pick one", id.UID)
	case osident.ReasonLookupFailed:
		return fmt.Sprintf(
			"the passwd database could not be read for uid %d, so the caller cannot be "+
				"identified", id.UID)
	case osident.ReasonNoPasswdEntry:
		return fmt.Sprintf(
			"uid %d has no passwd entry, so the caller cannot be identified", id.UID)
	}
	return fmt.Sprintf("uid %d could not be resolved to an account name", id.UID)
}

// rootOmittedClass documents why uid 0 listed with NO class gets the root
// default rather than the fail-closed class, when a non-root account in the
// same shape is denied.
//
// The two are genuinely different questions. For a non-root account, `system
// login` is the authority on what that account may do, and saying nothing is
// not permission — denying is the only safe reading. For uid 0 it is neither
// safe nor meaningful:
//
//   - it is not an instruction. `set system login user root authentication
//     ssh-ed25519 "..."` is an ordinary way to give root a key, and it leaves
//     the class empty without expressing any intent to restrict anything. The
//     first draft of this function denied on it, which demoted the CONSOLE root
//     shell to `unauthorized` — a lockout of the lifeline, triggered by a
//     config that reads as purely additive. That is over-reach: a gate that
//     rejects valid configuration is its own outage.
//   - it is not enforceable. uid 0 owns the config database, the daemon process
//     and the on-disk secrets. A CLI-level denial is advisory at best.
//
// An EXPLICIT `system login user root class <c>` is a different matter and is
// still honoured (decision 1) — that IS an instruction, and a configured
// restriction silently ignored is the defect this whole change exists to
// remove. It remains advisory for the reason above; docs/system-login.md says
// so rather than implying uid 0 is contained.
const rootOmittedClass = "see ResolveLoginClass decision 2"

// configuredClass looks up id in the `system login user` list and returns its
// class plus whether the account was LISTED AT ALL. The two are distinct: a
// listed account with an empty class is a different state from an absent one,
// and they resolve differently for uid 0.
//
// For uid 0 the literal name "root" is consulted as well as the passwd-resolved
// name. A box may alias uid 0 to another entry (the classic `toor`), so an
// operator's explicit `system login user root class <c>` would otherwise be
// silently skipped on exactly the identity it names. The resolved name is tried
// first so a stanza written for the alias still wins where both exist.
//
// When BOTH rows exist, osident reports the uid as ambiguous rather than
// picking one (see osident.lookupPasswd), so the resolved name is empty and
// only the literal "root" is consulted here — deterministic, and still the
// console lifeline.
func configuredClass(login *config.LoginConfig, id osident.Identity) (string, bool) {
	if login == nil {
		return "", false
	}
	var listed bool
	for _, name := range candidateNames(id) {
		for _, u := range login.Users {
			if u == nil || u.Name != name {
				continue
			}
			listed = true
			if u.Class != "" {
				return u.Class, true
			}
		}
	}
	return "", listed
}

// configuredName reports which candidate name actually carried the class, for
// the log line — so an operator whose uid 0 resolved through a passwd alias can
// see WHICH stanza governed the decision.
func configuredName(login *config.LoginConfig, id osident.Identity) string {
	if login == nil {
		return id.Name
	}
	for _, name := range candidateNames(id) {
		for _, u := range login.Users {
			if u != nil && u.Name == name && u.Class != "" {
				return name
			}
		}
	}
	return id.Name
}

// candidateNames is the ordered set of `system login user` names that may
// govern id: its passwd-resolved name, plus the literal "root" for uid 0.
//
// It is deliberately at most ONE non-root name. A uid shared by several passwd
// accounts is reported by osident as unresolved (Name == "", ReasonAmbiguousUID)
// rather than as one of them, so no non-root caller can inherit a class
// configured for a different account that happens to share its uid. Enumerating
// every name for the uid here instead would be the wrong shape: it would grant
// the union of what those accounts may do.
//
// The `id.Resolved()` test is LOAD-BEARING, not a tidiness check, and this is
// the only place that protection exists. An unidentified caller has Name == "",
// and `system login user "" { class super-user; }` can be LIVE today. The
// reason is not a missing validator, and the exact mechanism matters because
// two plausible wrong versions of it exist.
//
//   - `config.ValidateLoginUsername` DOES reject an empty name
//     (schema_validators.go), and STRICT commit-check enforces it:
//     configstore.compileTreeStrict runs schemaValidateExpandedTreeForNode,
//     which returns `system login user: invalid value "": login user name must
//     not be empty`, and the commit fails.
//   - The TOLERANT ingress — Store.Load and Store.SyncApply, i.e. boot and
//     peer-sync — runs the SAME gate via Store.compileTreeLenient, but
//     DOWNGRADES the violation to `slog.Warn("typed-leaf schema violation in
//     tolerated config; continuing (a strict commit would reject this)")` and
//     KEEPS the entry. That downgrade is deliberate (#1319): hard-failing here
//     would blackout-boot a node carrying a legacy config, or alarm-loop HA
//     config sync from an un-upgraded primary.
//
// So the entry reaches the active config by a route that logs a warning and
// proceeds — not by one that rejects, and not silently either.
//
// Do NOT verify this against `config.CompileConfigLenient`. That is a
// different function: it runs no schema gate, returns nil, and keeps the entry
// with no warning at all. Probing it and concluding "the tolerant path is
// silent" is wrong, and was the mistake that produced an earlier revision of
// this comment. The tolerant PATH is configstore's compileTreeLenient.
//
// A guard that only held on the strict commit path would therefore not hold on
// the one path an operator does not drive by hand.
// Without this test the empty name would be offered to the match loop
// below, where `u.Name != name` succeeds against that entry and the
// unidentifiable caller is handed super-user — the #6701 hole reopened from the
// other side, reached without touching $USER at all.
//
// Note this is NOT protected by the `!id.Resolved()` branch in
// ResolveLoginClass: that branch runs AFTER the lookup and only selects the
// denial MESSAGE (with it removed the final return denies identically). The
// refusal to match has to happen here, before any name reaches the loop.
// TestUnresolvedIdentityMatchesNoConfiguredUser_6701 binds it.
func candidateNames(id osident.Identity) []string {
	var names []string
	if id.Resolved() {
		names = append(names, id.Name)
	}
	if id.IsRoot() && id.Name != "root" {
		names = append(names, "root")
	}
	return names
}
