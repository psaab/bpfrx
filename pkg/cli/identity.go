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
// function is for. Called with a nil login it still fails closed rather than
// asserting, so a future caller cannot accidentally reopen the hole.
//
// Order of decision:
//
//  1. an EXPLICIT class on a matching `system login user` always wins, for any
//     uid including 0. An explicit class is an instruction, and honouring it can
//     only narrow privilege.
//  2. uid 0 otherwise gets ClassRootDefault — whether root is absent from
//     `system login` or is LISTED WITH NO CLASS. See rootOmittedClass below for
//     why the omission case must not fail closed.
//  3. a non-root account listed with an EMPTY class -> ClassUnidentified. RBAC
//     is configured and this account is listed but says nothing about what it
//     may do; falling through to the empty-string legacy mode would grant it
//     everything. (Pre-#6662 a packed `user alice class ops;` compiled exactly
//     this shape from a config that READS as restrictive, which is how the two
//     defects compounded.)
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
		return ClassRootDefault, fmt.Sprintf(
			"uid 0 (%s) is not configured under `system login`; applying the root default", id)
	}
	if listed {
		return ClassUnidentified, fmt.Sprintf(
			"login user %q is configured with no class; refusing to fall back to the "+
				"unrestricted legacy mode", id.Name)
	}
	if !id.Resolved() {
		return ClassUnidentified, fmt.Sprintf(
			"uid %d has no passwd entry, so the caller cannot be identified", id.UID)
	}
	return ClassUnidentified, fmt.Sprintf(
		"OS account %q (uid %d) is not configured under `system login`", id.Name, id.UID)
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
// name. A box may alias uid 0 to another entry (the classic `toor`), and
// os/user.LookupId returns whichever passwd row comes first — so an operator's
// explicit `system login user root class <c>` would otherwise be silently
// skipped on exactly the identity it names. The resolved name is tried first so
// a stanza written for the alias still wins where both exist.
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
