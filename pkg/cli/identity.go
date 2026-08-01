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
//  1. resolved name matches a `system login user` with a NON-EMPTY class -> that class;
//  2. resolved name matches a user with an EMPTY class -> ClassUnidentified.
//     RBAC is configured and this account is listed but says nothing about what
//     it may do; falling through to the empty-string legacy mode would grant it
//     everything. (Pre-#6662 a packed `user alice class ops;` compiled exactly
//     this shape from a config that READS as restrictive.)
//  3. uid 0 with no match -> ClassRootDefault;
//  4. anything else — unresolvable identity, or an OS account absent from
//     `system login` -> ClassUnidentified.
func ResolveLoginClass(login *config.LoginConfig, id osident.Identity) (string, string) {
	if login != nil && id.Resolved() {
		for _, u := range login.Users {
			if u == nil || u.Name != id.Name {
				continue
			}
			if u.Class == "" {
				return ClassUnidentified, fmt.Sprintf(
					"login user %q is configured with no class; refusing to fall back to the "+
						"unrestricted legacy mode", id.Name)
			}
			return u.Class, fmt.Sprintf("login user %q class %q", id.Name, u.Class)
		}
	}
	if id.IsRoot() {
		return ClassRootDefault, fmt.Sprintf(
			"uid 0 (%s) is not configured under `system login`; applying the root default", id)
	}
	if !id.Resolved() {
		return ClassUnidentified, fmt.Sprintf(
			"uid %d has no passwd entry, so the caller cannot be identified", id.UID)
	}
	return ClassUnidentified, fmt.Sprintf(
		"OS account %q (uid %d) is not configured under `system login`", id.Name, id.UID)
}
