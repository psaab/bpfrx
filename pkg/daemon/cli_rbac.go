package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// userClassSetter is the SetUserClass seam applyCLILoginClass writes through.
// Production passes the real *cli.CLI; the test passes a recorder, so the
// daemon-side wiring is asserted without standing up a shell.
type userClassSetter interface {
	SetUserClass(class string)
}

// applyCLILoginClass sets the RBAC login class on the in-process console shell
// from the invoking process's OS credential (#6701).
//
// It replaces:
//
//	osUser := os.Getenv("USER")
//	found := false
//	for _, u := range cfg.System.Login.Users {
//	    if u.Name == osUser { shell.SetUserClass(u.Class); found = true; break }
//	}
//	if !found { shell.SetUserClass("super-user") }
//
// Two independent holes, either sufficient on its own:
//
//   - `$USER` is set by whoever invoked the process. Per #5278 the daemon
//     provisions every `system login user` with a real shell account
//     (`useradd -m -s /bin/bash`), so an operator restricted to
//     `class read-only` ran `USER=nobody xpf` — or unset the variable — and
//     matched nothing. Identity now comes from the kernel instead: pkg/osident
//     reads the REAL uid and resolves it through passwd, which the caller's own
//     environment cannot rewrite.
//
//   - the `!found` default PROMOTED. An OS account that exists on the box but
//     is absent from `system login` — and, before the fix, any caller at all —
//     received the highest class in the system. cli.ResolveLoginClass defaults
//     DOWN to cli.ClassUnidentified (`unauthorized`: an empty-but-PRESENT
//     permission set, so checkPermission denies every command by name and
//     showConfigRedacted masks secrets). uid 0 keeps the Junos-parity
//     super-user default, but only when `system login` says nothing about it —
//     an explicit `system login user root class <c>` still wins, because a
//     configured restriction silently ignored is the very defect being removed.
//
// The `cfg.System.Login == nil` early return is deliberate and is NOT a
// fail-open: with no `system login` stanza the class is left UNSET, which is
// pkg/cli's documented legacy allow-everything mode for a deployment that never
// configured RBAC (permissions.go checkPermission / showConfigRedacted both
// short-circuit on the empty class). That contract is unchanged here; #6662 is
// what stops a config that DOES configure RBAC from compiling into it.
//
// Every resolution is logged once, at shell startup — not in a loop — so an
// operator locked out by their own config can see exactly why in the journal.
func applyCLILoginClass(shell userClassSetter, cfg *config.Config, id osident.Identity) {
	if shell == nil || cfg == nil || cfg.System.Login == nil {
		return
	}
	class, reason := cli.ResolveLoginClass(cfg.System.Login, id)
	if class == cli.ClassUnidentified {
		slog.Warn("CLI RBAC: caller is not authorized by `system login`",
			"identity", id.String(), "uid", id.UID, "class", class, "reason", reason)
	} else {
		slog.Info("CLI RBAC: resolved login class",
			"identity", id.String(), "uid", id.UID, "class", class, "reason", reason)
	}
	shell.SetUserClass(class)
}
