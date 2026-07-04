// Login-class based RBAC permission enforcement for CLI actions.
// `checkPermission` is invoked by the dispatch layer before any top-level
// command runs; when the user's login class is unset we keep the legacy
// behavior of allowing everything.
package cli

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// checkPermission verifies the current user's login class permits the given
// command. `parts` is the resolved operational command line (parts[0] is the
// canonical top-level word, parts[1:] its arguments). Most commands are gated
// on the top-level word alone, but a few privileged subcommands need a finer
// gate (see requiredPermission). If userClass is empty (not set), all actions
// are allowed for backward compatibility.
func (c *CLI) checkPermission(parts []string) error {
	if c.userClass == "" {
		return nil
	}
	if len(parts) == 0 {
		return nil
	}

	perms, ok := config.LoginClassPermissions[c.userClass]
	if !ok {
		return fmt.Errorf("permission denied: unknown login class %q", c.userClass)
	}

	required := requiredPermission(parts)

	for _, p := range perms {
		if p == config.PermAll || p == required {
			return nil
		}
	}

	return fmt.Errorf("permission denied: %q requires a higher login class", strings.Join(parts, " "))
}

// requiredPermission returns the login-class permission a resolved operational
// command needs. Gating is on the top-level word (parts[0]) for almost every
// command, with one important exception: `monitor traffic` spawns a root
// tcpdump live packet capture, so it must require the same control-level
// permission as the `request`/shell-out command family rather than the plain
// view permission the rest of `monitor` (interface stats, flow trace) uses.
// Without this a read-only / config-viewer class — intended only to VIEW
// config and status — could run an unprivileged root packet capture and read
// other users' cleartext traffic (#4067).
func requiredPermission(parts []string) config.LoginClassPermission {
	action := parts[0]

	// `monitor traffic` = privileged capture (root tcpdump). Gate it at the
	// control level even though the `monitor` top-level word is view-level.
	if action == "monitor" && monitorSubcommandIsTraffic(parts[1:]) {
		return config.PermControl
	}

	switch action {
	case "show", "ping", "traceroute", "monitor":
		return config.PermView
	case "clear":
		return config.PermClear
	case "request", "test":
		return config.PermControl
	case "configure":
		return config.PermConfig
	default:
		return config.PermAll
	}
}

// monitorSubcommandIsTraffic reports whether the monitor arguments resolve to
// the `traffic` subcommand. It applies the same prefix resolution the monitor
// dispatcher uses (`handleMonitor`), so an abbreviated `monitor tr` is gated
// identically to the fully-spelled `monitor traffic` — the RBAC gate and the
// dispatcher can never disagree about what a token resolves to.
func monitorSubcommandIsTraffic(args []string) bool {
	if len(args) == 0 {
		return false
	}
	monNode, ok := operationalTree["monitor"]
	if !ok || monNode == nil {
		return false
	}
	resolved, err := resolveCommand(args[0], keysFromTree(monNode.Children))
	if err != nil {
		return false
	}
	return resolved == "traffic"
}
