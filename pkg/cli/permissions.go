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

// showConfigRedacted reports whether the config-render CLI show paths — `show
// configuration` (all formats), `show system rollback`, `show system
// login|internet-options|root-authentication`, `show system configuration
// rescue`, and the config-mode `show`/`show | compare` — must mask secret
// leaves for the current login class (#4099).
//
// Junos never renders cleartext secrets in `show configuration` (it shows the
// $9$/##SECRET-DATA form to every class), and xpf already redacts the REST and
// gRPC ShowConfig raw-AST render paths unconditionally (#4051/F-020). The
// on-box CLI, however, historically printed cleartext for every class (the
// deliberate #4057 scope note: "operator reads own secret, root has DB
// access"). That rationale holds for the privileged super-user / root operator
// working at the console, but NOT for a VIEW-only read-only or config-viewer
// login class — both PermView (types_system.go) — which could run `show
// configuration | display set` and harvest every IKE PSK, SNMP community and
// authentication-key in cleartext.
//
// We therefore redact for every login class EXCEPT super-user (the only class
// carrying PermAll). super-user == the console root that #4057 protected and
// that already has direct DB filesystem access, so it still reads cleartext to
// copy a secret; read-only, config-viewer and operator see ##SECRET-DATA##. An
// UNSET login class (CLI spawned without RBAC configured — the legacy
// allow-everything mode, mirroring checkPermission's empty-class shortcut) is
// treated as privileged and reads cleartext, so a deployment with no `system
// login` classes is bit-identical to before this change. An UNKNOWN class
// fails closed (redacted).
func (c *CLI) showConfigRedacted() bool {
	if c.userClass == "" {
		return false
	}
	perms, ok := config.LoginClassPermissions[c.userClass]
	if !ok {
		return true
	}
	for _, p := range perms {
		if p == config.PermAll {
			return false
		}
	}
	return true
}

// showActiveConfigPath renders an active-config subtree as hierarchical text,
// masking secret leaves when showConfigRedacted() flags the current login
// class (#4099). It is the redaction-aware replacement for direct
// store.ShowActivePath calls on secret-bearing subtrees (`show system login`,
// `show system root-authentication`).
func (c *CLI) showActiveConfigPath(path []string) string {
	if c.showConfigRedacted() {
		return c.store.ShowActiveRedacted(path)
	}
	return c.store.ShowActivePath(path)
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

	// `request system {reboot,halt,power-off,zeroize}` and `request chassis
	// cluster failover` are DESTRUCTIVE maintenance verbs. On Junos the
	// predefined `operator` class lacks the `maintenance` permission and so
	// cannot reboot/zeroize; xpf mirrors that by gating them at the
	// super-user-only PermMaint level instead of the plain PermControl the
	// rest of the `request` family (request session, request security, etc.)
	// keeps, so `operator` retains benign request verbs but not the ones that
	// take the box down or wipe it (#4108 F21).
	if action == "request" && requestSubcommandIsMaintenance(parts[1:]) {
		return config.PermMaint
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

// requestSubcommandIsMaintenance reports whether the `request` arguments
// resolve to a destructive maintenance verb: `request system
// {reboot,halt,power-off,zeroize}` or `request chassis cluster failover ...`.
// It applies the same prefix resolution the CLI dispatcher uses (resolveCommand
// over the cmdtree children), so an abbreviated `request system zero` or
// `request sys reboot` is gated identically to the fully-spelled form and
// cannot bypass the gate. Resolution errs toward the dispatcher: an
// unresolvable/ambiguous token that would never actually run returns false
// (plain control), while every token the dispatcher would execute as a
// destructive verb resolves here and elevates to PermMaint (fail-closed).
func requestSubcommandIsMaintenance(args []string) bool {
	if len(args) == 0 {
		return false
	}
	reqNode, ok := operationalTree["request"]
	if !ok || reqNode == nil {
		return false
	}
	target, err := resolveCommand(args[0], keysFromTree(reqNode.Children))
	if err != nil {
		return false
	}
	switch target {
	case "system":
		if len(args) < 2 {
			return false
		}
		sysNode := reqNode.Children["system"]
		if sysNode == nil {
			return false
		}
		verb, err := resolveCommand(args[1], keysFromTree(sysNode.Children))
		if err != nil {
			return false
		}
		switch verb {
		case "reboot", "halt", "power-off", "zeroize":
			return true
		}
		return false
	case "chassis":
		// request chassis cluster failover ...
		if len(args) < 3 {
			return false
		}
		chNode := reqNode.Children["chassis"]
		if chNode == nil {
			return false
		}
		clusterTok, err := resolveCommand(args[1], keysFromTree(chNode.Children))
		if err != nil || clusterTok != "cluster" {
			return false
		}
		clNode := chNode.Children["cluster"]
		if clNode == nil {
			return false
		}
		failoverTok, err := resolveCommand(args[2], keysFromTree(clNode.Children))
		if err != nil {
			return false
		}
		return failoverTok == "failover"
	}
	return false
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
