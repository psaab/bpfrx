// Login-class based RBAC permission enforcement for CLI actions.
// `checkPermission` is invoked by the dispatch layer before any top-level
// command runs; when the user's login class is unset we keep the legacy
// behavior of allowing everything.
package cli

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// checkPermission verifies the current user's login class permits the given action.
// If userClass is empty (not set), all actions are allowed for backward compatibility.
func (c *CLI) checkPermission(action string) error {
	if c.userClass == "" {
		return nil
	}

	perms, ok := config.LoginClassPermissions[c.userClass]
	if !ok {
		return fmt.Errorf("permission denied: unknown login class %q", c.userClass)
	}

	// Determine required permission for the action.
	var required config.LoginClassPermission
	switch action {
	case "show", "ping", "traceroute", "monitor":
		required = config.PermView
	case "clear":
		required = config.PermClear
	case "request", "test":
		required = config.PermControl
	case "configure":
		required = config.PermConfig
	default:
		required = config.PermAll
	}

	for _, p := range perms {
		if p == config.PermAll || p == required {
			return nil
		}
	}

	return fmt.Errorf("permission denied: %q requires class super-user or higher", action)
}
