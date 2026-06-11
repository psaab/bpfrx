package cli

import (
	"fmt"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// showSecurityWireguard renders `show security wireguard [detail]`
// from the userspace helper's per-tunnel telemetry rows (#1865). The
// rendering is shared with the remote CLI via
// dpuserspace.FormatWireguardStatus (the FormatSystemBuffers pattern),
// so local and gRPC output are identical.
func (c *CLI) showSecurityWireguard(detail bool) error {
	if c.dp == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	provider, ok := c.dp.(cliUserspaceStatusProvider)
	if !ok {
		fmt.Println("WireGuard telemetry requires the userspace dataplane")
		return nil
	}
	status, err := provider.Status()
	if err != nil {
		fmt.Printf("WireGuard telemetry unavailable: %v\n", err)
		return nil
	}
	fmt.Print(dpuserspace.FormatWireguardStatus(status, detail, time.Now()))
	return nil
}
