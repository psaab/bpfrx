package cli

import (
	"fmt"
	"time"

	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// showSecurityWireguard renders `show security wireguard [detail]`
// from the userspace helper's per-tunnel telemetry rows (#1865). The
// rendering is shared with the remote CLI via
// dpformat.FormatWireguardStatus (the FormatSystemBuffers pattern),
// so local and gRPC output are identical.
func (c *CLI) showSecurityWireguard(detail bool) error {
	if c.dp == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	provider, ok := c.dpProbe().(cliUserspaceStatusProvider)
	if !ok {
		fmt.Println("WireGuard telemetry requires the userspace dataplane")
		return nil
	}
	status, err := provider.Status()
	if err != nil {
		fmt.Printf("WireGuard telemetry unavailable: %v\n", err)
		return nil
	}
	fmt.Print(dpformat.FormatWireguardStatus(status, detail, time.Now()))
	return nil
}

// showSecurityWireguardPublicKey renders `show security wireguard
// public-key` (#1434 Increment 1): the LOCAL public key per configured
// WG tunnel, in WireGuard-canonical base64 — the key an operator hands
// to the peer. Like the status view it reads helper telemetry only and
// works without an active config.
func (c *CLI) showSecurityWireguardPublicKey() error {
	if c.dp == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	provider, ok := c.dpProbe().(cliUserspaceStatusProvider)
	if !ok {
		fmt.Println("WireGuard telemetry requires the userspace dataplane")
		return nil
	}
	status, err := provider.Status()
	if err != nil {
		fmt.Printf("WireGuard telemetry unavailable: %v\n", err)
		return nil
	}
	fmt.Print(dpformat.FormatWireguardPublicKeys(status))
	return nil
}
