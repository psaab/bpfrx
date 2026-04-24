package cli

import (
	"fmt"

	"github.com/psaab/xpf/pkg/fwdstatus"
)

// showChassisForwarding renders the `show chassis forwarding` Junos-
// style one-screen view.  Uses the shared pkg/fwdstatus package so
// the gRPC handler and this local TTY path produce identical output.
//
// #877: local-node MVP.  Cluster peer rendering is stubbed via
// fwdstatus.ClusterPeerFollowup.
func (c *CLI) showChassisForwarding() error {
	fs, err := fwdstatus.Build(
		c.dp,
		fwdstatus.OSProcReader{},
		c.startTime,
		c.cluster != nil,
	)
	if err != nil {
		return fmt.Errorf("build forwarding status: %w", err)
	}
	fmt.Print(fwdstatus.Format(fs))
	return nil
}
