package cli

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// showPortMirroring displays port mirroring (SPAN) configuration.

func (c *CLI) showPortMirroring() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) == 0 {
		fmt.Println("No port-mirroring instances configured")
		return nil
	}

	for _, name := range sortedInstanceNames(pm.Instances) {
		inst := pm.Instances[name]
		fmt.Printf("Instance: %s\n", name)
		if inst.InputRate > 0 {
			fmt.Printf("  Input rate: 1/%d\n", inst.InputRate)
		} else {
			fmt.Printf("  Input rate: all packets\n")
		}
		if len(inst.Input) > 0 {
			fmt.Printf("  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
		}
		if inst.Output != "" {
			fmt.Printf("  Output interface: %s\n", inst.Output)
		}
		// #6534: the builder DROPS such an instance, so nothing above is in
		// effect. Sharpest for a negative input rate, which the branch above
		// renders as the maximally permissive "all packets" while the
		// dataplane mirrors nothing at all. Verdict shared with
		// buildMirrorSnapshots so the two cannot disagree.
		if reason := config.PortMirroringInstanceExcludedReason(inst); reason != "" {
			fmt.Printf("  NOT INSTALLED: %s\n", reason)
		}
		fmt.Println()
	}
	return nil
}
