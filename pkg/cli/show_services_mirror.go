package cli

import (
	"fmt"
	"strings"
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

	for name, inst := range pm.Instances {
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
		fmt.Println()
	}
	return nil
}
