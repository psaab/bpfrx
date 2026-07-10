package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

func (c *CLI) handleRequestSystem(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children))
		return nil
	}

	switch args[0] {
	case "reboot":
		fmt.Print("Reboot the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Reboot cancelled")
			return nil
		}
		fmt.Println("System going down for reboot NOW!")
		cmd := exec.Command("systemctl", "reboot")
		return cmd.Run()

	case "halt":
		fmt.Print("Halt the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Halt cancelled")
			return nil
		}
		fmt.Println("System halting NOW!")
		cmd := exec.Command("systemctl", "halt")
		return cmd.Run()

	case "power-off":
		fmt.Print("Power off the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Power-off cancelled")
			return nil
		}
		fmt.Println("System powering off NOW!")
		cmd := exec.Command("systemctl", "poweroff")
		return cmd.Run()

	case "zeroize":
		fmt.Println("WARNING: This will erase all configuration and return to factory defaults.")
		fmt.Print("Zeroize the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Zeroize cancelled")
			return nil
		}

		// Securely erase the config-DB SSOT + master.key + audit journal +
		// rollback history (#4858). The pre-fix wipe removed only top-level
		// .conf / rollback* files and LEFT .configdb/{active,candidate,
		// rollback.N}.json + master.key + .config.journal behind, so the daemon
		// reloaded the "erased" config and secrets on the next boot (a false
		// factory reset). Route through the shared configstore primitive and
		// refuse to report success if the erasure did not complete.
		configDir := "/etc/xpf"
		if err := configstore.FactoryResetConfigDir(configDir, "xpf.conf"); err != nil {
			return fmt.Errorf("zeroize: configuration state not fully erased: %w", err)
		}

		// Remove BPF pins (no secret material)
		os.RemoveAll("/sys/fs/bpf/xpf")

		// Remove managed networkd files
		ndFiles, _ := os.ReadDir("/etc/systemd/network")
		for _, f := range ndFiles {
			if strings.HasPrefix(f.Name(), "10-xpf-") {
				os.Remove("/etc/systemd/network/" + f.Name())
			}
		}

		// Verify the config DB SSOT is gone before reporting success — a
		// zeroize that leaves it behind must not print "erased".
		if _, err := os.Stat(filepath.Join(configDir, ".configdb")); !os.IsNotExist(err) {
			return fmt.Errorf("zeroize: config DB still present after wipe (stat err=%v)", err)
		}

		// Stop the daemon so it releases interface/dataplane state; the reboot
		// completes the factory reset.
		exec.Command("systemctl", "stop", "xpfd").Run()

		fmt.Println("System zeroized. Configuration erased.")
		fmt.Println("Reboot to complete factory reset.")
		return nil

	case "configuration":
		return c.handleRequestSystemConfiguration(args[1:])

	case "software":
		return c.handleRequestSystemSoftware(args[1:])

	case "dynamic-dns":
		return c.handleRequestSystemDynamicDNS(args[1:])

	default:
		return fmt.Errorf("unknown request system command: %s", args[0])
	}
}

// handleRequestSystemDynamicDNS implements `request system dynamic-dns
// update|check` (#3276): an operator force-now / check-now verb that triggers an
// immediate DDNS publish out-of-band of the poll cycle. `update` re-asserts
// every owned record now (force); `check` re-observes and publishes only changed
// records. Both honor the per-RG owner gate — on a node that masters no RG the
// daemon returns a clear "not the active node" message and takes no action.
func (c *CLI) handleRequestSystemDynamicDNS(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system dynamic-dns:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["dynamic-dns"].Children))
		return nil
	}
	if c.surfaceADDNSForceFn == nil {
		return fmt.Errorf("dynamic-dns: DDNS engine not running")
	}
	switch args[0] {
	case "update":
		_, msg := c.surfaceADDNSForceFn(true)
		fmt.Println(msg)
		return nil
	case "check":
		_, msg := c.surfaceADDNSForceFn(false)
		fmt.Println(msg)
		return nil
	default:
		return fmt.Errorf("unknown request system dynamic-dns command: %s", args[0])
	}
}

func (c *CLI) handleRequestSystemSoftware(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system software:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["software"].Children))
		return nil
	}

	if args[0] != "in-service-upgrade" {
		return fmt.Errorf("unknown request system software command: %s", args[0])
	}

	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}

	fmt.Println("WARNING: This will force this node to secondary for all redundancy groups.")
	fmt.Print("Proceed with in-service upgrade? [yes,no] (no) ")
	c.rl.SetPrompt("")
	line, err := c.rl.Readline()
	c.rl.SetPrompt(c.operationalPrompt())
	if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
		fmt.Println("ISSU cancelled")
		return nil
	}

	if err := c.cluster.ForceSecondary(); err != nil {
		return fmt.Errorf("ISSU: %v", err)
	}

	c.reportInServiceUpgradeDrain()
	return nil
}

// reportInServiceUpgradeDrain fences the drain-complete message on an OBSERVED
// peer takeover before telling the operator it is safe to stop this node
// (#5039). ForceSecondary only sets desired state and enqueues a droppable
// election event; the actual handoff happens asynchronously and can lag, so
// the command waits (bounded) to see the peer own primary before printing stop
// instructions, and otherwise warns and withholds them. Split out so the
// rendering is unit-testable without driving the interactive confirmation
// prompt.
func (c *CLI) reportInServiceUpgradeDrain() {
	ctx, cancel := context.WithTimeout(context.Background(), cluster.DefaultUpgradeHandoffTimeout)
	defer cancel()
	confirmed := c.cluster.WaitForUpgradeHandoff(ctx, cluster.DefaultUpgradeHandoffPoll)
	printISSUDrainReport(confirmed)
}

// printISSUDrainReport writes the honest ISSU drain report to stdout.
func printISSUDrainReport(handoffConfirmed bool) {
	for _, line := range cluster.UpgradeDrainReport(handoffConfirmed) {
		fmt.Println(line)
	}
}

func (c *CLI) handleRequestSystemConfiguration(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system configuration:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["configuration"].Children))
		return nil
	}

	if args[0] != "rescue" {
		return fmt.Errorf("unknown request system configuration command: %s", args[0])
	}

	if len(args) < 2 {
		fmt.Println("request system configuration rescue:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["configuration"].Children["rescue"].Children))
		return nil
	}

	switch args[1] {
	case "save":
		if err := c.store.SaveRescueConfig(); err != nil {
			return err
		}
		fmt.Println("Rescue configuration saved")
		return nil

	case "delete":
		if err := c.store.DeleteRescueConfig(); err != nil {
			return err
		}
		fmt.Println("Rescue configuration deleted")
		return nil

	default:
		return fmt.Errorf("unknown request system configuration rescue command: %s", args[1])
	}
}
