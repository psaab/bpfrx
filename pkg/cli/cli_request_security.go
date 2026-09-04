package cli

import (
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/wgkey"
)

func (c *CLI) handleRequestSecurity(args []string) error {
	if len(args) == 0 {
		fmt.Println("request security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children))
		return nil
	}
	switch args[0] {
	case "ipsec":
		if len(args) < 3 || args[1] != "sa" || args[2] != "clear" {
			fmt.Println("request security ipsec sa:")
			writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["ipsec"].Children["sa"].Children))
			return nil
		}
		// #5647: `ipsec sa clear` terminates EVERY IPsec SA
		// (TerminateAllSAs). Reject a scoped-looking suffix such as
		// `... sa clear 42` / `... sa clear tunnel gw-a` BEFORE the mutation
		// instead of silently dropping the selector and tearing down all SAs.
		if len(args) > 3 {
			return rejectScopedClear("request security ipsec sa clear",
				"terminates every IPsec SA", args[3:])
		}
		if c.ipsec == nil {
			return fmt.Errorf("IPsec manager not available")
		}
		count, err := c.ipsec.TerminateAllSAs()
		if err != nil {
			return err
		}
		fmt.Printf("Cleared %d IPsec SA(s)\n", count)
		return nil
	case "wireguard":
		return c.handleRequestSecurityWireguard(args[1:])
	case "policies":
		return c.handleRequestSecurityPolicies(args[1:])
	default:
		return fmt.Errorf("unknown request security target: %s", args[0])
	}
}

// handleRequestSecurityPolicies implements `request security policies check`
// (fable-167 C-1c, #4314): a static analysis of the configured policy set
// that reports shadowed / redundant rules. Junos `request security policies
// check` validates the compiled policy DB; xpf runs a conservative
// name-set-containment pass over config.ZonePairPolicies (no dataplane call —
// this is a config lint). It never mutates config.
func (c *CLI) handleRequestSecurityPolicies(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		fmt.Println("request security policies:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["policies"].Children))
		return nil
	}
	// #8597 K47: the ANALYSIS and its RENDERING both live in pkg/policymatch
	// now, because the remote `cli` serves this verb through a gRPC ShowText
	// topic that runs the same two functions. Two surfaces printing the same
	// command must not each own a copy of the header line.
	fmt.Print(policymatch.RenderPolicyCheck(c.store.ActiveConfig()))
	return nil
}

// handleRequestSecurityWireguard implements `request security wireguard
// generate-private-key` (#1434 Increment 1): a stateless utility that
// prints a fresh WireGuard key pair for the operator to paste into
// config. Junos `request` semantics — it does NOT mutate config and
// needs no dataplane (pure-Go X25519 keygen). Mirrors `wg genkey` /
// `wg pubkey` output in WireGuard-canonical base64.
func (c *CLI) handleRequestSecurityWireguard(args []string) error {
	if len(args) == 0 || args[0] != "generate-private-key" {
		fmt.Println("request security wireguard:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["wireguard"].Children))
		return nil
	}
	kp, err := wgkey.Generate()
	if err != nil {
		return fmt.Errorf("generate WireGuard key: %w", err)
	}
	fmt.Printf("Private key: %s\n", kp.PrivateKey)
	fmt.Printf("Public key:  %s\n", kp.PublicKey)
	return nil
}
