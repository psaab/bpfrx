package main

import (
	"fmt"
	"strconv"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// requireClearNoScope rejects any trailing operand on a GLOBAL-ONLY clear
// command — one whose backend action can ONLY clear everything and has no
// scoped variant. Such handlers historically recognized a fixed keyword prefix
// and silently DISCARDED the remaining tokens, then issued the unscoped
// mutation, so an operator who typed a scope (e.g. `clear arp 192.0.2.10`) got
// a success message while the ENTIRE cache/table/counter set was wiped (#5811).
// Require exact arity instead: return an error naming the stray tokens and
// stating the command takes no scope, BEFORE any mutation runs. cmd is the full
// command path shown in the message; clears names what it unconditionally
// clears. The wording is kept byte-identical to pkg/cli's copy so both CLIs
// reject the same input the same way.
func requireClearNoScope(cmd, clears string, extra []string) error {
	if len(extra) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument(s) %v after %q; this command clears %s "+
		"and takes no scope (per-scope clear is not supported)", extra, cmd, clears)
}

func (c *ctl) handleClear(args []string) error {
	showHelp := func() {
		printRemoteTreeHelp("clear:", "clear")
	}
	if len(args) < 1 {
		showHelp()
		return nil
	}

	switch args[0] {
	case "arp":
		return c.handleClearArp(args[1:])
	case "ipv6":
		return c.handleClearIPv6(args[1:])
	case "security":
		return c.handleClearSecurity(args[1:])
	case "firewall":
		return c.handleClearFirewall(args[1:])
	case "dhcp":
		return c.handleClearDHCP(args[1:])
	case "interfaces":
		return c.handleClearInterfaces(args[1:])
	case "system":
		return c.handleClearSystem(args[1:])
	default:
		showHelp()
		return nil
	}
}

func (c *ctl) handleClearSystem(args []string) error {
	if len(args) < 1 || args[0] != "config-lock" {
		printRemoteTreeHelp("clear system:", "clear", "system")
		return nil
	}
	if err := requireClearNoScope("clear system config-lock", "the configuration lock", args[1:]); err != nil {
		return err
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "clear-config-lock",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearInterfaces(args []string) error {
	if len(args) >= 1 && args[0] == "statistics" {
		if err := requireClearNoScope("clear interfaces statistics", "all interface statistics", args[1:]); err != nil {
			return err
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "clear-interfaces-statistics",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	}
	printRemoteTreeHelp("clear interfaces:", "clear", "interfaces")
	return nil
}

func (c *ctl) handleClearArp(args []string) error {
	if err := requireClearNoScope("clear arp", "the ARP cache", args); err != nil {
		return err
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "clear-arp",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearIPv6(args []string) error {
	if len(args) < 1 || args[0] != "neighbors" {
		printRemoteTreeHelp("clear ipv6:", "clear", "ipv6")
		return nil
	}
	if err := requireClearNoScope("clear ipv6 neighbors", "the IPv6 neighbor cache", args[1:]); err != nil {
		return err
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "clear-ipv6-neighbors",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearSecurity(args []string) error {
	if len(args) < 1 {
		printRemoteTreeHelp("clear security:", "clear", "security")
		return nil
	}

	switch args[0] {
	case "nat":
		if len(args) >= 3 && args[1] == "source" && args[2] == "persistent-nat-table" {
			if err := requireClearNoScope("clear security nat source persistent-nat-table",
				"the entire persistent NAT table", args[3:]); err != nil {
				return err
			}
			resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
				Action: "clear-persistent-nat",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Println(resp.Message)
			return nil
		}
		if len(args) >= 2 && args[1] == "statistics" {
			if err := requireClearNoScope("clear security nat statistics",
				"all NAT translation statistics", args[2:]); err != nil {
				return err
			}
			resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
				Action: "clear-nat-counters",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Println(resp.Message)
			return nil
		}
		printRemoteTreeHelp("clear security nat:", "clear", "security", "nat")
		return nil

	case "flow":
		if len(args) < 2 || args[1] != "session" {
			return fmt.Errorf("usage: clear security flow session [filters...]")
		}
		req := &pb.ClearSessionsRequest{}
		for i := 2; i < len(args); i++ {
			// Valueless flags first — they may legally be the last token.
			if args[i] == "nat-only" || args[i] == "nat" {
				req.NatOnly = true
				continue
			}
			// Every remaining filter keyword takes a value. A keyword
			// without one (or an unknown token) MUST error: silently
			// dropping it can leave the request empty, and the server
			// interprets an empty ClearSessionsRequest as clear-all.
			if i+1 >= len(args) {
				return fmt.Errorf("missing value for %q", args[i])
			}
			switch args[i] {
			case "source-prefix":
				i++
				req.SourcePrefix = args[i]
			case "destination-prefix":
				i++
				req.DestinationPrefix = args[i]
			case "protocol":
				i++
				req.Protocol = args[i]
			case "zone":
				i++
				req.Zone = args[i]
			case "source-port":
				i++
				v, err := strconv.Atoi(args[i])
				if err != nil || v <= 0 || v > 65535 {
					return fmt.Errorf("invalid source-port %q", args[i])
				}
				req.SourcePort = uint32(v)
			case "destination-port":
				i++
				v, err := strconv.Atoi(args[i])
				if err != nil || v <= 0 || v > 65535 {
					return fmt.Errorf("invalid destination-port %q", args[i])
				}
				req.DestinationPort = uint32(v)
			case "application":
				i++
				req.Application = args[i]
			case "interface":
				i++
				req.Interface = args[i]
			case "source-nat-pool":
				i++
				req.SourceNatPool = args[i]
			default:
				return fmt.Errorf("unknown session filter %q", args[i])
			}
		}
		resp, err := c.client.ClearSessions(c.ctx(), req)
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", resp.Ipv4Cleared, resp.Ipv6Cleared)
		return nil

	case "policies":
		// Fail CLOSED for this destructive command. `clear security
		// policies hit-count` resets EVERY policy hit counter globally —
		// the backend `clear-policy-counters` action carries no zone or
		// policy selector. Any trailing token (e.g. `... from-zone
		// trust`) means the operator intended a SCOPED clear the command
		// cannot honor; silently issuing the global wipe would erase
		// counters they meant to keep and destroy policy evidence during
		// incident response. So require EXACT arity and reject any
		// trailing selector instead of clearing all (#5570).
		if len(args) < 2 || args[1] != "hit-count" {
			return fmt.Errorf("usage: clear security policies hit-count")
		}
		if err := requireClearNoScope("clear security policies hit-count",
			"all policy hit counters", args[2:]); err != nil {
			return err
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "clear-policy-counters",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil

	case "counters":
		if err := requireClearNoScope("clear security counters", "all counters", args[1:]); err != nil {
			return err
		}
		_, err := c.client.ClearCounters(c.ctx(), &pb.ClearCountersRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println("all counters cleared")
		return nil

	default:
		printRemoteTreeHelp("clear security:", "clear", "security")
		return nil
	}
}

func (c *ctl) handleClearFirewall(args []string) error {
	if len(args) < 1 || args[0] != "all" {
		printRemoteTreeHelp("clear firewall:", "clear", "firewall")
		return nil
	}
	if err := requireClearNoScope("clear firewall all", "all firewall filter counters", args[1:]); err != nil {
		return err
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "clear-firewall-counters",
	})
	if err != nil {
		return fmt.Errorf("clear firewall counters: %w", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleClearDHCP(args []string) error {
	if len(args) < 1 || args[0] != "client-identifier" {
		printRemoteTreeHelp("clear dhcp:", "clear", "dhcp")
		return nil
	}

	req := &pb.ClearDHCPClientIdentifierRequest{}
	// A bare `clear dhcp client-identifier` (no selector) is the intentional
	// clear-ALL. But a malformed selector must NOT silently degrade to it:
	// the server branches on `Interface != ""`, so `... interface` (no name)
	// or `... interfce ge-0/0/0` (unknown selector) used to fall through with
	// an empty Interface and wipe EVERY DHCPv6 DUID (#4883-E). Require a
	// well-formed `interface <name>` selector when one is typed.
	if len(args) >= 2 {
		if args[1] != "interface" {
			return fmt.Errorf("usage: clear dhcp client-identifier [interface <name>]")
		}
		if len(args) < 3 || args[2] == "" {
			return fmt.Errorf("clear dhcp client-identifier: 'interface' requires a name")
		}
		if len(args) > 3 {
			return fmt.Errorf("clear dhcp client-identifier: unexpected argument %q after interface name", args[3])
		}
		req.Interface = args[2]
	}

	resp, err := c.client.ClearDHCPClientIdentifier(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}
