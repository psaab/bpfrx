package main

import (
	"fmt"
	"strconv"

	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
)

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
		return c.handleClearArp()
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

func (c *ctl) handleClearArp() error {
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
			if i+1 >= len(args) {
				break
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
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.SourcePort = uint32(v)
				}
			case "destination-port":
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.DestinationPort = uint32(v)
				}
			case "application":
				i++
				req.Application = args[i]
			}
		}
		resp, err := c.client.ClearSessions(c.ctx(), req)
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Printf("%d IPv4 and %d IPv6 session entries cleared\n", resp.Ipv4Cleared, resp.Ipv6Cleared)
		return nil

	case "policies":
		if len(args) >= 2 && args[1] == "hit-count" {
			resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
				Action: "clear-policy-counters",
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Println(resp.Message)
			return nil
		}
		return fmt.Errorf("usage: clear security policies hit-count")

	case "counters":
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
	if len(args) >= 3 && args[1] == "interface" {
		req.Interface = args[2]
	}

	resp, err := c.client.ClearDHCPClientIdentifier(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}
