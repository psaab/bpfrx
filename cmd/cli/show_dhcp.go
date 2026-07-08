package main

import (
	"fmt"
	"strings"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) showDHCPLeases() error {
	resp, err := c.client.GetDHCPLeases(c.ctx(), &pb.GetDHCPLeasesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Leases) == 0 {
		fmt.Println("No active DHCP leases")
		return nil
	}
	fmt.Println("DHCP leases:")
	for _, l := range resp.Leases {
		fmt.Printf("  Interface: %s, Family: %s\n", l.Interface, l.Family)
		fmt.Printf("    Address:   %s\n", l.Address)
		if l.Gateway != "" {
			fmt.Printf("    Gateway:   %s\n", l.Gateway)
		}
		if len(l.Dns) > 0 {
			fmt.Printf("    DNS:       %s\n", strings.Join(l.Dns, ", "))
		}
		fmt.Printf("    Lease:     %s\n", l.LeaseTime)
		fmt.Printf("    Obtained:  %s\n", l.Obtained)
		if len(l.DelegatedPrefixes) > 0 {
			fmt.Println("    Delegated prefixes:")
			for _, dp := range l.DelegatedPrefixes {
				fmt.Printf("      Prefix:    %s\n", dp.Prefix)
				fmt.Printf("      Preferred: %s\n", dp.PreferredLifetime)
				fmt.Printf("      Valid:     %s\n", dp.ValidLifetime)
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showDHCPClientIdentifier() error {
	resp, err := c.client.GetDHCPClientIdentifiers(c.ctx(), &pb.GetDHCPClientIdentifiersRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Identifiers) == 0 {
		fmt.Println("No DHCPv6 DUIDs configured")
		return nil
	}
	fmt.Println("DHCPv6 client identifiers:")
	for _, d := range resp.Identifiers {
		fmt.Printf("  Interface: %s\n", d.Interface)
		fmt.Printf("    Type:    %s\n", d.Type)
		fmt.Printf("    DUID:    %s\n", d.Display)
		fmt.Printf("    Hex:     %s\n", d.Hex)
		fmt.Println()
	}
	return nil
}
