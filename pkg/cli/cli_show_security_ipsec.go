package cli

import (
	"fmt"
	"sort"
)

func (c *CLI) showIPsec(args []string) error {
	if c.ipsec == nil {
		fmt.Println("IPsec manager not available")
		return nil
	}

	if len(args) > 0 && args[0] == "security-associations" {
		detail := len(args) >= 2 && args[1] == "detail"
		sas, err := c.ipsec.GetSAStatus()
		if err != nil {
			return fmt.Errorf("IPsec SA status: %w", err)
		}
		if len(sas) == 0 {
			fmt.Println("No IPsec security associations")
			return nil
		}
		for _, sa := range sas {
			fmt.Printf("SA: %s\n", sa.Name)
			fmt.Printf("  State: %s\n", sa.State)
			if sa.LocalAddr != "" {
				fmt.Printf("  Local: %s\n", sa.LocalAddr)
			}
			if sa.RemoteAddr != "" {
				fmt.Printf("  Remote: %s\n", sa.RemoteAddr)
			}
			if sa.LocalTS != "" {
				fmt.Printf("  Local TS: %s\n", sa.LocalTS)
			}
			if sa.RemoteTS != "" {
				fmt.Printf("  Remote TS: %s\n", sa.RemoteTS)
			}
			if detail {
				inBytes := sa.InBytes
				if inBytes == "" {
					inBytes = "0"
				}
				outBytes := sa.OutBytes
				if outBytes == "" {
					outBytes = "0"
				}
				fmt.Printf("  Bytes transferred In/Out: %s/%s\n", inBytes, outBytes)
			}
			fmt.Println()
		}
		return nil
	}

	if len(args) > 0 && args[0] == "statistics" {
		return c.showIPsecStatistics()
	}

	// Default: show configured VPNs
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(cfg.Security.IPsec.VPNs) == 0 {
		fmt.Println("No IPsec VPNs configured")
		return nil
	}

	for name, vpn := range cfg.Security.IPsec.VPNs {
		fmt.Printf("VPN: %s\n", name)
		fmt.Printf("  Gateway: %s\n", vpn.Gateway)
		if vpn.LocalAddr != "" {
			fmt.Printf("  Local address: %s\n", vpn.LocalAddr)
		}
		if vpn.IPsecPolicy != "" {
			fmt.Printf("  IPsec policy: %s\n", vpn.IPsecPolicy)
		}
		if vpn.BindInterface != "" {
			fmt.Printf("  Bind interface: %s\n", vpn.BindInterface)
		}
		if vpn.LocalID != "" {
			fmt.Printf("  Local identity: %s\n", vpn.LocalID)
		}
		if vpn.RemoteID != "" {
			fmt.Printf("  Remote identity: %s\n", vpn.RemoteID)
		}
		if len(vpn.TrafficSelectors) > 0 {
			names := make([]string, 0, len(vpn.TrafficSelectors))
			for tsName := range vpn.TrafficSelectors {
				names = append(names, tsName)
			}
			sort.Strings(names)
			for _, tsName := range names {
				ts := vpn.TrafficSelectors[tsName]
				fmt.Printf("  Traffic selector %s: %s -> %s\n", tsName, ts.LocalIP, ts.RemoteIP)
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showIPsecStatistics() error {
	if c.ipsec == nil {
		fmt.Println("IPsec manager not available")
		return nil
	}
	sas, err := c.ipsec.GetSAStatus()
	if err != nil {
		return fmt.Errorf("IPsec statistics: %w", err)
	}

	activeTunnels := 0
	for _, sa := range sas {
		if sa.State == "ESTABLISHED" || sa.State == "INSTALLED" {
			activeTunnels++
		}
	}

	fmt.Println("IPsec statistics:")
	fmt.Printf("  Active tunnels: %d\n", activeTunnels)
	fmt.Printf("  Total SAs:      %d\n", len(sas))
	fmt.Println()

	if len(sas) > 0 {
		fmt.Printf("  %-20s %-14s %-12s %-12s\n", "Name", "State", "Bytes In", "Bytes Out")
		for _, sa := range sas {
			inBytes := sa.InBytes
			if inBytes == "" {
				inBytes = "-"
			}
			outBytes := sa.OutBytes
			if outBytes == "" {
				outBytes = "-"
			}
			fmt.Printf("  %-20s %-14s %-12s %-12s\n", sa.Name, sa.State, inBytes, outBytes)
		}
	}

	// Show configured VPN count
	cfg := c.store.ActiveConfig()
	if cfg != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		fmt.Printf("\n  Configured VPNs: %d\n", len(cfg.Security.IPsec.VPNs))
	}

	return nil
}

func (c *CLI) showIKE(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(args) > 0 && args[0] == "security-associations" {
		// Show IKE SA status from strongSwan
		if c.ipsec != nil {
			sas, err := c.ipsec.GetSAStatus()
			if err != nil {
				return fmt.Errorf("IKE SA status: %w", err)
			}
			if len(sas) == 0 {
				fmt.Println("No IKE security associations")
				return nil
			}
			for _, sa := range sas {
				fmt.Printf("IKE SA: %s  State: %s\n", sa.Name, sa.State)
				if sa.LocalAddr != "" {
					fmt.Printf("  Local:  %s\n", sa.LocalAddr)
				}
				if sa.RemoteAddr != "" {
					fmt.Printf("  Remote: %s\n", sa.RemoteAddr)
				}
				fmt.Println()
			}
			return nil
		}
		fmt.Println("IPsec manager not available")
		return nil
	}

	// Show configured IKE gateways
	gateways := cfg.Security.IPsec.Gateways
	if len(gateways) == 0 {
		fmt.Println("No IKE gateways configured")
		return nil
	}

	names := make([]string, 0, len(gateways))
	for name := range gateways {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		gw := gateways[name]
		fmt.Printf("IKE gateway: %s\n", name)
		if gw.Address != "" {
			fmt.Printf("  Remote address:     %s\n", gw.Address)
		}
		if gw.DynamicHostname != "" {
			fmt.Printf("  Dynamic hostname:   %s\n", gw.DynamicHostname)
		}
		if gw.LocalAddress != "" {
			fmt.Printf("  Local address:      %s\n", gw.LocalAddress)
		}
		if gw.ExternalIface != "" {
			fmt.Printf("  External interface: %s\n", gw.ExternalIface)
		}
		if gw.LocalCertificate != "" {
			fmt.Printf("  Local certificate:  %s\n", gw.LocalCertificate)
		}
		if gw.IKEPolicy != "" {
			fmt.Printf("  IKE policy:         %s\n", gw.IKEPolicy)
			if pol, ok := cfg.Security.IPsec.IKEPolicies[gw.IKEPolicy]; ok {
				fmt.Printf("    Mode:     %s\n", pol.Mode)
				fmt.Printf("    Proposal: %s\n", pol.Proposals)
			}
		}
		ver := gw.Version
		if ver == "" {
			ver = "v1+v2"
		}
		fmt.Printf("  IKE version:        %s\n", ver)
		if gw.DeadPeerDetect != "" {
			fmt.Printf("  DPD:                %s\n", gw.DeadPeerDetect)
			if gw.DPDInterval > 0 {
				fmt.Printf("  DPD interval:       %ds\n", gw.DPDInterval)
			}
			if gw.DPDThreshold > 0 {
				fmt.Printf("  DPD threshold:      %d\n", gw.DPDThreshold)
			}
		}
		if gw.NoNATTraversal {
			fmt.Printf("  NAT-T:              disabled\n")
		} else if gw.NATTraversal == "force" {
			fmt.Printf("  NAT-T:              force\n")
		} else if gw.NATTraversal == "enable" {
			fmt.Printf("  NAT-T:              enabled\n")
		}
		if gw.LocalIDValue != "" {
			fmt.Printf("  Local identity:     %s %s\n", gw.LocalIDType, gw.LocalIDValue)
		}
		if gw.RemoteIDValue != "" {
			fmt.Printf("  Remote identity:    %s %s\n", gw.RemoteIDType, gw.RemoteIDValue)
		}
		fmt.Println()
	}

	// Show IKE proposals
	proposals := cfg.Security.IPsec.IKEProposals
	if len(proposals) > 0 {
		pNames := make([]string, 0, len(proposals))
		for name := range proposals {
			pNames = append(pNames, name)
		}
		sort.Strings(pNames)
		fmt.Println("IKE proposals:")
		for _, name := range pNames {
			p := proposals[name]
			fmt.Printf("  %s: auth=%s enc=%s dh=group%d", name, p.AuthMethod, p.EncryptionAlg, p.DHGroup)
			if p.LifetimeSeconds > 0 {
				fmt.Printf(" lifetime=%ds", p.LifetimeSeconds)
			}
			fmt.Println()
		}
	}
	return nil
}
