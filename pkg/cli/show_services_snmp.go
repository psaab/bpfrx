package cli

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func (c *CLI) showSNMP() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil {
		fmt.Println("No SNMP configured")
		return nil
	}
	snmpCfg := cfg.System.SNMP

	if snmpCfg.Location != "" {
		fmt.Printf("Location:    %s\n", snmpCfg.Location)
	}
	if snmpCfg.Contact != "" {
		fmt.Printf("Contact:     %s\n", snmpCfg.Contact)
	}
	if snmpCfg.Description != "" {
		fmt.Printf("Description: %s\n", snmpCfg.Description)
	}

	if len(snmpCfg.Communities) > 0 {
		fmt.Println("Communities:")
		// #4111: mask the secret community name for any non-super-user login
		// class (reuse the #4099/#4106 showConfigRedacted predicate). The
		// authorization mode stays visible; only the community credential is
		// masked. Super-user / unset class reads cleartext. #6532 routed the
		// mask itself through the shared config.SNMPCommunityDisplayName
		// helper; the per-class PREDICATE stays here, since only the CLI has a
		// login class to gate on.
		redactCommunity := c.showConfigRedacted()
		for name, comm := range snmpCfg.Communities {
			fmt.Printf("  %s: %s\n",
				config.SNMPCommunityDisplayName(name, redactCommunity), comm.Authorization)
		}
	}

	if len(snmpCfg.TrapGroups) > 0 {
		fmt.Println("Trap groups:")
		for name, tg := range snmpCfg.TrapGroups {
			fmt.Printf("  %s: %s\n", name, strings.Join(tg.Targets, ", "))
		}
	}

	if len(snmpCfg.V3Users) > 0 {
		fmt.Println("SNMPv3 USM users:")
		for name, u := range snmpCfg.V3Users {
			auth := u.AuthProtocol
			if auth == "" {
				auth = "none"
			}
			priv := u.PrivProtocol
			if priv == "" {
				priv = "none"
			}
			fmt.Printf("  %s: auth=%s priv=%s\n", name, auth, priv)
		}
	}
	return nil
}

func (c *CLI) showSNMPv3() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil || len(cfg.System.SNMP.V3Users) == 0 {
		fmt.Println("No SNMPv3 users configured")
		return nil
	}
	fmt.Println("SNMPv3 USM Users:")
	fmt.Printf("  %-20s %-12s %-12s\n", "User", "Auth", "Privacy")
	for _, u := range cfg.System.SNMP.V3Users {
		auth := u.AuthProtocol
		if auth == "" {
			auth = "none"
		}
		priv := u.PrivProtocol
		if priv == "" {
			priv = "none"
		}
		fmt.Printf("  %-20s %-12s %-12s\n", u.Name, auth, priv)
	}
	return nil
}
