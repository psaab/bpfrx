package userspace

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

func buildScreenSnapshots(cfg *config.Config) []ScreenProfileSnapshot {
	if cfg == nil || len(cfg.Security.Screen) == 0 || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out []ScreenProfileSnapshot
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		sp := cfg.Security.Screen[zone.ScreenProfile]
		if sp == nil {
			continue
		}
		snap := ScreenProfileSnapshot{
			Zone:        zone.Name,
			Land:        sp.TCP.Land,
			SynFin:      sp.TCP.SynFin,
			NoFlag:      sp.TCP.NoFlag,
			FinNoAck:    sp.TCP.FinNoAck,
			WinNuke:     sp.TCP.WinNuke,
			PingDeath:   sp.ICMP.PingDeath,
			Teardrop:    sp.IP.TearDrop,
			SynFrag:     sp.TCP.SynFrag, // #1137 — port from typed config
			SourceRoute: sp.IP.SourceRouteOption,
		}
		if sp.ICMP.FloodThreshold > 0 {
			snap.ICMPFloodThreshold = uint32(sp.ICMP.FloodThreshold)
		}
		if sp.UDP.FloodThreshold > 0 {
			snap.UDPFloodThreshold = uint32(sp.UDP.FloodThreshold)
		}
		if sp.TCP.SynFlood != nil && sp.TCP.SynFlood.AttackThreshold > 0 {
			snap.SYNFloodThreshold = uint32(sp.TCP.SynFlood.AttackThreshold)
			snap.SYNCookie = cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie"
		}
		if sp.LimitSession.SourceIPBased > 0 {
			snap.SessionLimitSrc = uint32(sp.LimitSession.SourceIPBased)
		}
		if sp.LimitSession.DestinationIPBased > 0 {
			snap.SessionLimitDst = uint32(sp.LimitSession.DestinationIPBased)
		}
		if sp.TCP.PortScanThreshold > 0 {
			snap.PortScanThreshold = uint32(sp.TCP.PortScanThreshold)
		}
		if sp.IP.IPSweepThreshold > 0 {
			snap.IPSweepThreshold = uint32(sp.IP.IPSweepThreshold)
		}
		// Only include profiles that have at least one check enabled
		if snap.Land || snap.SynFin || snap.NoFlag || snap.FinNoAck ||
			snap.WinNuke || snap.PingDeath || snap.Teardrop ||
			snap.SynFrag || snap.SourceRoute ||
			snap.ICMPFloodThreshold > 0 || snap.UDPFloodThreshold > 0 ||
			snap.SYNFloodThreshold > 0 ||
			snap.SessionLimitSrc > 0 || snap.SessionLimitDst > 0 ||
			snap.PortScanThreshold > 0 || snap.IPSweepThreshold > 0 {
			out = append(out, snap)
		}
	}
	return out
}

func buildSYNCookieMasterKey(cfg *config.Config) string {
	if !userspaceSynCookieProtectionActive(cfg) {
		return ""
	}
	secretMaterial := synCookieSecretMaterial(cfg)
	if secretMaterial == "" {
		return ""
	}

	var zones []string
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		profile := cfg.Security.Screen[zone.ScreenProfile]
		if profile == nil || profile.TCP.SynFlood == nil ||
			profile.TCP.SynFlood.AttackThreshold <= 0 {
			continue
		}
		zones = append(zones, zone.Name+"\x00"+zone.ScreenProfile)
	}
	if len(zones) == 0 {
		return ""
	}
	sort.Strings(zones)

	h := sha256.New()
	h.Write([]byte("xpf-userspace-syn-cookie-v1\x00"))
	if cfg.Chassis.Cluster != nil {
		fmt.Fprintf(h, "cluster-id=%d\x00", cfg.Chassis.Cluster.ClusterID)
	} else {
		h.Write([]byte("standalone\x00"))
	}
	h.Write([]byte("root-auth-encrypted-password\x00"))
	h.Write([]byte(secretMaterial))
	h.Write([]byte{0})
	for _, zone := range zones {
		h.Write([]byte(zone))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum[:16])
}

func synCookieSecretMaterial(cfg *config.Config) string {
	if cfg == nil || cfg.System.RootAuthentication == nil {
		return ""
	}
	// Use already cluster-synced secret material. Do not use
	// system master-password: it is a PRF selector for configstore
	// at-rest encryption, not a dataplane secret.
	return cfg.System.RootAuthentication.EncryptedPassword
}

func userspaceSynCookieProtectionActive(cfg *config.Config) bool {
	if cfg == nil || cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
		return false
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		profile := cfg.Security.Screen[zone.ScreenProfile]
		if profile != nil && profile.TCP.SynFlood != nil &&
			profile.TCP.SynFlood.AttackThreshold > 0 {
			return true
		}
	}
	return false
}

// userspaceSupportsScreenProfiles returns true if the configured screen
// profiles only use checks that the userspace dataplane implements.
// Port scan detection, IP sweep detection, and per-IP session limiting
// are now implemented in the userspace dataplane.
func userspaceSupportsScreenProfiles(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Security.Screen) == 0 {
		return true
	}
	if userspaceSynCookieProtectionActive(cfg) && synCookieSecretMaterial(cfg) == "" {
		return false
	}
	return true
}
