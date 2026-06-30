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
			Zone:         zone.Name,
			Land:         sp.TCP.Land,
			SynFin:       sp.TCP.SynFin,
			NoFlag:       sp.TCP.NoFlag,
			FinNoAck:     sp.TCP.FinNoAck,
			WinNuke:      sp.TCP.WinNuke,
			PingDeath:    sp.ICMP.PingDeath,
			ICMPFragment: sp.ICMP.Fragment,
			Teardrop:     sp.IP.TearDrop,
			SynFrag:      sp.TCP.SynFrag, // #1137 — port from typed config
			SourceRoute:  sp.IP.SourceRouteOption,
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
			// #3315: carry the SYN-flood sub-thresholds across the wire. The
			// #3024 default guarantees AttackThreshold > 0 whenever a syn-flood
			// screen is enabled, so this block is the single publish gate for
			// every syn-flood control. alarm/source/destination are non-zero only
			// when the operator configured them.
			if sp.TCP.SynFlood.AlarmThreshold > 0 {
				snap.SYNFloodAlarmThreshold = uint32(sp.TCP.SynFlood.AlarmThreshold)
			}
			if sp.TCP.SynFlood.DestinationThreshold > 0 {
				snap.SYNFloodDstThreshold = uint32(sp.TCP.SynFlood.DestinationThreshold)
			}
			if sp.TCP.SynFlood.SourceThreshold > 0 {
				snap.SYNFloodSrcThreshold = uint32(sp.TCP.SynFlood.SourceThreshold)
			}
			// #3527: carry `syn-flood timeout` (seconds) so the dataplane can
			// enforce it as a per-zone override of the half-open session window
			// (tcp_opening_ns). It maps to the session layer, not the screen-rate
			// substrate above; closing the #3315 deferred leaf.
			if sp.TCP.SynFlood.Timeout > 0 {
				snap.SYNFloodTimeout = uint32(sp.TCP.SynFlood.Timeout)
			}
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
			snap.WinNuke || snap.PingDeath || snap.ICMPFragment || snap.Teardrop ||
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

// buildScreenMissingProfileRefs records every zone that REFERENCES a screen
// profile which is NOT defined in the config (#3082). buildScreenSnapshots
// silently skips these zones (`sp == nil`), so without this the dataplane
// cannot tell "zone has no screen configured" (legit Pass) apart from "zone
// references a MISSING screen" (error → should signal). Reachable on the
// lenient/HA-sync path where a dangling screen reference loads with only an
// apply-time warning. The dataplane uses this to emit a rate-limited runtime
// WARN; the verdict stays Pass (the fail-closed posture is deferred).
func buildScreenMissingProfileRefs(cfg *config.Config) []ScreenMissingProfileRef {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out []ScreenMissingProfileRef
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			// No screen configured for this zone — legit Pass, not a
			// missing reference.
			continue
		}
		if cfg.Security.Screen[zone.ScreenProfile] != nil {
			// Reference resolves to a defined profile.
			continue
		}
		out = append(out, ScreenMissingProfileRef{
			Zone:    zone.Name,
			Profile: zone.ScreenProfile,
		})
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
	return cfg.System.RootAuthentication.EncryptedPassword.Reveal()
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
