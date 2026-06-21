package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/dataplane"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

func (c *CLI) showScreen() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(cfg.Security.Screen) == 0 {
		fmt.Println("No screen profiles configured")
		return nil
	}

	// Build reverse map: profile name -> zones using it
	zonesByProfile := make(map[string][]string)
	for name, zone := range cfg.Security.Zones {
		if zone.ScreenProfile != "" {
			zonesByProfile[zone.ScreenProfile] = append(
				zonesByProfile[zone.ScreenProfile], name)
		}
	}

	for name, profile := range cfg.Security.Screen {
		fmt.Printf("Screen profile: %s\n", name)

		// TCP checks
		if profile.TCP.Land {
			fmt.Println("  TCP LAND attack detection: enabled")
		}
		if profile.TCP.SynFin {
			fmt.Println("  TCP SYN+FIN detection: enabled")
		}
		if profile.TCP.NoFlag {
			fmt.Println("  TCP no-flag detection: enabled")
		}
		if profile.TCP.FinNoAck {
			fmt.Println("  TCP FIN-no-ACK detection: enabled")
		}
		if profile.TCP.WinNuke {
			fmt.Println("  TCP WinNuke detection: enabled")
		}
		if profile.TCP.SynFrag {
			fmt.Println("  TCP SYN fragment detection: enabled")
		}
		if profile.TCP.SynFlood != nil {
			fmt.Printf("  TCP SYN flood protection: attack-threshold %d\n",
				profile.TCP.SynFlood.AttackThreshold)
		}

		// ICMP checks
		if profile.ICMP.PingDeath {
			fmt.Println("  ICMP ping-of-death detection: enabled")
		}
		if profile.ICMP.FloodThreshold > 0 {
			fmt.Printf("  ICMP flood protection: threshold %d\n",
				profile.ICMP.FloodThreshold)
		}

		// IP checks
		if profile.IP.SourceRouteOption {
			fmt.Println("  IP source-route option detection: enabled")
		}

		// UDP checks
		if profile.UDP.FloodThreshold > 0 {
			fmt.Printf("  UDP flood protection: threshold %d\n",
				profile.UDP.FloodThreshold)
		}

		// Zones using this profile
		if zones, ok := zonesByProfile[name]; ok {
			fmt.Printf("  Applied to zones: %s\n", strings.Join(zones, ", "))
		} else {
			fmt.Println("  Applied to zones: (none)")
		}

		fmt.Println()
	}

	// Show screen drop counters (total + per-type)
	if c.dp != nil && c.dp.IsLoaded() {
		readCtr := func(idx uint32) uint64 {
			v, _ := c.dp.ReadGlobalCounter(idx)
			return v
		}

		totalDrops := readCtr(dataplane.GlobalCtrScreenDrops)
		fmt.Printf("Total screen drops: %d\n", totalDrops)

		if totalDrops > 0 {
			screenCounters := []struct {
				idx  uint32
				name string
			}{
				{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
				{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
				{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
				{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
				{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
				{dataplane.GlobalCtrScreenTearDrop, "Teardrop"},
				{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
				{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no flag"},
				{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN no ACK"},
				{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
				{dataplane.GlobalCtrScreenIPSrcRoute, "IP source route"},
				{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
			}
			for _, sc := range screenCounters {
				v := readCtr(sc.idx)
				if v > 0 {
					fmt.Printf("  %-25s %d\n", sc.name+":", v)
				}
			}
		}
	}

	return nil
}

func (c *CLI) showScreenIdsOption(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok {
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status:\n\n")
	fmt.Printf("  %-45s %s\n", "Name", "Value")
	if profile.TCP.Land {
		fmt.Printf("  %-45s %s\n", "TCP land attack", "enabled")
	}
	if profile.TCP.SynFin {
		fmt.Printf("  %-45s %s\n", "TCP SYN+FIN", "enabled")
	}
	if profile.TCP.NoFlag {
		fmt.Printf("  %-45s %s\n", "TCP no-flag", "enabled")
	}
	if profile.TCP.FinNoAck {
		fmt.Printf("  %-45s %s\n", "TCP FIN-no-ACK", "enabled")
	}
	if profile.TCP.WinNuke {
		fmt.Printf("  %-45s %s\n", "TCP WinNuke", "enabled")
	}
	if profile.TCP.SynFrag {
		fmt.Printf("  %-45s %s\n", "TCP SYN fragment", "enabled")
	}
	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %d\n", "TCP SYN flood attack threshold", profile.TCP.SynFlood.AttackThreshold)
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood source threshold", profile.TCP.SynFlood.SourceThreshold)
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood destination threshold", profile.TCP.SynFlood.DestinationThreshold)
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood timeout", profile.TCP.SynFlood.Timeout)
		}
	}
	if profile.ICMP.PingDeath {
		fmt.Printf("  %-45s %s\n", "ICMP ping of death", "enabled")
	}
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "ICMP flood threshold", profile.ICMP.FloodThreshold)
	}
	if profile.IP.SourceRouteOption {
		fmt.Printf("  %-45s %s\n", "IP source route option", "enabled")
	}
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "UDP flood threshold", profile.UDP.FloodThreshold)
	}

	// Show zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	}
	return nil
}

func (c *CLI) showScreenIdsOptionDetail(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok {
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status (detail):\n\n")
	fmt.Printf("  %-45s %-12s %s\n", "Name", "Value", "Default")

	// TCP checks
	fmt.Printf("  %-45s %-12s %s\n", "TCP land attack",
		enabledStr(profile.TCP.Land), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN+FIN",
		enabledStr(profile.TCP.SynFin), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP no-flag",
		enabledStr(profile.TCP.NoFlag), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP FIN-no-ACK",
		enabledStr(profile.TCP.FinNoAck), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP WinNuke",
		enabledStr(profile.TCP.WinNuke), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN fragment",
		enabledStr(profile.TCP.SynFrag), "disabled")

	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "enabled", "disabled")
		fmt.Printf("  %-45s %-12d %s\n", "  Attack threshold",
			profile.TCP.SynFlood.AttackThreshold, "200")
		if profile.TCP.SynFlood.AlarmThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Alarm threshold",
				profile.TCP.SynFlood.AlarmThreshold, "512")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Alarm threshold", "(default)", "512")
		}
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Source threshold",
				profile.TCP.SynFlood.SourceThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Source threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Destination threshold",
				profile.TCP.SynFlood.DestinationThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Destination threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Timeout (seconds)",
				profile.TCP.SynFlood.Timeout, "20")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Timeout (seconds)", "(default)", "20")
		}
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "disabled", "disabled")
	}

	// ICMP checks
	fmt.Printf("  %-45s %-12s %s\n", "ICMP ping of death",
		enabledStr(profile.ICMP.PingDeath), "disabled")
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "ICMP flood threshold",
			profile.ICMP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "ICMP flood threshold", "disabled", "disabled")
	}

	// IP checks
	fmt.Printf("  %-45s %-12s %s\n", "IP source route option",
		enabledStr(profile.IP.SourceRouteOption), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "IP teardrop",
		enabledStr(profile.IP.TearDrop), "disabled")

	// UDP checks
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "UDP flood threshold",
			profile.UDP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "UDP flood threshold", "disabled", "disabled")
	}

	// Zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	} else {
		fmt.Printf("\n  Bound to zones: (none)\n")
	}
	return nil
}

func (c *CLI) showScreenStatistics(zoneName string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}
	cr := c.applyResult()
	if cr == nil {
		fmt.Println("no compile result available")
		return nil
	}
	zoneID, ok := cr.ZoneIDs[zoneName]
	if !ok {
		fmt.Printf("Zone '%s' not found\n", zoneName)
		return nil
	}
	fs, err := c.dp.ReadFloodCounters(zoneID)
	if err != nil {
		fmt.Printf("Error reading flood counters: %v\n", err)
		return nil
	}
	totalSyn, totalICMP, totalUDP := fs.SynCount, fs.ICMPCount, fs.UDPCount
	screenProfile := ""
	if z, ok := cfg.Security.Zones[zoneName]; ok {
		screenProfile = z.ScreenProfile
	}
	fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
	if screenProfile != "" {
		fmt.Printf("  Screen profile: %s\n", screenProfile)
	}
	fmt.Printf("  %-30s %s\n", "Counter", "Value")
	fmt.Printf("  %-30s %d\n", "SYN flood events", totalSyn)
	fmt.Printf("  %-30s %d\n", "ICMP flood events", totalICMP)
	fmt.Printf("  %-30s %d\n", "UDP flood events", totalUDP)
	fmt.Print(c.screenSYNCookieCounterRows())
	return nil
}

func (c *CLI) showScreenStatisticsAll() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}
	cr := c.applyResult()
	if cr == nil {
		fmt.Println("no compile result available")
		return nil
	}
	// Collect zone names and sort for deterministic output
	var zones []string
	for name := range cr.ZoneIDs {
		zones = append(zones, name)
	}
	sort.Strings(zones)

	for _, zoneName := range zones {
		zoneID := cr.ZoneIDs[zoneName]
		fs, err := c.dp.ReadFloodCounters(zoneID)
		if err != nil {
			continue
		}
		screenProfile := ""
		if z, ok := cfg.Security.Zones[zoneName]; ok {
			screenProfile = z.ScreenProfile
		}
		fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
		if screenProfile != "" {
			fmt.Printf("  Screen profile: %s\n", screenProfile)
		}
		fmt.Printf("  %-30s %s\n", "Counter", "Value")
		fmt.Printf("  %-30s %d\n", "SYN flood events", fs.SynCount)
		fmt.Printf("  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
		fmt.Printf("  %-30s %d\n", "UDP flood events", fs.UDPCount)
		fmt.Println()
	}
	if rows := c.screenSYNCookieCounterRows(); rows != "" {
		fmt.Print(rows)
	}
	return nil
}

func (c *CLI) screenSYNCookieCounterRows() string {
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return ""
	}
	return dpformat.FormatSYNCookieCounterRows(dpformat.SumSYNCookieCounters(status))
}
