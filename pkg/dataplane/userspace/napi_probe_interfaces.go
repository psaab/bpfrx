package userspace

// Interface enumeration for the mlx5 NAPI bootstrap probe: expands the
// configured interfaces (and their VLAN units) into the deterministic list of
// Linux netdev names process_napi.go sends probe traffic on.

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

func userspaceBootstrapProbeInterfaces(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(cfg.Interfaces.Interfaces)*2)
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for ifName := range cfg.Interfaces.Interfaces {
		names = append(names, ifName)
	}
	sort.Strings(names)
	for _, ifName := range names {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		base := config.LinuxIfName(ifName)
		if !seen[base] {
			seen[base] = true
			out = append(out, base)
		}
		if len(ifc.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil || unit.VlanID <= 0 {
				continue
			}
			linuxName := fmt.Sprintf("%s.%d", base, unit.VlanID)
			if seen[linuxName] {
				continue
			}
			seen[linuxName] = true
			out = append(out, linuxName)
		}
	}
	return out
}
