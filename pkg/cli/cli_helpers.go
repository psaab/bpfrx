package cli

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/cmdtree"
	"github.com/psaab/bpfrx/pkg/config"
	dpuserspace "github.com/psaab/bpfrx/pkg/dataplane/userspace"
	"github.com/psaab/bpfrx/pkg/routing"
	"github.com/vishvananda/netlink"
)

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func (c *CLI) handleShowIPv6(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show ipv6:", operationalTree, "show", "ipv6")
		return nil
	}
	switch args[0] {
	case "neighbors":
		return c.showIPv6Neighbors()
	case "router-advertisement":
		return c.showIPv6RouterAdvertisement()
	default:
		return fmt.Errorf("unknown show ipv6 target: %s", args[0])
	}
}

func neighState(state int) string {
	switch state {
	case netlink.NUD_REACHABLE:
		return "reachable"
	case netlink.NUD_STALE:
		return "stale"
	case netlink.NUD_DELAY:
		return "delay"
	case netlink.NUD_PROBE:
		return "probe"
	case netlink.NUD_FAILED:
		return "failed"
	case netlink.NUD_PERMANENT:
		return "permanent"
	case netlink.NUD_INCOMPLETE:
		return "incomplete"
	case netlink.NUD_NOARP:
		return "noarp"
	default:
		return "unknown"
	}
}

func (c *CLI) buildInterfacesInput() cluster.InterfacesInput {
	var input cluster.InterfacesInput
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return input
	}
	cc := cfg.Chassis.Cluster
	input.ControlInterface = cc.ControlInterface
	input.FabricInterface = cc.FabricInterface
	if fabIfc, ok := cfg.Interfaces.Interfaces[cc.FabricInterface]; ok {
		input.FabricMembers = fabIfc.FabricMembers
	}
	input.Fabric1Interface = cc.Fabric1Interface
	if fab1Ifc, ok := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; ok {
		input.Fabric1Members = fab1Ifc.FabricMembers
	}

	rethMap := cfg.RethToPhysical()
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup > 0 && strings.HasPrefix(name, "reth") {
			status := "Up"
			if phys, ok := rethMap[name]; ok {
				linuxName := config.LinuxIfName(phys)
				link, err := netlink.LinkByName(linuxName)
				if err != nil || (link.Attrs().OperState != netlink.OperUp &&
					link.Attrs().Flags&net.FlagUp == 0) {
					status = "Down"
				}
			}
			input.Reths = append(input.Reths, cluster.RethInfo{
				Name:            name,
				RedundancyGroup: ifc.RedundancyGroup,
				Status:          status,
			})
		}
	}
	sort.Slice(input.Reths, func(i, j int) bool { return input.Reths[i].Name < input.Reths[j].Name })

	localMonMap := make(map[string]bool)
	monStatuses := make(map[int][]routing.InterfaceMonitorStatus)
	if c.routing != nil {
		if ms := c.routing.InterfaceMonitorStatuses(); ms != nil {
			monStatuses = ms
		}
	}
	for _, rg := range cc.RedundancyGroups {
		if statuses, ok := monStatuses[rg.ID]; ok {
			for _, st := range statuses {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:       st.Interface,
					Weight:          st.Weight,
					Up:              st.Up,
					RedundancyGroup: rg.ID,
				})
				localMonMap[st.Interface] = true
			}
		} else {
			for _, mon := range rg.InterfaceMonitors {
				input.Monitors = append(input.Monitors, cluster.InterfaceMonitorInfo{
					Interface:       mon.Interface,
					Weight:          mon.Weight,
					Up:              true,
					RedundancyGroup: rg.ID,
				})
				localMonMap[mon.Interface] = true
			}
		}
	}

	if c.cluster != nil {
		peerLive := c.cluster.PeerMonitorStatuses()
		peerMap := make(map[string]bool)
		for _, pm := range peerLive {
			peerMap[pm.Interface] = true
			input.PeerMonitors = append(input.PeerMonitors, pm)
		}
		for _, rg := range cc.RedundancyGroups {
			for _, mon := range rg.InterfaceMonitors {
				if localMonMap[mon.Interface] {
					continue
				}
				if peerMap[mon.Interface] {
					continue
				}
				input.PeerMonitors = append(input.PeerMonitors, cluster.InterfaceMonitorInfo{
					Interface:       mon.Interface,
					Weight:          mon.Weight,
					Up:              false,
					RedundancyGroup: rg.ID,
				})
			}
		}
	}

	return input
}

func (c *CLI) userspaceDataplaneStatus() (dpuserspace.ProcessStatus, error) {
	provider, ok := c.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return dpuserspace.ProcessStatus{}, fmt.Errorf("userspace status unavailable")
	}
	return provider.Status()
}

func (c *CLI) userspaceDataplaneControl() (interface {
	Status() (dpuserspace.ProcessStatus, error)
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}, error) {
	provider, ok := c.dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
		SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
		SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
		SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
		InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return nil, fmt.Errorf("userspace dataplane control unavailable")
	}
	return provider, nil
}

func fmtPref(p int) string {
	if p == 0 {
		return "-"
	}
	return strconv.Itoa(p)
}

func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
		if matchPolicyAddrSet(a, ip, cfg, 0) {
			return true
		}
	}
	return false
}

func matchPolicyAddrSet(setName string, ip net.IP, cfg *config.Config, depth int) bool {
	if depth > 5 || cfg.Security.AddressBook == nil {
		return false
	}
	as, ok := cfg.Security.AddressBook.AddressSets[setName]
	if !ok {
		return false
	}
	for _, addrName := range as.Addresses {
		if addr, ok := cfg.Security.AddressBook.Addresses[addrName]; ok {
			_, cidr, err := net.ParseCIDR(addr.Value)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	for _, nested := range as.AddressSets {
		if matchPolicyAddrSet(nested, ip, cfg, depth+1) {
			return true
		}
	}
	return false
}

func matchPolicyApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if matchSingleApp(a, proto, dstPort, cfg) {
			return true
		}
		if cfg.Applications.ApplicationSets != nil {
			if as, ok := cfg.Applications.ApplicationSets[a]; ok {
				for _, appRef := range as.Applications {
					if matchSingleApp(appRef, proto, dstPort, cfg) {
						return true
					}
				}
			}
		}
	}
	return false
}

func matchSingleApp(appName, proto string, dstPort int, cfg *config.Config) bool {
	if cfg.Applications.Applications == nil {
		return false
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return false
	}
	if app.Protocol != "" && !strings.EqualFold(app.Protocol, proto) {
		return false
	}
	if app.DestinationPort != "" && dstPort > 0 {
		if strings.Contains(app.DestinationPort, "-") {
			parts := strings.SplitN(app.DestinationPort, "-", 2)
			lo, _ := strconv.Atoi(parts[0])
			hi, _ := strconv.Atoi(parts[1])
			if dstPort < lo || dstPort > hi {
				return false
			}
		} else {
			p, _ := strconv.Atoi(app.DestinationPort)
			if p != dstPort {
				return false
			}
		}
	}
	return true
}
