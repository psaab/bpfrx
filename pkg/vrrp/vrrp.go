// Package vrrp manages keepalived configuration for VRRP high availability.
package vrrp

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"

	"github.com/psaab/bpfrx/pkg/config"
)

// Instance describes a single VRRP instance to configure in keepalived.
type Instance struct {
	Interface        string
	GroupID          int
	Priority         int
	Preempt          bool
	AcceptData       bool
	AdvertiseInterval int
	VirtualAddresses []string // CIDR notation
	AuthType         string   // "" or "md5"
	AuthKey          string
	TrackInterface   string
	TrackPriorityCost int
}

// CollectInstances extracts VRRP instances from the interface config.
func CollectInstances(cfg *config.Config) []*Instance {
	if cfg == nil {
		return nil
	}
	var instances []*Instance
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			for _, vg := range unit.VRRPGroups {
				inst := &Instance{
					Interface:         ifName,
					GroupID:           vg.ID,
					Priority:          vg.Priority,
					Preempt:           vg.Preempt,
					AcceptData:        vg.AcceptData,
					AdvertiseInterval: vg.AdvertiseInterval,
					VirtualAddresses:  vg.VirtualAddresses,
					AuthType:          vg.AuthType,
					AuthKey:           vg.AuthKey,
					TrackInterface:    vg.TrackInterface,
					TrackPriorityCost: vg.TrackPriorityDelta,
				}
				if inst.AdvertiseInterval == 0 {
					inst.AdvertiseInterval = 1
				}
				instances = append(instances, inst)
			}
		}
	}
	return instances
}

// CollectRethInstances generates VRRP instances for RETH interfaces that have
// a RedundancyGroup > 0. These provide keepalived-backed failover for HA
// cluster RETH interfaces. VRID = 100 + redundancyGroupID.
func CollectRethInstances(cfg *config.Config, localPriority map[int]int) []*Instance {
	if cfg == nil {
		return nil
	}
	// Sort interface names for deterministic output.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	var instances []*Instance
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc.RedundancyGroup <= 0 {
			continue
		}
		rgID := ifc.RedundancyGroup

		pri := localPriority[rgID]
		if pri == 0 {
			pri = 100 // default to secondary priority
		}

		linuxName := config.LinuxIfName(ifc.Name)

		// For VLAN-tagged interfaces, create one VRRP instance per
		// sub-interface (e.g. reth0.50) since the parent bond has no
		// IPv4 and keepalived requires one for VRRP advertisements.
		// For non-VLAN interfaces, use the base interface.
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)

		if ifc.VlanTagging {
			for _, n := range unitNums {
				unit := ifc.Units[n]
				if len(unit.Addresses) == 0 {
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				instances = append(instances, &Instance{
					Interface:         subIface,
					GroupID:           100 + rgID,
					Priority:          pri,
					Preempt:           true,
					AcceptData:        true,
					AdvertiseInterval: 1,
					VirtualAddresses:  unit.Addresses,
				})
			}
		} else {
			var vips []string
			for _, n := range unitNums {
				vips = append(vips, ifc.Units[n].Addresses...)
			}
			if len(vips) == 0 {
				continue
			}
			instances = append(instances, &Instance{
				Interface:         linuxName,
				GroupID:           100 + rgID,
				Priority:          pri,
				Preempt:           true,
				AcceptData:        true,
				AdvertiseInterval: 1,
				VirtualAddresses:  vips,
			})
		}
	}
	return instances
}

// UpdatePriority regenerates RETH VRRP instances with the given priorities,
// merges them with user-configured VRRP instances, and applies the combined
// config. Called on cluster state changes to update keepalived priorities.
func UpdatePriority(cfg *config.Config, localPriority map[int]int) error {
	var all []*Instance
	all = append(all, CollectInstances(cfg)...)
	all = append(all, CollectRethInstances(cfg, localPriority)...)
	return Apply(all)
}

const keepalivedConf = "/etc/keepalived/keepalived.conf"

// Apply generates the keepalived config and manages the service.
// If keepalived is already running, it reloads (SIGHUP) to pick up config
// changes without cycling through FAULT state. A full restart is only done
// when keepalived is not yet running.
func Apply(instances []*Instance) error {
	if len(instances) == 0 {
		// No VRRP configured — stop keepalived if running
		_ = exec.Command("systemctl", "stop", "keepalived").Run()
		return nil
	}

	confContent := generateConfig(instances)

	// Ensure directory exists
	if err := os.MkdirAll("/etc/keepalived", 0755); err != nil {
		return fmt.Errorf("mkdir /etc/keepalived: %w", err)
	}

	if err := os.WriteFile(keepalivedConf, []byte(confContent), 0644); err != nil {
		return fmt.Errorf("write keepalived.conf: %w", err)
	}
	slog.Info("keepalived config written", "instances", len(instances))

	_ = exec.Command("systemctl", "enable", "keepalived").Run()

	// If keepalived is already running, reload config via SIGHUP.
	// This avoids cycling through FAULT state on every priority update.
	// keepalived recovers from FAULT automatically via netlink events
	// when interfaces get their addresses.
	out, _ := exec.Command("systemctl", "is-active", "keepalived").Output()
	if strings.TrimSpace(string(out)) == "active" {
		if err := exec.Command("systemctl", "reload", "keepalived").Run(); err != nil {
			slog.Warn("keepalived reload failed, falling back to restart", "err", err)
			if err := exec.Command("systemctl", "restart", "keepalived").Run(); err != nil {
				return fmt.Errorf("restart keepalived: %w", err)
			}
		}
		return nil
	}

	// Not running — start it. May enter FAULT initially if interfaces
	// lack IPv4, but will recover via netlink when addresses appear.
	if err := exec.Command("systemctl", "start", "keepalived").Run(); err != nil {
		return fmt.Errorf("start keepalived: %w", err)
	}
	return nil
}

func generateConfig(instances []*Instance) string {
	var sb strings.Builder
	sb.WriteString("# Generated by bpfrx — do not edit\n\n")

	for _, inst := range instances {
		name := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
		sb.WriteString(fmt.Sprintf("vrrp_instance %s {\n", name))
		sb.WriteString("    state BACKUP\n") // always start as BACKUP; preempt handles promotion
		sb.WriteString(fmt.Sprintf("    interface %s\n", inst.Interface))
		sb.WriteString(fmt.Sprintf("    virtual_router_id %d\n", inst.GroupID))
		sb.WriteString(fmt.Sprintf("    priority %d\n", inst.Priority))
		sb.WriteString(fmt.Sprintf("    advert_int %d\n", inst.AdvertiseInterval))
		if !inst.Preempt {
			sb.WriteString("    nopreempt\n")
		}
		if inst.AcceptData {
			sb.WriteString("    accept\n")
		}

		if inst.AuthKey != "" {
			sb.WriteString("\n    authentication {\n")
			authType := "PASS"
			if inst.AuthType == "md5" {
				authType = "AH"
			}
			sb.WriteString(fmt.Sprintf("        auth_type %s\n", authType))
			sb.WriteString(fmt.Sprintf("        auth_pass %s\n", inst.AuthKey))
			sb.WriteString("    }\n")
		}

		if len(inst.VirtualAddresses) > 0 {
			sb.WriteString("\n    virtual_ipaddress {\n")
			for _, vip := range inst.VirtualAddresses {
				// Add /24 if not already CIDR
				addr := vip
				if !strings.Contains(addr, "/") {
					addr += "/32"
				}
				sb.WriteString(fmt.Sprintf("        %s dev %s\n", addr, inst.Interface))
			}
			sb.WriteString("    }\n")
		}

		if inst.TrackInterface != "" {
			sb.WriteString("\n    track_interface {\n")
			weight := -50
			if inst.TrackPriorityCost > 0 {
				weight = -inst.TrackPriorityCost
			}
			sb.WriteString(fmt.Sprintf("        %s weight %d\n", inst.TrackInterface, weight))
			sb.WriteString("    }\n")
		}

		sb.WriteString("}\n\n")
	}

	return sb.String()
}

// InstanceState holds the runtime state of a VRRP instance.
type InstanceState struct {
	Interface string
	GroupID   int
	State     string // "MASTER", "BACKUP", "INIT", "FAULT"
}

// RuntimeStates determines the actual state of each VRRP instance by
// checking whether keepalived is running, then signaling it to dump
// state and parsing the data file. Falls back to checking virtual IP
// presence on interfaces.
func RuntimeStates(instances []*Instance) map[string]string {
	states := make(map[string]string) // key: "VI_<iface>_<group>"
	if len(instances) == 0 {
		return states
	}

	// Check if keepalived is running
	out, err := exec.Command("systemctl", "is-active", "keepalived").Output()
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		for _, inst := range instances {
			key := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
			states[key] = "INIT"
		}
		return states
	}

	// Signal keepalived to dump data, then parse it
	if parsed := dumpAndParse(); len(parsed) > 0 {
		// Fill in any missing instances with INIT
		for _, inst := range instances {
			key := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
			if st, ok := parsed[key]; ok {
				states[key] = st
			} else {
				states[key] = "INIT"
			}
		}
		return states
	}

	// Fallback: check if virtual IPs are assigned to determine MASTER vs BACKUP
	for _, inst := range instances {
		key := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
		if hasVirtualAddrs(inst) {
			states[key] = "MASTER"
		} else {
			states[key] = "BACKUP"
		}
	}
	return states
}

// dumpAndParse signals keepalived to dump state and parses the data file.
func dumpAndParse() map[string]string {
	// Send SIGUSR1 to keepalived to dump data to /tmp/keepalived.data
	pidBytes, err := os.ReadFile("/run/keepalived.pid")
	if err != nil {
		return nil
	}
	pid := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(string(pidBytes)), "%d", &pid); err != nil || pid <= 0 {
		return nil
	}
	// Signal keepalived
	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		slog.Debug("failed to signal keepalived", "err", err)
		return nil
	}

	// Give keepalived a moment to write the file
	data, err := os.ReadFile("/tmp/keepalived.data")
	if err != nil {
		return nil
	}

	return parseDataFile(string(data))
}

// parseDataFile parses /tmp/keepalived.data to extract instance states.
// Format:
//
//	VRRP Instance = VI_trust0_100
//	  State               = MASTER
func parseDataFile(content string) map[string]string {
	states := make(map[string]string)
	var currentInstance string

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "VRRP Instance = ") {
			currentInstance = strings.TrimPrefix(trimmed, "VRRP Instance = ")
		} else if currentInstance != "" && strings.HasPrefix(trimmed, "State") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				st := strings.TrimSpace(parts[1])
				states[currentInstance] = st
				currentInstance = ""
			}
		}
	}
	return states
}

// hasVirtualAddrs checks if any of the instance's virtual addresses
// are currently assigned to its interface.
func hasVirtualAddrs(inst *Instance) bool {
	iface, err := net.InterfaceByName(inst.Interface)
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	addrSet := make(map[string]bool)
	for _, a := range addrs {
		// a.String() returns "ip/prefix" CIDR
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil {
			addrSet[ip.String()] = true
		}
	}

	for _, vip := range inst.VirtualAddresses {
		// Virtual addresses may or may not have a CIDR suffix
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		if addrSet[addr] {
			return true
		}
	}
	return false
}

// Status reads the keepalived status and returns a formatted string.
func Status() (string, error) {
	out, err := exec.Command("systemctl", "is-active", "keepalived").Output()
	if err != nil {
		return "keepalived: not running\n", nil
	}
	state := strings.TrimSpace(string(out))
	if state != "active" {
		return fmt.Sprintf("keepalived: %s\n", state), nil
	}

	// Try to read keepalived stats
	statsFile := "/tmp/keepalived.stats"
	if data, err := os.ReadFile(statsFile); err == nil {
		return fmt.Sprintf("keepalived: active\n\n%s", string(data)), nil
	}

	// Fall back to just showing the config
	confData, err := os.ReadFile(keepalivedConf)
	if err != nil {
		return "keepalived: active (config not readable)\n", nil
	}

	return fmt.Sprintf("keepalived: active\n\nConfig:\n%s", string(confData)), nil
}
