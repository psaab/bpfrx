// Package networkd generates systemd-networkd .link and .network files
// for interfaces managed by xpfd.
package networkd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// networkctlTimeout bounds every networkctl shell-out. Apply runs on
// the config-apply path under applyConfigLocked's applySem
// (daemon_apply.go d.networkd.Apply), so a hung networkctl (dbus stall,
// wedged systemd-networkd) would otherwise block every commit
// indefinitely. Mirrors the 15s FRR reload precedent
// (pkg/frr/manager.go reloadTimeout). #1794/#1800.
const networkctlTimeout = 15 * time.Second

// runNetworkctl runs `networkctl <args...>` under networkctlTimeout.
func runNetworkctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), networkctlTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "networkctl", args...).Run()
}

const (
	// DefaultNetworkDir is the systemd-networkd configuration directory.
	DefaultNetworkDir = "/etc/systemd/network"
	// filePrefix distinguishes xpf-managed files from manually created ones.
	filePrefix = "10-xpf-"
)

// InterfaceConfig describes a single interface for networkd generation.
type InterfaceConfig struct {
	Name             string   // interface name (trust0, untrust0, wan0, etc.)
	MACAddress       string   // hardware MAC address (from kernel)
	OriginalName     string   // kernel name before rename (for .link OriginalName= match)
	Addresses        []string // CIDR addresses (10.0.1.10/24, 2001:db8::1/64, etc.)
	PrimaryAddress   string   // address marked as primary (listed first for source selection)
	PreferredAddress string   // address marked as preferred (gets PreferredLifetime=forever)
	IsVLANParent     bool     // true = don't assign addresses (they go on sub-interface)
	DHCPv4           bool     // true = daemon runs DHCPv4 client (don't set static addr)
	DHCPv6           bool     // true = daemon runs DHCPv6 client
	Unmanaged        bool     // true = not in config; keep down with no addresses
	Disable          bool     // true = administratively disabled (keep down)
	DADDisable       bool     // true = disable IPv6 Duplicate Address Detection
	Speed            string   // link speed: "10M", "100M", "1G", "10G", etc.
	Duplex           string   // "full", "half"
	MTU              int      // interface MTU (0 = default)
	Description      string   // interface description (maps to .network [Network] Description)
	BondMaster       string   // LAG parent: bind this interface to a bond master (ae0, etc.)
	IsBond           bool     // true = this is a bond/LAG device (needs .netdev file)
	BondMode         string   // bond mode: "802.3ad" (default for ae interfaces)
	LACPRate         string   // LACP transmit rate: "fast" or "slow" (default)
	MinLinks         int      // minimum active member links (0 = no minimum)
	KeepAddresses    bool     // true = KeepConfiguration=static (preserve external addresses across reload)
	VRFName          string   // VRF device name (e.g. "vrf-mgmt") — emits [Network] VRF= so networkctl reconfigure preserves binding
	BridgeMaster     string   // bridge device name to join (e.g. "br-bd0")
	IsBridge         bool     // true = this is a bridge device (needs .netdev file)
}

// Manager handles systemd-networkd .link and .network file generation.
type Manager struct {
	networkDir string
	// protectedResolver returns the #1922 management protected set (logical
	// names). Files for these interfaces (10-xpf-<name>.{link,network}) are
	// NEVER swept by Apply even when the interface is absent from the
	// compiled config — sweeping them would delete the live management NIC's
	// rename + addressing and lock the operator out (#1956 AGY r3 CRITICAL,
	// also the #1922 lifeline invariant). nil => no exemption (legacy).
	protectedResolver func() map[string]bool
}

// SetProtectedResolver registers the management protected-set provider so
// Apply can exempt the lifeline's files from the stale-file sweep. Called once
// at daemon init alongside the dataplane protected resolver.
func (m *Manager) SetProtectedResolver(fn func() map[string]bool) {
	m.protectedResolver = fn
}

// New creates a new networkd manager.
func New() *Manager {
	return NewInDir(DefaultNetworkDir)
}

// NewInDir creates a networkd manager rooted at networkDir. Production callers
// use New(); tests and offline renderers use this to avoid touching /etc.
func NewInDir(networkDir string) *Manager {
	if networkDir == "" {
		networkDir = DefaultNetworkDir
	}
	return &Manager{
		networkDir: networkDir,
	}
}

// Apply writes .link and .network files for all interfaces,
// then calls networkctl reload if any files changed.
// Interfaces with existing non-xpf networkd configs (e.g. management
// interface) are skipped to avoid conflicts.
func (m *Manager) Apply(interfaces []InterfaceConfig) error {
	if len(interfaces) == 0 {
		return nil
	}

	// Discover interfaces with existing non-xpf networkd .network files.
	// Only skip unmanaged interfaces that have external configs (e.g.
	// management interface). Configured interfaces always get xpf files
	// even if old external files exist — xpf takes ownership.
	external := m.findExternallyManaged()

	var filtered []InterfaceConfig
	for _, ifc := range interfaces {
		if ifc.Unmanaged && external[ifc.Name] {
			slog.Debug("skipping externally managed interface", "name", ifc.Name)
			continue
		}
		filtered = append(filtered, ifc)
	}
	interfaces = filtered

	// Build set of expected filenames.
	// .link files are only for managed physical interfaces (have MAC address,
	// not unmanaged). Unmanaged interfaces are named by the daemon at startup.
	// .netdev files are for bond (LAG) and bridge devices.
	// VLAN sub-interfaces (wan0.50) only get .network files.
	expected := make(map[string]bool)
	for _, ifc := range interfaces {
		if ifc.MACAddress != "" && !ifc.Unmanaged {
			expected[filePrefix+ifc.Name+".link"] = true
		}
		if ifc.IsBond || ifc.IsBridge {
			expected[filePrefix+ifc.Name+".netdev"] = true
		}
		expected[filePrefix+ifc.Name+".network"] = true
	}

	// #1956 AGY r3 CRITICAL: never sweep the management protected set's files.
	// A protected interface (the lifeline / fxp0 / mgmt leaf) is exempt from
	// the unmanaged bring-down and is therefore absent from `interfaces`, so
	// the stale-file sweep below would otherwise delete its 10-xpf-*.link and
	// .network — instantly stripping the live mgmt NIC's rename + addressing
	// on reload. Add its files to `expected` so the sweep preserves them.
	if m.protectedResolver != nil {
		for name := range m.protectedResolver() {
			if name == "" {
				continue
			}
			expected[filePrefix+name+".link"] = true
			expected[filePrefix+name+".network"] = true
		}
	}

	changed := false

	// Remove stale xpf-managed files
	matches, _ := filepath.Glob(filepath.Join(m.networkDir, filePrefix+"*"))
	for _, path := range matches {
		base := filepath.Base(path)
		if !expected[base] {
			if err := os.Remove(path); err != nil {
				slog.Warn("failed to remove stale networkd file", "path", path, "err", err)
			} else {
				slog.Info("removed stale networkd file", "path", path)
				changed = true
			}
		}
	}

	// Write .netdev, .link, and .network files
	for _, ifc := range interfaces {
		// .netdev file: for bond/LAG devices and bridge devices
		if ifc.IsBond {
			netdevPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".netdev")
			netdevContent := m.generateNetdev(ifc)
			if writeIfChanged(netdevPath, netdevContent) {
				changed = true
			}
		}
		if ifc.IsBridge {
			netdevPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".netdev")
			netdevContent := m.generateBridgeNetdev(ifc)
			if writeIfChanged(netdevPath, netdevContent) {
				changed = true
			}
		}

		// .link file: only for managed physical interfaces with a MAC address.
		// Skip unmanaged interfaces — the daemon's linksetup handles their
		// naming at startup. Writing .link files for unmanaged interfaces would
		// override the FPC-aware naming (e.g. ge-7-0-X on node1).
		if ifc.MACAddress != "" && !ifc.Unmanaged {
			linkPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".link")
			linkContent := m.generateLink(ifc)
			if writeIfChanged(linkPath, linkContent) {
				changed = true
			}
		}

		// .network file: for all interfaces
		networkPath := filepath.Join(m.networkDir, filePrefix+ifc.Name+".network")
		networkContent := m.generateNetwork(ifc)
		if writeIfChanged(networkPath, networkContent) {
			changed = true
		}
	}

	if changed {
		slog.Info("networkd config updated, reloading", "interfaces", len(interfaces))
		if err := runNetworkctl("reload"); err != nil {
			return fmt.Errorf("networkctl reload: %w", err)
		}
		// Dynamically created interfaces (bonds, VLANs) may not get their
		// addresses applied by reload alone. Reconfigure all managed
		// interfaces to ensure addresses are applied.
		// Skip bond member interfaces — reconfigure can eject them from
		// their bond. Their Bond= directive is picked up by reload.
		var reconf []string
		for _, ifc := range interfaces {
			if !ifc.Unmanaged && !ifc.Disable && ifc.BondMaster == "" {
				reconf = append(reconf, ifc.Name)
			}
		}
		if len(reconf) > 0 {
			args := append([]string{"reconfigure"}, reconf...)
			// Best-effort (reload above already applied the files), but
			// the failure is no longer silent.
			if err := runNetworkctl(args...); err != nil {
				slog.Warn("networkctl reconfigure failed",
					"interfaces", len(reconf), "err", err)
			}
		}
		restoreSlowPathRPFilter()
	}

	return nil
}

// procSysNetRoot is the root of the IPv4 sysctl tree. It is a package var
// (not a const) so tests can point the slow-path rp_filter handling at a
// temp-file fixture instead of the live /proc.
var procSysNetRoot = "/proc/sys/net/ipv4"

// restoreSlowPathRPFilter re-disables rp_filter on the userspace dataplane's
// slow-path TUN device after a networkctl reload. networkd resets sysctls to
// defaults (rp_filter=2) on all interfaces during reload, which breaks
// locally-originated traffic delivery via the TUN (the kernel drops packets
// whose source route doesn't point at the TUN interface).
//
// The kernel computes the effective rp_filter for a packet as
// max(conf/all/rp_filter, conf/<dev>/rp_filter), so the per-device 0 we write
// here is ignored if conf/all/rp_filter is non-zero (a common Debian/Ubuntu
// default). We do NOT mutate the host-global conf/all knob — instead, when it
// is non-zero, we emit a one-time operator-visible warning that slow-path
// reinjection will be dropped until it is lowered (#2378). This runs only on
// the reload/clear path, never per-packet.
func restoreSlowPathRPFilter() {
	const tunName = "xpf-usp0"
	path := fmt.Sprintf("%s/conf/%s/rp_filter", procSysNetRoot, tunName)
	// BestEffortKernelKnob (#1894): procfs has no rename, so the
	// fsatomic writers are impossible here by construction — the direct
	// write is correct, not an oversight.
	if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
		if os.IsNotExist(err) {
			// TUN may not exist (userspace DP not active) — not an error.
			return
		}
		slog.Warn("failed to restore rp_filter on slow-path TUN", "path", path, "err", err)
	}
	warnIfAllRPFilterOverrides(tunName)
}

// warnIfAllRPFilterOverrides emits a loud warning when net.ipv4.conf.all.rp_filter
// is non-zero. The kernel uses max(conf/all/rp_filter, conf/<dev>/rp_filter), so
// a non-zero conf/all knob silently drops slow-path reinjected IPv4 packets
// regardless of the per-device value (#2378). The message states the hazard from
// the all-knob directly and does NOT assert that the per-device write above
// succeeded — so it stays accurate when the per-device write failed (in which
// case the drop hazard is in fact MORE acute, and suppressing the warning would
// hide a still-relevant signal). A missing or unparsable conf/all/rp_filter is
// treated as "cannot determine" and stays quiet so a read failure never produces
// a spurious warning.
func warnIfAllRPFilterOverrides(tunName string) {
	allPath := fmt.Sprintf("%s/conf/all/rp_filter", procSysNetRoot)
	raw, err := os.ReadFile(allPath)
	if err != nil {
		return
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || val == 0 {
		return
	}
	slog.Warn("net.ipv4.conf.all.rp_filter is non-zero; kernel uses max(all,dev) "+
		"so slow-path reinjected IPv4 packets will be SILENTLY DROPPED until "+
		"'sysctl -w net.ipv4.conf.all.rp_filter=0' is set",
		"tun", tunName, "all_rp_filter", val, "issue", 2378)
}

// Clear removes all xpf-managed networkd files and reloads.
func (m *Manager) Clear() error {
	matches, _ := filepath.Glob(filepath.Join(m.networkDir, filePrefix+"*"))
	if len(matches) == 0 {
		return nil
	}

	for _, path := range matches {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove networkd file", "path", path, "err", err)
		}
	}

	if err := runNetworkctl("reload"); err != nil {
		return fmt.Errorf("networkctl reload: %w", err)
	}
	restoreSlowPathRPFilter()
	slog.Info("cleared xpf networkd files", "removed", len(matches))
	return nil
}

// FindExternallyManaged scans the given networkd directory for non-xpf
// .network files and returns the set of interface names they match. This
// protects the management interface (and any other externally configured
// interface) from being modified or brought down by xpf.
func FindExternallyManaged(dir string) map[string]bool {
	result := make(map[string]bool)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, ".network") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Name=") {
				ifName := strings.TrimSpace(strings.TrimPrefix(line, "Name="))
				if ifName != "" {
					result[ifName] = true
				}
			}
		}
	}
	return result
}

func (m *Manager) findExternallyManaged() map[string]bool {
	return FindExternallyManaged(m.networkDir)
}

// sanitizeUnitValue strips ASCII control characters — the C0 set
// (0x00-0x1F, including newline) and DEL (0x7F), each replaced by a
// space — from a free-text config value before it is interpolated into
// a generated systemd unit line. Render-side belt for #1798: a
// description like "lan\nDHCP=ipv4" must not be able to inject extra
// directives into a .network/.netdev/.link unit even if the
// commit-time validation layer were bypassed (e.g. an old persisted
// value reaching the renderer ahead of the load-time sanitizer).
func sanitizeUnitValue(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

func (m *Manager) generateNetdev(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[NetDev]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)
	b.WriteString("Kind=bond\n")
	if ifc.Description != "" {
		fmt.Fprintf(&b, "Description=%s\n", sanitizeUnitValue(ifc.Description))
	}
	if ifc.MTU > 0 {
		fmt.Fprintf(&b, "MTUBytes=%d\n", ifc.MTU)
	}
	b.WriteString("\n[Bond]\n")
	mode := ifc.BondMode
	if mode == "" {
		mode = "802.3ad"
	}
	fmt.Fprintf(&b, "Mode=%s\n", mode)
	if mode == "active-backup" {
		// Active-backup uses MII monitoring, no LACP
		b.WriteString("MIIMonitorSec=100ms\n")
	} else {
		// LACP modes (802.3ad, balance-xor, etc.)
		rate := ifc.LACPRate
		if rate == "" {
			rate = "fast"
		}
		fmt.Fprintf(&b, "LACPTransmitRate=%s\n", rate)
		b.WriteString("TransmitHashPolicy=layer3+4\n")
	}
	if ifc.MinLinks > 0 {
		fmt.Fprintf(&b, "MinLinks=%d\n", ifc.MinLinks)
	}
	return b.String()
}

func (m *Manager) generateBridgeNetdev(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[NetDev]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)
	b.WriteString("Kind=bridge\n")
	if ifc.Description != "" {
		fmt.Fprintf(&b, "Description=%s\n", sanitizeUnitValue(ifc.Description))
	}
	if ifc.MTU > 0 {
		fmt.Fprintf(&b, "MTUBytes=%d\n", ifc.MTU)
	}
	return b.String()
}

func (m *Manager) generateLink(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[Match]\n")
	if ifc.OriginalName != "" {
		// RETH members: match by kernel name (PCI-based, stable across
		// reboots) because the MAC alternates between physical and virtual.
		fmt.Fprintf(&b, "OriginalName=%s\n", ifc.OriginalName)
	} else {
		fmt.Fprintf(&b, "MACAddress=%s\n", ifc.MACAddress)
	}
	b.WriteString("\n[Link]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)
	if ifc.MTU > 0 {
		fmt.Fprintf(&b, "MTUBytes=%d\n", ifc.MTU)
	}
	if ifc.Speed != "" {
		fmt.Fprintf(&b, "BitsPerSecond=%s\n", junosSpeedToNetworkd(ifc.Speed))
	}
	if ifc.Duplex != "" {
		fmt.Fprintf(&b, "Duplex=%s\n", ifc.Duplex)
	}
	if ifc.Description != "" {
		fmt.Fprintf(&b, "Description=%s\n", sanitizeUnitValue(ifc.Description))
	}
	return b.String()
}

func (m *Manager) generateNetwork(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by xpfd — do not edit\n")
	b.WriteString("[Match]\n")
	fmt.Fprintf(&b, "Name=%s\n", ifc.Name)

	if ifc.Unmanaged || ifc.Disable {
		b.WriteString("\n[Link]\n")
		b.WriteString("ActivationPolicy=always-down\n")
		b.WriteString("RequiredForOnline=no\n")
		b.WriteString("\n[Network]\n")
		b.WriteString("DHCP=no\n")
		b.WriteString("IPv6AcceptRA=no\n")
		b.WriteString("LinkLocalAddressing=no\n")
		return b.String()
	}

	if ifc.IsVLANParent {
		b.WriteString("\n[Link]\n")
		b.WriteString("RequiredForOnline=no\n")
	}

	b.WriteString("\n[Network]\n")
	b.WriteString("IPv6AcceptRA=no\n")

	if ifc.IsVLANParent {
		b.WriteString("DHCP=no\n")
	}

	// Preserve externally-added addresses (e.g. VRRP VIPs) across networkctl reload.
	if ifc.KeepAddresses {
		b.WriteString("KeepConfiguration=static\n")
	}

	b.WriteString("LinkLocalAddressing=ipv6\n")

	// VRF membership — ensures networkctl reconfigure preserves the binding
	if ifc.VRFName != "" {
		fmt.Fprintf(&b, "VRF=%s\n", ifc.VRFName)
	}

	// Bond member: bind to bond master
	if ifc.BondMaster != "" {
		fmt.Fprintf(&b, "Bond=%s\n", ifc.BondMaster)
	}

	// Bridge member: bind to bridge device
	if ifc.BridgeMaster != "" {
		fmt.Fprintf(&b, "Bridge=%s\n", ifc.BridgeMaster)
	}

	// Disable IPv6 Duplicate Address Detection if configured
	if ifc.DADDisable {
		b.WriteString("IPv6DuplicateAddressDetection=0\n")
	}

	// Write static Address= lines for VLAN-parent-exempt interfaces, gating
	// each family independently on its own DHCP flag (#2986). DHCP is a
	// per-family property on the wire (DHCPv4 vs DHCPv6/PD), so a static
	// address must be suppressed ONLY for the family whose DHCP client owns
	// it — not the opposite family. The common WAN shape DHCPv4 + static
	// IPv6 (and the mirror static IPv4 + DHCPv6) previously dropped the
	// static address of the non-DHCP family because the gate keyed on
	// whole-interface (!DHCPv4 && !DHCPv6).
	if !ifc.IsVLANParent {
		ordered := orderAddresses(ifc.Addresses, ifc.PrimaryAddress)
		addrs := make([]string, 0, len(ordered))
		for _, addr := range ordered {
			if addressIsIPv6(addr) {
				if ifc.DHCPv6 {
					continue
				}
			} else if ifc.DHCPv4 {
				continue
			}
			addrs = append(addrs, addr)
		}
		if ifc.PreferredAddress != "" {
			// Use [Address] sections so we can set PreferredLifetime
			for _, addr := range addrs {
				b.WriteString("\n[Address]\n")
				fmt.Fprintf(&b, "Address=%s\n", addr)
				if addr == ifc.PreferredAddress {
					b.WriteString("PreferredLifetime=forever\n")
				}
			}
		} else {
			for _, addr := range addrs {
				fmt.Fprintf(&b, "Address=%s\n", addr)
			}
		}
	}

	return b.String()
}

// junosSpeedToNetworkd converts Junos speed notation to systemd-networkd BitsPerSecond.
// Junos uses "10m", "100m", "1g", "10g", "25g", "40g", "100g", "auto".
// networkd expects numeric bps value (e.g. "1000000000" for 1G).
func junosSpeedToNetworkd(speed string) string {
	s := strings.ToLower(strings.TrimSpace(speed))
	switch s {
	case "10m":
		return "10000000"
	case "100m":
		return "100000000"
	case "1g":
		return "1000000000"
	case "2.5g":
		return "2500000000"
	case "5g":
		return "5000000000"
	case "10g":
		return "10000000000"
	case "25g":
		return "25000000000"
	case "40g":
		return "40000000000"
	case "100g":
		return "100000000000"
	default:
		return speed // pass through as-is
	}
}

// addressIsIPv6 reports whether a CIDR address string (e.g.
// "2001:db8::1/64" or "10.0.1.10/24") is IPv6. An IPv6 literal always
// contains a colon and an IPv4 literal never does, so a colon test
// classifies the family without a full netip parse — keeping the static
// render allocation-free and tolerant of zone-id suffixes.
func addressIsIPv6(addr string) bool {
	return strings.Contains(addr, ":")
}

// orderAddresses returns a copy of addrs with primaryAddr first (if set and present).
func orderAddresses(addrs []string, primaryAddr string) []string {
	if primaryAddr == "" || len(addrs) <= 1 {
		return addrs
	}
	ordered := make([]string, 0, len(addrs))
	found := false
	for _, a := range addrs {
		if a == primaryAddr {
			found = true
		} else {
			ordered = append(ordered, a)
		}
	}
	if found {
		ordered = append([]string{primaryAddr}, ordered...)
	}
	return ordered
}

// writeIfChanged writes content to path only if the content differs from
// the existing file. Returns true if the file was written.
func writeIfChanged(path, content string) bool {
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return false
	}

	// AtomicGeneratedConfig (#1894): .link/.network snippets are
	// regenerated on boot/apply — keep them un-torn for networkd, but
	// never pay an fsync on this hot apply path (many small files per
	// reconcile).
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to write networkd file", "path", path, "err", err)
		return false
	}

	slog.Info("wrote networkd file", "path", path)
	return true
}
