// Package networkd generates systemd-networkd .link and .network files
// for interfaces managed by bpfrxd.
package networkd

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// DefaultNetworkDir is the systemd-networkd configuration directory.
	DefaultNetworkDir = "/etc/systemd/network"
	// filePrefix distinguishes bpfrx-managed files from manually created ones.
	filePrefix = "10-bpfrx-"
)

// InterfaceConfig describes a single interface for networkd generation.
type InterfaceConfig struct {
	Name         string   // interface name (trust0, untrust0, wan0, etc.)
	MACAddress   string   // hardware MAC address (from kernel)
	Addresses    []string // CIDR addresses (10.0.1.10/24, 2001:db8::1/64, etc.)
	IsVLANParent bool     // true = don't assign addresses (they go on sub-interface)
	DHCPv4       bool     // true = daemon runs DHCPv4 client (don't set static addr)
	DHCPv6       bool     // true = daemon runs DHCPv6 client
	Unmanaged    bool     // true = not in config; keep down with no addresses
	Disable      bool     // true = administratively disabled (keep down)
	DADDisable   bool     // true = disable IPv6 Duplicate Address Detection
	Speed        string   // link speed: "10M", "100M", "1G", "10G", etc.
	Duplex       string   // "full", "half"
	MTU          int      // interface MTU (0 = default)
	Description  string   // interface description (maps to .network [Network] Description)
}

// Manager handles systemd-networkd .link and .network file generation.
type Manager struct {
	networkDir string
}

// New creates a new networkd manager.
func New() *Manager {
	return &Manager{
		networkDir: DefaultNetworkDir,
	}
}

// Apply writes .link and .network files for all interfaces,
// then calls networkctl reload if any files changed.
// Interfaces with existing non-bpfrx networkd configs (e.g. management
// interface) are skipped to avoid conflicts.
func (m *Manager) Apply(interfaces []InterfaceConfig) error {
	if len(interfaces) == 0 {
		return nil
	}

	// Discover interfaces with existing non-bpfrx networkd .network files.
	// Only skip unmanaged interfaces that have external configs (e.g.
	// management interface). Configured interfaces always get bpfrx files
	// even if old external files exist — bpfrx takes ownership.
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
	// .link files are only for physical interfaces (have MAC address).
	// VLAN sub-interfaces (wan0.50) only get .network files.
	expected := make(map[string]bool)
	for _, ifc := range interfaces {
		if ifc.MACAddress != "" {
			expected[filePrefix+ifc.Name+".link"] = true
		}
		expected[filePrefix+ifc.Name+".network"] = true
	}

	changed := false

	// Remove stale bpfrx-managed files
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

	// Write .link and .network files
	for _, ifc := range interfaces {
		// .link file: only for physical interfaces with a MAC address
		if ifc.MACAddress != "" {
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
		if err := exec.Command("networkctl", "reload").Run(); err != nil {
			return fmt.Errorf("networkctl reload: %w", err)
		}
	}

	return nil
}

// Clear removes all bpfrx-managed networkd files and reloads.
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

	if err := exec.Command("networkctl", "reload").Run(); err != nil {
		return fmt.Errorf("networkctl reload: %w", err)
	}
	slog.Info("cleared bpfrx networkd files", "removed", len(matches))
	return nil
}

// FindExternallyManaged scans the given networkd directory for non-bpfrx
// .network files and returns the set of interface names they match. This
// protects the management interface (and any other externally configured
// interface) from being modified or brought down by bpfrx.
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

func (m *Manager) generateLink(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by bpfrxd — do not edit\n")
	b.WriteString("[Match]\n")
	fmt.Fprintf(&b, "MACAddress=%s\n", ifc.MACAddress)
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
		fmt.Fprintf(&b, "Description=%s\n", ifc.Description)
	}
	return b.String()
}

func (m *Manager) generateNetwork(ifc InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by bpfrxd — do not edit\n")
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

	b.WriteString("LinkLocalAddressing=ipv6\n")

	// Disable IPv6 Duplicate Address Detection if configured
	if ifc.DADDisable {
		b.WriteString("IPv6DuplicateAddressDetection=0\n")
	}

	// Only write Address= lines for static (non-DHCP, non-VLAN-parent) interfaces
	if !ifc.IsVLANParent && !ifc.DHCPv4 && !ifc.DHCPv6 {
		for _, addr := range ifc.Addresses {
			fmt.Fprintf(&b, "Address=%s\n", addr)
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

// writeIfChanged writes content to path only if the content differs from
// the existing file. Returns true if the file was written.
func writeIfChanged(path, content string) bool {
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return false
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to write networkd file", "path", path, "err", err)
		return false
	}

	slog.Info("wrote networkd file", "path", path)
	return true
}
