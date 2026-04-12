// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/bpfrx/pkg/cluster"
	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fixRethLinkFile rewrites the .link file for a RETH member to use
// OriginalName= (the kernel name) instead of MACAddress= for matching.
// This ensures the .link works on reboot when the MAC reverts to physical.
func fixRethLinkFile(ifName, kernelName string) {
	path := fmt.Sprintf("/etc/systemd/network/10-bpfrx-%s.link", ifName)
	content := fmt.Sprintf("# Managed by bpfrxd — do not edit\n[Match]\nOriginalName=%s\n\n[Link]\nName=%s\n", kernelName, ifName)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to fix RETH .link file", "path", path, "err", err)
	}
}

// ensureRethLinkOriginalName checks that a RETH member's .link file uses
// OriginalName= (PCI kernel name) instead of MACAddress=. If the file still
// uses MACAddress=, it derives the kernel name and rewrites the file. This
// handles bootstrap .link files that were created before the daemon ran.
func ensureRethLinkOriginalName(ifName string) {
	path := fmt.Sprintf("/etc/systemd/network/10-bpfrx-%s.link", ifName)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	if !strings.Contains(content, "MACAddress=") {
		return // already uses OriginalName= or other match
	}
	// Derive kernel name from altnames or sysfs
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	var kernelName string
	for _, alt := range link.Attrs().AltNames {
		if strings.HasPrefix(alt, "enp") || strings.HasPrefix(alt, "eno") ||
			strings.HasPrefix(alt, "ens") || strings.HasPrefix(alt, "eth") {
			kernelName = alt
			break
		}
	}
	if kernelName == "" {
		kernelName = deriveKernelName(ifName)
	}
	if kernelName == "" {
		return
	}
	slog.Info("fixing RETH .link file to use OriginalName",
		"iface", ifName, "kernelName", kernelName)
	fixRethLinkFile(ifName, kernelName)
}

// deriveKernelName returns the predictable kernel name (e.g. enp8s0) for an
// interface by examining its sysfs device path. Handles both PCI-direct
// devices (device → 0000:09:00.0) and virtio-over-PCI (device → virtioN,
// parent → 0000:08:00.0).
func deriveKernelName(ifName string) string {
	devPath, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/class/net/%s/device", ifName))
	if err != nil {
		return ""
	}
	pciAddr := pciAddrFromPath(devPath)
	if pciAddr == "" {
		// Virtio: device is virtioN, parent directory is the PCI device
		parent := filepath.Dir(devPath)
		pciAddr = pciAddrFromPath(parent)
	}
	if pciAddr == "" {
		return ""
	}
	return pciAddrToEnp(pciAddr)
}

// pciAddrFromPath extracts a PCI address (domain:bus:slot.fn) from a sysfs
// path basename. Returns "" if the basename is not a PCI address.
func pciAddrFromPath(path string) string {
	base := filepath.Base(path)
	// PCI addresses look like "0000:08:00.0"
	parts := strings.SplitN(base, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	// Validate slot.fn exists
	if !strings.Contains(parts[2], ".") {
		return ""
	}
	return base
}

// pciAddrToEnp converts a PCI address like "0000:08:00.0" to a predictable
// network name like "enp8s0".
func pciAddrToEnp(pciAddr string) string {
	parts := strings.SplitN(pciAddr, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	bus, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return ""
	}
	sf := strings.SplitN(parts[2], ".", 2)
	if len(sf) != 2 {
		return ""
	}
	slot, err := strconv.ParseUint(sf[0], 16, 16)
	if err != nil {
		return ""
	}
	fn, err := strconv.ParseUint(sf[1], 16, 8)
	if err != nil {
		return ""
	}
	if fn > 0 {
		return fmt.Sprintf("enp%ds%df%d", bus, slot, fn)
	}
	return fmt.Sprintf("enp%ds%d", bus, slot)
}

// renameRethMember finds an interface by its RETH virtual MAC and renames it
// to the expected config name. Returns the old kernel name if renamed, or "".
// The interface must be DOWN for the rename to succeed.
func renameRethMember(targetName string, expectedMAC net.HardwareAddr) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if !bytes.Equal(iface.HardwareAddr, expectedMAC) || iface.Name == targetName {
			continue
		}
		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			return ""
		}
		// Ensure interface is DOWN for rename.
		netlink.LinkSetDown(link)
		if err := netlink.LinkSetName(link, targetName); err != nil {
			slog.Warn("failed to rename RETH member",
				"from", iface.Name, "to", targetName, "err", err)
			return ""
		}
		return iface.Name
	}
	return ""
}

// programRethMAC sets a deterministic virtual MAC on a RETH member interface.
// Skips if the interface already has the correct MAC.
// The interface must be brought DOWN to change its MAC, then back UP.
func programRethMAC(ifName string, mac net.HardwareAddr) (linkCycled bool, err error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return false, fmt.Errorf("interface %s: %w", ifName, err)
	}
	current := link.Attrs().HardwareAddr
	if bytes.Equal(current, mac) {
		return false, nil
	}
	slog.Info("setting RETH virtual MAC", "iface", ifName, "mac", mac)
	// Try setting MAC while link is UP (avoids link DOWN/UP cycle).
	// mlx5 zero-copy AF_XDP sockets break on link cycle — the driver
	// doesn't reinitialize XSK WQEs after link UP. If the driver
	// supports IFF_LIVE_ADDR_CHANGE, this succeeds without any cycle.
	if err := netlink.LinkSetHardwareAddr(link, mac); err == nil {
		slog.Info("RETH MAC set without link cycle", "iface", ifName)
		return false, nil
	}
	// Fallback: bring link down, set MAC, bring back up.
	slog.Info("RETH MAC requires link cycle (driver does not support live change)",
		"iface", ifName)
	if err := netlink.LinkSetDown(link); err != nil {
		return false, fmt.Errorf("link down %s: %w", ifName, err)
	}
	if err := netlink.LinkSetHardwareAddr(link, mac); err != nil {
		netlink.LinkSetUp(link) // best-effort restore
		return false, fmt.Errorf("set mac %s: %w", ifName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return true, fmt.Errorf("link up %s: %w", ifName, err)
	}
	return true, nil
}

// clearDadFailed removes any dadfailed link-local IPv6 addresses and re-adds
// them with IFA_F_NODAD so they become usable. This handles the case where the
// virtual MAC was already set but accept_dad wasn't disabled at that time.
func clearDadFailed(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, addr := range addrs {
		if !addr.IP.IsLinkLocalUnicast() {
			continue
		}
		if addr.Flags&unix.IFA_F_DADFAILED == 0 {
			continue
		}
		// Remove the dadfailed address and re-add with NODAD.
		netlink.AddrDel(link, &addr)
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, &addr); err != nil {
			slog.Warn("failed to re-add link-local with NODAD", "iface", ifName, "err", err)
		} else {
			slog.Info("cleared dadfailed link-local", "iface", ifName, "addr", addr.IP)
		}
	}
}

// removeAutoLinkLocal removes the kernel auto-generated link-local IPv6 address
// from a RETH member interface. With addr_gen_mode=1 set, no new link-local will
// be created on link-up, but a stale one may remain from before the sysctl change.
func removeAutoLinkLocal(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			// Preserve stable router link-locals managed by addStableRethLinkLocal.
			if cluster.IsStableRethLinkLocal(addr.IP) {
				continue
			}
			if err := netlink.AddrDel(link, &addr); err == nil {
				slog.Info("removed auto link-local from RETH member", "iface", ifName, "addr", addr.IP)
			}
		}
	}
}

// ensureRethLinkLocal adds a link-local IPv6 address to a RETH member
// interface (or its VLAN sub-interface) if one is missing. RETH interfaces
// have addr_gen_mode=1 to suppress MLDv2 noise, but the kernel needs a
// link-local source address for NDP Neighbor Solicitations when forwarding
// IPv6 traffic to on-link destinations. Without this, bpf_fib_lookup returns
// NO_NEIGH and the kernel can never resolve the neighbor.
//
// Computes EUI-64 link-local from the interface MAC and adds it with NODAD.
func ensureRethLinkLocal(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	mac := link.Attrs().HardwareAddr
	if len(mac) != 6 {
		return
	}
	// Check if link-local already exists.
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, a := range addrs {
		if a.IP.IsLinkLocalUnicast() {
			return // already have one
		}
	}

	// Compute EUI-64 link-local from MAC.
	ll := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		slog.Warn("failed to add link-local to RETH interface",
			"iface", ifName, "addr", ll, "err", err)
	} else {
		slog.Info("added link-local for NDP on RETH interface",
			"iface", ifName, "addr", ll)
	}
}

// rethUnitHasConfiguredLinkLocal checks whether the RETH config has an
// explicitly configured link-local IPv6 address (fe80::/10) on the given unit.
func rethUnitHasConfiguredLinkLocal(rethCfg *config.InterfaceConfig, unitNum int) bool {
	unit, ok := rethCfg.Units[unitNum]
	if !ok {
		return false
	}
	for _, addr := range unit.Addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() && ip.To4() == nil {
			return true
		}
	}
	return false
}

// rethUnitHasIPv6 checks whether the RETH config has IPv6 addresses on the
// given unit number (VLAN ID). Unit 0 is the native/untagged interface.
func rethUnitHasIPv6(rethCfg *config.InterfaceConfig, unitNum int) bool {
	unit, ok := rethCfg.Units[unitNum]
	if !ok {
		return false
	}
	for _, addr := range unit.Addresses {
		if strings.Contains(addr, ":") {
			return true
		}
	}
	return unit.DHCPv6
}
