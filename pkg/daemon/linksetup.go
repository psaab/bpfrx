// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
)

const (
	linkDir    = "/etc/systemd/network"
	linkPrefix = "10-bpfrx-"
)

// pciNIC holds enumeration data for one physical NIC.
type pciNIC struct {
	sortKey int    // 0 = virtio, 1 = hardware
	busAddr string // PCI bus address (e.g. "0000:05:00.0")
	name    string // current kernel name (e.g. "enp5s0")
}

// enumerateAndRenameInterfaces assigns vSRX-style names to all PCI NICs.
//
// Standalone (clusterMode=false):
//
//	idx 0 → fxp0, idx 1+ → ge-0-0-{idx-1}
//
// Cluster (clusterMode=true):
//
//	idx 0 → fxp0, idx 1 → em0, idx 2+ → ge-{FPC}-0-{idx-2}
//	FPC = 0 for node 0, FPC = 7 for node 1
func enumerateAndRenameInterfaces(nodeID int, clusterMode bool) error {
	nics, err := enumeratePCINICs()
	if err != nil {
		return fmt.Errorf("enumerate NICs: %w", err)
	}
	if len(nics) == 0 {
		slog.Info("linksetup: no PCI network interfaces found")
		return nil
	}

	fpc := 0
	if clusterMode && nodeID == 1 {
		fpc = 7
	}

	changed := false
	for idx, nic := range nics {
		target := assignName(idx, fpc, clusterMode)

		// Determine original kernel name — if the interface was already
		// renamed in a previous run, recover OriginalName from the
		// existing .link file.
		original := recoverOriginalName(nic.name)

		// Write .link file with OriginalName= for boot persistence.
		if wrote := writeLinkFile(target, original); wrote {
			changed = true
		}

		// Rename immediately if current name doesn't match target.
		if nic.name != target {
			if err := renameInterface(nic.name, target); err != nil {
				slog.Warn("linksetup: rename failed",
					"from", nic.name, "to", target, "err", err)
			} else {
				slog.Info("linksetup: renamed interface",
					"from", nic.name, "to", target)
				changed = true
			}
		}
	}

	// Ensure fxp0 has a bootstrap DHCP .network file (needed before
	// the daemon writes its own networkd configs).
	if wrote := writeBootstrapFxp0Network(); wrote {
		changed = true
	}

	if changed {
		if err := networkctlReload(); err != nil {
			slog.Warn("linksetup: networkctl reload failed", "err", err)
		}
		slog.Info("linksetup: interface naming updated")
	} else {
		slog.Info("linksetup: interface naming unchanged")
	}
	return nil
}

// enumeratePCINICs discovers all PCI network interfaces via sysfs, sorted
// by driver type (virtio first) then PCI bus address.
func enumeratePCINICs() ([]pciNIC, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}

	var nics []pciNIC
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}

		devicePath := filepath.Join("/sys/class/net", name, "device")
		if _, err := os.Stat(devicePath); err != nil {
			continue // not a PCI device
		}

		// Read driver name.
		driverLink, err := os.Readlink(filepath.Join(devicePath, "driver"))
		if err != nil {
			continue
		}
		driver := filepath.Base(driverLink)

		// Extract PCI bus address from the device symlink target.
		devReal, err := filepath.EvalSymlinks(devicePath)
		if err != nil {
			continue
		}
		busAddr := extractPCIAddr(devReal)
		if busAddr == "" {
			continue
		}

		sk := 1 // hardware
		if driver == "virtio_net" {
			sk = 0
		}
		nics = append(nics, pciNIC{sortKey: sk, busAddr: busAddr, name: name})
	}

	// Sort: virtio first, then by PCI bus address (lexicographic on
	// bus address is equivalent to numeric for same-width addresses).
	sort.Slice(nics, func(i, j int) bool {
		if nics[i].sortKey != nics[j].sortKey {
			return nics[i].sortKey < nics[j].sortKey
		}
		return nics[i].busAddr < nics[j].busAddr
	})

	return nics, nil
}

// extractPCIAddr extracts the last PCI address (DDDD:BB:DD.F) from a sysfs path.
func extractPCIAddr(path string) string {
	// Walk path components and find the last one matching PCI format.
	parts := strings.Split(path, "/")
	var last string
	for _, p := range parts {
		if len(p) >= 10 && p[4] == ':' && p[7] == ':' && p[10] == '.' {
			last = p
		}
	}
	return last
}

// assignName returns the vSRX target name for a given enumeration index.
func assignName(idx, fpc int, clusterMode bool) string {
	if idx == 0 {
		return "fxp0"
	}
	if clusterMode {
		if idx == 1 {
			return "em0"
		}
		return fmt.Sprintf("ge-%d-0-%d", fpc, idx-2)
	}
	return fmt.Sprintf("ge-0-0-%d", idx-1)
}

// recoverOriginalName returns the OriginalName from an existing .link file
// if the interface was previously renamed, otherwise returns the current name.
func recoverOriginalName(currentName string) string {
	// Search existing .link files for one that renames TO this name.
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return currentName
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), linkPrefix) || !strings.HasSuffix(e.Name(), ".link") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(linkDir, e.Name()))
		if err != nil {
			continue
		}
		content := string(data)
		// Check if this .link file has Name=<currentName>.
		if !containsLine(content, "Name="+currentName) {
			continue
		}
		// Extract OriginalName= value.
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "OriginalName=") {
				orig := strings.TrimPrefix(line, "OriginalName=")
				if orig != "" {
					return orig
				}
			}
		}
	}
	return currentName
}

// containsLine checks if the text contains an exact line matching s.
func containsLine(text, s string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == s {
			return true
		}
	}
	return false
}

// writeLinkFile writes a systemd .link file for the given target name.
// Returns true if the file was created or changed.
func writeLinkFile(target, originalName string) bool {
	path := filepath.Join(linkDir, linkPrefix+target+".link")
	content := fmt.Sprintf(`# Managed by bpfrxd — do not edit
[Match]
OriginalName=%s

[Link]
Name=%s`, originalName, target)

	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return false // unchanged
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		slog.Warn("linksetup: failed to write .link file",
			"path", path, "err", err)
		return false
	}
	slog.Info("linksetup: wrote .link file",
		"original", originalName, "target", target)
	return true
}

// writeBootstrapFxp0Network writes a bootstrap DHCP .network file for fxp0
// if one doesn't already exist (needed during provisioning before the daemon
// writes its own networkd configs).
func writeBootstrapFxp0Network() bool {
	path := filepath.Join(linkDir, linkPrefix+"fxp0.network")
	if _, err := os.Stat(path); err == nil {
		return false // already exists
	}

	content := `# Managed by bpfrxd — bootstrap DHCP for provisioning
[Match]
Name=fxp0

[Network]
DHCP=yes

[DHCPv4]
UseDNS=yes
UseRoutes=yes`

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		slog.Warn("linksetup: failed to write fxp0 .network file",
			"path", path, "err", err)
		return false
	}
	slog.Info("linksetup: created fxp0 DHCP .network file")
	return true
}

// renameInterface brings the interface down, renames it, and brings it back up.
func renameInterface(oldName, newName string) error {
	link, err := netlink.LinkByName(oldName)
	if err != nil {
		return fmt.Errorf("link %s not found: %w", oldName, err)
	}

	if err := netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("link down %s: %w", oldName, err)
	}

	if err := netlink.LinkSetName(link, newName); err != nil {
		// Bring back up on rename failure.
		_ = netlink.LinkSetUp(link)
		return fmt.Errorf("rename %s -> %s: %w", oldName, newName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up %s: %w", newName, err)
	}

	return nil
}

// networkctlReload calls networkctl reload to apply .link/.network changes.
func networkctlReload() error {
	out, err := execCommand("networkctl", "reload")
	if err != nil {
		return fmt.Errorf("networkctl reload: %w (output: %s)", err, out)
	}
	return nil
}

// execCommand runs a command and returns combined output.
func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
