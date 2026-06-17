// Package daemon — #1956 bare-metal device-map resolver and mapped-rename.
//
// This file owns device-map MODE: when the active config carries a non-empty
// `chassis device-map`, the daemon renames ONLY the mapped NICs (by stable
// identity — PCI bus address with permanent-MAC fallback) instead of the
// positional enumerate-and-rename path, and leaves every other NIC alone
// (unmapped-interface-policy leave-alone, the bare-metal default).
//
// None of this is hot-path: it runs at daemon start and on bootstrap-exit.
package daemon

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// presentNIC is one live host NIC as seen at resolve time. Captured as plain
// data so the resolver core is unit-testable without sysfs/netlink.
type presentNIC struct {
	name       string // current kernel name (post-udev, pre-xpf-rename)
	pciAddr    string // PCI bus address ("" if none)
	permMAC    string // permanent/factory MAC ("" if unavailable)
	runningMAC string // current running MAC (diagnostic only)
}

// bindStatus classifies how a device-map entry resolved.
type bindStatus int

const (
	bindBound          bindStatus = iota // resolved cleanly to a present NIC
	bindBoundPCIOnly                     // PCI matched, no perm-MAC to cross-check
	bindBoundViaMAC                      // PCI missed, perm-MAC matched (PCI moved)
	bindUnbound                          // no present NIC matches the identity
	bindRefusedAmbig                     // PCI matched but perm-MAC mismatched (card swapped)
)

func (s bindStatus) String() string {
	switch s {
	case bindBound:
		return "bound"
	case bindBoundPCIOnly:
		return "bound (PCI-only, unverified — no permanent MAC)"
	case bindBoundViaMAC:
		return "bound (via MAC fallback — PCI moved, re-pin)"
	case bindUnbound:
		return "UNBOUND (no NIC at identity)"
	case bindRefusedAmbig:
		return "REFUSED (topology changed — card swapped at this PCI address)"
	default:
		return "unknown"
	}
}

// resolvedBinding is the outcome of resolving one device-map entry.
type resolvedBinding struct {
	entry      config.DeviceMapEntry
	logical    string     // Linux logical name (ge-0-0-3), "" if unbound/refused
	currentNIC string     // the NIC's CURRENT kernel name, "" if unbound/refused
	status     bindStatus
}

// resolveDeviceMap resolves every entry against the present NICs using each
// entry's key order, applying topology-change detection (PCI hit + perm-MAC
// mismatch => REFUSE, never silent hijack — R-1/AGY HIGH-3). It is pure: the
// caller supplies the NIC inventory. RETH members are restricted to PCI
// matching (their MAC alternates physical<->virtual — R-6); the schema/strict
// validator already rejects key mac on a RETH member, so here we simply skip
// the MAC leg for them as defense in depth.
func resolveDeviceMap(entries []config.DeviceMapEntry, nics []presentNIC, rethMembers map[string]bool) []resolvedBinding {
	byPCI := make(map[string]*presentNIC)
	byPermMAC := make(map[string][]*presentNIC)
	for i := range nics {
		n := &nics[i]
		if n.pciAddr != "" {
			byPCI[strings.ToLower(n.pciAddr)] = n
		}
		if n.permMAC != "" {
			lm := strings.ToLower(n.permMAC)
			byPermMAC[lm] = append(byPermMAC[lm], n)
		}
	}

	out := make([]resolvedBinding, 0, len(entries))
	for _, e := range entries {
		logical := config.LinuxIfName(e.LogicalName)
		isRETH := rethMembers[e.LogicalName]
		rb := resolvedBinding{entry: e, status: bindUnbound}

		allowMAC := e.MAC != "" && !isRETH
		allowPCI := e.PCIAddr != ""

		// Try keys in the entry's configured order.
		for _, key := range keySequence(e, allowPCI, allowMAC) {
			switch key {
			case config.DeviceMapKeyPCI:
				if nic, ok := byPCI[strings.ToLower(e.PCIAddr)]; ok {
					// PCI matched. Cross-check perm-MAC when both sides
					// have one.
					if e.MAC != "" && nic.permMAC != "" {
						if strings.EqualFold(nic.permMAC, e.MAC) {
							rb.status, rb.currentNIC, rb.logical = bindBound, nic.name, logical
						} else {
							// Card swapped into this slot — refuse (R-1).
							rb.status, rb.currentNIC, rb.logical = bindRefusedAmbig, "", ""
						}
					} else {
						// No perm-MAC to verify (common on VFs/virtio).
						rb.status, rb.currentNIC, rb.logical = bindBoundPCIOnly, nic.name, logical
					}
				}
			case config.DeviceMapKeyMAC:
				matches := byPermMAC[strings.ToLower(e.MAC)]
				if len(matches) == 1 {
					nic := matches[0]
					// If PCI was tried first and missed, this is a fallback.
					st := bindBound
					if allowPCI {
						st = bindBoundViaMAC
					}
					rb.status, rb.currentNIC, rb.logical = st, nic.name, logical
				} else if len(matches) > 1 {
					// Ambiguous MAC (cloned/bonded) — refuse.
					rb.status, rb.currentNIC, rb.logical = bindRefusedAmbig, "", ""
				}
			}
			// Stop on any decisive outcome (bound or refused). An unbound
			// result from one key falls through to the next key.
			if rb.status != bindUnbound {
				break
			}
		}
		out = append(out, rb)
	}
	return out
}

// keySequence returns the ordered list of identity keys to try for an entry,
// filtered by which keys are usable (allowPCI/allowMAC). RETH members and
// missing-key entries naturally drop the unusable leg.
func keySequence(e config.DeviceMapEntry, allowPCI, allowMAC bool) []string {
	var raw []string
	switch e.EffectiveKeyOrder() {
	case config.DeviceMapKeyPCI:
		raw = []string{config.DeviceMapKeyPCI}
	case config.DeviceMapKeyMAC:
		raw = []string{config.DeviceMapKeyMAC}
	case config.DeviceMapKeyMACThenPCI:
		raw = []string{config.DeviceMapKeyMAC, config.DeviceMapKeyPCI}
	default: // pci-then-mac
		raw = []string{config.DeviceMapKeyPCI, config.DeviceMapKeyMAC}
	}
	out := raw[:0:0]
	for _, k := range raw {
		if k == config.DeviceMapKeyPCI && !allowPCI {
			continue
		}
		if k == config.DeviceMapKeyMAC && !allowMAC {
			continue
		}
		out = append(out, k)
	}
	return out
}

// enumeratePresentNICs builds the present-NIC inventory from sysfs + netlink:
// current kernel name, PCI address, permanent (factory) MAC, running MAC.
func enumeratePresentNICs() ([]presentNIC, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var nics []presentNIC
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		devicePath := filepath.Join("/sys/class/net", name, "device")
		devReal, err := filepath.EvalSymlinks(devicePath)
		if err != nil {
			continue // not a PCI device
		}
		pci := extractPCIAddr(devReal)
		if pci == "" {
			continue
		}
		nic := presentNIC{name: name, pciAddr: pci}
		if link, err := netlink.LinkByName(name); err == nil {
			a := link.Attrs()
			nic.runningMAC = a.HardwareAddr.String()
			if len(a.PermHWAddr) != 0 {
				nic.permMAC = a.PermHWAddr.String()
			}
		}
		nics = append(nics, nic)
	}
	sort.Slice(nics, func(i, j int) bool { return nics[i].pciAddr < nics[j].pciAddr })
	return nics, nil
}

// rethMembersFromConfig returns the set of logical names that are RETH
// members in the active config (RedundantParent set). Used by the resolver to
// keep them on PCI matching and by .link generation to keep OriginalName=.
func rethMembersFromConfig(cfg *config.Config) map[string]bool {
	m := make(map[string]bool)
	if cfg == nil {
		return m
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			m[ifc.Name] = true
		}
	}
	return m
}

// enumerateAndRenameMapped is the device-map-mode replacement for
// enumerateAndRenameInterfaces. It renames ONLY mapped NICs to their bound
// logical names, writes .link files for ONLY those, scrubs stale xpf .link
// files for names no longer mapped, and (under leave-alone, the default)
// leaves every unmapped NIC entirely alone. It implements the collision-safe
// multi-pass rename (V-2) so a stale-udev misrename does not deadlock on
// EEXIST, and renames any temp-stranded unmapped NIC back to a host-
// predictable name in the SAME pass (OQ-15.3).
//
// It does NOT run the D3 RSS indirection (that is driven from the caller, as
// in the positional path) — the caller invokes applyStep0Tunables after.
func enumerateAndRenameMapped(dm *config.DeviceMapConfig, cfg *config.Config) error {
	if !dm.Active() {
		return nil
	}
	nics, err := enumeratePresentNICs()
	if err != nil {
		return fmt.Errorf("enumerate NICs: %w", err)
	}
	rethMembers := rethMembersFromConfig(cfg)
	bindings := resolveDeviceMap(dm.Entries, nics, rethMembers)

	// Desired final name -> the NIC currently holding the identity.
	desiredByCurrent := make(map[string]string) // currentName -> finalName
	desiredNames := make(map[string]bool)       // set of final logical names
	for _, b := range bindings {
		switch b.status {
		case bindBound, bindBoundPCIOnly, bindBoundViaMAC:
			desiredByCurrent[b.currentNIC] = b.logical
			desiredNames[b.logical] = true
			slog.Info("device-map: resolved binding",
				"logical", b.entry.LogicalName, "current", b.currentNIC, "status", b.status.String())
		case bindUnbound:
			slog.Warn("device-map: entry UNBOUND — no present NIC matches its identity; "+
				"logical name left unassigned",
				"logical", b.entry.LogicalName, "pci", b.entry.PCIAddr, "mac", b.entry.MAC)
		case bindRefusedAmbig:
			slog.Error("device-map: entry REFUSED — a different card is present at this identity "+
				"(topology changed). Refusing to bind to avoid hijacking the wrong NIC; re-pin "+
				"the device-map.",
				"logical", b.entry.LogicalName, "pci", b.entry.PCIAddr, "mac", b.entry.MAC)
		}
	}

	// Phase 1: break name collisions. Any present NIC whose CURRENT name
	// equals a desired final name, but which is NOT the NIC we want there,
	// is moved to a unique temp name first (V-2).
	tempStranded := make(map[string]presentNIC) // tempName -> original NIC info
	tmpIdx := 0
	for i := range nics {
		n := &nics[i]
		if !desiredNames[n.name] {
			continue
		}
		// Is this NIC the intended occupant of n.name?
		if final, ok := desiredByCurrent[n.name]; ok && final == n.name {
			continue // already correctly named, leave it
		}
		// A different NIC occupies a desired name (stale-udev misrename, or
		// the intended NIC is elsewhere). Move it out of the way.
		tmpName := fmt.Sprintf("xpf-tmp-%d", tmpIdx)
		tmpIdx++
		if err := renameInterface(n.name, tmpName); err != nil {
			slog.Warn("device-map: temp-rename to break collision failed",
				"from", n.name, "to", tmpName, "err", err)
			continue
		}
		slog.Info("device-map: temp-renamed conflicting interface", "from", n.name, "to", tmpName)
		stranded := *n
		// Update desiredByCurrent if THIS nic was itself a desired source.
		if final, ok := desiredByCurrent[n.name]; ok {
			delete(desiredByCurrent, n.name)
			desiredByCurrent[tmpName] = final
		} else {
			// Unmapped NIC that was wearing a desired name — strand it for
			// predictable-name restore in phase 3.
			tempStranded[tmpName] = stranded
		}
		n.name = tmpName
	}

	// Phase 2: rename each mapped NIC to its final logical name.
	changed := false
	for current, final := range desiredByCurrent {
		if current == final {
			// Ensure a .link exists for boot persistence even when the name
			// already matches (idempotent — writeDeviceMapLinkFile skips
			// unchanged files).
			if writeDeviceMapLinkFile(final, current, rethMembers, dm.Entries) {
				changed = true
			}
			continue
		}
		// Write the .link FIRST so next boot's udev is correct, then rename.
		original := deviceMapOriginalName(current, final)
		if writeDeviceMapLinkFile(final, original, rethMembers, dm.Entries) {
			changed = true
		}
		if err := renameInterface(current, final); err != nil {
			slog.Warn("device-map: rename failed", "from", current, "to", final, "err", err)
		} else {
			slog.Info("device-map: renamed interface", "from", current, "to", final)
			changed = true
		}
	}

	// Phase 3: any temp-stranded UNMAPPED NIC is renamed back to a
	// host-predictable name (OQ-15.3) so it is never left as xpf-tmp-* and
	// never re-matched as "managed".
	for tmp, nic := range tempStranded {
		predictable := predictableName(nic)
		if predictable == "" || predictable == tmp {
			slog.Warn("device-map: could not determine a predictable name for a stranded NIC; "+
				"leaving it under its temp name (xpf does not manage it)",
				"temp", tmp, "pci", nic.pciAddr)
			continue
		}
		if err := renameInterface(tmp, predictable); err != nil {
			slog.Warn("device-map: restore stranded NIC to predictable name failed",
				"from", tmp, "to", predictable, "err", err)
		} else {
			slog.Info("device-map: restored unmapped NIC to predictable name",
				"from", tmp, "to", predictable)
			changed = true
		}
	}

	// Phase 4: scrub stale xpf .link files whose target name is no longer a
	// desired binding (a NIC dropped from the map). This keeps next boot's
	// udev rule set exactly equal to the resolved bindings (R-2).
	if scrubStaleDeviceMapLinks(desiredNames) {
		changed = true
	}

	// fxp0 bootstrap DHCP .network is NOT auto-created in device-map mode
	// (§9.6: console is the lifeline; no fabricated fxp0). It is written
	// only if the operator explicitly mapped a NIC to fxp0.
	if desiredNames["fxp0"] {
		if writeBootstrapFxp0Network() {
			changed = true
		}
	}

	if changed {
		if err := networkctlReload(); err != nil {
			slog.Warn("device-map: networkctl reload failed", "err", err)
		}
		slog.Info("device-map: interface naming updated")
	} else {
		slog.Info("device-map: interface naming unchanged")
	}
	return nil
}

// deviceMapOriginalName returns the OriginalName= value to record for a
// mapped NIC's .link file. We record the pre-rename kernel name (recovering
// through any existing .link chain so a re-run is idempotent).
func deviceMapOriginalName(current, final string) string {
	// If `current` is already an xpf temp/logical name, recover the true
	// original via the existing .link chain.
	if rec := recoverOriginalName(current); rec != "" && rec != current {
		return rec
	}
	return current
}

// writeDeviceMapLinkFile writes the .link for a mapped NIC. RETH members
// match by OriginalName= (their MAC alternates — R-6); the file content is
// identical to the positional path's writeLinkFile, so the two share a format.
// Returns true if the file changed.
func writeDeviceMapLinkFile(target, originalName string, rethMembers map[string]bool, entries []config.DeviceMapEntry) bool {
	// All device-map .link files match by OriginalName= (the current kernel
	// name at rename time). This is correct for RETH members (mandatory) and
	// is also stable for plain NICs because device-map mode resolves the
	// identity to the kernel name at rename time and rewrites the .link set
	// every boot (scrub-then-rewrite, R-2). Keeping one match discipline
	// avoids the MAC-vs-OriginalName drift the positional path carries.
	return writeLinkFile(target, originalName)
}

// predictableNameLookup is the udev predictable-name resolver, injectable
// for tests (the real one shells out to `udevadm`, unavailable in the unit
// sandbox). It maps a present NIC (currently wearing a temp name) to the
// host's own predictable name. Empty result => caller leaves it under the
// temp name (never guesses a name that could collide — V-6).
var predictableNameLookup = udevPredictableName

// predictableName resolves the host-predictable name for a stranded NIC via
// the udev database, using the PUBLIC `udevadm info` interface rather than
// parsing /run/udev/data directly (Codex r3 MEDIUM — that couples to internal
// systemd storage layout). It prefers the most stable of ONBOARD > SLOT >
// PATH, mirroring systemd's own net-naming priority.
func predictableName(nic presentNIC) string {
	return predictableNameLookup(nic)
}

func udevPredictableName(nic presentNIC) string {
	// Query by the temp name's sysfs node — the kernel name has changed but
	// the device node and its ID_NET_NAME_* properties have not.
	out, err := execCommand("udevadm", "info", "--query=property",
		"--path=/sys/class/net/"+nic.name)
	if err != nil {
		return ""
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			props[k] = v
		}
	}
	for _, key := range []string{"ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH"} {
		if v := props[key]; v != "" {
			return v
		}
	}
	return ""
}

// scrubStaleDeviceMapLinks removes 10-xpf-*.link files whose target name is
// not in the desired set, so a NIC dropped from the device-map does not keep
// a stale udev rename rule (R-2). The bootstrap .network and any non-.link
// file are left untouched. Returns true if anything was removed.
func scrubStaleDeviceMapLinks(desiredNames map[string]bool) bool {
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return false
	}
	removed := false
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, linkPrefix) || !strings.HasSuffix(name, ".link") {
			continue
		}
		target := strings.TrimSuffix(strings.TrimPrefix(name, linkPrefix), ".link")
		if desiredNames[target] {
			continue
		}
		if err := os.Remove(filepath.Join(linkDir, name)); err == nil {
			removed = true
			slog.Info("device-map: removed stale .link for unmapped name", "file", name, "target", target)
		}
	}
	return removed
}
