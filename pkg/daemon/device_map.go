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
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/devicemap"
	"github.com/vishvananda/netlink"
)

// The pure identity resolver, present-NIC model, and host enumeration live in
// pkg/devicemap so the daemon (rename + pre-flight) and the CLI
// (`show chassis device-map`) share ONE resolution discipline. The daemon
// keeps only the rename / teardown / pre-flight glue below.

// presentNIC is the daemon-local alias for the shared inventory type.
type presentNIC = devicemap.PresentNIC

// enumeratePresentNICs reads the live host NIC inventory (sysfs + netlink).
func enumeratePresentNICs() ([]presentNIC, error) {
	return devicemap.EnumeratePresentNICs()
}

// resolveDeviceMap resolves entries against present NICs (see devicemap.Resolve).
func resolveDeviceMap(entries []config.DeviceMapEntry, nics []presentNIC, rethMembers map[string]bool) []devicemap.Binding {
	return devicemap.Resolve(entries, nics, rethMembers)
}

// rethMembersFromConfig returns the RETH-member logical-name set.
func rethMembersFromConfig(cfg *config.Config) map[string]bool {
	return devicemap.RethMembersFromConfig(cfg)
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
	// originalByCurrent records the TRUE pre-rename kernel name for each
	// bound NIC, captured BEFORE any temp rename, so the .link OriginalName=
	// is the real udev-matchable name (a transient xpf-tmp-* name must never
	// be recorded as OriginalName — it would not match on next boot).
	originalByCurrent := make(map[string]string) // currentName -> OriginalName
	for _, b := range bindings {
		switch {
		case b.Status.Bound():
			desiredByCurrent[b.CurrentNIC] = b.Logical
			originalByCurrent[b.CurrentNIC] = recoverOriginalName(b.CurrentNIC)
			desiredNames[b.Logical] = true
			slog.Info("device-map: resolved binding",
				"logical", b.Entry.LogicalName, "current", b.CurrentNIC, "status", b.Status.String())
		case b.Status == devicemap.BindUnbound:
			slog.Warn("device-map: entry UNBOUND — no present NIC matches its identity; "+
				"logical name left unassigned",
				"logical", b.Entry.LogicalName, "pci", b.Entry.PCIAddr, "mac", b.Entry.MAC)
		case b.Status == devicemap.BindRefusedAmbig:
			slog.Error("device-map: entry REFUSED — a different card is present at this identity "+
				"(topology changed). Refusing to bind to avoid hijacking the wrong NIC; re-pin "+
				"the device-map.",
				"logical", b.Entry.LogicalName, "pci", b.Entry.PCIAddr, "mac", b.Entry.MAC)
		}
	}

	// Phase 1: break name collisions. Any present NIC whose CURRENT name
	// equals a desired final name, but which is NOT the NIC we want there,
	// is moved to a unique temp name first (V-2).
	tempStranded := make(map[string]presentNIC) // tempName -> original NIC info
	// Track names currently in use (present NICs) so a leftover xpf-tmp-N
	// from a prior crashed run does not cause an EEXIST temp-rename (AGY
	// MEDIUM-3). freeTempName picks the first unused xpf-tmp-N.
	inUse := make(map[string]bool, len(nics))
	for i := range nics {
		inUse[nics[i].Name] = true
	}
	freeTempName := func() string {
		for k := 0; ; k++ {
			cand := fmt.Sprintf("xpf-tmp-%d", k)
			if !inUse[cand] {
				inUse[cand] = true
				return cand
			}
		}
	}
	for i := range nics {
		n := &nics[i]
		if !desiredNames[n.Name] {
			continue
		}
		// Is this NIC the intended occupant of n.Name?
		if final, ok := desiredByCurrent[n.Name]; ok && final == n.Name {
			continue // already correctly named, leave it
		}
		// A different NIC occupies a desired name (stale-udev misrename, or
		// the intended NIC is elsewhere). Move it out of the way.
		tmpName := freeTempName()
		if err := renameInterface(n.Name, tmpName); err != nil {
			slog.Warn("device-map: temp-rename to break collision failed",
				"from", n.Name, "to", tmpName, "err", err)
			continue
		}
		slog.Info("device-map: temp-renamed conflicting interface", "from", n.Name, "to", tmpName)
		stranded := *n
		// Update desiredByCurrent if THIS nic was itself a desired source.
		if final, ok := desiredByCurrent[n.Name]; ok {
			delete(desiredByCurrent, n.Name)
			desiredByCurrent[tmpName] = final
			// Carry the TRUE original name across the temp rename so phase 2
			// writes the correct OriginalName= (not xpf-tmp-N).
			if orig, ok := originalByCurrent[n.Name]; ok {
				delete(originalByCurrent, n.Name)
				originalByCurrent[tmpName] = orig
			}
		} else {
			// Unmapped NIC that was wearing a desired name — strand it for
			// predictable-name restore in phase 3.
			tempStranded[tmpName] = stranded
		}
		n.Name = tmpName
	}

	// Phase 2: rename each mapped NIC to its final logical name.
	changed := false
	for current, final := range desiredByCurrent {
		// The OriginalName= is the TRUE pre-rename kernel name captured
		// before any temp rename; fall back to recovering it if absent.
		original := originalByCurrent[current]
		if original == "" {
			original = recoverOriginalName(current)
		}
		if current == final {
			// Ensure a .link exists for boot persistence even when the name
			// already matches (idempotent — writeDeviceMapLinkFile skips
			// unchanged files).
			if writeDeviceMapLinkFile(final, original, rethMembers, dm.Entries) {
				changed = true
			}
			continue
		}
		// Write the .link FIRST so next boot's udev is correct, then rename.
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
				"temp", tmp, "pci", nic.PCIAddr)
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

// deviceMapStrandsManagement reports whether applying cfg's device-map would,
// on next boot, leave the #1922 management/lifeline NIC unbound or rebound to
// a different port — i.e. strand the operator. It resolves the LOCAL node's
// device-map against the present hardware (nics) and checks the protected set
// (lifeline record + management leaf). Returns a non-empty reason when it
// would strand, "" when safe. A nil/empty device-map is always safe (the
// #1922 protected set is the independent backstop; positional mode is
// unchanged). Pure given the NIC inventory + protected set, so it is unit
// testable.
func deviceMapStrandsManagement(cfg *config.Config, nics []presentNIC, protected map[string]bool) string {
	if cfg == nil {
		return ""
	}
	dm := cfg.Chassis.DeviceMap
	if !dm.Active() {
		// Positional mode: the protected set shields management; never
		// stranded by a device-map (there is none).
		return ""
	}
	bindings := resolveDeviceMap(dm.Entries, nics, rethMembersFromConfig(cfg))

	// Map current kernel name -> its resolved final logical name.
	finalByCurrent := make(map[string]string)
	for _, b := range bindings {
		// A REFUSED binding on ANY entry is a hard stop: a card was swapped
		// at a pinned slot, so the operator's intent no longer matches the
		// hardware — refuse the commit while they are still connected.
		if b.Status == devicemap.BindRefusedAmbig {
			return fmt.Sprintf("device-map entry %q refuses to bind: a different card is present "+
				"at its pinned identity (topology changed). Re-pin the entry before committing.",
				b.Entry.LogicalName)
		}
		if b.CurrentNIC != "" {
			finalByCurrent[b.CurrentNIC] = b.Logical
		}
	}

	// For each protected (management/lifeline) NIC currently present: if it
	// would be renamed to a logical name by this map, that is fine (the
	// operator deliberately mapped it). The dangerous case is a protected
	// NIC that is NOT mapped while unmapped-policy is manage-down — but the
	// protected set is config-independent and the reconcile already exempts
	// it, so it is never downed. The genuine lockout we CAN detect here is a
	// device-map that maps the mgmt NIC's logical name to a DIFFERENT
	// physical NIC than the one currently carrying management (a port swap).
	for prot := range protected {
		if prot == "" {
			continue
		}
		// Is `prot` currently a present NIC (the live mgmt NIC)?
		liveMgmtPresent := false
		for i := range nics {
			if nics[i].Name == prot {
				liveMgmtPresent = true
				break
			}
		}
		if !liveMgmtPresent {
			continue // protected name not currently a present NIC
		}
		// Case A: the live mgmt NIC itself is mapped to a DIFFERENT name —
		// management moves off it on next boot.
		if final, ok := finalByCurrent[prot]; ok && final != prot {
			return fmt.Sprintf("device-map would rename the live management NIC %q to %q on next "+
				"boot, moving management off it. Map the management NIC to its own name, or "+
				"adjust the map before committing.", prot, final)
		}
		// Case B: some OTHER NIC is mapped to the protected name and the live
		// mgmt NIC is NOT itself mapped to keep that name — a collision that
		// would steal the management name from the live NIC on next boot.
		for current, final := range finalByCurrent {
			if final == prot && current != prot {
				return fmt.Sprintf("device-map would rename NIC %q to the management name %q on "+
					"next boot, taking it from the live management NIC. Re-pin the device-map "+
					"before committing.", current, prot)
			}
		}
	}
	return ""
}

// deviceMapCommitPreflight is the #1956 R-8/V-3 node-local commit pre-flight.
// It resolves the candidate's LOCAL device-map (and, for commit-confirmed,
// the rollback target) against present hardware and rejects a commit that
// would strand management on next boot — converting a latent reboot-time
// lockout into a commit-time error while the operator is still connected.
// rollbackTarget is the config that would be restored on a confirmed-commit
// timeout (the currently-active config); pass nil for a plain commit.
func (d *Daemon) deviceMapCommitPreflight(candidate, rollbackTarget *config.Config) error {
	// Fast path: neither config engages device-map mode — nothing to check.
	candActive := candidate != nil && candidate.Chassis.DeviceMap.Active()
	rbActive := rollbackTarget != nil && rollbackTarget.Chassis.DeviceMap.Active()
	if !candActive && !rbActive {
		return nil
	}
	nics, err := enumeratePresentNICs()
	if err != nil {
		// Cannot enumerate hardware — do not block the commit on a
		// transient sysfs error; the #1922 lifeline is the backstop.
		slog.Warn("device-map pre-flight: NIC enumeration failed; skipping (lifeline still protects mgmt)", "err", err)
		return nil
	}
	// AGY HIGH-2: resolve the protected set from EACH config's OWN
	// management-interface leaf (not the active config's), so a commit that
	// repoints `system management-interface` is validated against the
	// intent it is establishing — neither a silent lockout (using the stale
	// active leaf) nor a false rejection of a legitimate mgmt migration. The
	// lifeline record stays config-independent in both.
	if reason := deviceMapStrandsManagement(candidate, nics, protectedForConfig(candidate)); reason != "" {
		return fmt.Errorf("device-map commit rejected: %s", reason)
	}
	// V-3(a): validate the rollback target too, so a confirmed-commit
	// timeout reverts to a KNOWN-safe config and can be applied
	// unconditionally (OQ-15.2 — no rollback-time abort, no split-brain).
	if rollbackTarget != nil {
		if reason := deviceMapStrandsManagement(rollbackTarget, nics, protectedForConfig(rollbackTarget)); reason != "" {
			return fmt.Errorf("commit confirmed rejected: the rollback target (current active "+
				"config, restored on timeout) would strand management: %s", reason)
		}
	}
	return nil
}

// protectedForConfig resolves the #1922 protected set using the SPECIFIC
// config's management-interface leaf (plus the config-independent lifeline
// record), rather than the currently-active config. The pre-flight uses this
// so a commit that repoints `system management-interface` is validated
// against the mgmt NIC it is ESTABLISHING.
func protectedForConfig(cfg *config.Config) map[string]bool {
	mgmtLeaf := ""
	if cfg != nil {
		mgmtLeaf = cfg.System.ManagementInterface
	}
	return protectedInterfaces(mgmtLeaf)
}

// teardownUnmappedManaged is the #1956 V-4 managed->unmapped teardown,
// ordered to run BEFORE networkd.Apply on the live apply path. It is the
// single authority for the leave-alone transition: a NIC that xpf PREVIOUSLY
// managed (has a 10-xpf-<name>.link on disk) but whose name is no longer a
// desired binding is renamed back to its host-predictable name and its xpf
// .link/.network removed — so by the time networkd.Apply's stale-file sweep
// runs, that interface is already absent from BOTH the desired set and the
// on-disk xpf set and Apply has nothing to half-clean (which would otherwise
// un-rename it).
//
// The "previously managed" source of truth is the 10-xpf-*.link glob (the
// durable record of what xpf renamed), NOT the now-absent config. It runs
// only in device-map mode with leave-alone; manage-down keeps today's
// claim-all teardown via the compiler reconcile. It is no-op idempotent:
// when nothing transitioned, it touches nothing (operator priority #1 —
// zero churn on an unrelated commit).
func teardownUnmappedManaged(dm *config.DeviceMapConfig) {
	if !dm.Active() || dm.EffectiveUnmappedPolicy() != config.DeviceMapPolicyLeaveAlone {
		return
	}
	desiredNames := make(map[string]bool)
	for _, e := range dm.Entries {
		desiredNames[config.LinuxIfName(e.LogicalName)] = true
	}

	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return
	}
	reloaded := false
	for _, fe := range entries {
		fname := fe.Name()
		if !strings.HasPrefix(fname, linkPrefix) || !strings.HasSuffix(fname, ".link") {
			continue
		}
		target := strings.TrimSuffix(strings.TrimPrefix(fname, linkPrefix), ".link")
		if desiredNames[target] {
			continue // still managed — leave it
		}
		// A previously-managed NIC is no longer mapped. Find the live device
		// currently wearing this xpf name and restore it.
		if link, err := netlink.LinkByName(target); err == nil {
			nic := presentNIC{Name: target}
			if devReal, err := filepath.EvalSymlinks(
				filepath.Join("/sys/class/net", target, "device")); err == nil {
				nic.PCIAddr = devicemap.ExtractPCIAddr(devReal)
			}
			predictable := predictableName(nic)
			if predictable != "" && predictable != target {
				if err := renameInterface(target, predictable); err == nil {
					slog.Info("device-map teardown: restored unmapped NIC to predictable name",
						"from", target, "to", predictable)
					reloaded = true
				} else {
					slog.Warn("device-map teardown: rename-back failed; leaving device under xpf "+
						"name but dropping management", "name", target, "err", err)
				}
			} else {
				slog.Warn("device-map teardown: no predictable name for unmapped NIC; dropping "+
					"xpf management without renaming", "name", target)
			}
			_ = link
		}
		// Remove the stale .link and any matching .network regardless of the
		// rename outcome — xpf stops managing this NIC.
		if err := os.Remove(filepath.Join(linkDir, fname)); err == nil {
			reloaded = true
			slog.Info("device-map teardown: removed stale .link", "file", fname)
		}
		netFile := linkPrefix + target + ".network"
		if err := os.Remove(filepath.Join(linkDir, netFile)); err == nil {
			reloaded = true
			slog.Info("device-map teardown: removed stale .network", "file", netFile)
		}
	}
	if reloaded {
		if err := networkctlReload(); err != nil {
			slog.Warn("device-map teardown: networkctl reload failed", "err", err)
		}
	}
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
		"--path=/sys/class/net/"+nic.Name)
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
