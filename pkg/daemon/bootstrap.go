// Package daemon — #1922 SAFE-BOOTSTRAP daemon state (M1b Items 2-4).
//
// This file owns the explicit bootstrap mode, the five-case boot predicate,
// the PCI-keyed management lifeline record, and the protected-set resolution
// that keeps the daemon from ever locking an operator out of a remote box it
// manages. None of this is hot-path: it runs at startup and on the Item-1b
// first-commit rollback only.
package daemon

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

// lifelineRecordFile persists the management-NIC identity (PCI bus address +
// MAC) so the protected set (Item 4) survives the rename that turns the
// recorded kernel name (enp5s0) into fxp0, AND survives daemon restarts and
// rollback-to-bootstrap. Keyed by PCI address, NOT name (a name-keyed record
// goes stale the instant the rename runs — AGY #1879 r2 Critical).
const lifelineRecordFile = "/etc/xpf/lifeline-interface"

// defaultMgmtInterface is the conventional management interface name. It is
// always a member of the protected set unless an explicit non-fxp0
// `system management-interface` leaf narrows it off (Item 4 / OQ-D escape
// valve).
const defaultMgmtInterface = "fxp0"

// bootClass is the result of the #1922 five-case boot predicate. Each value
// maps to exactly one of {bootstrap, normal, fail-safe}.
type bootClass int

const (
	// bootClassNormal — a valid active config exists (case 2 day-0/preseeded
	// import, case 3 valid active.json) OR the operator committed an empty
	// config (case 5 committed-empty). Full takeover; zero behavior change
	// from pre-#1922.
	bootClassNormal bootClass = iota
	// bootClassBootstrap — fresh/no config (case 1) or never-committed
	// (case 5 never-committed, incl. the post-first-commit-rollback state).
	// No NIC rename beyond the lifeline path, no link cycles, no networkd
	// takeover, no dataplane arm, no FRR managed-section, no boot-time apply.
	bootClassBootstrap
	// bootClassFailSafe — corrupt/too-new active.json (case 4). #1917 D1
	// makes this fatal BEFORE this predicate is consulted; it is represented
	// here only for completeness and the predicate never returns it on a
	// reachable path (Load already returned ErrConfigDBUnreadable and Run
	// exited fatally).
	bootClassFailSafe
)

func (c bootClass) String() string {
	switch c {
	case bootClassNormal:
		return "normal"
	case bootClassBootstrap:
		return "bootstrap"
	case bootClassFailSafe:
		return "fail-safe"
	default:
		return "unknown"
	}
}

// hasNodeIDFile reports whether the install-time-stable HA signal
// (/etc/xpf/node-id) is present. The cluster short-circuit (C2/C8) keys on
// this FILE, NOT on the config-derived clusterMode (which is false until a
// cluster config loads and so cannot pre-empt the predicate).
func hasNodeIDFile() bool {
	_, err := os.Stat(nodeIDFile)
	return err == nil
}

// computeBootClass implements the #1922 five-case boot predicate. It is
// computed ONCE at startup (after Store.Load + bootstrapFromFile have
// resolved) and again on rollback-to-bootstrap. It is deterministic and
// stable across restarts given the same on-disk state.
//
// Inputs (all already resolved by the caller in daemon_run.go):
//   - hasActiveConfig: store.ActiveConfig() != nil — a compiled config is
//     loaded (case 2 import-clean or case 3 valid-active.json).
//   - everCommitted: store.EverCommitted() — the #1922 step-0 marker.
//   - nodeID: /etc/xpf/node-id presence (the HA-node guard, C2/C8).
//
// Case 4 (corrupt/too-new) is handled by #1917 D1 fatal-on-parse in Run
// BEFORE this is called, so it never reaches here.
func computeBootClass(hasActiveConfig, everCommitted, nodeIDPresent bool) bootClass {
	// HA-node guard (C2 + C8): a node with /etc/xpf/node-id is HA-managed.
	// It resolves NOT-bootstrap via its own DB/xpf.conf (case 2/3). If it
	// has node-id but NEITHER a DB nor an importable xpf.conf, it is
	// fail-safe-with-loud-error and HA availability is NOT promised — but it
	// still must not enter bootstrap mode (which would refuse takeover and
	// silently break HA on a normal deploy). The loud-error logging happens
	// at the call site; here we resolve it to normal so takeover proceeds
	// (an HA node with no config does nothing harmful — empty config, the
	// protected set still shields mgmt).
	if nodeIDPresent {
		return bootClassNormal
	}

	// The step-0 marker (everCommitted) is checked BEFORE hasActiveConfig.
	// This is load-bearing (AGY r1 CRITICAL): after an Item-1b first-commit
	// rollback the DB holds an EMPTY tree with committed=0. On the next
	// restart Store.Load compiles that empty tree into a NON-nil
	// *config.Config, so hasActiveConfig is TRUE even though the box was
	// never successfully committed. Checking hasActiveConfig first would
	// then misclassify the rolled-back box as normal and take over
	// interfaces on an empty config — exactly the lockout this issue closes.
	//
	//   - everCommitted == false → fresh/no-config (case 1) OR
	//     never-committed incl. post-first-commit-rollback (case 5) →
	//     bootstrap.
	//   - everCommitted == true  → a real commit/sync happened, OR a
	//     legacy/older-build DB (migration rule C3 defaults committed=true),
	//     OR operator-committed-empty (case 5 committed-empty) → normal
	//     (cases 2/3, and the operator-meant-it empty case; the protected
	//     set still shields mgmt). hasActiveConfig is implied here for
	//     cases 2/3 and not required for the decision, but is retained in
	//     the signature for the call-site log/HA-guard diagnostics.
	if !everCommitted {
		return bootClassBootstrap
	}
	_ = hasActiveConfig
	return bootClassNormal
}

// inBootstrap reports whether the daemon is currently in bootstrap mode.
// Read from many goroutines (gate checks, commit gate); written once at
// startup and at most once more on rollback-to-bootstrap, so an atomic is
// sufficient and avoids taking a lock on every gate check.
func (d *Daemon) inBootstrap() bool {
	return d.bootstrapMode.Load()
}

// exitBootstrapMode clears bootstrap mode (one-way for the daemon's
// lifetime). Called when the FIRST non-empty config is applied to the store
// — a local confirmed commit (Item 1 / the 4-gate) OR a cluster SyncApply
// from the primary (C2 belt-and-suspenders). The caller is responsible for
// running the full normal reconcile (rename, networkd, dataplane, FRR) after
// this returns; exitBootstrapMode only flips the flag.
func (d *Daemon) exitBootstrapMode(reason string) {
	if d.bootstrapMode.CompareAndSwap(true, false) {
		slog.Info("exiting bootstrap mode; full interface/dataplane takeover will proceed",
			"reason", reason)
	}
}

// enterBootstrapMode rolls the daemon back to bootstrap mode after a failed
// first takeover (#1922 Item 1b / the enterBootstrapMode cleanup sequence).
// A normal applyConfig(empty) is WRONG — the userspace apply path ensures
// the helper exists, i.e. it would resurrect the dataplane bootstrap promises
// not to run. Instead this performs explicit cleanup, in order:
//
//  1. set bootstrap mode (re-suppress takeover for the daemon's lifetime),
//  2. remove xpf-written takeover .network/.link files EXCEPT the lifeline
//     fxp0 .network and the .link files, then networkctl reload,
//  3. clear the FRR managed section,
//  4. detach the dataplane (inverse of Start; the helper object is kept so a
//     later confirmed commit can re-arm it).
//
// Renames persist deliberately — reverting them would link-cycle a degraded
// box for cosmetic benefit. Post-rollback state = renamed NICs + lifeline
// fxp0 .network + zero config-driven claims. The caller holds d.applySem.
func (d *Daemon) enterBootstrapMode() {
	d.bootstrapMode.Store(true)

	// Test seam: when the apply body is stubbed (unit tests), skip the
	// real filesystem / networkctl / FRR / dataplane teardown — those touch
	// /etc/systemd/network and run external commands. The flag flip above is
	// the observable behavior under test.
	if d.applyBodyForTest != nil {
		return
	}

	// (2) Remove xpf-written takeover .network files (NOT the lifeline fxp0
	// .network and NOT the .link rename files — those keep mgmt reachable and
	// the rename stable). The lifeline .network is the bootstrap fxp0 file.
	lifelineNetwork := linkPrefix + "fxp0.network"
	entries, err := os.ReadDir(linkDir)
	if err == nil {
		removed := false
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, linkPrefix) {
				continue
			}
			// Keep .link files (rename persistence) and the lifeline .network.
			if strings.HasSuffix(name, ".link") || name == lifelineNetwork {
				continue
			}
			if strings.HasSuffix(name, ".network") {
				if err := os.Remove(filepath.Join(linkDir, name)); err == nil {
					removed = true
					slog.Info("bootstrap rollback: removed takeover .network file", "file", name)
				}
			}
		}
		if removed {
			if err := networkctlReload(); err != nil {
				slog.Warn("bootstrap rollback: networkctl reload failed", "err", err)
			}
		}
	}

	// (3) Clear the FRR managed section.
	if d.frr != nil {
		if err := d.frr.Clear(); err != nil {
			slog.Warn("bootstrap rollback: failed to clear FRR managed section", "err", err)
		}
	}

	// (4) Detach the dataplane (inverse of Start). Keep the object so a later
	// confirmed commit re-arms it via runBootstrapExitStartup.
	if d.dp != nil {
		if err := d.dp.Teardown(); err != nil {
			slog.Warn("bootstrap rollback: dataplane teardown failed", "err", err)
		}
	}

	slog.Warn("bootstrap rollback complete: takeover removed, management lifeline preserved; " +
		"system is back in bootstrap mode — 'commit confirmed' a corrected config")
}

// lifelineRecord is the persisted management-NIC identity.
type lifelineRecord struct {
	PCIAddr string // PCI bus address (e.g. "0000:05:00.0"); primary key
	MAC     string // MAC address (tiebreaker for non-PCI NICs)
}

// lifelineRecordFileForTest overrides lifelineRecordFile in tests (the real
// path is /etc, not writable in the test sandbox). Empty => use the const.
var lifelineRecordFileForTest string

func lifelinePath() string {
	if lifelineRecordFileForTest != "" {
		return lifelineRecordFileForTest
	}
	return lifelineRecordFile
}

// writeLifelineRecord persists the lifeline identity. Keyed by PCI address so
// it survives the rename to fxp0 and daemon restarts (invariant 2). The file
// lives outside .configdb so it is config-independent (Item 4 invariant 3)
// and survives rollback-to-bootstrap.
func writeLifelineRecord(rec lifelineRecord) error {
	return writeLifelineRecordAt(lifelinePath(), rec)
}

func writeLifelineRecordAt(path string, rec lifelineRecord) error {
	content := fmt.Sprintf("# Managed by xpfd — #1922 management lifeline identity\npci=%s\nmac=%s\n",
		rec.PCIAddr, rec.MAC)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create lifeline record dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write lifeline record: %w", err)
	}
	return nil
}

// readLifelineRecord loads the persisted lifeline identity. Returns
// (zero, false) when the record is absent or unparseable (no lifeline pinned
// — the protected set then falls back to fxp0 + any management-interface
// leaf only).
func readLifelineRecord() (lifelineRecord, bool) {
	return readLifelineRecordAt(lifelinePath())
}

func readLifelineRecordAt(path string) (lifelineRecord, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return lifelineRecord{}, false
	}
	var rec lifelineRecord
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "pci":
			rec.PCIAddr = strings.TrimSpace(v)
		case "mac":
			rec.MAC = strings.TrimSpace(v)
		}
	}
	if rec.PCIAddr == "" && rec.MAC == "" {
		return lifelineRecord{}, false
	}
	return rec, true
}

// detectLifelineInterface picks the management lifeline NIC for a bootstrap
// boot (Item 3, lifeline-identification path).
//
// Resolution ladder (OQ-C resolution): the interface carrying the active
// IPv4 default route, else the active IPv6 default route, else none
// (refuse takeover, stay bootstrap, console-only). The default-route
// interface is "the NIC the operator reaches the box on" in the common
// single-homed case. A multi-homed / policy-routed mgmt box is the residual
// the operator resolves with an explicit `system management-interface` leaf
// once a config exists; the genuinely-fresh box has no leaf yet, so the
// default-route signal is the only config-independent option.
//
// Returns the current kernel name of the lifeline NIC and ok=false when no
// default route exists.
func detectLifelineInterface() (name string, ok bool) {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			continue
		}
		for i := range routes {
			r := &routes[i]
			// A default route has a nil/zero-length destination.
			if r.Dst != nil && len(r.Dst.IP) != 0 && !r.Dst.IP.IsUnspecified() {
				continue
			}
			if r.LinkIndex <= 0 {
				continue
			}
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				continue
			}
			return link.Attrs().Name, true
		}
	}
	return "", false
}

// pciAddrForInterface resolves the PCI bus address + MAC for a kernel
// interface name via sysfs (the same source enumeratePCINICs uses).
func pciAddrForInterface(name string) (lifelineRecord, bool) {
	devicePath := filepath.Join("/sys/class/net", name, "device")
	devReal, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		return lifelineRecord{}, false
	}
	busAddr := extractPCIAddr(devReal)
	if busAddr == "" {
		return lifelineRecord{}, false
	}
	rec := lifelineRecord{PCIAddr: busAddr}
	if link, err := netlink.LinkByName(name); err == nil {
		rec.MAC = link.Attrs().HardwareAddr.String()
	}
	return rec, true
}

// resolveLifelineCurrentName resolves the persisted lifeline record to the
// device's CURRENT kernel name (post-rename). It walks every NIC and matches
// on PCI address first (stable across rename), then MAC. Returns ("", false)
// when no record is pinned or it resolves to no present device.
func resolveLifelineCurrentName() (string, bool) {
	rec, ok := readLifelineRecord()
	if !ok {
		return "", false
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		if cur, ok := pciAddrForInterface(name); ok {
			if rec.PCIAddr != "" && cur.PCIAddr == rec.PCIAddr {
				return name, true
			}
		}
		if rec.MAC != "" {
			if link, err := netlink.LinkByName(name); err == nil &&
				strings.EqualFold(link.Attrs().HardwareAddr.String(), rec.MAC) {
				return name, true
			}
		}
	}
	return "", false
}

// protectedInterfaces returns the management protected set (Item 4): the
// union of the explicit `system management-interface` leaf (when set), the
// default fxp0 (unless narrowed off by an explicit non-fxp0 leaf), and the
// lifeline-recorded interface resolved from its PCI address to the current
// name. Members are NEVER marked Unmanaged / always-down / address-stripped
// by the reconcile path, regardless of the active config (config-independent;
// invariant 3).
//
// mgmtLeaf is the configured `system management-interface` value ("" when
// unset). The OQ-D escape valve: an explicit non-fxp0 leaf NARROWS fxp0 out
// of the auto-protection so an operator can repurpose fxp0 as a revenue port.
func protectedInterfaces(mgmtLeaf string) map[string]bool {
	lifeline, ok := resolveLifelineCurrentName()
	if !ok {
		lifeline = ""
	}
	return protectedInterfacesWith(mgmtLeaf, lifeline)
}

// protectedInterfacesWith is the pure core of protectedInterfaces, taking the
// already-resolved lifeline name (or "") so the OQ-D narrowing is unit
// testable without sysfs.
func protectedInterfacesWith(mgmtLeaf, lifeline string) map[string]bool {
	set := make(map[string]bool)
	// narrowFxp0 is the OQ-D escape valve: an explicit non-fxp0
	// management-interface leaf removes fxp0 from the auto-protection so the
	// operator can repurpose fxp0 as a revenue port. It must apply to BOTH
	// the leaf/default contribution AND the lifeline-record union — the
	// persisted lifeline record can resolve to fxp0 and would otherwise
	// silently re-add it (Codex r3 BLOCKER).
	narrowFxp0 := mgmtLeaf != "" && mgmtLeaf != defaultMgmtInterface
	if mgmtLeaf != "" {
		set[mgmtLeaf] = true
	} else {
		set[defaultMgmtInterface] = true
	}
	if lifeline != "" && !(narrowFxp0 && lifeline == defaultMgmtInterface) {
		set[lifeline] = true
	}
	return set
}

// setupBootstrapLifeline runs the Item-3 lifeline-gated path in place of the
// full rename loop when the daemon boots into bootstrap mode. It:
//
//  1. detects the management lifeline NIC (default-route interface),
//  2. records its PCI identity to /etc/xpf/lifeline-interface so the
//     protected set survives rename/restart/rollback,
//  3. if (and only if) that NIC is enumeration index 0 — i.e. it WOULD
//     become fxp0 in a normal rename — renames JUST that NIC to fxp0 and
//     writes a lifeline-aware bootstrap .network that snapshots its current
//     addressing (DHCP or static) so the link cycle restores reachability,
//  4. otherwise touches NO interface (refuse takeover, stay reachable on the
//     un-renamed kernel name), logs loudly, and requires the operator to
//     re-wire or set `system management-interface` + commit.
//
// No other NIC is renamed, cycled, or reconfigured in bootstrap mode.
func (d *Daemon) setupBootstrapLifeline() {
	lifeline, ok := detectLifelineInterface()
	if !ok {
		slog.Warn("bootstrap lifeline: no IPv4/IPv6 default route found; cannot identify a " +
			"management NIC. Staying in bootstrap with NO interface changes — reach the box " +
			"via its hypervisor/physical console and 'commit confirmed' a config.")
		return
	}

	// Record PCI identity (keyed by PCI, MAC tiebreaker) so the protected
	// set resolves the lifeline to its post-rename name (Item 4).
	if rec, ok := pciAddrForInterface(lifeline); ok {
		if err := writeLifelineRecord(rec); err != nil {
			slog.Warn("bootstrap lifeline: failed to persist lifeline record", "err", err)
		} else {
			slog.Info("bootstrap lifeline: recorded management NIC identity",
				"interface", lifeline, "pci", rec.PCIAddr, "mac", rec.MAC)
		}
	} else {
		slog.Warn("bootstrap lifeline: management NIC has no PCI address; protected set will "+
			"fall back to fxp0 only", "interface", lifeline)
	}

	// Determine the enumeration index of the lifeline NIC. Only index 0
	// becomes fxp0; renaming a higher-index NIC would not match the mgmt
	// convention and risks cutting off management.
	nics, err := enumeratePCINICs()
	if err != nil {
		slog.Warn("bootstrap lifeline: NIC enumeration failed; no rename performed", "err", err)
		return
	}
	idx := -1
	for i, nic := range nics {
		if nic.name == lifeline {
			idx = i
			break
		}
	}
	if idx != 0 {
		slog.Warn("bootstrap lifeline: management default-route NIC is NOT enumeration index 0, "+
			"so it would not become fxp0. Refusing to rename/cycle any interface; staying in "+
			"bootstrap. Re-wire the management NIC to the first PCI slot, or set "+
			"'system management-interface' and 'commit confirmed'.",
			"interface", lifeline, "enum_index", idx)
		return
	}

	// The lifeline NIC would become fxp0. Snapshot its current addressing
	// into the bootstrap .network BEFORE the rename, so the link cycle
	// restores the same reachability under the fxp0 name.
	if wrote := writeBootstrapLifelineNetwork(lifeline); wrote {
		// reload picks up the new .network keyed on Name=fxp0.
	}

	// Rename just this one NIC to fxp0 (writes the .link + renames).
	original := recoverOriginalName(lifeline)
	_ = writeLinkFile(defaultMgmtInterface, original)
	if lifeline != defaultMgmtInterface {
		if err := renameInterface(lifeline, defaultMgmtInterface); err != nil {
			slog.Warn("bootstrap lifeline: rename to fxp0 failed; mgmt stays on original name",
				"from", lifeline, "err", err)
		} else {
			slog.Info("bootstrap lifeline: renamed management NIC to fxp0", "from", lifeline)
		}
	}
	if err := networkctlReload(); err != nil {
		slog.Warn("bootstrap lifeline: networkctl reload failed", "err", err)
	}
}

// writeBootstrapLifelineNetwork writes the bootstrap fxp0 .network, snapshotting
// the lifeline NIC's CURRENT addressing so the rename's link cycle restores
// reachability. DHCP-managed lifelines get a plain DHCP .network (matching the
// historical writeBootstrapFxp0Network); a statically-addressed lifeline gets
// Address=/Gateway= lines. Returns true if the file changed.
func writeBootstrapLifelineNetwork(lifeline string) bool {
	path := filepath.Join(linkDir, linkPrefix+"fxp0.network")

	// Snapshot the lifeline's addressing ONCE (Copilot: avoid the duplicate
	// netlink walk). DHCP-managed or address-less lifelines get a plain DHCP
	// .network; a statically-addressed one gets an Address=/Gateway= snapshot.
	v4, v6, gw4, gw6 := interfaceAddrSnapshot(lifeline)
	var content string
	if isDHCPManaged(lifeline) || (len(v4) == 0 && len(v6) == 0) {
		content = "# Managed by xpfd — #1922 bootstrap lifeline (DHCP)\n" +
			"[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nUseDNS=yes\nUseRoutes=yes\n"
	} else {
		var b strings.Builder
		b.WriteString("# Managed by xpfd — #1922 bootstrap lifeline (static snapshot)\n")
		b.WriteString("[Match]\nName=fxp0\n\n[Network]\n")
		for _, a := range v4 {
			fmt.Fprintf(&b, "Address=%s\n", a)
		}
		for _, a := range v6 {
			fmt.Fprintf(&b, "Address=%s\n", a)
		}
		if gw4 != "" {
			fmt.Fprintf(&b, "Gateway=%s\n", gw4)
		}
		if gw6 != "" {
			fmt.Fprintf(&b, "Gateway=%s\n", gw6)
		}
		content = b.String()
	}

	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return false
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		slog.Warn("bootstrap lifeline: failed to write fxp0 .network", "path", path, "err", err)
		return false
	}
	slog.Info("bootstrap lifeline: wrote fxp0 bootstrap .network", "source_interface", lifeline)
	return true
}

// resolveProtectedInterfaces is the daemon's #1922 Item 4 protected-set
// provider, registered with the dataplane compiler via
// SetProtectedInterfaceResolver. It returns the union of fxp0 (the default),
// the explicit `system management-interface` leaf when set, and the
// lifeline-recorded NIC resolved to its current name. Config-independent: it
// reads the persisted lifeline record + the active config's optional leaf,
// so the protection holds under an empty/absent/rolled-back config.
func (d *Daemon) resolveProtectedInterfaces() map[string]bool {
	mgmtLeaf := ""
	if cfg := d.store.ActiveConfig(); cfg != nil {
		mgmtLeaf = cfg.System.ManagementInterface
	}
	return protectedInterfaces(mgmtLeaf)
}

// interfaceAddrSnapshot collects the current global addresses + default
// gateways on name, for the lifeline-aware bootstrap .network writer.
func interfaceAddrSnapshot(name string) (v4, v6 []string, gw4, gw6 string) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, nil, "", ""
	}
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
	for i := range addrs {
		ip := addrs[i].IPNet
		if ip == nil || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() {
			continue
		}
		if ip.IP.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	// Default-route gateways for this link.
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteList(link, family)
		if err != nil {
			continue
		}
		for i := range routes {
			r := &routes[i]
			if r.Dst != nil && len(r.Dst.IP) != 0 && !r.Dst.IP.IsUnspecified() {
				continue
			}
			if r.Gw == nil {
				continue
			}
			if r.Gw.To4() != nil && gw4 == "" {
				gw4 = r.Gw.String()
			} else if r.Gw.To4() == nil && gw6 == "" {
				gw6 = r.Gw.String()
			}
		}
	}
	return v4, v6, gw4, gw6
}

// isDHCPManaged reports whether name currently has a DHCP-assigned address
// (heuristic: a global address with a finite valid lifetime). Used by the
// lifeline writer to choose DHCP vs static snapshot. Best-effort: on any
// uncertainty it returns false so the writer snapshots the static addresses
// (a static snapshot of a DHCP lease still keeps mgmt reachable until the
// lease would have expired, which is the bootstrap window).
func isDHCPManaged(name string) bool {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return false
	}
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
	for i := range addrs {
		if addrs[i].IP.IsLinkLocalUnicast() {
			continue
		}
		// A DHCP lease carries a finite ValidLft; a static address is
		// typically permanent (ValidLft == 0xffffffff / forever).
		if addrs[i].ValidLft > 0 && addrs[i].ValidLft != 0xffffffff {
			return true
		}
	}
	return false
}
