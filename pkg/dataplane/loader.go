package dataplane

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
)

const linkPinPath = "/sys/fs/bpf/xpf/links"

// go:generate directives -- run "make generate" with clang + libbpf-dev installed.
// These produce the *_bpfel.go files with embedded ELF objects.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpMain ../../bpf/xdp/xdp_main.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate bash build-userspace-xdp.sh
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpScreen ../../bpf/xdp/xdp_screen.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpZone ../../bpf/xdp/xdp_zone.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpConntrack ../../bpf/xdp/xdp_conntrack.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpPolicy ../../bpf/xdp/xdp_policy.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpNat ../../bpf/xdp/xdp_nat.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpForward ../../bpf/xdp/xdp_forward.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpNat64 ../../bpf/xdp/xdp_nat64.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfXdpCpumap ../../bpf/xdp/xdp_cpumap.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfTcMain ../../bpf/tc/tc_main.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfTcConntrack ../../bpf/tc/tc_conntrack.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfTcNat ../../bpf/tc/tc_nat.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfTcScreenEgress ../../bpf/tc/tc_screen_egress.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 xpfTcForward ../../bpf/tc/tc_forward.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu

// Manager manages the eBPF dataplane: programs, maps, and attachments.
type Manager struct {
	loaded             bool
	programs           map[string]*ebpf.Program
	maps               map[string]*ebpf.Map
	xdpLinks           map[int]link.Link
	tcLinks            map[int]link.Link
	lastCompile        *CompileResult
	PersistentNAT      *PersistentNATTable
	EnableCPUMap       bool // Enable cpumap multi-CPU distribution (adds startup overhead)
	XDPEntryProg       string
	VlanSubInterfaces      map[int]bool       // VLAN sub-interface ifindexes (skip XDP swap for these)
	mu                     sync.Mutex         // protects userspaceCounterOffsets
	userspaceCounterOffsets map[uint32]uint64  // userspace counter deltas merged in ReadGlobalCounter
}

// New creates a new dataplane Manager.
func New() *Manager {
	return &Manager{
		programs:      make(map[string]*ebpf.Program),
		maps:          make(map[string]*ebpf.Map),
		xdpLinks:      make(map[int]link.Link),
		tcLinks:       make(map[int]link.Link),
		PersistentNAT:     NewPersistentNATTable(),
		XDPEntryProg:      "xdp_main_prog",
		VlanSubInterfaces: make(map[int]bool),
	}
}

// Load loads all eBPF programs and maps. Returns an error if eBPF
// programs have not been generated yet (run "make generate" first).
func (m *Manager) Load() error {
	slog.Info("loading eBPF programs")

	// loadAllObjects is implemented in loader_ebpf.go (generated build)
	// or returns an error in loader_stub.go (no generated files).
	if err := m.loadAllObjects(); err != nil {
		return err
	}

	m.loaded = true
	slog.Info("eBPF programs loaded successfully")
	return nil
}

// IsLoaded returns true if eBPF programs are loaded.
func (m *Manager) IsLoaded() bool {
	return m.loaded
}

// xdpAttachModeMatches reports whether the kernel's current XDP attach mode
// on ifindex matches what AttachXDP is about to request.  Returns true on
// "probe failed" so we fall through to the existing Update() path rather
// than punishing transient netlink hiccups.
//
// Kernel XDP attach modes (nl/link_linux.go):
//   XDP_ATTACHED_NONE = 0 — no prog attached
//   XDP_ATTACHED_DRV  = 1 — driver (native) mode
//   XDP_ATTACHED_SKB  = 2 — generic (skb) mode
//   XDP_ATTACHED_HW   = 3 — hw offload
func xdpAttachModeMatches(ifindex int, wantGeneric bool) bool {
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil || l == nil {
		return true
	}
	xdp := l.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return true
	}
	isGeneric := xdp.AttachMode == 2 /* XDP_ATTACHED_SKB */
	return isGeneric == wantGeneric
}

// AttachXDP attaches the XDP main program to the given interface.
// If forceGeneric is true, uses generic (SKB) mode instead of native driver mode.
// When forceGeneric is false, tries native driver mode only (no automatic fallback).
// On restart, reuses a previously pinned link and atomically replaces the program.
func (m *Manager) AttachXDP(ifindex int, forceGeneric bool) error {
	if !m.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	entryProg := m.XDPEntryProg
	if entryProg == "" {
		entryProg = "xdp_main_prog"
	}
	prog, ok := m.programs[entryProg]
	if !ok {
		return fmt.Errorf("%s not found", entryProg)
	}

	if _, exists := m.xdpLinks[ifindex]; exists {
		return fmt.Errorf("XDP already attached to ifindex %d", ifindex)
	}

	// Try to load a previously pinned link and update it atomically.
	//
	// #864: before reusing, verify the pinned link's attach mode matches
	// what the caller requested.  If a previous boot fell back to generic
	// (skb-mode) and pinned a generic-mode link, we would otherwise keep
	// running in generic forever — losing native-XDP performance even
	// after the driver/firmware issue that forced the fallback is resolved,
	// and leaving IFACE_FLAG_NATIVE_XDP stale in the BPF maps.
	pinFile := filepath.Join(linkPinPath, fmt.Sprintf("xdp_%d", ifindex))
	if existing, err := link.LoadPinnedLink(pinFile, nil); err == nil {
		if xdpAttachModeMatches(ifindex, forceGeneric) {
			if err := existing.Update(prog); err == nil {
				m.xdpLinks[ifindex] = existing
				slog.Info("updated pinned XDP link", "ifindex", ifindex)
				return nil
			}
			// Update failed (e.g. program type mismatch) — detach + re-attach.
			existing.Close()
			os.Remove(pinFile)
		} else {
			// Attach mode mismatch — existing pin is generic but we want
			// driver (or vice versa).  Drop the pin and attach fresh so the
			// mode picks up correctly and IFACE_FLAG_NATIVE_XDP stays true.
			slog.Warn("pinned XDP link has wrong attach mode; re-attaching",
				"ifindex", ifindex, "forceGeneric", forceGeneric)
			existing.Close()
			os.Remove(pinFile)
		}
	}

	// Fresh attachment (first boot or pin was removed/incompatible).
	opts := link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	}
	if forceGeneric {
		opts.Flags = link.XDPGenericMode
	} else {
		opts.Flags = link.XDPDriverMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		return fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
	}

	// Pin the link for future restarts.
	if err := os.MkdirAll(linkPinPath, 0700); err != nil {
		slog.Warn("failed to create link pin dir", "err", err)
	} else if err := l.Pin(pinFile); err != nil {
		slog.Warn("failed to pin XDP link", "ifindex", ifindex, "err", err)
	}

	m.xdpLinks[ifindex] = l
	m.seedInterfaceCounter(ifindex)
	mode := "native"
	if forceGeneric {
		mode = "generic"
	}
	slog.Info("attached XDP program", "ifindex", ifindex, "mode", mode)
	return nil
}

// seedInterfaceCounter pre-populates the PERCPU_HASH interface_counters
// entry for ifindex. Called from control-plane interface registration
// (AttachXDP, AddTxPort) so the BPF hot path stays lookup-only and
// never allocates in softirq context (#759). Idempotent: UpdateNoExist
// races safely across repeated registrations.
func (m *Manager) seedInterfaceCounter(ifindex int) {
	ic := m.maps["interface_counters"]
	if ic == nil {
		return
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]InterfaceCounterValue, numCPUs)
	_ = ic.Update(uint32(ifindex), zero, ebpf.UpdateNoExist)
}

// SwapXDPEntryProg atomically replaces the XDP entry program on all
// attached interfaces. Used to switch between the userspace XDP shim
// and xdp_main_prog based on HA forwarding state.
func (m *Manager) SwapXDPEntryProg(name string) error {
	prog, ok := m.programs[name]
	if !ok {
		return fmt.Errorf("XDP program %q not found", name)
	}
	if m.XDPEntryProg == name {
		return nil // already using this program
	}
	var errs []error
	for ifindex, l := range m.xdpLinks {
		// Skip VLAN sub-interfaces: the parent's XDP handles VLAN-tagged
		// traffic. Swapping the shim onto VLAN sub-interfaces breaks NDP
		// because generic XDP + XDP_PASS doesn't properly deliver to the
		// kernel's IPv6 NDP stack on VLAN devices.
		if m.VlanSubInterfaces[ifindex] {
			continue
		}
		if err := l.Update(prog); err != nil {
			errs = append(errs, fmt.Errorf("swap XDP on ifindex %d: %w", ifindex, err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	m.XDPEntryProg = name
	slog.Info("swapped XDP entry program", "program", name, "interfaces", len(m.xdpLinks))
	return nil
}

// DetachXDP detaches the XDP program from the given interface and
// removes its pin file.
func (m *Manager) DetachXDP(ifindex int) error {
	l, exists := m.xdpLinks[ifindex]
	if !exists {
		return nil
	}
	l.Unpin()
	if err := l.Close(); err != nil {
		return fmt.Errorf("detach XDP from ifindex %d: %w", ifindex, err)
	}
	delete(m.xdpLinks, ifindex)
	slog.Info("detached XDP program", "ifindex", ifindex)
	return nil
}

// SetZone maps an {ifindex, vlanID} to a security zone and routing table in the BPF map.
func (m *Manager) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32, flags uint8, rgID uint8, screenFlags uint32) error {
	zm, ok := m.maps["iface_zone_map"]
	if !ok {
		return fmt.Errorf("iface_zone_map not found")
	}
	key := IfaceZoneKey{Ifindex: uint32(ifindex), VlanID: vlanID}
	val := IfaceZoneValue{
		ZoneID:       zoneID,
		Flags:        flags,
		RGID:         rgID,
		RoutingTable: routingTable,
		ScreenFlags:  screenFlags,
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// SetVlanIfaceInfo maps a VLAN sub-interface ifindex to its parent info.
func (m *Manager) SetVlanIfaceInfo(subIfindex int, parentIfindex int, vlanID uint16) error {
	zm, ok := m.maps["vlan_iface_map"]
	if !ok {
		return fmt.Errorf("vlan_iface_map not found")
	}
	val := VlanIfaceInfo{ParentIfindex: uint32(parentIfindex), VlanID: vlanID}
	return zm.Update(uint32(subIfindex), val, ebpf.UpdateAny)
}

// ClearIfaceZoneMap deletes all iface_zone_map entries.
func (m *Manager) ClearIfaceZoneMap() error {
	zm, ok := m.maps["iface_zone_map"]
	if !ok {
		return fmt.Errorf("iface_zone_map not found")
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	var keys []IfaceZoneKey
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// clearNativeXDPFlags removes IfaceFlagNativeXDP from all iface_zone_map
// entries.  Called when falling back from native to generic XDP mode.
func (m *Manager) clearNativeXDPFlags() {
	zm, ok := m.maps["iface_zone_map"]
	if !ok {
		return
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if val.Flags&IfaceFlagNativeXDP != 0 {
			val.Flags &^= IfaceFlagNativeXDP
			zm.Update(key, val, ebpf.UpdateAny)
		}
	}
}

// clearNativeXDPFlagsForIfindexes removes IfaceFlagNativeXDP from iface_zone_map
// entries that belong to the specified physical interfaces.
func (m *Manager) clearNativeXDPFlagsForIfindexes(ifindexes []int) {
	zm, ok := m.maps["iface_zone_map"]
	if !ok || len(ifindexes) == 0 {
		return
	}
	targets := make(map[uint32]struct{}, len(ifindexes))
	for _, ifindex := range ifindexes {
		if ifindex > 0 {
			targets[uint32(ifindex)] = struct{}{}
		}
	}
	if len(targets) == 0 {
		return
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if _, ok := targets[key.Ifindex]; !ok {
			continue
		}
		if val.Flags&IfaceFlagNativeXDP != 0 {
			val.Flags &^= IfaceFlagNativeXDP
			zm.Update(key, val, ebpf.UpdateAny)
		}
	}
}

// ClearVlanIfaceMap deletes all vlan_iface_map entries.
func (m *Manager) ClearVlanIfaceMap() error {
	zm, ok := m.maps["vlan_iface_map"]
	if !ok {
		return fmt.Errorf("vlan_iface_map not found")
	}
	var key uint32
	var vval VlanIfaceInfo
	iter := zm.Iterate()
	var keys []uint32
	for iter.Next(&key, &vval) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// AddTxPort adds an interface to the devmap for XDP_REDIRECT.
//
// tx_ports is a DEVMAP sized MaxInterfaces; kernel ifindex is used as
// the dense key. If ifindex >= MaxInterfaces the bpf_map_update_elem
// would return E2BIG, which bubbles up as "key too big for map" and
// aborts dataplane compile before ever_ok flips. Guard at the call
// site so the error names the interface rather than needing journalctl
// archaeology. See issue #814.
func (m *Manager) AddTxPort(ifindex int) error {
	if ifindex < 0 || uint32(ifindex) >= MaxInterfaces {
		return fmt.Errorf(
			"AddTxPort: ifindex %d exceeds tx_ports cap %d (raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
			ifindex, MaxInterfaces,
		)
	}
	tm, ok := m.maps["tx_ports"]
	if !ok {
		return fmt.Errorf("tx_ports not found")
	}
	val := struct {
		Ifindex uint32
		ProgFD  uint32
	}{Ifindex: uint32(ifindex)}
	if err := tm.Update(uint32(ifindex), val, ebpf.UpdateAny); err != nil {
		return err
	}
	m.seedInterfaceCounter(ifindex)
	return nil
}

// linkLister is the netlink enumeration surface used by
// preflightCheckIfindexCaps. Exposed as a package variable so tests
// can inject a fake without spinning up a netns.
var linkLister = netlink.LinkList

// preflightCheckIfindexCaps enumerates kernel links and returns a
// descriptive error if any ifindex already exceeds MaxInterfaces. Called
// from Manager.Compile() so every compile cycle fires it — catching
// cases where a new namespace pushed ifindex past the cap between
// config snapshots, before AddTxPort hits E2BIG deep in zone apply.
//
// This is a bonus early-warning gate; the call-site cap checks in
// AddTxPort and userspace/maps_sync.go are the real guardrails. Both
// layers exist because interfaces can appear via netlink events at any
// time (HA reconcile, link hotplug), not only at compile.
func (m *Manager) preflightCheckIfindexCaps() error {
	links, err := linkLister()
	if err != nil {
		// Non-fatal: a transient netlink error on preflight should not
		// abort compile. The call-site checks will still fire if any
		// offending interface is actually touched.
		slog.Warn("preflightCheckIfindexCaps: netlink.LinkList failed, skipping preflight", "err", err)
		return nil
	}
	for _, l := range links {
		attrs := l.Attrs()
		if attrs == nil {
			continue
		}
		if attrs.Index < 0 || uint32(attrs.Index) >= MaxInterfaces {
			return fmt.Errorf(
				"preflightCheckIfindexCaps: interface %q ifindex %d exceeds MAX_INTERFACES cap %d (raise MAX_INTERFACES in bpf/headers/xpf_common.h)",
				attrs.Name, attrs.Index, MaxInterfaces,
			)
		}
	}
	return nil
}

// AttachTC attaches the TC main program to the egress path of the given interface.
// On restart, reuses a previously pinned link and atomically replaces the program.
func (m *Manager) AttachTC(ifindex int) error {
	if !m.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	prog, ok := m.programs["tc_main_prog"]
	if !ok {
		return fmt.Errorf("tc_main_prog not found")
	}

	if _, exists := m.tcLinks[ifindex]; exists {
		return fmt.Errorf("TC already attached to ifindex %d", ifindex)
	}

	// Try to load a previously pinned link and update it atomically.
	pinFile := filepath.Join(linkPinPath, fmt.Sprintf("tc_%d", ifindex))
	if existing, err := link.LoadPinnedLink(pinFile, nil); err == nil {
		if err := existing.Update(prog); err == nil {
			m.tcLinks[ifindex] = existing
			slog.Info("updated pinned TC link", "ifindex", ifindex)
			return nil
		}
		existing.Close()
		os.Remove(pinFile)
	}

	// Fresh attachment (first boot or pin was removed/incompatible).
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
		Interface: ifindex,
	})
	if err != nil {
		return fmt.Errorf("attach TC to ifindex %d: %w", ifindex, err)
	}

	// Pin the link for future restarts.
	if err := os.MkdirAll(linkPinPath, 0700); err != nil {
		slog.Warn("failed to create link pin dir", "err", err)
	} else if err := l.Pin(pinFile); err != nil {
		slog.Warn("failed to pin TC link", "ifindex", ifindex, "err", err)
	}

	m.tcLinks[ifindex] = l
	slog.Info("attached TC egress program", "ifindex", ifindex)
	return nil
}

// DetachTC detaches the TC program from the given interface and
// removes its pin file.
func (m *Manager) DetachTC(ifindex int) error {
	l, exists := m.tcLinks[ifindex]
	if !exists {
		return nil
	}
	l.Unpin()
	if err := l.Close(); err != nil {
		return fmt.Errorf("detach TC from ifindex %d: %w", ifindex, err)
	}
	delete(m.tcLinks, ifindex)
	slog.Info("detached TC egress program", "ifindex", ifindex)
	return nil
}

// GetPersistentNAT returns the persistent NAT table.
func (m *Manager) GetPersistentNAT() *PersistentNATTable {
	return m.PersistentNAT
}

// Map returns a named eBPF map, or nil if not found.
func (m *Manager) Map(name string) *ebpf.Map {
	return m.maps[name]
}

// Program returns a named eBPF program, or nil if not found.
func (m *Manager) Program(name string) *ebpf.Program {
	return m.programs[name]
}

// NewEventSource creates an EventSource that reads from the eBPF events ring buffer.
func (m *Manager) NewEventSource() (EventSource, error) {
	evMap := m.maps["events"]
	if evMap == nil {
		return nil, fmt.Errorf("events map not loaded")
	}
	rd, err := ringbuf.NewReader(evMap)
	if err != nil {
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}
	return &ebpfEventSource{reader: rd}, nil
}

// ebpfEventSource reads events from a cilium/ebpf ring buffer.
type ebpfEventSource struct {
	reader *ringbuf.Reader
}

func (s *ebpfEventSource) ReadEvent() ([]byte, error) {
	rec, err := s.reader.Read()
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

func (s *ebpfEventSource) Close() error {
	return s.reader.Close()
}

// LastCompileResult returns the result from the most recent Compile call.
func (m *Manager) LastCompileResult() *CompileResult {
	return m.lastCompile
}

func (m *Manager) XDPLinks() map[int]link.Link {
	return m.xdpLinks
}

func (m *Manager) TCLinks() map[int]link.Link {
	return m.tcLinks
}

// Close releases Go handles for eBPF resources but leaves pinned maps
// and links in the kernel for the next daemon to reuse. This enables
// hitless restarts — sessions survive and XDP/TC programs keep running.
func (m *Manager) Close() error {
	for ifindex, l := range m.xdpLinks {
		if err := l.Close(); err != nil {
			slog.Error("failed to close XDP link handle", "ifindex", ifindex, "err", err)
		}
	}
	for ifindex, l := range m.tcLinks {
		if err := l.Close(); err != nil {
			slog.Error("failed to close TC link handle", "ifindex", ifindex, "err", err)
		}
	}
	m.loaded = false
	return nil
}

// Teardown performs a full teardown: closes handles then removes all
// pinned BPF state. Use when switching dataplanes or decommissioning.
func (m *Manager) Teardown() error {
	m.Close()
	return Cleanup()
}

// Cleanup removes all pinned BPF maps and links. This fully tears down
// the dataplane — use when decommissioning, not during normal restarts.
func Cleanup() error {
	// Unpin and close any pinned links first.
	if entries, err := os.ReadDir(linkPinPath); err == nil {
		for _, e := range entries {
			pinFile := filepath.Join(linkPinPath, e.Name())
			if l, err := link.LoadPinnedLink(pinFile, nil); err == nil {
				l.Unpin()
				l.Close()
			} else {
				// If we can't load it, just remove the file.
				os.Remove(pinFile)
			}
		}
	}
	// Remove the entire pin directory tree.
	if err := os.RemoveAll(bpfPinPath); err != nil {
		return fmt.Errorf("remove %s: %w", bpfPinPath, err)
	}
	slog.Info("removed all pinned BPF state", "path", bpfPinPath)
	return nil
}
