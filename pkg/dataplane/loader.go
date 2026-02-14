package dataplane

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const linkPinPath = "/sys/fs/bpf/bpfrx/links"

// go:generate directives -- run "make generate" with clang + libbpf-dev installed.
// These produce the *_bpfel.go files with embedded ELF objects.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpMain ../../bpf/xdp/xdp_main.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpScreen ../../bpf/xdp/xdp_screen.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpZone ../../bpf/xdp/xdp_zone.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpConntrack ../../bpf/xdp/xdp_conntrack.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpPolicy ../../bpf/xdp/xdp_policy.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpNat ../../bpf/xdp/xdp_nat.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpForward ../../bpf/xdp/xdp_forward.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpNat64 ../../bpf/xdp/xdp_nat64.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxXdpCpumap ../../bpf/xdp/xdp_cpumap.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcMain ../../bpf/tc/tc_main.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcConntrack ../../bpf/tc/tc_conntrack.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcNat ../../bpf/tc/tc_nat.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcScreenEgress ../../bpf/tc/tc_screen_egress.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-21 -cflags "-O2 -g -Wall" -target amd64 bpfrxTcForward ../../bpf/tc/tc_forward.c -- -I../../bpf/headers -I/usr/include/x86_64-linux-gnu

// Manager manages the eBPF dataplane: programs, maps, and attachments.
type Manager struct {
	loaded        bool
	programs      map[string]*ebpf.Program
	maps          map[string]*ebpf.Map
	xdpLinks      map[int]link.Link
	tcLinks       map[int]link.Link
	lastCompile   *CompileResult
	PersistentNAT *PersistentNATTable
	EnableCPUMap  bool // Enable cpumap multi-CPU distribution (adds startup overhead)
}

// New creates a new dataplane Manager.
func New() *Manager {
	return &Manager{
		programs:      make(map[string]*ebpf.Program),
		maps:          make(map[string]*ebpf.Map),
		xdpLinks:      make(map[int]link.Link),
		tcLinks:       make(map[int]link.Link),
		PersistentNAT: NewPersistentNATTable(),
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

// AttachXDP attaches the XDP main program to the given interface.
// If forceGeneric is true, uses generic (SKB) mode instead of native driver mode.
// When forceGeneric is false, tries native driver mode only (no automatic fallback).
// On restart, reuses a previously pinned link and atomically replaces the program.
func (m *Manager) AttachXDP(ifindex int, forceGeneric bool) error {
	if !m.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	prog, ok := m.programs["xdp_main_prog"]
	if !ok {
		return fmt.Errorf("xdp_main_prog not found")
	}

	if _, exists := m.xdpLinks[ifindex]; exists {
		return fmt.Errorf("XDP already attached to ifindex %d", ifindex)
	}

	// Try to load a previously pinned link and update it atomically.
	pinFile := filepath.Join(linkPinPath, fmt.Sprintf("xdp_%d", ifindex))
	if existing, err := link.LoadPinnedLink(pinFile, nil); err == nil {
		if err := existing.Update(prog); err == nil {
			m.xdpLinks[ifindex] = existing
			slog.Info("updated pinned XDP link", "ifindex", ifindex)
			return nil
		}
		// Update failed (e.g. program type mismatch) — detach old and re-attach.
		existing.Close()
		os.Remove(pinFile)
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
	mode := "native"
	if forceGeneric {
		mode = "generic"
	}
	slog.Info("attached XDP program", "ifindex", ifindex, "mode", mode)
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
func (m *Manager) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32) error {
	zm, ok := m.maps["iface_zone_map"]
	if !ok {
		return fmt.Errorf("iface_zone_map not found")
	}
	key := IfaceZoneKey{Ifindex: uint32(ifindex), VlanID: vlanID}
	val := IfaceZoneValue{ZoneID: zoneID, RoutingTable: routingTable}
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
func (m *Manager) AddTxPort(ifindex int) error {
	tm, ok := m.maps["tx_ports"]
	if !ok {
		return fmt.Errorf("tx_ports not found")
	}
	val := struct {
		Ifindex uint32
		ProgFD  uint32
	}{Ifindex: uint32(ifindex)}
	return tm.Update(uint32(ifindex), val, ebpf.UpdateAny)
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

// LastCompileResult returns the result from the most recent Compile call.
func (m *Manager) LastCompileResult() *CompileResult {
	return m.lastCompile
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
