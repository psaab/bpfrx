package dataplane

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
)

// HA / fabric map accessors.
// Same-package split of maps.go (#1686): fabric cross-chassis forwarding
// config, redundancy-group active state, the HA liveness watchdog, the FIB
// generation counter, and the eBPF no-op lifecycle hooks.

// UpdateFabricFwd writes the fabric cross-chassis forwarding config.
// Pass a zero FabricFwdInfo (Ifindex=0) to disable fabric redirect.
func (m *Manager) UpdateFabricFwd(info FabricFwdInfo) error {
	zm, ok := m.maps["fabric_fwd"]
	if !ok {
		return fmt.Errorf("fabric_fwd map not found")
	}
	return zm.Update(uint32(0), info, ebpf.UpdateAny)
}

// UpdateFabricFwd1 writes the secondary fabric cross-chassis forwarding config (key=1).
// Pass a zero FabricFwdInfo (Ifindex=0) to disable fabric1 redirect.
func (m *Manager) UpdateFabricFwd1(info FabricFwdInfo) error {
	zm, ok := m.maps["fabric_fwd"]
	if !ok {
		return fmt.Errorf("fabric_fwd map not found")
	}
	return zm.Update(uint32(1), info, ebpf.UpdateAny)
}

// UpdateRGActive sets the active state of a redundancy group in BPF.
// active=true means this node is primary for the RG; false means secondary.
func (m *Manager) UpdateRGActive(rgID int, active bool) error {
	zm, ok := m.maps["rg_active"]
	if !ok {
		return fmt.Errorf("rg_active map not found")
	}
	var val uint8
	if active {
		val = 1
	}
	return zm.Update(uint32(rgID), val, ebpf.UpdateAny)
}

// UpdateHAWatchdog writes the current monotonic timestamp (seconds) for a
// redundancy group. BPF checks this to detect userspace liveness — if the
// timestamp is stale (>2s), the RG is treated as inactive (fail-closed).
func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	zm, ok := m.maps["ha_watchdog"]
	if !ok {
		return fmt.Errorf("ha_watchdog map not found")
	}
	return zm.Update(uint32(rgID), timestamp, ebpf.UpdateAny)
}

// BumpFIBGeneration increments the global FIB generation counter, causing
// all cached FIB entries in sessions to miss on the next packet. BPF programs
// compare session.fib_gen against fib_gen_map[0] and re-run bpf_fib_lookup
// when they differ.
//
// This replaces the old InvalidateFIBCache() approach which iterated sessions
// and wrote them back via sm.Update(). That caused RCU replacement of hash map
// entries — BPF programs holding pointers from bpf_map_lookup_elem would write
// to the OLD (about-to-be-freed) entry, losing counter/last_seen updates and
// causing sessions to expire prematurely.
// StartFIBSync is a no-op for eBPF — bpf_fib_lookup handles FIB queries in-kernel.
func (m *Manager) StartFIBSync(_ context.Context) {}

func (m *Manager) NotifyLinkCycle() {} // no-op: eBPF programs survive link cycles

func (m *Manager) SyncFabricState() {} // no-op: eBPF uses fabric_fwd BPF map directly

func (m *Manager) BumpFIBGeneration() uint32 {
	zm, ok := m.maps["fib_gen_map"]
	if !ok {
		slog.Warn("fib_gen_map not found, cannot bump FIB generation")
		return 0
	}
	var key uint32
	var gen uint32
	if err := zm.Lookup(key, &gen); err != nil {
		gen = 0
	}
	gen++
	if err := zm.Update(key, gen, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to bump FIB generation", "err", err)
		return gen - 1
	}
	slog.Info("bumped FIB generation counter", "generation", gen)
	return gen
}
