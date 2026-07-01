package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// Cross-cutting counter map accessors.
// Same-package split of maps.go (#1686): the generic global/interface/zone
// counters plus the ClearAllCounters orchestrator. Domain-specific counters
// (policy, filter, NAT, flood) live in their own domain files; ClearAllCounters
// calls those domain clears via same-package method dispatch.

// ErrCounterNotPopulated reports that a counter family is safely readable but
// is not sourced by the userspace dataplane (#3643). It is DISTINCT from a
// genuine read failure (a missing map or a degraded IPC bridge, which must
// still bump the #3345 xpf_counter_read_errors_total signal) and DISTINCT from
// a real zero. Read surfaces treat it as "not available" -- never a 500, never
// a false read-error alert, never a bare misleading 0. Per-zone traffic and
// flood counters currently report this because the eBPF writers were deleted
// in #1476 and the userspace POPULATE path is deferred (#3643 plan §5A).
var ErrCounterNotPopulated = errors.New("counter not populated in userspace dataplane")

// ReadGlobalCounter reads a per-CPU global counter and returns the sum across all CPUs.
func (m *Manager) ReadGlobalCounter(index uint32) (uint64, error) {
	zm, ok := m.maps["global_counters"]
	if !ok {
		return 0, fmt.Errorf("global_counters map not found")
	}
	var perCPU []uint64
	if err := zm.Lookup(index, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	// Add userspace counter offsets (stored separately to avoid per-CPU race).
	m.mu.Lock()
	total += m.userspaceCounterOffsets[index]
	m.mu.Unlock()
	return total, nil
}

// IncrementGlobalCounter adds delta to a per-CPU global counter (on CPU 0).
// This is used by the userspace dataplane to account for packets forwarded
// outside the BPF pipeline.
func (m *Manager) IncrementGlobalCounter(index uint32, delta uint64) error {
	if delta == 0 {
		return nil
	}
	// Store delta in the userspace counter offset map instead of writing
	// directly to the per-CPU BPF array. ReadGlobalCounter merges both.
	// This avoids the read-modify-write race with concurrent eBPF increments.
	m.mu.Lock()
	if m.userspaceCounterOffsets == nil {
		m.userspaceCounterOffsets = make(map[uint32]uint64)
	}
	m.userspaceCounterOffsets[index] += delta
	m.mu.Unlock()
	return nil
}

// ReadUserspaceCounterOffset returns just the in-memory userspace counter
// delta accumulated for index via IncrementGlobalCounter, independent of the
// BPF global_counters map. ReadGlobalCounter merges this offset with the
// per-CPU map sum; this accessor exposes the userspace half on its own so the
// userspace-dp counter bridge accounting (e.g. the #3343 per-screen-reason
// publish path) can be inspected without a loaded BPF map.
func (m *Manager) ReadUserspaceCounterOffset(index uint32) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.userspaceCounterOffsets[index]
}

// ReadInterfaceCounters reads the per-CPU interface counter values and sums them.
// interface_counters is a PERCPU_HASH (#756): a missing key simply means
// no traffic has traversed the interface yet, which reads as zero.
func (m *Manager) ReadInterfaceCounters(ifindex int) (InterfaceCounterValue, error) {
	zm, ok := m.maps["interface_counters"]
	if !ok {
		return InterfaceCounterValue{}, fmt.Errorf("interface_counters map not found")
	}
	var perCPU []InterfaceCounterValue
	if err := zm.Lookup(uint32(ifindex), &perCPU); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return InterfaceCounterValue{}, nil
		}
		return InterfaceCounterValue{}, err
	}
	var total InterfaceCounterValue
	for _, v := range perCPU {
		total.RxPackets += v.RxPackets
		total.RxBytes += v.RxBytes
		total.TxPackets += v.TxPackets
		total.TxBytes += v.TxBytes
	}
	return total, nil
}

// ReadZoneCounters returns the userspace-reported per-zone traffic counter for
// zoneID in the given direction (0 = ingress, 1 = egress).
//
// #3643: zone ids are stable name-hashes in [1,65533] (#3075), but the legacy
// zone_counters BPF array is a dense MaxZones*2-entry per-CPU array. Indexing it
// by a stable-hash id >= MaxZones OOBs the bounded Lookup (ErrKeyNotExist),
// which the read surfaces mis-reported as a hard failure (REST 500, false
// Prometheus read-error alert, CLI/gRPC error rows). This now keys a Go-side
// sparse offset map -- the exact treatment #2255 gave nat_rule_counters -- and
// NEVER indexes the dense array, so an id >= MaxZones can no longer OOB. The
// userspace helper does not yet populate per-zone traffic counters (POPULATE
// deferred, #3643 plan §5A), so the map is empty and this reports
// ErrCounterNotPopulated; surfaces render "not available" rather than a
// misleading 0.
func (m *Manager) ReadZoneCounters(zoneID uint16, direction int) (CounterValue, error) {
	if direction != 0 && direction != 1 {
		return CounterValue{}, fmt.Errorf("invalid zone counter direction %d", direction)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	vals, ok := m.zoneCounterOffsets[zoneID]
	if !ok {
		return CounterValue{}, ErrCounterNotPopulated
	}
	return vals[direction], nil
}

// SetZoneCounterOffset records the absolute cumulative per-zone ingress/egress
// traffic counters reported by the userspace dataplane for zoneID (#3643
// POPULATE hook, mirroring SetNATRuleCounterOffset). Values are absolute
// (overwrite), matching the helper's cumulative-since-launch totals. Once set,
// ReadZoneCounters returns them (nil error) instead of ErrCounterNotPopulated.
func (m *Manager) SetZoneCounterOffset(zoneID uint16, ingress, egress CounterValue) {
	m.mu.Lock()
	if m.zoneCounterOffsets == nil {
		m.zoneCounterOffsets = make(map[uint16][2]CounterValue)
	}
	m.zoneCounterOffsets[zoneID] = [2]CounterValue{ingress, egress}
	m.mu.Unlock()
}

// ClearZoneCounterOffsets drops all userspace-reported per-zone traffic offsets
// (#3643), mirroring ClearNATRuleCounterOffsets. Wired into ClearZoneCounters.
func (m *Manager) ClearZoneCounterOffsets() {
	m.mu.Lock()
	m.zoneCounterOffsets = nil
	m.mu.Unlock()
}

// ClearGlobalCounters zeroes all global counter entries.
func (m *Manager) ClearGlobalCounters() error {
	zm, ok := m.maps["global_counters"]
	if !ok {
		return fmt.Errorf("global_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]uint64, numCPUs)
	for i := uint32(0); i < GlobalCtrMax; i++ {
		if err := zm.Update(i, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear global counter %d: %w", i, err)
		}
	}
	return nil
}

// ClearInterfaceCounters zeroes all interface counter entries.
// interface_counters is a PERCPU_HASH (#756): iterate-and-zero existing
// keys; missing keys stay absent and read as zero.
func (m *Manager) ClearInterfaceCounters() error {
	zm, ok := m.maps["interface_counters"]
	if !ok {
		return fmt.Errorf("interface_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]InterfaceCounterValue, numCPUs)
	var key uint32
	var val []InterfaceCounterValue
	iter := zm.Iterate()
	var keys []uint32
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate interface_counters: %w", err)
	}
	for _, k := range keys {
		if err := zm.Update(k, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear interface_counters %d: %w", k, err)
		}
	}
	return nil
}

// ClearZoneCounters zeroes all zone counter entries.
func (m *Manager) ClearZoneCounters() error {
	// #3643: drop the userspace-reported offsets first so an operator clear
	// takes effect on the read path (the only source of per-zone values today)
	// even when the legacy dense BPF map is absent, mirroring
	// ClearNATRuleCounters.
	m.ClearZoneCounterOffsets()
	zm, ok := m.maps["zone_counters"]
	if !ok {
		return nil
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < 128; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// ClearAllCounters zeroes all counter maps (global, interface, zone, policy, filter).
func (m *Manager) ClearAllCounters() error {
	if err := m.ClearGlobalCounters(); err != nil {
		return err
	}
	if err := m.ClearInterfaceCounters(); err != nil {
		return err
	}
	if err := m.ClearZoneCounters(); err != nil {
		return err
	}
	// #3643: drop the userspace-reported per-zone flood offsets too (no dense
	// map to zero -- flood counters live only in the sparse offset map now).
	m.ClearFloodCounterOffsets()
	if err := m.ClearPolicyCounters(); err != nil {
		return err
	}
	return m.ClearFilterCounters()
}
