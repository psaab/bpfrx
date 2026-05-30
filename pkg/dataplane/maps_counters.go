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

// ReadZoneCounters reads the per-CPU zone counter values and sums them.
// direction: 0 = ingress, 1 = egress.
func (m *Manager) ReadZoneCounters(zoneID uint16, direction int) (CounterValue, error) {
	zm, ok := m.maps["zone_counters"]
	if !ok {
		return CounterValue{}, fmt.Errorf("zone_counters map not found")
	}
	idx := uint32(zoneID)*2 + uint32(direction)
	var perCPU []CounterValue
	if err := zm.Lookup(idx, &perCPU); err != nil {
		return CounterValue{}, err
	}
	var total CounterValue
	for _, v := range perCPU {
		total.Packets += v.Packets
		total.Bytes += v.Bytes
	}
	return total, nil
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
	zm, ok := m.maps["zone_counters"]
	if !ok {
		return fmt.Errorf("zone_counters map not found")
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
	if err := m.ClearPolicyCounters(); err != nil {
		return err
	}
	return m.ClearFilterCounters()
}
