package dataplane

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Firewall-filter map accessors.
// Same-package split of maps.go (#1686): interface->filter binding, filter
// configs/rules, policers, and the filter hit counters. ReadFilterCounters and
// ClearFilterCounters live together here (a map's read+clear stay in one file,
// #1686 rule).

// SetIfaceFilter assigns a filter ID to an interface + family combination.
func (m *Manager) SetIfaceFilter(key IfaceFilterKey, filterID uint32) error {
	zm, present, st := m.lookupMapLocked("iface_filter_map")
	if st == registryFresh {
		return fmt.Errorf("%w: iface_filter_map", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("iface_filter_map not found")
	}
	return zm.Update(key, filterID, ebpf.UpdateAny)
}

// ClearIfaceFilterMap removes all entries from the iface_filter_map.
func (m *Manager) ClearIfaceFilterMap() error {
	zm, present, st := m.lookupMapLocked("iface_filter_map")
	if st == registryFresh {
		return fmt.Errorf("%w: iface_filter_map", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("iface_filter_map not found")
	}
	var key IfaceFilterKey
	var val []byte
	iter := zm.Iterate()
	var keys []IfaceFilterKey
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetFilterConfig writes a filter config entry.
func (m *Manager) SetFilterConfig(filterID uint32, cfg FilterConfig) error {
	zm, present, st := m.lookupMapLocked("filter_configs")
	if st == registryFresh {
		return fmt.Errorf("%w: filter_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("filter_configs not found")
	}
	return zm.Update(filterID, cfg, ebpf.UpdateAny)
}

// ReadFilterConfig reads a filter config entry.
func (m *Manager) ReadFilterConfig(filterID uint32) (FilterConfig, error) {
	zm, present, st := m.lookupMapLocked("filter_configs")
	if st == registryFresh {
		return FilterConfig{}, fmt.Errorf("%w: filter_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return FilterConfig{}, fmt.Errorf("filter_configs not found")
	}
	var cfg FilterConfig
	if err := zm.Lookup(filterID, &cfg); err != nil {
		return FilterConfig{}, err
	}
	return cfg, nil
}

// SetFilterRule writes a filter rule entry.
func (m *Manager) SetFilterRule(index uint32, rule FilterRule) error {
	zm, present, st := m.lookupMapLocked("filter_rules")
	if st == registryFresh {
		return fmt.Errorf("%w: filter_rules", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("filter_rules not found")
	}
	return zm.Update(index, rule, ebpf.UpdateAny)
}

// SetPolicerConfig writes a policer configuration entry.
func (m *Manager) SetPolicerConfig(id uint32, cfg PolicerConfig) error {
	zm, present, st := m.lookupMapLocked("policer_configs")
	if st == registryFresh {
		return fmt.Errorf("%w: policer_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("policer_configs map not found")
	}
	return zm.Update(id, cfg, ebpf.UpdateAny)
}

// ClearPolicerConfigs zeroes all policer_configs entries.
func (m *Manager) ClearPolicerConfigs() error {
	zm, present, st := m.lookupMapLocked("policer_configs")
	if st == registryFresh {
		return fmt.Errorf("%w: policer_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("policer_configs map not found")
	}
	empty := PolicerConfig{}
	for i := uint32(0); i < MaxPolicers; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// ClearFilterConfigs clears all filter config and rule entries.
func (m *Manager) ClearFilterConfigs() error {
	zm, present, st := m.lookupMapLocked("filter_configs")
	if st == registryFresh {
		return fmt.Errorf("%w: filter_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("filter_configs not found")
	}
	var empty FilterConfig
	for i := uint32(0); i < MaxFilterConfigs; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// ReadFilterCounters reads the per-CPU firewall filter counter values and sums them.
func (m *Manager) ReadFilterCounters(ruleIdx uint32) (CounterValue, error) {
	zm, present, st := m.lookupMapLocked("filter_counters")
	if st == registryFresh {
		return CounterValue{}, fmt.Errorf("%w: filter_counters", ErrDataplaneNotArmed)
	}
	if !present {
		return CounterValue{}, fmt.Errorf("filter_counters map not found")
	}
	var perCPU []CounterValue
	if err := zm.Lookup(ruleIdx, &perCPU); err != nil {
		return CounterValue{}, err
	}
	var total CounterValue
	for _, v := range perCPU {
		total.Packets += v.Packets
		total.Bytes += v.Bytes
	}
	return total, nil
}

// ClearFilterCounters zeroes all filter counter entries.
func (m *Manager) ClearFilterCounters() error {
	zm, present, st := m.lookupMapLocked("filter_counters")
	if st == registryFresh {
		return fmt.Errorf("%w: filter_counters", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("filter_counters map not found")
	}
	return clearFilterCountersIn(zm)
}

// clearFilterCountersRaw is the UNGATED ClearAllCounters composition leg
// (#2114 A3 nested-call rule — see clearInterfaceCountersRaw).
func (m *Manager) clearFilterCountersRaw() error {
	zm, present, _ := m.lookupMapLocked("filter_counters")
	if !present {
		return fmt.Errorf("filter_counters map not found")
	}
	return clearFilterCountersIn(zm)
}

// clearFilterCountersIn zeroes every filter_counters slot.
//
// #2114 (Codex PR #6743 r4-F2): the Update error is PROPAGATED, for the
// same reason as clearPolicyCountersIn — a discarded error made
// `clear firewall counters` unconditionally report success. The bound is
// exact: MaxFilterRules (pkg/dataplane/types.go) == MAX_FILTER_RULES ==
// 512 (bpf/headers/xpf_common.h:710), which is filter_counters'
// max_entries (bpf/headers/xpf_maps.h), so no index below can be out of
// range on an armed map.
func clearFilterCountersIn(zm *ebpf.Map) error {
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < MaxFilterRules; i++ {
		if err := zm.Update(i, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear filter_counters %d: %w", i, err)
		}
	}
	return nil
}
