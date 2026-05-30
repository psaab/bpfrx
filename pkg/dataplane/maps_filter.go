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
	zm, ok := m.maps["iface_filter_map"]
	if !ok {
		return fmt.Errorf("iface_filter_map not found")
	}
	return zm.Update(key, filterID, ebpf.UpdateAny)
}

// ClearIfaceFilterMap removes all entries from the iface_filter_map.
func (m *Manager) ClearIfaceFilterMap() error {
	zm, ok := m.maps["iface_filter_map"]
	if !ok {
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
	zm, ok := m.maps["filter_configs"]
	if !ok {
		return fmt.Errorf("filter_configs not found")
	}
	return zm.Update(filterID, cfg, ebpf.UpdateAny)
}

// ReadFilterConfig reads a filter config entry.
func (m *Manager) ReadFilterConfig(filterID uint32) (FilterConfig, error) {
	zm, ok := m.maps["filter_configs"]
	if !ok {
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
	zm, ok := m.maps["filter_rules"]
	if !ok {
		return fmt.Errorf("filter_rules not found")
	}
	return zm.Update(index, rule, ebpf.UpdateAny)
}

// SetPolicerConfig writes a policer configuration entry.
func (m *Manager) SetPolicerConfig(id uint32, cfg PolicerConfig) error {
	zm, ok := m.maps["policer_configs"]
	if !ok {
		return fmt.Errorf("policer_configs map not found")
	}
	return zm.Update(id, cfg, ebpf.UpdateAny)
}

// ClearPolicerConfigs zeroes all policer_configs entries.
func (m *Manager) ClearPolicerConfigs() error {
	zm, ok := m.maps["policer_configs"]
	if !ok {
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
	zm, ok := m.maps["filter_configs"]
	if !ok {
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
	zm, ok := m.maps["filter_counters"]
	if !ok {
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
	zm, ok := m.maps["filter_counters"]
	if !ok {
		return fmt.Errorf("filter_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < MaxFilterRules; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}
