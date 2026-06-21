package dataplane

import (
	"fmt"
	"log/slog"
	"math/rand/v2"

	"github.com/cilium/ebpf"
)

// NAT map accessors.
// Same-package split of maps.go (#1686): DNAT/SNAT rules, NAT pools, SNAT
// egress IPs, static 1:1 NAT, NAT64, NPTv6, plus the NAT-specific rule/port
// counters and the port-counter seed. NAT counters live here (not
// maps_counters.go) by the #1686 rule that domain-specific counters stay with
// their domain.

// SetDNATEntry writes a dnat_table entry.
func (m *Manager) SetDNATEntry(key DNATKey, val DNATValue) error {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return fmt.Errorf("dnat_table map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// DeleteDNATEntry deletes a dnat_table entry.
func (m *Manager) DeleteDNATEntry(key DNATKey) error {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return fmt.Errorf("dnat_table map not found")
	}
	return zm.Delete(key)
}

// ClearDNATStatic deletes all static (flags=1) dnat_table entries.
func (m *Manager) ClearDNATStatic() error {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return fmt.Errorf("dnat_table map not found")
	}
	var key DNATKey
	var val DNATValue
	iter := zm.Iterate()
	var toDelete []DNATKey
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic {
			toDelete = append(toDelete, key)
		}
	}
	for _, k := range toDelete {
		zm.Delete(k)
	}
	return nil
}

// SetSNATRule writes a snat_rules entry at the computed flat index.
// The snat_rules map is an ARRAY keyed by flat index:
// from_zone * MaxZones * MaxSNATRulesPerPair + to_zone * MaxSNATRulesPerPair + rule_idx.
func (m *Manager) SetSNATRule(fromZone, toZone, ruleIdx uint16, val SNATValue) error {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return fmt.Errorf("snat_rules map not found")
	}
	key := uint32(fromZone)*MaxZones*MaxSNATRulesPerPair + uint32(toZone)*MaxSNATRulesPerPair + uint32(ruleIdx)
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATRules zeroes all snat_rules entries (ARRAY map semantics).
func (m *Manager) ClearSNATRules() error {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return fmt.Errorf("snat_rules map not found")
	}
	empty := SNATValue{}
	for i := uint32(0); i < MaxZones*MaxZones*MaxSNATRulesPerPair; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// SetDNATEntryV6 writes a dnat_table_v6 entry.
func (m *Manager) SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return fmt.Errorf("dnat_table_v6 map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// DeleteDNATEntryV6 deletes a dnat_table_v6 entry.
func (m *Manager) DeleteDNATEntryV6(key DNATKeyV6) error {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return fmt.Errorf("dnat_table_v6 map not found")
	}
	return zm.Delete(key)
}

// ClearDNATStaticV6 deletes all static (flags=1) dnat_table_v6 entries.
func (m *Manager) ClearDNATStaticV6() error {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return fmt.Errorf("dnat_table_v6 map not found")
	}
	var key DNATKeyV6
	var val DNATValueV6
	iter := zm.Iterate()
	var toDelete []DNATKeyV6
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic {
			toDelete = append(toDelete, key)
		}
	}
	for _, k := range toDelete {
		zm.Delete(k)
	}
	return nil
}

// SetSNATRuleV6 writes a snat_rules_v6 entry at the computed flat index.
// The snat_rules_v6 map is an ARRAY keyed by flat index:
// from_zone * MaxZones * MaxSNATRulesPerPair + to_zone * MaxSNATRulesPerPair + rule_idx.
func (m *Manager) SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val SNATValueV6) error {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return fmt.Errorf("snat_rules_v6 map not found")
	}
	key := uint32(fromZone)*MaxZones*MaxSNATRulesPerPair + uint32(toZone)*MaxSNATRulesPerPair + uint32(ruleIdx)
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATRulesV6 zeroes all snat_rules_v6 entries (ARRAY map semantics).
func (m *Manager) ClearSNATRulesV6() error {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return fmt.Errorf("snat_rules_v6 map not found")
	}
	empty := SNATValueV6{}
	for i := uint32(0); i < MaxZones*MaxZones*MaxSNATRulesPerPair; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// SetNATPoolConfig writes a NAT pool configuration entry.
func (m *Manager) SetNATPoolConfig(poolID uint32, cfg NATPoolConfig) error {
	zm, ok := m.maps["nat_pool_configs"]
	if !ok {
		return fmt.Errorf("nat_pool_configs map not found")
	}
	return zm.Update(poolID, cfg, ebpf.UpdateAny)
}

// SetNATPoolIPV4 writes an IPv4 address to a NAT pool IP slot.
func (m *Manager) SetNATPoolIPV4(poolID, index uint32, ip uint32) error {
	zm, ok := m.maps["nat_pool_ips_v4"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v4 map not found")
	}
	mapIdx := poolID*MaxNATPoolIPsPerPool + index
	return zm.Update(mapIdx, ip, ebpf.UpdateAny)
}

// SetNATPoolIPV6 writes an IPv6 address to a NAT pool IP slot.
func (m *Manager) SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error {
	zm, ok := m.maps["nat_pool_ips_v6"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v6 map not found")
	}
	mapIdx := poolID*MaxNATPoolIPsPerPool + index
	val := NATPoolIPV6{IP: ip}
	return zm.Update(mapIdx, val, ebpf.UpdateAny)
}

// ClearNATPoolConfigs zeroes all nat_pool_configs entries.
func (m *Manager) ClearNATPoolConfigs() error {
	zm, ok := m.maps["nat_pool_configs"]
	if !ok {
		return fmt.Errorf("nat_pool_configs map not found")
	}
	empty := NATPoolConfig{}
	for i := uint32(0); i < 32; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// ClearNATPoolIPs zeroes all nat_pool_ips_v4 and nat_pool_ips_v6 entries.
func (m *Manager) ClearNATPoolIPs() error {
	v4Map, ok := m.maps["nat_pool_ips_v4"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v4 map not found")
	}
	v6Map, ok := m.maps["nat_pool_ips_v6"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v6 map not found")
	}
	maxEntries := uint32(32 * MaxNATPoolIPsPerPool)
	var zeroV4 uint32
	zeroV6 := NATPoolIPV6{}
	for i := uint32(0); i < maxEntries; i++ {
		v4Map.Update(i, zeroV4, ebpf.UpdateAny)
		v6Map.Update(i, zeroV6, ebpf.UpdateAny)
	}
	return nil
}

// SetSNATEgressIP writes a per-interface SNAT address for interface-mode SNAT.
func (m *Manager) SetSNATEgressIP(key SNATEgressKey, val SNATEgressValue) error {
	zm, ok := m.maps["snat_egress_ips"]
	if !ok {
		return fmt.Errorf("snat_egress_ips map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATEgressIPs deletes all snat_egress_ips entries.
func (m *Manager) ClearSNATEgressIPs() error {
	zm, ok := m.maps["snat_egress_ips"]
	if !ok {
		return fmt.Errorf("snat_egress_ips map not found")
	}
	var key SNATEgressKey
	iter := zm.Iterate()
	var keys []SNATEgressKey
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetStaticNATEntryV4 writes a static NAT v4 entry.
func (m *Manager) SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error {
	zm, ok := m.maps["static_nat_v4"]
	if !ok {
		return fmt.Errorf("static_nat_v4 map not found")
	}
	key := StaticNATKeyV4{IP: ip, Direction: direction}
	return zm.Update(key, translated, ebpf.UpdateAny)
}

// SetStaticNATEntryV6 writes a static NAT v6 entry.
func (m *Manager) SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error {
	zm, ok := m.maps["static_nat_v6"]
	if !ok {
		return fmt.Errorf("static_nat_v6 map not found")
	}
	key := StaticNATKeyV6{IP: ip, Direction: direction}
	val := StaticNATValueV6{IP: translated}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearStaticNATEntries deletes all static_nat_v4 and static_nat_v6 entries.
func (m *Manager) ClearStaticNATEntries() error {
	// Clear v4
	if zm, ok := m.maps["static_nat_v4"]; ok {
		var key StaticNATKeyV4
		iter := zm.Iterate()
		var keys []StaticNATKeyV4
		var val []byte
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			zm.Delete(k)
		}
	}
	// Clear v6
	if zm, ok := m.maps["static_nat_v6"]; ok {
		var key StaticNATKeyV6
		iter := zm.Iterate()
		var keys []StaticNATKeyV6
		var val []byte
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			zm.Delete(k)
		}
	}
	return nil
}

// SetNAT64Config writes a NAT64 prefix config at the given index and hash map.
func (m *Manager) SetNAT64Config(index uint32, cfg NAT64Config) error {
	zm, ok := m.maps["nat64_configs"]
	if !ok {
		return fmt.Errorf("nat64_configs not found")
	}
	if err := zm.Update(index, cfg, ebpf.UpdateAny); err != nil {
		return err
	}
	// Also write to the hash map for O(1) lookup in BPF
	hm, ok := m.maps["nat64_prefix_map"]
	if ok {
		key := NAT64PrefixKey{Prefix: cfg.Prefix}
		hm.Update(key, cfg, ebpf.UpdateAny)
	}
	return nil
}

// SetNAT64Count writes the number of active NAT64 prefixes.
func (m *Manager) SetNAT64Count(count uint32) error {
	zm, ok := m.maps["nat64_count"]
	if !ok {
		return fmt.Errorf("nat64_count not found")
	}
	var zero uint32
	return zm.Update(zero, count, ebpf.UpdateAny)
}

// ClearNAT64Configs zeroes all NAT64 config entries and sets count to 0.
func (m *Manager) ClearNAT64Configs() error {
	zm, ok := m.maps["nat64_configs"]
	if !ok {
		return fmt.Errorf("nat64_configs not found")
	}
	var empty NAT64Config
	for i := uint32(0); i < 4; i++ { // MAX_NAT64_PREFIXES
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	// Clear the hash map
	if hm, ok := m.maps["nat64_prefix_map"]; ok {
		var key NAT64PrefixKey
		var val []byte
		iter := hm.Iterate()
		var keys []NAT64PrefixKey
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			hm.Delete(k)
		}
	}
	return m.SetNAT64Count(0)
}

// SetNPTv6Rule writes an NPTv6 prefix translation rule.
func (m *Manager) SetNPTv6Rule(key NPTv6Key, val NPTv6Value) error {
	zm, ok := m.maps["nptv6_rules"]
	if !ok {
		return fmt.Errorf("nptv6_rules map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ReadNATRuleCounter returns the per-rule NAT translation hit total for a
// counter ID (#2218). The value is the userspace-reported offset: the Rust
// userspace dataplane never writes the legacy nat_rule_counters BPF array map
// (the #1476 eBPF retirement dropped the XDP increment), it reports per-rule
// hits over the status channel, which the userspace Manager mirrors here via
// SetNATRuleCounterOffset.
//
// #2255: counter IDs are now a stable key-derived hash (sparse u32), not a
// dense [0,256) array index, so this read path keys the sparse offset map
// directly and never indexes the legacy 256-entry nat_rule_counters array
// (a hash id ≥ MaxNATRuleCounters would fail that bounded Lookup). The legacy
// array only ever held zeros at runtime, so dropping the Lookup changes no
// observable value.
func (m *Manager) ReadNATRuleCounter(counterID uint32) (CounterValue, error) {
	m.mu.Lock()
	offset := m.natRuleCounterOffsets[counterID]
	m.mu.Unlock()
	return offset, nil
}

// SetNATRuleCounterOffset records the absolute cumulative per-rule NAT
// translation hit total reported by the Rust userspace dataplane for the
// given counter ID (#2218). ReadNATRuleCounter merges this offset on top of
// the BPF map value. The total is absolute (overwrites), since the helper
// reports cumulative-since-start totals on every status poll.
func (m *Manager) SetNATRuleCounterOffset(counterID uint32, val CounterValue) {
	m.mu.Lock()
	if m.natRuleCounterOffsets == nil {
		m.natRuleCounterOffsets = make(map[uint32]CounterValue)
	}
	m.natRuleCounterOffsets[counterID] = val
	m.mu.Unlock()
}

// ClearNATRuleCounterOffsets zeroes all userspace-reported NAT rule counter
// offsets (#2218). Called by ClearNATRuleCounters so an operator clear also
// drops the mirrored helper totals.
func (m *Manager) ClearNATRuleCounterOffsets() {
	m.mu.Lock()
	m.natRuleCounterOffsets = nil
	m.mu.Unlock()
}

// ClearNATRuleCounters zeroes all NAT rule counter entries.
func (m *Manager) ClearNATRuleCounters() error {
	// Drop userspace-reported offsets first so a clear takes effect even
	// without a BPF map (userspace-only runtime) (#2218).
	m.ClearNATRuleCounterOffsets()
	zm, ok := m.maps["nat_rule_counters"]
	if !ok {
		return nil
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < MaxNATRuleCounters; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// ReadNATPortCounter reads the per-CPU NAT port allocation counter for a pool
// and returns the sum across all CPUs.
func (m *Manager) ReadNATPortCounter(poolID uint32) (uint64, error) {
	zm, ok := m.maps["nat_port_counters"]
	if !ok {
		return 0, fmt.Errorf("nat_port_counters map not found")
	}
	var perCPU []NATPortCounter
	if err := zm.Lookup(poolID, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v.Counter
	}
	return total, nil
}

// SeedNATPortCounters initializes all NAT port allocation counters with a
// random offset. This prevents SNAT port reuse after daemon restart — without
// the seed, the allocator starts from port_low and reuses ports that remote
// servers may still have in ESTABLISHED state from pre-restart sessions.
func (m *Manager) SeedNATPortCounters() {
	zm, ok := m.maps["nat_port_counters"]
	if !ok {
		return
	}
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil || numCPUs <= 0 {
		return
	}
	for poolID := uint32(0); poolID < 32; poolID++ {
		vals := make([]NATPortCounter, numCPUs)
		// Only seed CPU 0; the CPU-interleaved formula ensures each CPU
		// gets a distinct sequence regardless of starting offset.
		vals[0] = NATPortCounter{Counter: rand.Uint64()}
		zm.Update(poolID, vals, ebpf.UpdateAny)
	}
	slog.Info("seeded NAT port counters with random offset")
}
