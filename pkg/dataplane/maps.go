package dataplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
)

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

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ipToUint32BE converts a net.IP to a uint32 matching the in-memory layout
// that BPF programs use when copying __be32 fields (e.g. iph->daddr).
// The IP address bytes are stored as-is; on little-endian hosts this means
// the uint32 numeric value differs from the big-endian interpretation, but
// the byte pattern in the BPF map key matches what BPF writes.
func ipToUint32BE(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(ip4)
}

// ipTo16Bytes converts a net.IP to a [16]byte array.
func ipTo16Bytes(ip net.IP) [16]byte {
	var b [16]byte
	copy(b[:], ip.To16())
	return b
}

// --- Hitless restart: delete-stale methods ---
// These methods remove map entries that are no longer present in the new config,
// AFTER new entries have been written. This avoids the clear-then-repopulate
// window where BPF programs see empty maps.

// DeleteStaleIfaceZone removes iface_zone_map entries not in the written set.
func (m *Manager) DeleteStaleIfaceZone(written map[IfaceZoneKey]bool) {
	zm, ok := m.maps["iface_zone_map"]
	if !ok {
		return
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	var stale []IfaceZoneKey
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale iface_zone entries", "count", len(stale))
	}
}

// DeleteStaleVlanIface removes vlan_iface_map entries not in the written set.
func (m *Manager) DeleteStaleVlanIface(written map[uint32]bool) {
	zm, ok := m.maps["vlan_iface_map"]
	if !ok {
		return
	}
	var key uint32
	var val VlanIfaceInfo
	iter := zm.Iterate()
	var stale []uint32
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale vlan_iface entries", "count", len(stale))
	}
}

// DeleteStaleZonePairPolicies zeros zone_pair_policies entries not in the written set.
// The map is an ARRAY so entries cannot be deleted — zero means "no policy".
func (m *Manager) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
		return
	}
	zeroPS := PolicySet{}
	var key uint32
	var val PolicySet
	iter := zm.Iterate()
	count := 0
	for iter.Next(&key, &val) {
		if val.NumRules == 0 {
			continue // already empty
		}
		fromZone := uint16(key / MaxZones)
		toZone := uint16(key % MaxZones)
		zpk := ZonePairKey{FromZone: fromZone, ToZone: toZone}
		if !written[zpk] {
			zm.Update(key, zeroPS, ebpf.UpdateAny)
			count++
		}
	}
	if count > 0 {
		slog.Info("zeroed stale zone_pair_policies entries", "count", count)
	}
}

// DeleteStaleApplications removes application entries not in the written set.
func (m *Manager) DeleteStaleApplications(written map[AppKey]bool) {
	zm, ok := m.maps["applications"]
	if !ok {
		return
	}
	var key AppKey
	var val []byte
	iter := zm.Iterate()
	var stale []AppKey
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale application entries", "count", len(stale))
	}
}

// DeleteStaleSNATRules zeroes snat_rules ARRAY entries not in the written set.
// The map is an ARRAY so entries cannot be deleted — zero means "no rule".
func (m *Manager) DeleteStaleSNATRules(written map[SNATKey]bool) {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return
	}
	empty := SNATValue{}
	var key uint32
	var val SNATValue
	iter := zm.Iterate()
	count := 0
	for iter.Next(&key, &val) {
		if val.Mode == 0 && val.SrcAddrID == 0 && val.DstAddrID == 0 {
			continue // already empty
		}
		fromZone := uint16(key / (MaxZones * MaxSNATRulesPerPair))
		rem := key % (MaxZones * MaxSNATRulesPerPair)
		toZone := uint16(rem / MaxSNATRulesPerPair)
		ruleIdx := uint16(rem % MaxSNATRulesPerPair)
		sk := SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ruleIdx}
		if !written[sk] {
			zm.Update(key, empty, ebpf.UpdateAny)
			count++
		}
	}
	if count > 0 {
		slog.Info("zeroed stale snat_rules entries", "count", count)
	}
}

// DeleteStaleSNATRulesV6 zeroes snat_rules_v6 ARRAY entries not in the written set.
// The map is an ARRAY so entries cannot be deleted — zero means "no rule".
func (m *Manager) DeleteStaleSNATRulesV6(written map[SNATKey]bool) {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return
	}
	empty := SNATValueV6{}
	var key uint32
	var val SNATValueV6
	iter := zm.Iterate()
	count := 0
	for iter.Next(&key, &val) {
		if val.Mode == 0 && val.SrcAddrID == 0 && val.DstAddrID == 0 {
			continue // already empty
		}
		fromZone := uint16(key / (MaxZones * MaxSNATRulesPerPair))
		rem := key % (MaxZones * MaxSNATRulesPerPair)
		toZone := uint16(rem / MaxSNATRulesPerPair)
		ruleIdx := uint16(rem % MaxSNATRulesPerPair)
		sk := SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ruleIdx}
		if !written[sk] {
			zm.Update(key, empty, ebpf.UpdateAny)
			count++
		}
	}
	if count > 0 {
		slog.Info("zeroed stale snat_rules_v6 entries", "count", count)
	}
}

// DeleteStaleDNATStatic removes static dnat_table entries not in the written set.
func (m *Manager) DeleteStaleDNATStatic(written map[DNATKey]bool) {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return
	}
	var key DNATKey
	var val DNATValue
	iter := zm.Iterate()
	var stale []DNATKey
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic && !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale dnat_table entries", "count", len(stale))
	}
}

// DeleteStaleDNATStaticV6 removes static dnat_table_v6 entries not in the written set.
func (m *Manager) DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool) {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return
	}
	var key DNATKeyV6
	var val DNATValueV6
	iter := zm.Iterate()
	var stale []DNATKeyV6
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic && !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale dnat_table_v6 entries", "count", len(stale))
	}
}

// DeleteStaleStaticNAT removes static_nat entries not in the written sets.
func (m *Manager) DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool) {
	if zm, ok := m.maps["static_nat_v4"]; ok {
		var key StaticNATKeyV4
		var val []byte
		iter := zm.Iterate()
		var stale []StaticNATKeyV4
		for iter.Next(&key, &val) {
			if !writtenV4[key] {
				stale = append(stale, key)
			}
		}
		for _, k := range stale {
			zm.Delete(k)
		}
		if len(stale) > 0 {
			slog.Info("deleted stale static_nat_v4 entries", "count", len(stale))
		}
	}
	if zm, ok := m.maps["static_nat_v6"]; ok {
		var key StaticNATKeyV6
		var val []byte
		iter := zm.Iterate()
		var stale []StaticNATKeyV6
		for iter.Next(&key, &val) {
			if !writtenV6[key] {
				stale = append(stale, key)
			}
		}
		for _, k := range stale {
			zm.Delete(k)
		}
		if len(stale) > 0 {
			slog.Info("deleted stale static_nat_v6 entries", "count", len(stale))
		}
	}
}

// DeleteStaleNPTv6 removes nptv6_rules entries not in the written set.
func (m *Manager) DeleteStaleNPTv6(written map[NPTv6Key]bool) {
	zm, ok := m.maps["nptv6_rules"]
	if !ok {
		return
	}
	var key NPTv6Key
	var val []byte
	iter := zm.Iterate()
	var stale []NPTv6Key
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale nptv6_rules entries", "count", len(stale))
	}
}

// DeleteStaleNAT64 zeroes stale nat64_configs entries and removes stale prefix map entries.
func (m *Manager) DeleteStaleNAT64(count uint32, writtenPrefixes map[NAT64PrefixKey]bool) {
	if zm, ok := m.maps["nat64_configs"]; ok {
		var empty NAT64Config
		for i := count; i < 4; i++ {
			zm.Update(i, empty, ebpf.UpdateAny)
		}
	}
	if hm, ok := m.maps["nat64_prefix_map"]; ok {
		var key NAT64PrefixKey
		var val []byte
		iter := hm.Iterate()
		var stale []NAT64PrefixKey
		for iter.Next(&key, &val) {
			if !writtenPrefixes[key] {
				stale = append(stale, key)
			}
		}
		for _, k := range stale {
			hm.Delete(k)
		}
	}
}

// ZeroStaleScreenConfigs zeroes screen_configs entries above maxID.
func (m *Manager) ZeroStaleScreenConfigs(maxID uint32) {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return
	}
	empty := ScreenConfig{}
	for i := maxID + 1; i < 64; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
}

// ZeroStaleNATPoolConfigs zeroes nat_pool_configs and nat_pool_ips entries
// for pool IDs from startID onwards.
func (m *Manager) ZeroStaleNATPoolConfigs(startID uint32) {
	if zm, ok := m.maps["nat_pool_configs"]; ok {
		empty := NATPoolConfig{}
		for i := startID; i < 32; i++ {
			zm.Update(i, empty, ebpf.UpdateAny)
		}
	}
	if v4Map, ok := m.maps["nat_pool_ips_v4"]; ok {
		var zeroV4 uint32
		start := startID * MaxNATPoolIPsPerPool
		end := uint32(32) * MaxNATPoolIPsPerPool
		for i := start; i < end; i++ {
			v4Map.Update(i, zeroV4, ebpf.UpdateAny)
		}
	}
	if v6Map, ok := m.maps["nat_pool_ips_v6"]; ok {
		zeroV6 := NATPoolIPV6{}
		start := startID * MaxNATPoolIPsPerPool
		end := uint32(32) * MaxNATPoolIPsPerPool
		for i := start; i < end; i++ {
			v6Map.Update(i, zeroV6, ebpf.UpdateAny)
		}
	}
}

// DeleteStaleIfaceFilter removes iface_filter_map entries not in the written set.
func (m *Manager) DeleteStaleIfaceFilter(written map[IfaceFilterKey]bool) {
	zm, ok := m.maps["iface_filter_map"]
	if !ok {
		return
	}
	var key IfaceFilterKey
	var val []byte
	iter := zm.Iterate()
	var stale []IfaceFilterKey
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale iface_filter entries", "count", len(stale))
	}
}

// ZeroStaleFilterConfigs zeroes filter_configs entries from startID onwards.
func (m *Manager) ZeroStaleFilterConfigs(startID uint32) {
	zm, ok := m.maps["filter_configs"]
	if !ok {
		return
	}
	var empty FilterConfig
	for i := startID; i < MaxFilterConfigs; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
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

// MapStats holds utilization info for a BPF map.
type MapStats struct {
	Name       string
	Type       string
	MaxEntries uint32
	UsedCount  uint32
	KeySize    uint32
	ValueSize  uint32
}

// GetMapStats returns utilization statistics for key BPF maps.
func (m *Manager) GetMapStats() []MapStats {
	// Maps to report on and whether to count entries (only for hash maps)
	reportMaps := []struct {
		name      string
		countable bool // hash maps can be iterated; arrays cannot meaningfully count
	}{
		{"sessions", true},
		{"sessions_v6", true},
		{"zone_configs", false},
		{"policy_rules", false},
		{"address_book_v4", true},
		{"address_book_v6", true},
		{"address_membership", true},
		{"applications", true},
		{"snat_rules", false},
		{"dnat_table", true},
		{"dnat_table_v6", true},
		{"nat_pool_config", false},
		{"screen_profiles", false},
		{"global_counters", false},
		{"policy_counters", false},
		{"filter_rules", true},
	}

	var stats []MapStats
	for _, rm := range reportMaps {
		bm, ok := m.maps[rm.name]
		if !ok || bm == nil {
			continue
		}
		info, err := bm.Info()
		if err != nil {
			continue
		}
		ms := MapStats{
			Name:       rm.name,
			Type:       info.Type.String(),
			MaxEntries: info.MaxEntries,
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
		}

		if rm.countable {
			// Count entries by iterating the map
			var count uint32
			iter := bm.Iterate()
			var key, val []byte
			for iter.Next(&key, &val) {
				count++
			}
			ms.UsedCount = count
		}

		stats = append(stats, ms)
	}
	return stats
}
