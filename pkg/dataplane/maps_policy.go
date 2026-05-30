package dataplane

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// Policy / zone / address-book / application map accessors.
// Same-package split of maps.go (#1686): zone configs, zone-pair policy sets,
// policy rules, address books + membership, applications, default policy, the
// scheduler-driven Active-flag toggle, and the policy hit counters.

// SetZoneConfig writes a zone configuration entry.
func (m *Manager) SetZoneConfig(zoneID uint16, cfg ZoneConfig) error {
	zm, ok := m.maps["zone_configs"]
	if !ok {
		return fmt.Errorf("zone_configs map not found")
	}
	return zm.Update(uint32(zoneID), cfg, ebpf.UpdateAny)
}

// SetZonePairPolicy writes a zone-pair policy set entry.
// The zone_pair_policies map is an ARRAY keyed by flat index:
// from_zone * MaxZones + to_zone.
func (m *Manager) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error {
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	key := uint32(fromZone)*MaxZones + uint32(toZone)
	return zm.Update(key, ps, ebpf.UpdateAny)
}

// SetPolicyRule writes a policy rule at the computed flat index.
func (m *Manager) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	zm, ok := m.maps["policy_rules"]
	if !ok {
		return fmt.Errorf("policy_rules map not found")
	}
	idx := policySetID*MaxRulesPerPolicy + ruleIndex
	return zm.Update(idx, rule, ebpf.UpdateAny)
}

// SetAddressBookEntry writes an LPM trie entry for an address.
// Auto-detects IPv4 vs IPv6 from the CIDR and routes to the correct map.
func (m *Manager) SetAddressBookEntry(cidr string, addressID uint32) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	ones, _ := ipNet.Mask.Size()

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		zm, ok := m.maps["address_book_v4"]
		if !ok {
			return fmt.Errorf("address_book_v4 map not found")
		}
		key := LPMKeyV4{
			PrefixLen: uint32(ones),
			Addr:      binary.BigEndian.Uint32(ip4),
		}
		val := AddrValue{AddressID: addressID}
		return zm.Update(key, val, ebpf.UpdateAny)
	}

	// IPv6
	zm, ok := m.maps["address_book_v6"]
	if !ok {
		return fmt.Errorf("address_book_v6 map not found")
	}
	key := LPMKeyV6{
		PrefixLen: uint32(ones),
	}
	copy(key.Addr[:], ipNet.IP.To16())
	val := AddrValue{AddressID: addressID}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// SetAddressMembership writes an address-set membership entry.
// This maps (resolvedID, setID) -> 1, indicating that resolvedID
// is a member of the address-set identified by setID.
func (m *Manager) SetAddressMembership(resolvedID, setID uint32) error {
	zm, ok := m.maps["address_membership"]
	if !ok {
		return fmt.Errorf("address_membership map not found")
	}
	key := AddrMembershipKey{IP: resolvedID, AddressID: setID}
	val := uint8(1)
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearAddressBookV4 removes all entries from the address_book_v4 LPM trie.
func (m *Manager) ClearAddressBookV4() error {
	zm, ok := m.maps["address_book_v4"]
	if !ok {
		return fmt.Errorf("address_book_v4 map not found")
	}
	var key LPMKeyV4
	iter := zm.Iterate()
	var keys []LPMKeyV4
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// ClearAddressBookV6 removes all entries from the address_book_v6 LPM trie.
func (m *Manager) ClearAddressBookV6() error {
	zm, ok := m.maps["address_book_v6"]
	if !ok {
		return fmt.Errorf("address_book_v6 map not found")
	}
	var key LPMKeyV6
	iter := zm.Iterate()
	var keys []LPMKeyV6
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// ClearAddressMembership removes all entries from the address_membership map.
func (m *Manager) ClearAddressMembership() error {
	zm, ok := m.maps["address_membership"]
	if !ok {
		return fmt.Errorf("address_membership map not found")
	}
	var key AddrMembershipKey
	iter := zm.Iterate()
	var keys []AddrMembershipKey
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetApplication writes an application map entry.
func (m *Manager) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	zm, ok := m.maps["applications"]
	if !ok {
		return fmt.Errorf("applications map not found")
	}
	key := AppKey{
		Protocol: protocol,
		DstPort:  htons(dstPort),
	}
	val := AppValue{
		AppID:       appID,
		ALGType:     algType,
		Timeout:     timeout,
		SrcPortLow:  srcPortLow,
		SrcPortHigh: srcPortHigh,
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// SetAppRange writes a range-based application entry at the given index.
func (m *Manager) SetAppRange(index uint32, entry AppRangeEntry) error {
	zm, ok := m.maps["app_ranges"]
	if !ok {
		return fmt.Errorf("app_ranges map not found")
	}
	return zm.Update(index, entry, ebpf.UpdateAny)
}

// ClearAppRanges zeros all app_ranges entries.
func (m *Manager) ClearAppRanges() error {
	zm, ok := m.maps["app_ranges"]
	if !ok {
		return fmt.Errorf("app_ranges map not found")
	}
	zero := AppRangeEntry{}
	for i := uint32(0); i < MaxAppRanges; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// ClearZonePairPolicies zeros all zone-pair policy entries.
// The map is an ARRAY so entries cannot be deleted — zero means "no policy".
func (m *Manager) ClearZonePairPolicies() error {
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	zeroPS := PolicySet{}
	var key uint32
	var val PolicySet
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if val.NumRules > 0 {
			zm.Update(key, zeroPS, ebpf.UpdateAny)
		}
	}
	return nil
}

// ClearApplications deletes all application map entries.
func (m *Manager) ClearApplications() error {
	zm, ok := m.maps["applications"]
	if !ok {
		return fmt.Errorf("applications map not found")
	}
	var key AppKey
	iter := zm.Iterate()
	var keys []AppKey
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetDefaultPolicy writes the global default policy action (0=deny, 1=permit).
func (m *Manager) SetDefaultPolicy(action uint8) error {
	zm, ok := m.maps["default_policy"]
	if !ok {
		return fmt.Errorf("default_policy map not found")
	}
	return zm.Update(uint32(0), action, ebpf.UpdateAny)
}

// UpdatePolicyScheduleState iterates policy rules and toggles the Active flag
// based on scheduler state. Only rules whose scheduler state changed are updated.
func (m *Manager) UpdatePolicyScheduleState(_ *config.Config, activeState map[string]bool) {
	zm, ok := m.maps["policy_rules"]
	if !ok {
		return
	}
	result := m.LastCompileResult()
	if result == nil {
		return
	}

	for _, slot := range result.PolicyScheduleRuleSlots {
		active, exists := activeState[slot.SchedulerName]
		if !exists {
			active = true // default active if scheduler not found
		}

		idx := slot.PolicySetID*MaxRulesPerPolicy + slot.RuleIndex
		var rule PolicyRule
		if err := zm.Lookup(idx, &rule); err != nil {
			continue
		}

		var newActive uint8
		if active {
			newActive = 1
		}
		if rule.Active != newActive {
			rule.Active = newActive
			zm.Update(idx, rule, ebpf.UpdateAny)
			slog.Info("policy schedule state updated",
				"policy", slot.PolicyName,
				"scheduler", slot.SchedulerName,
				"active", active)
		}
	}
}

// ReadPolicyCounters reads the per-CPU policy counter values and sums them.
func (m *Manager) ReadPolicyCounters(policyID uint32) (CounterValue, error) {
	zm, ok := m.maps["policy_counters"]
	if !ok {
		return CounterValue{}, fmt.Errorf("policy_counters map not found")
	}
	var perCPU []CounterValue
	if err := zm.Lookup(policyID, &perCPU); err != nil {
		return CounterValue{}, err
	}
	var total CounterValue
	for _, v := range perCPU {
		total.Packets += v.Packets
		total.Bytes += v.Bytes
	}
	return total, nil
}

// ClearPolicyCounters zeroes all policy counter entries.
func (m *Manager) ClearPolicyCounters() error {
	zm, ok := m.maps["policy_counters"]
	if !ok {
		return fmt.Errorf("policy_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < 4096; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}
