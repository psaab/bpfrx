package dataplane

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// SetZoneConfig writes a zone configuration entry.
func (m *Manager) SetZoneConfig(zoneID uint16, cfg ZoneConfig) error {
	zm, ok := m.maps["zone_configs"]
	if !ok {
		return fmt.Errorf("zone_configs map not found")
	}
	return zm.Update(uint32(zoneID), cfg, ebpf.UpdateAny)
}

// SetZonePairPolicy writes a zone-pair policy set entry.
func (m *Manager) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error {
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	key := ZonePairKey{FromZone: fromZone, ToZone: toZone}
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

// SetApplication writes an application map entry.
func (m *Manager) SetApplication(protocol uint8, dstPort uint16, appID uint32) error {
	zm, ok := m.maps["applications"]
	if !ok {
		return fmt.Errorf("applications map not found")
	}
	key := AppKey{
		Protocol: protocol,
		DstPort:  htons(dstPort),
	}
	val := AppValue{AppID: appID}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// IterateSessions iterates all session entries, calling fn for each.
// fn receives the key and value; return false to stop iteration.
func (m *Manager) IterateSessions(fn func(SessionKey, SessionValue) bool) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}

	var key SessionKey
	var val SessionValue
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val) {
			break
		}
	}
	return iter.Err()
}

// DeleteSession deletes a session entry by key.
func (m *Manager) DeleteSession(key SessionKey) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}
	return sm.Delete(key)
}

// ClearZonePairPolicies deletes all zone-pair policy entries.
func (m *Manager) ClearZonePairPolicies() error {
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	var key ZonePairKey
	iter := zm.Iterate()
	var keys []ZonePairKey
	for iter.Next(&key, nil) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
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
	for iter.Next(&key, nil) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

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

// SetSNATRule writes a snat_rules entry.
func (m *Manager) SetSNATRule(fromZone, toZone uint16, val SNATValue) error {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return fmt.Errorf("snat_rules map not found")
	}
	key := SNATKey{FromZone: fromZone, ToZone: toZone}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATRules deletes all snat_rules entries.
func (m *Manager) ClearSNATRules() error {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return fmt.Errorf("snat_rules map not found")
	}
	var key SNATKey
	iter := zm.Iterate()
	var keys []SNATKey
	for iter.Next(&key, nil) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// IterateSessionsV6 iterates all IPv6 session entries, calling fn for each.
func (m *Manager) IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}

	var key SessionKeyV6
	var val SessionValueV6
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val) {
			break
		}
	}
	return iter.Err()
}

// DeleteSessionV6 deletes an IPv6 session entry by key.
func (m *Manager) DeleteSessionV6(key SessionKeyV6) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}
	return sm.Delete(key)
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

// SetSNATRuleV6 writes a snat_rules_v6 entry.
func (m *Manager) SetSNATRuleV6(fromZone, toZone uint16, val SNATValueV6) error {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return fmt.Errorf("snat_rules_v6 map not found")
	}
	key := SNATKey{FromZone: fromZone, ToZone: toZone}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATRulesV6 deletes all snat_rules_v6 entries.
func (m *Manager) ClearSNATRulesV6() error {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return fmt.Errorf("snat_rules_v6 map not found")
	}
	var key SNATKey
	iter := zm.Iterate()
	var keys []SNATKey
	for iter.Next(&key, nil) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
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

// SetScreenConfig writes a screen profile configuration entry.
func (m *Manager) SetScreenConfig(profileID uint32, cfg ScreenConfig) error {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return fmt.Errorf("screen_configs map not found")
	}
	return zm.Update(profileID, cfg, ebpf.UpdateAny)
}

// ClearScreenConfigs zeroes all screen_configs entries.
func (m *Manager) ClearScreenConfigs() error {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return fmt.Errorf("screen_configs map not found")
	}
	empty := ScreenConfig{}
	for i := uint32(0); i < 64; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// ReadInterfaceCounters reads the per-CPU interface counter values and sums them.
func (m *Manager) ReadInterfaceCounters(ifindex int) (InterfaceCounterValue, error) {
	zm, ok := m.maps["interface_counters"]
	if !ok {
		return InterfaceCounterValue{}, fmt.Errorf("interface_counters map not found")
	}
	var perCPU []InterfaceCounterValue
	if err := zm.Lookup(uint32(ifindex), &perCPU); err != nil {
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

// SetDefaultPolicy writes the global default policy action (0=deny, 1=permit).
func (m *Manager) SetDefaultPolicy(action uint8) error {
	zm, ok := m.maps["default_policy"]
	if !ok {
		return fmt.Errorf("default_policy map not found")
	}
	return zm.Update(uint32(0), action, ebpf.UpdateAny)
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ipToUint32BE converts a net.IP to a uint32 in network byte order.
func ipToUint32BE(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

// ipTo16Bytes converts a net.IP to a [16]byte array.
func ipTo16Bytes(ip net.IP) [16]byte {
	var b [16]byte
	copy(b[:], ip.To16())
	return b
}
