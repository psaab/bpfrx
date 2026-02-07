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
func (m *Manager) SetAddressBookEntry(cidr string, addressID uint32) error {
	zm, ok := m.maps["address_book_v4"]
	if !ok {
		return fmt.Errorf("address_book_v4 map not found")
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	ones, _ := ipNet.Mask.Size()
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 addresses supported: %s", cidr)
	}

	key := LPMKeyV4{
		PrefixLen: uint32(ones),
		Addr:      binary.BigEndian.Uint32(ip4),
	}
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
