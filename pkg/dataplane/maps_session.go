package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/cilium/ebpf"
)

// Conntrack session-table map accessors.
// Same-package split of maps.go (#1686): iterate/batch/get/set/delete for the
// v4 and v6 session maps, session counting, full-table clear (which also drops
// the associated dynamic DNAT entries — see ClearAllSessions), and the
// node-scoped session-ID counter seed.

// IterateSessions iterates all session entries, calling fn for each.
// fn receives the key and value; return false to stop iteration.
//
// When the userspace dataplane is active, this map contains mirrored
// sessions written by the Rust helper's publish_bpf_conntrack_entry.
// The helper periodically refreshes LastSeen (~10s) so callers see
// reasonably accurate idle times.  Session lifetime is owned by the
// helper, not Go GC (GC.SkipSweep is set).  See #333.
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

// SetSessionV4 writes a v4 session entry (used by cluster sync to install sessions from peer).
func (m *Manager) SetSessionV4(key SessionKey, val SessionValue) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}
	return sm.Update(key, val, ebpf.UpdateAny)
}

// GetSessionV4 looks up a single v4 session entry by key.
func (m *Manager) GetSessionV4(key SessionKey) (SessionValue, error) {
	sm, ok := m.maps["sessions"]
	if !ok {
		return SessionValue{}, fmt.Errorf("sessions map not found")
	}
	var val SessionValue
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValue{}, err
	}
	return val, nil
}

// GetSessionV6 looks up a single v6 session entry by key.
func (m *Manager) GetSessionV6(key SessionKeyV6) (SessionValueV6, error) {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return SessionValueV6{}, fmt.Errorf("sessions_v6 map not found")
	}
	var val SessionValueV6
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValueV6{}, err
	}
	return val, nil
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

// IterateSessionsFrom iterates v4 session entries starting after cursorKey.
// If cursorKey is nil, iteration starts from the beginning.
// fn returns false to stop iteration.
func (m *Manager) IterateSessionsFrom(cursorKey *SessionKey, fn func(SessionKey, SessionValue) bool) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}

	var nextKey SessionKey
	var startKey interface{} = cursorKey
	if cursorKey == nil {
		startKey = nil
	}

	// Get the first key to iterate from.
	if err := sm.NextKey(startKey, &nextKey); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // no entries or cursor at end
		}
		return fmt.Errorf("sessions NextKey: %w", err)
	}

	for {
		var val SessionValue
		if err := sm.Lookup(nextKey, &val); err != nil {
			// Entry may have been deleted between NextKey and Lookup; skip.
			var next SessionKey
			if err := sm.NextKey(nextKey, &next); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					return nil
				}
				return fmt.Errorf("sessions NextKey: %w", err)
			}
			nextKey = next
			continue
		}
		if !fn(nextKey, val) {
			return nil
		}
		var next SessionKey
		if err := sm.NextKey(nextKey, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil // end of map
			}
			return fmt.Errorf("sessions NextKey: %w", err)
		}
		nextKey = next
	}
}

// IterateSessionsV6From iterates v6 session entries starting after cursorKey.
// If cursorKey is nil, iteration starts from the beginning.
// fn returns false to stop iteration.
func (m *Manager) IterateSessionsV6From(cursorKey *SessionKeyV6, fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}

	var nextKey SessionKeyV6
	var startKey interface{} = cursorKey
	if cursorKey == nil {
		startKey = nil
	}

	if err := sm.NextKey(startKey, &nextKey); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("sessions_v6 NextKey: %w", err)
	}

	for {
		var val SessionValueV6
		if err := sm.Lookup(nextKey, &val); err != nil {
			var next SessionKeyV6
			if err := sm.NextKey(nextKey, &next); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					return nil
				}
				return fmt.Errorf("sessions_v6 NextKey: %w", err)
			}
			nextKey = next
			continue
		}
		if !fn(nextKey, val) {
			return nil
		}
		var next SessionKeyV6
		if err := sm.NextKey(nextKey, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return fmt.Errorf("sessions_v6 NextKey: %w", err)
		}
		nextKey = next
	}
}

// BatchIterateSessions iterates sessions using batch lookup for reduced
// kernel lock contention.  Yields between batches so BPF datapath isn't
// starved of hash-table bucket locks.
func (m *Manager) BatchIterateSessions(fn func(SessionKey, SessionValue) bool) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}

	const batchSize = 256
	keys := make([]SessionKey, batchSize)
	vals := make([]SessionValue, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i]) {
				return nil
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // done
		}
		if err != nil {
			return fmt.Errorf("batch lookup sessions: %w", err)
		}
		runtime.Gosched() // yield to reduce lock contention with BPF datapath
	}
}

// BatchIterateSessionsV6 is the IPv6 variant of BatchIterateSessions.
func (m *Manager) BatchIterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}

	const batchSize = 256
	keys := make([]SessionKeyV6, batchSize)
	vals := make([]SessionValueV6, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i]) {
				return nil
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("batch lookup sessions_v6: %w", err)
		}
		runtime.Gosched()
	}
}

// BatchDeleteSessions deletes multiple session entries in a single syscall.
func (m *Manager) BatchDeleteSessions(keys []SessionKey) (int, error) {
	sm, ok := m.maps["sessions"]
	if !ok {
		return 0, fmt.Errorf("sessions map not found")
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return sm.BatchDelete(keys, nil)
}

// BatchDeleteSessionsV6 deletes multiple IPv6 session entries in a single syscall.
func (m *Manager) BatchDeleteSessionsV6(keys []SessionKeyV6) (int, error) {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return 0, fmt.Errorf("sessions_v6 map not found")
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return sm.BatchDelete(keys, nil)
}

// DeleteSessionV6 deletes an IPv6 session entry by key.
func (m *Manager) DeleteSessionV6(key SessionKeyV6) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}
	return sm.Delete(key)
}

// SetSessionV6 writes a v6 session entry (used by cluster sync to install sessions from peer).
func (m *Manager) SetSessionV6(key SessionKeyV6, val SessionValueV6) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}
	return sm.Update(key, val, ebpf.UpdateAny)
}

// SessionCount returns the number of active IPv4 and IPv6 sessions.
// Only forward entries are counted (IsReverse == 0).
func (m *Manager) SessionCount() (v4, v6 int) {
	if sm, ok := m.maps["sessions"]; ok {
		var key SessionKey
		var val SessionValue
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v4++
			}
		}
	}
	if sm, ok := m.maps["sessions_v6"]; ok {
		var key SessionKeyV6
		var val SessionValueV6
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v6++
			}
		}
	}
	return
}

// ClearAllSessions deletes all IPv4 and IPv6 sessions, plus associated
// dynamic DNAT table entries for SNAT sessions. Returns (v4_deleted, v6_deleted, err).
func (m *Manager) ClearAllSessions() (int, int, error) {
	v4Deleted := 0
	v6Deleted := 0

	// IPv4: collect all keys and SNAT entries for DNAT cleanup
	var v4Keys []SessionKey
	var snatDNATKeys []DNATKey
	if err := m.IterateSessions(func(key SessionKey, val SessionValue) bool {
		v4Keys = append(v4Keys, key)
		// Track dynamic SNAT sessions for dnat_table cleanup
		if val.IsReverse == 0 &&
			val.Flags&SessFlagSNAT != 0 &&
			val.Flags&SessFlagStaticNAT == 0 {
			snatDNATKeys = append(snatDNATKeys, DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
				FromZone: 0,
			})
		}
		return true
	}); err != nil {
		return 0, 0, fmt.Errorf("iterate sessions: %w", err)
	}
	for _, key := range v4Keys {
		if err := m.DeleteSession(key); err == nil {
			v4Deleted++
		}
	}
	for _, dk := range snatDNATKeys {
		m.DeleteDNATEntry(dk)
	}

	// IPv6: collect all keys and SNAT entries for DNAT cleanup
	var v6Keys []SessionKeyV6
	var snatDNATKeysV6 []DNATKeyV6
	if err := m.IterateSessionsV6(func(key SessionKeyV6, val SessionValueV6) bool {
		v6Keys = append(v6Keys, key)
		if val.IsReverse == 0 &&
			val.Flags&SessFlagSNAT != 0 &&
			val.Flags&SessFlagStaticNAT == 0 {
			snatDNATKeysV6 = append(snatDNATKeysV6, DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
				FromZone: 0,
			})
		}
		return true
	}); err != nil {
		return v4Deleted, 0, fmt.Errorf("iterate sessions_v6: %w", err)
	}
	for _, key := range v6Keys {
		if err := m.DeleteSessionV6(key); err == nil {
			v6Deleted++
		}
	}
	for _, dk := range snatDNATKeysV6 {
		m.DeleteDNATEntryV6(dk)
	}

	return v4Deleted, v6Deleted, nil
}

// SeedSessionIDCounter seeds the session_id_gen PERCPU map with a
// node-specific base to avoid collisions between cluster nodes.
// Each CPU gets base = (nodeID << 48) | (cpuIndex << 32).
func (m *Manager) SeedSessionIDCounter(nodeID int) {
	zm, ok := m.maps["session_id_gen"]
	if !ok {
		return
	}
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil || numCPUs <= 0 {
		return
	}
	vals := make([]uint64, numCPUs)
	for i := range vals {
		vals[i] = (uint64(nodeID) << 48) | (uint64(i) << 32)
	}
	if err := zm.Update(uint32(0), vals, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to seed session ID counter", "err", err)
		return
	}
	slog.Info("seeded session ID counter", "nodeID", nodeID, "cpus", numCPUs)
}
