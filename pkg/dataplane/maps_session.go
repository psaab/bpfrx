package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// IsKeyNotFound reports whether err is a map "key does not exist" error
// from a session/DNAT/companion delete or lookup. It keeps the
// github.com/cilium/ebpf sentinel behind the dataplane boundary so
// operator packages (pkg/cli, pkg/grpcapi) can classify a delete result
// without importing the BPF-artifact package directly (the
// retirement-boundary canary forbids that import). It treats both
// ebpf.ErrKeyNotExist and unix.ENOENT as not-found.
//
// Used by the session-clear paths (#2468): a NAT'd session's reverse
// companion is keyed on the TRANSLATED tuple, so the naive-swap reverse
// key and the DNAT companion key are frequently absent on an otherwise
// successful clear — a benign idempotent not-found, not a failure.
func IsKeyNotFound(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, unix.ENOENT)
}

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
	var val bpfSessionValue
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val.sessionValue()) {
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
	return sm.Update(key, val.toBPF(), ebpf.UpdateAny)
}

// GetSessionV4 looks up a single v4 session entry by key.
func (m *Manager) GetSessionV4(key SessionKey) (SessionValue, error) {
	sm, ok := m.maps["sessions"]
	if !ok {
		return SessionValue{}, fmt.Errorf("sessions map not found")
	}
	var val bpfSessionValue
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValue{}, err
	}
	return val.sessionValue(), nil
}

// GetSessionV6 looks up a single v6 session entry by key.
func (m *Manager) GetSessionV6(key SessionKeyV6) (SessionValueV6, error) {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return SessionValueV6{}, fmt.Errorf("sessions_v6 map not found")
	}
	var val bpfSessionValueV6
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValueV6{}, err
	}
	return val.sessionValue(), nil
}

// IterateSessionsV6 iterates all IPv6 session entries, calling fn for each.
func (m *Manager) IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}

	var key SessionKeyV6
	var val bpfSessionValueV6
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val.sessionValue()) {
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
		var val bpfSessionValue
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
		if !fn(nextKey, val.sessionValue()) {
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
		var val bpfSessionValueV6
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
		if !fn(nextKey, val.sessionValue()) {
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
	vals := make([]bpfSessionValue, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i].sessionValue()) {
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
	vals := make([]bpfSessionValueV6, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i].sessionValue()) {
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
	return sm.Update(key, val.toBPF(), ebpf.UpdateAny)
}

// SessionCount returns the number of active IPv4 and IPv6 sessions.
// Only forward entries are counted (IsReverse == 0).
func (m *Manager) SessionCount() (v4, v6 int) {
	if sm, ok := m.maps["sessions"]; ok {
		var key SessionKey
		var val bpfSessionValue
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v4++
			}
		}
	}
	if sm, ok := m.maps["sessions_v6"]; ok {
		var key SessionKeyV6
		var val bpfSessionValueV6
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v6++
			}
		}
	}
	return
}

// sessionClearBatchObserver, when non-nil, is invoked with the number of keys
// passed to each BPF_MAP_DELETE_BATCH syscall issued by the full-table clear
// path (clearSessionsV4/clearSessionsV6). It is a test-only seam that lets a
// unit test assert the batched delete path is taken so a regression back to a
// per-key delete loop (#4719) is detectable. Production leaves it nil (a single
// non-hot-path nil check per chunk).
var sessionClearBatchObserver func(batchKeys int)

// ClearAllSessions deletes all IPv4 and IPv6 sessions, plus associated
// dynamic DNAT table entries for SNAT sessions. Returns (v4_deleted, v6_deleted, err).
//
// The full table can hold up to ~10M sessions, so the clear must not
// monopolize the controller goroutine — a multi-second synchronous stall can
// starve the HA peer watchdog/heartbeat and trip a spurious failover (#4719).
// Both phases are therefore cooperative: collection uses the batch-lookup
// iterators (BatchIterateSessions{,V6}, which yield via runtime.Gosched between
// batches), and deletion uses chunked BPF_MAP_DELETE_BATCH syscalls that yield
// between chunks (clearSessionsV4/clearSessionsV6). Semantics are unchanged:
// every session — both the forward and the reverse conntrack entry — is still
// removed, plus the dynamic dnat_table entries for SNAT sessions.
func (m *Manager) ClearAllSessions() (int, int, error) {
	// IPv4: collect all keys and SNAT entries for DNAT cleanup
	var v4Keys []SessionKey
	var snatDNATKeys []DNATKey
	if err := m.BatchIterateSessions(func(key SessionKey, val SessionValue) bool {
		v4Keys = append(v4Keys, key)
		// Track dynamic SNAT sessions for dnat_table cleanup
		if val.IsReverse == 0 &&
			val.Flags&SessFlagSNAT != 0 &&
			val.Flags&SessFlagStaticNAT == 0 {
			// Must match the write-side key encoding (#2406: host-order port).
			snatDNATKeys = append(snatDNATKeys, dnatKeyForSessionV4(key, val))
		}
		return true
	}); err != nil {
		return 0, 0, fmt.Errorf("iterate sessions: %w", err)
	}
	v4Deleted := m.clearSessionsV4(v4Keys)
	for i, dk := range snatDNATKeys {
		m.DeleteDNATEntry(dk)
		if (i+1)%sessionDeleteBatchSize == 0 {
			runtime.Gosched()
		}
	}

	// IPv6: collect all keys and SNAT entries for DNAT cleanup
	var v6Keys []SessionKeyV6
	var snatDNATKeysV6 []DNATKeyV6
	if err := m.BatchIterateSessionsV6(func(key SessionKeyV6, val SessionValueV6) bool {
		v6Keys = append(v6Keys, key)
		if val.IsReverse == 0 &&
			val.Flags&SessFlagSNAT != 0 &&
			val.Flags&SessFlagStaticNAT == 0 {
			// Must match the write-side key encoding (#2406: host-order port).
			snatDNATKeysV6 = append(snatDNATKeysV6, dnatKeyForSessionV6(key, val))
		}
		return true
	}); err != nil {
		return v4Deleted, 0, fmt.Errorf("iterate sessions_v6: %w", err)
	}
	v6Deleted := m.clearSessionsV6(v6Keys)
	for i, dk := range snatDNATKeysV6 {
		m.DeleteDNATEntryV6(dk)
		if (i+1)%sessionDeleteBatchSize == 0 {
			runtime.Gosched()
		}
	}

	return v4Deleted, v6Deleted, nil
}

// clearSessionsV4 deletes every key in keys from the v4 session map using
// chunked BPF_MAP_DELETE_BATCH syscalls (sessionDeleteBatchSize keys per
// syscall) instead of one syscall per key, yielding between chunks so a
// full-table clear cannot monopolize the controller goroutine (#4719). It
// returns the number of entries deleted.
//
// A key removed concurrently (GC/datapath) between collection and delete is
// tolerated: the kernel stops the batch at the first missing key, so the chunk
// remainder is retried one key at a time to guarantee every key is attempted
// and the clear stays complete (never a partial clear reported as done). The
// same per-key fallback covers a map that does not support batch delete.
func (m *Manager) clearSessionsV4(keys []SessionKey) int {
	deleted := 0
	for len(keys) > 0 {
		n := sessionDeleteBatchSize
		if len(keys) < n {
			n = len(keys)
		}
		chunk := keys[:n]
		cnt, err := m.BatchDeleteSessions(chunk)
		if cnt < 0 {
			cnt = 0
		} else if cnt > len(chunk) {
			cnt = len(chunk)
		}
		deleted += cnt
		if sessionClearBatchObserver != nil {
			sessionClearBatchObserver(n)
		}
		if err != nil {
			// Batch stopped early (a key vanished, or batch delete is
			// unsupported): finish the chunk remainder per-key so the clear
			// is complete. The first cnt keys were already deleted above.
			for _, k := range chunk[cnt:] {
				if delErr := m.DeleteSession(k); delErr == nil {
					deleted++
				}
			}
		}
		keys = keys[n:]
		runtime.Gosched()
	}
	return deleted
}

// clearSessionsV6 is the IPv6 variant of clearSessionsV4.
func (m *Manager) clearSessionsV6(keys []SessionKeyV6) int {
	deleted := 0
	for len(keys) > 0 {
		n := sessionDeleteBatchSize
		if len(keys) < n {
			n = len(keys)
		}
		chunk := keys[:n]
		cnt, err := m.BatchDeleteSessionsV6(chunk)
		if cnt < 0 {
			cnt = 0
		} else if cnt > len(chunk) {
			cnt = len(chunk)
		}
		deleted += cnt
		if sessionClearBatchObserver != nil {
			sessionClearBatchObserver(n)
		}
		if err != nil {
			for _, k := range chunk[cnt:] {
				if delErr := m.DeleteSessionV6(k); delErr == nil {
					deleted++
				}
			}
		}
		keys = keys[n:]
		runtime.Gosched()
	}
	return deleted
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
