package userspace

// Per-zone flood-counter clear plumbing (#3651), the sibling of
// zonecounters.go for the SYN/ICMP/UDP flood-event family.
//
// There is no dedicated operator "clear flood counters" command today: the
// per-zone flood offsets are dropped by dataplane.Manager.ClearAllCounters,
// which is what `clear firewall all`, the REST stats reset, and the gRPC
// counter reset all resolve to. So the helper-side reset rides that same path
// (Manager.ClearAllCounters below calls clearHelperFloodCountersLocked). If a
// dedicated clear is ever added, it must call this helper too -- clearing only
// the Go offset map is undone by the next status poll.

// clearHelperFloodCountersLocked sends the clear_flood_counters IPC to the Rust
// helper so its FloodCounterStore resets to zero, then records the refreshed
// (zeroed) status. Mirrors clearHelperZoneCountersLocked. Caller holds m.mu.
//
// This is the load-bearing half of the clear. The helper reports cumulative
// per-zone flood counts on every 1/s status poll and syncBPFCountersLocked
// REPLACES the offset map from that snapshot (ReplaceFloodCounterOffsets), so
// zeroing only the Go map would be undone within <=1s.
//
// After the IPC clear the zone reads as NOT POPULATED, not as zero: the helper's
// snapshot is sparse and omits all-zero rows, so a just-cleared zone produces no
// row and the Go replacement drops its offset -- ReadFloodCounters then returns
// ErrCounterNotPopulated and the surfaces render "not available" until the next
// flood drop repopulates the row.
//
// With no live helper process the cached helper-reported flood counters in
// m.lastStatus are dropped directly so a clear takes effect even in the
// userspace-only / pre-start state (parity with the bpfShim offset clear).
func (m *Manager) clearHelperFloodCountersLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		m.lastStatus.ZoneFloodCounters = nil
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "clear_flood_counters"}, &status); err != nil {
		return err
	}
	m.recordHelperStatusLocked(&status)
	return nil
}
