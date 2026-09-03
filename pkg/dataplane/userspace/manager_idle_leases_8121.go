package userspace

import "errors"

// #8121: idle persistent-NAT lease export/import over the helper control
// socket.
//
// Both calls set SuppressStatus. The control socket is shared with the 1/s
// status poll, HA session sync, session installs, snapshot sync and forwarding
// sync, and CLAUDE.md is explicit that a new caller at >1/s starves session
// installs during bulk sync. These run on a slow cadence (see the daemon's lease
// ticker) and have no use for a status blob, so they neither ask for one nor pay
// to carry it back.

// ExportIdleLeases returns every persistent-NAT lease this node holds that has
// NO live flows but is still inside its persistence timeout — the population
// session sync cannot observe, because a lease is learned from a session.
func (m *Manager) ExportIdleLeases() ([]IdleLeaseWire, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "export_idle_leases",
		SuppressStatus: true,
	})
	if err != nil {
		return nil, err
	}
	return resp.IdleLeases, nil
}

// ImportIdleLeases installs a peer's idle leases. A nil/empty batch is a no-op
// rather than a round trip: on a healthy pair most pushes carry nothing, and
// spending a socket turn to say so is the contention this file's header is
// about.
func (m *Manager) ImportIdleLeases(leases []IdleLeaseWire) error {
	if len(leases) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return errors.New("userspace dataplane helper not running")
	}
	_, err := m.requestDetailedLocked(ControlRequest{
		Type:           "import_idle_leases",
		SuppressStatus: true,
		IdleLeases:     leases,
	})
	return err
}
