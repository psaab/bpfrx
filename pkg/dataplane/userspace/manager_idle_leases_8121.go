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

// ExportPersistentLeaseDisplay returns every persistent-NAT lease this node
// would HONOUR — the allocator's own reuse predicate, `active_flows > 0 ||
// expires_at_ns > now_ns` — for the SHOW table (#8615).
//
// This is the read ExportIdleLeases cannot be: that one is filtered to the IDLE
// population because it feeds the HA sync path, where carrying a live-flow count
// is forbidden. This verb feeds a display only, travels on its own record type,
// and has no import counterpart.
//
// Same SuppressStatus discipline and same slow cadence as the calls above — the
// caller is the 30s show-table refresher, not an interactive path.
func (m *Manager) ExportPersistentLeaseDisplay() ([]DisplayLeaseWire, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "export_persistent_lease_display",
		SuppressStatus: true,
	})
	return displayLeasesFromResponse(resp, err)
}

// ErrPersistentLeaseDisplayUnsupported means the running helper predates #8615
// and does not implement the display verb. The caller degrades to
// ExportIdleLeases, which answers the same question for the IDLE population
// only.
//
// A distinct sentinel rather than a generic error because the two outcomes have
// different remedies AND different truth: "this helper is older, you are seeing
// the idle half" is a degraded but honest table, while a genuine failure must
// leave the previous snapshot standing rather than assert an emptiness nobody
// observed (#8607).
var ErrPersistentLeaseDisplayUnsupported = errors.New(
	"userspace helper does not support export_persistent_lease_display")

// displayLeasesFromResponse is the classification half, extracted from the
// request path for the reason sessionCountersFromResponse states: the request
// path has no test seam, and an inline choice cannot be bound by a test.
//
// An UNSUPPORTED verb must not become an empty result. Returning `nil, nil` for
// an old helper would tell the refresher "this node holds no bindings", which
// renders as "No persistent NAT bindings" — the exact false statement #8607
// exists to remove, now produced by the fix for #8615.
func displayLeasesFromResponse(resp ControlResponse, err error) ([]DisplayLeaseWire, error) {
	if err != nil {
		if isUnknownVerbError(err) {
			return nil, ErrPersistentLeaseDisplayUnsupported
		}
		return nil, err
	}
	return resp.DisplayLeases, nil
}
