package dataplane

import "sync"

// #7191: publication of the arm-coverage proof so it can GATE rather than only
// log.
//
// Before this, ProveArmCoverage ran after every attach and its verdict was
// discarded at the call site (loader.go). That made the per-interface attach a
// blind spot in the arm posture: attachUserspaceShimXDP treats a NATIVE attach
// failure as a warning and continues, and even the GENERIC failure path returns
// an error that is joined as a deferred commit error rather than disarming. So
// a box where Start() succeeded but an interface never got a shim reported
// itself armed and kept ip_forward=1, with nothing adjudicating that
// interface's transit — the same class of hole #5275 closed at whole-box
// granularity, one layer down.
//
// This publishes the LAST report only. It deliberately does not accumulate
// history: the gate asks "is the dataplane covered NOW", and a stale report
// answering for a previous generation is worse than no report.

type armCoverageCell struct {
	mu     sync.RWMutex
	report ArmCoverageReport
	seen   bool
}

// publishArmCoverage records the most recent proof.
func (m *Manager) publishArmCoverage(r ArmCoverageReport) {
	if m == nil {
		return
	}
	m.armCoverage.mu.Lock()
	m.armCoverage.report = r
	m.armCoverage.seen = true
	m.armCoverage.mu.Unlock()
}

// ArmCoverageSummary returns the most recent proof reduced to PRIMITIVES.
//
// Primitives, not the report type, so pkg/daemon can consume the verdict
// without importing pkg/dataplane. That keeps the #1451 retirement-boundary
// import allowlist from growing an entry for a gate that needs four numbers —
// the boundary exists to shrink, and widening it for a diagnostic would be the
// wrong direction.
func (m *Manager) ArmCoverageSummary() (uncovered, total int, ran, seen bool) {
	rep, ok := m.lastArmCoverage()
	return rep.Uncovered, len(rep.Surfaces), rep.Ran, ok
}

// lastArmCoverage returns the most recent arm-coverage report and whether one
// has EVER been published.
//
// The boolean is not redundant with the report's own Ran field, and conflating
// them is the bug this signature exists to prevent. Three states must stay
// distinct for a fail-closed consumer:
//
//	seen==false          -> no proof has run yet (pre-first-apply). NOT evidence
//	                        of anything; a consumer must not gate on it.
//	seen && !Ran         -> a proof ran but could not classify.
//	seen && Ran          -> a real verdict; Uncovered is meaningful.
//
// Collapsing the first into "uncovered" would disarm every box before its first
// apply — a brick, not a fence (#1960).
func (m *Manager) lastArmCoverage() (ArmCoverageReport, bool) {
	if m == nil {
		return ArmCoverageReport{}, false
	}
	m.armCoverage.mu.RLock()
	defer m.armCoverage.mu.RUnlock()
	return m.armCoverage.report, m.armCoverage.seen
}
