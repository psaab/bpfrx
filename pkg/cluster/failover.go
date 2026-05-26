// Package cluster — failover.go owns the entire manual-failover locking
// domain: single-RG and multi-RG (batch) manual failover protocol, the
// transfer-commit state machine (peer transfer-out overrides, transfer-
// commit grace windows, local transfer-out hold), and the heartbeat
// peer-state override application helper. Co-locating these keeps the
// shared *Locked helpers next to every caller that needs them and makes
// the "committed-failover-suppresses-stale-heartbeat" invariant
// answerable by reading this file end-to-end.
//
// Cross-file callers:
//   - heartbeat_manager.go::handlePeerHeartbeat calls
//     applyTransferCommitOverridesOnPeerStateLocked to apply pending
//     transfer-out overrides + expire grace windows while rebuilding
//     newPeerGroups.
//   - heartbeat_manager.go::handlePeerTimeout calls
//     suppressPeerTimeoutForTransferCommitLocked to keep a recent
//     transfer-commit window from triggering an immediate
//     peer-lost cascade.
//
// Both are package-private cross-file method calls on *Manager.
package cluster

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Single-RG manual failover and transfer protocol.
// =============================================================================

// ManualFailover forces a redundancy group to transfer out of primary.
// Unlike ForceSecondary, this preserves the group's monitor-derived weight
// and advertises an explicit transfer-out state so the peer can claim
// primary without relying on weight-zero election semantics.
func (m *Manager) ManualFailover(rgID int) error {
	m.mu.Lock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if m.failoverInProgress[rgID] {
		m.mu.Unlock()
		return fmt.Errorf("failover already in progress for redundancy group %d, please wait", rgID)
	}
	m.failoverInProgress[rgID] = true
	preHook := m.preManualFailoverFn
	retryTimeout := m.preManualFailoverRetryTimeout
	retryInterval := m.preManualFailoverRetryInterval
	m.mu.Unlock()

	var preHookErr error
	if preHook != nil {
		deadline := time.Now().Add(retryTimeout)
		for attempts := 1; ; attempts++ {
			if err := preHook(rgID); err != nil {
				if !IsRetryablePreFailoverError(err) {
					preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
					break
				}
				remaining := time.Until(deadline)
				if remaining <= 0 {
					preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
					break
				}
				sleep := retryInterval
				if sleep <= 0 {
					sleep = DefaultPreManualFailoverRetryInterval
				}
				if sleep > remaining {
					sleep = remaining
				}
				slog.Info("cluster: waiting to admit manual failover",
					"rg", rgID,
					"attempt", attempts,
					"remaining", remaining.String(),
					"err", err)
				time.Sleep(sleep)
				continue
			}
			break
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Always clear the in-progress flag under the same lock acquisition
	// that performs the state change, so there is no window where another
	// caller can slip in between flag-clear and state-commit.
	defer delete(m.failoverInProgress, rgID)

	if preHookErr != nil {
		return preHookErr
	}

	rg, ok = m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	oldState := rg.State
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now()
	rg.State = StateSecondaryHold
	rg.FailoverCount++
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State, "Manual failover")
	}
	slog.Info("cluster: manual failover", "rg", rgID)
	return nil
}

// ForceSecondary sets weight to 0 for all redundancy groups, forcing this node
// to become secondary. Used by ISSU to drain traffic to the peer before upgrade.
// Returns an error if the peer is not alive (no peer to take over).
func (m *Manager) ForceSecondary() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.peerAlive {
		return fmt.Errorf("peer not alive — cannot force secondary without active peer")
	}

	for _, rg := range m.groups {
		if rg.State == StateDisabled {
			continue
		}
		oldState := rg.State
		rg.Weight = 0
		rg.ManualFailover = true
		rg.ManualFailoverAt = time.Now()
		rg.State = StateSecondary
		if oldState != rg.State {
			rg.FailoverCount++
			m.sendEvent(rg.GroupID, oldState, rg.State, "Forced secondary (ISSU)")
		}
	}

	slog.Info("cluster: forced secondary for all RGs (ISSU)")
	return nil
}

// ResetFailover clears manual failover and resumes normal election.
func (m *Manager) ResetFailover(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	rg.ManualFailover = false
	rg.ManualFailoverAt = time.Time{}
	m.recalcWeight(rg) // restore weight from monitor state + run election
	slog.Info("cluster: failover reset", "rg", rgID)
	return nil
}

// FenceStatus returns the configured fencing action and history of fence events.
func (m *Manager) FenceStatus() (action string, events []HistoryEvent) {
	m.mu.RLock()
	action = m.peerFencing
	m.mu.RUnlock()
	events = m.history.Events(EventFence)
	return
}

// RequestPeerFailover asks the peer to transfer the given RG out of primary,
// making the local node eligible to become primary. Used when
// "request chassis cluster failover redundancy-group N node <local>" is run.
func (m *Manager) RequestPeerFailover(rgID int) error {
	m.mu.Lock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if rg.State == StatePrimary {
		m.mu.Unlock()
		return fmt.Errorf("node is already primary for redundancy group %d", rgID)
	}
	if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
		readySince := "<zero>"
		if !rg.ReadySince.IsZero() {
			readySince = rg.ReadySince.Format(time.RFC3339Nano)
		}
		reasons := append([]string(nil), rg.ReadinessReasons...)
		m.mu.Unlock()
		return fmt.Errorf(
			"local redundancy group %d not ready for explicit failover ready=%t ready_since=%s reasons=%v",
			rgID,
			rg.Ready,
			readySince,
			reasons,
		)
	}
	fn := m.peerFailoverFn
	commitFn := m.peerFailoverCommitFn
	transferReadyFn := m.transferReadinessFn
	peerAlive := m.peerAlive
	localCommitReadyFn := m.localTransferCommitReadyFn
	m.mu.Unlock()

	if fn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer failover not available (sync not connected)")
	}
	if commitFn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer failover commit not available (sync not connected)")
	}
	if transferReadyFn != nil {
		ready, reasons := transferReadyFn(rgID)
		if !ready {
			return fmt.Errorf(
				"local redundancy group %d not transfer-ready for explicit failover reasons=%v",
				rgID,
				append([]string(nil), reasons...),
			)
		}
	}
	reqID, err := fn(rgID)
	if err != nil {
		return err
	}
	m.mu.Lock()
	rg, ok = m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	// Preserve a local manual-failover hold until the peer has explicitly
	// acknowledged the transfer-out request. Preflight rejection or request-send
	// failure must not silently release the existing transfer-out state.
	if rg.ManualFailover {
		rg.ManualFailover = false
		rg.ManualFailoverAt = time.Time{}
		m.recalcWeight(rg)
	}
	m.mu.Unlock()
	if err := m.commitRequestedPeerFailover(rgID, reqID); err != nil {
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn([]int{rgID}); err != nil {
			m.abortRequestedPeerFailover(rgID, reqID)
			return err
		}
	}
	if err := commitFn(rgID, reqID); err != nil {
		m.abortRequestedPeerFailover(rgID, reqID)
		return err
	}
	m.notePeerTransferCommitted(rgID)
	return nil
}

func (m *Manager) commitRequestedPeerFailover(rgID int, reqID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
		readySince := "<zero>"
		if !rg.ReadySince.IsZero() {
			readySince = rg.ReadySince.Format(time.RFC3339Nano)
		}
		return fmt.Errorf(
			"redundancy group %d lost takeover readiness before transfer commit ready=%t ready_since=%s reasons=%v",
			rgID,
			rg.Ready,
			readySince,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}

	m.applyPeerTransferOutOverrideLocked(rgID, reqID)
	delete(m.peerTransferCommitGraceUntil, rgID)
	delete(m.localTransferOutHoldUntil, rgID)
	peerGroup := m.peerGroups[rgID]

	m.runElection()
	if rg.State != StatePrimary {
		return fmt.Errorf(
			"failed to commit redundancy group %d primary ownership local_state=%s peer_state=%s ready=%t reasons=%v",
			rgID,
			rg.State,
			peerGroup.State,
			rg.Ready,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}
	return nil
}

func (m *Manager) abortRequestedPeerFailover(rgID int, reqID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.restorePeerTransferOutOverrideLocked(rgID, reqID) {
		return
	}
	delete(m.peerTransferCommitGraceUntil, rgID)
	m.runElection()
}

func (m *Manager) notePeerTransferCommitted(rgID int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clearPeerTransferOutOverrideLocked(rgID)
	m.peerTransferCommitGraceUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
	peerGroup, ok := m.peerGroups[rgID]
	if !ok {
		return
	}
	peerGroup.State = StateSecondaryHold
	m.peerGroups[rgID] = peerGroup
}

// FinalizePeerTransferOut completes a previously acknowledged transfer-out
// after the peer commits ownership on the sync channel.
func (m *Manager) FinalizePeerTransferOut(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if rg.State == StatePrimary {
		return fmt.Errorf("%w: redundancy group %d still primary locally", ErrRemoteFailoverRejected, rgID)
	}
	if rg.State == StateSecondary && !rg.ManualFailover {
		return nil
	}

	oldState := rg.State
	rg.ManualFailover = false
	rg.ManualFailoverAt = time.Time{}
	rg.State = StateSecondary
	// A completed transfer-out invalidates any stale inbound-transfer view
	// from the previous owner direction. If we keep forcing the peer into
	// secondary-hold here, the next heartbeat can immediately re-elect the
	// old owner during rapid failback/failover sequences.
	delete(m.peerTransferOutOverride, rgID)
	delete(m.peerTransferCommitGraceUntil, rgID)
	m.localTransferOutHoldUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State, "Peer transfer committed")
	}
	return nil
}

// =============================================================================
// Multi-RG (batch) manual failover and transfer protocol.
//
// Folded in from the former failover_batch.go (#1541, plan v3) so the entire
// manual-failover locking domain — single-RG, batch, and the shared *Locked
// helpers — lives in one file. Gemini r2: "the entire manual-failover locking
// domain belongs in one file."
// =============================================================================

// IsSupportedClusterNodeID reports whether nodeID is a valid chassis node.
// Cluster failover targets are currently limited to the two chassis nodes.
func IsSupportedClusterNodeID(nodeID int) bool {
	return nodeID == 0 || nodeID == 1
}

func normalizeFailoverRGIDs(rgIDs []int) ([]int, error) {
	if len(rgIDs) == 0 {
		return nil, fmt.Errorf("no redundancy groups specified")
	}
	seen := make(map[int]struct{}, len(rgIDs))
	ids := make([]int, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		if _, ok := seen[rgID]; ok {
			continue
		}
		seen[rgID] = struct{}{}
		ids = append(ids, rgID)
	}
	sort.Ints(ids)
	return ids, nil
}

func failoverBatchKey(rgIDs []int) string {
	if len(rgIDs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		parts = append(parts, strconv.Itoa(rgID))
	}
	return strings.Join(parts, ",")
}

// ManualFailoverBatch forces multiple redundancy groups to transfer out of
// primary together. Used for full data-plane handoff so a paired move does not
// transiently pass through split ownership.
func (m *Manager) ManualFailoverBatch(rgIDs []int) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return m.ManualFailover(ids[0])
	}

	m.mu.Lock()
	for _, rgID := range ids {
		if _, ok := m.groups[rgID]; !ok {
			m.mu.Unlock()
			return fmt.Errorf("redundancy group %d not found", rgID)
		}
		if m.failoverInProgress[rgID] {
			m.mu.Unlock()
			return fmt.Errorf("failover already in progress for redundancy groups %v, please wait", ids)
		}
	}
	for _, rgID := range ids {
		m.failoverInProgress[rgID] = true
	}
	preHook := m.preManualFailoverFn
	retryTimeout := m.preManualFailoverRetryTimeout
	retryInterval := m.preManualFailoverRetryInterval
	m.mu.Unlock()

	var preHookErr error
	if preHook != nil {
		for _, rgID := range ids {
			deadline := time.Now().Add(retryTimeout)
			for attempts := 1; ; attempts++ {
				if err := preHook(rgID); err != nil {
					if !IsRetryablePreFailoverError(err) {
						preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
						break
					}
					remaining := time.Until(deadline)
					if remaining <= 0 {
						preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
						break
					}
					sleep := retryInterval
					if sleep <= 0 {
						sleep = DefaultPreManualFailoverRetryInterval
					}
					if sleep > remaining {
						sleep = remaining
					}
					slog.Info("cluster: waiting to admit manual failover batch",
						"rgs", ids,
						"rg", rgID,
						"attempt", attempts,
						"remaining", remaining.String(),
						"err", err)
					time.Sleep(sleep)
					continue
				}
				break
			}
			if preHookErr != nil {
				break
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		for _, rgID := range ids {
			delete(m.failoverInProgress, rgID)
		}
	}()

	if preHookErr != nil {
		return preHookErr
	}

	now := time.Now()
	for _, rgID := range ids {
		rg := m.groups[rgID]
		oldState := rg.State
		rg.ManualFailover = true
		rg.ManualFailoverAt = now
		rg.State = StateSecondaryHold
		rg.FailoverCount++
		if oldState != rg.State {
			m.sendEvent(rg.GroupID, oldState, rg.State, "Manual failover batch")
		}
	}
	slog.Info("cluster: manual failover batch", "rgs", ids)
	return nil
}

// RequestPeerFailoverBatch asks the peer to transfer multiple redundancy
// groups out of primary and commits local ownership in one election pass.
func (m *Manager) RequestPeerFailoverBatch(rgIDs []int) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return m.RequestPeerFailover(ids[0])
	}

	m.mu.Lock()
	for _, rgID := range ids {
		rg, ok := m.groups[rgID]
		if !ok {
			m.mu.Unlock()
			return fmt.Errorf("redundancy group %d not found", rgID)
		}
		if rg.State == StatePrimary {
			m.mu.Unlock()
			return fmt.Errorf("node is already primary for redundancy groups %v", ids)
		}
		if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
			readySince := "<zero>"
			if !rg.ReadySince.IsZero() {
				readySince = rg.ReadySince.Format(time.RFC3339Nano)
			}
			reasons := append([]string(nil), rg.ReadinessReasons...)
			m.mu.Unlock()
			return fmt.Errorf(
				"local redundancy group %d not ready for explicit failover ready=%t ready_since=%s reasons=%v",
				rgID,
				rg.Ready,
				readySince,
				reasons,
			)
		}
	}
	fn := m.peerFailoverBatchFn
	commitFn := m.peerFailoverCommitBatchFn
	transferReadyFn := m.transferReadinessFn
	peerAlive := m.peerAlive
	localCommitReadyFn := m.localTransferCommitReadyFn
	m.mu.Unlock()

	if fn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer batch failover not available (sync not connected)")
	}
	if commitFn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer batch failover commit not available (sync not connected)")
	}
	if transferReadyFn != nil {
		for _, rgID := range ids {
			ready, reasons := transferReadyFn(rgID)
			if !ready {
				return fmt.Errorf(
					"local redundancy group %d not transfer-ready for explicit failover reasons=%v",
					rgID,
					append([]string(nil), reasons...),
				)
			}
		}
	}

	reqID, err := fn(ids)
	if err != nil {
		return err
	}

	m.mu.Lock()
	for _, rgID := range ids {
		rg := m.groups[rgID]
		if rg != nil && rg.ManualFailover {
			rg.ManualFailover = false
			rg.ManualFailoverAt = time.Time{}
			m.recalcWeight(rg)
		}
	}
	m.mu.Unlock()

	if err := m.commitRequestedPeerFailoverBatch(ids, reqID); err != nil {
		m.abortRequestedPeerFailoverBatch(ids, reqID)
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn(ids); err != nil {
			m.abortRequestedPeerFailoverBatch(ids, reqID)
			return err
		}
	}
	if err := commitFn(ids, reqID); err != nil {
		m.abortRequestedPeerFailoverBatch(ids, reqID)
		return err
	}
	m.notePeerTransferCommittedBatch(ids)
	return nil
}

func (m *Manager) commitRequestedPeerFailoverBatch(rgIDs []int, reqID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		rg, ok := m.groups[rgID]
		if !ok {
			return fmt.Errorf("redundancy group %d not found", rgID)
		}
		if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
			readySince := "<zero>"
			if !rg.ReadySince.IsZero() {
				readySince = rg.ReadySince.Format(time.RFC3339Nano)
			}
			return fmt.Errorf(
				"redundancy group %d lost takeover readiness before transfer commit ready=%t ready_since=%s reasons=%v",
				rgID,
				rg.Ready,
				readySince,
				append([]string(nil), rg.ReadinessReasons...),
			)
		}
	}

	for _, rgID := range rgIDs {
		m.applyPeerTransferOutOverrideLocked(rgID, reqID)
		delete(m.peerTransferCommitGraceUntil, rgID)
		delete(m.localTransferOutHoldUntil, rgID)
	}

	m.runElection()
	for _, rgID := range rgIDs {
		rg := m.groups[rgID]
		peerGroup := m.peerGroups[rgID]
		if rg == nil || rg.State == StatePrimary {
			continue
		}
		return fmt.Errorf(
			"failed to commit redundancy groups %v primary ownership local_rg=%d local_state=%s peer_state=%s ready=%t reasons=%v",
			rgIDs,
			rgID,
			rg.State,
			peerGroup.State,
			rg.Ready,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}
	return nil
}

func (m *Manager) abortRequestedPeerFailoverBatch(rgIDs []int, reqID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		delete(m.peerTransferCommitGraceUntil, rgID)
		m.restorePeerTransferOutOverrideLocked(rgID, reqID)
	}
	m.runElection()
}

func (m *Manager) notePeerTransferCommittedBatch(rgIDs []int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		m.clearPeerTransferOutOverrideLocked(rgID)
		m.peerTransferCommitGraceUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
		peerGroup, ok := m.peerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.State = StateSecondaryHold
		m.peerGroups[rgID] = peerGroup
	}
}

// FinalizePeerTransferOutBatch completes a previously acknowledged multi-RG
// transfer after the peer commits ownership on the sync channel.
func (m *Manager) FinalizePeerTransferOutBatch(rgIDs []int) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return m.FinalizePeerTransferOut(ids[0])
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range ids {
		rg, ok := m.groups[rgID]
		if !ok {
			return fmt.Errorf("redundancy group %d not found", rgID)
		}
		if rg.State == StatePrimary {
			return fmt.Errorf("%w: redundancy group %d still primary locally", ErrRemoteFailoverRejected, rgID)
		}
	}

	for _, rgID := range ids {
		rg := m.groups[rgID]
		if rg.State == StateSecondary && !rg.ManualFailover {
			continue
		}
		oldState := rg.State
		rg.ManualFailover = false
		rg.ManualFailoverAt = time.Time{}
		rg.State = StateSecondary
		// Clear stale inbound-transfer markers from the previous direction
		// before we park this node as the old owner. Otherwise the next peer
		// heartbeat can still force the peer into secondary-hold and snap the
		// RG back during rapid alternating moves.
		delete(m.peerTransferOutOverride, rgID)
		delete(m.peerTransferCommitGraceUntil, rgID)
		m.localTransferOutHoldUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
		if oldState != rg.State {
			m.sendEvent(rg.GroupID, oldState, rg.State, "Peer transfer committed batch")
		}
	}
	return nil
}

// =============================================================================
// Transfer-commit state machine *Locked helpers.
//
// All callers (single-RG, batch, and the heartbeat-driven peer-state apply
// helper below) live in this file. heartbeat_manager.go::handlePeerTimeout
// calls suppressPeerTimeoutForTransferCommitLocked across the file boundary
// — that is the one cross-file dependency by design.
// =============================================================================

func (m *Manager) applyPeerTransferOutOverrideLocked(rgID int, reqID uint64) {
	previous, ok := m.peerGroups[rgID]
	m.peerTransferOutOverride[rgID] = reqID
	m.peerTransferOutPrevious[rgID] = peerGroupSnapshot{
		state:   previous,
		present: ok,
	}
	peerGroup := previous
	peerGroup.GroupID = rgID
	peerGroup.State = StateSecondaryHold
	m.peerGroups[rgID] = peerGroup
	if rg := m.groups[rgID]; rg != nil {
		rg.PeerPriority = peerGroup.Priority
	}
}

func (m *Manager) clearPeerTransferOutOverrideLocked(rgID int) {
	delete(m.peerTransferOutOverride, rgID)
	delete(m.peerTransferOutPrevious, rgID)
}

func (m *Manager) restorePeerTransferOutOverrideLocked(rgID int, reqID uint64) bool {
	currentReqID, ok := m.peerTransferOutOverride[rgID]
	if !ok || currentReqID != reqID {
		return false
	}
	delete(m.peerTransferOutOverride, rgID)
	snapshot, hadSnapshot := m.peerTransferOutPrevious[rgID]
	delete(m.peerTransferOutPrevious, rgID)
	if hadSnapshot && snapshot.present {
		// A fresh heartbeat can race this restore and overwrite peerGroups
		// with newer live state. If that happens we may briefly put the older
		// snapshot back here, but the next heartbeat corrects it again.
		m.peerGroups[rgID] = snapshot.state
	} else {
		delete(m.peerGroups, rgID)
	}
	if rg := m.groups[rgID]; rg != nil {
		if snapshot.present {
			rg.PeerPriority = snapshot.state.Priority
		} else {
			rg.PeerPriority = 0
		}
	}
	return true
}

func (m *Manager) transferCommitGracePeriodLocked() time.Duration {
	grace := 2*time.Duration(m.hbThreshold)*m.hbInterval + transferCommitHeartbeatSlack
	if grace < minTransferCommitGracePeriod {
		grace = minTransferCommitGracePeriod
	}
	return grace
}

func (m *Manager) suppressPeerTimeoutForTransferCommitLocked(now time.Time) (bool, string) {
	activeRGs := make([]int, 0, len(m.localTransferOutHoldUntil))
	for rgID, until := range m.localTransferOutHoldUntil {
		if now.Before(until) {
			activeRGs = append(activeRGs, rgID)
			continue
		}
		delete(m.localTransferOutHoldUntil, rgID)
	}
	if len(activeRGs) == 0 {
		return false, ""
	}
	sort.Ints(activeRGs)
	return true, fmt.Sprintf("recent transfer commit grace active rgs=%v", activeRGs)
}

// applyTransferCommitOverridesOnPeerStateLocked applies pending peer
// transfer-out overrides and expires transfer-commit grace windows while
// handlePeerHeartbeat rebuilds the peer-groups map. Called once per heartbeat
// from heartbeat_manager.go::handlePeerHeartbeat, after newPeerGroups has been
// freshly populated from the heartbeat packet and before m.peerGroups is
// replaced.
//
// The three loops are lifted verbatim from the inline block that previously
// lived in handlePeerHeartbeat (cluster.go pre-#1541 lines 1516-1541).
// Encapsulating them here keeps the entire transfer-commit state machine
// (override map, grace windows, expiry, suppression) co-located in
// failover.go so reviewers can trace the "committed-failover-suppresses-
// stale-heartbeat" invariant by reading one file end-to-end.
//
// The helper takes newPeerGroups as the map being rebuilt (Go maps are
// reference types, so mutations on the parameter are visible to the caller)
// and now as the heartbeat reception timestamp. m.peerTransferOutOverride,
// m.peerTransferCommitGraceUntil, and m.localTransferOutHoldUntil are
// read/mutated through the *Manager receiver as before. Caller must hold
// m.mu write-locked (matching the existing handlePeerHeartbeat protocol).
func (m *Manager) applyTransferCommitOverridesOnPeerStateLocked(newPeerGroups map[int]PeerGroupState, now time.Time) {
	for rgID := range m.peerTransferOutOverride {
		peerGroup, ok := newPeerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.GroupID = rgID
		peerGroup.State = StateSecondaryHold
		newPeerGroups[rgID] = peerGroup
	}
	for rgID, until := range m.peerTransferCommitGraceUntil {
		if !now.Before(until) {
			delete(m.peerTransferCommitGraceUntil, rgID)
			continue
		}
		peerGroup, ok := newPeerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.GroupID = rgID
		peerGroup.State = StateSecondaryHold
		newPeerGroups[rgID] = peerGroup
	}
	for rgID, until := range m.localTransferOutHoldUntil {
		if !now.Before(until) {
			delete(m.localTransferOutHoldUntil, rgID)
		}
	}
}
