package cluster

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
		m.peerTransferOutOverride[rgID] = reqID
		peerGroup := m.peerGroups[rgID]
		peerGroup.GroupID = rgID
		peerGroup.State = StateSecondaryHold
		m.peerGroups[rgID] = peerGroup
		if rg := m.groups[rgID]; rg != nil {
			rg.PeerPriority = peerGroup.Priority
		}
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
		if currentReqID, ok := m.peerTransferOutOverride[rgID]; ok && currentReqID == reqID {
			delete(m.peerTransferOutOverride, rgID)
		}
	}
	m.runElection()
}

func (m *Manager) notePeerTransferCommittedBatch(rgIDs []int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		delete(m.peerTransferOutOverride, rgID)
		peerGroup, ok := m.peerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.State = StateSecondary
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
		if oldState != rg.State {
			m.sendEvent(rg.GroupID, oldState, rg.State, "Peer transfer committed batch")
		}
	}
	return nil
}
