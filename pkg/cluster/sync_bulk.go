package cluster

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"time"

	"github.com/psaab/bpfrx/pkg/dataplane"
)

// BulkSync sends all locally-owned forward sessions to the peer.
// doBulkSync runs BulkSyncOverride if set, otherwise falls back to BulkSync.
// When the override is used, sessions are delivered as incremental updates
// (via event stream), but we still send BulkStart/BulkEnd markers so the
// peer completes the bulk receive handshake (releasing sync hold, etc.).
// The peer sees an empty bulk and skips stale reconciliation.
func (s *SessionSync) doBulkSync() error {
	if s.BulkSyncOverride != nil {
		slog.Info("cluster sync: using bulk sync override (event stream)")
		if err := s.BulkSyncOverride(); err != nil {
			slog.Warn("cluster sync: bulk sync override failed, falling back", "err", err)
			return s.BulkSync()
		}
		// Send empty BulkStart/BulkEnd so the peer completes the
		// bulk receive handshake. Sessions were already delivered as
		// incremental updates via the event stream.
		return s.sendBulkMarkers()
	}
	return s.BulkSync()
}

// sendBulkMarkers sends a BulkStart/BulkEnd pair with no session data.
// Used after event stream export to signal the peer that a complete
// bulk transfer happened (the sessions were delivered incrementally).
func (s *SessionSync) sendBulkMarkers() error {
	s.bulkSendMu.Lock()
	defer s.bulkSendMu.Unlock()

	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("no peer connection")
	}

	epoch := s.bulkSendNext.Add(1)
	var epochBuf [8]byte
	binary.LittleEndian.PutUint64(epochBuf[:], epoch)

	slog.Info("cluster sync: sending bulk markers after event stream export",
		"epoch", epoch,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn))

	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBulkStart, epochBuf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.handleDisconnect(conn)
		return err
	}

	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgBulkEnd, epochBuf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.handleDisconnect(conn)
		return err
	}

	s.pendingBulkAckEpoch.Store(epoch)
	s.pendingBulkAckSince.Store(time.Now().UnixNano())
	s.stats.BulkSyncs.Add(1)
	slog.Info("cluster sync: bulk markers sent", "epoch", epoch)
	return nil
}

func (s *SessionSync) BulkSync() error {
	s.bulkSendMu.Lock()
	defer s.bulkSendMu.Unlock()

	if s.dp == nil {
		return fmt.Errorf("dataplane not ready")
	}
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("no peer connection")
	}

	// Assign a monotonically increasing epoch to this bulk transfer.
	epoch := s.bulkSendNext.Add(1)
	var epochBuf [8]byte
	binary.LittleEndian.PutUint64(epochBuf[:], epoch)

	stats := s.Stats()
	slog.Info("cluster sync: bulk sync starting",
		"epoch", epoch,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn),
		"sessions_sent", stats.SessionsSent,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled,
		"queue_len", len(s.sendCh),
		"queue_cap", cap(s.sendCh))

	// Send bulk start marker with epoch.
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBulkStart, epochBuf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.handleDisconnect(conn)
		return err
	}

	var count, skipped int
	slog.Info("cluster sync: bulk sync iterating v4", "epoch", epoch)
	// Send owned v4 forward sessions.
	err = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !s.ShouldSyncZone(val.IngressZone) {
			skipped++
			return true
		}
		msg := encodeSessionV4Payload(key, val)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgSessionV4, msg)
		s.writeMu.Unlock()
		if err != nil {
			s.handleDisconnect(conn)
			slog.Warn("bulk sync v4 write error", "err", err)
			return false
		}
		count++
		// Yield briefly every 64 sessions to let barrier/bulk ack
		// writers acquire writeMu. Go's mutex is not fair — a tight
		// lock/unlock loop can starve other goroutines waiting on
		// the same mutex.
		if count%64 == 0 {
			runtime.Gosched()
		}
		return true
	})
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		return fmt.Errorf("bulk sync v4 iterate: %w", err)
	}
	slog.Info("cluster sync: bulk sync iterated v4",
		"epoch", epoch,
		"sessions", count,
		"skipped", skipped)

	// Send owned v6 forward sessions.
	slog.Info("cluster sync: bulk sync iterating v6", "epoch", epoch, "sessions", count, "skipped", skipped)
	err = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !s.ShouldSyncZone(val.IngressZone) {
			skipped++
			return true
		}
		msg := encodeSessionV6Payload(key, val)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgSessionV6, msg)
		s.writeMu.Unlock()
		if err != nil {
			s.handleDisconnect(conn)
			slog.Warn("bulk sync v6 write error", "err", err)
			return false
		}
		count++
		if count%64 == 0 {
			runtime.Gosched()
		}
		return true
	})
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		return fmt.Errorf("bulk sync v6 iterate: %w", err)
	}
	slog.Info("cluster sync: bulk sync iterated v6",
		"epoch", epoch,
		"sessions", count,
		"skipped", skipped)

	// Send bulk end marker with matching epoch.
	slog.Info("cluster sync: bulk sync writing end marker", "epoch", epoch, "sessions", count, "skipped", skipped)
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgBulkEnd, epochBuf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.handleDisconnect(conn)
		return err
	}
	s.pendingBulkAckEpoch.Store(epoch)
	s.pendingBulkAckSince.Store(time.Now().UnixNano())

	s.stats.BulkSyncs.Add(1)
	slog.Info("cluster sync: bulk sync complete", "sessions", count, "skipped", skipped, "epoch", epoch)
	return nil
}

// PendingBulkAck reports the latest outbound bulk epoch that is still awaiting
// peer acknowledgement, if any.
func (s *SessionSync) PendingBulkAck() (epoch uint64, age time.Duration, ok bool) {
	epoch = s.pendingBulkAckEpoch.Load()
	if epoch == 0 {
		return 0, 0, false
	}
	since := s.pendingBulkAckSince.Load()
	if since == 0 {
		return epoch, 0, true
	}
	age = time.Since(time.Unix(0, since))
	if age < 0 {
		age = 0
	}
	return epoch, age, true
}

// TransferReadiness snapshots the sync state that makes manual failover
// timing-sensitive: an unacked outbound bulk or an in-progress inbound bulk.
func (s *SessionSync) TransferReadiness() TransferReadinessSnapshot {
	snap := TransferReadinessSnapshot{
		Connected: s.stats.Connected.Load(),
	}
	if epoch, age, ok := s.PendingBulkAck(); ok {
		snap.PendingBulkAckEpoch = epoch
		snap.PendingBulkAckAge = age
	}
	s.bulkMu.Lock()
	snap.BulkReceiveInProgress = s.bulkInProgress
	snap.BulkReceiveEpoch = s.bulkRecvEpoch
	snap.BulkReceiveSessions = len(s.bulkRecvV4) + len(s.bulkRecvV6)
	s.bulkMu.Unlock()
	return snap
}

func (s *SessionSync) sendBarrierAck(conn net.Conn, seq uint64) {
	if conn == nil {
		return
	}
	// Write barrier ack directly under writeMu instead of going through
	// barrierCh → sendLoop. The sendLoop may be blocked on writeMu
	// (held by BulkSync writing session data), so routing through
	// barrierCh doesn't help — the ack sits in the channel while
	// sendLoop is stuck. Direct write with writeMu guarantees the ack
	// is sent as soon as the current BulkSync per-session write releases
	// the lock (each session write is <1ms).
	var payload [24]byte
	binary.LittleEndian.PutUint64(payload[:], seq)
	stats := s.Stats()
	binary.LittleEndian.PutUint64(payload[8:16], stats.SessionsReceived)
	binary.LittleEndian.PutUint64(payload[16:24], stats.SessionsInstalled)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBarrierAck, payload[:])
	s.writeMu.Unlock()
	if err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: barrier ack write failed", "seq", seq, "err", err)
		return
	}
	slog.Info("cluster sync: barrier ack sent",
		"seq", seq,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled)
}

func (s *SessionSync) completeBarrierWait(seq uint64) {
	s.barrierWaitMu.Lock()
	waiter := s.barrierWaiters[seq]
	delete(s.barrierWaiters, seq)
	s.barrierWaitMu.Unlock()
	if waiter != nil {
		close(waiter)
	}
}

func (s *SessionSync) sendBulkAck(conn net.Conn, epoch uint64) {
	if conn == nil {
		slog.Debug("cluster sync: skipping bulk ack on nil connection", "epoch", epoch)
		return
	}
	// Write bulk ack directly under writeMu — same rationale as
	// sendBarrierAck: the sendLoop may be blocked on writeMu during
	// BulkSync writes, so routing through barrierCh doesn't help.
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], epoch)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBulkAck, payload[:])
	s.writeMu.Unlock()
	if err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: bulk ack write failed", "epoch", epoch, "err", err)
		return
	}
	slog.Info("cluster sync: bulk ack sent",
		"epoch", epoch,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn))
}

func (s *SessionSync) writeBarrierMessage(payload []byte, timeout time.Duration) error {
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("session sync not connected")
	}
	// Pause the sendLoop so it stops writing session data to the TCP
	// connection. This ensures the barrier isn't queued behind hundreds
	// of session messages in the kernel TCP send buffer. After the
	// pause, the sendLoop's current write finishes and writeMu becomes
	// available for the barrier write.
	s.PauseSendLoop()
	defer s.ResumeSendLoop()
	// Brief yield to let sendLoop finish its current write and release writeMu.
	runtime.Gosched()
	time.Sleep(2 * time.Millisecond)

	msg := encodeRawMessage(syncMsgBarrier, payload)
	seq := binary.LittleEndian.Uint64(payload)
	s.writeMu.Lock()
	err := writeFull(conn, msg)
	s.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("barrier write failed: %w", err)
	}
	slog.Info("cluster sync: barrier sent (direct)",
		"seq", seq,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn))
	return nil
}

// DrainSendQueue discards all pending messages in sendCh so the TCP
// send buffer isn't clogged when a barrier needs prompt delivery.
func (s *SessionSync) DrainSendQueue() int {
	drained := 0
	for {
		select {
		case <-s.sendCh:
			drained++
		default:
			if drained > 0 {
				slog.Info("cluster sync: drained send queue", "messages", drained)
			}
			return drained
		}
	}
}

// WaitForPeerBarrier queues an ordered marker on the session-sync stream and
// waits until the peer acknowledges that it processed all earlier messages.
func (s *SessionSync) WaitForPeerBarrier(timeout time.Duration) error {
	if !s.stats.Connected.Load() {
		return fmt.Errorf("session sync not connected")
	}
	seq := s.barrierSeq.Add(1)
	waiter := make(chan struct{})
	s.barrierWaitMu.Lock()
	if s.barrierWaiters == nil {
		s.barrierWaiters = make(map[uint64]chan struct{})
	}
	s.barrierWaiters[seq] = waiter
	s.barrierWaitMu.Unlock()

	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], seq)
	stats := s.Stats()
	slog.Info("cluster sync: queueing barrier",
		"seq", seq,
		"sessions_sent", stats.SessionsSent,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled,
		"queue_len", len(s.sendCh),
		"queue_cap", cap(s.sendCh))
	if err := s.writeBarrierMessage(payload[:], timeout/2); err != nil {
		s.barrierWaitMu.Lock()
		delete(s.barrierWaiters, seq)
		s.barrierWaitMu.Unlock()
		return err
	}
	// Record the install fence sequence for status observability (#311).
	s.stats.LastFenceSeq.Store(seq)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-waiter:
		return nil
	case <-timer.C:
		s.barrierWaitMu.Lock()
		delete(s.barrierWaiters, seq)
		s.barrierWaitMu.Unlock()
		stats := s.Stats()
		return fmt.Errorf(
			"timed out waiting for session sync barrier ack seq=%d sessions_sent=%d sessions_received=%d sessions_installed=%d queue_len=%d",
			seq,
			stats.SessionsSent,
			stats.SessionsReceived,
			stats.SessionsInstalled,
			len(s.sendCh),
		)
	}
}

// WaitForPeerBarriersDrained waits until all still-pending barrier waiters have
// been acknowledged by the peer. Timed-out barriers are not treated as
// permanently blocking: a later barrier ack is cumulative, so retries should
// not get stuck on stale sequence numbers after the original waiter was removed.
func (s *SessionSync) WaitForPeerBarriersDrained(timeout time.Duration) error {
	s.barrierWaitMu.Lock()
	target := uint64(0)
	for seq := range s.barrierWaiters {
		if seq > target {
			target = seq
		}
	}
	s.barrierWaitMu.Unlock()
	if target == 0 || s.barrierAckSeq.Load() >= target {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.barrierAckSeq.Load() >= target {
			return nil
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return fmt.Errorf(
				"timed out waiting for previous session sync barriers acked through seq=%d last_acked=%d",
				target,
				s.barrierAckSeq.Load(),
			)
		}
	}
}
