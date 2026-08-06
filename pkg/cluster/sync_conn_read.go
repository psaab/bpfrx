package cluster

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *SessionSync) receiveLoop(ctx context.Context, conn net.Conn) {
	defer func() {
		s.handleDisconnect(conn)
	}()
	hdrBuf := make([]byte, syncHeaderSize)
	readDeadline := s.readDeadlineDuration()
	missedHeartbeats := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(readDeadline))
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if s.peerHeartbeatAckEver.Load() {
					missedHeartbeats++
				}
				if missedHeartbeats >= 2 {
					slog.Warn("cluster sync: heartbeat ack timeout, closing stale connection", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "missed_heartbeats", missedHeartbeats)
					return
				}
				s.writeMu.Lock()
				err := writeMsg(conn, syncMsgHeartbeat, nil)
				s.writeMu.Unlock()
				if err != nil {
					return
				}
				continue
			}
			slog.Debug("cluster sync: read header error", "err", err)
			return
		}
		var hdr syncHeader
		copy(hdr.Magic[:], hdrBuf[:4])
		hdr.Type = hdrBuf[4]
		hdr.Length = binary.LittleEndian.Uint32(hdrBuf[8:12])
		if hdr.Magic != syncMagic {
			slog.Warn("cluster sync: bad magic")
			s.stats.Errors.Add(1)
			return
		}
		var payload []byte
		if hdr.Length > 0 {
			if hdr.Length > 16*1024*1024 {
				slog.Warn("cluster sync: payload too large", "len", hdr.Length)
				return
			}
			payload = make([]byte, hdr.Length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}
		// #4107 F23: on an authenticated connection every frame carries a
		// per-connection sequence + HMAC trailer. Read and verify it before the
		// message is trusted; a bad HMAC (forgery/tamper) or a non-increasing
		// sequence (replay/regression) drops the connection.
		if ac, ok := conn.(*authConn); ok && ac.authed() {
			trailer := make([]byte, syncAuthFrameTrailerSize)
			if _, err := io.ReadFull(conn, trailer); err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Debug("cluster sync: read auth trailer error", "err", err)
				return
			}
			if err := ac.verifyFrame(hdrBuf, payload, trailer); err != nil {
				slog.Warn("cluster sync: frame authentication failed, dropping connection",
					"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "err", err)
				s.stats.Errors.Add(1)
				return
			}
		}
		missedHeartbeats = 0
		s.lastPeerRxMono.Store(MonotonicNanos())
		s.handleMessage(conn, hdr.Type, payload)
	}
}
func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {
	switch msgType {
	case syncMsgSessionV4:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v4", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			}
		}
		if s.sessions != nil {
			if key, val, ok := decodeSessionV4Payload(payload); ok {
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV4[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}
				offset := s.peerClockOffset.Load()
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
				s.installClusterSyncedV4(key, val)
			}
		}
	case syncMsgSessionV6:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v6", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			}
		}
		if s.sessions != nil {
			if key, val, ok := decodeSessionV6Payload(payload); ok {
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV6[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}
				offset := s.peerClockOffset.Load()
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
				s.installClusterSyncedV6(key, val)
			}
		}
	case syncMsgDeleteV4:
		s.stats.DeletesReceived.Add(1)
		if s.sessions != nil && len(payload) >= 16 {
			var key dataplane.SessionKey
			copy(key.SrcIP[:], payload[0:4])
			copy(key.DstIP[:], payload[4:8])
			key.SrcPort = binary.LittleEndian.Uint16(payload[8:10])
			key.DstPort = binary.LittleEndian.Uint16(payload[10:12])
			key.Protocol = payload[12]
			// #2170: length-gated trailing install generation (absent on a
			// legacy peer → 0 → unconditional delete in the apply guard).
			var gen uint64
			if len(payload) >= 24 {
				gen = binary.LittleEndian.Uint64(payload[16:24])
			}
			s.deleteClusterSyncedV4(key, gen)
		}
	case syncMsgDeleteV6:
		s.stats.DeletesReceived.Add(1)
		if s.sessions != nil && len(payload) >= 40 {
			var key dataplane.SessionKeyV6
			copy(key.SrcIP[:], payload[0:16])
			copy(key.DstIP[:], payload[16:32])
			key.SrcPort = binary.LittleEndian.Uint16(payload[32:34])
			key.DstPort = binary.LittleEndian.Uint16(payload[34:36])
			key.Protocol = payload[36]
			// #2170: length-gated trailing install generation.
			var gen uint64
			if len(payload) >= 48 {
				gen = binary.LittleEndian.Uint64(payload[40:48])
			}
			s.deleteClusterSyncedV6(key, gen)
		}
	case syncMsgBulkStart:
		var epoch uint64
		if len(payload) >= 8 {
			epoch = binary.LittleEndian.Uint64(payload[:8])
		}
		s.stats.BulkSyncStartTime.Store(time.Now().UnixNano())
		s.stats.BulkSyncEndTime.Store(0)
		s.stats.BulkSyncSessions.Store(0)
		// #2198 F2: the peer is re-priming its authoritative live set. Reset
		// our stored generations so a rebooted peer's bulk (whose genCounter
		// restarted lower) is accepted by the install guard instead of being
		// refused as stale (stale-RETAIN, the inverse of #2170).
		s.resetRecvGen()
		zoneSnap := s.snapshotZoneOwnership()
		s.bulkMu.Lock()
		s.bulkInProgress = true
		s.bulkRecvEpoch = epoch
		s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
		s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
		s.bulkZoneSnapshot = zoneSnap
		s.bulkMu.Unlock()
		slog.Info("cluster sync: bulk transfer starting", "epoch", epoch, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	case syncMsgBulkEnd:
		var epoch uint64
		if len(payload) >= 8 {
			epoch = binary.LittleEndian.Uint64(payload[:8])
		}
		s.bulkMu.Lock()
		if !s.bulkInProgress {
			// #5272: a BulkEnd with NO bulk transfer actually in progress
			// on our side is spurious or replayed — a buggy / mixed-version
			// / replaying peer frame, or a BulkEnd that arrives after we
			// tore the transfer down on disconnect. Completing it here would
			// reconcile-as-done, ACK, latch bulkEverCompleted, and fire
			// OnBulkSyncReceived, which RELEASES the VRRP sync hold: the node
			// would become MASTER-eligible while forwarding with an empty /
			// stale peer session table (stateful failover broken — a mid-
			// session failover blackholes). Only a real BulkStart -> ... ->
			// BulkEnd transfer may release the safety gate. This is LOCAL
			// state (no wire field, no version bump), so a legacy peer's
			// legitimate bulk still completes.
			s.bulkMu.Unlock()
			slog.Debug("cluster sync: ignoring BulkEnd with no bulk transfer in progress", "got", epoch)
			break
		}
		if s.bulkRecvEpoch != epoch {
			// #5718 (codex-182 C-HA C01b): snapshot the mutex-protected
			// expected epoch BEFORE releasing bulkMu. Reading s.bulkRecvEpoch
			// in the log arguments after Unlock races a concurrent BulkStart
			// on another fabric receive loop (which writes bulkRecvEpoch under
			// bulkMu, sync_conn_read.go BulkStart handler) — a diagnostic-only
			// data race the Go memory model forbids and go test -race flags.
			want := s.bulkRecvEpoch
			s.bulkMu.Unlock()
			slog.Warn("cluster sync: ignoring BulkEnd with mismatched epoch", "expected", want, "got", epoch)
			break
		}
		s.bulkMu.Unlock()
		s.stats.BulkSyncEndTime.Store(time.Now().UnixNano())
		s.reconcileStaleSessions()
		slog.Info("cluster sync: bulk transfer complete", "epoch", epoch, "sessions", s.stats.BulkSyncSessions.Load(), "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		s.sendBulkAck(conn, epoch)
		s.bulkEverCompleted.Store(true)
		if s.OnBulkSyncReceived != nil {
			go s.OnBulkSyncReceived()
		}
	case syncMsgBulkAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: bulk ack message too short")
			return
		}
		epoch := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		slog.Info("cluster sync: bulk ack received", "epoch", epoch, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		pending := s.pendingBulkAckEpoch.Load()
		if pending == 0 || epoch < pending {
			// #5272: a BulkAck with no matching pending outbound bulk (we
			// never sent a bulk we are awaiting the ack for, or this ack is
			// for a stale/older epoch) is spurious or replayed. Setting
			// bulkEverCompleted / outboundBulkAcked and firing
			// OnBulkSyncAckReceived would release the outbound-bulk safety
			// gate (and suppress the #4090/#4360 stranded-bulk re-drive) with
			// no real outbound transfer having been acknowledged. Ignore it.
			// The gate is LOCAL pending-outbound state (recorded before we
			// write the BulkEnd, #3912) — no wire field, no version bump — so
			// a legacy peer's legitimate ack of our outbound bulk still
			// completes.
			slog.Debug("cluster sync: ignoring BulkAck with no pending outbound bulk", "got", epoch, "pending", pending)
			return
		}
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.bulkEverCompleted.Store(true)
		// #4360: the peer acked OUR outbound bulk — record it on the
		// outbound-only flag so a stranded outbound bulk can be re-driven on a
		// survivor fabric independently of whether an inbound bulk (which also
		// sets bulkEverCompleted at syncMsgBulkEnd) completed first.
		s.outboundBulkAcked.Store(true)
		if s.OnBulkSyncAckReceived != nil {
			go s.OnBulkSyncAckReceived()
		}
	case syncMsgHeartbeat:
		if conn == nil {
			return
		}
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgHeartbeatAck, nil)
		s.writeMu.Unlock()
		if err != nil {
			slog.Debug("cluster sync: heartbeat ack send error", "err", err)
			s.stats.Errors.Add(1)
			s.handleDisconnect(conn)
		}
	case syncMsgHeartbeatAck:
		s.peerHeartbeatAckEver.Store(true)
	case syncMsgConfig:
		s.stats.ConfigsReceived.Add(1)
		s.stats.LastConfigSyncTime.Store(time.Now().UnixNano())
		configText, gen := decodeConfigPayload(payload)
		s.stats.LastConfigSyncSize.Store(uint64(len(configText)))
		slog.Info("cluster sync: config received from peer", "size", len(configText), "gen", gen)
		// #5563: advance the received-config high-water BEFORE enqueue. This is
		// the receiver's view of the peer's current committed generation and
		// gates manual-failover readiness against lastAppliedConfigGen. Record it
		// even if the enqueue below drops the payload (queue full) so the standby
		// stays flagged config-stale until the apply actually lands on a re-push.
		// It stays a monotonic max so a reordered older frame cannot pull it
		// down. #5084: the load/compare/store moved into recordRecvConfigGen and
		// is taken under configGenMu — the prior justification here ("the
		// receiveLoop is single-threaded per connection, so the load/store pair
		// needs no CAS") holds per connection but there are TWO receive loops,
		// so a raise driven by one fabric raced resetRecvGen's clear driven by
		// the other and could re-raise the mark that clear had just zeroed.
		s.recordRecvConfigGen(gen)
		// #3931: enqueue onto the single-consumer ordered apply queue instead
		// of spawning a racing `go OnConfigReceived`. The receiveLoop is
		// single-threaded per connection, so this preserves receive order;
		// configApplyLoop then applies only strictly-newer generations. The
		// enqueue is non-blocking so a slow apply never stalls session sync /
		// heartbeats on this connection.
		if s.configApplyCh != nil {
			select {
			case s.configApplyCh <- configApplyItem{gen: gen, text: configText}:
			default:
				// Ordered apply queue full — practically impossible (commits
				// are seconds apart, apply is sub-second). Drop with an alarm;
				// the next commit / reconnect re-push (fresh higher gen)
				// re-converges the standby.
				s.stats.Errors.Add(1)
				slog.Error("cluster sync: config apply queue full, dropping config (will re-converge on next push)", "gen", gen, "size", len(configText))
			}
		}
	case syncMsgIPsecSA:
		s.stats.IPsecSAReceived.Add(1)
		// #5706: split off the (incarnation, seq) ordering trailer and admit
		// only a strictly-newer full-set. A stale set reordered across the
		// redundant fabric streams is dropped so it cannot regress the held SA
		// set. A legacy peer sends no trailer -> (0,0) -> accept-always.
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.ipsecRecvSeq.admit(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.IPsecSAStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order IPsec SA set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		// #5706 review fold: strip the '\n' delimiter a new sender inserts
		// between the SA name list and the trailer so a new->new roundtrip
		// leaves no trailing empty name. A legacy / pre-fold frame has no
		// delimiter, so this is a no-op for it.
		names := decodeIPsecSAPayload(stripIPsecFullSetDelim(base))
		s.peerIPsecSAsMu.Lock()
		s.peerIPsecSAs = names
		s.peerIPsecSAsMu.Unlock()
		slog.Debug("cluster sync: received IPsec SA list", "count", len(names), "incarnation", incarnation, "seq", seq)
		if s.OnIPsecSAReceived != nil {
			s.OnIPsecSAReceived(names)
		}
	case syncMsgDHCPLeaseV4:
		s.stats.DHCPLeasesReceived.Add(1)
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.dhcpV4RecvSeq.admit(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v4 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		leases := decodeDHCPLeasePayload(base)
		s.storePeerDHCPLeases(4, leases)
		slog.Debug("cluster sync: received DHCP v4 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
		if s.OnDHCPLeasesReceived != nil {
			s.OnDHCPLeasesReceived(4, leases)
		}
	case syncMsgDHCPLeaseV6:
		s.stats.DHCPLeasesReceived.Add(1)
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.dhcpV6RecvSeq.admit(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v6 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		leases := decodeDHCPLeasePayload(base)
		s.storePeerDHCPLeases(6, leases)
		slog.Debug("cluster sync: received DHCP v6 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
		if s.OnDHCPLeasesReceived != nil {
			s.OnDHCPLeasesReceived(6, leases)
		}
	case syncMsgFailover:
		if len(payload) < 9 {
			slog.Warn("cluster sync: failover message too short")
			return
		}
		rgID := int(payload[0])
		reqID := binary.LittleEndian.Uint64(payload[1:9])
		slog.Info("cluster sync: remote failover request received", "rg", rgID, "req_id", reqID)
		go s.handleRemoteFailover(conn, rgID, reqID)
	case syncMsgFailoverAck:
		if len(payload) < 10 {
			slog.Warn("cluster sync: failover ack message too short")
			return
		}
		rgID := int(payload[0])
		status := payload[1]
		reqID := binary.LittleEndian.Uint64(payload[2:10])
		detail := string(payload[10:])
		slog.Info("cluster sync: failover ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverWait(rgID, reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverCommit:
		if len(payload) < 9 {
			slog.Warn("cluster sync: failover commit message too short")
			return
		}
		rgID := int(payload[0])
		reqID := binary.LittleEndian.Uint64(payload[1:9])
		slog.Info("cluster sync: remote failover commit received", "rg", rgID, "req_id", reqID)
		go s.handleRemoteFailoverCommit(conn, rgID, reqID)
	case syncMsgFailoverCommitAck:
		if len(payload) < 10 {
			slog.Warn("cluster sync: failover commit ack message too short")
			return
		}
		rgID := int(payload[0])
		status := payload[1]
		reqID := binary.LittleEndian.Uint64(payload[2:10])
		detail := string(payload[10:])
		slog.Info("cluster sync: failover commit ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverCommitWait(rgID, reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverBatch:
		rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover message decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: remote batch failover request received", "rgs", rgIDs, "req_id", reqID)
		go s.handleRemoteFailoverBatch(conn, rgIDs, reqID)
	case syncMsgFailoverBatchAck:
		rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover ack decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: batch failover ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverBatchWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverBatchCommit:
		rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover commit message decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: remote batch failover commit received", "rgs", rgIDs, "req_id", reqID)
		go s.handleRemoteFailoverCommitBatch(conn, rgIDs, reqID)
	case syncMsgFailoverBatchCommitAck:
		rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover commit ack decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: batch failover commit ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverBatchCommitWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
	case syncMsgFence:
		s.stats.FencesReceived.Add(1)
		slog.Warn("cluster sync: fence received from peer — disabling all RGs")
		if s.OnFenceReceived != nil {
			s.OnFenceReceived()
		}
	case syncMsgClockSync:
		if len(payload) < 8 {
			slog.Warn("cluster sync: clock sync message too short")
			return
		}
		peerMono := binary.LittleEndian.Uint64(payload[:8])
		localMono := monotonicSeconds()
		offset := int64(localMono) - int64(peerMono)
		s.peerClockOffset.Store(offset)
		s.clockSynced.Store(true)
		slog.Info("cluster sync: clock synced with peer", "peer_mono", peerMono, "local_mono", localMono, "offset", offset)
	case syncMsgPrepareActivation:
		if len(payload) < 1 {
			slog.Warn("cluster sync: prepare_activation message too short")
			return
		}
		rgID := int(payload[0])
		slog.Info("cluster sync: prepare_activation received from demoting peer", "rg", rgID)
		if s.OnPrepareActivation != nil {
			go s.OnPrepareActivation(rgID)
		}
	case syncMsgBarrier:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier message too short")
			return
		}
		seq := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		slog.Info("cluster sync: barrier received", "seq", seq, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		s.sendBarrierAck(conn, seq)
	case syncMsgBarrierAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier ack message too short")
			return
		}
		seq := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		peerSessionsReceived := uint64(0)
		peerSessionsInstalled := uint64(0)
		if len(payload) >= 24 {
			peerSessionsReceived = binary.LittleEndian.Uint64(payload[8:16])
			peerSessionsInstalled = binary.LittleEndian.Uint64(payload[16:24])
		}
		slog.Info("cluster sync: barrier ack received", "seq", seq, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "peer_sessions_received", peerSessionsReceived, "peer_sessions_installed", peerSessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		for {
			current := s.barrierAckSeq.Load()
			if seq <= current || s.barrierAckSeq.CompareAndSwap(current, seq) {
				break
			}
		}
		s.stats.LastFenceAckAt.Store(time.Now().UnixNano())
		s.completeBarrierWait(seq)
	}
}
