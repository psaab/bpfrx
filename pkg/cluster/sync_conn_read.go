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
		if ac, ok := conn.(*authConn); ok && ac.readAuthed() {
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
		// #5084: the peer's boot incarnation, when it sent one. Recorded on the
		// CONNECTION so every config payload arriving on it is stamped with the
		// incarnation that primed it, and compared against the receiver-wide
		// current incarnation to decide a namespace switch.
		//
		// ORDER MATTERS: both records land BEFORE resetRecvGen below. Reversing
		// them opens a window in which the high-waters are already zeroed while
		// the current incarnation is still the DEAD one, so a prior-boot payload
		// dequeued by configApplyLoop in that window passes the fence and
		// records its (large) generation — the exact defect this exists to
		// close. In this order there is no such window.
		//
		// Not covered by a test, and deliberately called out rather than left
		// implied: binding it would mean interleaving the apply-loop goroutine
		// between two adjacent statements here, which no deterministic fixture
		// in this package can do. A mutation moving both records after the
		// reset leaves the whole suite green.
		inc := parseBootIncarnation(payload)
		s.noteConnBootIncarnation(conn, inc)
		switched := s.notePeerBootIncarnation(inc)
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
		slog.Info("cluster sync: bulk transfer starting", "epoch", epoch,
			"peer_boot_incarnation", inc.String(), "incarnation_switched", switched,
			"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		// #5084: a peer that primes without an incarnation gets today's
		// generation-only ordering (fail open). Warn ONCE per connection, not
		// per frame — a silent fallback is how a half-upgraded cluster hides,
		// and the CLAUDE.md logging rule forbids the per-frame version.
		if !inc.known() {
			s.warnUnincarnatedPrimeOnce(conn)
		}
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
	case syncMsgConfigApplyNack:
		// #7328: the peer did not apply a config generation this node pushed.
		// Length-gated: a short/absent payload is ignored rather than treated
		// as generation 0, which would be a valid-looking "legacy" value.
		if len(payload) < 8 {
			slog.Debug("cluster sync: short config-apply nack ignored", "len", len(payload))
			return
		}
		nackedGen := binary.LittleEndian.Uint64(payload[:8])
		// Only a nack for the generation this node most recently sent can
		// re-arm the push marker. An older generation is a straggler for a
		// push already superseded by a newer one; acting on it would re-push
		// a config the peer may already have applied.
		if sent := s.lastSentConfigGen.Load(); nackedGen != sent {
			slog.Debug("cluster sync: ignoring stale config-apply nack",
				"nacked_gen", nackedGen, "last_sent_gen", sent)
			return
		}
		s.stats.ConfigApplyNacksReceived.Add(1)
		slog.Warn("cluster sync: peer did not apply the config generation we pushed — re-arming the push marker",
			"gen", nackedGen)
		if s.OnPeerConfigApplyFailed != nil {
			s.OnPeerConfigApplyFailed(nackedGen)
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
		// #5718 C01a (fold F1): bind the capability to the peer INCARNATION
		// that proved it — only a currently-installed fabric connection can
		// speak for the current one. See noteHeartbeatAck (sync_conn.go).
		s.noteHeartbeatAck(conn)
	case syncMsgConfig:
		s.handleConfigPayload(conn, payload)
	case syncMsgConfigEncrypted:
		// #6629: same payload, sealed under this connection's ephemeral key.
		// Decrypt, then hand the plaintext to the SAME handler — the two arms
		// must never diverge in ordering, generation accounting or apply
		// admission, and a divergence there would always be a bug, so there is
		// one implementation rather than two kept in agreement.
		key := s.configKeyForConn(conn)
		if key == nil {
			// A sealed payload arrived on a connection with no derived key:
			// either the exchange never completed or this is a stale
			// connection the slots no longer reference. Either way it cannot
			// be opened, and it must NOT be opened with another connection's
			// key. Drop it; the sender re-pushes on the next reconcile tick.
			//
			// NOT BOUND BY A TEST, and deliberately recorded as such: removing
			// this branch changes nothing observable, because
			// openConfigPayload fails closed on a nil key (aes.NewCipher(nil)
			// errors) and the decrypt-failure branch below drops the payload
			// anyway. It is kept for the DIAGNOSTIC — "we never negotiated"
			// and "it did not decrypt" send an operator to entirely different
			// places — and as defence in depth if openConfigPayload ever grows
			// a path that tolerates a short key. The safety property (an
			// unopenable payload never reaches the apply path) is bound by
			// TestConfigCryptoDropsUndecryptablePayload6629.
			s.stats.Errors.Add(1)
			slog.Error("cluster sync: encrypted config received but no key was negotiated on "+
				"this connection — dropping (#6629)", "remote", connRemoteAddrString(conn))
			return
		}
		plaintext, err := openConfigPayload(key, payload)
		if err != nil {
			s.stats.Errors.Add(1)
			slog.Error("cluster sync: could not decrypt config payload — dropping (#6629)",
				"err", err, "remote", connRemoteAddrString(conn))
			return
		}
		s.handleConfigPayload(conn, plaintext)
	case syncMsgConfigKeyExchange:
		s.handleConfigKeyExchange(conn, payload)
	case syncMsgAuthUpgradeHello:
		// #6628: the peer committed a key and is offering to authenticate this
		// established connection in place. Never drops it.
		s.handleAuthUpgradeHello(conn, payload)
	case syncMsgAuthUpgradeProof:
		s.handleAuthUpgradeProof(conn, payload)
	case syncMsgAuthUpgradeAck:
		s.handleAuthUpgradeAck(conn, payload)
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
	case syncMsgPeerCapabilities:
		// #6650. Length-gated with the #2170 trailing-field discipline: a
		// SHORTER frame than we expect is a peer we cannot interpret, so it is
		// ignored (leaving the 0 = incapable default) rather than partially
		// decoded; a LONGER one is a newer peer with extra fields we skip.
		if len(payload) < 2 {
			slog.Warn("cluster sync: peer capabilities message too short", "len", len(payload))
			return
		}
		peerProto := binary.LittleEndian.Uint16(payload[:2])
		s.peerSnapshotProtocol.Store(uint32(peerProto))
		slog.Info("cluster sync: peer advertised config-snapshot protocol version", "version", peerProto)
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

// handleConfigPayload processes a decoded config-sync payload, whether it
// arrived in the clear (syncMsgConfig) or sealed (syncMsgConfigEncrypted,
// #6629). Both arms funnel here because the receiver-side ordering, the
// generation high-water accounting and the apply-queue admission must be
// identical for the two — a divergence between them is always a bug, so the
// behaviour is single-sourced rather than duplicated and kept in agreement.
// The conn parameter is #5084: the payload is stamped with the boot incarnation
// the CONNECTION primed under, so a payload queued from a peer's prior boot can
// be dropped at apply time rather than applying across a reset and stranding
// the high-water.
func (s *SessionSync) handleConfigPayload(conn net.Conn, payload []byte) {
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
	// #5084: a payload arriving under a peer boot incarnation that a re-prime
	// has ALREADY replaced is dead, and has to be refused here as well as at
	// apply. recordRecvConfigGen below is a monotone max that gates
	// manual-failover readiness (#5563 refuses promotion while PeerConfigGen >
	// AppliedConfigGen), and a dead incarnation's generation is drawn from the
	// peer's PRE-reboot counter, so it is far higher than anything the live
	// incarnation can produce. Raising the received mark for a payload the
	// apply loop is then going to drop would strand the standby reading
	// config-stale, with nothing able to close the gap short of another
	// re-prime — trading the #5084 divergence for a different silent wedge.
	//
	// The apply-time check is NOT made redundant by this one. This site sees
	// only payloads that ARRIVE after the switch; the apply-time site catches a
	// payload that was already QUEUED when the re-prime landed, which is the
	// reported defect ("resetRecvGen does not drain items already queued from
	// the prior boot"). Neither site subsumes the other.
	item := configApplyItem{gen: gen, text: configText, incarnation: s.connBootIncarnation(conn)}
	if s.configItemIncarnationStale(item) {
		s.stats.ConfigsDeadIncarnationDropped.Add(1)
		slog.Warn("cluster sync: dropping config received under a replaced peer boot "+
			"incarnation — the peer rebooted and re-primed, so this payload's generation "+
			"is incomparable with the current one (#5084)",
			"item_incarnation", item.incarnation.String(),
			"current_incarnation", s.PeerBootIncarnation().String(),
			"gen", gen, "size", len(configText), "remote", connRemoteAddrString(conn))
		return
	}
	s.recordRecvConfigGen(gen)
	// #3931: enqueue onto the single-consumer ordered apply queue instead
	// of spawning a racing `go OnConfigReceived`. The receiveLoop is
	// single-threaded per connection, so this preserves receive order;
	// configApplyLoop then applies only strictly-newer generations. The
	// enqueue is non-blocking so a slow apply never stalls session sync /
	// heartbeats on this connection.
	if s.configApplyCh != nil {
		select {
		case s.configApplyCh <- item:
		default:
			// Ordered apply queue full — practically impossible (commits
			// are seconds apart, apply is sub-second). Drop with an alarm;
			// the next commit / reconnect re-push (fresh higher gen)
			// re-converges the standby.
			s.stats.Errors.Add(1)
			slog.Error("cluster sync: config apply queue full, dropping config (will re-converge on next push)", "gen", gen, "size", len(configText))
		}
	}
}
