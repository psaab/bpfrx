package cluster

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func shouldInitiateFabricDial(localAddr, peerAddr string) bool {
	local, err := netip.ParseAddrPort(localAddr)
	if err != nil {
		return true
	}
	peer, err := netip.ParseAddrPort(peerAddr)
	if err != nil {
		return true
	}
	if cmp := local.Addr().Compare(peer.Addr()); cmp != 0 {
		return cmp < 0
	}
	return local.Port() < peer.Port()
}

// activeConnLocked returns the preferred active connection. fab0 is preferred;
// fab1 is used only when fab0 is down. The caller must hold s.mu.
func (s *SessionSync) activeConnLocked() net.Conn {
	if s.conn0 != nil {
		return s.conn0
	}
	return s.conn1
}

// getActiveConn returns the active connection while taking s.mu.
func (s *SessionSync) getActiveConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeConnLocked()
}
func connRemoteAddrString(conn net.Conn) (remote string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			remote = "<unavailable>"
		}
	}()
	addr := conn.RemoteAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}
func connLocalAddrString(conn net.Conn) (local string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			local = "<unavailable>"
		}
	}()
	addr := conn.LocalAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}
func configureSessionSyncConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConn.SetNoDelay(true); err != nil {
		slog.Warn("cluster sync: failed to enable TCP_NODELAY", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "err", err)
	}
	if err := tcpConn.SetWriteBuffer(256 * 1024); err != nil {
		slog.Warn("cluster sync: failed to set write buffer", "local", connLocalAddrString(conn), "err", err)
	}
	if err := tcpConn.SetReadBuffer(256 * 1024); err != nil {
		slog.Warn("cluster sync: failed to set read buffer", "local", connLocalAddrString(conn), "err", err)
	}
}

func (s *SessionSync) handleNewConnection(ctx context.Context, fabricIdx int, conn net.Conn) {
	// #5303: the caller (acceptLoop / fabricConnectLoop) already admitted this
	// connection into its pre-auth setup window via beginSetup. NOTE: the large
	// 256 KiB socket buffers are NOT sized here — configureConnFn is deferred
	// until AFTER the handshake succeeds so a connection flood cannot pin socket
	// memory before proving possession of the PSK.

	// #4107 F23: authenticate the stream at connection setup before any session
	// frame flows. A dropped handshake (bad PSK proof / downgrade attempt / I/O)
	// closes the connection; the accept/connect loops retry, so this never
	// bricks a keyed↔keyed reconnect during failover (both nodes are up and
	// keyed → the handshake completes in milliseconds).
	mode, frameKey, pending, err := s.performSyncHandshake(conn)
	// #5303: release the pre-auth admission slot (and the setup-tracking entry)
	// the moment the handshake resolves — an admitted slot must cover only the
	// brief pre-auth window, never the subsequent bulk sync. Post-auth the
	// connection is tracked for shutdown by conn0/conn1 instead.
	s.finishSetup(conn)
	if err != nil {
		slog.Warn("cluster sync: auth handshake failed, dropping connection",
			"fabric", fabricIdx, "remote", connRemoteAddrString(conn), "err", err)
		conn.Close()
		return
	}
	// #5303: only NOW, after auth succeeds, size the large (256 KiB) socket
	// buffers on the raw TCP connection (before it is wrapped in *authConn, which
	// would defeat the *net.TCPConn type assertion inside configureConnFn).
	configureConnFn(conn)
	// Wrap so writeFull seals and receiveLoop verifies per-frame auth when the
	// connection authenticated; an unauthenticated wrapper is a pass-through.
	conn = s.wrapSyncConn(fabricIdx, conn, mode, frameKey)
	// A legacy/unkeyed peer's first real frame was consumed by the handshake
	// read — process it before the receive loop starts so no message is lost.
	if pending != nil {
		s.handleMessage(conn, pending.typ, pending.payload)
	}

	// #4962: install the connection and DECIDE cold-prime atomically under
	// s.mu. Computing the decision after unlock (the pre-#4962 shape) let a
	// racing same-fabric accept supersede this connection between the unlock and
	// the decision's use, so the surviving connection could DROP cold-prime (see
	// installConn / the needColdPrime doc in sync.go).
	d := s.installConn(fabricIdx, conn)
	slog.Info("cluster sync: handling new connection", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "was_disconnected", d.wasDisconnected, "active_before", d.activeBefore, "active_after", d.activeAfter, "became_active", d.becameActive, "should_cold_prime", d.shouldColdPrime, "had_conn0", d.hadConn0, "had_conn1", d.hadConn1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.receiveLoop(ctx, conn)
	}()
	s.sendClockSync(conn)
	coldStart := !s.bulkEverCompleted.Load()
	if d.shouldColdPrime {
		slog.Info("cluster sync: driving authoritative cold-prime bulk on active connection", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "cold_start", coldStart, "was_disconnected", d.wasDisconnected)
		s.flushDeleteJournal()
		if s.OnPeerConnected != nil {
			slog.Info("cluster sync: scheduling OnPeerConnected callback", "fabric", fabricIdx)
			go s.OnPeerConnected()
		}
		// Re-read the resync arm AFTER flushDeleteJournal: a rejournalTail
		// eviction during that flush (or a journalDelete drop while we were
		// disconnected) arms forceResync, and dropped deletes are only
		// recoverable via a full authoritative bulk snapshot (#5450).
		// Consume the resync arm with CAS (symmetric with syncSweep) BEFORE the
		// bulk, so a NEW overflow that arms forceResync DURING this bulk survives
		// to trigger the next resync instead of being cleared by an unconditional
		// Store(false) (#5450 MINOR 1); a consumed arm is re-armed on bulk
		// failure so a later sweep/reconnect retries.
		forcedConsumed := s.forceResync.CompareAndSwap(true, false)
		// #5480: ALWAYS re-push our authoritative session table on a fresh
		// connection after a full (both-fabric) disconnect — not only on a
		// first-ever cold start (bulkEverCompleted false) or a #5450
		// delete-journal-overflow forced resync. bulkEverCompleted is a sticky,
		// process-local flag: once the survivor completes one bulk it stays true
		// forever, so the old `coldStart || forcedConsumed` reconnect gate wrongly
		// SKIPPED the re-push when the PEER rebooted and lost its session table
		// (the peer's own flag reset to false, but ours stayed true). The rebooted
		// peer then sends only its own empty bulk and OnPeerConnected re-pushes
		// non-session state, so the standby ends up with NO synced sessions — and
		// blackholes every established flow on the next failover to it.
		//
		// The survivor cannot locally tell a rebooted peer (empty table, needs
		// priming) from a pure fabric flap (peer kept its table): the sync
		// handshake carries no peer-cold / boot-incarnation / table-count signal,
		// and an unkeyed dual-accept peer sends no HELLO at all. So it re-primes
		// unconditionally. Re-priming is safe and idempotent — the receiver
		// upserts every session and reconcileStaleSessions on the peer prunes what
		// we no longer own — and a both-fabric disconnect means incremental deltas
		// may have been missed during the outage, so the "already primed"
		// assumption no longer holds even for a peer that never rebooted.
		//
		// Cost: one redundant full bulk on a genuine both-fabric flap. It is
		// bounded — this arm fires ONLY on a both-fabric down->up transition, never
		// on a routine single-fabric flip (those hit the becameActive/else branches
		// below and still do NOT re-bulk). The blackhole it prevents is far worse
		// than the redundant transfer (correctness over the optimization). A more
		// surgical fix that keeps the #466 flap-suppression optimization needs a
		// peer boot-incarnation field in the sync handshake — a wire change tracked
		// on #5480 and deferred here.
		switch {
		case forcedConsumed && !coldStart:
			slog.Warn("cluster sync: forcing full bulk resync on reconnect after delete-journal overflow (standby may retain stale sessions)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		case coldStart:
			slog.Info("cluster sync: starting bulk sync on cold start", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		default:
			slog.Info("cluster sync: re-priming bulk sync on reconnect (peer may have rebooted and lost its session table, #5480)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		}
		if err := s.doBulkSync(); err != nil {
			slog.Warn("cluster sync: bulk sync failed", "err", err, "fabric", fabricIdx)
			if forcedConsumed {
				s.forceResync.Store(true)
			}
		} else {
			// #4962: the authoritative cold-prime landed on the (surviving)
			// active connection, discharging the outstanding obligation. Consume
			// the needColdPrime latch so routine single-fabric flips do NOT
			// re-bulk; a later full-disconnect epoch re-arms it via installConn.
			// On FAILURE the latch stays armed, so the next accept that becomes
			// active re-drives the bulk instead of dropping it.
			s.needColdPrime.Store(false)
		}
	} else if d.becameActive {
		slog.Info("cluster sync: active fabric changed, resuming incremental sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "active_before", d.activeBefore, "active_after", d.activeAfter)
	} else {
		slog.Info("cluster sync: connection added without bulk sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
	}
}

// connColdPrimeDecision is the atomically-computed outcome of installing a sync
// connection into a fabric slot (#4962): which fabric was active before/after,
// whether this connection became the active fabric, and whether it must drive
// the authoritative cold-prime bulk. All fields are derived under s.mu together
// with the conn0/conn1 install so the decision is consistent with the registry
// state it was computed from — a racing supersession cannot invalidate it.
type connColdPrimeDecision struct {
	wasDisconnected bool
	becameActive    bool
	shouldColdPrime bool
	activeBefore    int
	activeAfter     int
	hadConn0        bool
	hadConn1        bool
}

// installConn wires conn into the fabric slot (superseding and closing any
// existing same-fabric connection) and returns the cold-prime decision computed
// ATOMICALLY with that install under s.mu (#4962).
//
// The needColdPrime latch is armed here on a full disconnect -> connect edge
// (both slots were empty) and consumed by handleNewConnection only when a
// cold-prime bulk SUCCEEDS. shouldColdPrime is therefore true whenever THIS
// connection is the active fabric AND a cold-prime is still owed for the current
// connected epoch — so a second same-fabric accept that supersedes an in-flight
// cold-prime INHERITS the obligation rather than dropping it. Computing the
// decision under the same lock that installs the connection is the fix's core:
// the pre-#4962 code read wasDisconnected under the lock but USED it after
// unlock, where a concurrent accept could already have changed the registry.
func (s *SessionSync) installConn(fabricIdx int, conn net.Conn) connColdPrimeDecision {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := connColdPrimeDecision{activeBefore: -1, activeAfter: -1}
	d.wasDisconnected = s.conn0 == nil && s.conn1 == nil
	if s.conn0 != nil {
		d.activeBefore = 0
	} else if s.conn1 != nil {
		d.activeBefore = 1
	}
	d.hadConn0 = s.conn0 != nil
	d.hadConn1 = s.conn1 != nil
	switch fabricIdx {
	case 0:
		if s.conn0 != nil {
			s.conn0.Close()
		}
		s.conn0 = conn
	case 1:
		if s.conn1 != nil {
			s.conn1.Close()
		}
		s.conn1 = conn
	}
	if s.conn0 != nil {
		d.activeAfter = 0
	} else if s.conn1 != nil {
		d.activeAfter = 1
	}
	s.stats.Connected.Store(true)
	s.lastPeerRxMono.Store(MonotonicNanos())
	// #4962: arm the cold-prime obligation on a full-disconnect -> connect edge.
	// The latch outlives this goroutine so a superseding same-fabric accept
	// still sees the obligation even though it observes a non-empty registry.
	if d.wasDisconnected {
		s.needColdPrime.Store(true)
	}
	d.becameActive = d.activeAfter == fabricIdx
	// #4962: commit the decision under the lock. becameActive means this
	// connection is now the active fabric; needColdPrime means the cold-prime
	// for this connected epoch has not yet succeeded. Both are read here, atomic
	// with the install above.
	d.shouldColdPrime = d.becameActive && s.needColdPrime.Load()
	return d
}

func (s *SessionSync) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)
	lc := vrfListenConfig(s.vrfDevice)
	ln, err := lc.Listen(ctx, "tcp", s.localAddr)
	if err != nil {
		return fmt.Errorf("sync listen: %w", err)
	}
	s.listener = ln
	slog.Info("cluster sync: listening", "addr", s.localAddr)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, ln, 0)
	}()
	if s.localAddr1 != "" {
		lc1 := vrfListenConfig(s.vrfDevice)
		ln1, err := lc1.Listen(ctx, "tcp", s.localAddr1)
		if err != nil {
			slog.Warn("cluster sync: secondary fabric listen failed, using primary only", "addr", s.localAddr1, "err", err)
		} else {
			s.listener1 = ln1
			slog.Info("cluster sync: listening on secondary fabric", "addr", s.localAddr1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(ctx, ln1, 1)
			}()
		}
	}
	if shouldInitiateFabricDial(s.localAddr, s.peerAddr) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 0, s.peerAddr)
		}()
	}
	if s.peerAddr1 != "" && shouldInitiateFabricDial(s.localAddr1, s.peerAddr1) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 1, s.peerAddr1)
		}()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sendLoop(ctx)
	}()
	// #3931: single ordered consumer for config-sync apply. Started once here
	// so it lives for the whole sync lifetime; it drains configApplyCh in
	// receive order and enforces the monotonic config-generation guard.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.configApplyLoop(ctx)
	}()
	return nil
}

func (s *SessionSync) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if s.listener1 != nil {
		s.listener1.Close()
	}
	s.mu.Lock()
	if s.conn0 != nil {
		s.conn0.Close()
	}
	if s.conn1 != nil {
		s.conn1.Close()
	}
	s.mu.Unlock()
	// #5303: close every connection still in its pre-auth setup window so a
	// stalled handshake read unblocks and its setup goroutine exits — otherwise a
	// flooder's abandoned pre-auth connections would hold setup goroutines until
	// their handshake deadlines and make Stop wait out the full 5s budget.
	s.closeSetupConns()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("cluster sync: Stop timed out waiting for goroutines, proceeding with shutdown")
	}
}

func (s *SessionSync) acceptLoop(ctx context.Context, ln net.Listener, fabricIdx int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("cluster sync: accept error", "err", err)
				time.Sleep(time.Second)
				continue
			}
		}
		slog.Info("cluster sync: peer connected", "remote", conn.RemoteAddr(), "fabric", fabricIdx)
		// #5303: admit the connection into the bounded pre-auth setup pool BEFORE
		// spawning a setup goroutine, so a connection flood that stalls before
		// authentication cannot exhaust FDs/goroutines/socket-memory. Excess
		// connections (pool saturated) are closed immediately without allocating
		// the large socket buffers; a reserved tail keeps the legitimate peer
		// able to reconnect (see beginSetup). This does NOT revert #4370 — an
		// admitted connection still runs its handshake in its own goroutine.
		if !s.beginSetup(conn, true) {
			s.notePreAuthRejected(conn)
			conn.Close()
			continue
		}
		// #4370: run connection setup (the auth handshake + wire-up + cold-start
		// bulk sync inside handleNewConnection) in a per-connection goroutine so
		// a slow or hung handshake on ONE connection cannot stall accepting the
		// NEXT for up to syncHandshakeTimeout. An active control-link attacker
		// could otherwise open connections that each serially block the accept
		// loop for the full handshake bound. The auth gate is preserved because
		// the connection is not wired into conn0/conn1 (and no session frame is
		// read from it) until performSyncHandshake succeeds INSIDE the goroutine;
		// a failed handshake closes the connection and returns. The goroutine is
		// tracked by s.wg (this loop already holds a wg token, so Add is safe)
		// so Stop() waits for in-flight setup. The outbound fabricConnectLoop
		// stays synchronous — it is a dedicated per-fabric dialer that must not
		// redial while a connection is being handled.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleNewConnection(ctx, fabricIdx, conn)
		}()
	}
}

func (s *SessionSync) fabricConnectLoop(ctx context.Context, fabricIdx int, peerAddr string) {
	for first := true; ; // fabricConnectLoop retries outbound connection on a single fabric link.
	// Each fabric gets its own loop so fab0 reconnects independently of fab1.
	first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
		s.mu.Lock()
		var connected bool
		if fabricIdx == 0 {
			connected = s.conn0 != nil
		} else {
			connected = s.conn1 != nil
		}
		s.mu.Unlock()
		if connected {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}
		dialer := net.Dialer{Timeout: 3 * time.Second}
		if s.vrfDevice != "" {
			dialer.Control = vrfListenConfig(s.vrfDevice).Control
		}
		conn, err := dialer.DialContext(ctx, "tcp", peerAddr)
		if err != nil {
			continue
		}
		slog.Info("cluster sync: connected to peer", "addr", peerAddr, "fabric", fabricIdx)
		// #5303: register our own outbound dial for shutdown cleanup (so Stop()
		// closes it if it stalls in the handshake). Outbound dials are bounded to
		// one per fabric and initiated by us, so they are NOT subject to the
		// inbound admission cap — beginSetup(inbound=false) never rejects and does
		// not consume a counted slot.
		s.beginSetup(conn, false)
		s.handleNewConnection(ctx, fabricIdx, conn)
	}
}
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
			s.bulkMu.Unlock()
			slog.Warn("cluster sync: ignoring BulkEnd with mismatched epoch", "expected", s.bulkRecvEpoch, "got", epoch)
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
		// The receiveLoop is single-threaded per connection, so the load/store
		// pair needs no CAS; guard on gen>current to keep it a monotonic max
		// against a reordered older frame.
		if gen > s.lastRecvConfigGen.Load() {
			s.lastRecvConfigGen.Store(gen)
		}
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
func (s *SessionSync) handleDisconnect(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.conn0 != nil && s.conn0 == conn:
		s.conn0.Close()
		s.conn0 = nil
		slog.Info("cluster sync: fabric 0 disconnected")
	case s.conn1 != nil && s.conn1 == conn:
		s.conn1.Close()
		s.conn1 = nil
		slog.Info("cluster sync: fabric 1 disconnected")
	default:
		slog.Debug("cluster sync: ignoring stale disconnect", "stale", fmt.Sprintf("%p", conn))
		return
	}
	connected := s.conn0 != nil || s.conn1 != nil
	s.stats.Connected.Store(connected)
	if !connected {
		pendingBarriers := s.barrierSeq.Load()
		ackedBarriers := s.barrierAckSeq.Load()
		s.barrierWaitMu.Lock()
		clearedWaiters := len(s.barrierWaiters)
		staleWaiters := s.barrierWaiters
		s.barrierWaiters = nil
		s.barrierWaitMu.Unlock()
		for _, ch := range staleWaiters {
			close(ch)
		}
		s.failoverWaitMu.Lock()
		failoverWaiters := s.failoverWaiters
		failoverCommitWaiters := s.failoverCommitWaiters
		failoverBatchWaiters := s.failoverBatchWaiters
		failoverBatchCommitWaiters := s.failoverBatchCommitWaiters
		clearedFailoverWaiters := len(failoverWaiters)
		clearedFailoverCommitWaiters := len(failoverCommitWaiters)
		clearedFailoverBatchWaiters := len(failoverBatchWaiters)
		clearedFailoverBatchCommitWaiters := len(failoverBatchCommitWaiters)
		s.failoverWaiters = make(map[int]failoverWaiter)
		s.failoverCommitWaiters = make(map[int]failoverWaiter)
		s.failoverBatchWaiters = make(map[string]failoverWaiter)
		s.failoverBatchCommitWaiters = make(map[string]failoverWaiter)
		s.failoverWaitMu.Unlock()
		for _, waiter := range failoverWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverCommitWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverBatchWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverBatchCommitWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		s.clockSynced.Store(false)
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.bulkMu.Lock()
		hadBulkInProgress := s.bulkInProgress
		s.bulkInProgress = false
		s.bulkRecvEpoch = 0
		s.bulkRecvV4 = nil
		s.bulkRecvV6 = nil
		s.bulkZoneSnapshot = nil
		s.bulkMu.Unlock()
		if hadBulkInProgress {
			slog.Info("cluster sync: reset in-progress bulk receive on disconnect")
		}
		slog.Info("cluster sync: peer disconnected (all fabrics down)")
		if pendingBarriers != 0 || ackedBarriers != 0 || clearedWaiters != 0 || clearedFailoverWaiters != 0 || clearedFailoverCommitWaiters != 0 || clearedFailoverBatchWaiters != 0 || clearedFailoverBatchCommitWaiters != 0 {
			slog.Info("cluster sync: reset barrier state after disconnect", "pending_seq", pendingBarriers, "acked_seq", ackedBarriers, "cleared_waiters", clearedWaiters, "cleared_failover_waiters", clearedFailoverWaiters, "cleared_failover_commit_waiters", clearedFailoverCommitWaiters, "cleared_failover_batch_waiters", clearedFailoverBatchWaiters, "cleared_failover_batch_commit_waiters", clearedFailoverBatchCommitWaiters)
		}
		if s.OnPeerDisconnected != nil {
			go s.OnPeerDisconnected()
		}
	} else if !s.outboundBulkAcked.Load() {
		// #4090: a survivor fabric is still up but the cold-start bulk
		// never completed. The bulk streams over a SINGLE connection
		// (BulkSync pins s.getActiveConn once); if that
		// connection dropped mid-stream the bulk is stranded — it is not
		// retried on the survivor and handleNewConnection will not
		// re-trigger it (its wasDisconnected gate needs BOTH fabrics to
		// have dropped). Re-drive doBulkSync over the survivor.
		//
		// #4360: this gates on outboundBulkAcked, NOT bulkEverCompleted.
		// The re-drive's job is to get OUR outbound bulk to the peer; a
		// small INBOUND bulk (peer->us) completing first sets
		// bulkEverCompleted but says nothing about whether the peer
		// received our table, so keying on the shared flag would wrongly
		// suppress the re-drive of a stranded outbound bulk.
		//
		// This MUST be a goroutine, not inline: handleDisconnect holds
		// s.mu, and doBulkSync -> BulkSync -> getActiveConn
		// re-locks s.mu (self-deadlock if run inline). The CAS guard bounds
		// re-drives to one in-flight at a time so a survivor that also flaps
		// (its own write failure re-entering handleDisconnect) cannot spawn a
		// storm; the flag is reset when the re-drive goroutine returns.
		if s.bulkRedriveInFlight.CompareAndSwap(false, true) {
			slog.Info("cluster sync: scheduling cold-start bulk re-drive on survivor fabric",
				"had_conn0", s.conn0 != nil, "had_conn1", s.conn1 != nil)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.bulkRedriveInFlight.Store(false)
				// A concurrent reconnect (both-fabric drop then reconnect)
				// may have already re-primed via handleNewConnection.
				// #4360: re-check the SAME outbound-only flag the gate above
				// used — bulkEverCompleted may be true from an inbound bulk
				// while our outbound bulk is still un-acked, and bailing on
				// it here would make the fix inert.
				if s.outboundBulkAcked.Load() {
					return
				}
				// Reset the stranded pending-ack epoch so the re-run's fresh
				// epoch supersedes it (a latched phantom pending epoch would
				// block manual failover, #3912).
				s.pendingBulkAckEpoch.Store(0)
				s.pendingBulkAckSince.Store(0)
				if err := s.doBulkSync(); err != nil {
					slog.Warn("cluster sync: cold-start bulk re-drive failed", "err", err)
				}
			}()
		}
	}
}
