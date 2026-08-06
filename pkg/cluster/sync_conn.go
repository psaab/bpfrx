package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
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
	mode, frameKey, err := s.performSyncHandshake(conn)
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
	// #6387: stop the config-apply grace-expiry timer and invalidate any
	// in-flight callback so no timer survives this SessionSync's teardown (a
	// comms transport change tears down this instance and creates a fresh one).
	s.stopConfigApplyGraceTimer()
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
