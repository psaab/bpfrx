package cluster

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *SessionSync) noteHelperMirrorResult(af string, warned *atomic.Bool, err error) {
	if err == nil {
		warned.Store(false)
		return
	}
	s.stats.Errors.Add(1)
	if warned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: failed to mirror synced session into dataplane helper", "af", af, "err", err)
		return
	}
	slog.Debug("cluster sync: repeated synced-session helper mirror failure", "af", af, "err", err)
}

// genGuardMapCap bounds the sender-side echo maps and the receiver-side
// stored-generation maps so a churning workload cannot grow them without
// limit. Both are evicted on delete; the cap is a safety valve for keys whose
// delete never arrives (e.g. dropped close delta). It matches the delete
// journal cap order-of-magnitude.
//
// Overflow handling (#2198 F1): when a map is at cap, a NEW key is NOT
// recorded (skip-record-on-full) and an EXISTING key is updated in place. The
// map is NEVER cleared. Clearing the whole map would drop the stored
// generation of every live key, disabling the guard cluster-wide for a churn
// window — exactly the #2170 hazard the guard exists to close: a stale delete
// could then kill a live re-established session. A skipped new key degrades to
// gen-0 (unconditional delete / unconditional install), which is always SAFE
// — gen-0 never causes a wrongful delete of a *different* live incarnation,
// it only loses the stale-delete protection for that one new key.
const genGuardMapCap = 200000

// putGenBounded records gen for key in m without ever clearing the map or
// dropping the stored generation of an existing key. An existing key is always
// updated in place; a new key is recorded only while the map is below
// genGuardMapCap. Returns true if the entry was stored. The caller holds the
// map's mutex. Generic over the two wire-key types.
func putGenBounded[K comparable](m map[K]uint64, key K, gen uint64) bool {
	if _, exists := m[key]; exists {
		m[key] = gen
		return true
	}
	if len(m) >= genGuardMapCap {
		// Map is full and this is a new key: skip-record. The key degrades to
		// gen-0 behavior, which is safe (see genGuardMapCap doc).
		return false
	}
	m[key] = gen
	return true
}

// nextInstallGen returns the next strictly-monotonic install generation.
func (s *SessionSync) nextInstallGen() uint64 {
	return s.genCounter.Add(1)
}

// fullSetSeqGuard is the receiver-side high-water mark for one FULL-SET sync
// stream (IPsec SA, or DHCP leases per family) under #5706. It records the
// last-applied (incarnation, seq) and admits only a strictly-newer pair, so a
// stale full-set delivered out of order across the redundant fabric
// receiveLoops (conn0/conn1) is dropped instead of regressing the held set.
//
// Ordering is lexicographic on (incarnation, seq): a strictly-higher
// incarnation always supersedes (a peer restart draws a fresh epoch), and
// within an incarnation the per-type seq orders the pushes. A LOWER
// incarnation is stale and refused — EXCEPT that the guard is reset() to zero
// on a peer bulk re-prime (resetRecvGen), so an OS-rebooted peer whose
// monotonic epoch restarts LOWER is re-accepted from its fresh set rather than
// stranded on the pre-reboot set (the #2198 F2 stale-RETAIN inverse, applied
// to full-set sync). The zero value is the initial/legacy state.
//
// Access is serialized by SessionSync.recvSeqMu because the two fabric
// receiveLoops can invoke admit concurrently.
type fullSetSeqGuard struct {
	incarnation uint64
	seq         uint64
}

// admit reports whether a full-set stamped (incarnation, seq) is strictly
// newer than the last-applied pair and, when it is, advances the high-water
// mark. incarnation==0 || seq==0 marks a LEGACY (pre-#5706) sender that sends
// no ordering trailer: admit-always and do NOT advance the mark, mirroring the
// config-gen gen==0 accept-always compat. The caller holds recvSeqMu.
func (g *fullSetSeqGuard) admit(incarnation, seq uint64) bool {
	if incarnation == 0 || seq == 0 {
		return true // legacy sender — no sequence, accept-always
	}
	if g.incarnation == 0 ||
		incarnation > g.incarnation ||
		(incarnation == g.incarnation && seq > g.seq) {
		g.incarnation = incarnation
		g.seq = seq
		return true
	}
	return false
}

// reset returns the guard to its zero (accept-next) state. Called from
// resetRecvGen on a peer bulk re-prime so a rebooted peer with a lower epoch is
// re-accepted. The caller holds recvSeqMu.
func (g *fullSetSeqGuard) reset() {
	g.incarnation = 0
	g.seq = 0
}

// stampInstallGenV4 assigns a fresh install generation to a v4 session being
// sent and records it (keyed by wire key) so the matching delete can echo the
// exact generation of the install it cancels (#2170 SMR fix #1). It mutates
// val.Generation in place. A re-send (sweep/bulk) of a live key intentionally
// bumps the generation: the per-key stored generation only ever climbs, so a
// journaled delete from before the re-send is strictly older and refused.
func (s *SessionSync) stampInstallGenV4(key dataplane.SessionKey, val *dataplane.SessionValue) {
	g := s.nextInstallGen()
	val.Generation = g
	s.genSentMu.Lock()
	if s.genSentV4 == nil {
		s.genSentV4 = make(map[dataplane.SessionKey]uint64)
	}
	if !putGenBounded(s.genSentV4, key, g) {
		s.stats.GenMapOverflow.Add(1)
	}
	s.genSentMu.Unlock()
}

func (s *SessionSync) stampInstallGenV6(key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) {
	g := s.nextInstallGen()
	val.Generation = g
	s.genSentMu.Lock()
	if s.genSentV6 == nil {
		s.genSentV6 = make(map[dataplane.SessionKeyV6]uint64)
	}
	if !putGenBounded(s.genSentV6, key, g) {
		s.stats.GenMapOverflow.Add(1)
	}
	s.genSentMu.Unlock()
}

// takeDeleteGenV4 returns the generation a delete for this wire key should
// carry and evicts the sender-side stamp.
//
// #2221: the delete draws a FRESH, strictly-greater generation
// (nextInstallGen) rather than echoing the install's stamp. The stamp and the
// sendCh enqueue are not atomic and two producer goroutines (the sweep
// stamping a live re-send, the delta-drain taking the close) mutate the same
// key, so a delete can be enqueued onto sendCh BEFORE the install it cancels.
// On the wire the receiver then applies delete then install with IDENTICAL
// generations; the receiver guards only refuse a STRICTLY-older operation, so
// the late install resurrects the closed session (the #2170 residual:
// stale-RETAIN rather than stale-delete). Drawing a fresh generation that is
// strictly greater than every prior install of this key makes a delete always
// out-rank the install it cancels: the receiver's install guard refuses a
// reordered older install (incoming < the delete tombstone), while a genuinely
// newer incarnation (re-established + re-stamped by a later sweep) carries an
// even higher generation and still applies. This composes with #2170: the
// per-key generation only ever climbs, so a journaled stale delete from before
// a re-sync is still strictly older than the live entry and refused.
//
// A key never installed in this boot (no stamp recorded) returns 0 (legacy
// fallback → unconditional delete in the apply guard), which is the safe
// behavior and preserves rolling-upgrade compatibility.
func (s *SessionSync) takeDeleteGenV4(key dataplane.SessionKey) uint64 {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	if _, ok := s.genSentV4[key]; !ok {
		return 0
	}
	delete(s.genSentV4, key)
	return s.nextInstallGen()
}

func (s *SessionSync) takeDeleteGenV6(key dataplane.SessionKeyV6) uint64 {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	if _, ok := s.genSentV6[key]; !ok {
		return 0
	}
	delete(s.genSentV6, key)
	return s.nextInstallGen()
}

// installGenGuardV4 implements the receiver-side install-side guard (#2170 SMR
// fix #2): refuse to overwrite a stored entry with a strictly-older-generation
// install so the per-key stored generation never regresses. Returns the
// generation to record on a successful apply (the incoming generation, or the
// preserved stored generation when the incoming one is 0). The bool reports
// whether the install should proceed.
func (s *SessionSync) installGenGuardV4(key dataplane.SessionKey, incoming uint64) (record uint64, apply bool) {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored, ok := s.recvGenV4[key]
	if ok && stored != 0 && incoming != 0 && incoming < stored {
		return 0, false
	}
	if incoming == 0 {
		// Legacy / unknown install: apply but keep the stored generation
		// (do not roll it back to 0).
		return stored, true
	}
	return incoming, true
}

func (s *SessionSync) installGenGuardV6(key dataplane.SessionKeyV6, incoming uint64) (record uint64, apply bool) {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored, ok := s.recvGenV6[key]
	if ok && stored != 0 && incoming != 0 && incoming < stored {
		return 0, false
	}
	if incoming == 0 {
		return stored, true
	}
	return incoming, true
}

// recordInstalledGenV4 stores the per-key generation after a successful
// install-apply, bounded by genGuardMapCap.
func (s *SessionSync) recordInstalledGenV4(key dataplane.SessionKey, gen uint64) {
	if gen == 0 {
		return
	}
	s.recvGenMu.Lock()
	if s.recvGenV4 == nil {
		s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	}
	if !putGenBounded(s.recvGenV4, key, gen) {
		s.stats.GenMapOverflow.Add(1)
	}
	s.recvGenMu.Unlock()
}

func (s *SessionSync) recordInstalledGenV6(key dataplane.SessionKeyV6, gen uint64) {
	if gen == 0 {
		return
	}
	s.recvGenMu.Lock()
	if s.recvGenV6 == nil {
		s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
	}
	if !putGenBounded(s.recvGenV6, key, gen) {
		s.stats.GenMapOverflow.Add(1)
	}
	s.recvGenMu.Unlock()
}

// deleteGenGuardV4 implements the receiver-side delete guard (#2170): a delete
// is refused only when both the stored and delete generations are non-zero and
// the delete generation is STRICTLY older than the stored entry's. Equality
// applies (it is the delete of the very session installed); gen==0 on either
// side falls back to today's unconditional delete (rolling-upgrade safe). The
// bool reports whether the delete should proceed.
//
// #2221: on an applied delete the stored generation is NOT evicted — it is
// upgraded to the (strictly-greater, see takeDeleteGenV4) delete generation as
// a TOMBSTONE. A subsequent reordered install that carries the OLDER generation
// of the very session this delete cancelled is then refused by installGenGuard*
// (incoming < the tombstone), so the standby converges to the master's state
// (session GONE) regardless of install/delete arrival order. A genuinely newer
// incarnation re-established and re-stamped by a later sweep carries a higher
// generation and still applies (incoming > tombstone). A gen-0 (legacy) delete
// evicts (no tombstone to record) — the legacy unconditional path is unchanged.
// Tombstones are bounded by genGuardMapCap (putGenBounded) and cleared by the
// bulk barrier (resetRecvGen), so a churning workload cannot grow the map
// without limit and a cross-boot generation regression is handled at BulkStart.
func (s *SessionSync) deleteGenGuardV4(key dataplane.SessionKey, deleteGen uint64) bool {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored := s.recvGenV4[key]
	if stored != 0 && deleteGen != 0 && deleteGen < stored {
		return false
	}
	if deleteGen != 0 {
		// Record the delete generation as a tombstone so a reordered older
		// install of the cancelled session is refused. Bounded; never clears.
		if s.recvGenV4 == nil {
			s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
		}
		if !putGenBounded(s.recvGenV4, key, deleteGen) {
			s.stats.GenMapOverflow.Add(1)
		}
	} else {
		delete(s.recvGenV4, key)
	}
	return true
}

func (s *SessionSync) deleteGenGuardV6(key dataplane.SessionKeyV6, deleteGen uint64) bool {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored := s.recvGenV6[key]
	if stored != 0 && deleteGen != 0 && deleteGen < stored {
		return false
	}
	if deleteGen != 0 {
		if s.recvGenV6 == nil {
			s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
		}
		if !putGenBounded(s.recvGenV6, key, deleteGen) {
			s.stats.GenMapOverflow.Add(1)
		}
	} else {
		delete(s.recvGenV6, key)
	}
	return true
}

// resetRecvGen clears the receiver-side stored-generation maps. It is called
// when the peer begins a fresh bulk transfer (#2198 F2): a reconnecting peer
// may have REBOOTED, which legitimately restarts its sender genCounter (it is
// seeded from CLOCK_MONOTONIC nanos, which resets at OS boot). Its bulk
// re-prime then carries generations that may be LOWER than the generations we
// stored from the peer's previous boot. Without this reset the install guard
// would refuse the bulk re-prime as "stale" (stored > incoming) — the inverse
// of the #2170 bug (stale-RETAIN) — and the cold-start re-prime would silently
// fail to land.
//
// This is safe against opening a stale-delete window: deletes are only acted
// on after the bulk completes (reconcileStaleSessions runs at BulkEnd), and
// the bulk re-prime re-establishes the live set (re-recording each key's fresh
// generation) before any such delete is processed. A delete that arrives
// mid-bulk for a key the bulk has not yet re-recorded falls back to gen-0
// (stored==0 after reset) → unconditional, which is the legacy-safe behavior.
func (s *SessionSync) resetRecvGen() {
	s.recvGenMu.Lock()
	s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
	s.recvGenMu.Unlock()
	// #3931: also reset the last-applied config generation. A reconnecting
	// peer may have REBOOTED, restarting its monotonic configGenCounter at a
	// value LOWER than the generation we stored from its previous boot.
	// Without this reset the config guard (admitConfigGen) would refuse the
	// reconnect config re-push as stale (last > incoming) — the same
	// stale-RETAIN inverse the session reset closes (#2198 F2). Resetting to
	// 0 makes the next config apply unconditionally; it is always the peer's
	// CURRENT config (pushConfigToPeer sends ShowActive), so the newest
	// content still wins.
	s.lastAppliedConfigGen.Store(0)
	// #5563: reset the received-config high-water alongside the applied mark so
	// the manual-failover readiness gate's applied<=received invariant holds
	// across the reset window. The reconnect re-push then re-establishes both
	// (received on receive, applied on successful apply).
	s.lastRecvConfigGen.Store(0)
	// #5706: reset the full-set (IPsec/DHCP) ordering high-water marks for the
	// same reason. A reconnecting peer that OS-rebooted restarts its monotonic
	// incarnation LOWER; without this reset the guard would refuse its fresh
	// full-set re-push (nudged on reconnect) as stale and strand the standby on
	// the pre-reboot set. Resetting to the zero state admits the next push
	// unconditionally — it is always the peer's CURRENT set.
	s.recvSeqMu.Lock()
	s.ipsecRecvSeq.reset()
	s.dhcpV4RecvSeq.reset()
	s.dhcpV6RecvSeq.reset()
	s.recvSeqMu.Unlock()
}

// Non-atomicity note (#2198 F3): the apply sequence — guard check
// (installGenGuard*), PutClusterSynced*, recordInstalledGen* / deleteGenGuard*
// — does NOT hold recvGenMu across the whole sequence; the mutex is taken
// independently inside each of installGenGuard*/recordInstalledGen*/
// deleteGenGuard*. This is safe in production because the receiver apply path
// for a given peer is single-threaded: messages are decoded and dispatched
// serially within one receiveLoop goroutine over the single ACTIVE fabric
// connection (activeConnLocked prefers conn0; conn1 is used only when conn0 is
// down — never both at once for sends, and the peer sends over one stream). So
// no two installs/deletes for the SAME key are ever applied concurrently, and
// the per-key stored generation cannot be interleaved between the guard read
// and the record write. The standby fabric's receiveLoop exists but the active
// sender never duplicates a key's traffic across both, so cross-goroutine
// same-key races do not occur. Holding recvGenMu across the dataplane Put would
// also serialize unrelated keys and block on dataplane I/O under the lock,
// which is not worth it for a race that the single-active-fabric invariant
// already precludes.
func (s *SessionSync) installClusterSyncedV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	if s.sessions == nil {
		return
	}
	record, apply := s.installGenGuardV4(key, val.Generation)
	if !apply {
		s.stats.InstallsStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v4 install",
			"incoming_gen", val.Generation)
		return
	}
	if err := s.sessions.PutClusterSyncedV4(key, val); err == nil {
		s.recordInstalledGenV4(key, record)
		s.stats.SessionsInstalled.Add(1)
		s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, nil)
		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
			s.OnForwardSessionInstalled()
		}
	} else {
		s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, err)
	}
}

func (s *SessionSync) installClusterSyncedV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	if s.sessions == nil {
		return
	}
	record, apply := s.installGenGuardV6(key, val.Generation)
	if !apply {
		s.stats.InstallsStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v6 install",
			"incoming_gen", val.Generation)
		return
	}
	if err := s.sessions.PutClusterSyncedV6(key, val); err == nil {
		s.recordInstalledGenV6(key, record)
		s.stats.SessionsInstalled.Add(1)
		s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, nil)
		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
			s.OnForwardSessionInstalled()
		}
	} else {
		s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, err)
	}
}

func (s *SessionSync) deleteClusterSyncedV4(key dataplane.SessionKey, deleteGen uint64) {
	if s.sessions == nil {
		return
	}
	if !s.deleteGenGuardV4(key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v4 delete (replacement session survives)",
			"delete_gen", deleteGen)
		return
	}
	if err := s.sessions.DeleteWithCompanionsV4(key, dataplane.DeleteReasonClusterStale); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v4 session", "err", err)
	}
}

func (s *SessionSync) deleteClusterSyncedV6(key dataplane.SessionKeyV6, deleteGen uint64) {
	if s.sessions == nil {
		return
	}
	if !s.deleteGenGuardV6(key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v6 delete (replacement session survives)",
			"delete_gen", deleteGen)
		return
	}
	if err := s.sessions.DeleteWithCompanionsV6(key, dataplane.DeleteReasonClusterStale); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v6 session", "err", err)
	}
}

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

func (s *SessionSync) StartSyncSweep(ctx context.Context) {
	s.lastSweepTime = monotonicSeconds()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		activeInterval, idleInterval := s.sweepIntervals()
		interval := activeInterval
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				activeInterval, idleInterval = s.sweepIntervals()
				synced := s.syncSweep()
				if synced > 0 || s.syncBackfillNeeded.Load() {
					interval = activeInterval
				} else {
					interval = min(interval*2, idleInterval)
				}
				timer.Reset(interval)
			}
		}
	}()
	slog.Info("cluster sync: sweep started")
}
func (s *SessionSync) sweepIntervals() (time.Duration, time.Duration) {
	if s.sessions != nil {
		if source := s.sessions.SessionDeltas(); source != nil {
			return sweepIntervalsForDataPlane(source)
		}
	}
	return sweepIntervalsForDataPlane(nil)
}
func sweepIntervalsForDataPlane(dp any) (time.Duration, time.Duration) {
	activeInterval := time.Second
	idleInterval := 10 * time.Second
	if profiler, ok := dp.(sessionSyncSweepProfiler); ok {
		if enabled, active, idle := profiler.SessionSyncSweepProfile(); enabled {
			if active > 0 {
				activeInterval = active
			}
			if idle > 0 {
				idleInterval = idle
			}
		}
	}
	if idleInterval < activeInterval {
		idleInterval = activeInterval
	}
	return activeInterval, idleInterval
}

func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool {
	if s.IsPrimaryForRGFn != nil {
		s.zoneRGMu.RLock()
		rgID, ok := s.zoneRGMap[zoneID]
		s.zoneRGMu.RUnlock()
		if ok {
			return s.IsPrimaryForRGFn(rgID)
		}
	}
	if s.IsPrimaryFn != nil {
		return s.IsPrimaryFn()
	}
	return false
}
func (s *SessionSync) syncSweep() int {
	if s.IsPrimaryFn == nil && s.IsPrimaryForRGFn == nil {
		return 0
	}
	if s.incrementalPauseDepth.Load() > 0 {
		return 0
	}
	if !s.stats.Connected.Load() {
		return 0
	}
	// #3926: converge journaled deletes while CONNECTED. A delete generated
	// during a connected-but-backpressured moment (sendCh full) is journaled by
	// QueueDeleteV4/V6 but was previously flushed ONLY on a full
	// disconnect/reconnect (handleNewConnection) — the install-replay below
	// never carried it, so a journaled-while-connected delete never reached the
	// standby until an unrelated disconnect, leaving the standby with a dead
	// session (wrong forwarding on failover). Mirror the install-replay here:
	// flush the delete journal every sweep tick while connected so the standby
	// converges to the primary's DELETED set without requiring a disconnect.
	// flushDeleteJournal is a no-op when the journal is empty, re-sends each
	// entry at most once (take-all under the journal lock, DeletesSent counted
	// on success), preserves the encoded #2170/#2221 delete generation, and
	// re-journals any un-sent tail if sendCh is still full (retried next tick,
	// #2121). The delete backpressure that journaled the entry set
	// syncBackfillNeeded, which holds the sweep at the 1s active cadence, so
	// convergence is bounded by one active sweep interval. This flush is
	// independent of the kernel session iteration below and runs even when
	// s.sessions is nil.
	s.flushDeleteJournal()
	if s.sessions == nil {
		return 0
	}
	// #5450: a delete-journal overflow (rejournalTail/journalDelete dropped
	// records) armed forceResync — the standby may still hold sessions the
	// primary already closed. Recover by sending a full authoritative bulk
	// snapshot so the peer's reconcileStaleSessions deletes them. Consume the
	// arm exactly once (CAS true->false); re-arm on failure so a later sweep or
	// reconnect retries. flushDeleteJournal already ran this tick, so any tail
	// still queued replays before this snapshot's window closes.
	if s.forceResync.CompareAndSwap(true, false) {
		slog.Warn("cluster sync: forcing full bulk resync after delete-journal overflow (standby may retain stale sessions)")
		if err := s.doBulkSync(); err != nil {
			s.forceResync.Store(true)
			slog.Warn("cluster sync: forced resync bulk failed, will retry", "err", err)
		}
	}
	if s.lastSweepEmpty && !s.syncBackfillNeeded.Load() {
		if s.telemetry != nil {
			newCtr, err1 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
			closedCtr, err2 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
			if err1 == nil && err2 == nil && newCtr == s.lastNewCounter && closedCtr == s.lastClosedCounter {
				s.lastSweepTime = monotonicSeconds()
				return 0
			}
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	threshold := s.lastSweepTime
	now := monotonicSeconds()
	var count int
	var overflow bool
	replaying := s.syncBackfillNeeded.Load()
	if err := s.sessions.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			s.stampInstallGenV4(key, &val)
			msg := encodeSessionV4(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v4") {
				count++
			} else {
				overflow = true
			}
		}
		return true
	}); err != nil {
		slog.Warn("cluster sync: sweep v4 iteration failed", "err", err)
		s.stats.Errors.Add(1)
		return count
	}
	if err := s.sessions.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			s.stampInstallGenV6(key, &val)
			msg := encodeSessionV6(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v6") {
				count++
			} else {
				overflow = true
			}
		}
		return true
	}); err != nil {
		slog.Warn("cluster sync: sweep v6 iteration failed", "err", err)
		s.stats.Errors.Add(1)
		return count
	}
	if overflow {
		s.syncBackfillNeeded.Store(true)
		slog.Warn("cluster sync: sweep queue overflow, replaying previous window", "threshold", threshold, "queued", count, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		return count
	}
	if replaying {
		s.syncBackfillNeeded.Store(false)
		slog.Info("cluster sync: sweep replay recovered", "queued", count, "threshold", threshold)
	}
	s.lastSweepTime = now
	s.lastSweepEmpty = (count == 0)
	if count == 0 && s.telemetry != nil {
		newCtr, err1 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil {
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	if count > 0 {
		// Debug, not Info: this fires on every 1s sweep tick under steady
		// session churn (CLAUDE.md: never slog.Info per poll tick).
		slog.Debug("cluster sync: sweep synced sessions", "count", count)
	}
	return count
}

// PauseIncrementalSync temporarily disables background sweep-driven session
// replication. Explicit sync producers may continue queueing messages.
func (s *SessionSync) PauseIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(1)
	if depth == 1 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync paused", "reason", reason, "depth", depth, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	}
}

// ResumeIncrementalSync releases a previous PauseIncrementalSync call.
func (s *SessionSync) ResumeIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(-1)
	if depth < 0 {
		s.incrementalPauseDepth.Store(0)
		depth = 0
	}
	if depth == 0 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync resumed", "reason", reason, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	}
}
func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool {
	if !s.stats.Connected.Load() {
		return false
	}
	select {
	case s.sendCh <- msg:
		sentCounter.Add(1)
		return true
	default:
		s.stats.Errors.Add(1)
		if s.syncBackfillNeeded.CompareAndSwap(false, true) {
			slog.Warn("cluster sync: send queue full, enabling sweep replay", "source", source, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		}
		return false
	}
}

// QueueSessionV4 queues a v4 session for synchronization to the peer. The
// session is stamped with a fresh #2170 install generation so the matching
// delete can echo it and the peer can refuse a stale superseded delete.
func (s *SessionSync) QueueSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	s.stampInstallGenV4(key, &val)
	msg := encodeSessionV4(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v4")
}

// QueueSessionV6 queues a v6 session for synchronization to the peer.
func (s *SessionSync) QueueSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	s.stampInstallGenV6(key, &val)
	msg := encodeSessionV6(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v6")
}

// QueueDeleteV4 queues a v4 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect. The delete
// draws a fresh generation strictly greater than the install it cancels
// (takeDeleteGenV4, #2170 + #2221) so (a) a journaled delete that replays after
// a same-key replacement was re-synced is refused by the peer (its generation
// is strictly older than the live entry) and (b) a delete reordered ahead of
// its own install out-ranks it, letting the peer's tombstone refuse the late
// install of the cancelled session.
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
	gen := s.takeDeleteGenV4(key)
	msg := encodeDeleteV4(key, gen)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v4") {
		s.journalDelete(msg)
	}
}

// QueueDeleteV6 queues a v6 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect.
func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6) {
	gen := s.takeDeleteGenV6(key)
	msg := encodeDeleteV6(key, gen)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v6") {
		s.journalDelete(msg)
	}
}

// armDeleteResync marks that a delete-journal overflow dropped session-delete
// records the standby still needs, arming a full authoritative bulk resync
// (#5450). It is a pure atomic CAS — safe to call while holding
// deleteJournalMu because it never blocks and performs no I/O — and idempotent:
// repeated drops in one overflow episode re-arm the already-set flag as a
// no-op. The arm is consumed once by whichever of the sweep loop (syncSweep) or
// the next reconnect (handleNewConnection) runs first; both send a full
// BulkSync so the peer's reconcileStaleSessions deletes the sessions the
// primary already closed. Returns true only on the false->true transition so
// the caller can log the episode exactly once (outside the lock).
func (s *SessionSync) armDeleteResync() bool {
	return s.forceResync.CompareAndSwap(false, true)
}

// journalDelete stores a delete message in the bounded ring buffer for replay
// on reconnect. If the journal is full, the oldest entry is evicted,
// DeletesDropped is incremented, and a full bulk resync is armed (#5450) so the
// standby does not silently retain the session the evicted delete would have
// torn down.
func (s *SessionSync) journalDelete(msg []byte) {
	s.deleteJournalMu.Lock()
	cap := s.deleteJournalCap
	if cap <= 0 {
		cap = deleteJournalDefaultCap
	}
	armed := false
	if len(s.deleteJournal) >= cap {
		s.deleteJournal = s.deleteJournal[1:]
		s.stats.DeletesDropped.Add(1)
		armed = s.armDeleteResync()
	}
	s.deleteJournal = append(s.deleteJournal, msg)
	s.deleteJournalMu.Unlock()
	if armed {
		slog.Warn("cluster sync: delete journal full, evicted oldest delete and armed full bulk resync to reconcile standby",
			"deletes_dropped_total", s.stats.DeletesDropped.Load(),
			"journal_cap", cap)
	}
}

func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	var flushed int
	// Replay journaled deletes through the ordered send stream. queueMessage
	// is non-blocking and increments DeletesSent on success; on a full sendCh
	// (or a peer disconnect) it returns false. Mirror the QueueDeleteV4
	// contract: re-journal (retain) the un-sent tail instead of dropping it,
	// so it replays on the next reconnect flush. Previously a full sendCh
	// here silently dropped the un-sent deletes (the journal was already
	// nil'd), leaving stale sessions on the peer (#2121).
	for i, msg := range journal {
		if s.queueMessage(msg, &s.stats.DeletesSent, "journal_flush") {
			flushed++
			continue
		}
		// queueMessage returned false — the send queue is full or the peer
		// disconnected (queueMessage checks Connected first). Either way the
		// remaining messages would also fail, so re-journal this message and
		// the rest (FIFO-prepended ahead of any deletes concurrently journaled
		// during the flush) and stop. Stopping keeps the un-sent suffix
		// contiguous and ordered; they replay on the next reconnect flush.
		s.rejournalTail(journal[i:])
		// "unsent_tail" is the count handed to rejournalTail; some of those
		// may still be evicted there if the journal is over cap — that loss is
		// counted in DeletesDropped (logged here as the running total), so
		// this field is the tail size, not a guarantee that all were retained.
		slog.Warn("cluster sync: delete journal flush could not enqueue (queue full or disconnected), re-journaled un-sent tail for next reconnect",
			"total", len(journal), "flushed", flushed, "unsent_tail", len(journal)-i,
			"deletes_dropped_total", s.stats.DeletesDropped.Load(),
			"connected", s.stats.Connected.Load(),
			"queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		return
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "flushed", flushed)
}

// rejournalTail re-inserts the un-sent delete tail at the FRONT of the
// delete journal so it replays before any deletes that were concurrently
// journaled (by QueueDeleteV4/V6) while the flush ran, preserving FIFO
// order. On overflow it drops the OLDEST entries from the front of the
// merged list (the tail is older than the concurrently-journaled deletes,
// so the tail is evicted first; only if the entire tail is dropped does it
// also evict the oldest of the concurrent deletes, e.g. when the journal
// was already at cap), counting the dropped entries in DeletesDropped.
// Acquires deleteJournalMu exactly once. Used by flushDeleteJournal when
// the send stream is full or disconnected; the retained deletes replay on
// the next reconnect flush.
func (s *SessionSync) rejournalTail(tail [][]byte) {
	if len(tail) == 0 {
		return
	}
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	capN := s.deleteJournalCap
	if capN <= 0 {
		capN = deleteJournalDefaultCap
	}
	total := len(tail) + len(s.deleteJournal)
	if total <= capN {
		merged := make([][]byte, 0, total)
		merged = append(merged, tail...)
		merged = append(merged, s.deleteJournal...)
		s.deleteJournal = merged
		return
	}
	dropped := total - capN
	s.stats.DeletesDropped.Add(uint64(dropped))
	// #5450: the evicted deletes are session teardowns the standby still needs;
	// they are gone from our local table, so no incremental install sweep can
	// re-derive them. Arm a full authoritative bulk resync (consumed by the
	// sweep loop / next reconnect) so the peer's reconcileStaleSessions deletes
	// the sessions we already closed instead of carrying ghosts until the next
	// far-off full reconcile. Pure atomic CAS under deleteJournalMu — no I/O,
	// idempotent, armed once per overflow episode.
	s.armDeleteResync()
	merged := make([][]byte, 0, capN)
	if dropped < len(tail) {
		// Drop the oldest prefix of the tail; keep the rest plus all of the
		// newer concurrently-journaled deletes.
		merged = append(merged, tail[dropped:]...)
		merged = append(merged, s.deleteJournal...)
	} else {
		// The entire tail is evicted; also drop the oldest prefix of the
		// concurrently-journaled deletes to fit the cap.
		merged = append(merged, s.deleteJournal[dropped-len(tail):]...)
	}
	s.deleteJournal = merged
}

// nextConfigGen draws the next strictly-monotonic config generation stamped
// on an outgoing config-sync message (#3931). The counter is seeded from
// CLOCK_MONOTONIC nanos at construction so it never regresses below a value
// the peer may already hold across this node's restarts within a boot.
func (s *SessionSync) nextConfigGen() uint64 {
	return s.configGenCounter.Add(1)
}

// QueueConfig sends the full config text to the peer for configuration
// synchronization. The payload carries a monotonic config generation (#3931)
// so the receiver can order a rapid commit pair and refuse a reordered older
// config.
func (s *SessionSync) QueueConfig(configText string) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	gen := s.nextConfigGen()
	payload := encodeConfigPayload(configText, gen)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgConfig, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: config send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	s.stats.ConfigsSent.Add(1)
	slog.Info("cluster sync: config sent to peer", "size", len(configText), "gen", gen)
}

// shouldApplyConfigGen is the admission half of the #3931 receiver-side config
// ordering guard. It returns true if a config with generation gen should be
// ATTEMPTED — gen==0 (a legacy sender / unknown, applied unconditionally) or
// strictly newer than the last SUCCESSFULLY-applied generation — and false if
// it is an out-of-order older / duplicate config that must be dropped.
//
// It deliberately does NOT advance the high-water mark; the caller advances via
// recordAppliedConfigGen ONLY after the apply succeeds (M-2/#4151). Advancing
// on admission (the pre-#4151 behavior) meant an apply failure left the
// high-water ahead of the actually-applied config, so the primary's re-push of
// the same generation was dropped as stale and the standby stayed silently
// stranded on the prior config. It is called ONLY from the single-consumer
// configApplyLoop, so the load needs no CAS.
func (s *SessionSync) shouldApplyConfigGen(gen uint64) bool {
	if gen == 0 {
		return true
	}
	last := s.lastAppliedConfigGen.Load()
	return last == 0 || gen > last
}

// recordAppliedConfigGen advances the config high-water mark after a config of
// generation gen has been SUCCESSFULLY applied. gen==0 (legacy / unconditional)
// never advances the mark, mirroring the pre-#3931 behavior. It is called ONLY
// from the single-consumer configApplyLoop after OnConfigReceived returns nil,
// so the load/store pair needs no CAS.
func (s *SessionSync) recordAppliedConfigGen(gen uint64) {
	if gen == 0 {
		return
	}
	if gen > s.lastAppliedConfigGen.Load() {
		s.lastAppliedConfigGen.Store(gen)
	}
}

// configApplyLoop is the single ordered consumer of config-sync messages
// (#3931). It drains configApplyCh in receive order and attempts a config only
// when shouldApplyConfigGen accepts its generation, so a reordered older config
// from a rapid commit pair (C1 after C2) is dropped and the standby always
// converges to the newest config. Replaces the pre-#3931 racing
// `go OnConfigReceived` per message.
//
// The config high-water mark (lastAppliedConfigGen) advances ONLY after the
// apply succeeds (recordAppliedConfigGen, gated on OnConfigReceived returning
// nil). An apply failure counts ConfigsApplyFailed and leaves the high-water at
// the last-applied generation, so the primary's re-push of the same generation
// is re-admitted and the standby re-converges instead of being silently
// stranded on the prior config (M-2/#4151).
func (s *SessionSync) configApplyLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-s.configApplyCh:
			if !s.shouldApplyConfigGen(item.gen) {
				s.stats.ConfigsStaleIgnored.Add(1)
				slog.Warn("cluster sync: dropping out-of-order config sync (stale generation) — standby retains newer config",
					"incoming_gen", item.gen, "last_applied_gen", s.lastAppliedConfigGen.Load(), "size", len(item.text))
				continue
			}
			if s.OnConfigReceived == nil {
				// No apply handler wired — the config cannot be applied, so the
				// high-water must NOT advance (M-2/#4151). A later wired handler
				// re-applies on the primary's next push of this generation.
				continue
			}
			if err := s.OnConfigReceived(item.text); err != nil {
				// The apply did not take effect (compile/promote failure or a
				// transient RG0-primary rejection). Do NOT advance the
				// high-water: leaving it at the last-applied generation keeps
				// the standby eligible for the primary's re-push so it
				// re-converges instead of being silently stranded (M-2/#4151).
				s.stats.ConfigsApplyFailed.Add(1)
				// Debug, not Warn: handleConfigSync (the callback) already logs
				// the authoritative one-time reason WHY the apply failed
				// (RG0-primary rejection at Warn, compile/promote failure at
				// Error). This line is the per-retry diagnostic detail of the
				// M-2/#4151 high-water retention, and the same generation may be
				// re-pushed on every reconnect while the condition persists — a
				// Warn here would spam (CLAUDE.md logging rule). The
				// rate-independent observable is the ConfigsApplyFailed counter
				// above (surfaced in cluster status), not this log.
				slog.Debug("cluster sync: config apply failed — retaining prior high-water so the peer re-push re-converges",
					"incoming_gen", item.gen, "last_applied_gen", s.lastAppliedConfigGen.Load(), "size", len(item.text), "err", err)
				continue
			}
			// Apply confirmed — advance the high-water so a duplicate re-push of
			// the same generation is correctly skipped as stale.
			s.recordAppliedConfigGen(item.gen)
		}
	}
}

// SendLivenessKeepalive writes a sync-level heartbeat to the active peer
// connection so the peer's last-receive timestamp (lastPeerRxMono, read by
// LastPeerReceiveAge) is refreshed immediately. Used around the local
// heartbeat-socket restart window (Manager.RestartHeartbeat): while our UDP
// heartbeat sockets are torn down and rebound, the peer's only evidence that
// this node is still alive is sync traffic — and the sync-level heartbeat is
// normally emitted only on the 10s read-timeout cadence, far coarser than
// the 2s recency window of the peer's heartbeat-timeout suppression guard
// (shouldSuppressPeerHeartbeatTimeout). Best-effort: a no-op when no peer
// connection exists; a write error follows the standard sender pattern and
// triggers reconnect via handleDisconnect.
func (s *SessionSync) SendLivenessKeepalive() {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgHeartbeat, nil)
	s.writeMu.Unlock()
	if err != nil {
		slog.Debug("cluster sync: liveness keepalive send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
	}
}

// sendClockSync exchanges the local monotonic clock over the sync channel.
func (s *SessionSync) sendClockSync(conn net.Conn) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], monotonicSeconds())
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgClockSync, buf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.handleDisconnect(conn)
		slog.Warn("cluster sync: failed to send clock sync", "err", err)
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
func (s *SessionSync) sendLoop(ctx context.Context) {
	sendOne := func(msg []byte) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn := s.getActiveConn()
			if conn == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.writeMu.Lock()
			err := writeFull(conn, msg)
			s.writeMu.Unlock()
			if err != nil {
				slog.Debug("cluster sync: send error", "err", err)
				s.stats.Errors.Add(1)
				s.handleDisconnect(conn)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-s.sendCh:
			sendOne(msg)
		}
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
