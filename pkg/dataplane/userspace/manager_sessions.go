package userspace

// Session-table mutation entry points for the userspace dataplane: the
// dataplane.DataPlane install/delete/batch/clear verbs, the #5305
// transactional cluster-synced install (BPF pre-image snapshot + rollback on
// mirror failure), the chunked authoritative helper deletes, and the bulk
// event-stream session export. Each writes the BPF mirror and mirrors the
// change to the authoritative Rust helper.

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// ExportAllSessionsViaEventStream tells the Rust helper to push all current
// sessions through the event stream as Open events. The Go daemon receives
// them via handleEventStreamDelta and queues them to the peer automatically.
// This replaces the old BulkSync path that iterated BPF maps from Go.
func (m *Manager) ExportAllSessionsViaEventStream() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "export_all_sessions"}, &status); err != nil {
		return err
	}
	return m.applyHelperStatusLocked(&status)
}

func (m *Manager) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	if err := m.bpfShim.SetSessionV4(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mirrorSessionPairV4(key, val)
	return nil
}

// mirrorSessionPairV4 mirrors a forward session and its pre-installed reverse
// companion (#310) to the Rust helper.
//
// #5007: it resolves BOTH requests against ONE consistent config snapshot by
// building them under a single uninterrupted m.mu hold — BEFORE any control
// socket I/O drops the lock — then transmits both. buildSessionSyncRequestV4
// resolves egress/zone/tunnel-endpoint metadata from m.lastSnapshot (and the
// compile result); a concurrent ApplyConfig publishes a new m.lastSnapshot
// while holding m.mu, so resolving both requests during one continuous hold
// guarantees the forward/reverse pair derives from the SAME snapshot.
// Transmitting only after both builds preserves the deliberate "socket I/O
// must not block snapshot publishes" property (the transmit drops m.mu for the
// send).
//
// #5698: the transmit goes through syncSessionPairLocked, which holds
// m.sessionMu for BOTH requests. The single m.mu unlock says nothing about
// session-socket ordering — the per-request path frees m.sessionMu between
// requests, and a concurrent generation-0 forward delete landing in that gap
// removes both halves in the helper, after which this pair's already-built
// explicit reverse re-creates a standalone reverse-only permit. One
// m.sessionMu hold removes the gap. It does not make the pair ATOMIC: a
// transport failure on the reverse still leaves the forward installed alone.
func (m *Manager) mirrorSessionPairV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	reqs := make([]SessionSyncRequest, 0, 2)
	reqs = append(reqs, m.buildSessionSyncRequestV4("upsert", key, &val))
	// Pre-install the reverse companion so the Rust worker has it before
	// RG activation, avoiding activation-time synthesis (#310).
	if val.ReverseKey.Protocol != 0 {
		revVal := val
		revVal.IsReverse = 1
		revVal.ReverseKey = key
		revVal.IngressZone = val.EgressZone
		revVal.EgressZone = val.IngressZone
		// Clear FIB cache — reverse egress must be re-resolved locally.
		revVal.FibIfindex = 0
		revVal.FibVlanID = 0
		revVal.FibDmac = [6]byte{}
		revVal.FibSmac = [6]byte{}
		revVal.FibGen = 0
		reqs = append(reqs, m.buildSessionSyncRequestV4("upsert", val.ReverseKey, &revVal))
	}
	// Snapshot reads are complete; transmit both requests under ONE sessionMu
	// hold so nothing interleaves between the halves (#5698). The mirror upsert
	// is best-effort (the periodic session sync reconciles a transient miss),
	// so the helper IPC error is intentionally discarded.
	_ = m.syncSessionPairLocked(reqs...)
}

func (m *Manager) SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	// The helper already synthesizes the correct reverse companion from the
	// forward cluster-synced entry using local forwarding and HA state. An
	// explicit reverse cluster update can overwrite that locally-derived
	// companion with peer NAT/FIB metadata, so only mirror forward entries. A
	// reverse entry is never mirrored, so there is no mirror failure to
	// compensate: write the BPF mirror and return.
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return m.bpfShim.SetSessionV4(key, installVal)
	}
	// Forward entry: make the install transactional (#5305). Capture the
	// pre-image of the BPF session entry BEFORE writing it, then mirror to the
	// helper. On mirror failure RESTORE the pre-image (rewrite the prior value,
	// or DELETE the key if it was absent) so a failed cluster-synced install
	// leaves the BPF map exactly as it was. Otherwise the pinned map holds a
	// session the helper never received — a split truth the GC and fallback
	// bulk export would propagate as if the install had succeeded, producing
	// nondeterministic HA session ownership after takeover.
	//
	// snapshot + write + mirror + compensate run under m.mu so the sequence is
	// atomic w.r.t. any other m.mu-holding path; the per-peer receiver apply
	// loop is single-threaded (pkg/cluster/sync_conn.go installClusterSyncedV4),
	// so no concurrent install of the SAME key races. syncSessionV4Locked drops
	// m.mu only for the socket send and reacquires it before returning, so the
	// compensate that follows still observes our own BPF write.
	m.mu.Lock()
	defer m.mu.Unlock()
	prior, hadPrior, err := m.snapshotBPFSessionV4Locked(key)
	if err != nil {
		// The pre-image could not be read; refuse the install rather than write
		// an entry that could not later be rolled back on a mirror failure.
		return fmt.Errorf("snapshot synced v4 session pre-image: %w", err)
	}
	if err := m.bpfShim.SetSessionV4(key, installVal); err != nil {
		return err
	}
	if err := m.syncSessionV4Locked("upsert", key, &installVal); err != nil {
		m.recordSessionMirrorFailureLocked(err)
		slog.Debug("userspace: session mirror failed", "err", err)
		compErr := m.restoreBPFSessionV4Locked(key, prior, hadPrior)
		return errors.Join(
			fmt.Errorf("mirror synced v4 session to userspace helper: %w", err),
			compErr,
		)
	}
	// A successful mirror proves the helper session socket is healthy again;
	// clear any sticky failure so the standby regains takeover-readiness
	// without waiting for a helper restart (#5247).
	m.recordSessionMirrorSuccessLocked()
	return nil
}

// bpfSessionReadAbsent reports whether a bpfShim session GET error means the
// key is ABSENT rather than a hard read failure. The transactional snapshot
// (#5305) treats an absent pre-image as existed=false with a nil error so a
// later mirror-failure rollback DELETES the freshly-installed key; any OTHER
// read error is surfaced so the install is refused rather than leaving an
// entry that could not be rolled back (the fail-safe direction).
//
// It accepts the SAME key-absent error set as the Layer-1
// dataplane.sessionNotFound predicate — ebpf.ErrKeyNotExist OR unix.ENOENT,
// via the shared dataplane.IsKeyNotFound helper — so the two transaction
// layers agree on what "key absent" means (#6194). With the production cilium
// bpfShim the two sentinels never diverge (a missing lookup yields
// ErrKeyNotExist, not bare ENOENT), so this is a consistency fix, not a live
// bug; sharing one predicate removes the latent skew.
func bpfSessionReadAbsent(err error) bool {
	return dataplane.IsKeyNotFound(err)
}

// snapshotBPFSessionV4Locked reads the current BPF-mirror value for key so a
// failed cluster-synced install can be rolled back to it (#5305). Returns
// (value, existed, err); a missing key is existed=false with a nil error.
// Named "Locked" for the m.mu convention of the compensation sequence — it
// touches only the independently-locked bpfShim map, not m.mu directly.
func (m *Manager) snapshotBPFSessionV4Locked(key dataplane.SessionKey) (dataplane.SessionValue, bool, error) {
	val, err := m.bpfShim.GetSessionV4(key)
	if err != nil {
		if bpfSessionReadAbsent(err) {
			return dataplane.SessionValue{}, false, nil
		}
		return dataplane.SessionValue{}, false, err
	}
	return val, true, nil
}

// restoreBPFSessionV4Locked reverts the BPF session entry for key to the
// pre-install snapshot: rewrite the prior value, or delete the key if it was
// absent (#5305). Deleting an already-absent key is treated as success.
func (m *Manager) restoreBPFSessionV4Locked(key dataplane.SessionKey, prior dataplane.SessionValue, hadPrior bool) error {
	if hadPrior {
		if err := m.bpfShim.SetSessionV4(key, prior); err != nil {
			return fmt.Errorf("restore synced v4 session pre-image: %w", err)
		}
		return nil
	}
	if err := m.bpfShim.DeleteSession(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove orphan synced v4 session: %w", err)
	}
	return nil
}

func (m *Manager) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if err := m.bpfShim.SetSessionV6(key, val); err != nil {
		return err
	}
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return nil
	}
	m.mirrorSessionPairV6(key, val)
	return nil
}

// mirrorSessionPairV6 is the IPv6 analogue of mirrorSessionPairV4 — see that
// method for the #5007 single-snapshot rationale and the #5698 contiguous-
// transmit rationale. It builds the forward request and its reverse companion
// under one uninterrupted m.mu hold, then transmits both through
// syncSessionPairLocked (one m.sessionMu hold for the pair).
func (m *Manager) mirrorSessionPairV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	reqs := make([]SessionSyncRequest, 0, 2)
	reqs = append(reqs, m.buildSessionSyncRequestV6("upsert", key, &val))
	// Pre-install the reverse companion so the Rust worker has it before
	// RG activation, avoiding activation-time synthesis (#310).
	if val.ReverseKey.Protocol != 0 {
		revVal := val
		revVal.IsReverse = 1
		revVal.ReverseKey = key
		revVal.IngressZone = val.EgressZone
		revVal.EgressZone = val.IngressZone
		// Clear FIB cache — reverse egress must be re-resolved locally.
		revVal.FibIfindex = 0
		revVal.FibVlanID = 0
		revVal.FibDmac = [6]byte{}
		revVal.FibSmac = [6]byte{}
		revVal.FibGen = 0
		reqs = append(reqs, m.buildSessionSyncRequestV6("upsert", val.ReverseKey, &revVal))
	}
	// Snapshot reads are complete; transmit both requests under ONE sessionMu
	// hold so nothing interleaves between the halves (#5698). The mirror upsert
	// is best-effort (the periodic session sync reconciles a transient miss),
	// so the helper IPC error is intentionally discarded.
	_ = m.syncSessionPairLocked(reqs...)
}

func (m *Manager) SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	installVal := val
	installVal.FibIfindex = 0
	installVal.FibVlanID = 0
	installVal.FibDmac = [6]byte{}
	installVal.FibSmac = [6]byte{}
	installVal.FibGen = 0
	// Reverse entries are never mirrored (see SetClusterSyncedSessionV4): write
	// the BPF mirror and return — no mirror failure to compensate.
	if !shouldMirrorUserspaceSession(val.IsReverse) {
		return m.bpfShim.SetSessionV6(key, installVal)
	}
	// Forward entry: transactional install (#5305) — the IPv6 analogue of
	// SetClusterSyncedSessionV4. Snapshot the BPF pre-image, write, mirror, and
	// restore the pre-image on mirror failure so a failed install never leaves
	// an orphan split-truth BPF entry the helper never received.
	m.mu.Lock()
	defer m.mu.Unlock()
	prior, hadPrior, err := m.snapshotBPFSessionV6Locked(key)
	if err != nil {
		return fmt.Errorf("snapshot synced v6 session pre-image: %w", err)
	}
	if err := m.bpfShim.SetSessionV6(key, installVal); err != nil {
		return err
	}
	if err := m.syncSessionV6Locked("upsert", key, &installVal); err != nil {
		m.recordSessionMirrorFailureLocked(err)
		slog.Debug("userspace: session mirror failed", "err", err)
		compErr := m.restoreBPFSessionV6Locked(key, prior, hadPrior)
		return errors.Join(
			fmt.Errorf("mirror synced v6 session to userspace helper: %w", err),
			compErr,
		)
	}
	// A successful mirror proves the helper session socket is healthy again;
	// clear any sticky failure so the standby regains takeover-readiness
	// without waiting for a helper restart (#5247).
	m.recordSessionMirrorSuccessLocked()
	return nil
}

// snapshotBPFSessionV6Locked is the IPv6 sibling of snapshotBPFSessionV4Locked
// (#5305).
func (m *Manager) snapshotBPFSessionV6Locked(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, bool, error) {
	val, err := m.bpfShim.GetSessionV6(key)
	if err != nil {
		if bpfSessionReadAbsent(err) {
			return dataplane.SessionValueV6{}, false, nil
		}
		return dataplane.SessionValueV6{}, false, err
	}
	return val, true, nil
}

// restoreBPFSessionV6Locked is the IPv6 sibling of restoreBPFSessionV4Locked
// (#5305).
func (m *Manager) restoreBPFSessionV6Locked(key dataplane.SessionKeyV6, prior dataplane.SessionValueV6, hadPrior bool) error {
	if hadPrior {
		if err := m.bpfShim.SetSessionV6(key, prior); err != nil {
			return fmt.Errorf("restore synced v6 session pre-image: %w", err)
		}
		return nil
	}
	if err := m.bpfShim.DeleteSessionV6(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove orphan synced v6 session: %w", err)
	}
	return nil
}

func shouldMirrorUserspaceSession(isReverse uint8) bool {
	return isReverse == 0
}

func (m *Manager) DeleteSession(key dataplane.SessionKey) error {
	// Look up the session value BEFORE deleting from the BPF map so we
	// can retrieve the ReverseKey for the pre-installed companion (#351).
	val, valErr := m.bpfShim.GetSessionV4(key)

	if err := m.bpfShim.DeleteSession(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV4Locked("delete", key, nil)
	// Also delete the reverse companion that SetSessionV4 pre-installed.
	if valErr == nil && val.ReverseKey.Protocol != 0 {
		_ = m.syncSessionV4Locked("delete", val.ReverseKey, nil)
	}
	return nil
}

func (m *Manager) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	// Look up the session value BEFORE deleting from the BPF map so we
	// can retrieve the ReverseKey for the pre-installed companion (#351).
	val, valErr := m.bpfShim.GetSessionV6(key)

	if err := m.bpfShim.DeleteSessionV6(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.syncSessionV6Locked("delete", key, nil)
	// Also delete the reverse companion that SetSessionV6 pre-installed.
	if valErr == nil && val.ReverseKey.Protocol != 0 {
		_ = m.syncSessionV6Locked("delete", val.ReverseKey, nil)
	}
	return nil
}

// sessionHelperDeleteChunk bounds how many per-session helper "delete" IPCs the
// batch/clear session paths transmit under a single control-socket unlock so a
// large clear stays cooperative and cannot monopolize the shared control socket
// (#5096). syncSessionRequestsLocked drops and reacquires m.mu once per chunk,
// giving a concurrent snapshot publish a window between chunks, and takes
// m.sessionMu once per REQUEST so live session installs can interleave INSIDE a
// chunk. A chunk this large deliberately stays interleavable: the contiguous
// transmit (syncSessionPairLocked, #5698) is capped at sessionPairMaxRequests
// precisely because holding m.sessionMu across 256 round trips would starve
// those installs for minutes.
const sessionHelperDeleteChunk = 256

// BatchDeleteSessions deletes a batch of IPv4 sessions from the BPF mirror AND
// issues an authoritative "delete" to the Rust helper for every key (#5096).
//
// The LegacyDataPlaneAdapter embeds the bpfShim as its dataplane.DataPlane, so
// without this method Go promotion would dispatch a batch delete to the mirror
// map ONLY — leaving the helper, which owns packet lookup/lifetime, forwarding
// under the just-revoked decision until it re-publishes the mirror ~10s later.
// The singular DeleteSession already routes per-session deletes to the helper;
// this does the same for the batch path used by policy invalidation and the
// cluster-stale sweep. The bpf mirror's delete count is returned unchanged so
// caller count semantics are preserved.
func (m *Manager) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessions(keys)
	// Attempt the helper delete for every key regardless of the mirror result:
	// a batch where a key vanished concurrently returns ErrKeyNotExist with a
	// partial count, and the helper delete of an already-absent key is a no-op,
	// so skipping on error would strand the still-present helper sessions.
	//
	// The batch path (policy invalidation, cluster-stale sweep) keeps the
	// #5096 best-effort contract — the periodic session sync and GC delta
	// reconcile a transient helper miss — so the helper IPC error is
	// intentionally discarded here. The operator clear-all path propagates it
	// instead (ClearAllSessions, #5881).
	_ = m.deleteHelperSessionsV4(keys)
	return deleted, err
}

// BatchDeleteSessionsV6 is the IPv6 analogue of BatchDeleteSessions (#5096).
func (m *Manager) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	deleted, err := m.bpfShim.BatchDeleteSessionsV6(keys)
	_ = m.deleteHelperSessionsV6(keys)
	return deleted, err
}

// ClearAllSessions clears the BPF mirror AND issues an authoritative "delete" to
// the Rust helper for every session so an operator `clear security flow session
// all` actually stops forwarding under revoked decisions (#5096). The helper
// exposes no bulk-clear verb (only the per-session "delete" the singular path
// uses), so every mirror key — forward AND reverse conntrack entries — must be
// deleted on the helper too.
//
// The keys are NOT snapshotted here. Enumerating the full v4+v6 mirror into
// wrapper-owned slices while the shim's own clear snapshots them AGAIN (plus the
// dynamic-DNAT key lists) stacked ~1 GB of duplicate key slices in RSS on a
// max-loaded 10M/family table — enough for the recovery command to stall or
// OOM-kill the daemon (#5304). Instead the shim's ClearAllSessionsChunked drives
// a per-chunk callback: it collects a bounded chunk, deletes it from the mirror,
// and hands that same bounded chunk here for deletion on the helper, so neither
// side ever holds more than one chunk of keys. deleteHelperSessions{V4,V6} keeps
// the #5096 chunked-transmission behaviour (sessionHelperDeleteChunk).
//
// The Rust helper is AUTHORITATIVE in userspace mode — it owns packet
// lookup/forwarding while the BPF mirror is a read model. A helper-delete IPC
// failure therefore means a session the operator asked to revoke may still be
// forwarding, even though the mirror was emptied. Losing that error (as the
// pre-#5881 void callbacks did) let `clear security flow session all` report
// success while sessions lived on — a security bug. So the first helper-delete
// error is captured across chunks and, when the mirror clear itself succeeded,
// surfaced as ClearAllSessions's returned error. The bpf mirror's partial
// (v4, v6) counts are still returned alongside the error, matching the #5882
// non-atomic clear-all reporting contract, so a caller learns what the mirror
// side revoked while also learning the authoritative revocation is unconfirmed.
// A mirror-side error still takes precedence and is returned as before.
//
// #5380 residual: the per-chunk callbacks skip the helper delete once a
// transport failure is recorded, so a full clear-all under a hung helper pays
// ~one round-trip deadline total rather than one per 4096-key mirror chunk.
// See the helperDown guard below.
func (m *Manager) ClearAllSessions() (int, int, error) {
	var helperErr error
	recordHelperErr := func(err error) {
		if err != nil && helperErr == nil {
			helperErr = err
		}
	}
	// Fast-fail the WHOLE clear-all once the helper transport is down, not just
	// the 256-request loop inside a single deleteHelperSessions call (#5380
	// only aborted that inner loop). ClearAllSessionsChunked invokes these
	// callbacks ONCE PER sessionClearSnapshotChunk (4096-key) mirror chunk, and
	// the callbacks return void, so an inner abort does not propagate up: the
	// shim keeps handing every remaining chunk to a hung helper. A max table is
	// ~10M keys / 4096 ≈ 2440 chunks per family, so without this guard a
	// clear-all under a hung helper still pays ~one round-trip deadline PER
	// chunk (~2 h/family) even though each chunk's own delete already
	// fast-fails. Once a TRANSPORT failure has been recorded, skip the helper
	// delete for the remaining chunks so the clear-all pays ~one deadline
	// total. Only errSessionHelperUnreachable (a hung/unreachable helper) trips
	// the skip; an application-level rejection (helper alive, resp.OK=false) is
	// NOT wrapped as the sentinel, so a live helper that refuses one delete
	// keeps clearing the rest of the batch (#5881). The BPF mirror still clears
	// fully — the shim deletes each chunk BEFORE invoking the callback — and
	// helperErr stays set, so the #5881 error-propagation and #5882
	// partial-count contracts are unchanged.
	helperDown := func() bool { return errors.Is(helperErr, errSessionHelperUnreachable) }
	v4, v6, mirrorErr := m.bpfShim.ClearAllSessionsChunked(
		func(keys []dataplane.SessionKey) {
			if helperDown() {
				return
			}
			recordHelperErr(m.deleteHelperSessionsV4(keys))
		},
		func(keys []dataplane.SessionKeyV6) {
			if helperDown() {
				return
			}
			recordHelperErr(m.deleteHelperSessionsV6(keys))
		},
	)
	if mirrorErr != nil {
		return v4, v6, mirrorErr
	}
	if helperErr != nil {
		return v4, v6, fmt.Errorf("clear-all: authoritative helper session revocation failed: %w", helperErr)
	}
	return v4, v6, nil
}

// deleteHelperSessionsV4 tells the Rust helper to delete every key so the batch
// and clear session paths converge the helper's authoritative session table
// with the BPF mirror (#5096). Requests are transmitted in bounded chunks (see
// sessionHelperDeleteChunk) so a large clear does not monopolize the shared
// control socket. A "delete" request built with a nil value carries only the
// 5-tuple, so no snapshot read happens under m.mu.
//
// It returns the FIRST helper IPC error across all chunks (nil if all
// succeeded, or if there is no live helper). The best-effort batch callers
// discard it; ClearAllSessions propagates it so a failed authoritative
// revocation is reported rather than reported as success (#5881).
func (m *Manager) deleteHelperSessionsV4(keys []dataplane.SessionKey) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			reqs = append(reqs, m.buildSessionSyncRequestV4("delete", keys[i], nil))
		}
		if err := m.syncSessionRequestsLocked(reqs...); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking. Every remaining chunk
			// would fast-fail identically, so a large clear (10M keys ≈ 40K
			// chunks) does not spend one round-trip deadline PER chunk (#5380).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// deleteHelperSessionsV6 is the IPv6 analogue of deleteHelperSessionsV4 (#5096).
func (m *Manager) deleteHelperSessionsV6(keys []dataplane.SessionKeyV6) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			reqs = append(reqs, m.buildSessionSyncRequestV6("delete", keys[i], nil))
		}
		if err := m.syncSessionRequestsLocked(reqs...); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking (see deleteHelperSessionsV4).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}
