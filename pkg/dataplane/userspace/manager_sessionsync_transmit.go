package userspace

// Session-sync transmit for the userspace dataplane, and the single owner of
// its lock discipline: every path here drops m.mu for the socket I/O and
// reacquires it (#5007 one-snapshot build), takes m.sessionMu once per
// request for the interleavable bulk path, once for the whole group on the
// contiguous pair path (#5698), and fast-fails a batch on a transport
// failure (#5380).

import (
	"errors"
	"log/slog"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (m *Manager) syncSessionV4Locked(op string, key dataplane.SessionKey, val *dataplane.SessionValue) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV4(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) syncSessionV6Locked(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV6(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) syncSessionRequestLocked(req SessionSyncRequest) error {
	// Build the control request under mu (for data access), then release mu
	// before the socket I/O so snapshot publishes aren't blocked.
	ctrlReq := ControlRequest{
		Type:           "sync_session",
		SuppressStatus: true,
		SessionSync:    &req,
	}
	m.mu.Unlock()
	err := m.requestSessionSync(ctrlReq)
	m.mu.Lock()
	if err != nil {
		slog.Debug("userspace session sync mirror failed", "operation", req.Operation, "err", err)
	}
	return err
}

// sendSessionSyncBatch transmits reqs through send, which performs one
// session-socket round trip per request. It is the single implementation of the
// batch loop shared by syncSessionRequestsLocked (send = the per-request
// locking wrapper) and syncSessionPairLocked (send = the unlocked inner, under
// one caller-held sessionMu), so the two transmit paths cannot drift apart on
// error handling.
//
// It attempts every request as long as the helper keeps answering — an
// APPLICATION-level rejection of one request (helper alive, resp.OK=false) does
// not stop the loop, so a bulk revocation drops as many helper sessions as it
// can. It returns the FIRST helper IPC error encountered, or nil if all
// succeeded.
//
// #5380: if a request fails at the TRANSPORT layer (dial/write/read wrapped
// with errSessionHelperUnreachable), the helper is down or hung and every
// remaining request would pay the full per-request deadline too. A bulk delete
// chunk is up to sessionHelperDeleteChunk (256) requests, so looping on would
// stall bulk session ops — and repeatedly hold sessionMu, starving live session
// installs — for ~256 * sessionSyncRoundtripDeadline (~13 min). So the batch
// fast-fails: it stops after the first transport failure and returns it. The
// mirror is best-effort — the periodic sweep retries once the helper is healthy
// again.
func sendSessionSyncBatch(reqs []SessionSyncRequest, send func(ControlRequest) error) error {
	var firstErr error
	for i := range reqs {
		ctrlReq := ControlRequest{
			Type:           "sync_session",
			SuppressStatus: true,
			SessionSync:    &reqs[i],
		}
		if err := send(ctrlReq); err != nil {
			slog.Debug("userspace session sync mirror failed", "operation", reqs[i].Operation, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: abort the batch instead of paying the
			// per-request deadline once per remaining request (#5380).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// syncSessionRequestsLocked transmits one or more PRE-BUILT session-sync
// requests to the Rust helper over the session socket. Like
// syncSessionRequestLocked it drops m.mu once for the socket I/O (so snapshot
// publishes are not blocked by a session install) and reacquires it before
// returning; the caller keeps the lock across the call. It performs NO
// snapshot reads — callers MUST have built every request under a single,
// uninterrupted prior m.mu hold so a forward/reverse companion pair is
// resolved against one consistent snapshot (#5007).
//
// The single m.mu unlock buys exactly two things and NOTHING more: the
// deliberate "socket I/O must not block snapshot publishes" property, and the
// #5007 one-snapshot build (every request was resolved before the lock was
// dropped). It does NOT make the transmit contiguous. This path acquires and
// releases m.sessionMu once PER request (requestSessionSync), so m.sessionMu is
// free between consecutive requests and an unrelated session-socket mutation —
// an operator clear, a policy invalidation, a GC delete, a stale-session
// reconciliation — can land between them (#5698). That interleaving is the
// CORRECT behaviour here: a bulk caller passes up to sessionHelperDeleteChunk
// (256) requests, and holding sessionMu across a chunk that large would starve
// live session installs for minutes — the exact harm the #5380 fast-fail
// exists to avoid. Contiguity, where a group genuinely must not be split,
// comes from syncSessionPairLocked's single sessionMu hold instead.
//
// It returns the FIRST helper IPC error encountered, or nil if all succeeded.
// Best-effort mirror callers (batch delete) discard the result; the
// authoritative clear-all path (#5881) propagates it so a failed helper
// revocation is reported instead of masquerading as success.
func (m *Manager) syncSessionRequestsLocked(reqs ...SessionSyncRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	m.mu.Unlock()
	firstErr := sendSessionSyncBatch(reqs, m.requestSessionSync)
	m.mu.Lock()
	return firstErr
}

// sessionPairMaxRequests is the hard cap on how many requests
// syncSessionPairLocked will transmit under ONE m.sessionMu hold. The only
// group that needs an uninterrupted transmit is a forward session plus its
// pre-installed reverse companion (#310), so two is the real bound; the
// constant exists so a future caller cannot quietly turn the contiguous path
// into a bulk path. Holding sessionMu across a large group would starve live
// session installs — see the #5380 note on sendSessionSyncBatch — so a group
// larger than this falls back to the per-request discipline rather than
// trading a rare interleave for a multi-minute install stall.
const sessionPairMaxRequests = 2

// syncSessionPairLocked transmits a SMALL, PRE-BUILT group of session-sync
// requests to the Rust helper with nothing interleaved between them.
//
// Like syncSessionRequestsLocked it drops m.mu once for the socket I/O and
// reacquires it before returning, so snapshot publishes are still never blocked
// by a session install and the #5007 one-snapshot build still holds. The
// difference is m.sessionMu: this path takes it ONCE for the whole group
// instead of once per request, so no other session-socket caller can run
// between the group's members. That closes the #5698 window in which a
// generation-0 forward delete landed between a pair's forward and its reverse:
// the delete removed BOTH halves in the helper, and the pair's already-built
// explicit reverse then re-created a standalone reverse-only permit.
//
// The group is capped at sessionPairMaxRequests. A larger group falls back to
// syncSessionRequestsLocked's per-request locking: an oversized contiguous hold
// would starve live session installs, which is a worse failure than the
// interleave it would prevent. The fallback is logged because reaching it means
// a caller mis-sized the group — it is unreachable from the pair mirrors, which
// build at most two requests.
//
// Error semantics are identical to syncSessionRequestsLocked (see
// sendSessionSyncBatch): first error wins, application-level rejections do not
// stop the group, a transport failure aborts it.
//
// RESIDUAL (deliberately out of scope): this makes the pair's transmit
// contiguous, not atomic. If the SECOND request fails at the transport layer
// the helper is left with a half-installed pair; nothing rolls the first half
// back. Closing that needs a helper-side pair transaction over the wire.
func (m *Manager) syncSessionPairLocked(reqs ...SessionSyncRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	if len(reqs) > sessionPairMaxRequests {
		slog.Error("userspace session pair transmit oversized; falling back to "+
			"per-request locking (no contiguity guarantee)",
			"requests", len(reqs), "max", sessionPairMaxRequests)
		return m.syncSessionRequestsLocked(reqs...)
	}
	m.mu.Unlock()
	m.sessionMu.Lock()
	firstErr := sendSessionSyncBatch(reqs, m.requestSessionSyncLocked)
	m.sessionMu.Unlock()
	m.mu.Lock()
	return firstErr
}
