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
func sendSessionSyncBatch(reqs []SessionSyncRequest, send func(ControlRequest) error) sessionPairResult {
	res := sessionPairResult{total: len(reqs)}
	for i := range reqs {
		ctrlReq := ControlRequest{
			Type:           "sync_session",
			SuppressStatus: true,
			SessionSync:    &reqs[i],
		}
		if err := send(ctrlReq); err != nil {
			slog.Debug("userspace session sync mirror failed", "operation", reqs[i].Operation, "err", err)
			res.failed = append(res.failed, i)
			if res.firstErr == nil {
				res.firstErr = err
			}
			// Helper unreachable/hung: abort the batch instead of paying the
			// per-request deadline once per remaining request (#5380). Record
			// how far the batch got: the requests never attempted are not
			// failures the helper saw, and telling them apart is what lets the
			// caller distinguish a wholly-undelivered pair from a partially
			// APPLIED one.
			if errors.Is(err, errSessionHelperUnreachable) {
				res.aborted = true
				break
			}
			continue
		}
		res.applied = append(res.applied, i)
	}
	return res
}

// sessionPairResult is the per-half outcome of a pair transmit.
//
// A bare first-error could not answer the question that matters (#7179): it
// says something went wrong, not whether the helper is now holding state the
// control plane did not intend. The two outcomes need opposite handling. A
// wholly-undelivered pair is benign — the helper applied nothing and the
// periodic session sync reconciles it — while a partially APPLIED pair leaves
// residue that no later transmit necessarily corrects.
type sessionPairResult struct {
	total    int
	applied  []int
	failed   []int
	aborted  bool
	firstErr error
}

// orphanedReverse reports the one partial outcome measured to strand state in
// the helper: the FORWARD was refused while the explicit REVERSE was applied,
// leaving a reverse-only entry with no forward.
//
// The direction is deliberate and is the opposite of what #7179 was filed
// describing. A forward that SUCCEEDS never leaves a half pair, because the
// helper synthesizes and publishes the reverse companion itself on every
// non-reverse import (userspace-dp session_import.rs) — measured as
// `entries=2` from a single forward upsert. And a forward that fails at the
// TRANSPORT layer aborts the batch above, so the reverse is never sent. The
// only way to publish a lone reverse is a forward the helper actively REFUSED
// — an application error such as a capacity rejection — after which the batch
// continues and the explicit reverse lands alone. That case is already
// documented helper-side as a bounded, self-inflicted "+1 orphan"; what was
// missing is any signal on this side that it happened.
func (r sessionPairResult) orphanedReverse() bool {
	if r.total < 2 {
		return false
	}
	// No explicit `aborted` guard, deliberately. A transport abort breaks the
	// batch at the forward, so the reverse is never SENT and cannot appear in
	// `applied` — the loop below already returns false for that shape. A guard
	// here would be unreachable by construction, and an unreachable branch is
	// one a mutation cannot bind: removing it changed no test result, which is
	// how it was found. `aborted` stays recorded because it distinguishes a
	// batch that stopped early from one that ran to completion, which the
	// per-request Debug logs alone do not say.
	forwardFailed := false
	for _, i := range r.failed {
		if i == 0 {
			forwardFailed = true
			break
		}
	}
	if !forwardFailed {
		return false
	}
	// Any applied request at this point IS the reverse: index 0 is in `failed`,
	// so it cannot also be in `applied`. An `i > 0` filter here reads as
	// careful and is another distinction that cannot differ -- mutating it to
	// `i >= 0` changed no test result, which is how it was found.
	return len(r.applied) > 0
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
	res := sendSessionSyncBatch(reqs, m.requestSessionSync)
	m.mu.Lock()
	return res.firstErr
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
// RESIDUAL, corrected (#7179): this makes the pair's transmit contiguous, not
// atomic — but the half-pair long attributed to that gap does not occur in the
// direction it was described. A FORWARD that succeeds never leaves a half pair,
// because the helper synthesizes and publishes the reverse companion itself on
// every non-reverse import (measured: one forward upsert yields two entries).
// A forward that fails at the TRANSPORT layer aborts the batch, so the reverse
// is never sent. The one partial that does strand state is the opposite one — a
// forward the helper actively REFUSES, after which the explicit reverse lands
// alone — and sessionPairResult.orphanedReverse is what makes it visible.
func (m *Manager) syncSessionPairLocked(reqs ...SessionSyncRequest) sessionPairResult {
	if len(reqs) == 0 {
		return sessionPairResult{}
	}
	if len(reqs) > sessionPairMaxRequests {
		slog.Error("userspace session pair transmit oversized; falling back to "+
			"per-request locking (no contiguity guarantee)",
			"requests", len(reqs), "max", sessionPairMaxRequests)
		return sessionPairResult{
			total:    len(reqs),
			firstErr: m.syncSessionRequestsLocked(reqs...),
		}
	}
	m.mu.Unlock()
	m.sessionMu.Lock()
	res := sendSessionSyncBatch(reqs, m.requestSessionSyncLocked)
	m.sessionMu.Unlock()
	m.mu.Lock()
	return res
}
