# #2121 — flushDeleteJournal must not silently drop journaled deletes on a full send queue

Status: DRAFT v4 — incorporates Claude-SMR (NEEDS-MINOR) + AGY (NEEDS-MAJOR)
findings on v3; pending re-review.

## Design history

- **v1 (re-journal failed deletes for retry on the NEXT reconnect):
  KILLED (Codex).** Deletes are key-only on the peer
  (`deleteClusterSynced*` → `DeleteWithCompanions*`, no generation guard).
  Deferring a delete across a healthy connected interval can replay it on
  a later reconnect after a replacement session with the same key was
  re-synced, wrongly deleting the live replacement.
- **v2 (direct-write each frame under writeMu, bypass sendCh): KILLED
  (Codex).** `handleDisconnect` does NOT drain `sendCh`, so a session
  frame `S(K)` queued before a disconnect survives; on reconnect the flush
  direct-writes `D(K)` while the stale `S(K)` is still in `sendCh` and
  `sendLoop` writes it AFTER `D(K)`, resurrecting the deleted session. The
  codebase already solves this class: `writeBarrierMessage` (sync_bulk.go)
  goes through `sendCh` "to preserve ordering with already-queued session
  messages."
- **v3 (replay through sendCh, per-message blocking send): NEEDS-MAJOR.**
  Correct channel-ordered approach, but three implementation defects, all
  fixed in v4 below:
  - **Liveness hang (SMR finding #1 + AGY §3, CRITICAL):** the per-message
    `syncWriteDeadline` reset means a slow-but-not-stalled peer
    (~1.5s/frame) blocks the synchronous accept/dial loop for
    `N × syncWriteDeadline` — up to `deleteJournalCap × 2s` (~hours for a
    10k journal). Worse than the silent drop. → **Fix A: single global
    flush timeout.**
  - **Re-journal FIFO inversion + overflow bias (AGY §4, CRITICAL):**
    `rejournalAll` appended the un-sent tail to the END of the journal,
    placing it AFTER deletes concurrently journaled during the flush
    (`QueueDeleteV4` on a full `sendCh` while connected), inverting replay
    order; and on overflow `journalDelete`'s front-eviction drops the
    NEWER concurrent deletes. → **Fix B: FIFO-prepend merge under a single
    lock, evict oldest from the merged front.**
  - **Active-deferral stale-replacement (AGY §4 + SMR Q4, MAJOR):** on a
    timeout where the link does NOT immediately drop, the re-journaled
    deletes wait for the next reconnect while a replacement `S'(K)` is
    synced on the healthy link → on reconnect `D(K)` kills the live
    `S'(K)` (the v1 hazard, reintroduced via the timeout path). → **Fix C:
    on timeout, force-close the connection so the deferral is to a genuine
    disconnect, not a healthy interval.**

## Issue framing

`pkg/cluster/sync_conn.go`. `flushDeleteJournal` — invoked from
`handleNewConnection` on the first post-disconnect connection — drains the
bounded delete journal under lock (`s.deleteJournal = nil`), then replays
each delete via `queueMessage`, whose `sendCh` send is **non-blocking**.
If `sendCh` (cap 4096) is full at replay time the un-sent deletes are
**silently dropped** (journal already nil'd), leaving stale sessions on
the peer until they age out. `queueMessage`'s overflow re-sweeps SESSIONS
(`syncBackfillNeeded`), not deletes, so the drop is unrecovered.

Severity: LOW — narrow window, consequence is a stale standby session.

## Relevant existing behavior (verified against master 325d10683)

- Journaled messages are full framed frames (`encodeDeleteV4`/`V6`);
  `sendLoop` writes them verbatim via `writeFull`.
- `sendCh` is the SINGLE ordered FIFO path; `sendLoop` (sync_conn.go:681)
  the SINGLE writer (under `writeMu`). The only `sendCh <-` sites are
  `queueMessage` (489), `writeBarrierMessage` (320), and the proposed
  flush. (Confirmed by both reviewers.)
- `writeBarrierMessage` (sync_bulk.go:308) sends through `sendCh` with a
  timed blocking send "to preserve ordering with already-queued session
  messages" — the precedent v4 follows.
- `flushDeleteJournal` runs synchronously in `handleNewConnection`
  (sync_conn.go:200) BEFORE `OnPeerConnected` and `doBulkSync` (207), on
  the accept/dial-loop goroutine. `Connected` set true earlier (186).
- **`handleNewConnection` is single-flush per reconnect:** `wasDisconnected`
  is computed under `s.mu` (158-159) before the conn pointer is set, so
  only the first fabric to flip `conn0/conn1` from nil sees
  `wasDisconnected==true` and flushes. Two simultaneous fresh connections
  cannot both flush the (nil'd) journal. (SMR finding.)
- `handleDisconnect` does NOT drain `sendCh` (verified) — already-queued
  frames survive a disconnect.
- `journalDelete` (534): bounded ring append, FIFO front-eviction +
  `DeletesDropped++` at cap (`deleteJournalCap`, default 10000).
- `BulkSync` (sync_bulk.go:79) writes session frames DIRECTLY under
  `writeMu` (not via `sendCh`).
- `syncWriteDeadline = 2s` (sync.go:73). `sendCh` cap 4096 (sync.go:381).

## Concrete design (v4)

Replay journaled deletes through `sendCh` with a **single global-timeout**
blocking send; on timeout or disconnect, **FIFO-prepend** the un-sent tail
back into the journal and, on timeout, **force-close** the connection.

```go
func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	// Fix A: ONE global timeout for the whole flush bounds how long the
	// accept/dial loop can block to a constant, independent of journal size
	// or drain rate (per-message reset allowed O(N*deadline) hangs).
	timer := time.NewTimer(syncWriteDeadline)
	defer timer.Stop()

	var sent int
	for i, msg := range journal {
		if !s.stats.Connected.Load() {
			// Disconnected mid-flush: defer the tail to the next reconnect
			// flush (runs before normal sync — the original contract).
			s.rejournalTail(journal[i:])
			slog.Warn("cluster sync: delete journal flush aborted (disconnected), re-journaled tail",
				"total", len(journal), "sent", sent, "rejournaled", len(journal)-i)
			return
		}
		select {
		case s.sendCh <- msg:
			s.stats.DeletesSent.Add(1)
			sent++
		case <-timer.C:
			// Fix A: global budget exhausted (sendCh stayed full → stream
			// stalled). Defer the tail AND (Fix C) force-disconnect so the
			// deferral is to a genuine reconnect, not a healthy interval —
			// otherwise a replacement S'(K) synced on the still-up link
			// would be killed by the deferred D(K) on the next reconnect.
			s.rejournalTail(journal[i:])
			s.stats.Errors.Add(1)
			slog.Warn("cluster sync: delete journal flush timed out on full send queue, re-journaled tail and forcing reconnect",
				"total", len(journal), "sent", sent, "rejournaled", len(journal)-i,
				"queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
			if conn := s.getActiveConn(); conn != nil {
				s.handleDisconnect(conn)
			}
			return
		}
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "sent", sent)
}

// rejournalTail re-inserts the un-sent delete tail at the FRONT of the
// journal so it replays BEFORE any deletes concurrently journaled during
// the flush (Fix B — preserve FIFO; appending to the end inverted order).
// On overflow it drops the OLDEST entries from the front of the merged
// list (the tail), counting them in DeletesDropped — never the newer
// concurrently-journaled deletes. One lock acquisition.
func (s *SessionSync) rejournalTail(tail [][]byte) {
	if len(tail) == 0 {
		return
	}
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	cap := s.deleteJournalCap
	if cap <= 0 {
		cap = deleteJournalDefaultCap
	}
	total := len(tail) + len(s.deleteJournal)
	if total <= cap {
		merged := make([][]byte, 0, total)
		merged = append(merged, tail...)            // older un-sent first
		merged = append(merged, s.deleteJournal...) // then concurrent new
		s.deleteJournal = merged
		return
	}
	dropped := total - cap
	s.stats.DeletesDropped.Add(uint64(dropped))
	merged := make([][]byte, 0, cap)
	if dropped < len(tail) {
		merged = append(merged, tail[dropped:]...)  // drop oldest tail prefix
		merged = append(merged, s.deleteJournal...)
	} else {
		newDropped := dropped - len(tail)           // tail fully dropped
		merged = append(merged, s.deleteJournal[newDropped:]...)
	}
	s.deleteJournal = merged
}
```

### Notes on the fixes

- **Fix A bound:** total flush block ≤ `syncWriteDeadline` (2s) regardless
  of journal length. The risk table's old "one write deadline" claim is now
  TRUE because the timer is global, not per-message.
- **Fix B FIFO:** concurrent `QueueDeleteV4`/`V6` during the flush append
  `D(new)` to `s.deleteJournal` (the now-empty journal). Prepending the
  un-sent older `tail` keeps replay order `tail` (older) → `D(new)`
  (newer). Overflow drops the oldest (front of `tail`), never `D(new)`.
- **Fix C deferral safety:** force-`handleDisconnect` on timeout means the
  link goes down; a replacement session cannot be synced on a healthy link
  in the deferral window, so the deferred delete cannot kill a live
  replacement. The deferral is now to a genuine reconnect — identical to
  the existing journal-on-disconnect contract. `getActiveConn` +
  `handleDisconnect` reuse the project's standard teardown (matches
  `BulkSync`/`sendLoop`).

### Residual ordering exposure (scoped, not introduced here)

`QueueDeleteV4`/`V6` (sync_conn.go:515-529) STILL re-journal on a full
`sendCh` while the link is healthy and connected (`queueMessage` returns
false → `journalDelete`). That is the v1 hazard (a delete journaled during
a healthy interval can later kill a same-key replacement). It is
**pre-existing and untouched by #2121**; fully closing it needs a
generation/session-identity guard on the delete wire (a separate change).
#2121 **narrows** the loss (flush no longer drops, and the flush-deferral
path is now disconnect-gated) but does NOT eliminate this class. Out of
scope; recommend a follow-up issue for the generation guard.

Cold-start bulk interleaving (AGY §1): `doBulkSync` direct-writes current
LIVE sessions under `writeMu` after the flush has enqueued all deletes to
`sendCh`. A live `S(K)` landing after a stale `D(K)` on the wire is the
SAFE direction (the peer ends with the live session). Pre-existing
property of direct-write bulk; not introduced by #2121.

## Public API preservation

No exported API changes. `flushDeleteJournal`, `rejournalTail`,
`journalDelete`, `queueMessage` unexported. `SyncStats` fields/semantics
unchanged. No new field.

## Hidden invariants the change must preserve

1. No lock held across the blocking `sendCh` send (matches
   `writeBarrierMessage`). `rejournalTail` takes `deleteJournalMu` once,
   from outside any held lock.
2. No deadlock with `sendLoop`: it consumes `sendCh` independently;
   `writeFull` is `syncWriteDeadline`-bounded; the flush holds no lock
   during the send. Termination guaranteed by the global timer + the
   `Connected` check.
3. FIFO on the wire: deletes share the single `sendCh → sendLoop` path
   with queued sessions (fixes v2 reorder). Re-journal prepend keeps FIFO
   across a deferral (Fix B).
4. `DeletesSent` incremented once per enqueue; re-journaled messages not
   counted as sent (matches `queueMessage` semantics).
5. Bounded journal: `rejournalTail` enforces cap; `tail` ≤ original journal
   ≤ cap, and `total = len(tail)+len(concurrent)` can exceed cap only via
   concurrent journaling — handled by the overflow branch (drops oldest,
   counts `DeletesDropped`).
6. Termination: loop bounded by captured `journal`; re-journaled messages
   go to `s.deleteJournal`, not the loop slice. No livelock.
7. Single-flush per reconnect (mutex-gated `wasDisconnected`), so no two
   flushes race the nil'd journal.
8. Force-disconnect on timeout uses the standard `handleDisconnect`
   teardown; idempotent on a stale conn (handleDisconnect ignores
   non-active conns).

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Same wire path as today's queueMessage; only the full-queue branch changes drop→bounded-block→deferred-with-disconnect. |
| Concurrency / deadlock | LOW | No lock across send; global timer bounds block; rejournalTail single-lock. -race covered. |
| Liveness | LOW | Global 2s flush cap (Fix A); force-disconnect prevents inconsistent-state lingering (Fix C). |
| Ordering | LOW | Single ordered sendCh path; FIFO-prepend on deferral (Fix B). Residual healthy-interval QueueDelete hazard explicitly scoped out. |
| Performance | LOW | Reconnect-only; blocks only when sendCh full, capped at 2s. |

## Test plan

New `pkg/cluster` tests, `go test -race ./pkg/cluster/`:

1. **TestDeleteJournalFlushBlocksThenDeliversOnFullQueue** (non-tautological
   regression): Connected=true, active `net.Pipe`, pre-fill `sendCh` to cap
   FIRST, journal N deletes, launch `flushDeleteJournal` in a goroutine,
   THEN start a drainer that reads `sendCh` + writes the conn (strict
   ordering — drainer starts after the flush goroutine to keep it
   non-tautological per SMR). Assert: all N delete frames arrive on the
   wire IN ORDER after the pre-filled frames, `DeletesSent == N`, journal
   empty, `DeletesDropped == 0`. Pre-fix (non-blocking queueMessage) drops
   all N → 0 frames → fails. (Verify by reverting the fix.)
2. **TestDeleteJournalFlushTimeoutRejournalsAndDisconnects**: fill `sendCh`
   to cap with NO drainer, Connected=true, active conn, journal N deletes,
   flush with a TEST-INJECTED short flush timeout (see Q-test). Assert: the
   full tail is re-journaled (`s.deleteJournal` len == N), `DeletesSent ==
   0`, `Errors >= 1` (>=, not ==, per SMR — sendLoop/handleDisconnect may
   also bump), and the connection was torn down (Connected false / conn
   closed).
3. **TestDeleteJournalFlushRejournalFIFOPrepend** (Fix B): simulate a
   concurrent journal: pre-seed `s.deleteJournal` is empty, but during the
   timeout path inject a `D(new)` into the journal before `rejournalTail`
   runs (or unit-test `rejournalTail` directly): assert the older tail is
   at the FRONT and `D(new)` after it, and that an overflowing merge drops
   the oldest tail entries (counted in `DeletesDropped`), never `D(new)`.
4. **TestDeleteJournalFlushDisconnectedRejournals**: Connected=false,
   journal N, flush; assert all re-journaled, `DeletesSent == 0`.
5. **TestDeleteJournalFlushOrderingWithQueuedSession**: enqueue a session
   frame to `sendCh`, then flush a delete for the SAME key; drain; assert
   the session is read BEFORE the delete (through-sendCh FIFO — the
   property v2 violated).
6. Existing `TestDeleteJournal*` updated for the new active-conn wiring
   where needed; asserted behavior (deletes delivered, journal emptied,
   `DeletesSent==N`) preserved.

Gates: `go test -race ./pkg/cluster/`, `go build ./...`, full
`go test ./...`.

No loss-cluster iperf smoke: control-plane HA delete-journal replay logic,
not a dataplane forwarding change.

## Docs

`docs/session-sync-architecture.md` §"Delete Journal" (244) + §"Delete
Journal Overflow" (425): flush now replays journaled deletes through the
ordered send stream with a bounded (global-timeout) blocking enqueue (full
queue blocks until drained rather than dropping); on stall it re-journals
the un-sent tail FIFO-first and forces a reconnect; genuine loss at cap is
counted in `DeletesDropped`.

## Out of scope (explicitly)

- `sendCh` capacity (4096).
- Generation/session-identity guard on deletes (closes the residual
  healthy-interval `QueueDelete` re-journal hazard) — separate wire+receive
  change; recommend a follow-up issue.
- Cold-start bulk direct-write interleaving — pre-existing; safe direction
  for live sessions.
- A distinct `DeletesRequeued` metric — Warn log + `DeletesDropped` cover
  observability.
- #2120 (`syncSweep`) — different function, sibling agent.

## Open questions for adversarial re-review

Q1. Fix A: is a single global `syncWriteDeadline` (2s) the right budget for
    the whole flush, or should the flush get its own (larger?) constant so a
    near-full but draining queue still completes? Trade-off: longer budget =
    more deletes delivered on this connection vs. longer accept-loop block.
Q2. Fix C: force-`handleDisconnect` on timeout drops the connection (and any
    deletes already enqueued to `sendCh` this flush ride out the disconnect
    in `sendCh`, replayed on reconnect). Is dropping a freshly-established
    connection on a transient full-queue acceptable, given it guarantees the
    deferral is disconnect-gated? Any reconnect storm risk if the queue is
    chronically full?
Q3. Fix B: is FIFO-prepend correct given deletes are idempotent by key? Does
    order among deletes actually matter, or is the prepend belt-and-braces?
    (Idempotent-by-key suggests order among pure deletes is not load-
    bearing, but the inversion-vs-new-delete and overflow-drop-bias are real
    correctness issues regardless — confirm the prepend resolves both.)
Q4. Is the residual healthy-interval `QueueDeleteV4` re-journal hazard
    correctly scoped OUT of #2121, or must it be fixed here for the fix to
    be meaningful? (It needs a wire-protocol generation guard.)
Q5. Test injection: tests #1/#2 need a controllable flush timeout. Add an
    unexported `flushSendTimeout time.Duration` field defaulting to
    `syncWriteDeadline`, set small in tests? Acceptable seam?
Q6. Any remaining sequence where v4 is WORSE than the silent drop?
