# #2121 — flushDeleteJournal must not silently drop journaled deletes on a full send queue

Status: DRAFT v5 — radical simplification after THREE NEEDS-MAJOR on v4
(Codex + Claude-SMR + AGY converged: the timeout/force-disconnect/deferral
machinery is the problem). Pending re-review.

## Design history (why every "active drain" variant failed)

- **v1 (non-blocking send; re-journal failures for next-reconnect retry):
  KILLED (Codex)** for an ordering regression vs the existing flush — but
  see the v5 reframing below: re-journal is identical in exposure to the
  already-accepted `QueueDeleteV4` full-queue path, and strictly better
  than the silent drop.
- **v2 (direct-write, bypass sendCh): KILLED (Codex).** Reorders the
  delete ahead of sessions already queued in `sendCh` (not drained on
  disconnect) → resurrection.
- **v3 (through-sendCh, per-message blocking timeout): NEEDS-MAJOR.**
  Per-message reset → O(N·deadline) accept-loop hang on a slow peer.
- **v4 (single global timeout + FIFO-prepend re-journal + force-
  disconnect): THREE NEEDS-MAJOR, converging:**
  - **AGY:** the single global 2s budget → on a slow link the budget
    exhausts mid-flush → force-disconnect → reconnect re-blocks on the
    un-drained `sendCh` → **reconnect storm, 0% sync, worse than the
    silent drop.** Its proposed "progress-resetting timer" reintroduces
    v3's O(N·deadline) hang — so no timeout policy on a synchronous
    blocking flush is correct.
  - **Claude-SMR:** Fix C does NOT close the resurrection hole — a
    replacement `S'(K)` enqueued to `sendCh` before the timeout survives
    the force-disconnect (sendCh not drained) and on reconnect is written
    by `sendLoop`, then the re-journaled `D(K)` (re-enqueued by the next
    flush) lands after it and kills the live `S'(K)`. **Pre-fix this is
    SAFE (drop ⇒ D(K) never sent), so v4 is strictly worse on this path.**
  - **Codex:** dual-fabric — `handleDisconnect(getActiveConn())` closes
    only one fabric (getActiveConn prefers conn0; the other fabric can
    connect during the unlocked flush); flush returns and
    `handleNewConnection` still runs `OnPeerConnected`/`doBulkSync` on the
    remaining fabric, where `BulkSync` direct-writes the live `S'(K)`,
    which the deferred `D(K)` later kills. Worse than the silent drop.

**Unifying conclusion:** the timeout / force-disconnect / active-deferral
machinery is the source of every defect. The original bug is ONLY the
*silent drop*. The minimal fix is to make `flushDeleteJournal`'s full-queue
handling **identical to the already-shipped `QueueDeleteV4` contract**:
non-blocking enqueue, and on a full queue **re-journal (retain) the
un-sent deletes** instead of dropping them — with NO blocking, NO timeout,
NO force-disconnect. This fixes the drop, matches the issue's stated goal
("Match how the session-UPSERT/delete sync path handles queue-full"), and
introduces **no hazard beyond what `QueueDeleteV4` already has**.

## Issue framing

`pkg/cluster/sync_conn.go`. `flushDeleteJournal` drains the bounded delete
journal under lock (`s.deleteJournal = nil`), then replays each delete via
`queueMessage`, whose `sendCh` send is **non-blocking**. On a full `sendCh`
(cap 4096) the un-sent deletes are **silently dropped** (journal already
nil'd), leaving stale sessions on the peer. By contrast `QueueDeleteV4`/`V6`
already RE-JOURNAL on a `queueMessage` failure (sync_conn.go:515-529) — the
flush path is the lone inconsistency. The issue asks for exactly this:
"re-journal ... any message for which queueMessage returns false, instead
of dropping it ... Mirror the QueueDeleteV4 contract."

Severity: LOW.

## Relevant existing behavior (verified, master 325d10683)

- `queueMessage` (sync_conn.go:484): non-blocking `select { case s.sendCh
  <- msg: sent++; return true; default: Errors++; set syncBackfillNeeded;
  return false }`. The single source of `sendCh` enqueues for sessions and
  deletes; ordering with queued sessions is preserved for messages that DO
  enqueue.
- `QueueDeleteV4`/`V6` (515-529): `if !queueMessage(...) { journalDelete }`.
  This ALREADY journals deletes that hit a full `sendCh` **while connected**
  (queueMessage returns false on a full queue regardless of Connected).
  That delete then replays on the next reconnect flush — i.e. the
  "healthy-interval deferral" exposure already exists and is accepted.
- `journalDelete` (534): bounded ring, FIFO front-eviction +
  `DeletesDropped++` at cap (default 10000).
- `flushDeleteJournal` runs in `handleNewConnection` (200) before
  `OnPeerConnected`/`doBulkSync`. `handleDisconnect` does NOT drain
  `sendCh`.
- `DeletesSent` is incremented inside `queueMessage` on a successful
  enqueue (so the flush does not separately count).

## Concrete design (v5)

Replace the flush's drop-on-failure with re-journal-on-failure, FIFO-
correct. No blocking, no timeout, no disconnect.

```go
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
	// is non-blocking and increments DeletesSent on success; on a full
	// sendCh it returns false. Mirror the QueueDeleteV4 contract: re-journal
	// (retain) the un-sent tail instead of dropping it, so it replays on the
	// next reconnect flush. The journal was nil'd, so re-journaling here is
	// the SAME deferral the QueueDeleteV4 full-queue path already performs —
	// no new hazard, and strictly better than the previous silent drop.
	for i, msg := range journal {
		if s.queueMessage(msg, &s.stats.DeletesSent, "journal_flush") {
			flushed++
			continue
		}
		// First failure: queue is full. Re-journal this message and the rest
		// (FIFO-prepended ahead of any deletes concurrently journaled during
		// the flush) and stop — further attempts on a full queue would also
		// fail, and stopping preserves order.
		s.rejournalTail(journal[i:])
		slog.Warn("cluster sync: delete journal flush hit full send queue, re-journaled un-sent tail for next reconnect",
			"total", len(journal), "flushed", flushed, "rejournaled", len(journal)-i,
			"queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		return
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "flushed", flushed)
}

// rejournalTail re-inserts the un-sent delete tail at the FRONT of the
// journal so it replays BEFORE any deletes concurrently journaled during
// the flush (preserve FIFO). On overflow it drops the OLDEST entries from
// the front of the merged list, counted in DeletesDropped — never the
// newer concurrently-journaled deletes. Single lock acquisition.
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
	merged := make([][]byte, 0, capN)
	if dropped < len(tail) {
		merged = append(merged, tail[dropped:]...)
		merged = append(merged, s.deleteJournal...)
	} else {
		merged = append(merged, s.deleteJournal[dropped-len(tail):]...)
	}
	s.deleteJournal = merged
}
```

(Stop at the first failure rather than re-trying each message: once `sendCh`
is full the rest will fail too, and stopping keeps the un-sent suffix
contiguous and ordered. This matches `QueueDeleteV4`, which makes a single
attempt per delete.)

### Why this is correct AND never worse than today

- **Fixes the filed bug:** un-sent journaled deletes are RETAINED, not
  dropped. They replay on the next reconnect flush.
- **No new hazard:** the only behavior change on failure is "re-journal"
  vs "drop". Re-journal is exactly what `QueueDeleteV4` already does on a
  full queue (sync_conn.go:517), so the deferred-delete-vs-replacement
  exposure is identical to existing, accepted behavior — NOT introduced or
  widened by #2121.
- **Never worse than the silent drop:** for any `D(K)` that today is
  silently dropped, v5 retains it for later delivery. The only outcome
  difference is "D(K) eventually delivered" vs "D(K) lost". Delivering the
  delete is the issue's goal (the lost delete is the bug). The
  replacement-resurrection concern is the pre-existing journal property,
  not a regression here.
- **No liveness risk:** non-blocking throughout (queueMessage's
  `default`). No timeout, no force-disconnect, no reconnect storm, no
  accept-loop hang, no dual-fabric teardown — all the v3/v4 hazard surface
  is gone.
- **Ordering for the delivered deletes:** the deletes that DO enqueue go
  through `sendCh` in journal order behind already-queued sessions (the v2
  reorder cannot occur — same single ordered path). The re-journaled tail
  is FIFO-prepended so a later flush replays it before concurrently-
  journaled newer deletes.

### Residual exposure (pre-existing, scoped out)

The "a journaled delete can kill a same-key replacement re-synced before
it replays" class is intrinsic to key-only deletes + a reconnect-surviving
journal. It already exists for `QueueDeleteV4`'s full-queue and disconnect
journaling. #2121 does not widen it (v5 only changes drop→retain on the
flush path, matching `QueueDeleteV4`). Fully eliminating it needs a wire-
protocol generation/session-identity guard on deletes — a larger,
backward-incompatible change. **Recommend a follow-up issue.** #2121
deliberately does the narrow, safe fix.

## Public API preservation

No exported changes. `flushDeleteJournal`, `rejournalTail`,
`journalDelete`, `queueMessage` unexported. `SyncStats` fields/semantics
unchanged. No new field, no test seam needed (non-blocking ⇒ no timing
dependence in tests).

## Hidden invariants preserved

1. `deleteJournalMu` released before the loop; `rejournalTail` re-takes it
   once from outside any held lock. No new lock nesting.
2. No lock held across `queueMessage` (it takes none of these locks).
3. FIFO: delivered deletes share the single `sendCh → sendLoop` path with
   queued sessions; the re-journaled tail is FIFO-prepended.
4. `DeletesSent` incremented once per enqueue inside `queueMessage`;
   re-journaled messages are not counted as sent (no double-count — the v4
   double-count came from the force-disconnect path, which is gone).
5. Bounded journal: `rejournalTail` enforces cap; overflow drops oldest,
   counts `DeletesDropped`.
6. Termination: loop bounded by captured `journal`; stops at first failure;
   re-journaled messages go to `s.deleteJournal`, not the loop slice.
7. Single-flush per reconnect (mutex-gated `wasDisconnected`).
8. Concurrency: a `QueueDeleteV4` racing the flush appends to the new
   (nil'd→empty) journal; `rejournalTail` FIFO-prepends the older tail
   ahead of it under one lock. No race, no lost delete (validated -race).

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Only change: full-queue branch drop→retain, matching QueueDeleteV4. |
| Concurrency / deadlock | LOW | Non-blocking; single-lock rejournalTail. -race covered. |
| Liveness | NONE | No blocking/timeout/disconnect. |
| Ordering | LOW | Single ordered sendCh path; FIFO-prepend tail. Residual key-only-delete class pre-existing, scoped out. |
| Performance | NONE | Reconnect-only, non-blocking. |

## Test plan

New `pkg/cluster` tests, `go test -race ./pkg/cluster/`:

1. **TestDeleteJournalFlushRetainsTailOnFullQueue** (non-tautological
   regression): Connected=true, NO drainer; pre-fill `sendCh` to cap so
   `queueMessage` fails immediately; journal N deletes; `flushDeleteJournal`.
   Assert: `s.deleteJournal` now holds all N (re-journaled, FIFO order),
   `DeletesSent == 0`, `DeletesDropped == 0` (N ≤ cap). Pre-fix: journal
   nil'd + all dropped → `len(s.deleteJournal)==0` → test fails pre-fix.
   Deterministic (no goroutine/timing — sendCh full ⇒ queueMessage's
   `default` fires synchronously).
2. **TestDeleteJournalFlushPartialThenRetains**: cap-3 `sendCh`, drain
   nothing; Connected=true; journal 5 deletes; flush. Assert `DeletesSent
   == 3` (first 3 enqueue), the un-sent 2 are re-journaled at the FRONT,
   journal len == 2.
3. **TestRejournalTailFIFOPrependAndOverflow** (unit-test rejournalTail
   directly): seed `s.deleteJournal` with concurrent `[N1,N2]`; call
   `rejournalTail([T3,T4,T5])`; assert order `[T3,T4,T5,N1,N2]`. Then with a
   small cap assert overflow drops oldest tail first
   (`[T4,T5,N1,N2]`/`[N2,N3]`-style per the dry-runs) and `DeletesDropped`
   counts exactly the dropped.
4. **TestDeleteJournalFlushAllFit**: room in `sendCh` + a drainer; journal
   N; flush; assert `DeletesSent == N`, journal empty.
5. **TestDeleteJournalFlushOrderingWithQueuedSession**: enqueue a session
   frame to `sendCh`, then flush a same-key delete (with room); drain;
   assert session read BEFORE delete (through-sendCh FIFO).
6. Existing `TestDeleteJournalBasic` / `…Overflow` / `…FlushNoEntries` /
   `…ReconnectConvergence` / `TestSessionQueueDoesNotJournal` still green
   (v5 preserves their asserted outcomes: deletes delivered when room,
   journal emptied, `DeletesSent==N`).

Gates: `go test -race ./pkg/cluster/`, `go build ./...`, full
`go test ./...`.

No loss-cluster iperf smoke: control-plane HA delete-journal replay logic.

## Docs

`docs/session-sync-architecture.md` §"Delete Journal" (244) + §"Delete
Journal Overflow" (425): flush now re-journals (retains) un-sent deletes
on a full send queue — matching `QueueDeleteV4` — instead of dropping
them; they replay on the next reconnect; genuine loss only at the journal
cap (`DeletesDropped`).

## Out of scope (explicitly)

- Generation/session-identity guard on deletes (closes the residual
  key-only-delete-kills-replacement class) — separate wire change; FILE A
  FOLLOW-UP ISSUE.
- Delivering ALL journaled deletes on the CURRENT connection regardless of
  queue depth (the v3/v4 goal) — every mechanism for it (blocking,
  timeout, force-disconnect) was shown worse than the narrow fix. The
  deletes that don't fit replay on the next reconnect, exactly as
  `QueueDeleteV4`'s full-queue deletes already do.
- `sendCh` capacity (4096).
- #2120 (`syncSweep`) — different function, sibling agent.

## Open questions for adversarial re-review

Q1. Is v5 genuinely never-worse-than-the-silent-drop? Construct any
    sequence where retaining (re-journaling) the un-sent delete produces a
    worse outcome than dropping it. (Claim: no — drop loses the delete;
    retain delivers it later, which is the bug's intent; the
    replacement-resurrection class is pre-existing in QueueDeleteV4.)
Q2. Is stopping at the first failure (vs attempting every message) correct
    given `sendCh` is full at that point and order must be preserved?
Q3. Is the FIFO-prepend in `rejournalTail` necessary, or would a plain
    append suffice (deletes idempotent by key)? (Prepend still correct for
    overflow-eviction bias even if intra-delete order is not load-bearing.)
Q4. Does v5 leave the issue meaningfully fixed (silent drop eliminated),
    or does the "deletes that don't fit wait for next reconnect" deferral
    make it a no-op? Note `QueueDeleteV4` already behaves this way; the
    delta is purely drop→retain on the flush path.
Q5. Any concurrency hazard between the flush's nil-ing of `s.deleteJournal`
    and a concurrent `QueueDeleteV4`→`journalDelete` (race / lost delete /
    eviction bias) that `rejournalTail`'s single-lock prepend does not
    cover?
Q6. Is reusing `DeletesDropped` (cap eviction only) + the Warn log
    sufficient observability for "flush hit a full queue and deferred",
    or is a distinct counter warranted?
