# #2121 — flushDeleteJournal must not silently drop journaled deletes on a full send queue

Status: DRAFT v1 — pending adversarial plan review

## Issue framing

`pkg/cluster/sync_conn.go`. `QueueDeleteV4`/`QueueDeleteV6` follow a
journal-on-failure contract: when `queueMessage` returns false (peer
disconnected or `sendCh` full), the delete is re-journaled via
`journalDelete` so it is not lost. `flushDeleteJournal` — invoked from
`handleNewConnection` on the first post-disconnect connection — drains
the whole journal under lock (`s.deleteJournal = nil`), then replays each
message via `queueMessage` directly. It does **not** re-journal a message
for which `queueMessage` returns false.

Consequence: if `sendCh` (cap 4096) is full at replay time — a large
delete journal coinciding with bulk/session traffic on the same channel
immediately after connect — the deletes that hit the full channel are
silently dropped. The journal was already nil'd, so they are neither
sent nor retained. A dropped delete leaves a stale session on the peer
until it independently ages out, defeating the journal's purpose
(preventing indefinite stale-session leak across a disconnect).
`queueMessage` sets `syncBackfillNeeded` on overflow, but that triggers
a SESSION re-sweep (re-sending sessions), not a delete replay — so a
dropped delete is not recovered.

Severity: LOW. The window (queue full immediately after a fresh connect,
before the send loop drains it) is narrow and the consequence is a stale
standby session, not a forwarding error.

## Honest scope / value framing

This is a small, focused HA-correctness fix in the control-plane session-
sync path. It is not a perf change and not a dataplane (hot-path) change.
The win is: no journaled delete is silently lost on the flush path; the
flush path becomes consistent with the `QueueDeleteV4` contract; and any
genuinely-unavoidable bounded loss (journal cap reached) is surfaced via
the existing `DeletesDropped` counter + a log line rather than vanishing.

If reviewers conclude the change is unnecessary (e.g. the drop is already
recovered by some path I missed) or wrong (re-journaling introduces a
worse failure mode), PLAN-KILL is an acceptable verdict.

## What's already shipped / relevant existing behavior

- `journalDelete(msg)` (sync_conn.go:534) is the bounded ring-buffer
  append. It evicts the oldest entry and increments `DeletesDropped`
  when the journal is at cap (`deleteJournalCap`, default
  `deleteJournalDefaultCap = 10000`). It takes `deleteJournalMu`.
- `QueueDeleteV4`/`V6` (sync_conn.go:517/526) call
  `journalDelete(msg)` when `queueMessage` returns false. This is the
  contract to mirror.
- `queueMessage` (sync_conn.go:484) returns false when not connected or
  when `sendCh` is full; on a full-channel failure it sets
  `syncBackfillNeeded` (session re-sweep) and increments `Errors`.
- `flushDeleteJournal` is called only from `handleNewConnection` when
  `wasDisconnected` is true (sync_conn.go:200), before `OnPeerConnected`
  and before bulk sync. It runs on the connection-accept goroutine, not
  under `s.mu`.
- `DeletesDropped` is surfaced in `SyncStatsSnapshot` (sync.go:477) and
  thus to status/metrics consumers.

## Concrete design

In `flushDeleteJournal`, when `queueMessage` returns false during the
replay loop, re-journal that message via `journalDelete(msg)` instead of
dropping it. This mirrors the `QueueDeleteV4` contract exactly.

```go
func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	var flushed, requeued int
	// Replay journaled delete messages before normal sync resumes. If the
	// send queue is full mid-replay, re-journal the un-sent delete (mirror
	// the QueueDeleteV4 journal-on-failure contract) so it is retried on
	// the next flush instead of being silently lost. journalDelete itself
	// enforces the bounded cap and increments DeletesDropped if the ring
	// is genuinely full, so unavoidable loss stays observable.
	for _, msg := range journal {
		if s.queueMessage(msg, &s.stats.DeletesSent, "journal_flush") {
			flushed++
			continue
		}
		s.journalDelete(msg)
		requeued++
	}
	if requeued > 0 {
		slog.Warn("cluster sync: delete journal flush hit full send queue, re-journaled un-sent deletes for retry",
			"total", len(journal), "sent", flushed, "requeued", requeued,
			"journal_len_after", s.deleteJournalLen())
	} else {
		slog.Info("cluster sync: flushed delete journal", "total", len(journal), "sent", flushed)
	}
}
```

`deleteJournalLen()` is a tiny lock-guarded accessor (`len(s.deleteJournal)`
under `deleteJournalMu`) added for the log line; if reviewers prefer, the
log can omit it to avoid a re-lock — open question Q5.

### Why re-journal (not block / not stop-and-restore-tail)

The issue lists three options: block/retry until drained, re-queue failed
deletes, or stop and restore the un-flushed tail. Re-journaling per-failed-
message is chosen because:

1. It is the **exact contract `QueueDeleteV4` already uses** — consistency
   was an explicit goal in the issue. One code path, one behavior.
2. It does **not block** the connection-accept goroutine. Blocking until
   `sendCh` drains would stall `handleNewConnection` (and therefore
   `OnPeerConnected`/bulk sync) behind the send loop, on the very goroutine
   that accepted the connection — a worse failure mode than a deferred
   retry. `queueMessage` is deliberately non-blocking everywhere else.
3. Re-journaled deletes are retried on the next `flushDeleteJournal`, which
   fires on the next first-post-disconnect connection. In the meantime they
   sit in the bounded ring exactly as a delete journaled while disconnected
   would — no new invariant.
4. `journalDelete` already enforces the cap and increments `DeletesDropped`,
   so if the ring is genuinely full the loss is surfaced (counter + the new
   Warn log), satisfying the "if bounded loss is unavoidable, surface it"
   fallback in the issue.

### Ordering note (re-journal preserves FIFO-enough semantics)

The journal is a ring (oldest-first). When we re-journal failed messages
during a flush, they append to the tail of the now-empty journal. Because
`sendCh` fills up only after some prefix succeeded, the failed messages are
a suffix of the original order, so re-appending them preserves their
relative order. Deletes are idempotent on the peer (delete-by-key), so
absolute global ordering vs. other message types is not required — a delete
that arrives "late" still removes the stale entry.

## Public API preservation

No exported API changes. `flushDeleteJournal`, `journalDelete`,
`queueMessage` are all unexported. `SyncStats.DeletesDropped` semantics are
unchanged (still: a journaled delete the bounded ring could not retain).
No new exported field. (`deleteJournalLen()` is an unexported helper.)

## Hidden invariants the change must preserve

1. **Lock ordering / no deadlock**: `flushDeleteJournal` releases
   `deleteJournalMu` before the replay loop (current behavior). `journalDelete`
   re-acquires `deleteJournalMu` per failed message — called from OUTSIDE
   the lock, so no re-entrant deadlock. `queueMessage` does not take
   `deleteJournalMu`. Confirm no path holds `deleteJournalMu` across
   `journalDelete`.
2. **Concurrent `QueueDeleteV4` during flush**: while a flush runs,
   `QueueDeleteV4` on another goroutine may call `journalDelete`
   concurrently. Both serialize on `deleteJournalMu`; the slice append is
   safe. The re-journaled flush messages and concurrently-journaled new
   deletes interleave in the ring — both are valid deletes, order among
   them is not load-bearing (idempotent by key). No data race (validated
   under `-race`).
3. **No unbounded growth**: re-journaling is bounded by `deleteJournalCap`
   via `journalDelete`'s eviction. A persistently-full `sendCh` cannot grow
   the journal past cap.
4. **`DeletesSent` accounting**: only incremented on a real channel enqueue
   (inside `queueMessage`). Re-journaled messages do not double-count.
5. **`syncBackfillNeeded` still set**: `queueMessage`'s overflow path still
   fires (session re-sweep), unchanged.
6. **Termination**: the flush loop is bounded by the captured `journal`
   slice length; re-journaled messages go to `s.deleteJournal`, NOT back
   into the loop's `journal` — so the loop cannot livelock.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure additive on the false-branch; success path (flushed++) unchanged. Empty-journal early return unchanged. |
| Lifetime / concurrency | LOW | journalDelete called outside the lock it takes; -race covers the concurrent-journal interleave. |
| Performance | NONE | Control-plane reconnect path, runs at most once per reconnect; bounded by journal len. Not a hot path. |
| Architectural mismatch | LOW | Reuses the established journal-on-failure contract; no new mechanism. |

## Test plan

New `pkg/cluster` unit tests, run with `go test -race ./pkg/cluster/`:

1. **TestDeleteJournalFlushRequeuesOnFullQueue** (the non-tautological
   regression test): construct a `SessionSync` with a TINY `sendCh` (e.g.
   replace with a cap-2 channel) and Connected=true. Journal N>2 deletes.
   Pre-fill / saturate `sendCh` so only the first 2 enqueue succeed. Call
   `flushDeleteJournal`. Assert: `DeletesSent == 2`, and the journal now
   contains the remaining N-2 messages (re-journaled), NOT empty. Pre-fix
   this FAILS (journal is empty — deletes dropped). Confirm it fails
   against base by reverting the fix locally.
2. **TestDeleteJournalFlushRequeueRetriedOnNextFlush**: after #1, drain
   `sendCh` and call `flushDeleteJournal` again; assert the remaining
   deletes now flush (DeletesSent reaches N) and the journal empties —
   proving the re-journaled deletes are actually retried, not just parked.
3. **TestDeleteJournalFlushRequeueRespectsCapAndCounts**: set a small
   `deleteJournalCap`; saturate `sendCh`; journal more than cap; flush;
   assert journal len == cap and `DeletesDropped` increments for the
   genuinely-evicted ones (surfaced bounded loss). This proves the
   fallback path in the issue.
4. Existing tests unchanged and still green: `TestDeleteJournalBasic`,
   `TestDeleteJournalOverflow`, `TestDeleteJournalFlushNoEntries`,
   `TestDeleteJournalReconnectConvergence`, `TestSessionQueueDoesNotJournal`.

Gates:
- `go test -race ./pkg/cluster/` green.
- `go build ./...` clean.
- Full `go test ./...` for the cluster package + dependents.

No loss-cluster iperf smoke: this is control-plane HA delete-journal
replay logic, not a dataplane forwarding change. The standing
"smoke v4+v6, per-class CoS" matrix in the triple-review skill is for
dataplane/CoS refactors and does not apply.

## Docs

`docs/session-sync-architecture.md` §"Delete Journal" (line 244) and
§"Delete Journal Overflow" (line 425) describe the journal + replay. The
Delete Journal section will be updated to note that flush re-journals
un-sent deletes on a full send queue (retry on next reconnect) rather than
dropping them, and that genuinely-unavoidable loss at the journal cap is
counted in `DeletesDropped`. No other doc references the flush path.

## Out of scope (explicitly)

- Changing `sendCh` capacity (4096) — orthogonal sizing question.
- Blocking/backpressure redesign of `queueMessage` — rejected above
  (would stall the accept goroutine).
- A dedicated `DeletesRequeued` Prometheus counter — the Warn log surfaces
  the requeue, and `DeletesDropped` surfaces genuine loss. Could be a
  trivial follow-up if operators want a metric for "requeue happened" vs
  "drop happened"; not needed for correctness. Open question Q4.
- #2120 (standby session-expiry / `syncSweep`) — a DIFFERENT function in
  the same file, owned by a sibling research agent. Untouched here.

## Open questions for adversarial review

Q1. Is re-journal (vs block-until-drained vs stop-and-restore-tail) the
    right choice given `flushDeleteJournal` runs on the connection-accept
    goroutine before `OnPeerConnected`/bulk sync? Argue for blocking if you
    think the deferred-retry window is unacceptable.
Q2. Re-journaled deletes are only retried on the NEXT first-post-disconnect
    flush. If the link stays up, they sit in the journal until the next
    disconnect/reconnect. Is that acceptable, or must they be drained on
    the current connection (e.g. by a deferred re-flush once `sendCh`
    drains)? Note: the session re-sweep (`syncBackfillNeeded`) re-sends
    SESSIONS but not deletes, so a still-open standby session for a deleted
    flow is the failure being fixed — does the deferred-retry fully close
    it, or only on next reconnect?
Q3. Concurrency: a `QueueDeleteV4` racing the flush both call
    `journalDelete`. Any ordering or correctness hazard beyond "interleaved
    but all valid"? Any case where a re-journaled delete could be evicted by
    a concurrent journal append before it is ever retried (silent loss under
    the cap path)? Is the `DeletesDropped` accounting still meaningful?
Q4. Counter design: is reusing `DeletesDropped` (only on genuine cap
    eviction) + a Warn log sufficient, or does the issue's "surface via a
    counter" intent require a distinct `DeletesRequeued` metric?
Q5. Is the `deleteJournalLen()` re-lock for the log line worth it, or should
    the log omit journal_len_after to avoid re-taking `deleteJournalMu`?
Q6. Is the FIFO/ordering reasoning (failed messages are a suffix; deletes
    idempotent by key) sound? Any scenario where late delete arrival is
    incorrect (e.g. key reuse — a NEW session installed with the same key
    before the stale delete arrives, and the delete then removes the new
    session)? How does the existing journal already handle that, and does
    re-journal change the exposure?
