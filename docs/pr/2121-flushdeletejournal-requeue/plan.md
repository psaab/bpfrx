# #2121 — flushDeleteJournal must not silently drop journaled deletes on a full send queue

Status: DRAFT v2 — revised after Codex PLAN-KILL of v1; pending re-review

## v1 → v2 change (why the design changed)

v1 proposed re-journaling un-sent deletes for retry on the NEXT
reconnect. Codex PLAN-KILLed it for a real ordering regression: deletes
are key-only on the peer (`deleteClusterSynced*` → `DeleteWithCompanions*`
deletes whatever currently owns the key, no generation guard). Deferring
a delete across a healthy connected interval means a stale delete can
replay on a later reconnect AFTER a replacement session with the same key
has been re-synced — wrongly removing the live replacement. That is worse
than the stale standby session the journal exists to prevent. Codex also
correctly refuted v1's "failed messages are a suffix" FIFO claim
(`queueMessage` is retried per-entry; `sendLoop` can drain between
iterations so a later entry can succeed after an earlier one fails) and
noted that re-journal-only does not restore current-connection
convergence.

v2 fixes the bug WITHOUT changing the journal's ordering contract:
**drain the un-sent deletes on the CURRENT connection, before normal sync
resumes**, by writing them directly under `writeMu` — the exact
direct-write path `BulkSync`/`QueueConfig` already use to bypass the
bounded `sendCh`. No deferral, no cross-reconnect re-journal of a delete
while the link is up, no stale-replacement hazard.

## Issue framing

`pkg/cluster/sync_conn.go`. `QueueDeleteV4`/`QueueDeleteV6` follow a
journal-on-failure contract: when `queueMessage` returns false (peer
disconnected or `sendCh` full), the delete is re-journaled via
`journalDelete` so it is not lost. `flushDeleteJournal` — invoked from
`handleNewConnection` on the first post-disconnect connection — drains
the whole journal under lock (`s.deleteJournal = nil`), then replays each
message via `queueMessage`. It does **not** handle a `queueMessage`
failure: a delete that hits a full `sendCh` (cap 4096) during replay is
silently dropped (the journal was already nil'd). The dropped delete
leaves a stale session on the peer until it independently ages out.

Severity: LOW — narrow window (queue full immediately after a fresh
connect, before the send loop drains it), consequence is a stale standby
session, not a forwarding error.

## Honest scope / value framing

Small, focused HA-correctness fix in the control-plane session-sync
reconnect path. Not a perf change, not a dataplane (hot-path) change. The
win: every journaled delete is delivered on the reconnect, in journal
order, before normal sync resumes — no silent loss, no ordering
regression. If reviewers conclude the change is unnecessary or the
direct-write approach introduces a worse failure mode, PLAN-KILL is
acceptable.

## Relevant existing behavior (verified against master 325d10683)

- Journaled messages are **full framed frames**: `encodeDeleteV4`/`V6`
  return `syncHeaderSize+payload` bytes (magic, type, length, body). They
  are written verbatim by `sendLoop` via `writeFull(conn, msg)` — NOT
  re-framed with `writeMsg`.
- `sendLoop` (sync_conn.go:681) pulls each `sendCh` message and writes it
  under `writeMu` via `writeFull`, retrying on disconnect.
- The established **direct-write, bypass-sendCh** pattern: `BulkSync`
  (sync_bulk.go:79) and `QueueConfig` (sync_conn.go:566) take `writeMu`,
  call `writeMsg(conn, ...)`, and on error call `s.handleDisconnect(conn)`
  and stop. `BulkSync` writes potentially thousands of messages this way.
- `flushDeleteJournal` is called only from `handleNewConnection` when
  `wasDisconnected` is true (sync_conn.go:200), synchronously, BEFORE
  `OnPeerConnected` and before bulk sync, on the connection-accept
  goroutine. While disconnected `syncSweep` does not advance, so the flush
  replays the outage's deletes before any newer session state can become
  durable on the peer — the ordering contract v2 must preserve.
- `journalDelete` (sync_conn.go:534) is the bounded ring append: evicts
  oldest + increments `DeletesDropped` at cap (`deleteJournalCap`,
  default 10000). Takes `deleteJournalMu`.
- `DeletesSent` is incremented only on a real send. `DeletesDropped` is
  surfaced in `SyncStatsSnapshot` (sync.go:477).

## Concrete design

Rewrite the `flushDeleteJournal` replay loop to **write each journaled
delete directly to the active connection under `writeMu`** (mirror
`BulkSync`), instead of enqueueing to the bounded `sendCh`. This delivers
every journaled delete on the current connection, in journal order,
before normal sync resumes — eliminating the `sendCh`-full drop and
preserving the ordering contract.

```go
func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	conn := s.getActiveConn()
	if conn == nil {
		// No active connection: re-journal everything for the next
		// reconnect flush (the original journal-on-disconnect contract —
		// safe because the next flush again runs before normal sync).
		s.rejournalAll(journal)
		return
	}
	var sent int
	// Replay journaled delete frames directly under writeMu (bypassing the
	// bounded sendCh, like BulkSync) so they are delivered IN ORDER on the
	// current connection before normal sync resumes. Journaled messages are
	// already fully framed (encodeDeleteV4/V6), so write them verbatim.
	for i, msg := range journal {
		s.writeMu.Lock()
		err := writeFull(conn, msg)
		s.writeMu.Unlock()
		if err != nil {
			// Genuine disconnect mid-flush: re-journal the un-sent tail
			// (including this one) for the next reconnect flush, and tear
			// down the connection like the other senders.
			s.rejournalAll(journal[i:])
			s.stats.Errors.Add(1)
			s.handleDisconnect(conn)
			slog.Warn("cluster sync: delete journal flush write error, re-journaled un-sent tail",
				"err", err, "total", len(journal), "sent", sent, "rejournaled", len(journal)-i)
			return
		}
		s.stats.DeletesSent.Add(1)
		sent++
		// Yield periodically so barrier/ack writers can acquire writeMu
		// (Go mutex is not fair) — mirror BulkSync's runtime.Gosched().
		if sent%64 == 0 {
			runtime.Gosched()
		}
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "sent", sent)
}

// rejournalAll re-appends un-sent delete frames to the journal under lock,
// honoring the bounded cap (journalDelete increments DeletesDropped on
// eviction). Used only when the connection is gone — the next reconnect
// flush will replay them before normal sync resumes.
func (s *SessionSync) rejournalAll(msgs [][]byte) {
	for _, msg := range msgs {
		s.journalDelete(msg)
	}
}
```

### Why direct-write on the current connection (vs sendCh / vs block)

- **Preserves the ordering contract.** Sequential `writeFull` under one
  `writeMu` delivers the journaled deletes in strict journal order, on the
  current connection, before `handleNewConnection` proceeds to
  `OnPeerConnected`/bulk. No delete is deferred across a healthy interval,
  so the v1 stale-replacement-delete hazard cannot occur.
- **No silent drop.** There is no bounded queue to overflow on the flush
  path. `writeFull` blocks on TCP backpressure (with `syncWriteDeadline`),
  it does not drop.
- **Does not stall indefinitely.** `writeFull` has a write deadline
  (`syncWriteDeadline`); a wedged peer trips the deadline → error →
  `handleDisconnect` + re-journal-tail (correct: genuinely failing peer,
  defer to next reconnect). This is the same bound `BulkSync`/`sendLoop`
  rely on.
- **Consistent with the codebase.** `BulkSync` already direct-writes far
  more messages on this exact goroutine sequence under `writeMu`.

### Re-journal only on genuine disconnect

Re-journaling now happens ONLY when there is no active connection (or a
write fails → disconnect). In that case deferring to the next reconnect
flush is correct and matches the original journal-on-disconnect contract:
the next flush again runs before normal sync resumes, so the deletes still
replay ahead of newer session state. The v1 "re-journal while connected
and retry next reconnect" path — the source of the ordering regression —
is gone.

## Public API preservation

No exported API changes. `flushDeleteJournal`, `journalDelete`,
`queueMessage`, `rejournalAll` are unexported. `SyncStats` fields and
semantics unchanged (`DeletesSent` still per-send; `DeletesDropped` still
cap-eviction). No new field.

## Hidden invariants the change must preserve

1. **Lock ordering**: `flushDeleteJournal` releases `deleteJournalMu`
   before writing; `rejournalAll`/`journalDelete` re-take it from outside
   any held lock. `writeMu` is taken/released per message (never held
   across `deleteJournalMu`). No new lock nesting vs `BulkSync`.
2. **writeMu serialization**: direct writes serialize with `sendLoop`,
   heartbeat, bulk, config writers on `writeMu` — same as every other
   sender. Frame integrity preserved (whole frame written under the lock).
3. **No double-send / accounting**: `DeletesSent` incremented once per
   successful `writeFull`. Re-journaled (disconnect) messages are not
   counted as sent.
4. **Bounded re-journal**: `rejournalAll` → `journalDelete` honors the cap
   and counts genuine loss via `DeletesDropped`.
5. **Termination**: loop bounded by captured `journal`; re-journaled
   messages go to `s.deleteJournal`, not the loop slice. No livelock.
6. **handleDisconnect on write error**: mirrors `BulkSync`/`sendLoop`
   exactly — required so the dead connection is torn down and reconnect
   re-armed.
7. **Ordering contract**: flush completes (all deletes written, or tail
   re-journaled on disconnect) synchronously before `handleNewConnection`
   calls `OnPeerConnected`/bulk — unchanged call sequence.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Happy path now direct-writes (like BulkSync) instead of via sendCh; same wire output, same writeMu serialization, runs at most once per reconnect. |
| Concurrency / deadlock | LOW | Reuses BulkSync's writeMu+handleDisconnect pattern; deleteJournalMu released before writes. Covered by -race. |
| Performance | NONE | Reconnect-only, bounded by journal len; BulkSync writes far more this way. |
| Architectural mismatch | LOW | Adopts the established direct-write-bypass-sendCh pattern; removes the broken deferred-retry idea. |

## Test plan

New `pkg/cluster` unit tests, `go test -race ./pkg/cluster/`:

1. **TestDeleteJournalFlushDeliversAllOnFullQueue** (non-tautological
   regression): saturate `sendCh` (fill to cap so any `queueMessage` would
   fail), wire an active `net.Pipe` conn, journal N deletes, run
   `flushDeleteJournal` with a reader draining the conn. Assert: ALL N
   frames are read off the wire (in order) and `DeletesSent == N`, and the
   journal is empty. Against the PRE-FIX code (which used `queueMessage`
   into the full `sendCh`) this delivers 0 and drops N — so the test fails
   pre-fix. (Verify by reverting the fix locally.)
2. **TestDeleteJournalFlushRejournalsTailOnDisconnect**: journal N
   deletes, set an active conn, then close the peer side so `writeFull`
   errors after some prefix; assert the un-sent tail is re-journaled (back
   in `s.deleteJournal`) and `handleDisconnect` ran (Connected false), so a
   later reconnect flush re-delivers them.
3. **TestDeleteJournalFlushNoConnRejournals**: journal N deletes with NO
   active conn; flush; assert all N are re-journaled (journal len == N, or
   == cap with `DeletesDropped` for the overflow) and `DeletesSent == 0`.
4. Existing tests still green — note `TestDeleteJournalReconnectConvergence`
   and `TestDeleteJournalBasic` may need the active-conn / reader wiring
   updated since flush now writes directly instead of to `sendCh`; the
   ASSERTED behavior (deletes delivered, journal emptied, DeletesSent==N)
   is preserved.

Gates: `go test -race ./pkg/cluster/`, `go build ./...`, full
`go test ./...` (cluster + dependents).

No loss-cluster iperf smoke: control-plane HA delete-journal replay, not a
dataplane forwarding change.

## Docs

`docs/session-sync-architecture.md` §"Delete Journal" (line 244) and
§"Delete Journal Overflow" (line 425): note that flush now delivers
journaled deletes directly on the reconnect (in order, before normal sync
resumes) and re-journals only on a genuine disconnect, so a full send
queue no longer drops them.

## Out of scope (explicitly)

- `sendCh` capacity (4096) — orthogonal.
- Generation/session-identity guard on deletes (Codex's deeper
  alternative) — larger change touching the wire protocol + receive path;
  not needed once deletes are delivered in-order on the current
  connection. Could be a separate hardening issue.
- A distinct `DeletesRequeued` metric — re-journal now happens only on
  genuine disconnect (already the normal journaled path); the Warn log +
  `DeletesDropped` cover the observable cases.
- #2120 (standby session-expiry / `syncSweep`) — different function, owned
  by a sibling research agent. Untouched.

## Open questions for adversarial review

Q1. Is direct-write-under-`writeMu` on the accept goroutine the right
    drain mechanism, given `BulkSync` already does exactly this on the same
    sequence? Any reason the delete flush must NOT block on TCP
    backpressure the way bulk does?
Q2. `writeFull` uses `syncWriteDeadline`. Is that deadline an acceptable
    upper bound on how long `flushDeleteJournal` can hold up
    `OnPeerConnected`/bulk on a slow peer? (BulkSync accepts the same.)
Q3. Concurrency: while flush direct-writes under `writeMu`, `sendLoop` may
    also be draining `sendCh` and writing under `writeMu`. Both serialize on
    `writeMu` so frames don't interleave, but a normal session/delete
    enqueued to `sendCh` just before reconnect could be written BETWEEN two
    journaled deletes. Deletes are idempotent by key; is any
    delete-vs-session interleave hazardous here, or is "all journaled
    deletes delivered before OnPeerConnected/bulk" the only contract that
    matters?
Q4. On write error mid-flush we re-journal `journal[i:]` and call
    `handleDisconnect`. Is re-journaling the CURRENT failed message (index
    i) correct, or could it have been partially written (torn frame) — does
    `writeFull` guarantee all-or-nothing per frame? (It loops on short
    writes but a mid-frame error leaves a partial frame on the wire; the
    peer then resyncs on disconnect — confirm that's the existing behavior
    for BulkSync too.)
Q5. Test #1 non-tautological: does saturating `sendCh` + asserting frames
    arrive on the wire actually fail against the pre-fix `queueMessage`
    path? (Pre-fix: full sendCh → queueMessage false → silent drop → 0
    frames on the wire.)
Q6. Should `rejournalAll` preserve order strictly (it appends in slice
    order to an empty/!empty journal)? Any case where re-journal order
    matters given the next flush re-delivers in order anyway?
