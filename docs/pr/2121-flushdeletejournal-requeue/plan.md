# #2121 — flushDeleteJournal must not silently drop journaled deletes on a full send queue

Status: DRAFT v3 — revised after Codex PLAN-KILL of v1 AND v2; pending re-review

## Design history (why v1 and v2 were killed)

- **v1 (re-journal for next-reconnect retry): KILLED.** Deferring a
  journaled delete across a healthy connected interval can replay it on a
  later reconnect after a replacement session with the same key was
  re-synced, wrongly deleting the live replacement (deletes are key-only
  on the peer — `deleteClusterSynced*` → `DeleteWithCompanions*`, no
  generation guard). Codex also refuted v1's FIFO "suffix" claim.
- **v2 (direct-write under writeMu, bypass sendCh): KILLED.** Bypassing
  `sendCh` re-orders the delete ahead of session frames already queued in
  `sendCh`. Concrete resurrection: (1) `S(K)` queued to `sendCh` while
  connected, not yet written; (2) connection drops — **`handleDisconnect`
  does NOT drain `sendCh`** (verified, sync_conn.go); (3) `D(K)` journaled
  while disconnected; (4) reconnect flush direct-writes `D(K)`; (5)
  `sendLoop` later writes the stale queued `S(K)`, resurrecting the
  deleted session. Codex noted the codebase already solves this class:
  **barriers deliberately go through `sendCh`** (`writeBarrierMessage`,
  sync_bulk.go:308) "to preserve ordering with already-queued session
  messages."

## v3 design (the correct ordering discipline)

Replay journaled deletes **through `sendCh`, with a bounded blocking
send** — exactly the pattern `writeBarrierMessage` uses for ordering-
sensitive stream messages. This reconciles the two kill findings:

- Through `sendCh` ⇒ the delete is enqueued **behind** any session frames
  already queued in `sendCh`, then drained by `sendLoop` in FIFO order →
  no S(K)/D(K) reordering (fixes v2 kill).
- Blocking (bounded) send instead of `queueMessage`'s non-blocking
  `select/default` ⇒ a full `sendCh` no longer drops; the flush waits for
  `sendLoop` to make room (fixes the original bug).
- Re-journal ONLY on send timeout or no-connection ⇒ deferral happens
  only when the stream is genuinely stalled (peer wedged), the one case
  where the next-reconnect flush is the correct place to retry. No
  deferral while the link is healthy (so the v1 stale-replacement hazard
  does not arise in the common case).

## Issue framing

`pkg/cluster/sync_conn.go`. `flushDeleteJournal` — invoked from
`handleNewConnection` on the first post-disconnect connection — drains the
bounded delete journal under lock (`s.deleteJournal = nil`), then replays
each delete via `queueMessage`, whose `sendCh` send is **non-blocking**
(`select { case s.sendCh <- msg: ... default: return false }`). If
`sendCh` (cap 4096) is full at replay time the un-sent deletes are
**silently dropped** (the journal was already nil'd). The dropped delete
leaves a stale session on the peer until it independently ages out,
defeating the journal's purpose. `queueMessage`'s overflow sets
`syncBackfillNeeded`, which re-sweeps SESSIONS (not deletes), so the drop
is not recovered.

Severity: LOW — narrow window (queue full immediately after a fresh
connect, before the send loop drains it), consequence is a stale standby
session, not a forwarding error.

## Relevant existing behavior (verified against master 325d10683)

- Journaled messages are **full framed frames**: `encodeDeleteV4`/`V6`
  return `syncHeaderSize+payload` bytes; `sendLoop` writes them verbatim
  via `writeFull(conn, msg)` (sync_conn.go:694). So a journaled delete is
  a valid `sendCh` element exactly as produced (`QueueDeleteV4` already
  puts the same frame on `sendCh` via `queueMessage`).
- `sendLoop` (sync_conn.go:681) pulls each `sendCh` message and writes it
  under `writeMu`, retrying on disconnect; it drains continuously on a
  healthy connection.
- **Ordering precedent:** `writeBarrierMessage` (sync_bulk.go:308) sends
  through `sendCh` with a timed blocking send
  (`select { case s.sendCh <- msg: case <-timer.C: return err }`)
  expressly "to preserve ordering with already-queued session messages."
  v3 adopts this for delete replay.
- `flushDeleteJournal` runs synchronously in `handleNewConnection`
  (sync_conn.go:200) BEFORE `OnPeerConnected` and bulk, on the accept
  goroutine. `Connected` is set true earlier (sync_conn.go:186), so
  `sendLoop` and producers run concurrently with the flush — which is
  fine: through-`sendCh` FIFO is exactly the ordering we want.
- `handleDisconnect` does NOT drain `sendCh` (verified) — the reason v2's
  bypass was unsafe and why v3 must use the same channel.
- `journalDelete` (sync_conn.go:534): bounded ring append, evicts oldest +
  increments `DeletesDropped` at cap (default 10000). Takes
  `deleteJournalMu`.
- `DeletesSent` incremented only on a real `sendCh` enqueue (inside
  `queueMessage` today; v3 increments on the blocking enqueue). Surfaced
  via `SyncStatsSnapshot`.
- `syncWriteDeadline = 2s` (sync.go:73) — the per-frame wire write bound
  used as the per-message enqueue timeout below.

## Concrete design

```go
func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	var sent int
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	// Replay journaled deletes THROUGH sendCh (not a direct write) so they
	// stay ordered behind any session frames already queued in sendCh, then
	// drain via sendLoop in FIFO order. Use a bounded blocking send (mirror
	// writeBarrierMessage) so a full sendCh does not drop the delete — we
	// wait for sendLoop to make room. On a genuine stall (timeout) or a
	// dropped connection, re-journal the un-sent tail for the next reconnect
	// flush (the original journal-on-disconnect contract — still ordered
	// ahead of normal sync because flush runs before it).
	for i, msg := range journal {
		if !s.stats.Connected.Load() {
			s.rejournalAll(journal[i:])
			slog.Warn("cluster sync: delete journal flush aborted (disconnected), re-journaled tail",
				"total", len(journal), "sent", sent, "rejournaled", len(journal)-i)
			return
		}
		timer.Reset(syncWriteDeadline)
		select {
		case s.sendCh <- msg:
			s.stats.DeletesSent.Add(1)
			sent++
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			// sendCh stayed full past the deadline: stream stalled. Defer
			// the rest to the next reconnect flush rather than spin.
			s.rejournalAll(journal[i:])
			s.stats.Errors.Add(1)
			slog.Warn("cluster sync: delete journal flush stalled on full send queue, re-journaled un-sent tail",
				"total", len(journal), "sent", sent, "rejournaled", len(journal)-i,
				"queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
			return
		}
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "sent", sent)
}

// rejournalAll re-appends un-sent delete frames to the journal under lock,
// honoring the bounded cap (journalDelete counts genuine loss via
// DeletesDropped). Used only when the stream is stalled or the connection
// is gone — the next reconnect flush replays them before normal sync.
func (s *SessionSync) rejournalAll(msgs [][]byte) {
	for _, msg := range msgs {
		s.journalDelete(msg)
	}
}
```

(The single reusable `timer` with the standard drain-on-Reset dance avoids
allocating a timer per message in a possibly-large journal.)

### Why through-sendCh blocking send (vs bypass / vs non-blocking)

- **Ordering:** the delete shares the single `sendCh → sendLoop → writeFull`
  path with queued sessions, so FIFO is preserved — the v2 reordering /
  resurrection cannot occur.
- **No silent drop:** the bounded blocking send waits for room; it never
  takes the `default` drop branch.
- **Bounded liveness:** `sendLoop` drains continuously on a healthy
  connection, so the send rarely blocks; on a wedged peer the per-message
  `syncWriteDeadline` timeout caps the stall and re-journals the rest —
  the same bound `writeBarrierMessage`/`writeFull` rely on. The flush
  cannot hang `handleNewConnection` longer than one write deadline beyond
  the time `sendLoop` needs to drain.
- **No new ordering hazard on the deferral path:** re-journal happens only
  on a stall/disconnect — i.e. when nothing is making it onto the wire
  anyway — so re-journaled deletes still replay on the next reconnect
  before normal sync. This is the SAME exposure the existing
  journal-on-disconnect path already has; v3 does not widen it.

## Public API preservation

No exported API changes. `flushDeleteJournal`, `journalDelete`,
`queueMessage`, `rejournalAll` unexported. `SyncStats` fields/semantics
unchanged. No new field.

## Hidden invariants the change must preserve

1. **No lock held across the blocking send.** `deleteJournalMu` is
   released before the loop; the `sendCh` send holds NO lock (matches
   `writeBarrierMessage`). `rejournalAll`/`journalDelete` re-take
   `deleteJournalMu` from outside any held lock.
2. **No deadlock with sendLoop.** `sendLoop` only blocks on `writeFull`
   (deadline-bounded) or waiting for a conn; it consumes `sendCh`
   independently of any lock the flush holds (none). Blocking send + active
   consumer = progress.
3. **FIFO / ordering:** deletes interleave with queued sessions in `sendCh`
   in submission order; `sendLoop` is the single writer. Same stream-order
   guarantee barriers rely on.
4. **Accounting:** `DeletesSent` incremented once per successful enqueue;
   re-journaled (stall/disconnect) messages are not counted as sent.
5. **Bounded re-journal:** `rejournalAll`→`journalDelete` honors the cap;
   genuine loss surfaced via `DeletesDropped`.
6. **Termination:** loop bounded by captured `journal`; re-journaled
   messages go to `s.deleteJournal`, not the loop slice. No livelock.
7. **Ordering contract preserved:** flush still completes (all enqueued, or
   tail re-journaled) synchronously before `OnPeerConnected`/bulk.
8. **Timer hygiene:** one reused `time.Timer`, drained correctly on Reset
   to avoid a stale fire (the standard Go idiom).

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Still enqueues to sendCh (same wire path as today's queueMessage); only the full-queue branch changes from drop→bounded-block. |
| Concurrency / deadlock | LOW | Mirrors writeBarrierMessage (no lock across send); sendLoop drains independently. Covered by -race. |
| Performance | NONE | Reconnect-only, bounded by journal len; blocking only when sendCh is full (the failure the issue describes). |
| Architectural mismatch | LOW | Adopts the established ordered-through-sendCh pattern; abandons both broken alternatives. |

## Test plan

New `pkg/cluster` unit tests, `go test -race ./pkg/cluster/`:

1. **TestDeleteJournalFlushBlocksThenDeliversOnFullQueue** (non-tautological
   regression): Connected=true, an active `net.Pipe` conn + a `sendLoop`
   (or a manual drainer reading `sendCh` and writing the conn). Pre-fill
   `sendCh` to cap, journal N deletes, start `flushDeleteJournal` in a
   goroutine, then start draining `sendCh` slowly. Assert: all N delete
   frames eventually arrive on the wire IN ORDER (after the pre-filled
   frames), `DeletesSent == N`, journal empty, NO `DeletesDropped`. Against
   PRE-FIX (`queueMessage` non-blocking) the full sendCh drops all N → 0
   frames, journal empty → test fails pre-fix.
2. **TestDeleteJournalFlushStallTimeoutRejournals**: fill `sendCh` to cap
   with NO drainer (stream stalled), set Connected=true, journal N deletes,
   flush. With the per-message `syncWriteDeadline`, the first send times out
   → assert the full tail is re-journaled (`s.deleteJournal` len == N or ==
   cap with `DeletesDropped`), `DeletesSent == 0`, and an `Errors` bump.
   (Use a test-injected short deadline if `syncWriteDeadline` is too long
   for the suite — see Q5.)
3. **TestDeleteJournalFlushDisconnectedRejournals**: Connected=false,
   journal N deletes, flush; assert all re-journaled, `DeletesSent == 0`.
4. **TestDeleteJournalFlushOrderingWithQueuedSession**: enqueue a session
   frame to `sendCh`, then flush a delete for the SAME key; drain and assert
   the session frame is read BEFORE the delete (proving through-sendCh FIFO
   — the property v2 violated).
5. Existing tests still green; update `TestDeleteJournalBasic` /
   `TestDeleteJournalReconnectConvergence` wiring as needed (they still
   assert deletes delivered + journal emptied + `DeletesSent==N`, which
   v3 preserves).

Gates: `go test -race ./pkg/cluster/`, `go build ./...`, full
`go test ./...`.

No loss-cluster iperf smoke: control-plane HA delete-journal replay, not a
dataplane forwarding change.

## Docs

`docs/session-sync-architecture.md` §"Delete Journal" (244) and §"Delete
Journal Overflow" (425): note flush now replays journaled deletes through
the ordered send stream with a bounded blocking enqueue (so a full send
queue blocks until drained rather than dropping), and re-journals only on
a genuine stall/disconnect.

## Out of scope (explicitly)

- `sendCh` capacity (4096) — orthogonal.
- Generation/session-identity guard on deletes — larger wire+receive
  change; not required once deletes are ordered through `sendCh`. Possible
  separate hardening issue.
- A distinct `DeletesRequeued` metric — re-journal now only on
  stall/disconnect (the normal journaled path); Warn log + `DeletesDropped`
  cover observability.
- #2120 (`syncSweep`) — different function, sibling agent. Untouched.

## Open questions for adversarial review

Q1. Does through-`sendCh` blocking send fully resolve the v2 reordering
    (S(K) queued / D(K) flushed / S(K) resurrects)? Confirm `sendCh` is
    the single ordered path and `sendLoop` the single writer.
Q2. Liveness: per-message `syncWriteDeadline` blocking send on the accept
    goroutine. Can `flushDeleteJournal` ever hang `handleNewConnection`
    longer than acceptable? Is the timeout→re-journal-tail abort the right
    escape, or should it keep blocking (matching barriers, which also bound
    with a timeout)?
Q3. Deadlock: any scenario where `sendLoop` is blocked AND the flush's
    blocking send waits on it (with no timeout escape)? The deadline should
    prevent indefinite block — verify against `sendLoop`'s
    conn-wait/writeFull-deadline behavior.
Q4. Stall/disconnect deferral: on timeout/disconnect we re-journal the
    tail. A stale `S(K)` may still sit in `sendCh` and be written on
    reconnect after the re-journaled `D(K)` replays — the SAME exposure the
    existing journal-on-disconnect path has. Is that acceptable (pre-
    existing, not widened by v3), or must v3 also address it (out of
    scope)?
Q5. Test hygiene: `syncWriteDeadline = 2s` makes the stall test slow.
    Acceptable to add a test-only injectable enqueue deadline field
    (defaulting to `syncWriteDeadline`)? Or restructure the stall test to
    avoid the wait?
Q6. Is incrementing `DeletesSent` on the blocking enqueue (same as
    `queueMessage` does on its enqueue) correct, vs only on actual wire
    write? (Existing `DeletesSent` semantics = "handed to the send stream",
    not "acked".)
Q7. Timer reuse + drain idiom — is the Reset/Stop/drain dance correct to
    avoid a stale fire across iterations?
