# Claude SMR hostile plan-review — round 34 (v9.9.18 @ 31f39f4ba)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.18 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.18-as-committed** — one self-found HIGH (the park-overflow clause
points at the wrong replay mechanism — receiver-side drop-oldest loses
deltas the sender will never re-send) plus one nit. Everything else verified
sound against code.

## Finding 1 (HIGH — drop-oldest has no replay source; the latch must disconnect once per epoch)

The v9.9.18 no-reset-loop clause says: "while parked, buffer overflow does
NOT reset the connection — it drops the OLDEST buffered deltas and sets
`syncBackfillNeeded`". Two code-verified defects: (a) `syncBackfillNeeded`
is a SENDER-side flag for the sender's own send-queue overflow
(`sync_conn_write.go:46` sets it when the send queue fills;
`sync_conn_sweep.go:181` replays the previous window) — the receiver setting
its own flag only affects what IT sends, never what it receives; and (b) the
sender's sweep cutoff advanced on LOCAL QUEUE success
(`sync_conn_sweep.go:185`), so deltas the receiver drops from its park
buffer are NEVER re-sent — silent standby session loss, the exact class the
deferral exists to prevent. The corrected composition, using only existing
machinery: the park buffer is bounded; on overflow the receiver DISCONNECTS
ONCE PER LATCHED EPOCH (the latch prevents hot reset loops — not once per
overflow); during the outage the sender's send queue fills and the SENDER
self-marks `syncBackfillNeeded` (`sync_conn_write.go:46`), so its sweep
holds the window (`sync_conn_sweep.go:181`) instead of advancing past it; on
reconnect the sender's config-first ordering (protocol rule 3) lets the
config apply BEFORE the re-driven bulk, the park drains, the buffered window
plus the sender's window replay restore everything. If the config is stuck
(#6387): the park latches again after the next buffer of churn, the cycle
repeats at reconnect/bulk cadence (not hot), the node is operator-visible
via `configSyncFailing`, and the takeover fence (rule 5) keeps it from
mastering. Progress is guaranteed whenever the config can apply.

## Finding 2 (nit — the receipt's critical section must be stated against GC)

The `Replaced(old_state)` reinstatement is safe from expiry-GC interference
ONLY because evaluate → claim → reinstate all run in the one allocator
critical section (expiry GC takes the same `live` lock,
`allocator.rs:2302`). State it explicitly, or a reviewer must re-derive it.

## Verified sound this round (my own re-trace)

- **Watermark on authority transition**: `max(own_committed, lastApplied)`
  is monotone; the new authority's v9.9.13 `max(own, received)` counter-floor
  adoption keeps stamps and watermarks ordered across transition; the
  active/active directional-zero trace is closed (the authority's
  own_committed covers its side). The split-brain epoch-collision window
  (partition: both issue the same epoch value for different configs) is the
  PRE-EXISTING #6284 directional-namespace/dual-active hazard, not
  introduced by this fold — accepted residual, belongs to the authority-epoch
  design's documented assumptions.
- **Selective park ordering**: buffered session-state keeps FIFO per key;
  control messages bypass; the enabling Config frame always reaches the
  async apply queue (reconnect self-deadlock closed by construction).
- **Token indirection**: the retarget is one atomic swap per slot under the
  write permit; a mutation that drained before the snapshot has its state in
  B and its token's release lands in B post-retarget — refcount continuity
  exact; retired A owns nothing.
- **Receipt taxonomy**: covers port-bearing persistent, address-only
  persistent, non-persistent; deterministic pools are persistent-exclusive
  at commit (`compiler_nat_source.go:594`), so no deterministic-persistent
  shape exists to miss.

## Verdict

**PLAN NO for v9.9.18** — fold Finding 1 (latched-once-per-epoch disconnect
+ sender-side backfill composition) and Finding 2 (GC critical-section
statement) as v9.9.19. Part A remains converged and untouched.
