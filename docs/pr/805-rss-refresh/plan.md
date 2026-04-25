# #805 — D3 RSS indirection refresh on workers ↔ queues transition

## 1. Bug

When `system dataplane workers` is bumped from a value below the
NIC RX-queue count to a value at-or-above it (e.g. 4 → 6 on a
6-queue mlx5), the D3 RSS indirection table from the previous
workers-count stays live: queues 4 and 5 keep weight 0 even
though they now host worker-bound AF_XDP sockets.

Concrete symptom (from #800 investigation, doc preserved on
closed branch `pr/800-workers-queues-alignment`):
- Pre-change: workers=4, queues=6 → table `[1,1,1,1,0,0]`.
- Post-change: workers=6, queues=6 → expected default round-
  robin table; observed: still `[1,1,1,1,0,0]`. Queues 4 and 5
  receive 0 traffic via RSS, the dataplane workers bound there
  starve.

## 2. Root cause

`pkg/daemon/rss_indirection.go:applyRSSIndirectionOne()` calls
`computeWeightVector(workers, queues)`. When `workers >= queues`
that function returns `nil, "workers (N) >= queues (M)"`. The
caller treats nil as "skip" and **does not** touch the live
table. The configured-from-previous-workers state persists.

The skip is correct for "fresh install with workers >= queues"
(default table is fine, no write needed) but incorrect for
"transition from workers < queues to workers >= queues" (the
previously-written constrained table is now wrong and must be
reset to default).

## 3. Fix

Smallest correct change: in `applyRSSIndirectionOne`, when
`computeWeightVector` returns nil because `workers >= queues`
(specifically, NOT because of misconfig like workers <= 0 or
workers == 1), inspect the live indirection table; if it is
not the default round-robin shape (i.e., some queue index
≥ active count appears as 0 weight in concentrated form), run
`ethtool -X <iface> default` to restore.

The decision to restore-default-on-skip is gated on:

- `workers >= queues > 1` (the transition case)
- `live table != default` (otherwise no-op)

Other skip reasons (`workers <= 0`, `workers == 1`) leave the
table alone — those are bring-up / single-worker paths where
no prior workers<queues state could exist for this iface.

## 4. Detection of "live table != default"

Default RSS layout from `ethtool -X iface default` is
round-robin over all queues: indices map to `q = i mod
queue_count`. The current `indirectionTableMatches(out,
weights)` helper checks for "table only uses queues
0..(activeCount-1)". For the "is default?" question we need
the inverse: "does the table use queues 0..queue_count-1
(all of them)?".

Add a sibling helper:

```go
// indirectionTableIsDefault reports true if the live ethtool
// -x output describes a table that uses every queue index in
// 0..queueCount-1 at least once.
func indirectionTableIsDefault(output []byte, queueCount int) bool { ... }
```

If `false` and `workers >= queues`, fire `ethtool -X iface
default`. Caller applies same lock + bump semantics as the
existing apply path (rssWriteMu held by parent
`applyRSSIndirectionLocked`; epoch bump on successful write).

## 5. Implementation

Single-file change in `pkg/daemon/rss_indirection.go`:

1. Add `indirectionTableIsDefault(output []byte, queueCount
   int) bool` helper.
2. In `applyRSSIndirectionOne`, after `computeWeightVector`
   returns nil, branch on the reason:
   - `workers >= queues > 1`: read live table; if not default,
     run `ethtool -X iface default`. Return whether a write
     happened (matches the existing bool return contract).
   - Other reasons: return false unchanged.

Because `applyRSSIndirectionOne` already returns `bool`, the
caller (`applyRSSIndirectionLocked`) bumps the epoch via the
existing path. No new plumbing needed.

## 6. Tests

`pkg/daemon/rss_indirection_test.go`:

1. `TestApplyRSSIndirectionOne_WorkersBecomeEqualQueues_RestoresDefault`:
   stub returns a live table with concentrated layout (uses
   only queues 0..3 of 6). Call with workers=6, queues=6.
   Expect: `ethtool -X iface default` invocation, function
   returns true.
2. `TestApplyRSSIndirectionOne_WorkersBecomeGreaterThanQueues_NoOpIfDefault`:
   stub returns default round-robin layout. Call with
   workers=8, queues=6. Expect: no ethtool write, function
   returns false.
3. `TestIndirectionTableIsDefault_RoundRobin_True`: pure
   parser test on canned default output.
4. `TestIndirectionTableIsDefault_Concentrated_False`: pure
   parser test on canned `[1,1,1,1,0,0]` output.
5. Regression: existing `TestApplyRSSIndirectionOne_*` tests
   still pass (workers < queues path unchanged).

## 7. Acceptance

- All 880+ existing Go tests pass.
- New tests pass.
- `go test ./pkg/daemon/` clean.
- Live deploy on `loss:xpf-userspace-fw0` (RG0 primary):
  - Set workers=4, observe table `[1,1,1,1,0,0]` via
    `ethtool -x ge-0-0-2`.
  - Bump to workers=6 via cli commit.
  - Confirm table reverts to round-robin default.
- Codex hostile review: at least 1 round, MERGE YES.
- Copilot inline review: addressed.
- `make test-failover`: pass (defense — touching RSS indirection
  near HA boundary).

## 8. Risks

- **Race with #840-style rebalance loop**: the rebalance loop
  was reverted in #840, so no live concurrent writer. If a
  future re-introduction lands, this path interacts via the
  existing `rssWriteMu` (already in place from #785 / #840
  partial state).
- **False-positive default detection**: a future operator who
  manually wrote a custom table via `ethtool -X` would have it
  reverted by the daemon. Acceptable — the daemon claims D3
  ownership of the indirection table on managed mlx5 ifaces.
- **Boot ordering**: this change runs in the same path that
  D3 already runs in (linksetup at startup, applyConfig on
  reconcile). No new ordering concern.

## 9. Out of scope

- General `ethtool -X` state-machine refactor.
- D3 enable on non-mlx5 NICs.
- Workers count NOT changing (the no-op case is preserved by
  `indirectionTableIsDefault` early-returning true).
