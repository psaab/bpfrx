# #805 — D3 RSS indirection refresh on workers ↔ queues transition

## 1. Bug

When `system dataplane workers` is bumped from a value below the
NIC RX-queue count to a value at-or-above it (e.g. 4 → 6 on a
6-queue mlx5), the D3 RSS indirection table from the previous
workers-count stays live: queues 4 and 5 keep weight 0 even
though they now host worker-bound AF_XDP sockets.

Concrete symptom (from #800 investigation, doc preserved on
closed branch `pr/800-workers-queues-alignment`):
- Pre-change: workers=4, queues=6 → table written
  `[1,1,1,1,0,0]` so the indirection only references queues 0-3.
- Post-change: workers=6, queues=6 → expected default
  round-robin table; observed: still references only queues 0-3.
  Queues 4 and 5 receive 0 traffic via RSS, the dataplane
  workers bound there starve.

## 2. Root cause

`pkg/daemon/rss_indirection.go:applyRSSIndirectionOne()` calls
`computeWeightVector(workers, queues)`. When `workers >= queues`
that function returns `nil, "workers (N) >= queues (M)"`. The
caller treats nil as "skip" and does not touch the live
table. The configured-from-previous-workers state persists.

The skip is correct for "fresh install with workers >= queues"
(default table is fine, no write needed) but incorrect for
"transition from workers < queues to workers >= queues" (the
previously-written constrained table is now wrong and must be
reset to default).

## 3. Master-state contract (Codex R1 HIGH 1+2 grounding)

The current call chain in master is:

```
reapplyRSSIndirectionWith → applyRSSIndirection → applyRSSIndirectionOne
```

All three return **void**. There is no `rssWriteMu`, no
`applyRSSIndirectionLocked` split, no epoch counter — those were
introduced in #840 (Slice D rebalance) and removed when #840 was
reverted. The fix here MUST work against this simpler contract:

- No locking required: there is no concurrent writer of the RSS
  indirection table in master. The only callers are
  daemon-startup (`linksetup.go:113`, runs from
  `enumerateAndRenameInterfaces` BEFORE the API / gRPC / CLI
  commit paths are wired up) and reconcile-on-commit
  (`daemon.go:2566`, runs under the config-apply path which the
  daemon enforces serially). Startup-vs-reconcile serialization
  is **lifecycle ordering** (R2#1: not the apply semaphore as a
  prior revision incorrectly claimed), but the practical
  outcome is the same: no two RSS-indirection writers ever run
  concurrently in master.
- No bool return: `applyRSSIndirectionOne` stays void. The
  caller is unaware whether a write happened.
- No epoch bump: not present in master.

The fix is purely additive within `applyRSSIndirectionOne`'s
existing void-returning shape.

## 4. Default-table shape (empirical, Codex R1 MED #4 closure)

`ethtool -X iface default` on mlx5 produces a 128-entry
indirection table where `entry[i] = i mod queue_count`, exactly.
Verified live on `loss:xpf-userspace-fw0/ge-0-0-2` with 6 RX
queues:

```
    0:      0     1     2     3     4     5     0     1
    8:      2     3     4     5     0     1     2     3
   16:      4     5     0     1     2     3     4     5
   24:      0     1     2     3     4     5     0     1
   ...
```

So "is default" detection can be exact:
```
for each row in `ethtool -x` output:
    parse <row-index>: <q0> <q1> ... <q7>
    for col j in 0..7:
        if int(q[j]) != (row_index + j) % queue_count:
            return false
return true
```

This is strictly tighter than "uses every queue index at least
once" (Codex MED #3): a custom table that hits every queue once
in non-round-robin order would fail this check, so the daemon
would correctly reset it to true round-robin on the next apply.

## 5. Skip-reason discrimination (Codex R1 MED #5 fix)

Don't parse the human string from `computeWeightVector`. The
caller already knows `workers` and `queues`; check the structured
condition directly:

```go
queues := execer.readQueueCount(iface)
if queues <= 0 {
    slog.Debug("rss indirection: queue count unknown, skipping",
        "iface", iface)
    return  // unchanged: nothing we can do without queue count
}
weights, _ := computeWeightVector(workers, queues)
if weights == nil {
    // computeWeightVector skipped. Distinguish:
    //   workers <= 0 / workers == 1 → leave table alone
    //   workers >= queues > 1 → maybe restore default if the
    //                            live table is configured-stale
    if workers > 1 && workers >= queues {
        maybeRestoreDefault(iface, queues, execer)
    }
    return
}
// existing path for workers < queues — write `weights`
...
```

The `workers > 1 && workers >= queues` condition is unambiguous,
deterministic, and decoupled from any reason-string text.

## 6. maybeRestoreDefault behavior (Codex R1 MED #6 fix)

```go
func maybeRestoreDefault(iface string, queues int, execer rssExecutor) {
    out, err := execer.runEthtool("-x", iface)
    if err != nil {
        // Same probe-failure behavior as the existing apply path:
        //   ErrNotFound → log Warn, return
        //   other error → log Warn with output, return
        // No write attempted on probe failure.
        if isExecNotFound(err) {
            slog.Warn("rss indirection: ethtool not found, cannot probe for default",
                "iface", iface)
            return
        }
        slog.Warn("rss indirection: ethtool -x failed, cannot probe for default",
            "iface", iface, "err", err,
            "output", strings.TrimSpace(string(out)))
        return
    }
    if indirectionTableIsDefault(out, queues) {
        slog.Debug("rss indirection: already default, no restore needed",
            "iface", iface)
        return
    }
    if _, err := execer.runEthtool("-X", iface, "default"); err != nil {
        if isExecNotFound(err) {
            slog.Warn("rss indirection: ethtool not found, cannot restore default",
                "iface", iface)
            return
        }
        slog.Warn("rss indirection: ethtool -X default failed",
            "iface", iface, "err", err)
        return
    }
    slog.Info("rss indirection: restored default round-robin",
        "iface", iface, "reason", "workers>=queues with stale constrained table")
}
```

Probe-failure handling explicitly mirrors the existing
`applyRSSIndirectionOne` apply-path failure handling (Codex R1
MED #6 fix).

## 7. indirectionTableIsDefault helper

```go
// indirectionTableIsDefault reports true iff the live ethtool -x
// output describes a round-robin indirection table where
// entry[i] == i mod queueCount. This is the exact shape mlx5
// produces on `ethtool -X iface default` (verified live on the
// loss:xpf-userspace-fw0 cluster, 6-queue ge-0-0-2).
//
// Stricter than indirectionTableMatches: rejects any custom
// table that happens to use every queue at least once but
// doesn't match the round-robin pattern.
func indirectionTableIsDefault(output []byte, queueCount int) bool {
    if queueCount <= 0 {
        return false
    }
    // R2#2 + R3 LOW: prevent vacuously-true on empty,
    // unparseable, or value-less ("0:" with no queue tokens)
    // output. Set the flag only after at least one queue value
    // has been successfully parsed and verified.
    sawAnyEntry := false
    for _, line := range bytes.Split(output, []byte{'\n'}) {
        trimmed := bytes.TrimSpace(line)
        if len(trimmed) == 0 {
            continue
        }
        colon := bytes.IndexByte(trimmed, ':')
        if colon <= 0 {
            continue
        }
        rowIdx, err := strconv.Atoi(string(trimmed[:colon]))
        if err != nil {
            continue
        }
        for j, tok := range bytes.Fields(trimmed[colon+1:]) {
            q, err := strconv.Atoi(string(tok))
            if err != nil {
                return false
            }
            expected := (rowIdx + j) % queueCount
            if q != expected {
                return false
            }
            sawAnyEntry = true
        }
    }
    return sawAnyEntry
}
```

## 8. Implementation footprint

Single-file change in `pkg/daemon/rss_indirection.go`:

1. Add `indirectionTableIsDefault(output []byte, queueCount int) bool`.
2. Add `maybeRestoreDefault(iface string, queues int, execer rssExecutor)`.
3. Modify `applyRSSIndirectionOne`: read `queues` BEFORE
   `computeWeightVector`; on nil-weights with the
   `workers > 1 && workers >= queues` structured condition,
   call `maybeRestoreDefault`.

Existing `applyRSSIndirectionOne` signature (void) and
locking (none) preserved.

## 9. Tests (Codex R1 MED #7+#8, LOW #8 fixes)

`pkg/daemon/rss_indirection_test.go`:

1. `TestApplyRSSIndirectionOne_WorkersEqualsQueues_StaleTable_RestoresDefault`:
   stub returns concentrated `[0,1,2,3]`-only table for a 6-queue
   iface. Call with workers=6. Expect: `ethtool -X iface default`
   invocation.
2. `TestApplyRSSIndirectionOne_WorkersGreaterThanQueues_StaleTable_RestoresDefault`:
   stub returns concentrated table; workers=8, queues=6. Expect:
   restore call. (R1 MED #7 — covers `workers > queues`, not
   just `==`.)
3. `TestApplyRSSIndirectionOne_WorkersGreaterEqualQueues_DefaultTable_NoOp`:
   stub returns true round-robin table. Call with workers=6,
   queues=6. Expect: probe call only, no `ethtool -X` write.
4. `TestApplyRSSIndirectionOne_WorkersIsOne_StaleTable_NotTouched`:
   stub returns concentrated table. Call with workers=1, queues=6.
   Expect: zero ethtool calls. (R1 LOW #8 — workers==1
   regression guard.)
5. `TestApplyRSSIndirectionOne_WorkersIsZero_StaleTable_NotTouched`:
   stub returns concentrated table. Call with workers=0, queues=6.
   Expect: zero ethtool calls. (R1 LOW #8.)
6. `TestApplyRSSIndirectionOne_QueueCountZero_NoOp`:
   stub `readQueueCount` returns 0 for the iface. Expect: zero
   ethtool calls. (R1 MED #7 — defensive against sysfs failure.)
7. `TestApplyRSSIndirectionOne_RestoreEthtoolXProbeMissing_LogAndSkip`:
   stub `ethtool -x` returns ErrNotFound on the restore-default
   probe. Expect: warning logged, no `-X default` write. (R1
   MED #6.)
8. `TestIndirectionTableIsDefault_RoundRobin_True`: pure-parser
   test using the captured `ethtool -x` output from
   `loss:xpf-userspace-fw0/ge-0-0-2`. Fixture is **inline
   string literal** in the test (R2#4: pinned — small enough
   to embed, keeps the test self-contained without a
   `testdata/` file).
9. `TestIndirectionTableIsDefault_Concentrated_False`: pure
   parser test on the `[1,1,1,1,0,0]` shape.
10. `TestIndirectionTableIsDefault_EveryQueueOnceButNonRoundRobin_False`:
    pure parser test on a hand-built table that uses every queue
    but in non-round-robin order. Asserts the stricter check.
    (R1 MED #3.)
11. `TestIndirectionTableIsDefault_EmptyOutput_False`: pure parser
    test on empty / unparseable / value-less inputs. Three
    sub-cases:
    - empty `[]byte{}` → false (no rows seen)
    - non-row text only (e.g. just the "RX flow hash..." header)
      → false (no rows seen)
    - row index with no queue tokens (e.g. `"0:\n"`) → false
      (R3 LOW: sawAnyEntry guard, not just sawAnyRow)
    Asserts the parser distinguishes "no entries parsed" from
    "all entries match expected pattern".
12. `TestApplyRSSIndirectionOne_BootSequence_4then6_RestoresDefault`:
    multi-cycle test simulating the actual operator scenario.
    Step 1: workers=4, queues=6, default round-robin live table —
    expect concentrated `[1,1,1,1,0,0]` write. Step 2: same iface,
    workers=6, queues=6, live table now constrained — expect
    `ethtool -X iface default` write. Asserts the full transition
    behavior end-to-end. (R2 LOW #5.)

Existing `TestApplyRSSIndirectionOne_*` tests (workers < queues
path) must still pass unchanged.

## 10. Acceptance

- All 880+ existing Go tests pass.
- New tests pass.
- `go test ./pkg/daemon/` clean.
- Live deploy on `loss:xpf-userspace-fw0` (RG0 primary):
  - Build with the change.
  - Set workers=4, observe table with concentrated layout via
    `ethtool -x ge-0-0-2`.
  - Bump to workers=6 via cli commit.
  - Confirm table reverts to round-robin default.
- Codex hostile review: at least 1 round, MERGE YES.
- Copilot inline review: addressed.
- `make test-failover` is **NOT** a merge blocker (Codex R1
  LOW #9 — this change is a per-iface RSS-indirection concern
  that doesn't intersect HA except via the existing serialized
  apply path). Run as optional defense-in-depth if convenient.

## 11. Risks

- **False-positive default detection**: tightened (§4 + §7) to
  exact round-robin `entry[i] == i mod queue_count`. A future
  operator who manually wrote a custom table via `ethtool -X`
  on a managed mlx5 iface would have it reverted by the daemon
  on the next reconcile. Acceptable — the daemon claims D3
  ownership of the indirection table on managed mlx5 ifaces.
- **Boot ordering**: at startup the live table is whatever the
  kernel left it (likely default — most systems boot with
  default RSS). The fix's "if not default, restore" logic is a
  no-op on default. No new boot-ordering concern. Probe-error
  handling explicit per §6.

## 12. Out of scope

- General `ethtool -X` state-machine refactor.
- D3 enable on non-mlx5 NICs.
- Re-introduction of the #840 lock/epoch infrastructure.
- **Runtime queue-count changes without a config commit** (R2#3):
  if the operator runs `ethtool -L iface combined N` to change
  the NIC's queue count without bumping `system dataplane
  workers` afterwards, the daemon won't notice and the live
  indirection table may reference non-existent queues until the
  next config commit triggers `reapplyRSSIndirection`. Operators
  changing queue counts are expected to follow up with a config
  commit (or restart the daemon). This change does NOT add a
  netlink-watch loop for ringparam changes — that's a separate
  scope of work.

## 13. Codex round-1 review responses

| # | Sev | Topic                                  | Resolution |
|---|-----|----------------------------------------|------------|
| 1 | HIGH| `rssWriteMu` claim wrong               | §3: dropped — those came from #840 (reverted). Fix works against current void-returning master contract |
| 2 | HIGH| Bool return contract claim wrong       | §3: dropped — `applyRSSIndirectionOne` stays void; `maybeRestoreDefault` is also void |
| 3 | MED | Default-detection too loose            | §4 + §7: tightened to exact round-robin `entry[i] == i mod queue_count` |
| 4 | MED | Default-table shape unverified         | §4: empirically captured on `loss:xpf-userspace-fw0/ge-0-0-2` |
| 5 | MED | Skip-reason string parsing fragile     | §5: structured `workers > 1 && workers >= queues` condition |
| 6 | MED | Boot-time probe-error unspecified      | §6: explicit ErrNotFound + generic err handling, mirrors existing apply path |
| 7 | MED | Missing tests: queueCount=0, workers>queues | §9 tests #2 (workers>queues) and #6 (queueCount=0) |
| 8 | LOW | Missing regression: workers∈{0,1}     | §9 tests #4 and #5 |
| 9 | LOW | `make test-failover` overbroad         | §10: demoted to optional defense, not a merge blocker |

### Round 2 (5 findings)

| # | Sev | Topic                                  | Resolution |
|---|-----|----------------------------------------|------------|
| 1 | LOW | §3 wrongly cited apply semaphore       | §3 reworded: serialization is lifecycle ordering (startup runs from enumerateAndRenameInterfaces before API/CLI are wired up), not the apply semaphore |
| 2 | MED | indirectionTableIsDefault vacuously true | §7 added `sawAnyRow` guard (mirrors existing `indirectionTableMatches` shape); §9 test #11 pins empty-output behavior |
| 3 | MED | Runtime queue-count-only changes       | §12 explicit out-of-scope: operator changing `ethtool -L` without config commit is not auto-handled; netlink-watch for ringparam is separate scope |
| 4 | LOW | Test fixture path unpinned             | §9 test #8 specifies inline-string-literal in the test (small enough to embed, keeps test self-contained) |
| 5 | LOW | Multi-cycle boot scenario untested     | §9 test #12 added: `BootSequence_4then6_RestoresDefault` covers the full transition end-to-end |

### Round 3 (1 finding)

| # | Sev | Topic                                  | Resolution |
|---|-----|----------------------------------------|------------|
| 1 | LOW | sawAnyRow set before queue tokens parsed | Renamed `sawAnyRow` → `sawAnyEntry`, set inside the inner field loop after a value has been parsed AND verified. Test #11 expanded to cover the value-less row case (`"0:\n"`) explicitly |
