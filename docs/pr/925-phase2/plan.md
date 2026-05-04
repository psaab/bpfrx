---
status: DRAFT v1 — pending adversarial plan review
issue: https://github.com/psaab/xpf/issues/925
phase: Phase 2 — Prometheus gauge + decision-doc closeout
---

# #925 Phase 2 — `xpf_userspace_worker_dead{worker_id}` gauge + no-respawn decision

> *If reviewers conclude the perf gain is too small to justify the
> churn, PLAN-KILL is an acceptable verdict.*

## 1. Issue framing

#925 asked for a worker thread supervisor: catch panics, report
liveness, optionally respawn. Phase 1 (already shipped via the
`#925-A`/`#925-B` commit stream that landed before #1183) covered:

- `spawn_supervised_worker` and `spawn_supervised_aux` helpers
  in `userspace-dp/src/afxdp/coordinator/mod.rs` (~`:1894`/~`:1922`),
  both wrapping the body in `catch_unwind`.
- `WorkerRuntimeAtomics.dead` (atomic) and `panic_message` (Mutex<Option<String>>)
  per worker.
- All three production worker-spawn sites switched to the
  supervised helper.
- 4 panic-injection unit tests in `userspace-dp/src/afxdp/coordinator/tests.rs`
  (`spawn_supervised_worker_catches_string_panic_and_marks_dead`,
  `spawn_supervised_aux_catches_string_panic_and_returns_cleanly`,
  `spawn_supervised_aux_runs_body_to_completion_when_no_panic`,
  `spawn_supervised_aux_catches_non_string_panic_payload`).
- `WorkerRuntimeStatus.Dead` (bool) and `WorkerRuntimeStatus.PanicMessage`
  (string) on the userspace-dp control-socket JSON wire
  (`pkg/dataplane/userspace/protocol.go:541-545`,
  `userspace-dp/src/protocol.rs:1076-1077`).
- The `cli show userspace-dp ...` text/JSON renderer already
  surfaces both fields.

What Phase 1 did NOT do (and Phase 2 closes out):

- **Prometheus exposure of the dead state.** The xpfCollector
  in `pkg/api/metrics.go:308-340` exposes 7 worker counters
  (wall, active, idle-spin, idle-block, thread-cpu, work-loops,
  idle-loops) but does **not** expose `dead` as a gauge. An
  operator running a Prometheus alert on this fleet can't
  detect a dead worker without scraping the JSON status.
- **No-respawn rationale recorded in tree.** Issue #925 lists
  "automatic respawn implementation OR documented decision NOT
  to respawn (with rationale)" as an acceptance criterion. We
  decided NOT to respawn (rationale below) but didn't record it.
- **HA interaction note.** Issue #925 acceptance criterion
  requires "HA interaction documented and tested." Current
  behavior: a dead worker does NOT trigger chassis-cluster
  failover. That's a deliberate choice and needs a doc note.

## 2. Honest scope/value framing

This is a **doc + 1 Prometheus gauge** PR. Scope:

- ~30 LOC change in `pkg/api/metrics.go` (one new `*prometheus.Desc`,
  one `Describe` send, one emit-loop call).
- ~50 LOC of documentation in `docs/operations/worker-supervisor.md`
  (no-respawn rationale + HA interaction + how to alert on `dead`).
- Optional: 1 Go unit test in `pkg/api/metrics_test.go` asserting
  the metric appears in the `/metrics` endpoint output when a
  worker has `Dead=true`.

Win at absolute scale:

- The change does NOT improve throughput; this is reliability/
  operability closeout, not perf.
- The fleet-wide value is "one less alert blind spot." A worker
  panic without Prometheus exposure means an SRE has to know to
  poll the JSON status — they won't, so the panic stays invisible
  until it manifests as user-visible packet loss on that
  binding's flows.
- Cost is small (~80 LOC across two files + docs). PLAN-KILL is
  on the table if reviewers think this should just be folded into
  a future #925 Phase 3 that ships respawn too.

## 3. What's already shipped / partially batched

See §1 issue framing — Phase 1 is fully landed in master at
`753d4e8f` (current HEAD as of this plan). Phase 2 builds
strictly on top; no Rust changes required.

## 4. Concrete design

### 4.1 Prometheus gauge

```go
// pkg/api/metrics.go (additions)

type xpfCollector struct {
    // ... existing fields ...
    workerDeadGauge *prometheus.Desc  // NEW
}

func newXPFCollector(...) *xpfCollector {
    return &xpfCollector{
        // ... existing init ...
        workerDeadGauge: prometheus.NewDesc(
            "xpf_userspace_worker_dead",
            "1 if the userspace-dp worker thread has panicked and been "+
                "caught by the supervisor; 0 otherwise. Cleared by daemon "+
                "restart (Phase 1 has no automatic respawn).",
            []string{"worker_id"}, nil,
        ),
    }
}

func (c *xpfCollector) Describe(ch chan<- *prometheus.Desc) {
    // ... existing sends ...
    ch <- c.workerDeadGauge  // NEW
}

func (c *xpfCollector) emitWorkerRuntime(
    ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus,
) {
    for _, w := range status.WorkerRuntime {
        label := strconv.FormatUint(uint64(w.WorkerID), 10)
        // ... existing 7 emit calls ...
        var deadValue float64
        if w.Dead {
            deadValue = 1
        }
        ch <- prometheus.MustNewConstMetric(c.workerDeadGauge,
            prometheus.GaugeValue, deadValue, label)
    }
}
```

Metric type: `GaugeValue` (binary 0/1, can transition both ways
in principle — only daemon restart clears it today, but a future
Phase 3 respawn would also clear it).

### 4.2 Operations doc

New file: `docs/operations/worker-supervisor.md`. Contents:

- One-paragraph summary of Phase 1 supervisor (catch_unwind,
  mark-dead, no respawn).
- Suggested Prometheus alert:
  ```yaml
  - alert: XpfUserspaceWorkerDead
    expr: xpf_userspace_worker_dead == 1
    for: 30s
    labels: { severity: critical }
    annotations:
      summary: "userspace-dp worker {{ $labels.worker_id }} panicked"
      description: |
        Restart xpfd to recover. Investigation: check
        `cli show userspace-dp status | json` for panic_message.
  ```
- **No-respawn rationale.** Three reasons we chose not to
  auto-respawn in Phase 1/Phase 2:
  1. **Reentrancy hazard.** A panic mid-`poll_binding_process_descriptor`
     leaves the XSK rings, UMEM frame allocator, and conntrack
     entries in an arbitrary state. Re-entering the same worker
     loop without rebuilding all of that risks corruption that's
     worse than the outage.
  2. **Sticky-failure trap.** If the panic is deterministic
     (assert tripwire on a specific config / packet shape /
     session entry), an unconditional respawn loops forever and
     turns into a CPU-hot livelock. Sticky-failure detection
     adds enough complexity that it deserves its own design pass
     (deferred to Phase 3 if observability shows we need it).
  3. **Operator visibility.** A dead worker with a Prometheus
     gauge alert + clear panic_message is more actionable than a
     respawn that masks the bug. We'd rather page once than have
     an undebuggable flaky binding.
- **HA interaction.** Current state: a dead worker on the
  chassis-cluster primary does NOT trigger failover. Reasons:
  - The chassis-cluster failover state machine watches VRRP
    advertisements and the userspace-dp helper's "alive"
    heartbeat; it doesn't watch per-worker liveness.
  - A single dead worker affects only the bindings owned by that
    worker — not the whole node. The other 5 workers continue
    to forward.
  - Deliberately escalating to a node-level failover for a
    partial-outage condition would be a regression in HA
    semantics. If the operator wants that behavior, the right
    path is a node-level health check (Prometheus alert →
    operator-driven failover), not an in-daemon decision.

  This is documented; tested by inspection (no specific
  failover test added — the existing `make test-failover`
  harness exercises the VRRP path which is unchanged).

## 5. Public API preservation

- No Rust public API change.
- No protocol-wire change (Phase 1 already added `Dead` /
  `PanicMessage`).
- `pkg/api/metrics.go` exposes one NEW Prometheus metric name
  (`xpf_userspace_worker_dead`); the metrics endpoint adds a
  series, no removals.

## 6. Hidden invariants the change must preserve

- **xpfCollector caches a `ProcessStatus` snapshot from a 1s
  cadence.** The Phase 1 atomic flip happens immediately on
  catch; the snapshot lag means the gauge can be up to ~1s
  behind reality. Acceptable — the alert `for: 30s` clause
  absorbs that. Confirm no shorter lag is required by current
  alerts.
- **Worker IDs are stable for the lifetime of the daemon.** The
  `worker_id` label values match the existing 7 metric series,
  so users grouping by `worker_id` get a coherent view.
- **`Dead` is set-only in Phase 1** — once flipped, only daemon
  restart clears it. The gauge will therefore read `1` until
  process restart even after the panic-causing condition is
  resolved. Document this on the metric description so SREs
  don't expect auto-clearing.

## 7. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | **LOW** | Pure additive metric + docs. No code path on the dataplane hot path is touched. |
| Lifetime / borrow-checker | **LOW** | No Rust change. |
| Performance regression | **LOW** | One extra `MustNewConstMetric` call per scrape (≤6 workers, scraped at 15s/30s typical). Negligible. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **LOW** | This is closeout of an already-shipped Phase 1; not a new architecture. |

## 8. Test plan

- `cargo build` clean (no Rust change, but build sanity).
- `cargo test --release`: unchanged from Phase 1 (954+ pass).
- `go test ./pkg/api/...` for the new Prometheus assertion if
  added.
- Smoke matrix (per `triple-review` SKILL.md Step 6): full Pass A
  + Pass B 30 measurements (the change is fleet-side metrics; no
  expected throughput delta, but we still smoke to confirm zero
  regression).
- Optional manual verification: deploy, force a panic in a worker
  via a debug knob (or wait for an org-internal panic-injection
  fixture if available), `curl localhost:8080/metrics | grep
  xpf_userspace_worker_dead` — should show `1` for the affected
  worker_id, `0` for the rest.

## 9. Out of scope (explicitly)

- Automatic respawn (Phase 3 if ever needed).
- Sticky-failure detection.
- Coordinated state recovery (re-bind dead worker's queues to
  surviving workers).
- HA escalation rules ("dead worker → chassis-cluster failover").
- Test that exercises the metric end-to-end on the cluster (the
  manual-fixture path above is fine for now).

## 10. Open questions for adversarial review

1. Is the gauge alone enough value to justify a PR, or should
   this wait until Phase 3 ships actual respawn? (PLAN-KILL is
   acceptable if the reviewer thinks the gauge can wait.)
2. Should the gauge default to `0` for healthy workers, or be
   ABSENT until the first panic? (This plan: emit `0` always so
   the metric is always present in the time series and alerts
   don't fire on metric absence.)
3. Should `panic_message` be a separate Prometheus metric (as a
   `_info` gauge with the message in a label)? Or is the JSON
   status enough? (This plan: JSON status only — Prometheus
   labels with arbitrary panic strings are a known cardinality
   trap.)
4. Is the no-respawn decision the right one? Reviewers should
   stress-test the rationale in §4.2 — particularly the
   sticky-failure-trap argument.
5. Should we add ANY automated test for the HA interaction, or
   is the "documented + manual verification" approach OK? Issue
   #925 acceptance criterion says "documented and tested" —
   reviewer call on whether the existing failover test plus the
   documented note is sufficient.
