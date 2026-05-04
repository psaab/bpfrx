# #925 Phase 2 — Prometheus liveness + panic-injection test + no-respawn rationale

Status: **DRAFT v2 — addressing Codex round-1 PLAN-NEEDS-MINOR + Gemini round-1 PLAN-NEEDS-MINOR (concurrency + framing)**

## v2 changes (round-1 reviewer findings)

### 1. Test surface: use existing `spawn_supervised_worker`

Codex caught: `spawn_supervised_worker` already exists in
`coordinator/mod.rs` and existing tests at
`coordinator/tests.rs:848` already call it directly with an
arbitrary closure. v1's proposed
`spawn_supervised_panicking_test_thread` was unnecessary
ceremony.

v2 simplifies: test calls `spawn_supervised_worker(..., ||
panic!("..."))` directly and asserts on the post-join state.

### 2. Drop "No public API changes" claim

Both reviewers caught: a Prometheus metric IS a monitoring
API. Once shipped, dashboards / alerts / SLOs will pin to
the gauge name and label cardinality.

v2 explicitly:
- Documents `xpf_userspace_worker_dead{worker_id}` as
  stable. Value `1` means caught panic, cleared only by
  daemon restart.
- Adds a Go test that asserts the metric registers and emits
  the expected sample shape (mirrors existing pattern at
  `pkg/api/metrics_test.go` for other worker gauges).
- Mentions explicit `Describe()` registration at
  `pkg/api/metrics.go:345` — easy to forget; the gauge
  doesn't emit if not Describe'd.

### 3. Update stale "Phase 2 respawn" comments

Codex caught: comments at `pkg/dataplane/userspace/protocol.go:539`
and `userspace-dp/src/afxdp/worker_runtime.rs:71` still
promise that Phase 2 will implement respawn. With v2's
documented decision NOT to respawn, those comments are
inconsistent with the codebase.

v2 mandates updating both comments to:
- Describe the current behavior (mark-dead until daemon
  restart).
- Reference this Phase 2 plan + the no-respawn rationale.

### 4. HA section: document the real black-hole consequence

Codex caught: `pkg/cluster` has no `WorkerRuntimeStatus.dead`
awareness, and userspace takeover readiness checks (in
`pkg/dataplane/userspace/manager_ha.go:247`) check helper /
queue / binding readiness, NOT dead workers.

v2 adds explicit consequence: **if a dead worker owns an
important binding (e.g., the RETH-VIP-bearing one), that
binding is black-holed until operator restart**. The
chassis-cluster will NOT detect this and trigger failover.
Operators MUST alert on the gauge to detect.

### 5. Panic-hook concurrency: not a blocker (Codex), critical (Gemini)

Codex: no `std::panic::set_hook` users in the repo; tests
should not install one and should not need to serialize.
Gemini: critical concurrency risk in cargo test default
parallel runner.

v2 takes the conservative path: panic-injection tests do NOT
install a custom hook, but the test setup uses
`std::panic::take_hook` + `set_hook(Box::new(|_| {}))` to
silence stderr noise during the test, then restores the
prior hook in a Drop guard. Plus the test is wrapped in a
`#[serial_test::serial]` attribute (using the
[`serial_test`](https://crates.io/crates/serial_test) crate
already in dev-dependencies if available, OR a
hand-rolled global mutex if not).

v2 mandates auditing existing dev-dependencies before
deciding; if `serial_test` isn't already vendored, fall back
to the hand-rolled mutex pattern (`OnceLock<Mutex<()>>` with
the test taking the lock at entry).

### 6. Gauge name: `xpf_userspace_worker_dead` (Codex confirmed)

v1 asked which name. Codex's analysis: no existing alive/dead
convention in `metrics.go`; existing worker metrics use
`xpf_userspace_worker_*` with `worker_id`; a bad-state gauge
is alert-friendly (`alert: workerDead == 1` reads naturally);
`alive` creates missing-series ambiguity (gauge missing vs
worker missing vs scrape missing).

v2 commits: `xpf_userspace_worker_dead{worker_id}`.

(Phase 1 — catch + report — shipped in #913. See `plan.md`
in this directory for that historical record.)

## Issue framing

#925 wants a complete worker-thread supervisor:
1. catch_unwind around all spawn sites — ✅ shipped in #913 (Phase 1).
2. Per-worker liveness counter via Prometheus — ❌ not shipped.
3. Automatic respawn OR documented decision NOT to respawn — ❌ not shipped.
4. Panic-injection test — ❌ not shipped.
5. HA interaction docs/tests — ❌ not shipped.

Phase 2 ships items 2-5. Item 3 is **a documented decision NOT
to auto-respawn**, with rationale captured in this plan.

## Honest scope/value framing

Small additive feature: ~60 LOC of Go (Prometheus gauge) +
~80 LOC of Rust unit tests + ~50 LOC of plan rationale. No
data-structure refactor. No hot-path code change. Pure
observability + test-coverage addition.

Why ship it: a worker-loop panic is logged + recorded in the
per-worker `WorkerRuntimeStatus.dead` field, but operators
have no Prometheus metric to alert on. The gauge closes the
observability gap that #925 explicitly calls out.

Why NOT auto-respawn: the worker holds many resources
(BindingPlan, BPF map FDs, AF_XDP rings, slab session table,
flow cache). Respawn would either tear all of that down and
rebuild from scratch (long downtime, complex state recovery,
possibly loses HA-synced sessions) or keep the resources and
restart the loop (the panic likely poisoned that state).
Documenting "no respawn; daemon restart required" is the
honest minimum.

If reviewers conclude the perf gain is too small to justify
the churn, **PLAN-KILL is an acceptable verdict.** Phase 2
is small enough that PLAN-KILL would be unusual but possible
if the no-respawn decision is judged wrong.

## What's already shipped (Phase 1)

- `panic_slot: Arc<Mutex<Option<String>>>` per worker
  (coordinator/mod.rs:677-678).
- `panic_payload_message()` helper renders panic payload as
  String (coordinator/mod.rs:1849).
- `spawn_supervised_aux()` for aux thread catch_unwind
  (coordinator/mod.rs:1860+).
- Worker loop spawned with `panic_slot.clone()` and
  catch_unwind wrapping the loop body, setting
  `runtime.dead.store(true, Relaxed)` + `panic_slot.lock()
  → Some(msg)` on catch.
- `WorkerRuntimeStatus { dead: bool, panic_message: String }`
  exposed via the helper status endpoint
  (`pkg/dataplane/userspace/protocol.go:539-544`).
- Status sampler reads `WorkerRuntimeStatus.dead` per worker.

## Concrete design

### 1. Prometheus gauge `xpf_userspace_worker_dead`

Add to `pkg/api/metrics.go` xpfCollector:

```go
workerDead: prometheus.NewDesc(
    "xpf_userspace_worker_dead",
    "1 if the userspace-dp worker thread panicked and was caught by the supervisor; 0 if running. Cleared only by daemon restart (#925).",
    []string{"worker_id"}, nil,
),
```

In `Collect()`, emit one sample per worker:

```go
for _, w := range status.WorkerRuntime {
    val := float64(0)
    if w.Dead {
        val = 1
    }
    ch <- prometheus.MustNewConstMetric(
        c.workerDead, prometheus.GaugeValue, val,
        fmt.Sprintf("%d", w.WorkerID),
    )
}
```

### 2. Panic-injection unit tests (Rust)

Add to `userspace-dp/src/afxdp/coordinator/tests.rs`:

```rust
#[test]
fn supervisor_catches_worker_panic_and_marks_dead() {
    let panic_slot = Arc::new(Mutex::new(None::<String>));
    let runtime = Arc::new(WorkerRuntimeAtomics::default());

    spawn_supervised_panicking_test_thread(
        runtime.clone(),
        panic_slot.clone(),
        || panic!("test panic from supervisor_catches_worker_panic_and_marks_dead"),
    );

    assert!(runtime.dead.load(Ordering::Relaxed));
    let captured = panic_slot.lock().unwrap().clone();
    assert!(captured.is_some());
    assert!(captured.unwrap().contains("test panic from supervisor"));
}

#[test]
fn supervisor_clean_exit_does_not_set_dead() {
    let panic_slot = Arc::new(Mutex::new(None::<String>));
    let runtime = Arc::new(WorkerRuntimeAtomics::default());

    spawn_supervised_panicking_test_thread(
        runtime.clone(),
        panic_slot.clone(),
        || { /* clean return */ },
    );

    assert!(!runtime.dead.load(Ordering::Relaxed));
    assert!(panic_slot.lock().unwrap().is_none());
}
```

`spawn_supervised_panicking_test_thread` is a small test
helper added to coordinator/tests.rs that wraps the same
catch_unwind pattern used in production worker spawns.
Lifecycle: spawn → run closure → join. The helper joins
inside itself so the test sees the post-mutation state.

### 3. No-respawn rationale (in this plan)

Decision: **xpfd does NOT auto-respawn dead workers**. A
worker-loop panic indicates corrupted state that the loop
itself can't recover from cleanly. Respawning would either:

- **Reuse the existing BindingWorker / SessionTable / FlowCache /
  BPF map FDs** — but those structures may be inconsistent
  (the panic site likely was an `assert!` tripping on an
  invariant violation, e.g. MQFQ vtime rollback). Restarting
  the loop on poisoned state would re-trigger the same panic
  or produce undefined behavior.

- **Tear down and rebuild from scratch** — but this requires
  rebuilding the BindingPlan, re-binding AF_XDP queues
  (kernel may refuse rebind if the FD was held), reloading
  BPF maps, reconnecting to peer for HA session sync, etc.
  This is a daemon-restart-equivalent flow with extra
  complexity for doing it from inside a long-lived process.

The mark-dead-and-stop strategy gives operators:
- Clear observability (Prometheus alert + journald log).
- Clean state on the surviving workers (one dead worker
  doesn't cascade).
- Predictable recovery (`systemctl restart xpfd` from the
  alert handler).

This trades **partial outage for the dead worker's bindings**
against **full daemon restart latency**.

### 4. HA interaction documented

Worker death does NOT trigger chassis-cluster failover.
Rationale:

- The cluster-level VRRP timer (~60ms failover) is separate
  from worker liveness.
- A dead worker's bindings stop forwarding, but the surviving
  workers' bindings (including any RETH-VIP-bearing one) keep
  serving.
- Auto-failing-over on partial outage would create a flap loop
  on any deployment with a single panic-prone worker.

Operators detect the dead worker via Prometheus
(`xpf_userspace_worker_dead{worker_id="N"} == 1`), then
choose to restart xpfd (which does its planned-shutdown
priority-0 VRRP burst → peer takes over fast), avoiding any
hot failover.

## Public API preservation

No public API changes. Adds:
- One new Prometheus gauge.
- Two new private unit tests.
- Plan documentation.

All existing `WorkerRuntimeStatus`, `WorkerRuntimeAtomics`,
gRPC, and JSON shapes preserved.

## Hidden invariants

- **`WorkerRuntimeStatus.dead` is one-shot**: set once on
  catch, cleared only by daemon restart. The Prometheus
  gauge inherits this — no oscillation.
- **Status sampler must NOT crash on Dead == true**: the
  metric pulls from the same status sample that already
  drives existing `xpf_userspace_worker_*` gauges, which
  must already be Dead-tolerant.
- **Test must not interfere with real worker spawn paths**:
  `spawn_supervised_panicking_test_thread` is test-only and
  doesn't touch a real BindingWorker.

## Risk assessment

| Risk | Level | Note |
|------|-------|------|
| Behavioral regression | LOW | Pure additive — new metric, new tests, no existing-code change. |
| Lifetime / borrow-checker | LOW | Test uses `Arc<Mutex<…>>` which is the existing shape. |
| Performance regression | LOW | Prometheus Collect already iterates WorkerRuntime; one extra gauge per worker per scrape. |
| Architectural mismatch (#946 P2 / #961 / #964 Step 2-3 dead-end) | LOW | Not an architectural refactor — concrete observability + test addition. |

## Test plan

- `cargo build` clean.
- 952+ cargo tests pass + 2 new tests.
- 5/5 named flake check on `supervisor_catches_worker_panic_and_marks_dead`.
- 30 Go test packages pass — `pkg/api` tests in particular
  to verify the new gauge wires up.
- Smoke: deploy on loss userspace cluster, verify
  `curl localhost:8080/metrics | grep xpf_userspace_worker_dead`
  shows one sample per worker with value 0 in steady state.
- v4 + v6 smoke against `172.16.80.200` /
  `2001:559:8585:80::200`. Not strictly required for an
  observability addition but cheap insurance.

## Out of scope

- Automatic worker respawn (documented decision NOT to do
  this; rationale above).
- Sticky-failure detection (no respawn → no respawn loop to
  detect).
- Cross-worker binding redistribution (would require
  respawn-equivalent state recovery).
- HA failover trigger on worker death (documented decision
  NOT to do this; rationale above).
- Per-class CoS smoke is NOT required for this observability
  addition.

## Open questions for adversarial review

1. **Is documenting "no auto-respawn" sufficient?** The issue
   says "Automatic respawn implementation OR documented
   decision NOT to respawn (with rationale)" — this plan
   chooses the latter. Is the rationale sound?
2. **Should the gauge be `xpf_userspace_worker_dead` or
   `xpf_userspace_worker_alive` (inverted)?** Convention in
   the codebase suggests `dead=1 means panic`; operators may
   prefer `alive=1 means healthy`. Which is more idiomatic?
3. **Is `spawn_supervised_panicking_test_thread` the right
   test surface**, or should the test exercise a smaller
   `supervise_panic` free-function helper extracted from
   coordinator/mod.rs?
4. **HA interaction**: should there be ANY automatic action on
   worker death (e.g., adjust per-RG weight to deprioritize
   this node), or is "operator restarts xpfd" the only
   correct behavior?
5. **Panic-injection test stability**: catch_unwind has subtle
   thread-local-state interactions in Rust (`std::panic::set_hook`
   can be hijacked by other tests). Does the new test risk
   flaking under concurrent test runs (cargo test runs tests
   in parallel by default)?
