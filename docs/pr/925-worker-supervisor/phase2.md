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

Reuse the existing `spawn_supervised_worker` (which already
takes an arbitrary closure and is tested directly at
`coordinator/tests.rs:848`). No new test helper.

Add to `userspace-dp/src/afxdp/coordinator/tests.rs`:

```rust
// Serialize the panic-injection test against any other test
// that touches the global panic hook. Cargo's default
// parallel runner makes this otherwise flaky.
#[test]
#[serial_test::serial]  // or hand-rolled OnceLock<Mutex<()>> if not in dev-deps
fn supervisor_catches_worker_panic_and_marks_dead() {
    // Silence stderr noise during the catch_unwind. Drop guard
    // restores the prior hook even if the test panics.
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let _restore = scopeguard::guard((), |_| std::panic::set_hook(prior_hook));

    let panic_slot = Arc::new(Mutex::new(None::<String>));
    let runtime = Arc::new(WorkerRuntimeAtomics::default());

    let handle = spawn_supervised_worker(
        "worker-test",
        runtime.clone(),
        panic_slot.clone(),
        || panic!("test panic from supervisor_catches_worker_panic_and_marks_dead"),
    );
    handle.join().expect("thread join");

    assert!(runtime.dead.load(Ordering::Relaxed));
    let captured = panic_slot.lock().unwrap().clone();
    assert!(captured.is_some());
    assert!(captured.unwrap().contains("test panic from supervisor"));
}

#[test]
#[serial_test::serial]
fn supervisor_clean_exit_does_not_set_dead() {
    let panic_slot = Arc::new(Mutex::new(None::<String>));
    let runtime = Arc::new(WorkerRuntimeAtomics::default());

    let handle = spawn_supervised_worker(
        "worker-test",
        runtime.clone(),
        panic_slot.clone(),
        || { /* clean return */ },
    );
    handle.join().expect("thread join");

    assert!(!runtime.dead.load(Ordering::Relaxed));
    assert!(panic_slot.lock().unwrap().is_none());
}
```

If `serial_test` isn't already in `userspace-dp`'s dev-deps,
fall back to a hand-rolled global mutex:

```rust
static PANIC_TEST_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();
fn panic_test_guard() -> std::sync::MutexGuard<'static, ()> {
    PANIC_TEST_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap()
}
```

Test entry: `let _g = panic_test_guard();` instead of the
`#[serial_test::serial]` attribute.

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

### 3.5. Stale-comment cleanup (mandatory)

Phase-1 comments still promise auto-respawn in Phase 2.
These now contradict v2's documented no-respawn decision:

- `pkg/dataplane/userspace/protocol.go:539` — update to
  describe the current behavior (mark-dead until daemon
  restart) and reference this Phase 2 plan.
- `userspace-dp/src/afxdp/worker_runtime.rs:71` — same
  update.

Ship this comment cleanup in the same PR as the metric +
tests so the codebase stays internally consistent.

### 4. HA interaction documented

Worker death does NOT trigger chassis-cluster failover.
Rationale:

- The cluster-level VRRP timer (~60ms failover) is separate
  from worker liveness.
- `pkg/cluster` has no `WorkerRuntimeStatus.dead` awareness,
  and userspace takeover readiness checks at
  `pkg/dataplane/userspace/manager_ha.go:247` check helper /
  queue / binding readiness — NOT dead workers.
- Auto-failing-over on partial outage would create a flap
  loop on any deployment with a single panic-prone worker.

**Real consequence — black-hole**: if the dead worker owns an
important binding (e.g., the RETH-VIP-bearing one, or a NAT
pool's egress queue), that binding is **black-holed** until
operator restart. Surviving workers' bindings keep forwarding,
but traffic destined for the dead worker's queues is dropped.
The chassis-cluster will NOT detect this and will NOT trigger
failover automatically.

Operators MUST alert on
`xpf_userspace_worker_dead{worker_id="N"} == 1` to detect.
Recovery is `systemctl restart xpfd` (which does its
planned-shutdown priority-0 VRRP burst → peer takes over
fast), avoiding any hot failover.

## Public API surface

Existing `WorkerRuntimeStatus`, `WorkerRuntimeAtomics`, gRPC,
and JSON shapes are unchanged.

**Adds one new monitoring API surface**: the
`xpf_userspace_worker_dead{worker_id}` Prometheus gauge.
Once shipped this gauge is **stable** — operator alerts /
Grafana dashboards / SLOs will pin to its name and labels.
Future changes to either the metric name, label cardinality,
or value semantics (`1` = caught panic, `0` = running,
cleared only by daemon restart) constitute a breaking change
to monitoring infrastructure and require a follow-up
deprecation cycle.

**Implementation reminder**: the gauge MUST be added to
`Describe()` at `pkg/api/metrics.go:345` in addition to the
descriptor field — Prometheus collectors silently drop
`MustNewConstMetric` calls for descs that aren't
described.

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

## Open questions for round-2 adversarial review

(v1's 5 questions were resolved in v2: gauge name committed
to `_dead`; test surface uses existing `spawn_supervised_worker`;
panic-hook concurrency mitigated via `serial_test` /
hand-rolled mutex + take_hook/set_hook with Drop guard;
no-respawn rationale accepted in principle. The HA-action
question persists.)

1. **HA interaction — should there be ANY automatic action on
   worker death** (e.g., `pkg/cluster` adjusts per-RG weight
   to deprioritize this node), or is "operator restarts
   xpfd" the only correct behavior? v2 picks the latter; the
   open question is whether a "soft demote weight on dead
   worker" hook is worth a follow-up issue.
2. **Long-term respawn roadmap**: v2 commits to no-respawn
   based on the state-poisoning argument. But Gemini round 1
   noted this is an availability flaw for HPC. Should we
   commit to a future "respawn with full state rebuild"
   issue, or is the answer "any respawn = daemon restart, so
   automate the daemon restart instead"?
