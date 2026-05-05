---
status: DRAFT v1 — pending adversarial plan review
issue: https://github.com/psaab/xpf/issues/915
phase: Add `surplus-sharing` opt-in for exact CoS queues
---

## 1. Issue framing

`exact` CoS queues are non-work-conserving: even when the root
shaper has slack and other queues are idle, an `exact 1G` queue
sitting on a 100 G interface shaped to 10 G stays at 1 G forever.
This matches Junos `exact` strict semantics (hard-cap), but
operators have asked for a way to opt an `exact` queue into
surplus participation while keeping its guarantee floor.

Issue #915 proposes:

1. Remove the hard `queue.exact` skip in
   `select_cos_surplus_batch`.
2. Introduce a config attribute (e.g. `surplus-sharing`)
   to control this behavior, **or** allow it by default if
   `surplus_weight` is non-zero.

## 2. Honest scope/value framing

This is a **non-Junos extension**, not a bug fix. Junos
`transmit-rate <r> exact` is by design a hard cap — the whole
point of the `exact` qualifier. The proposal adds a
`surplus-sharing` qualifier on the scheduler that, when set on
an `exact` queue, lifts the surplus skip and lets the queue
draw from root surplus tokens once its own guarantee phase has
finished.

Concrete operator value: an `iperf-a 1 Gbps exact` queue on a
10 Gbps interface can burst into the spare 9 Gbps when no other
class is hungry, then drop back to 1 Gbps when contention
returns.  Per #915's "100E100M" framing this is the canonical
high-utilization scenario.

If reviewers conclude the operator value is too small to
justify the config-schema + plumbing churn, PLAN-KILL is an
acceptable verdict.

## 3. What's already shipped / partially batched

- `TransmitRateExact bool` already plumbs through
  `pkg/config/types.go:359 → pkg/dataplane/userspace/protocol.go:179
  → userspace-dp/src/afxdp/types/cos.rs:409 (queue.exact)`.
- `cos_surplus_weight` at `userspace-dp/src/afxdp/forwarding_build.rs:858`
  already computes a per-queue weight in [1, 16] proportional to
  configured rate / root rate. Every queue (including exact ones)
  already has a non-zero `surplus_weight` — that means the
  "default-on if `surplus_weight > 0`" form of the issue's
  proposed fix would silently flip every existing `exact` queue
  into work-conserving mode. **This is not what we want as the
  default**, because it breaks the Junos contract for every
  operator already running `transmit-rate <r> exact`. The plan
  picks the **explicit opt-in** form.
- `select_cos_surplus_batch` is at
  `userspace-dp/src/afxdp/cos/queue_service/mod.rs:561-615`. The
  guarantee phase already calls
  `select_exact_cos_guarantee_queue_with_fast_path` BEFORE the
  surplus phase, so the guarantee floor is preserved by the
  existing schedule order — no token-bucket changes needed in
  this plan.

## 4. Concrete design

### 4.1 Config syntax (Junos-style extension)

```
set class-of-service schedulers iperf-a transmit-rate 1g exact
set class-of-service schedulers iperf-a surplus-sharing
```

Both hierarchical (`schedulers iperf-a { surplus-sharing; }`)
and flat-set are supported by the existing parser. The flag is
a leaf node with no value; presence = true. Default =
absent = false.

The flag is **only meaningful on `exact` queues**. On
non-exact queues it has no effect (they already participate in
surplus). Validation emits a warning if `surplus-sharing` is
set without `transmit-rate <r> exact` so operators don't think
they've asked for new behavior they didn't get; doesn't reject
the config.

### 4.2 Go config plumbing

- `pkg/config/types.go:CoSScheduler`: add
  `SurplusSharing bool`.
- `pkg/config/compiler_class_of_service.go`: extract
  `surplus-sharing` leaf inside the scheduler block.
- `pkg/dataplane/userspace/protocol.go:CoSSchedulerSnapshot`:
  add `SurplusSharing bool` json field (`omitempty`).
- `pkg/dataplane/userspace/snapshot.go`: copy
  `sched.SurplusSharing` into the snapshot per scheduler.
- `pkg/cmdtree/tree.go`: add the new leaf under
  `class-of-service schedulers <name>`.

### 4.3 Rust runtime plumbing

- `userspace-dp/src/afxdp/types/cos.rs:CoSQueueRuntime`: add
  `pub(in crate::afxdp) surplus_sharing: bool`. Doc-comment
  records: "Only meaningful when `exact == true`. When set,
  the queue participates in `select_cos_surplus_batch` as if it
  were non-exact (#915)."
- `userspace-dp/src/afxdp/forwarding_build.rs`: populate
  `surplus_sharing` from
  `scheduler.surplus_sharing`, defaulting to `false`. Mirror
  the `exact` field's `.map(...).unwrap_or(false)` shape.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:572`:
  change the surplus-phase skip from
  ```rust
  if cos_queue_is_empty(queue) || !queue.runnable || queue.exact {
      continue;
  }
  ```
  to
  ```rust
  if cos_queue_is_empty(queue) || !queue.runnable {
      continue;
  }
  if queue.exact && !queue.surplus_sharing {
      continue;
  }
  ```
  Two-stage gate keeps the empty/non-runnable fast skip
  unchanged and the `exact && !surplus-sharing` skip explicit
  for grep-ability and review.

### 4.4 What NOT to change

- The exact-guarantee phase
  (`select_exact_cos_guarantee_queue_with_fast_path`) is
  unchanged. Exact queues still get strict-priority
  guarantee-phase service before any surplus runs, so the
  guarantee floor is preserved.
- `cos_surplus_quantum_bytes` is unchanged. The DRR per-queue
  quantum still applies — surplus-sharing exact queues
  participate fairly with non-exact queues at the same priority
  level, weighted by `surplus_weight`.
- `queue.tokens` is unchanged on the surplus path. Surplus
  consumes only `root.tokens`, same as for non-exact queues
  today. So an exact queue with surplus-sharing draws bytes
  from the root shaper, not from its own per-queue bucket
  (which has already been consumed during the guarantee phase).

### 4.5 Validation rule

`pkg/config/compiler_class_of_service.go` emits a warning when
`SurplusSharing == true` and `TransmitRateExact == false`:
"surplus-sharing is meaningful only on transmit-rate exact
schedulers; ignored." Doesn't reject. Aligns with #1183 lesson
(post-build "useful state" gate) — config validation should
warn-and-strip, not error-and-block.

## 5. Public API preservation

- `CoSScheduler` gains one new bool field. Existing `omitempty`
  JSON tags ensure forward-compat with older snapshots that
  lack the field — they decode to `false`, preserving today's
  behavior.
- `CoSQueueRuntime` gains one bool. No struct-size concern;
  Rust doesn't pin layout.
- No public-API method signatures change.

## 6. Hidden invariants the change must preserve

- **Strict-priority exact guarantee over surplus**: exact queues
  with surplus-sharing must still drain their guarantee budget
  via `select_exact_cos_guarantee_queue_with_fast_path` before
  hitting the surplus phase. The combined-batch dispatcher at
  `select_combined_cos_batch:200-212` already enforces this
  ordering (exact → nonexact-guarantee → surplus). No change
  to dispatcher.
- **Per-queue token bucket**: an exact queue's `queue.tokens`
  cap is enforced ONLY in guarantee phase. Surplus consumes
  `root.tokens` exclusively. So surplus-sharing does NOT let a
  1 Gbps queue exceed 1 Gbps overall — it lets it consume root
  surplus on top of its 1 Gbps guarantee.
- **DRR fairness**: `surplus_deficit` accumulation is unchanged.
  An exact-with-surplus-sharing queue will land in the priority
  RR alongside non-exact queues at the same priority and DRR
  fairly via its existing `surplus_weight`.
- **Park accounting**: `count_park_reason` /
  `park_cos_queue` paths in surplus already have
  `RootTokenStarvation` for the non-exact case; exact queues
  reaching surplus phase share that path uniformly.
- **#1183 useful-state gate**: exact queues with no
  surplus-sharing (the default) keep the same code path they
  have today. The new branch fires only for opted-in queues.
  This is the post-build "useful CoS state" pattern — extra
  state only for queues that need it.

## 7. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | **LOW** | Default = false. No change for existing operators. New behavior only when operator explicitly opts in. |
| Lifetime / borrow-checker | **LOW** | Plain bool field, no lifetime changes. |
| Performance regression | **LOW** | One extra `&& !queue.surplus_sharing` branch in surplus path. Predictable not-taken on the common case (most queues are non-exact). |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **LOW** | Targeted fix at one specific call site. Not a refactor. The proposed surplus-sharing semantic maps cleanly to existing surplus mechanics; no new abstraction. |

## 8. Test plan

- `make generate` clean.
- `cargo build --release` clean.
- `cargo test --release` 962+ pass, plus new tests:
  - `pkg/config/parser_class_of_service_test.go`:
    `TestSchedulerSurplusSharingHierarchical` /
    `TestSchedulerSurplusSharingFlatSet` — both parse paths set
    the bool.
  - `pkg/config/parser_class_of_service_test.go`:
    `TestSurplusSharingWithoutExactWarns` — validation warning
    fires when surplus-sharing is set without `exact`.
  - `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
    `select_cos_surplus_batch_includes_exact_with_surplus_sharing` —
    exact queue with surplus_sharing=true is selected for
    surplus.
  - `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
    `select_cos_surplus_batch_excludes_exact_without_surplus_sharing` —
    default-false preserves today's hard-cap behavior.
  - `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
    `exact_surplus_sharing_consumes_root_tokens_only` — verify
    `queue.tokens` is unchanged after surplus drain.
  - `userspace-dp/src/afxdp/cos/builders_tests.rs`:
    `cos_queue_runtime_propagates_surplus_sharing` — snapshot
    → runtime field copy works.
- Go test suite clean.
- Smoke matrix per `triple-review` SKILL.md Step 6: full
  Pass A + Pass B 30 measurements (CoS-disabled best-effort
  fast path + per-class CoS 5201-5206 v4+v6 push+reverse).
  Expected: zero throughput delta on default config (all
  classes default surplus-sharing=false).
- Smoke validation: configure
  `set class-of-service schedulers iperf-a surplus-sharing`,
  re-apply CoS, run `iperf3 -c 172.16.80.200 -p 5201 -P 12
  -t 30`. Expect throughput on 5201 to exceed 1 Gbps shape rate
  when other classes idle (target: ≥ 6 Gbps single-stream cap
  per the loss-cluster baseline).

## 9. Out of scope (explicitly)

- Default-true `surplus-sharing` semantics. Risk of breaking
  operators relying on Junos `exact` hard-cap is too high.
- Surplus-share weighting different from `surplus_weight`. The
  feature reuses the existing weight; a separate
  `surplus-sharing-weight <n>` knob can be a follow-up if
  operators ask.
- Glide-style per-flow rate signal (#747).
- HA sync of per-scheduler `surplus-sharing` config — config
  sync already covers all scheduler config including this
  field.
- DPDK pipeline parity. The DPDK manager mirrors scheduler
  config but the DPDK CoS scheduler doesn't yet match the
  Rust queue_service — separate scope.

## 10. Open questions for adversarial review

1. **Scope/value**: is the operator value of opt-in
   surplus-sharing on exact queues high enough to justify the
   config-schema + plumbing churn (≈ 30 LOC across 6 files)?
   If reviewers consider the scenario rare enough that
   operators should just remove the `exact` qualifier instead,
   PLAN-KILL is acceptable.
2. **Default semantics**: the plan picks explicit opt-in.
   Reviewers may prefer "default-on if `surplus_weight > 0`"
   (closer to the issue's text). Argument for opt-in:
   `surplus_weight` is computed for every queue including
   `exact` ones today, so default-on would silently flip every
   existing exact queue. Argument against opt-in: more knobs
   to know about. Settled in §4 but invites pushback.
3. **Validation rule**: warn-and-strip vs reject when
   `surplus-sharing` is set without `exact`. Plan picks
   warn (per #1183 lesson). Reviewers may prefer reject for
   strictness.
4. **Token-bucket interaction**: confirm that surplus phase
   really doesn't touch `queue.tokens` for exact queues (the
   plan claims this; the code shows `queue.tokens` is read in
   surplus only for the wakeup-tick estimate, not consumed —
   verify against `select_cos_surplus_batch:594-611`).
5. **CLI exposure**: the new flag should appear in
   `show class-of-service interface` per-queue output so
   operators can see at a glance which exact queues have it.
   Plan §4.2 doesn't currently address this — should it?
6. **Schema migration**: snapshot format gains a new field.
   Worker fast-path forwarding-build code must handle older
   snapshots (decode to `false`). Plan §5 claims `omitempty`
   covers this; verify against `pkg/dataplane/userspace/snapshot.go`
   reader paths.
7. **Smoke evidence**: the success criterion (≥ 6 Gbps
   single-stream on 5201 with surplus-sharing on) assumes
   no other CoS class is hungry. Reviewers may require a
   contention scenario that proves the guarantee floor still
   holds when other classes pressure the root shaper.
8. **DPDK parity**: not in scope, but should we file a
   follow-up to keep DPDK ↔ Rust CoS feature symmetry?
   (See out-of-scope §9.)
