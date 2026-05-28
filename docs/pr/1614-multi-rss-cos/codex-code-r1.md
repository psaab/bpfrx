# Codex code-review r1 - PR #1618 / #1614 Axis A

Reviewer: Codex hostile implementation review.

Target: branch `refactor/1614-multi-rss-cos`, HEAD `3e2b1f4a9b1064e06a5b9bfed8eadb14775ac957`.

Scope: implementation correctness only, against `docs/pr/1614-multi-rss-cos/plan.md` v5.1 and the requested review checklist.

Verdict: **NEEDS-MAJOR**.

## Findings

### MAJOR: `guarantee_fraction` is only a boolean enable, not the v5.1 allocator input

The default/proportional safety gate is correct, but the opt-in `guarantee-rate <fraction>` semantics are not implemented as documented. In the hot path, `oversubscription_guarantee_fraction` appears only in the gate:

> `) && root.oversubscription_guarantee_fraction > 0.0`

Evidence: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:603-608`.

The waterfill implementation then walks the sorted exact queue list and never reads the fraction:

> `let sorted_indices: Vec<usize> = root.exact_queues_by_rate_ascending.clone();`

Evidence: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:767-878`; repo-wide `rg oversubscription_guarantee_fraction` finds the hot-path read only at `queue_service/mod.rs:606`.

That contradicts the plan, which makes the fraction the Phase 1 budget multiplier:

> `guarantee_fraction = root.config.pass1_guarantee_fraction  // 0.0..1.0`
> `pass1_budget = (cap * guarantee_fraction).floor()`

Evidence: `docs/pr/1614-multi-rss-cos/plan.md:240-243`.

Consequence: `guarantee-rate 0.1`, `0.4`, `0.7`, and `1.0` all run the same allocator. Operators see a numeric knob and warnings report `guarantee-rate <X>`, but the dataplane treats every positive value identically. This is not a boundary coverage nit; it is the central opt-in control being ignored.

## Checklist Review

### (a) Proportional-mode gate

Pass. The new selector is gated on both `GuaranteeRate` and `fraction > 0.0`:

> `if matches!(root.oversubscription_policy, CoSOversubscriptionPolicy::GuaranteeRate) && root.oversubscription_guarantee_fraction > 0.0`

Evidence: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:603-608`.

The legacy body follows immediately after the gate (`queue_count`, `start`, RR loop, token gates, and cursor advance), so default `Proportional` cannot enter waterfill. Repo search shows `select_exact_cos_guarantee_queue_waterfill` is only called from this gate and otherwise only defined.

### (b) Waterfill cursor and empty-set handling

Pass for the stated invariant. Empty queue sets return `None`:

> `if queue_count == 0 || root.exact_queues_by_rate_ascending.is_empty() { return None; }`

Evidence: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:777-780`.

On selection, telemetry cursor parity advances to one past the selected queue:

> `root.exact_guarantee_rr = (queue_idx + 1) % queue_count;`

Evidence: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:856-862`.

### (c) Sorted exact queue list construction

Pass. `exact_queues_by_rate_ascending` is built once in runtime construction and uses stable `sort_by_key`:

> `.filter(|&idx| config.queues[idx].exact && config.queues[idx].guarantee_enabled)`
> `.sort_by_key(|&idx| config.queues[idx].transmit_rate_bytes);`

Evidence: `userspace-dp/src/afxdp/cos/builders.rs:75-84`.

Production search shows no runtime mutation outside construction; assignments in `queue_service/tests.rs` are test setup only.

### (d) Wire protocol compatibility

Pass. Go adds all requested fields with `omitempty`:

> `CoSOversubscriptionPolicy string ... omitempty`
> `CoSOversubscriptionGuaranteeFraction float64 ... omitempty`
> `CoSPriorityLowMinShareBytes uint64 ... omitempty`
> `CodelTargetNS uint64 ... omitempty`

Evidence: `pkg/dataplane/userspace/protocol.go:145-158`, `pkg/dataplane/userspace/protocol.go:225-228`.

Rust has matching defaulted fields:

> `#[serde(rename = "cos_oversubscription_policy", default)]`
> `#[serde(rename = "cos_oversubscription_guarantee_fraction", default)]`
> `#[serde(rename = "cos_priority_low_min_share_bytes", default)]`
> `#[serde(rename = "codel_target_ns", default)]`

Evidence: `userspace-dp/src/protocol/snapshot.rs:96-108`, `userspace-dp/src/protocol/cos.rs:118-119`.

Old Go snapshots omit zero fields; new Rust defaults absent fields to empty/zero. New snapshots with extra fields remain safe for Rust serde because unknown JSON fields are ignored by default.

### (e) Config warning nil-safety and AST shapes

Pass. `validateCoSOversubscriptionWarnings` checks `cos`, `iface`, `unit`, `schedMap`, `entry`, and `sched` before dereference:

> `if cos == nil { return warnings }`
> `if iface == nil { continue }`
> `if unit == nil || unit.ShapingRateBytes == 0 || unit.SchedulerMap == "" { continue }`
> `if !ok || schedMap == nil { continue }`
> `if entry == nil || entry.Scheduler == "" { continue }`
> `if !ok || sched == nil || !sched.TransmitRateExact { continue }`

Evidence: `pkg/config/compiler.go:1066-1090`.

Flat set syntax and hierarchical child syntax are both handled:

> `len(oversubNode.Keys) >= 2 && oversubNode.Keys[1] == "guarantee-rate"`
> `else if grNode := oversubNode.FindChild("guarantee-rate"); grNode != nil`

Evidence: `pkg/config/compiler_class_of_service.go:331-379`.

### (f) A2/A3 deferred hot-path code

Pass. `priority_low_min_share_bytes` and `codel_target_ns` are wire-plumbed and copied into runtime structs, but not read by dequeue/service logic. Repo-wide search shows non-test uses only in protocol parsing, forwarding build, runtime construction, and comments. The Rust compiler also reports:

> `field codel_target_ns is never read`

Evidence from `cargo test` warnings; field definition at `userspace-dp/src/afxdp/types/cos.rs:580`.

`priority_low_reserved_tokens` and `priority_low_last_refill_ns` are initialized in `build_cos_interface_runtime` but not consumed:

> `priority_low_reserved_tokens: 0,`
> `priority_low_last_refill_ns: now_ns,`

Evidence: `userspace-dp/src/afxdp/cos/builders.rs:105-107`; repo-wide search shows no production reads.

### (g) Tests and boundary gaps

Current tests pass for the narrow assertions:

> `waterfill_default_proportional_mode_uses_legacy_rr`
> `waterfill_guarantee_rate_mode_picks_smallest_rate_first`
> `waterfill_guarantee_rate_skips_non_exact_queues`

Evidence: `userspace-dp/src/afxdp/cos/queue_service/tests.rs:2195-2275`.

Go warning tests cover default and flat-key `guarantee-rate 0.7` parsing:

> `TestValidateCoSOversubscriptionWarning`
> `TestValidateCoSOversubscriptionWarningGuaranteeRate`

Evidence: `pkg/config/parser_class_of_service_test.go:877-982`.

Blocking coverage gap: there is no test proving `guarantee-rate 0.4`, `0.7`, and `1.0` produce different budgets/distributions. That missing boundary test would expose the MAJOR issue above.

Additional non-blocking gaps: no empty-exact-set unit test, no `GuaranteeRate` with fraction `0.0` bypass test, no hierarchical AST fixture for `oversubscription-policy { guarantee-rate 0.7; }`, and no explicit `codel-target` protocol round-trip test.

### (h) `make test-failover` / HA impact

No direct HA path touched. The changed implementation files are CoS config/protocol/build/runtime files; the only HA-adjacent changed Rust files are tests and CoS forwarding-build plumbing. `make test-failover` maps to `./test/incus/test-failover.sh` and was not run in this sandbox.

Evidence: `Makefile:123-124`; changed HA-adjacent files from `git diff --name-only origin/master...HEAD` are limited to `userspace-dp/src/afxdp/coordinator/tests.rs`, `userspace-dp/src/afxdp/forwarding_build/cos.rs`, and `userspace-dp/src/afxdp/forwarding_build/tests.rs`.

## Validation Run

Passed:

- `go test ./pkg/config -run 'TestValidateCoSOversubscription'`
- `cargo test --manifest-path userspace-dp/Cargo.toml waterfill_`
- `cargo test --manifest-path userspace-dp/Cargo.toml protocol::tests::wire_invariant_default_specimens`
- `cargo test --manifest-path userspace-dp/Cargo.toml cos_scheduler_snapshot`

Environment-limited failures, not counted against the PR:

- `cargo test --manifest-path userspace-dp/Cargo.toml protocol` also selected `tests::apply_snapshot_rejects_unsupported_protocol_version`, which failed with `Operation not permitted` while writing a request.
- `go test ./pkg/dataplane/userspace -run 'Test.*CoS|Test.*Snapshot|TestProtocol|TestBuild.*Snapshot'` was too broad and hit unrelated environment-dependent tests: loopback ifindex resolution and Unix socket `setsockopt: operation not permitted`.

## Required Fix

Either implement the v5.1 Phase 1/Phase 2 budget semantics using `oversubscription_guarantee_fraction`, or remove the numeric fraction from the operator/API contract and document `guarantee-rate` as a binary small-first policy. The current hybrid is misleading and behaviorally wrong.
