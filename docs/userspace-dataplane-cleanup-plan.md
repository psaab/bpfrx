# Userspace Dataplane Cleanup And Optimization Plan

This document is the current phased plan for cleaning up and optimizing the
Rust AF_XDP userspace dataplane on `master`.

It is not a historical implementation log. It is the execution plan for making
the current userspace dataplane easier to debug, safer to change, and faster.

Related documents:

- [userspace-dataplane-architecture.md](userspace-dataplane-architecture.md)
- [userspace-dataplane-gaps.md](userspace-dataplane-gaps.md)
- [userspace-debug-map.md](userspace-debug-map.md)
- [afxdp-packet-processing.md](afxdp-packet-processing.md)

## Current Baseline

The code review on current `master` found these main problems:

1. The forwarding hot path is too concentrated in `userspace-dp/src/afxdp.rs`.
2. Compiler warning debt is high enough to hide new regressions.
3. There is still always-on logging and debug residue in dataplane paths.
4. Tuple authority, reverse-session repair, and embedded ICMP handling are too
   tightly coupled inside the AF_XDP worker logic.
5. AF_XDP queue, fill-ring, completion, and backpressure logic need a cleaner
   ownership model before more performance work is attempted.
6. Validation coverage still catches some regressions only after manual
   debugging rather than as part of the normal userspace test path.

## Goals

1. Make the userspace dataplane easier to reason about and review.
2. Reduce correctness regressions in reply-path, NAT, and ICMP error handling.
3. Make queue and frame lifecycle behavior explicit enough to debug stalls.
4. Improve sustained forwarding performance without layering more tuning on top
   of unclear code.
5. Turn the current manual debugging workflow into repeatable regression tests.

## Non-Goals

1. This plan does not change the control-plane model in Go unless required by
   a dataplane correctness issue.
2. This plan does not rebuild the test topology or redefine the userspace
   architecture.
3. This plan does not treat warning cleanup as an end in itself. Warning
   reduction matters because it improves signal and review quality.

## Phase 1: Logging And Warning Cleanup

### Purpose

Reduce noise and remove the current class of "debugging residue shipped into the
runtime" problems.

### Work

1. Gate all nonessential dataplane debugging behind `debug-log` or a similar
   explicit mechanism.
2. Keep only operator-facing lifecycle logs always enabled.
3. Remove or fix unused imports, unused variables, dead helpers, and stale test
   scaffolding across `userspace-dp`.
4. Eliminate warning clusters that currently mask new problems during `cargo
   test --no-run`.

### Primary Files

- [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs)
- [userspace-dp/src/session.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/session.rs)
- [userspace-dp/src/main.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/main.rs)
- [userspace-dp/src/flowexport.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/flowexport.rs)
- [userspace-dp/src/screen.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/screen.rs)

### Exit Criteria

1. Production builds no longer emit ad hoc dataplane debug noise by default.
2. Warning count is reduced to a level where new warnings are actionable.
3. The remaining warnings are intentional and documented.

## Phase 2: Split `afxdp.rs` Into Real Submodules

### Purpose

Reduce the blast radius of changes in the core dataplane file and make hot-path
logic auditable.

### Work

1. Extract RX metadata parse and packet classification helpers.
2. Extract session and reverse-session lookup glue.
3. Extract NAT and frame rewrite helpers that do not need worker-local state.
4. Extract ICMP and ICMPv6 error handling.
5. Extract TX queue, completion, and recycle handling.
6. Keep the worker loop focused on orchestration rather than implementation
   detail.

### Candidate Module Split

1. `afxdp_rx.rs`
2. `afxdp_session.rs`
3. `afxdp_rewrite.rs`
4. `afxdp_icmp.rs`
5. `afxdp_tx.rs`
6. `afxdp_debug.rs`

### Exit Criteria

1. `afxdp.rs` becomes a coordinator layer instead of a monolith.
2. ICMP, NAT, and TX bugs can be changed without touching unrelated worker
   logic.
3. Review diffs for dataplane fixes become smaller and easier to validate.

## Phase 3: Tuple Authority And Session Resolution Cleanup

### Purpose

Stop the repeated class of reply-path and embedded-ICMP regressions caused by
inconsistent ownership of the packet tuple and NAT state.

### Work

1. Define a single authoritative tuple source for each stage:
   metadata tuple, session tuple, embedded tuple, or rewritten frame tuple.
2. Consolidate reverse-session and NAT-reverse lookup paths.
3. Consolidate embedded ICMP and ICMPv6 return-path resolution.
4. Remove duplicated "repair" behavior that currently lives in multiple AF_XDP
   branches.
5. Make the chosen tuple source explicit in code and tests.

### Primary Files

- [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs)
- [userspace-dp/src/session.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/session.rs)
- [userspace-dp/src/nat.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/nat.rs)
- [userspace-dp/src/nat64.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/nat64.rs)
- [userspace-dp/src/nptv6.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/nptv6.rs)

### Exit Criteria

1. Reply-path tuple reconstruction uses one consistent model.
2. Embedded ICMP handling no longer needs special-case repairs sprinkled across
   the worker loop.
3. Session and NAT regression tests cover both IPv4 and IPv6 return paths.

## Phase 4: AF_XDP Queue, TX, And Recycle Cleanup

### Purpose

Make frame ownership and queue backpressure predictable before further
performance tuning.

### Work

1. Audit and simplify the lifecycle of:
   RX frames, fill frames, prepared TX, local TX, and shared recycle paths.
2. Remove dead or nearly-dead transmit paths that are not part of the common
   forwarding path.
3. Make backpressure behavior explicit and measurable.
4. Verify that fill-ring replenishment is not coupled to the wrong TX
   conditions.
5. Separate correctness invariants from performance heuristics.

### Primary Files

- [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs)
- [docs/afxdp-packet-processing.md](/home/ps/git/codex-bpfrx/docs/afxdp-packet-processing.md)
- [docs/userspace-afxdp-idle-softirq-starvation.md](/home/ps/git/codex-bpfrx/docs/userspace-afxdp-idle-softirq-starvation.md)

### Exit Criteria

1. Frame ownership rules are documented and reflected in code structure.
2. Queue stalls and frame leaks are diagnosable from counters and tests.
3. The common forward path is clear enough to profile without first reverse
   engineering queue behavior.

## Phase 5: Validation And Regression Hardening

### Purpose

Move current manual failure discovery into repeatable test coverage.

### Work

1. Add permanent traceroute and `mtr` validation for:
   - IPv4 to `1.1.1.1`
   - IPv6 to `2607:f8b0:4005:814::200e`
2. Keep sustained-throughput collapse detection in the userspace validation
   workflow.
3. Add regression coverage for:
   - embedded ICMP NAT reversal
   - reverse-session repair
   - tuple authority under rewritten frames
   - AF_XDP build failure fallback behavior
4. Keep synchronized capture workflows available for failures, but do not make
   them the first line of detection.

### Primary Files

- [docs/userspace-ha-validation.md](/home/ps/git/codex-bpfrx/docs/userspace-ha-validation.md)
- [docs/userspace-perf-compare.md](/home/ps/git/codex-bpfrx/docs/userspace-perf-compare.md)
- [docs/userspace-debug-map.md](/home/ps/git/codex-bpfrx/docs/userspace-debug-map.md)
- [scripts/userspace-ha-validation.sh](/home/ps/git/codex-bpfrx/scripts/userspace-ha-validation.sh)
- [scripts/userspace-perf-compare.sh](/home/ps/git/codex-bpfrx/scripts/userspace-perf-compare.sh)

### Exit Criteria

1. Traceroute and throughput-collapse regressions fail automatically.
2. The standard validation workflow catches the main correctness regressions.
3. Manual capture/debug skills remain for diagnosis, not for basic detection.

## Phase 6: Performance Optimization On A Cleaner Base

### Purpose

Improve sustained forwarding throughput after correctness and queue ownership
have been stabilized.

### Work

1. Profile the cleaned fast path on live userspace forwarding.
2. Optimize the highest-cost common-path work only:
   session lookup, cross-binding forward path, frame build, queue drain, and
   completion/fill recycle.
3. Reevaluate copy-mode versus zero-copy work only after the queue/frame model
   is clear.
4. Treat line-rate forwarding as the target, but not as an excuse to keep
   accumulating low-confidence hot-path patches.

### Expected Focus Areas

1. Session lookup and reverse lookup cost
2. Frame rewrite/build cost
3. Cross-binding forwarding cost
4. Completion and fill-ring recycle cost
5. Shared-state lock pressure

### Exit Criteria

1. Sustained throughput remains high after startup rather than collapsing.
2. Performance improvements are measured by the standard userspace workflow.
3. Optimization changes land on top of a clearer, smaller fast-path surface.

## Recommended Execution Order

1. Phase 1: Logging And Warning Cleanup
2. Phase 2: Split `afxdp.rs` Into Real Submodules
3. Phase 3: Tuple Authority And Session Resolution Cleanup
4. Phase 4: AF_XDP Queue, TX, And Recycle Cleanup
5. Phase 5: Validation And Regression Hardening
6. Phase 6: Performance Optimization On A Cleaner Base

This order is deliberate.

- Cleanup first so new regressions are visible.
- Structural split second so correctness work stops landing in one giant file.
- Tuple and reply-path cleanup before queue tuning because reply-path bugs are
  still the most frequent correctness failures.
- Queue cleanup before serious performance work because stalls and leaks distort
  any throughput profile.
- Validation before optimization so wins and regressions are measured the same
  way every time.

## Immediate Next Tasks

1. Finish Phase 1 by removing or gating the remaining always-on dataplane
   `eprintln!` paths.
2. Carve ICMP and ICMPv6 error handling out of `afxdp.rs`.
3. Reduce the warning count enough that new warnings become actionable.
4. Add the traceroute checks to the standard userspace validation flow.
