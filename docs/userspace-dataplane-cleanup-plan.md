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

## Status Snapshot

Current execution state as of 2026-03-15:

1. Phase 1 is complete and merged on `master` via PR `#222`.
2. Phase 2 is complete on branch `fix/userspace-phase2-icmp-extract` via
   PR `#223` and is pending merge.
3. Phase 5 is partially complete on `master` via PR `#221`.
4. Phase 3 is the next active cleanup phase.
5. Phases 4 and 6 have not started as formal cleanup phases yet.

Completed under this plan:

1. Production dataplane debug noise is now gated behind `debug-log` instead of
   being emitted by default.
2. `userspace-dp` default-build warning debt was reduced from `145` warnings to
   `0`.
3. Standard userspace validation now includes traceroute and `mtr` checks for:
   - IPv4 to `1.1.1.1`
   - IPv6 to `2607:f8b0:4005:814::200e`
4. Phase 2 extracted the main helper clusters out of `userspace-dp/src/afxdp.rs`
   into:
   - `userspace-dp/src/afxdp/bind.rs`
   - `userspace-dp/src/afxdp/icmp.rs`
   - `userspace-dp/src/afxdp/icmp_embed.rs`
   - `userspace-dp/src/afxdp/frame.rs`
   - `userspace-dp/src/afxdp/session_glue.rs`
   - `userspace-dp/src/afxdp/tx.rs`
5. `userspace-dp/src/afxdp.rs` was reduced from the previous monolith size to a
   smaller coordinator-oriented file:
   - before Phase 2 completion: about `17.6k` lines
   - after Phase 2 completion: about `12.3k` lines
6. The Phase 2 branch also carries the driver-aware AF_XDP bind strategy work
   and the shared-lock-ordering fix found during PR review.
7. Live validation proved that the extracted Phase 2 branch still forwards
   correctly through the userspace dataplane on the active node:
   - userspace forwarding armed on `bpfrx-userspace-fw0`
   - IPv4 and IPv6 internal reachability working
   - IPv4 and IPv6 TTL=1 probes return native time-exceeded responses
   - IPv4 and IPv6 `mtr` still show the same unresolved intermediate hops as
     before, but first hop and destination visibility remain correct
8. Live validation now proves the runtime AF_XDP bind split is correct for the
   current hardware mix:
   - `mlx5_core` stays on the existing UMEM-owner zerocopy path
   - `virtio_net` fabric bindings on `ifindex 4` now bind cleanly in copy mode
     via the UMEM-owner path with `bind_flags=0`
   - active node validation on `bpfrx-userspace-fw0` shows `24/24` bound and
     `24/24` ready bindings after deploy

Still left to do at a high level:

1. Start the formal tuple/session authority cleanup in Phase 3.
2. Clean up AF_XDP queue and frame ownership in Phase 4.
3. Finish hardening validation coverage in Phase 5.
4. Only then do the serious sustained-throughput optimization work in Phase 6.

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

Status: Complete

Completed:

1. Nonessential dataplane debug logging was gated behind `debug-log`.
2. Operator-facing lifecycle logging remained enabled.
3. Warning cleanup was completed across `userspace-dp`.
4. Default `cargo test --no-run` warning count for `userspace-dp` is now `0`.

Delivered in:

1. PR `#222`
2. Commits:
   - `58660cf` `userspace: start phase1 dataplane cleanup`
   - `84e53c3` `userspace: finish phase1 dataplane cleanup`

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

Status: Complete On Branch, Pending Merge

Completed:

1. Local TTL-expiry detection, ICMP/ICMPv6 Time Exceeded builders, ICMP error
   classification, and related local-request helpers were extracted into
   [userspace-dp/src/afxdp/icmp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/icmp.rs).
2. Embedded ICMP and ICMPv6 helper logic was extracted into
   [userspace-dp/src/afxdp/icmp_embed.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/icmp_embed.rs).
3. Shared lock ordering in embedded ICMP resolution was fixed during the PR
   review cycle.
4. AF_XDP bind/open strategy helpers were extracted into
   [userspace-dp/src/afxdp/bind.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/bind.rs).
5. Session and reverse-session lookup / repair glue was extracted into
   [userspace-dp/src/afxdp/session_glue.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/session_glue.rs).
6. Frame parsing, tuple parsing, frame build, NAT rewrite, and checksum helpers
   were extracted into
   [userspace-dp/src/afxdp/frame.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/frame.rs).
7. TX queueing, completion, recycle, and wake helpers were extracted into
   [userspace-dp/src/afxdp/tx.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/tx.rs).
8. Focused Rust tests passed after the extraction.
9. The extracted branch was deployed live to:
   - `loss:bpfrx-userspace-fw0`
   - `loss:bpfrx-userspace-fw1`
10. Live validation on the active userspace node confirmed:
   - userspace forwarding armed successfully
   - internal dual-stack reachability still works
   - native IPv4 and IPv6 traceroute time-exceeded behavior still works

Live findings already established for this extraction area:

1. `mlx5_core` requires the current shared-owner / UMEM-owner bind path in this
   implementation.
2. `virtio_net` on the fabric interface binds reliably with the UMEM-owner path
   in copy mode when `bind_flags=0` are used.
3. The attempted separate-owner `virtio_net` path was removed from the active
   strategy selection after live validation showed the direct UMEM-owner
   auto-mode path was the correct contract for this environment.

Delivered so far in:

1. PR `#223`
2. Commits already on that branch:
   - `e4453a7` `userspace: start phase2 icmp helper extraction`
   - `cf587cd` `userspace: retry neighbor refresh after probe`
   - `19bc561` `userspace: extract embedded icmp helpers`
   - `6b1d65f` `userspace: probe AF_XDP bind strategy per driver`
   - `af89e42` `userspace: complete embedded icmp extraction and fix shared lock ordering`
   - additional completion commits on the same branch finish the bind, frame,
     session-glue, and TX extraction work

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

Phase 2 result:

1. Achieved on the branch and validated live.
2. The `virtio_net` fabric AF_XDP bring-up issue is resolved for the current
   HA lab:
   - `virtio_net` `ifindex 4` binds cleanly in copy mode via the UMEM-owner
     path with `bind_flags=0`
   - `mlx5_core` remains on the existing zerocopy UMEM-owner path
3. The remaining work now moves cleanly into Phase 3 rather than being blocked
   on AF_XDP driver bring-up.

## Phase 3: Tuple Authority And Session Resolution Cleanup

Status: Next Active Phase

Preparatory work already exists:

1. Recent userspace fixes reduced tuple-authority and embedded-ICMP bugs before
   this cleanup plan started.
2. Phase 2 extraction is intentionally setting up this phase by moving ICMP and
   embedded-ICMP logic into smaller modules first.

Still left:

1. Define one authoritative tuple model per stage and enforce it consistently.
2. Consolidate reverse-session and NAT-reverse resolution.
3. Remove duplicated repair logic that still lives inside `afxdp.rs`.

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

Status: Not Started

Relevant known issues still left for this phase:

1. Queue ownership and frame lifecycle are still too implicit in
   `userspace-dp/src/afxdp.rs`.
2. The common forward path and fallback paths still share more queueing logic
   than they should.
3. AF_XDP driver-specific bring-up behavior is now understood for the current
   lab:
   - `mlx5_core` should stay on the current zerocopy UMEM-owner path
   - `virtio_net` should stay on the copy-mode UMEM-owner path with
     `bind_flags=0`
4. The queue/frame cleanup can now proceed without the `virtio_net` fabric bind
   problem distorting live validation.

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

Status: Partially Complete

Completed so far:

1. Standard userspace validation now checks IPv4 traceroute and `mtr` behavior
   to `1.1.1.1`.
2. Standard userspace validation now checks IPv6 traceroute and `mtr` behavior
   to `2607:f8b0:4005:814::200e`.
3. Sustained-throughput collapse detection was already added before this plan
   and remains part of the normal workflow.

Delivered in:

1. PR `#221`
2. Commit:
   - `4a5006f` `test: add traceroute checks to userspace validation`

Still left:

1. Add more direct regression coverage for tuple authority and embedded ICMP
   corner cases.
2. Add coverage for AF_XDP build-failure fallback behavior.
3. Keep synchronized capture workflows available as diagnosis tools, not first
   line validation.

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

Status: Not Started

Why it is still deferred:

1. Phase 3 tuple/session authority cleanup has not started formally yet.
2. Phase 4 queue/frame lifecycle cleanup has not started formally yet.
4. Performance work before those phases would stack new tuning on top of code
   that is still too hard to reason about.

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

## Immediate Next Steps

1. Start Phase 3 by making tuple authority explicit at each stage of packet
   processing.
2. Consolidate reverse-session and NAT-reverse lookup paths now that the helper
   clusters live in separate modules.
3. Keep the resolved driver split intact:
   - `mlx5_core` on zerocopy UMEM-owner
   - `virtio_net` on auto-mode copy UMEM-owner
4. Keep the new traceroute and `mtr` checks as the mandatory correctness gate
   for any Phase 3 or Phase 4 changes.
