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

Current execution state as of 2026-03-17:

1. Phase 1 is complete and merged on `master` via PR `#222`.
2. Phase 2 is complete and merged on `master` via PRs `#223` and `#225`.
3. Phase 3 is complete and merged on `master` via PR `#228`.
4. Phase 4 is complete and merged on `master` via PR `#229`.
5. Phase 5 is complete and merged on `master` via PRs `#221`, `#230`, and
   `#231`.
6. Phase 6 remains the active area, but the first current job inside it was
   baseline recovery on `fix/userspace-disable-shared-umem-runtime`.

Latest status-sync update for this document:

1. PR `#226` records the current cleanup-plan state on top of `master`.
2. That update specifically captures:
   - Phase 2 completion status
   - the resolved `virtio_net` fabric AF_XDP bind outcome on `ifindex 4`
   - the remaining work for Phases 3 through 6

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
9. A later merge regressed the HA lab by enabling the same-device shared-UMEM
   prototype in normal worker startup on `master`, which left the lab at
   `16/24` ready bindings.
10. The current restore branch disables that runtime path again and brings the
    HA lab back to:
    - `24/24` bound bindings
    - `24/24` ready bindings
    - working IPv4/IPv6 internal reachability
    - working IPv4/IPv6 TTL or hop-limit time-exceeded replies
    - passing short userspace HA validation

Still left to do at a high level:

1. Keep the restored `24/24` HA baseline intact before accepting any new
   performance results.
2. Continue sustained-throughput optimization work in Phase 6 on top of that
   restored baseline.
3. Keep the same-device shared-UMEM work explicitly experimental rather than
   part of the normal runtime path.
4. Tighten measurement discipline before landing more hot-path changes because
   the lab currently shows meaningful run-to-run throughput variance.

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

Status: Complete And Merged

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

Delivered in:

1. PR `#223`
2. PR `#225`
3. Commits across those branches:
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

Status: Complete And Merged

Completed:

1. Session resolution for the worker fast path is now centralized in
   [userspace-dp/src/afxdp/session_glue.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/session_glue.rs)
   instead of being split across direct-hit, shared-hit, and reverse-repair
   branches inside `afxdp.rs`.
2. Shared-session lookup and forward-NAT reverse lookup are now centralized via:
   - `lookup_session_across_scopes(...)`
   - `lookup_forward_nat_across_scopes(...)`
3. Reverse-session installation from a forward NAT match is now centralized via:
   - `install_reverse_session_from_forward_match(...)`
4. Synced-session promotion is now centralized via:
   - `maybe_promote_synced_session(...)`
5. The worker fast path now uses one entrypoint for existing-session resolution:
   - `resolve_flow_session_decision(...)`
6. Embedded ICMP and ICMPv6 NAT-reversal lookup now use the same shared/local
   session and shared/local NAT-reverse helpers rather than maintaining a
   parallel lookup stack.
7. Focused Rust tests passed for:
   - shared session resolution
   - shared NAT-reverse resolution
   - IPv4 and IPv6 tuple-authority regressions
   - IPv4 and IPv6 embedded ICMP return-path handling
8. Live validation on `loss:bpfrx-userspace-fw0/1` passed after deployment:
   - userspace forwarding armed on `bpfrx-userspace-fw0`
   - IPv4 internal reachability to `172.16.80.200`
   - IPv6 internal reachability to `2001:559:8585:80::200`
   - IPv4 TTL=1 probe to `1.1.1.1` returns time-exceeded
   - IPv6 hop-limit=1 probe to `2607:f8b0:4005:814::200e` returns time-exceeded
   - IPv4 `mtr 1.1.1.1` first hop and destination visibility are correct
   - IPv6 `mtr 2607:f8b0:4005:814::200e` first hop and destination visibility
     are correct
   - single-stream IPv4 and IPv6 `iperf3` both complete through the userspace
     dataplane

Delivered in:

1. PR `#228`
2. Additional note:
   - the standard validator shell path currently aborts early on TTL probes
     because `ping -t 1` returns a non-zero exit status even when the expected
     time-exceeded response is present; this is a Phase 5 validation-script bug,
     not a Phase 3 dataplane regression

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

Phase 3 result:

1. Achieved and merged on `master`; validated live on the isolated userspace HA
   lab.
2. The remaining validation issue for traceroute checks is now in the shell
   harness, not in the Rust dataplane.
3. The next cleanup phase is Phase 4.

## Phase 4: AF_XDP Queue, TX, And Recycle Cleanup

Status: Complete And Merged

Completed:

1. Prepared-TX recycle ownership is now explicit in code via
   `PreparedTxRecycle` instead of the older implicit `Option<u32>` slot model.
2. Completion handling now routes all prepared-TX recycle decisions through a
   single explicit helper path instead of open-coded slot restoration.
3. Pending prepared/local TX request merging, draining, and restoration are now
   centralized in `userspace-dp/src/afxdp/tx.rs`.
4. Immediate prepared-TX cancellation now uses the same recycle ownership model
   as completion reaping.
5. Focused Rust tests were added for:
   - pending TX merge order
   - shared/local queue merge behavior
   - explicit prepared recycle routing
6. The Phase 4 slice was deployed live to:
   - `loss:bpfrx-userspace-fw0`
   - `loss:bpfrx-userspace-fw1`
7. Live validation on the active userspace node (`bpfrx-userspace-fw0`) passed:
   - `24/24` bindings bound and ready
   - IPv4 and IPv6 internal reachability
   - native IPv4 and IPv6 time-exceeded responses
   - IPv4 and IPv6 `mtr` first-hop and destination visibility unchanged
   - short single-stream `iperf3` runs completed without collapse
8. The remaining issue discovered during this validation is not a dataplane
   queue bug:
   - `scripts/userspace-ha-validation.sh` still aborts early because
     `ping -t 1` / `ping -6 -t 1` return non-zero even when the expected
     time-exceeded response is present

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

Phase 4 result:

1. Achieved and merged on `master`; validated live on the isolated userspace HA
   lab.
2. Queue and completion ownership is now explicit enough to reason about from
   `userspace-dp/src/afxdp/tx.rs`.
3. The next cleanup phase is Phase 5 validation hardening, starting with the
   TTL / hop-limit shell-harness fix.

## Phase 5: Validation And Regression Hardening

Status: Complete And Merged

Completed so far:

1. Standard userspace validation now checks IPv4 traceroute and `mtr` behavior
   to `1.1.1.1`.
2. Standard userspace validation now checks IPv6 traceroute and `mtr` behavior
   to `2607:f8b0:4005:814::200e`.
3. Sustained-throughput collapse detection was already added before this plan
   and remains part of the normal workflow.
4. The shell harness now accepts TTL / hop-limit probe
   exit status `1` when the captured output contains the expected native
   time-exceeded response.
5. `iperf3 -J` output is now analyzed on the repo host
   instead of assuming `python3` exists on `cluster-userspace-host`.
6. Direct regression coverage was added for:
   - non-error ICMP packets not triggering embedded NAT reversal
   - slow-path fallback no-op behavior for forward-candidate traffic
   - slow-path extract-failure accounting
   - slow-path unavailable accounting
7. Tuple-authority regression coverage now also checks:
   - metadata tuple preference when the flow tuple is absent
   - live-frame fallback when metadata ports are missing
8. Embedded ICMP NAT reversal now has direct regression
   coverage for shared-NAT-session lookup across worker scopes.
9. The exact `enqueue_pending_forwards` build-failure
   path is now covered through the extracted `handle_forward_build_failure(...)`
   helper, including:
   - `forward_build_failed`
   - `forward_build_slow_path`
   - no-fallback build-failure behavior

Delivered in:

1. PR `#221`
2. PR `#230`
3. Commit:
   - `4a5006f` `test: add traceroute checks to userspace validation`
4. PR `#231` completes the remaining direct regression coverage for tuple
   authority, embedded ICMP shared-NAT lookup, and the
   `enqueue_pending_forwards` build-failure fallback path.

Still left:

1. Keep synchronized capture workflows available as diagnosis tools, not first
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

Phase 5 result:

1. Achieved and merged on `master`.
2. Traceroute, throughput-cliff detection, tuple-authority regressions,
   embedded ICMP shared-scope lookup, and AF_XDP forward-build failure fallback
   now all have direct automated coverage.
3. The remaining work under this plan is Phase 6 performance optimization.

## Phase 6: Performance Optimization On A Cleaner Base

Status: In Progress

Current measured state on the Phase 6 branch:

0. The first current Phase 6 task is already complete:
   - restore a valid HA lab runtime after the shared-UMEM prototype was merged
     into normal worker startup
   - current restore branch returns the lab to `24/24` ready bindings and a
     passing short HA validation baseline

1. The current kept Phase 6 slice is intentionally small:
   - `userspace-dp/src/afxdp/tx.rs`
     - only `PreparedTxRecycle::FillOnSlot(_)` is tracked in
       `in_flight_prepared_recycles`
     - the redundant final `bound_pending_tx_prepared(binding)` in
       `drain_pending_tx(...)` was removed
   - `userspace-dp/src/afxdp/frame.rs`
     - redundant `bound_pending_tx_prepared(target_binding)` calls were removed
       from pure local-copy enqueue paths in `enqueue_pending_forwards(...)`
2. Larger Phase 6 experiments were tested live and rejected because they did
   not hold throughput:
   - target-binding cache in `enqueue_pending_forwards(...)`
   - `apply_nat_ipv6` fast-path experiment
   - TCP/UDP no-op removal around `restore_l4_tuple_from_meta(...)`
   - idle-binding poll thinning
   - borrowed `BindingIdentity` fast-path refactor
   - larger RX-batch polling
3. Live validation on the current Phase 6 branch shows the userspace dataplane
   still passes the correctness gate:
   - IPv4 TTL probe: pass
   - IPv6 TTL probe: pass
   - IPv4 `mtr`: pass
   - IPv6 `mtr`: pass
4. Direct repeated `iperf3` runs on the current kept slice are steady within
   each run but variable across runs:
   - IPv4 about `18.10` to `22.13 Gbps`
   - IPv6 about `16.19` to `20.43 Gbps`
5. The latest paired `userspace-perf-compare.sh` run on the same slice was:
   - IPv4 about `17.81 Gbps`
   - IPv6 about `17.68 Gbps`
   - both families were internally steady rather than collapsing after
     startup
6. Helper counters on the active node during that paired perf run confirm that
   traffic is traversing userspace without starvation symptoms:
   - `24/24` bindings bound and ready
   - `TX errors: 0`
   - `Neighbor misses: 0` during the measured interval
   - about `25.5M` forwarded packets and `37.39 GB` transmitted in the sample
7. Current hot symbols after these slices still point to the same remaining
   work:
   - `bpfrx_userspace_dp::afxdp::poll_binding`
   - `bpfrx_userspace_dp::afxdp::frame::enqueue_pending_forwards`
   - `bpfrx_userspace_dp::afxdp::frame::build_forwarded_frame_into_from_frame`
   - `bpfrx_userspace_dp::afxdp::frame::apply_nat_ipv6`
8. The earlier session-resolution cleanup is holding:
   - IPv4 `resolve_flow_session_decision` is now around `2.38%`
   - IPv6 `resolve_flow_session_decision` is now around `3.46%`
9. The remaining Phase 6 problem is measurement-quality optimization work, not
   correctness:
   - there is no current evidence of AF_XDP starvation, queue collapse, or
     traceroute regression on the kept slice
   - there is clear run-to-run throughput variance, so only large measured wins
     should be kept

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
2. Performance improvements are measured by the standard userspace workflow and
   by repeated direct `iperf3` runs so run-to-run variance is visible.
3. Optimization changes land on top of a clearer, smaller fast-path surface.
4. The remaining hot symbols on the live branch are explained and intentionally
   targeted rather than guessed at.
5. The kept Phase 6 branch contains only measured wins; rejected experiments do
   not remain mixed into the branch.

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

1. Keep the resolved driver split intact:
   - `mlx5_core` on zerocopy UMEM-owner
   - `virtio_net` on auto-mode copy UMEM-owner
2. Keep the same-device shared-UMEM prototype out of the baseline runtime until
   it proves clean on a real same-device topology.
3. Keep the traceroute, `mtr`, and throughput-collapse checks as the mandatory
   correctness gate for any Phase 6 performance changes.
4. Continue Phase 6 on the measured remaining costs:
   - `poll_binding`
   - `enqueue_pending_forwards`
   - `build_forwarded_frame_into_from_frame`
   - `apply_nat_ipv6`
5. Keep release-build warning debt in non-hot subsystems visible while Phase 6
   work continues so new perf changes do not disappear into unrelated noise.
