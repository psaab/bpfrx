# Codex Refactor Audit 176

## Audit Identity

- **Repository:** `/home/ps/git/codex-bpfrx`
- **Immutable base:** `23eb4506864c0d7749157331ba279cbde7b7d5a7`
- **Role:** Codex orchestrator with disjoint module specialists, adversarial design reviewers, a global scope/dedup reviewer, an independent coverage reviewer, and a final coordinator source check.
- **Repository mutations:** only the required `git pull --rebase`; no source, documentation, generated artifact, branch, commit, issue, or PR was changed.
- **Final artifact:** `/tmp/codex-review-176.md`

## Executive Result

- Inspected **302 unique assigned source/test/tooling paths** across **27 non-overlapping batches** at one immutable commit.
- Started from **89 raw candidates**: 85 High-confidence and 4 Medium-confidence; classes A=4, B=71, C=14.
- Adversarial scope review retained **47 canonical non-duplicate refactor issues**: 38 from the primary pass and 9 from the independent coverage pass.
- The primary 65 raw candidates became 38 issues after 9 new, 28 narrowed, one two-finding merge, duplicate suppression, correctness-only routing, and weak-proposal rejection.
- The 24 supplemental candidates became 9 new issues, 5 acceptance merges into existing owners, 9 correctness-only routes, and 1 weak drop.
- Final confidence: **43 High**, **4 Medium**, **0 Low**. Low-confidence proposals were not silently promoted merely to meet a quota.
- Recorded **19 D-class boundaries that must not be split** because locality, code generation, verifier shape, synchronization ownership, or fail-closed ordering would regress.

## Dedup Corpus

- Read 79 prior final `/tmp/{codex,agy,fable,opus}-review-NNN.md` reports available at campaign start.
- Indexed 218 prior refactor/HPC entries, 247 repository issue-history headings, and 192 PR-history headings from repository Markdown history.
- Read current open refactor trackers, including `#4404`, `#4407`, `#4408`, `#4409`, `#4421`, and `#4662`, and suppressed broad monolith reports already owned there.
- Used exact owner/deliverable matching, not title similarity. Real bugs whose fix did not require a new ownership boundary were classified correctness-only rather than inflated into refactor findings.

## Inventory and Coverage

- Inventory: 2,352 tracked code files, comprising 883 production files and 1,469 test/fixture files.
- Large-function census: approximately 372 production functions at or above 120 LOC.
- Primary assignment covered 207 candidates. Independent coverage review found 95 omitted unique paths and dispatched eight supplemental batches, bringing coverage to 302 unique paths.
- The final independent coverage review verified every omitted large-function candidate and every identified large-test gap was assigned and logged; it returned PASS with no remaining manifest gap.
- Fresh `bash scripts/refactoring-audit.sh` found 46 heatmap entries while the committed ledger has 16. `make audit-check` failed on that stale generated gate. Existing ownership was deduplicated; only the missing owned-root/type registry and mandatory enforcement increment is retained as `R10-B1-007`.

## Validation Performed

Specialists ran focused Rust and Go suites while tracing their assigned modules, including poll-descriptor/stage/reject/forward/cache tests; event-stream and session-glue tests; Go config, cmdtree, API, gRPC, CLI, daemon, dataplane, cluster, routing, and service packages; race/vet passes where applicable; release AF_XDP runtime tests; ShellCheck/Python syntax and 11 script tests; and exact Rust leaf discovery in debug/release profiles (611/612 at the inspected base).

No full repository Rust test suite, allocator-sanitizer run, release disassembly campaign, private/shared-XSK conservation run, paired packet-rate benchmark, loss-cluster smoke matrix, or HA crash/failover campaign was run. Those are implementation merge gates, not claims made by this read-only audit.

# Audit 176 Coordinator Verification

Independent verification was performed against detached worktree
`/tmp/review-wt-codex-176-inventory-b0` at immutable base
`23eb4506864c0d7749157331ba279cbde7b7d5a7`. This is a source check of
representative high-risk retained findings after the architect, design-review,
performance-review, and scope/dedup passes. It adds no findings and changes no
repository files.

1. **Native AF_XDP ring ABI ownership confirmed.** `userspace-dp/src/xsk_ffi.rs:17-39`
   hand-mirrors libxdp producer/consumer ring layouts in `#[repr(C)]` Rust types;
   Rust allocates them through `Box` at `:342-343` and `:1163-1168`. The retained
   issue correctly limits the boundary to C-owned opaque allocation/free while
   preserving call count and socket-before-UMEM destruction order.
2. **Reservation-guard linearity confirmed.** `xsk_ffi.rs:889-913,918-1015`
   exposes `release(&mut self)` and `commit(&mut self)`, so the same guard remains
   callable after the ownership transition. Consuming finish methods are an
   independently testable type-state/API hardening boundary.
3. **UMEM rewrite decline-after-mutation confirmed.** `frame/mod.rs:520-572`
   prepares L2 bytes before later v4/v6 checks at `:764-785`; address and port
   writes at `:915-953,1136-1151` precede fallible checksum adjustment. The
   flow-cache fallback at `poll_descriptor/flow_cache_hit.rs:411-427` can then
   reuse the same frame. The narrowed fail-before-write/infallible-commit issue
   is source-backed.
4. **Partial shared-session publication confirmed.** `shared_ops.rs:882-943`
   publishes canonical sessions, NAT aliases, wire aliases, and indexes under
   separate locks while readers acquire those stores independently around
   `:482-505` and `:594+`. The retained issue correctly requires one observable
   transaction owner without prematurely mandating a global lock.
5. **HA stored/applied identity and constructor generation gaps confirmed.**
   `pkg/daemon/daemon_ha_sync.go:362-390` can treat equal stored text as applied
   after a later apply stage failed. `:398+` launches asynchronous construction
   whose goroutine publishes `d.sessionSync` around `:551-553` without a local
   generation/join owner. Both narrowed lifecycle findings are real.
6. **Userspace map/helper mixed-generation publication confirmed.**
   `pkg/dataplane/userspace/manager_compile.go:291-343` updates maps, caches,
   snapshots, and published pointers before `applyHelperStatusLocked` can fail;
   `maps_sync.go:253-288` only fail-closes map failures. One publication
   generation and fault-injected outcome policy are required.
7. **Host actuation during compilation confirmed.** `pkg/dataplane/compiler.go:216-284`
   continues through fallible phases after zone/interface compilation, while
   `compiler_iface.go:249+` performs zone, VLAN, address, and MTU host mutations.
   Pure planning plus explicit compensation/fail-closed semantics is a valid
   cold-path ownership boundary, coordinated with the prior publication issue.
8. **Cluster connection/cold-prime ownership confirmed.**
   `pkg/cluster/sync_conn.go:475-550,1207-1211` permits concurrent connection
   handlers to publish a connection and derive cold-prime behavior from shared
   disconnect state. A per-fabric publication token and acknowledgement-bound
   prime owner are required; broad transport movement is not.
9. **AF_XDP worker bring-up commit ordering confirmed.**
   `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:21+` mutates live
   state and maps before worker thread spawn; spawn failures around `:385-405`
   are logged while the routine proceeds and returns no failure outcome. The
   supplemental issue correctly moves all fallible thread preparation ahead of
   destructive reconcile commit.
10. **Proxy-ARP removed-interface residue confirmed.**
    `pkg/dataplane/proxyarp.go:185-367` builds the managed interface set only
    from desired config and lists `NTF_PROXY` entries only for that set.
    `pkg/daemon/daemon_proxyarp.go:107-136` remembers responder sysctl families,
    not the prior proxy-neighbor plan. Removing the last desired address from an
    interface therefore leaves no owner that sweeps its installed entry.
11. **Mapped-interface actuation success laundering confirmed.**
    `pkg/daemon/device_map.go:132-282` logs collision, final rename, stranded
    restore, and reload failures but can return nil; teardown at `:593-608` can
    delete durable ownership after rename-back failure. The config-arrival call
    sites at `daemon_run.go:2059-2067` and `daemon_apply.go:613` can consume the
    retry opportunity and continue dependent apply. The retained typed-outcome
    issue is narrower than prior device-map layout/collision work.
12. **Tracked XDP object provenance gap confirmed.** The normal `make test`
    path does not prove source/object digest equivalence, while the README says
    the userspace XDP object is tracked and normal builds do not regenerate it.
    The retained item is a provenance gate, not another generator refactor.

All checked source anchors matched the reports. No checked retained finding was
downgraded or removed. The final canonical set remains 47 issues.

## Canonical Findings

The issue scopes below are authoritative. Where a primary report proposed a broader package tree, the adversarial scope sentence in **Proposed decomposition** overrides it.

## High Confidence (43)

### 1. `R1B2-02` - Make in-place rewrite failure atomic before any UMEM byte is committed
- **Title:** Make in-place rewrite failure atomic before any UMEM byte is committed
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/frame/mod.rs:520`  
  `rewrite_prepare_eth_from_parts` writes MAC/VLAN bytes immediately and, without headroom, moves the L3 payload at lines 550-562.  
  Generic rewrite invokes that mutation at line 764 and only afterward runs fallible v4/v6 validation at lines 766-785.  
  NAT helpers write IPs/ports before fallible checksum-field reads (`frame/mod.rs:915-953`, `1136-1151`).  
  Descriptor rewrite likewise prepares L2 at `frame/rewrite/mod.rs:73-85` before fragment, family, TTL, and port-mismatch declines.  
  The flow-cache caller immediately chains descriptor `None` into generic rewrite on the same UMEM (`poll_descriptor/flow_cache_hit.rs:411-427`) and later builds a request from the same slice.  
  TX dispatch rebuilds from `source_frame` after in-place `None` and can reinject that same source on a second failure (`tx/dispatch/mod.rs:711-770`, `1285-1300`).  
  The property test at `frame/prop_tests/rewrite.rs:391-432` permits L2 scribbling because it assumes every caller drops, which the two fallback call graphs disprove.
- **Proposed decomposition:** **Authoritative adversarial scope:** `frame/mod.rs:520` can mutate bytes before a later decline. Retain only fail-before-write/preflight-and-infallible-commit semantics with byte-identical `None` tests. Do not approve broad rewrite-plan structs until stack size, constant folding, call shape, and release assembly are pinned. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Plans must be fixed-size stack values with concrete per-family functions; no `Vec`, trait object, virtual dispatch, lock, atomic, or frame copy. Carrying parsed offsets prevents validation/commit double parsing. Keep descriptor v4/v6 leaves `#[inline(always)]` and the orchestrators `#[inline]`, preserve descriptor-shift/no-headroom zero-copy behavior and sole-worker UMEM ownership, and do not alter `UserspaceDpMeta` or descriptor layout. Compare assembly and cycles because moving branches before stores can affect icache and scheduling even when semantics improve.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add property tests asserting the full original frame and surrounding UMEM sentinel bytes are unchanged for every `None` reason. Include TTL/hop-limit expiry, descriptor port mismatch, non-first fragment, unknown family/ether type, malformed IHL/IPv6 extension chains, truncated TCP/UDP checksum fields, and VLAN-push-without-headroom. Add caller tests proving `.or_else` and copy/reinject fallbacks receive original bytes. Run targeted release tests plus the existing descriptor-vs-generic differential; add `benches/frame_rewrite.rs` and require zero allocations, byte-identical success output, and no more than 2% regression in median cycles/packet or forwarding throughput.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A failed speculative rewrite can be retried, copied, or reinjected as though its source were pristine. Double VLAN shifts and partially adjusted NAT/checksum state can turn a recoverable fallback into corruption or a hard drop, violating the zero-copy ownership contract.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Pin full-byte rollback semantics first; enumerate every post-store `?`/`None`; implement immutable preflight plans; convert commits to infallible writes; update the stale “caller drops” test comment; then validate differential output, failure atomicity, assembly, and throughput.
- **Labels:** `bug`, `userspace-dataplane`, `zero-copy`, `packet-rewrite`, `checksum`, `test-gap`, `performance`
- **Dedup note:** Searched the shared index and history for `partial rewrite`, `rewrite None`, `rollback`, `UMEM mutation`, and `scribble`; no matching tracker exists. `#963`/PR `#975` and `#1352`/PR `#1583` decomposed the rewrite code while preserving mutation order, and codex-review-173 A2 F9 says the current per-family codegen split is sound. This finding is the untracked transactional failure contract, not another file split. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R1B2-02`.

### 2. `R1B2-04` - Unify frame-derived filter match inputs behind one metadata-neutral builder
- **Title:** Unify frame-derived filter match inputs behind one metadata-neutral builder
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/frame/inspect.rs:535`  
  `term_match_extra_from_frame` and `_fwd` at lines 535-665 duplicate fragment detection, ICMP truncation, L4-presence, and borrowed flex-slice construction.  
  The only material input difference is `UserspaceDpMeta` versus `ForwardPacketMeta`; both expose the exact fields consumed here.  
  A concrete `From<UserspaceDpMeta> for ForwardPacketMeta` already exists (`afxdp/types/mod.rs:161-180`).  
  The duplicated logic is security-sensitive: zero-valued ICMP type/code are valid matches, so truncation must clear `l4_present`.  
  The `#2449` fix had to update both builders manually, demonstrating real drift cost.  
  Current frame tests cover the `UserspaceDpMeta` builder but do not assert parity with the forwarding/CoS builder.
- **Proposed decomposition:** **Authoritative adversarial scope:** The duplicated frame-to-filter projection at `frame/inspect.rs:535` is real, but retain one private scalar helper in `inspect.rs`, not a one-function `filter_view/` directory or a forced `ForwardPacketMeta` materialization. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Conversion copies a small `Copy` value and should fold away after inlining. The result continues to borrow frame/UMEM slices; no allocation, packet copy, ownership transfer, trait-object dispatch, lock, atomic, hash, or ABI/layout change occurs. Preserve the current branch order and inspect release assembly to ensure the wrapper does not materialize or add a call. This narrows icache footprint by removing one duplicate body.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Compare every output field and borrowed slice range for both wrappers across v4/v6, TCP/UDP, ICMP/ICMPv6 lengths 0/1/2+, first/non-first fragments, and flexible L3/L4 ranges. Run `cargo test --release --manifest-path userspace-dp/Cargo.toml filter_view`; require identical release assembly branch/call shape at both callers or no more than 1% regression in a filter-match microbenchmark.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Input-filter and TX/output-filter policy must fail closed identically. A future one-sided fragment or truncation fix would create path-dependent security behavior even though both builders consume the same facts.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Add wrapper-parity characterization tests; move the forwarding-metadata body unchanged; replace the full-metadata body with conversion plus delegation; run release assembly/perf checks; then make this module the only owner of `TermMatchExtra` frame construction.
- **Labels:** `refactor`, `userspace-dataplane`, `firewall-filter`, `packet-parsing`, `test-gap`
- **Dedup note:** Searched the shared index for `term_match_extra`, `TermMatchExtra`, `truncated ICMP`, and filter-view duplication; no matching finding exists. `#2449` fixed both copies behaviorally but did not consolidate them. Deferred `#2150` covers canonical L2/IP/IPv6 walkers, not the filter-context builder or metadata-type convergence. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R1B2-04`.

### 3. `R2-B1-01` - Reuse non-exact CoS batch deques across service visits
- **Title:** Reuse non-exact CoS batch deques across service visits
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** `userspace-dp/src/afxdp/cos/queue_service/mod.rs:1775`, `:1807`, `:1832`, `:1853`, `:1875`, `:1901`
  `build_cos_batch_from_queue` creates `VecDeque::new()` independently for Local and Prepared batches.
  Every returned batch is non-empty, so its first `push_back` must allocate element storage.
  The deque is moved into `CoSBatch`, then into a variant submit handler; no capacity is returned to worker state.
  Success settlement and retry restoration consume the remaining deque, after which its allocation is dropped.
  `drain_shaped_tx` is called repeatedly until no work, so saturation repeats this allocation once per 1-64 packet batch.
  The exact path already uses `WorkerScratch` vectors preallocated to `TX_BATCH_SIZE`, proving the local ownership model.
  Prepared items carry UMEM recycle ownership, so the fix must drain, not copy or silently drop, every retry suffix.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain reusable, separately typed Local/Prepared deques in existing worker scratch for the paths at `queue_service/mod.rs:1775-1901`. Exclude the proposed `batch/` tree and require post-warmup zero reallocations plus unchanged retry/recycle order. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Allocation improves from one heap allocation/free per selected batch to zero after binding construction. Keep the current enum match and concrete functions, with no trait object, function pointer, or new generic dispatch. Preserve `#[inline]` on the orchestrator/variant boundary and the exact `TX_BATCH_SIZE` batching cap. Moving requests must not clone payload bytes or Prepared recycle metadata; accepted-prefix and reverse-order retry restoration stay byte/order-identical. No lock or atomic changes are needed. The extra deque headers alter private `BindingWorker`/`WorkerScratch` layout, so place them at the cold end of scratch (or compare a one-time boxed scratch owner) and gate cache/cycle impact. Branch shape and DSCP/UMEM handling remain in the existing typed handlers; moving them under `batch/` may reduce queue-service i-cache scope without changing calls.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a test-only counting allocator around 10,000 warmed Local and Prepared non-exact batches at sizes 1 and `TX_BATCH_SIZE`; the post-construction gate is exactly zero allocations/reallocations/frees in the measured section. Run full accepted-prefix, ring-full, malformed-frame, mirror-reserve, flow-fair snapshot, DSCP rewrite, and retry-order tests; queue contents, byte counters, token debits, and Prepared recycle destinations must match baseline. Run `cargo test --release afxdp::cos::queue_service` and the full Rust suite. On the isolated userspace cluster, require five paired 120-second shaped Local/Prepared runs with aggregate throughput no worse than 1% and no fairness/undergrant regression; allocator samples for `build_cos_batch_from_queue` must disappear.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A queue shaper at line rate executes this lifecycle continuously; small or token-limited batches make the cost approach one allocator round trip per packet. Allocator latency and cache pollution directly oppose the repository's no-allocation packet-path discipline and add jitter to fair scheduling.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First land R2-B1-04 so tests no longer depend on the dead exact batch path. Add reusable deques with explicit construction capacity, change restore/apply APIs to drain borrowed deques, then return storage after every submit outcome. Add the allocation gate before optimizing layout, and compare direct-inline versus boxed scratch ownership under the same perf matrix.
- **Labels:** `refactor`, `userspace-dp`, `performance`, `cos`, `hot-path`
- **Dedup note:** Searched the shared index and issue/PR history for `VecDeque::new`, `build_cos_batch_from_queue`, `non-exact allocation`, `per-batch allocation`, and `CoSBatch`. #1732/PR #1737 removes allocations from waterfill selection, #3968 fixes `pop_snapshot_stack` growth, and #1331 only preserves submit-handler allocation behavior. None owns the fresh Local/Prepared batch deque lifecycle, so this is separately actionable. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R2-B1-01`.

### 4. `R2-B1-04` - Delete the test-only unified guarantee scheduler and test production selectors
- **Title:** Delete the test-only unified guarantee scheduler and test production selectors
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/cos/queue_service/tests/selector.rs:18`, `:433`, `:683`, `:728`, `:772`, `:881`, `:994`
  Nine assigned tests call `select_cos_guarantee_batch`, which forwards to a 91-line selector compiled only for tests.
  Production `drain_shaped_tx` instead runs exact direct service first, then the specialized non-exact selector.
  Exact batch-cap tests at `728` and `772` therefore exercise `build_cos_batch_from_queue`, not the production direct scratch service.
  The dead selector has a third `legacy_guarantee_rr` field in test builds (`types/cos.rs:694-704`).
  One 29-line test exists solely to prove this test-only cursor does not mutate the two real cursors.
  Token-bucket tests outside this file also call the alternate selector, so it remains a maintenance dependency.
  Production selector and full-drain coverage already exists and can receive the remaining assertions.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain migration of assertions to production selectors and deletion of the alternate test-only scheduler/cursor at `queue_service/tests/selector.rs:18-994`. Exclude the unrelated test-directory split already covered generically by codex-review-171 finding 29. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** The deleted code and field are `cfg(test)`, so release allocation, dispatch, inlining, layout, batching, locks/atomics, branches, i-cache, and UMEM ownership are unchanged. Test binaries get smaller and stop compiling a semantically obsolete scheduling branch. The replacement tests must use concrete production functions and retain Local/Prepared ownership checks; do not introduce a new adapter that recreates the alternate skeleton under another name.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Port each of the nine call sites and both external token-bucket call sites before deletion. Add full-path assertions for exact Local and Prepared batch cap, zero-token parking, class-specific RR, and queue lease top-up. Require zero references to `legacy_guarantee_rr` and `select_cos_guarantee_batch_with_fast_path`, then run `cargo test --release afxdp::cos` and the full Rust suite. For each ported test, demonstrate fail-on-revert against the production predicate or accounting site it claims to guard.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A green test can currently validate behavior that the release binary cannot execute, especially for exact batch sizing and rotation. That false assurance raises the risk of scheduler or scratch-ownership refactors and forces production types/builders to carry test-only state.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Inventory and port non-exact/surplus tests first, then exact tests through a real binding fixture, then token-bucket tests. Delete the self-referential cursor test, function pair, field, and all test initializers. Split the assigned selector suite by production invariant only after every test runs through a live entry point.
- **Labels:** `refactor`, `userspace-dp`, `cos`, `tests`, `correctness`
- **Dedup note:** Searched `legacy_guarantee_rr`, `legacy guarantee selector`, `select_cos_guarantee_batch_with_fast_path`, and `selector.rs`. PR history for #689 documents why the compatibility cursor was introduced, but no cleanup tracker exists. #1207 concerns sharing the production service skeleton, and #1035/PR #1088 concerns module/test relocation; neither removes this dead alternate scheduler. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R2-B1-04`.

### 5. `R2-B1-05` - Make epoch-carry rotation ownership a Rust privacy boundary
- **Title:** Make epoch-carry rotation ownership a Rust privacy boundary
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs:1836`, `:1841`, `:1856`, `:1864`, `:1881`
  `v8_carry_field_is_reader_private` recursively reads every Rust source file and searches for the field name.
  Its allowlist permits all references in `epoch.rs`, `rotate_epoch_v8.rs`, and the test file because the field is `pub(super)`.
  The intended invariant is stronger: only the rotation winner may read or write carry inside the seqlock ODD section.
  A new accessor in allowlisted `epoch.rs` plus a differently named call from acquire/status would evade this textual test.
  Support source confirms `epoch_carry_bytes` is a `pub(super) AtomicU64` (`epoch.rs:187-202`).
  Rotation itself states its Acquire/Release operations are redundant and the field is single-writer (`rotate_epoch_v8.rs:194-197`).
  The sibling-module layout from #2158 forced visibility wider than the actual atomic owner.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain only the minimum sibling-module topology needed to make epoch carry private around `shared_cos_lease_tests.rs:1836-1881`; do not move equal-flow publication or atomics for directory symmetry. `#1329` and `#2158` own the broad split, not this compiler-enforced privacy increment. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Preserve `SharedCoSEpochState` field order/type, all atomic orderings, seqlock sequence, and packed layouts exactly; this issue should not opportunistically replace the carry atomic with a plain integer. Keep concrete inherent/free functions and explicit `#[inline]` on calls that cross the new module boundary because LTO is off and codegen units are split. Add no allocation, lock, branch, trait object, or new atomic operation. `acquire_v8_with_cause` and rotation batching remain unchanged; the goal is compile-time visibility, not control-flow extraction. Compare optimized assembly and binary size to catch outlining/i-cache drift.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Keep all bounded-carry regime, cold-resume, unclaimed-budget, concurrent budget-bound, tag-wrap, release, and seqlock tests. Replace direct field access with test-only methods defined inside `epoch`; no production method may expose carry. Run the carry tests repeatedly (at least 20 iterations for contention cases), `cargo test --release afxdp::types::shared_cos_lease`, and the full suite. Gate optimized `acquire_v8_with_cause`/rotation assembly on unchanged atomic order/branch structure and binary-size movement below 0.5%; a deliberate attempted production access outside `epoch` must fail to compile.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The carry is excluded from the seqlock snapshot specifically to prevent cross-epoch tearing and post-failback bursts. A source-string convention is a porous substitute for ownership: the compiler should make an accidental acquire/status read impossible.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Nest rotation/publication under `epoch` without changing bodies, add explicit inlining/visibility, introduce test-only seed/read methods, port carry tests, then remove the grep walk. Review the diff as pure topology/privacy and reject any simultaneous ordering, field-layout, or algorithm change.
- **Labels:** `refactor`, `userspace-dp`, `cos`, `concurrency`, `atomics`, `rust`
- **Dedup note:** Searched `epoch_carry_bytes`, `reader private`, `shared lease`, `#1329`, `#2158`, and `rotate_epoch_v8`. #1329/PR #1588 extracted rotation bodies; #2158/PR #2207 performed the sibling split and documented the resulting `pub(super)` widening. Neither tracker restores compiler-enforced carry ownership; this finding is a narrower follow-up prompted by the current grep test. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R2-B1-05`.

### 6. `R2-b2-01` - Hide libxdp ring layouts behind the C boundary
- **Title:** Hide libxdp ring layouts behind the C boundary
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/xsk_ffi.rs:17` manually redeclares every field of `struct xsk_ring_prod` and `struct xsk_ring_cons` in Rust.
  `userspace-dp/build.rs:3` compiles the bridge against the installed `/usr/include/xdp/xsk.h`, but does not compare C size, alignment, or offsets with the Rust declarations.
  `userspace-dp/src/xsk_ffi.rs:342` and `:1163` allocate zeroed Rust boxes and pass them to libxdp creation functions for C/library code to populate.
  `userspace-dp/csrc/xsk_bridge.c:20` accepts those pointers as native libxdp structs, so an upstream field/layout change can write outside or misinterpret the Rust allocation.
  The static libxdp and headers normally come from one package, but the Rust layout is an independent third copy with no build-time coupling to either one.
  The seven `xsk_ffi_tests.rs` cases exercise ring ownership and append behavior, not ABI size/alignment/offset compatibility.
- **Proposed decomposition:** **Authoritative adversarial scope:** `xsk_ffi.rs:17` mirrors native libxdp ring layouts in Rust. C-owned allocation/free with opaque Rust handles is a real ABI owner and can preserve the existing per-operation FFI count and socket-before-UMEM destruction order. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Ring allocation/free remains startup/teardown work. RX/TX descriptor operations already cross the C bridge, so opaque ownership adds no packet-path allocation, trait object, virtual dispatch, refcount, lock, or branch. Preserve the current one-FFI-call-per-ring-operation shape; cache the C-returned flags pointer at bind time if needed so `needs_wakeup` does not gain an extra call. The single-writer and batch-64 contracts remain unchanged.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add C-backed synthetic-ring constructors and destructor tests, then run `cargo test --release --manifest-path userspace-dp/Cargo.toml xsk_ffi -- --test-threads=1`. Build against the oldest and newest supported libxdp development packages under ASan/UBSan. Compile and run both `test/xsk-repro/libbpf_xsk_test.c` and `libbpf_xsk_shared_test.c`; require private/shared bind, teardown, ring wrap, and zero-copy checks to pass with no sanitizer finding. Gate also requires no Rust `repr(C)` definition containing libxdp ring fields.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A package/header upgrade can turn an otherwise source-compatible rebuild into memory corruption in the AF_XDP ownership core. The failure mode is more severe than a clean bind error and is difficult to diagnose from Rust.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First add C ownership/accessors and tests while retaining existing safe Rust APIs. Migrate UMEM rings, then socket RX/TX and shared fill/completion rings, preserving socket-before-UMEM drop order. Remove Rust field access and mirrored layouts last. Restack R2-b2-07 on the new `rings.rs` API if the two changes overlap.
- **Labels:** `refactor`, `afxdp`, `ffi`, `memory-safety`, `test-gap`
- **Dedup note:** Searched `xsk_ring_prod`, `xsk_ring_cons`, `libxdp ABI`, `ring layout`, `sizeof xsk`, `offsetof xsk`, `opaque ring`, and `xsk_bridge` across the dedup index and issue/PR history. Closed `#253` documents semantic migration failures, and PR #1299 covers private/shared creation, but neither tracks unchecked Rust/C ring layout. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R2-b2-01`.

### 7. `R2-b2-02` - Remove heap work from TX retry and partial-submit recovery
- **Title:** Remove heap work from TX retry and partial-submit recovery
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** `userspace-dp/src/afxdp/tx/transmit/mod.rs:17` stores both expected retry and exceptional drop reasons in owned `String`s.
  Lines 93, 194, and 243 allocate a new retry string for no-frame and ring-full outcomes that can recur every drain pass under backpressure.
  Lines 251-263 allocate `retry_tail` when a partial producer reservation accepts only a prefix of the staged local batch.
  `userspace-dp/src/afxdp/tx/transmit/finalise.rs:31` and `:39` repeat both shapes for prepared batches.
  Direct callers pass retry strings to `BindingLiveState::set_error` (`tx/drain/phase_backup.rs:102` and `:186`), taking the `last_error` mutex on expected congestion.
  The successful full-batch path is allocation-free; the issue is concentrated exactly where allocator and lock pressure are least tolerable.
- **Proposed decomposition:** **Authoritative adversarial scope:** `tx/transmit/mod.rs:17` allocates owned error strings and takes status locks on expected retry/partial-submit paths. A copyable outcome plus existing scratch has a measurable zero-allocation/zero-lock boundary and no prior owner. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Reverse-pop restoration is O(batch), preserves FIFO (`c,d` are popped `d,c` and each pushed front), and reuses the existing batch-64 scratch with no copy or allocation. A small enum removes allocator calls and expected-pressure locking; it adds no trait object, dispatch table, refcount, or atomic unless the optional compact status code is retained. Keep local and prepared loops monomorphic rather than forcing a trait abstraction that could inhibit inlining.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add local and prepared cases for `inserted == 0`, `0 < inserted < staged`, and full insertion, asserting packet order, free-frame order, in-flight recycle ownership, and exact sent bytes. In a dedicated serial allocation-count test binary, prebuild requests and warm scratch, then force 10,000 retry/partial-submit cycles and require zero alloc/realloc calls inside the measured region. Run the existing exact-drain release benchmark and require no greater than 3% median regression; pressure-smoke AF_XDP with a deliberately small TX ring and require frame conservation plus zero allocator growth attributable to submit retries.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Ring pressure is a normal operational state. Heap and mutex work in the retry loop amplifies stalls, adds tail latency, and can turn a bounded NIC backlog into allocator contention on the owner worker.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Introduce typed outcomes first and migrate all match sites without changing counters or retry control flow. Replace local and prepared retry-tail vectors independently with order tests. Remove expected retry `set_error` calls only after equivalent compact observability is pinned, then add allocation/perf gates.
- **Labels:** `performance`, `hot-path`, `afxdp`, `tx`, `allocation`, `test-gap`
- **Dedup note:** Searched `retry_tail`, `TxError`, `set_error`, `partial reservation`, `tx ring insert failed`, and `no free TX frame`. PR #4268/T-6(g) removed per-drop CoS admission strings, while `#1354`/PR #1586 extracted prepared phases; neither removes these remaining retry strings, retry-tail allocations, or expected-pressure last-error lock traffic. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R2-b2-02`.

### 8. `R2-b2-04` - Separate consuming redirect enqueue from ownership-preserving enqueue
- **Title:** Separate consuming redirect enqueue from ownership-preserving enqueue
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/umem/mod.rs:1153` exposes `enqueue_tx -> Result<(), String>` but unconditionally calls a consuming push and returns `Ok`.
  `enqueue_tx_owned` at line 1158 likewise consumes the request and always returns `Ok`, including overflow.
  `push_redirect_inbox` at lines 1217-1224 deliberately drops the incoming request on admission/ring overflow and records counters; it cannot return ownership.
  The separate `try_enqueue_tx_owned` at lines 1193-1195 already models ownership-preserving failure correctly.
  `tx/dispatch/cos.rs:79` and `tx/drain/mod.rs:507` document production `Err` arms as unreachable, yet callers retain fallback control flow as if ownership could return.
  `umem/tests/tx_inbox.rs:14` explicitly requires every push, including drop-newest overflow, to report `Ok`.
- **Proposed decomposition:** **Authoritative adversarial scope:** At `umem/mod.rs:1153`, consuming and ownership-preserving enqueue contracts are obscured. Retain explicit in-place API names and return an outcome only where consumed; exclude a directory for two wrappers and preserve `#715` drop-newest behavior. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** The change preserves the existing bounded MPSC queue, drop-newest policy, relaxed atomics, cacheline layout, and single consumer. A small returned enum is register-only and can be ignored without a branch; there is no allocation, lock, refcount, trait object, or dynamic dispatch. Removing impossible cascades should reduce branch and instruction-cache footprint.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Convert the existing overflow tests to assert explicit `Queued`/`DroppedOverflow` outcomes and counter lockstep. Add ownership tests proving `try_enqueue` returns the exact request while consuming enqueue never does. Update dispatch/drain tests to pin terminal drop behavior and ensure no request is duplicated into a fallback queue. Run the full release Rust suite and a redirect-inbox throughput benchmark; require unchanged admitted/dropped counts and no greater than 3% throughput regression.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The current `Result` looks ownership-preserving but actually means only "the caller no longer owns the request." That ambiguity has already forced test-only error injection and makes future backpressure refactors prone to duplicate, leaked, or incorrectly rerouted packets.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Add the explicit outcome APIs and migrate tests first. Move consuming callers without behavioral change, then migrate the few true fallback users to `try_enqueue`. Delete unreachable `Err` branches/fault injection only after the `#2208` descriptor-finalization tests have an equivalent direct failure seam.
- **Labels:** `refactor`, `afxdp`, `tx`, `ownership`, `api`, `test-gap`
- **Dedup note:** Searched `enqueue_tx_owned`, `swallows overflow`, `drop-newest returns Ok`, `redirect inbox`, `try_enqueue_tx_owned`, and `cascade-equivalence`. PR #715 intentionally established lock-free drop-newest behavior and its counters; this finding does not revisit that policy, only separates its consuming ownership contract from the existing ownership-preserving API. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R2-b2-04`.

### 9. `R4-b1-03` - Reuse worker scratch for pending-neighbor key sweeps
- **Title:** Reuse worker scratch for pending-neighbor key sweeps
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** - `userspace-dp/src/afxdp/neighbor_dispatch.rs:175` exits only when `pending_neigh` is empty.
  - `userspace-dp/src/afxdp/neighbor_dispatch.rs:197` explains that every nonempty sweep snapshots keys to release the map borrow.
  - `userspace-dp/src/afxdp/neighbor_dispatch.rs:204` creates a fresh `Vec<(i32, IpAddr)>` with `collect()` on every such sweep.
  - Support read `userspace-dp/src/afxdp/worker/lifecycle.rs:143` invokes the sweep on the RX-empty path, and line 315 invokes it again after RX batching.
  - The map can hold up to `MAX_PENDING_NEIGH = 4096` distinct hops at `userspace-dp/src/afxdp/mod.rs:414`.
  - `userspace-dp/src/afxdp/worker/scratch.rs:34` already centralizes reusable worker-local vectors, initialized in `worker/mod.rs:529`; pending keys are the missing scratch member.
- **Proposed decomposition:** **Authoritative adversarial scope:** `neighbor_dispatch.rs:175` allocates a pending-neighbor key vector on repeated sweeps. Existing worker scratch is the concrete owner; pointer/capacity reuse, frame ordering, and post-warmup zero allocation make this independently gateable. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This removes repeated allocator traffic while preserving the required key snapshot and iteration order semantics. Keep the direct concrete function so inlining and monomorphization are unchanged; add no trait object or indirect call. The extra internal `Vec` header belongs beside existing scratch, not hot atomics, limiting cacheline/false-sharing effects. No packet bytes, endianness, XSK/UMEM frame ownership, recycle ordering, or RX/TX batch size changes. Branch shape is unchanged after the empty fast exit, and instruction-cache impact is limited to `take/clear/restore` around the existing loop. `BindingScratch` has no public ABI or `repr(C)` contract.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Extract a small key-snapshot helper over the map and scratch vector. After one growth call, run repeated equal/smaller sweeps and assert capacity and allocation pointer remain stable while key sets are exact. Add cases for empty, one, and 4,096 keys plus resolved/removal iteration. Gate with an allocation-count or criterion microbenchmark showing zero allocations after warm-up, then run neighbor dispatch and AF_XDP packet tests.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** One unresolved hop keeps this path active for its dwell window. Allocating and freeing a vector on every poll taxes the worker that also owns RX/TX rings; a wide unresolved-hop scan amplifies the allocator and copy cost during the exact degraded condition where forwarding latency matters.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Extend the established worker-owned scratch model; do not change the one-packet-per-hop state machine or move the sweep behind dynamic dispatch.
- **Labels:** `rust`, `afxdp`, `performance`, `hot-path`, `neighbor`, `allocation`, `refactor`, `benchmark`
- **Dedup note:** #1771/PR #1774 replaced the old queue rotation with the current per-key map and intentionally introduced the key snapshot. Neither the shared index nor that change tracks reuse of the snapshot allocation, so this is a narrow follow-up rather than a duplicate state-machine redesign. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R4-b1-03`.

### 10. `R4-b1-04` - Index tunnel replay purge membership before filtering sessions
- **Title:** Index tunnel replay purge membership before filtering sessions
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** - `userspace-dp/src/afxdp/coordinator/mod.rs:133` filters the full preserved synced-session vector during reconcile.
  - `userspace-dp/src/afxdp/coordinator/mod.rs:140` stores drop keys in a `Vec<SessionKey>`.
  - `userspace-dp/src/afxdp/coordinator/mod.rs:143` runs linear `purge_ids.contains` for every entry.
  - `userspace-dp/src/afxdp/coordinator/mod.rs:154` then runs linear `drop_keys.contains` from `retain` for every entry, making the dominant phase O(entries x drop_keys).
  - Support read `userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs:331` invokes this on tunnel remap/removal before replay.
  - The default worker session ceiling is 131,072 at `userspace-dp/src/session/mod.rs:60`, so the input is not inherently tiny.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain pre-sized set membership inside `filter_replayed_synced_sessions` at `coordinator/mod.rs:133`, preserving survivor order and asymmetric companion semantics. Exclude a one-function `session_replay.rs`; require linear operation counts and a material large-vector speedup. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This runs only on coordinator reconcile and adds bounded temporary hash-set allocation there, replacing repeated linear comparisons. It adds no worker atomics, locks, trait objects, packet-path branches, or cacheline sharing. AF_XDP batching, UMEM ownership, packet endian handling, monomorphized forwarding code, and public ABI/layout are untouched. The change should reduce reconcile instruction and data-cache work without moving anything into the packet loop.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add table/property tests covering direct forward purge, derived NAT reverse companion, reverse-only purge, duplicate IDs/keys, and stable survivor order. Add an instrumented operation-count test proving one seed visit and one retain visit per entry, independent of the number of dropped keys. Record a 4K/32K/131K benchmark for regression visibility and run tunnel reconcile/replay tests.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A tunnel remap can coincide with a large synced-session set, precisely when teardown/replay latency affects HA recovery. If most entries are dropped, the current second pass performs a linear scan of a drop vector for each session and can turn a bounded reconcile into quadratic work.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Replace `Vec::contains` membership with pre-sized `FastSet`s behind a small replay-owned module, retaining exact companion semantics.
- **Labels:** `rust`, `afxdp`, `performance`, `ha`, `tunnel`, `sessions`, `refactor`, `benchmark`
- **Dedup note:** No shared-index entry covers `filter_replayed_synced_sessions` or tunnel replay complexity. #1873 established the companion semantics but is not a performance/refactor tracker; the proposed change preserves those semantics. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R4-b1-04`.

### 11. `R4B2-01` - Make shared-session publication one observable transaction
- **Title:** Make shared-session publication one observable transaction
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/shared_ops.rs:882`  
  `publish_shared_session` commits the canonical entry/index, reverse-wire and reverse-canonical aliases/indexes, then the forward-wire alias/index under separate locks.  
  `remove_shared_session` at line 945 performs the inverse sequence while exposing intermediate states to alias-only readers.  
  Cross-scope reads at lines 482-505 and 594-665 lock canonical, NAT, and forward-wire maps independently rather than reading one snapshot.  
  `SessionManager` explicitly says these tables are written and queried as a unit, but its support definition gives each table and each index its own mutex.  
  The same `Arc<Mutex<...>>` handles are cloned into every packet worker, so publication and lookup can overlap across threads.  
  Tests at `session_glue/tests.rs:921-1220` verify only before/after alias and index state; none pins a reader interleaving or concurrent same-key replacement.  
  A translated reply can therefore miss during publish, see a stale alias during remove, or observe map generations from different overlapping updates.
- **Proposed decomposition:** **Authoritative adversarial scope:** `shared_ops.rs:882` publishes canonical entries, aliases, and owner indexes through separately observable mutations. Retain one transaction owner, but do not preselect one global `RwLock` until contention, poison behavior, collision handling, and an epoch/seqlock alternative are compared. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Established flows still hit the worker-local `SessionTable` before the shared store, so the steady packet path, UMEM ownership, batch shape, and branch order do not change. Shared misses take one concrete `RwLock` read instead of one or more independent mutexes; no trait object, virtual dispatch, extra hash, or extra heap allocation is required beyond the existing cloned key/entry result. Private Rust layout and wire endianness are unchanged. One lock/cacheline replaces seven independently contended lock objects, while mutex/RwLock acquire-release ordering replaces the current partial publication; existing relaxed telemetry atomics stay relaxed. Do not hold the write guard across forwarding computation, BPF syscalls, queue sends, or bulk iteration.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** First land R4B2-05, then add store invariant tests for publish/replace/remove, NAT alias displacement, owner change, demotion, poison recovery, and deterministic reader barriers proving every observation is entirely pre- or post-transaction. Run `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::session_glue::tests:: -- --test-threads=1` (all 84 current leaf tests plus new tests), `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha_tests::`, and `TOTAL_CYCLES=12 CYCLE_INTERVAL=5 ./scripts/userspace-ha-failover-validation.sh --duration 600 --parallel 8`. Gate on zero invariant failures/session loss, all long-lived streams surviving every move, and a shared-hit microbenchmark within 5% of baseline with no allocation increase; established local-hit codegen must remain unchanged.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** These maps encode the canonical and translated identities of the same HA session. Partial visibility is a correctness risk precisely during sync, promotion, demotion, and translated reply lookup, where a transient miss or stale hit can drop or misroute a live flow. The ownership correction is independently issue-worthy even though the earlier extraction moved these functions out of `session_glue`.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: 1. Split the test suite by invariant (R4B2-05). 2. Add a pure `SharedSessionState` and invariant checker while retaining adapters for existing callers. 3. Move publish/remove/demote and generation checks under one write transaction, preserving collision telemetry and poison policy. 4. Migrate lookup and owner-snapshot callers to one store handle. 5. Remove raw maps/indexes from `SessionManager` and worker parameters. 6. Run unit, race/interleaving, benchmark, and live failover gates before deleting adapters.
- **Labels:** `refactor`, `userspace-dp`, `ha`, `session-sync`, `concurrency`, `correctness`
- **Dedup note:** Searched the dedup index for `shared_session`, `shared map`, `owner-RG index`, `forward_wire`, `atomic publish`, `transaction`, and `partial session`. The nearest history is #369/PR #385 (move shared operations out of `session_glue`) and PR #1030 (`SessionManager` extraction). Neither makes the documented unit atomic or adds interleaving invariants, so this is a narrower, materially new ownership fix. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R4B2-01`.

### 12. `R4B2-02` - Replace event-stream prefix drains with a cursor-backed write backlog
- **Title:** Replace event-stream prefix drains with a cursor-backed write backlog
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** `userspace-dp/src/event_stream/mod.rs:1126`  
  The connected loop stores pending socket bytes in one `Vec<u8>` that may grow to 16 MiB plus one 256-byte frame.  
  Every successful short write at lines 1146-1152 calls `write_buf.drain(..n)`, which shifts the entire remaining suffix to offset zero.  
  A slow reader that repeatedly accepts small writes therefore causes repeated multi-megabyte copies and quadratic total copy work in the backlog size.  
  The channel drain at lines 1576-1617 appends more frames to that same vector and uses `len()` as the backpressure bound.  
  The documented slow-consumer invariant is bounded, counted degradation without stealing forwarding-plane resources (`session-sync-design.md:598-616`).  
  The 7 existing backpressure tests cover cap, ordering, loss, and `WouldBlock`, but no test forces a sequence of short successful writes or measures bytes moved.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain a bounded cursor-backed backlog for partial writes at `event_stream/mod.rs:1126`, with geometric compaction and exact ordering. The transport move is optional and overlaps `#366`/PR `#382`; behavior and movement must not be one issue. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is the single event I/O thread, not the AF_XDP packet loop. It retains one reusable `Vec` allocation, adds no per-frame allocation, trait object, dynamic dispatch, hashing, endian conversion, packet/UMEM ownership change, or atomic/cacheline traffic. `UnixStream::write` receives `&bytes[start..]`; a successful write advances one integer. Occasional geometric compaction makes copy work amortized linear. The full-write common branch still clears/reset indices, while sequence allocation, channel FIFO order, replay batching, keepalive ordering, and acquire/release flags remain byte-for-byte semantic boundaries.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Extend `event_stream/tests/backpressure.rs` with a deterministic short-writer seam that accepts 1-4096 bytes per call and asserts exact output bytes/order, `pending_len <= WRITE_BACKLOG_MAX_BYTES + 256`, correct keepalive placement, and disconnect/retry preservation. Add `benches/event_stream_backlog.rs` and run `cargo test --manifest-path userspace-dp/Cargo.toml event_stream::tests::backpressure:: -- --test-threads=1` plus `cargo bench --manifest-path userspace-dp/Cargo.toml --bench event_stream_backlog`. Gate test instrumentation at total compacted bytes no greater than twice appended bytes, at least 10x less wall time than the current 16-MiB/1-KiB-drain baseline, and no more than 5% regression for full-buffer writes.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The current cap prevents OOM but can turn ordinary partial-write progress into large CPU and memory-bandwidth spikes. That delays ACK/control processing, fills the producer channel, drops telemetry, and can force HA session resync under exactly the slow-consumer condition the transport is designed to tolerate.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: 1. Check in the reproducing benchmark against the current `Vec::drain` implementation. 2. Add `WriteBacklog` without moving control/replay logic. 3. Switch cap accounting to pending bytes and route frames/keepalives through `append_frame`. 4. Add geometric compaction and short-write tests. 5. Move only connected-loop ownership into `transport/`; update the design doc and retain all public sender/worker APIs in `event_stream::mod`.
- **Labels:** `refactor`, `userspace-dp`, `event-stream`, `performance`, `ha`, `backpressure`
- **Dedup note:** Searched for `event stream`, `write_buf`, `write backlog`, `partial write`, `replay buffer`, `socket transport`, and `codec`. #366/PR #382 split codec from transport, and `codex-review-174` concerned codec frame families; neither identifies prefix-drain copy amplification. Source issue #2381 added the memory cap, while this finding preserves that cap and fixes a distinct algorithmic cost inside it. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R4B2-02`.

### 13. `R5B1-GATE-01` - Route section-level semantic rejects through the strict/tolerant gate policy
- **Title:** Route section-level semantic rejects through the strict/tolerant gate policy
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/config/compiler.go:1561`, `pkg/config/compiler.go:2031`, `pkg/config/compiler_dispatch.go:31`, `pkg/config/compiler_firewall.go:259`, `pkg/config/compiler_class_of_service.go:148`, and `pkg/config/compiler_nat.go:1634` establish the boundary. `CompileConfigLenient` promises persisted/peer config boot-through, but P4 returns any section compiler error before P6/P7 can downgrade it. Firewall TCP-flags validation returns directly at lines 267-270; its own comment says older behavior committed such input. CoS code-point collectors return directly at lines 148-150, 184-186, 236-238, and 276-278; lines 1154-1158 say older code accepted and dropped/masked the value. Deterministic NAT returns semantic errors at lines 1640-1687, immediately before lines 1690-1695 warn that this placement would brick lenient legacy load. `compileSections` receives `compileOpts` but calls firewall and CoS without a mode policy; `pkg/configstore/store.go:378` says that a strict reject here blackouts Load or alarm-loops SyncApply. The AST wiring canary only inventories top-level `validate*Strict(cfg *Config) error` functions, so these inline rejects evade its completeness check.
- **Proposed decomposition:** **Authoritative adversarial scope:** P4 section errors bypass tolerant gates (`compiler.go:1561`, firewall `:259`, CoS `:148`). Retain explicit domain-by-domain fatal/quarantine outcomes in the owning compilers. Drop the generic `compilegate` package and the unsupported deterministic-NAT legacy premise: `compiler_nat.go:1634-1687` hard-checks deterministic NAT, while the compatibility comment at `:1690-1695` concerns only pool-utilization alarm. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is a cold control-plane compile path. Use a concrete reporter and a `Decision` enum rather than closures or interface callbacks, so there is no interface dispatch and no new escape/heap allocation on successful compilation. Allocate diagnostic text only on a failed check. Preserve tree-child/source order and the existing first-error position while migrating each gate; sort the existing deterministic-NAT pool map before selecting an error/warning. No goroutine, mutex, atomic, packet structure, Rust ABI, snapshot layout, or dataplane branch changes are required. Any tolerant fallback must retain current fail-closed publication: TCP flags keep an explicit invalid sentinel and the dataplane retains the last good generation or a documented cold-boot deny artifact; it must never erase the constraint into match-all.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** First add table tests for invalid TCP flags, numeric DSCP/PCP, conflicting CoS queue ownership, RSS expectation, and deterministic NAT across `strict/generic`, `lenient/generic`, `strict/node0`, `strict/node1`, `lenient/node0`, and `lenient/node1`. Strict cells must retain the exact current error; tolerant cells must return a non-nil config, one ordered warning, and the domain's asserted safe fallback. Add Store.Load and Store.SyncApply tests proving no `ErrConfigCompile`/sync loop for a pre-gate semantic value, while candidate commit still rejects. Add snapshot tests proving invalid TCP flags cannot widen a term and CoS/NAT fallback cannot publish unsafe state. Gate with `go test ./pkg/config ./pkg/configstore ./pkg/dataplane/userspace` plus the targeted Rust filter/NAT snapshot tests; the valid-corpus `TestCompileGolden4406` output must stay byte-identical.

Merged MG-02 differential-matrix acceptance coverage:
Require 12 results per fixture (two AST shapes times six compiler cells). Valid cases must deep-equal config, exact warning order, and nil errors per paired cell. Invalid cases must match strict error class/text, tolerant warning code/order, and an explicit fail-closed fallback fingerprint. Node fixtures must differ only where `${node}` is expected and remain shape-equal within each node. Gate with `go test ./pkg/config -run 'TestDualAST(RoundTrip|CompileMatrix)' -count=20`; no warning sorting is allowed once `R5B1-DIAG-02` lands.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** An upgraded node can carry exactly these values because the source comments document that older binaries accepted them. The current tolerant entry point then hard-fails, leaving `ActiveConfig()==nil` on local load or rejecting HA peer sync. Configstore fails closed, which protects forwarding ownership, but the operational result is a bootstrap/availability outage or repeated HA sync failure rather than the promised warn-and-recover path.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: (1) Land the mode/shape matrix from `R5B1-MATRIX-03`; (2) classify each existing section error as syntax-fatal or semantic strict/tolerant and document its fail-closed fallback; (3) introduce the concrete reporter without changing behavior; (4) migrate TCP flags and prove last-good/default-deny behavior; (5) migrate CoS; (6) migrate deterministic NAT with sorted pool traversal; (7) extend the wiring canary to inventory registered `GateID`s and require both strict and tolerant expectations; (8) regenerate the golden only for intentional new tolerant outcomes.
- **Labels:** `bug`, `config`, `validation`, `availability`, `ha`, `refactor`, `test-gap`
- **Dedup note:** Searched the dedup index for `CompileConfigLenient`, `compileFirewall`, `compileClassOfService`, `compileNATSource`, `strict-vs-lenient`, `hard-fail`, `brick`, and `section compiler`. This is not fable-review-161 `F-044` (duplicated option literals), `F-206`/agy-review-171 `AGY-171-10` (NAT file size), codex-review-154 `L07` (firewall package split), codex-review-133 `L13` (Go/Rust boundary matrix), or closed `#4405/#4406`: it identifies currently executed semantic checks that bypass the tolerant policy entirely and supplies a cross-domain migration boundary. `R5B1-MATRIX-03` is acceptance coverage for this issue, not a separate tracker. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R5B1-GATE-01`.

### 14. `R5B1-DIAG-02` - Publish one immutable deterministic warning snapshot to every operator surface
- **Title:** Publish one immutable deterministic warning snapshot to every operator surface
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/config/compiler_validate_warn.go:82` presents `ValidateConfig` as non-fatal validation, but lines 1190-1202 append a warning and mutate `sched.SurplusSharing=false`. `pkg/config/parser_class_of_service_test.go:848` explicitly records that a second call is a no-op after the strip. `pkg/config/compiler_tailgates.go:25` stores the first result in `cfg.Warnings`, including P1/P6/P7 diagnostics not reproducible by `ValidateConfig`. CLI and gRPC alarm paths call `ValidateConfig` again (`cli_show_system.go:948`, `cli_show_security_log.go:166`, `server_show_system.go:111`, `server_show_security_text.go:346`) instead of presenting `cfg.Warnings`; REST/gRPC commit responses do use `cfg.Warnings`. Consequently a tolerated strict-gate warning can be logged/applied but absent from `show ... alarms`, and the surplus-sharing warning disappears on recomputation. Warning order is also not stable: `validateSurfaceADDNSWarnings` ranges a provider map at line 2948, while the dual-AST harness admits map-dependent order and sorts warnings at lines 1006-1009.
- **Proposed decomposition:** **Authoritative adversarial scope:** `compiler_validate_warn.go:1190-1202` mutates CoS while collecting warnings, whereas `compiler_tailgates.go:25` publishes a canonical slice and show paths recompute it. Retain pure deterministic collection plus immutable copied publication; a new diagnostic package is not a prerequisite. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Warning collection runs only during compile or operator show. Finalize once, sort only domain keys that currently come from maps, and retain the compiled string slice; repeated show calls copy the slice but do not rescan the whole config or mutate active state. No packet-path code, snapshot ABI, goroutine, atomic, or lock is added. Returning a copy respects `Store.ActiveConfig`'s post-lock pointer exposure and avoids a new shared-mutation race. The only extra allocations are bounded diagnostic records/strings at compile time; successful dataplane reconciliation is unchanged.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add an idempotence test that deep-copies a compiled config, calls the pure collector twice, and requires identical ordered output plus no config diff. Compile a multi-provider/multi-CoS warning fixture repeatedly and require byte-identical warning order without sorting in the assertion. Seed one advisory and one synthetic tolerant downgrade, then require REST commit, CLI system/security alarms, and gRPC system/security alarms to expose the same canonical set and order. Run `go test -race ./pkg/config ./pkg/configstore ./pkg/api ./pkg/cli ./pkg/grpcapi`; the race gate must report no write through an active config returned after the store lock is released.

Merged MG-02 differential-matrix acceptance coverage:
Require 12 results per fixture (two AST shapes times six compiler cells). Valid cases must deep-equal config, exact warning order, and nil errors per paired cell. Invalid cases must match strict error class/text, tolerant warning code/order, and an explicit fail-closed fallback fingerprint. Node fixtures must differ only where `${node}` is expected and remain shape-equal within each node. Gate with `go test ./pkg/config -run 'TestDualAST(RoundTrip|CompileMatrix)' -count=20`; no warning sorting is allowed once `R5B1-DIAG-02` lands.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Warning-only and downgraded gates are the operator's recovery signal on tolerated boot/peer sync. Hiding those warnings from alarm views, changing output after the first call, or reordering it across runs makes API/CLI/gRPC disagree precisely when the dataplane is using a safe fallback or retaining stale state.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: (1) Characterize every current warning producer and its order; (2) split CoS configured intent from effective state and make `ValidateConfig` pure; (3) stabilize all map-derived warning order; (4) populate one immutable snapshot at P7; (5) switch all presentation callers to a copy of that snapshot; (6) add parity/race tests; (7) only then let the known warning-validator decomposition consume the diagnostic module.
- **Labels:** `bug`, `config`, `observability`, `cli`, `grpc`, `api`, `ha`, `refactor`
- **Dedup note:** Searched for `ValidateConfig mutate`, `warning mutate`, `surplus-sharing`, `cfg.Warnings`, `show alarms`, `warning order`, `map iteration`, `CLI`, and `gRPC`; no matching prior entry or tracker was indexed. codex-review-171 item 20 and fable-review-173 A6 `F2` report only the warning-validator monolith. This finding is narrower and behaviorally independent: one mutable query and multiple non-canonical presentation surfaces lose tolerated diagnostics. `R5B1-MATRIX-03` is acceptance coverage for this issue, not a separate tracker. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R5B1-DIAG-02`.

### 15. `R5B2-IPMON-01` - Extract atomic IP-monitoring analysis from the mutating strict validator
- **Title:** Extract atomic IP-monitoring analysis from the mutating strict validator
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/config/compiler_services.go:895` (exact function span 895-970)  
  `validateIPMonitoringStrict` both checks invariants and rewrites `PreferredRoute` in place at lines 954-959; a later routing-instance check at 961-965 can still fail after that write.  
  The function ranges `IPMonitoringConfig.Policies` as a map at line 924 and returns the first error, so which invalid policy wins is not deterministic across equivalent maps.  
  `pkg/config/types_system.go:774-795` represents next-hop identity as two independently writable strings, allowing neither/both variants until this validator repairs one path.  
  `pkg/config/schema_system.go:578-633` owns the grammar and scalar bounds, but cross-references and next-hop classification are deferred to this mixed validator/resolver.  
  Support contract `compiler_derivations.go:5-17` says P5 exclusively owns cross-section derived mutation, while `compiler_earlystrict.go:13-17,104-140` documents only two security folds yet invokes this hidden third mutator as an "independent" validator.  
  Support call graph `compiler.go:1561-1573,2071-2073` promises tolerant load/peer-sync boot but has no IP-monitoring leniency option; every IP-monitoring validation error is returned by `CompileConfigLenient` as a hard failure.  
  Support tests `parser_ipmonitoring_test.go:125-199,416-436` cover strict rejection and successful idempotent mutation only; they do not pin input immutability on failure, deterministic diagnostics, or tolerant-path behavior.
- **Proposed decomposition:** **Authoritative adversarial scope:** `compiler_services.go:895-970` mutates `PreferredRoute` before a later error and ranges a map nondeterministically, but the outer compiler discards the fresh candidate on error. Retain deterministic staged analysis in the owning compiler; drop the runtime partial-publication claim, unproved tolerant policy, and four-file domain package. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Config compilation runs on commit, boot load, and HA sync, not per packet. The analyzer may allocate one sorted policy-name slice and one resolved model per compile; it must not add allocations to `pkg/ipmon.Engine.Apply`, probe transitions, FRR rendering, or dataplane route lookup. Use a concrete catalog value, not an interface or callback, so there is no dynamic dispatch or escape-prone closure. Keep runtime model values directly consumable by `pkg/ipmon`; do not translate on each actuation. No goroutine, mutex, atomic, cache-line layout, or packet batch changes are involved, and the existing `Engine.mu -> dhcp.Manager.mu` lock order remains untouched. Outer compile already discards `cfg` on error, so this is not a claim of current partial runtime publication; the gain is making that transactionality local and enforceable before future phase reuse. Root aliases keep CLI/API/gRPC source compatibility during migration.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** First characterize byte-identical successful output for literal and DHCP-interface next hops in hierarchical/flat-set syntax across strict/lenient and generic/node-aware entry points. Add a pure-analyzer test proving an error on route N leaves the complete input byte-for-byte unchanged and publishes no partial resolution. Add insertion-order permutations proving identical diagnostic order. Add strict-versus-tolerant tests for missing probes, bad prefixes/family, bad interfaces, and missing routing instances; strict errors stay text/order compatible, while tolerant compile returns a config plus warning and the invalid route is absent from the runtime overlay. Pin schema/compiler acceptance parity for hold-down, metric, and next-hop forms. Run `go list -deps ./pkg/config ./pkg/ipmon`, `go test ./pkg/config ./pkg/configstore ./pkg/ipmon ./pkg/cmdtree ./pkg/cli ./pkg/api ./pkg/grpcapi`, and `go test -race ./pkg/config ./pkg/configstore ./pkg/ipmon`; require zero import cycle, unchanged success goldens, deterministic output over `-count=100`, zero mutation on diagnostics, and no route injection from quarantined entries.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The current shape makes a function called validation silently own model normalization, contradicting the compiler's phase contract and making safe movement/reuse difficult. More concretely, a legacy, hand-recovered, or mixed-version peer config with an IP-monitoring cross-reference violation can hard-fail the supposedly tolerant load/sync ingress, causing boot blackout or HA sync alarm-loop instead of preserving the base route set with a warning. A domain package also puts the model next to the runtime semantics it serves rather than scattering one feature across broad services/schema/type files.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: (1) Obtain explicit architecture signoff on the tolerant quarantine rule and exact warning ordering. (2) Add failure-immutability, insertion-order, strict/lenient, and successful-output characterization tests against the current facade. (3) Add the import-independent domain package and root aliases without changing consumers. (4) Replace in-place validation with pure analysis and staged publication at the existing fifth-family accumulator slot so cross-family error precedence stays unchanged. (5) Enable the approved tolerant projection and document it in config/IP-monitoring docs. (6) Migrate `pkg/ipmon` and display/API consumers to the domain model, then remove aliases only after downstream compile gates are green.
- **Labels:** `refactor`, `go`, `config`, `ip-monitoring`, `architecture`, `correctness`, `high-availability`, `test-gap`
- **Dedup note:** Searched prior reports/issues/PRs for `validateIPMonitoringStrict`, `NextHopInterface`, validator mutation, strict/lenient IP monitoring, and IP-monitoring module/package. Codex-review-171 finding 23 and ps-review-039 finding 3 propose only a flat same-package `compiler_services_ip_monitoring.go`; fable-review-173 A6 F4/F6/F7 cover unrelated dispatcher/test splits. PR #1851/#1844 intentionally added derivation inside the validator, while closed #3757-#3763/#4423 concern runtime actuation. Closed #4406 / PR #4470 extracted P6a and documented exactly two mutations, but did not identify this third mutation or add tolerant semantics. This finding is the narrower, separately actionable correction: an import-independent domain analyzer, atomic publication, deterministic diagnostics, and an explicit strict/tolerant boundary. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R5B2-IPMON-01`.

### 16. `R6-b1-01` - Track successful peer application separately from active-store equality
- **Title:** Track successful peer application separately from active-store equality
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/daemon/daemon_ha_sync.go:362`
  `handleConfigSync` returns nil at lines 367-375 when incoming text matches `Store.ShowActive`, and nil authorizes the config-generation high-water to advance.  
  `pkg/daemon/daemon_apply.go:331` calls `Store.SyncApply` at line 344, which promotes active state, before `applyConfigLocked` at line 349 can return an error.  
  On that error, `syncAndApply` returns at lines 349-350 before policy-deletion/session invalidation and the passive device-map alarm at lines 352-366.  
  `pkg/daemon/daemon_apply.go:235` already classifies local apply errors: required-protocol/context errors are fatal, while joined tail errors leave the dataplane armed and must still run finalization and peer convergence. The peer path does not share that policy.  
  `pkg/daemon/daemon_apply.go:1816` joins recoverable networkd, Kea, nft, lo0, and IPsec failures only after all reconcile steps; a later identical peer push should retry those failures, not bypass reconcile.  
  `pkg/cluster/sync_conn.go:1091` advances `lastAppliedConfigGen` only when the callback returns nil and explicitly relies on same-generation retry after failure.  
  Concrete trace: delivery N promotes C1, reconcile fails, and high-water stays N-1; retry N then sees active text C1 and returns nil without reconcile, so high-water becomes N while dataplane/finalization never successfully converged. A required-protocol failure can leave the helper disarmed; a tail failure can permanently skip deletion clears and the passive admission alarm.  
  `pkg/cluster/sync_config_gen_test.go:302` models a callback that fails before changing state, so it cannot expose the daemon callback's promote-before-error behavior; `pkg/daemon/config_sync_test.go:76` currently enshrines active-text equality as sufficient.
- **Proposed decomposition:** **Authoritative adversarial scope:** `daemon_ha_sync.go:362` can equate stored text with successfully applied state after a failed tail stage. Retain explicit attempted/successful identity and outcome policy in the daemon owner; package extraction is incidental and nonfatal tail errors need a defined retry contract. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Config sync and commit reconciliation are cold control-plane operations, not packet processing. Computing one fixed `[32]byte` digest per received config adds no per-packet work and no persistent copy of config text. Keep `applySem` as the sole serialization boundary, so no new mutex, atomic, dynamic dispatch, goroutine, or reordered reconcile branch enters the apply path. Existing dataplane publication, batching, layout, and inlining are untouched.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a daemon characterization test using a real temp store plus `applyBodyForTest`/`applyErrForTest`: first delivery promotes and fails, the identical second delivery must increment the apply count again, and only a successful delivery may make a third duplicate skip without adding history. Add fatal-protocol and joined-tail cases; the latter must still invoke deletion/default-policy finalization and the passive device-map alarm while returning its error. Extend the cluster high-water test through the daemon callback so `lastAppliedConfigGen` remains old after the first failure and advances only after the second apply succeeds. Gates: `go test ./pkg/daemon ./pkg/cluster`, `go test -race ./pkg/daemon ./pkg/cluster`, `make test-failover`, and `make test-ha-crash`. Pass means no nil/error callback advances high-water and the repeated same digest reaches reconcile until one complete success.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The standby can acknowledge a generation whose promoted config was never successfully reconciled. On failover that can expose stale forwarding/session state or a fail-closed, disarmed dataplane while control-plane status claims the generation is applied.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: 1. Add RED tests for promote-then-error and retry. 2. Move duplicate detection inside the `applySem` transaction and base it on successful-applied identity. 3. Extract and share post-promotion finalization policy with the local commit path. 4. Record applied identity only after a nil outcome. 5. Run package/race gates, then HA failover and crash gates before merging; do not combine this with further #4407 phase motion.
- **Labels:** `correctness`, `ha`, `config-sync`, `reconcile`, `refactor`
- **Dedup note:** Searched `#4151`, `config high-water`, `active matches`, `SyncApply failure`, `#4034`, and `config divergence` in the dedup index, prior reports, and issues. #4151 fixed advance-before-callback and tests failure before state change. This finding is the residual opposite ordering: the daemon callback has already promoted C1 before returning an error, and its active-text shortcut converts the mandated retry into false success. #4034 covers sender-side propagation after nonfatal local apply, not receiver-side applied identity/finalization. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R6-b1-01`.

### 17. `R6-b1-02` - Own HA communications as a cancellable, joined generation
- **Title:** Own HA communications as a cancellable, joined generation
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/daemon/daemon_ha_sync.go:398`
  `startClusterComms` publishes `clusterCommsCancel`, context, and transport immediately, then starts session-sync construction in an untracked goroutine at lines 490-491.  
  After address resolution, that goroutine writes the shared `d.sessionSync` at lines 550-553 without a final `commsCtx` or generation check, then repeatedly dereferences the shared field beginning at line 560 instead of closing over its local instance.  
  `stopClusterComms` at lines 975-992 cancels but does not join the constructor; it reads/stops/nils whichever `d.sessionSync` happens to be visible.  
  A valid interleaving is old generation publish -> stop sets `d.sessionSync=nil` -> old generation executes `d.sessionSync.SetAuthProvider`, causing a nil dereference. Another is stop/start while old resolution is blocked -> old resolution returns an address after cancellation -> old generation overwrites the new session/endpoints.  
  `pkg/daemon/daemon_apply.go:1738` serializes stop/start under apply reconciliation, but the old constructor is outside `applySem`, so that serialization does not protect publication.  
  The same constructor replaces `fabricRefreshCh`/`fabricRefreshCh1` at `pkg/daemon/daemon_ha_sync.go:821`; fabric loops select on those mutable fields at `pkg/daemon/daemon_ha_fabric.go:227` and `:624`, while triggers read them at `:952`.  
  There is no generation-local wait group or detach operation. Cancellation is therefore a request, not proof that stale writers and listeners can no longer publish or consume the new generation's handles.  
  Existing fabric tests inject stable channels directly; no test overlaps delayed construction with runtime transport restart.
- **Proposed decomposition:** **Authoritative adversarial scope:** `daemon_ha_sync.go:398` can let a stale asynchronous HA constructor publish after stop/restart. Retain a local generation object with publish-if-current, detach/cancel/join, callback fencing, and a proved lock order. Exclude a broad hooks/god-interface package. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is HA control/session synchronization, not packet forwarding. Publication and detach can take one mutex on start/stop only; established sync, heartbeat, and fabric loops use generation-local pointers/channels with no recurring mutex or atomic lookup. No packet object, BPF map layout, batch, ABI, or dataplane branch changes. Callback function dispatch already exists and remains one call; joining affects only restart/shutdown. Moving handles out of `Daemon` reduces cross-cache-line mutation rather than adding it.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add injectable resolver/session factories and barriers. Test (a) cancel old generation while its resolver is blocked, start a new generation, release old, and assert old can neither publish nor change endpoints; (b) stop after old publication but before hook wiring and assert no nil panic; (c) assert `Stop` waits for every tracked constructor/listener; (d) repeat transport restart at least 100 times under race detection and assert exactly one live session generation and one refresh-channel pair. Gates: `go test -race ./pkg/daemon -run 'TestHACommsGeneration|TestClusterCommsRestart' -count=50`, `go test -race ./pkg/daemon ./pkg/cluster`, `make test-failover`, and `make test-ha-crash`. Pass means stale-generation publication count is zero and all generation goroutine counters return to zero after stop.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A runtime transport change can panic xpfd, revive stale peer endpoints, split callback ownership between generations, or leak listeners. In HA those outcomes can suppress sync/fencing or apply operations to the wrong peer during failover.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: 1. Add deterministic stale-publication and nil-dereference tests around the current code. 2. Introduce generation-local values and stop dereferencing `d.sessionSync` inside the constructor. 3. Add publish-if-current and atomic detach. 4. Track and join every comms child. 5. Move refresh channels/endpoints into the generation. 6. Only after these invariants are green, split the remaining callback wiring; do not perform the generic Fable-173 F5 extraction first.
- **Labels:** `correctness`, `ha`, `lifecycle`, `concurrency`, `race`, `refactor`
- **Dedup note:** Searched `startClusterComms`, `sessionSync`, `pointer-swap`, `comms restart`, `generation`, `#87`, `#94`, `#4033`, and `#4038`. Fable-173 A8 F5 is only the generic 466-line wiring split. Fable-161 explicitly noted the unsynchronized pointer but dropped it as "pointer-swap-once-per-comms-start"; #87 makes it multi-generation, and the cancel-without-join interleavings above provide the materially new stale overwrite and panic. #4033 fixed the heartbeat retry generation; it does not guard session-sync/fabric publication. #4038 fixed dual-channel fanout, not channel lifetime. #94 covers pre-signal shutdown context, not runtime restart publication. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R6-b1-02`.

### 18. `R6-b1-04` - Replace per-apply aggregation callbacks with one owned subscription
- **Title:** Replace per-apply aggregation callbacks with one owned subscription
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** `pkg/daemon/daemon_system.go:215`
  `applyAggregator` cancels the previous aggregator's `Run` context and clears daemon fields at lines 217-222, but it has no handle for the callback previously registered on the `EventReader`.  
  Every enabled reconcile creates a new `SessionAggregator` and calls `er.AddCallback(agg.HandleEvent)` at lines 228-240. `applySyslogConfig` reaches this path on every config apply when an event reader exists.  
  `pkg/logging/ringbuf.go:305` implements `AddCallback` as append-only; the only removal API clears all consumers, so daemon reconciliation cannot remove just the old aggregator.  
  Event dispatch at `pkg/logging/ringbuf.go:656` invokes every retained callback for every event, making cost O(number of enabled reconciles).  
  Canceling `SessionAggregator.Run` only stops periodic flushing at `pkg/logging/aggregator.go:239`; `HandleEvent` continues to call `Add` at lines 254-256.  
  Each stale aggregator can retain two Space-Saving sets capped at 10,000 keys each (`pkg/logging/aggregator.go:13`), but no run loop remains to flush/reset them; total retained memory is unbounded in reconcile count.  
  Disabling report mode also leaves all historical callbacks active, so later session-close events continue allocating/locking stale aggregation state despite the feature appearing disabled.  
  `EventReader.CallbackCount` already exists to guard the analogous flow-export/trace lifecycle, but there is no aggregation callback-count test.
- **Proposed decomposition:** **Authoritative adversarial scope:** `daemon_system.go:215` registers append-only event callbacks on every apply, retaining old large aggregators. A bind-once subscription with one swappable, joined active runtime is a real callback-lifecycle owner and matches no prior tracker. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** EventReader dispatch is a per-session-event path, so the shape matters. Keep one already-existing function callback and add one allocation-free atomic pointer load; retain the same `SessionAggregator.Add` lock and Space-Saving algorithm. This removes O(reconcile-count) function dispatches, stale mutex/heap work, and retained 20,000-key generations. It adds no packet-path branch, dynamic allocation, map copy, goroutine per event, or ABI/layout change. Replacement/joins occur only during config reconcile.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Reconcile report enabled 100 times, then disable: `CallbackCount` must increase by exactly one total, active goroutine count must return to zero on disable, and one SESSION_CLOSE must mutate only the active generation. Run replacement/event overlap under `go test -race`. Add `BenchmarkSessionReportEvent` for one versus 100 reconciles; active allocations/op must equal the one-generation baseline, disabled dispatch must allocate zero, and 100-reconcile ns/op must remain within 10% of one-reconcile ns/op. Gates: `go test ./pkg/daemon ./pkg/logging`, `go test -race ./pkg/daemon ./pkg/logging`, and `go test ./pkg/daemon -run '^$' -bench BenchmarkSessionReportEvent -benchmem`.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A long-lived daemon accumulates callback work and stale 20,000-key aggregation generations across ordinary commits. That grows event-processing latency and memory even after reporting is disabled and can amplify load during high-cardinality session churn.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: 1. Add callback-cardinality and disabled-state RED tests. 2. Introduce the bind-once runtime with an atomic active target and done channel. 3. Replace `aggregator`/`aggCancel` with the runtime owner. 4. Swap target before cancel/join so new events cannot enter the retired generation. 5. Add race and stable-cost benchmark gates. 6. Land independently of the broad Fable-173 A8 F10 file motion.
- **Labels:** `performance`, `resource-leak`, `logging`, `lifecycle`, `refactor`
- **Dedup note:** Searched `aggregator callback`, `SessionAggregator`, `EventReader callback leak`, `CallbackCount`, Fable-173 A8 F10/F-6, and #3932. No aggregator issue matched. #3932 fixed the same callback-lifetime class for `TraceWriter` by using one stable callback and a swappable target; this is a distinct still-live consumer in `applyAggregator`, with its own canceled-flusher memory behavior. The broad EventReader god-struct and daemon-system file-split findings do not identify this lifecycle defect.

**Medium confidence:** None retained.

**Low confidence:** None retained. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R6-b1-04`.

### 19. `R6B2-01` - Make shim-map and helper-snapshot publication one fail-closed transaction
- **Title:** Make shim-map and helper-snapshot publication one fail-closed transaction
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/dataplane/userspace/maps_sync.go:253`, `pkg/dataplane/userspace/maps_sync.go:272`, `pkg/dataplane/userspace/maps_sync.go:883`, `pkg/dataplane/userspace/maps_sync.go:1062`, `pkg/dataplane/userspace/maps_sync.go:1515`, `pkg/dataplane/userspace/manager_compile.go:228`, `pkg/dataplane/userspace/manager_compile.go:291`, `pkg/dataplane/userspace/manager_compile.go:323`.
  `snapshotBindingPlanKey` covers worker/ring/interface binding identity, not local or interface-NAT addresses, so address-only commits take `samePlanRefresh`.
  That path mutates ingress/local/interface-NAT BPF maps before sending `apply_snapshot` to Rust.
  The map reconcilers update/delete keys in place; ingress and nft-RST caches also advance, with no previous-plan journal or restore operation.
  `syncUserspaceClassifierMapsFailClosedLocked` disables ctrl only when a map operation itself fails; a successful map mutation followed by helper rejection leaves ctrl enabled.
  The helper request can then fail, while `lastSnapshot`, `publishedSnapshot`, and the content hash advance only on the later success path.
  Enabled XDP reads these maps before deciding kernel pass versus XSK redirect (`userspace-xdp/src/lib.rs:405`, `:621`, `:637`), so candidate classification can run beside the previous-good Rust snapshot.
- **Proposed decomposition:** **Authoritative adversarial scope:** `maps_sync.go:253-1515` and `manager_compile.go:228-323` can leave maps/caches, Rust snapshot, helper status, and published pointers on mixed generations. Retain one fail-closed publication coordinator covering all of them; require failure injection before selecting rollback versus disablement. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Reconcile only, not a packet-processing implementation change. Keep BPF map key/value layout, native-endian conversion, XDP branches, and helper JSON unchanged. Hold the existing `Manager.mu` scope, use concrete callbacks rather than interface dispatch on packet/event paths, and add at most one ctrl-map quiesce write when the classifier plan changes. Plan/hash allocations occur only per config apply; no packet allocation, atomic, cache-line, batching, or instruction-cache behavior changes.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a fake ordered publisher test for map success followed by helper reject/EOF; assert restore precedes return and publication caches stay old. Add real in-memory BPF-map tests for local-v4 and interface-NAT replacement with a rejecting control server; the measurable gate is: every error return has either `(old classifier hash == old applied snapshot hash)` or `ctrl.Enabled == 0`, never enabled mixed generations. Run `go test ./pkg/dataplane/userspace -count=1` and `go test -race ./pkg/dataplane/userspace -run 'Publication|Classifier' -count=1`; add a netns/helper rejection integration case before merge.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A rejected security/NAT snapshot is supposed to retain the previous-good dataplane. Today the shim can classify packets with candidate local/NAT ownership while Rust enforces the old policy and route state, producing wrong kernel delivery, wrong XSK steering, or an availability/security boundary mismatch.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First add a classifier-plan snapshot/hash and failure-injection tests. Next centralize ctrl quiesce and map restore without moving existing map builders. Then route same-plan and startup publication through the transaction. Finally let the already-tracked F-A7-2 map-status split depend on this coordinator instead of duplicating ordering.
- **Labels:** `bug`, `refactor`, `userspace-dp`, `transaction`, `fail-closed`, `bpf`
- **Dedup note:** Searched `classifier map publication`, `same-plan classifier`, `shim snapshot transaction`, `partial publication`, `rollback classifier`, and `userspace_local_v4 apply_snapshot` across the index and prior reports; no exact result. `codex-review-161` H1-H3 concerns Rust's internal same-plan snapshot mutation, while this finding is the earlier Go/XDP-map versus Rust-helper boundary. F-A7-2 only proposes splitting `applyHelperStatusLocked` and does not provide rollback for a later helper rejection. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R6B2-01`.

### 20. `R6B2-02` - Split pure compilation from host and shim actuation before publishing
- **Title:** Split pure compilation from host and shim actuation before publishing
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/dataplane/compiler.go:173`, `pkg/dataplane/compiler.go:216`, `pkg/dataplane/compiler.go:286`, `pkg/dataplane/compiler_iface.go:105`, `pkg/dataplane/compiler_iface.go:187`, `pkg/dataplane/compiler_iface.go:1021`, `pkg/dataplane/loader.go:169`, `pkg/dataplane/loader.go:345`.
  `CompileConfig` interleaves result construction with 14 ordered groups of `DataPlane` mutations and returns immediately on any later group error; it has no undo log.
  The first phase is not abstract emission only: it creates/raises VLAN links, changes sysctls, deletes/adds addresses, deletes stale bonds, strips addresses, and downs unmanaged links.
  A later address-book/application/policy/NAT/filter error therefore leaves earlier host and map effects live while the old Rust snapshot remains published.
  Recompile also calls `BumpFIBGeneration` after map emission and discards its error, before userspace snapshot construction/publication can fail.
  The sole runtime loader invokes this legacy compiler through a 130-method `DataPlane` contract and 55 no-op overrides, retaining only metadata plus direct host effects.
  `CompileUserspaceShim` attaches XDP and records `lastCompile` only after compile success, but it cannot reverse direct netlink operations performed inside `compileZones`.
- **Proposed decomposition:** **Authoritative adversarial scope:** `dataplane/compiler.go:173-286` performs host mutation before later compile failures. Retain pure planning plus explicit per-operation compensation/fail-closed semantics, but reuse R6B2-01's publication generation and do not create a second transaction framework or another wide actuator interface. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This runs on config apply, not per packet. Preserve successful syscall/map-write ordering and count initially, stable ID/counter hashing, byte order, and concrete Go calls. The immutable plan adds bounded commit-time allocations only; it removes a 130-method dynamic interface from compilation and does not touch Rust packet structs, UMEM ownership, locks/atomics, batching, branch shape, or inlining. Do not widen `Manager.mu`; pure planning should occur before the publication lock, while host/shim apply remains serialized by the daemon apply semaphore.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Build a recorder characterization corpus that compares current and planned zone/app/NAT/filter IDs and emitted operations byte-for-byte. Inject a late NAT/filter/snapshot error and assert the host actuator was never called. Add a network-namespace test starting with a VLAN/address/bond baseline, force a late compile failure, and assert link state/address inventory is unchanged; add helper-rejection coverage that restores the prior host plan or leaves ctrl disabled. Gate with `go test ./pkg/dataplane ./pkg/dataplane/userspace ./pkg/configstore -count=1`, `go test -race ./pkg/dataplane/userspace -count=1`, and the interface/failover integration suite.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A syntactically valid but runtime-unrepresentable config can fail after destructive interface changes, cutting traffic while the control plane reports an apply failure and Rust retains old forwarding state. The no-op adapter also forces every userspace feature through retired backend vocabulary, making compiler/snapshot parity harder to audit.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First capture operation-order and ID golden tests. Extract pure value builders from NAT/filter/policy phases, then split interface discovery from mutation and prevalidate all config-derived snapshot content. Introduce the transactional host applier; realize kernel-assigned ifindices, materialize/publish the final snapshot from the `RealizedPlan`, and restore the prior plan or keep ctrl disabled on failure. Finally migrate `CompileUserspaceShim` and remove the legacy no-op sink; do not combine semantic changes with F-A7-1/F-A7-5 mechanical function splits.
- **Labels:** `bug`, `refactor`, `dataplane-compiler`, `userspace-dp`, `transaction`, `netlink`
- **Dedup note:** Searched `pure compile plan`, `userspaceShimCompileDataplane`, `CompileUserspaceShim`, `55 no-op`, `compileZones actuation`, and `compiler rollback`. F-A7-1 and F-A7-5 request intra-function phase extraction; the F-A7 loader note calls the adapter cohesive and suggests a flat-file move. This finding is materially different: make planning side-effect-free and establish rollback/publication ownership across the only runtime backend. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R6B2-02`.

### 21. `R6B2-04` - Establish a populated Go-Rust wire contract before decomposing protocol DTOs
- **Title:** Establish a populated Go-Rust wire contract before decomposing protocol DTOs
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/dataplane/userspace/protocol.go:10`, `pkg/dataplane/userspace/protocol.go:1848`, `pkg/dataplane/userspace/protocol.go:3013`, `pkg/dataplane/userspace/protocol_test.go:17`, `pkg/dataplane/userspace/protocol_test.go:1173`, `userspace-dp/src/protocol/tests.rs:1528`, `userspace-dp/src/protocol/tests.rs:1613`, `userspace-dp/src/protocol/tests.rs:1700`.
  Go has 78 wire structs, two custom JSON methods, and duplicated control/event constants in one file; Rust already owns domain modules.
  Rust serializes 70 top-level `Default` specimens and compares them with `protocol_wire_v1.json`; its own comment limits that gate to default-visible keys.
  No executable Go source opens that fixture; repository Go references are comments or unrelated constant assertions.
  The 41 Go tests are valuable field-level round trips and hand-copied Rust JSON, but they do not enumerate every Go/Rust type or consume bytes generated by the other language.
  Defaults do not populate `Option`/`omitempty`, boundary-width, non-empty array/map, enum, legacy-alias, or event-constant cases.
  `ProcessStatus`'s legacy alias methods and the separate Go/Rust protocol/event constants make a mechanical file move insufficient as the only compatibility gate.
- **Proposed decomposition:** **Authoritative adversarial scope:** `userspace/protocol.go:10-3013` and Rust fixtures lack a populated bidirectional executable inventory. Retain only the fixture/inventory gate first; eventual DTO movement remains under Fable-review-173 **A7-F6**, and mixed internal/wire types must not be aliased blindly. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Control/status JSON is reconcile/telemetry, not packet processing. Go package movement with concrete structs/type aliases preserves layout and `encoding/json` allocation/reflection behavior; do not add interface wrappers. Binary event decoding remains static and little-endian in the codec. No Rust production code, `repr`, alignment, stack buffer, endianness locality, UMEM ownership, batching, branch shape, atomics, or inlining changes; fixture/reflection work is test-only.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Populate every optional branch and numeric boundary (`u8/u16/u32/u64`, signed protocol version, empty/non-empty collections, aliases) in the shared fixture. Both Go and Rust must decode it and canonical re-encode to an agreed JSON value; a constants manifest must pin protocol versions, frame IDs, flags, and fixed sizes. Gate: all 70 Rust specimen entries have an explicit Go classification, all 78 Go structs are classified, and undocumented key/type drift fails both suites. Run `go test ./pkg/dataplane/userspace/... -run Wire -count=1` and `CARGO_NET_OFFLINE=true cargo test --manifest-path userspace-dp/Cargo.toml --bin xpf-userspace-dp wire_invariant_default_specimens`.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Go's permissive JSON decoder silently zeros unknown/missing helper fields, while Rust can reject wrong widths or required shapes. A protocol refactor without a populated shared contract can therefore compile and pass same-language tests while dropping telemetry or rejecting an entire snapshot at deployment.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Land the populated fixture and inventory test against current types first. Move one domain at a time into `wire/` with aliases, keeping `ProcessStatus` methods with the status type and event constants with the codec. Remove aliases only after all callers migrate; restack the existing F-A7-6 split behind this guardrail.
- **Labels:** `refactor`, `userspace-dp`, `protocol`, `wire-compat`, `go`, `rust`, `testing`
- **Dedup note:** Searched `protocol_wire_v1`, `wire fixture`, `Go control-plane consumption`, `protocol.go split`, `schema parity`, and `cross-language fixture`. F-A7-6 classifies the move as pure A and says parity lives in `protocol_test.go`; the current Rust fixture exists but has no Go consumer. This finding changes the split to guardrail-first and specifies the missing shared populated contract rather than repeating the six-file seam. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R6B2-04`.

### 22. `R7B2-HC-001` - Make one typed command specification own local and remote CLI grammar
- **Title:** Make one typed command specification own local and remote CLI grammar
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/cmdtree/tree.go:133` calls the operational tree canonical, but it currently owns completion metadata rather than executable grammar.  
  `pkg/cli/cli_show.go:14` resolves local `show` prefixes against that tree before dispatch, while `cmd/cli/shared.go:209` and `cmd/cli/show.go:31` use exact handwritten switches.  
  `cmd/cli/main.go:98` asks the server completion RPC for candidates, so the remote client can advertise a tree leaf that its own dispatcher does not implement.  
  `pkg/cmdtree/tree.go:570` advertises top-level `show bgp`; local dispatch implements the alias at `pkg/cli/cli_show.go:180`, but the complete remote top-level case list at `cmd/cli/show.go:38` through `cmd/cli/show.go:345` has no `bgp` case.  
  `pkg/cmdtree/tree.go:221` advertises `show firewall effective`, and local dispatch renders the compiled snapshot at `pkg/cli/cli_show.go:133`.  
  Remote dispatch at `cmd/cli/show.go:272` recognizes only `filter`; `show firewall effective` silently falls through to raw `showText("firewall")`, certifying a different view than the advertised command.  
  The `cmd/cli/show.go:3` header explicitly describes PR #4660 as same-package pure code motion, confirming that the prior flat split did not establish command ownership or parity.
- **Proposed decomposition:** **Authoritative adversarial scope:** `cmdtree/tree.go:133` is the canonical completion tree, while local/remote dispatch omit different commands. Retain a machine-checked command-support matrix, the two concrete parity fixes, and only grammar-required typed parsers. Reject fragmented registries, reflection, and a wide handler context. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is serialized operator command parsing, outside reconcile and packet paths. Parse once into small value structs and pass them by value/pointer to an executor; do not introduce reflection, a runtime plugin registry, or interface dispatch inside row-render loops. Immutable specs require no locks after initialization. Existing manager snapshot/iterator ownership, command cancellation, RPC batching, and output ordering remain in the executors. Replacing repeated `strings.Fields`/`Join`/prefix scans can reduce transient allocations, but the acceptance gate is no new allocation proportional to rendered rows and no change to dataplane layout, atomics, branch shape, or cache lines.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add table-driven parser tests for exact tokens, unique abbreviations, ambiguity, aliases, modifier order, and invalid trailing tokens. Add an executor-matrix test that enumerates every leaf and fails unless both surfaces map it to the same typed command or one has an explicit unsupported marker. Pin `show bgp summary` and `show firewall effective` on both surfaces, including a remote assertion that effective never maps to raw firewall output. Run `go test -count=1 ./pkg/clicommand ./pkg/cmdtree ./pkg/cli ./cmd/cli`; gate on zero unowned leaves and zero silent fallback for recognized modifiers.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Operators receive completion/help as a contract. Today the remote CLI can accept an advertised command and either reject it or return a semantically different view, which is dangerous during routing and firewall diagnosis. Typed command ownership also gives future presenter/protocol work a stable boundary instead of another switch/file split.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First inventory every existing operational leaf and mark intentional local-only/remote-only commands. Add characterization tests around both current dispatchers. Introduce typed parsing behind the current entrypoints, migrate one domain at a time without changing presenters, then derive `cmdtree` completion from the registered specs. Remove old switches only after the matrix is complete; land the BGP/effective parity fixes with the owning domain migrations.
- **Labels:** `refactor`, `cli`, `feature-parity`, `grpc`, `test-gap`
- **Dedup note:** Searched `A9-go-api-cli F10`, `cmd/cli/show.go nested dispatch`, codex-review-174 finding 18, the codex-review-175 remote-mutation module-log note that the handwritten grammar differs from the tree, PR #4660, #1687, #1700, `cmdtree canonical`, `show bgp`, and `firewall effective`. F10/#4660 proposed and landed per-feature same-package files, and the codex-review-175 observation was not retained as an issue or given a decomposition. This finding is materially different: one executable grammar/support matrix, with two concrete current local/remote parity failures. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R7B2-HC-001`.

### 23. `R7B2-HC-002` - Extract one bounded, case-preserving CLI output pipeline
- **Title:** Extract one bounded, case-preserving CLI output pipeline
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** `cmd/cli/shared.go:111` duplicates the local pipe grammar instead of importing a shared owner.  
  Remote `dispatchWithPipe` redirects process-global `os.Stdout`, calls `io.ReadAll` at `cmd/cli/shared.go:143`, converts the result to a string, and splits all lines at `cmd/cli/shared.go:155`.  
  Its match/except/find branches lowercase both operands at `cmd/cli/shared.go:161`, changing the case-sensitive command contract.  
  The local implementation at `pkg/cli/cli_dispatch.go:54` now consumes concurrently through `filterStream`, retaining at most one line, a count, or the `last N` ring, and compares case-sensitively at `pkg/cli/cli_dispatch.go:96`.  
  Remote packet-drop monitoring receives and prints each gRPC frame at `cmd/cli/monitor.go:405`; when the command is piped, the outer `io.ReadAll` withholds every matching line until stream EOF/cancellation and grows with the stream.  
  `pkg/cli/cli_dispatch_pipe_stream_4731_test.go:12` pins the local bounded path, while no `cmd/cli` test invokes `dispatchWithPipe` or proves first-line-before-EOF behavior.  
  Thus PRs #4709/#4731 fixed only one copy of a cross-surface output contract, leaving the remote copy both slower and semantically stale.
- **Proposed decomposition:** **Authoritative adversarial scope:** `cmd/cli/shared.go:111` fully buffers remote output, lowercases matches, and writes through global stdout while local filtering is streaming/case-sensitive. One bounded, writer-injected streaming pipeline is a real shared owner; prior C175-HC-093/`#4709`/`#4731` fixed only local paths. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is operator I/O rather than packet forwarding, but remote monitor streams are unbounded-duration hot streams. Consume concurrently so match/except/find/no-more retain one line, count retains one integer, and last retains exactly `N` lines; peak live memory must be independent of total input except the configured ring. Keep one producer and one consumer goroutine, the current pipe backpressure, and command-context cancellation; add no locks or per-row dynamic dispatch. A line reader can still allocate per line, so claim bounded live memory rather than zero total allocation. Writer injection removes cross-command stdout capture; it must not reorder gRPC frames or widen ownership of terminal state.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Port the local golden matrix for every filter, trailing-newline edge, invalid `last`, and case-sensitive matches into `pkg/clioutput`. Add a blocking-reader test whose first matching line must reach the writer before EOF, and a remote streaming-monitor test that observes a line before the server closes. Feed at least 100 MiB through match/count/no-more and gate peak live heap to a fixed bound (for example, less than 8 MiB above baseline); `last 5` must retain exactly five lines. Run `go test -count=1 ./pkg/clioutput ./pkg/cli ./cmd/cli` and `go test -race -count=1 ./pkg/clioutput ./pkg/cli ./cmd/cli`; gate on byte-identical local output, case-sensitive remote parity, bounded peak heap, prompt cancellation, and no process-global stdout mutation after the writer phase.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A piped remote monitor currently appears silent until it ends and can consume memory for its full lifetime. Ordinary large shows pay multiple full-output allocations, and remote filters disagree with local filters on case. This is independently issue-worthy resource safety, usability, and parity work.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First extract and characterize newline/filter semantics from the proven local implementation. Switch remote filtering to the shared streaming function while preserving current command cancellation. Add remote first-byte and heap gates. Then thread command-local writers through dispatch/presenters and remove stdout swapping from both surfaces; keep that writer migration separate if review size requires it.
- **Labels:** `refactor`, `cli`, `performance`, `resource-safety`, `feature-parity`, `test-gap`
- **Dedup note:** Searched `C175-HC-093`, `io.ReadAll`, `pipe filter`, #4709, #4731, PR #4734, `case-sensitive`, and remote monitor buffering. `C175-HC-093` reported the local buffering/pager path and is fixed at this base by #4709/#4731. The retained issue is the still-unfixed remote copy plus a shared package boundary, live-stream behavior, and local/remote semantic parity; it is not a restatement of the resolved local finding. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R7B2-HC-002`.

### 24. `R7B2-HC-003` - Replace the delimiter-encoded ShowText request grammar with typed domain requests
- **Title:** Replace the delimiter-encoded ShowText request grammar with typed domain requests
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `proto/xpf/v1/xpf.proto:961` exposes only `string topic` and `string filter`; the comment lists a small subset of the actual accepted grammar.  
  Remote dispatch assembles ad hoc colon-delimited requests such as firewall filters and logs at `cmd/cli/show.go:272` and `cmd/cli/show.go:290`, then sends them through one helper at `cmd/cli/show.go:426`.  
  Server `ShowText` begins a separate prefix grammar at `pkg/grpcapi/server_show.go:20`, with route, CoS, screen, test, and firewall parameter parsing before a large exact-topic switch.  
  `cmd/cli/main.go:467` must reject otherwise valid zone values containing comma or equals because `test-policy:from=X,to=Y,...` cannot encode them.  
  Every parameterized topic must independently reimplement missing/unknown/duplicate-key validation; the prior `C175-HC-110` duplicate-selector defect in `test-routing` is one already-tracked consequence.  
  The unary response remains one `string output` at `proto/xpf/v1/xpf.proto:967`, so request validation, routing, and presentation allocation are hidden behind an untyped topic rather than enforced by protobuf.  
  Existing typed RPCs for config, sessions, monitors, and system actions show that the service already has a schema-owned alternative; the generic path is the residual protocol exception.
- **Proposed decomposition:** **Authoritative adversarial scope:** `xpf.proto:961` encodes parameterized ShowText requests in delimiter-bearing strings. Retain typed requests only for parameterized topics behind a measured legacy adapter; exclude a mega-oneof, renderer unification, and dependency on HC-001's rejected broad registry. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This RPC is serialized operator control-plane work. A protobuf oneof replaces topic concatenation/splitting with generated field decoding; it adds no locks, goroutines, packet-path dispatch, cache-line changes, or per-row interface calls. Small request objects may allocate comparably to the current topic string; benchmark and reject material regression, but do not claim this change fixes output allocation. Preserve existing manager snapshot ownership and unary `strings.Builder` output during migration. Streaming large responses is a separate follow-up after typed request parity, so wire/schema work cannot accidentally reorder presenter output.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Inventory every exact/prefix topic and add a golden legacy-to-typed mapping table. For each topic, invoke old and new RPCs against the same fixture and require byte-identical output and equivalent status codes. Fuzz string fields containing comma, equals, colon, whitespace, and Unicode and require lossless typed transport; unknown oneof/view values must return `InvalidArgument`. Keep old-client/new-server compatibility tests. Run `make proto`, require `git diff --exit-code` after generated files are committed, then run `go test -count=1 ./pkg/grpcapi ./cmd/cli ./pkg/api`; gate on 100% live-topic inventory and zero legacy-only remote command before deprecation.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The wire format currently makes syntax characters unrepresentable and shifts schema validation into scattered string parsers. That causes API/CLI drift, silent last-wins/fallback risks, and repeated validation fixes. A typed request boundary makes command evolution reviewable while retaining each surface's intentionally different rendering contract.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First inventory topics and freeze old output/error behavior. Add the new typed RPC alongside `ShowText` and implement one low-risk domain end to end. Route legacy topics through a strict compatibility decoder into the same typed executor. Migrate the remote CLI domain by domain after `R7B2-HC-001`; leave old `ShowText` available for a documented compatibility window, then remove only after call-site and telemetry evidence shows no users.
- **Labels:** `refactor`, `api`, `grpc`, `cli`, `feature-parity`, `input-validation`
- **Dedup note:** Searched codex-review-171 finding 24, fable-review-173 A9 F4, #1687, #1700, `ShowText registry`, `test-policy`, `C175-HC-110`, and PR #4660. The prior findings share REST/gRPC renderers or split large presenter files. This finding deliberately preserves divergent renderers and instead types the wire request/validation boundary; the known selector bugs are evidence of the protocol debt, not re-reported defects. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R7B2-HC-003`.

### 25. `R8-B1-02` - Scope RA supersession generations to per-interface intent
- **Title:** Scope RA supersession generations to per-interface intent
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/ra/ra.go:69`, `pkg/ra/ra.go:138`, `pkg/ra/ra.go:235`, `pkg/ra/ra.go:324`, `pkg/ra/ra.go:496`, `pkg/daemon/daemon_ha.go:737`.
  `Manager.epoch` is bumped by every Apply, Withdraw, WithdrawInterfaces, WithdrawOnce, and Clear, regardless of interface scope.
  A changed-config Apply removes sender A, installs A's tombstone, captures the one global epoch, and joins the old owner unlocked.
  `releaseDrain` starts A's replacement only when the global epoch still equals that capture; otherwise it deletes A's tombstone and returns.
  `WithdrawInterfaces([B])` increments that same epoch even when B is unrelated to A, so it can invalidate A during the join window.
  The resulting sequence is active A -> draining A -> unrelated B withdrawal -> no A replacement and no A tombstone.
  HA drives per-RG Apply/WithdrawInterfaces from concurrent event/reconcile paths, while service reconciliation re-drives RA only on an RG state change.
  Existing #2033 tests cover same-interface supersession and lock atomicity, not cross-interface cancellation of a still-valid serve intent.
- **Proposed decomposition:** **Authoritative adversarial scope:** The manager-wide RA epoch at `ra.go:69-506` lets interface B supersede interface A's restart. Retain per-interface intent revisions inside the existing `senders`/`draining` registry, with whole-manager fencing for Clear/Withdraw. Exclude a second lifecycle registry package. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** RA lifecycle is control-plane work, not a packet hot path. The change replaces one global integer comparison with an existing-map-adjacent per-interface revision lookup under the same mutex. It adds no sender-loop branch, socket, goroutine, dynamic dispatch, or lock. Keep blocking joins and NDP writes outside `Manager.mu`, and keep the decision/start act atomic under that mutex to preserve #2033.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a deterministic two-interface test: gate A's old `Close`, start a changed-config Apply for A, call `WithdrawInterfaces([B])`, release A, then assert exactly one live A replacement, no A goodbye, and no tombstone. Add the converse whole-manager Clear/Withdraw case, which must cancel A, and hammer both under `-race`. Gates: `go test -race ./pkg/ra -run 'Unrelated|Restart|WithdrawInterfaces|Round5' -count=100`, `go test -race ./pkg/ra`, `make test-failover`; pass means per-interface operations cannot cancel unrelated serve intent and global teardown still wins.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The losing path silently leaves a still-primary interface with no RA sender. Hosts retain old information only until advertised lifetimes expire, then lose IPv6 default routing/RDNSS with no automatic steady-state repair because the daemon starts/stops services only on a later RG transition.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: (1) Add the two-interface interleaving test against current code. (2) Model slot intent/revision without moving sender I/O. (3) migrate changed-config restart and deferred Apply first. (4) migrate WithdrawInterfaces/WithdrawOnce. (5) migrate whole-manager Withdraw/Clear last and prove their all-slot fence. Keep this separate from the prior `buildRA` extraction.
- **Labels:** `bug`, `ha`, `ipv6`, `router-advertisement`, `concurrency`, `refactor`
- **Dedup note:** Searched `RA epoch`, `global epoch`, `per-interface epoch`, `WithdrawInterfaces`, `deferred Apply`, `#2033`, `#2272`, `#2453`, `#2834`, fable-review-173 A8-F12, codex-review-175, and all prior top-level review files. Prior work covers one-interface goodbye/restart races, lock latency across interfaces, and `buildRA`/`configEqual`; none covers a scoped B operation invalidating A's replacement through the global epoch. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R8-B1-02`.

### 26. `R8-B1-03` - Make session-sync publication and cold-prime ownership generation-aware
- **Title:** Make session-sync publication and cold-prime ownership generation-aware
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/cluster/sync_conn.go:475`, `pkg/cluster/sync_conn.go:493`, `pkg/cluster/sync_conn.go:499`, `pkg/cluster/sync_conn.go:1180`, `pkg/cluster/sync_conn.go:1717`, `pkg/cluster/sync_bulk.go:87`.
  #4370 moved each accepted handshake into an independent tracked goroutine, but no per-fabric setup/publication sequence was added.
  An older accept A can stall, newer B can authenticate and publish, then A can finish later, close B, and become the slot owner.
  A legacy pending frame is dispatched before either setup competes for publication, so a setup that should lose can mutate shared sync state.
  Only the setup observing `wasDisconnected` publishes OnPeerConnected and owns cold bulk; A observes an existing B and skips both.
  If B's BulkSync already captured B, A closes it mid-stream; B's write fails, but `handleDisconnect(B)` is stale and returns before survivor redrive.
  The surviving A connection is live with no immediate cold-prime owner; daemon retry is delayed and direct `SessionSync` users have no repair trigger.
  Assigned tests cover accept non-blocking, stale disconnect, cold start, reconnect, and dual-fabric redrive separately, not this composition.
- **Proposed decomposition:** **Authoritative adversarial scope:** Concurrent setup at `sync_conn.go:475-529,1180` lacks reservation/publication order and can lose the cold-prime obligation. Retain a per-fabric high-water publication token plus acknowledgement-bound prime ownership; legacy-frame dispatch, Stop admission, and stale disconnect behavior must be in scope. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** The registry runs only on connection setup/removal. Per-frame read/write, HMAC, payload allocation, little-endian codecs, send batching, and `writeMu` remain unchanged. Use the existing connection mutex plus scalar sequences; add no interface, reflection, per-message generation lookup, heap object, or goroutine per frame. The prime coordinator reuses `bulkSendMu`/one CAS owner and must never hold the registry lock while iterating sessions or writing the socket.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add controlled handshake seams and three fail-on-revert tests: A accepted before B but B completes first and remains published; a rejected A pending frame is never dispatched; B bulk pins B, C replaces it, and exactly one complete BulkEnd is re-driven on C without waiting for daemon retry. Assert one connectivity callback per epoch and no goroutine leak. Gates: `go test -race ./pkg/cluster -run 'Accept|HandleNewConnection|ColdStart|BulkSyncRedrive' -count=100`, `go test -race ./pkg/cluster`, `make test-failover`, and `make test-ha-crash`.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Connection identity currently protects teardown but not setup ordering or cold-prime ownership. A routine reconnect race can delay/omit complete session publication, hold transfer readiness, or let a losing legacy setup apply a stale control frame after a newer connection has won.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: (1) Land deterministic completion-order tests. (2) add publication tokens and move pending-frame handling after accepted publication. (3) make cold-prime obligation survive active connection replacement and loop on connection-generation change. (4) only then perform the already-tracked generation-guard/dispatcher split, because both touch `SessionSync` ownership fields. Preserve wire bytes throughout.
- **Labels:** `bug`, `ha`, `session-sync`, `concurrency`, `failover`, `refactor`
- **Dedup note:** Searched `#4370`, PR `#4473`, `handshake generation`, `out-of-order handshake`, `stale setup`, `cold bulk`, F-095, F-157, F-258, `#551`, and PR `#632`. #4370 covers accept-loop head-of-line blocking; F-157 covers a carrying fabric loss; F-258 covers concurrent dual-fabric receiver generation guards; F-095/#551 cover broad file boundaries. None assigns publication order and cold-prime obligation across two same-fabric setup goroutines, which is the new residual introduced by async setup. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R8-B1-03`.

### 27. `R8B2-NETWORKD-01` - Retain networkd reload and reconfigure debt across identical applies
- **Title:** Retain networkd reload and reconfigure debt across identical applies
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/networkd/networkd.go:74`
  1. `Manager` owns only `networkDir` and the protected-set resolver; it has no applied generation, dirty bit, or pending reconfigure set.
  2. `Apply` creates a call-local `changed` flag at line 169, set only by file writes or successful stale-file removals in that invocation.
  3. Files are already replaced when `networkctl reload` fails at lines 239-243, so the first call correctly returns an error but leaves desired disk state behind.
  4. An identical retry reaches `writeIfChanged` lines 657-660, sees byte-identical files, leaves `changed == false`, skips reload, and returns nil against unchanged observed networkd/kernel state.
  5. A process restart has the same hole because a new manager reconstructs no pending activation state from the desired files.
  6. `networkctl reconfigure` failures at lines 255-262 are warn-only and likewise receive no retry on an identical apply, even though the preceding comment says dynamic devices may require reconfigure for addresses.
  7. The daemon joins the first `Apply` error into commit status at `pkg/daemon/daemon_apply.go:834`, but it cannot detect the later false-success path because the manager has forgotten the failed publication.
- **Proposed decomposition:** **Authoritative adversarial scope:** `networkd.go:74-262` remembers only call-local `changed`; a failed reload followed by identical apply can return success without retry. Retain manager-owned reload/reconfigure debt. Do not claim `networkctl reload` proves observed external generation or persist a self-authored convergence marker. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This runs only on serialized config apply, not on the Go or Rust packet path. Manifest construction already allocates expected-file maps; one generation value and a bounded pending-name set do not alter packet allocations, dispatch, ABI, or cache-line layout. Keep the existing direct function calls and timeout-bounded subprocesses. The daemon's `applySem` already serializes the production caller; any manager mutex should protect only generation bookkeeping, with no new goroutine or callback while locked. Retrying an idempotent `networkctl` command is cheaper and safer than rewriting unchanged files.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a stubbed two-call test where reload fails once: call one must fail, call two with identical desired files must invoke reload again, and no call may return nil until reload succeeds. Add a manager-recreation test over pre-existing desired files, plus a reconfigure-failure test that retains and retries the exact interface set. Preserve `TestApply_WriteErrorFailsCommit`, empty-set sweep, and lifeline tests. Gate with `go test -race ./pkg/networkd ./pkg/daemon` and a systemd-networkd integration test asserting addresses/VRF membership after fail-once reload/reconfigure injection.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A retry or daemon restart can report a successful commit while networkd and the kernel still implement the previous address, rename, bond, bridge, or VRF state. On a firewall this can preserve a route leak, strand a data interface, or lock out management despite a green commit result.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First add fail-once characterization seams for reload and reconfigure. Extract the pure manifest/store boundary without behavior change. Add durable or first-apply activation debt, clear it only after observed activation succeeds, and return joined activation errors. Finally wire health/metrics to the pending generation and verify an unchanged retry converges without file churn.
- **Labels:** `networkd`, `reconciliation`, `state-machine`, `host-config`, `route-leak`, `test-gap`
- **Dedup note:** Searched `networkctl reload`, `reload pending`, `unchanged apply`, `networkctl reconfigure`, #2987, #2988, and all prior review reports. `codex-review-175 C175-HC-047` is the stale-file `os.Remove` failure and remains separately valid; it does not cover a successful disk diff followed by failed activation and false success on the next identical apply. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R8B2-NETWORKD-01`.

### 28. `R9B2-001` - Make flow-export generation retirement wait for callbacks admitted to the old bundle
- **Title:** Make flow-export generation retirement wait for callbacks admitted to the old bundle
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/flowexport/netflow.go:589`. `Exporter.Run` performs its last `flushBatches` only after context cancellation, then returns at line 606. `ExportSessionClose` has no running/retired admission check and can append at line 673 after that final drain; `Close` at line 717 closes only collector connections. `pkg/flowexport/ipfix.go:806` and `pkg/flowexport/ipfix.go:830` have the same lifecycle. The direct caller loads one atomic bundle, computes the close record, and submits to every group; reconcile publishes the replacement and immediately cancels/waits/closes the old generation (`pkg/daemon/daemon_flowexport.go:255` and `:461`). A callback that loaded the old pointer just before publication can therefore append after the old runner's final drain. The bounded batch prevents OOM but leaves that record permanently stranded, with nonzero `BatchDepth` and no lifecycle-drop counter. Existing tests exercise build-before-swap and callbacks after publication, not a callback paused between old-bundle load and submission.
- **Proposed decomposition:** **Authoritative adversarial scope:** `flowexport/netflow.go:589-720`, `ipfix.go:806-830`, and `daemon_flowexport.go:255-517` allow a callback that loaded the old bundle to append after final flush. Retain allocation-free admission leases and retirement waiting on the concrete daemon bundles; exclude a generic `flowexport/runtime.Generation` with erased ownership. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is the RT_FLOW session-close telemetry path, not per-packet forwarding. Use one allocation-free read lease per protocol callback, not per template group or record. A small stateful RW lock or equivalent gate adds one bounded lock pair and branch while preserving the existing plain `flowBatch.add`, batch amortization, encoder calls, sequence locks, and concrete dispatch. Do not add per-record goroutines, interface boxing, queue copies, or collector-dependent labels. Benchmark must show zero added allocations and separately report callback nanoseconds; any fixed metric should use only the bounded `protocol={netflow9,ipfix}` label.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** First add deterministic two-window tests for both protocols: pause a callback after old-generation acquisition and prove retire waits plus the final drain exports exactly once; pause it after pointer load but before acquisition and prove it retries the current generation or is explicitly rejected on removal. Add a repeated concurrent producer/swap test under `-race` asserting `accepted == exported + capacity_dropped`, every retired exporter ends at `BatchDepth()==0`, and no record ID is duplicated. Gate with `go test -race ./pkg/flowexport ./pkg/daemon -run 'FlowExport|IPFIX|Generation'` and an allocation benchmark requiring `0 allocs/op` for lease acquisition/submission.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A clean day-2 collector, template, sampling-rate, or removal reconcile can silently lose a session-close record at precisely the lifecycle boundary that claims lossless handoff. That creates a forensic/accounting hole while all exporter health and bounded-queue metrics can otherwise look normal.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Land failing lifecycle characterization tests first. Introduce the protocol-neutral generation lease without moving wire encoders. Wrap both v9 and IPFIX bundles, acquire before sampling, and make retirement precede cancellation/final flush/connection close. Add a fixed-cardinality handoff retry/reject counter. Land this guardrail before further `#4421` flowexport package movement so subsequent module extraction inherits a linearizable lifecycle contract.
- **Labels:** `refactor`, `flowexport`, `observability`, `service-lifecycle`, `concurrency`, `test-gap`
- **Dedup note:** Searched `flow exporter`, `callback loss`, `#3742`, `build-before-swap`, `in-flight`, `bundle`, and `reconcile` in the supplied index and prior reports. `codex-review-158` H05 covered the old stop-before-publish window; base `23eb4506` fixes that ordering by publishing the replacement first. This is the narrower residual the fix does not cover: a callback that already loaded the old bundle has no admission lease, so publication alone cannot make retirement wait for it. The guardrail is separately actionable and does not duplicate the broad `codex-review-158` L07 / open `#4421` package split. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R9B2-001`.

### 29. `R10-B1-001` - Retire orphaned BPF implementation headers after relocating live ABI ownership
- **Title:** Retire orphaned BPF implementation headers after relocating live ABI ownership
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md:126`, `pkg/dataplane/build-userspace-xdp.sh:97`, `bpf/headers/xpf_helpers.h:23`, `bpf/headers/xpf_maps.h:11`
  The #1476 manifest retained these headers only until shared definitions were moved or retired, and explicitly requested a later orphan proof.
  That proof now finds no production BPF C translation unit under `bpf/`; the tree is seven headers, while the unrelated tracked C units include none of them.
  `xpf_helpers.h` carries 50 `static __always_inline` functions and `xpf_maps.h` carries 67 map definitions that therefore produce no object code or maps.
  The only executable ownership left in the assigned set is `MAX_INTERFACES`, parsed by the shim build, plus a legacy event-layout test parsed from `xpf_common.h`.
  `xpf_maps.h:372-375` still tells maintainers to regenerate bpf2go objects that were removed, so edits can appear production-relevant while changing nothing.
  Splitting these dead headers would preserve that false authority; moving helpers to `.c` would also invent verifier call boundaries rather than remove debt.
- **Proposed decomposition:** **Authoritative adversarial scope:** The `#1476` manifest at `source-removal-manifest-1476.md:126-144` deliberately retained these headers and says a future PR is a separate reviewed boundary, so `#1476` is not an exact duplicate. Retain a complete live-consumer/orphan proof, move `MAX_INTERFACES` and the legacy event-layout fixture to active owners, then delete only proven orphan headers; do not imply every retained header was audited. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** None of the 50 helpers or 67 map definitions is compiled, so retirement changes no packet-path instruction, allocation, copy, branch, map, stack, or cache behavior. Keep `MAX_INTERFACES=65536` and the event offsets byte-identical during ownership migration. Regenerate the Rust object with the pinned toolchain and require identical XDP/text/map section bytes or an explained verifier-equivalent delta before deleting the old input.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a failing-first test that active build code cannot reference `bpf/headers/`; retain Go/Rust/object max-entry parity; run `go test ./pkg/dataplane ./pkg/logging`; run the pinned `make generate-userspace-xdp` verifier gate and require a clean object diff for the constant-only move; finish with `rg` proving no active source read/include of the deleted headers.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Canonical-looking, unbuilt packet and map logic is a production maintenance hazard: a security, verifier, or map-layout fix can land in code that ships nowhere. Closing the deferred ownership boundary also prevents future work from trying to modularize or revive an obsolete C dataplane accidentally.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First establish the active constant/layout owners and parity tests. Second switch all executable reads and documentation. Third prove object equivalence. Last delete the dead implementation headers and stale bpf2go guidance as one reviewed retirement change.
- **Labels:** `refactor`, `bpf`, `build`, `tech-debt`
- **Dedup note:** Searched closed #1473/#1476, the #1373 source-removal manifest, C175 A10-b1, and the dedup index. #1476 intentionally deferred this exact follow-up rather than completing it; C175 only suppressed dormant correctness defects because the headers are not runtime. No open tracker item was found for completing the orphan proof and moving the two live reads. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R10-B1-001`.

### 30. `R10-B1-003` - Gate the tracked XDP object against an explicit source and toolchain provenance manifest
- **Title:** Gate the tracked XDP object against an explicit source and toolchain provenance manifest
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/dataplane/README.md:42`, `Makefile:79`, `debian/rules:36`, `scripts/image/bake.py:567`
  `userspace_xdp_bpfel.o` is tracked, embedded, and explicitly not regenerated by ordinary `make build`.
  `make test` runs Go and `userspace-dp` tests, but it neither rebuilds the shim nor proves that the embedded object corresponds to current `userspace-xdp/**` inputs.
  Existing Go canaries validate program/map allowlists and loadability, not semantic source-to-object freshness.
  Debian packaging delegates to `make build`, and the image bake packages that binary, so a source-only shim fix can pass normal gates while shipping the prior object.
  The documented pinned rebuild plus clean diff is not represented by a repository CI/Make dependency and requires a privileged verifier run.
  At this base, source and object are synchronized in the same `024cab8878be49b9d6b90d3dbf3b7fdfe5df9570` commit; this is a latent ownership defect, not a claim of current artifact drift.
- **Proposed decomposition:** **Authoritative adversarial scope:** `pkg/dataplane/README.md:42`, `Makefile:79`, and packaging paths use a tracked XDP object without binding normal builds to current source inputs. A deterministic source/toolchain/object provenance manifest plus cheap mandatory digest gate is a real build ownership boundary distinct from `#1864`'s privileged regeneration/verifier gate. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** The manifest and digest check are build/test-time only and must not be embedded into packet processing or add maps, instructions, loads, branches, allocations, or object sections. The deployable `.o` remains byte-for-byte the artifact verified by the kernel. Build both files in temp paths, install the object, and publish the manifest last; every consumer must reject a missing or mismatched digest, so interruption may leave a rejected pair but can never leave a pair that passes the freshness gate.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add fail-on-revert tests for changed Rust source, changed ABI input, changed linker/toolchain pin, tampered object bytes, missing manifest, partial install, and successful pinned regeneration. Make the cheap digest check part of `make test`, `make build`, Debian build, and image preflight. Keep the privileged pinned rebuild/clean-diff and cluster smoke as release gates; the cheap gate must fail before packaging even when root is unavailable.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The checked-in object, not the Rust source, is what production executes. A source/object mismatch can silently ship an old parser, map behavior, or security fix even though source review and normal tests are green.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Define canonical input enumeration and manifest schema; add read-only validation; update the generator to verify then atomically install both artifacts; wire the cheap check into build/test/package/bake; only then use it as the prerequisite for R10-B1-002.
- **Labels:** `build`, `bpf`, `generated-code`, `supply-chain`, `testing`
- **Dedup note:** Searched #1473, #1476, #1864, PR #4113, the loader/retirement canaries, and prior reports. #1864 gates toolchain drift and verifier rejection of a newly generated object; it does not bind current source inputs to the already tracked object used by ordinary builds. No source digest/manifest gate was found. C175-HC-007 is unrelated queue-index correctness and remains suppressed. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R10-B1-003`.

### 31. `R10-B1-004` - Package xpf-deploy by backend and rollout transaction while preserving the command path
- **Title:** Package xpf-deploy by backend and rollout transaction while preserving the command path
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `scripts/deploy/xpf-deploy.py:415`, `scripts/deploy/xpf-deploy.py:482`, `scripts/deploy/xpf-deploy.py:888`, `scripts/deploy/xpf-deploy.py:1173`, `scripts/deploy/xpf-deploy.py:1453`
  Incus and libvirt preflight/mutation/cleanup are separate transactions but share one global module with inventory, config-drive, and CLI code.
  Signed fetch/import owns network bytes, anti-rollback state, signature verification, and optional libvirt install, independent of VM mutation.
  Lease acquisition and remote execution are shared by two different HA state machines with distinct stop/rollback semantics.
  Kernel roll spans 172 lines and image roll 187 lines; both must validate the pair before mutation and never leave both peers drained.
  The 142-line `main` parser imports and dispatches every domain, while tests load the whole hyphenated script through `importlib`.
  These are operational ownership and failure boundaries, not merely a large-file threshold.
- **Proposed decomposition:** **Authoritative adversarial scope:** `xpf-deploy.py:415-1657` contains separate backend, distribution, lease, kernel-roll, and image-roll transactions. A compatibility wrapper over concrete transaction-owning modules is a real cold-path package boundary; preserve exact preflight/mutation/cleanup and avoid plugin abstractions. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is operator-driven cold-path orchestration dominated by subprocess, network, disk, hypervisor, and reboot latency; it is not called from packet forwarding. Avoid an abstract plugin framework or import-time backend probing. Keep one injected `Runner`, exact argv lists, fail-closed return-code handling, and current mutation order. Module imports must not acquire leases, read mutable state, or touch hypervisors.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Move the existing 71 passing tests to package imports without weakening them. Add per-backend ordered event traces that prove all preflight precedes the first mutation and cleanup runs only for resources created by this invocation. Add kernel/image rollout traces for lease order, drain/rejoin, timeout, recreate-hook validation, and every abort point; preserve exact dry-run golden argv. Gate with `make selftest`, `py_compile`, and throwaway Incus/libvirt lifecycle tests plus a two-node HA roll rehearsal before replacing the wrapper.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Deploy, fetch, and HA roll changes currently share import/global scope despite different trust and rollback boundaries. A package split makes the security and transaction owner explicit, reducing the chance that a backend or CLI change bypasses a preflight, cleanup, lease, or mixed-base gate.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First convert tests to package-aware imports and capture ordered traces. Extract pure model/config-drive code, then one backend at a time, then fetch. Extract remote/lease only after call-order tests are red-on-reorder; move kernel and image state machines last. Keep wrapper CLI and documented invocations stable throughout.
- **Labels:** `refactor`, `deployment`, `ha`, `python`, `testing`
- **Dedup note:** Searched #1879, #1930, closed #4211, Fable-165 H20-H30, C175-HC-017, deploy PR history, and prior modularity reports. Those items address concrete correctness/test gaps and are fixed or separately reported. This is a new package boundary that preserves their invariants; it does not restate transient status handling or missing tests. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R10-B1-004`.

### 32. `R10-B1-005` - Modularize and adopt the cold-path flooder under explicit build and performance gates
- **Title:** Modularize and adopt the cold-path flooder under explicit build and performance gates
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `test/incus/cold-path-flooder/Cargo.toml:22`, `test/incus/cold-path-flooder/src/main.rs:573`, `test/incus/cold-path-flooder/src/main.rs:1051`, `Makefile:114`
  The crate is intentionally outside both workspaces, but no standard Make target compiles, tests, or formats it.
  Its one file combines CLI policy, Linux FFI, packet serialization, raw-pointer ring lifetime, a high-rate worker loop, thread control, reporting, and 592 lines of tests.
  `TxRing.msg_name` points to an inline field and becomes dangling if `wire_msgs()` runs before the final move into `worker_loop`.
  The hot loop preallocates buffers, mutates packet fields, calls `sendmmsg`, and uses Relaxed per-batch atomics; an ordinary abstraction split can regress Mpps or safety.
  The 39 executable unit tests pass, but the privileged AF_PACKET smoke is ignored and `cargo fmt --check` currently reports drift.
  The original four-thread acceptance gate is measurable: at least 2.5 Mpps, max/min worker ratio at most 2.0, and EAGAIN below 0.1 percent.
- **Proposed decomposition:** **Authoritative adversarial scope:** `cold-path-flooder/main.rs:573,1051` combines cold CLI/reporting with a raw-pointer `TxRing`/worker unit, while `Makefile:114` has no standard owner. Retain build/format/test/perf adoption first, then move cold code; keep `TxRing`, final-location wiring, and worker loop together unless disassembly and the recorded Mpps gate approve movement. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Preserve `#[inline(always)]` on PRNG and packet fill, fixed `[u8;64]` frames, preallocated vectors, one `sendmmsg` per batch, no per-packet allocation, no trait objects/dynamic dispatch, and current endian/checksum locality. Keep `WorkerCtx` ownership by value, `wire_msgs()` after the last move, `#[repr(align(64))]` statistics, Relaxed high-frequency atomics, AcqRel only for first-error publication, CPU pinning, and shared deadlines. The release profile's thin LTO and single codegen unit should inline across source modules, but disassembly and the Mpps gate must prove it.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** First add `make test-tooling-rust` with locked release build/test and rustfmt, then make the current format drift fail visibly. Preserve all 40 tests, make the privileged raw-socket smoke opt-in rather than silently owned nowhere, and add a compile-fail or construction API test preventing pre-move wiring. Compare release `worker_loop` disassembly for allocation/call changes. On the recorded mlx5 venue, require four threads >=2.5 Mpps, max/min <=2.0, and EAGAIN <0.1 percent before and after extraction.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** This binary is measurement infrastructure for dataplane capacity. Unowned build drift or a modularity-induced pointer/performance regression can invalidate the evidence used to make production scaling decisions.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Wire format/test ownership and clean rustfmt first. Move cold CLI/reporting, then packet/Linux helpers. Move `TxRing` and `worker_loop` together only after disassembly and hardware baselines are captured. Re-run the privileged and four-thread gates before accepting the final split.
- **Labels:** `refactor`, `rust`, `performance`, `testing`, `linux`
- **Dedup note:** Searched #1607/#1611/#1615, their plans/measurements, C175-HC-072, and prior modularity reports. C175-HC-072 reports bounded-mode tuple reuse and is not repeated. The closed flooder work established implementation/perf gates but left the crate outside standard ownership and did not propose this raw-pointer-preserving module boundary. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R10-B1-005`.

### 33. `R10-B1-006` - Split the fairness suite by owned executable and wire it into self-test discovery
- **Title:** Split the fairness suite by owned executable and wire it into self-test discovery
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** A
- **Evidence:** `test/incus/fairness_multi_sample_test.py:20`, `test/incus/fairness_multi_sample_test.py:39`, `test/incus/fairness_multi_sample_test.py:383`, `scripts/run-selftests.sh:136`
  The file imports two Python modules and names two shell executables before placing all tests in one class through line 1421.
  Wrapper/reducer tests start at line 40, harness subprocess tests at 383, class-sweep tests at 493, and equal-flow capture tests at 724.
  Fake harness/process builders begin at 1126 and are shared support, not tests of the multi-sample module itself.
  A failure or fixture change in any one executable requires loading and reviewing all four ownership domains.
  Direct execution passes 42 tests, but the repository's hermetic self-test discovery only scans `scripts/image`, `scripts/deploy`, and `scripts`.
  This is a test ownership and gate gap; `fairness_multi_sample.py` production code itself is already cohesive.
- **Proposed decomposition:** **Authoritative adversarial scope:** `fairness_multi_sample_test.py:20-1421` tests four executables in one class, and `run-selftests.sh:136` does not discover it. Ownership-aligned test modules plus a nonzero-discovery standard target is a concrete test boundary not supplied by the generic giant-test reports. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Test-only movement changes no dataplane, fairness algorithm, process-under-test, packet allocation, branch, lock, or runtime codegen. Keep subprocess environment, process-group cleanup, fixture bytes, and timeout behavior identical. Do not move production reducer logic into test support merely to share helpers.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Require each new module to pass independently and package discovery to report the same 42 tests. Wire `test-fairness-tooling` into `make selftest`; add a canary that fails if zero tests are discovered or one of the four target paths disappears. Preserve subprocess execution under each shell target's declared shebang and Python `unittest`; keep temporary files outside the tree.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** These tests guard evidence-generating fairness tools, yet the suite is not run by the advertised hermetic self-test target. Ownership-aligned files make failures attributable and turn the existing coverage into a real repository gate.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Extract shared fixtures without behavior changes, move one test cluster at a time while holding the count at 42, add the discovery target, then update `make selftest` and documentation. Do not combine this with production wrapper changes.
- **Labels:** `refactor`, `testing`, `fairness`, `python`
- **Dedup note:** Searched C175-HC-084, Fable-173 giant-test-file findings, fairness PR history, and the dedup index. C175-HC-084 is a production verdict bug and remains suppressed. Prior generic test-mass findings did not enumerate this four-executable suite or its missing self-test registration; this is a concrete, separately actionable split. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R10-B1-006`.

### 34. `R10-B1-007` - Make the refactoring heatmap a scope-complete enforced generated gate
- **Title:** Make the refactoring heatmap a scope-complete enforced generated gate
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `scripts/refactoring-audit.sh:2`, `scripts/refactoring-audit.sh:82`, `Makefile:118`, `docs/refactoring-audit-current.txt:1`
  The generator advertises a modularity audit but scans only Go, two Rust runtime roots, and now-absent BPF `.c` roots.
  It cannot surface the 1,805-line deploy tool or 2,170-line standalone flooder at all, and it has no separate tooling-test ledger for multi-owner suites.
  The Make target correctly regenerates to a temp file and diffs, but comments deliberately keep it outside `test` and `all`.
  Independent execution now yields 46 entries while the committed artifact has 16, and `make audit-check` fails.
  The same artifact was regenerated repeatedly immediately after PR #1671 added the guard, showing that an optional check has no effective owner.
  Inline-test inflation and test filename classification are already known; broadening scope must report production and test mass separately rather than mixing them.
- **Proposed decomposition:** **Authoritative adversarial scope:** Stale heatmap contents and inline-test distortion are already `#1661` item 8/PR `#1671` and Fable-review-173 A1-F6. Retain only the new increment: an explicit owned-root/type registry, separate production/test ledgers, fixture-tested generation, and a mandatory standard gate covering Python and standalone Rust tooling. Do not file another one-off 16-to-46 refresh issue. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is build/review tooling only and has no runtime packet, control-plane, allocation, lock, or codegen effect. Keep generation read-only and linear in source size; do not parse Rust/Python with brittle range regexes. Separate raw LOC, production estimate, and test mass so gate wiring does not incentivize moving tests merely to reduce a misleading number.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Pin fixture output, run `bash -n` and shellcheck, and assert every owned root contributes a sentinel file. `make test` must fail on a stale artifact and pass immediately after `make audit-update`; legitimate growth is allowed by committing the regenerated artifact. At this base the acceptance test must reproduce 46 current legacy-scope entries before any intentional scope expansion, then add deterministic new tooling/test rows.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** The committed heatmap is the repository's modularity queue. A stale, partially scoped queue directs refactor work at old shapes and misses the tooling modules audited in this batch, while repeatedly consuming manual cleanup PRs.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First add fixture tests and an explicit scope policy. Second split production/test reporting and add missing owned roots. Third regenerate once. Last wire the check into the standard gate; do not file the 16-versus-46 diff as another one-off refresh issue.
- **Labels:** `build`, `refactor`, `generated-code`, `testing`, `developer-experience`
- **Dedup note:** Searched closed #1208/#1661, PRs #1214/#1671/#1675/#1683/#1684, Fable-173 A1-F6, and the dedup index. The stale contents and inline-test distortion are known and not independently re-reported. The retained increment is that #1661's deliberately standalone check has demonstrably allowed recurrence and its root policy omits owned Python/standalone-Rust tooling; enforcing and broadening ownership is different from another regeneration. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R10-B1-007`.

### 35. `R2-b2-03` - Eliminate warmed CoS Arc churn and settlement allocation across selection and settlement
- **Title:** Eliminate warmed CoS Arc churn and settlement allocation across selection and settlement
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** C
- **Evidence:** `userspace-dp/src/afxdp/tx/dispatch/mod.rs:690` calls an owner helper for each eligible forwarded packet; `tx/dispatch/cos.rs:30` returns it by cloning `Arc<BindingLiveState>` even when only pointer equality is needed.
  `userspace-dp/src/afxdp/cos/tx_completion.rs:437` clones the shared root-lease `Arc` on every root-prime call.
  Lines 836 and 950 clone `shared_exact_backlog` for every local and prepared settlement, then also borrow the same handle for peer checks.
  These Arcs are shared across workers, so each transient clone/drop adds atomic RMW traffic to a cross-core refcount cacheline.
  `refresh_cos_interface_activity` creates a fresh `Vec` at line 740 and first allocates at line 774 whenever an empty leased queue returns banked tokens.
  That refresh runs after both settlement variants, so bursty on/off classes repeatedly enter this allocation path.

Merged exact-backlog evidence:
`userspace-dp/src/afxdp/cos/queue_service/mod.rs:261`, `:267`, `:271`, `:282`, `:289`, `:303`
  `build_nonexact_cos_batch` clones `Option<Arc<SharedCoSExactBacklog>>` before each non-exact selection attempt.
  Clone/drop performs shared strong-count atomic RMWs even when no queue is selected.
  All worker bindings for the interface share that Arc, so the refcount cache line can bounce across cores.
  The adjacent `queue_fast_path` is already borrowed by reference from the same `cos_fast_interfaces` map.
  That reference lives safely across a disjoint mutable borrow of `cos_interfaces`, proving field-split borrowing works here.
  The backlog is only read/called synchronously; it is never retained in the returned `CoSBatch`.
  Support tracing found the same avoidable clone again in both Local and Prepared settlement paths (`cos/tx_completion.rs:836`, `:950`).
- **Proposed decomposition:** **Authoritative adversarial scope:** `tx/dispatch/mod.rs:690` and related settlement paths clone fast-path `Arc`s and allocate scratch. Merge R2-B1-02 into this issue; keep changes in existing files unless a later ownership split is independently justified. The shared exact-backlog `Arc` churn at `queue_service/mod.rs:261-303` is the same ownership work as R2-b2-03. It becomes one audited clone/settlement inventory, not a second issue. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Borrowing removes atomic refcount increments/decrements without changing the pointed-to layout or atomic ordering inside lease objects. Reused scratch preserves current publish-before-release order and batch amortization without heap growth; direct release is preferable if borrow splitting proves that order equivalent. Keep helpers concrete and `#[inline]`, with no trait-object dispatch, added pointer chase, locks, or per-call allocation. The queue/root structs and cacheline-isolated live counters stay in place.

Merged exact-backlog guard:
This removes two strong-count increment/decrement pairs from a successful non-exact batch and one pair from an unsuccessful selection attempt; it adds no allocation, lock, atomic, branch, copy, or pointer indirection. Concrete methods and existing `#[inline]` boundaries remain, with no trait object or code-size expansion. The Arc allocation and `SharedCoSExactBacklog` layout do not change, and all backlog payload atomics retain their exact orderings. The batch and UMEM ownership lifetimes remain synchronous. A narrow lexical borrow is important so Rust does not lengthen live references or force an outlining/codegen workaround.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Extend dispatch tests for local owner, foreign owner, no owner, and shared-exact short-circuit. Extend completion tests for one and multiple leases draining in a call, release ordering, token conservation, and scratch capacity stability. Add a serial allocation-count test requiring zero allocations after warm-up for 10,000 settle/refresh calls. Isolate owner lookup and empty settlement in a release microbenchmark; require no `Arc` strong-count RMW in generated code/perf lock-load samples and no greater than 3% latency regression.

Merged exact-backlog gate:
Retain all local/peer exact-demand and residual-budget selector tests plus Local/Prepared settlement tests. Add a source/assembly gate: no `.clone()` of `shared_exact_backlog` in queue service or settlement, and optimized assembly for the three functions contains no Arc strong-count `lock` increment/decrement or `drop_slow` edge. Benchmark 1/2/4/8 workers repeatedly selecting and settling shared backlog; require no cycle regression and a reduction in contended locked instructions/cache-to-cache transfers. Run the shaped exact-plus-best-effort cluster matrix and require byte-identical demand masks, residual debits, and throughput/fairness counters.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Contended refcount RMWs serialize otherwise worker-local packet handling, while lease-return allocation violates the documented no-allocation TX path exactly for bursty shaped traffic.

The shared backlog was designed with padded per-worker payload slots to avoid cross-core write sharing. Refcounting the Arc on every batch reintroduces a single shared write hotspot outside those slots and charges it even on a no-selection exit.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Change borrowed owner lookup first and migrate pointer-comparison/enqueue callers. Add characterization tests around completion ordering, then borrow-split root/backlog handling. Replace the release vector with direct release or preallocated scratch, and land the perf gate before any wider completion file split.

Convert the builder clone first, using the already-proven disjoint map borrow. Convert both settlement clones in the same issue so one batch cannot retain the second refcount pair. Add assembly/perf gates, then audit only direct neighboring `SharedCoSExactBacklog` clones for the same synchronous-borrow shape without broadening scope.
- **Labels:** `performance`, `hot-path`, `afxdp`, `cos`, `allocation`, `atomics`, `refactor`, `refactor`, `userspace-dp`, `performance`, `cos`, `atomics`, `cache-layout`
- **Dedup note:** Searched `cos_owner_live_for_request`, `shared_root_lease.clone`, `shared_exact_backlog.clone`, `released_queue_leases`, `Arc clone`, `refcount`, and `refresh_cos_interface_activity`. Closed `#4270` covers timer-wheel allocation and active-flow false sharing, not these transient Arc RMWs or the lease-release vector. The current campaign merged `R2-B1-02` into this issue as MG-01. Campaign disposition: **IN-SCOPE-MERGE (MG-01: R2-B1-02 + R2-b2-03)**. Canonical issue `R2-b2-03`.

### 36. `S1-RUST-RUNTIME-B2-01` - Preflight all AF_XDP worker thread creation before destructive reconcile commit
- **Title:** Preflight all AF_XDP worker thread creation before destructive reconcile commit
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:21`.
  `bring_up_workers` returns `()`, although every `spawn_supervised_worker` at lines 323-364 returns `io::Result`.
  On `Err`, lines 385-405 record an exception and remove the panic slot, but neither abort remaining launches nor return failure.
  Lines 408-413 then overwrite `spawn_worker_failed:*` with `spawned:*`, erasing the only reconcile-stage signal.
  `coordinator/reconcile/mod.rs:246` has already torn down the old workers before this launch, and lines 299-308 unconditionally refresh and return `Ok(())`.
  `server/handlers/snapshot.rs:211-236` only rolls back and returns `ok=false` when reconcile returns `Err`; this path therefore persists and acknowledges the snapshot.
  Failed-worker bindings retain newly-created `BindingLiveState` entries but never bind an XSK, so refresh marks them unready while the control transaction still reports success.
  The existing `ReconcileError` contract at `coordinator/reconcile/mod.rs:24-51` explicitly models only pre-teardown failures where prior forwarding remains live.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain desired/prepared/applied/failed generation semantics and parked-thread abort/join before teardown. Do not promise rollback after post-gate AF_XDP setup failure, and do not pre-approve the proposed three-directory tree. This is a real reconcile ownership boundary, not merely the swallowed `spawn` error. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Preparation and gate release are control-path-only. After the one-shot gate opens, call the existing monomorphic `worker_loop` directly with the same owned vectors/Arcs; add no per-packet branch, allocation, lock, atomic, trait object, or dispatch. `BindingWorker` construction, UMEM ownership, XSK binding, batch scratch, and raw-area lifetime stay on the worker thread. The gate and prepared launch objects must be dropped before entering the polling loop so they do not enlarge hot worker state or change cache-line layout.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a deterministic generic/test-only thread-spawner seam that fails on launch N. Before-teardown failure tests must assert: old handles/live slots/generation remain unchanged, every parked candidate is aborted and joined, no BPF/CoS/mirror publication occurs, `last_reconcile_stage` remains `spawn_worker_failed`, the response is `ok=false`, and persistence is not requested. Add all-success and abort-race tests proving each worker enters `worker_loop` at most once. Gate with `cargo test --release --bin xpf-userspace-dp coordinator`, the server snapshot tests, a real AF_XDP apply/reapply smoke, and HA forwarding continuity. Pass/fail criterion: forced launch failure causes zero old-worker teardown and zero acknowledged/persisted snapshot, while success has identical release symbols inside the post-gate polling path.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A recoverable OS thread-spawn failure after resource exhaustion can remove the previously working dataplane, leave only a subset of queues serviced, and still tell the daemon the snapshot is durable and active. That prevents normal retry and turns a local launch failure into a silent forwarding outage.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First add the deterministic launch-failure characterization and a distinct error type that cannot enter the existing pre-teardown rollback branch. Next introduce `PreparedWorkerSet` and parked launches while preserving current side-effect order after commit. Then move teardown behind successful preparation, atomically install coordinator state, release the gates, and delete the post-teardown swallow path. Land S1-RUST-RUNTIME-B2-02 first or in the same stack so auxiliary-service launch state follows the same commit discipline.
- **Labels:** bug, refactor, userspace-dataplane, af-xdp, lifecycle, high-availability
- **Dedup note:** Searched `spawn_worker_failed`, `spawned overwrite`, `worker thread spawn failure`, `bring_up_workers Result`, and `post-teardown spawn` in the campaign dedup index, repository issue/PR history, and prior Codex/Fable reports. `docs/issues/pr-history.md:25709` explicitly calls the failure-stage overwrite a "pre-existing ... quirk" preserved by PR #1328, but no issue fixes or accepts it. #3789/PR #3832 is materially different: it propagates pre-teardown forwarding-build/map errors specifically because old workers remain live; it does not cover fallible post-teardown worker launch. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S1-RUST-RUNTIME-B2-01`.

### 37. `S1-RUST-RUNTIME-B2-03` - Separate session-delta projection, publication, and retirement under one ordered batch owner
- **Title:** Separate session-delta projection, publication, and retirement under one ordered batch owner
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/session_delta.rs:55`.
  The 301-line `flush_session_deltas` grew from 165 lines at PR #1068 and now has three independently changing domains.
  Lines 85-180 allocate/project `SessionDeltaInfo` and optionally clone it into the one binding-dependent fallback.
  Lines 182-290 perform correctness-critical lossless HA publication plus best-effort close/create RT_FLOW enrichment and policy/AppID re-resolution.
  Lines 291-352 retain recent status, delete forward/reverse BPF and shared-map state, delete dynamic DNAT state, and replicate both keys to sibling workers.
  The out-of-sync latch intentionally bounds lossless waits to one failed push per batch; moving it into a per-delta helper must not reset it.
  No-binding operation is a required ownership contract (#2669), not an edge case: every global consumer and cleanup must still execute.
  Recent fixes #2874, #2979, #3395, #3416, and #3878 touched different sections of this one loop, making cross-domain review increasingly fragile.
- **Proposed decomposition:** **Authoritative adversarial scope:** Keep one batch shell as the owner of iteration order and the first-lossless-failure latch. Extract only private projection, publication, and retirement helpers after failure-order tests. Exclude `queued_flow` movement and the proposed five-module tree. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Delta flush runs on the worker loop under session churn but is not a per-packet cache-hit path. Preserve one batch loop, one `SessionDeltaInfo` construction, the conditional `info.clone()` only when a live fallback exists, and the current bounded lossless wait. Use concrete borrowed context structs or direct parameters, not trait objects/boxed callbacks; add no allocation beyond existing strings/event encoding and no lock held across a newly-expanded scope. These helpers need not be forced out of line, but codegen must show no extra work in `poll_binding` or the descriptor processor. Packet/UMEM ownership stays solely in `purge_queued_flows_for_closed_deltas` and its same-worker recycle route.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Before movement, add a test-only ordered trace around the existing sinks proving the current per-delta sequence, plus failure tests showing an event-stream failure still reaches recent-state and retirement, only one lossless failure is attempted per batch, both forward/reverse keys are removed once, and zero bindings reaches every global consumer. Retain the four passing `flush_session_deltas*` release tests. Gate with `cargo test --release --bin xpf-userspace-dp flush_session_deltas`, session-glue/event-stream tests, and an HA open/close churn run. Measurable gate: identical event frames and cleanup trace, zero added heap allocations per delta, and no more than 2% worker throughput regression in a fixed session-churn benchmark.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** This function is the ownership handoff between a worker-local session table, BPF maps, shared HA state, peer workers, operator status, and two event semantics. Keeping pure projection and distinct sinks inside one 301-line loop makes correctness fixes in one consumer unnecessarily risky to every other consumer.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First add the ordered/failure characterization without production dispatch. Move the pure projection and its golden tests. Move publication while retaining the latch in `mod.rs`. Move retirement last, with forward/reverse deletion-count assertions. Relocate the queued-flow helper only after the session-delta tests and HA churn gate remain green.
- **Labels:** refactor, userspace-dataplane, sessions, high-availability, event-stream, test-gap
- **Dedup note:** Searched `session_delta.rs`, `flush_session_deltas`, `session-delta cluster`, `projection`, `retirement`, and `Issue 67.1` in the dedup index, issue history, and prior reports. PR #1068 only moved the then-165-line function out of `afxdp.rs`; it did not separate sinks, and the current function is 301 lines. #2669/#2874/#2979 and #3878 are behavior fixes whose invariants become characterization gates here, not duplicate decomposition work. `/tmp/codex-review-175.md` recorded a broad negative on delta representation but no current responsibility tree or guarded split. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S1-RUST-RUNTIME-B2-03`.

### 38. `S2GDPB2-01` - Track proxy-ARP applied state so removed interfaces are swept before responder teardown
- **Title:** Track proxy-ARP applied state so removed interfaces are swept before responder teardown
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/dataplane/proxyarp.go:185`, `pkg/dataplane/proxyarp.go:216`, `pkg/dataplane/proxyarp.go:250`, `pkg/dataplane/proxyarp.go:272`, `pkg/dataplane/proxyarp.go:336`, `pkg/daemon/daemon_proxyarp.go:107`, `pkg/daemon/daemon_proxyarp.go:122`, `pkg/daemon/daemon_proxyarp.go:136`.
  `ReconcileProxyARP` derives `managedIfindexes` exclusively from the new config, lists existing `NTF_PROXY` entries only on that set, and removes stale addresses only from those results.
  When the last proxy address is removed from an interface, the daemon deliberately skips `ReconcileProxyARP`; it remembers only `(interface name, family)` sysctl state, diffs it, and writes the responder sysctl to zero.
  The old neighbor entry is therefore outside every subsequent sweep. The file's own kernel-path analysis records that IPv4's pneigh branch can answer an installed `NTF_PROXY` entry without consulting `proxy_arp`, depending on routing topology.
  The core function also returns immediately on the first add failure after earlier map-order-dependent adds may have succeeded, while the daemon replaces its remembered responder set with nil on the error path. There is no single applied-plan or cleanup-debt owner.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain one applied-plan/cleanup-debt owner spanning prior and desired interfaces, deterministic operation order, and promote-on-convergence semantics. Do not scan/adopt all `NTF_PROXY` entries after restart without durable ownership evidence, and do not require a new package before the contract is tested. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This runs on config apply and the existing periodic reassert, not per packet. Keep concrete netlink/sysctl methods, family-specific `netip.Addr` keys, deterministic slices, and one list per `(ifindex,family)` per pass. The applied plan is bounded by configured proxy addresses and introduces no packet allocation, BPF/Rust ABI change, lock on forwarding, goroutine, or dynamic dispatch. Retain the daemon's `applySem -> reconciler mutex` order; do not hold the reconciler lock across GARP transmission.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a fake-kernel two-generation test: `{ifindex 5, 198.51.100.10}` then empty must issue `NeighDel` for that exact key and disable v4, and a third pass must be a no-op. Cover one-of-two interface removal, v6, restart adoption, nth-add/delete/sysctl failures, and retry convergence; no failure may falsely promote the candidate plan or forget cleanup debt. Add a privileged netns test proving `ip neigh show proxy dev <if>` is exactly the desired set after success. Run `go test ./pkg/proxyarp ./pkg/daemon -count=1`, `go test -race ./pkg/proxyarp ./pkg/daemon -run ProxyARP -count=20`; gate on exact kernel set equality and zero stale entries after on-to-empty.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Removing a static-NAT/proxy-ARP address can leave the firewall claiming the retired IPv4 address after the config says it is gone. That can attract traffic to an obsolete translation, misroute a reassigned VIP, or keep an unintended L2 ownership claim until link reset or reboot.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First add the on-to-empty failing test at the current daemon/core seam. Introduce a typed plan/outcome without moving behavior, then move previous-applied state out of `Daemon.proxyARPEnabled`. Add union-of-generations listing and explicit cleanup debt, preserve add/remove/sysctl ordering, and finally add restart adoption plus netns evidence. Do not fold this into the broader dataplane compiler transaction.
- **Labels:** `bug`, `refactor`, `proxy-arp`, `netlink`, `reconciliation`, `security`
- **Dedup note:** Searched the dedup index, prior reports, and issue history for `proxy-arp`, `NTF_PROXY`, `pneigh`, `stale proxy`, `removed interface`, #2160, #2197, and #2475. #2197 added v6 and periodic reassert; #2475 added only remembered sysctl teardown, and its tests assert the disable sink rather than `NeighDel`. No prior tracker or report owns removed-interface proxy-neighbor cleanup or a unified applied-plan outcome. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S2GDPB2-01`.

### 39. `S2GDPB2-02` - Fail config-arrival apply until mapped interface naming and durable ownership converge
- **Title:** Fail config-arrival apply until mapped interface naming and durable ownership converge
- **Severity:** High
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/daemon/device_map.go:132`, `pkg/daemon/device_map.go:186`, `pkg/daemon/device_map.go:213`, `pkg/daemon/device_map.go:217`, `pkg/daemon/device_map.go:225`, `pkg/daemon/device_map.go:236`, `pkg/daemon/device_map.go:274`, `pkg/daemon/device_map.go:282`, `pkg/daemon/device_map.go:593`, `pkg/daemon/device_map.go:607`, `pkg/daemon/daemon_run.go:2059`, `pkg/daemon/daemon_run.go:2067`, `pkg/daemon/daemon_apply.go:613`.
  The mapped naming path is a four-phase host transaction: temp-renames break collisions, durable `.link` files are written, mapped NICs receive final names, stranded NICs are restored, stale files are scrubbed, then networkd reloads.
  `breakNameCollisions` logs temp-rename failures and returns no error. Final rename, stranded restore, and reload failures are also warnings, after which `enumerateAndRenameMapped` unconditionally returns nil.
  The config-arrival state machine consumes `emptyHANamingPending` whenever the top-level call returns nil, so these swallowed failures defeat PR #4182's retry-on-error guard. `applyConfigLocked` ignores the boolean result and continues VRF/interface/dataplane reconcile even when a top-level naming error was returned and the marker stayed set.
  The removal path can fail to rename a NIC back, then delete its `.link`/`.network` ownership record anyway, leaving the kernel under an xpf name with no durable recovery intent.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain a typed naming outcome, durable recovery intent, final-name verification, and abort of dependent VRF/interface/dataplane apply. Reuse `R8B2-NETWORKD-01` as the sole reload/activation-debt owner; physical package movement and a second retry state machine are excluded. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Naming runs at startup, bootstrap exit, or the one config-arrival transition, never on packets. Preserve the current phase order, concrete netlink calls, stable identity resolution, management preflight, and atomic file writer. A bounded operation plan and outcome allocate only on this cold path. No userspace worker, XDP map/ABI, lock/atomic fast path, queue cache line, or interface dispatch changes. The daemon continues to serialize under `applySem`; the new reconciler must not start a retry goroutine that can race config apply.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a deterministic fake host for failures at each temp rename, final rename, stranded restore, manifest write/delete, and reload. Gate: a partial outcome leaves config-arrival pending, `applyConfigLocked` does not enter VRF/interface/dataplane reconciliation, durable ownership is retained for every unverified NIC, and a second identical apply converges without an `xpf-tmp-*` residue. Add process-restart/idempotence tests and a privileged netns collision cycle. Run `go test ./pkg/devicemap/... ./pkg/daemon -run 'DeviceMap|ConfigArrival|Naming' -count=1`, the same packages under `-race -count=20`, and require exact final logical-name/identity and manifest equality.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A logged-but-successful naming pass can wire a cluster config onto nonexistent or wrong interface names, consume the only automatic retry, and continue into dataplane publication. That can strand management, leave a node unable to forward, or bind the wrong physical NIC while the commit path reports no naming error.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: First make every existing phase report structured failures and add fault-injection tests. Change config-arrival naming to return an error/outcome and abort the current reconcile until convergence. Add final-state verification and retained cleanup debt, then move the operation owner into `pkg/devicemap/naming`. Coordinate the reload outcome shape with R8B2-NETWORKD-01, but keep NIC rename identity/collision semantics in this issue.
- **Labels:** `bug`, `refactor`, `device-map`, `netlink`, `startup`, `reconciliation`, `high-availability`
- **Dedup note:** Searched `device-map`, `mapped naming`, `rename failure`, `xpf-tmp`, `config arrival`, `pending naming`, #2004, #2083, #4178, #4179, PR #4182, and R8B2-NETWORKD-01. #2083 fixes low-level `renameInterface` link-up failure; #4178/PR #4182 add collision-safe naming and retain the marker only for errors that reach the caller. #2004 is a closed device-map/RSS layout proposal. R8B2 owns generated networkd activation debt, not swallowed NIC rename outcomes. This finding supplies the missing aggregate actuation result those fixes depend on. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S2GDPB2-02`.

### 40. `S2B3-COMPLETE-03` - Centralize completion behind a backward-compatible UTF-8 cursor contract
- **Title:** Centralize completion behind a backward-compatible UTF-8 cursor contract
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/cli/completion.go:47` receives a readline `[]rune` cursor and correctly forms its prefix with `string(line[:pos])`.  
  The remote adapter does the same conversion but sends `Pos: int32(pos)` at `cmd/cli/shared.go:528-543`, turning a rune index into a position for a UTF-8 string.  
  `pkg/grpcapi/server_cluster.go:420-432` compares and slices that string using byte lengths/indices; non-ASCII text before the cursor can drop suffix bytes or split a code point.  
  The remote `?` listener instead sends `Pos: int32(len(text))` at `cmd/cli/main.go:97-103`, so Tab and `?` already assign different units to the same RPC field.  
  Local `completeConfigWithDesc` (lines 148-204) and gRPC `completeConfigPairs` (lines 568-629) repeat the same config-mode routing and schema calls.  
  Local `valueProvider` (lines 400-577) and gRPC `valueProvider` (lines 631-808) are near-branch-for-branch copies of every `ValueHint`, including tolerant nil handling.  
  Config-mode `run` keeps descriptions locally at line 183, while gRPC converts `CompleteFromTree` names to empty-description pairs at lines 600-609 and relies on a client fallback that cannot preserve every dynamic candidate's metadata.  
  Both surfaces sort the final list, but duplicated sorting/projection means name-description alignment and future hints require parallel fixes.
- **Proposed decomposition:** **Authoritative adversarial scope:** Preserve legacy `pos` as validated byte offset, fix the rune-based caller, and add an explicit prefix or versioned cursor-unit path. Share a prefix-to-candidate engine and value provider while leaving readline/protobuf adapters and both grammar sources in their owners. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Completion is not a packet/reconcile path, but it is keystroke-latency-sensitive. Take `ActiveConfig()` exactly once per request and pass the pointer into the engine/value provider; do not add locks, I/O, goroutines, reflection, protobuf conversion inside the engine, or callback calls per candidate. Continue using concrete slices and one final in-place O(C log C) paired sort. Candidate sets remain finite functions of the command trees and active config. Characterize allocations first and require the extraction not to add a second full candidate copy beyond the adapter's unavoidable rune/protobuf conversion.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add one cross-adapter table that drives identical operational/config lines through local and gRPC completion and compares ordered `(name, description)` pairs. Include multibyte text before/at the cursor, cursor zero/end/past-end/inside-code-point, and identical Tab/`?` behavior; invalid byte boundaries must return `InvalidArgument`, never malformed text or panic. Cover every `config.ValueHint`, nil store/config/zone/policy values, config-mode `run`, dynamic candidates, show-configuration paths, and pipes. Run insertion-order permutations and require deterministic paired output. Fuzz arbitrary UTF-8 plus cursor offsets. Gate with `go test -race ./pkg/clicomplete ./pkg/cmdtree ./pkg/config ./pkg/cli ./pkg/grpcapi ./cmd/cli`, exactly one active-config snapshot per completion, and no allocation increase over a recorded pre-extraction baseline outside adapter conversion.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Remote completion can misparse ordinary non-ASCII descriptions, names, or pasted text, while local completion remains correct. The duplicated 170-plus-line value projection makes schema additions and tolerant-load safeguards easy to update on only one surface, producing hard-to-notice CLI drift.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Pin and document the RPC cursor unit; add failing Unicode and paired-description tests; extract the snapshot-backed value provider; extract prefix-to-candidate coordination and paired sorting; migrate gRPC, then local readline; remove redundant client sorting/fallback only after parity tests pass. Let the later `R7B2-HC-001` command-spec work supply operational nodes to this engine rather than merging the two issues.
- **Labels:** `bug`, `refactor`, `cli`, `grpc`, `completion`, `feature-parity`, `unicode`, `test-gap`
- **Dedup note:** Searched prior reports/tracker/PR history for `completion`, `CompleteRequest pos`, `cursor`, `ValueHint`, `valueProvider`, `cmdtree`, #1319, #1892, #2282, `R7B2-HC-001`, and `R7B2-HC-003`. #2282 covers only negative-position panic validation; #1319/#1892 establish the two grammar SSOTs and help discipline; `R7B2-HC-001` owns executable command grammar. No prior searched item identifies the rune/byte split between the two remote callers or the duplicated config value-provider/coordinator owner. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S2B3-COMPLETE-03`.

### 41. `S2B3-NEIGH-04` - Build one deterministic neighbor snapshot while preserving local and remote profiles
- **Title:** Build one deterministic neighbor snapshot while preserving local and remote profiles
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `pkg/grpcapi/server_show_status.go:200-236` consumes `netlink.NeighList` order directly for both ARP and IPv6 rows.  
  `writeNeighSummary` resolves `LinkByIndex` for every valid row at `pkg/grpcapi/server_helpers.go:332-345`; each gRPC row loop resolves the same index again at lines 212 and 231.  
  Local ARP repeats acquisition and per-row resolution at `pkg/cli/cli_show_routing.go:559-592`.  
  Local IPv6 neighbors repeat summary and row resolution at lines 597-660, including a second lookup for each row.  
  Interface-count maps are sorted for the summary, but neither frontend sorts the actual neighbor rows, so identical kernel state can produce capture-order drift.  
  Local ARP intentionally renders `permanent` flags while gRPC renders full neighbor state; that is a legitimate profile difference, not a reason to duplicate acquisition.  
  The copies also disagree on summary shape while deriving the same totals/state/interface counts from the same semantic rows.  
  No existing test permutes neighbor input or constrains link-resolution calls.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain one request-local semantic snapshot, one link lookup per distinct ifindex, byte-identical dedup only, and a total comparator over every visible row field. Local and remote summary/text profiles remain separate; no universal renderer is approved. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** This is a read-only operator path. Keep one `NeighList` snapshot and no goroutines/locks. A request-local map changes up to two `LinkByIndex` netlink calls per row into at most one call per distinct ifindex; the added O(N log N) in-place row sort is preferable to repeated syscalls and gives stable output. Use concrete row structs and copied string/netip values so no netlink-owned mutable slice escapes. No packet neighbor cache, reconcile order, atomic state, or kernel mutation is touched.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Feed IPv4/IPv6 fixtures in every permutation, including duplicate IPs on different interfaces, nil IP/MAC, unknown state, unresolved ifindex, and permanent entries. Require byte-stable canonical row order, identical summary counts, and exactly one resolver call per distinct valid ifindex. Keep separate local/gRPC golden profiles and assert they consume the same ordered semantic rows. Add a fake resolver error case proving one missing name does not discard other rows. Gate with `go test -race ./pkg/neighview ./pkg/grpcapi ./pkg/cli` and repeated permutation runs (`-count=64`).

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Neighbor tables are compared during routing and HA incidents. Kernel-order drift creates false diffs, while repeated netlink lookups add avoidable latency and failure points exactly when the neighbor table is large. A shared snapshot fixes acquisition/order without forcing local and remote text to match.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Add injectable fixture characterization around both current formatters; define and approve the canonical comparator; introduce the memoized snapshot; migrate gRPC summary/rows, then local IPv6 and ARP; retain profile-specific goldens; finally apply `S2B3-DIAG-02`'s output budget to the remote rendering. Restack this before the diagnostic-output change if both touch `GetSystemInfo`.
- **Labels:** `bug`, `refactor`, `cli`, `grpc`, `routing`, `neighbors`, `determinism`, `performance`, `presentation`, `test-gap`
- **Dedup note:** Searched prior reports/tracker/PR history for `NeighList`, `show arp`, `ipv6-neighbors`, `neighbor order`, `LinkByIndex`, `neighview`, codex-review-171 item 24, fable-review-173 A9 F4, and #1687. Prior show work concerns config/runtime text topics or rejects a universal renderer; packet-path ARP/NDP issues concern learning and forwarding, not this read-only view. No searched item identifies the unsorted local/gRPC rows or duplicated per-row link lookups. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S2B3-NEIGH-04`.

### 42. `S3B1-IPERF-03` - Version and share fail-closed iperf interval metrics across live and final HA gates
- **Title:** Version and share fail-closed iperf interval metrics across live and final HA gates
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B
- **Evidence:** `scripts/iperf-json-metrics.py:149-169` applies the default 0.05 Gbps threshold to every stream, then defines `zero_intervals_total` as aggregate zero intervals plus those per-stream samples.  
  Active documentation requires separate aggregate and per-stream counts at `docs/userspace-ha-validation.md:109-114`, and the shell checks both fields separately at lines 1722-1735.  
  The live `recent_interval_metric` instead uses literal `<= 0.0`, silently skips malformed JSON, and returns success with `0` when no interval is parseable at shell lines 1234-1290.  
  Those zeros make `validate_cycle_health` report all streams carrying and let preflight thresholds pass at lines 1488-1493 and 1526-1539.  
  A targeted fixture at this base made one 10 Mbps interval produce live count `0` but final `zero_intervals_total=2` and `stream_zero_intervals_total=1`.  
  One all-zero interval produced totals `5` at `-P4` and `9` at `-P8`, so the field labeled as an interval count changes with parallelism before the separate stream gate runs.  
  `summarize` spans lines 65-214 and currently couples format parsing, cohort selection, metric schema, and collapse policy with only receiver-summary test coverage.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain a versioned schema with separate aggregate-interval and per-stream-sample units, strict no-complete-interval behavior, stdin/file input, and explicit migration of every caller. This remains separate from `#1661` because the Python helper already has multiple direct consumers outside the assigned failover harness. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Not a packet path: active docs state interval analysis runs on the repo host after iperf capture. The refactor adds no dataplane allocation, copy, branch, dispatch, lock, atomic, ABI, or endianness change. Parse each event once, retain O(intervals + stream samples) concrete lists/sets, sort only serialized keys, and deduplicate stream identities deterministically. A recent-tail call may process fewer events than final summary, but identical events and thresholds must yield identical metrics. Do not add pandas/numpy or nondeterministic hashing to the output contract.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Build checked-in fixtures for TCP/UDP, push/reverse, whole JSON/JSON-stream, reordered streams, duplicate socket IDs, 0/10/50/just-over-50 Mbps, partial terminal interval, absent start/end, iperf error, truncated line, malformed number, and no complete interval. Require whole/stream formats and live/final cohorts to agree for identical events; missing/malformed live evidence exits nonzero; aggregate counts are independent of `-P`; stream-sample counts and deduplicated stream IDs have explicit deterministic expectations. Preserve received-summary preference and retransmits. Run the package unit suite plus `scripts.userspace_ha_validation_matrix_test`, `bash -n`, and `shellcheck`; then run strict IPv4/IPv6 push/reverse and one failover Gate 6 with old/new JSON recorded for an intentional schema comparison.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** These fields decide whether a baseline is healthy enough to mutate the cluster and whether a failover run is accepted. Two parsers currently disagree on what zero means, while one metric mixes two units and can report a healthy live tail when no usable event was parsed. That weakens attribution and makes results across `-P` values non-comparable.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Freeze current outputs in fixtures; approve the corrected versioned field meanings; extract parser/model without behavior change; add strict recent mode; migrate every direct caller to explicit fields; switch the failover preflight and final path together; retain aliases for archived tooling; remove the embedded Python parser only after parity and live gates pass.
- **Labels:** `bug`, `refactor`, `test-infrastructure`, `iperf3`, `metrics`, `determinism`, `fail-closed`, `ha`, `test-gap`
- **Dedup note:** Searched prior reports and issue/PR history for `iperf-json-metrics`, `recent_interval_metric`, `zero_intervals_total`, `stream_zero_intervals_total`, `50 Mbps`, `collapse_detected`, and `throughput collapse`. PR history documents that final counters are thresholded at 50 Mbps and prior HA failures, but no tracker defines aggregate-versus-stream units, aligns the live parser, or requires parseable live evidence. #1661's broad harness package item does not own the separately reused Python parser or its four direct callers. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S3B1-IPERF-03`.

### 43. `S4LTB1-OWNER-03` - Finish the cluster production split by co-locating its remaining tests
- **Title:** Finish the cluster production split by co-locating its remaining tests
- **Severity:** Low
- **Confidence:** High
- **Refactor class:** A
- **Evidence:** `pkg/cluster/cluster_test.go:30-2227` contains 72 flat tests with no subtests, skips, or parallel markers.  
  The tested owners are now separate: `manager.go:292-394`, `group_state.go:13-217`, `election.go:410-455`, `failover.go:40-848`, `status.go:11-99`, and `heartbeat_manager.go:294-468`.  
  Tests at `cluster_test.go:43-163` cover config publication; `171-249` cover monitor/election weight; `268-1378` cover failover transfer and rollback; `1380-1468` cover status.  
  `cluster_test.go:1492-2023` covers reset/group snapshots/priorities/events and `2024-2227` covers election, peer timeout fencing, and fence status.  
  `makeConfig` and `makeRG` live at `cluster_test.go:14-28` even though seven other test files consume them. Moving `cluster_test.go` before those fixtures would break package test compilation.  
  Runtime discovery found exactly 72 terminal leaves, so Go file relocation can preserve the complete leaf set without introducing nested names.  
  This is leftover test ownership after closed issue #1541 and merged PR #1575 split the production manager into election, heartbeat, failover, and status modules.
- **Proposed decomposition:** **Authoritative adversarial scope:** `#1541`/PR `#1575` explicitly left test files unmoved, so this is not duplicate production work. Extract the two shared fixtures, move complete tests to existing same-package owners, preserve all names, and require full package race/shuffle validation. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Test-file relocation is not a production hot-path change and does not alter interface width, allocation/escape behavior, goroutine creation, mutex ownership, heartbeat timing, election/reconcile ordering, failover transaction publication, rollback/fail-closed behavior, or API/CLI/gRPC output. Package test compilation must show no new init state. The race and shuffle gate protects against hidden file-order, lock, or shared-fixture coupling.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Capture sorted `go test -list '^Test' ./pkg/cluster` output and `go test -json` terminal leaf identities before the move; require the same 72 candidate names and the same 391 package top-level tests afterward. Run a regex containing all moved names, then `go test -race -shuffle=on -count=1 ./pkg/cluster`. Gate on zero discovery delta, no duplicate tests, no race, and all package tests passing. The audit’s current-base candidate run and full package race/shuffle run both passed.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Reviewers currently have to search a historical catch-all to find tests for six production owners, while two globally shared fixtures are accidentally owned by that catch-all. Completing test co-location makes production changes and their guards reviewable together without changing behavior.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Extract shared fixtures first and prove all eight consuming files compile. Record the exact 72-name baseline. Move one owner cluster per commit, appending to an existing owner test file where one already exists, and run race/shuffle after each move. Delete `cluster_test.go` only after an inventory accounts for every leaf and helper.
- **Labels:** `testing`, `go`, `cluster`, `refactor`
- **Dedup note:** Searched the dedup index and prior reports for `cluster_test.go`, `manager_test.go`, issue #1541, PR #1575, `election_test.go`, and `test ownership`. Prior `fable-review-173` A7 material mapped the former giant `manager_test.go` and tracker #1541/PR #1575 split production ownership; no prior report records this current 72-test residue or the seven-file fixture dependency. This is the mechanical completion of that closed production split, not a duplicate proposal to split the manager again. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `S4LTB1-OWNER-03`.

## Medium Confidence (4)

### 44. `R2-b2-06` - Require a router for every foreign prepared-frame recycle
- **Title:** Require a router for every foreign prepared-frame recycle
- **Severity:** High
- **Confidence:** Medium
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/afxdp/tx/transmit/mod.rs:22` accepts `Option<&mut Vec<(slot, offset)>>` for cancellation recycling.
  For foreign `FillOnSlot` variants, lines 39-46 route correctly only when the option is `Some`; `None` silently pushes the RX-origin offset into the current binding's TX free-frame pool.
  `types/tx.rs:167` encodes the required fill owner and, for descriptor-view rewrites, a distinct original recycle offset, so local-free fallback contradicts the value's ownership contract.
  Assigned `cos_classify.rs` propagates this optional sink through local/prepared enqueue, demotion, and admission-drop paths at lines 759, 899, 1013, and 1164.
  Current production callers that can carry foreign prepared frames were traced to `Some(shared_recycles)` (for example `tx/drain/mod.rs:398-416`); no live omission was found.
  The existing unknown-slot path in `session_glue/mod.rs:855-872` correctly fails closed and counts instead of inventing local ownership.
- **Proposed decomposition:** **Authoritative adversarial scope:** `tx/transmit/mod.rs:22` makes a foreign-recycle sink optional, although current live callers supply it. Retain a mandatory borrowed concrete routing value and a fail-closed local-only API; exclude a broad completion-routing move and lower the claim from a live corruption bug to an API guardrail. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** A mandatory borrowed sink removes the option branch and uses the already preallocated worker-loop recycle vector, so it adds no allocation, copy, lock, atomic, refcount, or dispatch. A concrete router should inline to the existing match. Preserve deferred cross-binding application so mutable binding borrows remain non-overlapping and exactly-once fill ownership remains explicit.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add a full matrix for `FreeTxFrame`, same-slot `FillOnSlot`, foreign slot, and `FillOnSlotWithOffset`; assert no foreign value can enter `free_tx_frames`. Add cancellation, CoS admission-drop, runtime-reset, unknown-slot, and descriptor-view frame-conservation tests. Run the shared-UMEM Rust tests and both private/shared XSK repros, then a cross-NIC shared-UMEM failover smoke requiring `tx_shared_recycle_unknown_slot_drops == 0`, stable total frame count, and no copy-path regression.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** If a future caller omits the optional sink, the origin fill ring loses a descriptor while another binding treats that RX frame as TX-owned. That can starve RX and eventually create duplicate or cross-owner frame use rather than a bounded drop.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Add the router and characterization matrix first. Migrate cancellation/admission paths while all current callers still pass a sink. Remove optional parameters and the local-free fallback, then consolidate completion routing only after frame-conservation tests pass on shared UMEM hardware.
- **Labels:** `afxdp`, `umem`, `tx`, `ownership`, `memory-safety`, `refactor`, `test-gap`
- **Dedup note:** Searched `recycle_cancelled_prepared_offset_with_shared`, `FillOnSlotWithOffset`, `shared recycle`, `unknown slot`, `foreign recycle`, and `free_tx_frames`. PR #1301 fixed live cancellation call routing and validated shared UMEM; this is a narrower guardrail that makes omission unrepresentable. It does not claim the fixed production path is currently corrupting frames. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R2-b2-06`.

### 45. `R2-b2-07` - Make XSK ring reservation guards linear
- **Title:** Make XSK ring reservation guards linear
- **Severity:** High
- **Confidence:** Medium
- **Refactor class:** B
- **Evidence:** `userspace-dp/src/xsk_ffi.rs:934` indexes TX writes from `base_idx + written`, but `WriteTx::commit(&mut self)` at line 952 resets `written` to zero while retaining any unused reservation and the original base.
  After a partial commit, another `insert` can therefore overwrite the already submitted prefix instead of writing after it; `WriteFill` repeats the state machine at lines 994-1025.
  `ReadRx::release(&mut self)` at line 889 leaves the guard readable after releasing its consumed prefix, with `base_idx`, `peeked`, and `read_count` still representing the old reservation.
  `ReadComplete::release(&mut self)` at line 1051 resets `read_count` and shrinks `peeked` without advancing `base_idx`, so subsequent reads restart at an already released slot.
  Current production sites call commit/release once and immediately `drop`; no active reuse was found.
  The seven XSK tests cover multiple inserts before one commit, but neither post-commit/post-release reuse nor reader guard lifecycle.
- **Proposed decomposition:** **Authoritative adversarial scope:** `xsk_ffi.rs:934-1051` leaves reservation guards usable after commit/release even though callers use them once. Consuming finish methods are a distinct linear-resource API boundary; keep this separate from, but sequence it before or with, R2-b2-01. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Consuming guards is a compile-time ownership restriction. It adds no allocation, branch, FFI call, dynamic dispatch, lock, atomic, or layout indirection; it can remove the `released` state check. Existing call sites merely delete explicit `drop(guard)` after finish, and libxdp submit/release/cancel ordering stays identical.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add TX/fill tests that commit a strict prefix and prove the remaining reservation is canceled exactly once, plus RX/completion tests for partial read/release and unread cancellation. Add compile-fail coverage or API signature checks proving insert/read cannot follow finish. Run all XSK tests under Miri where the synthetic backing permits, ASan/UBSan for the C bridge, and the private/shared repros; require producer/consumer indices and descriptor contents to match exactly across wraparound.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Ring reservations are linear resources. Allowing a safe Rust guard to outlive commit/release leaves descriptor overwrite and double-accounting states representable, even though current callers happen to follow the intended one-shot convention.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Add lifecycle tests against the current implementation, change writer finish methods and callers, then reader methods and callers. Land before or together with R2-b2-01 so the safe Rust facade is settled before the raw ring representation becomes opaque.
- **Labels:** `afxdp`, `xsk`, `ownership`, `memory-safety`, `api`, `test-gap`
- **Dedup note:** Searched `commit consume`, `release consume`, `linear guard`, `partial commit`, `after commit`, `base_idx`, `double release`, and `double commit`. PR #2383 fixes multiple `insert()` calls before one commit; this finding is the distinct after-commit/release lifecycle. Closed `#253` records general libxdp semantic lessons but not this type-state gap. Campaign disposition: **IN-SCOPE-NEW**. Canonical issue `R2-b2-07`.

### 46. `R3B2-SCREEN-01` - Join each zone screen profile and mutable flood state under one owner
- **Title:** Join each zone screen profile and mutable flood state under one owner
- **Severity:** Medium
- **Confidence:** Medium
- **Refactor class:** C
- **Evidence:** `userspace-dp/src/screen/mod.rs:162`
  `ScreenState` stores the profile and flood/cookie state in thirteen hot/config `FxHashMap<String, _>` tables, plus separate missing-profile maps.
  `update_profiles` at lines 400-495 manually retains and prepopulates every parallel table; adding a field requires preserving several implicit lifecycle rules.
  The ICMP and UDP paths each look up the profile, destination sketch, and aggregate bucket by the same string on a screened packet (lines 648-727 and 798-900).
  A fully configured initial-SYN path separately probes profile generation, aggregate counter, destination sketch, active window, alarm cadence, and source sketch after the profile lookup (lines 922-1072).
  Missing table entries generally become `false`, `0`, or `Pass`, so refresh drift can silently disable a configured limiter instead of failing at construction.
  The production caller has already resolved a stable `zone_id: u16` and passes it beside the name (`afxdp/poll_stages.rs:431-447,601-608`), but most hot state ignores it.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain one `ZoneScreenState` joining profile and mutable flood/cookie state around `screen/mod.rs:162`, initially with existing name keys. Defer numeric IDs until `#4421` supplies a stable ID/name/profile join and ID-reuse contract. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Use the existing `u16` identity and an integer-keyed `FxHashMap`; do not introduce a 65,536-slot dense table, `Arc`, trait object, interior mutex, or per-packet allocation. `SynRateSketch` allocations remain optional and refresh-only, and all worker-local counters remain non-atomic. Borrow `zones` and the global cookie runtime as disjoint fields so SYN-cookie validation does not force repeated zone-map lookup. Preserve stateless-before-rate ordering, aggregate/destination/source precedence, fabric skip behavior, cookie generation invalidation, audit-mode semantics, and scan trackers' existing numeric keys. Event text may continue to use the caller's cold zone name.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Before moving state, add a profile-refresh state-machine test covering add, unrelated edit, threshold enable/disable, SYN-cookie signature change, removal, ID reuse, and unresolved-profile recovery; assert counters/sketches are preserved or reset exactly as today. Retain all screen tests, especially `syn_flood_sketches_allocated_only_when_configured`, cookie cache-generation invalidation, `update_profiles_prepopulates_syn_cookie_active_state`, `update_profiles_clears_stale_counters`, flowless flood parity, fabric suppression, and scan cleanup. Add criterion/perf coverage for stateless pass, ICMP, UDP, initial SYN below threshold, and cookie-active SYN; require no per-packet allocations, no dynamic dispatch, and no cycles/packet or throughput regression, with the normal flood paths performing one zone-state lookup. Run the full userspace test suite and screen-enabled cluster throughput/failover validation before merge.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** Screen runs before session processing whenever profiles exist, so redundant dependent string lookups are paid at packet rate and are most expensive during the floods this code must withstand. More importantly, the current security behavior depends on parallel-map construction staying synchronized; a missed prepopulation step converts a configured limiter into a fail-open branch.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Establish refresh/equivalence and performance baselines, introduce `ZoneScreenState` while retaining string keys, then switch the single outer map to resolved numeric IDs once snapshot construction supplies the join. Keep `check_packet_with_zone_id_opts` behavior unchanged during this issue; the separately reported function decomposition can consume the new state object later.
- **Labels:** `rust`, `userspace-dp`, `screen`, `ddos`, `syn-cookie`, `hot-path`, `state-ownership`, `performance`, `refactor`
- **Dedup note:** Searched the full shared dedup index for `ScreenState`, screen maps/counters, zone state/ID, string-keyed state, SYN flood, and `check_packet_with_zone_id`. Closed `#1543`, prior `F-138`, and `fable-review-173` F10 propose source/module extraction of the inline SYN-flood body; `codex-review-174` rejects a naive `scan.rs` split. No prior report or tracker consolidates the parallel per-zone maps, changes their key/ownership, or removes repeated hot-path hashes. This finding is independent of the prior function-length report. Campaign disposition: **REVISE-SCOPE**. Canonical issue `R3B2-SCREEN-01`.

### 47. `S1-RUST-RUNTIME-B2-04` - Measure four-way flow-cache probe cost against the actual 496-byte entry layout
- **Title:** Measure four-way flow-cache probe cost against the actual 496-byte entry layout
- **Severity:** Low
- **Confidence:** Medium
- **Refactor class:** C
- **Evidence:** `userspace-dp/src/afxdp/flow_cache.rs:5`.
  The source performance model says four `~96 B` entries make a set touch about six cache lines (lines 6-12).
  Release `-Zprint-type-sizes` at the immutable base measured `FlowCacheEntry` and `Option<FlowCacheEntry>` at 496 bytes each, with a 232-byte rewrite descriptor and 80-byte metadata.
  The 4,096-slot entry vector therefore reserves 2,031,616 bytes (about 1.94 MiB) per binding before the 4 KiB LRU vector.
  Rust's current release layout places the 40-byte key far from the 4-byte ingress discriminator and large payload, while lookup lines 866-921 scans up to four strided entries before payload use.
  No existing `userspace-dp/benches` target measures flow-cache hit, same-set miss, collision, or L1D behavior; tests establish semantics only.
  Release `nm` showed no standalone lookup symbol, confirming it is inlined, while `poll_binding_process_descriptor` is already 89,070 bytes and `FlowCache::insert` is 2,216 bytes.
  The size drift is objective, but the throughput benefit of a probe/payload split is not yet measured; implementation must remain conditional on the benchmark.
- **Proposed decomposition:** **Authoritative adversarial scope:** Retain only the stale-size correction and a release benchmark of the real hash, four-way probe, validation, MRU update, hit use, and miss path. No production layout change is approved; a compact layout needs a later Class-C proposal meeting the stated cycle/L1 and MRU-regression gates. This scope overrides any broader directory/package proposal in the primary pass.
- **Hot-path preservation analysis:** Preserve four compile-time ways, seeded hashing, LRU semantics, one startup allocation for the set vector, no allocation on lookup/insert, no lock or atomic beyond the existing relaxed RG epoch load, no trait object, and no extra pointer-indirect payload allocation. A miss should touch only the compact probe array; a hit may then touch one metadata/payload way. Keep lookup `#[inline]` and verify it remains folded into the descriptor processor. The types have no FFI/wire ABI, but add compile-time probe size/alignment assertions and do not pin the large payload with `repr(C)` unless measurements require it. Endianness remains localized in `SessionKey` construction; the cache stores typed host values.

Campaign-wide mandatory gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Tests + gate:** Add `[[bench]] name = "flow_cache"` with current and compact shapes at 25/50/90% load: MRU hit, LRU hit, random miss, adversarial four-way same-set miss, insert/dedup, and fifth-key eviction. Run Criterion plus `perf stat -e cycles,instructions,branches,branch-misses,L1-dcache-loads,L1-dcache-load-misses` on a pinned core, and retain all 76 passing `flow_cache` release tests. Require at least 10% lower cycles or L1D misses for the dominant miss/collision profiles, no more than 2% regression for MRU hits, no memory growth, identical LRU/stamp/epoch behavior, and no standalone lookup call in `nm`/disassembly. If those gates fail, retain the current class-D layout and only correct the stale comment.

Campaign-wide merge gate: The implementation must be RED-on-revert and machine-failing. For packet/worker paths, use the actual no-LTO multi-codegen-unit release profile, prove zero new warmed-path allocations or indirect dispatch, inspect assembly/stack/layout where movement crosses a codegen boundary, and reject more than 1% paired median cycles/packet or throughput regression. Preserve exact descriptor/UMEM ownership, endianness, wire layout, atomic ordering, cache-line ownership, branch shape, and fail-closed semantics. Cold-path work must instead prove deterministic operation order, idempotent retry, and exact attempted/applied/debt state under injected failures.
- **Why it matters:** A flow-cache miss is on the forwarding path and can inspect four candidates; the actual per-binding working set is over five times the size assumed by the code comment. A compact probe front may reduce cache pressure, but changing a successful inlined data structure without data would be more dangerous than the current drift.
- **Fix direction:** Implement only the authoritative scope above. The primary implementation sequence, where consistent with that scope, was: Land the side-by-side benchmark and release layout report first. Collect pinned-core baseline distributions and emitted-code evidence. Prototype the set-local probe/metadata/payload shape without changing behavior. Adopt it only if every performance and semantic gate passes; otherwise close the structural experiment and update the source model to 496-byte entries.
- **Labels:** performance, refactor, userspace-dataplane, flow-cache, benchmark
- **Dedup note:** Searched `flow_cache.rs`, `496`, `compact probe`, `cache layout`, `set associative`, and `FlowCacheEntry` across the dedup index and prior reports. #918/PR #919 introduced four-way associativity and must be preserved; #2364 concerns seeded hashing, not entry layout. `/tmp/fable-review-173.md` marked the cohesive module D/CLEAN but did not measure the 496-byte release layout or propose a benchmark-gated set-local probe split. Prior Fable F-154/session-liveness work was fixed by #3776/PR #3806 and is independently covered by reap invalidation tests; it is not this performance candidate. Campaign disposition: **REVISE-SCOPE**. Canonical issue `S1-RUST-RUNTIME-B2-04`.

## Low Confidence (0)

No Low-confidence candidate survived dedup and adversarial scope review.

## D-class boundaries to preserve

These boundaries are tempting because they are large or contain phases, but splitting them would weaken locality, transaction ownership, or verifier/codegen behavior. Several were omitted from primary retained findings and should be recorded as negative design constraints.

1. **Flow-cache hit stage:** `poll_descriptor/flow_cache_hit.rs::stage_flow_cache_hit` must remain one fused, monomorphic packet stage. Do not split hit validation, rewrite, accounting, and fallback behind a wide context, trait, or phase calls.
2. **Policy evaluation core:** keep `policy.rs::evaluate_policy_result_l3_aware` and `try_match_rule` local/concrete with v4/v6 const folding. Do not introduce rule traits, iterator adapters, or separate callback-owned match phases.
3. **Session transaction:** `session::update_session`, canonical/reverse alias maintenance, and `remove_entry` ownership must remain cohesive until a measured transactional store replaces them. Do not box hot/cold halves or add pointer chases merely to shrink the type.
4. **CoS lease CAS:** `acquire_v8_with_cause` and epoch-carry rotation's CAS/check/rollback sequence is one synchronization transaction. Module privacy may tighten, but the state transition must not split across owners.
5. **Typed CoS service:** Local and Prepared exact/non-exact service/drain leaves must remain separately monomorphized. A generic trait or closure unifying them risks indirect calls, spills, and ambiguous recycle ownership.
6. **Binding lifetime anchor:** `BindingLiveState` remains the owner of lifetime/drop/layout-sensitive fast state. Do not split it into independently allocated objects without cache, pointer, and destructor proof.
7. **Frame rewrite leaves:** family-specific checksum/build/rewrite commit leaves stay codegen-local and infallible after preflight. Do not genericize checksum or frame-family mutation across a trait/TU boundary.
8. **Screen scan engine:** the generic bounded tracker in `screen/scan.rs` is a cohesive monomorphized algorithm. Do not split its heap/index/accounting phases or replace it with dyn dispatch.
9. **NAT destination index:** exact/LPM destination lookup and its cold builder remain one locality boundary. Do not interpose family traits or move endianness conversion into the packet lookup.
10. **WireGuard packet engine:** production encapsulation, session/demux ownership, and reconcile lock ordering must stay together; test seams must not become packet-path interfaces.
11. **Event ACK transaction:** frame class, sequence continuity, decode outcome, dispatch acceptance, and cumulative ACK watermark are one owner. Codec files may move, but no independent module may advance the watermark.
12. **Flow-export sampling/admission:** acquire at most one generation lease per protocol callback, outside per-instance/template loops. Sampling once per instance and batch submission order must not be split into independently locked group owners.
13. **Strict/tolerant compiler order:** `runPreWalkGates`/uniform gates retain source order, first-error precedence, warnings, and fail-closed fallback as one ordered pipeline. Do not parallelize validators or let domain packages publish partial config.
14. **Daemon apply/bootstrap:** `applySem` remains the single apply transaction, and `pkg/daemon/bootstrap.go` remains one ordered fail-safe bootstrap/teardown state machine. Do not lock or package each subsystem independently.
15. **HA failover state machine:** RG transition computation/epoch validation/actuation in `pkg/daemon/daemon_ha.go` remains one state owner until a complete state-machine extraction lands. Individual side effects cannot gain independent locks.
16. **RA replacement decision:** under `pkg/ra`, supersession decision plus replacement registration stays atomic under the manager mutex; joins, close, and NDP writes stay outside it.
17. **DDNS exact ownership:** ownership record, original backend identity, exact-RR delete, and per-call backend state are one serialized transaction. Do not split provider calls from the ownership decision while the backend remains mutable.
18. **Routing dedup/priority:** semantic canonicalization, stable first-seen dedup, and finite-window priority assignment form one plan. Assigning priorities in a later independently mutable phase reintroduces overflow loss.
19. **XDP verifier boundary:** `try_xdp_userspace` remains one XDP program. Source modules are allowed; BPF subprogram/tail-call decomposition is not.

## Sequenced Issue Split

### Wave 0 - Characterization, provenance, and machine gates

1. `R2-B1-04` - Delete the test-only unified guarantee scheduler and test production selectors
2. `R2-B1-05` - Make epoch-carry rotation ownership a Rust privacy boundary
3. `R6B2-04` - Establish a populated Go-Rust wire contract before decomposing protocol DTOs
4. `R10-B1-001` - Retire orphaned BPF implementation headers after relocating live ABI ownership
5. `R10-B1-003` - Gate the tracked XDP object against an explicit source and toolchain provenance manifest
6. `R10-B1-006` - Split the fairness suite by owned executable and wire it into self-test discovery
7. `R10-B1-007` - Make the refactoring heatmap a scope-complete enforced generated gate
8. `S1-RUST-RUNTIME-B2-04` - Measure four-way flow-cache probe cost against the actual 496-byte entry layout
9. `S3B1-IPERF-03` - Version and share fail-closed iperf interval metrics across live and final HA gates
10. `S4LTB1-OWNER-03` - Finish the cluster production split by co-locating its remaining tests

### Wave 1 - Security, transaction, lifecycle, and fail-closed ownership

1. `R2-b2-01` - Hide libxdp ring layouts behind the C boundary
2. `R2-b2-06` - Require a router for every foreign prepared-frame recycle
3. `R2-b2-07` - Make XSK ring reservation guards linear
4. `R5B1-GATE-01` - Route section-level semantic rejects through the strict/tolerant gate policy
5. `R6-b1-01` - Track successful peer application separately from active-store equality
6. `R6-b1-02` - Own HA communications as a cancellable, joined generation
7. `R6B2-01` - Make shim-map and helper-snapshot publication one fail-closed transaction
8. `R6B2-02` - Split pure compilation from host and shim actuation before publishing
9. `R8-B1-02` - Scope RA supersession generations to per-interface intent
10. `R8B2-NETWORKD-01` - Retain networkd reload and reconfigure debt across identical applies
11. `S1-RUST-RUNTIME-B2-01` - Preflight all AF_XDP worker thread creation before destructive reconcile commit
12. `S2GDPB2-01` - Track proxy-ARP applied state so removed interfaces are swept before responder teardown
13. `S2GDPB2-02` - Fail config-arrival apply until mapped interface naming and durable ownership converge

### Wave 2 - Measured hot-path and bounded-memory improvements

1. `R2-B1-01` - Reuse non-exact CoS batch deques across service visits
2. `R2-b2-02` - Remove heap work from TX retry and partial-submit recovery
3. `R3B2-SCREEN-01` - Join each zone screen profile and mutable flood state under one owner
4. `R4-b1-03` - Reuse worker scratch for pending-neighbor key sweeps
5. `R4-b1-04` - Index tunnel replay purge membership before filtering sessions
6. `R4B2-02` - Replace event-stream prefix drains with a cursor-backed write backlog
7. `R6-b1-04` - Replace per-apply aggregation callbacks with one owned subscription
8. `R7B2-HC-002` - Extract one bounded, case-preserving CLI output pipeline
9. `R2-b2-03` - Eliminate warmed CoS Arc churn and settlement allocation across selection and settlement

### Wave 3 - Cold-path modularity, operator surfaces, and cleanup

1. `R1B2-02` - Make in-place rewrite failure atomic before any UMEM byte is committed
2. `R1B2-04` - Unify frame-derived filter match inputs behind one metadata-neutral builder
3. `R2-b2-04` - Separate consuming redirect enqueue from ownership-preserving enqueue
4. `R4B2-01` - Make shared-session publication one observable transaction
5. `R5B1-DIAG-02` - Publish one immutable deterministic warning snapshot to every operator surface
6. `R5B2-IPMON-01` - Extract atomic IP-monitoring analysis from the mutating strict validator
7. `R7B2-HC-001` - Make one typed command specification own local and remote CLI grammar
8. `R7B2-HC-003` - Replace the delimiter-encoded ShowText request grammar with typed domain requests
9. `R8-B1-03` - Make session-sync publication and cold-prime ownership generation-aware
10. `R9B2-001` - Make flow-export generation retirement wait for callbacks admitted to the old bundle
11. `R10-B1-004` - Package xpf-deploy by backend and rollout transaction while preserving the command path
12. `R10-B1-005` - Modularize and adopt the cold-path flooder under explicit build and performance gates
13. `S1-RUST-RUNTIME-B2-03` - Separate session-delta projection, publication, and retirement under one ordered batch owner
14. `S2B3-COMPLETE-03` - Centralize completion behind a backward-compatible UTF-8 cursor contract
15. `S2B3-NEIGH-04` - Build one deterministic neighbor snapshot while preserving local and remote profiles

Rules for splitting work:

1. Land Wave 0 guardrails before moving packet-loop, ABI, protocol, compiler, or giant-test ownership.
2. Keep each Wave 1 transaction owner in a separate PR unless one finding explicitly says it shares a generation owner; do not merge unrelated lifecycle locks into a global framework.
3. Require paired release-profile performance evidence for every Wave 2 PR; source-level claims are insufficient.
4. Perform package/file moves only after behavior and ownership tests are RED-on-revert. Use domain directories (`feature/*.rs` or `feature/*.go`), not flat `feature_foo` proliferation, when a real multi-file owner is approved.
5. Route correctness-only drops to their current owners without a refactor label; do not lose them, but do not reopen rejected architecture to fix them.

## Primary Raw-Disposition Ledger

## Complete Disposition Table

| Raw ID | Disposition | Audited scope, source, and dedup result |
|---|---|---|
| R1B2-01 | **DROP-CORRECTNESS-ONLY** | `frame/inspect.rs:1373` can trust ports outside the IP-declared datagram. Add the declared-end predicate to the existing cohesive parser and its malformed-packet tests; `frame/inspect/session_meta.rs` is incidental. This is a residual of closed `#2361`, not a parser-refactor issue. |
| R1B2-02 | **REVISE-SCOPE** | `frame/mod.rs:520` can mutate bytes before a later decline. Retain only fail-before-write/preflight-and-infallible-commit semantics with byte-identical `None` tests. Do not approve broad rewrite-plan structs until stack size, constant folding, call shape, and release assembly are pinned. |
| R1B2-03 | **DROP-DUPLICATE** | Closed `#1163`, **Recursive String-Based Routing Lookups Should Use Precomputed ID-Based Resolution**, already owns string `next_table` removal, integer IDs, and flattened/iterative lookup. Open `#4421` additionally owns `ForwardingState` representation. `forwarding/mod.rs:1970` is not a new deliverable. |
| R1B2-04 | **REVISE-SCOPE** | The duplicated frame-to-filter projection at `frame/inspect.rs:535` is real, but retain one private scalar helper in `inspect.rs`, not a one-function `filter_view/` directory or a forced `ForwardPacketMeta` materialization. |
| R2-B1-01 | **REVISE-SCOPE** | Retain reusable, separately typed Local/Prepared deques in existing worker scratch for the paths at `queue_service/mod.rs:1775-1901`. Exclude the proposed `batch/` tree and require post-warmup zero reallocations plus unchanged retry/recycle order. |
| R2-B1-02 | **IN-SCOPE-MERGE (MG-01: R2-B1-02 + R2-b2-03)** | The shared exact-backlog `Arc` churn at `queue_service/mod.rs:261-303` is the same ownership work as R2-b2-03. It becomes one audited clone/settlement inventory, not a second issue. |
| R2-B1-03 | **DROP-WEAK** | `forwarding_build/cos.rs:3-779` is a cohesive cold materialization/admission transaction produced by `#1342`/PR `#1577`. Its 291-line body and ordering comments do not justify six modules without a reusable intermediate or independently published phase. |
| R2-B1-04 | **REVISE-SCOPE** | Retain migration of assertions to production selectors and deletion of the alternate test-only scheduler/cursor at `queue_service/tests/selector.rs:18-994`. Exclude the unrelated test-directory split already covered generically by codex-review-171 finding 29. |
| R2-B1-05 | **REVISE-SCOPE** | Retain only the minimum sibling-module topology needed to make epoch carry private around `shared_cos_lease_tests.rs:1836-1881`; do not move equal-flow publication or atomics for directory symmetry. `#1329` and `#2158` own the broad split, not this compiler-enforced privacy increment. |
| R2-b2-01 | **IN-SCOPE-NEW** | `xsk_ffi.rs:17` mirrors native libxdp ring layouts in Rust. C-owned allocation/free with opaque Rust handles is a real ABI owner and can preserve the existing per-operation FFI count and socket-before-UMEM destruction order. |
| R2-b2-02 | **IN-SCOPE-NEW** | `tx/transmit/mod.rs:17` allocates owned error strings and takes status locks on expected retry/partial-submit paths. A copyable outcome plus existing scratch has a measurable zero-allocation/zero-lock boundary and no prior owner. |
| R2-b2-03 | **IN-SCOPE-MERGE (MG-01: R2-B1-02 + R2-b2-03)** | `tx/dispatch/mod.rs:690` and related settlement paths clone fast-path `Arc`s and allocate scratch. Merge R2-B1-02 into this issue; keep changes in existing files unless a later ownership split is independently justified. |
| R2-b2-04 | **REVISE-SCOPE** | At `umem/mod.rs:1153`, consuming and ownership-preserving enqueue contracts are obscured. Retain explicit in-place API names and return an outcome only where consumed; exclude a directory for two wrappers and preserve `#715` drop-newest behavior. |
| R2-b2-05 | **DROP-DUPLICATE** | Fable-review-173 **A3-F6** already identifies the same `cos_classify.rs` functions, calls the file cohesive, and prescribes guarded within-file selection-stage decomposition with no new file. The raw selection/preparation/admission tree supplies no independently evidenced increment and contradicts that prior boundary. |
| R2-b2-06 | **REVISE-SCOPE** | `tx/transmit/mod.rs:22` makes a foreign-recycle sink optional, although current live callers supply it. Retain a mandatory borrowed concrete routing value and a fail-closed local-only API; exclude a broad completion-routing move and lower the claim from a live corruption bug to an API guardrail. |
| R2-b2-07 | **IN-SCOPE-NEW** | `xsk_ffi.rs:934-1051` leaves reservation guards usable after commit/release even though callers use them once. Consuming finish methods are a distinct linear-resource API boundary; keep this separate from, but sequence it before or with, R2-b2-01. |
| R3B2-NAT-01 | **DROP-DUPLICATE** | Open `#4409` explicitly owns `PortAllocator`/source-NAT decomposition and allocator extraction. The common deterministic claim primitive at `nat/allocator.rs:1297` is an acceptance increment to `#4409`, not another issue. |
| R3B2-SCREEN-01 | **REVISE-SCOPE** | Retain one `ZoneScreenState` joining profile and mutable flood/cookie state around `screen/mod.rs:162`, initially with existing name keys. Defer numeric IDs until `#4421` supplies a stable ID/name/profile join and ID-reuse contract. |
| R4-b1-01 | **DROP-CORRECTNESS-ONLY** | `coordinator/mod.rs:424` stops but does not join neighbor monitor/warmer work before reset. The existing `NeighborManager` should own both task slots and joins; creating another manager/module is incidental. Broad neighbor movement is already under `#985/#4421`. |
| R4-b1-02 | **DROP-CORRECTNESS-ONLY** | Poisoned shared-session maps can be skipped at `coordinator/mod.rs:557`. Add poison-recovering snapshot/clear methods to the existing `SessionManager`; do not couple this residual of closed `#2402` to a session lock-layout refactor. |
| R4-b1-03 | **IN-SCOPE-NEW** | `neighbor_dispatch.rs:175` allocates a pending-neighbor key vector on repeated sweeps. Existing worker scratch is the concrete owner; pointer/capacity reuse, frame ordering, and post-warmup zero allocation make this independently gateable. |
| R4-b1-04 | **REVISE-SCOPE** | Retain pre-sized set membership inside `filter_replayed_synced_sessions` at `coordinator/mod.rs:133`, preserving survivor order and asymmetric companion semantics. Exclude a one-function `session_replay.rs`; require linear operation counts and a material large-vector speedup. |
| R4B2-01 | **REVISE-SCOPE** | `shared_ops.rs:882` publishes canonical entries, aliases, and owner indexes through separately observable mutations. Retain one transaction owner, but do not preselect one global `RwLock` until contention, poison behavior, collision handling, and an epoch/seqlock alternative are compared. |
| R4B2-02 | **REVISE-SCOPE** | Retain a bounded cursor-backed backlog for partial writes at `event_stream/mod.rs:1126`, with geometric compaction and exact ordering. The transport move is optional and overlaps `#366`/PR `#382`; behavior and movement must not be one issue. |
| R4B2-03 | **DROP-DUPLICATE** | Codex-review-171 finding 10 already owns `server/helpers.rs` status decomposition; Fable-review-173 **A5 `server/helpers.rs` INCREMENT** adds the exact queue-planning/plan-key and HA session-build owners. The raw status/session-sync/binding-plan tree at `helpers.rs:16` is the same deliverable. |
| R4B2-04 | **DROP-DUPLICATE** | Codex-review-173 finding 16 already maps `slowpath.rs` into reinjector/worker/write/TUN/sysctl owners and says to extract TUN/sysctl first; Fable-review-173 A4-F13 validates that seam. The raw `tun/{device,packet_io}` proposal at `slowpath.rs:461` is the same work. |
| R4B2-05 | **DROP-DUPLICATE** | Codex-review-171 finding 29 owns giant Rust integration-test splits, while Fable-review-173 A4-F14/F17 explicitly ties `session_glue/tests.rs` clusters to production owners. Splitting the file at `session_glue/tests.rs:1` adds no new behavior or owner. |
| R5B1-GATE-01 | **REVISE-SCOPE** | P4 section errors bypass tolerant gates (`compiler.go:1561`, firewall `:259`, CoS `:148`). Retain explicit domain-by-domain fatal/quarantine outcomes in the owning compilers. Drop the generic `compilegate` package and the unsupported deterministic-NAT legacy premise: `compiler_nat.go:1634-1687` hard-checks deterministic NAT, while the compatibility comment at `:1690-1695` concerns only pool-utilization alarm. |
| R5B1-DIAG-02 | **REVISE-SCOPE** | `compiler_validate_warn.go:1190-1202` mutates CoS while collecting warnings, whereas `compiler_tailgates.go:25` publishes a canonical slice and show paths recompute it. Retain pure deterministic collection plus immutable copied publication; a new diagnostic package is not a prerequisite. |
| R5B1-MATRIX-03 | **IN-SCOPE-MERGE (MG-02: into R5B1-GATE-01 and R5B1-DIAG-02)** | `dual_ast_differential_test.go:941-1009` omits tolerant/node cells and sorts away order. Fatal-versus-quarantine cases belong to GATE-01; repeated-call purity/order cases belong to DIAG-02. No `internal/testmatrix` issue is warranted. |
| R5B2-IPMON-01 | **REVISE-SCOPE** | `compiler_services.go:895-970` mutates `PreferredRoute` before a later error and ranges a map nondeterministically, but the outer compiler discards the fresh candidate on error. Retain deterministic staged analysis in the owning compiler; drop the runtime partial-publication claim, unproved tolerant policy, and four-file domain package. |
| R6-b1-01 | **REVISE-SCOPE** | `daemon_ha_sync.go:362` can equate stored text with successfully applied state after a failed tail stage. Retain explicit attempted/successful identity and outcome policy in the daemon owner; package extraction is incidental and nonfatal tail errors need a defined retry contract. |
| R6-b1-02 | **REVISE-SCOPE** | `daemon_ha_sync.go:398` can let a stale asynchronous HA constructor publish after stop/restart. Retain a local generation object with publish-if-current, detach/cancel/join, callback fencing, and a proved lock order. Exclude a broad hooks/god-interface package. |
| R6-b1-03 | **DROP-CORRECTNESS-ONLY** | `daemon_run.go:625` exposes HTTP before assigning the in-process HA session service, allowing a local-only fallback. Construct/capture the service before listener exposure. The `controlsurface` package is incidental; its fabric-listener clause belongs in R6-b1-02's lifecycle work. |
| R6-b1-04 | **IN-SCOPE-NEW** | `daemon_system.go:215` registers append-only event callbacks on every apply, retaining old large aggregators. A bind-once subscription with one swappable, joined active runtime is a real callback-lifecycle owner and matches no prior tracker. |
| R6B2-01 | **REVISE-SCOPE** | `maps_sync.go:253-1515` and `manager_compile.go:228-323` can leave maps/caches, Rust snapshot, helper status, and published pointers on mixed generations. Retain one fail-closed publication coordinator covering all of them; require failure injection before selecting rollback versus disablement. |
| R6B2-02 | **REVISE-SCOPE** | `dataplane/compiler.go:173-286` performs host mutation before later compile failures. Retain pure planning plus explicit per-operation compensation/fail-closed semantics, but reuse R6B2-01's publication generation and do not create a second transaction framework or another wide actuator interface. |
| R6B2-03 | **DROP-CORRECTNESS-ONLY** | `userspace/eventstream.go:328-502` can ACK past an undecodable session delta. Fix replay/resync/close semantics and the malformed-delta-then-telemetry test in the current owner. The structural eventstream move is already Fable-review-173 **A7-F7**. |
| R6B2-04 | **REVISE-SCOPE** | `userspace/protocol.go:10-3013` and Rust fixtures lack a populated bidirectional executable inventory. Retain only the fixture/inventory gate first; eventual DTO movement remains under Fable-review-173 **A7-F6**, and mixed internal/wire types must not be aliased blindly. |
| R7B1-SESS-01 | **DROP-DUPLICATE** | Fable-review-173 **A9-F3** already owns the exact shared `pkg/sessionview` pagination/filter/projection boundary. Negative `PageSize`/`Limit` behavior at `server_sessions.go:33-589` is acceptance coverage for that prior report, not another module issue. |
| R7B1-SHOW-02 | **DROP-CORRECTNESS-ONLY** | Unsorted map output is real at `server_show_security_text.go:263-905`; sort each existing renderer and decide REST feed-data parity as a product/API contract. Closed `#1687` explicitly rejected a universal security renderer, so the proposed canonical presenter must not be revived. |
| R7B1-IFACE-03 | **DROP-DUPLICATE** | Fable-review-173 **A9-F6** already owns the shared interface presenter and logical-unit ordering. The nondeterministic groups at `server_show_interfaces.go:81-278` are its first guardrail/acceptance commit, not a second `ifaceview` issue. |
| R7B2-HC-001 | **REVISE-SCOPE** | `cmdtree/tree.go:133` is the canonical completion tree, while local/remote dispatch omit different commands. Retain a machine-checked command-support matrix, the two concrete parity fixes, and only grammar-required typed parsers. Reject fragmented registries, reflection, and a wide handler context. |
| R7B2-HC-002 | **IN-SCOPE-NEW** | `cmd/cli/shared.go:111` fully buffers remote output, lowercases matches, and writes through global stdout while local filtering is streaming/case-sensitive. One bounded, writer-injected streaming pipeline is a real shared owner; prior C175-HC-093/`#4709`/`#4731` fixed only local paths. |
| R7B2-HC-003 | **REVISE-SCOPE** | `xpf.proto:961` encodes parameterized ShowText requests in delimiter-bearing strings. Retain typed requests only for parameterized topics behind a measured legacy adapter; exclude a mega-oneof, renderer unification, and dependency on HC-001's rejected broad registry. |
| R8-B1-01 | **DROP-CORRECTNESS-ONLY** | The MASTER stop branch at `vrrp/instance.go:1089` leaves state/`garpEpoch` valid while detached bursts continue. Revoke the existing epoch before every MASTER exit in `vrrpInstance`; a new `announcelease` package around one scalar is incidental. |
| R8-B1-02 | **REVISE-SCOPE** | The manager-wide RA epoch at `ra.go:69-506` lets interface B supersede interface A's restart. Retain per-interface intent revisions inside the existing `senders`/`draining` registry, with whole-manager fencing for Clear/Withdraw. Exclude a second lifecycle registry package. |
| R8-B1-03 | **REVISE-SCOPE** | Concurrent setup at `sync_conn.go:475-529,1180` lacks reservation/publication order and can lose the cold-prime obligation. Retain a per-fabric high-water publication token plus acknowledgement-bound prime ownership; legacy-frame dispatch, Stop admission, and stale disconnect behavior must be in scope. |
| R8B2-NETWORKD-01 | **REVISE-SCOPE** | `networkd.go:74-262` remembers only call-local `changed`; a failed reload followed by identical apply can return success without retry. Retain manager-owned reload/reconfigure debt. Do not claim `networkctl reload` proves observed external generation or persist a self-authored convergence marker. |
| R8B2-FRR-01 | **DROP-CORRECTNESS-ONLY** | `policy_render.go:712` filters `PeerAS==0` only in the root pass, not AF/BFD projections. Build one local renderable-neighbor slice/predicate in the existing renderer. A new BGP package is incidental and broad FRR decomposition already landed under `#1547`. |
| R8B2-IPSEC-01 | **DROP-CORRECTNESS-ONLY** | `ipsec/policy.go:372-486` sanitizes distinct selector names to colliding CHILD_SA keys. Reject generated-name collisions before publication while preserving safe names. An injective migration and `children/` package are unsupported by parity evidence and unnecessary for the fix. |
| R8B2-ROUTING-01 | **DROP-CORRECTNESS-ONLY** | `routing/rules.go:680-1235` caps duplicate normalized PBR rules before semantic dedup. Add a stable comparable key and first-seen dedup in the existing builder. Broad `rules/` movement is already owned by open `#4421`. |
| R9B1-DDNS-01 | **DROP-DUPLICATE** | Codex-review-175 **C175-HC-027**, *Surface B keeps one representative DDNS updater for two independent families and can withdraw IPv6 through the IPv4 provider*, cites the same `ddns/manager.go:607-634` trace and already requires per-family previous-live backend identity/fingerprint. |
| R9B1-DHCP-01 | **DROP-CORRECTNESS-ONLY** | `dhcp/commit.go:128-136` removes the old address before fallible new-address installation. Make the existing commit owner forward-recoverable with an injectable actuator and generation-guarded cleanup debt. The proposed client/netlink tree reopens broad closed `#1987` and is incidental. |
| R9B1-RELAY-01 | **DROP-CORRECTNESS-ONLY** | `dhcprelay/relay.go:627-819` keeps a dead registry entry after an unexpected one-sided session exit. Classify that exit as retry in the existing supervisor/backoff path; no second registry/supervisor package is needed. |
| R9B1-SERVER-01 | **DROP-CORRECTNESS-ONLY** | `dhcpserver.go:259-300` can discover deterministic v6 shape failure after v4 effects. Move deterministic shape validation before mutation and keep per-family convergence. The proposed cross-family rollback/paired-stop transaction conflicts with the package's per-family contract and can widen an outage. |
| R9B1-SERVER-02 | **DROP-DUPLICATE** | Codex-review-175 **C175-HC-071**, *Async DHCP server apply drops transient failures permanently and has no convergence retry*, cites the same pending-slot drain (`dhcpserver.go:365-377`) and attempted-generation advance (`:259-303`) and already specifies latest-only retry and desired/applied generations. |
| R9B2-001 | **REVISE-SCOPE** | `flowexport/netflow.go:589-720`, `ipfix.go:806-830`, and `daemon_flowexport.go:255-517` allow a callback that loaded the old bundle to append after final flush. Retain allocation-free admission leases and retirement waiting on the concrete daemon bundles; exclude a generic `flowexport/runtime.Generation` with erased ownership. |
| R10-B1-001 | **REVISE-SCOPE** | The `#1476` manifest at `source-removal-manifest-1476.md:126-144` deliberately retained these headers and says a future PR is a separate reviewed boundary, so `#1476` is not an exact duplicate. Retain a complete live-consumer/orphan proof, move `MAX_INTERFACES` and the legacy event-layout fixture to active owners, then delete only proven orphan headers; do not imply every retained header was audited. |
| R10-B1-002 | **DROP-WEAK** | `userspace-xdp/src/lib.rs:405-1319` is verifier-shaped and has one program boundary. Fable-review-173 **A5-F6** records a D-negative for modularity here. Same-crate files may be technically possible, but this raw tree has no forcing owner or measured benefit beyond source aesthetics and must not reopen the D result. |
| R10-B1-003 | **IN-SCOPE-NEW** | `pkg/dataplane/README.md:42`, `Makefile:79`, and packaging paths use a tracked XDP object without binding normal builds to current source inputs. A deterministic source/toolchain/object provenance manifest plus cheap mandatory digest gate is a real build ownership boundary distinct from `#1864`'s privileged regeneration/verifier gate. |
| R10-B1-004 | **IN-SCOPE-NEW** | `xpf-deploy.py:415-1657` contains separate backend, distribution, lease, kernel-roll, and image-roll transactions. A compatibility wrapper over concrete transaction-owning modules is a real cold-path package boundary; preserve exact preflight/mutation/cleanup and avoid plugin abstractions. |
| R10-B1-005 | **REVISE-SCOPE** | `cold-path-flooder/main.rs:573,1051` combines cold CLI/reporting with a raw-pointer `TxRing`/worker unit, while `Makefile:114` has no standard owner. Retain build/format/test/perf adoption first, then move cold code; keep `TxRing`, final-location wiring, and worker loop together unless disassembly and the recorded Mpps gate approve movement. |
| R10-B1-006 | **IN-SCOPE-NEW** | `fairness_multi_sample_test.py:20-1421` tests four executables in one class, and `run-selftests.sh:136` does not discover it. Ownership-aligned test modules plus a nonzero-discovery standard target is a concrete test boundary not supplied by the generic giant-test reports. |
| R10-B1-007 | **REVISE-SCOPE** | Stale heatmap contents and inline-test distortion are already `#1661` item 8/PR `#1671` and Fable-review-173 A1-F6. Retain only the new increment: an explicit owned-root/type registry, separate production/test ledgers, fixture-tested generation, and a mandatory standard gate covering Python and standalone Rust tooling. Do not file another one-off 16-to-46 refresh issue. |

## Supplemental Raw-Disposition Ledger

## Complete 24-ID Disposition Table

| Raw ID | Disposition | Final narrowed title or canonical target | Scope and dedup result |
|---|---|---|---|
| `S1-RUST-RUNTIME-B2-01` | **REVISE-SCOPE** | **Preflight all AF_XDP worker thread creation before destructive reconcile commit** | Retain desired/prepared/applied/failed generation semantics and parked-thread abort/join before teardown. Do not promise rollback after post-gate AF_XDP setup failure, and do not pre-approve the proposed three-directory tree. This is a real reconcile ownership boundary, not merely the swallowed `spawn` error. |
| `S1-RUST-RUNTIME-B2-02` | **DROP-CORRECTNESS-ONLY** | No refactor issue | The monitor/warmer `.ok()` calls and false installed state are real. Fix install-on-success, retry debt, and stop/join in the existing `NeighborManager`, alongside the same owner-local lifecycle work identified by primary row `R4-b1-01`. A new `aux_services/` hierarchy is incidental. |
| `S1-RUST-RUNTIME-B2-03` | **REVISE-SCOPE** | **Separate session-delta projection, publication, and retirement under one ordered batch owner** | Keep one batch shell as the owner of iteration order and the first-lossless-failure latch. Extract only private projection, publication, and retirement helpers after failure-order tests. Exclude `queued_flow` movement and the proposed five-module tree. |
| `S1-RUST-RUNTIME-B2-04` | **REVISE-SCOPE** | **Measure four-way flow-cache probe cost against the actual 496-byte entry layout** | Retain only the stale-size correction and a release benchmark of the real hash, four-way probe, validation, MRU update, hit use, and miss path. No production layout change is approved; a compact layout needs a later Class-C proposal meeting the stated cycle/L1 and MRU-regression gates. |
| `S1-B3-001` | **DROP-CORRECTNESS-ONLY** | No refactor issue | Unbounded local-delivery/TUN drains can delay generation pickup and starve a direction. Add bounded two-direction rounds and no-sleep-on-budget-exhaustion in the existing tunnel loop. The proposed `local_origin/{io_round,plan,session}` partition is not required for the fix. |
| `S1-B3-002` | **DROP-CORRECTNESS-ONLY** | No refactor issue | Resolve MTU from the selected peer and effective endpoint in the existing WireGuard control owner, with a round-local snapshot/cache if needed. `#2845` and `#2921` are adjacent acceptance history, not exact duplicates; the proposed `tunnel_underlay/` and `wg_control/` split remains incidental. |
| `S1-B3-003` | **DROP-CORRECTNESS-ONLY** | No refactor issue | Clear `martian_dropped` and `ipv6_ext_header_dropped` in the current unbound projection and add an exhaustive live-field parity test. A new binding-status module or generated callback table is disproportionate to the two-field residual. |
| `S2GCB1-SCREEN-01` | **DROP-CORRECTNESS-ONLY** | No refactor issue | Repeated screen profile/family blocks are truncated before validation. Collect and fold them in `compiler_security_screen.go`, with explicit scalar-conflict semantics and snapshot-equivalence tests. The proposed three-file compiler subpackage is incidental. |
| `S2GCB1-IPSEC-02` | **DROP-CORRECTNESS-ONLY** | No refactor issue | Same-name IKE/IPsec objects are replaced before strict gates and renderer defaults. Use typed owner-local collection/fold helpers in `compiler_ipsec.go`, preserving secret redaction and render parity. The four-file neutral-model package is not needed to correct the defect. |
| `S2GCB1-FLOW-03` | **DROP-CORRECTNESS-ONLY** | No refactor issue | `compileFlow` must consume the same all-child declaration collection as its validators. Fix that in the existing compiler owner and preserve warning order and snapshot parity. A new `securitycompile/flow` package is incidental. |
| `S2GCB1-ROUTE-04` | **DROP-CORRECTNESS-ONLY** | No refactor issue | Restore `ospf6` and `ripng` in the strict validator and add a compile-to-render parity table. `#2943`/PR `#2948` owns the earlier renderer support, not this later validator regression, so the bug is real but a new `pkg/routingcontract` package is unnecessary. |
| `S2GDPB2-01` | **REVISE-SCOPE** | **Track proxy-ARP applied state so removed interfaces are swept before responder teardown** | Retain one applied-plan/cleanup-debt owner spanning prior and desired interfaces, deterministic operation order, and promote-on-convergence semantics. Do not scan/adopt all `NTF_PROXY` entries after restart without durable ownership evidence, and do not require a new package before the contract is tested. |
| `S2GDPB2-02` | **REVISE-SCOPE** | **Fail config-arrival apply until mapped interface naming and durable ownership converge** | Retain a typed naming outcome, durable recovery intent, final-name verification, and abort of dependent VRF/interface/dataplane apply. Reuse `R8B2-NETWORKD-01` as the sole reload/activation-debt owner; physical package movement and a second retry state machine are excluded. |
| `S2GDPB2-03` | **IN-SCOPE-MERGE** | Tracker `#4875`: **Require authoritative userspace readiness and complete bounded worker liveness before reporting Online** | Audit-175 `C175-HC-098` already owns empty/future heartbeat false-Online. Merge the supplemental enabled/armed/supported, expected-worker, per-binding readiness, manager-gate, standby, and empty-config semantics into that classifier issue. No `pkg/dataplane/runtime` package is approved without another neutral consumer. |
| `S2B3-FILTER-01` | **IN-SCOPE-MERGE** | Open tracker `#4372` A1: **Pin firewall-filter surface profiles, then share ordered semantic rows** | `#4372` already owns the missing local firewall-filter policer status and Prometheus projection. Add the opposite gRPC DSCP omission, explicit per-surface profiles, one status/counter snapshot, and shared ordered semantic rows to that owner. Do not create a parallel filter-view issue, revive the universal renderer rejected by `#1687`, or migrate the effective view before its contract is characterized. |
| `S2B3-DIAG-02` | **DROP-CORRECTNESS-ONLY** | No refactor issue | Bound command stdout and generated neighbor text in the existing unary `GetSystemInfo` owner, with deterministic truncation and safe child drain/kill behavior. A transport-neutral package and streaming RPC are separate product/API work, not prerequisites for the resource-bound fix. |
| `S2B3-COMPLETE-03` | **REVISE-SCOPE** | **Centralize completion behind a backward-compatible UTF-8 cursor contract** | Preserve legacy `pos` as validated byte offset, fix the rune-based caller, and add an explicit prefix or versioned cursor-unit path. Share a prefix-to-candidate engine and value provider while leaving readline/protobuf adapters and both grammar sources in their owners. |
| `S2B3-NEIGH-04` | **REVISE-SCOPE** | **Build one deterministic neighbor snapshot while preserving local and remote profiles** | Retain one request-local semantic snapshot, one link lookup per distinct ifindex, byte-identical dedup only, and a total comparator over every visible row field. Local and remote summary/text profiles remain separate; no universal renderer is approved. |
| `S3B1-LOCK-01` | **IN-SCOPE-MERGE** | Tracker `#4020`: **Self-lock every destructive HA validator under the shared cluster cell** | This script is an omitted destructive caller of the exact `cluster-cell.sh`/PR `#4026` boundary. Extend the existing static canary and lock entry, preserve all material environment controls, and hold the lock through restore. Do not add another flock implementation. |
| `S3B1-EVIDENCE-02` | **IN-SCOPE-MERGE** | Tracker `#1661` item 5: **Fail HA phase gates closed on missing or malformed transition snapshots** | `#1661` already owns modularizing this exact 1,781-line harness around timing, `|| true`, baseline capture, and failover attribution into a reusable library/Python package. Merge the strict fabric snapshot parser, typed failure outcome, dependent-PASS suppression, and cleanup-preserving shell contract as its first bounded slice; do not file another harness package issue. |
| `S3B1-IPERF-03` | **REVISE-SCOPE** | **Version and share fail-closed iperf interval metrics across live and final HA gates** | Retain a versioned schema with separate aggregate-interval and per-stream-sample units, strict no-complete-interval behavior, stdin/file input, and explicit migration of every caller. This remains separate from `#1661` because the Python helper already has multiple direct consumers outside the assigned failover harness. |
| `S4LTB1-GATE-01` | **IN-SCOPE-MERGE** | `codex-review-171` finding 29 plus Fable-review-173 A1-F4/A5: **Partition Rust test owners without changing debug or release leaf discovery** | Exact dual-profile discovery is acceptance coverage for the prior giant Rust test-owner work. Compare sorted before/after names and ignored subsets as CI/review artifacts, and guard the few documented exact leaves. Do not check in permanent 611/612-name manifests or create a stand-alone gate issue. |
| `S4LTB1-OWNER-02` | **DROP-WEAK** | No issue | Same-namespace `.inc.rs` fragments preserve one crate-root owner and create no production-module ownership, narrower visibility, or dependency boundary. Keep the root suite until complete tests can move to real owners without exporting internals. |
| `S4LTB1-OWNER-03` | **IN-SCOPE-NEW** | **Finish the cluster production split by co-locating its remaining tests** | `#1541`/PR `#1575` explicitly left test files unmoved, so this is not duplicate production work. Extract the two shared fixtures, move complete tests to existing same-package owners, preserve all names, and require full package race/shuffle validation. |

## Canonical New Issues

These are the nine new supplemental issue records to file or carry forward:

| Canonical raw ID | Final narrowed title |
|---|---|
| `S1-RUST-RUNTIME-B2-01` | **Preflight all AF_XDP worker thread creation before destructive reconcile commit** |
| `S1-RUST-RUNTIME-B2-03` | **Separate session-delta projection, publication, and retirement under one ordered batch owner** |
| `S1-RUST-RUNTIME-B2-04` | **Measure four-way flow-cache probe cost against the actual 496-byte entry layout** |
| `S2GDPB2-01` | **Track proxy-ARP applied state so removed interfaces are swept before responder teardown** |
| `S2GDPB2-02` | **Fail config-arrival apply until mapped interface naming and durable ownership converge** |
| `S2B3-COMPLETE-03` | **Centralize completion behind a backward-compatible UTF-8 cursor contract** |
| `S2B3-NEIGH-04` | **Build one deterministic neighbor snapshot while preserving local and remote profiles** |
| `S3B1-IPERF-03` | **Version and share fail-closed iperf interval metrics across live and final HA gates** |
| `S4LTB1-OWNER-03` | **Finish the cluster production split by co-locating its remaining tests** |

## Complete Module and File Inspection Log

# Audit 176 Aggregated Coverage

## R1-b1: Rust AF_XDP packet-loop and compiler-inlining specialist

Assigned candidates: **8**. Primary report: `codex-R1-b1.md`.

### Module Checklist

- [x] `userspace-dp/src/afxdp/poll_descriptor/mod.rs` - RX descriptor loop, session/NAT/policy/route orchestration, disposition, and local helper tests.
- [x] `userspace-dp/src/afxdp/poll_descriptor/filter.rs` - hot filter guards, cold log/reject tails, cached-filter replay, and inline tests.
- [x] `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` - established-flow cache-hit fast path and live-frame fallback.
- [x] `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` - cold generated reject feasibility, rate-limit, classification, enqueue, and event ordering.
- [x] `userspace-dp/src/afxdp/poll_stages.rs` - bounded pre-session packet stages and verdict contracts.
- [x] `userspace-dp/src/afxdp/forward_request.rs` - live pending-forward descriptor construction and output-filter terminal handling.
- [x] `userspace-dp/src/afxdp/poll_stages_tests.rs` - stage characterization tests and fixtures.
- [x] `userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs` - reject-reply characterization and call-site tests.

### File-by-File Inspection Log

**1. `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (6,294 LOC)**

Inspected the complete file, including helpers, the descriptor loop, every major session/flowless/neighbor arm, and the inline tests. `poll_binding_process_descriptor` spans lines 683-5478 (4,796 lines at this base), not the stale 1,368-line size in open issue `#4404`. It still couples RX batch scratch reset, descriptor/frame ownership, parse stages, flow-cache handling, session hit/miss, DNAT/NAT64, route and policy resolution, session transaction commit/rollback, pending-neighbor ownership transfer, and final disposition/recycle. This is a genuine decomposition target, but it is exactly the open `#4404` scope and is therefore suppressed rather than re-filed. Any implementation must preserve the single descriptor loop, exactly-once recycle/ownership transfer on every `continue`, in-place UMEM mutation, and transaction-before-publication order. The compiler warning at line 4980 about an overwritten initial `source_nat_release_key` assignment is a local cleanup, not an independently issue-worthy refactor. The private helper tests at lines 5480-6294 are small concern-specific clusters; moving them solely to lower file size would either expose private seams or duplicate the already-tracked loop work.

**2. `userspace-dp/src/afxdp/poll_descriptor/filter.rs` (1,201 LOC)**

Inspected all production helpers and six inline tests. The production portion is already decomposed by semantic boundary: small `#[inline]` guards remain visible to the hot caller, while event formatting and reject/log tails are `#[cold] #[inline(never)]`. Cached output-filter replay remains inline because `stage_flow_cache_hit` invokes it unconditionally; the rare emitting body is separately outlined. Input, output, lo0, host-inbound, and cached-filter helpers share policy types but do not form a new ownership domain worth another directory layer. No trait-object dispatch, unconditional heap allocation, new atomics, or widened packet ownership was found. The inline tests directly exercise private terminal ordering and logical-ifindex behavior; extracting six tests has negligible maintenance value. Negative result: preserve the present hot-guard/cold-tail boundary.

**3. `userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs` (533 LOC)**

Inspected the full `#[inline(always)] stage_flow_cache_hit` body at lines 65-533 and both call/fallback contracts. Its 469 lines are long but encode one fused established-flow operation: validate cache/session/TTL before side effects, replay counters and filters, enforce policers, reclassify BA per packet, touch/account the session, rewrite the live UMEM frame, optionally clone only an admitted sampled mirror, then transfer or recycle descriptor ownership. Splitting by apparent phases would lengthen live ranges across calls, risk duplicate lookups/branches, or require a wide mutable context; forcing every extracted phase inline would increase compiler and instruction-cache pressure without creating a real ownership boundary. The opening comment's old "280-LOC" measurement is stale, but that is not a separate refactor issue. Prior reports already reached the same D-class conclusion, so no finding is retained.

**4. `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` (417 LOC)**

Inspected every entry point and the shared enqueue body. The production code is intentionally exception-path code: public-to-module entry points and the shared body are `#[cold] #[inline(never)]`, keeping generated-reply construction and classification out of the poll-loop instruction stream. The sequence is cohesive and correctness-sensitive: establish reply feasibility before consuming scarce budget/tokens, select the per-zone reject bucket, classify on the logical ingress interface, enqueue, then report truthful sent/drop counters and event action. A split would pass a broad partially-built reply state among cold helpers without reducing hot-path work. The former inline test bulk is already in the sibling candidate file via commit `5707d4304`. Negative result: retain this cold module as one unit.

**5. `userspace-dp/src/afxdp/poll_stages.rs` (975 LOC)**

Inspected all stage verdict enums and stage bodies: link layer, native GRE decap, parse/learn, fabric ingress, flowless address extraction, screen, SYN-cookie ACK, and IPsec passthrough. The file is already the stage-oriented extraction boundary described by the AF_XDP architecture docs. Each stage returns an explicit compact verdict and preserves the caller's descriptor ownership; hot stages use `#[inline]`, while the native-GRE owned-frame branch makes ownership visible rather than hiding it behind dynamic dispatch. `stage_screen_check` is the largest body (lines 390-693), but its flow/flowless branches share profile lookup, counters, alarms, and a single verdict contract. The previously proposed six-way production split would fragment the pre-session pipeline and has already been classified D in prior review. Tests were moved out by commit `79903e233`, so the old file-size finding is resolved.

**6. `userspace-dp/src/afxdp/forward_request.rs` (310 LOC)**

Inspected the reverse-session predicate, test wrapper, and `build_live_forward_request_from_frame` at lines 77-310. The 234-line builder has a wide signature, but the values are all part of one owned `PendingForwardRequest` transition: fragment-safe tuple derivation, target binding selection, post-NAT wire-key output classification, truthful active-reject/log ordering, and final descriptor packing. Its three production call sites and the flow-cache fallback depend on the same ordering and `Option` terminal contract. It is already an out-of-line module boundary from the poll loop; another split would either add calls on session-miss/fallback traffic or require aggressive inline annotations and a wide borrowed context. The only request ownership copy is the stored flow key; there is no unconditional frame clone. Existing tests directly cover hints, flow-vs-frame ports, fragment/control-packet behavior, CoS selection, output-filter discard/reject, logging, target-binding caching, and fabric redirect. Negative result: size alone does not justify a new submodule.

**7. `userspace-dp/src/afxdp/poll_stages_tests.rs` (2,552 LOC)**

Inspected all 26 tests and helpers. The file is long because fixtures construct real `WorkerContext`/forwarding state and packet bytes for four coherent stage families: SYN-cookie/VLAN parsing, ARP/NDP learning, screen/fragment behavior, and IPsec/IKE gating. Several context initializations repeat, but a generic fixture would need many mutable references and leaked/static test state, making ownership less obvious and failures harder to localize. Splitting again immediately after the landed production/test separation would add navigation without changing compile or runtime behavior. An earlier IPsec explanatory block still describes the once-deferred NEW-IKE gate even though the later `#4323` test now pins it; that is local comment drift, not a module refactor. Negative result: no independently issue-worthy follow-up.

**8. `userspace-dp/src/afxdp/poll_descriptor/reject_reply_tests.rs` (1,895 LOC)**

Inspected all 27 tests and fixture helpers. The suite forms a single behavioral matrix around reject feasibility, TX reserve, per-zone rate limiting, output-filter classification, logical VLAN interface resolution, IPv4/IPv6 source selection, zone `tcp-rst`, and truthful RT_FLOW action/kind ordering. Repeated packet/snapshot setup is intentional enough to expose each fail-on-revert condition, and the shared helpers are already limited to stable primitives. Further family splitting would not reduce production coupling and would separate paired policy/filter variants. This file is the landed corrective action from the prior inline-test finding; no new issue remains.

## R1-b2: Rust packet parsing, forwarding, checksum, and zero-copy specialist

Assigned candidates: **9**. Primary report: `codex-R1-b2.md`.

### Module Checklist

- [x] `userspace-dp/src/afxdp/forwarding/mod.rs` (2,795 lines)
- [x] `userspace-dp/src/afxdp/forwarding/tests.rs` (4,668 lines; 120 `#[test]` functions)
- [x] `userspace-dp/src/afxdp/frame/inspect.rs` (1,888 lines)
- [x] `userspace-dp/src/afxdp/frame/mod.rs` (1,743 lines)
- [x] `userspace-dp/src/afxdp/frame/checksum.rs` (984 lines; 15 `#[test]` functions)
- [x] `userspace-dp/src/afxdp/frame/tcp_segmentation.rs` (995 lines; six inline `#[test]` functions)
- [x] `userspace-dp/src/afxdp/frame/tests.rs` (8,342 lines; 132 `#[test]` functions)
- [x] `userspace-dp/src/afxdp/frame/tcp_tests.rs` (1,105 lines; 51 `#[test]` functions)
- [x] `userspace-dp/src/afxdp/forwarding_build/mod.rs` (705 lines)

### File-by-File Inspection Log

### `userspace-dp/src/afxdp/forwarding/mod.rs`

Inspected packet validation, route-table canonicalization, NAT/zone helpers, HA/fabric resolution, MTU/MSS selection, local delivery, PBR, v4/v6 FIB recursion, tunnel/neighbor resolution, and ECMP selection. The broad facade split and `ForwardingState` width are already tracked, so they are suppressed. Retained only the materially narrower zero-allocation FIB seam in R1B2-03: recursive `next-table` lookups allocate names and cycle state on every affected new-flow lookup. Direct-route lookup remains allocation-free; the allocation is specifically inside the route-leak branch.

### `userspace-dp/src/afxdp/forwarding/tests.rs`

Mapped all 120 tests across validation, HA/fabric, NAT/local delivery, policy/PBR, FIB, neighbors, tunnels, IPsec, VRFs, and ECMP. The giant-test-file split is a known duplicate. The tests correctly pin v6 next-table canonicalization and A-to-B-to-A cycle rejection, but none pins allocation count or lookup latency, which is the missing guard for R1B2-03.

### `userspace-dp/src/afxdp/frame/inspect.rs`

Inspected every L2/L3/L4 offset parser, IPv6 extension walker, fragment predicate, filter-match view, declared-length helper, live-port extractor, session-flow arbitration path, debug decoder, and metadata parser. The repeated L2/IPv6 walkers are known parser-unification work and are suppressed. Retained R1B2-01 because the complete TCP/UDP metadata return bypasses the file's own IP-declared-end invariant, and R1B2-04 because the two security-sensitive `TermMatchExtra` builders are byte-for-byte policy paths with no shared implementation.

### `userspace-dp/src/afxdp/frame/mod.rs`

Inspected NAT64 and generic builders, UMEM in-place L2 preparation, generic v4/v6 rewrite, NAT address/port/ICMP mutation, expected-port repair, injected-packet builders, and debug checksum verification. The existing `frame/build` and `frame/rewrite` per-family split is codegen-conscious and should not be reopened. Retained R1B2-02 because `Option::None` is not transactional: UMEM can be modified before later validation fails, while live callers reuse those bytes. Debug checksum atomics are relaxed diagnostics behind the debug path and are not a production hot-path finding.

### `userspace-dp/src/afxdp/frame/checksum.rs`

Negative result. The file is cohesive checksum arithmetic: big-endian word extraction stays local, v4/v6 zero-checksum rules use `ChecksumFamily`, short inputs stay scalar, and AVX2 is isolated behind architecture/runtime gating with scalar-equivalence tests. Production functions allocate nothing, take borrowed slices, use no trait objects or locks, and do not change packet ownership. Further splitting would risk losing constant-family folding and checksum-rule locality; prior checksum dedup work is already tracked.

### `userspace-dp/src/afxdp/frame/tcp_segmentation.rs`

Inspected the 218-line admission/segmentation loop, descriptor adapter, extracted v4/v6 emitters, tunnel encapsulation dispatch, and all inline mode-aware tests. `Vec<Vec<u8>>` and one output allocation per software segment are intentional emission ownership for oversized TCP packets, not an accidental normal-forwarding allocation. The phase split is already tracked and the current base contains the `#4652` emitter/encapsulation extraction; the open `#4384` checksum landmine is also known. No new independent finding retained.

### `userspace-dp/src/afxdp/frame/tests.rs`

Mapped all 132 tests across parser arbitration, builders, NAT/NAT64, zero-copy VLAN rewrite, descriptors, fragments, segmentation, injection, and MSS handling. The broad test split is known. The audit found two precise missing guards: no complete-nonzero-metadata short-IP-length case for R1B2-01, and no assertion that the full UMEM/source frame is unchanged on every rewrite `None` branch for R1B2-02.

### `userspace-dp/src/afxdp/frame/tcp_tests.rs`

Negative result. The 51 tests form a coherent TCP-owned suite: flags/window inspection, MSS option walking, RST construction/suppression, and IPv6 extension-header awareness. There is no production code, packet ownership, allocation contract, ABI, lock, or atomic boundary to extract here. Splitting 1,105 lines would mostly scatter shared TCP fixtures and weaken protocol-focused review.

### `userspace-dp/src/afxdp/forwarding_build/mod.rs`

Inspected all wrappers, the exact 409-line `build_forwarding_state_with_policy_counters_and_previous` span (`200..=608`), and neighbor-timeout/sysctl logic. The large cold builder is the known A2 F4 finding and is suppressed. Its production callers build a complete state before publication, so fallible construction does not partially publish; the late RST-suppression call is currently a no-op. The `SysctlReader` is statically dispatched and the relaxed `AtomicBool` only gates a cold process-wide warning transition.

### Support Reads

Read only to verify assigned-module contracts: `userspace-xdp/src/lib.rs`; `frame/inspect_tests.rs`; `frame/prop_tests/{inspect,rewrite}.rs`; `frame/rewrite/{mod,ipv4,ipv6}.rs`; `poll_descriptor/flow_cache_hit.rs`; `tx/dispatch/{mod,slow_path}.rs`; `forward_request.rs`; `neighbor_dispatch.rs`; `forwarding_build/fib.rs`; `types/{mod,forwarding}.rs`; coordinator snapshot publication callers; `afxdp/rst.rs`; and the relevant issue/PR history sections. No finding is assigned to those support files.

## R2-b1: HFT queueing, fair scheduling, cache-layout, and atomic ownership specialist

Assigned candidates: **8**. Primary report: `codex-R2-b1.md`.

### Module Checklist

| Assigned candidate | Inspected | Result |
|---|---:|---|
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | Full file | Two new hot-path findings; known waterfill work suppressed |
| `userspace-dp/src/afxdp/cos/queue_service/drain.rs` | Full file | Negative result; typed drain variants should remain specialized |
| `userspace-dp/src/afxdp/cos/queue_service/service.rs` | Full file | Negative result; proposed generic skeleton is known and rejected |
| `userspace-dp/src/afxdp/cos/queue_service/tests/selector.rs` | Full file | One new guardrail/test-ownership finding |
| `userspace-dp/src/afxdp/types/cos.rs` | Full file | Negative result; supports legacy-selector finding; known layout work suppressed |
| `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs` | Full file | Negative on splitting the CAS transaction; supports ownership-boundary finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs` | Full file | One new compiler-enforced ownership finding; generic test split suppressed |
| `userspace-dp/src/afxdp/forwarding_build/cos.rs` | Full file | One new guardrail-first decomposition finding |

### File-by-File Inspection Log

### `userspace-dp/src/afxdp/cos/queue_service/mod.rs`

- Read all 2,057 lines. Traced `drain_shaped_tx` through exact direct service, non-exact selection, batch construction, submit dispatch, rollback, and queue/accounting settlement.
- `build_cos_batch_from_queue` is 122 lines (`1775-1896`) and creates a fresh typed `VecDeque` in both variants. Every returned non-empty batch therefore allocates and then loses that capacity at synchronous submit completion. Retained as R2-B1-01.
- `build_nonexact_cos_batch` clones `shared_exact_backlog` before borrowing the disjoint mutable runtime map, even though the adjacent `queue_fast_path` borrow proves the clone is unnecessary. Retained as R2-B1-02.
- UMEM ownership remains explicit: Local unwind returns free-frame offsets; Prepared unwind preserves recycle metadata; accepted-prefix settlement and retry suffix restoration remain variant-specific.
- The 432-line `select_exact_cos_guarantee_queue_waterfill` (`926-1357`) is real debt, but exact tracker #4408 already owns that function. Suppressed.
- The test-only unified guarantee selector is a dead alternate scheduler, not a production decomposition boundary. Its removal is covered under the assigned selector test file in R2-B1-04.

### `userspace-dp/src/afxdp/cos/queue_service/drain.rs`

- Read all 608 lines. The four functions separate Local/Prepared and FIFO/flow-fair ownership, not merely naming variants.
- Flow-fair drains carry bucket identity, pop snapshots, vtime updates, and rollback metadata. Prepared drains additionally preserve UMEM recycle ownership; Local drains stage copied frame payloads.
- No heap allocation occurs in these drains after the preallocated exact scratch vectors are built. Batch caps are fixed at `TX_BATCH_SIZE`; dispatch is static; there are no trait objects or locks.
- A shared generic drain would either introduce adapter machinery or make the borrow/rollback state harder to audit. Separate typed functions also let the compiler monomorphize and inline without an indirect call.
- **Negative result:** no independently useful split. Keep this file cohesive unless a measured code-size change justifies moving the four opaque bodies by variant without sharing their algorithm.

### `userspace-dp/src/afxdp/cos/queue_service/service.rs`

- Read all 718 lines and traced the four exact service bodies through reserve, insert, stamp, zero-insert unwind, accepted-prefix settlement, V_min publication, and accounting.
- The bodies are 184, 172, 174, and 171 lines. Their similarity is real, but Local/Prepared and FIFO/flow-fair have materially different scratch types, error cleanup, recycle ownership, and settlement functions.
- No dynamic dispatch or hot-path allocation was found. Direct specialized calls preserve static dispatch and variant-specific inlining.
- Closed issue #1207 already proposed one monomorphized service skeleton. Its review history records function-pointer indirect calls, borrow-checker conflicts, argument-spill/codegen risk, and semantic asymmetry; it was PLAN-KILLed.
- **Negative result / known suppression:** do not revive the generic skeleton. At most, outline a demonstrably cold common epilogue after differential assembly and throughput gates.

### `userspace-dp/src/afxdp/cos/queue_service/tests/selector.rs`

- Read all 1,262 lines and classified all 31 tests: non-exact guarantee/residual budget, exact starvation/surplus sharing, parking, batch cap/quantum, class-specific RR, surplus priority/weight, and promotion pairing.
- Nine tests call the test-only unified selector. Two exact-queue batch tests (`728`, `772`) therefore exercise a scheduler that production does not call; one test (`994-1022`) exists only to pin the dead selector's private cursor.
- Production selector coverage elsewhere in this file is strong, including direct exact/non-exact selectors and `build_nonexact_cos_batch`; full-path tests also exist in `drain.rs`, `refund.rs`, and `sojourn.rs`.
- Retained R2-B1-04 to port the remaining assertions to production entry points and remove the parallel implementation before changing batch storage.
- A file-only split by test names would be low value on its own. The proposed test directory in R2-B1-04 is tied to production entry points and accompanies deletion of the false test surface.

### `userspace-dp/src/afxdp/types/cos.rs`

- Read all 1,786 lines. Audited config/runtime split, queue hot state, boxed `FlowFairState`, V_min state, telemetry, timer-wheel state, fixed RR ring, and compile-time layout guards.
- The large flow-fair arrays are boxed once; `new_boxed` constructs the roughly 352 KiB value in place and has field-equivalence and collection-usability tests. No new allocation or stack-probestack finding survived review.
- `CoSQueueRuntime` already reflects #1206/PR #1216's config/hot/flow-fair/V_min/telemetry split. A new broad type-file split would duplicate that tracker without a narrower ownership benefit.
- `legacy_guarantee_rr` (`694-704`) is compiled only for tests and exists solely for the dead unified selector. It is part of R2-B1-04, not a release-layout concern.
- `CoSQueueOwnerProfile` atomics remain inline and cross-thread-read, but #1187/#1209 explicitly own double-buffered CoS owner-profile telemetry. Suppressed rather than restated.
- `priority_low_min_share_bytes` remains explicitly wire-only/deferred (`573-588`), matching known #4220 history; no new parity finding.

### `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs`

- Read all 1,460 lines. Traced legacy packed-credit acquire/release, v8 construction, epoch snapshot, primary fair-share acquire, bypass surplus acquire, give-back, and tag-checked rollback.
- `acquire_v8_with_cause` is 278 lines (`546-823`), but its class CAS, outstanding-credit CAS, worker-grant CAS, rotation checks, and rollback are one linearizable ownership protocol.
- Splitting that transaction into strategy callbacks or trait adapters would obscure ordering and risk an indirect call on every queue-lease acquire. The current free helpers are small, statically dispatched, and `#[inline]` where cross-module codegen needs it.
- Per-worker write-heavy arrays are cache-line padded where justified; `worker_fair_share` is read-mostly and rotation-written, so padding it would expand the footprint without removing a per-worker write-sharing pattern.
- `snapshot_epoch_v8` uses the documented seqlock sequence/fence contract. Existing contention and tag-wrap tests cover the difficult ownership boundaries.
- **Negative result:** keep the acquire transaction cohesive. Retained R2-B1-05 only for the narrower module-privacy defect exposed by the assigned tests.

### `userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs`

- Read all 2,511 lines. Coverage spans root lease bounds/alignment, v8 acquire and rehydration, equal-flow suppression, bypass, bounded carry, claim flow, give-back, concurrent ledger invariants, and seqlock publication.
- The suite contains valuable cross-field/concurrent invariants, including tag wrap, stale release, aggregate cap, and reader/writer ordering. It is not evidence that the production CAS transaction should be fragmented.
- `v8_carry_field_is_reader_private` (`1836-1891`) walks every Rust source file and enforces ownership with a string allowlist because the production field is `pub(super)`. That is weaker than a Rust module boundary. Retained as R2-B1-05.
- The opening `FlowRrRing` comment (`10-16`) is stale and unrelated to this suite, but comment hygiene alone is not issue-worthy.
- A generic “split the 2.5K test file” observation overlaps `codex-review-171.md` finding 29 and #2158's shared-lease modularity work. Suppressed; R2-B1-05 changes topology only where it restores compiler-enforced ownership.

### `userspace-dp/src/afxdp/forwarding_build/cos.rs`

- Read all 850 lines and traced table construction, scheduler-map resolution, per-interface queue materialization, useful-CoS admission, synthetic fallback, classifier flattening, rewrite generation, and final publication.
- `build_cos_iface_config` is 291 lines (`503-793`) despite the module header still describing the #1342 result as three sub-100-line helpers.
- Ten feature/correctness commits after #1342 have accumulated fail-closed parsing, safe dangling-reference behavior, equal-flow policy, priority validation, loss-priority rewrite, and percent-rate resolution in this one helper.
- The critical order is queue materialization, useful-state gate, synthetic fallback, final materialized set, classifier fallback tables, then config publication. A casual extraction can reintroduce owner-worker funneling or code-point blackholes.
- Retained as R2-B1-03 with characterization-first boundaries. This is config-apply code, not a packet hot path.

### Support reads (not independently audited modules)

- Queue lifecycle: `queue_service/submit_local.rs`, `submit_prepared.rs`, `cos/tx_completion.rs`, `tx/transmit/mod.rs`, `tx/drain/phase_shaped.rs`, `worker/scratch.rs`, `worker/mod.rs`, and `worker/cos_state.rs`.
- Shared ownership/layout: `shared_cos_lease/{mod.rs,epoch.rs,rotate_epoch_v8.rs,publish_equal_flow_epoch_v8.rs,backlog.rs}`, plus relevant CoS builders and token-bucket tests.
- Forwarding contracts: `forwarding_build/mod.rs`, targeted sections/test names in `forwarding_build/tests.rs`, and #1342 history.
- Required context and architecture: `agent-contract.md`, `orientation.md`, `shape-inventory.md`, `dedup-index.md`, `docs/engineering-style.md`, CoS/types READMEs, relevant PR plans, and issue/PR history.

## R2-b2: AF_XDP TX/UMEM ownership and zero-allocation hot-path specialist

Assigned candidates: **9**. Primary report: `codex-R2-b2.md`.

### Module Checklist

- [x] `userspace-dp/src/afxdp/tx/dispatch/mod.rs` (1,486 lines)
- [x] `userspace-dp/src/afxdp/tx/cos_classify.rs` (1,335 lines)
- [x] `userspace-dp/src/afxdp/tx/cos_classify_tests.rs` (4,617 lines)
- [x] `userspace-dp/src/afxdp/cos/tx_completion.rs` (1,080 lines)
- [x] `userspace-dp/src/afxdp/cos/tx_completion_tests.rs` (1,076 lines)
- [x] `userspace-dp/src/afxdp/tx/transmit/mod.rs` (365 lines)
- [x] `userspace-dp/src/afxdp/umem/mod.rs` (1,363 lines)
- [x] `userspace-dp/src/afxdp/umem/snapshot.rs` (359 lines)
- [x] `userspace-dp/src/xsk_ffi.rs` (1,288 lines)

### File-by-File Inspection Log

### `userspace-dp/src/afxdp/tx/dispatch/mod.rs`

Inspected the full file, including `compute_forwarded_egress_ptb` and the 1,049-line `enqueue_pending_forwards` span at lines 271-1319. The function still combines borrowed-ingress validation, same-UMEM in-place forwarding, direct target-UMEM construction, allocated NAT64/tunnel fallback, PTB generation, shared recycle routing, and exactly-once ingress finalization. That broad decomposition is already `#4408`/F-126 and is suppressed. The finalizer at lines 1285-1308 now reaches build-failure fallback and recycles every non-retained ingress descriptor; no recurrence of `#2208` was found. Ordinary same-UMEM forwarding retains descriptor ownership without a payload allocation; the explicit `Vec` copy path is limited to transformations that cannot preserve the original frame. Retained result: the owner lookup at lines 690-696 unnecessarily clones a shared `Arc` through its direct helper, covered by R2-b2-03.

### `userspace-dp/src/afxdp/tx/cos_classify.rs`

Inspected cached selection (lines 101-330), live selection/filter/rewrite resolution (lines 404-689), BA/PCP helpers, local/prepared queue ingress (lines 759-959), prepared-to-local demotion (lines 1006-1122), and admission (lines 1164-1331). Normal live selection uses borrowed filter results and fixed lookup tables; no new ordinary per-packet heap allocation was found. `clone_prepared_request_for_cos` copies by design when ownership cannot remain prepared, and the 64 KiB frontier snapshot plus temporary `VecDeque`/`Vec` in demotion is explicitly a rare TX-frame-exhaustion fallback. The file nevertheless contains four real ownership domains with different mutation and rollback rules. Retained results: R2-b2-05 for the production/test boundary and R2-b2-06 for the optional foreign-recycle sink exposed through this API.

### `userspace-dp/src/afxdp/tx/cos_classify_tests.rs`

Inspected all 4,617 lines and all 55 `#[test]` cases. The suite has distinct clusters for prepared ownership/admission (lines 1-714), cached/live filter and BA selection (715-2870), enqueue timestamps, generated replies/NAT64/PTB (2928-3490), TCP flags/PBR, counter/policer replay, and fail-closed PCP handling. It has strong semantic regression coverage but repeats large snapshot fixtures and can access every private helper only because it is one monolithic child module. It has no allocator-count gate for hot selection/admission or the pressure fallbacks. Retained result: colocate these clusters with the real modules in R2-b2-05; no separate test-only issue is warranted.

### `userspace-dp/src/afxdp/cos/tx_completion.rs`

Inspected timer-wheel state and scratch reuse, root priming, queue/root lease accounting, retry restoration, local/prepared settlement, and activity refresh. The timer wheel now reuses scratch and does not reproduce closed `#4270`. Local and prepared result paths preserve queue bytes, token/deficit debits, root debits, lease consumption, and refresh ordering. Three shared `Arc` handles are cloned per service/settlement call, and `refresh_cos_interface_activity` creates a fresh vector that allocates when a leased queue drains with banked tokens. Retained result: R2-b2-03. The near-duplicate local/prepared settlement bodies should not be genericized independently because request restoration and monomorphized hot code are deliberately type-specific.

### `userspace-dp/src/afxdp/cos/tx_completion_tests.rs`

Inspected all 1,076 lines and 23 tests. Coverage pins lease phase gating, root/shared backlog accounting, residual-surplus debit, retry-byte restoration for both request types, queue-state normalization, timer-wheel snap/cascade behavior, and park counters. The suite is cohesive with the completion module and is not large enough to justify a separate split. It does not measure allocation count or shared-`Arc` refcount traffic, which is the test gap carried by R2-b2-03.

### `userspace-dp/src/afxdp/tx/transmit/mod.rs`

Inspected local TX staging/submission, prepared entry points, cancellation recycling, error unwind, and the already extracted prepared `stage`/`rewrite`/`verify`/`write`/`finalise` phases. Successful full-batch submission uses preallocated binding scratch and preserves single-writer ring ownership. Partial ring reservation creates a new retry-tail vector, while expected no-frame/ring-full retries allocate `String`s and are sent to a locking last-error path. Foreign prepared cancellation also accepts an optional routing sink and falls back to the local TX free list when it is absent. Retained results: R2-b2-02 and R2-b2-06. A second broad prepared-transmit split is suppressed as completed `#1354`/PR #1586.

### `userspace-dp/src/afxdp/umem/mod.rs`

Inspected `WorkerUmem`/`Rc` ownership, `BindingLiveState`, cacheline-separated profiles, redirect-inbox admission, snapshots/status helpers, and queue drains. Per-worker `Rc<WorkerUmemPool>` is intentional and does not cross threads; `take_pending_tx_into` correctly appends into reusable caller storage without allocating. `BindingLiveState` is large but is an ownership/lifetime anchor whose cacheline layout and atomic placement should not be mechanically split, matching codex-review-173 item 22. The consuming drop-newest enqueue wrappers always return `Ok` even when the incoming request is dropped, while a separate `try_` API returns ownership. Retained result: R2-b2-04. The `pending_tx_admitted` false-sharing suspicion is suppressed as closed `#4096`.

### `userspace-dp/src/afxdp/umem/snapshot.rs`

Inspected the full operator snapshot projection. Its relaxed atomic loads, status lock/clone, histogram export, and diagnostic vector clones run on the control/status path, not packet submission. It is already the cold projection extracted from `BindingLiveState` by `#1351`; moving more live fields across this boundary would weaken ownership clarity. Negative result: no new refactor or hot-path finding.

### `userspace-dp/src/xsk_ffi.rs`

Inspected FFI declarations, UMEM and private/shared ring ownership, partial producer reservation, test-ring construction, RX/TX/fill/completion guards, socket creation, and drop order. Current production callers use one commit/release then immediately drop; multiple inserts before one commit are append-safe after PR #2383. Two separate guardrails remain: Rust manually mirrors libxdp ring struct layouts without a size/offset check (R2-b2-01), and reservation guards remain usable after partial commit/release even though their base index no longer represents the remaining range (R2-b2-07). No current caller was found exercising the latter misuse.

### Support Reads

Targeted source reads used only to verify assigned-file contracts: `tx/dispatch/cos.rs`, `tx/dispatch/shared_recycle.rs`, `tx/transmit/{stage,rewrite,verify,write,finalise}.rs`, `tx/transmit_tests.rs`, `tx/rings.rs`, `tx/drain/{mod,phase_backup}.rs`, `cos/cross_binding.rs`, `cos/queue_service/{mod,service,drain,submit_local,submit_prepared}.rs`, `worker/{mod,scratch}.rs`, `worker/cos/mod.rs`, `worker/loop_body/mod.rs`, `session_glue/mod.rs`, `types/tx.rs`, `umem/tests/{tx_inbox,latency_buckets,snapshot_propagation}.rs`, `xsk_ffi_tests.rs`, `csrc/xsk_bridge.c`, and `build.rs`.

Architecture and history reads: `AGENTS.md`, `userspace-dp/src/afxdp/README.md`, `userspace-dp/src/afxdp/{tx,cos,umem}/README.md`, `docs/userspace-dataplane-architecture.md`, `docs/userspace-libxdp-migration.md`, `docs/issues/{issue-history,pr-history}.md`, and the campaign orientation, shape inventory, and dedup index.

## R3-b1: Stateful firewall policy/session/filter architecture specialist

Assigned candidates: **9**. Primary report: `codex-R3-b1.md`.

### Module Checklist

| Candidate | Size at base | Inspection | Result |
|---|---:|---|---|
| `userspace-dp/src/policy.rs` | 3,657 LOC | Complete production-code read and symbol/call-boundary map | No new issue; exact #4421 / C131-L02 / A4-F1/F2 / AGY-171-07/08 duplicate |
| `userspace-dp/src/policy_snapshot_error.rs` | 896 LOC | Complete read, including every variant and `Display` arm | Negative; clean #4421 increment and recorded A4-F3 D-class boundary |
| `userspace-dp/src/policy_tests.rs` | 7,280 LOC / 180 tests | Complete test/symbol inventory; cluster boundaries and high-risk bodies inspected | No new issue; exact A4-F17 and codex-171-29 test-split duplicate |
| `userspace-dp/src/session/mod.rs` | 2,054 LOC | Complete production-code read and field/method ownership map | No new issue; exact #4421 / AGY-171-03 / A4-F4 duplicate |
| `userspace-dp/src/session/tests.rs` | 6,994 LOC / 165 tests | Complete test/symbol inventory; lifecycle, differential, stale-handle, NAT-index, HA, and limit clusters inspected | No new issue; known test-layout backlog; coverage is strong |
| `userspace-dp/src/filter/mod.rs` | 939 LOC | Complete read | No new issue; F-128 suppressed; A4-F16/#4566 status respected |
| `userspace-dp/src/filter/compiler.rs` | 1,056 LOC | Complete read | No new issue; exact AGY-171-17 / A4-F15 / #4421 duplicate |
| `userspace-dp/src/filter/engine/eval.rs` | 1,026 LOC | Complete read | Negative; existing engine decomposition is sound and A4-F16 says do not split further |
| `userspace-dp/src/filter/tests.rs` | 8,330 LOC / 152 tests | Complete test/symbol inventory; compiler-fail-closed, fall-through, cached replay, log, PBR, and counter-ownership bodies inspected | No new issue; exact A4-F17 and codex-171-29 test-split duplicate |

Support reads used only to validate boundaries, not to broaden the candidate set: `userspace-dp/README.md`, `userspace-dp/src/{filter,session}/README.md`, `docs/{engineering-style,refactoring-audit,userspace-dataplane-architecture}.md`, and the session siblings `ctx.rs`, `entry.rs`, `key.rs`, `install.rs`, `lookup.rs`, `expire.rs`, and `wheel.rs`.

### File-by-File Inspection Log

### `userspace-dp/src/policy.rs`

- Inspected the full 3,657-line module. It contains zone/address-book substrate, `PolicyRule` (`342`), the counter subsystem (`514-840`), compiled applications and `AppCatalog` (`873-1333`), `PolicyState` (`1336-1693`), snapshot compilation, evaluation, fragment-deny handling, and leaf parsers.
- `parse_policy_state_with_counters` (`1717-2248`, 532 lines) still combines zone maps, address books, rule identity/order, match compilation, global scope, applications, and stable counter linking. This is the exact cold parser seam already owned by #4421, A4-F1/F2, AGY-171-08, and codex-171-7.
- The application/catalog boundary (`CompiledApplications` at `873`, `AppCatalog` at `1116`) is the exact AGY-171-07/A4-F1 extraction. The counter boundary is the exact AGY-171-08/A4-F1 extraction. No materially different ownership boundary emerged.
- `evaluate_policy_result_l3_aware` starts at `2600` and keeps ordered zone-pair/global tiers, default decisions, fragment policy, app matching, and hit ownership in one hot new-flow/flowless evaluator. Repetition is visible, but the prior D-class instruction to keep this evaluator and `try_match_rule` (`3352`) co-located remains correct.
- Hot-path result: no proposed trait objects, heap objects, extra pointer indirection, or layout changes. Existing policy hit recording remains thread-local/batched with relaxed atomics; any future code motion must preserve rule order, stable rule IDs, counter identity, global-scope tier order, monomorphic calls, and inlining.
- Packet/ABI result: this module evaluates typed tuples and does not own or rewrite UMEM frames. No new endianness conversion, packet-copy, `repr(C)`, or FFI boundary was found.
- **Outcome:** negative after dedup. Reopening a broad policy split would duplicate #4421.

### `userspace-dp/src/policy_snapshot_error.rs`

- Inspected all 896 lines: one `SnapshotIntegrityError` enum (`11-626`), one exhaustive `Display` implementation (`628-894`), and the `Error` impl.
- The variants intentionally span policy, applications, NAT/NPTv6, filters, CoS, interfaces, routes, neighbors, and tunnels because one fail-closed reconcile preflight propagates a single error type.
- Commit `e3b487a6b6118a6deae89b83077e648d68bb22c8` already performed the safe flat extraction from `policy.rs`. Domain sub-enums would add wrappers/conversions without improving the single propagation boundary and would increase drift risk for stable error text.
- Cold-path result: no packet-path allocations, atomics, locking, layout, inlining, or packet-ownership concern. The mechanical `Display` size is not an independent god-function.
- **Outcome:** D-class negative. This confirms the A4-F3 status correction and suppresses AGY-171-02/F-242-style re-proposals.

### `userspace-dp/src/policy_tests.rs`

- Inventoried all 180 `#[test]` cases and 204 functions across 7,280 lines, then inspected representative bodies at every ownership boundary.
- Coverage clusters include snapshot/action/address parsing, applications and `AppCatalog`, address books and exclusions, ICMP, Junos-host policy, fragments, counter stability/reordering, wildcard and global policy ordering, NAT64 interactions, duplicate-ID preflight, and port parsing.
- The global-policy matrix around `5880-6235` pins scope/tier order and default behavior. Counter/reorder tests pin stable telemetry identity. Fragment and NAT64 clusters pin fail-closed behavior.
- There is clear file-layout debt, but A4-F17 already supplies the concrete `policy/tests_{apps,global,...}.rs` mapping, and codex-171-29 already owns the generic giant-test-file issue.
- Test-only split result: no production hot-path effect; preserve test names, fixtures, and cluster coverage when #4421 moves production modules.
- **Outcome:** no new issue. Known test-split suppressed.

### `userspace-dp/src/session/mod.rs`

- Inspected the full 2,054-line coordinator. `SessionEntry` (`344-459`) carries state/NAT/accounting/HA metadata; `SessionTable` (`501-650`) owns the slab, five tuple/index structures, timer wheel/GC, timeout policy, HA deltas, admission/limit maps, and counters.
- Hot mutation boundaries were traced: limit activation (`776`), stale touch (`989`), accounting (`1048`), companion state propagation (`1103`), `update_session` (`1170-1399`), delta enqueue (`1596`), centralized removal (`1616-1689`), restoration/index maintenance (`1701-1878`), multimap bucket maintenance (`1948-1984`), and timeout selection (`2014-2050`).
- `update_session` is long, but its collision checks, old-index snapshot, reindexing, entry mutation, wheel refresh, and HA delta are one atomic invariant. A casual helper split could create rollback gaps. `remove_entry` correctly keeps stale-handle guard/rollback, secondary-index cleanup, slab release, and limit decrement together.
- Existing sibling modules from PR #2028 already use code-motion-only `impl SessionTable` blocks. A further `{limit,delta,timeout}` peel and the 25-field hot/cold map are exactly A4-F4/#4421/AGY-171-03/codex-171-17.
- No `size_of::<SessionEntry|SessionMetadata|SessionKey|SessionTable>` or offset pin exists. That is not new: A4-F4 explicitly recorded the missing guard. Any field reorder or hot/cold object split remains prohibited until size/offset and assembly/performance baselines exist.
- Hot-path result: preserve worker-owned single-writer `&mut SessionTable`, the single allocation/ownership object, direct slab/index access, seeded maps, no new locks/atomics, no virtual dispatch, no extra pointer chase, and wheel/index mutation order. The current plain accounting fields correctly rely on worker ownership.
- **Outcome:** no new issue. Exact known architecture item suppressed.

### `userspace-dp/src/session/tests.rs`

- Inventoried all 165 tests and 203 functions across 6,994 lines. Inspected the base install/expiry and wheel clusters, TCP opening/close/companion transitions, HA sync/origin/index behavior, and timeout/iteration cases.
- Inspected the differential/reference harness (`3264-3939`), including stale and vacant handle rigs. These tests are strong guardrails for in-place update ordering and rollback behavior.
- Inspected NAT 1:N collision/index cleanup (`3940-4507`), admission and HA expiry (`4508-5279`), per-IP limit invariants (`5280-6188`), keepalive (`6189-6415`), delta loss/resync (`6416-6685`), and seeded-hash/accounting/close-delta cases (`6686-6994`).
- A physical split should follow `session/{lookup,install,expire,limit,delta,timeout}` and preserve shared rigs, but that is already covered by codex-171-29/A4-F17's test-layout backlog and #4421's session increment.
- Negative result: no uncovered ownership domain justifies a new issue. The only absent structural guard is the already-known layout pin from A4-F4.
- **Outcome:** no new issue. Known test-layout work suppressed.

### `userspace-dp/src/filter/mod.rs`

- Inspected all 939 lines: the compiled `FilterTerm` carrier (`113-259`), borrowed `TermMatchExtra` (`297-354`), port matcher/filter containers, counters, policer/cache descriptors, `FilterState` (`750-818`), and result types (`836-935`).
- The wide `FilterTerm` is a cache/match/action carrier shared by compiler and monomorphic evaluator; splitting it into boxed subobjects would add per-term pointer chasing and hurt the packet path. No field-layout change is justified without cache/assembly data.
- `CachedThreeColorPolicers` uses `SmallVec<[Arc<_>; 2]>`: the inline capacity is not a hard cap, and overflow occurs during cold descriptor construction. This is the resolved #4566 item and the A4-F16 status correction.
- `ThreeColorPolicerRuntime::meter` (`585-609`) takes the policer's state mutex. `filter/README.md:353-357` explicitly records this as the current correctness-first, non-final contention model. Replacing it requires a semantics design for one logical global rate, not a mechanical module refactor, so it is not recast as a batch finding.
- `FilterResult::default` (`898-909`) creates `Arc::<str>::from("")`, and matched modifiers clone string-bearing values. That is the exact known F-128 per-evaluation allocation finding and is suppressed below.
- Packet/ABI result: `TermMatchExtra` borrows the inspected frame; this module does not transfer UMEM ownership or perform byte-order rewrites. Counter batching remains thread-local with relaxed atomics.
- **Outcome:** no independent modularity issue; one exact performance duplicate suppressed.

### `userspace-dp/src/filter/compiler.rs`

- Inspected the full 1,056-line cold compiler. `parse_filter_state_with_three_color_preserving` (`54-337`) preserves runtime identity, compiles policers/filters, links interfaces, and applies lo0/default fail-closed checks.
- `parse_term` (`526-944`, 419 lines) parses and validates address scopes, protocol bitmap, positive/except ports, DSCP, TCP flags, ICMP, flexible match, actions, counters, and policer links.
- The concrete `filter/compile/{parse,validate,link}.rs` decomposition and a short `parse_term` driver are already AGY-171-17 and A4-F15, under the firewall-filter portion of #4421. No different phase boundary was found.
- Cold-path preservation: pure code motion only; do not reorder validation, silently drop unsupported fields, change stable policer/counter identity, or publish partial state. Every `SnapshotIntegrityError` path must remain before teardown/publication.
- Runtime result: compiler allocations are intentional snapshot-build work and are not per-packet. No packet ownership, inlining, ABI, endianness, or hot-layout issue originates here.
- **Outcome:** no new issue. Exact compiler split suppressed.

### `userspace-dp/src/filter/engine/eval.rs`

- Inspected all 1,026 lines. The file contains v4/v6 first-match loops (`103-220`), non-routing evaluation and deferred counter ownership (`249-483`), routing-instance/PBR evaluation (`495-605`), interface/lo0/output wrappers, and the log-only path.
- The visible v4/v6 and wrapper repetition encodes distinct typed matching calls, fall-through accumulation, latest-log identity, terminal-action normalization, PBR ownership, and exactly-once counting. It is not a safe invitation to generic trait dispatch or boxed evaluators.
- All core functions are inline candidates and remain monomorphic. The surrounding engine is already split into matching, cache-sensitive, TX-selection, policer, and eval modules by PR #1574.
- Hot-path result: preserve no allocation, no packet copy, borrowed metadata/frame access, direct branches, counter batching, fall-through order, cache/live parity, and the split between action evaluation and second-pass counter recording. Further file carving has no demonstrated i-cache benefit and creates inlining/codegen risk.
- Existing tests cover terminal/fall-through decisions, cached multi-counter and multi-policer replay, latest log term/final verdict, PBR miss/fallback, and non-routing counter ownership.
- **Outcome:** D-class negative, matching A4-F16 and superseding AGY-171-18's older split proposal.

### `userspace-dp/src/filter/tests.rs`

- Inventoried all 152 tests and 171 functions across 8,330 lines. Inspected matching, protocol/port/DSCP, policer/cache, interface/PBR/output/lo0, per-packet TCP/fragment/ICMP, and malformed-snapshot fail-closed clusters.
- Inspected fall-through, cached replay, logging, PBR, and counter-ownership tests around `6491-7561`. They pin modifier accumulation, final terminal verdict, latest logging-term identity, every matched cached counter/policer, and exactly-once counts.
- Prefix-list and flexible-match clusters pin compiler/evaluator parity; port-except boundary tests close the file. These are the correct guardrails for any compiler code motion and against evaluator over-generalization.
- A physical split mirroring `filter/{compiler,engine/{matching,eval,cache_sensitive,tx_selection}}` is warranted, but A4-F17 already provides that exact cluster-to-module mapping and codex-171-29 already owns giant Rust test files.
- **Outcome:** no new issue. Exact test-split suppressed.

## R3-b2: NAT/CGNAT/NAT64 and screen hot-cold state specialist

Assigned candidates: **12**. Primary report: `codex-R3-b2.md`.

### Module Checklist

| Candidate | Lines | Inspection result |
|---|---:|---|
| `userspace-dp/src/nat64.rs` | 3,102 | Inspected completely; broad split suppressed under `#4421`. |
| `userspace-dp/src/nat64_tests.rs` | 4,447 | Inspected test inventory and clusters; test split suppressed as prior art. |
| `userspace-dp/src/nat/allocator.rs` | 1,796 | Inspected completely; retained `R3B2-NAT-01`; broader allocator observations suppressed. |
| `userspace-dp/src/nat/source.rs` | 1,440 | Inspected completely; known matcher/source split suppressed under `#4409` and prior reports. |
| `userspace-dp/src/nat/destination.rs` | 1,109 | Inspected completely; cohesive hot lookup plus cold builder, no retained issue. |
| `userspace-dp/src/nat/static_nat.rs` | 808 | Inspected completely; cohesive static host/block mapping, no retained issue. |
| `userspace-dp/src/nat/tests_pool.rs` | 4,237 | Inspected all 82 tests; supports `R3B2-NAT-01`; broad test split suppressed. |
| `userspace-dp/src/nat/tests_destination.rs` | 1,770 | Inspected all 42 tests; no separate retained issue. |
| `userspace-dp/src/nat/tests_static.rs` | 1,198 | Inspected all 32 tests; no separate retained issue. |
| `userspace-dp/src/screen/mod.rs` | 1,540 | Inspected completely; retained `R3B2-SCREEN-01`; inline SYN split suppressed. |
| `userspace-dp/src/screen/scan.rs` | 1,213 | Inspected completely; confirmed prior do-not-split result. |
| `userspace-dp/src/screen/tests.rs` | 5,395 | Inspected all 173 tests; exact test split suppressed as prior art. |

### File-by-File Inspection Log

### `userspace-dp/src/nat64.rs`

Read all 3,102 lines. The file owns configuration snapshots and allocator reuse, fragment-association state, IPv4/IPv6 header walking, both translation directions, ICMP/ICMPv6 error translation, checksum adjustment, non-first-fragment writers, and frame construction. Those are real module boundaries, but the broad decomposition and essentially the same proposed child modules are already tracked by open issue `#4421`; no duplicate was retained. The current `_into` translation APIs preserve caller-owned packet buffers, frame builders are the deliberate allocation boundary, fragment-cache locking is sharded and fragment-only, and no newly distinct allocation, dynamic dispatch, or synchronization defect was found.

### `userspace-dp/src/nat64_tests.rs`

Inspected the complete 121-test inventory and representative bodies across parsing/classification, deterministic NAPT64, TCP/UDP/ICMP translation, VLAN/frame handling, extension headers, fragments, BIB allocation/release/HA reservation/reload, checksum differential checks, and fragment-association capacity/TTL. The file is large, but its exact family-based split is already represented in prior audit output and belongs with `#4421`; no new test-architecture issue was retained. It provides useful guards for allocator extraction, especially deterministic route selection, unsupported-prefix fallback, no-allocation `_into` APIs, and checksum parity.

### `userspace-dp/src/nat/allocator.rs`

Read all 1,796 lines, including pure deterministic mapping/reverse functions, atomic address occupancy, non-persistent and persistent allocation, release/rollback, HA reservation, snapshots, and chunked GC. The broad hot-allocation versus persistent-lease/GC split is known (`AGY-171-15`, `#4409`), and global live-map contention is tracked by `#2852`. One narrower post-tracker seam was retained: the deterministic IPv4 and IPv6 paths duplicate the same critical block-claim state machine after family-specific index derivation. The recently chunked GC releases the live mutex between chunks; the pressure fallback remains intentionally covered by the existing tracker rather than being restated here.

### `userspace-dp/src/nat/source.rs`

Read all 1,440 lines. The file combines source-NAT rule parsing, predicate matching, pool allocator state reuse across snapshots, release/rollback/HA wrappers, NAT64 adapters, and the new-flow match/allocate orchestration. The long `match_source_nat_result_for_tuple` extraction is already an exact prior finding and part of `#4409`; it was suppressed. No separate parser/runtime correctness seam survived dedup, and allocator identity reuse across reload remains explicit rather than accidentally rebuilding live occupancy.

### `userspace-dp/src/nat/destination.rs`

Read all 1,109 lines. Roughly the first half constructs exact and prefix indexes from snapshots; the runtime half performs exact-tier then longest-prefix lookup with protocol, interface, routing-instance, source-prefix, and port constraints. This matches the prior D-class assessment: the hot lookup structures and their cold builder share one clear DNAT indexing invariant. A builder extraction may become useful if the constraints grow, but current size and coupling do not justify a new issue. Constraint-specific coverage also exists in sibling NAT test modules, so this candidate alone does not reveal a missing guardrail.

### `userspace-dp/src/nat/static_nat.rs`

Read all 808 lines. Host and block static NAT parsing, index construction, bidirectional translation, zone matching, and port/protocol rejection form one cohesive one-to-one mapping component. The v4/v6 and forward/reverse paths are similar but encode different address-width and direction contracts; no sufficiently valuable split or current drift was found. Existing tests cover host mappings, block offsets, both families, zones, invalid blocks, and unsupported port translation.

### `userspace-dp/src/nat/tests_pool.rs`

Inspected all 82 tests and their fixtures. Coverage spans pool selection, PAT/ICMP behavior, persistent lease modes, expiry and rollback, sticky hashing, collision/FIFO behavior, fragment handling, HA reservation, deterministic CGNAT/NAPT64, concurrent bitmap fill/churn, exact capacity, and chunked GC. The large-file observation is already owned by `#4409` and the prior giant-test-file report. The separate deterministic v4 and v6 scenarios are strong behavior tests but do not directly prove that their common block-claim semantics remain identical, which motivates the differential guard in `R3B2-NAT-01`.

### `userspace-dp/src/nat/tests_destination.rs`

Inspected all 42 tests. They cover basic and protocol-specific DNAT, source scopes, exact-versus-prefix precedence, longest-prefix match, local destination registration, reverse lookup, defaults, duplicate handling, and parse failures. Interface/routing-instance and L4 constraint coverage is supplemented by sibling scope/L4/protocol test modules. No candidate-local refactor or test gap warranted a separate issue.

### `userspace-dp/src/nat/tests_static.rs`

Inspected all 32 tests. Coverage includes IPv4/IPv6 host mappings, block translation in both directions, invalid ranges, zones, port rejection, and parse failures. The fixtures are aligned with the cohesive `static_nat.rs` API; splitting this modest test file would add navigation without isolating a distinct contract.

### `userspace-dp/src/screen/mod.rs`

Read all 1,540 lines. The already reported large `check_packet_with_zone_id_opts` SYN-flood body was suppressed, but inspection found a distinct ownership problem: profile and mutable per-zone flood/cookie state are spread across many parallel `FxHashMap<String, _>` tables. Profile refresh must manually retain and prepopulate each table, while screened packets repeatedly hash the same zone name even though the caller already resolved and passes a stable `u16` zone ID. This is retained as `R3B2-SCREEN-01`; it addresses state locality and fail-open initialization invariants, not merely source-function length.

### `userspace-dp/src/screen/scan.rs`

Read all 1,213 lines, including the generic bounded tracker core, port-scan/IP-sweep wrappers, cleanup/eviction, pressure signaling, and inline tests. The shared generic core is monomorphized, keeps caps and cleanup policy together, and avoids trait objects. This confirms the prior `codex-review-174` and `fable-review-173` D-class result: a naive production split would duplicate or obscure the common bounded-state invariant. No issue retained.

### `userspace-dp/src/screen/tests.rs`

Inspected all 173 tests and their clusters: stateless extraction/checks, ICMP/UDP/SYN rates, cookie mint/validation/failover/cache generation, scan/sweep pressure and cleanup, missing profiles, flowless fragments, alarm-only behavior, and fabric re-screen suppression. The exact proposal to split this file into stateless/extract/rate/syncookie/scan/fabric suites already appears in `codex-review-171` item 29, so it was suppressed. The refresh tests for stale-state removal, threshold-controlled sketch allocation, and cookie generation are relevant gates for `R3B2-SCREEN-01`.

### Support Reads (not candidates)

- `userspace-dp/src/afxdp/poll_stages.rs:378`: verified that screen runs for every descriptor when any profile exists, resolves both `zone_id` and `zone_name`, and passes both to `ScreenState` before session processing.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:786`: verified the stage-10 placement in the descriptor loop and therefore the per-packet cost sensitivity.
- `userspace-dp/src/afxdp/forwarding_build/mod.rs:83`: verified that screen profiles are currently constructed as a name-keyed map; an ID-keyed state migration needs an explicit snapshot-build join rather than ad hoc lookup in the packet path.
- `userspace-dp/src/screen/packet.rs` and `userspace-dp/src/screen/syn_rate.rs`: verified profile ownership, fixed sketch allocation, and absence of per-increment heap allocation.
- `userspace-dp/src/nat/tests_scope.rs`, `userspace-dp/src/nat/tests_l4_match.rs`, and `userspace-dp/src/nat/tests_dnat_proto.rs`: verified destination constraint coverage outside the assigned test candidate.
- `docs/engineering-style.md`, `docs/deterministic-nat-cgnat.md`, `docs/syn-cookie-flood-protection.md`, `userspace-dp/README.md`, `docs/userspace-dataplane-architecture.md`, and `docs/research/2852-portalloc/microbench-results.md`: verified hot-path, deterministic reverse mapping, SYN-cookie HA, allocator sharing, and benchmark contracts only.

## R4-b1: Rust AF_XDP worker/coordinator/netlink concurrency specialist

Assigned candidates: **10**. Primary report: `codex-R4-b1.md`.

### Module Checklist

| File | Lines | Result |
|---|---:|---|
| `worker/loop_body/mod.rs` | 1,784 | Inspected completely; no new finding. Existing worker-loop decomposition trackers cover the broad shape. |
| `worker/mod.rs` | 1,631 | Inspected completely; no independent finding. Drop order, hot hashing, construction preallocation, and internal snapshot layout remain deliberate. |
| `coordinator/mod.rs` | 982 | Inspected completely; three retained findings: detached neighbor-monitor lifecycle, residual session poison swallowing, and quadratic replay filtering. |
| `coordinator/status.rs` | 1,045 | Inspected completely; no new finding. Long builders are cold read-side projections with cohesive status ownership. |
| `coordinator/cos_leases.rs` | 838 | Inspected completely; no new finding. Prior CoS and ArcSwap tracker boundaries apply. |
| `neighbor.rs` | 2,036 | Inspected completely; detached monitor lifecycle retained. Generic file splitting and probe-family abstraction suppressed. |
| `neighbor_dispatch.rs` | 1,399 | Inspected completely; reusable pending-neighbor sweep scratch retained as a performance-positive refactor. |
| `neighbor_resolver.rs` | 805 | Inspected completely; no new finding. Persistent socket, bounded queue, epoch guard, and joined lifecycle are coherent. |
| `coordinator/tests.rs` | 4,005 | Inspected completely; no correctness finding. Test-file decomposition is already covered by the giant-Rust-test tracker. |
| `worker/cos/tests.rs` | 2,708 | Inspected completely; no correctness finding. Test-file decomposition is already covered by the giant-Rust-test tracker. |

### File-by-File Inspection Log

### `userspace-dp/src/afxdp/worker/loop_body/mod.rs`

- Read lines 1-1,784, including `worker_loop` at lines 36-1,308 and all inline tests.
- Checked the command drain, ArcSwap refreshes, HA expiry, poll sweep, delta resync, per-second diagnostics, shutdown flush, and expired-session reaping boundaries.
- The packet sweep remains a direct call to monomorphized worker functions; no trait-object dispatch or new per-packet allocation was found here.
- The per-second diagnostics build a `String` and perform socket diagnostics outside the `debug-log` output gate, but the cadence is bounded and the behavior was deliberately retained by the closed Phase-2 worker-loop work. This is not independently issue-worthy without runtime evidence.
- Broad `worker_loop` extraction is suppressed under `[A1-rust-hotpath] F3`, #1326, #1776, and PR #1834.

### `userspace-dp/src/afxdp/worker/mod.rs`

- Read lines 1-1,631, including module wiring, `BindingWorker`, construction/test constructors, shared-group handling, Arc identity refresh, and `BindingLiveSnapshot`.
- Verified the explicit XSK-before-UMEM field/drop ordering at lines 98-200; this should not be obscured by a cosmetic split.
- `BindingWorker::create` preallocates packet/TX scratch and ring-dependent vectors at lines 375-607. The retained pending-neighbor finding extends this established scratch ownership rather than creating a new allocator boundary.
- Fabric hashing at lines 239-355 remains allocation-free and statically dispatched.
- `BindingLiveSnapshot` is a large internal telemetry DTO, not a public `repr(C)` ABI. No packet-path layout regression was identified.
- Generic `BindingWorker` deconstruction is suppressed under #959/#1125; telemetry restructuring is suppressed under #1187/#1209.

### `userspace-dp/src/afxdp/coordinator/mod.rs`

- Read lines 1-982, including tunnel-remap helpers, coordinator construction, neighbor apply, stop, session replay, warm scheduling, generation handling, and tests wiring.
- Retained the detached neighbor-monitor lifecycle at `stop_inner`, because its stop flag is signaled without retaining or joining the spawned thread before shared neighbor state is reset.
- Retained the session poison-recovery gap: final clear uses `if let Ok`, reconcile snapshot uses `unwrap_or_default`, and owner-index clear delegates to another poison-swallowing helper.
- Retained the replay filter's nested linear membership scans over potentially full session snapshots.
- Investigated poison swallowing around `manager_keys`. That mutex is coordinator-owned and its operations do not expose the same worker-panic path as shared session maps, so it is not bundled into the session finding without a demonstrated poisoning source.
- Broad coordinator decomposition is suppressed under #985/#1189/#1328/#1890.

### `userspace-dp/src/afxdp/coordinator/status.rs`

- Read lines 1-1,045, including neighbor, HA, policy/NAT, worker, binding, CoS, and WireGuard status projections.
- `drain_session_deltas` is the documented mutating exception in an otherwise read-side module; it has explicit ownership and is too narrow to justify another layer.
- `worker_runtime_snapshots` and `wg_tunnel_statuses` are long, but execute on status cadence and construct wire DTOs outside the packet path.
- No endianness, ABI, lock-order, or atomics/false-sharing defect was found in the assigned file.
- Splitting status solely by line count would create pass-through modules without removing a demonstrated coupling.

### `userspace-dp/src/afxdp/coordinator/cos_leases.rs`

- Read lines 1-838, covering six runtime-map publications, cross-worker status aggregation, owner selection, and root/queue/vtime lease construction.
- The field-by-field aggregation is verbose but has dedicated sum/max/min/sentinel tests in both assigned test files; no missing aggregation invariant was found.
- Sequential ArcSwap stores were examined for mixed-generation reads. #1188 already considered grouping runtime RCU state, and the accepted implementation retains independent pointer-identity short-circuits; no new broken cross-map invariant was demonstrated here.
- All allocation and map construction is coordinator/config cadence, not packet or UMEM cadence.
- The file is the cohesive result of #1890/PR #1897; another file-only split is suppressed.

### `userspace-dp/src/afxdp/neighbor.rs`

- Read lines 1-2,036, covering probe sockets, warmer, netlink message construction/parsing, startup dump, monitor, CPU affinity, and all inline tests.
- Retained the monitor lifecycle race spanning `neigh_monitor_thread` and coordinator teardown.
- Investigated the fixed 8,192-byte netlink receive buffers. The local Linux headers cap `NLMSG_GOODSIZE` below 8 KiB and neighbor messages are small; no present truncation bug was asserted without contrary evidence. A future shared recvmsg wrapper could add defense, but it is not a retained issue.
- Checked native-endian netlink header/attribute codecs; these are host-kernel ABI messages and consistently use native endian. IP payload octets remain network-order byte arrays.
- Startup dump sequence matching, seq-0 multicast absorption, ENOBUFS re-dump, and generation-1 gating correspond to closed #2918/#2919 work. No duplicate was opened.
- Generic decomposition is already open under #4421. The prior D-negative against family/socket traits for `trigger_kernel_arp_probe` is preserved.

### `userspace-dp/src/afxdp/neighbor_dispatch.rs`

- Read lines 1-1,399, including pending admission, retry/dispatch, RX neighbor learning, mirror/rewrite paths, and all inline tests.
- Retained the fresh `Vec` allocation at line 204 because this sweep runs on both RX-empty and post-batch worker poll paths whenever one pending key exists.
- RX learning uses a two-element stack array at lines 497-554 and keeps the common no-change case allocation-free; no regression was found there.
- The one-packet-per-hop map, negative cache, tunnel fail-closed gate, pre-rewrite mirror ordering, and UMEM recycle ownership remain explicit.
- Broad state-machine redesign is closed under #1771/PR #1774; the retained scratch reuse is a narrower allocator-cadence issue not covered by that tracker.

### `userspace-dp/src/afxdp/neighbor_resolver.rs`

- Read lines 1-805, including queue/counter layout, persistent netlink socket, GET request/reply codec, action and rate-limit decisions, worker loop, and test-module wiring.
- Worker enqueue is nonblocking and throttled before the `String` clone path; netlink I/O stays on one auxiliary thread.
- The single-key reply is bounded and small; the 8 KiB receive buffer is not treated as an independent issue.
- The epoch is loaded with Acquire and monitor mutation publishes with Release; confirmed insertion rechecks under the destination shard lock.
- Resolver stop retains and joins its `JoinHandle`, which is the correct lifecycle model and the direct contrast supporting R4-b1-01.
- No trait objects, packet-buffer aliasing, or public ABI/layout issue was found.

### `userspace-dp/src/afxdp/coordinator/tests.rs`

- Read lines 1-4,005 and inventoried all 88 tests.
- Covered clusters: injection tuple stamping, CoS ownership/leases/status aggregation, supervisor panic containment, binding refresh, reconcile teardown/quiesce, neighbor warming, WG lifecycle, GRE lifecycle, mandatory/optional map preflight, integrity failure atomicity, and manager-neighbor atomicity.
- The clusters map cleanly to existing production submodules, so a mechanical test directory split is feasible.
- That split is suppressed by the prior broad "giant Rust integration test files obscure ownership" tracker and PR #1081's prior relocation boundary.
- Missing guardrails relevant to retained findings: no poisoned reconcile-snapshot/final-clear test, no deterministic detached-monitor teardown test, and no replay-filter scale/operation-count test.

### `userspace-dp/src/afxdp/worker/cos/tests.rs`

- Read lines 1-2,708 and inventoried all 27 tests.
- Covered clusters: reset/drop accounting, worker status and owner-profile aggregation, fast-interface assembly, shared-exact classification, config-change detection, active-flow peak merge, waterfill minimum, and sojourn staleness.
- Large fixtures dominate the file, but they explicitly pin sum/max/min, sentinel, ownership, and Arc identity semantics.
- A directory split by `status`, `fast_interfaces`, and `shared_exact_policy` is mechanically possible but duplicates the giant-Rust-test tracker and PR #1089 relocation history.
- No production hot-path defect was inferred solely from test fixture size or formatting.

## R4-b2: Rust control protocol, WireGuard, event-stream, and slow-path specialist

Assigned candidates: **13**. Primary report: `codex-R4-b2.md`.

### Module Checklist

- [x] `userspace-dp/src/afxdp/wg/engine.rs`
- [x] `userspace-dp/src/afxdp/wg/engine_tests.rs`
- [x] `userspace-dp/src/afxdp/coordinator/wg_control.rs`
- [x] `userspace-dp/src/event_stream/mod.rs`
- [x] `userspace-dp/src/event_stream/codec/mod.rs`
- [x] `userspace-dp/src/protocol/binding.rs`
- [x] `userspace-dp/src/protocol/control.rs`
- [x] `userspace-dp/src/protocol/snapshot.rs`
- [x] `userspace-dp/src/server/helpers.rs`
- [x] `userspace-dp/src/slowpath.rs`
- [x] `userspace-dp/src/afxdp/shared_ops.rs`
- [x] `userspace-dp/src/afxdp/session_glue/mod.rs`
- [x] `userspace-dp/src/afxdp/session_glue/tests.rs`

### File-by-File Inspection Log

| Candidate | Inspection result |
|---|---|
| `userspace-dp/src/afxdp/wg/engine.rs` | Read all 1,805 lines. The file owns peer-table publication, handshake reservations, session/demux installation, timer edges, encap, and decap. `ArcSwap<PeerTable>` publishes routing state atomically; session slots and demux retain their documented `RwLock` discipline; packet crypto uses caller output buffers and fixed stack scratch with no trait-object dispatch. A further production-path split is not new after #1441/#2158 and risks separating `reconcile_lock` from demux/session rotation. Negative result; broad extraction suppressed. |
| `userspace-dp/src/afxdp/wg/engine_tests.rs` | Read all 1,464 lines and 23 tests. Coverage is cohesive around peer reconciliation, index collisions, session installation, AllowedIPs, PSK/secret handling, counters, and cookie pressure. The tests were already relocated by PR #2201; 23 invariant-heavy cases do not justify another split. Negative result. |
| `userspace-dp/src/afxdp/coordinator/wg_control.rs` | Read all 1,579 lines. The 314-line control loop combines attempt/timer FSM orchestration with UDP/TUN polling, while lower helpers own bind/send, CMSG parsing, TOS, sockaddr conversion, and packet delivery. The credible socket/CMSG-versus-FSM seam exactly duplicates `codex-review-173` item 17. Hot burst loops remain allocation-free and use concrete calls. Negative result after suppression. |
| `userspace-dp/src/event_stream/mod.rs` | Read all 1,692 lines. Producer sequencing is serialized by `producer_seq_lock`; replay, pause/drain fencing, loss latching, control parsing, and bounded channel/backlog semantics were traced. The remaining `Vec::drain` partial-write behavior is a distinct performance seam retained as R4B2-02. No separate generic size-only split is proposed. |
| `userspace-dp/src/event_stream/codec/mod.rs` | Read all 86 lines. This is now a clean facade over `wire`, `session_sync`, `rt_flow`, and `decode`; frames remain fixed `[u8; 256]`, with endianness localized in codec modules and no allocation or dynamic dispatch. The earlier codec-monolith observation has landed via #366/PR #382. Negative result. |
| `userspace-dp/src/protocol/binding.rs` | Read all 1,185 lines. `BindingStatus`, counter snapshots, conversion code, queue/HA rows, and exception/session-delta DTOs are wire-schema projection, not runtime ownership. Splitting the wide flattened status into nested runtime objects would add serde/Go parity risk without removing behavior. Keep the DTO and its projection adjacent (class-D boundary). Negative result. |
| `userspace-dp/src/protocol/control.rs` | Read all 1,088 lines. The request cap, request/response enums, `ProcessStatus`, slow-path/WireGuard status, and session-sync requests form the JSON control contract. This is already the control-domain result of #1325/PR #1567; further field-family shuffling would obscure cross-language schema review. Negative result. |
| `userspace-dp/src/protocol/snapshot.rs` | Read all 829 lines. Snapshot DTOs, capability gates, secret-redacting `Debug`, tunnel/WireGuard shapes, and the derived slow-path MTU belong to one versioned configuration contract. No packet hot path or mutable transaction is present. Negative result. |
| `userspace-dp/src/server/helpers.rs` | Read all 1,304 lines. It contains a 323-line status projection, session-sync wire reconstruction, binding settle gates, plan-key hashing, queue planning/sysfs access, and persistence. These have distinct callers and error boundaries, while hash/planner coupling must stay explicit. Retained as R4B2-03. |
| `userspace-dp/src/slowpath.rs` | Read all 913 lines. Slow-path queue/rate/status ownership is cohesive, but generic TUN creation, ioctl ABI, and whole-packet writers are also consumed by GRE and WireGuard through `crate::slowpath`. The packet semantics have strong characterization tests. Retained as R4B2-04. |
| `userspace-dp/src/afxdp/shared_ops.rs` | Read all 1,131 lines. Shared canonical, NAT-alias, forward-wire, and owner-index mutations were traced through publish, remove, demote, prewarm, and cross-scope lookup. Independent locks expose partial multi-map state even though `SessionManager` documents the structures as one unit. Retained as R4B2-01. |
| `userspace-dp/src/afxdp/session_glue/mod.rs` | Read all 1,277 lines. Forwarding resolution, filter revalidation, command dispatch, queue cancellation, and shared-hit promotion were traced. The broad dispatcher/shared-op splits are already #1346/PR #1595 and #369/PR #385. This file supplies cross-scope lookup evidence for R4B2-01; no second production split is retained. |
| `userspace-dp/src/afxdp/session_glue/tests.rs` | Read all 5,587 lines and 84 tests. The file has stable, non-overlapping clusters for shared-map aliases/indexes, promotion/lookup, command/failover behavior, collision/upsert behavior, and delta/event-stream integration. Retained as the mechanical test decomposition R4B2-05. |

## R5-b1: Go compiler/validator architecture and strict-vs-tolerant gate specialist

Assigned candidates: **10**. Primary report: `codex-R5-b1.md`.

### Module Checklist

- [x] `pkg/config/compiler_validate_warn.go`
- [x] `pkg/config/compiler_uniformgates.go`
- [x] `pkg/config/compiler_validate_strict_filter.go`
- [x] `pkg/config/compiler_validate_strict_policy.go`
- [x] `pkg/config/compiler_nat.go`
- [x] `pkg/config/compiler.go`
- [x] `pkg/config/compiler_prewalk.go`
- [x] `pkg/config/compiler_firewall.go`
- [x] `pkg/config/compiler_class_of_service.go`
- [x] `pkg/config/dual_ast_differential_test.go`

### File-by-File Inspection Log

### `pkg/config/compiler_validate_warn.go` (3,600 lines)

`ValidateConfig` spans most of the first 1,658 lines and mixes cross-reference warnings, accepted-but-inert advisories, runtime-capability checks, warning ordering, and one CoS normalization. The remainder contains partly extracted warning families and mirrored runtime predicates. This is compile/show-time control-plane work: no packet hot path, goroutine, or lock is owned here. Retained `R5B1-DIAG-02` because the public warning query mutates its input, is non-idempotent, and is not the warning source used consistently by REST/CLI/gRPC. The broad monolith observation is suppressed as known work.

### `pkg/config/compiler_uniformgates.go` (1,659 lines)

`runUniformGates` is one 1,633-line ordered function. Each typed-config gate returns the first strict error or appends a tolerant warning under a per-gate `compileOpts` flag. Its source order is an external contract for strict error precedence and tolerant warning order; it performs no config mutation beyond appending warnings. This is cold compile work with no dynamic interface dispatch, goroutine, lock, or dataplane allocation effect. No new finding: its decomposition is already tracked, and a naive domain split would obscure ordering unless an ordered runner is introduced first.

### `pkg/config/compiler_validate_strict_filter.go` (1,660 lines)

Inspected all filter reference, protocol, cross-field, action, match-value, flex-match, positive/except, literal, routing-instance, terminal-action, and DSCP validators. Filter maps are generally sorted before terms are walked, stabilizing first-error selection; helpers also form the Go-side semantic catalog used by runtime builders. Lenient behavior is owned at the caller, with invalid evidence retained for fail-closed Rust or deterministic fallback where documented. No new finding beyond the known package-style firewall validation split; the direct TCP-flags reject lives outside this suite and is covered by `R5B1-GATE-01`.

### `pkg/config/compiler_validate_strict_policy.go` (1,032 lines)

Inspected named-address recognition, application and address-set resolution, zone references, duplicate names, terminal/log actions, and address-book name validation. Policy and zone-pair slices preserve authored order; local maps are used for membership rather than publication order. The shared predicates intentionally mirror runtime resolvers and have no goroutine, lock, or hot-path ownership. No separately actionable refactor survived dedup; moving these validators without their ordering and resolver-parity tests would be a regression risk already covered by existing tracker work.

### `pkg/config/compiler_nat.go` (2,565 lines)

The file owns NAT parse/fold logic plus mode-aware host-mask, NPTv6, NAT64, and alarm validators. `compileNATSource` also performs deterministic-pool semantic validation directly over a map and returns hard errors before the uniform/tail mode gates. Lines 1690-1695 explicitly document that placing a semantic threshold check there would hard-fail `CompileConfigLenient` and brick legacy load. Retained this contradiction as part of `R5B1-GATE-01`; the generic NAT-monolith/package observation is suppressed as a duplicate.

### `pkg/config/compiler.go` (2,110 lines)

Inspected `compileOpts`, strict and tolerant generic/node entry points, inactive pruning, group expansion, collision gates, and P1-P7 orchestration. Compilation clones the input before mutating prewalks, builds a new `Config`, and returns no partially published object on error. `compileSections` is invoked in P4 before the mode-aware P6/P7 gates; section errors therefore terminate both strict and tolerant calls. The duplicated tolerant literals currently contain the same field set, so the known drift risk is suppressed rather than restated. Retained the missing section-gate policy boundary in `R5B1-GATE-01`.

### `pkg/config/compiler_prewalk.go` (432 lines)

`runPreWalkGates` is an ordered AST phase containing strict/tolerant checks plus sanitization, VRRP pruning, and interface-range expansion. It mutates only the compiler's cloned tree and emits warnings in source order before the typed skeleton is built. No new finding: this is a class-D boundary to preserve as one ordered phase unless mutation dependencies are first represented explicitly; the completed `#4406` extraction already documents that invariant.

### `pkg/config/compiler_firewall.go` (1,206 lines)

Inspected policer/filter compilation, family collision/`family any` AST gates, dual-AST match readers, term match parsing, and action parsing. The canonical `firewallMatchValues` reader correctly merges `Keys[1:]` and child forms. Lines 259-270 parse and hard-reject unrepresentable TCP flags inside P4, without a tolerant policy, even though the snapshot builder has an explicit unparseable marker and Rust fail-closed backstop. Retained in `R5B1-GATE-01`; the known broader firewall package split is suppressed.

### `pkg/config/compiler_class_of_service.go` (1,205 lines)

`compileClassOfService` spans lines 12-510 and combines typed construction with queue-ownership, DSCP/PCP code-point, and RSS-expectation rejects. The later helpers own interface-level inheritance, traffic-control resolution, rate parsing, and dual-AST code-point collection. Several comments state that older behavior accepted and dropped or masked out-of-range values, but the new rejects do not receive `compileOpts`; this is another concrete `R5B1-GATE-01` case. All work is commit/snapshot-build time; no scheduler packet-path layout, locks, or allocations are changed by the proposed boundary.

### `pkg/config/dual_ast_differential_test.go` (1,054 lines)

Inspected every fixture and the parse, `FormatSet`, replay, compile, and reflective section-diff pipeline. The harness covers valid hierarchical versus flat-set strict/generic compilation and deliberately sorts warnings because validator map order is unstable. It cannot express a hierarchical strict rejection as an expected result, does not invoke tolerant or node-aware entry points, and therefore cannot gate shape-dependent downgrade/fallback behavior. Retained `R5B1-MATRIX-03` as a refactor prerequisite, distinct from the known duplicated dual-AST grammar issue.

### Support reads (contract verification only)

- `AGENTS.md`, `pkg/config/README.md`, and `docs/config-schema.md`: compiler phases, schema/compiler parity, dual-AST rules, and strict/tolerant doctrine.
- `pkg/config/compiler_dispatch.go`, `compiler_tailgates.go`, `compile_golden_4406_test.go`, and `strict_gate_wiring_canary_test.go`: P4 dispatch, warning publication, six-entry compile matrix, first-error/warning-order guard, and canary scope.
- `pkg/configstore/store.go`, `store_format.go`, and `load_compile_fail_test.go`: strict commit versus tolerant Load/SyncApply, transactional promotion, active-config pointer ownership, and fail-closed recovery.
- `pkg/dataplane/userspace/filters.go`, `userspace-dp/src/filter/compiler.rs`, and associated tests: TCP-flags sentinel and Rust snapshot rejection.
- `pkg/api/config.go`, `pkg/cli/cli_show_system.go`, `pkg/cli/cli_show_security_log.go`, and `pkg/grpcapi/server_show_{system,security_text}.go`: warning/API/CLI/gRPC presentation parity.

## R5-b2: Go domain compiler/schema/type and CLI grammar modularity specialist

Assigned candidates: **13**. Primary report: `codex-R5-b2.md`.

### Module Checklist

| Candidate | Inspection result |
|---|---|
| `pkg/config/compiler_system.go` | Inspected all declarations and both large dispatchers; broad split is prior-tracked, with no new real package boundary retained. |
| `pkg/config/compiler_services.go` | Inspected all 27 functions; retained one IP-monitoring domain/phase boundary finding. |
| `pkg/config/compiler_interfaces.go` | Inspected interface/unit/tunnel/VRRP compilation and AST validators; prior dispatcher and dual-AST findings own the credible work. |
| `pkg/config/compiler_routing.go` | Inspected routing-options, static routes, instances, policy-options, and term parsers; no independent non-duplicate package seam. |
| `pkg/config/compiler_protocols.go` | Inspected the complete protocol dispatcher and helper parsers; prior `compileProtocols` finding owns it. |
| `pkg/config/types_system.go` | Inspected declarations and behavior-bearing methods; IP-monitoring model participates in the retained finding, remainder is declarative D-class. |
| `pkg/config/types_security.go` | Inspected declarations and zone/NAT/policy helper methods; no god type or safe standalone package extraction found. |
| `pkg/config/schema_security.go` | Inspected builders and both schema literals; preserve the grammar SSOT as D-class. |
| `pkg/config/schema_system.go` | Inspected system/services/SNMP/event schemas and builders; IP-monitoring registration participates in the retained finding, remainder is D-class. |
| `pkg/cmdtree/tree.go` | Inspected operational grammar, dynamic completions, typed leaves, traversal, lookup, and help; preserve the literal as D-class. |
| `pkg/config/parser_security_test.go` | Inspected 114 tests plus 6 helpers by function cluster and representative bodies; prior test-colocation finding owns the split. |
| `pkg/config/parser_ast_test.go` | Inspected 121 tests plus 1 helper by parser/compiler/groups/system clusters and representative bodies; prior finding owns the split. |
| `pkg/config/parser_routing_test.go` | Inspected 95 tests plus 1 helper by routes/protocols/tunnels/bridge clusters and representative bodies; prior finding owns the split. |

### File-by-File Inspection Log

### `pkg/config/compiler_system.go`

At 1,888 lines and 27 functions, `compileSystem` spans lines 16-518 and `compileChassis` spans 1558-1827. The file also owns login, syslog, userspace dataplane, Shared-UMEM artifact ingestion, DDNS, SNMP, schedulers, and backup-router validation. Those are cold compiler responsibilities with no goroutine, lock, or packet-path ownership. The tempting per-feature file carve is already codex-review-171 finding 22 and ps-review-039 finding 2; it would remain flat `package config` shuffling, not a new domain module. No new finding retained.

### `pkg/config/compiler_services.go`

At 1,821 lines and 27 functions, this file spans RPM validation, DHCP, dynamic feeds, IP monitoring, flow export, sampling, relay, event-options, and bridge domains. The broad same-package split is already codex-review-171 finding 23 and ps-review-039 finding 3. The IP-monitoring slice at lines 790-1042 is different: parsing, cross-domain resolution, strict validation, and typed-model mutation form one runtime-owned semantic unit, and its mutation violates the newly documented compiler phase boundary. Retained as R5B2-IPMON-01.

### `pkg/config/compiler_interfaces.go`

`compileInterfaces` spans lines 25-537, `parseVRRPGroups` spans 694-910, and lines 931-1211 hold shape-sensitive AST validators/warning derivation before interface DDNS at 1213-1279. State is built locally and published into `InterfacesConfig`; no reconcile lock or goroutine is involved. Fable-review-173 A6 F6 already owns the dispatcher extraction, while codex-review-175 F-205 owns the duplicated dual-AST property walkers. A subpackage would have to import or re-expose the private `Node` AST and shared config types, creating a wider interface without an independently owned state machine. No new finding retained.

### `pkg/config/compiler_routing.go`

The file has 16 functions: routing-options (9-139), static routes (155-373), routing instances (385-499), policy-options (535-677), and policy-term parsing (679-1167), plus a public connected-prefix derivation. The largest current body is `compileStaticRoutes` at 219 lines. Source order and dual hierarchical/flat-set shapes are load-bearing, but no function publishes runtime state or holds locks. Fable-review-173 A6 F6 already records these mid-band compiler dispatchers, and routing policy extraction without its types/schema would only move private-AST switch arms to flat files. No new finding retained.

### `pkg/config/compiler_protocols.go`

`compileProtocols` spans lines 12-803 (792 lines) and contains LLDP, OSPF/OSPFv3, BGP, IS-IS, RIP, and related nested grammar; router advertisement is already separate at 805-920. This is the exact fable-review-173 A6 F4 finding. Its proposed helper/file extraction is duplicate work, while a true protocol package would also require the unassigned routing types/schema contracts and a private-AST adapter. No new finding retained.

### `pkg/config/types_system.go`

The file is predominantly typed configuration declarations plus redaction/effective-value helpers. `SystemConfig` is an aggregate root rather than behavior-owning god state; SNMP marshal methods deliberately keep JSON/YAML secret projections together. The IP-monitoring model at lines 748-818 is the exception relevant to R5B2-IPMON-01: it exposes an unchecked two-string next-hop union that the compiler later rewrites. Fable-review-173's D-negative remains correct for the rest of the file.

### `pkg/config/types_security.go`

The 1,306-line file contains small domain records for scheduler, feeds, zones, policy, NAT, screen, address books, applications, and IPsec. Its 15 functions are narrow canonicalization/presentation helpers such as sorted zone refs, global-zone scope predicates, session-log tokens, and NAT scalar/plural compatibility. No type owns goroutines, locks, publication, or a broad mutable lifecycle. Moving declarations alone would churn imports and split model locality without moving behavior. The prior D-negative is confirmed.

### `pkg/config/schema_security.go`

`schemaSecurity` spans lines 154-1221 and `schemaApplications` spans 1223-1250; three builders create fresh mutable schema nodes to avoid aliasing between grammar locations. The bulk is the declarative `setSchema` SSOT consumed by completion and strict schema validation. Splitting literals into feature files or packages would either fragment that review surface or require exporting mutable `schemaNode`. Fable-review-173's schema D-negative is confirmed.

### `pkg/config/schema_system.go`

The file owns the declarative `system`, `services`, `snmp`, and `event-options` registrations plus fresh-node builders for shared DHCP/DDNS grammar. IP monitoring is one cohesive subtree at lines 578-633; it remains a thin root-schema adapter in R5B2-IPMON-01 rather than moving the private schema engine. The remaining table is a completion/validation SSOT, not executable control flow. The prior D-negative is confirmed.

### `pkg/cmdtree/tree.go`

Lines 134-1067 are the canonical operational-command literal, lines 1099-1137 are the config top-level/description overlay, and lines 1142-1549 are completion/help mechanics. The local README explicitly requires the operational grammar to remain greppable in one file and separates it from config-mode `setSchema`. Dynamic completion runs at keystroke cadence and reads candidate config snapshots; it performs no I/O or long-held locking. Fable-review-173 A9 F11 already permits only an optional low-value tail carve and classifies the grammar literal D. Codex-review-175's nil-entry completion defects are correctness trackers, not a new modularity seam. No finding retained.

### `pkg/config/parser_security_test.go`

The file contains 114 tests and 6 helpers across firewall, flow export, IPsec, policies, routing-policy terms, screen, NAT, address books, and flexible matches. Tests exercise both hierarchical and flat-set shapes, but test ownership is visibly multi-domain. Fable-review-173 A6 F7 already gives the exact per-domain colocation plan; moving tests does not establish a production package boundary. No duplicate finding retained.

### `pkg/config/parser_ast_test.go`

The file contains 121 tests and 1 helper across lexer/parser/edit/format, generic compile/validation, RPM, interfaces, event-options, routing instances, dataplane/Shared-UMEM, groups, and policers. It is a broad regression ledger whose split is already part of fable-review-173 A6 F7. Existing IP-monitoring tests live in the separate support file `parser_ipmonitoring_test.go`, so this candidate does not close R5B2-IPMON-01's phase-purity/tolerant-mode gap. No duplicate finding retained.

### `pkg/config/parser_routing_test.go`

The file contains 95 tests and 1 helper across static routes, routing instances, OSPF/BGP/IS-IS/LLDP, port mirroring, tunnels, bridge domains, and policy terms. It includes useful cross-domain end-to-end fixtures, so a package-directory move would require exporting compiler internals; the prior same-package colocation finding is the safer boundary. No duplicate finding retained.

### Support reads (not candidate findings)

- Architecture/contracts: `AGENTS.md`, `pkg/config/README.md`, `pkg/cmdtree/README.md`, `docs/architecture.md`, `docs/engineering-style.md`, `docs/config-schema.md`, `docs/multi-wan.md`, and `pkg/ipmon/README.md`.
- Compiler phase/call graph: `pkg/config/compiler.go`, `compiler_dispatch.go`, `compiler_derivations.go`, `compiler_earlystrict.go`, `compiler_uniformgates.go`, and `pkg/configstore/store.go`.
- IP-monitoring behavior/tests/consumers: `pkg/config/parser_ipmonitoring_test.go`, `pkg/ipmon/ipmon.go`, daemon/FRR/dataplane references found by call-site search, and the Shared-UMEM capabilities consumer checked while classifying `compiler_system.go`.
- Dedup/history: the full shared dedup index, codex-review-171, fable-review-173, codex-review-175, ps-review-039, issue history, PR history, and relevant git log/blame for #1827, #1844/PR #1851, #3757-#3763, #4423, and #4406/PR #4470.

## R6-b1: Go daemon lifecycle/reconcile ordering and god-struct decomposition specialist

Assigned candidates: **10**. Primary report: `codex-R6-b1.md`.

### Module Checklist

| Candidate | Result |
|---|---|
| `pkg/daemon/daemon_run.go` | Inspected; retained R6-b1-03. Broad `Run` decomposition is landed in #4662 and suppressed. |
| `pkg/daemon/daemon_apply.go` | Inspected; retained R6-b1-01. The `applyConfigLocked` phase extraction is landed in #4407 and suppressed. |
| `pkg/daemon/daemon_ha.go` | Inspected; no new finding. Prior `reconcileRGState` / `watchClusterEvents` decomposition remains the applicable item. |
| `pkg/daemon/daemon_ha_sync.go` | Inspected; retained R6-b1-01 and R6-b1-02. Generic `startClusterComms` size/splitting is suppressed as prior work. |
| `pkg/daemon/daemon_ha_fabric.go` | Inspected; supports R6-b1-02. No independent file split is warranted. |
| `pkg/daemon/daemon_nft.go` | Inspected; no new finding. Prior lowering split and landed fail-open-state grouping cover the credible seams. |
| `pkg/daemon/daemon_system.go` | Inspected; retained R6-b1-04. Generic file-by-domain motion is suppressed as prior work. |
| `pkg/daemon/daemon_ddns_surface_a.go` | Inspected; no new finding. The bounded state owner is already landed under #4407. |
| `pkg/daemon/bootstrap.go` | Inspected; D-class negative. Preserve its ordered safe-bootstrap owner. |
| `docs/pr/4662-daemon-run-decompose/plan.md` | Inspected against current #4662; historical plan is stale but the seven planned increments landed. |

### File-by-File Inspection Log

### `pkg/daemon/daemon_run.go` (2,422 lines)

`Run`, its phase helpers, and the ordered shutdown were traced from config load through manager construction, first apply, background launches, signal handling, and teardown. #4662 has reduced `Run` to bounded phase orchestration; re-proposing that landed extraction would be duplicate work. The retained concern is narrower: `startHTTPServer` publishes a serving goroutine before `startGRPCServer` constructs and publishes the HA-aware session service, despite REST clear semantics depending on that service. This is control-plane startup, not a packet path. Existing daemon/API tests do not stage a request in that publication window.

### `pkg/daemon/daemon_apply.go` (2,033 lines)

All commit, commit-confirmed, rollback, sync, and background apply entry points were traced through `applySem`, store promotion, the named reconcile phases, deferred errors, peer sync, and post-apply session invalidation. The #4407 extraction is materially complete: `applyConfigLocked` at lines 546-659 is now a linear phase shell, while the ordering-sensitive dataplane/HA block remains cohesive in `applyDataplaneAndHACore`. The retained defect is outside that landed split: peer sync treats promoted store identity as applied identity after an apply error and also skips post-apply finalization on nonfatal errors. No packet-loop allocation or dispatch is involved.

### `pkg/daemon/daemon_ha.go` (1,511 lines)

Cluster and VRRP event consumption, RG transition computation/actuation, periodic reconciliation, blackhole ownership, direct/VRRP mode differences, and shutdown state clearing were inspected. The state-machine ordering is centralized and guarded by epochs/current-state checks. Fable-173 A8 F8 already proposes separating transition computation from actuation and event decoding; no materially different owner or guardrail emerged. Splitting individual transition side effects before that characterization gate would make ordering harder to audit.

### `pkg/daemon/daemon_ha_sync.go` (1,020 lines)

Sync-ready timers, peer callbacks, config receive, heartbeat/session startup, retries, fabric listeners, fencing, bulk sync, and runtime restart were inspected. The generic 466-line `startClusterComms` observation is already Fable-173 A8 F5. R6-b1-02 retains a narrower ownership defect: mutable generation handles are published piecemeal by an unjoined goroutine after runtime restart became supported. R6-b1-01 also originates here because the active-text duplicate shortcut can acknowledge an apply that previously failed after promotion.

### `pkg/daemon/daemon_ha_fabric.go` (965 lines)

Fabric IPVLAN setup, neighbor probing, BPF `fabric_fwd` publication/clear, dual-fabric refresh, and netlink monitoring were traced. The file is one fabric-forwarding ownership domain, and the fwd0/fwd1 duplication is known helper-level work rather than a package split. Its refresh loops currently select on replaceable `Daemon` channel fields, which is evidence for the HA-generation owner in R6-b1-02; no separate fabric issue is retained.

### `pkg/daemon/daemon_nft.go` (1,455 lines)

Host-inbound and lo0 fail-closed apply paths, fail-open state, family-specific rendering, command execution, and cleanup were inspected. The recent host-inbound state grouping is bounded and keeps its mutex/atomic contracts. `nftRulesFromTerm` remains the known Fable-173 A8 F7 lowering seam. No new transaction, lock, schema-parity, allocation, or API-consistency defect was found.

### `pkg/daemon/daemon_system.go` (1,310 lines)

Security-log destination reconciliation, session aggregation, hostname/timezone, kernel settings, users/login/SSH, password hashing, and sudoers ownership were inspected. Generic per-domain file motion is already Fable-173 A8 F10 and is suppressed. One concrete lifecycle owner is missing: every apply creates and registers a new aggregation callback, while cancellation stops only its flush goroutine. That independently actionable resource/per-event-cost defect is R6-b1-04.

### `pkg/daemon/daemon_ddns_surface_a.go` (843 lines)

Surface-A manager publication, generation/hash guards, DDNS timers, DHCP/event callbacks, nudge coalescing, context ownership, and shutdown were inspected. Its state is already grouped under `surfaceA`, uses atomics/mutexes for cross-goroutine publication, and has bounded reconcile entry points. No new owner, rollback gap, stale generation, or hot-path regression was found beyond the landed #4407 increment.

### `pkg/daemon/bootstrap.go` (931 lines)

Bootstrap entry/exit, lifeline setup, interface naming, dataplane detach/reattach, FRR/networkd cleanup, NAT alarm teardown, and rollback posture were inspected. This remains the Fable-173 A8 F13 D-negative: the ordered safe-bootstrap state machine is a correctness boundary. Decomposing its teardown by subsystem would obscure the fail-safe order without adding ownership.

### `docs/pr/4662-daemon-run-decompose/plan.md` (191 lines)

The plan's phase map, extraction constraints, defer timing, and test posture were checked against source and the current tracker. It documents only Increment 1, while #4662 records seven merged increments and closure. The source has the named phase helpers described by the current issue. Updating historical PR-plan status may be useful housekeeping, but it is neither a new module seam nor an ownership/guardrail defect for this audit.

### Support Reads (Not Candidates)

- `pkg/daemon/daemon.go`: `Daemon` fields and construction, especially `sessionSync`, `grpcSrv`, cluster-comms context, peer addresses, and fabric channels.
- `pkg/configstore/store.go`: `SyncApply` parse/compile, active promotion, history, and persistence ordering.
- `pkg/cluster/manager.go`, `pkg/cluster/sync_conn.go`, `pkg/cluster/sync_config_gen_test.go`: stop/event contracts, config generation high-water, callback success semantics, and retry tests.
- `pkg/vrrp/manager.go`: event-channel and stop ownership.
- `pkg/logging/ringbuf.go`, `pkg/logging/aggregator.go`: callback registration/dispatch and aggregator memory/run-loop ownership.
- `pkg/api/api.go`, `pkg/api/server.go`, `pkg/api/sessions.go`, `pkg/api/sessions_ha_scope_3423_test.go`: REST dependency injection and HA clear behavior.
- `cmd/xpfd/main.go`: production `Run(context.Background())` caller.
- Current GitHub issue bodies/comments for #4407 and #4662; nearest prior issues #94, #3932, #4033, #4038, and #4151 were checked for deduplication.

## R6-b2: Go control-plane to dataplane protocol/compilation modularity specialist

Assigned candidates: **14**. Primary report: `codex-R6-b2.md`.

### Module Checklist

- [x] `pkg/dataplane/userspace/protocol.go`
- [x] `pkg/dataplane/userspace/maps_sync.go`
- [x] `pkg/dataplane/userspace/manager.go`
- [x] `pkg/dataplane/userspace/manager_ha.go`
- [x] `pkg/dataplane/userspace/eventstream.go`
- [x] `pkg/dataplane/compiler.go`
- [x] `pkg/dataplane/compiler_iface.go`
- [x] `pkg/dataplane/compiler_nat.go`
- [x] `pkg/dataplane/compiler_filter.go`
- [x] `pkg/dataplane/loader.go`
- [x] `pkg/dataplane/types.go`
- [x] `pkg/configstore/store_commit.go`
- [x] `pkg/dataplane/userspace/protocol_test.go`
- [x] `pkg/dataplane/userspace/eventstream_test.go`

### File-by-File Inspection Log

- `pkg/dataplane/userspace/protocol.go` (3,064 lines): inspected all 78 exported wire structs, the two `ProcessStatus` JSON methods, protocol versions, and binary event constants. Retain R6B2-04. The six-domain file split itself is exact duplicate F-A7-6 and is suppressed.
- `pkg/dataplane/userspace/maps_sync.go` (1,763): traced ctrl fail-close, bootstrap, classifier-map mutation/caches, helper-status reconciliation, binding verification, and plan-key derivation. Retain R6B2-01. The 451-line `applyHelperStatusLocked` extraction is duplicate F-A7-2.
- `pkg/dataplane/userspace/manager.go` (421): inspected `Manager` state ownership, runtime facade methods, mode/lifecycle locks, RST retry state, and apply-result publication. Negative: this is a composition root; no independent split improves ownership before the publication transaction is extracted.
- `pkg/dataplane/userspace/manager_ha.go` (1,440): traced RG/watchdog publication, forwarding-arm decisions, status-counter deltas, session install/delete wire conversion, lock release around IPC, and endian conversion. Negative: no new issue beyond F-A7-3; its HA/counter/session split and native-endian guardrails are already indexed.
- `pkg/dataplane/userspace/eventstream.go` (1,169): traced accept/read/ACK goroutines, sequence watermarks, pending callbacks, drain fences, decode branches, and counter atomics. Retain R6B2-03. The generic transport/dispatch/codec carve is duplicate F-A7-7.
- `pkg/dataplane/compiler.go` (1,733): traced `CompileConfig` phase ordering, every early return after prior sink mutation, stable ID allocation, and ignored FIB-bump error. Retain R6B2-02. The 295-line `compilePolicies` file split is already covered by F-A7-5.
- `pkg/dataplane/compiler_iface.go` (1,394): inspected VLAN creation, address reconciliation, the measured 915-line `compileZones`, networkd metadata, fabric/bridge assembly, destructive unmanaged-interface cleanup, protected-interface/device-map guards, and stale-map deletion. Retain R6B2-02; suppress the narrower five-helper split as F-A7-1.
- `pkg/dataplane/compiler_nat.go` (1,258): inspected deterministic counter IDs, the measured 726-line NAT compiler, source/destination/static/NPTv6/NAT64 ordering, and stale deletes. It contributes to R6B2-02's plan boundary. Negative for a separate issue: source/destination phase extraction is exact F-A7-5.
- `pkg/dataplane/compiler_filter.go` (814): inspected the measured 354-line filter compiler, protocol preflight, term expansion, port/address lowering, policer IDs, and stale table clearing. It contributes to R6B2-02. Negative: no filter-specific ownership or hot-path split survives independently.
- `pkg/dataplane/loader.go` (1,207): traced userspace-only load/attach, `CompileUserspaceShim`, legacy-pin cleanup, attach fallback, and all 55 no-op `userspaceShimCompileDataplane` overrides. Retain R6B2-02; moving the adapter to another flat file alone is not a module boundary.
- `pkg/dataplane/types.go` (1,056): inspected all 51 C/Rust/BPF mirror structs, padding, native/network byte-order comments, constants, and the userspace-only session trailers. Negative: no new split beyond F-A7-12; ABI/layout tests must remain attached to any future domain move.
- `pkg/configstore/store_commit.go` (835): traced persist-before-promote, history/journal ordering, nested confirmed commits, generation-guarded timeout rollback, lock order, durable confirm state, and rollback-file failure policy. Negative: the store-local transaction is cohesive. The accepted cross-layer rule that a fatal apply does not unwind an already persisted promotion is explicitly documented by #2138 and is not re-reported.
- `pkg/dataplane/userspace/protocol_test.go` (1,914; 41 tests): inspected field-specific round trips, hand-authored Rust-shaped JSON, legacy aliases, and ProcessStatus parity tests. Retain R6B2-04 because no Go test consumes the shared Rust fixture or checks the full type inventory.
- `pkg/dataplane/userspace/eventstream_test.go` (2,412; 38 tests): inspected codec boundaries, callback/ACK behavior, malformed telemetry, reconnect/drain, session-gap resync, and telemetry-gap tolerance. Retain R6B2-03: truncation is tested only as a pure decoder and no stream test places malformed session sequence N before valid telemetry N+1.

### Support Reads

- Architecture: `docs/userspace-dataplane-architecture.md`, `docs/architecture.md`, `pkg/dataplane/README.md`, and `pkg/configstore/README.md` for the sole-runtime-path, reconcile, fail-closed, and durability contracts.
- Go publication/callers: `pkg/dataplane/userspace/manager_compile.go`, `manager_generation.go`, `process_status.go`, `applied_nat_view.go`, `pkg/dataplane/dataplane.go`, `pkg/dataplane/maps_fabric.go`, and `pkg/daemon/daemon_apply.go`.
- Go supporting tests: classifier-map capacity/fail-close tests, route-overlay publish-failure tests, required-protocol-gate tests, and retirement-boundary canaries.
- Rust control wire: `userspace-dp/src/protocol/{mod,control,binding,cos,nat,resolution,security,snapshot,tests}.rs` plus `userspace-dp/tests/fixtures/protocol_wire_v1.json`.
- Rust event wire: `userspace-dp/src/event_stream/{mod,producer}.rs` and `event_stream/codec/{mod,wire,session_sync,rt_flow,decode}.rs`.
- XDP consumer: `userspace-xdp/src/lib.rs`, used only to confirm that the candidate Go classifier maps directly affect enabled per-packet branch decisions. No finding is assigned to these support files.

## R7-b1: Go API/gRPC metrics, session, and show-surface architecture specialist

Assigned candidates: **12**. Primary report: `codex-R7-b1.md`.

### Module Checklist

- [x] `pkg/api/metrics_descriptors.go`
- [x] `pkg/api/metrics_userspace.go`
- [x] `pkg/api/metrics.go`
- [x] `pkg/api/sessions.go`
- [x] `pkg/api/security.go`
- [x] `pkg/api/show_text.go`
- [x] `pkg/grpcapi/server_sessions.go`
- [x] `pkg/grpcapi/server_show_security_text.go`
- [x] `pkg/grpcapi/server_show_interfaces.go`
- [x] `pkg/grpcapi/server_show_zones.go`
- [x] `pkg/grpcapi/server_diag_system_action.go`
- [x] `pkg/api/metrics_test.go`

### File-by-File Inspection Log

### `pkg/api/metrics_descriptors.go` (2,013 lines)

`newCollector` spans lines 10-2013 and initializes exactly 287 Prometheus descriptors in one struct literal. Construction runs once at API server setup, not on scrape or packet paths. The descriptor count matches the 287 `*prometheus.Desc` fields and the 287 sends in `Describe`; `metrics_descriptor_coverage_test.go` is the non-nil guard. This is a real merge-conflict and reviewability concentration, but the exact per-domain extraction is already cataloged by codex-review-171 item 15, fable-review-173 A9 F1, and ps-review-039 F-039-05, so no duplicate finding is retained.

### `pkg/api/metrics_userspace.go` (1,839 lines)

`collectUserspaceStatus` performs one control-socket `Status()` call and fans the resulting `ProcessStatus` into 27 domain emitters. The emitters receive the large status value by value, but its slices/maps remain header copies; compiler escape diagnostics identify bounded per-scrape maps/slices in histogram and fairness derivation rather than a second status fetch or deep status copy. Changing every signature to a pointer would save only scrape-cadence stack copies and is not independently material. The established invariant is the single `Status()` call, and the known per-domain file carve must preserve it; this is suppressed as codex-review-171 item 16 / fable-review-173 A9 F2.

### `pkg/api/metrics.go` (1,091 lines)

The collector type occupies lines 17-593; `Describe` is a manual 287-descriptor publication table at lines 595-889, and `Collect` is the ordered scrape orchestrator at lines 891-1055. I traced pre-dataplane health metrics, loaded-dataplane gating, the cached session snapshot, userspace status fanout, and final error-series publication. The 3-second session cache and singleflight avoid duplicate concurrent table walks, while `collectUserspaceStatus` remains one status RPC. No new allocation, lock, or ordering seam survived dedup; splitting the descriptor fields/publication table separately from the known descriptor constructor would increase three-way drift unless done as one existing metrics workstream.

### `pkg/api/sessions.go` (1,291 lines)

The REST surface owns offset and cursor pagination, reverse-entry enrichment, peer adaptation, summaries, clear delegation, filter/view construction, v4/v6 projection, and token codecs. REST parses `limit`, `offset`, and `page_size` with unsigned canonical parsing and rejects negatives before iteration. Cursor rows are bounded by `page_size`, while the legacy path intentionally walks both maps to return an exact total; per-row reverse lookup remains one extra lookup when enrichment is enabled. The broad REST/gRPC/CLI extraction, first-interface model, peer first-page sizing, scan amplification, and token padding are known work. The REST validation behavior is retained only as the parity side of `R7B1-SESS-01`.

### `pkg/api/security.go` (805 lines)

`zonesHandler`, `policiesHandler`, and `screenHandler` duplicate the structured gRPC zone/policy/screen projection; `eventsHandler` and `matchPoliciesHandler` own REST-specific grammar and response mapping. Policy counters use one `NewPolicyCounterReader` snapshot, preserving the O(P+C) bulk boundary and first-read error; policy and global-policy slices preserve authored priority. Zone and screen response rows are sorted before publication. The policy/match-policy extraction is already fable-review-173 A9 F8 and the lifeline visibility gap is codex-review-127 M08/L05 plus #3682; no new finding is retained.

### `pkg/api/show_text.go` (338 lines)

`showTextHandler` locally renders 12 topics already rendered by gRPC. The #4712 fix added `sortedKeys` and routes every map-backed REST topic through it, so repeated REST output is deterministic. The `dynamic-address` branch still renders only configured URL/name/interval data even though `api.Server` already owns a wired `feedsFn`; gRPC and local CLI additionally render live prefix, last-fetch, and degraded state. That concrete parity drift, plus the unpropagated ordering fix in the other copies, is retained in `R7B1-SHOW-02`; the generic renderer duplication remains suppressed.

### `pkg/grpcapi/server_sessions.go` (1,402 lines)

This file owns cursor and legacy reads, filter construction/matching, peer fanout, summaries, destructive clear, projection, and page-token codecs. `GetSessions` rejects negative `Offset`, but dispatches every non-positive `PageSize` to legacy mode; the legacy normalizer turns every non-positive `Limit` into 100. Consequently negative signed pagination fields are accepted here although REST rejects them, and a negative page size silently ignores a supplied cursor. This is retained as `R7B1-SESS-01`. The cursor's unfiltered `setSessionsTotal` calls the O(N) `dataplane.Manager.SessionCount` scan and enriched rows do one reverse lookup each, but repeated session-scan amplification is already ps-review-038 F-08 / #4484; filtered clear materialization and multi-interface filtering are also existing findings.

### `pkg/grpcapi/server_show_security_text.go` (1,063 lines)

The file is already function-partitioned into 23 focused render/helper functions covering security log, schedulers, applications, screen views, dynamic address, address book, IKE, WireGuard, RPM, and IPsec. Most inventory loops explicitly sort names, but `showSchedulers` line 268, `showDynamicAddress` line 860, and both address-book loops at lines 899/905 range maps directly. These are the gRPC renderers used by remote CLI and they retain live feed status that REST drops. `R7B1-SHOW-02` retains this exact incomplete #4712/parity guard; a generic file carve would be flat-file shuffling and is not proposed.

### `pkg/grpcapi/server_show_interfaces.go` (935 lines)

`ShowInterfacesDetail` spans lines 69-415 and `showInterfacesTerse` lines 417-773; both combine config inventory, RETH resolution, kernel/sysfs observations, addresses, DHCP leases, counters, and rendering. Terse mode canonicalizes `(physName, unitNum)` at lines 547-552. Detail mode instead builds `logicals` by ranging a map, sorts only physical names, and emits each physical group's unsorted units. The local CLI repeats the same defect and remote CLI consumes this gRPC output. `R7B1-IFACE-03` retains the missing canonical model/order guard; the broad god-function/shared-presenter work and authored/kernel/VLAN identity bugs are suppressed as prior findings.

### `pkg/grpcapi/server_show_zones.go` (395 lines)

`GetZones`, `GetPolicies`, and `GetScreen` are near-line-for-line transport projections of the REST handlers. They preserve one active config pointer per call, one bulk policy-counter snapshot, sorted zone/screen rows, authored policy order, runtime policy IDs, scheduler state, and lifeline visibility. The proto3 zone counter scalars cannot distinguish an omitted unavailable value from zero as cleanly as REST's `per_zone_counters_available`, but that is part of the shipped #3643/#3651 counter contract rather than a new decomposition seam. No additional finding is retained beyond the already cataloged shared policy/security projection.

### `pkg/grpcapi/server_diag_system_action.go` (486 lines)

`SystemAction` spans lines 66-486 and multiplexes power, wipe, lock, neighbor, counter, routing, IPsec, DHCP, DDNS, cluster failover, and userspace-control actions. I traced journal-before-power/wipe ordering, peer proxy recursion guards, typed provider calls, and error-code mapping. The fabric interceptor separately parses the two proxied failover grammars in `server.go`, while this handler reparses them; #4693 already demonstrates validation drift, but typed parsing/action-registry extraction is a refinement of fable-review-173 A9 F5 and #4122, not a new issue. The known negative-to-uint32 userspace IDs are also suppressed.

### `pkg/api/metrics_test.go` (2,432 lines)

The file contains 25 tests grouped around worker/cold-path metrics, event stream, policy and policer counters, NAT/dynamic buffers, CoS fairness, binding telemetry, and sojourn histograms. Tests construct partial collectors deliberately and compare descriptor identity, labels, metric type, and value. It is large but contains the characterization coverage needed by the known per-domain metrics split; moving each test cluster with its emitter/descriptor domain is reasonable only as part of that existing work. No independent production boundary, hot-path concern, or new test-only issue is retained.

### Support reads (contract verification only)

- Campaign context: `orientation.md`, `dedup-index.md`, `shape-inventory.md`, the exact candidate list, and `agent-contract.md`.
- Architecture/style: `pkg/api/README.md`, `pkg/grpcapi/README.md`, `pkg/cli/README.md`, `proto/README.md`, `docs/architecture.md`, `docs/engineering-style.md`, and `docs/session-sync-architecture.md`.
- Session contracts: `proto/xpf/v1/xpf.proto`, `pkg/dataplane/maps_session.go`, `pkg/grpcapi/runtime.go`, session pagination/filter/HA tests, and local/remote CLI session callers.
- Show contracts: `pkg/api/server.go` (wired feed status), `pkg/grpcapi/server_show.go`, `cmd/cli/show.go`, `cmd/cli/show_interfaces.go`, `pkg/cli/cli_show_services.go`, `pkg/cli/cli_show_security_objects.go`, and `pkg/cli/cli_show_interfaces.go`.
- Security/action contracts: host-inbound lifeline helpers/tests, `pkg/grpcapi/server.go` fabric allowlist parser, SystemAction tests, and `docs/research/3643-dead-counters/plan.md`.

## R7-b2: Interactive/remote CLI dispatch and presenter modularity specialist

Assigned candidates: **13**. Primary report: `codex-R7-b2.md`.

### Module Checklist

- [x] `pkg/cli/cli_show_flow.go` (1,247 lines)
- [x] `pkg/cli/cli_show_routing.go` (1,131 lines)
- [x] `pkg/cli/cli_show_system.go` (1,055 lines)
- [x] `pkg/cli/cli_show_nat.go` (897 lines)
- [x] `pkg/cli/cli_show_interfaces.go` (486 lines)
- [x] `pkg/cli/cli_show_security_dispatch.go` (538 lines)
- [x] `pkg/cli/cli_show.go` (281 lines)
- [x] `pkg/cli/monitor.go` (949 lines)
- [x] `pkg/cli/cli.go` (540 lines)
- [x] `cmd/cli/show.go` (449 lines)
- [x] `cmd/cli/main.go` (551 lines)
- [x] `cmd/cli/shared.go` (610 lines)
- [x] `cmd/xpfd/main.go` (335 lines)

### File-by-File Inspection Log

### `pkg/cli/cli_show_flow.go`

The file owns local session projection for IPv4/IPv6, summary/brief/detail modes, peer augmentation, top-talker ordering, flow statistics, timeout/config output, and flow-monitoring health. `showFlowSession` deliberately captures one command's config/name maps and iterates dataplane state in order; iterator failures are surfaced after partial output and peer RPC failures are warnings, so extraction must preserve those error boundaries. Session rows allocate formatted strings and top-talker mode retains/sorts session projections, while ordinary display streams through the iterator; this is operator control-plane work, not packet processing. The tempting `showFlowSession`/session-view split is already covered by `codex-review-171` finding 25 and fable-review-173 A9 F3/F7, while RG ownership, peer summary/pagination, and top-talker bounds have separate prior findings. No new file-size-only split is retained.

### `pkg/cli/cli_show_routing.go`

This is a flat collection of one-function-per-routing-topic presenters: route/RIB/instance views, OSPF/BGP/ISIS/RIP/BFD/VRRP, ARP/IPv6 neighbors, and fixed FRR/netlink queries. Each handler owns a narrow query-render cycle; there is no shared transaction, goroutine, lock, or publication boundary to extract. External commands use fixed argument vectors, manager errors generally terminate the command, and presentation allocations are bounded by returned route/protocol snapshots rather than a dataplane loop. A directory containing the same set of `show_bgp.go`, `show_ospf.go`, and `show_route.go` files would only reproduce the current flat split. The routing-instance `next-table` omission is already `C175-HC-129`; no new modularity finding is retained.

### `pkg/cli/cli_show_system.go`

The file groups independent system show commands over `/proc`, `/sys`, fixed external tools, config history, services, process/connection state, and redacted configuration. The handlers do not share mutable state beyond the `CLI` dependency bag; each command owns its read, formatting, and error policy. Some commands materialize command output or file lines, but none is on a reconcile or packet path, and no extraction would alter lock, atomic, batching, or cache behavior. The prior package split proposal would create topic-named siblings without a stronger owner; this base already routes each topic through a small handler. Known `show log` authorization/bounds concerns such as `C175-HC-099` are behavioral issues, not a new decomposition seam, so no finding is retained here.

### `pkg/cli/cli_show_nat.go`

The file owns local source/destination/static/NPTv6/persistent NAT presentations and their config, counter, pool, and session-count joins. Command-local maps and counters are built before rows are emitted; dataplane/session iterator errors are reported rather than silently publishing a complete-looking result. Work is proportional to configured rules and, for selected views, session scans, but it does not run in packet processing and adds no shared locks. The genuine cross-surface boundary already landed as `pkg/natshow`; the remaining local and remote adapters have intentionally different output contracts under the closed #1687 design. Splitting the residual handlers by NAT subtype would be flat file motion, and the known per-rule count attribution defect is fable-review-161 F-071, so no new finding is retained.

### `pkg/cli/cli_show_interfaces.go`

The residual file now owns interface dispatch/summary and tunnel views after the larger detail/terse/extensive/statistics/RETH split landed in sibling files. `showInterfaces` still interleaves kernel discovery, configured/logical identity joins, zone state, and summary rendering, but those reads form one snapshot-like command and have ordering-sensitive visible output. It allocates per-command maps/slices and performs netlink/sysfs reads; there is no persistent mutation or forwarding-path effect. Codex-review-174 finding 11 and fable-review-173 A9 F6 already cover the interface presenter/RETH decomposition, and the base shows substantial implementation of that work. A further summary file move without a shared interface view model would not create a module, so no new finding is retained.

### `pkg/cli/cli_show_security_dispatch.go`

This file is a security command router plus the inline policy-list/detail presenter; it delegates zones, screens, IPsec, WireGuard, objects, logs, and filters to existing siblings. The policy path reads counters once, joins active config metadata, and renders in policy order; it does not call status once per row or hold a lock across output. `handleShowSecurity` is large because it encodes command grammar and help behavior, while the policy branch's projection is coupled to ordering, tier, scheduler, exclusion, and counter semantics. Moving each switch arm into another `cli_show_security_*` file would continue the existing flat split. The grammar ownership issue is retained as `R7B2-HC-001`; previously indexed policy/ALG presentation gaps are suppressed.

### `pkg/cli/cli_show.go`

This is the local `show` umbrella. It resolves unique prefixes against the canonical command tree before exact dispatch, then delegates almost every domain to an existing handler. It has no transaction or long-lived state; mutation is limited to normalizing `args[0]` for the current command. The important coupling is not its 281-line size but the fact that local parsing semantics differ from the remote dispatch while both advertise the same command tree. That ownership/parity issue is retained as `R7B2-HC-001`; another same-package dispatch split is not.

### `pkg/cli/monitor.go`

The file owns the local flow-trace lifecycle: validated path creation, rotating writer, subscription/goroutine startup, cancellation, status, and event-line formatting. `monitorFlowState.mu` is the lifecycle owner; start publishes state after resources exist, stop cancels and clears it, and the worker owns the writer/subscription until exit. This is background telemetry, not packet processing; per-event formatting allocates, but writer rotation and subscription ordering matter more than file size. The state machine and writer are a coherent module already, and fable-review-173 explicitly reached the same negative result. The writer-error stale-`active` defect is already `C175-HC-064`, so no new refactor finding is retained.

### `pkg/cli/cli.go`

`CLI` is the local REPL composition root: it holds managers/provider functions, readline/config state, command cancellation, signal handling, and roughly thirty narrow setter hooks used by daemon assembly and tests. The run loop serializes interactive commands; its mutex protects only the current command context, while managers retain their own lock and lifecycle ownership. The wide dependency bag makes command modules desirable but is not itself an independent split: moving setters or field groups would add indirection without reducing domain coupling. No hot dataplane state is stored here, and command allocations are terminal/readline work. The typed command boundary in `R7B2-HC-001` gives future modules narrow executor interfaces; no separate god-struct finding is retained.

### `cmd/cli/show.go`

The remote `show` shell performs a 325-line exact-token switch, selects typed RPCs for some domains, and constructs `ShowText` topic strings for the remainder. Its header states that PR #4660 was pure code motion into same-package `show_*` siblings and intentionally preserved call sequences and text proxy behavior. That split improved navigation but did not create a parser/protocol owner: completion still comes from `cmdtree`, dispatch remains handwritten, and string topics remain a second grammar. Concrete command drift is retained in `R7B2-HC-001`; the stringly wire boundary is retained separately in `R7B2-HC-003`. Repeating the PR #4660 per-feature split is suppressed.

### `cmd/cli/main.go`

This file owns remote CLI process bootstrap, flags, TLS/dial/status setup, readline, non-TTY execution, and a small residual set of commit/diagnostic/test handlers. Startup ordering intentionally establishes the server connection before most requests; command cancellation is scoped by `shared.go`, and `-c` exits after one dispatch. The `test policy` path explicitly rejects commas and equals because the legacy `ShowText` topic cannot encode those values, providing direct evidence for `R7B2-HC-003`. Moving each residual handler to another `cmd/cli/*.go` file would not change process or protocol ownership. The already-reported daemon-dependent local WireGuard key generator is suppressed.

### `cmd/cli/shared.go`

This file combines remote command context ownership, output-pipe parsing/filtering, operational/config dispatch, and command-tree help lookup. The command mutex guards cancellation state, while dispatch itself is serial; config mode transitions and RPC error boundaries are explicit. The output path is materially stale: it redirects process-global stdout, reads the entire pipe, splits/copies it, and applies case-insensitive filters, unlike the current local streaming implementation. That is retained as `R7B2-HC-002`; shared grammar ownership is retained as `R7B2-HC-001`. The remaining helpers are small adapters, so no generic `shared.go` file split is proposed.

### `cmd/xpfd/main.go`

The daemon entrypoint performs one-shot subcommand selection, strict config checking, generated configuration display, protocol-version output, and normal daemon bootstrap. Its main function is long because startup order is the contract: parse, choose one-shot behavior, load/validate, construct, then run; moving stages behind generic interfaces would obscure fail-fast ordering and error exits. One-shot renderers already live in their domain packages, and there is no packet-path loop, shared lock, or repeated allocation here. The package currently has no tests, but the absence of tests alone does not justify a structural split. This is a negative/D-boundary observation: preserve visible startup sequencing and extract only if a future lifecycle object acquires an independently testable owner.

### Support Reads (Contract Tracing Only)

- `pkg/cli/cli_dispatch.go` and `pkg/cli/cli_dispatch_pipe_stream_4731_test.go`: local dispatch, pager/filter semantics, bounded streaming implementation, and its regression gates.
- `cmd/cli/monitor.go`, `cmd/cli/show_flow.go`, `cmd/cli/show_nat.go`, and remote CLI tests: remote streaming producers, structured RPC adapters, and coverage boundaries.
- `pkg/cmdtree/tree.go` and its tests: advertised operational grammar, dynamic completion, aliases, and the claim that this is canonical.
- `proto/xpf/v1/xpf.proto`, `pkg/grpcapi/server_show.go`, `pkg/grpcapi/server_sessions.go`, and focused gRPC tests: `ShowText` wire schema, topic parsing, unary output ownership, and session API contracts.
- `pkg/cli/README.md`, `cmd/cli/README.md`, `cmd/xpfd/README.md`, and plans #1044c, #1444, #1517, #1563, and #1687: intended local/remote contracts, historical file moves, and the rejected universal-presenter design.
- Support files were used only to verify candidate contracts; no standalone findings are assigned to them.

## R8-b1: HA/VRRP/RA distributed-state and wire-codec modularity specialist

Assigned candidates: **13**. Primary report: `codex-R8-b1.md`.

### Module Checklist

- [x] `pkg/vrrp/instance.go` (2,417 lines)
- [x] `pkg/vrrp/manager.go` (1,108 lines)
- [x] `pkg/vrrp/vrrp_test.go` (2,468 lines)
- [x] `pkg/cluster/sync_conn.go` (1,858 lines)
- [x] `pkg/cluster/sync.go` (998 lines)
- [x] `pkg/cluster/sync_protocol.go` (829 lines)
- [x] `pkg/cluster/heartbeat.go` (881 lines)
- [x] `pkg/cluster/failover.go` (876 lines)
- [x] `pkg/cluster/election.go` (475 lines)
- [x] `pkg/cluster/status.go` (721 lines)
- [x] `pkg/cluster/sync_test.go` (4,717 lines)
- [x] `pkg/ra/sender.go` (990 lines)
- [x] `pkg/ra/ra.go` (880 lines)

### File-by-File Inspection Log

1. **`pkg/vrrp/instance.go`**
   Traced the instance state machine, timer ownership, IPv4/IPv6 receive goroutines, source-address refresh, packet transmit, VIP mutation, GARP/NA launch, and shutdown join. `run` is the state owner; receivers feed `rxCh`; socket closure releases blocking reads. Retained R8-B1-01 because the MASTER `stopCh` branch exits without invalidating the token used by detached GARP/NA follow-ups. The generic six-file split and state/preempt helper extraction are exact prior findings and were not repeated.

2. **`pkg/vrrp/manager.go`**
   Traced manager lock scope, instance reuse/restart/removal, sync-hold timers, address watcher lifecycle, RG priority/resign publication, and AF_PACKET socket construction. `UpdateInstances` builds replacements before stopping old instances where possible, and `Stop` joins each `vi.stop`; that join does not include detached cluster burst goroutines, which supports R8-B1-01. The broad `UpdateInstances`/instance file split is prior work; no separate finding retained.

3. **`pkg/vrrp/vrrp_test.go`**
   Inspected collection, packet codec, checksum, state, sync-hold, preempt/resign, dual-stack tie-break, AF_PACKET/VLAN/IPv6 extension-header, receive, event-drop, transmit, and GARP atomic tests. Codec tests cover normal round trips and malformed frames. GARP tests manipulate `garpEpoch`/state directly, but no assigned test drives the actual MASTER `stopCh` branch while a follow-up token is captured. Test-only file; no standalone decomposition finding.

4. **`pkg/cluster/sync_conn.go`**
   Traced generation maps, queue/journal producers, setup/auth publication, dual-fabric selection, send/receive goroutines, frame allocation/auth verification, the 27-case dispatcher, callback goroutines, and pointer-identity disconnect cleanup. Retained R8-B1-03: async accepted handshakes have no setup/publication generation, process a pending legacy frame before publication, and transfer cold-prime responsibility using only `wasDisconnected`. The embedded generation guard is an exact prior finding and was suppressed.

5. **`pkg/cluster/sync.go`**
   Traced message identifiers/header ownership, `SessionSync` lock and atomic domains, callback surfaces, bulk/barrier/failover waiters, generation initialization, config apply queue, failover batch payload helpers, status snapshots, and stale-session reconciliation. Wire ownership is split across this file, `sync_protocol.go`, `sync_conn.go`, `sync_auth.go`, and `sync_bulk.go`, but #551/PR #632 and F-095 already track that decomposition. No new broad codec finding retained.

6. **`pkg/cluster/sync_protocol.go`**
   Inspected framing/write-full behavior; monotonic clock helpers; IPv4/IPv6 session, delete, IPsec, config-generation, and DHCP lease codecs; every offset; little-endian boundary; optional trailing-field tolerance; and allocation shape. The session codec is cohesive and intentionally length-tolerant. A new package move would duplicate #551/PR #632 without a new failure boundary, so the current codec boundary is a negative result. Any future move still needs byte-golden, truncation, fuzz, and allocation gates.

7. **`pkg/cluster/heartbeat.go`**
   Traced the fixed-size heartbeat body, monitor/version truncation, auth tail reserve, HMAC/replay decision, sender ownership, receiver/auth/election order, timeout goroutine, and monotonic liveness. Wire/auth/send/receive locality is useful: tail reservation and verification depend on one size contract. The group-count overflow is fixed and exactly tracked by codex-review-172/#4434. Negative result: do not split this file absent a typed codec API that preserves the auth-tail invariant and allocation count.

8. **`pkg/cluster/failover.go`**
   Traced single and batch manual failover, pre-hook unlock/relock, revalidation, transfer-out and commit grace, timeout suppression, heartbeat override application, abort/rollback, and event publication. All mutable transfer state is under one `Manager.mu` domain; hooks run unlocked and state is re-read before commit. Negative class-D result: splitting protocol phases into independently locked owners would obscure the committed-transfer-versus-stale-heartbeat invariant. This is already a prior do-not-split observation.

9. **`pkg/cluster/election.go`**
   Traced single-node and peer election, readiness gating, preempt/transfer overrides, duplicate node handling, dual-active tie-break, state mutation, failover count, and event publication. The inline dual-active winner event can silently drop without `sendEvent` fallback, but that is the exact codex-review-175 finding and was suppressed. No additional ownership or arithmetic issue retained.

10. **`pkg/cluster/status.go`**
    Traced snapshots under `Manager.mu`, sync/readiness projection, history reads, and all text formatting. It does not mutate election/failover state and does not hold manager locks across external I/O. The section-builder split is exact fable-review-173 A8-F11. Negative result for this batch.

11. **`pkg/cluster/sync_test.go`**
    Inspected all 4,717 lines: wire round trips, short writes, sweep/RG filtering, bulk epochs and reconciliation, journals, barriers, failover request/commit acks, connection health, cold-start/reconnect behavior, and survivor redrive. The suite separately proves stale disconnect identity and first-connection cold bulk, but has no controlled out-of-order setup completion, rejected pending-frame, or same-fabric replacement-during-prime case. This is the characterization gap in R8-B1-03.

12. **`pkg/ra/sender.go`**
    Traced the single-owner socket contract, async/interruptible open, shutdown-mode publication, startup/reburst, detached bounded RS reader, final goodbye ordering, RA option assembly, marshalability pruning, interval floor, and link-local setup. Normal and goodbye writes remain owner-serialized; `rsReceiver` exits through deadline/close. `buildRA` extraction is exact fable-review-173 A8-F12. No sender-goroutine finding retained.

13. **`pkg/ra/ra.go`**
    Traced active sender and drain-tombstone ownership, global epoch mutation, Apply classification, join/timeout/reclaimer behavior, graceful upgrade, standalone goodbye, replacement publication, deferred starts, status, and `configEqual` parity with wire fields. Retained R8-B1-02: a manager-wide epoch is used to validate per-interface replacement intent, so an unrelated RG withdrawal can cancel a valid restart and remove its tombstone without starting a sender.

## R8-b2: Linux routing/FRR/IPsec/netlink reconciliation modularity specialist

Assigned candidates: **11**. Primary report: `codex-R8-b2.md`.

### Module Checklist

- [x] `pkg/frr/policy_render.go`
- [x] `pkg/frr/manager.go`
- [x] `pkg/frr/frr_test.go`
- [x] `pkg/routing/tunnel.go`
- [x] `pkg/routing/rules.go`
- [x] `pkg/routing/routing_test.go`
- [x] `pkg/ipsec/policy.go`
- [x] `pkg/ipsec/ike.go`
- [x] `pkg/ipsec/ipsec_test.go`
- [x] `pkg/networkd/networkd.go`
- [x] `pkg/ra/serialize_test.go`

Support reads, not additional finding scope:

- Campaign context: `orientation.md`, `dedup-index.md`, `shape-inventory.md`, and the agent contract.
- Repository contracts: `docs/architecture.md`, `docs/engineering-style.md`, `docs/critical-invariants.md`, `AGENTS.md`, and the FRR, routing, IPsec, networkd, and RA READMEs.
- Call and ownership traces: `pkg/daemon/daemon_apply.go`, `pkg/daemon/daemon_ha.go`, `pkg/routing/routing.go`, `pkg/routing/rules_test.go`, `pkg/routing/tunnel_reconcile_test.go`, `pkg/networkd/networkd_test.go`, and `pkg/ipsec/manager.go`.
- Schema/compiler traces: `pkg/config/schema_security.go`, `pkg/config/lexer.go`, `pkg/config/compiler_ipsec.go`, `pkg/config/compiler_validate_strict_routing.go`, `pkg/config/bgp_neighbor_peeras_2963_test.go`, `pkg/config/compiler_routing.go`, and `pkg/config/firewall_address_except_mutex_3359_test.go`.
- Prior-art searches: `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, `/tmp/fable-review*.md`, and `/tmp/opus-review*.md` for each retained and suppressed mechanism.

### File-by-File Inspection Log

### `pkg/frr/policy_render.go`

- Inspected all 1,938 lines. The largest measured functions are `generateProtocols` (633 LOC at line 491) and `renderRouteMapForPolicy` (407 LOC at line 1532).
- Traced protocol emission order, per-VRF rendering, consolidated BFD ownership, policy resolution, tolerant-load belts, and deterministic output.
- Retained `R8B2-FRR-01`: the `PeerAS == 0` fail-closed predicate is applied to the root neighbor loop but not the separately-built address-family or BFD projections.
- Suppressed the broad route-map split because `[A10-go-services] F-3` already covers the same 407-LOC function. A useful new split must follow protocol ownership, not move more methods into flat sibling files.

### `pkg/frr/manager.go`

- Inspected all 996 lines. Traced `ApplyFull -> buildManagedSection -> commitManagedSection -> writeManagedSection -> reloadLocked`, including `reloadMu`, `confGen`, degraded retry cancellation, additive fallback, and durable file replacement.
- The manager remains FRR's single writer. Write and reload are serialized under `reloadMu`; full-diff success clears degraded state, additive fallback schedules retry, and hard failure propagates.
- No new independent finding. The already-reported FRR/userspace FIB publication split (`codex-review-160 H1`) is outside this file's internal modular boundary and was not restated.

### `pkg/frr/frr_test.go`

- Inspected all 5,932 lines. The file is a broad rendering and manager regression matrix spanning static routes, protocols, policy options, BFD, injection belts, reload behavior, and strict/tolerant edge cases.
- It has strong fail-on-revert coverage for malformed route filters and many BGP family/policy cases, but no renderer test that combines `PeerAS == 0` with explicit/default address-family activation and BFD.
- No standalone test-file split finding. Splitting this file before the production protocol boundary is extracted would be flat shuffling; tests should move with a future `frr/bgp` module.

### `pkg/routing/tunnel.go`

- Inspected all 1,889 lines. `tunnelManager.Apply` spans 203 LOC at line 277 and owns desired/observed link reconciliation, adoption, GRE/TUN/WireGuard actuation, address and VRF claims, keepalive generations, and retry ownership.
- Traced every delete/recreate branch, `ownedNames`, `wgConfigured`, `appliedAddrs`, `appliedRI`, `linkGen`, `Clear`, and the netlink/exec lock scope. Failed removals retain ownership for a later apply; link-local deletion is identity-gated.
- No new finding. The full `t.mu` plan/netlink/commit split, including a structured `tunnelResult`, is already `[A10-go-services] F-1`. Re-reporting the same plan/result seam would duplicate that tracker.
- `Clear` has no production caller in this base; its failed-delete bookkeeping is therefore recorded as residual API risk, not promoted over the existing tunnel workstream.

### `pkg/routing/rules.go`

- Inspected all 1,313 lines. The file owns three kernel `ip rule` domains: next-table, rib-group, and PBR. It does not own route-table entries; FRR remains the route-table writer.
- Traced desired-rule construction, observed-window clearing, family handling, priority bounds, error aggregation, and the clear-then-add outage/rollback model.
- Retained `R8B2-ROUTING-01`: normalized PBR dimensions and final rules are not semantically deduplicated before the finite priority-window cap.
- Suppressed next-table/rib-group `RuleDel` error drift: #2273 explicitly left those deletes best-effort, `fable-review-161` records the same PBR-vs-leak-manager asymmetry, and broad `rules.go` decomposition is already in open #4421.

### `pkg/routing/routing_test.go`

- Inspected all 2,059 lines. Tests cover VRF adoption, partial failure ownership, orphan reap, rib-name parsing, PBR representability, family separation, priority overflow, L4 selectors, and attachment scoping.
- The VRF tests are notably stronger than the tunnel/rule facade tests about retaining ownership after failed deletion.
- No new finding. Existing PBR tests cover cross products and overflow but not semantic duplicates formed by aliases or overlap between literal addresses and positive prefix-lists; that gap is folded into `R8B2-ROUTING-01`.

### `pkg/ipsec/policy.go`

- Inspected all 1,059 lines. `renderConfig` spans 273 LOC at line 31 and combines connection/child rendering with proposal, identity, secret, endpoint, and prepared local-address inputs.
- Traced child-selector naming, deterministic map sorting, value sanitization, strict/tolerant traffic-selector handling, PSK rendering, DNS-family preparation, and render errors.
- Retained `R8B2-IPSEC-01`: `sanitizeChildName` is non-injective and no planner checks that distinct selector map keys remain distinct CHILD_SA identities.
- Suppressed the broad renderer/local-address split because `[A10-go-services] F-5` and `fable-review-161 F-115` already cover it.

### `pkg/ipsec/ike.go`

- Inspected all 890 lines. Traced IKE/ESP proposal normalization, bounded `swanctl` execution, SA parsing, termination, active-child naming, and failover initiation.
- `SAStatus.Name` deliberately becomes the CHILD_SA name and `InitiateConnection` uses `--child`, making child-name uniqueness an operational identity contract rather than presentation-only output.
- No separate finding. Parser and command responsibilities are cohesive enough at this size; the identity consequence is included in `R8B2-IPSEC-01`.

### `pkg/ipsec/ipsec_test.go`

- Inspected all 1,850 lines. Tests cover rendering, proposal fallback, real `swanctl --list-sas` fixtures, multiple children, DNS-family selection, traffic-selector value safety, and dynamic-hostname concurrency.
- No test supplies two legal selector names that sanitize to the same child name, and no test asserts child identity uniqueness through HA active-name sync/initiation.
- No standalone test split finding. Test movement should follow a future child-planner boundary and the already-tracked renderer/address-preparation split.

### `pkg/networkd/networkd.go`

- Inspected all 674 lines. Traced expected-manifest construction, protected lifeline ownership, atomic writes, stale sweep, reload/reconfigure execution, timeout bounds, and `Clear`.
- Retained `R8B2-NETWORKD-01`: activation state is inferred only from mutations in the current call, so failed reload/reconfigure work is forgotten once desired files match disk.
- The manager has no publication generation or pending activation state. The daemon serializes the call under `applySem`, but that serialization does not provide retry memory or rollback.

### `pkg/ra/serialize_test.go`

- Inspected all 2,648 lines. The file is a deliberate lifecycle/concurrency proof matrix for goodbye ordering, single live connection ownership, hard/graceful stop arbitration, epoch/tombstone behavior, timeout fallback, and dead-sender rebuild.
- Package-global hooks are restored with cleanup and concurrency cases have deterministic companions. There is no production hot path in this assigned test file.
- Negative class D result: do not split by line count. The shared fake connection/listener harness and cross-case lifecycle vocabulary make one invariant-focused matrix easier to audit; split only if the RA production state machine gains matching submodules.

## R9-b1: DDNS/DHCP/DHCP-relay state-machine and provider-boundary specialist

Assigned candidates: **10**. Primary report: `codex-R9-b1.md`.

### Module Checklist

- [x] `pkg/ddns/surface_a.go`
- [x] `pkg/ddns/manager.go`
- [x] `pkg/ddns/backend_rfc2136.go`
- [x] `pkg/dhcp/dhcp.go`
- [x] `pkg/dhcprelay/relay.go`
- [x] `pkg/dhcprelay/relay_test.go`
- [x] `pkg/dhcpserver/dhcpserver.go`
- [x] `pkg/dhcpserver/lease_sync.go`
- [x] `pkg/dhcpserver/ddns_leases.go`
- [x] `pkg/dhcpserver/dhcpserver_test.go`

### File-by-File Inspection Log

### `pkg/ddns/surface_a.go`

Read end to end. Traced scope observation, per-RG admission, write-ahead ownership, unlocked provider I/O, racing-operation revalidation, per-scope retry/backoff, dual-stack host-wide withdraw suppression, and provider endpoint fingerprinting. The endpoint-change classifier at lines 1496-1561 is a sound provider boundary and exposes the missing equivalent in the lease manager. The daemon single-flight assumption keeps full reconcile passes serialized while status readers remain responsive. No separate Surface A finding is retained: the generic file split is already recorded as `[A10-go-services] F-9`, and the provider-transition behavior is already covered by #3735/#4422 tests.

### `pkg/ddns/manager.go`

Read end to end. Traced independent v4/v6 policy resolution, lease parsing trust boundaries, scope admission, desired/owned diff ordering, write-ahead publication, partial PTR outcomes, delete-before-add reassignment, and durable ownership mutation. Retained one High-confidence finding: published lease ownership is provider-blind and the process keeps only one last-live updater even though current policy/updaters are per-family. This violates the file's own per-family independence and never-delete-at-the-wrong-provider boundary.

### `pkg/ddns/backend_rfc2136.go`

Read end to end. Traced update-server normalization, TSIG, source binding, UDP/TCP retry, DHCID prerequisites, forward/PTR partial outcomes, self-owned value-specific replacement, and exact-RR deletion. The backend intentionally treats `NXRRSET`/`NXDOMAIN` and DHCID-prerequisite misses as successful idempotent deletion; that is correct only when the caller proves endpoint provenance. It therefore turns the manager's wrong-endpoint selection into a false-success ownership drop and supports the retained DDNS finding. No standalone wire-protocol decomposition is warranted.

### `pkg/dhcp/dhcp.go`

Read end to end. Traced per-interface/per-family client registration, cancellation/deregistration, v4 acquire/renew/rebind/NAK transitions, v6 stateful/stateless IA_NA/IA_PD transitions, lease expiry behavior, address netlink operations, callbacks, and retry timing. Retained one High-confidence finding: a renewed/rebound address move removes the old address before the fallible new-address install, while the run loop continues to regard the old lease as committed. DHCPv6 relay absence and retention of an address after exchange timeout are documented feature semantics, not refactor findings.

### `pkg/dhcprelay/relay.go`

Read end to end. Traced desired-set construction, per-interface registry ownership, stop/start ordering, socket creation retry, ifindex/giaddr drift, HA gate reads, request/reply loops, cross-cancellation, and teardown joins. Retained one High-confidence finding: an unexpected one-sided socket exit closes `done` but leaves the terminal relay registered, so an unchanged day-2 `Apply` mistakes it for a running session. Packet-loop parsing, source validation, hop-limit handling, and atomics need no change for this fix. The broad `runRelaySession` god-function observation is already known as `[A10-go-services] F-4` and is suppressed.

### `pkg/dhcprelay/relay_test.go`

Read end to end. The suite strongly covers bind retry, cancellation, drift/readdress rebuild, packet filtering, source validation, L2/broadcast delivery, and bounded teardown. `TestRunRelay_OneSidedExitNoHang` and `TestRunRelay_ClosedNoSpin` prove the terminal-exit precondition but stop the manager afterward; neither reapplies identical config nor checks registry liveness. That missing characterization gate is part of the retained relay finding, not a separate test-only issue.

### `pkg/dhcpserver/dhcpserver.go`

Read end to end. Traced sync and async generation ordering, latest-wins mailbox ownership, family selection, Kea rendering, generated-config publication, systemd state reconciliation, clear semantics, stable subnet IDs, and lease-sync stanza injection. Retained two independent High-confidence findings: the v4 and v6 actions are not planned/staged as one transaction, and a failed newest async generation is marked attempted, discarded, and never retried. JSON rendering is deterministic and uses the correct `AtomicGeneratedConfig` writer; the issue is cross-family/state-machine ordering rather than file-write atomicity.

### `pkg/dhcpserver/lease_sync.go`

Read end to end. Traced control-socket versus memfile reads, active/expired filtering, v4/v6 identity and lease-type conversion, remaining-lifetime transport, add-to-update fallback, pre-seed schema, ownership/mode application, and readiness waits. The receiver re-anchors an unchanged `RemainingLifetime` at takeover; this is the already-recorded `codex-review-175` stale-aging/resurrection finding and is suppressed. No new narrower decomposition survived dedup. The parser/writer family mappings and external Kea schema boundary are adequately guarded.

### `pkg/dhcpserver/ddns_leases.go`

Read end to end. Traced destructive-safe CSV header validation, active-state and expiry filters, v4 identity fallback, v6 DUID/IAID identity, IA lease-type handling, hostname extraction, and parse-error propagation to the DDNS trust gate. No new refactor issue is retained. The known `splitV6Identity` swallowed-IAID defect is already closed as #2379, and the current path fails closed on malformed present IAIDs.

### `pkg/dhcpserver/dhcpserver_test.go`

Read end to end. The suite covers authoritative clear, per-family generation/restart failures, static rendering, async non-blocking/latest-wins/ABA ordering, cluster active/inactive behavior, and stable subnet IDs. It lacks a two-family late-failure test that asserts prior files/unit state are restored, and it lacks a fail-then-succeed-without-new-event async test. Those gaps are the characterization gates for the two retained server findings rather than separate findings.

## R9-b2: Observability/automation/service lifecycle and fanout modularity specialist

Assigned candidates: **12**. Primary report: `codex-R9-b2.md`.

### Module Checklist

| Assigned file | Lines | Responsibilities traced | Disposition |
|---|---:|---|---|
| `pkg/snmp/agent.go` | 1,519 | Agent/config ownership, UDP loop, v2c PDU dispatch, MIB snapshot, GET/GETNEXT/GETBULK, BER | No new finding; known splits and defects suppressed |
| `pkg/snmp/v3.go` | 1,084 | USM key derivation, auth-before-decrypt, privacy, timeliness, scoped PDU response | No new finding; known crypto/PDU split suppressed |
| `pkg/logging/ringbuf.go` | 1,376 | RT_FLOW decode, enrichment, buffer publication, callbacks, syslog/local fanout, binary encoding | No new finding; known fanout split and sink defects suppressed |
| `pkg/eventengine/engine.go` | 1,259 | Policy publication, temporal matching, action planning, bounded queue, retry worker, commit/cooldown | No new finding; known queue/lifecycle roots suppressed |
| `pkg/flowexport/ipfix.go` | 1,075 | IPFIX templates/options/data encoding, batching, sequence ownership, collector lifecycle | Retained finding R9B2-001 |
| `pkg/flowexport/netflow.go` | 815 | NetFlow v9 templates/data encoding, batching, sequence/source ID, collector lifecycle | Retained finding R9B2-001 |
| `pkg/flowexport/manager.go` | 889 | Config/group resolution, sampling state, family/direction selection, close-event model | No additional finding |
| `pkg/ipmon/ipmon.go` | 1,016 | Health FSM, overlay resolution, dirty generation, actuator loop, status projection | No new finding; known split suppressed |
| `pkg/lldp/lldp.go` | 861 | Apply generation, raw-socket sessions, receive/expiry loops, TLV codec, bounded neighbor table | No new finding; known lifecycle/TTL roots suppressed |
| `pkg/policymatch/policymatch.go` | 1,714 | Selector parsing/validation, policy-tier matching, address/app expansion, route-drop projection | No new finding; known decomposition suppressed |
| `pkg/monitoriface/monitor.go` | 952 | Snapshot aggregation, reset-safe rates, terse/detail presentation | No new finding; known renderer extraction suppressed |
| `pkg/upgrade/cutover.go` | 953 | Preflight, stage/copy/verify, journaled flip, rollback, cleanup/finalization | No new finding; known phase split suppressed |

### File-by-File Inspection Log

- `pkg/snmp/agent.go`: Read 1-1519. The 48-line `Start` loop serially owns packet dispatch and the request-local interface snapshot; `Stop` closes the UDP socket. The protocol/runtime/BER separation remains worthwhile but is already cataloged. The lazy trap worker is not joined by `Stop`, but that exact leak is prior finding `ps-review-040` Finding 11 and was reproduced indirectly by the race gate, so it is not re-filed.
- `pkg/snmp/v3.go`: Read 1-1084. Traced user localization, security-level gates, authentication verification before privacy decode, timeliness, scoped-PDU handling, and response encryption. Keeping auth-before-decrypt and exact HMAC/IV wire bytes is the guardrail for the already-known USM/PDU decomposition. No new ownership, allocation, or cardinality issue survived deduplication.
- `pkg/logging/ringbuf.go`: Read 1-1376. `logEvent` spans 467-811 and decodes, enriches, publishes, calls callbacks synchronously, and then fans out to human-facing sinks. Callback and sink slices are snapshot under separate locks; EventBuffer subscription limits live in the adjacent buffer module. The broad `EventReader` split, terminal-close snapshot problem, and SESSION_CLOSE sink field drift are all prior findings. Current production callbacks are stable indirections and queue into bounded flow batches, so no distinct backpressure finding was retained.
- `pkg/eventengine/engine.go`: Read 1-1259. Policy/runtime maps publish under `mu`; the worker is lazy-started and owns commit retries. The 64-entry action channel is bounded and fixed-reason metrics have bounded cardinality. Direct enqueue permits duplicates until full and `supersede` drains/refills concurrently, but both the duplicate/cooldown family and the exact non-atomic supersede mechanism are already recorded. The planner/matcher/worker decomposition is also cataloged.
- `pkg/flowexport/ipfix.go`: Read 1-1075. Template and record field order remain cohesive with the encoder. The run loop performs one final batch flush on cancellation at 819-821, while `ExportSessionClose` remains callable and appends at 831-894 with no admission state. This participates in R9B2-001. Sequence updates, option-template emission, packet size bounds, and fixed config-derived identities were otherwise coherent.
- `pkg/flowexport/netflow.go`: Read 1-815. The run loop has the same one-time shutdown flush at 603-606, and `ExportSessionClose` appends unconditionally at 616-674; `Close` only closes collector connections at 717-720. This participates in R9B2-001. The known multi-record padding defect was not duplicated.
- `pkg/flowexport/manager.go`: Read 1-889. Traced version/template grouping, deterministic collector deduplication, per-instance sampling counters, address-family service, direction selection, fallback duration, and `SessionCloseData`. Collector/template/instance metric dimensions are configuration-bounded. No second lifecycle owner or protocol-wire split was justified; protocol encoders should remain cohesive while lifecycle admission moves behind R9B2-001.
- `pkg/ipmon/ipmon.go`: Read 1-1016. Apply/Start/Stop serialize lifecycle; the worker uses cancellable context, dirty generations, and retryable actuation without publishing failed state. Resolver lock ordering and status snapshots were traced. The FSM/overlay/actuator split is already `codex-review-173` finding 10; no new failure or lower-risk boundary appeared.
- `pkg/lldp/lldp.go`: Read 1-861. Apply owns per-interface session cancellation and waits for old receive loops; sockets close on cancellation, expiry is periodic, and neighbor identities are bounded/sanitized. The prior raw-socket lifecycle work and TTL-zero withdrawal gap cover the credible observations. Splitting TLV wire parsing from session ownership without those existing guards would add churn, not a new issue.
- `pkg/policymatch/policymatch.go`: Read 1-1714. Traced strict selector parsing, protocol/port/ICMP validation, exact/wildcard/global/default policy tier order, scheduler fail-closed checks, exclusions, recursive address books, applications, and route-drop advisory projection. It owns no goroutines or metrics. Its parser/matcher/render decomposition and large Query/ValidateProtocol/Match functions are already cataloged; no fresh semantic boundary was found.
- `pkg/monitoriface/monitor.go`: Read 1-952. Snapshot collection composes kernel and userspace counters, handles counter resets, and leaves rate baselines with the caller; rendering is pure and owns no subscription or service lifecycle. The 178-line `RenderSingleInterface` extraction is already noted by `fable-review-173`; no new split is warranted.
- `pkg/upgrade/cutover.go`: Read 1-953. `Runner.Run` spans 135-566 and deliberately sequences preflight, durable journal records, irreversible flip, rollback, and cleanup. Error paths and journal-before-side-effect ordering were reconciled with `state.go`. The exact phase extraction is prior `fable-review-173` F-2; no new decomposition should bypass its crash-recovery guardrail.

## R10-b1: Linux/BPF/build/deploy tooling and translation-unit modularity specialist

Assigned candidates: **11**. Primary report: `codex-R10-b1.md`.

### Module Checklist

- [x] `bpf/headers/xpf_helpers.h`
- [x] `bpf/headers/xpf_maps.h`
- [x] `bpf/headers/xpf_common.h`
- [x] `userspace-xdp/src/lib.rs`
- [x] `scripts/deploy/xpf-deploy.py`
- [x] `scripts/image/bake.py`
- [x] `test/incus/cold-path-flooder/src/main.rs`
- [x] `test/incus/fairness_multi_sample.py`
- [x] `test/incus/fairness_multi_sample_test.py`
- [x] `scripts/refactoring-audit.sh`
- [x] `docs/refactoring-audit-current.txt`

### File-by-File Inspection Log

**`bpf/headers/xpf_helpers.h` (2,554 LOC)**

Fifty functions are `static __always_inline`. They cover parsing, checksums, counters/events, host-inbound policy, policers, three filter evaluators, MSS adjustment, and retired HA/fabric behavior. There is no tracked production BPF C translation unit that includes this header; the `bpf/` tree now contains headers only. Moving these functions to `.c` files would create BPF-to-BPF call and verifier/codegen boundaries for code that is not built. Finding R10-B1-001 therefore recommends retirement, not a cosmetic header split.

**`bpf/headers/xpf_maps.h` (921 LOC)**

This header defines 67 maps spanning tail calls, CPU/XSK redirect, interface/config, sessions/NAT, policy/filter, HA, telemetry, and trace state. No active C translation unit owns the definitions. Comments at lines 347-375 still describe regenerating retired bpf2go objects, which makes the file look authoritative despite having no build consumer. Included in R10-B1-001.

**`bpf/headers/xpf_common.h` (898 LOC)**

The file mixes network headers, 16-bit-era tail-call indices and limits, 42 ABI/config structs, packet metadata, events, sessions, NAT, policy, and retired flow configuration. Actual file reads found were the shim build's `MAX_INTERFACES` parse, a Go parity test for that constant, and a logging test that parses `struct event`; other source references are comments or names, not inclusion into a C translation unit. This is residual ownership explicitly deferred by the #1476 removal manifest. Included in R10-B1-001.

**`userspace-xdp/src/lib.rs` (1,541 LOC)**

The sole `cdylib` crate file contains constants, `repr(C)` ABI structs and layout assertions, all Aya map declarations, the 340-line `try_xdp_userspace` entry pipeline (405-744), GRE classifiers, degraded actions/trace, packet parsing, local/session decisions, and queue selection. The tracked ELF has one 45,968-byte global `xdp_userspace_prog` plus local `.text` functions for `parse_l4` and the explicitly `#[inline(never)]` GRE classifiers. A Rust source-module split is not a C translation-unit split and does not require a new XDP section or tail call. Findings R10-B1-002 and R10-B1-003.

**`scripts/deploy/xpf-deploy.py` (1,805 LOC)**

AST spans show independent ownership domains: inventory 82-209, appliance/config-drive 213-344, backend runner and Incus/libvirt transactions 348-806, CLI launch 810-847, signed fetch/import 850-1030, remote execution and lease 1060-1170, kernel roll 1173-1344, image compatibility/roll 1357-1657, and CLI parsing/dispatch 1660-1801. Preflight-before-mutation, cleanup ownership, lease ordering, and mixed-base gates are production HA invariants. All 71 deploy unit tests passed. Finding R10-B1-004.

**`scripts/image/bake.py` (740 LOC)**

Negative result. `virt_customize` (233-464) is a declarative, order-sensitive `virt-customize` argument transaction, while `main` (537-736) is one build -> select package -> pre-gate -> resize -> customize -> seal -> export -> manifest -> validate -> sign transaction. `finalize_artifacts` already isolates the security-critical validate-before-sign boundary and has nine passing ordering tests; twelve validation-scenario tests also passed. Splitting the ordered argv list or pipeline by LOC would obscure ordering and cleanup. The known `--skip-validate` signing defect is suppressed below, not refiled.

**`test/incus/cold-path-flooder/src/main.rs` (2,170 LOC)**

Production code occupies lines 1-1578 and the inline test module 1579-2170. Responsibilities include CLI/cohort validation, packet assembly/checksum, Linux AF_PACKET/ioctl setup, cache-aligned statistics, a self-referential `sendmmsg` ring, the per-worker hot loop, reporting, and thread lifecycle. The raw `msg_name` pointer is valid only after `wire_msgs()` runs at the worker context's final stack location. Unit validation passed 39 tests with the privileged socket smoke ignored; `cargo fmt --check` currently fails, and no standard Make target owns this standalone crate. Finding R10-B1-005.

**`test/incus/fairness_multi_sample.py` (471 LOC)**

Negative modularity result. Parsing/validation (42-138), reduction (141-249), process-group execution/artifact ownership (252-386), and CLI setup (389-467) are already function-separated around one multi-sample workflow. No packet hot path exists. Direct tests passed. The known exit-code/verdict mismatch is suppressed as C175-HC-084.

**`test/incus/fairness_multi_sample_test.py` (1,425 LOC)**

One class from lines 39-1421 tests four different executables/modules imported at lines 20-36: the multi-sample wrapper, `fairness-harness.sh`, the class-sweep shell driver, and `fairness_equal_flow_capture.py`. Test groups begin around lines 40, 383, 493, and 724; shared fake-process helpers begin at 1126. All 42 tests passed when invoked directly, but `make selftest` discovers only tests under `scripts/`, not this suite. Finding R10-B1-006.

**`scripts/refactoring-audit.sh` (148 LOC)**

The generator is deterministic and syntax-valid, but its declared roots are only Go runtime, `userspace-dp`, `userspace-xdp`, and retired BPF `.c` directories. It excludes production Python tooling and standalone Rust tooling, excludes separate test files, and cannot distinguish inline test mass from production LOC. Its stale-output check is deliberately standalone rather than part of `make test`. Finding R10-B1-007.

**`docs/refactoring-audit-current.txt` (16 LOC)**

Independent regeneration produced 46 lines. `make audit-check` failed with a complete 16-line replacement, including `userspace-xdp/src/lib.rs` at 1,541 LOC. The artifact last changed in `8bd1a1ea8f34cf81aac98100a32c81b608947abf`; the generator last changed in the #1661 fix `c39ad2173650ac768bc0e62ab20c6b1013d20b3f`. The raw stale diff is known; only the recurring ownership/gate defect is retained in R10-B1-007.

## S1-rust-focus-b1: Rust AF_XDP omitted hot-function and session/screen support specialist

Assigned candidates: **12**. Primary report: `codex-S1-rust-focus-b1.md`.

### Module Checklist

- [x] `userspace-dp/src/afxdp/frame/wg.rs`
- [x] `userspace-dp/src/afxdp/poll_descriptor/rx_telemetry.rs`
- [x] `userspace-dp/src/afxdp/frame/build/mod.rs`
- [x] `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`
- [x] `userspace-dp/src/afxdp/umem/debug_state.rs`
- [x] `userspace-dp/src/afxdp/tx/drain/mod.rs`
- [x] `userspace-dp/src/afxdp/cos/builders.rs`
- [x] `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`
- [x] `userspace-dp/src/afxdp/cos/queue_service/submit_local.rs`
- [x] `userspace-dp/src/screen/extract.rs`
- [x] `userspace-dp/src/session/expire.rs`
- [x] `userspace-dp/src/session/lookup.rs`

### File-by-File Inspection Log

### 1. `userspace-dp/src/afxdp/frame/wg.rs`

- Measured focus: `wg_encap_frame` spans lines 305-543 inclusive, 239 lines.
- The function is a cohesive transit-encapsulation transaction: AllowedIPs peer lookup, one outer-underlay route lookup, physical source/MTU selection, pad-aware size admission, final buffer sizing, WireGuard encryption directly into the final UDP payload, and outer Ethernet/IP/UDP construction.
- The single returned `Vec<u8>` is the ownership boundary expected by the current frame emission path. The two avoidable intermediate vectors were already removed by `#2792`; extracting phases behind owned buffers would add copies or obscure the one-route/one-output contract.
- Packet-path guardrails are sound: helpers are statically dispatched and inlineable, `impl Into` is monomorphized rather than trait-object dispatch, wire writes keep big-endian conversion local, and the production path takes no lock. The route counter is test-only and relaxed.
- Source and destination selection, outer MTU arithmetic, padding, nonce/session use, and encryption output offsets must remain in one ordered transaction. A split before final sizing or after encryption would make rollback and route/source consistency implicit.
- Existing tests pin v4/v6 physical source choice, exactly one outer route resolution, padding-aware sizing, MTU drop, in-place parity, and scalar checksum parity.
- Negative result: class D. The current boundary should remain cohesive. This is also an exact prior do-not-split conclusion, not a new issue.

### 2. `userspace-dp/src/afxdp/poll_descriptor/rx_telemetry.rs`

- Measured focus: `record_rx_descriptor_telemetry` spans lines 42-220 inclusive, 179 lines.
- In ordinary release builds the hot residue is metadata/frame prefetch plus owner-local counter updates. Most textual size is guarded by `cfg!(feature = "debug-log")`; the debug branch performs diagnostic vector/string formatting but is constant-folded away when the feature is disabled.
- The raw mmap-area dereference is immediately constrained through the checked `MmapArea::slice` API, and metadata offset validation precedes access. There is no release-path heap allocation, lock, trait object, or atomic read-modify-write in this helper.
- `#[inline]` is deliberate: it permits the small release residue to fold into descriptor processing without forcing the large debug body into every caller as `#[inline(always)]` could. A source split alone would not guarantee a smaller generated hot symbol.
- This helper was already extracted from descriptor processing by `#1327`/PR `#1571`. No separately useful owner exists for another layer, and moving diagnostics to another flat sibling would be file shuffling.
- There is no dedicated codegen test proving the debug branch disappears, but static feature gating is direct and no independent behavioral seam follows from that test gap.
- Negative result: class D for another decomposition. Preserve the current telemetry boundary and feature gate.

### 3. `userspace-dp/src/afxdp/frame/build/mod.rs`

- Measured focus: `build_forwarded_frame_into_from_frame` spans lines 28-192 inclusive, 165 lines.
- This is an intentionally concrete code-generation boundary: it accepts `ForwardPacketMeta`, is `#[inline(never)]` to keep one binary body, and dispatches into address-family helpers that are `#[inline(always)]` for local constant folding.
- The path uses one caller-owned output buffer and one `copy_nonoverlapping`; it introduces no heap allocation, trait-object call, lock, or atomic. Family modules keep NAT, checksum, header-length, and byte-order details close to the wire writes.
- Debug-only diagnostics may allocate, but ordinary forwarding does not. Replacing the concrete metadata type with a trait abstraction or splitting tiny stages into callable symbols would risk monomorphized duplication, extra branches, and instruction-cache growth.
- `#1352`/PR `#1583` already performed the meaningful split into the orchestrator plus `build/{ipv4,ipv6}.rs`, with explicit code-size and hot-path guardrails in the associated plan.
- Existing frame tests exercise family parity, rewrites, expected ports, checksums, and bounds through the public builders.
- Negative result: class D. Do not reopen the completed family split or replace its concrete ABI with generic phase traits.

### 4. `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`

- Measured focus: `segment_forwarded_tcp_frames_into_prepared` spans lines 4-309 inclusive, 306 lines.
- The whole routine is `#[cold]`. It validates protocol/tunnel/MTU/header/flag constraints, may drain TX only when resources are tight, preflights free frames, reserves UMEM offsets, emits segments, and publishes prepared requests only after all segments succeed.
- `Vec<PreparedTxRequest>` is sized to the segment count and is the transaction carrier, not an ordinary non-segmented packet allocation. Every failure returns all acquired UMEM offsets in reverse order before returning, preserving pool ownership and preventing partial publication.
- The unchecked mutable frame slice is bounded by TX frame capacity and by a successful frame lookup. Wire fields use local big-endian conversion and checksums are recomputed after payload/header mutation.
- `BTreeMap`/mutex-bearing recovery is reached only when scarcity triggers the drain path; it is not added to the normal forwarding path. Static helpers avoid trait-object dispatch.
- Tests cover segmentation properties, MTU and flags, IPv6 extensions, NAT/checksum outcomes, and dispatch integration. An isolated allocation-failure/rollback harness could improve characterization, but the exact routine has no new decomposition that would justify an issue.
- Negative result: class D. The transactional admission/emission/unwind loop is safer as one cold ownership boundary. The sibling frame segmentation phase work is already tracked and must not be generalized into a duplicate for this file.

### 5. `userspace-dp/src/afxdp/umem/debug_state.rs`

- Measured focus: `publish_binding_debug_state` spans lines 68-287 inclusive, 220 lines.
- Hot wrappers perform a wrapping counter/mask check and branch; publication runs at roughly 65 ms cadence or on the idle wall-clock path. This keeps the packet path to owner-local scratch updates.
- Publication flushes scratch counters into relaxed atomics, advances the flow-cache epoch, builds operator-facing snapshot vectors, and clears/percolates per-queue V-min telemetry. The `collect` allocations are intentional cold observability work, not per-packet work.
- Binding state has one worker writer. Relaxed ordering is appropriate for diagnostics, and this file does not introduce cross-core ownership or a trait-object call. Splitting each counter family would add call/borrow boundaries without changing cache-line traffic.
- `#1351` already extracted this publication owner from the UMEM monolith. Tests pin cadence, flow-cache aging, aggregate sums, queue snapshots, and scratch zeroing after publish.
- Negative result: class D. Keep publication as one cold snapshot transaction and the cadence checks as tiny hot wrappers.

### 6. `userspace-dp/src/afxdp/tx/drain/mod.rs`

- Measured focus: `ingest_cos_pending_tx_with_provenance` spans lines 377-555 inclusive, 179 lines. The outer `drain_pending_tx` is already a short phase orchestrator.
- Ingestion deliberately handles prepared requests before local requests. It preserves shared-UMEM recycling through redirect/enqueue fallbacks, then uses `mem::take` to reuse the local deque allocation and processes only the captured initial length.
- Owner/peer provenance is recorded before requests are mixed. A one-key decision cache amortizes route/egress resolution, while the exact step-1 -> step-2 -> step-3 fallthrough preserves ownership after every failure. The recovered-command mutex is only on a cross-worker recovery path.
- Counters use relaxed ordering and no trait-object dispatch is introduced. A warmed local deque is reused; scanning the captured deque is required so requests behind a blocked head cannot bypass CoS admission limits.
- Tests pin mixed-head scanning, rescue behavior, failure ordering, shared ownership, and shaped-interface guards. Further source extraction would make fallthrough and recycle obligations less visible without shortening a real independent phase.
- The consuming enqueue API and foreign prepared-frame recycle contracts adjacent to this function are already retained as current-campaign findings `R2-b2-04` and `R2-b2-06`; they are not re-reported here.
- Negative result: class D for splitting this ingestion transaction. Preserve the explicit ordered cascade.

### 7. `userspace-dp/src/afxdp/cos/builders.rs`

- Measured focus: `build_cos_interface_runtime` spans lines 82-255 inclusive, 174 lines.
- The packet-facing ensure wrapper is two predictable early exits followed by a `#[cold] #[inline(never)]` construction tail. `#1755` moved the approximately 36 KiB stack probe away from every packet.
- Runtime construction is a one-time complete projection of configuration into priority indexes, stable exact-rate ordering, queue runtimes, and timer-wheel storage. Its vector/array allocations are cold initialization work and preserve deterministic ordering.
- The full struct literals make token, rate, deficit, V-min, flow-hash seed, and timer defaults visible. Splitting those literals among builders could silently diverge defaults or reintroduce large stack frames into an inline caller.
- There is no packet/UMEM ownership, lock, dynamic dispatch, or atomic hot-state mutation here. Tests pin surplus sharing, exact-token initialization, flow-fair seed state, and zero-rate shaping behavior.
- Negative result: class D. Keep the cold complete-construction boundary and its outlined caller.

### 8. `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`

- Measured focus: `maybe_reinject_slow_path_from_frame` spans lines 186-355 inclusive, 170 lines.
- The main exception helpers are `#[cold] #[inline(never)]`. The filtered wrapper enforces an explicit disposition allowlist, while the raw primitive has one documented `ForwardCandidate` bypass and fail-closed exclusions for fabric redirects and tunnel failures before generic TUN reinjection.
- `to_vec` is required to transfer ownership of an L3 packet to a bounded channel/reinjector; NAT is applied to that owned packet. Treating this as an accidental packet-path allocation would ignore the cross-boundary lifetime.
- State is read through an ArcSwap snapshot. The recent-error mutex is limited to the exception path, and counters use relaxed ordering. Normal AF_XDP forwarding does not take these locks or allocate this buffer.
- Tests cover eligible/ineligible dispositions, fabric and tunnel exclusions, unavailable reinjection, NAT, and HA-inactive behavior.
- Extracting allowlist checks from the raw primitive would obscure the one intentional bypass and make fail-closed review harder. Prior audits reached the same negative conclusion.
- Negative result: class D. The cold exception-policy boundary is appropriately isolated.

### 9. `userspace-dp/src/afxdp/cos/queue_service/submit_local.rs`

- Measured focus: `submit_local` spans lines 10-168 inclusive, 159 lines.
- The handler is hot and concretely typed. It uses fixed stack sidecars for flow-bucket metadata (640 bytes) and enqueue timestamps (512 bytes), with no heap allocation inside the handler.
- Accounting applies only to the successfully committed prefix. Retry restores queue and token bytes, then publishes committed virtual time only after submission settles. Diagnostics use relaxed atomics.
- The batch `VecDeque` allocation originates in the queue builder, not this function. Current finding `R2-B1-01` owns reuse of that allocation and explicitly retains the local/prepared submit handlers as commit/rollback owners.
- Tests pin owner counters, successful-prefix accounting, sojourn attribution, retry restoration, and V-time publication. The known `mirror_clone` sidecar-prefix attribution defect is prior tracker material, not a new decomposition result.
- `#1331`/PR `#1585` already split Local and Prepared handlers into owner modules. Further phase files would create flat indirection across one short commit transaction.
- Negative result: class D. Preserve this typed batch commit/rollback owner.

### 10. `userspace-dp/src/screen/extract.rs`

- Measured focus: `extract_screen_info` spans lines 52-400 inclusive, 349 lines.
- This is one allocation-free packet parser: initialize `ScreenPacketInfo`; parse IPv4 IHL/options/source routing or IPv6 extension/fragment/routing state; then extract TCP sequence, ACK, flags, and MSS when an L4 header is present.
- It uses no heap, trait object, lock, or atomic. Every multi-byte wire value is decoded locally with `from_be_bytes`, keeping endianness review adjacent to bounds checks and protocol state.
- IPv6 walking is bounded to eight headers and all offset advances are checked. A non-first fragment stops before L4; a first fragment continues through legal post-fragment extension headers. Truncation and malformed option lengths fail closed.
- The extractor itself returns after the bounded loop without a distinct over-limit error. The production pipeline nevertheless drops that exact case immediately after flow parsing at `afxdp/poll_descriptor/mod.rs:759-776`, using the shared over-limit classifier before screen or forwarding. That ordering is a critical cross-module guardrail.
- Tests cover v4/v6 fragments, fragment -> destination-options -> TCP, uncommon extension headers, truncation/overshoot, malformed IPv4 options, source routes, and TCP options. A direct seven-versus-eight extractor parity test would help only as part of the already proposed known split.
- A parser-family decomposition is credible in isolation, but it is an exact duplicate of codex-review-171 finding 8 and fable-review-173 A4-F12; the shared IPv6 extension walker is separately prior work. No new issue is retained.
- Negative result after aggressive dedup: preserve current behavior until the known guardrail-first parser work lands; do not file a parallel split.

### 11. `userspace-dp/src/session/expire.rs`

- Measured focus: `expire_stale_entries_ha` spans lines 121-412 inclusive, 292 lines.
- This is a cold, once-per-second timer-wheel drain. It resets cycle statistics before gating, observes the cursor, snapshots the bucket length, and handles gone, stale-handle, expired, and still-alive records under one ordered pass.
- HA disposition is decided before mutation. Self-heal/hold records are re-bucketed, deliberate reaps disable companion retention, owner-side companions can extend life, and actual removal is centralized before delta/output publication. The cursor advances only after the bucket transaction completes.
- The returned `Vec` and key/metadata clones are GC/HA-delta output ownership, not lookup-path allocation. Bucket draining itself is allocation-free; documented wheel growth may allocate during warm-up. Session state is worker-owned, so this path adds no lock, atomic, dynamic dispatch, or false-sharing surface.
- Strict `>` expiration and no concurrent table mutation are important invariants. Helpers already isolate HA gate and companion decisions; cutting the remaining mutation sequence into calls would make ordering easier to violate.
- Timer-wheel, alias, companion, strict-boundary, HA hold/self-heal, and ceiling tests provide substantial characterization. PR `#2028` already split expiration from the session monolith.
- Negative result: class D for decomposing this transaction further. Broader session layout/module work is already under `#4421` and current campaign review.

### 12. `userspace-dp/src/session/lookup.rs`

- Measured focus: `lookup_with_origin` spans lines 48-213 inclusive, 166 lines.
- The hot transaction resolves direct or 1:N alias handles, rejects stale slots, resolves timeout/zone overrides, mutates TCP close/promotion/last-seen/expiry state under one borrow, clones return metadata, propagates companion state after releasing that borrow, and pushes the canonical key to the wheel.
- The direct primary lookup is the predictable path; alias collision traversal is exceptional. The table is worker-owned and uses concrete calls, so there is no lock, atomic, trait-object dispatch, or cross-core false-sharing addition.
- `SessionMetadata::clone` includes an `Arc<PolicyRuleCounter>` clone and the wheel operation clones the record key. Those costs and the 25-field SessionTable hot/cold layout are already exact prior findings; this batch found no distinct ownership representation that can be changed independently.
- Keeping TCP state mutation and expiry-wheel refresh in one method preserves borrow ordering and ensures alias hits enqueue the canonical record key. Splitting by lookup source would duplicate state-transition logic or add polymorphic dispatch.
- Tests cover canonical wheel keys after alias lookup, 1:N alias collisions, stale aliases, SYN-ACK promotion, FIN/RST close transitions, timeout handling, and companion behavior.
- Negative result after dedup: no new split. Preserve the transaction pending the existing session hot/cold and metadata-clone work under `#4421` and its prior findings.

## S1-rust-runtime-b2: Rust AF_XDP lifecycle, CoS epoch, flow-cache, and server runtime specialist

Assigned candidates: **13**. Primary report: `codex-S1-rust-runtime-b2.md`.

### Module Checklist

- [x] `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs`
- [x] `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs`
- [x] `userspace-dp/src/afxdp/worker/lifecycle.rs`
- [x] `userspace-dp/src/server/lifecycle.rs`
- [x] `userspace-dp/src/afxdp/session_delta.rs`
- [x] `userspace-dp/src/server/handlers/mod.rs`
- [x] `userspace-dp/src/afxdp/mod.rs`
- [x] `userspace-dp/src/afxdp/worker/cos/queue_row.rs`
- [x] `userspace-dp/src/fairness_eval/mod.rs`
- [x] `userspace-dp/src/afxdp/flow_cache.rs`
- [x] `userspace-dp/src/server/handlers/snapshot.rs`
- [x] `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs`
- [x] `userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs`

### File-by-File Inspection Log

### 1. `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs`

Measured 486 physical lines. `bring_up_workers` spans lines 21-469 (449 lines) and owns binding-plan construction, shared-UMEM policy, BPF-FD transfer, CoS/mirror publication, preserved-session replay, resolver/worker/monitor/warmer thread launch, and tunnel-source reconciliation. The ordering is not merely cosmetic: it follows destructive teardown and snapshot application, while worker launch is still fallible. Retained findings S1-RUST-RUNTIME-B2-01 and -02 cover the two actionable launch boundaries. Generic further phase splitting is not warranted until launch becomes an explicit transaction.

### 2. `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs`

Measured 446 lines; `maybe_rotate_epoch_v8` spans lines 34-445 (412 lines). This is a single-winner, one-epoch transaction: EVEN-to-ODD `AcqRel` claim, writer `Release` fence, packed class/event/worker swaps, reuse of preallocated mutex-protected scratch, carry and equal-flow calculation, payload publication, then ODD-to-EVEN `Release` completion. The mutex is uncontended by construction and no heap allocation occurs on rotation. Splitting the middle of this sequence would hide the tag-reset ordering and increase review risk. Negative result: preserve it as a class-D atomic transaction; PR #1329 already extracted it from the former monolith.

### 3. `userspace-dp/src/afxdp/worker/lifecycle.rs`

Measured 335 lines; `poll_binding` spans lines 17-335 (319 lines). It deliberately fuses one binding's TX/fill drain, RX backpressure, raw UMEM-area reborrow, bounded RX batches, descriptor processing, RST teardown, cross-binding recycle routing, completion reap, and idle-neighbor retry. `split_at_mut` proves exclusive binding ownership, scratch vectors are moved out and restored with `mem::take`, and batch counters amortize relaxed atomic publication. Release symbols measured `poll_binding` at 4,458 bytes while the descriptor processor is 89,070 bytes; flow-cache lookup is inlined into the latter. Negative result: class D. Another helper layer here would risk UMEM lifetime mistakes, calls in the hottest loop, and lost inlining without removing ownership complexity.

### 4. `userspace-dp/src/server/lifecycle.rs`

Measured 737 lines. `run` spans lines 124-426 (303 lines), while argument parsing is already separate at lines 469-516. It owns cold startup/shutdown sequencing: raise-only sysctls, fail-closed socket cleanup, listener creation, `ServerState` construction, event-stream startup, signal handling, the dedicated session listener, the serial control listener, final coordinator stop, persistence, and socket removal. The session thread and main listener intentionally share one state mutex; no packet path reaches this code. Negative result: cohesive cold lifecycle and already a class-D negative in `/tmp/fable-review-173.md`; no new split.

### 5. `userspace-dp/src/afxdp/session_delta.rs`

Measured 362 lines; `flush_session_deltas` spans lines 55-355 (301 lines), up from the 165-line function recorded when PR #1068 extracted it. It now combines wire/status projection, optional per-binding fallback, lossless HA publication, best-effort RT_FLOW enrichment, recent-event retention, BPF/shared-map retirement, and sibling-worker deletion. Only the `BindingLiveState` fallback is binding-dependent; all other consumers must run with zero bindings. Retained finding S1-RUST-RUNTIME-B2-03 defines a guarded decomposition that leaves the per-delta order visible.

### 6. `userspace-dp/src/server/handlers/mod.rs`

Measured 304 lines; `handle_stream` spans lines 44-304 (261 lines). It enforces request size, decodes one request, locks `ServerState` for verb dispatch, delegates each domain verb to existing handler modules, drops the lock, optionally persists, and encodes the response. PR #1568/#1345 already performed the useful per-verb split. The known persistence-before-response defect is prior report F-246, so it is suppressed below rather than restated. Negative result: the remaining function is the control protocol transaction shell.

### 7. `userspace-dp/src/afxdp/mod.rs`

Measured 1,069 lines, but it is mostly module wiring, shared constants/imports, and the packet-batch counter surface. `BatchCounters::flush` spans lines 693-952 (260 lines) and intentionally batches many worker-local counters into relaxed atomics once per RX batch/exit. Relocating it would either widen a large private field surface or add accessors/calls in the polling path; it would not reduce the counter ABI. Negative result: keep `BatchCounters` and its flush adjacent to the root hot-path vocabulary, and do not confuse a long fieldwise accumulator with independent behavior.

### 8. `userspace-dp/src/afxdp/worker/cos/queue_row.rs`

Measured 302 lines; `accumulate_queue_row` spans lines 53-302 (250 lines). This is an already-extracted status projection (#1349) with explicit aggregation semantics: first-worker priority, MAX for configured rate/buffer and peaks, SUM for disjoint worker counters, MIN for nonzero wakeup, and relaxed best-effort histogram loads. Plain waterfill/sojourn values are read on the owning worker; cross-thread telemetry uses atomics. Negative result: keep the fieldwise row projection contiguous so aggregation modes remain auditable; another split would be flat-file shuffling.

### 9. `userspace-dp/src/fairness_eval/mod.rs`

Measured 261 lines; `run_evaluation` spans lines 19-261 (243 lines). It is a tooling orchestrator over already-separated `args`, `inputs`, `windowing`, `metrics`, `rss`, and `verdict` modules. Its copies and allocations are command-line evaluation work, not AF_XDP forwarding, and the black-box contract asserts the complete emitted verdict. Negative result: the remaining sequence is the readable evaluation pipeline; splitting it would obscure gate order without runtime benefit.

### 10. `userspace-dp/src/afxdp/flow_cache.rs`

Measured 1,000 lines. `FlowCacheEntry::from_forward_decision` spans lines 332-558 (227 lines), while the lookup core is lines 851-925 (75 lines) and scans a fixed four-way set. Ownership is per binding on one worker, so lookup takes no lock, allocates nothing, uses a seeded hash, and reads RG epochs with relaxed atomics. Release type diagnostics show the entry has materially outgrown the source's `~96 B` model. Retained finding S1-RUST-RUNTIME-B2-04 is a measurement-first layout experiment, not permission to split the inlined lookup into calls.

### 11. `userspace-dp/src/server/handlers/snapshot.rs`

Measured 296 lines. `apply` spans lines 14-238 (225 lines) and `bump_fib` spans lines 240-296. `apply` snapshots prior control state, preflights policy, replaces/replans the snapshot, chooses defer/refresh/full-reconcile, restores prior bookkeeping on the currently modeled pre-teardown errors, refreshes status, and only then marks persistence. This is the transaction boundary that exposes S1-RUST-RUNTIME-B2-01, but it does not need a second independent split. Negative result: preserve the verb-local rollback sequence; #3766 and #3789 already cover build/map failures.

### 12. `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs`

Measured 341 lines; the refresh implementation spans lines 117-340 (224 lines). It builds policy/filter/forwarding state before mutation, preserves runtime fabrics, publishes ArcSwap state, refreshes tunnel/WG/CoS runtime maps, rehydrates leases, and queues neighbor warming. The build-first and publication order is covered by #3766 and the module was extracted by #1890. Negative result: this is a cohesive same-plan commit sequence; peeling individual stores into opaque helpers would make atomicity harder to audit.

### 13. `userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs`

Measured 247 lines; `publish_equal_flow_epoch_v8` spans lines 33-247 (215 lines). It runs only inside the rotation winner's ODD epoch, over fixed/preallocated slices, and publishes equal-flow payload before the epoch tag. A reader that captured the old global tag can transiently observe a new equal-flow payload before its tag, but rotation has already swapped both class and worker grant slots to the new packed tag at `rotate_epoch_v8.rs:101-163`; the old reader's tag-checked grant loops therefore return `EpochRotated` without granting. Fresh readers cannot pass the global seqlock until publication completes. Negative result: no torn-grant finding and no split; preserve tag-last publication and downstream packed-tag rejection together.

## S1-rust-runtime-b3: Rust tunnel, reconcile, event-codec, GRE, and ICMP ownership specialist

Assigned candidates: **12**. Primary report: `codex-S1-rust-runtime-b3.md`.

### Module Checklist

| Candidate | Inspection disposition |
|---|---|
| `userspace-dp/src/afxdp/tunnel.rs` | Full read; retained `S1-B3-001` for unbounded bidirectional drains and delayed ArcSwap/HA refresh. |
| `userspace-dp/src/afxdp/coordinator/refresh_bindings.rs` | Full read; retained `S1-B3-003` for live-counter/reset projection drift. |
| `userspace-dp/src/afxdp/worker/loop_body/setup.rs` | Full read; negative result. One-shot allocation and setup ownership is correctly kept out of the inlined worker tick. |
| `userspace-dp/src/event_stream/codec/session_sync.rs` | Full read; negative result. Fixed-stack encoding, explicit little-endian fields, and cross-language wire tests are coherent. |
| `userspace-dp/src/afxdp/coordinator/inject.rs` | Full read; negative result. Request limits, tuple checks, state stamping, and enqueue ownership form a bounded control path. |
| `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs` | Full read; negative result. Preflight/build-before-teardown and fail-closed publication boundaries are explicit. |
| `userspace-dp/src/fairness_eval/verdict.rs` | Full read; negative result. This is cohesive offline evaluation, not a packet hot path. |
| `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` | Full read; negative result. Interface, logical-parent, route, zone, and egress-MTU construction share one config-time invariant. |
| `userspace-dp/src/afxdp/gre.rs` | Full read; no new retained finding. Packet-path heap allocation is a known prior finding and is suppressed below. |
| `userspace-dp/src/afxdp/icmp_embed/builders.rs` | Full read; negative result. IPv4/IPv6 builders keep family-specific checksum and quoted-packet invariants local. |
| `userspace-dp/src/event_stream/codec/rt_flow.rs` | Full read; negative result. The intentional mixed-endian 152-byte payload is stack-built and test-pinned. |
| `userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs` | Full read; retained `S1-B3-002` for per-interface WG MTU ownership applied to per-peer routing. |

### File-by-File Inspection Log

### `userspace-dp/src/afxdp/tunnel.rs`

Measured `local_tunnel_source_loop` at lines 234-444 (211 lines), `drain_local_tunnel_deliveries` at 169-199 (31 lines), and the local-origin plan builder at 515-643. Traced eventfd wake/drain behavior, attachment validation, forwarding and HA snapshot loads, delivery-to-TUN ownership, TUN-to-`TxRequest` ownership, session synthesis, CoS selection, and enqueue failure handling. The two input directions are both drained until empty, while forwarding and HA state are refreshed only outside both drains. This produces `S1-B3-001`. The stop atomic remains checked per packet, so the finding is not a shutdown/join-latency duplicate.

### `userspace-dp/src/afxdp/coordinator/refresh_bindings.rs`

Measured `copy_live_snapshot` at lines 49-258 (210 lines) and `zero_unbound_slot` at 266-428 (163 lines). Compared every copied live counter with both this unbound clear and `reconcile/reset.rs`. The July 9 counter addition updated the bound copy and full-reconcile reset but omitted `martian_dropped` and `ipv6_ext_header_dropped` from the unbound path. The shared-UMEM strings were investigated and excluded from the finding because protocol documentation identifies them as coordinator-selected plan metadata, not unambiguously live-only telemetry. The two counter omissions produce `S1-B3-003`.

### `userspace-dp/src/afxdp/worker/loop_body/setup.rs`

Measured `worker_loop_setup` at lines 57-247 (191 lines). Traced thread affinity, TSC calibration, initial ArcSwap loads, session/screen setup, binding creation, CoS maps, pollfd construction, map-fd caching, and initial status publication into the returned setup bundle. Heap allocations occur at one-shot worker startup, and the function is deliberately `#[inline(never)]`; the caller destructures the result before entering the inlined per-tick loop. Negative result: splitting this bundle further would spread startup rollback and increase ownership ambiguity without reducing hot-path work. Preserve this cold boundary.

### `userspace-dp/src/event_stream/codec/session_sync.rs`

Read both session-open and session-close encoders plus close-flag construction. The encoders use fixed `[u8; 256]` storage, check payload bounds, write session identities and scalar fields explicitly little-endian, and copy IP octets without host reinterpretation. `SessionDeltaKind` routes only open/close; the reserved update constant is not an active divergent encoder. Cross-checked exact-offset Rust tests and Go decoding. Negative result: no heap allocation, trait-object dispatch, ABI cast, or newly scattered endian boundary warrants another split after #4651.

### `userspace-dp/src/afxdp/coordinator/inject.rs`

Traced request length rejection, address-family/protocol tuple validation, status stamping, forwarding-resolution lookup, optional wire-path constraints, frame construction, CoS selection, and `TxRequest` enqueue. The maximum-length gate precedes frame allocation and dataplane work. The Go manager validates the same tuple before issuing the local control request, while Rust remains the fail-closed authority. Negative result: this is a bounded control-socket operation; its `Vec` construction is not a per-forwarded-packet allocation, and enqueue transfers the owned request exactly once.

### `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs`

Read error/state types and all reconcile phases. Policy integrity, required map FDs, and a complete forwarding build occur before destructive teardown; preserved queue state is captured before stop; publication and worker bring-up happen only after preflight succeeds. The no-snapshot path clears runtime state and refreshes binding status. Negative result: the control transaction remains fail-closed and matches the documented #2440/#2484/#3766/#3789 ownership ordering. Further phase extraction would be mechanical tracker work already covered by #1328, not a new issue.

### `userspace-dp/src/fairness_eval/verdict.rs`

Read verdict inputs, decision shape, guard aggregation, raw/trimmed C-structure selection, RSS checks, structural cap, saturation, failure rendering, and inline tests. `Vec` clones and failure `String` construction run once in the offline evaluator, not in forwarding. Negative result: the decision is cohesive and already separated from parsing/reporting; no packet ownership, atomics, wire endianness, or ABI layout is involved. Existing tests pin the V-3/V-4 fail-closed gates.

### `userspace-dp/src/afxdp/forwarding_build/interfaces.rs`

Traced interface index construction, address parsing, logical-to-physical parent mapping, zone assignment, connected/local routes, NAT ownership, egress VLAN and MTU validation, route-table helpers, and deterministic address selection. All maps and strings are snapshot-build allocations outside the worker loop. Unknown zones and malformed addresses fail closed. Negative result: the current module is one coherent construction transaction, and its logical-interface resolution is consistently consumed by packet-path callers.

### `userspace-dp/src/afxdp/gre.rs`

Read GRE header parsing, declared-length trim, optional checksum verification, endpoint lookup by family/key/tuple, ECN propagation, inner IPv4/IPv6 and fragment handling, metadata construction, attachment ownership, outer MTU rejection, and checksum/header writes. Bounds and endian operations are local and explicit. The decap synthetic frame and encap frame copies do allocate on the packet path, but that exact issue is already retained in `codex-review-175.md` and the campaign dedup index. Negative result after suppression: no separate GRE wire, key, checksum, fragment, or UMEM ownership defect was found.

### `userspace-dp/src/afxdp/icmp_embed/builders.rs`

Read the complete IPv4 and IPv6 embedded-packet return builders and final resolution helper. Traced declared quoted bounds, fragment behavior, transport-port restoration, IPv4 header checksum, outer ICMP checksum, ICMPv6 pseudo-header checksum, and zero-checksum canonicalization. Each builder allocates one output `Vec` on the generated-error cold path; there is no trait object or unsafe UMEM ownership. Negative result: family separation preserves endian/checksum locality, and another split would duplicate the shared return-resolution contract. Existing tests cover fragments, DNAT restoration, checksum validity, and idempotence.

### `userspace-dp/src/event_stream/codec/rt_flow.rs`

Read event-kind mapping, payload shape, close/create/generic encoders, and exact offsets. The 152-byte payload intentionally mixes network-order addresses/ports with little-endian daemon fields; writes remain adjacent to named offsets and are backed by fixed stack storage. Cross-checked `wire.rs`, Rust codec tests, and Go legacy/new-length tests. Negative result: no allocation, dynamic dispatch, unaligned typed access, or unstated ABI dependency was found. Some historical size comments are stale, but constants and tests enforce the actual 152-byte wire contract and do not justify a refactor issue.

### `userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs`

Read all GRE and WG three-pass lifecycle code: finished sweep, stale prune, unpublish/stop/join ordering, tombstones/backoff, worker gating, generation stamps, spawn captures, liveness reconcile, and stop cleanup. GRE endpoint content intentionally follows the shared forwarding ArcSwap. WG instead resolves one scalar outer MTU from the first endpoint-bearing peer and captures it for the whole control thread, although TUN egress selects a peer per packet and peers may use different underlay routes. This produces `S1-B3-002`. The existing #2921 restart detects changes only to that same scalar and does not repair within-generation peer divergence.

## S2-go-config-b1: Go security/application/IPsec compiler phase specialist

Assigned candidates: **14**. Primary report: `codex-S2-go-config-b1.md`.

### Module Checklist

- [x] `pkg/config/compiler_security_screen.go`
- [x] `pkg/config/compiler_applications_collision.go`
- [x] `pkg/config/compiler_ipsec.go`
- [x] `pkg/config/compiler_security_flow.go`
- [x] `pkg/config/compiler_validate_strict_application.go`
- [x] `pkg/config/ast_edit.go`
- [x] `pkg/config/compiler_applications.go`
- [x] `pkg/config/compiler_policy_then.go`
- [x] `pkg/config/schema_complete.go`
- [x] `pkg/config/compiler_security_policy.go`
- [x] `pkg/config/compiler_tailgates.go`
- [x] `pkg/config/compiler_policy_match.go`
- [x] `pkg/appid/catalog.go`
- [x] `pkg/config/compiler_validate_strict_routing.go`

### File-by-File Inspection Log

### `pkg/config/compiler_security_screen.go` (474 lines)

`compileScreen` spans lines 156-474 and combines dual-AST extraction, numeric fallback evidence, unsupported-leaf evidence, profile folding, and typed publication. It creates a fresh profile for each `ids-option`, reads only the first `icmp`/`ip`/`tcp`/`udp`/`limit-session` child, and then assigns one map entry. The later strict gates and sorted snapshot builder see only that reduced object. Retained `S2GCB1-SCREEN-01`; no goroutine, lock, interface dispatch, or packet-path work occurs in this compiler.

### `pkg/config/compiler_applications_collision.go` (369 lines)

`validateApplicationNameCollisionsAST` (lines 79-369) is a large but cohesive pre-publication gate. It walks all application blocks, counts user and generated term names, distinguishes application/application-set namespaces, and preserves deterministic diagnostics through first-seen application order plus sorted set/parent names. Strict returns the first error and tolerant appends the same ordered evidence as warnings. No new finding: extracting fragments before preserving this one-pass namespace view would increase drift risk without establishing a better ownership boundary.

### `pkg/config/compiler_ipsec.go` (681 lines)

Inspected Phase-1 IKE extraction, DPD parsing, Phase-2 extraction, proposal-set expansion, gateway merge behavior, VPN/selector construction, and gateway-reference validation. Gateways deliberately fetch and extend an existing map object, while proposals, policies, VPNs, and selectors construct fresh objects and replace same-name entries before strict cross-reference validation. Retained `S2GCB1-IPSEC-02`. This is cold compiler/render input; it owns no strongSwan process lock, goroutine, or dataplane state directly.

### `pkg/config/compiler_security_flow.go` (728 lines)

Lines 11-477 own flow-trace and TCP-MSS AST gates, including the all-child traversal added by `#3566`; `compileFlow` at lines 479-728 owns the typed fold. The gate side now examines every duplicate `flow`/`traceoptions` subtree, but the compiler still uses first-only `FindChild` for aging, session, MSS, and trace subtrees. Retained `S2GCB1-FLOW-03` because valid later declarations disappear after passing validation. Existing size/file helpers correctly share parse semantics, and no additional finding was warranted for their strict/tolerant ordering.

### `pkg/config/compiler_validate_strict_application.go` (691 lines)

Inspected set-member resolution, protocol/port/ICMP syntax, direct-versus-term structure, duplicate scalar evidence, and the referenced-application reachability walk. Map-backed application and set names are sorted where first-error order matters; typed evidence is consumed after the application compiler has completed. `applicationsToValidateStrict` intentionally mirrors `appid.CatalogNames` because of the package import direction. That exact duplication is already tracked by `codex-review-122` L04, so no new finding was retained.

### `pkg/config/ast_edit.go` (828 lines)

Inspected copy, rename, relative insertion, schema-aware `SetPath`, delete, activate/deactivate, multi-leaf member removal, and key matching. Copy clones before insertion; rename validates source, destination, and collision before detach; relative insertion resolves both nodes before mutation; and `SetPath` has no fallible operation after incremental construction begins. The edit routines own no concurrent publication or locks; configstore supplies the transaction boundary around candidate edits. No new issue survived the prior AST/schema split work or the current multi-leaf deletion guards.

### `pkg/config/compiler_applications.go` (732 lines)

`compileApplications` (lines 43-223) builds direct and term-based applications; `parseApplicationTerms` (lines 224-428) handles dual token locations and records structural evidence; the remainder normalizes protocols, ICMP, ports, timeouts, and ALG names. The collision pre-gate protects strict same-name publication, and typed validators consume the recorded malformed/duplicate evidence. The duplicated port parser and compiler/catalog application walk are known tracker items; no additional phase or allocation issue was found in this cold path.

### `pkg/config/compiler_policy_then.go` (583 lines)

Inspected permit, reject, and deny AST gates plus collapsed-action token extraction. All three gates use the shared all-block policy helpers from `compiler_security_policy.go`, preserving source order and strict-versus-tolerant evidence after the F-006 fix. The repeated outer security/policies/zone-pair traversal and collapsed deny parsing are the known F-205/F-006 family, not a new module boundary. No finding retained.

### `pkg/config/schema_complete.go` (353 lines)

`CompleteSetPathWithValues` (lines 99-271) resolves exact/unique prefixes, wildcard values, typed placeholders, and examples; `ResolveConsumedSetPathTokens` mirrors traversal for consumed CLI paths. Schema child maps are ranged without sorting, so the exported helper itself does not promise order, but the CLI sorts at `pkg/cli/completion.go:122` and gRPC sorts immediately before response publication at `pkg/grpcapi/server_cluster.go:456`. No production CLI/gRPC determinism defect was retained. There is no goroutine, lock, or mutable global state in completion traversal.

### `pkg/config/compiler_security_policy.go` (451 lines)

Inspected zone/global policy collection, global-zone normalization, the all-block `policyMatchChildren`/`policyThenChildren` helpers, terminal-action extraction, and `compilePolicy` (lines 206-386). The compiler now accumulates duplicate inner match/then blocks in source order, while global zone lists are sorted/deduplicated for stable publication. No new finding: the former first-block loss is the already-reported F-006 issue, and the broader security compiler split is complete.

### `pkg/config/compiler_tailgates.go` (191 lines)

`runTailGates` is one explicit P7 sequence whose source order defines strict first-error precedence and tolerant warning order. Each gate receives the completed typed config and appends warnings without publishing a partial config; moving gates into unordered registries would alter behavior. This is a class-D boundary to preserve unless ordering is represented as data. The broader orchestrator and strict-validator splits are already tracked/completed, so no new finding was retained.

### `pkg/config/compiler_policy_match.go` (320 lines)

Inspected supported/global-only/unsupported leaf catalogs and `validatePolicyMatchLeavesStrict` (lines 166-320). It walks every security root, policies block, zone pair, policy, and match block through shared helpers, retaining source-order strict/tolerant diagnostics. Catalog duplication with schema and compiler parsing is the known F-205 family; current all-block behavior closes the prior F-006 gap. No new finding retained.

### `pkg/appid/catalog.go` (417 lines)

`BuildCatalog` (lines 70-237) deterministically assigns IDs from sorted reachable application names, expands protocol/port/ICMP constraints, and enforces the `uint16` catalog ceiling. Protocol naming and lenient reverse resolution are deterministic table operations. The catalog/compiler application walk, protocol conversion, and port parsing duplicates are already documented in `codex-review-122` L04 and `codex-review-155` L06/L07; no new finding was retained. Build time is snapshot/control-plane work, with no per-packet allocation or lock impact from this file.

### `pkg/config/compiler_validate_strict_routing.go` (830 lines)

Inspected export/community/auth/peer-AS/router-ID/RIB-group/route-filter validators and all helper catalogs. Map-backed policies and RIB groups are sorted before first-error selection; routing-instance and authored lists retain declaration order; tolerant behavior remains at the ordered outer gate. The redistribution token catalog has drifted from the renderer despite its stated mirror invariant, so `ospf6`/`ripng` are rejected by strict compilation but accepted downstream. Retained `S2GCB1-ROUTE-04`; the separate duplicated RIB-name matcher is explicitly covered by `#2253`/PR `#2266` and is suppressed.

### Support reads (contract verification only)

- `AGENTS.md`, `pkg/config/README.md`, `pkg/appid/README.md`, `pkg/ipsec/README.md`, `docs/architecture.md`, and `docs/snapshot-publish-redesign.md`: compiler phases, package ownership, strict/tolerant doctrine, and publication invariants.
- `pkg/config/parser.go`, `ast.go`, `compiler_security.go`, `compiler_validate_strict_screen.go`, and `compiler_validate_strict_ipsec.go`: duplicate sibling preservation, first/all-child semantics, security dispatch, and post-fold strict gates.
- `pkg/config/host_inbound_dup_block_4544_test.go` and `addressbook_dup_addrset_merge_4706_test.go`: repository-established Junos merge semantics for hierarchical load-override duplicates.
- `pkg/dataplane/userspace/screens.go`, `flow.go`, `pkg/dataplane/compiler.go`, and `pkg/logging/trace.go`: deterministic screen/flow snapshot publication and runtime consumption.
- `pkg/ipsec/ike.go`: IKE/ESP resolution, fail-closed chain behavior, and missing-encryption defaults.
- `pkg/frr/policy_render.go`, `frr_test.go`, and `pkg/routing/rules.go`: renderer vocabulary, `#2943` tests, and RIB apply-side parity.
- `pkg/cli/completion.go`, `pkg/cli/cli.go`, and `pkg/grpcapi/server_cluster.go`: sorted CLI/gRPC completion publication.

## S2-go-dataplane-services-b2: Go userspace dataplane compiler and host-service reconciliation specialist

Assigned candidates: **14**. Primary report: `codex-S2-go-dataplane-services-b2.md`.

### Module Checklist

- [x] `pkg/dataplane/userspace/nat_destination.go`
- [x] `pkg/dataplane/userspace/cos.go`
- [x] `pkg/dataplane/userspace/filters.go`
- [x] `pkg/dataplane/userspace/zones_host_inbound.go`
- [x] `pkg/dataplane/userspace/routes.go`
- [x] `pkg/dataplane/userspace/manager_compile.go`
- [x] `pkg/dataplane/proxyarp.go`
- [x] `pkg/daemon/daemon_neighbor.go`
- [x] `pkg/dataplane/userspace/nat_source.go`
- [x] `pkg/dataplane/userspace/interfaces.go`
- [x] `pkg/dataplane/userspace/tunnels.go`
- [x] `pkg/daemon/device_map.go`
- [x] `pkg/conntrack/gc.go`
- [x] `pkg/fwdstatus/builder.go`

### File-by-File Inspection Log

### 1. `pkg/dataplane/userspace/nat_destination.go`

Read all 520 lines. `buildDestinationNATSnapshotsWithFeeds` spans lines 92-520 and is a pure, cold snapshot lowerer: it expands literal/address-book/feed scopes, applications and port ranges, DNAT exemptions, pool validity, protocol constraints, and stable counter IDs into wire records. It performs no netlink, map, helper, lock, or host mutation. The allocations are bounded apply-time slices and coalesced ranges, not packet work. Strict validation is backed by tolerant-path fail-closed sentinels and skip behavior; exact-host versus prefix indexing and `off` ordering are Go/Rust protocol invariants. This file is the recent destination-NAT extraction (`591c4800c`, part of PR #4457), so another split would fragment one rule-expansion transaction or repeat known NAT-module work. Negative result.

### 2. `pkg/dataplane/userspace/cos.go`

Read all 259 lines. The 249-line `buildClassOfServiceSnapshot` deterministically sorts and lowers forwarding classes, DSCP/802.1p classifiers, rewrite rules, schedulers, scheduler maps, and interface references. It constructs a fresh immutable wire value, skips nil/unresolved rows under the existing validation contract, and has no host I/O, publication, goroutine, or lock ownership. The repeated sorted-map loops are domain-specific schema lowering and allocate only during config apply. Splitting each loop into a sibling helper would be flat motion without a stronger owner or rollback boundary. Negative result.

### 3. `pkg/dataplane/userspace/filters.go`

Read all 622 lines. The file owns deterministic filter and policer wire lowering plus the exported `ResolveFilterPrefixListAddrs` semantic boundary shared with the daemon's lo0 nft mirror. `buildFilterTermSnapshots` spans lines 71-319 and keeps address/prefix-list inversion, ports, ICMP, TCP flags, flexible match, actions, and unrepresentable markers in one ordered term lowering. The pure builder allocates apply-time slices only; warnings are the only side effect. Pulling the shared resolver or term fields apart before a common filter-domain design would risk nft/Rust strict-versus-tolerant drift and duplicates open #4421. Negative result.

### 4. `pkg/dataplane/userspace/zones_host_inbound.go`

Read all 394 lines. `BuildZoneHostInboundViews` (lines 80-309) combines zone/interface policy tokens with live interface addresses, VRRP VIPs, lifeline exclusions, and canonical grouping for the kernel nft primary path and Rust secondary enforcement. `BuildUnzonedHostInboundAddrs` derives the complementary deny scope. The policy projection is pure after `buildInterfaceSnapshots`, but that callee performs live host reads. Broad cross-layer host-inbound ownership is already L07/codex-review-128; repeated interface acquisition is also #41. Existing grouping, override, VRRP, learned-address, and unzoned tests are the required guardrails. No narrower new seam survived dedup.

### 5. `pkg/dataplane/userspace/routes.go`

Read all 422 lines. `buildRouteSnapshots` (lines 33-250) combines config statics, interface-derived connected prefixes, live `RuleList` leak rules, and route-monitor overlays, then emits a total deterministic order. This is planning with one explicit host observation and no actuation. Failure to enumerate either rule family aborts the whole build, preserving the prior published snapshot rather than publishing a partial FIB. Dedupe includes discard/preference, PBR selectors are excluded, and overlay replacement is whole-entry. The function is broad but its sources converge on one FIB-generation contract; no credible directory boundary or untracked allocation issue was found.

### 6. `pkg/dataplane/userspace/manager_compile.go`

Read all 622 lines and traced `Compile` (lines 162-378), protocol gates, delayed publication, same-plan refresh, post-publish caches, HA replay, forwarding-arm sync, and scheduled republish. It is not pure: it removes pinned links, invokes the legacy shim compiler and interface attachment, mutates classifier/bootstrap maps, starts/contacts the helper, publishes the snapshot, and then advances manager state under `Manager.mu`. Failures before and after `apply_snapshot` have materially different rollback behavior. The exact planning/actuation and map/helper transaction boundaries are already retained as R6B2-02 and R6B2-01; F-A7-2 separately owns the helper-status split. Repackaging those findings here would be duplicate campaign work, so this file is a documented suppression rather than a new finding.

### 7. `pkg/dataplane/proxyarp.go`

Read all 391 lines and traced desired-set construction, family-correct `NTF_PROXY` listing/add/delete, responder sysctls, added-entry GARP handoff, and daemon state ownership. The reconciler only lists interfaces present in the new proxy-ARP config. Once an interface disappears, neither this function nor its daemon caller visits its neighbor table; only the remembered sysctl family is disabled. This leaves an owned IPv4 proxy-neighbor entry installed and is retained as `S2GDPB2-01`. Existing tests cover stale addresses on an interface that remains managed and sysctl teardown, not interface removal from the neighbor sweep.

### 8. `pkg/daemon/daemon_neighbor.go`

Read all 604 lines. `collectNeighborProbeTargets` (lines 56-243) gathers static, DHCP, NAT, address-book, and backup-router targets through live `RouteGet`/`LinkByName`, then deduplicates `(IP, ifindex)` before probe dispatch. Periodic resolution, cluster warming, and probe goroutines have explicit in-flight atomics that prevent overlapping expensive passes; config slices are copied before append. Some duplicate candidates still incur lookup/string allocation before target dedupe, but this is a 15-second control-plane task with no measured regression, and #1197/#1780/#1781 already established the shared target collector, lifecycle guards, and copy discipline. No new issue-worthy split was found.

### 9. `pkg/dataplane/userspace/nat_source.go`

Read all 503 lines. `buildSourceNATSnapshotsWithFeeds` (lines 23-205) is pure rule planning; remaining helpers own deterministic scope precedence, address/application expansion, compact port ranges, protocol numbers, deterministic block fields, and pool port validity. Output sorting pins Rust first-match semantics, while invalid tolerant inputs retain explicit never-match/invalid state instead of widening. All maps and slices are cold apply-time allocations; there is no host I/O, lock, or runtime allocator mutation. This is the recent source-NAT extraction (`0d4af845c`, PR #4457), and another split would duplicate known NAT compiler/module work. Negative result.

### 10. `pkg/dataplane/userspace/interfaces.go`

Read all 561 lines. `buildInterfaceSnapshots` (lines 164-327) mixes config projection with live `net.InterfaceByName`, `netlink.LinkByName`/address reads, and sysfs RX-queue enumeration. Parent details are reacquired per unit, `snapshotLinuxName` rebuilds `TunnelNameMap` per unit, and `UserspaceBoundLinuxInterfaces` invokes the entire snapshot builder even though it only needs bind names. These are real apply-time lookup/allocation costs and can give separate helper/nft/RSS projections observations from different instants, but the proposed compile-pass inventory/cache is exactly closed #41 and the broader pure plan/host observation boundary is R6B2-02. Synthetic ifindex probing, sorted addresses, parent-bound VLAN semantics, and protocol fields are well tested. Suppressed rather than re-filed.

### 11. `pkg/dataplane/userspace/tunnels.go`

Read all 213 lines. `buildTunnelEndpointSnapshots` deterministically derives GRE/IPIP/WireGuard endpoints, stable collision-resolved IDs, transport tables, source addresses, and sorted peers from config plus already-built interface snapshots. It is pure planning. The only manager mutation is `logWgEndpointSetTransitionLocked`, called after successful helper publication and guarded by `Manager.mu`; it advances the remembered set only with the log. No packet-path allocation or host actuation occurs here, and separating each tunnel kind would duplicate the shared endpoint-ID/transport invariant. Negative result.

### 12. `pkg/daemon/device_map.go`

Read all 695 lines and traced identity resolution, collision breaking, durable `.link` publication, final and stranded-interface renames, stale manifest cleanup, networkd reload, management preflight, and managed-to-unmapped teardown. `enumerateAndRenameMapped` logs phase failures but returns nil; the config-arrival caller therefore consumes its retry marker and the apply pipeline proceeds. Teardown can also remove the durable ownership files after rename-back failure. This is an actuation-outcome ownership defect, retained as `S2GDPB2-02`; it is narrower than prior device-map layout/collision work.

### 13. `pkg/conntrack/gc.go`

Read all 554 lines. The GC goroutine snapshots mutable aging/limit settings under `gc.mu`, iterates/deletes v4 and periodically v6 sessions, runs persistent-NAT cleanup, publishes per-IP counts, updates hysteresis, and publishes stats under the same owner. On the sole userspace runtime, `SkipSweep` returns at lines 226-232 before all of this because Rust owns lifetime and session-limit state. The legacy count publisher incrementally updates current keys, ignores write errors, and never invokes its `ClearSessionCounts` method, so stale keys are possible only in the retired eBPF-shaped sweep. That observation is subsumed by F-212, which already calls for removing the unreachable GC machinery while the daemon still spins/configures it; a standalone fix would invest in dead runtime behavior and conflict with retirement. Negative/suppressed result.

### 14. `pkg/fwdstatus/builder.go`

Read all 268 lines. `Build` gathers process sensors, CPU windows, eBPF map or userspace binding pressure, one helper status snapshot, and the shared CLI/gRPC state. Its userspace state classifier checks only helper-status error and heartbeat freshness after shim `IsLoaded`; it does not inspect `Enabled`, `ForwardingArmed`, or `Capabilities.ForwardingSupported`, and an empty heartbeat slice is explicitly considered fresh. That can render an intentionally fail-closed or failed helper `Online`; retained as `S2GDPB2-03`. CPU and buffer collection are on-demand/cached as documented and do not reveal another allocation or lock problem.

## S2-go-surfaces-b3: Go gRPC/CLI show-surface and diagnostics presenter specialist

Assigned candidates: **16**. Primary report: `codex-S2-go-surfaces-b3.md`.

### Module Checklist

| Assigned path | Measured size | Primary ownership examined | Disposition |
|---|---:|---|---|
| `pkg/grpcapi/server_show.go` | 538 | Generic ShowText request grammar, topic dispatch, bounded tail/system text | Prior typed-RPC work; no new directory |
| `pkg/cli/cli_show_interfaces_terse.go` | 316 | Local terse interface acquisition, ordering, and rendering | Prior `pkg/ifaceview` work; no new directory |
| `pkg/grpcapi/server_cluster.go` | 828 | Cluster RPCs, policy matching, counter clearing, completion | Retain `pkg/clicomplete/` finding |
| `pkg/grpcapi/server_show_policies_text.go` | 541 | Policy hit/detail and policy-options text | Prior show-text work; no new directory |
| `pkg/grpcapi/server_show_firewall.go` | 584 | Raw firewall-filter all/single renderers and live counters/policers | Retain `pkg/filtershow/` finding |
| `pkg/grpcapi/server_diag_monitor.go` | 520 | Packet-drop and interface server streams, peer proxying | Existing stream owners are cohesive; no new directory |
| `pkg/api/server.go` | 715 | REST composition root, route registration, HTTP/TLS lifecycle | Composition root; no new directory |
| `pkg/cli/cli_show_interfaces_extensive.go` | 207 | Local extensive interface renderer | Prior `pkg/ifaceview` work; no new directory |
| `pkg/cli/completion.go` | 577 | Readline completion orchestration and config value projection | Retain `pkg/clicomplete/` finding |
| `pkg/cli/cli_show_security_zones.go` | 186 | Local zone text and policy summary | Prior interface/show work; no new directory |
| `pkg/cli/cli_show_security_filters.go` | 554 | Raw all/single and effective firewall-filter presentation | Retain `pkg/filtershow/` finding |
| `pkg/grpcapi/server_show_zones_text.go` | 251 | gRPC zone text and policy summary | Prior interface/show work; no new directory |
| `cmd/xpfd/upgrade_kernel.go` | 186 | Kernel-upgrade CLI adapter and process exit policy | Cohesive adapter; no new directory |
| `pkg/grpcapi/server_show_status.go` | 276 | Status/stats and unary host diagnostics | Retain `pkg/diagoutput/` and `pkg/neighview/` findings |
| `pkg/cli/cli_show_interfaces_detail.go` | 265 | Local detail interface acquisition and rendering | Prior `pkg/ifaceview` work; no new directory |
| `pkg/cli/cli_show_security.go` | 490 | Security command router and policy presenter | Prior command-spec/show work; no new directory |

Only four actual leaf directories are proposed: `pkg/filtershow/`, `pkg/clicomplete/`, `pkg/diagoutput/`, and `pkg/neighview/`. The remaining tempting cuts would be same-package file shuffling, composition-root fragmentation, or duplicates of active prior work.

### File-by-File Inspection Log

### pkg/grpcapi/server_show.go

`ShowText` spans lines 20-515 and owns a large string-topic compatibility grammar, config snapshot selection, direct subsystem calls, and text rendering. Tail counts are clamped, external commands use request deadlines, and request context is forwarded through recursive/peer paths; there is no newly discovered unbounded server stream in this file. Its stringly selector and local/remote grammar drift are exactly the typed command and typed Show RPC roots retained as `R7B2-HC-001` and `R7B2-HC-003`. Splitting switch arms into more `server_show_*` files would repeat #1700-era code motion without establishing ownership, so this file is a negative result.

### pkg/cli/cli_show_interfaces_terse.go

`showInterfacesTerse` occupies essentially the whole file and joins active config, RETH resolution, netlink links/addresses, DHCP state, and terminal formatting. It canonicalizes physical rows and logical units before output; no goroutine, transaction, or mutation owner lives here. Runtime reads remain request-local, and no stream accumulates output. The remaining duplication and interface-identity concerns belong to `R7B1-IFACE-03` and `C175-HC-087`; a new terse-only directory would split one view before its shared model lands. Negative result.

### pkg/grpcapi/server_cluster.go

This file contains several independent RPC implementations: interface-input construction near lines 20-130, `MatchPolicies` at lines 132-346, counter clearing, and completion at lines 420-808. Policy matching delegates semantic evaluation to `policymatch`, validates before evaluation, and does not publish mutable state. Counter clear paths preserve subsystem error boundaries. Completion, however, duplicates local config-mode orchestration and the complete snapshot-backed `ValueHint` projection and has a concrete cursor-unit mismatch; that bounded owner is retained as `S2B3-COMPLETE-03`. Moving the other RPCs into sibling files is not an issue-worthy directory seam.

### pkg/grpcapi/server_show_policies_text.go

The hit-count and detail presenters span lines 80-256 and 261-473. They read counters in bulk, preserve configured policy order, map rule IDs before rendering, and retain the first read failure until after the attempted view rather than silently certifying zeros. `showPolicyOptions` at lines 477-541 ranges prefix-list and statement maps without sorting, and the local support path repeats that renderer. That deterministic-order root is already within `R7B1-SHOW-02`'s staged `pkg/showtext` migration; #1687 also rejected a broad universal presenter. No separately actionable package is proposed here.

### pkg/grpcapi/server_show_firewall.go

`showFirewall` at lines 54-203 and `showFirewallFilter` at lines 417-583 repeat raw term projection, counter-stride traversal, userspace-counter joins, and policer status rendering. Filter names are sorted, term order is preserved, one userspace status snapshot is reused, `FilterTermExpansionCount` determines offsets, and a counter failure is reported only after reads complete. The duplicated semantic projection has already drifted from the local CLI in opposite action fields, so `S2B3-FILTER-01` retains a guardrail-first semantic-view owner. No streaming is involved.

### pkg/grpcapi/server_diag_monitor.go

`MonitorPacketDrop` spans lines 55-261. It validates node locality, count (`0` deliberate unlimited, otherwise capped at 8,192), ports, protocol, zones, interfaces, and prefixes before taking a 256-entry event subscription; the event producer drops to a slow subscriber rather than growing a queue. The loop exits on stream context, send error, or requested count. `MonitorInterface` at lines 312-475 emits one bounded frame per second, replaces prior snapshot maps rather than retaining history, forwards the caller context to a peer stream, and exits on cancellation/send/receive errors. The known daemon `GracefulStop` interaction and remote pipe buffering are suppressed as `C175-HC-051` and `R7B2-HC-002`; no new stream owner is warranted.

### pkg/api/server.go

`Config` is the REST composition dependency bag; `NewServer` at lines 347-543 wires routes and HTTP timeout policy, while `Run` and TLS helpers own listener lifecycle and certificate persistence. `http.ServeMux` remains the duplicate-route guard, and feature handlers own their resource caps rather than this constructor. REST is deliberately not endpoint-for-endpoint identical to gRPC, and the generic show-text differences are handled at semantic view boundaries rather than by splitting this root. The previously noted shared shutdown-budget/secondary HTTPS error handling is a lifecycle concern, not a new presenter directory. Negative result.

### pkg/cli/cli_show_interfaces_extensive.go

`showInterfacesExtensive` spans lines 16-207 and composes active config, sorted netlink links, sysfs/kernel details, configured units, and counters into a local-only extensive format. It owns no persistent state and performs no asynchronous work. Any authored-name/kernel-name or logical-unit ordering repair must land in the previously proposed shared interface model (`R7B1-IFACE-03`, `C175-HC-087`), not in an extensive-only package. Negative result.

### pkg/cli/completion.go

`cliCompleter.Do` at lines 47-146 coordinates readline suffix replacement, pipe help, operational-tree completion, and config-schema completion. `completeConfigWithDesc` at lines 148-204 and `valueProvider` at lines 400-577 duplicate the gRPC implementation almost branch for branch. Candidate sorting is deterministic and aligned locally, and completion is a finite unary/terminal operation, but the remote adapter mixes rune and byte cursor units while the two copies can drift in descriptions and nil-tolerant value cases. Retained as `S2B3-COMPLETE-03`.

### pkg/cli/cli_show_security_zones.go

`showSecurityZones` spans lines 12-186. It sorts zone names, uses shared host-inbound service/protocol expansion, preserves configured policy order, and joins interface descriptions and addresses without mutating config. Logical units are obtained from map-backed interface config, so their local order can drift; the same root is already assigned to `pkg/ifaceview` by `R7B1-IFACE-03`. The local/gRPC formatting differences are deliberate text profiles, not evidence for a universal renderer. Negative result.

### pkg/cli/cli_show_security_filters.go

`showFirewallFilters` at lines 13-175 and `showFirewallFilter` at lines 177-337 are two local raw-config projections with duplicated live counter traversal. `showEffectiveFirewallFilters` at lines 339-522 is intentionally different: it renders compiled snapshots, including resolved prefix lists and fail-closed states, without touching the live dataplane. Raw filter names are sorted and configured term order is retained, but raw local output omits policers that gRPC shows while gRPC omits DSCP rewrite actions that local output shows. Retained as `S2B3-FILTER-01`; the remote `show firewall effective` dispatch bug remains the separate `R7B2-HC-001` issue.

### pkg/grpcapi/server_show_zones_text.go

`showSecurityZones` spans lines 15-250 and mirrors the local zone acquisition with a gRPC text profile. Zone names are sorted, host-inbound semantics come from shared helpers, and runtime lookup failures are surfaced after the useful view rather than converted to clean state. Map-backed logical-unit ordering is the known interface-view root, while broad text equality would contradict #1687. Negative result.

### cmd/xpfd/upgrade_kernel.go

`runUpgradeKernelSubcommand` spans lines 28-186 and is cohesive command glue: it parses status/cancel/rollback/install verbs, delegates transaction and lock ownership to `pkg/upgrade`, prints progress, and applies daemon process exit policy only after successful state transitions. It does not implement the upgrade transaction or rollback itself. `os.Exit` makes the adapter integration-heavy, but extracting each verb into another directory would separate policy from its one caller without changing ownership. Negative result.

### pkg/grpcapi/server_show_status.go

`GetStatus` and `GetGlobalStats` are compact typed snapshot RPCs; global counters use a shared read closure and reject the response if any read failed, preventing partial zeros from looking healthy. `GetSystemInfo` at lines 123-275 multiplexes procfs, external commands, neighbor tables, and configured users. External command runtime is bounded but output bytes are not, and the unary builder also collects every neighbor row. The neighbor branches duplicate local acquisition, perform repeated link-index resolution, and preserve kernel enumeration order. These are two independent roots, retained as `S2B3-DIAG-02` and `S2B3-NEIGH-04`; the rest of the status file remains cohesive.

### pkg/cli/cli_show_interfaces_detail.go

`showInterfacesDetail` spans lines 15-265 and combines config names, RETH/kernel resolution, netlink addresses, zones, DHCP leases, and counters for the local profile. It sorts physical groups but inherits the already-reported map-derived logical-unit ordering and authored/kernel identity ambiguity. Reads are synchronous and request-local; no transaction, lock, or stream ownership moves. The correct dependency is the existing `pkg/ifaceview` work, not another detail directory. Negative result.

### pkg/cli/cli_show_security.go

This file is the security command router plus the local policy list/detail presenter. It delegates zones, filters, screens, VPN, logs, objects, and flows to existing owners; policy rendering reads its counter snapshot once and preserves policy/config order. The large switch is command grammar, whose local/remote parity is already `R7B2-HC-001`; broad policy/ALG presenter sharing was considered and narrowed by #1687. Another `cli_show_security_*` sibling would be flat code motion. Negative result.

### Support reads (unassigned)

Support source was read only to verify contracts and was not converted into unassigned findings: `pkg/cli/cli_show_interfaces_shared.go`, `pkg/cmdtree/tree.go`, `cmd/cli/show.go`, `cmd/cli/show_interfaces.go`, `cmd/cli/shared.go`, `cmd/cli/main.go`, `pkg/grpcapi/server_show_interfaces.go`, `pkg/grpcapi/server_helpers.go`, `pkg/grpcapi/exec_timeout.go`, `pkg/api/interfaces.go`, `pkg/api/show_text.go`, `pkg/cli/cli_show_routing.go`, `pkg/cli/cli_request_testcmd.go`, `pkg/logging/eventbuf.go`, `pkg/cluster/status.go`, and `proto/xpf/v1/xpf.proto`. Relevant completion, firewall, zone, interface, diagnostic stream, exec-timeout, API server, and upgrade tests were searched/read to identify existing guards and gaps.

## S3-tooling-b1: HA smoke, BPF NAT header, and iperf metrics tooling specialist

Assigned candidates: **3**. Primary report: `codex-S3-tooling-b1.md`.

### Module Checklist

| Assigned path | Measured size | Primary ownership examined | Disposition |
|---|---:|---|---|
| `scripts/userspace-ha-failover-validation.sh` | 1,781 | Cluster ownership/mutation, artifact capture, snapshot parsing, transition gates, iperf lifecycle, cleanup/restore | Retain lock, strict-evidence, and shared-metrics findings; suppress the broad split |
| `bpf/headers/xpf_nat.h` | 575 | Historical IPv4/IPv6 NAT checksum and address/port rewrites, embedded ICMP repair, NPTv6 | Negative result: preserve inline/endian locality; header retirement is prior R10 work |
| `scripts/iperf-json-metrics.py` | 234 | JSON and JSON-stream normalization, interval/stream metrics, collapse classification, stable JSON output | Retain one shared metric-contract finding |

Every assigned line was read. The shell validator was read in ten contiguous numbered ranges, the header in four, and the Python file in one.

### File-by-File Inspection Log

### scripts/userspace-ha-failover-validation.sh

The file is one stateful test program whose globals own target selection, timing and thresholds, artifact paths, the mutable `FAILED` verdict, and cleanup restoration. Cluster access and owner settling occupy lines 101-275; capture/path naming and four embedded Python snapshot parsers occupy lines 277-646 and 802-962; phase gates occupy lines 648-1122; iperf lifecycle and a fifth embedded parser occupy lines 1218-1468; orchestration and final verdicts occupy lines 1470-1781. `validate_phase_fabric_path` is 144 lines (657-800), while `validate_transition_window` is 159 lines (964-1122). Mutation order is meaningful: establish/arm the source owner, establish sync-idle, start traffic, move the RG, settle the requested userspace owner, sample, gate, and restore from the EXIT trap.

The script is destructive but has no shared-cluster cell entry before `ensure_rg_owner` and later explicit failover requests; this survives as `S3B1-LOCK-01`. Most newer snapshot readers return nonzero on missing sections, malformed counters, and counter regression, but `status_fabric_tx_packets` still maps missing/malformed evidence to zero and feeds an unchecked delta into a branch that can print PASS; this survives as `S3B1-EVIDENCE-02`. The live iperf parser silently skips malformed records, treats no intervals as zero failures, and uses literal zero while the final parser uses the configurable near-zero threshold; this survives with the assigned Python file as `S3B1-IPERF-03`. A generic request to split the 1,781-line script is already #1661 item 5 and is not repeated.

### bpf/headers/xpf_nat.h

The complete helper inventory is: IPv4 pseudo-header checksum update (20-43), IPv6 pseudo-header update (50-81), port checksum update (87-103), IPv4 rewrite (108-211), embedded ICMPv4 rewrite (218-288), embedded ICMPv6 rewrite (297-371), the exactly 150-line `nat_rewrite_v6` unit including its qualifier (377-526), and NPTv6 translation (539-573). The rewrite functions are `static __always_inline`, allocation-free, lock-free, concrete C. They keep packet bounds checks, old-value capture, incremental checksum adjustment, and packet mutation adjacent. Address/port fields stay `__be32`/`__be16`; NPTv6's native 16-bit arithmetic and checksum-partial branches must not be normalized into host/network conversion helpers without byte-for-byte fixtures.

No tracked C translation unit includes or calls this header at the base. The legacy XDP/TC programs were removed by #1476, `make generate` builds only the retained Rust shim, and the current `bpf/` tree contains headers only. Historical #179/PR #169 optimized the protocol-specialized switch; PR #178 restored packet-versus-metadata rewrite semantics after flag-gating broke reverse NAT. Splitting TCP/UDP/address legs into C translation units would invent call/verifier boundaries for unbuilt code, while header-only extraction offers no current runtime or review owner. The dependency-closed audit/retirement of all seven retained headers is already `R10-B1-001` as revised by `design-tooling.md`; no new NAT-header issue is warranted.

### scripts/iperf-json-metrics.py

`load_iperf_payload` accepts whole JSON or line-delimited `--json-stream`; `collect_intervals` normalizes both; `end_throughput_summary` deliberately prefers received throughput; and the 150-line `summarize` function (65-214) owns protocol/completion detection, UDP/TCP end metrics, interval filtering, stream deduplication, peak/tail statistics, and collapse policy. Output key order is deterministic through `sort_keys=True`; peak selection is the first maximum; `zero_streams_total` uses a set of socket/id strings.

The parser has only one focused repository test, for receiver-summary preference. More importantly, its metric schema conflicts with both the live preflight implementation and active documentation: `zero_intervals_total` adds aggregate intervals and per-stream samples even though a separate stream metric exists, and the live shell uses a different threshold and error policy. The parser is also consumed by the steady HA, native GRE, performance-compare, and assigned failover tools, so extraction cannot silently rename or reinterpret fields. `S3B1-IPERF-03` therefore requires characterization and a versioned compatibility migration rather than a mechanical function split.

### Support reads (unassigned)

Support source was read only to verify contracts and was not converted into unassigned findings: `scripts/userspace-ha-validation.sh`, `scripts/userspace-native-gre-validation.sh`, `scripts/userspace-perf-compare.sh`, `scripts/userspace_ha_validation_matrix_test.py`, `test/incus/cluster-cell.sh`, `test/incus/cluster-cell-selftest.sh`, `test/incus/with-cluster.sh`, `Makefile`, `pkg/dataplane/retirement_boundary_canary_test.go`, `docs/userspace-ha-validation.md`, `docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`, `testing-docs/userspace-fabric-failover.md`, and targeted issue/PR/design history. These reads established the cluster-lock protocol, aggregate/per-stream metric contract, retired BPF boundary, and direct caller behavior.

## S4-largest-tests-b1: Largest-test ownership and characterization-gate specialist

Assigned candidates: **11**. Primary report: `codex-S4-largest-tests-b1.md`.

### Module Checklist

| Candidate | Measured size | Discovery/ownership result |
|---|---:|---|
| `userspace-dp/src/afxdp/tests.rs` | 14,038 lines; 204 test attributes | Broad AF_XDP parent integration suite. Retain a discovery guardrail; suppress generic giant-file decomposition and keep transaction gates together. |
| `userspace-dp/src/afxdp/forwarding_build/tests.rs` | 5,075 lines; 106 test attributes | Cohesive forwarding-state build contract with reusable fixtures and policy variants. Generic split already covered by prior audit. |
| `userspace-dp/src/afxdp/wg/tests.rs` | 3,909 lines; 76 test attributes | WireGuard owner tests, already grouped into root plus four nested modules. Physical extraction is safe only with qualified names unchanged. |
| `pkg/dataplane/retirement_boundary_canary_test.go` | 3,356 lines; 26 top-level tests; 78 terminal leaves | Intentionally cross-boundary retirement canary. Preserve as one characterization boundary. |
| `userspace-dp/src/afxdp/flow_cache_tests.rs` | 2,836 lines; 64 test attributes | Cohesive `FlowCache` behavioral matrix. Profile-dependent leaves require the two-profile discovery gate. |
| `userspace-dp/src/protocol/tests.rs` | 2,393 lines; 65 test attributes | Parent protocol integration suite binding framing, status, schema, and wire invariants. Do not manufacture owner boundaries inside it. |
| `userspace-dp/src/main_tests.rs` | 2,350 lines; 46 test attributes | Legacy crate-root test owner now spans planner, session, protocol projection, and snapshot/server behavior. Retained owner-boundary finding. |
| `pkg/cluster/cluster_test.go` | 2,249 lines; 72 top-level and terminal tests | Tests now map to several production files created by the cluster decomposition. Retained mechanical owner split. |
| `pkg/config/parser_class_of_service_test.go` | 2,097 lines; 46 top-level tests; 49 terminal leaves | Cohesive parser/compiler parity matrix across strict, warning, and tolerant behavior. No credible independent split. |
| `pkg/configstore/store_test.go` | 2,005 lines; 54 top-level tests; 55 terminal leaves | Broad store contract with shared fixtures. Known decomposition target; no materially new boundary retained. |
| `userspace-dp/src/server/tests.rs` | 1,953 lines; 55 test attributes | Canonical `handle_stream` integration owner. Keep request framing and dispatcher error gates at the real parent call site. |

Rust compiled discovery from the assigned files was 611 leaves in debug and 612 in release. The profile totals are `204/204` AF_XDP parent, `106/106` forwarding build, `76/76` WireGuard, `59/60` flow cache, `65/65` protocol, `46/46` main, and `55/55` server. No assigned Rust leaf was ignored. The flow-cache source has 55 common leaves, four debug-only expected-panic leaves, and five release-only mismatch leaves, accounting for its 64 source attributes without pretending that all coexist in one binary.

### File-by-File Inspection Log

### userspace-dp/src/afxdp/tests.rs

Inspected all 14,038 lines and traced clusters to `afxdp/mod.rs`, forwarding-state construction, queue planning, worker transactions, UMEM/socket setup, maps, metrics, protocol bindings, and shutdown behavior. The file is a parent integration surface rather than a single production owner. Its 204 leaves include a 19-leaf `txn_*` cluster whose ordering, rollback, and publication checks form one behavioral gate; splitting that cluster by helper or operation would weaken review locality. Broad imports and shared packet/socket fixtures make arbitrary Rust submodules capable of changing visibility and exact test identities even when assertions remain unchanged.

Negative result: no new generic “large AF_XDP tests should be split” finding. Prior report `codex-review-171` finding 29 and `fable-review-173` A1-F4 already map this file and require the transaction cluster to stay intact. The materially new issue is the repository-level exact, two-profile discovery gate in `S4LTB1-GATE-01`.

Hot-path audit: this is test-only code. A physical same-module extraction does not touch production inlining, monomorphization or const generics, heap allocation, trait-object dispatch, byte-order conversion, packet/UMEM ownership, batching, branch layout, instruction-cache footprint, atomics, false sharing, or ABI/layout. Any proposal that changes production APIs to make the test split easier is out of bounds.

### userspace-dp/src/afxdp/forwarding_build/tests.rs

Inspected all 5,075 lines and traced the 106 leaves through the forwarding-build owner. The test clusters cover interface resolution, route/next-hop construction, zones and policies, NAT, class of service, IPsec/WireGuard binding, shared UMEM, generation behavior, counters, and malformed configuration. Their common builders deliberately exercise cross-feature publication into one forwarding state, so the largest blocks are behavioral matrices rather than accidental production ownership.

Negative result: directory extraction by domain could preserve qualified names with same-module `include!` fragments, but that is the generic giant-test cleanup already recorded by prior audits. No distinct production-owner seam or new rollback guardrail was found. Keep cross-feature build and generation checks together, especially cases that assert fail-closed rejection before state publication.

Hot-path audit: test rearrangement must leave production generic specialization, allocations, endianness, packet/UMEM ownership, batch shape, dispatch, branch layout, atomics, cache lines, and ABI untouched. There is no evidence supporting a performance-changing class C refactor.

### userspace-dp/src/afxdp/wg/tests.rs

Inspected all 3,909 lines and traced 76 leaves to the WireGuard dataplane owner. Existing logical ownership is already visible: 34 root leaves, 16 under `framed_handshake`, 10 under `telemetry_counters`, 14 under `s5_timer_tests`, and two under `tai64n_replay_tests`. These groups cover peer lookup and routing, encrypted framing, replay windows, timers, telemetry, and handshake state.

Negative result: moving the four nested modules to files is mechanically credible, but the generic WireGuard test split is already recorded by `fable-review-173` A5. It is not a new issue. If done under that tracker, preserve every existing module identifier so the 76 fully qualified leaf names remain byte-for-byte identical.

Hot-path audit: the tests characterize crypto framing, nonce/endianness handling, packet buffer ownership, per-peer state, atomics/counters, and timer branches. A test-only move must not introduce boxed trait dispatch, allocation, copies, changed atomic ordering, altered layout, or production helper exports.

### pkg/dataplane/retirement_boundary_canary_test.go

Inspected all 3,356 lines, 26 top-level tests, 82 discovered nodes, and 78 terminal leaves. The suite intentionally crosses retired eBPF symbols, active userspace ownership, configuration, generated artifacts, documentation, packaging, build tags, and repository-shape boundaries. Those cross-cutting scans are the product: they prevent a removed backend from leaking back through another surface.

Negative result, class D boundary: do not split by package artifact or scan type. Prior `fable-review-173` A7-F-A7-11 D already records the canary as deliberately broad. File movement would disperse the one retirement acceptance gate and make omissions easier. No nested parallelism, lock ownership, reconcile path, or transactional publication is involved; filesystem scans and parsers dominate.

### userspace-dp/src/afxdp/flow_cache_tests.rs

Inspected all 2,836 lines and traced 64 source test attributes to `FlowCache` insertion, lookup, replacement, generation mismatch, timeout/expiry, collision, tombstone, and accounting semantics. These cases share one data structure’s hash/table invariants and should remain reviewable as one matrix. The discovery distinction is material: debug compiles 59 leaves while release compiles 60, with four debug-only expected-panic tests and five release-only mismatch tests.

Negative result: no owner split is warranted. Separating collision, generation, and expiry tests would hide interactions in the same table mutation path. The only retained action is to make both compiled leaf sets explicit before any larger test reorganization.

Hot-path audit: the test file protects a production lookup/update hot path, but rearranging tests must not alter hashing, allocation, table layout, inlining, branch predictability, cache-line behavior, or atomics. No performance-positive refactor is supported without benchmarks.

### userspace-dp/src/protocol/tests.rs

Inspected all 2,393 lines and traced 65 leaves across framing, message parsing, status and snapshot projection, schema compatibility, limits, and byte-level wire round trips. The owner is the parent protocol contract; cross-type round trips intentionally couple request/response types and reject drift at their serialization boundary.

Negative result, class D boundary: keep wire-format and schema parity assertions at the protocol parent. Splitting solely by message struct would obscure API/daemon consistency and duplicate framing fixtures. Existing prior-art reports already identify protocol/wire as the single source of truth. The exact `protocol::tests::syn_cookie_counters_binding_status_wire_roundtrip` identity is also named in a PR plan, so module nesting is externally observable.

Hot-path audit: no runtime code change is proposed. Preserve stack/heap behavior, byte-order locality, monomorphized codecs, framing branches, ABI/wire layout, and absence of new trait-object dispatch.

### userspace-dp/src/main_tests.rs

Inspected all 2,350 lines and traced 46 leaves. Ownership clusters are planner/hash/helpers at lines 19-1004 and 1253-1502, session synchronization at 1005-1252, protocol binding/projection at 1526-1729 and 2119-2350, and snapshot/dispatcher behavior at 1733-2118. Meanwhile `main.rs:55-65` is now a lifecycle shell plus a path-mounted test module, and `server/tests.rs:1-8` says canonical handler coverage lives at the real `handle_stream` call site.

Retained result: `S4LTB1-OWNER-02`. The issue is not file size; it is stale ownership after server/protocol extraction. Physical fragments loaded into the same root `tests` module can restore owner navigation while retaining all 46 qualified identities and broad crate-private access.

Hot-path audit: test-only movement must preserve production queue-planner hashing, allocation, packet/UMEM ownership, batching, generic/inlining behavior, branch layout, atomics, false sharing, ABI, and protocol endianness exactly. Do not export production helpers merely to accommodate test modules.

### pkg/cluster/cluster_test.go

Inspected all 2,249 lines and all 72 tests. The file has no subtests, skips, or `t.Parallel` calls, so every top-level test is also a terminal leaf. Tests map to production owners now separated across `manager.go`, `group_state.go`, `election.go`, `failover.go`, `status.go`, and `heartbeat_manager.go`. The local `makeConfig` and `makeRG` helpers at lines 14 and 21 are also used by seven other cluster test files, making their accidental residence in `cluster_test.go` a concrete move-order constraint.

Retained result: `S4LTB1-OWNER-03`. A Go `*_test.go` owner split preserves all 72 package-level names without adding subtest nesting. Extract shared fixtures first, then move complete tests by the production API they exercise.

Concurrency audit: manager-owned locks, goroutines, heartbeat timing, failover publication, and election/reconcile ordering remain production concerns and are not changed. The gate includes `-race` and shuffled execution so file-level initialization or order coupling cannot be introduced.

### pkg/config/parser_class_of_service_test.go

Inspected all 2,097 lines, 46 top-level tests, 51 discovered nodes, and 49 terminal leaves. The matrix follows one class-of-service parser/compiler contract through schedulers, classifiers, rewrite rules, references, defaults, duplicate handling, range validation, warnings, strict rejection, and tolerant/lenient paths.

Negative result: no credible owner boundary exists that improves schema/compiler parity. Splitting parser syntax from semantic resolution would make strict-versus-tolerant drift harder to review and duplicate shared fixtures. The production concern is fail-closed publication of invalid config; this candidate already keeps the acceptance matrix together. No goroutine, lock, runtime hot path, API/CLI/gRPC divergence, or transaction rollback seam was found.

### pkg/configstore/store_test.go

Inspected all 2,005 lines, 54 top-level tests, 56 discovered nodes, and 55 terminal leaves. The suite covers load/save, candidate generations, validation, commit/confirm timers, rollback, concurrent access, persistence failures, and subscriptions. Its fixture is consumed across 25 configstore test files, and the commit-confirm generation/timer/rollback cases jointly characterize one fail-closed transaction.

Negative result: `fable-review-173` A10-F-12 and the dedup index already identify `store_test.go` as a catch-all. No narrower independent boundary was found that is not part of that work. Any eventual extraction must first move shared fixtures to a neutral test-helper owner and keep commit-confirm timer, generation publication, rollback, and restart recovery gates together.

Concurrency audit: preserve mutex ownership, timer cancellation, subscriber ordering, disk-before-publication semantics, rollback, and allocation/escape behavior. A file split alone must not widen interfaces or alter the transactional API.

### userspace-dp/src/server/tests.rs

Inspected all 1,953 lines and traced 55 leaves through the canonical server dispatcher. The suite drives framed and malformed requests through real `handle_stream` calls, checks maximum sizes and EOF/error boundaries, and validates request routing plus state-file effects. The header at lines 1-8 explicitly distinguishes this owner from legacy `main_tests.rs` coverage.

Negative result, class D boundary: keep dispatcher framing, protocol errors, and request routing at the parent server call site. Per-verb production handlers already have their own owners; fragmenting this integration suite by verb would weaken the shared framing and error boundary. There is no evidence for a separate performance refactor.

Hot-path audit: tests use threads and local streams, but no production change is proposed. Preserve allocation limits, framing copies, dispatch shape, lock ownership, atomics, protocol byte order, monomorphization, ABI, and branch behavior.

## Final Audit Statement

This report is complete for immutable base `23eb4506864c0d7749157331ba279cbde7b7d5a7`. It contains 47 canonical issue records, the negative D-class boundaries, the full disposition ledgers, and the full 302-path inspection log. No source change was made and no implementation is represented as validated by this audit.
