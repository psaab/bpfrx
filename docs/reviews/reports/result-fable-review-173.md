# Triage result — fable-review-173

**Title:** xpf Refactor / Monolith Coverage Audit — fable campaign 173
**Review base:** `e87d57e2d55784482c8285112d5cd941fc5a2df5`
**Freshness:** **FRESH** — base is a direct ancestor of `origin/master`, only **5 commits behind**
(those 5 = #2852 lock-free SNAT Phase 1, #4647 DHCP-cluster BUG A/B, 2 merges — none touch the
audited hot files). Line numbers + LOC metrics in the review match origin/master **exactly**.
**Triaged against:** `origin/master` = `f70146951583823a5ace87b0b11a2e58f46e8db9`
**Repo:** real bpfrx (`/home/ps/git/bpfrx`), verified against `git show origin/master:` — NOT avacado.

> **IMPORTANT lineage note:** the local working tree (HEAD `0160fbfb9`, "Merge #2739") is a
> STALE ancestor of origin/master — it predates the entire #4404–#4649 refactoring campaign.
> Reading files from the working checkout returns the OLD tree (e.g. poll_descriptor 3,866 LOC
> instead of 6,042). All dispositions below were re-verified with `git show origin/master:<path>`,
> where every cited symbol and line number matched the review.

## Nature of this review

This is a **refactoring / monolith-coverage audit**, not a bug hunt. ~110 of the 115 blocks are
god-function / oversized-file **decomposition proposals** with split plans, hot-path preservation
pins, and D-class ("do-not-split") negatives. The "57 High confidence" count means "high
confidence this is a monolith worth splitting," NOT "high-severity defect." Every block carries an
explicit dedup tag against tracked refactor issues **#4404–#4422** and prior campaigns
(codex-171/173, agy-171, opus-171, fable-168). The headline metrics I spot-checked are all
**accurate** against origin/master:

- `poll_descriptor/mod.rs` = **6,042 LOC**, `poll_binding_process_descriptor` starts line 603 ✓
- `forwarding/mod.rs` = **2,822 LOC** ✓
- `compiler_uniformgates.go` = **1,659 LOC**, one `runUniformGates` fn (line 27) ✓
- `daemon_run.go` = **2,329 LOC**, `Run` at line 175 ✓
- `compileZones` exists (`compiler_iface.go:249`), `compileExpanded` now a small orchestrator (1986) ✓

Status-corrections in the review are accurate where spot-checked (A2-F8 tcp_segmentation dead
branch removed; A4-F3 `policy_snapshot_error.rs` extraction landed).

## Outcome counts

- **GENUINE-RESIDUAL (material, actionable code-quality):** 6
  - 2 NEW (dead code, display-drift); 3 STATUS-UPDATE of cataloged perf; 1 lock-scope hygiene
- **GENUINE-but-LOW (tracked refactor proposals — monolith exists, metric verified, already on
  the #4404–#4422 backlog / prior campaigns):** ~100 blocks (the bulk of the review)
- **DELIBERATE / D-NEGATIVE (do-not-split, re-verified):** ~15 blocks
- **ALREADY-FIXED status-corrections (accurate, no action):** several (A2-F8, A4-F3, A4-F6,
  F-A7-4 partial #4477, etc.)
- **CONFABULATED:** 0 — every cited symbol exists on origin/master
- **NOT-MATERIAL (misclassified as a bug):** 0 material misreads found; the review is honest,
  it self-labels the perf items STATUS-UPDATE and the splits as reviewability, not defects.

No security or forwarding-correctness bug. No confabulation.

---

## Material GENUINE-RESIDUALs (the only blocks with substance beyond "split this file")

### A2-F2 — Dead `IcmpTeRateLimiter` in `forwarding/mod.rs` — GENUINE-RESIDUAL, LOW, lane=rust
- **Verified:** `forwarding/mod.rs:1241-1274` on origin/master carries `const ICMP_TE_MAX_PER_SEC`,
  `struct IcmpTeRateLimiter`, and its `impl` (new/allow), all `#[allow(dead_code)]`. Tree-wide
  `git grep IcmpTeRateLimiter` over origin/master returns **only the declaration** — zero callers.
  The live TE rate-limiting is the GCRA bucket in `icmp_ratelimit.rs` (exists, 11 fns).
- **Failure scenario:** none functional — it's stale pre-GCRA code. Cost is reviewer confusion (a
  second, divergent TE limiter appears to exist) + dead surface on a REFACTOR-tier hot file.
- **Fix:** delete the 34 lines. Mechanical.
- **Severity = LOW (not higher):** no reachable path, no layout/ABI, no security. Purely cosmetic
  cleanup. NEW (uncataloged dead code).

### A9-F3 — Session egress-interface drift REST vs gRPC — GENUINE-RESIDUAL, LOW, lane=go
- **Verified on origin/master:** REST `sessionEntryV4` (`pkg/api/sessions.go:1061`) resolves egress
  via `resolveSessionEgressIface(...)`, whose body (1047-1054) guards `if fibIfindex != 0 { ...
  egressIfaces[...] }` else falls back to `zoneIfaces[egressZone]`. gRPC `sessionEntryV4`
  (`pkg/grpcapi/server_sessions.go:1191`) and `sessionEntryV6` (1247) instead **inline**
  `egressIfaces[sessionEgressKey{ifindex: val.FibIfindex, vlanID: val.FibVlanID}]`
  **unconditionally** (no `fibIfindex != 0` guard) before falling back. gRPC is even internally
  inconsistent: its filter path (480/525) DOES call the guarded helper `resolveSessionEgressIface`
  (defined at 1309 with the same guard) — only the entry-projection sites (1191/1247) diverge.
- **Failure scenario:** a session with `FibIfindex == 0` AND a stale `egressIfaces[{0, vlan}]` map
  entry → gRPC (CLI) names that stale interface; REST skips it and shows `zoneIfaces[egressZone]`.
  The two surfaces print **different egress interface names** for the same session.
- **Fix:** route gRPC `sessionEntryV4/V6` through the guarded helper (or extract the cataloged
  `pkg/sessionview` and share one `ResolveEgressIface`). Add a cross-surface parity test.
- **Severity = LOW (review says Medium):** this is **display-only** — the egress interface *label*
  in a `show sessions` listing, in a narrow corner case (FibIfindex==0 with a stale {0,vlan}
  entry). It is NOT a forwarding decision, NOT policy enforcement, NOT NAT data disclosure. Real
  and confirmed drift (the review's #2935 precedent shows the seam bites), but blast radius is a
  possibly-wrong interface name to an operator, so LOW not Medium. Dedup INCREMENT(codex-171-25).

### A2-F1 — `DEFAULT_V4_TABLE.to_string()` per-resolution heap alloc — GENUINE, STATUS-UPDATE, LOW, lane=rust
- **Verified:** `forwarding/mod.rs:1460` (`unwrap_or_else(|| DEFAULT_V4_TABLE.to_string())`) and
  1544 (V6). `canonical_route_table` (line 48) returns owned `String` in all arms. One `String`
  alloc+free per FIB resolution.
- **Failure scenario:** allocator pressure on the **new-flow / session-miss** path under connection
  churn (SYN flood, short-lived HTTP). Established flows hit `flow_cache_hit.rs` and never reach it.
- **Fix:** `canonical_route_table -> Cow<'a,str>`; `Cow::Borrowed(DEFAULT_V4_TABLE)` on default arm.
- **Severity = LOW:** review itself STATUS-UPDATEs a cataloged perf note (dedup §2) and corrects
  hotness from "per-packet" to "per-resolution." Not line-rate; a bounded per-new-flow alloc.

### A4-F5 — `metadata.clone()` Arc refcount churn in `session/lookup.rs` — GENUINE, STATUS-UPDATE, LOW-MED, lane=rust
- **Verified:** `session/lookup.rs:183, 240, 281, 321` all do `entry.metadata.clone()`.
  `SessionMetadata` (`session/entry.rs:24`) carries `Option<Arc<...>>` (policy_counter etc.), so
  each clone is atomic `LOCK XADD` refcount bumps on the lookup read path.
- **Failure scenario:** atomic churn on every packet that misses the flow-cache and re-runs lookup.
- **Fix:** return `Copy` handle/indices from the lookup family; resolve owned metadata only at the
  ≤1 site that needs it (carry with the #4421 session split).
- **Severity = LOW-MED:** real hot-path atomics, but bounded to the lookup (post-flow-cache) path,
  not the 90%+ established fast path. Known cataloged item, STATUS-UPDATE confirming it's live.

### A4-F8 — NAT allocator GC runs under the shared alloc `Mutex` — GENUINE, STATUS-UPDATE(#4409), LOW-MED latent, lane=rust
- **Verified:** `nat/allocator.rs` `allocate_translation` (686) takes `self.shared.live.lock()`
  (736) then immediately `gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET)` (737); more
  budgeted GC at 805/847. GC on the alloc critical section. (Persists even after the #2852 Phase-1
  lock-free commit that landed in these 5 base..master commits.)
- **Failure scenario:** latent lock-contention — GC sweep (budgeted, ≤8 entries) holds the port-map
  lock other SNAT allocators contend on. Softened by the budget, not eliminated.
- **Fix:** move GC to a separate cadence off the alloc lock (behavior change — file separately, do
  NOT ride it in a code-motion split, per the review's own scope discipline).
- **Severity = LOW-MED:** latent contention, bounded by `ALLOCATION_GC_BUDGET`. Known (#4409).

### A10-F-1 — `routing/tunnel.go` `t.mu` held across full netlink+exec reconcile — GENUINE-but-LOW, lock-scope hygiene, lane=go
- **Verified:** `tunnel.go:277 Apply` does `t.mu.Lock(); defer t.mu.Unlock()` (278-279) and the
  entire reconcile (`applyAnchorLocked`, `reconcileAnchorMTULocked`, `applyKernelTunnelLocked`,
  `reconcileLinkAddrsLocked`, WG apply — all `*Locked`, all doing netlink/exec) runs under it.
- **Severity = LOW:** `Apply` is a config-apply path (not per-packet); holding the lock across the
  whole reconcile is arguably *correct* for consistency. Lock-scope-narrowing is a hygiene
  suggestion, not a demonstrated deadlock/contention bug. No failure scenario proven.

---

## The bulk: GENUINE-but-LOW refactor proposals (tracked, verified-accurate, no defect)

Every god-function / oversized-file finding below is a real monolith (metric verified accurate on
origin/master) and a legitimate decomposition proposal, but LOW-severity code hygiene already on
the #4404–#4422 backlog or prior campaigns. None is a bug. Grouped disposition:
**GENUINE-monolith / LOW / tracked-refactor.** Representative set (not exhaustive — ~100 blocks):

- Rust: A1-F1 `poll_binding_process_descriptor` 4,724 LOC (STATUS-UPDATE #4404 — 3.4× the cataloged
  1,368; verified file=6,042 LOC, fn@603); A1-F3 `worker_loop` ~1,300 LOC (Medium, class-C cold
  fusion); A1-F4 `afxdp/tests.rs` 13,598 test-split; A2-F3 forwarding facade seam; A2-F4/F5/F6
  builder/neighbor god-fns; A3-F1/F2/F3/F5/F6 CoS/TX (`acquire_v8_with_cause` 277 LOC, queue_service
  crossed 2,000); A4-F1/F2/F7/F12/F14/F15 policy/nat/session decomposition; A5-F1/F2 event codec /
  status projection.
- Go: A6-F1 `runUniformGates` 1,659 (order-pinned → safe table-drive); A6-F2 `ValidateConfig`
  1,534; A6-F4 `compileProtocols` 783; A6-F6 five compile-dispatch god-fns; A7-F-A7-1 `compileZones`
  931; A7-F-A7-2 `applyHelperStatusLocked` 483; A7-F-A7-9 `FormatStatusSummary` 610; A8-F1
  `daemon_run.Run` 1,692; A8-F3 `vrrp/instance.go` 2,417; A8-F5 `startClusterComms` 466; A9-F1
  `newCollector` 1,886; A9-F4/F5/F6/F7 cross-surface render dedup; A10-F-2..F-7 upgrade/frr/
  dhcprelay/ipsec/logging/snmp god-fns.

**Heatmap-distortion meta-finding (A1-F6 + exec-summary #2):** legitimate and useful — the audit
script counts inline `#[cfg(test)] mod tests` and misses the `nat/tests_*.rs` naming, so
`poll_stages.rs` (972 prod not 3,527), `reject_reply.rs` (414 not 2,174), `nat/tests_pool.rs`,
`nat/tests_destination.rs` are test-inflated in the committed REFACTOR tier. This correctly
downgrades several cataloged splits to D. GENUINE tooling-accuracy improvement, LOW.

## DELIBERATE / D-NEGATIVE (re-verified do-not-split; no action) — accurate

A1-F5 `reject_reply.rs` prod cohesive; A2-F9 D-confirmations; A3-F4 `cold_path_hist.rs` seqlock
structs; A4-F3 `SnapshotIntegrityError` flat enum (keep); A5-F3..F8 (`binding.rs`, `xsk_ffi.rs`,
`state_writer.rs`, `userspace-xdp/lib.rs` verifier-constrained, coordinator); A7-F-A7-11
`retirement_boundary_canary_test.go` deliberate gate; A9-F11 `cmdtree/tree.go` declarative table.
One partial-stale correction: A4-F10 `screen/mod.rs` — `check_packet_with_zone_id_opts` grew to
~330 LOC inline god-fn (the prior D is now partially stale). All consistent with
`docs/refactoring-audit.md`.

## Status-corrections (accurate, no action)

A2-F8 tcp_segmentation dead-branch removed (#4384 — verified, always-recompute now); A4-F6 nat64
ext-hdr walker divergence FIXED; A4-F3 / #4421 SnapshotIntegrityError extraction landed
(`policy_snapshot_error.rs` exists); F-A7-4 dead-counter indices PARTIALLY fixed (#4477, 2 of 4);
A6-F3 `compileExpanded` now a 124-LOC orchestrator. All spot-checks matched.
