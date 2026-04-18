# #678 hot-path cuts — architect plan

Status: plan. Implementation lands in a follow-up PR against the slice
defined in [§4](#4-narrow-write-scope-for-the-implementor). Docs-only
change.

## 1. Problem restatement

Issue #678 (2026-04-15 snapshot, post-#728) reported 23.02 Gbps IPv4 /
22.77 Gbps IPv6 on the `loss` userspace cluster with three remaining
hotspots per family:

- IPv4: `poll_binding` 13.4%, `enqueue_pending_forwards` 4.3%,
  `mlx5e_xsk_skb_from_cqe_linear` 4.6%.
- IPv6: `poll_binding` 13.3%, `enqueue_pending_forwards` 3.7%,
  `apply_nat_ipv6` 3.2%.

Remeasurement today (2026-04-17, master `7c1e55b9`, same
`./scripts/userspace-perf-compare.sh --duration 8 --parallel 12`
invocation, same cluster) shows the profile has shifted. Measurement
output was CoS-shaped to ~500 Mbps aggregate (not a valid throughput
data point — the cluster lab is currently running a restrictive CoS
config from the post-#728 / #742 validation runs and was not reset for
an unshaped measurement in the architect's window). Symbol-share
numbers are still comparable because per-packet work scales with pps,
not aggregate Gbps:

| Symbol | Issue #678 IPv4 / IPv6 | 2026-04-17 IPv4 / IPv6 |
|---|---|---|
| `poll_binding` | 13.4% / 13.3% | **10.4% / 10.6%** |
| `enqueue_pending_forwards` | 4.3% / 3.7% | **0.71% / below 1%** |
| `apply_nat_ipv6` | — / 3.2% | **below 1% (not in top 160)** |
| `mlx5e_xsk_skb_from_cqe_linear` | 4.6% / — | submerged in `bpf_prog` chain |
| `drain_pending_tx` | — | 3.25% / 2.90% |

`enqueue_pending_forwards` and `apply_nat_ipv6` have been largely
absorbed by the in-place fast path (#728 companion work) and the
ECN-gated single-address checksum specialization. Only `poll_binding`
remains a legitimate outlier above 10%.

## 2. Candidate slices at a glance

| Opt | Slice | Size | Risk | Predicted uplift | Interaction with failed ideas |
|-----|-------|------|------|------------------|-------------------------------|
| A | Split `poll_binding` into orchestration shell + per-descriptor hot path | ~300–500 LOC refactor, 1 file (`afxdp.rs`) | Med | Measurement-first: expect 2–4 pp symbol-share reduction on the hot inner loop; throughput uplift uncertain, likely <+500 Mbps | Does NOT re-introduce adaptive idle-skip (#678 failed idea). Pure structural split. |
| B | Shrink `enqueue_pending_forwards` cross-binding / fallback prologue | ~100–200 LOC, `frame_tx.rs` | Low | Negligible on current profile (0.71% → ~0.5%) | Does NOT touch `authoritative_forward_ports()` shortcut (failed) |
| C | Session-hit / flow-cache-hit temp-object removal (`BindingIdentity` clone, `resolution_target_for_session`, `build_live_forward_request_from_frame` wrapper) | ~150–250 LOC, `afxdp.rs` | Med | ~1–2 pp off `poll_binding` symbol-share | Does NOT re-propose direct-index `apply_nat_ipv6` rewrite (failed) |
| D | IPv6 NAT further optimization (live-validated only) | ~50–150 LOC, `frame.rs` | Low-Med | Near-zero on current profile (`apply_nat_ipv6` already below 1%). Architect flags this as potentially subsumed. | CANNOT use direct-index `apply_nat_ipv6` rewrite (failed) |
| E | `drain_pending_tx` / `apply_shared_recycles` microbatching | ~200 LOC, `tx.rs` + `frame_tx.rs` | Med | 1–2 pp if combined; overlaps #709 owner-drain work | — |
| F | **Close #678 as subsumed** — declare all three 2026-04-15 hotspots have fallen below the "worth-fixing" threshold | Docs only | None | N/A | — |

Notes on size/risk:

- Option A is structural-only. It moves code, it does not add or remove
  semantic branches. Risk is mostly in getting the `&mut binding` /
  scratch-vector borrow discipline right when the inner loop becomes a
  separate function (or a tightly scoped closure/block).
- Option B is small because the issue's `enqueue_pending_forwards`
  prologue is already narrow after #728. The cross-binding/fallback
  arms are the "generic" path; most traffic hits `pending_tx_prepared`
  direct or in-place now.
- Option D is listed for completeness; the remeasurement shows
  `apply_nat_ipv6` is no longer a meaningful hotspot. Any IPv6 NAT
  work needs fresh live data justifying the change or it risks the
  same rollback track record the issue cites.
- Option F is the "honest framing" outcome per `engineering-style.md`:
  two of three hotspots in #678's original framing are no longer real.
  The plan should be explicit that this is on the table.

## 3. Recommendation

**Option A, scoped as a measurement-first structural split.** Extract
the per-descriptor inner loop of `poll_binding` into a dedicated
function so the outer orchestration shell becomes small enough to
profile separately. Close #678 once the split lands and validates
against the post-#728 baseline, with Options B/C/D deferred as
individual tracking issues unless telemetry points at them.

Why A over the others:

- `poll_binding` is still the only symbol above 10% in the remeasured
  profile. B/C/D attack symbols that are now below 1% and offer
  vanishing uplift at real risk (the issue cites four previous
  false-positive "optimizations" rolled back).
- The split is the specific plan-level hint the issue body calls out.
  The split is structural, not algorithmic — it does not change
  behaviour, it changes what the profiler attributes the work to.
  After the split, `poll_binding_shell` and
  `poll_binding_process_descriptor` will each attribute their own
  share and we get actionable follow-up data (is the per-descriptor
  work genuinely dominant, or is the orchestration overhead
  surprisingly large?). **That telemetry is the primary deliverable**;
  any throughput uplift is a bonus.
- Option F is tempting but premature — `poll_binding` at 10.4%/10.6%
  is still a meaningful target. Splitting is cheap and buys the data
  to decide whether F is correct for a future close.

Expected metric movement (predictions to falsify):

- Throughput: no confident prediction. Rust inliner already inlines
  most of the inner block. Expect ±200 Mbps. If the split **regresses**
  by more than 200 Mbps per family, revert.
- Symbol share: `poll_binding` (shell) drops to 4–6%;
  `poll_binding_process_descriptor` appears at 4–7%. Sum should be
  within 1 pp of the pre-split 10.4%/10.6%.
- Branch predictor / I-cache: unmeasured; opinion is that a smaller
  shell with 5–6 early-return gates is branch-predictor-friendlier
  than the current 2650-line monolith, but this is not load-bearing
  for the recommendation.

What A does NOT fix:

- Does not reduce work per descriptor. The body is the same Rust; the
  inliner sees through a non-`#[inline(never)]` function boundary. If
  we end up wanting per-descriptor work reduction, C is the
  next-natural follow-up.
- Does not address the IPv4 `mlx5e_xsk_skb_from_cqe_linear` 4.6%
  (driver-side, RX path CSUM/copy). That's a driver + zerocopy
  negotiation issue, separate from userspace code.
- Does not interact with the CoS admission-path telemetry or
  counters added by #728/#731/#742. The split preserves every call
  site verbatim. No new `now_ns` reads, no new syscalls, no change
  to `apply_cos_admission_ecn_policy`, no change to
  `admission_*_drops` / `ecn_marked` / `drain_latency_hist` /
  `owner_profile` contracts. ECN path stays intact.

## 4. Narrow write scope for the implementor

Exact files.

1. `userspace-dp/src/afxdp.rs` — split `poll_binding` (currently lines
   248–2895) into two cooperating functions:
   - **`poll_binding` (shell, the orchestration part)** keeps the
     signature and return type. Retains:
     - Pre-loop work (lines ~367–395): `split_at_mut`,
       `maybe_touch_heartbeat`, first `drain_pending_tx`,
       `apply_shared_recycles`, first `drain_pending_fill`.
     - The outer `for _ in 0..MAX_RX_BATCHES_PER_POLL` loop (~line
       396).
     - The TX-backlog early-return gate (~lines 397–428).
     - The RX-available/empty gate (~lines 430–467, including
       `maybe_wake_rx` + `retry_pending_neigh` on empty path).
     - The identity cache (~lines 469–474).
     - `binding.rx.receive(available)` + the
       `while let Some(desc) = received.read()` loop body moves OUT
       (see next).
     - Post-inner-loop work (~lines 2797–2879): `received.release()`,
       `scratch_forwards` / `scratch_rst_teardowns` handling,
       `enqueue_pending_forwards` invocation, `reap_tx_completions`
       + cross-binding reap, `apply_shared_recycles`,
       `drain_pending_fill`, `rx_batches` counter bump.
     - The post-loop `retry_pending_neigh` + `counters.flush` +
       `update_binding_debug_state` + return.
   - **`poll_binding_process_descriptor`** (new, `fn` or
     `#[inline(always)] fn` — let the inliner decide; do NOT use
     `#[inline(never)]`, which would pessimize the hot path). Receives:
     - `desc: XdpDesc` by value.
     - `binding: &mut BindingWorker` mutable borrow (singleton).
     - `left: &mut [BindingWorker], right: &mut [BindingWorker]`
       passthrough for `apply_shared_recycles` / cross-binding helpers
       called from inside the body (e.g. `teardown_tcp_rst_flow`
       callees that already take them — note: those live OUTSIDE the
       per-descriptor loop today in the `rst_teardowns` drain; they
       stay in the shell).
     - `binding_lookup`, `sessions`, `screen`, `validation`, `now_ns`,
       `now_secs`, `ha_startup_grace_until_secs`, `forwarding`,
       `ha_state`, `dynamic_neighbors`, `shared_sessions`,
       `shared_nat_sessions`, `shared_forward_wire_sessions`,
       `shared_owner_rg_indexes`, `slow_path`,
       `local_tunnel_deliveries`, `recent_exceptions`,
       `last_resolution`, `peer_worker_commands`, `worker_id`,
       `worker_commands_by_id`, `dnat_fds`, `conntrack_v4_fd`,
       `conntrack_v6_fd`, `dbg`, `rg_epochs`,
       `cos_owner_worker_by_queue`, `cos_owner_live_by_queue`.
     - `ident: &BindingIdentity` by reference (computed once in the
       shell before the descriptor loop).
     - `area: *const MmapArea` by value (constant within a poll
       iteration; computed once in the shell).
     - `counters: &mut BatchCounters` — caller owns, inner function
       bumps.
     - Returns `()`. The function mutates `binding.scratch_recycle`,
       `binding.scratch_forwards`, `binding.scratch_rst_teardowns`,
       `binding.flow_cache`, `binding.pending_tx_prepared`, and the
       counters. No allocations; no `Arc::clone`; no syscalls.
   - **`BatchCounters` stays in place** as a nested type on
     `poll_binding` or gets lifted to a module-level type — keep
     whichever has the shortest diff. The `flush` method keeps the
     current shape.

2. **Extraction rules.** The inner loop body (~lines 480–2796) is
   currently ~2316 lines. The split must be mechanical — do NOT
   refactor within the body in the same PR. Specifically:
   - Every `continue` in the inner loop becomes `return;` in the new
     function. Every `break` becomes early-return with a distinguishing
     sentinel if the shell needs to know (today there is no `break` in
     the inner `while let` loop body).
   - The `recycle_now` boolean and its final `if recycle_now
     { binding.scratch_recycle.push(desc.addr); }` check move inside
     the new function verbatim.
   - The `meta` / `flow` / `ident` / `debug` / `decision` /
     `session_ingress_zone` / `flow_cache_owner_rg_id` /
     `apply_nat_on_fabric` / `owned_packet_frame` locals all move
     inside the new function. They are already per-descriptor today.
   - The `packet_fabric_ingress` calculation and the
     `FABRIC_INGRESS_FLAG` meta mutation move inside the new function.
   - The `MAX_RX_BATCHES_PER_POLL` loop stays in the shell. The
     counter `binding.dbg_poll_cycles += 1` stays in the shell.

3. **Closure vs function.** Prefer a free `fn` over a closure:
   - Rust inliner treats both identically when the call is the only
     one in the crate and `#[inline]` is absent, so no perf
     difference.
   - A free `fn` surfaces on `perf top` under its own symbol, which is
     the whole point of the split.
   - A closure would capture the shell's environment implicitly and
     make borrow-checker debugging harder during the refactor.

4. **Prerequisites for the refactor.**
   - NO field reordering on `BindingWorker` or `BindingLiveState`.
     Struct layouts stay identical.
   - NO new `Arc<T>::clone()` calls added on the hot path. Pass by
     reference.
   - NO lifetime elision beyond what already works; the new function
     takes explicit `&'a` on borrowed state where needed.
   - NO change to `BatchCounters::flush` semantics; shell still calls
     `counters.flush(&binding.live)` on the empty-RX return path and
     on the TX-backpressure return path and after the outer loop ends.
   - NO change to `retry_pending_neigh` call sites (empty-RX early
     return and post-loop — both stay in the shell).

5. **Testing hooks during refactor.**
   - Re-run the existing `userspace-dp` `cargo test` suite.
   - Re-run the existing `#[cfg(test)]` tests in `afxdp/tests.rs` that
     exercise session-hit / flow-cache-hit / session-miss paths. None
     of those call `poll_binding` directly today, but any test that
     does must keep working against the shell function's preserved
     signature.

6. **Docs update (Architect-owned, in the implementor's PR).**
   - `docs/afxdp-module-split.md` or new `docs/afxdp-poll-binding-split.md`:
     two-paragraph note stating the split rationale, the new symbol
     names to expect in `perf top`, and the post-split symbol-share
     decision tree: if
     `poll_binding_process_descriptor` ≥ 8% → Option C (per-descriptor
     work reduction) is the next slice; if the shell ≥ 4% → investigate
     the descriptor-loop orchestration itself (batch reap, empty-RX
     fast return).
   - No change to `cos-validation-notes.md` — this slice does not
     touch CoS admission or telemetry.

## 5. Invariants the implementor must preserve

Non-negotiables for the implementor:

- **No allocations on the packet hot path.** No `Vec::push` that may
  grow (the scratch vectors are already pre-sized), no `Box::new`, no
  `HashMap::entry`. Every local currently in the inner loop stays a
  stack local.
- **No new syscalls.** No `clock_gettime`, no `sendto`, no `recvfrom`
  added by the refactor. `now_ns` and `now_secs` come from the shell,
  same as today.
- **No `Arc::clone` added on the hot path.** Passing `ingress_live`
  via `*const BindingLiveState` (as `enqueue_pending_forwards` does
  today) stays unchanged. Do not "tidy" that to an
  `&Arc<BindingLiveState>` — the existing raw-pointer pattern is load-
  bearing for the 5% CPU saving cited in the source comment.
- **Existing counter contracts stay identical.** `admission_*_drops`,
  `admission_ecn_marked`, `buffer_drops`, `flow_share_drops`,
  `pacing_drops` (#742), `drain_latency_hist` (#731),
  `owner_profile` (#731), `rx_packets`, `rx_bytes`, `rx_batches`,
  `metadata_packets`, `validated_packets`, `forward_candidate_packets`,
  `session_hits/misses/creates`, `snat_packets`, `dnat_packets`,
  `screen_drops`, `slow_path_drops`, `flow_cache_*` all bump the same
  amount at the same points. Verify by diff: the inner function body
  is byte-for-byte the same Rust as today's inner-loop body.
- **No ABI / wire-format change.** No change to `PendingForwardRequest`,
  `PreparedTxRequest`, `TxRequest`, `FlowCacheEntry`, `SessionKey`,
  `SessionDecision`, `PacketResolution`, `UserspaceDpMeta`, gRPC
  `CoSInterfaceStatus`, Prometheus scrape shape.
- **Behaviour under the loss lab CoS config stays within post-#728
  jitter envelope.** Rate ratio ≤ 1.30× on queue 4 / 5201, retrans ≤
  150 k per 30 s, `admission_ecn_marked` stays active (> 50 k per
  30 s), no new drop source. Validate against
  `cos-validation-notes.md` § "How to read admission drop counters
  live". The ECN path is untouched; if CoS numbers shift, the
  refactor has bugs.
- **No reintroduction of any of the 4 failed ideas from issue #678.**
  - No `target-cpu=native` helper-build switch. Portable build only.
  - No adaptive idle-binding poll skipping. The
    `MAX_RX_BATCHES_PER_POLL` loop and empty-RX early return are
    preserved verbatim.
  - No `authoritative_forward_ports()` shortcut. The existing call
    sites in the flow-cache fast path stay as they are.
  - No direct-index `apply_nat_ipv6()` rewrite. The IPv6 NAT path is
    not touched at all by this PR.
- **Const-assert shape.** Add
  `const _: () = assert!(MAX_RX_BATCHES_PER_POLL >= 1)` at module
  level (cheap, catches future drift). Not strictly new — allowed
  because it pins an existing invariant that the refactor depends on.
- **Single-writer scratch vectors.** `scratch_recycle`,
  `scratch_forwards`, `scratch_rst_teardowns`, `scratch_post_recycles`
  remain owned by the binding and mutated only by the shell +
  per-descriptor function. No cross-worker access, no atomics.
- **`recycle_now` discipline preserved.** Every `continue` that
  intentionally skips recycle (because the frame was queued into
  `pending_tx_prepared` or `pending_neigh` or the ICMP TE path) still
  sets `recycle_now = false` before `continue`. The extracted function
  returns `()` in the same places and preserves the same final
  `if recycle_now { push(desc.addr); }` gate.

## 6. Acceptance criteria

Quantitative. Implementor must run
`./scripts/userspace-perf-compare.sh --duration 8 --parallel 12`
before the change (capturing a pre-PR baseline) and after (against
the same cluster state, ideally within the same hour), and report:

1. **Throughput delta.** IPv4 and IPv6 Gbps from `end.sum_sent.bits_per_second`
   and the script's "steady; peak=... tail=... ratio=..." sustain
   metric. Target:
   - **Zero regression floor:** net change ≥ −100 Mbps per family.
   - **Hoped-for uplift:** ≥ +200 Mbps per family is the "worth the
     refactor" line.
   - If net throughput regresses by more than 100 Mbps per family,
     revert the PR. The issue cites four previous false-positive
     rollbacks; adding a fifth is cheap if we catch it fast.
2. **Symbol-share check.** Post-PR `perf top` for the targeted
   symbol:
   - `poll_binding` (shell) symbol share should drop to **≤ 6%** per
     family.
   - `poll_binding_process_descriptor` (new) symbol share should
     appear at **4–8%** per family.
   - **Sum (shell + inner) should be within 1 pp of the pre-PR
     `poll_binding` share.** A large deviation means the inliner
     made a different choice across the split and the work moved
     somewhere unexpected; investigate before merging.
3. **CoS admission counter contract.** Run the 16-flow iperf3 on
   5201 per `cos-validation-notes.md`:
   - No new drop source on queue 4.
   - `admission_ecn_marked` stays active (> 50 k per 30 s baseline,
     ±50% tolerance).
   - `admission_flow_share_drops`, `admission_buffer_drops`,
     `admission_pacing_drops` within their post-#742 envelopes
     (±50% tolerance; this PR does not touch admission logic, so
     movement here is noise).
4. **`cargo test` is green.** Full userspace-dp test suite, not just
   `cargo test --lib`. Includes any Go binding tests that indirectly
   cover gRPC shape.
5. **Revert clause.** If any of (1) regresses, the PR is reverted in
   a follow-up commit, same-day. If (2) shows the sum drifted > 2 pp,
   the PR is held and investigated before merge. If (3) shows a new
   drop source or `ecn_marked` drops to zero, the PR is held and
   investigated — that would be a serious invariant break.

Mid-test read (same shape as existing methodology):

```bash
incus exec loss:cluster-userspace-host -- \
  iperf3 -c 172.16.80.200 -P 16 -t 30 -p 5201 -i 0 >/dev/null 2>&1 &
sleep 10
incus exec loss:xpf-userspace-fw0 -- \
  /usr/local/sbin/cli -c "show class-of-service interface"
wait
```

Note: the 2026-04-17 architect measurement ran with the lab in its
post-#742 CoS-shaped state (~500 Mbps per family). The implementor
should ensure the lab is at the intended steady-state CoS configuration
before capturing the pre/post runs, or explicitly call out that the
comparison is shape-to-shape with the same shaper configuration. Both
shape-to-shape and unshaped-to-unshaped comparisons are valid; mixed
comparisons are not.

## 7. Out-of-scope / deferred

Explicitly not in this slice. Each becomes a new tracking issue on
merge if follow-up telemetry points at it.

- **Option B — `enqueue_pending_forwards` prologue shrink.** Deferred
  because the remeasurement shows `enqueue_pending_forwards` is at
  0.71% IPv4. Follow-up issue title only if post-split telemetry
  still shows it above 2%: *"userspace-dp: shrink
  enqueue_pending_forwards cross-binding / fallback prologue"*.
- **Option C — session-hit / flow-cache-hit temporary-object
  removal.** Deferred pending the post-split symbol share of
  `poll_binding_process_descriptor`. Follow-up issue title:
  *"userspace-dp: eliminate per-descriptor temporary allocations on
  session-hit and flow-cache-hit paths"*.
- **Option D — IPv6 NAT further optimization.** Deferred as likely
  subsumed — `apply_nat_ipv6` is no longer in the top 160 perf
  symbols on 2026-04-17. Follow-up issue title if a future workload
  surfaces it again: *"userspace-dp: IPv6 NAT checksum-adjust
  optimization (live-validated)"*. Note: the failed direct-index
  rewrite is explicitly excluded from the scope of that future issue.
- **Option E — `drain_pending_tx` / `apply_shared_recycles`
  microbatching.** Overlaps #709 owner-drain telemetry work.
  Decision deferred to #709's Option B outcome. If #709 telemetry
  points at drain-side bottlenecks, E becomes part of that slice,
  not a standalone #678 follow-up.
- **Option F — close #678 as subsumed.** Filed as a decision-point
  after the A split lands and is validated. If the post-split
  `poll_binding` shell ≤ 3% AND
  `poll_binding_process_descriptor` ≤ 5%, close #678 with a pointer
  to the split PR and declare the three original hotspots
  individually subsumed. This is the expected path.
- **Driver-side `mlx5e_xsk_skb_from_cqe_linear` 4.6% (IPv4).**
  Not a userspace-dp issue — it lives in the mlx5 XSK RX path and
  is tied to zerocopy negotiation plus CSUM handling at the driver.
  Follow-up issue title if it persists: *"loss lab: investigate
  mlx5e_xsk_skb_from_cqe_linear RX share on IPv4 (driver-side)"*.
  Not actionable from Rust.
- **`target-cpu=native` helper build.** Explicitly deferred per
  issue #678 body — already disproved on the cluster. No follow-up
  issue; the existing issue #678 body is the authoritative reference.
- **Adaptive idle-binding poll skipping.** Explicitly deferred per
  issue #678 body. No follow-up issue.
- **`authoritative_forward_ports()` shortcut.** Explicitly deferred
  per issue #678 body. No follow-up issue.
- **Direct-index `apply_nat_ipv6()` rewrite.** Explicitly deferred
  per issue #678 body. No follow-up issue.

## Refs

- #678 userspace dataplane: cut remaining hot-path CPU (this plan)
- #708 enqueue-side pacing (companion plan, same structure)
- #709 owner-worker hotspot (companion plan, same structure)
- #728 ECN CE marking completed — the work that shifted
  `apply_nat_ipv6` and `enqueue_pending_forwards` below 1%
- #731 owner-profile telemetry — must not regress
- #742 per-SFQ-bucket pacing — must not regress
- `engineering-style.md` — narrow-scope, honest-framing, hot-path
  discipline principles driving the structural-split recommendation
  and the explicit "close as subsumed" Option F
- `cos-validation-notes.md` — validation methodology for the CoS
  admission counter contract in §5 and §6
