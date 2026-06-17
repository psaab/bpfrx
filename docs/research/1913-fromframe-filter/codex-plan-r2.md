Reading additional input from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed437-2234-7073-a457-043adbcfcce5
--------
user
HOSTILE PLAN REVIEW round 2. You PLAN-NEEDS-REVISION'd r1 of docs/research/1913-fromframe-filter/plan.md (issue #1913). The plan has been revised to r2 to fix your findings. Verify the corrections landed and check for any NEW defects.

Repo: /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter (branch research/1913-fromframe-filter @ d23d55022).
Plan: docs/research/1913-fromframe-filter/plan.md

Your r1 findings (confirm each is now correctly addressed in r2):
1. §2.1 table erratum: ForwardCandidate/FabricRedirect consumed at mod.rs:1794-1798, never reach :2814. (Check the r2 §2.1 table + the new lead-in paragraph.)
2. MissingNeighbor SNAT-failure early continues at :2533/:2564 omitted. (Check r2 table MissingNeighbor row.)
3. §2.6 over-broad proof: dispatch/mod.rs:238 desc branch uses the FILTERED wrapper => silently DROPS FabricRedirect (asymmetry, not clean intentional bypass); ALSO slow_path.rs:61 ForwardCandidate build-failure fallback relies on unfiltered _from_frame. (Check r2 §2.6 + Path B cons.)
4. Altitude: document _from_frame as raw/unchecked primitive. (Check Path A step 3 + §6.)

The recommendation is Path A: shared eligibility predicate, gate at mod.rs:2814 call site, wrapper refactored to call the same predicate, leave the two load-bearing unfiltered callers + the :238 asymmetry untouched (out of scope).

Be HOSTILE. Output VERDICT: PLAN-READY or PLAN-NEEDS-REVISION or PLAN-KILL with quoted evidence. If PLAN-READY, say so explicitly.
codex
I’ll audit the revised plan against the four prior findings first, then cross-check the referenced source lines for any new contradictions or overreach.
exec
/bin/bash -lc pwd in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter

exec
/bin/bash -lc 'git branch --show-current' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
research/1913-fromframe-filter

exec
/bin/bash -lc 'git rev-parse HEAD' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
d23d55022e991c3023e2eac530e6b9101df8ac7a

exec
/bin/bash -lc "rg -n \"§2\\.1|2\\.1|ForwardCandidate|FabricRedirect|MissingNeighbor|2\\.6|_from_frame|raw|unchecked|Path A|Path B|2814|1794|2533|2564|238|slow_path|FILTERED\" docs/research/1913-fromframe-filter/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
1:# Plan of Action — #1913: trailing `maybe_reinject_slow_path_from_frame` runs for ALL non-forward dispositions (incl. PolicyDenied)
14:**unconditional** call to `maybe_reinject_slow_path_from_frame(.., packet_frame,
15:meta, decision, ..)` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814`,
17:`:2156`. That match has arms for `LocalDelivery`, `NoRoute`, `MissingNeighbor`,
19:`ForwardCandidate`, `FabricRedirect`, `NextTableUnsupported`).
24:LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported
27:exists ONLY in the desc-based wrapper `maybe_reinject_slow_path`
28:(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:90`). The `_from_frame`
29:variant (`slow_path.rs:129+`) has **no disposition filter** — it goes
34:Because the trailing call at `:2814` uses the unfiltered `_from_frame`
41:### 2.1 The trailing chokepoint (mod.rs:2156–2820)
44:The forward branch at `mod.rs:1794-1798` is `if matches!(disposition,
45:ForwardCandidate | FabricRedirect)` — so **`ForwardCandidate` and
46:`FabricRedirect` are consumed by the forward `if` and NEVER enter the `else`
47:block** that contains the `:2156` match or the `:2814` trailing call (Codex +
48:AGY r1, verified). They cannot reach :2814. (r1 table erratum — corrected
52:(`:2802`) and then unconditionally `maybe_reinject_slow_path_from_frame(...,
53:packet_frame, meta, decision, "slow_path", ...)` at `:2814`. Per-arm exit
56:| Arm | Early `continue`/exit? | Reaches :2814 with disposition |
60:| `MissingNeighbor` (:2204) | **sometimes** — `neg_neigh_gate` fast-fail (:~2245) and resolved-wins paths `continue` (recycle+skip); **SNAT-allocation-failure** paths `scratch_recycle.push` + `continue` at **:2533 and :2564** (AGY + Codex r1, verified); the buffered (`recycle_now=false`) and capacity-drop paths fall through | `MissingNeighbor` ✅ in allow-list |
63:| `_` catch-all (:2801) | no | covers **`DiscardRoute`** (✗ NOT in allow-list — LEAK), plus `NextTableUnsupported` (✅ in allow-list). `ForwardCandidate`/`FabricRedirect` do NOT reach here (consumed at :1794-1798). |
77:Tracing `maybe_reinject_slow_path_from_frame` (slow_path.rs:129+) for a
88:4. `slow_path.cloned()` — present in production. → not the drop door.
89:5. `slow_path.enqueue(packet)` → writes the raw L3 packet to the slow-path
95:`record_slow_path_accept` (umem/mod.rs:941) bumps generic
96:`slow_path_packets`/`slow_path_bytes` and hits the `_ => {}` arm (no
117:By `:2814`, the safety-net conversions (`:1762`, `:1697`) have already turned
118:`HAInactive` into `FabricRedirect` whenever `owner_rg_for_resolution > 0`. A
139:route's entire purpose is to drop. Path A fixes PolicyDenied, HAInactive, and
142:### 2.5 Buffered-MissingNeighbor duplicate (issue Q3)
146:falls through to the trailing `:2814` call, which (since `MissingNeighbor` IS
156:HAInactive/DiscardRoute. The plan addresses it explicitly (see §5 Path A
159:**Explicit scope statement (Claude SMR r1, F2):** Path A keeps
160:`MissingNeighbor` in the allow-list, so the §2.5 duplicate-delivery is
166:### 2.6 Why a fix inside `_from_frame` is WRONG (critical finding)
168:`maybe_reinject_slow_path_from_frame` has **5 production call sites** (grep):
169:- `slow_path.rs:61` (build-failure fallback, via `handle_forward_build_failure`)
170:- `slow_path.rs:113` (the desc-wrapper's tail, AFTER its own allow-list filter)
172:- `tx/dispatch/mod.rs:225` ("no XSK binding" fallback — passes `FabricRedirect`
174:  re: the asymmetric `:238` desc branch.)
175:- `poll_descriptor/mod.rs:2814` (the buggy trailing call)
178:unfiltered `_from_frame` variant is load-bearing for them:
180:1. **`dispatch/mod.rs:225` — FabricRedirect, Owned-frame fallback.** Guarded by
181:   `if request.decision.resolution.disposition == FabricRedirect` (:223) AND
184:   `FabricRedirect` via unfiltered `_from_frame`. (Codex + AGY r1, verified.)
185:2. **`handle_forward_build_failure` → `slow_path.rs:61` — ForwardCandidate
187:   (`dispatch/mod.rs:855-857` sets `fallback_to_slow_path = true`),
188:   `handle_forward_build_failure` (`:887`) calls `_from_frame` unfiltered with
189:   a `ForwardCandidate` decision (Codex r1, verified). `ForwardCandidate` is
193:immediately-following `else` at dispatch/mod.rs:238 proves the bypass is
194:intentional." That is over-stated and partly wrong. The `:238` `else` branch
195:(non-Owned/desc frame) calls the FILTERED wrapper `maybe_reinject_slow_path`,
196:which REJECTS `FabricRedirect` → the desc-frame `FabricRedirect` fallback is
197:**silently dropped today**. So dispatch/mod.rs treats `FabricRedirect`
200:bypass." It is OUT OF SCOPE for #1913 (the trailing call at :2814 is a distinct
204:> **Conclusion (unchanged):** Adding the allow-list INSIDE `_from_frame` would
205:> break BOTH the `dispatch/mod.rs:225` FabricRedirect-Owned fallback AND the
206:> `slow_path.rs:61` ForwardCandidate build-failure fallback (neither
208:> `_from_frame`" option (Path B). The fix belongs at the `mod.rs:2814` call
210:> should be explicitly documented as the RAW/unchecked primitive whose callers
211:> own the eligibility decision (altitude fix, see Path A + §6).
224:- The trailing reinject at `mod.rs:2814` must NOT enqueue `PolicyDenied`,
226:- Preserve the existing intentional `_from_frame` bypass at
227:  `dispatch/mod.rs:225` (FabricRedirect fallback) and the IPsec LocalDelivery
230:  the gate lives, at the call site and in `tx/dispatch/slow_path.rs`.
231:- Decide the buffered-MissingNeighbor duplicate (§2.5): keep (document) or
243:### Path A — gate at the call site (mod.rs:2814) via a shared predicate (RECOMMENDED)
246:disposition_is_slow_path_eligible(d: ForwardingDisposition) -> bool` (or
247:`ForwardingDisposition::is_slow_path_eligible(self)`) in
248:`tx/dispatch/slow_path.rs` (or on the enum in `types/forwarding.rs`). Then:
250:1. Replace the inline `matches!(...)` in the wrapper `maybe_reinject_slow_path`
251:   (slow_path.rs:90) with a call to the shared predicate (no behavior change —
253:2. At `mod.rs:2814`, wrap the trailing call:
255:   if disposition_is_slow_path_eligible(decision.resolution.disposition) {
256:       maybe_reinject_slow_path_from_frame(...);
261:   `maybe_reinject_slow_path_from_frame` stating it is the RAW/unchecked
263:   `is_slow_path_eligible` unless they have a documented reason to bypass it
265:   FabricRedirect-Owned fallback and `slow_path.rs:61` ForwardCandidate
274:  2814) — a third future caller could forget it. Mitigated by the shared
275:  `const fn` name + the raw-primitive doc comment on `_from_frame`.
276:- **Buffered-MissingNeighbor (§2.5)**: `MissingNeighbor` stays in the
277:  allow-list, so the §2.5 duplicate behavior is UNCHANGED by Path A. Sub-
281:  **Recommendation: leave MissingNeighbor behavior unchanged in this fix**
285:### Path B — filter inside `_from_frame` (REJECTED)
287:Add the allow-list to `maybe_reinject_slow_path_from_frame` itself.
289:- **Pros**: every `_from_frame` caller is covered automatically.
290:- **Cons / FATAL**: breaks BOTH `dispatch/mod.rs:225` (FabricRedirect-Owned
291:  fallback) AND `slow_path.rs:61`/`handle_forward_build_failure`
292:  (ForwardCandidate build-failure fallback) — neither disposition is in the
296:  **Rejected** per §2.6.
298:### Path C — convert the trailing `_from_frame` call to the filtered wrapper `maybe_reinject_slow_path`
300:At `mod.rs:2814`, call the desc-based wrapper (which already filters) instead
301:of `_from_frame`.
320:**Path A.** Shared `const fn`/enum-method predicate, gate at the `mod.rs:2814`
323:FabricRedirect-Owned fallback; `slow_path.rs:61` ForwardCandidate
324:build-failure fallback). Add a raw-primitive doc comment to `_from_frame`
326:MissingNeighbor buffered-duplicate behavior (Q3) unchanged + DEFERRED. Do NOT
327:attempt to fix the dispatch/mod.rs:238 FabricRedirect desc-branch asymmetry in
334:1. `types/forwarding.rs` (or `tx/dispatch/slow_path.rs`): add
335:   `pub(in crate::afxdp) const fn is_slow_path_eligible` over the allow-list
336:   `LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported`, with a
338:   | ForwardCandidate | FabricRedirect`) and WHY each is excluded.
339:2. `slow_path.rs:90`: replace the inline `matches!` with the predicate (pure
341:3. `poll_descriptor/mod.rs:2814`: guard the trailing call with the predicate.
351:- Today the leak is invisible (generic `slow_path_packets` only). After the
356:- Optional: a `slow_path_disposition_filtered` counter to make the
364:- **T1 (the bug)**: `maybe_reinject_slow_path_from_frame` direct call is NOT
366:  the predicate: `is_slow_path_eligible(PolicyDenied) == false`,
368:  `(LocalDelivery|NoRoute|MissingNeighbor|NextTableUnsupported) == true`,
369:  `(FabricRedirect|ForwardCandidate) == false`.
370:- **T2 (wrapper SSOT)**: the wrapper `maybe_reinject_slow_path` with a
376:  fixture. If feasible, assert `slow_path_packets == 0` and the policy_deny
380:- **T4 (no regression)**: `dispatch/mod.rs:225` FabricRedirect fallback still
381:  reinjects (its `_from_frame` path is NOT gated by the predicate). Confirm via
406:- **Risk**: buffered-MissingNeighbor duplicate (§2.5) is untouched by Path A —
418:   Claude SMR (no earlier drop point; the `_from_frame` enqueue reaches the TUN).
422:3. Altitude — reviewers agreed Path A (call-site gate) is correct PROVIDED the
423:   `_from_frame` helper is documented as the raw/unchecked primitive (folded
424:   into Path A step 3 + §6). Filtering inside `_from_frame` (Path B) is fatal
425:   — breaks TWO load-bearing callers (FabricRedirect-Owned + ForwardCandidate
427:4. Buffered-MissingNeighbor duplicate (§2.5 / issue Q3) — **DEFERRED** (not
432:- **§2.1 table erratum (Codex + AGY):** `ForwardCandidate`/`FabricRedirect` are
433:  consumed by the forward `if` at mod.rs:1794-1798 and NEVER reach :2814 — they
435:- **MissingNeighbor SNAT-failure early continues (Codex + AGY):** :2533 and
436:  :2564 `scratch_recycle.push` + `continue`, skipping :2814 — omitted in r1.
438:- **§2.6 over-broad proof (Codex + AGY):** the r1 "the :238 else proves it's
439:  intentional" framing is wrong — the :238 desc branch calls the FILTERED
440:  wrapper which DROPS FabricRedirect, an asymmetry/pre-existing bug, not a
441:  clean bypass. ALSO the `slow_path.rs:61` ForwardCandidate build-failure
442:  fallback relies on unfiltered `_from_frame`. Both corrected; Path B is fatal
444:- **Altitude (Codex + AGY):** document `_from_frame` as the raw/unchecked
445:  primitive. FOLDED into Path A step 3.

exec
/bin/bash -lc 'git status --short' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
codex
The repo is on the requested branch and commit with a clean worktree. I’ve confirmed r2 contains explicit text for all four prior objections; now I’m checking that the cited code still supports those statements.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1760,1820p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  1760	                    // — those should NOT be fabric-redirected.
  1761	                    let egress_rg = owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
  1762	                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
  1763	                        && egress_rg > 0
  1764	                        && !packet_fabric_ingress
  1765	                    {
  1766	                        if flow_cache_owner_rg_id <= 0 {
  1767	                            flow_cache_owner_rg_id = egress_rg;
  1768	                        }
  1769	                        // #919: prefer the cached u16 zone ID; fall back to
  1770	                        // looking up the ifindex's zone name and translating
  1771	                        // to an ID. resolve_zone_encoded_fabric_redirect_by_id
  1772	                        // skips the name round-trip.
  1773	                        // #921: direct ifindex → u16 (was a two-hop
  1774	                        // name round-trip).
  1775	                        let zone_id = session_ingress_zone.or_else(|| {
  1776	                            worker_ctx
  1777	                                .forwarding
  1778	                                .ifindex_to_zone_id
  1779	                                .get(&(meta.ingress_ifindex as i32))
  1780	                                .copied()
  1781	                        });
  1782	                        if let Some(redirect) = zone_id
  1783	                            .and_then(|id| {
  1784	                                resolve_zone_encoded_fabric_redirect_by_id(
  1785	                                    worker_ctx.forwarding,
  1786	                                    id,
  1787	                                )
  1788	                            })
  1789	                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
  1790	                        {
  1791	                            decision.resolution = redirect;
  1792	                        }
  1793	                    }
  1794	                    if matches!(
  1795	                        decision.resolution.disposition,
  1796	                        ForwardingDisposition::ForwardCandidate
  1797	                            | ForwardingDisposition::FabricRedirect
  1798	                    ) {
  1799	                        telemetry.dbg.forward += 1;
  1800	                        // Direction-specific tracking
  1801	                        let ingress_if = meta.ingress_ifindex as i32;
  1802	                        let egress_if = decision.resolution.egress_ifindex;
  1803	                        if ingress_if == 5 {
  1804	                            telemetry.dbg.rx_from_trust += 1;
  1805	                            telemetry.dbg.fwd_trust_to_wan += 1;
  1806	                        } else if ingress_if == 6 {
  1807	                            telemetry.dbg.rx_from_wan += 1;
  1808	                            telemetry.dbg.fwd_wan_to_trust += 1;
  1809	                        }
  1810	                        // NAT decision tracking
  1811	                        if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some()
  1812	                        {
  1813	                            telemetry.dbg.nat_applied_snat += 1;
  1814	                            telemetry.dbg.nat_applied_dnat += 1;
  1815	                        } else if decision.nat.rewrite_src.is_some() {
  1816	                            telemetry.dbg.nat_applied_snat += 1;
  1817	                        } else if decision.nat.rewrite_dst.is_some() {
  1818	                            telemetry.dbg.nat_applied_dnat += 1;
  1819	                        } else {
  1820	                            telemetry.dbg.nat_applied_none += 1;

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/slow_path.rs | sed -n '1,180p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
     1	// Slow-path / exception / build-failure routing for the dispatch
     2	// loop (#1443).
     3	//
     4	// Pure code motion from `dispatch/mod.rs`. Hot-path callers reach
     5	// these helpers only on exception branches (build failure, missing
     6	// egress binding, fabric-redirect fallback), so we tag the
     7	// reinjection family `#[cold] #[inline(never)]` per AGY round-2
     8	// finding D — `#[cold]` alone does not stop LLVM from inlining a
     9	// single-caller helper and bloating the hot i-cache footprint;
    10	// `#[inline(never)]` guarantees the cold body stays out-of-line.
    11	//
    12	// The dispatch `mod.rs` re-exports
    13	// - `handle_forward_build_failure`,
    14	// - `maybe_reinject_slow_path`,
    15	// - `maybe_reinject_slow_path_from_frame`,
    16	// - `extract_l3_packet_with_nat`
    17	// at `pub(in crate::afxdp)`; `extract_l3_packet` and
    18	// `extract_l3_packet_from_frame` keep their pre-split `pub(super)`
    19	// (visible to all of `tx/`) via `pub(in crate::afxdp::tx)`.
    20	
    21	use super::*;
    22	
    23	#[cold]
    24	#[inline(never)]
    25	pub(in crate::afxdp) fn handle_forward_build_failure(
    26	    binding: &BindingIdentity,
    27	    live: &BindingLiveState,
    28	    slow_path: Option<&Arc<SlowPathReinjector>>,
    29	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    30	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    31	    dbg: &mut DebugPollCounters,
    32	    _target_ifindex: i32,
    33	    packet_length: u32,
    34	    frame: &[u8],
    35	    meta: impl Into<UserspaceDpMeta>,
    36	    decision: SessionDecision,
    37	    fallback_to_slow_path: bool,
    38	    forwarding: &ForwardingState,
    39	) {
    40	    let meta = meta.into();
    41	    dbg.build_fail += 1;
    42	    #[cfg(feature = "debug-log")]
    43	    if dbg.build_fail <= 3 {
    44	        debug_log!(
    45	            "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
    46	            _target_ifindex,
    47	            packet_length,
    48	            fallback_to_slow_path,
    49	        );
    50	    }
    51	    record_exception(
    52	        recent_exceptions,
    53	        binding,
    54	        "forward_build_failed",
    55	        packet_length,
    56	        Some(meta),
    57	        None,
    58	        forwarding,
    59	    );
    60	    if fallback_to_slow_path {
    61	        maybe_reinject_slow_path_from_frame(
    62	            binding,
    63	            live,
    64	            slow_path,
    65	            local_tunnel_deliveries,
    66	            frame,
    67	            meta,
    68	            decision,
    69	            recent_exceptions,
    70	            "forward_build_slow_path",
    71	            forwarding,
    72	        );
    73	    }
    74	}
    75	
    76	#[cold]
    77	#[inline(never)]
    78	pub(in crate::afxdp) fn maybe_reinject_slow_path(
    79	    binding: &BindingIdentity,
    80	    live: &BindingLiveState,
    81	    slow_path: Option<&Arc<SlowPathReinjector>>,
    82	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    83	    area: &MmapArea,
    84	    desc: XdpDesc,
    85	    meta: impl Into<UserspaceDpMeta>,
    86	    decision: SessionDecision,
    87	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    88	    forwarding: &ForwardingState,
    89	) {
    90	    let meta = meta.into();
    91	    if !matches!(
    92	        decision.resolution.disposition,
    93	        ForwardingDisposition::LocalDelivery
    94	            | ForwardingDisposition::NoRoute
    95	            | ForwardingDisposition::MissingNeighbor
    96	            | ForwardingDisposition::NextTableUnsupported
    97	    ) {
    98	        return;
    99	    }
   100	    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
   101	        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   102	        record_exception(
   103	            recent_exceptions,
   104	            binding,
   105	            "slow_path_extract_failed",
   106	            desc.len as u32,
   107	            Some(meta),
   108	            None,
   109	            forwarding,
   110	        );
   111	        return;
   112	    };
   113	    maybe_reinject_slow_path_from_frame(
   114	        binding,
   115	        live,
   116	        slow_path,
   117	        local_tunnel_deliveries,
   118	        frame,
   119	        meta,
   120	        decision,
   121	        recent_exceptions,
   122	        "slow_path",
   123	        forwarding,
   124	    );
   125	}
   126	
   127	#[cold]
   128	#[inline(never)]
   129	pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(
   130	    binding: &BindingIdentity,
   131	    live: &BindingLiveState,
   132	    slow_path: Option<&Arc<SlowPathReinjector>>,
   133	    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
   134	    frame: &[u8],
   135	    meta: impl Into<UserspaceDpMeta>,
   136	    decision: SessionDecision,
   137	    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
   138	    reason: &str,
   139	    forwarding: &ForwardingState,
   140	) {
   141	    let meta = meta.into();
   142	    let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {
   143	        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   144	        record_exception(
   145	            recent_exceptions,
   146	            binding,
   147	            "slow_path_prepare_failed",
   148	            frame.len() as u32,
   149	            Some(meta),
   150	            None,
   151	            forwarding,
   152	        );
   153	        return;
   154	    };
   155	    let packet_len = packet.len() as u64;
   156	    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
   157	        && decision.resolution.local_ifindex > 0
   158	    {
   159	        local_tunnel_deliveries
   160	            .load()
   161	            .get(&decision.resolution.local_ifindex)
   162	            .cloned()
   163	    } else {
   164	        None
   165	    };
   166	    if let Some(delivery) = tunnel_delivery {
   167	        match delivery.try_send(packet) {
   168	            Ok(()) => {
   169	                live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
   170	            }
   171	            Err(std::sync::mpsc::TrySendError::Full(_)) => {
   172	                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
   173	                record_exception(
   174	                    recent_exceptions,
   175	                    binding,
   176	                    "local_tunnel_delivery_queue_full",
   177	                    frame.len() as u32,
   178	                    Some(meta),
   179	                    None,
   180	                    forwarding,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '835,895p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   835	                                    cos_queue_id: request.cos_queue_id,
   836	                                    dscp_rewrite: request.dscp_rewrite,
   837	                                    mirror_clone: false,
   838	                                    enqueue_ns: 0,
   839	                                };
   840	                                if enqueue_local_request_to_target_or_owner(target_binding, req)
   841	                                    .is_err()
   842	                                {
   843	                                    build_failed = true;
   844	                                    fallback_to_slow_path = true;
   845	                                    continue;
   846	                                }
   847	                                dbg.enqueue_ok += 1;
   848	                                dbg.enqueue_copy += 1;
   849	                                target_binding.tx_counters.pending_copy_tx_packets += 1;
   850	                                dbg.tx_bytes_total += cp2_len as u64;
   851	                                if (cp2_len as u32) > dbg.tx_max_frame {
   852	                                    dbg.tx_max_frame = cp2_len as u32;
   853	                                }
   854	                            }
   855	                            None => {
   856	                                build_failed = true;
   857	                                fallback_to_slow_path = true;
   858	                            }
   859	                        }
   860	                    }
   861	                }
   862	            }
   863	            if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE
   864	                || target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE
   865	            {
   866	                let _ = drain_pending_tx_local_owner(
   867	                    target_binding,
   868	                    now_ns,
   869	                    post_recycles,
   870	                    forwarding,
   871	                    worker_id,
   872	                    worker_commands_by_id,
   873	                );
   874	            }
   875	        }
   876	        if !post_recycles.is_empty() {
   877	            apply_shared_recycles(
   878	                left,
   879	                ingress_index,
   880	                ingress_binding,
   881	                right,
   882	                binding_lookup,
   883	                post_recycles,
   884	            );
   885	        }
   886	        if build_failed {
   887	            handle_forward_build_failure(
   888	                ingress_ident,
   889	                ingress_live,
   890	                slow_path,
   891	                local_tunnel_deliveries,
   892	                recent_exceptions,
   893	                dbg,
   894	                request.target_ifindex,
   895	                request.desc.len,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '210,250p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   210	        let Some(target_binding) = resolve_pending_forward_target_binding(
   211	            left,
   212	            ingress_index,
   213	            ingress_binding,
   214	            request.ingress_queue_id,
   215	            right,
   216	            binding_lookup,
   217	            target_binding_index,
   218	            request.target_ifindex,
   219	        ) else {
   220	            // No XSK binding for the target interface.  Normally fabric
   221	            // parents have bindings; this is a safety-net fallback in case
   222	            // the binding is not yet ready or bind() failed.
   223	            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
   224	                if matches!(request.frame, PendingForwardFrame::Owned(_)) {
   225	                    maybe_reinject_slow_path_from_frame(
   226	                        ingress_ident,
   227	                        ingress_live,
   228	                        slow_path,
   229	                        local_tunnel_deliveries,
   230	                        source_frame,
   231	                        request.meta,
   232	                        request.decision,
   233	                        recent_exceptions,
   234	                        "slow_path",
   235	                        forwarding,
   236	                    );
   237	                } else {
   238	                    maybe_reinject_slow_path(
   239	                        ingress_ident,
   240	                        ingress_live,
   241	                        slow_path,
   242	                        local_tunnel_deliveries,
   243	                        unsafe { &*ingress_area },
   244	                        request.desc,
   245	                        request.meta,
   246	                        request.decision,
   247	                        recent_exceptions,
   248	                        forwarding,
   249	                    );
   250	                }

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2140,2225p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2140	                                        decision.resolution.neighbor_mac.map(|m| format!(
  2141	                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2142	                                            m[0], m[1], m[2], m[3], m[4], m[5]
  2143	                                        )),
  2144	                                        decision.resolution.src_mac.map(|m| format!(
  2145	                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
  2146	                                            m[0], m[1], m[2], m[3], m[4], m[5]
  2147	                                        )),
  2148	                                        desc.len,
  2149	                                        meta.protocol,
  2150	                                    );
  2151	                                }
  2152	                            }
  2153	                        }
  2154	                    } else {
  2155	                        // Debug: count non-forward dispositions
  2156	                        match decision.resolution.disposition {
  2157	                            ForwardingDisposition::LocalDelivery => {
  2158	                                telemetry.dbg.local += 1;
  2159	                                // Host-bound traffic (NDP, ICMP echo, BGP,
  2160	                                // GRE-to-self inner packets, etc.) is
  2161	                                // delivered by the SINGLE decap-aware
  2162	                                // reinject chokepoint at the end of this
  2163	                                // leg (`maybe_reinject_slow_path_from_frame`
  2164	                                // over `packet_frame`). #1885: this arm used
  2165	                                // to ALSO call the desc-based
  2166	                                // `maybe_reinject_slow_path` here, pairing
  2167	                                // the ORIGINAL UMEM frame (the VLAN-tagged
  2168	                                // GRE OUTER frame on a tagged underlay) with
  2169	                                // the post-decap INNER meta
  2170	                                // (`stage_native_gre_decap` rebinds `meta`
  2171	                                // but `desc` still points at the un-decapped
  2172	                                // frame) — the slice landed 4 bytes early on
  2173	                                // tagged ingress (TUN write EINVAL: payload
  2174	                                // started with the dot1q TCI tail instead of
  2175	                                // the IP version nibble) and delivered the
  2176	                                // still-encapsulated OUTER packet on
  2177	                                // untagged ingress. It was ALSO a duplicate
  2178	                                // enqueue for non-decapped local packets
  2179	                                // (both calls pass the same disposition
  2180	                                // filter). The first delivered packet
  2181	                                // creates a BPF session map entry so
  2182	                                // subsequent packets bypass userspace
  2183	                                // entirely.
  2184	                                recycle_now = true;
  2185	                            }
  2186	                            ForwardingDisposition::NoRoute => {
  2187	                                telemetry.dbg.no_route += 1;
  2188	                                if cfg!(feature = "debug-log") {
  2189	                                    if telemetry.dbg.no_route <= 3 {
  2190	                                        if let Some(flow) = flow.as_ref() {
  2191	                                            eprintln!(
  2192	                                                "DBG NO_ROUTE: {}:{} -> {}:{} proto={} ingress_if={}",
  2193	                                                flow.src_ip,
  2194	                                                flow.forward_key.src_port,
  2195	                                                flow.dst_ip,
  2196	                                                flow.forward_key.dst_port,
  2197	                                                meta.protocol,
  2198	                                                meta.ingress_ifindex,
  2199	                                            );
  2200	                                        }
  2201	                                    }
  2202	                                }
  2203	                            }
  2204	                            ForwardingDisposition::MissingNeighbor => {
  2205	                                telemetry.dbg.missing_neigh += 1;
  2206	                                // #1651 B3: dead-host fast-fail gate. Runs at
  2207	                                // the very top of the MissingNeighbor arm,
  2208	                                // BEFORE the kernel probe, session seed, and
  2209	                                // pending_neigh buffer, so a dead host never
  2210	                                // consumes a queue slot, fires a probe, or
  2211	                                // creates a MissingNeighborSeed session.
  2212	                                //
  2213	                                // Resolved-neighbor-wins (RTM_NEWNEIGH
  2214	                                // invalidation): check static then dynamic
  2215	                                // neighbors FIRST (same order as
  2216	                                // retry_pending_neigh / lookup_neighbor_entry).
  2217	                                // If the dst is now resolved, drop any stale
  2218	                                // negative entry and fall through to normal
  2219	                                // forwarding. Otherwise, if it is still
  2220	                                // negatively cached + un-expired, recycle the
  2221	                                // frame immediately.
  2222	                                if let Some(next_hop) = decision.resolution.next_hop {
  2223	                                    let neg_key =
  2224	                                        (decision.resolution.egress_ifindex, next_hop);
  2225	                                    // neg_neigh_gate runs the resolved-wins

exec
/bin/bash -lc "nl -ba docs/research/1913-fromframe-filter/plan.md | sed -n '1,460p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2780,2830p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2780	                                }
  2781	                                if cfg!(feature = "debug-log") {
  2782	                                    if telemetry.dbg.missing_neigh <= 3 {
  2783	                                        if let Some(flow) = flow.as_ref() {
  2784	                                            eprintln!(
  2785	                                                "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
  2786	                                                "SOLICIT+SLOW",
  2787	                                                flow.src_ip,
  2788	                                                flow.forward_key.src_port,
  2789	                                                flow.dst_ip,
  2790	                                                flow.forward_key.dst_port,
  2791	                                                meta.protocol,
  2792	                                                pending_decision.resolution.egress_ifindex,
  2793	                                                pending_decision.resolution.next_hop,
  2794	                                            );
  2795	                                        }
  2796	                                    }
  2797	                                }
  2798	                            }
  2799	                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
  2800	                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
  2801	                            _ => telemetry.dbg.disposition_other += 1,
  2802	                        }
  2803	                        record_forwarding_disposition(
  2804	                            &worker_ctx.ident,
  2805	                            DispositionCounters::Hot(telemetry.counters),
  2806	                            decision.resolution,
  2807	                            desc.len as u32,
  2808	                            Some(meta),
  2809	                            debug.as_ref(),
  2810	                            worker_ctx.recent_exceptions,
  2811	                            worker_ctx.last_resolution,
  2812	                            worker_ctx.forwarding,
  2813	                        );
  2814	                        maybe_reinject_slow_path_from_frame(
  2815	                            &worker_ctx.ident,
  2816	                            &binding.live,
  2817	                            worker_ctx.slow_path,
  2818	                            worker_ctx.local_tunnel_deliveries,
  2819	                            packet_frame,
  2820	                            meta,
  2821	                            decision,
  2822	                            worker_ctx.recent_exceptions,
  2823	                            "slow_path",
  2824	                            worker_ctx.forwarding,
  2825	                        );
  2826	                    }
  2827	                } else {
  2828	                    record_disposition(
  2829	                        &worker_ctx.ident,
  2830	                        &binding.live,

 succeeded in 0ms:
     1	# Plan of Action — #1913: trailing `maybe_reinject_slow_path_from_frame` runs for ALL non-forward dispositions (incl. PolicyDenied)
     2	
     3	- **Revision**: r2 (post round-1: Codex + AGY + Claude SMR)
     4	- **Issue**: #1913 (bug)
     5	- **Branch**: `research/1913-fromframe-filter`
     6	- **Mode**: `/research` — STOP at PLAN-READY. No PR, no production source touched.
     7	- **Base**: origin/master @ `d535f1f3e`
     8	
     9	---
    10	
    11	## 1. Problem statement
    12	
    13	`poll_binding_process_descriptor`'s non-forward branch ends with an
    14	**unconditional** call to `maybe_reinject_slow_path_from_frame(.., packet_frame,
    15	meta, decision, ..)` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814`,
    16	immediately after the `match decision.resolution.disposition` block at
    17	`:2156`. That match has arms for `LocalDelivery`, `NoRoute`, `MissingNeighbor`,
    18	`PolicyDenied`, `HAInactive`, and a `_` catch-all (which covers `DiscardRoute`,
    19	`ForwardCandidate`, `FabricRedirect`, `NextTableUnsupported`).
    20	
    21	The disposition allow-list
    22	
    23	```rust
    24	LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported
    25	```
    26	
    27	exists ONLY in the desc-based wrapper `maybe_reinject_slow_path`
    28	(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:90`). The `_from_frame`
    29	variant (`slow_path.rs:129+`) has **no disposition filter** — it goes
    30	straight to: `extract_l3_packet_with_nat` → LocalDelivery tunnel-delivery
    31	branch → #1873 R-C tunnel gate (`tunnel_endpoint_id != 0`) →
    32	`SlowPathReinjector::enqueue` → kernel slow-path TUN → kernel FIB.
    33	
    34	Because the trailing call at `:2814` uses the unfiltered `_from_frame`
    35	variant, **`PolicyDenied`, `HAInactive`, and `DiscardRoute` frames are
    36	handed to the kernel FIB** when the wrapper's allow-list says they should be
    37	dropped.
    38	
    39	## 2. Blast-radius walk (verified against source @ d535f1f3e)
    40	
    41	### 2.1 The trailing chokepoint (mod.rs:2156–2820)
    42	
    43	**First**: the `match` at `:2156` is inside the `else` of the FORWARD branch.
    44	The forward branch at `mod.rs:1794-1798` is `if matches!(disposition,
    45	ForwardCandidate | FabricRedirect)` — so **`ForwardCandidate` and
    46	`FabricRedirect` are consumed by the forward `if` and NEVER enter the `else`
    47	block** that contains the `:2156` match or the `:2814` trailing call (Codex +
    48	AGY r1, verified). They cannot reach :2814. (r1 table erratum — corrected
    49	below.)
    50	
    51	The `match` at `:2156` falls through to `record_forwarding_disposition(...)`
    52	(`:2802`) and then unconditionally `maybe_reinject_slow_path_from_frame(...,
    53	packet_frame, meta, decision, "slow_path", ...)` at `:2814`. Per-arm exit
    54	behavior verified end-to-end (corrected after r1):
    55	
    56	| Arm | Early `continue`/exit? | Reaches :2814 with disposition |
    57	|-----|-------------------|--------------------------------|
    58	| `LocalDelivery` (:2157) | no | `LocalDelivery` ✅ in allow-list |
    59	| `NoRoute` (:2186) | no | `NoRoute` ✅ in allow-list |
    60	| `MissingNeighbor` (:2204) | **sometimes** — `neg_neigh_gate` fast-fail (:~2245) and resolved-wins paths `continue` (recycle+skip); **SNAT-allocation-failure** paths `scratch_recycle.push` + `continue` at **:2533 and :2564** (AGY + Codex r1, verified); the buffered (`recycle_now=false`) and capacity-drop paths fall through | `MissingNeighbor` ✅ in allow-list |
    61	| `PolicyDenied` (:2799) | **no** | **`PolicyDenied` ✗ NOT in allow-list — LEAK** |
    62	| `HAInactive` (:2800) | no | **`HAInactive` ✗ NOT in allow-list — LEAK** |
    63	| `_` catch-all (:2801) | no | covers **`DiscardRoute`** (✗ NOT in allow-list — LEAK), plus `NextTableUnsupported` (✅ in allow-list). `ForwardCandidate`/`FabricRedirect` do NOT reach here (consumed at :1794-1798). |
    64	
    65	So three dispositions reach the unfiltered enqueue that the wrapper would
    66	reject: **`PolicyDenied`, `HAInactive`, `DiscardRoute`**. (`NextTableUnsupported`
    67	also flows through the `_` arm but IS in the allow-list, so it is correctly
    68	reinject-eligible.)
    69	
    70	### 2.2 What reinjecting a `PolicyDenied` frame actually does today
    71	
    72	`decision.resolution.disposition` is overwritten to `PolicyDenied` at
    73	`mod.rs:1694`, but the rest of `decision.resolution` (egress_ifindex,
    74	next_hop, tunnel_endpoint_id) and `decision.nat` retain whatever
    75	`resolve_forwarding` produced for the flow before the policy verdict.
    76	
    77	Tracing `maybe_reinject_slow_path_from_frame` (slow_path.rs:129+) for a
    78	typical denied transit flow:
    79	
    80	1. `extract_l3_packet_with_nat(frame, meta, decision.nat)` — depends ONLY on
    81	   a parseable L3 frame + addr_family, **not** on disposition. For a normal
    82	   IPv4/IPv6 transit packet this **succeeds** and returns the L3 bytes (NAT
    83	   default = no rewrite). → not the drop door.
    84	2. `tunnel_delivery` branch: requires `disposition == LocalDelivery`. False
    85	   for PolicyDenied. → skipped.
    86	3. #1873 R-C tunnel gate: `tunnel_endpoint_id != 0`. For a normal denied
    87	   transit flow this is **0**, so the gate does NOT fire. → not the drop door.
    88	4. `slow_path.cloned()` — present in production. → not the drop door.
    89	5. `slow_path.enqueue(packet)` → writes the raw L3 packet to the slow-path
    90	   TUN → **kernel FIB forwards it** (rate-limited only by the slow-path
    91	   reinjector's token bucket).
    92	
    93	**Conclusion: a policy-denied transit packet IS forwarded by the kernel**, a
    94	zone-policy bypass bounded only by the slow-path rate limiter. Telemetry:
    95	`record_slow_path_accept` (umem/mod.rs:941) bumps generic
    96	`slow_path_packets`/`slow_path_bytes` and hits the `_ => {}` arm (no
    97	disposition-specific counter), so the leak is invisible in
    98	per-disposition slow-path metrics. The `policy_deny` debug counter and
    99	`emit_policy_deny_event` still fire (deny is "logged"), masking the fact that
   100	the packet was also forwarded. **This is a correctness/security bug, not
   101	benign.**
   102	
   103	Caveats that bound (do NOT eliminate) the leak:
   104	- Only **first packets / cold-path packets** reach userspace at all; once a
   105	  session/flow-cache entry exists the BPF fast path handles it. A denied flow
   106	  never creates a session, so EVERY packet of a denied flow is a cold-path
   107	  packet → every packet is a leak candidate (not just the first).
   108	- The slow-path reinjector rate-limits, so the leak is a throttled trickle,
   109	  not line-rate. But "throttled" ≠ "blocked": a low-rate denied flow (e.g. a
   110	  port-scan probe, a single denied SSH attempt) is forwarded in full.
   111	- The kernel FIB must actually have a route to the dst for the forward to
   112	  land; for a denied **transit** flow it usually does (that is why policy,
   113	  not routing, was the gate).
   114	
   115	### 2.3 `HAInactive`
   116	
   117	By `:2814`, the safety-net conversions (`:1762`, `:1697`) have already turned
   118	`HAInactive` into `FabricRedirect` whenever `owner_rg_for_resolution > 0`. A
   119	**residual** `HAInactive` at the match means `egress_rg == 0` (unresolved
   120	ownership) or fabric-ingress anti-loop. Reinjecting it hands the packet to the
   121	standby node's kernel FIB — on a standby that does not own the RG this can
   122	produce duplicate/asymmetric forwarding or a plaintext send from the wrong
   123	node. Lower incidence than PolicyDenied (requires the residual-HAInactive
   124	corner) but still a should-drop disposition being reinjected.
   125	
   126	### 2.4 `DiscardRoute`
   127	
   128	A packet that matched a **discard/reject route** (`forwarding/mod.rs:1279`,
   129	`:1427`) lands in the `_` catch-all and is reinjected to the kernel FIB
   130	unfiltered. Discard routes exist precisely to drop traffic; reinjection
   131	re-routes it via the kernel (which may not have the same discard route or may
   132	default-route it). Another should-drop-but-forwarded leak. NOTE: `DiscardRoute`
   133	is ALSO absent from the wrapper allow-list, confirming the intended contract
   134	is "drop".
   135	
   136	**`DiscardRoute` is the cleanest proof the unfiltered reinject is a bug**
   137	(Claude SMR r1, F1): unlike PolicyDenied (which has the "deny is logged"
   138	partial mitigation) there is no plausible "intentional" reading — a discard
   139	route's entire purpose is to drop. Path A fixes PolicyDenied, HAInactive, and
   140	DiscardRoute identically.
   141	
   142	### 2.5 Buffered-MissingNeighbor duplicate (issue Q3)
   143	
   144	For the `PendingNeighAdmission::Buffer` path the frame is inserted into
   145	`pending_neigh` and `recycle_now = false` (mod.rs:2776) — but execution still
   146	falls through to the trailing `:2814` call, which (since `MissingNeighbor` IS
   147	in the allow-list) **enqueues a copy to the kernel slow path**. On neighbor
   148	resolution `retry_pending_neigh` ALSO TXes the buffered frame via in-place
   149	rewrite. → potential **duplicate first-packet delivery** (one via kernel FIB
   150	now, one via the userspace rewrite later). The in-arm comment block
   151	(mod.rs:2690+) says "the trailing decap-aware ... chokepoint (#1901) still
   152	hands the correctly-paired INNER packet to the kernel slow path" — i.e. the
   153	duplicate is currently **intentional/known** for the recovery story, but the
   154	issue flags the contradiction with the buffer's "we buffer it for retry"
   155	intent. This is a SECONDARY concern; the primary bug is PolicyDenied/
   156	HAInactive/DiscardRoute. The plan addresses it explicitly (see §5 Path A
   157	sub-decision) but does not block on it.
   158	
   159	**Explicit scope statement (Claude SMR r1, F2):** Path A keeps
   160	`MissingNeighbor` in the allow-list, so the §2.5 duplicate-delivery is
   161	**UNCHANGED** by this fix. Issue Q3 is acknowledged and **DEFERRED** — #1913
   162	does NOT close it. If the duplicate is judged undesirable it is a separate
   163	follow-up (file a new issue at /engineer time). The converged issue comment
   164	must say this plainly so a reader does not assume #1913 resolves Q3.
   165	
   166	### 2.6 Why a fix inside `_from_frame` is WRONG (critical finding)
   167	
   168	`maybe_reinject_slow_path_from_frame` has **5 production call sites** (grep):
   169	- `slow_path.rs:61` (build-failure fallback, via `handle_forward_build_failure`)
   170	- `slow_path.rs:113` (the desc-wrapper's tail, AFTER its own allow-list filter)
   171	- `poll_stages.rs:452` (IPsec local-delivery — synthesizes `LocalDelivery`)
   172	- `tx/dispatch/mod.rs:225` ("no XSK binding" fallback — passes `FabricRedirect`
   173	  via the Owned-frame branch; NOT in the allow-list. See the correction below
   174	  re: the asymmetric `:238` desc branch.)
   175	- `poll_descriptor/mod.rs:2814` (the buggy trailing call)
   176	
   177	Two of these callers pass dispositions OUTSIDE the wrapper allow-list, so the
   178	unfiltered `_from_frame` variant is load-bearing for them:
   179	
   180	1. **`dispatch/mod.rs:225` — FabricRedirect, Owned-frame fallback.** Guarded by
   181	   `if request.decision.resolution.disposition == FabricRedirect` (:223) AND
   182	   `matches!(request.frame, PendingForwardFrame::Owned(_))` (:224). When the
   183	   target binding is missing and the frame is owned, it reinjects a
   184	   `FabricRedirect` via unfiltered `_from_frame`. (Codex + AGY r1, verified.)
   185	2. **`handle_forward_build_failure` → `slow_path.rs:61` — ForwardCandidate
   186	   build-failure fallback.** When the forward-build returns `None`
   187	   (`dispatch/mod.rs:855-857` sets `fallback_to_slow_path = true`),
   188	   `handle_forward_build_failure` (`:887`) calls `_from_frame` unfiltered with
   189	   a `ForwardCandidate` decision (Codex r1, verified). `ForwardCandidate` is
   190	   NOT in the wrapper allow-list either.
   191	
   192	**Correction to the r1 framing (Codex + AGY r1):** the r1 plan argued "the
   193	immediately-following `else` at dispatch/mod.rs:238 proves the bypass is
   194	intentional." That is over-stated and partly wrong. The `:238` `else` branch
   195	(non-Owned/desc frame) calls the FILTERED wrapper `maybe_reinject_slow_path`,
   196	which REJECTS `FabricRedirect` → the desc-frame `FabricRedirect` fallback is
   197	**silently dropped today**. So dispatch/mod.rs treats `FabricRedirect`
   198	ASYMMETRICALLY: Owned → reinjected, Desc → dropped. This asymmetry is a
   199	**pre-existing inconsistency** (likely a latent bug), NOT a clean "intentional
   200	bypass." It is OUT OF SCOPE for #1913 (the trailing call at :2814 is a distinct
   201	chokepoint), but the plan must NOT mischaracterize it as deliberate, and the
   202	shared predicate must be defined so it does not silently "fix" or worsen it.
   203	
   204	> **Conclusion (unchanged):** Adding the allow-list INSIDE `_from_frame` would
   205	> break BOTH the `dispatch/mod.rs:225` FabricRedirect-Owned fallback AND the
   206	> `slow_path.rs:61` ForwardCandidate build-failure fallback (neither
   207	> disposition is in the allow-list). This rules out the "filter inside
   208	> `_from_frame`" option (Path B). The fix belongs at the `mod.rs:2814` call
   209	> site via a shared predicate, NOT inside the shared helper — and the helper
   210	> should be explicitly documented as the RAW/unchecked primitive whose callers
   211	> own the eligibility decision (altitude fix, see Path A + §6).
   212	
   213	## 3. Severity
   214	
   215	**Medium-High security/correctness bug.** A configured zone-policy DENY is
   216	silently bypassed for cold-path (sessionless) packets: every packet of a
   217	denied flow is reinjected to the kernel FIB and forwarded, rate-limited only
   218	by the slow-path token bucket, and invisible in per-disposition telemetry.
   219	Pre-existing since the #1054 extraction (`cc31ffb96`); untouched by #1911.
   220	
   221	## 4. Goals / non-goals
   222	
   223	**Goals**
   224	- The trailing reinject at `mod.rs:2814` must NOT enqueue `PolicyDenied`,
   225	  `HAInactive`, or `DiscardRoute` frames to the kernel slow path.
   226	- Preserve the existing intentional `_from_frame` bypass at
   227	  `dispatch/mod.rs:225` (FabricRedirect fallback) and the IPsec LocalDelivery
   228	  path at `poll_stages.rs:452`.
   229	- Document the contract: which dispositions are reinject-eligible, and where
   230	  the gate lives, at the call site and in `tx/dispatch/slow_path.rs`.
   231	- Decide the buffered-MissingNeighbor duplicate (§2.5): keep (document) or
   232	  suppress.
   233	
   234	**Non-goals**
   235	- No change to the policy-evaluation logic, the slow-path reinjector, NAT, or
   236	  the tunnel gate.
   237	- No change to the other 4 call sites' behavior.
   238	- No new Prometheus surface beyond what is needed to make the dropped-leak
   239	  observable (optional, see §5).
   240	
   241	## 5. Multiple Path Options
   242	
   243	### Path A — gate at the call site (mod.rs:2814) via a shared predicate (RECOMMENDED)
   244	
   245	Extract the allow-list into a single `pub(in crate::afxdp) const fn
   246	disposition_is_slow_path_eligible(d: ForwardingDisposition) -> bool` (or
   247	`ForwardingDisposition::is_slow_path_eligible(self)`) in
   248	`tx/dispatch/slow_path.rs` (or on the enum in `types/forwarding.rs`). Then:
   249	
   250	1. Replace the inline `matches!(...)` in the wrapper `maybe_reinject_slow_path`
   251	   (slow_path.rs:90) with a call to the shared predicate (no behavior change —
   252	   pure refactor, makes the two sites share one SSOT).
   253	2. At `mod.rs:2814`, wrap the trailing call:
   254	   ```rust
   255	   if disposition_is_slow_path_eligible(decision.resolution.disposition) {
   256	       maybe_reinject_slow_path_from_frame(...);
   257	   }
   258	   ```
   259	
   260	3. **Altitude fix (Codex + AGY r1):** add a doc comment to
   261	   `maybe_reinject_slow_path_from_frame` stating it is the RAW/unchecked
   262	   primitive — callers are responsible for applying
   263	   `is_slow_path_eligible` unless they have a documented reason to bypass it
   264	   (the two intentional/legacy bypass sites: `dispatch/mod.rs:225`
   265	   FabricRedirect-Owned fallback and `slow_path.rs:61` ForwardCandidate
   266	   build-failure fallback). This makes the "next caller forgets the gate"
   267	   footgun explicit at the helper definition.
   268	
   269	- **Pros**: minimal, surgical; fixes the exact leak; preserves the two
   270	  load-bearing unfiltered callers (neither calls the predicate); one SSOT for
   271	  the allow-list; trivially testable; the altitude doc-comment closes the
   272	  footgun the r1 reviewers flagged.
   273	- **Cons**: the predicate now lives at two ENFORCING call sites (wrapper +
   274	  2814) — a third future caller could forget it. Mitigated by the shared
   275	  `const fn` name + the raw-primitive doc comment on `_from_frame`.
   276	- **Buffered-MissingNeighbor (§2.5)**: `MissingNeighbor` stays in the
   277	  allow-list, so the §2.5 duplicate behavior is UNCHANGED by Path A. Sub-
   278	  decision: leave as-is (it is the documented #1901 recovery story) and
   279	  document it, OR additionally skip the trailing call when `recycle_now ==
   280	  false` (the frame is buffered for retry, no need to also kernel-reinject).
   281	  **Recommendation: leave MissingNeighbor behavior unchanged in this fix**
   282	  (it is a separate, lower-severity, already-documented concern) and note it
   283	  in the call-site comment; file a follow-up if the duplicate is undesirable.
   284	
   285	### Path B — filter inside `_from_frame` (REJECTED)
   286	
   287	Add the allow-list to `maybe_reinject_slow_path_from_frame` itself.
   288	
   289	- **Pros**: every `_from_frame` caller is covered automatically.
   290	- **Cons / FATAL**: breaks BOTH `dispatch/mod.rs:225` (FabricRedirect-Owned
   291	  fallback) AND `slow_path.rs:61`/`handle_forward_build_failure`
   292	  (ForwardCandidate build-failure fallback) — neither disposition is in the
   293	  allow-list, and both rely on the unfiltered helper. Would require
   294	  simultaneously rewriting two call sites to a different mechanism. Larger
   295	  blast radius, changes 5 call sites' contract for one buggy site.
   296	  **Rejected** per §2.6.
   297	
   298	### Path C — convert the trailing `_from_frame` call to the filtered wrapper `maybe_reinject_slow_path`
   299	
   300	At `mod.rs:2814`, call the desc-based wrapper (which already filters) instead
   301	of `_from_frame`.
   302	
   303	- **Cons / FATAL**: the wrapper takes `area: &MmapArea` + `desc: XdpDesc` and
   304	  re-slices the ORIGINAL UMEM frame. The trailing site MUST use `packet_frame`
   305	  (the post-decap `owned_packet_frame` when GRE decap rebound meta) — this is
   306	  the entire point of the #1885/#1901 fix (using `desc` here re-introduces the
   307	  4-byte-early VLAN slice / un-decapped-outer-packet bug the comments at
   308	  :2163+ describe). So switching to the desc wrapper RE-INTRODUCES #1885.
   309	  **Rejected.**
   310	
   311	### Path D — document-only ("intentional")
   312	
   313	Conclude the unfiltered behavior is intentional and just add comments.
   314	
   315	- **Cons / FATAL**: §2.2 proves a real policy bypass (denied packets
   316	  forwarded). Not intentional, not benign. **Rejected.**
   317	
   318	## 6. Recommended path
   319	
   320	**Path A.** Shared `const fn`/enum-method predicate, gate at the `mod.rs:2814`
   321	call site, wrapper refactored to call the same predicate (SSOT). Leave the two
   322	load-bearing unfiltered callers untouched (`dispatch/mod.rs:225`
   323	FabricRedirect-Owned fallback; `slow_path.rs:61` ForwardCandidate
   324	build-failure fallback). Add a raw-primitive doc comment to `_from_frame`
   325	documenting that callers own the eligibility decision. Leave the
   326	MissingNeighbor buffered-duplicate behavior (Q3) unchanged + DEFERRED. Do NOT
   327	attempt to fix the dispatch/mod.rs:238 FabricRedirect desc-branch asymmetry in
   328	#1913 (out of scope; note it for a follow-up). Add an observability counter for
   329	the now-dropped PolicyDenied/HAInactive/DiscardRoute case only if a reviewer
   330	wants it (the per-disposition counters at :2802 already tell the story).
   331	
   332	## 7. Implementation sketch (for the eventual /engineer pass — NOT executed here)
   333	
   334	1. `types/forwarding.rs` (or `tx/dispatch/slow_path.rs`): add
   335	   `pub(in crate::afxdp) const fn is_slow_path_eligible` over the allow-list
   336	   `LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported`, with a
   337	   doc comment stating the drop set (`PolicyDenied | HAInactive | DiscardRoute
   338	   | ForwardCandidate | FabricRedirect`) and WHY each is excluded.
   339	2. `slow_path.rs:90`: replace the inline `matches!` with the predicate (pure
   340	   refactor; no behavior change).
   341	3. `poll_descriptor/mod.rs:2814`: guard the trailing call with the predicate.
   342	   When the predicate is false, the frame is already counted by
   343	   `record_forwarding_disposition` (:2802) and recycled by the
   344	   `recycle_now` epilogue (:2852) — no leak, no double-count. Add a short
   345	   comment referencing #1913 + the eligibility predicate.
   346	4. (optional) bump a dedicated drop counter when the gate suppresses a
   347	   reinject, so the bypass-that-was is observable.
   348	
   349	## 8. Observability / telemetry
   350	
   351	- Today the leak is invisible (generic `slow_path_packets` only). After the
   352	  fix, the suppressed frames are counted via the existing
   353	  `record_forwarding_disposition` per-disposition counters
   354	  (`bump_discard_route`, `policy_deny`, `ha_inactive`) — already wired at
   355	  `:2802`. No NEW metric strictly required.
   356	- Optional: a `slow_path_disposition_filtered` counter to make the
   357	  "would-have-reinjected-but-gated" path explicit. Low value (the disposition
   358	  counters already tell the story); include only if a reviewer wants it.
   359	
   360	## 9. Test plan (for /engineer; describe only)
   361	
   362	Unit (in `userspace-dp/src/afxdp/tests.rs`, alongside the existing
   363	`tunnel_marked_*` tests):
   364	- **T1 (the bug)**: `maybe_reinject_slow_path_from_frame` direct call is NOT
   365	  the unit under test — the gate is at the call site, so add a test exercising
   366	  the predicate: `is_slow_path_eligible(PolicyDenied) == false`,
   367	  `(HAInactive) == false`, `(DiscardRoute) == false`,
   368	  `(LocalDelivery|NoRoute|MissingNeighbor|NextTableUnsupported) == true`,
   369	  `(FabricRedirect|ForwardCandidate) == false`.
   370	- **T2 (wrapper SSOT)**: the wrapper `maybe_reinject_slow_path` with a
   371	  `PolicyDenied` decision still early-returns with no enqueue (regression on
   372	  the existing wrapper filter, now via the shared predicate). Reuse the
   373	  existing wrapper test fixture.
   374	- **T3 (call-site integration)**: harder — exercising the full
   375	  `poll_binding_process_descriptor` PolicyDenied path requires the worker-ctx
   376	  fixture. If feasible, assert `slow_path_packets == 0` and the policy_deny
   377	  disposition counter == 1 for a denied transit frame. If the fixture is too
   378	  heavy, T1+T2 + a focused call-site assertion suffice (the call-site guard is
   379	  a one-line `if`, trivially reviewable).
   380	- **T4 (no regression)**: `dispatch/mod.rs:225` FabricRedirect fallback still
   381	  reinjects (its `_from_frame` path is NOT gated by the predicate). Confirm via
   382	  the existing dispatch tests / add one if absent.
   383	
   384	Build/lint: `make build-userspace-dp`, `cargo test -p` the userspace-dp crate.
   385	
   386	## 10. Smoke / validation (for /engineer)
   387	
   388	- Deploy to `loss:xpf-userspace-fw0/fw1`, install a config with an explicit
   389	  zone-policy DENY for a transit flow, send cold-path packets matching the
   390	  denied flow, and confirm they are NOT forwarded (kernel-side capture on the
   391	  far side shows zero). Before the fix: a trickle leaks. After: zero.
   392	- Standard fast smoke (P12R iperf3 v4/v6 line-rate) to confirm no regression on
   393	  the permitted/forwarded path.
   394	- `make test-failover` is advisable since HAInactive is in scope (the residual-
   395	  HAInactive reinject change could affect standby behavior). Confirm zero-drop
   396	  failover unchanged.
   397	
   398	## 11. Risks & rollback
   399	
   400	- **Risk**: a disposition currently relying on the unfiltered reinject for
   401	  legitimate delivery is now dropped. Mitigation: the allow-list is the
   402	  SAME set the wrapper has used since its introduction; the call-site fix
   403	  merely makes the trailing call match the wrapper's already-shipped contract.
   404	  The only NON-wrapper-aligned site (`dispatch/mod.rs:225`) is explicitly left
   405	  untouched.
   406	- **Risk**: buffered-MissingNeighbor duplicate (§2.5) is untouched by Path A —
   407	  if a reviewer deems the duplicate must also be fixed, that expands scope.
   408	  Recommendation: keep it out of this fix (separate concern, lower severity,
   409	  already documented as the #1901 recovery story).
   410	- **Rollback**: single-call-site guard + a pure-refactor predicate extraction;
   411	  revert is a one-commit `git revert`.
   412	
   413	---
   414	
   415	## Open questions for reviewers (hostile pass) — resolved in r1
   416	
   417	1. §2.2 PolicyDenied→kernel-FIB trace — **CONFIRMED correct** by Codex + AGY +
   418	   Claude SMR (no earlier drop point; the `_from_frame` enqueue reaches the TUN).
   419	2. `tunnel_endpoint_id == 0` for a denied transit flow — confirmed the typical
   420	   case; if a denied flow DID carry a tunnel id, the #1873 gate would drop it
   421	   (counted) — that is the safe direction, so it does not weaken the fix.
   422	3. Altitude — reviewers agreed Path A (call-site gate) is correct PROVIDED the
   423	   `_from_frame` helper is documented as the raw/unchecked primitive (folded
   424	   into Path A step 3 + §6). Filtering inside `_from_frame` (Path B) is fatal
   425	   — breaks TWO load-bearing callers (FabricRedirect-Owned + ForwardCandidate
   426	   build-failure).
   427	4. Buffered-MissingNeighbor duplicate (§2.5 / issue Q3) — **DEFERRED** (not
   428	   fixed by #1913); follow-up at /engineer time if undesirable.
   429	
   430	## Round-1 reviewer findings (Codex + AGY + Claude SMR) — folded into r2
   431	
   432	- **§2.1 table erratum (Codex + AGY):** `ForwardCandidate`/`FabricRedirect` are
   433	  consumed by the forward `if` at mod.rs:1794-1798 and NEVER reach :2814 — they
   434	  were wrongly listed in the `_` arm. CORRECTED.
   435	- **MissingNeighbor SNAT-failure early continues (Codex + AGY):** :2533 and
   436	  :2564 `scratch_recycle.push` + `continue`, skipping :2814 — omitted in r1.
   437	  ADDED to the table.
   438	- **§2.6 over-broad proof (Codex + AGY):** the r1 "the :238 else proves it's
   439	  intentional" framing is wrong — the :238 desc branch calls the FILTERED
   440	  wrapper which DROPS FabricRedirect, an asymmetry/pre-existing bug, not a
   441	  clean bypass. ALSO the `slow_path.rs:61` ForwardCandidate build-failure
   442	  fallback relies on unfiltered `_from_frame`. Both corrected; Path B is fatal
   443	  for BOTH callers.
   444	- **Altitude (Codex + AGY):** document `_from_frame` as the raw/unchecked
   445	  primitive. FOLDED into Path A step 3.
   446	- **F1 (Claude SMR):** DiscardRoute is the cleanest leak proof. ADDED to §2.4.
   447	- **F2 (Claude SMR):** Q3 deferral made explicit. ADDED to §2.5.
   448	- All three reviewers CONFIRMED the core diagnosis (real policy bypass, not
   449	  benign) and the Path C rejection (re-introduces #1885).

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2460,2580p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2460	                                                binding.cold_path.wrapper_ns_baseline;
  2461	                                            let delta_ns = if raw_ns < baseline {
  2462	                                                binding
  2463	                                                    .cold_path
  2464	                                                    .wrapper_underflow_count = binding
  2465	                                                    .cold_path
  2466	                                                    .wrapper_underflow_count
  2467	                                                    .saturating_add(1);
  2468	                                                0
  2469	                                            } else {
  2470	                                                raw_ns - baseline
  2471	                                            };
  2472	                                            // #1635: direct slot map lookup;
  2473	                                            // skip the sample on a miss.
  2474	                                            if let Some(slot) =
  2475	                                                crate::afxdp::cold_path_hist::lookup_slot(
  2476	                                                    &worker_ctx
  2477	                                                        .forwarding
  2478	                                                        .cold_path_slot_map,
  2479	                                                    from_zone_id,
  2480	                                                    to_zone_id,
  2481	                                                )
  2482	                                            {
  2483	                                                binding.cold_path.record_sample(
  2484	                                                    slot,
  2485	                                                    from_zone_id,
  2486	                                                    to_zone_id,
  2487	                                                    delta_ns,
  2488	                                                );
  2489	                                            }
  2490	                                        }
  2491	                                    }
  2492	                                    if permit {
  2493	                                        let nat_match_flow = flow.with_destination(
  2494	                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
  2495	                                        );
  2496	                                        // #1852: gate pool-mode SNAT allocation
  2497	                                        // for a non-first fragment (no L4 ports).
  2498	                                        let snat_non_first_fragment = {
  2499	                                            let l3 = meta.l3_offset as usize;
  2500	                                            l3 <= packet_frame.len()
  2501	                                                && is_non_first_fragment(
  2502	                                                    &packet_frame[l3..],
  2503	                                                    meta.addr_family,
  2504	                                                )
  2505	                                        };
  2506	                                        if pending_decision.nat.rewrite_dst.is_none() {
  2507	                                            match source_nat_decision_for_flow(
  2508	                                                worker_ctx.forwarding,
  2509	                                                &from_zone,
  2510	                                                &to_zone,
  2511	                                                pending_decision.resolution.egress_ifindex,
  2512	                                                &nat_match_flow,
  2513	                                                now_ns,
  2514	                                                snat_non_first_fragment,
  2515	                                            ) {
  2516	                                                Ok(snat_decision) => {
  2517	                                                    pending_decision.nat = snat_decision;
  2518	                                                    source_nat_release_key =
  2519	                                                        Some(nat_match_flow.forward_key.clone());
  2520	                                                }
  2521	                                                Err(failure) => {
  2522	                                                    record_source_nat_failure(
  2523	                                                        telemetry,
  2524	                                                        worker_ctx,
  2525	                                                        meta,
  2526	                                                        flow,
  2527	                                                        from_zone_id,
  2528	                                                        to_zone_id,
  2529	                                                        desc.len,
  2530	                                                        &failure,
  2531	                                                    );
  2532	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2533	                                                    continue;
  2534	                                                }
  2535	                                            }
  2536	                                        } else {
  2537	                                            match source_nat_decision_for_flow(
  2538	                                                worker_ctx.forwarding,
  2539	                                                &from_zone,
  2540	                                                &to_zone,
  2541	                                                pending_decision.resolution.egress_ifindex,
  2542	                                                &nat_match_flow,
  2543	                                                now_ns,
  2544	                                                snat_non_first_fragment,
  2545	                                            ) {
  2546	                                                Ok(snat_decision) => {
  2547	                                                    pending_decision.nat =
  2548	                                                        pending_decision.nat.merge(snat_decision);
  2549	                                                    source_nat_release_key =
  2550	                                                        Some(nat_match_flow.forward_key.clone());
  2551	                                                }
  2552	                                                Err(failure) => {
  2553	                                                    record_source_nat_failure(
  2554	                                                        telemetry,
  2555	                                                        worker_ctx,
  2556	                                                        meta,
  2557	                                                        flow,
  2558	                                                        from_zone_id,
  2559	                                                        to_zone_id,
  2560	                                                        desc.len,
  2561	                                                        &failure,
  2562	                                                    );
  2563	                                                    binding.scratch.scratch_recycle.push(desc.addr);
  2564	                                                    continue;
  2565	                                                }
  2566	                                            }
  2567	                                        }
  2568	                                    }
  2569	                                    let sess_meta = build_missing_neighbor_session_metadata(
  2570	                                        worker_ctx.forwarding,
  2571	                                        from_zone_id,
  2572	                                        to_zone_id,
  2573	                                        packet_fabric_ingress,
  2574	                                        pending_decision,
  2575	                                    );
  2576	                                    let pending_installed =
  2577	                                        sessions.install_with_protocol_with_origin(
  2578	                                            flow.forward_key.clone(),
  2579	                                            pending_decision,
  2580	                                            sess_meta.clone(),

codex
The core source checks line up so far: the forward branch consumes `ForwardCandidate | FabricRedirect`; the SNAT failure paths really `continue`; the desc fallback really calls the filtered wrapper; and build failure really reaches `_from_frame`. I’m doing one more pass for internal inconsistencies in the plan text itself.
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1660,1710p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  1660	                                            telemetry.dbg.session_create += created;
  1661	                                        }
  1662	                                    }
  1663	                                } else {
  1664	                                    emit_policy_deny_event(
  1665	                                        worker_ctx.event_stream,
  1666	                                        flow,
  1667	                                        meta,
  1668	                                        from_zone_id,
  1669	                                        to_zone_id,
  1670	                                        owner_rg_id,
  1671	                                        policy_result.policy_id,
  1672	                                        policy_result.action,
  1673	                                        now_ns,
  1674	                                    );
  1675	                                    telemetry.dbg.policy_deny += 1;
  1676	                                    if cfg!(feature = "debug-log")
  1677	                                        && (telemetry.dbg.policy_deny <= 3 || is_trust_flow)
  1678	                                    {
  1679	                                        debug_log!(
  1680	                                            "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
  1681	                                            telemetry.dbg.policy_deny,
  1682	                                            flow.src_ip,
  1683	                                            flow.forward_key.src_port,
  1684	                                            flow.dst_ip,
  1685	                                            flow.forward_key.dst_port,
  1686	                                            meta.protocol,
  1687	                                            from_zone,
  1688	                                            to_zone,
  1689	                                            meta.ingress_ifindex,
  1690	                                            resolution.egress_ifindex,
  1691	                                        );
  1692	                                    }
  1693	                                    decision.resolution.disposition =
  1694	                                        ForwardingDisposition::PolicyDenied;
  1695	                                }
  1696	                            } else if decision.resolution.disposition
  1697	                                == ForwardingDisposition::HAInactive
  1698	                                && !packet_fabric_ingress
  1699	                            {
  1700	                                let owner_rg_id =
  1701	                                    owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
  1702	                                if owner_rg_id > 0 {
  1703	                                    flow_cache_owner_rg_id = owner_rg_id;
  1704	                                }
  1705	                                // New flow to inactive RG: fabric-redirect to the peer
  1706	                                // that owns the egress RG.  Use from_zone_arc directly
  1707	                                // (always in scope) rather than going through the debug
  1708	                                // struct which may not have been populated.
  1709	                                // #919/#922: ID-keyed redirect — no name lookup.
  1710	                                if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_stages.rs | sed -n '430,470p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   430	    worker_ctx: &WorkerContext,
   431	) -> StageOutcome<()> {
   432	    let Some(flow) = flow else {
   433	        return StageOutcome::Continue(());
   434	    };
   435	    if !is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
   436	        return StageOutcome::Continue(());
   437	    }
   438	    let ipsec_decision = SessionDecision {
   439	        resolution: ForwardingResolution {
   440	            disposition: ForwardingDisposition::LocalDelivery,
   441	            local_ifindex: 0,
   442	            egress_ifindex: 0,
   443	            tx_ifindex: 0,
   444	            tunnel_endpoint_id: 0,
   445	            next_hop: None,
   446	            neighbor_mac: None,
   447	            src_mac: None,
   448	            tx_vlan_id: 0,
   449	        },
   450	        nat: NatDecision::default(),
   451	    };
   452	    maybe_reinject_slow_path_from_frame(
   453	        &worker_ctx.ident,
   454	        binding_live,
   455	        worker_ctx.slow_path,
   456	        worker_ctx.local_tunnel_deliveries,
   457	        packet_frame,
   458	        meta,
   459	        ipsec_decision,
   460	        worker_ctx.recent_exceptions,
   461	        "slow_path",
   462	        worker_ctx.forwarding,
   463	    );
   464	    StageOutcome::RecycleAndContinue
   465	}
   466	
   467	#[cfg(test)]
   468	mod tests {
   469	    use super::*;
   470	    use crate::event_stream::DataplaneEventRateLimitConfig;

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/umem/mod.rs | sed -n '920,965p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   920	        self.cos_active_flow_counts.store(Arc::new(rows));
   921	    }
   922	
   923	    pub(in crate::afxdp) fn cos_active_flow_counts_snapshot(
   924	        &self,
   925	    ) -> Vec<crate::protocol::CoSActiveFlowCountStatus> {
   926	        self.cos_active_flow_counts.load().as_ref().clone()
   927	    }
   928	
   929	    pub(super) fn clear_error(&self) {
   930	        if let Ok(mut err) = self.last_error.lock() {
   931	            err.clear();
   932	        }
   933	    }
   934	
   935	    pub(super) fn set_error(&self, msg: String) {
   936	        if let Ok(mut err) = self.last_error.lock() {
   937	            *err = msg;
   938	        }
   939	    }
   940	
   941	    pub(super) fn record_slow_path_accept(
   942	        &self,
   943	        disposition: ForwardingDisposition,
   944	        reason: &str,
   945	        packet_len: u64,
   946	    ) {
   947	        self.slow_path_packets.fetch_add(1, Ordering::Relaxed);
   948	        self.slow_path_bytes
   949	            .fetch_add(packet_len, Ordering::Relaxed);
   950	        if reason == "forward_build_slow_path" {
   951	            self.slow_path_forward_build_packets
   952	                .fetch_add(1, Ordering::Relaxed);
   953	            return;
   954	        }
   955	        match disposition {
   956	            ForwardingDisposition::LocalDelivery => {
   957	                self.slow_path_local_delivery_packets
   958	                    .fetch_add(1, Ordering::Relaxed);
   959	            }
   960	            ForwardingDisposition::MissingNeighbor => {
   961	                self.slow_path_missing_neighbor_packets
   962	                    .fetch_add(1, Ordering::Relaxed);
   963	            }
   964	            ForwardingDisposition::NoRoute => {
   965	                self.slow_path_no_route_packets

exec
/bin/bash -lc "rg -n \"maybe_reinject_slow_path_from_frame\\(|maybe_reinject_slow_path\\(\" userspace-dp/src/afxdp" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814:                        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:225:                    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:238:                    maybe_reinject_slow_path(
userspace-dp/src/afxdp/tests.rs:4163:    maybe_reinject_slow_path(
userspace-dp/src/afxdp/tests.rs:4224:    maybe_reinject_slow_path(
userspace-dp/src/afxdp/tests.rs:4287:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tests.rs:5371:        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tests.rs:5441:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:61:        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:78:pub(in crate::afxdp) fn maybe_reinject_slow_path(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:113:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:129:pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/poll_stages.rs:452:    maybe_reinject_slow_path_from_frame(

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2580,2865p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2580	                                            sess_meta.clone(),
  2581	                                            SessionOrigin::MissingNeighborSeed,
  2582	                                            now_ns,
  2583	                                            meta.protocol,
  2584	                                            meta.tcp_flags,
  2585	                                        );
  2586	                                    if pending_installed {
  2587	                                        let entry = SyncedSessionEntry {
  2588	                                            key: flow.forward_key.clone(),
  2589	                                            decision: pending_decision,
  2590	                                            metadata: sess_meta,
  2591	                                            origin: SessionOrigin::MissingNeighborSeed,
  2592	                                            protocol: meta.protocol,
  2593	                                            tcp_flags: meta.tcp_flags,
  2594	                                        };
  2595	                                        publish_shared_session(
  2596	                                            worker_ctx.shared_sessions,
  2597	                                            worker_ctx.shared_nat_sessions,
  2598	                                            worker_ctx.shared_forward_wire_sessions,
  2599	                                            &worker_ctx.shared_owner_rg_indexes,
  2600	                                            &entry,
  2601	                                        );
  2602	                                        // #1789: count a failed publish
  2603	                                        // (shim misses the key -> NO_SESSION
  2604	                                        // degraded path for the seeded flow).
  2605	                                        if publish_session_map_entry_for_session(
  2606	                                            binding.bpf_maps.session_map_fd,
  2607	                                            &flow.forward_key,
  2608	                                            pending_decision,
  2609	                                            &entry.metadata,
  2610	                                        )
  2611	                                        .is_err()
  2612	                                        {
  2613	                                            binding
  2614	                                                .live
  2615	                                                .session_publish_errors
  2616	                                                .fetch_add(1, Ordering::Relaxed);
  2617	                                        }
  2618	                                        publish_bpf_conntrack_entry(
  2619	                                            conntrack_v4_fd,
  2620	                                            conntrack_v6_fd,
  2621	                                            &flow.forward_key,
  2622	                                            pending_decision,
  2623	                                            &entry.metadata,
  2624	                                            &worker_ctx.forwarding.zone_name_to_id,
  2625	                                        );
  2626	                                        publish_dnat_table_entry(
  2627	                                            &worker_ctx.dnat_fds,
  2628	                                            &flow.forward_key,
  2629	                                            pending_decision.nat,
  2630	                                        );
  2631	                                        telemetry.counters.session_creates += 1;
  2632	                                    } else {
  2633	                                        // #1861 §5.3: at-cap seed refusal. The
  2634	                                        // single-entry install IS the
  2635	                                        // transaction here (no pair); the
  2636	                                        // refusal is counted by the table's
  2637	                                        // create_drops (exported since #1861 —
  2638	                                        // admission_refused stays preflight-
  2639	                                        // only). Roll back the SNAT allocation
  2640	                                        // and drop the frame instead of
  2641	                                        // buffering it for replay.
  2642	                                        seed_install_refused = true;
  2643	                                        rollback_source_nat_allocation(
  2644	                                            &worker_ctx.forwarding.source_nat_rules,
  2645	                                            source_nat_release_key
  2646	                                                .as_ref()
  2647	                                                .unwrap_or(&flow.forward_key),
  2648	                                            pending_decision.nat,
  2649	                                            false,
  2650	                                            now_ns,
  2651	                                        );
  2652	                                    }
  2653	                                }
  2654	                                // Buffer the packet. The ICMP probe resolves ARP
  2655	                                // in ~1ms. The retry loop below re-forwards the
  2656	                                // buffered packet once the neighbor resolves via the
  2657	                                // netlink monitor. The session was already created
  2658	                                // above so the SYN-ACK reverse path works too.
  2659	                                // Total latency: ~2ms (ARP + netlink + retry).
  2660	                                //
  2661	                                // NOTE: we do NOT reinject to slow-path here because
  2662	                                // kernel ARP resolution via XDP_PASS breaks VLAN demux
  2663	                                // in zero-copy mode (mlx5). The ICMP probe + netlink
  2664	                                // monitor + buffer-retry path bypasses this issue.
  2665	                                // #1771 §2.2: buffer one representative packet
  2666	                                // per (egress_ifindex, next_hop). Keep the
  2667	                                // OLDEST (it drives the probe/dwell clock):
  2668	                                // a duplicate for an already-buffered hop is
  2669	                                // dropped+recycled (recycle_now stays true),
  2670	                                // pinning ≤1 UMEM frame per unresolved hop.
  2671	                                // A packet with no next_hop cannot be keyed or
  2672	                                // resolved (the retry sweep needs next_hop to
  2673	                                // look up a MAC), so it is not buffered —
  2674	                                // recycled instead of held until timeout.
  2675	                                // #1861 §5.3: a refused seed is recycled, not
  2676	                                // buffered (see seed_install_refused above) —
  2677	                                // the kernel ARP probe already fired, and the
  2678	                                // next packet retries the install once the
  2679	                                // table has room, converging with the #1771
  2680	                                // duplicate-drop semantics.
  2681	                                // #1873 R-E: tunnel-marked decisions are
  2682	                                // NEVER admitted to pending_neigh. The retry
  2683	                                // path TXes buffered frames via in-place
  2684	                                // MAC/VLAN rewrite with no encapsulation, so
  2685	                                // a buffered tunnel inner packet would go out
  2686	                                // PLAINTEXT on the physical wire when the
  2687	                                // outer neighbor resolves (AGY plan r2,
  2688	                                // verified). The kernel ARP/ICMP probe above
  2689	                                // already fired, and the post-match
  2690	                                // maybe_reinject_slow_path_from_frame call
  2691	                                // routes this frame into the R-C tunnel gate
  2692	                                // (counted drop) — the #1769 resolver keeps
  2693	                                // driving the outer next-hop, and the flow
  2694	                                // recovers via retransmission once resolved.
  2695	                                // #1902 (sibling of #1885): a GRE-DECAPPED
  2696	                                // packet is NEVER admitted to pending_neigh.
  2697	                                // `desc` still references the un-decapped
  2698	                                // OUTER UMEM frame while `meta`/the decision
  2699	                                // describe the synthetic INNER frame in
  2700	                                // `owned_packet_frame`; the retry path's
  2701	                                // rewrite_forwarded_frame_in_place(pkt.desc,
  2702	                                // pkt.meta, ..) would MAC/NAT/TTL-rewrite the
  2703	                                // still-encapsulated outer packet at inner
  2704	                                // offsets and TX it toward the inner next-hop
  2705	                                // — a corrupt transmit, not a drop. The
  2706	                                // kernel ARP/ICMP probe above already fired,
  2707	                                // the trailing decap-aware
  2708	                                // maybe_reinject_slow_path_from_frame
  2709	                                // chokepoint (#1901) still hands the
  2710	                                // correctly-paired INNER packet to the kernel
  2711	                                // slow path, and the #1769 resolver +
  2712	                                // retransmission recover the flow once the
  2713	                                // neighbor resolves. Counted per binding so
  2714	                                // the live gate is observable
  2715	                                // (xpf_userspace_pending_neigh_decap_drops_total).
  2716	                                if !seed_install_refused
  2717	                                    && pending_decision.resolution.tunnel_endpoint_id == 0
  2718	                                    && pending_decision.resolution.next_hop.is_some()
  2719	                                    && owned_packet_frame.is_some()
  2720	                                {
  2721	                                    binding
  2722	                                        .live
  2723	                                        .pending_neigh_decap_drops
  2724	                                        .fetch_add(1, Ordering::Relaxed);
  2725	                                } else if !seed_install_refused
  2726	                                    && pending_decision.resolution.tunnel_endpoint_id == 0
  2727	                                    && let Some(hop) = pending_decision.resolution.next_hop
  2728	                                {
  2729	                                    let pending_key =
  2730	                                        (pending_decision.resolution.egress_ifindex, hop);
  2731	                                    // #1782: split the buffer-admission test so
  2732	                                    // the capture can tell WHY a sibling was not
  2733	                                    // buffered. The DuplicateDrop branch is the
  2734	                                    // H5 sibling drop (key already pending — the
  2735	                                    // first packet drove the kernel probe); the
  2736	                                    // CapacityDrop branch is a distinct
  2737	                                    // condition, counted nowhere here. #1771
  2738	                                    // §2.4: the decision is the pure
  2739	                                    // `pending_neigh_admission` helper so
  2740	                                    // invariant N1's "at most one buffered
  2741	                                    // packet per key" half is unit-tested;
  2742	                                    // behavior is unchanged — an insert happens
  2743	                                    // iff the key is absent AND there is room,
  2744	                                    // otherwise `recycle_now` stays true and
  2745	                                    // the frame is recycled.
  2746	                                    match pending_neigh_admission(
  2747	                                        binding.pending_neigh.contains_key(&pending_key),
  2748	                                        binding.pending_neigh.len(),
  2749	                                    ) {
  2750	                                        PendingNeighAdmission::DuplicateDrop => {
  2751	                                            binding
  2752	                                                .live
  2753	                                                .pending_neigh_duplicate_drops
  2754	                                                .fetch_add(1, Ordering::Relaxed);
  2755	                                        }
  2756	                                        PendingNeighAdmission::Buffer => {
  2757	                                            let pending_flow_key = flow
  2758	                                                .as_ref()
  2759	                                                .map(|flow| flow.forward_key.clone())
  2760	                                                .or_else(|| {
  2761	                                                    parse_session_flow_from_meta(meta)
  2762	                                                        .map(|flow| flow.forward_key)
  2763	                                                });
  2764	                                            binding.pending_neigh.insert(
  2765	                                                pending_key,
  2766	                                                PendingNeighPacket {
  2767	                                                    addr: desc.addr,
  2768	                                                    desc,
  2769	                                                    meta,
  2770	                                                    decision: pending_decision,
  2771	                                                    flow_key: pending_flow_key,
  2772	                                                    queued_ns: now_ns,
  2773	                                                    probe_attempts: 0,
  2774	                                                },
  2775	                                            );
  2776	                                            recycle_now = false;
  2777	                                        }
  2778	                                        PendingNeighAdmission::CapacityDrop => {}
  2779	                                    }
  2780	                                }
  2781	                                if cfg!(feature = "debug-log") {
  2782	                                    if telemetry.dbg.missing_neigh <= 3 {
  2783	                                        if let Some(flow) = flow.as_ref() {
  2784	                                            eprintln!(
  2785	                                                "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
  2786	                                                "SOLICIT+SLOW",
  2787	                                                flow.src_ip,
  2788	                                                flow.forward_key.src_port,
  2789	                                                flow.dst_ip,
  2790	                                                flow.forward_key.dst_port,
  2791	                                                meta.protocol,
  2792	                                                pending_decision.resolution.egress_ifindex,
  2793	                                                pending_decision.resolution.next_hop,
  2794	                                            );
  2795	                                        }
  2796	                                    }
  2797	                                }
  2798	                            }
  2799	                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
  2800	                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
  2801	                            _ => telemetry.dbg.disposition_other += 1,
  2802	                        }
  2803	                        record_forwarding_disposition(
  2804	                            &worker_ctx.ident,
  2805	                            DispositionCounters::Hot(telemetry.counters),
  2806	                            decision.resolution,
  2807	                            desc.len as u32,
  2808	                            Some(meta),
  2809	                            debug.as_ref(),
  2810	                            worker_ctx.recent_exceptions,
  2811	                            worker_ctx.last_resolution,
  2812	                            worker_ctx.forwarding,
  2813	                        );
  2814	                        maybe_reinject_slow_path_from_frame(
  2815	                            &worker_ctx.ident,
  2816	                            &binding.live,
  2817	                            worker_ctx.slow_path,
  2818	                            worker_ctx.local_tunnel_deliveries,
  2819	                            packet_frame,
  2820	                            meta,
  2821	                            decision,
  2822	                            worker_ctx.recent_exceptions,
  2823	                            "slow_path",
  2824	                            worker_ctx.forwarding,
  2825	                        );
  2826	                    }
  2827	                } else {
  2828	                    record_disposition(
  2829	                        &worker_ctx.ident,
  2830	                        &binding.live,
  2831	                        DispositionCounters::Hot(telemetry.counters),
  2832	                        disposition,
  2833	                        desc.len as u32,
  2834	                        Some(meta),
  2835	                        worker_ctx.recent_exceptions,
  2836	                        worker_ctx.forwarding,
  2837	                    );
  2838	                }
  2839	            } else {
  2840	                telemetry.dbg.metadata_err += 1;
  2841	                binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
  2842	                record_exception(
  2843	                    worker_ctx.recent_exceptions,
  2844	                    &worker_ctx.ident,
  2845	                    "metadata_parse",
  2846	                    desc.len as u32,
  2847	                    None,
  2848	                    None,
  2849	                    worker_ctx.forwarding,
  2850	                );
  2851	            }
  2852	            if recycle_now {
  2853	                binding.scratch.scratch_recycle.push(desc.addr);
  2854	            }
  2855	        }
  2856	        received.release();
  2857	        drop(received);
  2858	}

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2220,2310p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2220	                                // negatively cached + un-expired, recycle the
  2221	                                // frame immediately.
  2222	                                if let Some(next_hop) = decision.resolution.next_hop {
  2223	                                    let neg_key =
  2224	                                        (decision.resolution.egress_ifindex, next_hop);
  2225	                                    // neg_neigh_gate runs the resolved-wins
  2226	                                    // probe (static neighbors THEN dynamic,
  2227	                                    // same order as retry_pending_neigh /
  2228	                                    // lookup_neighbor_entry) and the TTL check.
  2229	                                    // Returns true ⇒ fast-fail this packet.
  2230	                                    let fast_fail = neg_neigh_gate(
  2231	                                        &mut binding.neg_neigh_cache,
  2232	                                        &neg_key,
  2233	                                        now_ns,
  2234	                                        || {
  2235	                                            worker_ctx
  2236	                                                .forwarding
  2237	                                                .neighbors
  2238	                                                .contains_key(&neg_key)
  2239	                                                || worker_ctx
  2240	                                                    .dynamic_neighbors
  2241	                                                    .get(&neg_key)
  2242	                                                    .is_some()
  2243	                                        },
  2244	                                    );
  2245	                                    if fast_fail {
  2246	                                        telemetry.dbg.neg_neigh_fast_fail += 1;
  2247	                                        // #1782: promote the debug counter to a
  2248	                                        // real per-binding atomic so the
  2249	                                        // cold-start capture can read it from
  2250	                                        // Prometheus. Single Relaxed fetch_add
  2251	                                        // on the existing discard path — no new
  2252	                                        // hot-path work, no behavior change.
  2253	                                        binding
  2254	                                            .live
  2255	                                            .neg_neigh_fast_fail
  2256	                                            .fetch_add(1, Ordering::Relaxed);
  2257	                                        // #1769: the negative gate suppresses
  2258	                                        // the probe + buffer below, so a dst
  2259	                                        // that lost its dynamic entry (transient
  2260	                                        // FAILED/DELNEIGH or a dropped good
  2261	                                        // RTM_NEWNEIGH) would blackhole for the
  2262	                                        // full 3s TTL with nothing nudging it
  2263	                                        // back. Route it through the shared
  2264	                                        // resolver: a single-key RTM_GETNEIGH
  2265	                                        // off the hot path caches a confirmed
  2266	                                        // REACHABLE/PERMANENT lladdr (epoch-
  2267	                                        // guarded) or probes to force kernel
  2268	                                        // revalidation on a DELAY/STALE one.
  2269	                                        // Per-key rate-limited in the resolver
  2270	                                        // thread, so a SYN storm fires at most
  2271	                                        // one GET/probe per key per window. The
  2272	                                        // hot path only pays a non-blocking
  2273	                                        // try_send here (not per-packet — this
  2274	                                        // arm fires only on the negative fast-
  2275	                                        // fail).
  2276	                                        if let Some(resolver) =
  2277	                                            worker_ctx.neighbor_resolver
  2278	                                        {
  2279	                                            // Per-binding throttle: only
  2280	                                            // clone the iface name +
  2281	                                            // try_send once per key per
  2282	                                            // RESOLVER_ENQUEUE_THROTTLE_NS
  2283	                                            // so a dead-host SYN storm does
  2284	                                            // NOT allocate per fast-failed
  2285	                                            // packet (the resolver coalesces
  2286	                                            // per-key anyway). The cheap
  2287	                                            // (i32, IpAddr) map check runs
  2288	                                            // before any clone.
  2289	                                            let throttled = matches!(
  2290	                                                binding
  2291	                                                    .resolver_enqueue_throttle
  2292	                                                    .get(&neg_key),
  2293	                                                Some(&t) if now_ns.saturating_sub(t)
  2294	                                                    < RESOLVER_ENQUEUE_THROTTLE_NS
  2295	                                            );
  2296	                                            if !throttled {
  2297	                                                if let Some(name) = worker_ctx
  2298	                                                    .forwarding
  2299	                                                    .ifindex_to_name
  2300	                                                    .get(&neg_key.0)
  2301	                                                {
  2302	                                                    resolver.enqueue(
  2303	                                                        neg_key.0,
  2304	                                                        neg_key.1,
  2305	                                                        name.clone(),
  2306	                                                    );
  2307	                                                    // Bound the throttle
  2308	                                                    // map like the negative
  2309	                                                    // cache: a /24 scan
  2310	                                                    // touches <=254 keys, so

exec
/bin/bash -lc "rg -n \"enum ForwardingDisposition|ForwardingDisposition::DiscardRoute|DiscardRoute|NextTableUnsupported\" userspace-dp/src -g '*.rs'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/event_stream/codec_tests.rs:447:    assert_eq!(encode_disposition(ForwardingDisposition::DiscardRoute), 7);
userspace-dp/src/event_stream/codec_tests.rs:449:        encode_disposition(ForwardingDisposition::NextTableUnsupported),
userspace-dp/src/event_stream/codec.rs:621:        ForwardingDisposition::DiscardRoute => DISP_DISCARD_ROUTE,
userspace-dp/src/event_stream/codec.rs:622:        ForwardingDisposition::NextTableUnsupported => DISP_NEXT_TABLE_UNSUPPORTED,
userspace-dp/src/afxdp/types/forwarding.rs:242:pub(crate) enum ForwardingDisposition {
userspace-dp/src/afxdp/types/forwarding.rs:250:    DiscardRoute,
userspace-dp/src/afxdp/types/forwarding.rs:251:    NextTableUnsupported,
userspace-dp/src/afxdp/types/forwarding.rs:282:    ///   - `DiscardRoute`: Matched a discard/reject route. Not cacheable for
userspace-dp/src/afxdp/types/forwarding.rs:284:    ///   - `NextTableUnsupported`: Inter-VRF route leaking hit an
userspace-dp/src/afxdp/types/forwarding.rs:322:                ForwardingDisposition::DiscardRoute => "discard_route",
userspace-dp/src/afxdp/types/forwarding.rs:323:                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
userspace-dp/src/afxdp/disposition.rs:389:        ForwardingDisposition::DiscardRoute => {
userspace-dp/src/afxdp/disposition.rs:402:        ForwardingDisposition::NextTableUnsupported => {
userspace-dp/src/afxdp/session_delta.rs:97:                ForwardingDisposition::DiscardRoute => "discard_route",
userspace-dp/src/afxdp/session_delta.rs:98:                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
userspace-dp/src/afxdp/forwarding/mod.rs:1215:            disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/mod.rs:1279:                    disposition: ForwardingDisposition::DiscardRoute,
userspace-dp/src/afxdp/forwarding/mod.rs:1293:                        disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/mod.rs:1363:            disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/mod.rs:1427:                    disposition: ForwardingDisposition::DiscardRoute,
userspace-dp/src/afxdp/forwarding/mod.rs:1441:                        disposition: ForwardingDisposition::NextTableUnsupported,
userspace-dp/src/afxdp/forwarding/tests.rs:1154:            disposition: ForwardingDisposition::DiscardRoute,
userspace-dp/src/afxdp/forwarding/tests.rs:2245:        ForwardingDisposition::NextTableUnsupported
userspace-dp/src/afxdp/icmp_embed/builders.rs:247:/// local resolution turned into HAInactive/NoRoute/DiscardRoute.
userspace-dp/src/afxdp/icmp_embed/builders.rs:263:                | ForwardingDisposition::DiscardRoute
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:96:            | ForwardingDisposition::NextTableUnsupported
userspace-dp/src/afxdp/umem/mod.rs:968:            ForwardingDisposition::NextTableUnsupported => {

exec
/bin/bash -lc 'rg -n "intentional|ForwardCandidate|FabricRedirect|catch-all|covers|raw/unchecked|unchecked|Path A|Path B|scope|out of scope" docs/research/1913-fromframe-filter/plan.md' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
18:`PolicyDenied`, `HAInactive`, and a `_` catch-all (which covers `DiscardRoute`,
19:`ForwardCandidate`, `FabricRedirect`, `NextTableUnsupported`).
45:ForwardCandidate | FabricRedirect)` — so **`ForwardCandidate` and
46:`FabricRedirect` are consumed by the forward `if` and NEVER enter the `else`
63:| `_` catch-all (:2801) | no | covers **`DiscardRoute`** (✗ NOT in allow-list — LEAK), plus `NextTableUnsupported` (✅ in allow-list). `ForwardCandidate`/`FabricRedirect` do NOT reach here (consumed at :1794-1798). |
118:`HAInactive` into `FabricRedirect` whenever `owner_rg_for_resolution > 0`. A
129:`:1427`) lands in the `_` catch-all and is reinjected to the kernel FIB
138:partial mitigation) there is no plausible "intentional" reading — a discard
139:route's entire purpose is to drop. Path A fixes PolicyDenied, HAInactive, and
153:duplicate is currently **intentional/known** for the recovery story, but the
156:HAInactive/DiscardRoute. The plan addresses it explicitly (see §5 Path A
159:**Explicit scope statement (Claude SMR r1, F2):** Path A keeps
172:- `tx/dispatch/mod.rs:225` ("no XSK binding" fallback — passes `FabricRedirect`
180:1. **`dispatch/mod.rs:225` — FabricRedirect, Owned-frame fallback.** Guarded by
181:   `if request.decision.resolution.disposition == FabricRedirect` (:223) AND
184:   `FabricRedirect` via unfiltered `_from_frame`. (Codex + AGY r1, verified.)
185:2. **`handle_forward_build_failure` → `slow_path.rs:61` — ForwardCandidate
189:   a `ForwardCandidate` decision (Codex r1, verified). `ForwardCandidate` is
194:intentional." That is over-stated and partly wrong. The `:238` `else` branch
196:which REJECTS `FabricRedirect` → the desc-frame `FabricRedirect` fallback is
197:**silently dropped today**. So dispatch/mod.rs treats `FabricRedirect`
199:**pre-existing inconsistency** (likely a latent bug), NOT a clean "intentional
205:> break BOTH the `dispatch/mod.rs:225` FabricRedirect-Owned fallback AND the
206:> `slow_path.rs:61` ForwardCandidate build-failure fallback (neither
208:> `_from_frame`" option (Path B). The fix belongs at the `mod.rs:2814` call
210:> should be explicitly documented as the RAW/unchecked primitive whose callers
211:> own the eligibility decision (altitude fix, see Path A + §6).
226:- Preserve the existing intentional `_from_frame` bypass at
227:  `dispatch/mod.rs:225` (FabricRedirect fallback) and the IPsec LocalDelivery
243:### Path A — gate at the call site (mod.rs:2814) via a shared predicate (RECOMMENDED)
261:   `maybe_reinject_slow_path_from_frame` stating it is the RAW/unchecked
264:   (the two intentional/legacy bypass sites: `dispatch/mod.rs:225`
265:   FabricRedirect-Owned fallback and `slow_path.rs:61` ForwardCandidate
277:  allow-list, so the §2.5 duplicate behavior is UNCHANGED by Path A. Sub-
285:### Path B — filter inside `_from_frame` (REJECTED)
290:- **Cons / FATAL**: breaks BOTH `dispatch/mod.rs:225` (FabricRedirect-Owned
292:  (ForwardCandidate build-failure fallback) — neither disposition is in the
311:### Path D — document-only ("intentional")
313:Conclude the unfiltered behavior is intentional and just add comments.
316:  forwarded). Not intentional, not benign. **Rejected.**
320:**Path A.** Shared `const fn`/enum-method predicate, gate at the `mod.rs:2814`
323:FabricRedirect-Owned fallback; `slow_path.rs:61` ForwardCandidate
327:attempt to fix the dispatch/mod.rs:238 FabricRedirect desc-branch asymmetry in
328:#1913 (out of scope; note it for a follow-up). Add an observability counter for
338:   | ForwardCandidate | FabricRedirect`) and WHY each is excluded.
369:  `(FabricRedirect|ForwardCandidate) == false`.
380:- **T4 (no regression)**: `dispatch/mod.rs:225` FabricRedirect fallback still
394:- `make test-failover` is advisable since HAInactive is in scope (the residual-
406:- **Risk**: buffered-MissingNeighbor duplicate (§2.5) is untouched by Path A —
407:  if a reviewer deems the duplicate must also be fixed, that expands scope.
422:3. Altitude — reviewers agreed Path A (call-site gate) is correct PROVIDED the
423:   `_from_frame` helper is documented as the raw/unchecked primitive (folded
424:   into Path A step 3 + §6). Filtering inside `_from_frame` (Path B) is fatal
425:   — breaks TWO load-bearing callers (FabricRedirect-Owned + ForwardCandidate
432:- **§2.1 table erratum (Codex + AGY):** `ForwardCandidate`/`FabricRedirect` are
439:  intentional" framing is wrong — the :238 desc branch calls the FILTERED
440:  wrapper which DROPS FabricRedirect, an asymmetry/pre-existing bug, not a
441:  clean bypass. ALSO the `slow_path.rs:61` ForwardCandidate build-failure
442:  fallback relies on unfiltered `_from_frame`. Both corrected; Path B is fatal
444:- **Altitude (Codex + AGY):** document `_from_frame` as the raw/unchecked
445:  primitive. FOLDED into Path A step 3.

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/umem/mod.rs | sed -n '955,980p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   955	        match disposition {
   956	            ForwardingDisposition::LocalDelivery => {
   957	                self.slow_path_local_delivery_packets
   958	                    .fetch_add(1, Ordering::Relaxed);
   959	            }
   960	            ForwardingDisposition::MissingNeighbor => {
   961	                self.slow_path_missing_neighbor_packets
   962	                    .fetch_add(1, Ordering::Relaxed);
   963	            }
   964	            ForwardingDisposition::NoRoute => {
   965	                self.slow_path_no_route_packets
   966	                    .fetch_add(1, Ordering::Relaxed);
   967	            }
   968	            ForwardingDisposition::NextTableUnsupported => {
   969	                self.slow_path_next_table_packets
   970	                    .fetch_add(1, Ordering::Relaxed);
   971	            }
   972	            _ => {}
   973	        }
   974	    }
   975	
   976	
   977	    pub(super) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
   978	        self.push_redirect_inbox(req);
   979	        Ok(())
   980	    }

codex
One possible wording problem remains in the problem statement: it still says the catch-all “covers” `ForwardCandidate`/`FabricRedirect`. I’m treating that as syntactic match coverage unless it conflicts with the actual recommendation; the §2.1 reachability correction itself is explicit and correct.
exec
/bin/bash -lc 'rg -n "maybe_reinject_slow_path|handle_forward_build_failure|extract_l3_packet|slow_path::" userspace-dp/src/afxdp/tx/dispatch/mod.rs userspace-dp/src/afxdp/poll_descriptor/mod.rs userspace-dp/src/afxdp/poll_stages.rs' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
userspace-dp/src/afxdp/poll_stages.rs:452:    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2163:                                // leg (`maybe_reinject_slow_path_from_frame`
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2166:                                // `maybe_reinject_slow_path` here, pairing
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2690:                                // maybe_reinject_slow_path_from_frame call
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2708:                                // maybe_reinject_slow_path_from_frame
userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814:                        maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:14:// - `slow_path`       — handle_forward_build_failure,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:15://                       maybe_reinject_slow_path*,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:16://                       extract_l3_packet* family. All marked
userspace-dp/src/afxdp/tx/dispatch/mod.rs:54:pub(in crate::afxdp) use slow_path::{
userspace-dp/src/afxdp/tx/dispatch/mod.rs:55:    extract_l3_packet_with_nat, handle_forward_build_failure, maybe_reinject_slow_path,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:56:    maybe_reinject_slow_path_from_frame,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:59:// extract_l3_packet[_from_frame] family; the re-export keeps the
userspace-dp/src/afxdp/tx/dispatch/mod.rs:61:pub(in crate::afxdp::tx) use slow_path::{extract_l3_packet, extract_l3_packet_from_frame};
userspace-dp/src/afxdp/tx/dispatch/mod.rs:225:                    maybe_reinject_slow_path_from_frame(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:238:                    maybe_reinject_slow_path(
userspace-dp/src/afxdp/tx/dispatch/mod.rs:887:            handle_forward_build_failure(

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/tx/dispatch/mod.rs | sed -n '1,80p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
     1	// Dispatch module (#1443). Pure code-motion split of the original
     2	// 1474-LOC `dispatch.rs` into cohesive submodules:
     3	//
     4	// - `cos`             — Phase 1 (CoS TX-selection resolve) +
     5	//                       the COS fast-path helpers
     6	//                       (cos_queue_fast_path_for_request,
     7	//                        cos_owner_live_for_request,
     8	//                        request_runs_under_shared_exact_policy,
     9	//                        enqueue_local_request_to_target_or_owner).
    10	// - `shared_recycle`  — Phase 10 + cross-tick recycle routing
    11	//                       (apply_shared_recycles*,
    12	//                        resolve_tx_binding_ifindex,
    13	//                        and the slot-resolution helpers).
    14	// - `slow_path`       — handle_forward_build_failure,
    15	//                       maybe_reinject_slow_path*,
    16	//                       extract_l3_packet* family. All marked
    17	//                       #[cold] #[inline(never)] per AGY round-2
    18	//                       finding D.
    19	//
    20	// The orchestrator (`enqueue_pending_forwards`) and Phase 8
    21	// (try_inplace_rewrite_or_build) intentionally stay in `mod.rs` for
    22	// this PR — Phase 8 body extraction is deferred to a follow-up so
    23	// reviewers can compare the in-tree control flow against current
    24	// master without a body-shape diff. See plan.md §"Out of scope".
    25	//
    26	// External callers reach the re-exported symbols via the
    27	// `use self::tx::dispatch::*;` glob at `afxdp/mod.rs:140`. The
    28	// re-export block below preserves every `pub(in crate::afxdp)`
    29	// symbol verbatim.
    30	
    31	use super::*;
    32	
    33	use super::tcp_segmentation::segment_forwarded_tcp_frames_into_prepared;
    34	
    35	mod cos;
    36	mod shared_recycle;
    37	mod slow_path;
    38	
    39	use cos::{
    40	    cos_owner_live_for_request, enqueue_local_request_to_target_or_owner,
    41	    pending_forward_needs_cos_tx_selection, request_runs_under_shared_exact_policy,
    42	    resolve_pending_forward_cos_tx_selection,
    43	};
    44	pub(in crate::afxdp) use shared_recycle::{
    45	    apply_shared_recycles, apply_shared_recycles_to_bindings, resolve_tx_binding_ifindex,
    46	};
    47	// Test-only access to internal shared_recycle helpers from
    48	// dispatch_tests.rs (which is `mod tests` under this `mod.rs`).
    49	#[cfg(test)]
    50	use shared_recycle::{
    51	    record_shared_recycle_unknown_slot_drops, shared_recycle_target_index,
    52	    shared_recycle_target_index_for_split,
    53	};
    54	pub(in crate::afxdp) use slow_path::{
    55	    extract_l3_packet_with_nat, handle_forward_build_failure, maybe_reinject_slow_path,
    56	    maybe_reinject_slow_path_from_frame,
    57	};
    58	// pub(in crate::afxdp::tx) was previously pub(super) on the
    59	// extract_l3_packet[_from_frame] family; the re-export keeps the
    60	// pre-split sibling-tx/ visibility verbatim.
    61	pub(in crate::afxdp::tx) use slow_path::{extract_l3_packet, extract_l3_packet_from_frame};
    62	
    63	#[inline]
    64	fn recycle_ingress_frame(ingress_binding: &mut BindingWorker, source_offset: u64, now_ns: u64) {
    65	    ingress_binding
    66	        .tx_pipeline
    67	        .pending_fill_frames
    68	        .push_back(source_offset);
    69	    if ingress_binding.tx_pipeline.pending_fill_frames.len() >= FILL_BATCH_SIZE {
    70	        let _ = drain_pending_fill(ingress_binding, now_ns);
    71	    }
    72	}
    73	
    74	pub(in crate::afxdp) fn enqueue_pending_forwards(
    75	    left: &mut [BindingWorker],
    76	    ingress_index: usize,
    77	    ingress_binding: &mut BindingWorker,
    78	    right: &mut [BindingWorker],
    79	    binding_lookup: &WorkerBindingLookup,
    80	    mirror_targets: &MirrorTargetMap,

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/types/forwarding.rs | sed -n '230,330p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
   230	}
   231	
   232	#[derive(Clone, Copy, Debug, PartialEq)]
   233	pub(in crate::afxdp) struct FabricLink {
   234	    pub(in crate::afxdp) parent_ifindex: i32,
   235	    pub(in crate::afxdp) overlay_ifindex: i32,
   236	    pub(in crate::afxdp) peer_addr: IpAddr,
   237	    pub(in crate::afxdp) peer_mac: [u8; 6],
   238	    pub(in crate::afxdp) local_mac: [u8; 6],
   239	}
   240	
   241	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
   242	pub(crate) enum ForwardingDisposition {
   243	    LocalDelivery,
   244	    ForwardCandidate,
   245	    FabricRedirect,
   246	    HAInactive,
   247	    PolicyDenied,
   248	    NoRoute,
   249	    MissingNeighbor,
   250	    DiscardRoute,
   251	    NextTableUnsupported,
   252	}
   253	
   254	impl ForwardingDisposition {
   255	    /// Whether this disposition produces a stable forwarding decision that can
   256	    /// be stored in the per-worker flow cache.
   257	    ///
   258	    /// Cacheable:
   259	    ///   - `ForwardCandidate`: Normal forwarded traffic with a resolved
   260	    ///     neighbor and egress interface. The common fast path.
   261	    ///   - `FabricRedirect`: Targets a fabric overlay binding. Cacheable
   262	    ///     because each cache entry captures the owning RG epoch into
   263	    ///     `FlowCacheStamp::owner_rg_epoch` at insert time
   264	    ///     (`flow_cache.rs:60-83`), and `FlowCache::lookup`
   265	    ///     (`flow_cache.rs:314-347`) treats the entry as a miss when
   266	    ///     `current_epoch != entry.stamp.owner_rg_epoch`. The owning RG
   267	    ///     bumps its epoch on every active/standby flip, so the window
   268	    ///     in which a cached `FabricRedirect` could point at a stale
   269	    ///     fabric peer is bounded by the next RG epoch bump (#1065).
   270	    ///
   271	    /// Not cacheable:
   272	    ///   - `LocalDelivery`: Delivered to the kernel stack, not forwarded
   273	    ///     through XSK bindings. No rewrite descriptor to cache.
   274	    ///   - `HAInactive`: The owning RG is not active on this node. Transient
   275	    ///     state that changes on failover — must never be cached.
   276	    ///   - `PolicyDenied`: Packet was denied by policy. Drop decisions are
   277	    ///     not cached to allow policy changes to take effect immediately.
   278	    ///   - `NoRoute`: No route to destination. Transient — may resolve when
   279	    ///     FIB is updated.
   280	    ///   - `MissingNeighbor`: Route exists but ARP/NDP is unresolved.
   281	    ///     Transient — resolves when the neighbor entry appears.
   282	    ///   - `DiscardRoute`: Matched a discard/reject route. Not cacheable for
   283	    ///     the same reason as PolicyDenied.
   284	    ///   - `NextTableUnsupported`: Inter-VRF route leaking hit an
   285	    ///     unsupported next-table. Permanent miss, not worth caching.
   286	    pub(in crate::afxdp) fn is_cacheable(self) -> bool {
   287	        matches!(
   288	            self,
   289	            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
   290	        )
   291	    }
   292	}
   293	
   294	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
   295	pub(crate) struct ForwardingResolution {
   296	    pub(crate) disposition: ForwardingDisposition,
   297	    pub(crate) local_ifindex: i32,
   298	    pub(crate) egress_ifindex: i32,
   299	    pub(crate) tx_ifindex: i32,
   300	    pub(crate) tunnel_endpoint_id: u16,
   301	    pub(crate) next_hop: Option<IpAddr>,
   302	    pub(crate) neighbor_mac: Option<[u8; 6]>,
   303	    pub(crate) src_mac: Option<[u8; 6]>,
   304	    pub(crate) tx_vlan_id: u16,
   305	}
   306	
   307	impl ForwardingResolution {
   308	    pub(in crate::afxdp) fn status(
   309	        self,
   310	        debug: Option<&ResolutionDebug>,
   311	        forwarding: &ForwardingState,
   312	    ) -> PacketResolution {
   313	        PacketResolution {
   314	            disposition: match self.disposition {
   315	                ForwardingDisposition::LocalDelivery => "local_delivery",
   316	                ForwardingDisposition::ForwardCandidate => "forward_candidate",
   317	                ForwardingDisposition::FabricRedirect => "fabric_redirect",
   318	                ForwardingDisposition::HAInactive => "ha_inactive",
   319	                ForwardingDisposition::PolicyDenied => "policy_denied",
   320	                ForwardingDisposition::NoRoute => "no_route",
   321	                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
   322	                ForwardingDisposition::DiscardRoute => "discard_route",
   323	                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
   324	            }
   325	            .to_string(),
   326	            local_ifindex: self.local_ifindex,
   327	            egress_ifindex: self.egress_ifindex,
   328	            ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
   329	            next_hop: self.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
   330	            neighbor_mac: self.neighbor_mac.map(format_mac).unwrap_or_default(),

exec
/bin/bash -lc 'rg -n "ForwardingDisposition|maybe_reinject_slow_path_from_frame|tx::dispatch" userspace-dp/src/afxdp/poll_descriptor/mod.rs | head -40' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
347:                                == ForwardingDisposition::LocalDelivery
385:                                ForwardingDisposition::ForwardCandidate
811:                            if resolution.disposition == ForwardingDisposition::LocalDelivery
826:                            if resolution.disposition == ForwardingDisposition::LocalDelivery
1025:                                == ForwardingDisposition::ForwardCandidate
1267:                                            != ForwardingDisposition::LocalDelivery
1694:                                        ForwardingDisposition::PolicyDenied;
1697:                                == ForwardingDisposition::HAInactive
1739:                            == ForwardingDisposition::HAInactive
1762:                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
1796:                        ForwardingDisposition::ForwardCandidate
1797:                            | ForwardingDisposition::FabricRedirect
2157:                            ForwardingDisposition::LocalDelivery => {
2163:                                // leg (`maybe_reinject_slow_path_from_frame`
2186:                            ForwardingDisposition::NoRoute => {
2204:                            ForwardingDisposition::MissingNeighbor => {
2690:                                // maybe_reinject_slow_path_from_frame call
2708:                                // maybe_reinject_slow_path_from_frame
2799:                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
2800:                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
2814:                        maybe_reinject_slow_path_from_frame(

codex
The MissingNeighbor table is directionally correct for the original finding, but it compresses several subpaths. I’m checking whether any omitted subpath changes the selected fix or just belongs as non-blocking detail.
exec
/bin/bash -lc 'rg -n "continue;|recycle_now = false|PendingNeighAdmission|seed_install_refused|fast_fail|MissingNeighbor" userspace-dp/src/afxdp/poll_descriptor/mod.rs' in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
110:                        continue;
119:                        continue;
171:                            continue;
185:                            continue;
199:                        continue;
343:                                    continue;
375:                                continue;
404:                                    continue;
423:                                    continue;
437:                                    continue;
516:                                    continue;
627:                                continue;
824:                                continue;
973:                                                recycle_now = false;
1194:                                                    continue;
1224:                                                    continue;
1253:                                        recycle_now = false;
1307:                                            continue;
1350:                                            continue;
2095:                            recycle_now = false;
2204:                            ForwardingDisposition::MissingNeighbor => {
2207:                                // the very top of the MissingNeighbor arm,
2211:                                // creates a MissingNeighborSeed session.
2230:                                    let fast_fail = neg_neigh_gate(
2245:                                    if fast_fail {
2246:                                        telemetry.dbg.neg_neigh_fast_fail += 1;
2255:                                            .neg_neigh_fast_fail
2341:                                        continue;
2414:                                let mut seed_install_refused = false;
2533:                                                    continue;
2564:                                                    continue;
2581:                                            SessionOrigin::MissingNeighborSeed,
2591:                                            origin: SessionOrigin::MissingNeighborSeed,
2642:                                        seed_install_refused = true;
2676:                                // buffered (see seed_install_refused above) —
2716:                                if !seed_install_refused
2725:                                } else if !seed_install_refused
2750:                                        PendingNeighAdmission::DuplicateDrop => {
2756:                                        PendingNeighAdmission::Buffer => {
2776:                                            recycle_now = false;
2778:                                        PendingNeighAdmission::CapacityDrop => {}

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '2308,2460p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  2308	                                                    // map like the negative
  2309	                                                    // cache: a /24 scan
  2310	                                                    // touches <=254 keys, so
  2311	                                                    // clear wholesale past
  2312	                                                    // the cap (best-effort —
  2313	                                                    // losing throttle for a
  2314	                                                    // few keys only risks one
  2315	                                                    // extra clone).
  2316	                                                    if binding
  2317	                                                        .resolver_enqueue_throttle
  2318	                                                        .len()
  2319	                                                        >= MAX_NEG_NEIGH_CACHE
  2320	                                                        && !binding
  2321	                                                            .resolver_enqueue_throttle
  2322	                                                            .contains_key(&neg_key)
  2323	                                                    {
  2324	                                                        binding
  2325	                                                            .resolver_enqueue_throttle
  2326	                                                            .clear();
  2327	                                                    }
  2328	                                                    binding
  2329	                                                        .resolver_enqueue_throttle
  2330	                                                        .insert(neg_key, now_ns);
  2331	                                                }
  2332	                                            }
  2333	                                        }
  2334	                                        // Fresh RX descriptor → recycle via
  2335	                                        // scratch_recycle + continue, matching
  2336	                                        // the source-NAT-failure discard
  2337	                                        // pattern. The continue skips the
  2338	                                        // recycle_now epilogue and the
  2339	                                        // session-seed/buffer below.
  2340	                                        binding.scratch.scratch_recycle.push(desc.addr);
  2341	                                        continue;
  2342	                                    }
  2343	                                }
  2344	                                // #919/#922: zero-allocation ID-native resolution.
  2345	                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
  2346	                                    worker_ctx.forwarding,
  2347	                                    meta.ingress_ifindex as i32,
  2348	                                    ingress_zone_override,
  2349	                                    decision.resolution.egress_ifindex,
  2350	                                );
  2351	                                // Borrow zone names as &str (no clone) for the
  2352	                                // string-typed downstream NAT helpers.
  2353	                                let from_zone: &str = worker_ctx
  2354	                                    .forwarding
  2355	                                    .zone_id_to_name
  2356	                                    .get(&from_zone_id)
  2357	                                    .map(|s| s.as_str())
  2358	                                    .unwrap_or("");
  2359	                                let to_zone: &str = worker_ctx
  2360	                                    .forwarding
  2361	                                    .zone_id_to_name
  2362	                                    .get(&to_zone_id)
  2363	                                    .map(|s| s.as_str())
  2364	                                    .unwrap_or("");
  2365	                                // Send ARP/NDP solicitation via RAW socket (not XSK)
  2366	                                // so the reply goes through the kernel's normal RX
  2367	                                // path (cpumap_or_pass), bypassing XSK fill ring issues.
  2368	                                // Also reinject original packet to slow-path for kernel
  2369	                                // to forward once the neighbor is resolved.
  2370	                                // Trigger ARP/NDP resolution via kernel netlink.
  2371	                                // Adding an INCOMPLETE neighbor entry makes the
  2372	                                // kernel send its own ARP/NDP solicitation through
  2373	                                // the normal stack, which correctly handles VLAN
  2374	                                // tagging and TX offload. The netlink monitor then
  2375	                                // picks up the resolved entry instantly.
  2376	                                if let Some(next_hop) = decision.resolution.next_hop {
  2377	                                    // Only spawn ping if we don't already have a
  2378	                                    // pending probe for this (ifindex, hop).
  2379	                                    // #1771 §2.2: pending_neigh is keyed by
  2380	                                    // (egress_ifindex, next_hop), so the
  2381	                                    // "already probing this hop" dedup is a
  2382	                                    // direct contains_key (was an O(n) iter scan).
  2383	                                    let already_probing = binding.pending_neigh.contains_key(&(
  2384	                                        decision.resolution.egress_ifindex,
  2385	                                        next_hop,
  2386	                                    ));
  2387	                                    if !already_probing {
  2388	                                        let iface_name = worker_ctx.forwarding
  2389	                                            .ifindex_to_name
  2390	                                            .get(&decision.resolution.egress_ifindex)
  2391	                                            .cloned();
  2392	                                        if let Some(name) = iface_name {
  2393	                                            // Fast path: ICMP socket triggers kernel ARP
  2394	                                            // in microseconds (no fork/exec).
  2395	                                            trigger_kernel_arp_probe(&name, next_hop);
  2396	                                        }
  2397	                                    }
  2398	                                }
  2399	                                // Create the session NOW so the SYN-ACK (reverse
  2400	                                // direction) finds the forward NAT match and creates
  2401	                                // a reverse session. Without this, the SYN-ACK hits
  2402	                                // session miss → policy deny (no rule for WAN→LAN).
  2403	                                let mut pending_decision = decision;
  2404	                                let mut source_nat_release_key = None;
  2405	                                // #1861 §5.3: true when the seed install was
  2406	                                // ATTEMPTED and refused (max_sessions). Gates
  2407	                                // the pending-neighbor buffering below: a
  2408	                                // refused seed's SNAT allocation was rolled
  2409	                                // back, so replaying the buffered frame after
  2410	                                // neighbor resolution would forward it on an
  2411	                                // unreserved NAT tuple with no session. Flow-
  2412	                                // less packets (no install attempted) keep
  2413	                                // buffering as before.
  2414	                                let mut seed_install_refused = false;
  2415	                                if let Some(flow) = flow.as_ref() {
  2416	                                    // #1620: cold-path histogram pre-eval gate
  2417	                                    // (session-install slow path). Per plan v4
  2418	                                    // §4.4: scoped &mut borrow ends before eval.
  2419	                                    let (cp_sample_tag, cp_t_in) = {
  2420	                                        let cp = &mut binding.cold_path;
  2421	                                        cp.sample_phase =
  2422	                                            cp.sample_phase.wrapping_add(1);
  2423	                                        let tag = (cp.sample_phase
  2424	                                            & worker_ctx.cold_path_sample_mask)
  2425	                                            == 0;
  2426	                                        let t = if tag {
  2427	                                            crate::afxdp::cold_path_hist::sample_tsc_start()
  2428	                                        } else {
  2429	                                            0
  2430	                                        };
  2431	                                        (tag, t)
  2432	                                    };
  2433	                                    let permit = matches!(
  2434	                                        evaluate_policy_with_len(
  2435	                                            &worker_ctx.forwarding.policy,
  2436	                                            from_zone_id,
  2437	                                            to_zone_id,
  2438	                                            flow.src_ip,
  2439	                                            flow.dst_ip,
  2440	                                            flow.forward_key.protocol,
  2441	                                            flow.forward_key.src_port,
  2442	                                            flow.forward_key.dst_port,
  2443	                                            desc.len as u64,
  2444	                                        ),
  2445	                                        PolicyAction::Permit
  2446	                                    );
  2447	                                    // #1620: cold-path histogram post-eval record.
  2448	                                    if cp_sample_tag {
  2449	                                        let t_out =
  2450	                                            crate::afxdp::cold_path_hist::sample_tsc_end();
  2451	                                        let q32 = binding.cold_path.ns_per_tsc_q32;
  2452	                                        if q32 != 0 {
  2453	                                            let delta_tsc =
  2454	                                                t_out.saturating_sub(cp_t_in);
  2455	                                            let raw_ns = ((delta_tsc as u128
  2456	                                                * q32 as u128)
  2457	                                                >> 32)
  2458	                                                as u64;
  2459	                                            let baseline =
  2460	                                                binding.cold_path.wrapper_ns_baseline;

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/poll_descriptor/mod.rs | sed -n '1710,1765p'" in /home/ps/git/bpfrx/.claude/worktrees/1913-research-fromframe-filter
 succeeded in 0ms:
  1710	                                if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
  1711	                                    worker_ctx.forwarding,
  1712	                                    from_zone_id,
  1713	                                )
  1714	                                .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
  1715	                                {
  1716	                                    decision.resolution = redirect;
  1717	                                }
  1718	                            }
  1719	                            decision
  1720	                        }
  1721	                    } else {
  1722	                        let non_flow_resolution = enforce_ha_resolution_snapshot(
  1723	                            worker_ctx.forwarding,
  1724	                            worker_ctx.ha_state,
  1725	                            now_secs,
  1726	                            resolve_forwarding(
  1727	                                // SAFETY: per the `area` contract in this
  1728	                                // function's header comment.
  1729	                                unsafe { &*area },
  1730	                                desc,
  1731	                                meta,
  1732	                                worker_ctx.forwarding,
  1733	                                worker_ctx.dynamic_neighbors,
  1734	                            ),
  1735	                        );
  1736	                        // For non-flow packets (no L4 ports), also attempt fabric
  1737	                        // redirect when the egress RG is inactive.
  1738	                        let final_resolution = if non_flow_resolution.disposition
  1739	                            == ForwardingDisposition::HAInactive
  1740	                            && !packet_fabric_ingress
  1741	                        {
  1742	                            resolve_fabric_redirect(worker_ctx.forwarding).unwrap_or(non_flow_resolution)
  1743	                        } else {
  1744	                            non_flow_resolution
  1745	                        };
  1746	                        SessionDecision {
  1747	                            resolution: final_resolution,
  1748	                            nat: NatDecision::default(),
  1749	                        }
  1750	                    };
  1751	                    // Safety net: convert any remaining HAInactive to fabric
  1752	                    // redirect. Session-hit and new-flow paths each attempt
  1753	                    // fabric redirect internally, but demoted sessions that
  1754	                    // arrive via DNAT/interface-NAT XDP shim paths can slip
  1755	                    // through with HAInactive when the inner conversion found
  1756	                    // no fabric link at the time. Anti-loop: never redirect
  1757	                    // packets that arrived on the fabric interface itself.
  1758	                    // Only redirect when the egress maps to a known RG.
  1759	                    // HAInactive with unknown ownership (rg=0) means unresolved
  1760	                    // — those should NOT be fabric-redirected.
  1761	                    let egress_rg = owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
  1762	                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
  1763	                        && egress_rg > 0
  1764	                        && !packet_fabric_ingress
  1765	                    {

codex
VERDICT: PLAN-READY

No blocking defects found in r2. The r1 corrections landed and match source.

1. §2.1 erratum fixed:
Plan now says: “`ForwardCandidate` and `FabricRedirect` are consumed by the forward `if` and NEVER enter the `else` block” and table says they “do NOT reach here.” Source confirms `mod.rs:1794-1798` matches `ForwardCandidate | FabricRedirect` before the `else`.

2. MissingNeighbor SNAT continues fixed:
Plan now says SNAT allocation failures `scratch_recycle.push` + `continue` at “`:2533 and :2564`.” Source confirms both continue paths.

3. §2.6 over-broad proof fixed:
Plan now says the `dispatch/mod.rs:238` desc branch calls the “FILTERED wrapper” and “silently dropped today,” not a clean intentional bypass. It also adds the `slow_path.rs:61` `ForwardCandidate` build-failure fallback as load-bearing. Source confirms both.

4. Altitude fixed:
Path A step 3 says `_from_frame` must be documented as “RAW/unchecked” and §6 repeats that callers own eligibility.

The recommendation is now coherent: shared predicate, wrapper refactor to that predicate, gate only the `mod.rs:2814` trailing call, and leave `dispatch/mod.rs:225`, `slow_path.rs:61`, and the `:238` asymmetry untouched/out of scope.

Only non-blocking nit: the problem statement still says the catch-all “covers” `ForwardCandidate`/`FabricRedirect`; §2.1 immediately corrects this as unreachable, so I’m not treating it as plan-blocking.
tokens used
59,240
VERDICT: PLAN-READY

No blocking defects found in r2. The r1 corrections landed and match source.

1. §2.1 erratum fixed:
Plan now says: “`ForwardCandidate` and `FabricRedirect` are consumed by the forward `if` and NEVER enter the `else` block” and table says they “do NOT reach here.” Source confirms `mod.rs:1794-1798` matches `ForwardCandidate | FabricRedirect` before the `else`.

2. MissingNeighbor SNAT continues fixed:
Plan now says SNAT allocation failures `scratch_recycle.push` + `continue` at “`:2533 and :2564`.” Source confirms both continue paths.

3. §2.6 over-broad proof fixed:
Plan now says the `dispatch/mod.rs:238` desc branch calls the “FILTERED wrapper” and “silently dropped today,” not a clean intentional bypass. It also adds the `slow_path.rs:61` `ForwardCandidate` build-failure fallback as load-bearing. Source confirms both.

4. Altitude fixed:
Path A step 3 says `_from_frame` must be documented as “RAW/unchecked” and §6 repeats that callers own eligibility.

The recommendation is now coherent: shared predicate, wrapper refactor to that predicate, gate only the `mod.rs:2814` trailing call, and leave `dispatch/mod.rs:225`, `slow_path.rs:61`, and the `:238` asymmetry untouched/out of scope.

Only non-blocking nit: the problem statement still says the catch-all “covers” `ForwardCandidate`/`FabricRedirect`; §2.1 immediately corrects this as unreachable, so I’m not treating it as plan-blocking.
