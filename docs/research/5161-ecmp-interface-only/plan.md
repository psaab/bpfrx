# Plan of Action — #5161: interface-only ECMP members starve to width-1

**Status:** PLAN-READY (awaiting manual approval — `/engineer 5161`)
**Research branch:** `research/5161-ecmp-interface-only` (docs only, off `origin/master` @ `a2c7d42d7`)
**Reviews:** Claude SMR (hostile) — see `claude-smr-plan-r1.md`. Codex/AGY: attempt; if infra-blocked, SMR-only (1-of-3, documented).
**Classification:** BOUNDED-after-redesign. The original "add interface-only members to the coordinator warmer" framing is **infeasible** (see §2); this plan centers on a **reactive cold-path bootstrap-probe** that reuses the existing rate-limited resolver.

---

## 1. Problem statement (defect)

An ECMP static route with **interface-only** members (`next_hop == None`, `ifindex > 0`,
`tunnel_endpoint_id == 0` — Junos `route X/Y next-hop <interface>`) permanently
collapses to **ECMP width 1**: after the first member's neighbor resolves, the
unresolved interface-only sibling(s) are never selected and never warmed, so
path-diversity / warm-failover is broken for the life of the route.

**Invariant broken:** ECMP path-diversity + warm-failover for supported
interface-only static ECMP routes.

## 2. Root-cause analysis (file:line, `origin/master` @ a2c7d42d7)

Two independent facts combine into the starvation:

1. **Selection is per-destination and collapses to one member.**
   `select_route_next_hop` (`userspace-dp/src/afxdp/forwarding/mod.rs:2811`) collects the
   *live* members and picks one; if any are live it never returns a non-live one.
   The non-tunnel `is_live` closure (v4 `forwarding/mod.rs:2165-2182`, v6 `~2378-2392`)
   evaluates an interface-only member's liveness as:
   ```rust
   let target = nh.next_hop.unwrap_or(ip);   // ip == the PACKET destination
   nh.ifindex > 0 && lookup_neighbor_entry(state, dyn, nh.ifindex, target).is_some()
   ```
   So an interface-only member is "live for destination D" **iff the neighbor
   `(ifindex, D)` is resolved** — a *per-destination* property.

2. **The coordinator warmer only warms explicit-next_hop members.**
   `coordinator/mod.rs:806-817` (v4) and `:818-829` (v6) iterate the route
   **snapshot** and enqueue only `(ifindex, hop)` where `hop = nh.next_hop`:
   ```rust
   if let Some(hop) = nh.next_hop { enqueue(nh.ifindex, IpAddr::V4(hop)); }  // no else
   ```
   Interface-only members (`next_hop == None`) are silently skipped.

**Why the warmer *cannot* be the fix.** The warmer operates on route **prefixes** and
has **no packet destination**. An interface-only member's neighbor key is
`(ifindex, D)` where D is a live traffic destination, not a static route field.
For a prefix route the warmer cannot enumerate destinations, so it can only ever
warm degenerate host routes (/32, /128) — not the general prefix-ECMP case the
invariant covers. **The warmer is architecturally the wrong place.**

**The starvation trace.** On the first packet to D, the live set is empty, so
`select_route_next_hop` falls to the non-live `candidates.get(pick)` branch
(`forwarding/mod.rs:2828`) and picks *one* member. If that member is
interface-only, the resolution is `MissingNeighbor`, and the poll path's
MissingNeighbor arm enqueues a resolve for `(ifindex, D)` via `try_enqueue_resolver`
(`poll_descriptor/mod.rs:4994` / `:5120`). That **one** member warms. Once it is
live, the live set is non-empty forever, so `select_route_next_hop` only ever
returns *that* member — the sibling is never picked, never reaches the
MissingNeighbor arm, and is never warmed. **Permanent width-1.**

## 3. Goals / non-goals

**Goals**
- Interface-only ECMP members converge to *live* for the destinations traffic
  actually uses, so ECMP width for those destinations reaches the count of
  **on-link** interface-only members (plus any explicit-next_hop members).
- Reuse the existing rate-limited resolver; **no new scheduler**, no wire/HA
  protocol change, no hot-path allocation.
- v4 and v6 parity.

**Non-goals**
- No change to *data-plane selection* semantics: DATA still forwards only via
  **resolved** members (never stall on an unresolved sibling).
- No warming of **point-to-point / off-link** interface-only members (there is no
  L2 neighbor to resolve — probing would ARP forever; see §6.3). These keep
  today's kernel-FIB slow-path behavior.
- No warmer change for the general case (the warmer stays as-is; see §2).
- No new config surface.

**Applicability boundary (SMR F1 — read before marking #5161 "fully fixed").**
The starvation this fix removes is specific to the **on-link** interface-only
subset — e.g. `route 10.0.0.0/24 next-hop [ ge-A ge-B ]` where A and B are both on
the 10.0.0.0/24 segment, so `(ifindex, D)` can ARP-resolve. The classic
`route 0.0.0.0/0 next-hop [ uplinkA uplinkB ]` over two uplinks is **off-link**
for an arbitrary internet D: `(ifindex, D)` can never resolve, so those members
were **already never fast-path-live** under current code (they ride the
kernel-FIB / MissingNeighbor slow path) — not a width-1 fast-path regression, and
**not addressed by this fix by design**. #5161 should be closed as "on-link
interface-only ECMP warms to full width"; off-link interface-only ECMP is a
separate (kernel-FIB) path and out of scope.

## 4. Options considered

| # | Option | Verdict |
|---|--------|---------|
| A | Extend the **coordinator warmer** to enqueue interface-only members | **Rejected** — warmer has no destination (§2); only helps /32,/128. |
| B | In `is_live`, treat unresolved interface-only members as *selectable* so the existing MissingNeighbor→resolver path warms them | **Rejected** — that stalls DATA on the unresolved member (drops/slow-paths a packet a live sibling could forward); violates "select data from resolved". |
| C | Add the sibling list to `ForwardingResolution` and probe from the caller | **Rejected** — a per-resolution `Vec`/`SmallVec` on the hot-path struct violates the no-hot-path-alloc rule. |
| **D** | **Reactive cold-path bootstrap-probe**: on the poll COLD path (session-miss) for an ECMP transit forward, enqueue rate-limited `(ifindex, D)` resolves for unresolved **on-link** interface-only siblings via the existing `try_enqueue_resolver` | **RECOMMENDED** |

## 5. Recommended design (Option D)

Two additive pieces plus a behavior-preserving extraction:

### 5.1 Shared candidate-resolution helper (the sibling-enumeration seam)

Extract the "prefix-match + next-table recursion → terminal Static route" prefix
of `lookup_forwarding_resolution_v{4,6}_inner` into a shared, pure helper, e.g.:

```rust
// Returns the terminal route's ECMP candidate slice + the terminal table,
// following next-table recursion with the SAME canonicalization + visited-cycle
// guard the resolver already uses. None => no route / discard / next-table-unsupported.
fn resolve_terminal_route_candidates_v4<'a>(
    state: &'a ForwardingState, ip: Ipv4Addr, table: &str,
    depth: u32, visited: &mut Vec<String>,
) -> Option<(&'a [RouteNextHopV4], /*terminal table*/ &'a str)>
```

`lookup_forwarding_resolution_v4_inner` calls this to obtain `route.next_hops`
(behavior-preserving code motion — the ECMP `select_route_next_hop` call is
unchanged), and the new probe collector (§5.2) calls the **same** helper. This
is the decisive choice over a stand-alone re-walk: a second copy of the
prefix-match + next-table recursion **will drift** and silently reintroduce the
bug for next-table / VRF routes. One source of truth eliminates that class.

**Fallback:** if the extraction proves too invasive to keep behavior-preserving
(e.g., borrow-checker friction with `visited`), fall back to a read-only
cold-path re-walk `ecmp_interface_only_probe_targets` that duplicates *only* the
prefix-match + next-table recursion — but the extraction is preferred and should
be attempted first, gated by the parent-RED + full forwarding suite (§8).

### 5.2 Probe-target collector (read-only, cold-path only)

```rust
// Cold-path only. Returns the (ifindex, dst) keys to warm so unresolved,
// ON-LINK, interface-only ECMP siblings for `dst` join the live set.
// Empty unless the route is ECMP (>1 candidate) with >=1 such sibling.
fn ecmp_interface_only_probe_targets_v4(
    state: &ForwardingState, dyn: &SharedNeighbors, dst: Ipv4Addr, table: &str,
) -> SmallVec<[(i32, IpAddr); 4]>
```

Filter each candidate to: `next_hop.is_none() && tunnel_endpoint_id == 0 &&
ifindex > 0` AND unresolved (`lookup_neighbor_entry(ifindex, dst).is_none()`) AND
**on-link** (§6.3). Skip the ECMP-degenerate case (≤1 candidate) so single-member
routes produce nothing.

### 5.3 Cold-path wiring

At the poll transit-forward session-miss site (`poll_descriptor/mod.rs:2056`,
where `lookup_forwarding_resolution_in_table_with_dynamic` is already called for
the cold path), after the resolution is computed and the flow is permitted by
policy, call the collector and loop:
```rust
for (ifidx, d) in ecmp_interface_only_probe_targets_v{4,6}(...) {
    try_enqueue_resolver(resolver, &mut binding.resolver_enqueue_throttle,
                         &fwd.ifindex_to_name, (ifidx, d), now_ns);
}
```
`resolver` = `worker_ctx.neighbor_resolver` (already used at `:4994/:5120`);
`binding.resolver_enqueue_throttle` bounds it to one probe per `(ifindex,dst)`
per `RESOLVER_ENQUEUE_THROTTLE_NS` (100 ms, `neighbor_resolver.rs:103`). DATA for
this packet still forwards via the selected **resolved** member (unchanged).

This runs on **both** the ForwardCandidate and MissingNeighbor cold-path arms
(a live sibling was selected in the ForwardCandidate case — that is exactly the
starvation case, so the probe must fire there), ×v4/v6.

## 6. Design-question resolutions (each explicit, per contract)

### 6.1 Sibling-enumeration seam — refactor vs re-walk → **refactor (§5.1)**
One source of truth; a duplicated recursive walk drifts and reintroduces the
next-table/VRF bug. Behavior-preserving code motion, gated by parent-RED + the
full forwarding suite. Re-walk is the documented fallback only.

### 6.2 Per-destination ECMP-width semantics
Width for interface-only members is **inherently per-destination**: member M is
live-for-D iff `(M.ifindex, D)` is resolved. The fix drives *all on-link*
interface-only members to live for the destinations traffic uses; the **first**
packet to a *new* D may still be width-1 until the sibling's `(ifindex, D)`
resolves (bounded by resolver latency + the 100 ms throttle). Tests assert
width-2 **for a specific D** after both resolve; docs state the per-destination,
eventually-converges contract explicitly (§7 docs). **Per-flow stickiness (SMR
F5):** width-2 is a property of the *selector* / **new** flows — an already
installed session for D stays pinned to its original member; the warmed sibling
carries new flows that miss after it resolves. Docs must not imply existing flows
rebalance.

### 6.3 On-link vs point-to-point member gate (**critical** — no ARP-forever)
A point-to-point / off-link interface-only member has **no L2 neighbor** for D;
probing `(ifindex, D)` would never resolve and would ARP forever. Gate: probe a
member **only if** its `ifindex` has a **connected route** (in the terminal
table) whose prefix **contains D** — i.e., D is genuinely on-link on that member.
Reuses `ConnectedRouteV{4,6} { prefix, ifindex, table }`
(`types/forwarding.rs:565`); the connected vec is a cheap cold-path linear scan
(one entry per interface address, per its own doc comment). Off-link members are
left to today's kernel-FIB slow path (unchanged). **Note (correctness win):**
under today's code a p2p interface-only member is *never* live anyway (no
neighbor), so this gate changes nothing for them — it only prevents a new storm.

### 6.4 Interaction with `neg_neigh_gate`, the resolver throttle, and pending_neigh
The sibling probe is a **pure warm** — it enqueues a resolve and returns; it does
**not** buffer the DATA packet in `pending_neigh` and does not touch the
negative-neighbor cache (`neg_neigh_gate`) or its buffering timeout. Rate-limiting
is solely the existing `resolver_enqueue_throttle` (100 ms / key), with the same
`MAX_NEG_NEIGH_CACHE` wholesale-clear bound the current resolver enqueue uses, so
a destination scan is bounded identically to the existing MissingNeighbor path.

### 6.5 RG gating
Mirror the warmer's gate (`coordinator/mod.rs:746-753`,
`owner_rg_for_flow(egress_ifindex)` forwarding-active): only probe a sibling whose
owning RG is forwarding-active on this node. The poll cold path already only
forwards locally-owned flows, so this is mostly inherited; the explicit gate
prevents probing a sibling on a standby RG in a mixed-RG ECMP group (waste, not
incorrectness). /engineer to confirm the poll site has the RG runtime in scope
(it does for the warmer; verify at the poll site).

### 6.6 Host-route vs prefix scope
The fix is destination-driven, so it covers **both** /32-/128 host routes and
prefix routes uniformly (the collector keys on the actual D). No special-casing.

### 6.7 Probe-on-every-cold-miss vs only-on-ECMP-with-unresolved-sibling
Collector returns empty unless the route is ECMP (>1 candidate) **and** has ≥1
unresolved on-link interface-only member. Combined with the 100 ms per-key
throttle, steady-state and single-member routes incur **zero** extra probes; a
converged ECMP group incurs zero (all resolved → empty). Only an
actively-unconverged interface-only ECMP group probes, ≤1/key/100 ms.

## 7. Implementation plan (files, phases) — for /engineer

1. **Extract** `resolve_terminal_route_candidates_v{4,6}` from
   `lookup_forwarding_resolution_v{4,6}_inner` (`forwarding/mod.rs`); prove
   behavior-preserving via the full existing forwarding suite + a parent-RED.
   **Do this as an ISOLATED code-motion commit** (sole diff = extraction, zero
   logic change) so a reviewer can eyeball behavior-preservation (SMR F2).
   **Optimization option (SMR F4):** to avoid a second cold-path route walk (the
   resolution already walks it once), a cold-path resolution variant returning
   `(resolution, Option<&[candidates]>)` in one pass is acceptable — but keep the
   fast path (`lookup_forwarding_resolution_v{4,6}_inner`) allocation-free and
   unchanged in behavior.
2. **Add** `ecmp_interface_only_probe_targets_v{4,6}` + the on-link gate helper
   (`forwarding/mod.rs`), read-only, cold-path.
3. **Wire** the collector into the poll cold-path forward sites
   (`poll_descriptor/mod.rs` ~2056 + the ForwardCandidate/MissingNeighbor arms),
   reusing `try_enqueue_resolver` + `binding.resolver_enqueue_throttle`, ×v4/v6,
   with the §6.5 RG gate.
4. **Docs:** update the routing/ECMP module doc (candidate: `docs/multi-wan.md`
   or a routing README section) with the interface-only-member warm contract +
   the per-destination-convergence semantics (§6.2) + the on-link gate (§6.3).
5. **Tests:** §8.

**Estimated surface:** ~1 extracted helper + 2 collector fns + 1 gate helper + 2
poll call sites (v4/v6) + tests + doc. Moderate; core-resolver touch is the risk
(mitigated by parent-RED + full suite + smoke).

## 8. Test plan (fail-on-revert)

**Unit (collector, no ring/poll):** build a forwarding state with an ECMP route
whose 2 interface-only members are on-link (connected prefixes on ifindex A and B
covering D):
- both unresolved → `ecmp_interface_only_probe_targets(state, dyn, D, table)` == `[(A,D),(B,D)]`;
- resolve `(A,D)` → `[(B,D)]`; resolve both → `[]`;
- an **off-link** interface-only member (no connected prefix covering D) → **not** in the set (§6.3 gate);
- a single-member route → `[]`.

**Integration fail-on-revert (poll-driven), v4 AND v6:** drive a cold-path transit
packet to D through `poll_binding_process_descriptor` with a **real
`NeighborResolver` injected** into `worker_ctx.neighbor_resolver` backed by an
`mpsc` channel — the stock `txn_run_descriptor*` harness sets
`neighbor_resolver: None`, so the §5.3 `if let Some(resolver)` wiring would enqueue
**nothing** and the test would falsely pass on an empty channel (SMR F3). Add a
harness variant that injects one (mirror the #6075 `txn_run_descriptor_with_neighbors`
addition + `neighbor_resolver_tests.rs`'s `ResolveItem` capture). Assert the
captured `ResolveItem`s == `{(A,D),(B,D)}`. Then, with both neighbors resolved,
assert `select_route_next_hop` yields **width-2** (both live for D).
**RED-on-revert:** exclude interface-only members from the collector → no sibling
probe → the sibling never resolves → `select_route_next_hop` width stays **1** →
test RED. Report RED + restored GREEN `test result` lines.

**Regression gate (HARD merge gate, SMR F2):** the full `forwarding::tests`
suite — which covers next-table recursion (#3768), canonical tables
(#2388/#3768-H6), discard, cross-table cycle guards, and tunnel ECMP (#2923) —
plus `poll_descriptor` + `neighbor_resolver` MUST stay GREEN across the §5.1
extraction. A green **full** suite (not just the new ECMP test) is the
behavior-preserving proof; an ECMP-only test could stay green while the extraction
silently blackholes a next-table/VRF route.

## 9. Validation plan (DECISIVE, deferred to /engineer)

**Loss-cluster forwarding smoke, v4 + v6.** ECMP path-diversity is real fast-path
forwarding behavior and the change touches `lookup_forwarding_resolution_v{4,6}_inner`.
After implementation: configure an interface-only ECMP route on the loss
userspace cluster, drive sustained iperf3 (v4 + v6) through the DUT, and confirm
(a) traffic forwards, (b) both interface-only members carry flows (width-2, e.g.
via per-member counters / `show route forwarding` diversity), (c) no
neighbor-probe storm on a p2p/off-link member (journal check). Standard smoke
discipline: loss userspace cluster only, serialized, push+reverse, CoS on/off if
the path overlaps CoS. This is the merge-blocking gate for the /engineer PR.

## 10. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| §5.1 extraction regresses next-table recursion / canonicalization / RG in the core resolver | Behavior-preserving code motion only; gate on the full forwarding suite + a parent-RED that fails if the extracted path diverges; fallback to read-walk. |
| ARP-forever storm on p2p/off-link members | On-link connected-route gate (§6.3); off-link members produce **no** probe. |
| Probe storm under destination scan | Reuse `resolver_enqueue_throttle` (100 ms/key) + `MAX_NEG_NEIGH_CACHE` wholesale-clear bound (identical to existing resolver enqueue). |
| Cold-path cost (second candidate resolution + connected scan per miss) | Cold path only (session-miss); shared helper avoids a second full lookup; connected scan is a cheap linear pass; zero cost once converged. |
| Mixed-RG ECMP group probes a standby-RG sibling | §6.5 RG active gate. |
| Per-destination width surprises operators | Document the eventually-converges, per-destination contract (§6.2, §7 docs). |

## 11. Verdict & open questions

**Verdict: PLAN-READY.** Option D is bounded (reuses the existing scheduler; no
wire/HA change; no hot-path alloc), with the §5.1 core-resolver extraction as the
one real regression risk — contained by a parent-RED + full-suite + loss-cluster
smoke gate. Recommend `/engineer 5161` with this plan.

**Open questions for /engineer (non-blocking):**
- Confirm the §5.1 extraction is borrow-checker-clean with the `visited`
  cycle-guard threading; if not, take the documented re-walk fallback.
- Confirm the poll cold-path site has the RG runtime in scope for the §6.5 gate
  (the warmer does; verify at the poll site).
- Pick the exact docs home for the ECMP interface-only contract (`docs/multi-wan.md`
  vs a routing README).
