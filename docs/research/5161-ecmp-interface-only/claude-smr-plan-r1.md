# Claude SMR — hostile plan review r1 (#5161)

Adversarial review of `plan.md`. Goal: break the plan, not confirm it.
Companions: Codex + AGY **not run** — per the standing infra-block pattern
(memory: "Codex infra-blocked: must retry", "Gemini infra-outage") and because
this is a **plan** review (not a merge gate), proceeding **SMR-only (1-of-3)** as
the contract permits. Re-attempt at `/engineer` merge time.

Verdict: **PLAN-READY with revisions applied** (findings F1–F3 folded into the
plan; F4–F7 are non-blocking notes / open questions).

---

## F1 (MAJOR, applicability boundary) — the on-link gate excludes the *classic* "default via two uplinks" case; the plan must state the boundary or it over-promises

Attack: the most common interface-only ECMP is `route 0.0.0.0/0 next-hop
[ ge-0/0/0 ge-0/0/1 ]` over two uplinks. For an arbitrary internet destination D,
D is **not** within any connected prefix on either uplink, so the §6.3 on-link
gate **skips** both members → the fix does **nothing** for that config. Does the
plan silently fail its headline case?

Resolution (holds, but must be documented): under **current** code that member is
*already never live* — `is_live` needs a resolved `(ifindex, D)` neighbor, and D
(off-link) can never ARP-resolve on a broadcast segment, so the member never
enters the live set today either. Off-link interface-only members ride the
**kernel-FIB / MissingNeighbor slow path**, not the fast-path neighbor selector —
they were never width->1 on the fast path, so this is **not a regression**, but
the fix genuinely does **not** apply to them. The starvation #5161 describes is
specific to the **on-link** interface-only subset (e.g. `route 10.0.0.0/24
next-hop [ ge-A ge-B ]` where both A and B are on the 10.0.0.0/24 segment), where
`(ifindex, D)` *can* resolve. **Action:** plan must state this applicability
boundary explicitly so the issue is not marked "fully fixed" when off-link ECMP
is untouched by design. → **folded into plan §3 non-goals + §6.3 note + §11.**

## F2 (MAJOR, correctness of the seam) — the refactor CAN regress the core resolver; the parent-RED must specifically bind next-table recursion, not just ECMP

Attack: §5.1 extracts prefix-match + next-table recursion out of a 200-line
recursive fn. A subtle drift (e.g. dropping a `visited.push(table)` before
recursion, or mis-canonicalizing the v6 table) would silently blackhole
next-table/VRF routes — and an ECMP-only fail-on-revert test would stay GREEN
while the extraction is broken. Is the regression gate strong enough?

Resolution: the regression gate must be the **full existing** `forwarding::tests`
suite (which already covers next-table recursion `#3768`, canonical tables
`#2388/#3768-H6`, discard, tunnel ECMP `#2923`, cross-table cycle guards) — a
green full suite across the extraction is the behavior-preserving proof, NOT just
the new ECMP test. The plan §8 "Regression gate" already requires this; **elevate
it to a hard merge gate** and require /engineer to run the extraction as a
*separate* commit whose sole diff is code motion, so a reviewer can eyeball
zero-logic-change. → **folded into plan §8 + §10 (extraction as isolated
behavior-preserving commit).**

## F3 (MEDIUM, test harness) — the integration fail-on-revert needs a resolver injected into the poll harness; today's harness sets `neighbor_resolver: None`

Attack: the plan's integration test asserts `(A,D)` and `(B,D)` are
resolver-enqueued, but `txn_run_descriptor*` sets `worker_ctx.neighbor_resolver =
None`, and the §5.3 wiring is guarded by `if let Some(resolver) = ...`. With None,
**nothing** enqueues and the test would assert on an empty channel — a false
setup, not a real pin.

Resolution: the test must inject a real `NeighborResolver` backed by an `mpsc`
channel (exactly the pattern in `neighbor_resolver_tests.rs::tunnel_marked_resolver_enqueue_keys_outer_l3_egress`)
via a new poll harness variant (mirrors the #6075 `txn_run_descriptor_with_neighbors`
addition). Assert the captured `ResolveItem`s == `{(A,D),(B,D)}`. → **folded into
plan §8 (explicit resolver-injection harness requirement).**

## F4 (MEDIUM, efficiency) — double route walk on the cold path

The cold path already resolves the route once (for the `ForwardingResolution`);
the collector walks it again. Even sharing the §5.1 helper, that's two
prefix-match + recursion passes per session-miss. Not fatal (cold path only,
converges to zero), but a `lookup_forwarding_resolution_cold` variant that
returns `(resolution, Option<&[candidates]>)` in one pass would avoid it. →
**non-blocking optimization note added to plan §7.**

## F5 (MINOR) — per-flow stickiness may confuse the width claim

Even after both members warm, an **already-installed** session for D stays pinned
to its original member (session stickiness). The sibling only carries **new**
flows to D that miss after it warmed. "Width-2" is therefore a property of the
*selector* / new flows, not of live sessions. The test asserts on
`select_route_next_hop` (the selector) + the resolver enqueues, which is correct;
docs must not imply existing flows rebalance. → **non-blocking; plan §6.2 already
frames width as per-destination/selector; add a one-line per-flow note in docs.**

## F6 (MINOR) — RG gate scope-in unverified at the poll site

§6.5 assumes the poll cold path can reach `owner_rg_for_flow` + rg_runtime like
the warmer does. If it can't cheaply, a simpler correct fallback is: rely on the
poll path only forwarding locally-owned flows (probing a standby sibling is waste,
not incorrectness). → left as plan open question §11 (acceptable either way).

## F7 (MINOR) — probe storm re-examined

Claim: no storm. Checked: the collector is empty unless (ECMP >1 candidate) AND
(≥1 unresolved on-link interface-only sibling); `resolver_enqueue_throttle` caps
1 probe/(ifindex,dst)/100 ms with the `MAX_NEG_NEIGH_CACHE` wholesale-clear bound.
Worst case (a /24 of new destinations all via an unconverged on-link ECMP group)
enqueues ≤ one probe per (member,dst) — identical envelope to the **existing**
MissingNeighbor resolver enqueue, which is already considered acceptable. **No new
storm class.** Holds.

---

### Net
The plan's mechanism (reuse `try_enqueue_resolver`, no new scheduler, no hot-path
alloc, no wire/HA change) is sound. The two things that would have made it *wrong*
— (F1) over-promising on off-link ECMP, and (F3) a false-green test on a
`None` resolver — are now explicit. The one real *risk* — (F2) the core-resolver
extraction — is contained by the full-suite behavior-preserving gate + isolated
code-motion commit + loss-cluster smoke. Recommend PLAN-READY → `/engineer 5161`.
