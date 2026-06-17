# Claude SMR — hostile plan review, #1946 (r1)

Role: domain SMR (AF_XDP dataplane / HA fabric) + SW design.

## Attack 1 — Is Option B (drop) right, or does it lose legit traffic?

Verified the Owned branch is the BUGGY side, not Live:

- `resolve_fabric_redirect_from_list` (`forwarding/mod.rs:349`) yields a
  resolution with `local_ifindex=0`, `egress=tx=fabric.parent_ifindex`,
  fabric peer/local MACs. It is a **cross-chassis L2 redirect**, not a
  routable local packet.
- `maybe_reinject_slow_path_from_frame` → `extract_l3_packet_with_nat`
  (`slow_path.rs:326`) STRIPS L2 (`frame[l3_offset..]`) and APPLIES NAT.
  So the Owned reinject hands a NAT'd, L2-stripped frame to the **local**
  kernel FIB — during the exact window (fabric parent bind not ready)
  where local routing is least trustworthy. `docs/fabric-cross-chassis-fwd.md`
  is explicit: the fabric mechanism exists to AVOID the kernel-route
  fallback that drops/poisons sessions. Reinjecting locally re-introduces
  that hazard.
- No legitimate traffic depends on the Owned reinject: even when it
  "succeeds," the packet went to the wrong chassis's kernel, not the
  peer. A counted drop is strictly more correct AND more observable.

Verdict on A vs B: **B is correct.** A contradicts the #1913
single-source-of-truth contract (`is_slow_path_eligible` already excludes
FabricRedirect) and the fabric design.

## Attack 2 — Owned vs Live a storage detail? (plan §2e)

Refined the plan. `owned_packet_frame` is `Some` ONLY after
`stage_native_gre_decap` (`poll_descriptor/mod.rs:164`). `Owned` = a
GRE-decapped inner copy; `Live` = raw outer in-UMEM frame. So Option A
would reinject DIVERGENT frames on the two branches (decapped inner vs
raw outer) — both wrong for fabric. Option B touches neither frame, so
the decap/meta hazard (#1902) is moot. Strengthens B. Plan §2e updated.

## Attack 3 — Counter justified + plumbing complete?

`tunnel_encap_unresolved_drops` (#1873 R-C) is the exact precedent: a
deliberate-drop counter for a wrong-path-hazard disposition. Traced its
plumbing — `umem/mod.rs` (field + ctor zero), `umem/snapshot.rs` (load),
`worker/mod.rs:1275` (rollup), `coordinator/refresh_bindings.rs:128,302`
(copy + zero), `coordinator/reconcile/reset.rs:58` (zero),
`protocol/binding.rs:457` (serde), `pkg/dataplane/userspace/protocol.go:1408`
(Go). The plan's plumbing list matches all 7 sites. A dedicated counter
(not exception-only) is warranted: the exception ring is bounded/rotating
and not a monotonic metric; a counter gives an operator-visible
"fabric fallback fired" signal. Keep the counter.

## Attack 4 — Borrow/recycle hazards

The non-fabric no-binding branch immediately below already does
`record_exception(recent_exceptions, ingress_ident, ...) ;
recycle_ingress_frame(ingress_binding, source_offset, now_ns); continue;`
with the same refs in scope. The counter bump targets `ingress_live`
(`&BindingLiveState`), a distinct shared ref from `ingress_binding`
(used by recycle) — no aliasing conflict (both are shared/atomic).
Low risk; will confirm at compile.

## Attack 5 — Doc-comment cleanup accurate?

After the change, `maybe_reinject_slow_path_from_frame` has exactly ONE
intentional unfiltered caller: `handle_forward_build_failure`
(ForwardCandidate). The plan's doc edits (remove the FabricRedirect-Owned
bullet from `slow_path.rs` + the parenthetical in
`is_slow_path_eligible`) are correct and required to keep the docs honest.

## Attack 6 — Should ForwardCandidate build-failure reinject change too?

No. ForwardCandidate IS a destination the kernel FIB may legitimately
serve (the userspace forward-frame build failed, but the route exists);
reinjecting it to the kernel is the documented intentional fallback and
NOT a wrong-path/leak (it's the local egress, not a cross-chassis
redirect). Correctly scoped out. Note: this is the lone surviving
unfiltered caller, which the doc cleanup reflects.

## Verdict

**PLAN-READY (Claude SMR).** Option B, symmetric drop + dedicated
counter + doc cleanup + both-frame-kind regression test. No blocking
findings. One nit folded in: §2e sharpened (Owned = decapped copy, not
mere storage).
