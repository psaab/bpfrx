# PR #1882 — Claude SMR hostile code review (round 2)

Reviewer: Claude (domain SMR). Head reviewed: 70206ae043b3 (the r1
publication-window fix 8909f3ac0e70); fix commits 140f310bd (and the
sticky-gate amendment) produced by this round.

## SMR verification of the r1 barrier design (pre-Codex r2)

- Worker tick order verified: Arc load (`worker/loop_body/mod.rs:306`
  `load_arc_if_changed`) precedes command drain (`:497`
  `apply_worker_commands`) precedes the RX sweep — the
  purge-before-store ordering argument holds for the common path.
- Barrier accounting verified: the coordinator's `load_full` handle is
  dropped before the weak check; refresh-path rebuild re-copies
  fabrics; reconcile fabrics derive from the same snapshot; the
  rebuild-failure arm is fail-safe (NoRoute drop, heals on next
  apply); double-build engine-Arc reuse holds (unchanged ids reuse
  through both builds; a re-owned id correctly gets a FRESH engine —
  it is a different tunnel).

## Codex r2 findings — both CONFIRMED in code by this review

1. **Private fabric-overlay Arc** (`worker/loop_body/mod.rs:617`):
   when `shared_fabrics` differs from the loaded state's fabrics, the
   worker replaces its local Arc with `Arc::new(updated)` — a private
   clone the barrier's `Weak::upgrade()` never sees. This review's r2
   verification pass MISSED it (I verified the tick ordering but not
   the overlay clone) — exactly the failure class quad review exists
   to catch.
2. **Fail-open timeout**: `while upgrade().is_some() && elapsed <
   250ms` then proceed. A worker stalled mid-iteration resumes with
   old state and can create an old-owner session after the final
   purge.

Conclusion ratified: timing cannot carry the invariant.

## The replacement (140f310bd) — hostile pass by this review

Structural per-packet owner check. Stored tunnel resolutions already
carry `egress_ifindex = endpoint.logical_ifindex` (set at
`resolve_tunnel_forwarding_resolution`, the only nonzero-id
constructor family for forward paths); kernel ifindexes are not
reused within a boot.

- **Choke-point coverage verified**: every encap funnels through
  `encapsulate_native_gre_frame` / `wg_encap_frame` (callers:
  `frame/mod.rs:273-274`, `tunnel.rs:189`,
  `frame/tcp_segmentation.rs:327`) — both now refuse an
  ifindex-mismatched id. The session-glue check fires BEFORE the
  fresh re-resolve can adopt the new owner.
- **Write-back hazard found and fixed by this review**: the
  re-resolved value is persisted (`maybe_promote_synced_session`
  install path, `upsert_synced.rs:56`). A gated NoRoute that ZEROED
  `egress_ifindex` would erase the discriminator and let the next
  packet adopt the new owner. Fix: the gated resolution PRESERVES the
  stale egress_ifindex (sticky gate; pinned in
  `stale_session_never_adopts_reowned_tunnel_id`).
- **LocalDelivery early-return**: stale LocalDelivery tunnel sessions
  key `local_tunnel_deliveries` by the OLD ifindex — absent in the
  new state — and fall through to the R-C gate. Fail-safe.
- **Synced entries with unresolvable id (egress 0)**: outside the
  ifindex check's reach — closed at install boundaries by the
  new-appearance purge arm in `tunnel_remap_purge_ids`, gated off for
  the helper's first apply (would wipe boot-time synced sessions —
  found by this review during implementation).
- **`prefer_local_forward_candidate_for_fabric_ingress` can override
  the gated NoRoute with a fresh dst-based lookup** (fabric ingress
  only). Judged CORRECT: a dst-route-following fresh lookup equals
  new-flow behavior (config intent), which is not the id-deref
  confusion this fix targets; the builders' ifindex guard still
  blocks any id-deref mismatch at build time.

Accepted residuals (documented in the commit): kernel ifindex
wrap-reuse + fold collision in one boot (~0 probability); Go-side
peer re-resolution during HA config skew + fold collision (plan v4
residual 3's class, self-heals at the lagging node's commit).

## AGY r2 triage (review-mqaam2as-a3fgqq, "needs-attention", 2 med 2 low)

- Medium 1 (barrier timeout/long-lived holders): SUPERSEDED — the
  barrier is deleted; no timing dependence remains.
- Medium 2 (consumers during deferral): SUPERSEDED — no deferral
  exists; rows install immediately.
- Low 1 (delayed healing on rebuild failure): SUPERSEDED — no second
  build exists.
- Low 2 (pin WG engine Arc reuse across the re-own apply): FOLDED —
  `reowned_tunnel_id_installs_immediately_with_engine_reuse` pins
  `Arc::ptr_eq` across the apply.

## Verdict

MERGE-READY at the head carrying 140f310bd + the sticky-gate
amendment, pending Codex r3 ratification of the replacement design
(its own r2 MAJOR) and AGY r3 on the delta.
