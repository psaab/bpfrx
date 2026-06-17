# Plan — #1946 FabricRedirect desc-frame (Live) fallback asymmetry

## 1. Problem statement

In `userspace-dp/src/afxdp/tx/dispatch/mod.rs` (~L219-253), the
FabricRedirect "no XSK binding for the target interface" safety-net
fallback (fires only when the fabric parent has no XSK binding — bind not
yet ready / `bind()` failed) is **asymmetric** between the two frame
kinds of `request.frame`:

- `PendingForwardFrame::Owned(_)` → `maybe_reinject_slow_path_from_frame`
  (the RAW, unfiltered primitive) → the FabricRedirect frame **is
  reinjected to the kernel slow path** (after `extract_l3_packet_with_nat`
  strips to L3 and applies NAT).
- `PendingForwardFrame::Live` (desc frame, the `else`) →
  `maybe_reinject_slow_path` (the FILTERED wrapper). Its first line is
  `if !decision.resolution.disposition.is_slow_path_eligible() { return; }`.
  `FabricRedirect` is **not** in the allow-list
  (`types/forwarding.rs:329` — only LocalDelivery / NoRoute /
  MissingNeighbor / NextTableUnsupported), so the frame is **silently
  dropped** with no exception recorded and no counter bumped.

So an Owned fabric-redirect fallback frame is reinjected to the local
kernel FIB while a Live one is discarded. Pre-existing latent
inconsistency (predates #1913; #1913 plan §2.6 explicitly scoped it out;
the #1913 wrapper refactor was behavior-identical here — `FabricRedirect`
was never in the wrapper allow-list).

## 2. The central design decision — what is the correct contract?

Two candidate contracts:

- **Option A (symmetric reinject):** make the Live branch reinject like
  the Owned branch (raw `_from_frame`, or add `FabricRedirect` to the
  wrapper allow-list).
- **Option B (symmetric drop + count):** drop BOTH branches deliberately
  and count the drop with a dedicated counter + exception.

### Decision: **Option B (symmetric drop + count).** The Owned-branch
reinject is the **buggy** side; the Live-branch drop is closer to correct
but must be made explicit (counted, not silent).

### Evidence

**(a) A FabricRedirect frame is an L2 cross-chassis redirect, not a
kernel-FIB-routable packet.** `resolve_fabric_redirect_from_list`
(`forwarding/mod.rs:349`) builds a resolution with
`egress_ifindex = tx_ifindex = fabric.parent_ifindex`,
`next_hop = peer_addr`, `neighbor_mac = peer_mac`,
`src_mac = local_mac`, `local_ifindex = 0`,
`tunnel_endpoint_id = 0`. The normal (binding-present) path
re-L2-headers the **original packet** with the fabric peer/local MACs and
TXes it out the fabric parent so the **peer** runs it through its full
pipeline (`docs/fabric-cross-chassis-fwd.md`: "redirect the original
(pre-NAT) packet to the peer via the fabric link instead of falling back
to kernel routing"). The whole point of the fabric mechanism is to
**avoid** the kernel-route fallback that drops/poisons the session in the
asymmetric-routing window. Reinjecting a FabricRedirect to the local
kernel FIB is exactly the wrong-path the mechanism was built to prevent.

**(b) The reinject helper mangles the frame for fabric semantics.**
`maybe_reinject_slow_path_from_frame` calls
`extract_l3_packet_with_nat` (`slow_path.rs:326`) which (i) strips the L2
header (`frame[l3_offset..]`) and (ii) **applies NAT** unconditionally.
For fabric the design wants the *original* L2 frame, pre-NAT
(`apply_nat_on_fabric` gates NAT on the normal path and defaults to the
peer doing NAT). So the Owned-branch reinject doesn't merely route to the
wrong place — it also strips L2 and double-applies/wrongly-applies NAT
relative to fabric intent. This is the same class of hazard as #1873 R-C
(reinjecting an inner/transformed packet to the kernel = plaintext /
wrong-path leak).

**(c) `is_slow_path_eligible` already encodes the intended contract.**
`types/forwarding.rs:313-328` documents `ForwardCandidate` /
`FabricRedirect` as **NOT eligible** ("handled by the forward / fabric
path, never the generic slow path"). The predicate — the single source of
truth for the allow-list (#1913) — already says FabricRedirect must be
dropped, not reinjected. Option A would contradict the documented
contract that #1913 deliberately established; Option B aligns with it.

**(d) There is an exact precedent for Option B's shape.** #1873 R-C
added `tunnel_encap_unresolved_drops` (`umem/mod.rs:388`): a deliberate
drop + counter for a disposition whose reinjection would be a wrong-path
hazard. Option B mirrors it: a `fabric_redirect_no_binding_drops`
counter + a `record_exception("fabric_redirect_no_binding")`.

**(e) Why is the Owned branch even reachable here?** `Owned` vs `Live`
is decided upstream (`poll_descriptor/mod.rs` and `flow_cache_hit.rs`:
`...map(PendingForwardFrame::Owned).unwrap_or(PendingForwardFrame::Live)`)
purely by whether the worker had to copy the frame out of UMEM (e.g.
the ingress slice had to be retained / shared-UMEM constraints), NOT by
any forwarding-semantic difference. There is **no semantic reason** the
two frame kinds should differ for the fabric-no-binding fallback — they
are the same packet, differing only in storage. That is precisely why the
asymmetry is a bug and symmetry is required regardless of A vs B.

### Why not Option A?

Option A would (1) contradict the #1913 single-source-of-truth contract
that FabricRedirect is not slow-path eligible, (2) route a cross-chassis
L2-redirect packet into the **local** kernel FIB during exactly the
window (fabric parent bind not ready) where local routing is most likely
to be wrong/asymmetric, and (3) strip L2 + apply NAT on a frame the
fabric design wants pristine. The fallback is a rare safety net (fabric
parents normally have bindings); when it fires, silently routing locally
is worse than a counted drop. Reject A.

### Live-frame hazard called out in the issue

The issue flags that the Live desc frame "may reference an un-decapped /
different UMEM frame than meta describes." Under Option B we **do not
touch the frame at all** on either branch (we drop + count using
`request.desc.len` / `request.meta` for bookkeeping only), so the
decap/meta-pairing hazard that would bite a reinject (#1902 concern) is
moot — Option B sidesteps it entirely. This is an additional point in
favor of B over A.

## 3. Scope

In scope:
- `userspace-dp/src/afxdp/tx/dispatch/mod.rs`: replace the asymmetric
  `if Owned { reinject } else { reinject-filtered }` block with a single
  symmetric **drop + count + record_exception** for the
  FabricRedirect-no-binding fallback (both frame kinds identical).
- A new per-binding counter `fabric_redirect_no_binding_drops`
  (`AtomicU64`) following the `tunnel_encap_unresolved_drops` precedent,
  plumbed snapshot → worker rollup → protocol JSON → Go struct.
- Update the `maybe_reinject_slow_path_from_frame` doc comment
  (`slow_path.rs:138-145`) — after this change there is **one** remaining
  intentional unfiltered caller (the ForwardCandidate build-failure
  fallback). Remove the FabricRedirect-Owned bullet.
- Update the `is_slow_path_eligible` doc (`types/forwarding.rs:322-328`)
  to drop the "FabricRedirect-Owned fallback ... bypass this predicate"
  clause.
- Regression test asserting BOTH frame kinds (Owned + Live) behave
  identically (drop + counter +1, no reinject) for the
  FabricRedirect-no-binding fallback.
- Doc: a note in `docs/fabric-cross-chassis-fwd.md` (the no-binding
  fallback contract).

Out of scope: the normal binding-present fabric path; any change to the
allow-list semantics for other dispositions; ForwardCandidate
build-failure fallback (it stays an intentional unfiltered reinject —
that frame IS meant for the kernel FIB).

## 4. Approach / implementation sketch

Replace mod.rs L223-252 inner block with:

```rust
if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
    // #1946: FabricRedirect with no XSK binding on the fabric parent is
    // a rare safety net (bind not ready / bind() failed). The frame is a
    // cross-chassis L2 redirect destined for the peer's pipeline, NOT a
    // kernel-FIB-routable packet — reinjecting it to the local kernel
    // slow path is a wrong-path hazard (cf. #1873 R-C). Drop both frame
    // kinds (Owned + Live) identically and count; never reinject.
    ingress_live.fabric_redirect_no_binding_drops.fetch_add(1, Ordering::Relaxed);
    record_exception(
        recent_exceptions, ingress_ident, "fabric_redirect_no_binding",
        request.desc.len, Some(request.meta.into()), None, forwarding,
    );
    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
    continue;
}
```

(Exact `ingress_live` / `ingress_ident` binding names + meta-into pattern
to match the surrounding code; verify the borrow of `ingress_binding`
vs `ingress_live` does not conflict with the subsequent
`recycle_ingress_frame(ingress_binding, ...)` — `ingress_live` is a
separate `&BindingLiveState` ref already in scope at the call sites.)

Counter plumbing (mirror `tunnel_encap_unresolved_drops`):
- `umem/mod.rs`: add field + zero-init in the constructor.
- `umem/snapshot.rs`: load into the snapshot struct.
- `worker/mod.rs`: add `fabric_redirect_no_binding_drops: u64` rollup.
- `coordinator/refresh_bindings.rs` + `reconcile/reset.rs`: copy / zero
  on refresh and reset (match the existing two sites).
- `protocol/binding.rs`: serde field.
- `pkg/dataplane/userspace/protocol.go`: Go struct field
  `FabricRedirectNoBindingDrops uint64`.

## 5. Risks / edge cases

- **Behavior change for the Owned branch:** previously Owned fabric
  fallback frames were reinjected (routed locally, possibly delivered).
  After this change they are dropped+counted. This is the intended fix
  (the reinject was the bug). The path is a rare safety net; functionally
  the peer would not have received the redirect anyway (local kernel
  routing during a bind-not-ready window is the wrong destination). No
  production traffic should depend on it. Counter makes the (rare) event
  observable.
- **Borrow checker:** ensure the new counter bump + record_exception +
  recycle compile (the prior code already called record_exception on the
  non-fabric no-binding path right below, so the refs are available).
- **Counter cardinality:** one new per-binding `AtomicU64`; negligible.
- **No new hot-path cost:** the block is on the cold no-binding exception
  branch (already `continue`s); no fast-path change.

## 6. Test plan

- New Rust unit test `fabric_redirect_no_binding_drops_both_frame_kinds`
  (in `afxdp/tests.rs`): drive the dispatch fallback with a
  FabricRedirect decision and no target binding, once with
  `PendingForwardFrame::Owned` and once with `PendingForwardFrame::Live`;
  assert (a) `fabric_redirect_no_binding_drops == 1` each, (b) no
  slow-path enqueue / no `slow_path_accept`, (c) frame recycled. If the
  full dispatch loop is hard to drive in a unit test, assert the
  invariant at the helper level: confirm `is_slow_path_eligible(
  FabricRedirect) == false` (already true) AND that the new symmetric
  block does not call either reinject helper (structural test / or a
  focused harness around the fallback block if one exists).
- `cargo build`, `cargo test --release`, 5× flake on the new test.
- `go test ./pkg/dataplane/userspace/` (protocol struct parses the new
  field).

## 7. Rollback

`git revert` the implementation commit. Counter field is additive
(serde `default`), so a mixed-version control socket tolerates its
absence.

## 8. Docs to update

- `docs/fabric-cross-chassis-fwd.md`: no-binding fallback = drop + count.
- `slow_path.rs` + `types/forwarding.rs` doc comments (see §3).
- `_Log.md` per project logging rule.

## 9. Alternative considered (and rejected): document-only / PLAN-KILL

If the asymmetry were correct-by-design (Owned reinject intended, Live
drop intended) the right outcome would be PLAN-KILL + a doc note. It is
NOT correct-by-design: the Owned/Live split is a storage detail
(copy-out vs in-UMEM), not a forwarding-semantic one (§2e), so the two
*must* agree; and the agreed value is "drop" per the #1913 contract
(§2c) and the fabric design (§2a/b). PLAN-KILL rejected.

## 10. Reviewer questions to settle

1. A vs B — does any reviewer believe a FabricRedirect frame is safe /
   intended to hand to the **local** kernel FIB when the fabric parent
   has no binding? (If yes, defend against §2a/b.)
2. Counter vs exception-only — is a dedicated `AtomicU64` warranted, or
   is `record_exception("fabric_redirect_no_binding")` alone sufficient?
   (Precedent #1873 R-C used a dedicated counter; lean counter.)
3. Should the ForwardCandidate build-failure fallback
   (`handle_forward_build_failure`) be revisited too, or is it correctly
   an intentional kernel-FIB reinject? (Out of scope — ForwardCandidate
   IS a route the kernel may serve; leave it.)

## 11. Reviewer verdicts

| Round | Reviewer | Verdict | Task id |
|-------|----------|---------|---------|
| r1 | Claude SMR | (pending) | — |
| r1 | Codex | (pending) | — |
| r1 | AGY | (pending) | — |
