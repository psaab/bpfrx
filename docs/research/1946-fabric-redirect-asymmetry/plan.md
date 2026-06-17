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
hazard. Option B mirrors it: a `fabric_redirect_unsendable_drops`
counter + a `record_exception("fabric_redirect_no_binding")`.

**(e) Why is the Owned branch even reachable here, and what does it
mean?** `Owned` vs `Live` is decided upstream
(`poll_descriptor/mod.rs:521-524` and `:2078-2081`,
`flow_cache_hit.rs:366-367`:
`owned_packet_frame.take().map(PendingForwardFrame::Owned).unwrap_or(PendingForwardFrame::Live)`).
`owned_packet_frame` is the output of `stage_native_gre_decap`
(`poll_descriptor/mod.rs:164`) — it is `Some` **only when the worker
GRE-decapped the frame into a fresh buffer**; otherwise the raw in-UMEM
desc frame (`Live`) is used. So the two kinds are NOT a benign
storage detail — `Owned` is specifically a *decapped copy whose meta may
diverge from the on-wire bytes*, which is exactly the un-decapped /
different-frame hazard the issue flags (#1902 class). This makes the
current asymmetry doubly wrong: Option A would reinject a **decapped**
inner frame on the Owned branch vs the raw outer frame on the Live
branch — divergent, both wrong for a fabric cross-chassis L2 redirect.
Option B touches **neither** frame (drop + count using `desc.len`/`meta`
for bookkeeping only), sidestepping the decap/meta-pairing hazard
entirely. The asymmetry is a bug regardless; the safe symmetric value is
"drop."

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
- **(Codex r1 HIGH)** `handle_forward_build_failure`
  (`tx/dispatch/slow_path.rs:25`): the SECOND FabricRedirect → kernel-FIB
  bypass. When the fabric parent binding EXISTS but the forward-frame
  build / enqueue fails (`build_failed = true; fallback_to_slow_path =
  true` at mod.rs:575/843/856; or the local-enqueue err at :555), the
  build-failure handler calls `maybe_reinject_slow_path_from_frame`
  (raw, no gate) with `request.decision` whose disposition is
  FabricRedirect → reinjected to the local kernel FIB. FabricRedirect
  reaches this because it has a valid `target_binding` (the fabric
  parent) and flows through `build_forwarded_frame_from_frame`. Fix:
  gate FabricRedirect inside `handle_forward_build_failure` BEFORE the
  reinject — drop + bump the SAME `fabric_redirect_unsendable_drops`
  counter (rename concept to "fabric_redirect_no_tx" / keep one counter;
  see §4) + record_exception. This makes BOTH FabricRedirect slow-path
  bypass paths (no-binding AND build-failure) fail-closed. ForwardCandidate
  build failure stays an intentional reinject (it IS a kernel-servable
  route).
- A new per-binding counter `fabric_redirect_unsendable_drops`
  (`AtomicU64`) following the `tunnel_encap_unresolved_drops` precedent,
  plumbed snapshot → worker rollup → protocol JSON → Go struct.
- Update the `maybe_reinject_slow_path_from_frame` doc comment
  (`slow_path.rs:138-145`) — after BOTH fixes there is **one** remaining
  intentional unfiltered caller: the ForwardCandidate build-failure
  fallback. Remove the FabricRedirect-Owned bullet. **(Codex r1 HIGH-2)**
  The doc claim is only true if `handle_forward_build_failure` actually
  gates FabricRedirect (above) — otherwise the comment would document an
  invariant the code does not enforce. The gate makes the "one remaining
  caller is ForwardCandidate" claim TRUE by construction. To make it
  enforced (not just documented), the gate is an explicit
  `if disposition == FabricRedirect { drop+count; return; }` at the top
  of the reinject section in `handle_forward_build_failure`.
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
    ingress_live.fabric_redirect_unsendable_drops.fetch_add(1, Ordering::Relaxed);
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

**Counter (single counter for BOTH paths).** Name it
`fabric_redirect_unsendable_drops` (covers no-binding AND build-failure —
"fabric redirect could not be TX'd to the peer, dropped fail-closed").
Both the no-binding block AND the `handle_forward_build_failure`
FabricRedirect gate bump this one counter (distinct
`record_exception` reasons: `"fabric_redirect_no_binding"` and
`"fabric_redirect_build_failed"` for observability of which path fired).

Plumbing — mirror `tunnel_encap_unresolved_drops` EXACTLY (it lives ONLY
on `BindingStatus`, NOT on `BindingCountersSnapshot` — confirmed
`protocol/binding.rs:457` is BindingStatus-only; **(Codex r1 MEDIUM-2)**
resolved: BindingStatus-only, do not add to the lean snapshot):
- `umem/mod.rs:382` region: add `AtomicU64` field; `:736` ctor zero-init.
- `umem/snapshot.rs:110` region: load into snapshot.
- `worker/mod.rs:1272` region: add `u64` rollup field.
- `coordinator/refresh_bindings.rs:128,302`: copy on refresh + zero.
- `coordinator/reconcile/reset.rs:58`: zero on reset.
- `protocol/binding.rs:457` region: serde `#[serde(rename, default)]`.
- `pkg/dataplane/userspace/protocol.go:1404` region: Go field
  `FabricRedirectUnsendableDrops uint64` with matching json tag.
- **(AGY r1 CRITICAL)** Regenerate the checked-in wire specimen
  `userspace-dp/tests/fixtures/protocol_wire_v1.json` — adding a
  `BindingStatus` field makes `wire_invariant_default_specimens`
  (`protocol/tests.rs:1083`) fail until the fixture is regenerated via
  `XPF_PROTOCOL_WIRE_REGEN=1 cargo test --bin xpf-userspace-dp
  wire_invariant_default_specimens`, then review the diff (it should add
  exactly the one new `"fabric_redirect_unsendable_drops": 0` line) and
  commit it. MUST be in the same commit as the serde field.

## 5. Risks / edge cases

- **Behavior change (fail-closed):** previously Owned no-binding +ANY
  build-failure FabricRedirect frames were reinjected (routed via the
  LOCAL kernel FIB). After this change they are dropped + counted —
  **fail-closed**. **(Codex r1 LOW)** A binding outage / build failure
  can drop packets the current bug might occasionally "salvage" IF the
  local kernel happened to route them to the right place. That salvage is
  unsound (local routing during a fabric-parent outage / on the standby
  is the wrong path — exactly the asymmetric-routing hazard the fabric
  mechanism exists to avoid, and on an HAInactive→FabricRedirect frame it
  is a wrong-node plaintext send). Fail-closed + counted is the correct
  posture; the counter makes the rare event observable. We do NOT claim
  "no traffic ever depended on it" — we assert the dependency was unsound.
- **Borrow checker:** ensure the new counter bump + record_exception +
  recycle compile (the prior code already called record_exception on the
  non-fabric no-binding path right below, so the refs are available).
- **Counter cardinality:** one new per-binding `AtomicU64`; negligible.
- **No new hot-path cost:** the block is on the cold no-binding exception
  branch (already `continue`s); no fast-path change.

## 6. Test plan

- **Test 1 (build-failure gate — Codex r1 HIGH):**
  `handle_forward_build_failure` with a FabricRedirect `SessionDecision`
  + `fallback_to_slow_path = true` + a stub `slow_path` reinjector MUST
  NOT enqueue (assert `slow_path.enqueue` not called / accept count 0)
  and MUST bump `fabric_redirect_unsendable_drops`. Contrast with a
  ForwardCandidate decision which MUST still reinject (regression guard
  that the gate is FabricRedirect-only). `handle_forward_build_failure`
  is directly callable (`pub(in crate::afxdp)`), so this is a focused
  unit test.
- **Test 2 (no-binding symmetry):** assert both frame kinds (`Owned` +
  `Live`) drop+count identically on the no-binding fallback. If the full
  dispatch loop is hard to drive, assert at the invariant level:
  `is_slow_path_eligible(FabricRedirect) == false` AND that the new
  symmetric no-binding block bumps the counter for both kinds without
  calling either reinject helper.
- **Wire test (Codex r1 MEDIUM-2):** a Rust serde round-trip test (or
  reuse the existing BindingStatus serde test) confirming
  `fabric_redirect_unsendable_drops` serializes/deserializes; the Go
  `go test ./pkg/dataplane/userspace/` confirms the Go
  `BindingStatus`-equivalent struct parses the new json field (default 0
  when absent — mixed-version tolerance).
- `cargo build`, `cargo test --release`, 5× flake on the new tests.

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
NOT correct-by-design: the Owned/Live split is a frame-representation
detail (Owned = GRE-decap copy, Live = raw in-UMEM frame; §2e), not a
forwarding-semantic one, so the two *must* agree; and the agreed value
is "drop" per the #1913 contract
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
| r1 | Claude SMR | PLAN-READY | (in-conversation) |
| r1 | Codex | PLAN-NEEDS-WORK → addressed | task-mqi86st4-5n620c |
| r1 | AGY | PLAN-NEEDS-WORK → addressed | adversarial-review-mqi87f3t-vf66ct |
| r2 | Codex | **PLAN-READY** | task-mqi8g0px-katnme |
| r2 | AGY | **PLAN-READY** | adversarial-review-mqi8g6qf-jyxikq |

**3-way converged PLAN-READY (Claude SMR + Codex r2 + AGY r2).** Codex r2
confirmed no other ungated FabricRedirect reinject path remains; AGY r2
confirmed gating in `handle_forward_build_failure` is the right layer and
mixed-version serde tolerance is fine. Codex r2 nit (stale
`fabric_redirect_no_binding_drops` name) folded — counter is
`fabric_redirect_unsendable_drops` throughout.

### AGY r1 findings → disposition

- CRITICAL (wire specimen fixture omission breaks
  `wire_invariant_default_specimens`): **ACCEPTED** — added the
  `XPF_PROTOCOL_WIRE_REGEN=1` regen + commit step to §4. Confirmed the
  fixture `userspace-dp/tests/fixtures/protocol_wire_v1.json` already
  carries `tunnel_encap_unresolved_drops`, so the new field needs the
  same treatment.
- HIGH (build-failure → wrong-path reinject): **ACCEPTED** — same as
  Codex r1 HIGH; gated in `handle_forward_build_failure` (§3/§4).
- (Owned/Live, borrow validation): AGY concurred no borrow hazard.

### Codex r1 findings → disposition

- HIGH (build-failure FabricRedirect raw-reinject): **ACCEPTED** —
  expanded scope (§3, §4) to gate FabricRedirect in
  `handle_forward_build_failure`; one shared counter, both paths
  fail-closed. Test 1 added.
- HIGH-2 (doc claim false unless build-failure gated): **ACCEPTED** —
  the gate makes "one remaining ForwardCandidate caller" true by
  construction (§3).
- MEDIUM (Owned vs Live not "purely storage"): **ACCEPTED** — §2e already
  reframed (Owned = GRE-decapped copy); rationale is "two representations
  of the canonical packet; representation must not change FabricRedirect
  disposition policy; the drop block touches neither frame."
- MEDIUM-2 (snapshot vs BindingStatus): **RESOLVED** — BindingStatus-only
  (precedent `tunnel_encap_unresolved_drops` is BindingStatus-only).
- LOW (soften "no legit traffic"): **ACCEPTED** — reframed as fail-closed
  / unsound-dependency (§5).
- LOW (no borrow hazard): acknowledged.
