# Plan of Action — #1913: trailing `maybe_reinject_slow_path_from_frame` runs for ALL non-forward dispositions (incl. PolicyDenied)

- **Revision**: r2 (post round-1: Codex + AGY + Claude SMR)
- **Issue**: #1913 (bug)
- **Branch**: `research/1913-fromframe-filter`
- **Mode**: `/research` — STOP at PLAN-READY. No PR, no production source touched.
- **Base**: origin/master @ `d535f1f3e`

---

## 1. Problem statement

`poll_binding_process_descriptor`'s non-forward branch ends with an
**unconditional** call to `maybe_reinject_slow_path_from_frame(.., packet_frame,
meta, decision, ..)` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2814`,
immediately after the `match decision.resolution.disposition` block at
`:2156`. That match has arms for `LocalDelivery`, `NoRoute`, `MissingNeighbor`,
`PolicyDenied`, `HAInactive`, and a `_` catch-all (which covers `DiscardRoute`,
`ForwardCandidate`, `FabricRedirect`, `NextTableUnsupported`).

The disposition allow-list

```rust
LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported
```

exists ONLY in the desc-based wrapper `maybe_reinject_slow_path`
(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:90`). The `_from_frame`
variant (`slow_path.rs:129+`) has **no disposition filter** — it goes
straight to: `extract_l3_packet_with_nat` → LocalDelivery tunnel-delivery
branch → #1873 R-C tunnel gate (`tunnel_endpoint_id != 0`) →
`SlowPathReinjector::enqueue` → kernel slow-path TUN → kernel FIB.

Because the trailing call at `:2814` uses the unfiltered `_from_frame`
variant, **`PolicyDenied`, `HAInactive`, and `DiscardRoute` frames are
handed to the kernel FIB** when the wrapper's allow-list says they should be
dropped.

## 2. Blast-radius walk (verified against source @ d535f1f3e)

### 2.1 The trailing chokepoint (mod.rs:2156–2820)

**First**: the `match` at `:2156` is inside the `else` of the FORWARD branch.
The forward branch at `mod.rs:1794-1798` is `if matches!(disposition,
ForwardCandidate | FabricRedirect)` — so **`ForwardCandidate` and
`FabricRedirect` are consumed by the forward `if` and NEVER enter the `else`
block** that contains the `:2156` match or the `:2814` trailing call (Codex +
AGY r1, verified). They cannot reach :2814. (r1 table erratum — corrected
below.)

The `match` at `:2156` falls through to `record_forwarding_disposition(...)`
(`:2802`) and then unconditionally `maybe_reinject_slow_path_from_frame(...,
packet_frame, meta, decision, "slow_path", ...)` at `:2814`. Per-arm exit
behavior verified end-to-end (corrected after r1):

| Arm | Early `continue`/exit? | Reaches :2814 with disposition |
|-----|-------------------|--------------------------------|
| `LocalDelivery` (:2157) | no | `LocalDelivery` ✅ in allow-list |
| `NoRoute` (:2186) | no | `NoRoute` ✅ in allow-list |
| `MissingNeighbor` (:2204) | **sometimes** — `neg_neigh_gate` fast-fail (:~2245) and resolved-wins paths `continue` (recycle+skip); **SNAT-allocation-failure** paths `scratch_recycle.push` + `continue` at **:2533 and :2564** (AGY + Codex r1, verified); the buffered (`recycle_now=false`) and capacity-drop paths fall through | `MissingNeighbor` ✅ in allow-list |
| `PolicyDenied` (:2799) | **no** | **`PolicyDenied` ✗ NOT in allow-list — LEAK** |
| `HAInactive` (:2800) | no | **`HAInactive` ✗ NOT in allow-list — LEAK** |
| `_` catch-all (:2801) | no | covers **`DiscardRoute`** (✗ NOT in allow-list — LEAK), plus `NextTableUnsupported` (✅ in allow-list). `ForwardCandidate`/`FabricRedirect` do NOT reach here (consumed at :1794-1798). |

So three dispositions reach the unfiltered enqueue that the wrapper would
reject: **`PolicyDenied`, `HAInactive`, `DiscardRoute`**. (`NextTableUnsupported`
also flows through the `_` arm but IS in the allow-list, so it is correctly
reinject-eligible.)

### 2.2 What reinjecting a `PolicyDenied` frame actually does today

`decision.resolution.disposition` is overwritten to `PolicyDenied` at
`mod.rs:1694`, but the rest of `decision.resolution` (egress_ifindex,
next_hop, tunnel_endpoint_id) and `decision.nat` retain whatever
`resolve_forwarding` produced for the flow before the policy verdict.

Tracing `maybe_reinject_slow_path_from_frame` (slow_path.rs:129+) for a
typical denied transit flow:

1. `extract_l3_packet_with_nat(frame, meta, decision.nat)` — depends ONLY on
   a parseable L3 frame + addr_family, **not** on disposition. For a normal
   IPv4/IPv6 transit packet this **succeeds** and returns the L3 bytes (NAT
   default = no rewrite). → not the drop door.
2. `tunnel_delivery` branch: requires `disposition == LocalDelivery`. False
   for PolicyDenied. → skipped.
3. #1873 R-C tunnel gate: `tunnel_endpoint_id != 0`. For a normal denied
   transit flow this is **0**, so the gate does NOT fire. → not the drop door.
4. `slow_path.cloned()` — present in production. → not the drop door.
5. `slow_path.enqueue(packet)` → writes the raw L3 packet to the slow-path
   TUN → **kernel FIB forwards it** (rate-limited only by the slow-path
   reinjector's token bucket).

**Conclusion: a policy-denied transit packet IS forwarded by the kernel**, a
zone-policy bypass bounded only by the slow-path rate limiter. Telemetry:
`record_slow_path_accept` (umem/mod.rs:941) bumps generic
`slow_path_packets`/`slow_path_bytes` and hits the `_ => {}` arm (no
disposition-specific counter), so the leak is invisible in
per-disposition slow-path metrics. The `policy_deny` debug counter and
`emit_policy_deny_event` still fire (deny is "logged"), masking the fact that
the packet was also forwarded. **This is a correctness/security bug, not
benign.**

Caveats that bound (do NOT eliminate) the leak:
- Only **first packets / cold-path packets** reach userspace at all; once a
  session/flow-cache entry exists the BPF fast path handles it. A denied flow
  never creates a session, so EVERY packet of a denied flow is a cold-path
  packet → every packet is a leak candidate (not just the first).
- The slow-path reinjector rate-limits, so the leak is a throttled trickle,
  not line-rate. But "throttled" ≠ "blocked": a low-rate denied flow (e.g. a
  port-scan probe, a single denied SSH attempt) is forwarded in full.
- The kernel FIB must actually have a route to the dst for the forward to
  land; for a denied **transit** flow it usually does (that is why policy,
  not routing, was the gate).

### 2.3 `HAInactive`

By `:2814`, the safety-net conversions (`:1762`, `:1697`) have already turned
`HAInactive` into `FabricRedirect` whenever `owner_rg_for_resolution > 0`. A
**residual** `HAInactive` at the match means `egress_rg == 0` (unresolved
ownership) or fabric-ingress anti-loop. Reinjecting it hands the packet to the
standby node's kernel FIB — on a standby that does not own the RG this can
produce duplicate/asymmetric forwarding or a plaintext send from the wrong
node. Lower incidence than PolicyDenied (requires the residual-HAInactive
corner) but still a should-drop disposition being reinjected.

### 2.4 `DiscardRoute`

A packet that matched a **discard/reject route** (`forwarding/mod.rs:1279`,
`:1427`) lands in the `_` catch-all and is reinjected to the kernel FIB
unfiltered. Discard routes exist precisely to drop traffic; reinjection
re-routes it via the kernel (which may not have the same discard route or may
default-route it). Another should-drop-but-forwarded leak. NOTE: `DiscardRoute`
is ALSO absent from the wrapper allow-list, confirming the intended contract
is "drop".

**`DiscardRoute` is the cleanest proof the unfiltered reinject is a bug**
(Claude SMR r1, F1): unlike PolicyDenied (which has the "deny is logged"
partial mitigation) there is no plausible "intentional" reading — a discard
route's entire purpose is to drop. Path A fixes PolicyDenied, HAInactive, and
DiscardRoute identically.

### 2.5 Buffered-MissingNeighbor duplicate (issue Q3)

For the `PendingNeighAdmission::Buffer` path the frame is inserted into
`pending_neigh` and `recycle_now = false` (mod.rs:2776) — but execution still
falls through to the trailing `:2814` call, which (since `MissingNeighbor` IS
in the allow-list) **enqueues a copy to the kernel slow path**. On neighbor
resolution `retry_pending_neigh` ALSO TXes the buffered frame via in-place
rewrite. → potential **duplicate first-packet delivery** (one via kernel FIB
now, one via the userspace rewrite later). The in-arm comment block
(mod.rs:2690+) says "the trailing decap-aware ... chokepoint (#1901) still
hands the correctly-paired INNER packet to the kernel slow path" — i.e. the
duplicate is currently **intentional/known** for the recovery story, but the
issue flags the contradiction with the buffer's "we buffer it for retry"
intent. This is a SECONDARY concern; the primary bug is PolicyDenied/
HAInactive/DiscardRoute. The plan addresses it explicitly (see §5 Path A
sub-decision) but does not block on it.

**Explicit scope statement (Claude SMR r1, F2):** Path A keeps
`MissingNeighbor` in the allow-list, so the §2.5 duplicate-delivery is
**UNCHANGED** by this fix. Issue Q3 is acknowledged and **DEFERRED** — #1913
does NOT close it. If the duplicate is judged undesirable it is a separate
follow-up (file a new issue at /engineer time). The converged issue comment
must say this plainly so a reader does not assume #1913 resolves Q3.

### 2.6 Why a fix inside `_from_frame` is WRONG (critical finding)

`maybe_reinject_slow_path_from_frame` has **5 production call sites** (grep):
- `slow_path.rs:61` (build-failure fallback, via `handle_forward_build_failure`)
- `slow_path.rs:113` (the desc-wrapper's tail, AFTER its own allow-list filter)
- `poll_stages.rs:452` (IPsec local-delivery — synthesizes `LocalDelivery`)
- `tx/dispatch/mod.rs:225` ("no XSK binding" fallback — passes `FabricRedirect`
  via the Owned-frame branch; NOT in the allow-list. See the correction below
  re: the asymmetric `:238` desc branch.)
- `poll_descriptor/mod.rs:2814` (the buggy trailing call)

Two of these callers pass dispositions OUTSIDE the wrapper allow-list, so the
unfiltered `_from_frame` variant is load-bearing for them:

1. **`dispatch/mod.rs:225` — FabricRedirect, Owned-frame fallback.** Guarded by
   `if request.decision.resolution.disposition == FabricRedirect` (:223) AND
   `matches!(request.frame, PendingForwardFrame::Owned(_))` (:224). When the
   target binding is missing and the frame is owned, it reinjects a
   `FabricRedirect` via unfiltered `_from_frame`. (Codex + AGY r1, verified.)
2. **`handle_forward_build_failure` → `slow_path.rs:61` — ForwardCandidate
   build-failure fallback.** When the forward-build returns `None`
   (`dispatch/mod.rs:855-857` sets `fallback_to_slow_path = true`),
   `handle_forward_build_failure` (`:887`) calls `_from_frame` unfiltered with
   a `ForwardCandidate` decision (Codex r1, verified). `ForwardCandidate` is
   NOT in the wrapper allow-list either.

**Correction to the r1 framing (Codex + AGY r1):** the r1 plan argued "the
immediately-following `else` at dispatch/mod.rs:238 proves the bypass is
intentional." That is over-stated and partly wrong. The `:238` `else` branch
(non-Owned/desc frame) calls the FILTERED wrapper `maybe_reinject_slow_path`,
which REJECTS `FabricRedirect` → the desc-frame `FabricRedirect` fallback is
**silently dropped today**. So dispatch/mod.rs treats `FabricRedirect`
ASYMMETRICALLY: Owned → reinjected, Desc → dropped. This asymmetry is a
**pre-existing inconsistency** (likely a latent bug), NOT a clean "intentional
bypass." It is OUT OF SCOPE for #1913 (the trailing call at :2814 is a distinct
chokepoint), but the plan must NOT mischaracterize it as deliberate, and the
shared predicate must be defined so it does not silently "fix" or worsen it.

> **Conclusion (unchanged):** Adding the allow-list INSIDE `_from_frame` would
> break BOTH the `dispatch/mod.rs:225` FabricRedirect-Owned fallback AND the
> `slow_path.rs:61` ForwardCandidate build-failure fallback (neither
> disposition is in the allow-list). This rules out the "filter inside
> `_from_frame`" option (Path B). The fix belongs at the `mod.rs:2814` call
> site via a shared predicate, NOT inside the shared helper — and the helper
> should be explicitly documented as the RAW/unchecked primitive whose callers
> own the eligibility decision (altitude fix, see Path A + §6).

## 3. Severity

**Medium-High security/correctness bug.** A configured zone-policy DENY is
silently bypassed for cold-path (sessionless) packets: every packet of a
denied flow is reinjected to the kernel FIB and forwarded, rate-limited only
by the slow-path token bucket, and invisible in per-disposition telemetry.
Pre-existing since the #1054 extraction (`cc31ffb96`); untouched by #1911.

## 4. Goals / non-goals

**Goals**
- The trailing reinject at `mod.rs:2814` must NOT enqueue `PolicyDenied`,
  `HAInactive`, or `DiscardRoute` frames to the kernel slow path.
- Preserve the existing intentional `_from_frame` bypass at
  `dispatch/mod.rs:225` (FabricRedirect fallback) and the IPsec LocalDelivery
  path at `poll_stages.rs:452`.
- Document the contract: which dispositions are reinject-eligible, and where
  the gate lives, at the call site and in `tx/dispatch/slow_path.rs`.
- Decide the buffered-MissingNeighbor duplicate (§2.5): keep (document) or
  suppress.

**Non-goals**
- No change to the policy-evaluation logic, the slow-path reinjector, NAT, or
  the tunnel gate.
- No change to the other 4 call sites' behavior.
- No new Prometheus surface beyond what is needed to make the dropped-leak
  observable (optional, see §5).

## 5. Multiple Path Options

### Path A — gate at the call site (mod.rs:2814) via a shared predicate (RECOMMENDED)

Extract the allow-list into a single `pub(in crate::afxdp) const fn
disposition_is_slow_path_eligible(d: ForwardingDisposition) -> bool` (or
`ForwardingDisposition::is_slow_path_eligible(self)`) in
`tx/dispatch/slow_path.rs` (or on the enum in `types/forwarding.rs`). Then:

1. Replace the inline `matches!(...)` in the wrapper `maybe_reinject_slow_path`
   (slow_path.rs:90) with a call to the shared predicate (no behavior change —
   pure refactor, makes the two sites share one SSOT).
2. At `mod.rs:2814`, wrap the trailing call:
   ```rust
   if disposition_is_slow_path_eligible(decision.resolution.disposition) {
       maybe_reinject_slow_path_from_frame(...);
   }
   ```

3. **Altitude fix (Codex + AGY r1):** add a doc comment to
   `maybe_reinject_slow_path_from_frame` stating it is the RAW/unchecked
   primitive — callers are responsible for applying
   `is_slow_path_eligible` unless they have a documented reason to bypass it
   (the two intentional/legacy bypass sites: `dispatch/mod.rs:225`
   FabricRedirect-Owned fallback and `slow_path.rs:61` ForwardCandidate
   build-failure fallback). This makes the "next caller forgets the gate"
   footgun explicit at the helper definition.

- **Pros**: minimal, surgical; fixes the exact leak; preserves the two
  load-bearing unfiltered callers (neither calls the predicate); one SSOT for
  the allow-list; trivially testable; the altitude doc-comment closes the
  footgun the r1 reviewers flagged.
- **Cons**: the predicate now lives at two ENFORCING call sites (wrapper +
  2814) — a third future caller could forget it. Mitigated by the shared
  `const fn` name + the raw-primitive doc comment on `_from_frame`.
- **Buffered-MissingNeighbor (§2.5)**: `MissingNeighbor` stays in the
  allow-list, so the §2.5 duplicate behavior is UNCHANGED by Path A. Sub-
  decision: leave as-is (it is the documented #1901 recovery story) and
  document it, OR additionally skip the trailing call when `recycle_now ==
  false` (the frame is buffered for retry, no need to also kernel-reinject).
  **Recommendation: leave MissingNeighbor behavior unchanged in this fix**
  (it is a separate, lower-severity, already-documented concern) and note it
  in the call-site comment; file a follow-up if the duplicate is undesirable.

### Path B — filter inside `_from_frame` (REJECTED)

Add the allow-list to `maybe_reinject_slow_path_from_frame` itself.

- **Pros**: every `_from_frame` caller is covered automatically.
- **Cons / FATAL**: breaks BOTH `dispatch/mod.rs:225` (FabricRedirect-Owned
  fallback) AND `slow_path.rs:61`/`handle_forward_build_failure`
  (ForwardCandidate build-failure fallback) — neither disposition is in the
  allow-list, and both rely on the unfiltered helper. Would require
  simultaneously rewriting two call sites to a different mechanism. Larger
  blast radius, changes 5 call sites' contract for one buggy site.
  **Rejected** per §2.6.

### Path C — convert the trailing `_from_frame` call to the filtered wrapper `maybe_reinject_slow_path`

At `mod.rs:2814`, call the desc-based wrapper (which already filters) instead
of `_from_frame`.

- **Cons / FATAL**: the wrapper takes `area: &MmapArea` + `desc: XdpDesc` and
  re-slices the ORIGINAL UMEM frame. The trailing site MUST use `packet_frame`
  (the post-decap `owned_packet_frame` when GRE decap rebound meta) — this is
  the entire point of the #1885/#1901 fix (using `desc` here re-introduces the
  4-byte-early VLAN slice / un-decapped-outer-packet bug the comments at
  :2163+ describe). So switching to the desc wrapper RE-INTRODUCES #1885.
  **Rejected.**

### Path D — document-only ("intentional")

Conclude the unfiltered behavior is intentional and just add comments.

- **Cons / FATAL**: §2.2 proves a real policy bypass (denied packets
  forwarded). Not intentional, not benign. **Rejected.**

## 6. Recommended path

**Path A.** Shared `const fn`/enum-method predicate, gate at the `mod.rs:2814`
call site, wrapper refactored to call the same predicate (SSOT). Leave the two
load-bearing unfiltered callers untouched (`dispatch/mod.rs:225`
FabricRedirect-Owned fallback; `slow_path.rs:61` ForwardCandidate
build-failure fallback). Add a raw-primitive doc comment to `_from_frame`
documenting that callers own the eligibility decision. Leave the
MissingNeighbor buffered-duplicate behavior (Q3) unchanged + DEFERRED. Do NOT
attempt to fix the dispatch/mod.rs:238 FabricRedirect desc-branch asymmetry in
#1913 (out of scope; note it for a follow-up). Add an observability counter for
the now-dropped PolicyDenied/HAInactive/DiscardRoute case only if a reviewer
wants it (the per-disposition counters at :2802 already tell the story).

## 7. Implementation sketch (for the eventual /engineer pass — NOT executed here)

1. `types/forwarding.rs` (or `tx/dispatch/slow_path.rs`): add
   `pub(in crate::afxdp) const fn is_slow_path_eligible` over the allow-list
   `LocalDelivery | NoRoute | MissingNeighbor | NextTableUnsupported`, with a
   doc comment stating the drop set (`PolicyDenied | HAInactive | DiscardRoute
   | ForwardCandidate | FabricRedirect`) and WHY each is excluded.
2. `slow_path.rs:90`: replace the inline `matches!` with the predicate (pure
   refactor; no behavior change).
3. `poll_descriptor/mod.rs:2814`: guard the trailing call with the predicate.
   When the predicate is false, the frame is already counted by
   `record_forwarding_disposition` (:2802) and recycled by the
   `recycle_now` epilogue (:2852) — no leak, no double-count. Add a short
   comment referencing #1913 + the eligibility predicate.
4. (optional) bump a dedicated drop counter when the gate suppresses a
   reinject, so the bypass-that-was is observable.

## 8. Observability / telemetry

- Today the leak is invisible (generic `slow_path_packets` only). After the
  fix, the suppressed frames are counted via the existing
  `record_forwarding_disposition` per-disposition counters
  (`bump_discard_route`, `policy_deny`, `ha_inactive`) — already wired at
  `:2802`. No NEW metric strictly required.
- Optional: a `slow_path_disposition_filtered` counter to make the
  "would-have-reinjected-but-gated" path explicit. Low value (the disposition
  counters already tell the story); include only if a reviewer wants it.

## 9. Test plan (for /engineer; describe only)

Unit (in `userspace-dp/src/afxdp/tests.rs`, alongside the existing
`tunnel_marked_*` tests):
- **T1 (the bug)**: `maybe_reinject_slow_path_from_frame` direct call is NOT
  the unit under test — the gate is at the call site, so add a test exercising
  the predicate: `is_slow_path_eligible(PolicyDenied) == false`,
  `(HAInactive) == false`, `(DiscardRoute) == false`,
  `(LocalDelivery|NoRoute|MissingNeighbor|NextTableUnsupported) == true`,
  `(FabricRedirect|ForwardCandidate) == false`.
- **T2 (wrapper SSOT)**: the wrapper `maybe_reinject_slow_path` with a
  `PolicyDenied` decision still early-returns with no enqueue (regression on
  the existing wrapper filter, now via the shared predicate). Reuse the
  existing wrapper test fixture.
- **T3 (call-site integration)**: harder — exercising the full
  `poll_binding_process_descriptor` PolicyDenied path requires the worker-ctx
  fixture. If feasible, assert `slow_path_packets == 0` and the policy_deny
  disposition counter == 1 for a denied transit frame. If the fixture is too
  heavy, T1+T2 + a focused call-site assertion suffice (the call-site guard is
  a one-line `if`, trivially reviewable).
- **T4 (no regression)**: `dispatch/mod.rs:225` FabricRedirect fallback still
  reinjects (its `_from_frame` path is NOT gated by the predicate). Confirm via
  the existing dispatch tests / add one if absent.

Build/lint: `make build-userspace-dp`, `cargo test -p` the userspace-dp crate.

## 10. Smoke / validation (for /engineer)

- Deploy to `loss:xpf-userspace-fw0/fw1`, install a config with an explicit
  zone-policy DENY for a transit flow, send cold-path packets matching the
  denied flow, and confirm they are NOT forwarded (kernel-side capture on the
  far side shows zero). Before the fix: a trickle leaks. After: zero.
- Standard fast smoke (P12R iperf3 v4/v6 line-rate) to confirm no regression on
  the permitted/forwarded path.
- `make test-failover` is advisable since HAInactive is in scope (the residual-
  HAInactive reinject change could affect standby behavior). Confirm zero-drop
  failover unchanged.

## 11. Risks & rollback

- **Risk**: a disposition currently relying on the unfiltered reinject for
  legitimate delivery is now dropped. Mitigation: the allow-list is the
  SAME set the wrapper has used since its introduction; the call-site fix
  merely makes the trailing call match the wrapper's already-shipped contract.
  The only NON-wrapper-aligned site (`dispatch/mod.rs:225`) is explicitly left
  untouched.
- **Risk**: buffered-MissingNeighbor duplicate (§2.5) is untouched by Path A —
  if a reviewer deems the duplicate must also be fixed, that expands scope.
  Recommendation: keep it out of this fix (separate concern, lower severity,
  already documented as the #1901 recovery story).
- **Rollback**: single-call-site guard + a pure-refactor predicate extraction;
  revert is a one-commit `git revert`.

---

## Open questions for reviewers (hostile pass) — resolved in r1

1. §2.2 PolicyDenied→kernel-FIB trace — **CONFIRMED correct** by Codex + AGY +
   Claude SMR (no earlier drop point; the `_from_frame` enqueue reaches the TUN).
2. `tunnel_endpoint_id == 0` for a denied transit flow — confirmed the typical
   case; if a denied flow DID carry a tunnel id, the #1873 gate would drop it
   (counted) — that is the safe direction, so it does not weaken the fix.
3. Altitude — reviewers agreed Path A (call-site gate) is correct PROVIDED the
   `_from_frame` helper is documented as the raw/unchecked primitive (folded
   into Path A step 3 + §6). Filtering inside `_from_frame` (Path B) is fatal
   — breaks TWO load-bearing callers (FabricRedirect-Owned + ForwardCandidate
   build-failure).
4. Buffered-MissingNeighbor duplicate (§2.5 / issue Q3) — **DEFERRED** (not
   fixed by #1913); follow-up at /engineer time if undesirable.

## Round-1 reviewer findings (Codex + AGY + Claude SMR) — folded into r2

- **§2.1 table erratum (Codex + AGY):** `ForwardCandidate`/`FabricRedirect` are
  consumed by the forward `if` at mod.rs:1794-1798 and NEVER reach :2814 — they
  were wrongly listed in the `_` arm. CORRECTED.
- **MissingNeighbor SNAT-failure early continues (Codex + AGY):** :2533 and
  :2564 `scratch_recycle.push` + `continue`, skipping :2814 — omitted in r1.
  ADDED to the table.
- **§2.6 over-broad proof (Codex + AGY):** the r1 "the :238 else proves it's
  intentional" framing is wrong — the :238 desc branch calls the FILTERED
  wrapper which DROPS FabricRedirect, an asymmetry/pre-existing bug, not a
  clean bypass. ALSO the `slow_path.rs:61` ForwardCandidate build-failure
  fallback relies on unfiltered `_from_frame`. Both corrected; Path B is fatal
  for BOTH callers.
- **Altitude (Codex + AGY):** document `_from_frame` as the raw/unchecked
  primitive. FOLDED into Path A step 3.
- **F1 (Claude SMR):** DiscardRoute is the cleanest leak proof. ADDED to §2.4.
- **F2 (Claude SMR):** Q3 deferral made explicit. ADDED to §2.5.
- All three reviewers CONFIRMED the core diagnosis (real policy bypass, not
  benign) and the Path C rejection (re-introduces #1885).
