# #6386 — poll_descriptor/mod.rs leaf-extraction plan

Status: DRAFT v1 — pending adversarial plan review

## 1. Canonical contract

The full, converged decomposition contract lives in **GitHub issue #6386**
(item→module map with line refs @ `e3f64a956`, hot-path preservation contract,
test plan, sequencing, out-of-scope). This doc is the adversarial-review surface;
it does not restate #6386 line-by-line — read the issue body as the design of
record. Below are only the review-critical framing, the risk table, the
leader's firsthand verifications, and the open questions.

## 2. Issue framing (in our words)

`poll_descriptor/mod.rs` is 7,168 LOC (6,113 prod) at `e3f64a956` — 3× the
2,000-prod-LOC modularity threshold. It is two things fused: (a) the ~5,060-LOC
per-packet dispatch core `poll_binding_process_descriptor` (lines 1049–6112),
whose decomposition is **PLAN-KILLED per #4404** and is NOT touched here; and
(b) 20 free-standing pre-loop helper items (lines 62–1047, ~960 prod LOC) + 6
inline `#[cfg(test)]` modules (1,055 LOC) that test those helpers, not the loop.
This issue moves (b) into 6 cohesive `pub(super)` sibling modules —
`frag_assoc.rs`, `host_inbound_policy.rs`, `flowless_verdict.rs`,
`session_admission.rs`, `resolver_enqueue.rs`, `prerouting_scope.rs` (+ `#[path]`
test siblings) — exactly the #1327/#1697 sibling-extraction class already shipped
8× against this file. mod.rs drops to ~5,170 prod (imports + the irreducible,
plan-killed dispatch core). It does NOT reach 2,000 prod — the residual IS the
killed god-function, stated honestly.

## 3. Honest scope/value framing

The win is maintainability, not perf: every unit-testable leaf gets its own
reviewable owner file; 1,055 test lines colocate with their code; and the
future-fix class (#5689/#6122/#5802 added ~490 prod + 225 test LOC of pre-loop
helpers to this file in July alone) stops funneling through a 7k-line
merge-conflict magnet. Pure code-motion → the only runtime-relevant risk is a
CGU/inlining shift across the new module boundary (§7). *If reviewers conclude
the churn is not worth it for a file that still won't cross the threshold,
PLAN-KILL is an acceptable verdict — but note #4404 already carved this exact
leaf class out as "what survives" while killing the arm decomposition.*

## 4. Already shipped / must compose with

8 sibling modules already extracted from this file: `flow_cache_hit`,
`rx_telemetry` (#1327); `filter`, `nat_exception`, `cookie_reply`,
`reject_reply` (#1697); `debug_log_throttle`; `embedded_icmp`. New siblings
follow their exact pattern: `use super::*;` header, `pub(super)` items, `#[path]`
test siblings (the `cookie_reply.rs:129` / `reject_reply.rs:445` convention).

## 5. Concrete design

Per #6386's table. Key mechanics: each moved bare `fn` (currently private to
mod.rs) becomes `pub(super)` in its sibling; mod.rs re-imports names via `use`
so every loop call site is textually unchanged; each sibling opens `use
super::*;`. The stranded `poll_binding_process_descriptor` contract comment
(824–849) relocates adjacent to the fn at 1049; the #3020 `policy_packet_icmp`
doc stranded at 62–72 reattaches to its fn. Dependency direction is strictly
leafward (`flowless_verdict` → `host_inbound_policy` + `filter::…`; `frag_assoc`
→ `prerouting_scope` + `nat_exception::…`) — no cycles.

## 6. Public API preservation

No public (`pub`/`pub(crate)`) API changes. All moved items are module-private
today and become `pub(super)` (poll_descriptor-internal). `PreroutingIngressScope`
/ `prerouting_ingress_scope` are already `pub(super)` (unchanged). Nothing widens
to `pub(crate)` or beyond.

## 7. Hidden invariants to preserve

- Fn/enum/struct bodies byte-identical; signatures unchanged; all loop call sites
  unchanged. Verify with `git diff --color-moved=dimmed-zebra`.
- Zero per-packet allocation added/removed (moved allocations are pre-existing +
  cold: `try_enqueue_resolver` name.clone() behind the per-key throttle; event
  emitters).
- Side-effect ordering unchanged by construction: host-inbound→lo0→junos-host
  (#3485/#3019), reply-enqueue-before-deny-emit (#3615), post-commit-only
  frag-assoc install (#5146), generation-checked consult (#5624), fail-closed
  discriminator-on-miss (#6122) all live inside moved bodies or at unchanged call
  sites.
- **CGU/inlining**: `codegen-units=16`, no LTO → moving a fn to a sibling can
  change same-CGU inlining eligibility. Mitigation (the ONLY permitted non-motion
  change): carry every existing attr verbatim AND add `#[inline]` to the 6 moved
  per-packet-capable fns that lack it (`junos_host_policy_eval`,
  `junos_host_local_policy`, `ipv6_ext_header_over_limit_drop`,
  `flowless_local_delivery_verdict`, `flowless_base_resolution`,
  `prerouting_ingress_scope`). Cold emitters stay un-hinted;
  `flowless_fragment_requires_nat_translation` keeps `#[cold] #[inline(never)]`.
- **Codegen spot-check**: before/after `objdump -d`/`nm` on release
  `xpf-userspace-dp` — the call-edge set out of `poll_binding_process_descriptor`
  into the moved symbols is unchanged. (cargo-asm 0.1.16 panics on this crate —
  use objdump.)

## 8. Risk assessment

| Class | Level | Rationale |
|---|---|---|
| Behavioral regression | LOW | Pure code-motion; bodies byte-identical; the 6 moved test modules bind the logic RED-on-revert and run verbatim from their `#[path]` siblings; loop call sites textually unchanged. |
| Lifetime / borrow-checker | LOW | No signature/lifetime changes; `PreroutingIngressScope<'a>` moves with its impl; `use super::*;` gives siblings mod.rs's imports. |
| Performance regression | LOW-MED | Only real vector = CGU/inlining shift across the boundary; mitigated by verbatim attrs + `#[inline]` on the 6 per-packet fns + the objdump call-edge spot-check. No allocation/ordering change. |
| Architectural mismatch (#961/#946-P2/#4404) | LOW | This is the #1697 leaf class the #4404 kill explicitly identified as the surviving work; it does NOT touch the killed dispatch core. |

## 9. Leader firsthand verifications (pre-review)

- **No external code references to any moved item.** Grepped all 20 moved
  symbols across `userspace-dp/src` excluding `poll_descriptor/`: the only 6 hits
  are in COMMENTS/doc-prose (`afxdp/mod.rs:798`, `event_emit.rs:258`,
  `screen/mod.rs:8`, `forwarding/fabric.rs:412`, and two `///` lines in
  `tests_gre_local_delivery.rs`) — no `use`, no call. `pub(super)` is therefore
  safe (afxdp/ never resolves these at compile time). Comment cross-references
  stay valid (symbol names unchanged).
- Master base confirmed `e3f64a956`; module inventory matches #6386.

## 10. Test plan / merge gate

Full `cargo test --release` green (6 moved test modules run verbatim from
`#[path]` siblings); `make test` (Go+Rust) green; objdump call-edge spot-check;
loss-userspace-cluster smoke on the implementing PR (RX hot path incl.
host-inbound/flowless/reject-cookie): iperf3 v4+v6 push+reverse to
172.16.80.200 / 2001:559:8585:80::200, host-inbound sanity (mgmt admitted; a
host-bound deny drops+emits), a fragmented-traffic pass (`frag_assoc` +
`flowless_verdict` move). `make test-failover` NOT claimed — no HA/failover/
session-sync code touched. Gate: behavior-preserving PR + Codex + AGY hostile +
independent Claude review.

## 11. Sequencing

- PR-1 (attr-verbatim): `frag_assoc`, `session_admission`, `resolver_enqueue`,
  `prerouting_scope` + test siblings.
- PR-2 (adds `#[inline]` hints + objdump spot-check): `host_inbound_policy`,
  `flowless_verdict` + test siblings.
- One combined PR acceptable (both halves motion-only); full smoke gates the
  final PR, `cargo test` gates each. Extractions share mod.rs → serial (one
  engineer, one logical commit per module); NOT parallelizable across agents.

## 12. Out of scope

Any restructuring of `poll_binding_process_descriptor` (1049–6112) — PLAN-KILLED
#4404. No logic/signature/behavior changes, no features, no visibility wider than
`pub(super)`, no changes to the 8 existing siblings beyond mod.rs `use` lines.

## 13. Open questions for adversarial review

1. Is the `pub(super)` widening (bare `fn` → `pub(super) fn`) genuinely the
   minimum, or does any moved item's caller sit in a DESCENDANT of poll_descriptor
   (a sub-sub-module) that would need `pub(crate)`? (Leader check says all callers
   are in mod.rs itself → `pub(super)` suffices — verify.)
2. Are the 6 `#[inline]` additions safe? Could adding `#[inline]` to
   `flowless_local_delivery_verdict` / `flowless_base_resolution` (large-ish fns)
   BLOAT the caller or change behavior vs. leaving them un-hinted? Is "restore
   inlining eligibility ≥ status quo" the right target, or should some stay
   un-hinted to match today's actual (cross-file-would-not-inline) reality?
3. Does moving `frag_assoc` + `flowless_verdict` (which reference
   `nat_exception::…` / `filter::…` / `host_inbound_policy` fns) create any
   `use super::*;` ambiguity or a cycle once both are siblings?
4. The 6 test modules move to `#[path]` siblings — do any reference mod.rs-private
   items (not in the moved set) via `super::` that would break once relocated?
5. Is one combined PR safer than the PR-1/PR-2 split for a reviewer verifying
   motion-purity (one `--color-moved` diff vs two), or does isolating the
   `#[inline]` discussion in PR-2 add real value?
6. PLAN-KILL check: does this plan stray one inch into the #4404-killed dispatch
   core, or stay strictly on the pre-loop leaf surface?
