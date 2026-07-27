# Claude SMR hostile plan-review — round 77 (v9.9.54.31 @ ddc70aba0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.31 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.31-as-committed** — six precision pins (1 LOW, 5 nit; no new
design defect found). All seven r76 Codex folds are operative; the
stable root_id + CAS, the 40-byte frame 42 with negotiated v2, the
complete ledger TLV, and the bounded drain verify against the code
citations.

## Finding 1 (LOW — the fold says the replacement class requires extension-v2 but never says what extension-v1 now means, and the unsafe reading is the natural one)

The B2 fold makes the replacement class require "the retirement-
extension at version ≥ 2" without defining the negotiation or the
v1 peer's posture toward the REST of the extension. Two readings:
(a) v1 of the extension is legacy only for the replacement class —
frames 40/41 (fence/clearance) still work at v1, only
supersedes/frame 42 need v2; or (b) the whole extension is v2-gated
— a v1-extension peer gets NO retirement extension at all. Reading
(a) recreates exactly the defect the version exists to kill: a v1
peer applies frame 41 (additive tolerance for the supersedes tail),
installs F2 as a new fence, and retains F1 forever — the
partial-replacement state. It must be (b), with the negotiation
stated: bit 7 = extension-v2, negotiated by the same min() machine;
at extension-v1 EVERY extension frame (40-43) is illegal (never
sent, never applied), and the operator's dead-peer case falls to
the external-fencing precondition alone. One sentence decides it;
the other reading silently re-opens the r76-B2 trace.

## Finding 2 (nit — a stale-incarnation ACTIVE fence record needs its lifecycle rule)

The B3 fold's config-carried incarnation makes a removed-and-
re-added RG3 a new instance — correct — but the OLD incarnation's
fence record is `Active` in the ledger, and Active records never
compact. It can never match anything again (the new RG3 has a new
incarnation), yet it sits Active forever. State the rule: a config
replace that removes an RG TOMBSTONES that RG's active fence
records as part of the replace (they can never match again — the
tombstone is the config replace's own journaled unit); the
tombstoned records then compact on the high-water floor like every
other Cleared record; and the fence display shows stale-incarnation
records as such until compacted (never as live fences).

## Finding 3 (nit — the old family's shadow reclamation on tuple reuse is bounded by the existing reaper)

The B1 fold's identity-fenced reclamation needs its liveness bound
for the tuple-reuse case: a new family with the same root_id sees
the old family's durable version (correct), and the old family's
shadow rows/aliases are reclaimable the moment the root's
`active_cohort_id` no longer references them — which happens with
the old family's death, and the reclamation is bounded by the
SAME expiry/reaper discipline that reaps the old family's session
(its idle timeout), never by a new mechanism.

## Finding 4 (nit — the shared-hit materialize path is an admission for drain purposes)

The H4 fold's admission fence gates new admissions; it never says
what happens to `materialize_shared_session_hit`
(`session_glue/mod.rs:1092-1118`) — a path that creates local
session state from a HIT, not an admission. For drain purposes it
creates state, so it belongs in the in-flight set: state it — the
drain's in-flight watermark includes pending materializations, and
a shared hit on an excess-RG flow during the drain declines to
materialize (the packet drops; the flow re-seeds on the new owner
after the lift).

## Finding 5 (nit — the per-CPU mirror is a hint; the release path flushes it synchronously)

The H5 fold's every-hit root read will want its cheap form
eventually. State it now: the per-CPU mirror of the root's
`(active_cohort_id, version)` is a HINT (bounded by the mirror
refresh interval — priced at one worker tick); the root record is
the truth; and the release path flushes the mirror synchronously
BEFORE touching the dependents (so the release's exact-version
hiding never rides a stale mirror).

## Finding 6 (nit — the replay floor retains the last tombstone per namespace, on the same write-ahead discipline)

The M7 fold's "durable replay floor" needs its semantics: the floor
retains the LAST tombstone per `(authority, target, generation)`
namespace (the most recent terminal state, never a history), is
persisted with the same write-ahead discipline as the store itself,
and is what a replay after an authority restart reads (never the
compacted region).

## Bottom line

The v9.9.54.31 fold set closes the r76 set in the prescribed
direction, and the round's two RESOLVED dispositions (notice
lifecycle, release lifecycle) are the first adjacent-pair
resolutions of the arc. Finding 1 is the pin with teeth: "version
≥ 2" without the negotiation and the v1-posture rule is exactly
the kind of half-named gate this plan keeps getting bitten by —
one sentence (bit 7, min(), whole-extension gating) closes it, and
the other reading silently re-opens the trace it exists to close.
