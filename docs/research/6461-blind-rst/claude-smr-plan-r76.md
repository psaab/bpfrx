# Claude SMR hostile plan-review — round 76 (v9.9.54.30 @ 4b3982ca5)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.30 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.30-as-committed** — seven precision pins (1 LOW, 6 nit; no
new design defect found). All seven r75 Codex folds are operative;
the single root record, the drain admission fence, the supersedes
tail + frame 42, and the conditional mechanism verify against the
code citations.

## Finding 1 (LOW — the rg_incarnation has no provenance that keeps both nodes agreeing on it)

The H6 fold binds the ledger scope to `(rg_id, rg_incarnation)` and
correctly notes `group_state.go:20, :42` has no such field today.
But the fold never says where the incarnation comes FROM, and the
two obvious provenances break differently: (a) runtime-derived
`(process_incarnation, per-RG counter)` — each node derives a
DIFFERENT incarnation for the same logical RG (different process
incarnations, different creation order on a fresh peer), and the
ledger's `(rg_id, rg_incarnation)` would never match across the
pair — the union merge silently forks the fence state; (b)
config-carried — minted once at RG creation and synced with the
config, so both nodes read the same value. It must be (b), and the
fold must say it: the `rg_incarnation` is minted at RG creation by
the daemon, carried in the synced config as a system-generated
display-only field (the operator never edits it), and a config
sync to a fresh peer re-establishes the SAME incarnation for the
same logical RG (that is what makes the ledger's scope meaningful
across nodes). Without the sentence, two conforming implementations
choose (a) and (b) and never share a fence.

## Finding 2 (nit — the root record's address must be a fixed function of cohort_id, and the flip has ONE owner)

The B1 fold's "well-known per-cohort address" needs two one-liners:
the address is a FIXED function of the full `cohort_id` (a
namespaced key in the same map — never a hash, so no collision
class), and the flip has exactly one owner — the cohort's minting
worker — which sequences the whole publication end-to-end (Rust
dependents → the durable journal receipt (the Go-side dependents'
completion) → the root flip). Any other shape reintroduces the
two-publisher ordering question the root record exists to kill.

## Finding 3 (nit — the extension-less receiver case is already closed by the predicate; say so)

The B3 fold's supersedes tail raises the old-decoder question
(a receiver ignoring the tail applies F2 as a new fence and strands
F1). The active-BIT-6 predicate already closes it: frames 40/41 are
illegal toward a peer whose BIT 6 is not ACTIVE, so the NOTICE
never delivers to an extension-less receiver at all — the
replacement class toward such peers belongs entirely to the
external-fencing precondition. One sentence so nobody re-derives
the old-decoder trace.

## Finding 4 (nit — at min() ≤ 1 neither side awaits a decision frame)

The H4 fold's conditional mechanism covers the owner withholding
the frame; the peer-side expectation needs its sentence: at min()
≤ 1 NEITHER side awaits a decision frame — the class commits per
the matrix's v0/v1 rows, and the next frame after the wrapper is
`ClockSync` or the CONFIRM (per the branch) — so a v1-only peer
(current code — no decision concept) and a new peer at min()=1
(matrix-derived) have the same expectation and no reconnect loop
can form.

## Finding 5 (nit — the Cleared tombstone compacts with the ledger's high-water floor)

The H5 fold's terminal Cleared tombstone is retained with no bound.
One sentence: the store's Cleared records compact on the SAME
high-water floor as the ledger (never compacting an Active record
or anything newer than the peer's acknowledged high-water), so the
store's growth is bounded by the same rule as the ledger's.

## Finding 6 (nit — the RELEASED tombstone carries a version bump, and the cache misses by revalidation)

The M7 fold's pending lifecycle never says how a cached verdict
dies at RELEASED. State: the RELEASED tombstone bumps the cohort's
version (the root record's `version` field advances); cached
entries revalidating against the root see the version mismatch and
miss; the flow re-lookups and finds the removed session — the
cache needs no explicit invalidation pass (the version IS the
invalidation), and the bump is atomic with the tombstone (one
journaled unit).

## Finding 7 (nit — the drain's production bound and pricing)

The B2 fold's admission fence on the excess RGs drops NEW sessions
on an otherwise-healthy dataplane. State the bound: the fence ends
on proof completion (lift), proof failure (operator-visible), or
the drain's deadline (the same class as the cutoff's bound); the
priced impact is NEW-flow loss on the excess RG for the drain's
duration (seconds at most; existing flows continue — the fence is
admission-scoped, never dataplane-scoped).

## Bottom line

The v9.9.54.30 fold set closes the r75 set in the prescribed
direction; the single-root-record construction is the first
publication rule in the arc with exactly one commit authority per
cohort. Finding 1 is the pin with teeth: the ledger's
`(rg_id, rg_incarnation)` scope is only as good as the
incarnation's provenance, and the fold currently lets two nodes
derive different values for it — which would silently fork the
fence state the whole ledger exists to share.
