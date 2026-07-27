# Claude SMR hostile plan-review — round 74 (v9.9.54.28 @ ee70c10ff)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.28 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.28-as-committed** — seven precision pins (1 LOW, 6 nit; no
new design defect found). All seven r73 Codex folds are operative;
the per-cohort bits, the excess fence, the config-carried ledger,
and the commit matrix verify against the code citations.

## Finding 1 (LOW — a cohort has K commit bits, and flipping them one-by-one exposes a torn cohort mid-publication)

The B1 fold gives every value its own `(commit_bit, payload)` and
"flips THAT COHORT'S bit LAST" — but a cohort is K values (session
row, NAT alias, wire alias, fragment shard), and K bits flip
one-by-one. A packet reading mid-flip can see the forward session
row (bit=1) while its NAT alias (bit=0) is still hidden: the row's
decision references the alias, the alias lookup misses, and the
packet takes a pre-NAT or drop path for a flow whose commit is
half-done — a correctness fault on the fast path during EVERY
publication, not just a crash window. The construction that closes
it is one sentence and matches how the lookups are already shaped:
the FORWARD ROW's commit bit is the cohort ROOT — every
dependency's bit flips FIRST, the row's bit flips LAST, and
reverse-direction alias values carry no answer of their own (a
pointer, not a verdict — the row's bit governs the response).
Then: row visible ⇒ every dependency's bit was already set (the
ordering), so no lookup shape can observe a torn cohort. Without
the root rule, "flip the cohort's bit last" is undefined for K > 1.

## Finding 2 (nit — the excess fence can blackhole an actively-used RG the authority never knew, and the pricing must be stated)

The B2 fold's whole-incarnation fence on excess membership: B is
PRIMARY for RG3 (an RG A never had in its config — the skew case).
The fence takes B out of RG3's election; A doesn't know RG3 exists,
so RG3 has NO candidate and its production traffic dies until
config convergence. That is the right fail-closed trade (Codex's
r73-B2 prescription), but it must be priced: the excess fence is
operator-VISIBLE (the fence display shows the fenced excess — the
display rule the fold already carries), the excess's sessions are
takeover candidates for the other node only after config
convergence teaches it the RG, and the convergence proof is the
receiver's config generation reaching the authority's
`membership_epoch` (not merely time passing).

## Finding 3 (nit — the clearance tombstone's exact-match and superseded-record no-op rules)

The B3 fold's tombstones need two one-liners against the succession
case: a tombstone is honored ONLY for its exact `(authority
incarnation, retirement generation)` tuple (A1's tombstone clears
A1's fence — legitimate operator intent from before A1 died); a
tombstone naming a SUPERSEDED record (A2 reissued the fence as G2,
superseding G1 by reference) is a no-op; and the generation
ordering protects A2's newer fence from any stale tombstone (a
tombstone for (A1, G1) can never match (A2, G2)).

## Finding 4 (nit — the tombstone/decrement two-record discipline)

The H4 fold says the tombstone is written "BEFORE (atomically
with)" the decrement. Make the discipline exact: TWO records —
the tombstone lands strictly first, the decrement is idempotent on
replay, and the derived count recomputes from receipts (tombstoned
excluded) — so a crash between the records leaves the holder
tombstoned and the rehydration's derived count already correct
(the phantom-holder case cannot arise in either crash window).

## Finding 5 (nit — the (v2-proof, repair-v1) connection's decision-frame illegality)

The H5 fold's matrix says (v2-proof, v0/v1) commits at the
proof-verified transcript. State the corollary: at (v2-proof,
min()=v1) there IS no tentative v2 (min() < 2), so the decision
phase does not exist and NO `CAPABILITY_DECISION`/`ACK` frame is
sent or expected on such a connection (the 33-34 predicate —
"mutually derived tentative v2" — already excludes it; one
sentence makes the matrix and the frame table read as one rule).

## Finding 6 (nit — the notice store's capacity bound and wake idempotence)

The H6 fold's keyed store needs its bound: the store is bounded
(N per target), overflow REJECTS the newest retirement with an
operator error (fail-visible — never evict-oldest, which would
silently drop a confirmed retirement), and the wake-on-activation
trigger is idempotent (a flapping capability re-wakes; the
freshness rule discards stale notices either way).

## Finding 7 (nit — the adoption reissue names the superseded record explicitly)

The H7 fold's successor reissue must name what it replaces: the
reissued NOTICE carries `supersedes = (old_authority_incarnation,
old_retirement_generation)` explicitly; B REPLACES the named record
(no union — A1's clearance can never arrive and need never arrive);
a reissue naming nothing adopts nothing (a genuinely new
retirement, not a successor adoption).

## Bottom line

The v9.9.54.28 fold set closes the r73 set in the prescribed
direction, and the three reviewers' traces were again the same set
(Codex B3 = AGY T73-2 = SMR F1 on the successor anchor; Codex H4 =
SMR F4 on the holder tombstones). Finding 1 is the pin with teeth,
and it is the same class as r73's domain-generation finding: every
"atomic commit" in this plan eventually has to answer "atomic
across how many values" — the cohort-root rule answers it once,
for every domain at once.
