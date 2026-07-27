# Claude SMR hostile plan-review — round 71 (v9.9.54.25 @ b301a2e7d)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.25 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.25-as-committed** — five precision pins (1 LOW, 4 nit; no new
design defect found). All four r70 Codex folds and the AGY r70 set are
operative; the commit cell, the split carriage, and the marker
layouts verify against the code citations.

## Finding 1 (LOW — the commit cell as folded is a discipline ("every lookup masks"), and disciplines like that are exactly what keep failing in this plan)

The B1 fold's commit cell is "a per-cohort visibility flag in the
shared map that EVERY lookup masks with". Enumerate the lookup
families that must remember: the fast-path session lookup, the
reverse-alias lookup, the NAT64 forward-wire immutable match
(`lookup.rs:258-293` via `shared_ops.rs:614-628`),
`materialize_shared_session_hit` (`session_glue/mod.rs:1092-1118`),
the flow-cache seed path, the prewarm/upsert imports, and every
future lookup added to the shared map. One family forgetting the
mask recreates the early-visibility window for that family — and the
fold's own history (six rounds of "sweep the family that was
forgotten") predicts that outcome. Construct invisibility instead:
the cohort's rows are keyed under a STAGING key namespace that no
canonical lookup can match, and the commit is ONE atomic key-space
publication (staging → canonical in a single map batch) — a lookup
cannot see hidden state by construction, no per-family discipline is
required, and the atomicity Codex's B1 demands is the batch itself.
Keep the visibility-flag text only as the semantic model; name the
key-space construction as the mechanism.

## Finding 2 (nit — the two-channel fence ordering needs the NOTICE-first rule)

The B2 fold splits the fence across the heartbeat (summary) and the
sync channel (`RETIREMENT_NOTICE` detail) with a fail-closed rule for
summary-before-detail. The other order is unstated: the NOTICE is
itself authenticated (it rides the authenticated session-sync
connection — the same trust domain), so a NOTICE arriving before the
summary APPLIES immediately (the detail is complete on its own); the
summary's later arrival dedups on the exact namespace. And the
summary's real role is the partition case — the sync channel dies
with the partition, so the heartbeat summary is the only carrier
that can reach a partitioned peer; the NOTICE is the
connected-case detail. One paragraph names both directions.

## Finding 3 (nit — the extended-marker parse rule for v0 receivers)

The H3 fold preserves the `bulk_epoch` prefix at offset 0 but never
states the v0 parse rule for the longer markers. State it: a
repair-v0 receiver reads the leading u64 and IGNORES the trailing
extension bytes (the same decode tolerance as the capability word —
read the declared frame length, parse the known prefix, skip the
rest); a repair-v1 receiver requires the full extension (a truncated
extension is a protocol violation and closes).

## Finding 4 (nit — the v1-proof proof input and the vector coverage)

The M4 fold names the two sequences but not the v1-proof proof's
input or test coverage. State: the v1-proof `AUTH_PROOF` input is
EXACTLY the existing nonce-only proof (`HMAC(tag || nonce)`,
`sync_auth.go:217` — production-tested by the current suite); the
golden vectors in §5.8 cover ONLY the NEW v2 transcript (a v1-proof
vector is unnecessary — the v1 proof is the deployed behavior, not a
new contract).

## Finding 5 (nit — the completed-repair receipt's restart semantics)

The receipt re-ACK rule (same-pair-same-tuple → re-ACK) never says
whether the receipt survives a restart (`manager.go:372, :386`
recreate the maps empty). A duplicate `JOURNAL_END` arriving
post-restart with no receipt must not be silently discarded (the
sender wedges). State: the completed-repair receipt persists with
the same write-ahead discipline as the commit receipt; a
restart-wiped receipt falls back to re-ACK-if-table-complete (the
re-ACK is truthful iff the receiver's table reflects the journal —
verified against the incumbent state — else the repair re-runs; an
unknown-pair terminal frame with no active obligation re-ACKs when
the table proves the content and is a protocol violation otherwise).

## Bottom line

The v9.9.54.25 fold set closes the r70 set in the prescribed
direction, and the round's three-way overlap was again exact (Codex
B1 = AGY Q1 = SMR F1 on the commit-cell atomicity; Codex B2 = AGY
Q2 on the fence carriage). Finding 1 is the pin with teeth, and it is
the same tooth this plan has been bitten by for ten rounds: a rule
phrased as "every X must remember to Y" is a future BLOCKER queued
for whichever lookup family is added next — the key-space
construction removes the class of failure instead of disciplining it.
