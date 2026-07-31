# Claude SMR hostile plan-review — round 105 (v10.21.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-fifth
pass; I authored the v10.21.0 fold of Codex r104's 4B/2H/2M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r104-1 (B — overlapping producers, no precedence).** Verified the
collision: a closing shared materialization is validator-refused AND
independently adopts/skips/fails. The fold splits the single enum
into two fields — `validation: Option<CloseValidation>` (present only
for closing-flagged drives) and `transition: TransitionResult` — so
`(Refused, OverdueSkipped)` and `(Refused, Installed)` are both
representable and no precedence rule is needed.

**r104-2 (B — UpsertRefused consumer coverage).** Bullet (i) now
names both `OverdueSkipped` and `UpsertRefused` for the teardown
skip, and the composition maps BOTH transitions + MissingNeighbor to
the live-backed ExistingResolved buffer-only arm — verified the
mechanism Codex cited (the promote no-ops for a non-ForwardCandidate,
`promote.rs:86-90`, leaving the predecessor installed, and the seed
block would otherwise replace it via `install.rs:139`).

**r104-3 (B — placeholder OUT staging).** Verified the ordering:
substitution precedes the `keep_transient` computation
(`shared_ops.rs:602-628` before `session_glue/mod.rs:1157-1197`), and
the purge deletes only the shared/canonical key
(`promote.rs:181-190`), so an unstaged OUT would invalidate P's cache
family on a purge-class close where P survives — changing master's
cache behavior (`flow_cache.rs:352-358`,
`poll_descriptor/mod.rs:298-327`). The fold stages the identity and
commits it only on the site-2c materialization branch; the
non-materializing callers (`icmp_embed/nat_match_v4.rs:78-95`,
`nat_match_v6.rs:100-125`, `return_resolution.rs:20-28`) discard it.

**r104-4 (H — dedup/capacity/promote preimage).** The set dedups by
(key, NAT decision, orientation); capacity 4 covers P + K + S2 + the
promote preimage; overflow is impossible by construction (mutually
exclusive producers, one family each); the promote's OUT contract is
named (`maybe_promote_synced_session`, `promote.rs:71-140` /
`session/mod.rs:1673-1675`, gains a preimage OUT parameter); an
UpsertRefused→promotion records both K and S2 (plus P if shadowed).

**r104-5 (H — impossible EMPTY case).** Verified: `UpsertRefused`
necessarily has a non-peer predecessor (`install.rs:310-315`) and a
no-predecessor `ValidatorRefused` installs S2 (carrying S2's family)
— so EMPTY survives only for an overdue skip with no shadowed
placeholder, and §9 now says exactly that.

**r104-6 (M — UpsertRefused state semantics).** "Unmodified" is
scoped to the failed-upsert instant; the post-promotion outcome is
defined by the transition field composition; accounting is explicitly
allowed (`session/mod.rs:1177-1210`).

**r104-7/8 (H/M — stragglers).** §5.8's "FULL MASTER PARITY" is
replaced by the exact scope (decision + dispatch; the lookup marks
and propagates before the purge decision — `lookup.rs:105-128`,
`:198-218`, `session_glue/mod.rs:1157-1197`); §10.6.1 and both §2
teardown summaries carry the purge-class exemption.

## 2. Consistency sweep

Assertion-checked replacements throughout; every mutated paragraph
re-read in place; the two-field outcome is named identically in §5.6,
§5.8, §9, and §11. The gate (§5.1–§5.4, §5.7) is untouched for the
twentieth consecutive round.

## 3. Bottom line

PLAN YES for v10.21.0.
