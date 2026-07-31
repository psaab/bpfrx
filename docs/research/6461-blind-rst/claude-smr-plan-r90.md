# Claude SMR hostile plan-review — round 90 (v10.6.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — tenth pass on
the cut line. This round I authored the v10.6.0 fold of Codex r89's
3B/2L, so this review attacks my own fold first (self-dealing check),
then re-sweeps the plan. Verdict: **PLAN YES**.

## 1. Fold verification (each Codex r89 finding, code-traced)

**r89-1 (B — RWoLB/ReplacedSyncedLocal SYN-bearing close → authoritative
HA kill).** Every link of Codex's trace verified at the branch base:
`strict_syn_check_drops_new_flow` rejects only `is_closing && !has_syn`
(`session_admission.rs:82-87`), so SYN|RST/SYN|FIN passes; the RWoLB
classifier/purge sit at `promote.rs:48`/`:165-207`; the fresh install
seeds closing/reset (`install.rs:179-180`) and emits Open
(`install.rs:235`); the fresh origin passes the Close gate
(`expire.rs:342-344`); the peer delete is unconditional
(`delete_synced.rs:16-17`); `ReplacedSyncedLocal` removes the synced
victim and raw-installs (`local_delivery.rs:90-113`). The fold (§5.6
site-3 supplement + §5.8 typed-outcomes bullet + site-3 row + §9(e)):
under peer-synced provenance the constructor suppresses the closing seed
for EVERY closing-flagged packet including SYN-bearing combos and emits
no Open; a genuinely-new tuple keeps master's raw-flags seed. This is
exactly Codex's prescription ("refuse/suppress every closing seed,
including SYN-bearing combinations, and must not emit Open").

Self-attack on the fold: (i) Does no-Open strand the entry? No — the
install is local-only probation; it clears on the first committed
non-close (matched-entry commit hook, §5.6) or reaps local-only at ≤20
s; the peer's Close delta deletes it unconditionally if the owner tears
down first (`delete_synced.rs:16`). (ii) Does the suppression break a
legitimate same-tuple re-seed? The packet is still forwarded; the entry
is alive, not marked; the flow continues and clears probation on its
next committed packet. Worst case is master's behavior minus a
replication the peer did not need (the peer holds the authoritative
row). (iii) Bare closes under RWoLB still drop at #4400 — the
round-87-accepted conservative edge, unchanged by this fold.

**r89-2 (B — re-materialization bypasses the probation fold
pre-admission).** Verified: `materialize_shared_session_hit`
(`session_glue/mod.rs:1092`) upserts unconditionally
(`upsert_synced_with_origin`, `install.rs:295`), which `remove_entry`s
the prior row and restamps `last_seen_ns` (`install.rs:352`) + wheel
(`install.rs:359`), running before input/TTL/output admission. The fold
(§5.6 site-2c + §5.8 + site-2c row + §9 "Materialize preservation"):
an identity-agreeing (canonical key AND NAT decision) existing probation
entry skips the upsert — deadline/flags preserved, packet forwarded
with the materialized decision. Self-attack: (i) identity agreement
makes the preserved K and the skipped upsert decision-identical, so
forwarding with the in-hand decision is coherent; (ii) if Codex's
placeholder/shared coexistence trace cannot actually fire for a full
probation entry, the guard is inert — fail-safe either way; (iii) a
non-probation or identity-disagreeing entry takes master's upsert
unchanged (stated), so no master's-behavior regression for live flows.

**r89-3 (B — probation deadline not fenced from HA/GC retention).**
Verified: the standby retention gate runs before removal
(`expire.rs:168-172`); SelfHeal restamps + continues
(`expire.rs:213-237`); `refresh_for_ha_transition` restamps
`last_seen_ns` (`session/mod.rs:1651`) and re-queues the wheel
(`:1666`), called from owner-RG refresh and demotion; `SharedMaterialize`
is peer-synced (`entry.rs:245`) so all three retention paths plus
companion freshness (`expire.rs:296-320`, `:490-523`) apply. The fold
(§5.6 local-only reap + §7 "Probation deadline integrity" + §9(b/c)):
probation at its immutable deadline bypasses SelfHeal/Hold/companion
retention; `refresh_for_ha_transition` preserves the deadline. Self-
attack: (i) scoping — the bypass triggers only when the entry is due,
and since probation never refreshes `last_seen_ns` (v10.5.0 fold), due
⇔ deadline passed; no live-window behavior change; (ii) all three
probation constructors (2c refuse, RWoLB, ReplacedSyncedLocal) set the
same `SessionEntry.probation` bit, so one fence covers all; (iii) the
fence cannot accelerate a NON-probation entry's reap — the gate checks
the flag.

**r89-4 (L — §3.1 table).** All four corrections re-verified against
both revisions: 19 commits (`git rev-list --count`); #6458's
`gate_fabric_zone_override_on_owner_rg` at master `fabric.rs:289` (the
worktree's `:331` is `redirect_via_fabric_if_needed`); tunnel pushes at
worktree `:739`/`:741` → master `:765-767`; `live_by_flow` field at
`nat/allocator.rs:481` in both revisions, `nat/source.rs:1548` is the
`allocate_translation` call site (the leak-site cite stands). #6473 row
added with the correct non-fatal reasoning (RWoLB re-entry derives
fresh from the packet through the full pipeline). Folded verbatim.

**r89-5 (L — editorials).** Verified: the header's "seed-lifecycle
completion" shipping claim contradicted the v10.4.0 retreat
(:1306-1311); site-9 test (b)'s exactly-one-Close promise lacked the
`MissingNeighborSeed` gate (`expire.rs:342`) the seed-class bullet
states. Both folded (header parenthetical; test (b) qualified). The
r89-2 "unqualified statements" (:1250-1252 §5.7, :1272-1273 §5.8
`lookup_with_origin` bullet) both now carry the probation exception.

## 2. Consistency sweep of the new text

- §5.6 site-3 supplement ↔ §5.8 typed-outcomes bullet ↔ site-3 row ↔
  §9(e): same rule, same names (peer-synced provenance, suppression
  incl. SYN-bearing, no Open, alive-at-probation).
- §5.6 site-2c preservation ↔ §5.8 threading bullet ↔ site-2c row ↔
  §9(a): same probe (canonical key AND NAT decision), same skip.
- §5.6 retention fence ↔ §7 deadline-integrity invariant ↔ §9(b/c):
  same four paths (SelfHeal, Hold, companion, `refresh_for_ha_transition`).
- No straggler re-references the fabric fast path as live; the v10.5.1
  qualifiers survived the fold.
- The gate itself (§5.1–§5.4, §5.7) is untouched this round — Codex's
  r89 findings were all Part-B, continuing the six-round pattern.

## 3. Bottom line

Three rounds of shrinking Codex findings (r87: 2B/1L; r88: 1B/1L;
r89: 3B/2L — count up but each precisely scoped and each folded with a
skip/preserve/suppress rule that only REDUCES state change on the
attacker-controlled paths). The v10.6.0 folds are minimal, fail-closed,
and code-verified; the plan is internally consistent end-to-end. PLAN
YES for v10.6.0. If Codex r90 verifies the folds and AGY's r89 retry
clears its infra block, the arc converges.
