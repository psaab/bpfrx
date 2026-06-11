# Claude SMR hostile plan review — #1760 stage-2 revisit, round 2

**Verdict on v2: PLAN-NEEDS-MAJOR (self-correcting).** Both external r2
reviews refuted my v2 adjudication of AGY r1 F1, and they are right. This
SMR records the self-correction and the hostile pass over the v3
amendments before round 3.

## Self-correction (the v2 error and why it happened)

v2 claimed the live loser "re-wins K on its next session refresh because
`update_session` unconditionally re-asserts secondary ADDS". I read
`update_session` (`session/mod.rs:928-940`) and the #1752/#1753 plan
language ("re-asserting secondary-index ADDS every refresh") and concluded
the re-assert was on the per-packet path — WITHOUT verifying who calls
`update_session` in production. The callers are: `promote_synced_with_origin`
(shared/synced promote), `refresh_for_ha_activation`/`_transition` (HA
events), and the upsert import path. `refresh_local` — the only plausible
per-packet caller — is `#[cfg_attr(not(test), allow(dead_code))]`
(`session/mod.rs:960`): TEST-ONLY. Ordinary traffic goes through
`lookup_with_origin` (`:523`) and `touch` (`:367`), which never re-index.
This is exactly the `feedback_verify_whole_function_body` failure mode
extended to callers: a claim about runtime behavior needs the call graph,
not just the function body. Both r2 reviewers (independently) caught it.

## Hostile pass over the v3 amendments

### Accepted as sound
- **W3′ revival**: `publish_shared_session` is provably on the seed path
  (`poll_descriptor:2466`) and the normal path (`:1311`); the displaced
  `SyncedSessionEntry` is already returned by `insert`. Predicate
  `displaced.key != entry.key` is immune to same-session republish
  (promote re-publishes the same forward key). Canonical-alias exclusion
  carried from v1.
- **Retraction of the event-detector defense** and the resulting honest
  coverage map in §2.3 (cases a/b/c).
- **W5 as optional + W-lite default**: the standing-collision case (b) is
  the bug's own aftermath; a watch that misses it still detects the
  install-time event for normal pairs (case a) and seed pairs (via W3′).
  Documenting the open window is honest; closing it costs an incremental
  sweep with a poll-tick budget risk (MED, gated).

### Residual concerns for round 3 (also in §11)
- **F1 (Medium)**: the LocalMiss/LocalDelivery install
  (`forwarding/mod.rs:1069`) occupies `nat_reverse_index` with neither
  shared publish nor replication. If a local-delivery session can share K
  with a transit NAT session (same interface IP), the local table on the
  reply worker — checked BEFORE the shared map
  (`lookup_forward_nat_across_scopes`, `shared_ops.rs:444`) — could even
  steer transit replies into the local-delivery path. Whether this is a
  real collision surface or definitionally disjoint (local-delivery
  reverse keys terminate at the firewall; transit Ks terminate at the
  SNAT'd internal host — both have dst=interface IP on the wire!) needs
  reviewer adjudication. If real, it is a (pre-existing) finding beyond
  #1760's enumerated modes — but for the WATCH it means W3′ alone cannot
  see it; only W5 over local tables could.
- **F2 (Low)**: W3′ counts displacement at EVERY publish of a colliding
  pair (per install, per promote) — multiplicities differ from the
  per-worker counter's; the help text should not imply the two counters
  are comparable magnitudes.
- **F3 (Low)**: W5's sweep over a slab shared with per-packet processing
  must bound per-tick work AND per-pass memory (the K-count map can reach
  live-session size); a Bloom/two-pass scheme or capping tracked Ks needs
  a one-line design note if W5 is taken.

## Verdict on v3 (this round's plan)

PLAN-READY-leaning-MINOR conditional on round-3 reviewer convergence over
Q1 (coverage map incl. LocalMiss) and Q2 (W3′ false positives). The W-vs-K
operator conditional is the honest framing: the lab cannot collide, so W's
value is entirely prospective; K is legitimate if the posture is lab-only.
I do not support A1 this round: 0 measured incidence + commit-order
inversion + unwind complexity is exactly the "measure first" case, and the
W detectors are A1's prerequisite instrument anyway.
