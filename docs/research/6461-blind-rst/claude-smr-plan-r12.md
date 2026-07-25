# Claude SMR hostile plan review — round 12 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v8.4 (@ 9f30a1fce),
Codex r12 verdict (PLAN NO, 5B/4H/4M), AGY r12 verdict (3 SOUND, 1
contradiction). Codex's blockers re-traced against the code — including
the NAT release path, where I verified the pre-existing bug independently
before filing it.

**Verdict: PLAN NO for v8.4 as a single ship — but the verdict comes
with a restructure, and v9 executes it.** Twelve rounds have established
a clean split: the packet-level plausibility gate has been stable since
v6 (Codex r12: "substantially converged"), while every PLAN NO since
round 6 has been in the HA cleanup/Phase-2 layer, where each fix exposed
the next protocol layer. The correct response is not a thirteenth fold
of the whole Phase-2 tower — it is to ship the converged gate with
minimal HA machinery, file the pre-existing bug Codex found, and split
Phase 2 to its own research track.

## The two decisive re-adjudications

**Codex 1 (per-worker reap is not a valid family release signal):
CONFIRMED — and it is a PRE-EXISTING master bug, filed as #6522.** I
verified it independently: `reap_expired_sessions`
(`worker/loop_body/mod.rs:1481`) calls `release_source_nat_allocation`
for EVERY expired entry with no origin/holder filter; `release_flow`
(`nat/allocator.rs:1318-1330`) removes the `live_by_flow` entry on first
matching release with NO refcount (`:1664`); locally-born forwards
replicate to every sibling worker (`poll_descriptor/mod.rs:2560`,
`session_glue/mod.rs:838`); the reservation is idempotent per tuple
(`upsert_synced.rs:80`). An idle sibling replica ages out, reaps, and
frees the LIVE flow's pool port — on master, today, independent of this
plan. The reap path's own comment ("can never drop another live flow's
entry") is aspirational, not enforced. This is exactly the kind of bug
the hostile-review process exists to surface: six rounds of "cleanup
design" review kept routing through this code until someone read the
release path itself.

**Codex 5/6/8/9/12 (Phase-2 protocol layer): CONFIRMED as a class — and
the honest disposition is the split, not another fold.** Cross-node
monotonic clocks are incomparable (`observed_ns`); the wire mark has no
emission trigger (closing packets never move anchors; the entry reaps
in 2 s); version counters are process-local (a former owner or
pre-restart process can block a new owner forever); `current_owner(rg)`
is not unique during overlap; secondary fabrics have a readiness race.
Each is individually foldable — and the last six rounds prove the NEXT
layer appears every time. Phase 2 is an optimization for a bounded
residual (imported flows refuse closes until churn); it does not gate
the issue's fix. v9 moves it to `phase2-brief.md` with all eight open
questions preserved, including the smaller-alternative sketch (owner-side
validation instead of anchor import).

## Remaining findings — folded into v9's Part B

- **Codex 2 (detached pre-purge clone):** the materialize commit re-reads
  the canonical record under lock and requires incarnation match + a
  live NAT reservation (retain probe); failure discards the stale
  decision and re-resolves. Small, closed.
- **Codex 3 (cross-node clocks):** moved to the brief (question 1).
- **Codex 4 (wire mark absent + no emission):** the mark rides the
  Phase-2 tail, which is now out of this plan's scope; Phase-1 zero-
  producer residuals stay documented as hygiene-bounded (sweep cleanup),
  and the reverse-synth accept now marks the forward family ATOMICALLY
  (the forward match is in hand — the Phase-2 zero-producer case Codex
  10 names closes too).
- **Codex 6 (family clock orphans + timeout provenance):** the clock
  lives on the family's canonical-KEY record (forward when present,
  reverse for lone reverse imports, `ha/session_import.rs:78`);
  `expires_after_ns` is copied onto the shared entry at publish; the
  maps-before-indexes lock transaction is named as the refactor it is.
- **Codex 7 (non-NAT stale-policy revival):** bounded by the sweep (any
  K is better than master's never-purge) and the commit recheck; the
  revival requires an exact 5-tuple match and revives an old permit —
  the same exposure master has today for every stranded alias.
- **Codex 8 (incarnation inheritance):** forward-mint inheritance for
  all constructors; owner-ID adoption on full import moves to the
  Phase-2 brief (question 6).
- **Codex 9 (overlap authority):** fail-closed rule in the brief —
  during unresolved/dual election, apply from NEITHER (decay to the
  Phase-1 posture).
- **Codex 11 (poisoned-walk bound):** corrected in §2/§5.2 — the bound
  is spray duration + one timeout (walk packets are non-close and DO
  refresh `last_seen`); the attacker buys that with the same in-window
  guesses a plain keep-alive spray needs, so it is not a new pin
  primitive — stated without the "bounded by one timeout" overclaim.
- **Codex 12/13/14 (readiness, capacity, text):** readiness + capacity
  moved to the brief; the pinned-commit text contradictions are swept
  in v9.

## AGY r12 dispositions

3× SOUND (mutation-path inventory — including `demote_shared_owner_rgs`
as a legitimate non-stamping administrative path; overlap flap safety
under the lexicographic merge; non-owner local-anchor poisoning blocked
by the emission gate) and one valid text contradiction (my own
"event/read/push" vs "reads never touch" — fixed in v8.4.1).

## Bottom line

v9 is the convergence the campaign has been driving at: **Part A ships
the demote gate** (the issue's fix, stable since v6, HA teeth closed by
construction), **Part B ships the minimal HA machinery** (closing-never-
promote, ONE emission predicate, family-clock sweep with commit
rechecks, last-holder purge pending #6522), and **Phase 2 becomes its
own research track** with the rounds 6-12 findings preserved as a
complete design brief. The trap this process exists to avoid — shipping
an unreviewed distributed protocol inside a security fix — is exactly
what the split prevents. My verdict on v9: PLAN-READY modulo the final
round verifying (1) the split leaves no issue-harm unaddressed, (2) the
#6522 trace, (3) the sweep's commit rechecks, (4) no zero-producer
traces remain, and (5) the residual inventory is complete.
