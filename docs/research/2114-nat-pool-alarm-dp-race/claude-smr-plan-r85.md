# Claude SMR hostile plan-review — round 85 (plan v86 @ `cee81d0b1b0f`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r84 pass
verified the escape shape but, like AGY, did not check the named
signature's sufficiency for every registry/type/caller cell — Codex r84
found the single `*ebpf.Map` helper could not serve the program
registry nor carry presence/classification. Recorded. This pass checks
the typed pair against every production access shape first, then the
rest. All line numbers re-verified against the worktree.

## A. Fold verification (r84 findings → v86)

### 1. Codex M1 (typed helper pair) — FOLDED

The single helper is replaced by `lookupMapLocked(name string) (h
*ebpf.Map, present bool, st registryState)` and
`lookupProgramLocked(name string) (p *ebpf.Program, present bool, st
registryState)` with per-class outcome rules and the canary allowlist
= the two helpers + `publishShimRegistryLocked`. Sufficiency verified
against the tree:

- 135 production registry access sites (`m.maps[`/`m.programs[` in
  non-test `pkg/dataplane`); ZERO `range m.maps`/`range m.programs`
  sites — every access is a keyed lookup, so (name in; handle,
  presence, classification out) serves every one.
- All 5 program sites are keyed lookups: the publisher insert
  (`loader_userspace_shim.go:185` — allowlisted writer, direct write
  under its own hold), `AttachXDP` (:495), `swapXDPEntryProg` (:609),
  `AttachTC` (:1086), `Program` getter (:1157 — plain `m.programs[name]`
  comma-ok-free return; the plan's class-4 fresh→nil rule reproduces
  master's missing-key→nil exactly).
- Presence is observably real: `swapXDPEntryProg` (:609-611) gates on
  comma-ok `!ok`, and the retained XDP fixture
  (`xdp_shim_decouple_test.go:321`) inserts a present-but-nil program
  — `present` distinguishes that from absent; a bare-pointer helper
  would conflate them and flip the fixture's class-3 outcome.
- No stale references: `registryLookupLocked` appears NOWHERE in v86
  (grep count 0); no contradictory "for the record" text survives in
  the normative sections (the v79 lesson applied).

### 2. Codex m1 (never-armed-Close qualification) — FOLDED

All three sites qualified: the §4 mechanics bullet (:3898 — "scoped to
an ARMED Manager's Close at v86 per r84 Codex m1", with the
`loader.go:89` empty-New + `daemon_run_bringup.go:483` bootstrap-skip
evidence), invariant 12 (:4066 — "an ARMED Manager's Close retains"),
and the §4.7 bullet (:4521 — "an ARMED Manager's Close retains").
Hunted for a FOURTH unconditional site: the only two "retains a
nonempty registry" occurrences are :4066 and :4521, both qualified;
the :3898 site carries the full qualification inline. No unqualified
instance remains.

## B. Fresh attacks on the v86 delta

**Attack 1 (FAILED) — the trichotomy misses a fourth state.** Mid-
publisher state: `loaded==false` with a partially-written registry is
UNOBSERVABLE to any helper — the publisher's whole-batch publication
holds `m.mu` for the writes AND the Store(true), so a helper taking
`m.mu` blocks during the batch and classifies either fresh (before the
hold) or armed (after). The whole-batch rule (verified: every fallible
pin step returns before the insert loops, `loader_userspace_shim.go`
:175-195) means no partial state exists outside the hold either. Three
states suffice. FAILED.

**Attack 2 (FAILED) — decision/use split through the returned
registryState.** The per-class rules consume (present, st) INSIDE the
outcome table (class-1: fresh→typed error / armed,retained+!present→
master's missing-map error / else proceed-with-handle; class-2:
fresh→neutral / else master's missing-map outcome; class-4: fresh→nil).
The caller receives the FINAL outcome (error, neutral, or the handle
itself), not a classification to re-decide — the atomic
classify-and-select rule (uniform registry-access rule, r76) is
preserved: classification and selection are one scoped operation under
the lock; only the selected handle crosses the boundary. Master
equivalence holds per cell: master's unlocked lookup observed
(loaded, presence) racily and produced exactly these outcomes modulo
the race; the gate pins the fresh-unarmed cell to the typed error,
which is the A3 deliverable. FAILED.

**Attack 3 (FAILED) — the `Program`/`Map` getters (class-4) change
observable behavior.** Master: `m.programs[name]` on an empty map
returns nil; v86 class-4 fresh→nil — identical. Retained+missing:
master nil, v86 master's missing-map outcome = nil — identical.
Present: both return the handle. No cell differs. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v86 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the typed pair serves every one of the 135 production
registry accesses (all keyed, zero iteration), the per-class outcome
table reproduces master's observable behavior in every cell except the
deliberate fresh-unarmed typed error (the A3 deliverable itself), and
the three-state classification is complete against the whole-batch
publisher. The r68-r84 chain is recorded on each round's doc.
