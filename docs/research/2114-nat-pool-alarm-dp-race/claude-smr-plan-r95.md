# Claude SMR hostile plan-review — round 95 (plan v98 @ `f9137e30ee67`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r94
pass enumerated the 41 reads but accepted the oracle-role definition
without testing its EXCLUSIVITY — Codex r94 found it non-exclusive in
both directions (a MAJOR). Recorded: a definition-by-criterion must be
tested for both under- and over-selection against the intended set.
This pass walks all 17 sites against the named legs first, then the
rest.

## A. Fold verification (r94 M1 → v98)

### The extensional definition + coextensive coverage — FOLDED

The 17-site subset is again extensional ("the 17 sites ARE the
enumerated list — the list is the definition"). I walked ALL 17
sites against the named legs:

- The 14 if-ok sites: ClearStaticNATEntries' pair (:261/:274) via
  the v91 v4→v6 continuation leg; SetNAT64Config's :300 via the new
  v98 (i) required-present/optional-absent leg; ClearNAT64Configs'
  :328 via the v89 discriminating chain; the seven stale sites via
  the v89 all-maps-processed legs; SessionCount's pair via the v89
  v4+v6 leg; setXDPAttachedFlag's :730 via the v91 vlan→physical
  continuation leg.
- The 2 single-value sites: compiler.go:353 via the v91 Compile
  continuation leg; loader.go:591 via the new v98 (ii) absent/present
  fixture pair.
- The comma-ok early return: loader.go:700 via the new v98 (iii)
  absent-iface_zone_map no-op leg.

All 17 covered. The three new legs are implementable (each is a
fixture-seeded quiescent assertion, no new hook semantics) and do not
conflict with the Detach leg (the absent-iface_zone_map leg is a
SEPARATE fixture from the Detach leg's map-present seed — the text
says "distinct from the Detach leg's map-present seed" explicitly).
The pattern-not-membership phrasing for ClearSessionCounts/
GetMapStats holds: their selectors sit in the single-access-selector
set, and the continuation PATTERN applies to their multi-runtime-map
execution without making them mixed-subset members. FOLDED.

## B. Fresh attacks on the v98 delta

**Attack 1 (FAILED) — the extensional list is an unchecked silent
gap.** The list IS load-bearing for the oracle coverage, and the
checking mechanism exists: the AST canary's stale-allowlist self-check
pattern (the /engineer pass asserts the inventory against the parsed
source — the same compile-time-invariant discipline as the registry
canary's exact allowlist). The plan's census (135 = 91+41+3) plus the
per-file optional table gives the /engineer pass a cross-check: any
site not in the 17 must appear in the single-selector or mixed-method
sets. Review-only would be weaker, but the invariant-checking
discipline is the plan's own §9 canary pattern. FAILED (as a blocker;
the /engineer pass's cross-check is noted).

**Attack 2 (FAILED) — the v98 (iii) leg contradicts the Detach
qualification.** The Detach leg (map-present seed) and the (iii) leg
(map-absent no-op) are DIFFERENT fixtures testing DIFFERENT paths —
:700's early return vs :711/:777's claim discovery. The plan text
separates them explicitly. No shared-fixture collision. FAILED.

**Attack 3 (FAILED) — the extensional revert re-opens the r93
transitivity hole.** The r93 hole was the CRITERION's transitivity;
the extensional list has no criterion. The host-shape description
(15+2) is explicitly marked as description-only. No transitivity
claim survives. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v98 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — all 17 enumerated sites walked against named legs
(full coverage), the three new legs are implementable and
non-conflicting, and the extensional definition closes the r94
non-exclusivity without re-opening the r93 transitivity hole. My r94
miss (not testing the criterion's exclusivity) is recorded; this
pass tested both directions.
