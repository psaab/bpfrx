# Claude SMR hostile plan-review — round 94 (plan v97 @ `3dd09a5de908`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r93
pass verified the 15+2 partition arithmetic but treated the four-shape
exhaustiveness as behavioral categories without enumerating the fifth
shape — Codex r93 found the class-4 getters' direct nil return fits
none of the four. Recorded: an exhaustiveness claim over N items must
be checked against ALL N, not the subset under discussion. This pass
enumerates the full 41, then the rest.

## A. Fold verification (r93 minors → v97)

### 1. minor-1 (the oracle-role reframe) — FOLDED

The 17-site subset is now defined by its §9 oracle role ("the sites
whose absent outcome the mixed-method oracle legs exercise") with the
15+2 host shapes explicitly marked as DESCRIPTION, not a defining
criterion. The circularity attack: the oracle-role definition is NOT
circular in a coverage-hiding way — the mixed-method oracle legs are
enumerated by NAME (ClearNAT64Configs' chain, SessionCount's pair,
ClearSessionCounts, GetMapStats, the stale cleanups, plus the three
v91 continuation paths), and each named leg maps to a subset of the
17 sites; the definition points at the legs, the legs point at the
sites, and the 17-site enumeration is independently given. A coverage
gap would be a site whose absent outcome NO leg exercises — the
inventory's composition chains (AttachXDP's, ClearNAT64Configs') plus
the continuation legs cover each. FOLDED.

### 2. minor-2 (the fifth shape + the full breakdown) — FOLDED

The fifth shape (the class-4 getters' direct nil return at
loader.go:1152/:1157 — verified: `return m.maps[name]` / `return
m.programs[name]`, nil on missing key) is added. The full breakdown
14 if-ok + 1 nil-guard + 3 skip/continue + 21 comma-ok early returns
+ 2 direct nil returns = 41 reconciles with my r88 per-file
classification: the 17 mixed (14 if-ok + 1 nil-guard at
loader.go:591 + 1 skip/continue at compiler.go:353 + 1 comma-ok
early return at loader.go:700) + the 14 single-access-selector
neutral + the 7 mixed-method neutral-returns + the 2 getters +
maps_nat.go:400 (class-3, accounted in the mixed-method paragraph)
= 41. FOLDED.

## B. Fresh attacks on the v97 delta

**Attack 1 (FAILED) — a shape is double-counted.** The five shapes
are behaviorally exclusive at each site: if-ok skip (body absent),
nil-guard return (single-value, return on nil), skip-and-continue
(single-value, fall through), comma-ok early return (two-value,
return on !ok), direct nil return (getter). A comma-ok read whose
!ok branch RETURNS is the early-return shape, not the if-ok shape
(the if-ok shape's body RUNS on present). No site fits two. FAILED.

**Attack 2 (FAILED) — the oracle-role definition under-covers.**
Checked each of the 17 sites against the named legs: the 14 if-ok
sites are all inside methods with a named continuation leg (the
stale cleanups' all-maps-processed, ClearStaticNATEntries' v4→v6,
SessionCount's v4+v6, setXDPAttachedFlag's vlan→physical); the 2
single-value sites have the Compile continuation leg and the
AttachXDP chain; the comma-ok early return has the Detach leg's
seeded iface_zone_map. No orphaned site. FAILED.

**Attack 3 (FAILED) — the 41st read unaccounted.** The set
arithmetic (17+14+7+2+1 = 41) closes with maps_nat.go:400 — named
in the mixed-method paragraph with the class-3 annotation. No
orphan. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v97 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the full 41-read enumeration reconciles with the
set assignments (17 mixed + 14 single-selector + 7 mixed-method + 2
getters + the class-3 :400), the five-shape taxonomy is behaviorally
exclusive at every site, and the oracle-role definition covers each
of the 17 sites with a named leg. My r93 miss (treating
exhaustiveness as categories rather than an enumeration) is
recorded; this pass enumerated all 41.
