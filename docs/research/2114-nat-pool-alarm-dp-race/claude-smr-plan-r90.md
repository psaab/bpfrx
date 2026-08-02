# Claude SMR hostile plan-review — round 90 (plan v92 @ `7eb2e20df0d4`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r89
pass verified the v91 residual folds against the code but did not run
the BOOKKEEPING sweep — Codex r89 found five minors including the stale
"four legs are the complete set" text and the "OTHER accesses are
required" falsehood, both of which a document-consistency pass (not a
code pass) catches. Recorded: after any fold that renumbers a set, the
next review must grep the old cardinality phrase. This pass runs the
bookkeeping sweep first, then the rest.

## A. Fold verification (r89 minors → v92)

### 1. minor-1 (class-partition completion) — FOLDED

`maps_nat.go:400` is now in the class-3 hybrid assignment (the triple:
`maps_counters.go:181`/`:233` + `maps_nat.go:400`), and the
mixed-method neutral-returns paragraph no longer lists it (it moved).
The "OTHER accesses are required" claim is deleted; the replacement
text (class-3 hybrids or class-2 by Go-side effects and signatures)
matches the code: `ClearNATRuleCounters` (:396-401, offsets-first),
`ClearZoneCounters` (:227-233, offsets-first), `SeedNATPortCounters`
(:434-437, single access, void), `UpdatePolicyScheduleState`
(:252-255, single access, nil-out), `SeedSessionIDCounter` (:611-614,
single access, void). A3's separate class-3 listing agrees.

### 2. minor-2 (per-site outcome precision) — FOLDED

The optional rule now reads "master's EXACT per-site outcome — the
silent skip, the nil-guard return, OR the skip-and-CONTINUE, preserved
site-by-site". No residual "simply returns" generalization. The two
corrections are in: compiler.go:353 continues (verified at :353-368),
loader.go:700 is a comma-ok early return (verified at :700-704).

### 3. minor-3 (§6/§8 pluralization) — FOLDED

Both the §6 parenthetical and the §8 risk-table cell now name the
IsLoaded surface (loader.go:456 → REST health.go:107 / gRPC
server_show_status.go:22, §9 leg 5) alongside the loaded-check
narrowing.

### 4. minor-4 (Detach-oracle seeding) — FOLDED

The test text now requires an explicitly seeded/seamed usable
`iface_zone_map`, and "cleanup always runs" now also EXCLUDES the
absent-`iface_zone_map` no-op. Verified against loader.go:700 (the
early return) and :711/:777 (claim discovery/deletion).

### 5. minor-5 (five-leg bookkeeping) — FOLDED

"The FIVE legs ... are the complete" set at :4854 (renumbered); the
"four-leg form at v81" historical text now carries the five-leg
correction inline; the hook-placement transition is explicitly marked
as the START-path seam (distinct from leg 5's Close-window hook). A
four-leg sweep: every remaining "four-leg" occurrence is either
historical narrative (revision history, the W-table's r23 history at
:680/:1282 — a different four-legged construct entirely) or the
corrective text itself.

## B. Fresh attacks on the v92 delta

**Attack 1 (FAILED) — a stale count survives.** Swept for "79
required" / "16 optional" / "16-site" / "13 + 3": zero occurrences
outside historical narrative. The census in §11 item 7 now reads
91 + 41 + 3 = 135, matching Codex's settled count. FAILED.

**Attack 2 (FAILED) — the five-leg set's hook semantics conflict.**
Legs (1)-(2) are pre-lock quiescent (no overlap); legs (3)-(4) use
the whole-batch hold's in-hold hook (readers block, observe armed
after release); leg (5) uses the Close-window hook after the entry
Store(false). Three distinct seams, each with the instance-scoped
one-hook-per-test protocol — no shared-hook collision because each
test arms exactly one. FAILED.

**Attack 3 (FAILED) — the Detach oracle's seeded iface_zone_map
breaks the retained fixture's classification.** The Detach test
seeds xdpLinks + xdpFlagClaims + iface_zone_map — a nonempty m.maps,
so the fixture classifies RETAINED under the two-state predicate,
consistent with the test's retained-claims purpose. No conflict with
the two-state predicate. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v92 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — all five r89 minors verified against the tree, the
bookkeeping sweep (cardinality phrases, stale counts) is clean, and
the five-leg oracle set's hook semantics are mutually consistent. My
r89 miss (skipping the document-consistency sweep) is recorded; this
pass ran it first.
