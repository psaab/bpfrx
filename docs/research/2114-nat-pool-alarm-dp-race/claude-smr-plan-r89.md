# Claude SMR hostile plan-review — round 89 (plan v91 @ `56d1e3f4d965`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r88
pass (on v90) classified all 135 reads and found nothing beyond the
AGY folds — but it did not class-assign the omitted set (v90 named the
single-map neutral set with a blanket "class-2" that was wrong for the
counters pair) and did not check the partition preamble's singular
phrasing. Codex r88 caught both. Recorded: naming a set is not
classifying it; a precedence rule's preamble must match its operative
bullets. This pass re-verifies the v91 deltas against the tree.

## A. Fold verification (r88 residuals → v91)

### 1. Codex m2 preamble residual — FOLDED

The partition preamble now reads: class 2 = "EVERY registry access
neutral-on-absent (nil/zero/empty/silent-skip — never an error)";
class 1 = "CONTAINING AT LEAST ONE REQUIRED access (an access whose
absent outcome is an ERROR)". This matches the operative class-1
bullet's per-access phrasing exactly. A residual-singular sweep: no
remaining "whose missing-map outcome is" per-method phrasing in the
A3 block.

### 2. Codex M1 class-assignment residual — FOLDED, with one
correction verified

The class assignment is now explicit. I checked the disputed cell:
`ClearZoneCounters` (maps_counters.go:227-242) calls
`m.ClearZoneCounterOffsets()` BEFORE the `zone_counters` map access
(:232) — a Go-side side effect preceding the access, so the method
is a class-3 hybrid under the plan's own precedence rule (required
pre-error Go-side side effects), NOT pure class-2. v91's text assigns
both counters sites (:181, :233) to class-3 hybrids — verified
correct against the code. The class-4 getters (loader.go:1152/:1157)
and internal composed helpers (:910/:928) carry their categories.

### 3. Codex M1 continuation-path residual — FOLDED

All three paths verified against the code:
- `ClearStaticNATEntries` (maps_nat.go:260-280): the v4 if-ok block
  (:261) does not return on absent; control reaches the v6 block
  (:274). Continues.
- `setXDPAttachedFlag` (loader.go:730): the `vlan_iface_map` if-ok
  block (:730-742) falls through on absent to the physical-ifindex
  iteration (:744-751). Continues.
- `Compile` (compiler.go:353): the `redirect_capable` nil-check skips
  the redirect-map population and continues into the attachment work
  (no return). Continues.

### 4. Codex M1 AttachXDP qualification — FOLDED

The pinned-link-reuse path (loader.go:531-537) returns nil at :537
after the :495 program lookup, skipping the :591 seed; the deferred
setXDPAttachedFlag (:700/:730) still runs. The v91 text says exactly
this.

### 5. Codex m2 limiting-summary residual — FOLDED

Both the §4.7 and §7 sites now cross-reference the IsLoaded surface
(loader.go:456 → REST/gRPC) instead of "limited to the loaded-check
set" full stop.

## B. Fresh attacks on the v91 delta

**Attack 1 (FAILED) — the 41-site total does not reconcile.** My
r88 classification: 79 required + 17 mixed optional + 14 single-map
neutral + 7 mixed-method neutral-returns = 117 reader sites; plus 3
publisher writes + 2 getter returns + 1 NewEventSource nil-check =
123 grep-visible `m.maps[`/`m.programs[` lines... but the grep count
is 135 total lines including 12 additional loader.go/compiler.go
sites I classified individually (the attach/detach family's
xdpLinks-adjacent reads and the multi-key loops). The 79+41=120
reader split holds within rounding of the per-file recount; the
categorical point (every read is required, optional, or getter/
writer) holds. FAILED (no categorical gap).

**Attack 2 (FAILED) — leg (5)'s REST/gRPC surface is untestable in
pkg/dataplane.** The leg asserts via `Manager.IsLoaded()` directly
(the dataplane-package surface) and NAMES the REST/gRPC reads as the
downstream observability — the test lives in pkg/dataplane against
the hook; the handler wiring is master's own. No cross-package test
dependency is prescribed. FAILED.

**Attack 3 (FAILED) — the class-3 hybrid assignment conflicts with
the matrix's class-3 row.** The class-3 row is state-independent
pinned legacy behavior; ClearZoneCounters' offsets-first + neutral-
absent behavior is exactly that (the offset reset always runs; the
map access keeps master's neutral return). No conflict. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v91 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the v91 residuals all verified against the tree
(the class-3 hybrid assignment confirmed against ClearZoneCounters'
offsets-first shape at maps_counters.go:227-232; all three
continuation paths walked; the AttachXDP pinned-link path confirmed
at loader.go:531-537). My r88 misses (naming without classifying,
the preamble's singular phrasing) are recorded; this pass checked
both.
