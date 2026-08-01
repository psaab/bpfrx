# Claude SMR hostile plan-review — round 69 (plan v70 @ `dd14047a6`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r68's SMR
returned PLAN-READY-WITH-NITS on v69 while Codex r68 found the armed-state
MAJOR — my r68 pass verified the watcher reachability of `Mode()` but
stopped one hop short of `SetRGActive` (`daemon_ha.go:297`). That miss is
recorded. This pass attacks the v70 A3 fold directly; all line numbers
re-verified against the worktree.

## A. Fold verification (r68 findings → v70)

### 1. Codex M1 (armed-state gate) — FOLDED, with nits m1+m2

The happens-before argument is sound under the Go memory model:
`loadUserspaceShimObjects` returns before `loaded.Store(true)`
(`loader.go:160-165` — verified the store is the last step), so all map
population is sequenced-before the release-store; a method that
acquire-loads `loaded==true` observes the fully-populated `m.maps`.
`loaded` has exactly one true-store (:164) and one false-store (:1217),
verified by grep. The no-successful-path claim holds: pre-arm, `m.maps`
is empty or mid-population, so every maps-touching method errors
("not found") or throws on master today — no caller can depend on
in-window success. The rejected publish-after-Start rationale is sound:
bootstrap's exit path (`daemon_run_naming.go:230-236`) finds the
constructed backend through the cell, so publication cannot move past
Start without an election-replay redesign. FOLDED — but the gate rule's
enumeration has two precision gaps (m1, m2 below).

### 2. Codex m1 (pure cell test leg) — FOLDED

`TestDataplaneCell_ConfirmTimerStoreVsApplyReader` is [CORE] in §9 item 2;
the gate legs (a)/(c) stay in the seed. Verified the leg has no G/H/H2
symbol. FOLDED.

### 3. Codex m2 / SMR r68 m1 (nil-receiver guard) — FOLDED

Both §4 A1 and §5.1 now read `d == nil || d.opts.NoDataplane`. FOLDED.

### 4. Codex m3 (docs/deletion inventory) — FOLDED

§5.5 names `pkg/fwdstatus/README.md:33` + `sampler.go:48`; the deletion
inventory gains the `errors` import. FOLDED.

### 5. Codex m4 (residue extraction) — FOLDED

§7's shutdown-admission invariant and §6's health-message growth
parenthetical are now verbatim in `followup-seed.md` (§7-mirror/§6-mirror
additions); §7 renumbers with the A3 invariant at item 12. FOLDED.

## B. Fresh attacks on the v70 delta (A3)

**Attack 1 (SUCCEEDED as nit m1) — the escaping-reference getter family
is not named.** The gate rule says "every exported maps-touching method,"
but `loader.go`'s accessor family returns RAW references the caller then
uses directly: `Map(name)` (:1151) and `Program(name)` (:1156) read
`m.maps[name]`/`m.programs[name]` and hand back the `*ebpf.Map`/
`*ebpf.Program`; `NewEventSource` (:1161) reads `m.maps["events"]` and
builds a ringbuf reader on it; `XDPLinks`/`TCLinks` (:1195/:1199) return
the attach-time link maps. The v70 text's "130 `m.maps[` sites"
enumeration covers the reads, but the ESCAPE semantics deserve an
explicit name: the gate on these getters returns nil pre-arm, and the
post-gate-true returned reference is fully constructed (population
finished before `loaded=true`), so the rule DOES cover them — say so,
and put the getter family in the pre-arm method-matrix test (a nil
return pre-arm, asserted). One clause in §4 A1's A3 block + the §9
matrix leg. MINOR.

**Attack 2 (SUCCEEDED as nit m2) — the ungated construction-value carve-
out is implicit.** The watcher legitimately calls `Mode()` pre-arm
(`userspaceDataplaneActive`, `daemon_ha_userspace_readiness.go:202` →
`userspace/manager.go:437` — a construction-time value, no
Start-populated state). If the enumerate-and-gate audit gates every
exported method indiscriminately, the watcher's blackhole-removal path
breaks. The v70 text scopes the rule to "maps-touching / Start-populated
state" methods, which is correct — but the carve-out must be explicit so
the /engineer pass does not over-gate: construction-time-value methods
(`Mode()`, `IsLoaded` itself) stay callable pre-arm. One clause. MINOR.

**Attack 3 (FAILED) — Teardown/Close creates a new use-after-close.**
Teardown's `loaded=false` (:1217) can strand an in-flight gated method
that passed the gate; its subsequent cilium/ebpf map op against a
closing map returns an error (library-level), never a Go fatal — and
this Teardown-vs-in-flight exposure exists on master today unchanged.
FAILED.

**Attack 4 (FAILED) — `m.programs` is a second unsynchronized map.**
`loader_userspace_shim.go:183` writes `m.programs[...]` during Start;
the A3 text's gate rule covers "any Start-populated state" and the only
readers are the same getter/method surface (no out-of-package access —
unexported field). Covered by m1's naming. FAILED (folded into m1).

**Attack 5 (FAILED) — the blocked-Start test is infeasible.** A
package-level test hook between pin iterations in
`loadUserspaceShimObjects` is the same test-seam pattern the codebase
already uses (backend-factory seams, `linkDir` override); the
method-matrix test is a plain enumeration. FAILED.

## C. Findings

### MAJOR (0)

None. The A3 fold is architecturally sound: the happens-before edge is
real, the rejected-alternative rationale holds, and the failure-shape
conversion (fatal throw / map-not-found → one typed error) is a strict
improvement with no successful-path change.

### MINOR (2)

**m1.** Name the escaping-reference getter family (`Map`/`Program`/
`NewEventSource`/`XDPLinks`/`TCLinks`, `loader.go:105-1199`) in the A3
gate rule: gate returns nil pre-arm; post-gate-true references are fully
constructed; the family joins the §9 pre-arm method-matrix assertions.

**m2.** Make the ungated carve-out explicit: construction-time-value
methods (`Mode()` — consumed pre-arm by `userspaceDataplaneActive`;
`IsLoaded` itself) stay callable pre-arm; the audit gates ONLY
Start-populated-state access.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v70's folds keep PR-1 self-contained.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the getter-family naming
and the carve-out clause). A v71 containing only these two pins is
PLAN-READY by inspection from me.
