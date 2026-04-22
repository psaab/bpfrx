## 1. Correctness of rebalance semantics
Severity: CRITICAL

Finding: The plan is internally inconsistent about what gets changed. Section 4.3 says to "move" specific hot-ring slots and even pick the "LAST" ones, but Section 4.4 then switches to `ethtool -X ... weight`, which delegates slot placement back to the driver/kernel. Those are different semantics. The claim that mlx5 supports the weighted path for this live-rebalance use case is [UNVERIFIABLE - assumption], and the fallback is not pinned anywhere concrete.

Evidence: `docs/pr/835-slice-d-rss/plan.md:131-146` says "Pick the specific slots to migrate" and then "Choose weight-based rewrite." `docs/pr/835-slice-d-rss/plan.md:162-166` gives a fallback, but `docs/pr/835-slice-d-rss/plan.md:62-64` says `pkg/daemon/rss_indirection.go` gets "no logic changes," and `docs/pr/835-slice-d-rss/plan.md:283-288` only plans a weight-failure/backoff test. Current code only proves the weight path exists for D3 boot-time apply: `pkg/daemon/rss_indirection.go:266-279`.

Remediation: Pick one mechanism and specify it exactly. Either make full-table rewrite the primary path with exact tests, or produce target-VF evidence for live `-X weight` behavior and drop the fake slot-order story.

## 2. In-flight flow disruption
Severity: HIGH

Finding: The safety claim is hand-waving. R2 says mlx5 rewrites steer "FUTURE packets" and "existing connections [are] pinned by conntrack," but nothing in the cited code ties Linux conntrack to NIC RX-ring selection. Existing D3 code is explicitly justified as safe because it runs before any AF_XDP bind, not because live rewrites are known-safe. Any claim about drivers briefly resetting RX rings is [UNVERIFIABLE - assumption] from the available files.

Evidence: `docs/pr/835-slice-d-rss/plan.md:378-381` makes the conntrack claim. Existing code says the current indirection rewrite is safe by ordering: `pkg/daemon/rss_indirection.go:17-27` and `pkg/daemon/linksetup.go:106-113` both pin the invariant to "before any AF_XDP bind." There is no comparable live-traffic proof in the plan.

Remediation: Treat mid-traffic `ethtool -X` as unsafe until measured on the target VF. Add a mandatory validation that runs long-lived traffic through repeated rebalance events and records retransmits, drops, and any link/ring reset symptoms around each write.

## 3. Stability window + cooldown math
Severity: HIGH

Finding: "After 3-4 iterations the table converges" is unsupported and likely false for the algorithm as written. With `3` consecutive `1s` samples and a `10s` cooldown, the earliest actions are roughly at `t=3,16,29,42,55s`. In a `10:1:1:1:1:1` skew, one-hot-to-one-cold 25% moves touch only one cold ring per action. Starting from the plan's `16 16 16 16 16 16`, you get a sequence like `12/20`, then `9/20/19`, then `7/20/19/18`... not "16 each."

Evidence: `docs/pr/835-slice-d-rss/plan.md:101-118,125-140` defines the 3-sample window, 10s cooldown, 25% migration, and the "After 3-4 iterations the table converges" claim.

Remediation: Add a worked convergence proof or simulation for the exact update rule, including integer rounding and repeated hot/cold selection. If you cannot show convergence and settling time on paper, the defaults are not reviewable.

## 4. Boot-time divide-by-zero / NaN
Severity: HIGH

Finding: Zero-traffic startup is not specified. The loop computes deltas immediately, then `max_rate / mean_rate` across "all workers rings." If the first real interval has zero traffic, that is `0/0`. If counters are missing, the parser returns only present rings, which contradicts the "all workers rings" ratio. The plan never states whether zero total traffic, a first-sample warm-up, or missing rings reset the imbalance counter or are treated as "no signal."

Evidence: `docs/pr/835-slice-d-rss/plan.md:91-99` defines the ratio; `docs/pr/835-slice-d-rss/plan.md:186-190` computes deltas/rates immediately; `docs/pr/835-slice-d-rss/plan.md:240-242` says missing rings are silently absent from the parsed map.

Remediation: Specify hard guards: first sample seeds state only; `sum(delta)==0` means balanced/no-signal; fewer than two valid rings means skip. Add tests for all-zero traffic, missing counters, and a counter map that omits one or more worker rings.

## 5. Kill switch + runtime disable
Severity: HIGH

Finding: The plan regresses behavior that already exists and still leaves "disable" undefined. It says the goroutine reads `rssEnabled/allowed` at startup and that "config reloads require a daemon restart," but current code already re-applies RSS on every config commit and restores default RSS immediately when disabled. The plan never says whether runtime disable stops the rebalance goroutine, prevents future writes, or restores the default table.

Evidence: `docs/pr/835-slice-d-rss/plan.md:216-227` claims startup-only state plus restart-on-reload. Current code contradicts that: `pkg/daemon/linksetup.go:117-133`, `pkg/daemon/daemon.go:2351-2394`, and `pkg/daemon/rss_indirection.go:127-147,191-223` show commit-time reapply plus immediate `ethtool -X <iface> default` restore.

Remediation: Reuse the existing reconcile semantics. Config changes must either restart the loop with new state or feed it updated state; runtime disable must immediately restore defaults and suppress further rebalance writes.

## 6. Locking / concurrency
Severity: HIGH

Finding: "No lock contention" is false on the current codebase. The plan pretends the only other caller is the one-shot boot path, but `applyConfig()` already calls `reapplyRSSIndirection(...)` on every config commit. There is no RSS-specific mutex in `rss_indirection.go` or the cited daemon paths. A rebalance tick can therefore race with commit-time restore/reapply on the same interface.

Evidence: `docs/pr/835-slice-d-rss/plan.md:221-222` says "that runs once at boot before the goroutine starts." `pkg/daemon/daemon.go:2351-2394` shows a second caller on every config apply. `pkg/daemon/rss_indirection.go:138-188,198-223,231-284` issues reads/writes directly with no synchronization.

Remediation: Introduce a single serialized owner for RSS writes, or at minimum a per-interface mutex shared by boot, reconcile, disable, and rebalance paths. Anything less leaves the kill switch and worker-count changes racy.

## 7. Test coverage gaps
Severity: HIGH

Finding: The 20 planned tests do not cover the sharp edges the plan introduces. There is no multi-interface state test even though the loop is "one goroutine, iterates over all allowed interfaces." There is no workers-greater-than-rings test for the rebalance path. The failure tests cover "logs and backs off" but not stderr/exit-code surfacing or the full-rewrite fallback. There is no race test between `reapplyRSSIndirection()` and the first rebalance tick.

Evidence: `docs/pr/835-slice-d-rss/plan.md:180-210` defines one goroutine over many interfaces. The full test list in `docs/pr/835-slice-d-rss/plan.md:229-307` has no explicit multi-interface loop test, no `workers > num_rings` case, no stderr/exit-code validation, and no boot/reconcile-vs-tick race coverage.

Remediation: Add tests for per-interface isolation, `workers > queue_count`, exact command/error propagation, fallback invocation, and serialized behavior when reconcile and rebalance contend on one iface.

## 8. `REBALANCE_TRIGGER_RATIO=1.8` defensibility
Severity: HIGH

Finding: The threshold justification is cargo-culted from the wrong dataset. The plan says `1.8` matches "#828 capture data (1.82x spread)," but the committed `1.82` I can verify is the lower bound of a bootstrap CI for Step-1 per-flow rate-spread threshold `Y`, not RX-ring packet spread from `ethtool -S`. That is a different metric, on different evidence, for a different decision rule.

Evidence: `docs/pr/835-slice-d-rss/plan.md:109-118,408-417` makes the `1.8` claim. The only grounded `1.82` I found is `docs/pr/line-rate-investigation/step1-plan.md:857-881`, which states `Y` has CI `[1.82, 2.88]`. The repo search did not surface a committed RX-ring packet-spread dataset backing `1.8`.

Remediation: Derive the trigger from committed `ethtool -S rx<N>_packets` time-series on the target mlx5 VF under known-good and bad distributions. Until then, `1.8` is numerology.

## 9. mlx5-only gating
Severity: HIGH

Finding: The driver gate is sloppy enough to break the feature if implemented literally. The plan repeatedly says "mlx5" and the pseudocode gates on `driver == mlx5`, but the existing daemon code uses the exact sysfs driver string `mlx5_core`. Any claim that future names like `mlx5e` matter here is [UNVERIFIABLE - assumption]; the plan cites no sysfs evidence for alternate names on this platform.

Evidence: `docs/pr/835-slice-d-rss/plan.md:37-38,185,289-290,416` uses `mlx5` generically. Current code is explicit: `pkg/daemon/rss_indirection.go:43-49` defines `mlx5Driver = "mlx5_core"`, and the checks at `pkg/daemon/rss_indirection.go:177-185,231-235` compare against that exact constant.

Remediation: Reuse the existing `mlx5Driver` constant or its helper path. Do not invent a new string gate in the new loop.

## 10. Plan quality
Severity: HIGH

Finding: The document overclaims and under-specifies in the same places. It asserts restart-only config behavior that current code already disproves, claims no lock contention while ignoring the existing reconcile caller, claims 3-4 step convergence with no proof, and uses "conntrack" as a magic word for NIC steering behavior. It also leans on the current D3 implementation without giving the file:line citations needed to show the intended integration points cleanly.

Evidence: Contradictions and unsupported claims are visible at `docs/pr/835-slice-d-rss/plan.md:62-64,139-146,216-227,378-390,408-417` when compared with `pkg/daemon/daemon.go:2351-2394`, `pkg/daemon/linksetup.go:106-133`, and `pkg/daemon/rss_indirection.go:127-147,231-284`.

Remediation: Rewrite the plan with explicit invariants, exact integration points, and assumptions marked as assumptions. Right now it reads like a sales pitch with code-shaped nouns.

## Verdict
PLAN-READY NO — the plan depends on unproven live `ethtool -X` semantics, contradicts the current daemon’s reload/reapply model, and does not specify a safe synchronization or convergence story.

## Round 2 Review (R2)
PLAN-READY NO

### R1 Finding Verdicts
**Finding 1 — slot-move vs weights-only: PARTIALLY RESOLVED**. `§4.3` now says `Slice D never writes individual slots`, and the first `§4.4` says the `Primary (and only) mechanism` is `ethtool -X <iface> weight`. But the document still contains a second `§4.4` that says `Fallback... then individual slot writes`, and `§9 Q2` still says `Fallback to full rewrite if the first probe fails.` That is not a clean weights-only spec.

**Finding 2 — in-flight disruption: PARTIALLY RESOLVED**. `§4.0` is real progress because it reports `Aggregate throughput 9.56 Gbps` and `Retransmits: 35 across both rewrites`, which is materially better than the old ungrounded safety claim. But the same document still says in `§8 R2` to `Verify empirically: connection count mid-rebalance ≥ pre-rebalance`, so the spike did not actually close the reset question. A connection-reset signature would need stronger evidence than 35 retransmits, and the plan still does not define that threshold or show connection-count data.

**Finding 3 — convergence: PARTIALLY RESOLVED**. `§4.3a` adds a worked four-iteration example, but the core step is still `Rates should redistribute roughly proportionally to new weights`, which is the unproven assumption that matters most. The plan itself undercuts the claim in `§4.0` by saying `R2.1... not knowable a priori`, so the `4 iterations ≈ 40 s` line is still a heuristic, not a grounded convergence argument.

**Finding 4 — guards for first sample / zero traffic / single ring: PARTIALLY RESOLVED**. `§4.5` now explicitly says `first-sample seeding, no imbalance check yet`, `zero-total-traffic = no signal`, and `fewer than 2 rings with data = can't compute ratio`, which closes the explicit `0/0` hole. But it still does not say how missing counters vs true zero traffic are distinguished, and it says nothing about counter resets or wraps feeding `deltaCounters`. The named guards exist; the edge-condition story is still incomplete.

**Finding 5 — runtime disable / restart requirement: NOT RESOLVED**. `§4.5b` says `Config reload → both paths reconcile without requiring a daemon restart` and that the kill switch makes the loop `a no-op until re-enabled`, but `§4.6` still says `config reloads require a daemon restart`, and `§8 R4` repeats `until daemon restart.` The loop pseudocode in `§4.5` also never shows the promised epoch or `rssEnabled` check. The exact suppression latency is therefore ambiguous; the best you can infer from the prose is `next tick`, but the document does not pin it.

**Finding 6 — concurrency / stale in-flight write: NOT RESOLVED**. `§4.5a` correctly adds `rssWriteMu` and says `ALL ethtool-X operations [are] strictly serialized`, but `§4.5b` only checks the epoch `at the top of each tick`. In the specific race where rebalance computes `newWeights`, then blocks while `reapplyRSSIndirection` runs, the plan does not say the stale rebalance attempt is abandoned after the lock is reacquired. Re-seeding on the next tick is not enough; the in-flight iteration itself needs an abandon-on-epoch-change rule.

**Finding 7 — test coverage: PARTIALLY RESOLVED**. `§5.8` genuinely closes several R1 gaps: `TestRebalance_MultiInterfaceStateIsolation`, `TestRebalance_WorkersGreaterThanRingCount`, `TestApplyWeights_StderrExitCodeSurfaced`, and the new first-sample / zero-traffic / single-ring tests are all on point. But there is still no explicit test for the mutex-contention scenario above, where a rebalance iteration computes weights, loses the lock to reconcile, then must not apply stale weights after unblocking. `TestLoop_ReconcileEpochResetsRebalanceState` only covers the `Next tick` case.

**Finding 8 — trigger derivation and calibration: NOT RESOLVED**. `§4.5d` is better than the old `#828` citation, but the math still uses one-ring variance as a proxy for the distribution of `max/mean` across six rings: `At one σ above mean... 1.56x. At two σ... 2.12x.` That is only a rough heuristic, which the section admits with `ORDER-OF-MAGNITUDE correct, not exact.` Worse, `§4.5d` says `§6.1 pre-flight adds a 10-sample baseline read`, but actual `§6.1` does not contain that step, so the empirical calibration backstop is not actually planned.

**Finding 9 — driver guard: RESOLVED**. `§4.5` now uses `if drv != mlx5Driver { continue }`, and the first `§4.4` explicitly says this `uses existing mlx5Driver constant from rss_indirection.go:43`. That is the right fix for the driver-string problem. The surrounding prose still says `mlx5` generically in places, but the actual guard is now specified correctly.

**Finding 10 — plan quality: NOT RESOLVED**. `§8a` claims `overclaims tightened throughout`, but the document still contains direct contradictions. The first `§4.4` says `No fallback in this PR`, the second `§4.4` says `Fallback... individual slot writes`; `§4.5b` withdraws restart-only reload behavior, while `§4.6` and `§8 R4` reassert it; `§4.5d` says `§6.1 pre-flight adds a 10-sample baseline read`, but `§6.1` does not. This is still a merged draft, not a clean R2 plan.

### New Issues (R2-introduced)
- Duplicate and contradictory sections were carried forward into R2: two `§4.4` headings, stale `§4.6`, stale `§8` risks, and stale `§9` answers now directly conflict with the claimed fixes.
- The executable logic and the prose drift apart in `§4.5`: the pseudocode shows `mu.Lock()` around the whole loop, but the actual concurrency fix is described later as `rssWriteMu`, and the promised epoch / `rssEnabled` checks are not present in the pseudocode.
- `§4.5d` claims a new `§6.1` calibration step exists, but `§6.1` was not updated to include it.
- `§7 Workflow` still says `Architect R1` and `Implement + 20 unit tests` even though the document is labeled R2 and `§5.8` raises the test target to `28 unit tests`.

### Summary
R2 improves the plan materially, but it does not actually land the fixes cleanly because the new text and the stale text coexist in the same document. Until the contradictions are removed and the reconcile / epoch / calibration behavior is specified in one consistent place, this is not plan-ready.

## R3 Verdict (Round 3 Review)

### Finding Resolution (R1 F1-F10, R2 F6/F8/F10)
- `R1-F1`: `RESOLVED` — `§2` says `Fallback path to individual-slot writes — weights-only`, `§4.3` is `Weight-shift rule (no slot writes)`, and `§4.4` is `Single path, no fallback`.
- `R1-F2`: `RESOLVED` — `§4.0` adds a live spike with `9.56 Gbps`, `35` retransmits across `2` rewrites, and the explicit conclusion that live `ethtool -X ... weight` works without `a link bounce or a driver-level reset`.
- `R1-F3`: `RESOLVED` — `§4.0` says convergence is an `Open empirical unknown — not knowable a priori`, and `§4.3a` is labelled `illustrative, not proof`, with `§6.5` handling non-convergence by revert/close.
- `R1-F4`: `RESOLVED` — `§4.2` now specifies first-sample, zero-traffic, single-ring, counter-reset, and missing-counter guards, and `§5.4` pins them with tests `#15-#18`.
- `R1-F5`: `PARTIALLY RESOLVED` — `§4.6` resolves runtime disable (`rssEnabled` atomic, `≤ 1 s` suppression latency, no restart required), but config-reload interface-set updates remain ambiguous because the goroutine is started `exactly once` in `§3.2`, iterates `allowed` in `§4.5`, and `§4.6` only mentions epoch bumps, not allowlist replacement.
- `R1-F6`: `PARTIALLY RESOLVED` — `§3.2` and `§4.5` define `rssWriteMu` plus epoch-based abandonment, but the same `§3.2` text says to wrap `applyRSSIndirection`, `restoreDefaultRSSIndirection`, and `applyRSSIndirectionOne` with the same mutex, which deadlocks nested calls.
- `R1-F7`: `RESOLVED` — `§5.5`, `§5.6`, and `§5.7` now cover stderr/exit-code handling, multi-interface isolation, workers-greater-than-ring-count, runtime disable, and the exact stale-weights race in test `#26`.
- `R1-F8`: `RESOLVED` — `§4.2a` replaces the bad `#828` citation with a multinomial-variance heuristic and `§6.1` now contains the missing empirical calibration step.
- `R1-F9`: `RESOLVED` — `§2` and `§4.4` explicitly reuse the existing `mlx5Driver = "mlx5_core"` constant.
- `R1-F10`: `PARTIALLY RESOLVED` — the R2 merge-artifact contradictions are gone in this clean rewrite (`§3` status text and the single `§4.4` / `§4.6` structure), but new logic gaps remain elsewhere in R3.
- `R2-F6`: `RESOLVED` — `§4.5` adds the missing `epochBefore` snapshot plus post-lock re-check and `§5.7` test `#26` pins the abandon-on-epoch-change behavior.
- `R2-F8`: `RESOLVED` — `§4.2a` explicitly says the derivation is `order-of-magnitude correct` rather than exact, and the previously-missing calibration step is now present in `§6.1`.
- `R2-F10`: `RESOLVED` — as a document-structure issue, the old duplicate/stale-section problem is fixed by the clean R3 rewrite; the remaining problems are new logic issues, not R2’s merged-draft contradiction.

### §4.5 Race Analysis
Under the plan’s stated model, the stale-weights race rule is correct against writer interleavings. `§3.2` says `rssIndirectionEpoch` is an `atomic.Uint64` bumped on every completed write, and `§4.5` compares epochs by inequality, not by expected next value. That means multiple external bumps between the rebalance snapshot and lock acquisition are still safe: there is no ABA problem as long as the epoch is monotonic, because any bump makes `LoadRSSEpoch() != epochBefore` true and forces abandonment.

The specific scenario in the prompt where the same rebalance attempt and another writer both bump the epoch before lock acquisition cannot happen as written. In `§4.5`, the rebalance attempt only calls `BumpRSSEpoch()` after it already holds `rssWriteMu`, after `applyWeights(...)` succeeds, and immediately before unlock. Before lock acquisition, only other writers can move the epoch. So monotonicity is preserved, and once the post-lock re-check passes, no other writer can interleave before `applyWeights`, because `§3.2` makes `rssWriteMu` the global serializer.

That closes the writer-induced stale-data window, but only for the epoch contract the plan defines. It does not make sampled packet-rate data immortal; natural traffic can shift between compute and write with no epoch change, and the plan implicitly accepts that because the epoch only tracks control-plane RSS rewrites. More importantly, the broader locking design in `§3.2` is still broken: wrapping nested callers with the same non-reentrant mutex deadlocks, so the race rule itself is sound while the surrounding integration is not.

### §4.3a Convergence Labelling
`§4.3a` is honestly labelled. The heading itself says `illustrative, not proof`, and the text immediately states the key assumption is `acknowledged as not empirically grounded in this plan, but plausible`. That is the opposite of a correctness guarantee.

The same restraint appears in `§4.0`, which calls convergence an `Open empirical unknown — not knowable a priori`, and in `§6.5`, which treats non-convergence as a revert/close outcome rather than something the paper analysis guarantees away. On labelling alone, R3 is clean.

### New Issues in R3
- `§4.2` computes `max_rate / mean_rate` only across rings `that saw non-zero packet deltas`, and `§4.3` picks `cold` only among rings with `non-zero delta`. That means pathological skews with idle rings can be invisible to the trigger. A distribution like `[4,4,4,4,0,0]` is exactly the kind of uneven 6-binding spread `§1` says this PR targets, but under `§4.2` the non-zero rings look perfectly balanced and no rebalance fires.
- `§3.2` says to wrap `applyRSSIndirection`, `restoreDefaultRSSIndirection`, and `applyRSSIndirectionOne` with the same package-level `rssWriteMu`. Since `applyRSSIndirection` already calls the other two paths, that is a self-deadlock with a non-reentrant `sync.Mutex`.
- `§3.2` says the goroutine is started `exactly once` at initial daemon start, `§4.5` iterates `for _, iface := range allowed`, and `§4.6` says config reload is handled by epoch bumps. There is still no described mechanism to replace `allowed` after startup, so reloads that add or remove userspace-bound interfaces are not actually specified.
- `§6.5` proposes `git checkout master -- pkg/daemon/` as the revert protocol. That is overly broad for a slice-specific rollback and can discard unrelated daemon work.

### Verdict
PLAN-READY NO — R3 fixes the old document-structure problems and closes the specific stale-weights race, but it still has a deadlocking mutex plan, an unresolved reload/allowlist story, and trigger logic that can ignore exactly the zero-ring skew the feature is supposed to correct.

## R4 Verdict (Round 4 Review)
PLAN-READY NO

1. `§4.2, §4.3, §4.5 pseudocode` | The idle-ring fix is still not internally consistent: trigger ratio now uses all rings, but `if nonZeroRings(delta) < 2 { continue }` still suppresses `[24,0,0,0,0,0]`, and `cold = argmin(rates) among rings with non-zero delta` still cannot move weight onto idle rings. `§4.3` also uses `ringCount = min(workers, queue_count)`, so “all NIC-exposed rings” can exceed the managed weight vector when `workers < queue_count`. | Fix: define one rebalance domain `0..ringCount-1`, zero-fill that domain for `maxMean` and `argmin`, and replace the `nonZeroRings(delta) < 2` guard with a guard on managed ring count instead of active-ring count.

2. `§3.2 mutex wrapping, §4.6 kill-switch path` | R3 new-2 is still only partially closed: `§3.2` says both `applyRSSIndirection` and `restoreDefaultRSSIndirection` are mutex-wrapped public entry points, while `§4.6` says `applyRSSIndirection(enabled=false, ...)` restores defaults via `restoreDefaultRSSIndirection`. That is still nested `rssWriteMu` re-entry on the disable path. | Fix: split locked vs unlocked restore helpers explicitly and have `applyRSSIndirection(enabled=false)` call the unlocked helper, or wrap only the true outermost entry points.

3. `§3.2 atomics/epoch, §4.5 lock re-check, §4.6 disable+reload claims` | The live reload design is not race-free when config changes but no successful write occurs: `rssEnabled/rssAllowedRef/rssWorkers` update on every invocation, but `rssIndirectionEpoch` only bumps `after any successful write completes`. An in-flight tick that already loaded old state can therefore pass the epoch re-check and still write after a disable/reload that changed config but produced no successful write. | Fix: add a separate config-generation counter bumped on every apply/reapply/restore invocation regardless of write success, and re-check that generation under `rssWriteMu` before `applyWeights` (or re-load enabled/workers/allowed under the lock and abandon on mismatch).

## Round 5
Date: 2026-04-22
Verdict: PLAN-READY NO

Findings:
1. `§4.5 pseudocode` | R4 Finding #3 is not fully closed because the code still snapshots `genBefore := rss_indirection.LoadRSSConfigGen()` AFTER `newWeights := computeWeightShift(...)`, while the comment says the snapshot must be `BEFORE computing weights`. A config change that lands during weight computation but before the snapshot still lets stale `newWeights` pass the post-lock check. | Fix: move `genBefore := LoadRSSConfigGen()` above `computeWeightShift(...)`, or recompute weights after the locked re-check.
2. `§3.2`, `§4.5`, `§2` | The new global `rssIndirectionEpoch` / `rssConfigGen` scheme creates cross-interface coupling: both are package-level, and a successful rebalance does `BumpRSSEpoch()` + `BumpRSSConfigGen()` in `§4.5`, while every iface resets when `curEpoch != s.lastSeenEpoch`. That means a write on iface A can reset iface B's `currentWeights`, `firstSample`, and cooldown, which conflicts with `§2` saying one interface's rebalance decision never references another interface's state. | Fix: make the generation/epoch tracking per-interface, or stop bumping the global counters on per-iface rebalance writes and reserve them for external apply/reapply/restore events.
3. `§5.4 test 17`, `§4.2`, `§5.2 test 6a` | R4 Finding #1 is only partially closed in the test plan. `§4.2` now says `we do NOT skip on nonZeroRings(delta) < 2`, and test `6a` says `[24, 0, 0, 0, 0, 0] ... fires`, but `§5.4` still says `TestGuard_SingleNonZeroRingSkipsRatio — 1 ring has delta, 5 have zero; no imbalance increment.` Those two test intents conflict. | Fix: rewrite or delete test 17 so the suite pins one behavior only, consistent with the new full-domain trigger rule.
4. `§3.2`, `§4.5`, `§5.7`, `§8`, `§7` | The R5 patch left stale doc references behind. `§3.2` says `Epoch` is a `write-completion marker`, but the same section now says it bumps `on every invocation regardless of write success`; `§4.5`/`§5.7`/`§8 R5` still describe the race fix as an epoch check even though the pseudocode now checks `ConfigGen`; and `§7 Workflow` / the status block still say `R3`. | Fix: rewrite the stale prose and test descriptions so `Epoch` vs `ConfigGen` have one consistent definition and the document identifies itself as the current round.

## Round 6

## R6 Verdict

**PLAN-READY: NO**

### R5 Finding Closure
- Finding 1 (ConfigGen snapshot): CLOSED — §4.5: "snapshot ConfigGen BEFORE computing weights" and "`genBefore := rss_indirection.LoadRSSConfigGen()`" now precedes "`computeWeightShift(delta, s.currentWeights)`". This closes the ordering bug.
- Finding 2 (cross-iface coupling): CLOSED — §3.2 says "Rebalance writes do NOT bump this" and "do NOT bump this either"; §4.5 adds "rebalance must NOT bump global Epoch or ConfigGen." That removes the global rebalance-write signal that would have reset peer ifaces.
- Finding 3 (test #17 contradiction): CLOSED — §5.4 now names "`TestGuard_SingleNonZeroRingFiresRatio`", says "ratio fires", and states "OLD test asserted skip". That matches §4.2: "we do NOT skip on `nonZeroRings(delta) < 2`".
- Finding 4 (stale R3 references): OPEN — §1 and §7 were updated to "Architect R5" and "round R5 → R6", but stale epoch language remains. §4.5 still says "The epoch snapshot" and "`if LoadRSSEpoch() != epochBefore { abandon }`"; §8 still says "`§4.5 epoch snapshot + re-check`".

### Q2 Epoch Consumer Analysis
- Reconcile/reset path — §3.2: "reads this via `LoadRSSEpoch()` at the top of each tick"; §4.5: "`if curEpoch != s.lastSeenEpoch`". This consumer needs successful control-plane writes only, because §3.2 also says "Rebalance writes do NOT bump this". Removing rebalance bumps is correct for this reader.
- Post-lock stale-write guard — §3.2 says "`rssConfigGen` bumped on EVERY invocation" and "Marks `RSS config intent changed`"; §4.5 checks "`LoadRSSConfigGen()` != genBefore". This consumer needs config-intent changes, including no-write invocations, not rebalance writes. Removing rebalance bumps is correct for this reader.
- Forced next-tick reseed after ConfigGen mismatch — §4.5 uses "`s.lastSeenEpoch = rss_indirection.LoadRSSEpoch() - 1`" to "Force the reconcile branch on next tick." This read needs the current control-plane epoch as a baseline, not rebalance writes; same-iface rebalance success is tracked locally by "`s.currentWeights = newWeights`".
- Test-plan consumer: external reset semantics — §5.7 test 27 is "`TestConcurrency_EpochBumpResetsCurrentWeights`". It needs successful control-plane write completion, not rebalance writes.
- Test-plan consumer: blocked race scenario — §5.7 test 26 simulates "`reapplyRSSIndirection` bumping epoch during the block". Removing rebalance bumps does not break that scenario because the described writer is reapply, not rebalance. The text is still stale relative to §4.5’s ConfigGen check.

**Verdict:** safe — the runtime readers in §3.2/§4.5 need control-plane or config-intent signals, not rebalance-write bumps; removing the rebalance bump does not strand a legitimate consumer.

### New Contradictions (R6)
1. §4.5 pseudocode uses "`LoadRSSConfigGen()`" and "`genBefore`", but the explanatory block below still says "The epoch snapshot" and "`if LoadRSSEpoch() != epochBefore { abandon }`". Those mechanisms do not match.
2. §5.7 is still "Concurrency + epoch", and test 26 still says "`bumping epoch during the block`", while §3.2 says "`rssConfigGen`" "Marks `RSS config intent changed`" and §4.5 re-checks ConfigGen. The test description trails the stated invariant.
3. §8 and §10 still map the stale-write fix to epoch, not ConfigGen. §8 says "`§4.5 epoch snapshot + re-check`"; §10 says "`§4.5 epoch snapshot + re-check; test #26`".

### Blocking Issues
1. The core stale-write mechanism is still specified two ways. §3.2 says "`rssConfigGen`" "Marks `RSS config intent changed`", and §4.5 uses "`LoadRSSConfigGen()`"; but §4.5’s explanation, §8, and §10 still describe an epoch-based post-lock check. That is still a blocking plan contradiction.
2. The test plan does not pin the distinct ConfigGen-without-epoch case that justified the R4 fix. §3.2 says "`rssConfigGen`" bumps "regardless of write success", but §5.7 test 26 only covers "`bumping epoch during the block`". The no-successful-write race is still untested in the plan.

## Round 7

## R7 Verdict

**PLAN-READY: NO**

### R6 Fix Verification
- §4.5 stale-write prose: CLOSED — the stale-write explanation now says "The ConfigGen snapshot (`genBefore := LoadRSSConfigGen()` taken BEFORE `computeWeightShift`) + re-check (`if LoadRSSConfigGen() != genBefore { abandon }`) post-lock" and no longer uses "epoch snapshot" / "Epoch re-check" language for that guard.
- §8 R5 row: CLOSED — `§8` now says the risk is "addressed by §4.5 ConfigGen snapshot + re-check; tests #26 + #29 pin."
- §10 R2-6 row: CLOSED — the `R2-6 stale-weights race after lock` row now points to "§4.5 ConfigGen snapshot + re-check; tests #26 + #29".
- §5.7 tests #29 and #30: CLOSED — `TestConcurrency_FailedApplyStillBumpsConfigGen` and `TestConcurrency_RebalanceWriteDoesNotBumpGlobalCounters` are present with matching descriptions, and the test list now runs through `30`.
- Test-count cross-check: OPEN — `§1` still says "`28 new unit tests pass`", `§5` still says "`Tests (target 28)`", and `§9` still asks "`28 tests adequate?`", while `§3.1` says "`30 unit tests`", `§5.7` enumerates tests `#29` and `#30`, and `§7` says "`30 unit tests`".

### New Blocking Issues
1. `§4.5`, `§4.6`, `§5.7` | The ConfigGen stale-write guard still snapshots too late in the tick. The loop reads live config at `§4.5` lines 350-355 and does epoch reconcile at lines 364-372 before `genBefore := rss_indirection.LoadRSSConfigGen()` at line 421. A control-plane apply / disable that lands in that window increments ConfigGen before the snapshot, so the post-lock `LoadRSSConfigGen() != genBefore` check at lines 427-431 passes even though `newWeights` were computed from pre-change tick state. `§5.7` only pins "bumping ConfigGen during the block" and failed-apply bump semantics, not this pre-snapshot window. | Fix: snapshot ConfigGen before any tick-local reads that influence the rebalance decision, or re-load and validate those inputs under `rssWriteMu` before `applyWeights`.
2. `§1`, `§3.1`, `§5`, `§7`, `§9` | The document still carries two different test targets. `§1` says "`28 new unit tests pass`", `§5` says "`Tests (target 28)`", and `§9` asks "`28 tests adequate?`"; but `§3.1` says "`30 unit tests`", `§5.7` enumerates tests through `30`, and `§7` says "`30 unit tests`". That leaves the implementation / review bar internally inconsistent. | Fix: update every count reference to `30`, or intentionally reduce the test list back to `28`.

## Round 8

## R8 Verdict

**PLAN-READY: NO**

### R7 → R8 Fix Verification
- R7 Finding 1 (snapshot-vs-lock window): PARTIALLY RESOLVED — `§4.5` adds the new locked re-validation block at lines 443-452 and `§5.7` adds test `#31` at lines 660-667, but the protection is incomplete. The locked branch only aborts on `!LoadRSSEnabled()`, `LoadRSSWorkers() <= 1`, or `!ifaceInAllowed(...)`; it does not compare the locked state to the tick-start snapshot, and it does not catch a same-state `reapplyRSSIndirection` that fires before `genBefore := LoadRSSConfigGen()` at line 421.
- R7 Finding 2 (test count drift): NOT RESOLVED — `§3.1`, `§5`, `§5.7`, and `§7` now say `31`, but `§1` still says "`30 new unit tests pass`" (line 25) and `§9 Q1` still asks "`30 tests adequate?`" (lines 796-797).
- R8 finding-map append: NOT PRESENT — `§10` ends at `R7 Finding 2 test count drift (28 vs 30)` on lines 836-837; there is no `R8` row in the finding map.

### Blocking Issues
1. `§3.2`, `§4.5`, `§4.6`, `§5.7` | The pre-snapshot stale-write race is still live for same-state control-plane reapply. `§3.2` defines `rssConfigGen` as a signal that "`RSS config intent changed`" on `EVERY invocation` of the public entry points, not only when `enabled/workers/allowed` values change (plan lines 64-70). But the new locked branch in `§4.5` only checks `!enabled`, `workers <= 1`, or iface removal (lines 443-452). If `reapplyRSSIndirection` fires between the top-of-tick reads (`§4.5` lines 352-355) and `genBefore := LoadRSSConfigGen()` (line 421) while leaving `enabled/workers/allowed` unchanged, then both the post-lock ConfigGen check (lines 437-441) and the new locked branch pass, and stale `newWeights` can still overwrite the reapply. Test `#31` still exercises a `ConfigGen` bump during the lock wait (lines 660-667), not this pre-snapshot same-state case. | Fix: snapshot `ConfigGen` before any tick-local state reads that influence the rebalance decision, or compare the locked state to the tick-start snapshot including the exact worker domain / epoch.
2. `§1`, `§3.1`, `§5`, `§5.7`, `§7`, `§9` | The test-count unification is still incomplete. `§1` / `§9` say `30`, while `§3.1` / `§5` / `§5.7` / `§7` say `31`. That keeps the acceptance bar and planned test inventory out of sync. | Fix: update every remaining count reference to `31`.

## Round 9

## R9 Verdict

**PLAN-READY: NO**

### R8 → R9 Fix Verification
- R8 Finding 1 (reapply-without-state-change race): VERIFIED — `§4.5` now takes `tickGenSnapshot := rss_indirection.LoadRSSConfigGen()` as the first line of the tick body (plan lines 350-357), before the live config loads at lines 359-365 and before counter sampling at line 384. The rebalance path then reuses that snapshot via `genBefore := tickGenSnapshot` at line 434 and the post-lock `LoadRSSConfigGen() != genBefore` check at lines 450-454.
- R8 Finding 2 (test count split): VERIFIED — `§1` now says `31 new unit tests pass` (line 25) and `§9 Q1` now asks `31 tests adequate?` (lines 809-810).
- R8 Finding 3 (finding-map missing R8): VERIFIED — `§10` now includes three R8 rows at lines 851-853.

### Blocking Issues
1. `§1`, `§6.4`, `§8` | The validation plan still does not actually require the failover run that the top-level acceptance bar demands. `§1` includes `make test-failover` passes (line 24), and `§8` calls the failover check mandatory (lines 801-805), but `§6.4 PASS iff ALL` omits any failover condition (lines 739-746) and `§6.1-§6.3` do not schedule a failover command. As written, an implementation could satisfy the formal validation section and still skip the required failover regression check. | Fix: add an explicit `make test-failover` validation step and include it in `§6.4 PASS iff ALL`.
2. `§3.2`, `§4.5`, `§5.6`, `§5.7` | The plan still does not pin the live-reload invariants for `allowed` and `workers` with tests. `§3.2` / `daemon.go` promise reload-driven allowlist and worker-count changes are picked up without restart (plan lines 105-109, 122-127), and `§4.5` says the loop reads live state on every tick (lines 359-365). But `§5.6` only tests runtime disable (`TestLoop_SkipsOnRSSDisabled`, lines 639-641), and `§5.7` only has a static `workers > ringCount` test (lines 659-660). There is no test that an allowlist removal/add or worker-count change on config reload is observed on the next tick. A bug that still live-loads `rssEnabled` but snapshots `allowed` or `workers` at goroutine start could pass the current suite. | Fix: add explicit reload tests for allowlist change and worker-count change being observed without restarting the loop.

## Round 10

## R10 Verdict

**PLAN-READY: YES**

### R9 → R10 Fix Verification
- R9 Finding 1 (failover not in PASS gate): VERIFIED — `§6.4 Acceptance` now includes `**make test-failover passes**` and explains it must run after the 10-run measurement.
- R9 Finding 2 (live-reload tests missing): VERIFIED — `§5.7` now includes `#32 TestLiveReload_AllowlistShrinkTakesEffectNextTick` and `#33 TestLiveReload_WorkerCountChangeTakesEffectNextTick`.
- Test-count cross-check: PARTIALLY VERIFIED — the document is now at `33` in `§3.1` (`33 unit tests`), `§5` (`Tests (target 33)`), `§5.7` (`Test count: **33**`), `§7` (`33 unit tests`), and `§9` (`33 tests adequate?`), but `§1 Acceptance` still says `31 new unit tests pass; no existing tests regress.`

### Findings
1. `§1`, `§3.1`, `§5`, `§5.7`, `§7`, `§9` | The only remaining issue I found is a stale test-count reference. `§1` still says `31 new unit tests pass; no existing tests regress.`, while `§3.1` says `33 unit tests`, `§5` says `Tests (target 33)`, `§5.7` enumerates tests `#32` and `#33` and ends with `Test count: **33**`, `§7` says `33 unit tests`, and `§9` asks `33 tests adequate?`. This is a documentation consistency issue, not a pre-implementation design blocker. | Fix: update `§1` from `31` to `33`.

### Convergence Assessment
- No remaining blocking architectural issues found after the full R10 read.
- Round 11 is not justified. The residual issue is implementation-review/doc-polish level, and the plan is ready for implementation once `§1` is trivially updated.
