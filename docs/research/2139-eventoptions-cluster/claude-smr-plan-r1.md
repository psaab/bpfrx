# Claude SMR — hostile plan review r1 (#2139/#2140/#2141/#2157)

Reviewing `plan.md` against master `0498b5143`. Bar: refute every claim;
surface PLAN-KILL candidates; find the design holes the author glossed.

## Verified claims (held up under scrutiny)

- **#2140 self-wipe is real, end-to-end.** Traced: engine `commitFn`
  (daemon_run.go:953) → `commitAndApply` → `applyConfigLocked`
  (daemon_apply.go:161) → `eventEngine.Apply(cfg.EventOptions)` at
  daemon_apply.go:1213 (confirmed inside `applyConfigLocked`, which starts at
  line 325). `Apply` does `e.lastTrigger = make(...)` (engine.go:75). So a
  triggered policy's own commit erases its own cooldown timestamp. NOT a
  by-design artifact, NOT rare — fires on EVERY remediation. **#2140 is NOT a
  PLAN-KILL candidate.** The author's worry "is the reload rare/by-design"
  is answered: it is the common case, and additionally every unrelated
  operator commit wipes ALL policies' windows. Confirmed HIGH.

- **#2157 concurrency is worse than the issue's own correction states.**
  `fireEvent` is called from per-(probe,test) goroutines (rpm.go:298 `go
  func(p,t,k)` → runProbeLoop → runSingleTest → fireEvent at rpm.go:419/422/467).
  Two probes failing simultaneously → two concurrent `HandleEvent` →
  `executeCommands` → `EnterConfigure` → one wins, one dropped. The issue
  text says policies within one event are sequential (true, engine.go:105),
  but cross-probe concurrency makes the lock race real. The plan's
  single-worker queue is the right shape and is justified by source, not
  speculation.

- **#2139 candidate-is-the-rollback is sound.** `EnterConfigure` →
  `EnterConfigureSession("")` clones `active` (store.go:682); `ExitConfigure`
  nils the candidate (store.go:765). Discard = full revert, zero bespoke
  undo. `CommitCheck` (store.go:1132) compiles the candidate without
  promoting. The plan's two-phase apply is implementable with existing API.

- **#2141 strict path already runs the validator.** `ValidateEventAttributesMatch`
  is called from `CompileConfig` (compiler.go:690) with a lenient downgrade
  flag already present. The gap is precisely the `if !ok { continue }`
  (event_options_match.go:71). Tightening it is a localized, low-risk edit.

- **ipmon precedent for #2140 is exact.** ipmon.go:218 carries forward
  `failed/since/transitions` iff `prev.cfg.MatchRPMProbe == pol.MatchRPMProbe`.
  The plan generalizes this correctly.

## Hostile findings (plan must address)

1. **[MED] #2140 window-append-before-cooldown ordering interacts with the
   reconcile.** `evaluateEvent` appends to `windows[pol.Name][ev.Name]`
   (engine.go:130) BEFORE the `withinMatches`/cooldown checks. So even a
   suppressed (cooldown'd) event still records a timestamp in the window. If
   the reconcile carries the window forward correctly this is fine — but the
   plan must ensure the carried-forward window keeps growing/pruning across
   the reconcile (the prune happens in `withinMatches`/`pruneWindows`, which
   is skipped when `withinMatches` returns early). This is a *pre-existing*
   latent unbounded-growth-under-cooldown concern (an event that is always
   cooldown-suppressed never reaches `pruneWindows` because the function
   returns at the cooldown check AFTER appending). The plan should note that
   carrying the window forward must not amplify this, and ideally prune
   on every append. **Action: add a sentence to §4.2 — prune the window on
   append (or before the early returns) so a perpetually-suppressed event
   cannot grow the window unboundedly across reloads.** Not a blocker for the
   four bugs but the plan touches this exact code and should not leave the
   latent leak worse.

2. **[MED] #2140 self-wipe could ALSO be fixed by simply not re-arming on
   the self-triggered commit — verify the reconcile actually preserves it.**
   The plan's carry-forward gates on `semanticRevision` equality. On the
   self-triggered commit, the policy set is the SAME (the remediation
   changed *other* config, e.g. a route, not the event-options stanza), so
   the revision matches and state is preserved. Good. BUT: what if the
   remediation's `change-configuration` edits the event-options stanza
   itself (a policy that rewrites another policy)? Then the revision of the
   edited policy changes and its state resets — arguably correct (the policy
   changed). The author should state this explicitly: self-edit of a
   policy's own match/action legitimately re-arms it. **Action: add to §4.2.**

3. **[MED] #2157 dedup-by-policy + #2140 cooldown interaction.** The plan
   says enqueue dedups by policy (newest supersedes). But the cooldown check
   happens in `evaluateEvent` (under `e.mu`) BEFORE enqueue, so a second
   trigger within cooldown is already filtered out and never enqueued — good,
   the dedup is mostly defensive. The one real case: trigger A is queued
   (lock held), cooldown is set, trigger B for the same policy arrives — B is
   cooldown-suppressed and not enqueued. So the queue holds at most one
   action per policy *naturally* via the cooldown, and the dedup is belt-and-
   braces. **The plan is consistent, but should state that the cooldown is
   set at evaluate time (engine.go:140), i.e. BEFORE the action runs — which
   means a queued-then-dropped action still consumed the cooldown.** That is
   a subtle correctness point: if an action is dropped (lock held past
   deadline), the cooldown was already armed at evaluate time, so the policy
   won't retry for 30 s even though nothing was applied. **Action: §4.4 must
   decide — arm cooldown at evaluate (current) vs at successful commit.**
   Recommendation: arm cooldown on SUCCESSFUL commit, not at evaluate, so a
   dropped action does not suppress the next legitimate attempt. This is a
   real design refinement the plan under-specified. (Counter-view: arming at
   evaluate prevents a queue flood from a flapping probe. Mitigation: the
   queue dedup already bounds the flood. Net: arm-on-commit is safer for the
   not-dropped guarantee #2157 wants.)

4. **[LOW] #2141 behavior change breaks an existing test.** Plan §6 already
   flags `TestAttributesMatch_UnknownFieldIgnored` must flip. Good — but the
   plan should be explicit that this test ENCODES the old fail-open behavior
   as intended (the comment at engine_test.go:88-90 says "preserves the prior
   default:continue behavior"). The engineer must update both the test and
   that comment, and the README's "Other attributes are silently ignored"
   line (README.md:34). **Action: add README.md:34 to §6 touch list.** (It is
   covered by "document strict attributes-match" but name the exact line.)

5. **[LOW] counter naming / collector plumbing is hand-waved.** §4.4 says
   "names TBD-reviewed." Fine for a plan, but the engineer must follow the
   const-metric collector pattern (metrics_userspace.go) and expose the
   engine's counters via an accessor the collector reads (the engine has no
   collector hook today). **Action: §6 should note a small accessor
   (`Engine.Stats()`) is needed so `pkg/api` can read the counters without a
   global.** Low risk, but not zero plumbing.

6. **[LOW — refuted concern] Does moving execution async break the #846
   serialization?** Checked: no. `commitFn` still goes through
   `commitAndApply` under `applySem` regardless of which goroutine calls it.
   The worker is just a different caller goroutine; the semaphore still
   serializes it with HTTP/gRPC commits. The plan's claim holds.

7. **[LOW — refuted PLAN-KILL probe] Is #2139 actually exploitable, or does
   `store.Set` already reject the whole batch?** Checked: no, it does not.
   `SetFromInput` → `ParseSetCommand` + `Set` mutate the candidate per-call;
   there is no batch boundary. The current loop explicitly logs-and-continues
   on each failure (engine.go:322-347) then commits (350). The partial-commit
   is real. NOT a PLAN-KILL.

## PLAN-KILL assessment

None of the four is a PLAN-KILL. Specifically the directive's hypothesis
"#2140's reload may be rare/by-design" is **refuted**: the reload is the
common path (every commit, including the policy's own remediation), so the
cooldown is defeated on essentially every trigger. All four are PLAN-READY.

## Required edits before PLAN-READY sign-off

- §4.2: prune-on-append note (finding 1); self-edit re-arm note (finding 2).
- §4.4: decide cooldown arm timing — recommend arm-on-successful-commit
  (finding 3); this is the one genuine design refinement.
- §6: add README.md:34 and `Engine.Stats()` accessor (findings 4, 5).

These are refinements, not redesigns. With them folded, the plan is
internally consistent and implementable against the existing API. Verdict:
**PLAN-READY (all four), pending the three §4 refinements above.**
