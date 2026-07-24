v5 is not implementation-ready. Most r4 repairs landed, but RACE-3 exposes an unhandled startup-order defect that atomic `d.dp` publication alone cannot fix.

## MAJOR

1. **R4 chain B — PARTIAL: recovered rollback is not ordered behind startup readiness.**

   The field-race chain is real, but the timer can fire much earlier than v5 models:

   - Startup orders config load before manager initialization and dataplane setup at [daemon_run.go:157](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:157).
   - Recovery installs `time.AfterFunc` at [store_persist.go:251](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:251). It may become immediately runnable after `Store.Load` releases `s.mu`.
   - A non-first rollback invokes the full `applyConfigLocked` pipeline at [daemon_apply_commit.go:697](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:697).
   - That pipeline unconditionally calls `d.vrrpMgr.UpdateInstances` at [daemon_apply_tail.go:50](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_tail.go:50), but `d.vrrpMgr` is not constructed until [daemon_run_bringup.go:219](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:219).

   Therefore an arbitrarily short recovered timer can execute a full apply against partially initialized daemon state and nil-dereference `d.vrrpMgr`. The atomic cell does nothing for this.

   The first-commit branch also has a lifecycle race: boot can observe `inBootstrap()==false` at [daemon_run_bringup.go:490](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:490), while the timer sets bootstrap true and calls `Teardown` at [bootstrap.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:321) and [bootstrap.go:472](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:472), then boot resumes with `Start` at [daemon_run_bringup.go:494](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:494). That can leave bootstrap mode with the dataplane armed.

   The proposed test at [plan.md:590](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:590) correctly tests atomic load/store mechanics, but it does not run recovered `Store.Load` concurrently with real startup or cover `Start` versus `Teardown`.

   The plan needs a startup-ready/deferred-dispatch invariant, including early-error handling, plus a real recovery/startup ordering test.

2. **Fresh RACE-3 audit is materially incomplete.**

   A non-nil rollback traverses more `d.dp` readers than the two rows annotated RACE-3:

   - [daemon_apply.go:280](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go:280) → [daemon_apply_interfaces.go:42](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_interfaces.go:42).
   - [daemon_apply_dataplane.go:165](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_dataplane.go:165) → [daemon_apply_tail.go:491](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_tail.go:491).
   - [daemon_apply.go:333](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go:333) → [daemon_apply_routing.go:367](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_routing.go:367).

   Yet [plan.md:422](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:422)–425 still labels these rows simply serialized. They are serialized against apply writers, not against the boot writers, which take no `applySem`. That contradicts §5.4’s promised exact classification snapshot.

## MINOR

1. **R4 M2 stream repair — PARTIAL.**

   `:122` mixed standalone/HA, `:235` per-callback, and `:259` capture-once are correct. However, [plan.md:402](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:402) incorrectly calls `:67` HA-only/uniformity.

   The standalone launcher is [daemon_run.go:365](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:365). If `d.dp` is cleared before the assertion at [daemon_ha_userspace_stream.go:122](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_userspace_stream.go:122), its fallback calls `syncUserspaceSessionDeltas` at `:125`, which reads `d.dp` at [daemon_ha_userspace_stream.go:67](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_userspace_stream.go:67) before checking `d.cluster == nil` at `:68`. Thus `:67` is capture-once but mixed standalone/HA and RACE-2-reachable.

2. **RACE-3 prose and citations were not propagated cleanly.**

   - [plan.md:71](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:71) says the watcher is the “ONLY pre-publication reader chain,” contradicting RACE-3 at `:86-99`.
   - [plan.md:387](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:387) says everything else is uniformity-only, despite its RACE-3 rows.
   - The operative chain lines are registration [daemon_run.go:136](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:136), re-arm [store_persist.go:251](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:251), and invocation [store_commit.go:819](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:819), not the narrower ranges cited by v5.
   - Chain A’s promotion call is [daemon_ha.go:311](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:311); `:310` is its condition.

3. **The four-link exclusion survives ordinary current-version records, but not as an absolute accepted-state invariant.**

   Current commit paths reject a first standalone→cluster confirmed commit at [daemon_apply_commit.go:553](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:553), and only a nil rollback target enters bootstrap at `:651-683`. Thus ordinary timer re-entry remains standalone and does not broaden RACE-2 to HA.

   However, recovery explicitly accepts legacy persisted confirm records without the modern generation binding at [store_persist.go:149](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:149) and applies no topology preflight. The plan must either scope its proof to current-guard-generated records or address a recovered legacy first-commit clustered record. A1 remains field-race-safe, but the reachability claim is overbroad.

4. **The three requested comment additions are folded, but the wider stale-citation sweep is not complete.**

   The requested sites are present at [plan.md:450](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:450). Copied stale `daemon_run.go:1868` citations remain at [cluster_identity_preflight_6192_test.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/cluster_identity_preflight_6192_test.go:27) and [ha-no-hitless-restart.md:85](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/ha-no-hitless-restart.md:85), `:130`.

## R4 fold ledger

| R4 finding | Status |
|---|---|
| MAJOR chain B, recovered timer | **PARTIAL** — chain recognized; startup/lifecycle consequences and production-path regression are missing |
| MAJOR chain A, readiness `:202` | **FOLDED** — promotion and demotion both reach `userspaceDataplaneActive`; `:230/:233` correctly split |
| M2 residuals | **PARTIAL** — all named prose/guard repairs landed, but stream `:67` and the broader RACE-3 rows remain wrong |
| MINOR 1, sustained teardown quiescence | **FOLDED** — synchronized successful-stat counter, ≥2× interval, bounded |
| MINOR 3, typed-nil matrix | **FOLDED** — pointer/slice/map/chan/func typed nils plus value receiver are sufficient |
| MINOR 5, three comment additions | **FOLDED** — all three requested production entries are present; wider copied-citation cleanup is a fresh nit |

VERDICT: NEEDS-REVISION

Codex session ID: 019f9237-a035-7a31-873a-a152ad74d10b
Resume in Codex: codex resume 019f9237-a035-7a31-873a-a152ad74d10b
