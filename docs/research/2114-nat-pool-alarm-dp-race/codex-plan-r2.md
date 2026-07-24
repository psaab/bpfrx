v2 is not plan-ready. The atomic-cell core is viable, but several claimed folds remain incomplete or incorrect.

### Round-one fold verification

| R1 finding | Status | Result |
|---|---|---|
| MAJOR 1 — boot-order/RACE-1 | **FOLDED** | [plan.md:59](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:59) correctly places election/watcher startup at [daemon_run_bringup.go:181](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:181) and `:203` before publication at `:469`, with the read at [daemon_ha.go:297](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:297). |
| MAJOR 2 — exhaustive/classified audit | **PARTIAL** | Classifications improved, but the table remains incomplete and still relies on a false bootstrap/HA reachability claim. |
| MAJOR 3 — snapshot boundaries | **FOLDED** | [plan.md:290](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:290) correctly specifies watchdog, shutdown, neighbor, bootstrap-arm, fence, and warm-cache snapshots. |
| MAJOR 4 — fwdstatus equivalence | **PARTIAL** | General `Build` equivalence is withdrawn, but sampler-only use is guarded only by a comment/test, not structurally. |
| MAJOR 5 — deterministic regression suite | **PARTIAL** | Arm extraction, recurrence, reversed transition intent, race target, and cluster-publication shape were added; deterministic participation by the real sampler remains unspecified. |
| MAJOR 6 — compiler completeness/canary | **FOLDED** | [plan.md:171](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:171) deliberately redesigns both canaries. The AST design is implementable. |
| MAJOR 7 — A2 and validation policy | **PARTIAL** | A2 is correctly deleted at [plan.md:253](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:253); smoke policy is still incomplete. |
| MINOR 1 — five writers/pre-goroutine framing | **FOLDED** | [plan.md:280](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:280) lists exactly five and identifies the boot race. |
| MINOR 2 — node-ID/bootstrap exclusion | **PARTIAL** | Compile-failure precedence is corrected, but the narrower bootstrap/cluster-runtime exclusion was wrongly removed. |
| MINOR 3 — health/policy classifications | **PARTIAL** | Policy invalidation is correctly APPLY-class; `daemon_health.go:141` remains falsely classified concurrent with a reachable writer. |
| MINOR 4 — typed nil | **NOT-FOLDED** | The proposed reflect guard itself can panic. |
| MINOR 5 — fair option comparison | **PARTIAL** | Mutex reasoning is corrected and Option D added, but Option D is rejected using two false claims. |
| MINOR 6 — migration/docs scope | **PARTIAL** | Migration size, architecture docs, `docs/` sweep, and `_Log.md` are added, but a live README reference and contradictory source comments remain outside the stated sweep. |

## MAJOR

1. **The typed-nil guard introduces a publication-time panic.**

   [plan.md:158-163](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:158) calls `reflect.ValueOf(dp).IsNil()` for every non-nil interface. `IsNil` panics for non-nilable concrete kinds such as a struct. `RuntimeDataPlane` has no pointer-only constraint ([apply.go:18](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:18)), and the runtime registry accepts arbitrary constructors ([dataplane.go:152](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/dataplane.go:152), [dataplane.go:215](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/dataplane.go:215)).

   Kind-check before `IsNil`, and require tests for both a typed-nil pointer and a valid value implementation.

2. **The adapter is not structurally sampler-only.**

   The proposed type still implements `fwdstatus.DataPlaneAccessor` and universally exposes `Status` ([plan.md:186-215](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:186)). Contrary to [plan.md:204](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:204), `Status` is not required by `DataPlaneAccessor`; that interface contains only `IsLoaded` and `GetMapStats` ([builder.go:35](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/builder.go:35)).

   `Build` treats the mere presence of `Status` as userspace identity ([builder.go:117](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/builder.go:117)) and maps its errors to `Unknown` at `:219`. `NewSampler` currently accepts that same broad interface ([sampler.go:57](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go:57)).

   A comment and equivalence test cannot prevent accidental `Build` use. Split a narrow sampler input—ideally `CachedStatus`-only—so the sampler adapter cannot satisfy `Build`. That necessarily revises the “`pkg/fwdstatus` untouched/out of scope” claim at [plan.md:514](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:514).

3. **The real-sampler race test is still not deterministic as specified.**

   [plan.md:469-475](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:469) merely says to “churn readers”; it does not require the real `fwdstatus.Sampler` or a barrier around the actual arm-failure store.

   No ticker seam is necessary: `Sampler.Start` synchronously invokes `sample` before starting its one-second loop ([sampler.go:61](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/fwdstatus/sampler.go:61)). Specify a blocking fake `CachedStatus`, start the real sampler on a goroutine, wait until that synchronous sample enters, execute `armBootstrapExitDataplane`, then release, cancel, and join. Barrier the direct status-reader loops as well.

4. **The regenerated audit is still incomplete and its count is not reproducible.**

   The “exhaustive” table at [plan.md:325-371](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:325) omits executable selectors including:

   - [daemon_apply_dataplane.go:397,459,463,482,485,497,501,505](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_dataplane.go:397)
   - [daemon_ha.go:842,1531,1545](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:842)
   - [daemon_ha_sync.go:1165,1297](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go:1165)
   - [daemon_run_naming.go:231](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go:231)

   The table lists `daemon_apply_dataplane.go:458`, which is only the local `deferSetter` declaration; the selector is at `:459`.

   The requested grep returns 159 total lines including comments and all five writes—not “5 W + ~159 reads.” It also cannot see the four `a.daemon.dp` selectors at [daemon_forwarding_status.go:21](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go:21). Field retyping will force edits, but it does not rescue the table’s claimed semantic completeness.

5. **The bootstrap-plus-live-cluster recurrence is unreachable.**

   [plan.md:75-77](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:75), `:113-117`, and `:332-334` claim compile-failed bootstrap can later run RACE-2 with cluster watchdog/sync/fabric goroutines alive.

   Actual lifecycle prevents that:

   - Compile failure leaves the compiled active config nil ([daemon_run_bringup.go:287](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:287)).
   - `d.cluster` is constructed only from a non-nil active cluster config ([daemon_run_bringup.go:161](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:161)).
   - A corrected commit-confirmed adding cluster topology is rejected before apply ([daemon_apply_commit.go:551](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:551)); peer sync has the same backstop at `:364`.
   - `enterBootstrapMode` is reached only for a nil rollback target ([daemon_apply_commit.go:645](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:645)), which cannot be the prior config of a live cluster runtime.

   RACE-1 remains real, and RACE-2 remains real for standalone consumers. But this false recurrence invalidates blanket HA classifications, including `daemon_health.go:141`, whose only production trigger is session sync ([daemon_ha_sync.go:970](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go:970)).

6. **The smoke plan is not policy-complete.**

   [plan.md:497-502](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:497) names the four broad lanes, but omits required details from [engineering-style.md:93-103](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/engineering-style.md:93):

   - reapply CoS after cluster deploy;
   - `iperf3 -P 16 -t 30 -p 5203` to `172.16.80.200`;
   - at least 23 Gbit/s with no regression;
   - standalone ping with 0% loss;
   - explicit HA loss/convergence criteria.

   The CoS wipe is separately called out at [engineering-style.md:422](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/engineering-style.md:422). Also state `make test` explicitly at [plan.md:494](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:494), rather than merely noting that Rust runs through it.

## MINOR

1. **The reversed transition test fails old code for the wrong reason.**

   [plan.md:461-468](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:461) starts at nil and says old code returns a base wrapper that permanently lacks `Status`. Old code actually returns nil immediately ([daemon_forwarding_status.go:123](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go:123)). Start with `readyProbeOnlyFake → userspaceFake → nil` to isolate dynamic capability selection.

2. **Option D is still compared unfairly.**

   [plan.md:240-246](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:240) says owner-plus-presence cannot represent “never constructed”; `dpOwner == nil && !dpPresent` does exactly that, while non-nil owner plus false presence represents cleared. Its future-republish tear also assumes violation of the option’s stated write-once-owner invariant. A1 remains preferable, but those are not valid objections.

3. **Documentation/comment scope still misses live contradictions.**

   The README work list at [plan.md:375-382](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:375) names two bootstrap bullets but misses the direct field reference at [pkg/daemon/README.md:936](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/README.md:936). Source comments also still call bootstrap exit one-way/at-most-once at [daemon_run_naming.go:200](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_naming.go:200), [bootstrap.go:284](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:284), and [daemon_apply.go:213](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply.go:213), contradicting the recurrence the plan now tests.

The retirement-canary sketch itself is implementable: `atomic.Pointer[dpSlot]` parses as `ast.IndexExpr`, while `dpSlot.v` is an ordinary `TypeSpec`/`StructType` match. I found no `package daemon_test` bypasses, reflective/unsafe field lookup, alternate receiver alias, or production method-value capture. The only formatting observation is `%T` at `daemon_ha_sync.go:311`, and v2 handles it.

VERDICT: NEEDS-REVISION

Codex session ID: 019f91df-1c32-7c50-8f29-3555e78fa4ce
Resume in Codex: codex resume 019f91df-1c32-7c50-8f29-3555e78fa4ce
