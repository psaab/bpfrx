# Codex hostile plan-review — round 69 (plan v70 @ dd14047a6)

Task: task-msaq97lv-1x28e8 (session 019fbeaa-94d1-77c1-a1fe-67049941304e).
Verdict: PLAN-NEEDS-MAJOR (2 MAJOR, 4 MINOR — both MAJORs inside v70's A3 fold: the universal typed-error gate falsified by non-error signatures + test-pinned mapless contracts; the teardown proof rested on a false cilium/ebpf premise). Raw companion output follows verbatim.

---

**Verdict: PLAN-NEEDS-MAJOR — 2 MAJOR / 4 MINOR.**

Yes. Both MAJOR findings are entirely inside PR-1 and block `PLAN-READY` for #2114. G/H/H2 were excluded. HEAD and branch match `dd14047a6` / `research/2114-nat-pool-alarm-dp-race`.

## Findings

1. **MAJOR — A3’s universal typed-error gate is neither API-compatible nor behavior-preserving.**

   The plan requires every exported maps-touching method to return `ErrDataplaneNotArmed` ([plan.md:3492](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3492)), and the test matrix literally expects every pre-arm call—including `IsLoaded`—to return that error ([plan.md:4082](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4082)). Existing signatures cannot implement that contract:

   - `IsLoaded() bool` ([loader.go:456](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:456))
   - `SessionCount() (int, int)` ([dataplane.go:299](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/dataplane.go:299))
   - `GetMapStats() []MapStats` ([dataplane.go:415](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/dataplane.go:415))
   - void seeders and stale cleaners ([dataplane.go:380](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/dataplane.go:380), [dataplane.go:418](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/dataplane.go:418))
   - `Map(string) *ebpf.Map` ([dataplane.go:445](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/dataplane.go:445))

   Section 6 nevertheless says `NewSampler` is the only intentional signature change ([plan.md:3891](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3891)).

   The “no successful path changes” claim is also false. `ClearNATRuleCounters` intentionally clears Go-side offsets and returns nil without a BPF map ([maps_nat.go:395](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go:395)); the userspace wrapper documents this as pre-start behavior ([natcounters.go:47](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/natcounters.go:47)), and an existing test calls it successfully on an unstarted `New()` manager ([manager_nat_test.go:320](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_nat_test.go:320)). `ClearGlobalCounters` has the same deliberately mapless success contract ([maps_counters.go:176](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go:176)), pinned by [manager_counters_test.go:455](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_counters_test.go:455).

   I did not find a normal daemon call that returns nil from `UpdateRGActive` during the short construct→Start window; the outer userspace call reaches an unconfigured helper socket. The regression is instead the explicit, tested pre-start API above.

   `Map`, `Program`, `XDPLinks`, and `TCLinks` also return raw references ([loader.go:1150](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1150), [loader.go:1195](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1195)); an entry gate cannot govern their callers’ subsequent accesses.

   A3 needs a complete method-by-method contract: typed error for fallible map-required methods, neutral/no-op outcomes for non-error methods, preserved Go-side behavior for hybrid methods, and explicit lifecycle/escaping-reference exceptions.

2. **MAJOR — `loaded` is an admission bit, not the teardown lease claimed by invariant 12.**

   The plan claims an in-flight method either finishes against still-open state or sees false ([plan.md:3959](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3959)). Current `Close` first ranges `xdpLinks` and `tcLinks`, then clears `loaded` ([loader.go:1206](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1206)). Concurrent attach operations write those Go maps ([loader.go:534](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:534), [loader.go:1124](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1124)).

   A real schedule exists: shutdown may proceed after the apply drain times out ([daemon_run_shutdown.go:50](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go:50)); userspace `Compile` invokes shim compilation/attachment before taking its outer mutex ([manager_compile.go:162](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:162)); `Close` can acquire that mutex and concurrently range the link maps ([manager.go:471](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go:471)). Moving `Store(false)` earlier still would not drain an operation that already observed true.

   Exact answer to the UAF question: current `Manager.Close` does not close the eBPF map handles, so v70 introduces no new eBPF-map UAF on this exact path. But the claimed teardown proof remains false because of the Go link-map race and escaped/in-flight operations. The cited library premise is also wrong: cilium/ebpf explicitly says closing a map in use by other goroutines is unsafe ([map.go:273](/home/ps/go/pkg/mod/github.com/cilium/ebpf@v0.20.0/map.go:273)).

   The plan needs lifecycle exclusion—RW lease/refcount plus drain, equivalent serialization—or must retract the teardown/L2-closure claim and retain the race as an explicit residual.

3. **MINOR — `TestManager_ArmedGate_BlockedStart` is not deterministic or directly implementable as written.**

   The root manager’s `Start` invokes the retired `Load` path ([apply.go:208](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/apply.go:208)); real shim population runs through the userspace manager and privileged loader ([loader.go:152](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:152), [loader_userspace_shim.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:95)). There is no injection seam.

   Merely pausing after a population write also orders readers after that write and need not trigger `-race`. Specify a synthetic per-manager loader, fixed entered/resume barriers, actual reader/writer overlap, and an AST/generated inventory paired with the callable matrix.

4. **MINOR — the publish-after-Start rejection uses a false replay premise.**

   The watcher records desired state before attempting the dataplane call ([daemon_ha.go:290](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:290)); reconciliation runs immediately ([daemon_ha.go:604](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:604)) and unconditionally retries desired-versus-applied state ([daemon_ha.go:809](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha.go:809)). That is the same repair mechanism A3 relies upon. Bootstrap requires retaining the pending owner, but it does not require publishing that owner to readers. A pending-owner/armed-cell design remains a bounded alternative; the plan has not validly rejected it.

5. **MINOR — the forwarding-status tests do not pin the folded construction contract.**

   The proposed transition test starts with a nonnil fake ([plan.md:4008](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4008)), so it cannot catch retention of the current nil-at-construction early return ([daemon_forwarding_status.go:123](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_forwarding_status.go:123)). Add nil receiver, `NoDataplane`, and initially-empty-cell→userspace legs.

6. **MINOR — the conversion inventory still leaves stale source comments.**

   The census explicitly subtracts comments ([plan.md:3720](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3720)), leaving comments that still describe direct `d.dp` access or its plain-interface race, including [daemon_run.go:373](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:373), [daemon_ha_sync.go:297](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_sync.go:297), and [daemon_natpoolalarm_race_test.go:11](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/daemon_natpoolalarm_race_test.go:11). The “3 files touched” statement at [plan.md:3419](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3419) also omits the new README and test rewrite.

## Fold re-verification

- Fold 1: **partial only**. The Store(true)→Load(true) initialization happens-before argument is sound under Go’s atomic memory model. It proves visibility of pre-Store population, not lifetime, teardown, reload, or escaped-reference safety. Subquestions: **(a) yes, narrowly; (b) yes, escapes/non-error APIs exist; (c) no new map UAF, but teardown proof fails; (d) rejection rationale is unsound.**
- Fold 2: **pass** — the pure Store-vs-Load CORE leg is restored at [plan.md:4058](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4058).
- Fold 3: **text passes** — `d == nil || d.opts.NoDataplane` is retained at [plan.md:3441](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3441); MINOR 5 is missing enforcement.
- Fold 4: **pass for the requested fold** — README/sampler wording and `errors` deletion are inventoried. MINOR 6 is a fresh source-comment gap.
- Fold 5: **pass** — §6/§7 now contain pointers, with the text present in [followup-seed.md:5408](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md:5408) and [followup-seed.md:5420](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/followup-seed.md:5420).

**PR-1 is therefore not PLAN-READY.** A3 needs redesign at the contract and teardown-synchronization levels; this is not a wording-only convergence fix.

Codex session ID: 019fbeaa-94d1-77c1-a1fe-67049941304e
Resume in Codex: codex resume 019fbeaa-94d1-77c1-a1fe-67049941304e
