# Codex adversarial plan-review — round 85 (plan v86 @ cee81d0b1b0f)

Codex companion task-msb9ibow-7q2orb (session 019fc098-0777-76a2-a17b-89b217d8ba29). Verdict: PLAN-NEEDS-MAJOR (1 MAJOR — the v86 class-2/class-4 outcome contract is not total: no present→proceed branch, class-4 armed/retained cells undefined, literal reading suppresses valid present-map behavior proven by SessionCount maps_session.go:326 / ClearSessionCounts maps_screen.go:57 / GetMapStats maps_stats.go:68 — 3 MINORS: four normative sites still mandate the singular "registry helper"; a fourth unconditional teardown claim survived in §9; the direct swap ownership fixture seeds only m.programs and is therefore FRESH, never reaching the :632 write). Verified passes: all 135 production registry accesses fit the typed pair (127 comma-ok + 3 one-value + 2 direct-return reads, exactly 3 publication writes); (handle, present, st) is a coherent snapshot with no TOCTOU; {armed, fresh, retained} exhaustive; no G+H+H2 leakage. Raw output follows verbatim.

---

## Verdict: PLAN-NEEDS-MAJOR — 1 major, 3 minors

Yes. Finding 1 is inside PR-1 and blocks `PLAN-READY` for #2114.

1. **MAJOR — the new class-2/class-4 outcome contract is not total, and class 2 is wrong when read literally.**

   The v86 rules say class 2 is “fresh → neutral; else master’s missing-map outcome,” without conditioning the latter on `!present` or defining the present→proceed path. Class 4 specifies only fresh behavior, leaving all armed/retained cells undefined ([plan.md:4824](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4824)).

   The required matrix for ordinary methods is:

   | Class | Fresh | Armed + absent | Armed + present | Retained + absent | Retained + present |
   |---|---|---|---|---|---|
   | 1 | typed error | legacy missing error | proceed | legacy missing error | proceed |
   | 2 | neutral | legacy neutral | **proceed** | legacy neutral | **proceed** |
   | 3 | ignore state; pinned legacy behavior | pinned legacy behavior | proceed | pinned legacy behavior | proceed |
   | 4 | nil / typed error | nil / legacy error | **proceed** | nil / legacy error | **proceed** |

   “Present” includes present-but-nil: callers must retain their existing handle-level nil behavior. Fresh+present is production-unreachable for map lookups; if constructed artificially, the fresh rule wins. The loaded-check class-1 subset still preempts the helper on both unarmed states.

   Real class-2 methods prove the missing branches matter: `SessionCount` counts present maps ([maps_session.go:326](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_session.go:326)), `ClearSessionCounts` mutates them ([maps_screen.go:57](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_screen.go:57)), and `GetMapStats` reports them ([maps_stats.go:68](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/maps_stats.go:68)). Class-4 master behavior is fully defined by `Map`, `Program`, and `NewEventSource` ([loader.go:1150](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1150)).

   Literal v86 behavior also contradicts its own retained-proceed contract ([plan.md:3700](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3700)) and retained oracle ([plan.md:4760](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4760)).

2. **MINOR — normative sections still require one registry helper.**

   The exact obsolete `registryLookupLocked` name is gone. However, A3 and §5.1 still mandate “the single `m.mu`-scoped registry helper” ([plan.md:3674](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3674), [plan.md:4139](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4139)). The source-comment contract and ownership test are also singular ([plan.md:4330](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4330), [plan.md:4782](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4782)), while §9 later pins two helpers.

   Pluralize these requirements and explicitly exercise both typed helpers in the ownership test.

3. **MINOR — a fourth unconditional teardown claim survived.**

   The three requested sites are correctly qualified as armed-only: [plan.md:3898](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3898), [plan.md:4065](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4065), and [plan.md:4520](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4520).

   But §9 still says Close and Teardown both yield `loaded=false` plus a nonempty registry without the armed qualification ([plan.md:4746](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4746)). `New()` starts empty, and never-armed `Close`/`Teardown` cannot populate it ([loader.go:89](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:89), [loader.go:1203](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1203)).

4. **MINOR — the direct swap ownership fixture is fresh, so it cannot reach the intended write.**

   The fixture seeds only `m.programs["test_prog"]` and `xdpEntryProg="other"` ([plan.md:4726](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4726)). Under the explicit `loaded=false && m.maps empty` predicate, it remains fresh ([plan.md:3696](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3696)); class 1 therefore returns `ErrDataplaneNotArmed` before reaching the `:632` write. Bind this test explicitly to the armed fixture or seed any map to make it retained.

Verified passes:

- All 135 production registry accesses fit the typed pair: 127 comma-ok reads, three one-value reads, two direct-return reads, and exactly three publication writes. There is no registry iteration, deletion, container alias, or other residual shape. The writes are exactly [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185), `:187`, and `:190`.
- Returning `(handle, present, st)` does not create a TOCTOU if callers branch only on that tuple. It is a coherent snapshot; copied handles remain live after unlock. No caller-side reclassification is needed.
- `{armed, fresh, retained}` is exhaustive for production observations. Acquisition mutates locals; the proposed publisher writes the whole batch and stores true under one `m.mu` hold, so helpers cannot observe partial publication. A Close/publisher race chooses retained or armed, not a fourth state; re-arm final-state ordering remains explicitly out of scope.
- No additional A3/§7/§9 contradiction or G+H+H2 dependency leakage was found.

HEAD and branch match `cee81d0b1b0f` / `research/2114-nat-pool-alarm-dp-race`. No files were changed.

Codex session ID: 019fc098-0777-76a2-a17b-89b217d8ba29
Resume in Codex: codex resume 019fc098-0777-76a2-a17b-89b217d8ba29
