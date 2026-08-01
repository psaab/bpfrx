# Codex hostile plan-review — round 74 (plan v75 @ e42b3429c)

Task: task-msavgg98-zoz2v0 (session 019fbf2f-dfb8-79e2-a990-a8c6eb6c98aa).
Verdict: PLAN-NEEDS-MAJOR (2 MAJOR — the DetachXDP class-2 gate breaks retained-claim cleanup semantics on re-arm; the XDP seam can silent-green the :632 lock — 3 MINOR: label hygiene, fixture migration, status-loop premise correction). Explicitly RE-CONFIRMED the VLAN adjudication conclusion while correcting one premise. Raw companion output follows verbatim.

---

## Verdict

**PLAN-NEEDS-MAJOR — 2 major, 3 minor.**

**Yes. Findings 1–2 are within PR-1 and block PLAN-READY for #2114.**

## Findings

1. **MAJOR — `DetachXDP`’s class-2 gate does not preserve re-arm state semantics.**

   V75 equates `loaded=false` with the existing no-map `nil` path ([plan.md:3677](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3677)). But `setXDPAttachedFlag(false)` has required Go-side work: it discovers retained claims ([loader.go:711](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:711)) and deletes the detaching ifindex from them ([loader.go:777](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:777)). Its comment explicitly says missing this cleanup permits later spurious re-flagging.

   `Close` clears neither `xdpLinks`, `m.maps`, nor `xdpFlagClaims` ([loader.go:1206](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:1206)), and bootstrap retains the Manager for re-arm ([bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:470)). The proposed entry gate skips claim cleanup, while `DetachXDP` still closes and deletes the link ([loader.go:655](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:655)). A later `SetZone` consumes the stale claims and sets `IfaceFlagXDPAttached` despite the missing link ([loader.go:851](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:851), [loader.go:865](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:865)).

   This helper needs a class-3-like split preserving detach claim cleanup while gating/synchronizing only Start-populated map access, or a proved invariant that claims are always empty on every reachable re-arm. V75 supplies neither.

   The seeded test is constructible without a real BPF link: a package-local fake can embed `link.Link` and override `Unpin`/`Close`. But §9 never actually specifies the promised Detach leg, and seeding only `xdpLinks` is insufficient; it must seed and assert cleanup of `xdpFlagClaims` ([plan.md:4394](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4394)).

2. **MAJOR — the dedicated XDP seam still cannot deterministically prove the `:632` lock.**

   The new selector-position barrier fixes the old blindness for getter/predicate versus the `:154` write. It does not guarantee execution of the swap assignment it claims to cover ([plan.md:4403](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4403)).

   During blocked Start, selection occurs at [loader.go:154](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:154), before program population at [loader_userspace_shim.go:185](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader_userspace_shim.go:185). Therefore:

   - The newly class-1 public Swap exits at its unarmed gate.
   - A direct private swap exits when `m.programs[name]` is absent ([loader.go:609](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:609)).
   - Even if the userspace program is seeded, it exits at the already-selected check when the selector wins ([loader.go:613](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/loader.go:613)).

   Thus omission of the `:632` lock can still silent-green. Pin a direct `swapXDPEntryProg` call with a seeded, distinct test-only program, or add a pre-`:632` barrier/assertion with no happens-before edge to the selector write.

3. **MINOR — the promised total/exclusive classification remains contradictory.**

   The trio is still explicitly listed in category F ([plan.md:3652](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3652)), then declared re-homed to G ([plan.md:3712](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:3712)). `DetachXDP` is described as “mixed” but receives no single manifest label, although §9 requires exactly one ([plan.md:4411](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:4411)).

4. **MINOR — the Swap class-1 fold breaks an existing fixture not named for migration.**

   `TestXSKLivenessFailureRestoresUserspaceShimEntry` constructs an unarmed `dataplane.New()` and seeds only `programs` ([xdp_shim_decouple_test.go:32](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/xdp_shim_decouple_test.go:32), [xdp_shim_decouple_test.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/xdp_shim_decouple_test.go:321)). The new gate prevents the selector change expected at line 69. §9 should name an explicitly armed synthetic fixture strategy.

5. **MINOR — the VLAN adjudication’s conclusion is acceptable, but one premise is false.**

   The status loop does not start only after successful Compile: `clearHelperHAStateWithDebtEnsureRetryLocked` starts it before propagating two Compile failures ([manager_ha.go:115](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_ha.go:115), [manager_compile.go:276](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:276), [manager_compile.go:378](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager_compile.go:378)).

   **Explicit ruling:** the residual-with-named-first-follow-up disposition remains acceptable. Every loop-start path is still after `bpfShim.CompileUserspaceShim` has returned; `Start` itself only delegates to `Load` ([manager.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/2114-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go:370)). Therefore the VLAN hazard remains post-arm Compile/status concurrency, outside A3’s Start-window scope. Its access inventory is now complete, and it does not itself block PR-1.

## Fold summary

- Locked-helper production design: **PASS**; no deadlock, no hold across link updates, no uncovered production `xdpEntryProg` access.
- `DetachXDP` mixed design: **FAIL** on retained claim-state semantics.
- Dedicated XDP seam: **PARTIAL**; getter/predicate covered, `:632` not pinned.
- Swap class-1 assignment: **PASS**, with the fixture migration above.
- §5.1/§5.5/§6 and totality wording: **mostly folded**, except the stale F/G and Detach-label contradictions.
- `setXDPAttachedFlag` callers: exactly Attach and Detach; no omitted caller. Attach is class 1, but the shared internal gate still has the Detach defect above.

Codex session ID: 019fbf2f-dfb8-79e2-a990-a8c6eb6c98aa
Resume in Codex: codex resume 019fbf2f-dfb8-79e2-a990-a8c6eb6c98aa
