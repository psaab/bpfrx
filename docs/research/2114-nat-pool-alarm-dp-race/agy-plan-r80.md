# AGY adversarial plan-review — round 80 (plan v81 @ ef86de7b0)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (folded stragglers verified; document-wide phrasing-extinction audit clean; the retained oracle legs consistent with the four-leg summary; the pre-rejection side-effect clause verified against the cleanup bodies; no blockers). Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 — Round 80 (CONVERGENCE)

**Verdict**: **`PLAN-READY`**
**Scope**: PR-1 ONLY (`d.dp` synchronized accessor core, work item A1 + armed-state admission gate A3 + site conversion + canaries + sampler narrowing). Follow-up unit G+H+H2 in `followup-seed.md` remains out of scope per §4.7.
**Blockers for PR-1**: **NONE**.

---

### 1. Folded Stragglers & Phrasing Extinction Audit
- **Class-1 Opening (`plan.md:L3607-L3625`)**:
  [plan.md:L3610-L3612](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3610-L3612) and [L3622-L3624](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3622-L3624) now read:
  > *"enter the registry helper and classify + select ATOMICALLY under `m.mu` (the uniform rule; the one-state acquire-load phrasing is deleted...)"*
- **§5.1 Class-2 Entry (`plan.md:L4078`)**:
  [plan.md:L4078](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4078) now explicitly specifies:
  > *"class-2 neutral-outcome ANY signature WITH the synchronization rule (class-2 joins the blocked-Start overlap)"*
- **Document-wide Extinction Check**:
  A full sweep of `plan.md` confirms that all pre-v79 `one-state` or pre-lock `acquire-load` phrases are either extinct or explicitly documented as deleted historical artifacts ([L3198](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3198), [L3612](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3612), [L3692](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3692), [L5202](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L5202)).

---

### 2. Retained Oracle Legs Verification (Codex r79 M1)
- **Summary Consistency ([plan.md:L4585-L4596](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4585-L4596))**:
  The four-leg summary explicitly partitions the oracle tests into:
  1. `TestManager_ArmedGate_FreshOutcomes` (quiescent fresh)
  2. `TestManager_ArmedGate_RetainedOutcomes` (quiescent retained)
  3. `TestManager_ArmedGate_BlockedStart` (blocked fresh-Start overlap)
  4. `TestManager_ArmedGate_RetainedReStartOverlap` (blocked retained-re-Start overlap)
- **Detailed Test Definitions ([plan.md:L4631-L4645](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4631-L4645))**:
  - `TestManager_ArmedGate_RetainedOutcomes` is defined as its own quiescent test where a seeded retained registry (`maps+programs` present, `loaded=false`, no overlap) runs every class and asserts master's exact outcomes (retained reads report, retained mutations reach maps, loaded-check set rejects per master).
  - `TestManager_ArmedGate_RetainedReStartOverlap` drives the retained fixture through a blocked re-`Start`, verifying that readers **block during the held window** and **observe the ARMED state after release**.
- **Result**: The summary and detailed test specifications are 100% aligned.

---

### 3. Pre-Rejection Side-Effect Clause Verification (Codex r79 M2)
- **Codebase Source Inspection**:
  Inspected [loader.go:L173-L186](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L173-L186) and [compiler.go:L178-L184](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L178-L184):
  1. `cleanupUserspaceShimLegacyTCLinks()` ([loader.go:L174](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L174), implementation [L288-L310](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L288-L310)): Reads link pin dir and unlinks legacy pins; handles `os.IsNotExist`. Idempotent.
  2. `cleanupUserspaceShimLegacyOnlyMapPins()` ([loader.go:L177](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L177), implementation [L267-L286](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L267-L286)): Removes map pins from array; ignores `os.IsNotExist`. Idempotent.
  3. `m.SelectUserspaceXDPShimEntryProgram()` ([loader.go:L181](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L181)): Writes a constant program name into `m.xdpEntryProg`. Idempotent.
  4. `CompileConfig` rejection ([compiler.go:L182-L183](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L182-L183)): Rejects with `"dataplane not loaded"` when `!dp.IsLoaded()`.
- **Plan Text Alignment ([plan.md:L4600-L4610](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4600-L4610))**:
  The plan accurately describes this sequence: cleanups + selector write precede `CompileConfig`'s rejection, all side-effects are idempotent, the rejection fires in every state, and an overlap blocked at selector proceeds after release when armed.

---

### 4. Invariant 12 & §5.5 Attribution
- **Invariant 12 Clause (iii) ([plan.md:L4427-L4432](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4427-L4432))**:
  Now explicitly includes the carve-out:
  > *"(iii) a retained-state method proceeds against the retained registry UNDER the uniform registry rule — master's exact behavior (r79 Codex M3's carve-out: methods WITH a pre-existing loaded check — the attaches, the CompileConfig path — reject per master on EVERY state and never reach the registry)."*
- **§5.5 Attribution ([plan.md:L4228-L4247](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4228-L4247))**:
  The source comment updates regarding bootstrap recurrence are properly assigned to the follow-up seed (`followup-seed.md` §4.7), matching the delivery boundary split.

---

### 5. Hostile Verification of Retained Outcomes & §10 Generation Hazard
- **Close-retained (Live pins/handles) vs. Teardown-retained (Dead pins / Old generation)**:
  - From the Go `*Manager` struct's internal state perspective, both Close-retained and Teardown-retained present `loaded==false` with `m.maps` non-empty.
  - `TestManager_ArmedGate_RetainedOutcomes` operates on this exact in-memory `*Manager` state to verify method behavior when `loaded==false` and handles are present.
  - The plan explicitly addresses the Teardown-retained + re-`Start` generation hazard in **§10 ([plan.md:L3914-L3931](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3914-L3931))**: when `Teardown()` retains the manager and `Cleanup()` removes pins while a subsequent `Start()` creates a new map generation, mutating an old handle affects the obsolete object.
  - §10 notes that this hazard is pre-existing master behavior on the recurrence path (terminated by follow-up work item H in `followup-seed.md`), and PR-1 neither creates nor worsens it.
- **Conclusion**: `TestManager_ArmedGate_RetainedOutcomes` does not need to split into separate sub-tests for Close vs. Teardown because both evaluate the identical in-memory retained-registry gate semantics, and the underlying kernel object lifecycle hazard is correctly bounded by §10.

---

### Final Summary
All text stragglers, oracle leg definitions, side-effect orderings, invariant carve-outs, and documentation attributions in plan v81 @ `ef86de7b0` are completely consistent and verified against the codebase.

**PR-1 design is fully converged and PLAN-READY for implementation.**
