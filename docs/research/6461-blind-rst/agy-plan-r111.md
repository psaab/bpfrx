# AGY hostile plan-review — round 111 (v10.27.2)

Reviewer: AGY (direct binary). Verdict: SOUND — struct/initializer/consumer reads fully consistent; no findings.

## Verbatim review

SOUND

### Design Document Consistency Review (v10.27.2 — Terminal Cut)

**Target Document:** [`docs/research/6461-blind-rst/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md)  
**Workspace:** `/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst`  
**Git Branch / Base Commit:** `research/6461-blind-rst` @ `eeddfdd63b2f` (cites worktree base `023f17a606d8` with §3.1 master drift deltas)

---

### Executive Summary

Following the integration of v10.27.1 (struct/type/consumer alignment) and v10.27.2 (`OverdueSkipped` qualification sweep across residual categorical claims), the design document is **SOUND**. All struct definitions, initializers, consumer gates, contract definitions, and test fixtures are fully aligned and internally consistent.

---

### Verification Checklist & Findings

#### (a) Struct Declaration, Initializer, and Consumer Read Verification
1. **Struct Declaration:** [`MaterializeReport`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1742-L1746) explicitly includes `effective_transition: Option<TransitionResult>`, cleanly separating `transition: TransitionResult` (where `None` is `TransitionResult::None`) from the derived optional effective transition (`Option::None` when unset).
2. **Initializer:** `MaterializeReport::NONE` ([§5.8:L1750-1751](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1750-L1751), [§5.8:L1783-1784](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1783-L1784)) initializes `transition = TransitionResult::None` and `effective_transition = None`. `ResolvedFlowSessionDecision` constructs `report: MaterializeReport` initialized to `MaterializeReport::NONE`.
3. **Consumer Gate Consistency:** Every consumer read ([§5.8:L1813-1818](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1813-L1818)) operates against `report.effective_transition` (with `Option<TransitionResult>` matching):
   - Ownership promotion ([§5.8:L1762-1763](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1762-L1763), [§5.8:L1842-1843](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1842-L1843)): `report.effective_transition == Some(OverdueSkipped)`
   - Terminal teardown ([§5.8:L1831-1832](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1831-L1832)): `report.effective_transition ∈ {Some(OverdueSkipped), Some(UpsertRefused)}`
   - Anchor commit hook & Cache insert ([§5.8:L1836-1838](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1836-L1838)): suppressed when `effective_transition ∈ {Some(OverdueSkipped), Some(UpsertRefused)}`
   - Probation clear + commit-time refresh ([§5.6:L1400](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1400), [§5.8:L1839-1841](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1839-L1841)): explicitly requires `report.effective_transition != Some(OverdueSkipped)`
   - MissingNeighbor composition ([§5.8:L1855](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1855), [§5.8:L1972](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1972)): `effective_transition ∈ {OverdueSkipped, UpsertRefused}`

---

#### (b) Single Source of Truth (SSOT) Contract Block Audit
The normative contract block ([§5.8:L1705-1970](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1705-L1970)) was evaluated sequentially from top to bottom as an implementer would execute it:
- **Producer Ordering:** The materializer computes the validation verdict and overdue check *before* calling `install_synced`/`upsert_synced`, eliminating invalid post-mutation normalization states by construction.
- **Phase-1 Legal Matrix:** The legal tuples `(site, validation, transition)` are strictly bounded. `(None, None)` represents non-materializing paths, `(None, T)` for non-close site-2c materializations, and `(Refused, T)` for closing site-2c materializations where `T ∈ {Installed, AdoptedPreservingDeadline, UpsertRefused, OverdueSkipped}`.
- **Fail-closed Fallback:** Applies exclusively to `Some(Site2c)` reports. An invalid `Some(Site2c)` tuple maps to `OverdueSkipped`, whereas a `site == None` report preserves master's default lookup dispatch.
- **No Internal Contradictions:** Statements regarding `UpsertRefused` (non-peer predecessor surviving at the failed-upsert instant), `OverdueSkipped` (skip upsert, retain GC schedule), and `displaced` identity collection (deduplicated inline array of capacity 3) are completely coherent across the block.

---

#### (c) Consumer Set Walkthrough
All six consumer sites maintain strict invariants under `OverdueSkipped` and `UpsertRefused`:
1. **Teardown Sites (`poll_descriptor/mod.rs:698-714, :768-784, :824-840`):** Correctly skip teardown execution for both `OverdueSkipped` and `UpsertRefused`, avoiding invalid deletion/NAT-release under S2's forwarding decision identity.
2. **Anchor Commit Hook:** Inhibited from recording uncommitted/overdue updates.
3. **Flow-Cache Insert (`poll_descriptor/mod.rs:3900-3959`):** Infallibly suppressed on `OverdueSkipped` and `UpsertRefused`.
4. **Probation Clear + Refresh:** Protected by explicit `effective_transition != Some(OverdueSkipped)` guards, preventing stale entry resurrection across long ARP/buffered delays or overdue materializations.
5. **Ownership Promotion (`promote.rs:86-107`):** Explicitly gated on `report.effective_transition == Some(OverdueSkipped)`, `validation == Some(Refused)`, and `K.probation`.
6. **MissingNeighbor Composition:** Redirects `effective_transition ∈ {OverdueSkipped, UpsertRefused}` with MissingNeighbor disposition directly to the `ExistingResolved` buffer-only arm, avoiding raw-flag seed overwrites.

---

#### (d) Qualification Sweep Verification for OverdueSkipped
The three residual claims identified in round 111 have been successfully updated to incorporate the `OverdueSkipped` qualification:
1. **Section 5.6 Site-2C Refuse-Install Summary ([§5.6:L1311](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1311)):** Correctly qualified with `" — UNLESS the existing entry is overdue, in which case the materialize is skipped wholesale (OverdueSkipped, §5.8 contract; v10.27.1)"`.
2. **Section 9 Test Plan Install-ALIVE Fixture ([§9:L2438](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2438)):** Qualified with `"(or skip wholesale when the existing entry is overdue — OverdueSkipped, v10.27.1)"`.
3. **Section 5.2 & Section 9 Retry-Path Claims ([§5.2:L651](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L651), [§9:L2616](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2616)):** Both explicitly qualify that unbuffered retry packets perform establishment, anchor updates, and probation clearing `"PROVIDED its effective transition is not OverdueSkipped"`.

---

#### (e) Full-Document Consistency Sweep
- **Section 3 Site Inventory Table ([§3:L437](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L437)):** Row 2c matches §5.6 and §5.8.
- **Master Drift (§3.1):** Commit deltas between `023f17a606d8` and `fff7a4ab5` (including #6478 site-6 removal) are correctly tabulated and accounted for in all sections.
- **Test Oracles (§9):** Unit, integration, and performance benchmarks accurately reflect all normative rules (including probation deadline preservation, local-only reaps, and cache invalidation timing).

---

### Final Verdict

**SOUND**  

The document `docs/research/6461-blind-rst/plan.md` (v10.27.2) is fully consistent, mathematically sound, and ready to serve as the definitive specification for implementation under `/engineer 6461`.
