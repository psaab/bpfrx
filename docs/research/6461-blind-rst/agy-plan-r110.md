# AGY hostile plan-review — round 110 (v10.27.0)

Reviewer: AGY (direct binary). Verdict: UNSOUND with three precise textual findings: (1) the struct declaration omitted effective_transition and three consumer references still read raw report.transition; (2) two stragglers omitted the effective_ prefix; (3) the field types needed explicit declaration to disambiguate TransitionResult::None from Option::None in MaterializeReport::NONE. All folded in v10.27.1.

## Verbatim review

UNSOUND

### 1. Incomplete Struct Definition & Contradictory Consumer Field References in §5.8 SSOT
**File: Line Trace:** [`docs/research/6461-blind-rst/plan.md:1739-1741`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1739-L1741), [`docs/research/6461-blind-rst/plan.md:1752`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1752), [`docs/research/6461-blind-rst/plan.md:1764-1768`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1764-L1768), [`docs/research/6461-blind-rst/plan.md:1802-1808`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1802-L1808), [`docs/research/6461-blind-rst/plan.md:1829`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1829), [`docs/research/6461-blind-rst/plan.md:1831`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1831)

The round-110 fold introduced `effective_transition` as a carried struct field on `MaterializeReport` to ensure consumers evaluate the post-validation effective result rather than the raw `transition` field. However, the SSOT contract in §5.8 contains two internal contradictions:
1. **Struct Definition Omission ([`plan.md:1739-1741`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1739-L1741)):** The explicit Rust struct definition of `MaterializeReport` is written as:
   ```rust
   MaterializeReport { site: Option<MaterializeSite>, validation: Option<CloseValidation>, transition: TransitionResult, displaced: DisplacedSet }
   ```
   It omits `effective_transition: Option<TransitionResult>` from the struct definition, contradicting lines 4, 1773, and 1807 which state that `effective_transition` is a carried struct field.
2. **Consumer Field Reference Contradiction ([`plan.md:1752`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1752), [`1829`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1829), [`1831`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1831)):** Lines 1764 and 1802-1806 state normatively that *"every consumer, INCLUDING the pre-resolved-result promotion, reads the effective transition, never the raw fields"* and *"EVERY consumer read of the transition is `report.effective_transition`"*. However:
   - Line 1752 (Producer section) states: `report.transition == OverdueSkipped` suppresses the promote...
   - Line 1829 (Consumer iv) states: `report.transition == OverdueSkipped` explicitly...
   - Line 1831 (Consumer v) states: `report.transition == OverdueSkipped` gate...
   These three lines still reference the raw `report.transition` field, creating a direct contradiction within §5.8.

### 2. Unqualified `transition` Stragglers Outside the SSOT
**File: Line Trace:** [`docs/research/6461-blind-rst/plan.md:1403`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1403), [`docs/research/6461-blind-rst/plan.md:2580`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2580)

While round 110 updated most outside-SSOT claims to specify `effective_transition != OverdueSkipped` (e.g., lines 651, 1228, 1398, 1534, 1629, 2400), two stragglers remain:
- **Line 1403 (§5.6):** `and (b) clears on the first COMMITTED non-close packet whose transition is NOT OverdueSkipped` omits `effective_` (unlike line 1398 5 lines earlier).
- **Line 2580 (§9):** `never on an OverdueSkipped transition — the explicit overdue guard` omits the `effective_` prefix in the test assertion specification.

### 3. Type Representation Ambiguity for `MaterializeReport::NONE`
**File: Line Trace:** [`docs/research/6461-blind-rst/plan.md:1712-1713`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1712-L1713), [`docs/research/6461-blind-rst/plan.md:1772-1773`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1772-L1773)

In §5.8 line 1712, `TransitionResult` is defined as `TransitionResult ::= None | Installed | AdoptedPreservingDeadline | UpsertRefused | OverdueSkipped` where `None` is an explicit variant of the `TransitionResult` enum. In line 1773, `MaterializeReport::NONE` is described as initializing `transition None, effective_transition None`. 
Because `effective_transition` is described elsewhere as `Option<TransitionResult>` (which also has an `Option::None`), an implementer faces ambiguity: `transition` is `TransitionResult::None` (an enum variant), whereas `effective_transition` is `Option<TransitionResult>::None` (an Option variant), or `effective_transition` is also `TransitionResult::None`. The struct definition in §5.8 should explicitly declare field types (`transition: TransitionResult`, `effective_transition: Option<TransitionResult>`) to disambiguate variant initialization in `MaterializeReport::NONE`.
