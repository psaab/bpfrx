# Claude SMR — hostile plan review, #4408 r2 → r3

Second adversarial pass, this time over r2 *plus* the Codex PLAN-NEEDS-MAJOR
relayed by the leader. Base `origin/master` `dd23119aa`.

**VERDICT: PLAN-READY on the narrowed scope (Option B′ — waterfill only).**
r2's Option B is not defensible as written; r3 narrows rather than argues.

---

## Convergence, stated explicitly

Codex and I reached the same place from opposite directions and the r2 doc
failed to say so:

| | Waterfill split | Dispatch de-dup |
|---|---|---|
| Codex (r2 review) | *"I would not kill the waterfill split… its value survives this review"* | blocks: *"benefit is not strong enough to override the current hottest-path churn and validation gaps"* |
| Claude SMR (r1) | *"the part of this plan I would defend hardest"* | *"a reviewer who weighs churn… above duplication-risk could reasonably land on 'not worth it', and I would not call that reviewer wrong"* |

Two independent passes, same line. r2 recommended shipping across that line
anyway. **That was the actual defect in r2's recommendation** — not the
analysis, which both passes agree on, but the decision to bundle a half that
both reviewers had already flagged as marginal with a half neither disputed.
r3 defers rather than bundles.

## F8 (MAJOR) — the r2 gate's inherited Rust-hash strip over-collapses generic instantiations

r2 congratulated itself for finding F2 (missing `.llvm.` strip) and then shipped
the adjacent rule unexamined. `s/17h[0-9a-f]{16}E?$//` collapses the three
distinct `VecDeque::grow` monomorphisations in the baseline into **one**
identity:

```
distinct `grow` keys, raw       : 3
distinct `grow` keys, r2 rule   : 1
```

So the r2 gate is blind to a change that swaps one generic instantiation for
another. Unlike F1 and F2, **this one is a false negative** — it does not block
correct work or cry wolf, it *passes* a real change. That is the worse failure
direction and it is why r3 rewrites the gate rather than patching it.

**Fix (r3 §2c-bis):** stop normalising in the primary key. Tier 1 is the raw
51-edge set — maximally sensitive, distinguishes all three `grow` instances by
construction. All tolerance moves into an explicit two-step Tier-2 classifier
that a reviewer signs off, consulted only when Tier 1 is non-empty and never as
an auto-pass.

**Proof it fixes the blind spot** (synthetic swap of one `grow` hash for a valid
lowercase 16-hex instantiation): Tier 1 **DETECTED**, r2 rule **MISSED**.
Negative control: a pure `.llvm.<N>` relabel is DETECTED by Tier 1 and correctly
*classified* by Tier 2a (stripped diff vanishes). The two rows discriminate.

**Method self-report:** the first attempt at that proof used an **uppercase**
synthetic hash, which `[0-9a-f]{16}` never matches — so it appeared to show the
r2 rule catching the swap when the rule simply was not applying. A demonstration
that cannot fail proves nothing. Caught it only by checking why the "old rule"
column disagreed with the arithmetic.

## F9 (MINOR) — I did not reproduce Codex's `.llvm.`-instability observation, and the plan should say so

Codex reported a second binary in which all five `.llvm.` suffixes changed while
Rust hashes held. I built two probe binaries in a scratch worktree (deleted
after measurement, never pushed) and could not reproduce it for the change class
this refactor belongs to:

| Probe | Perturbation to `dispatch/mod.rs` | Raw 51-edge diff |
|---|---|---|
| P1 | added a dead `#[inline(always)] fn` | 0 lines — but weak; dead-stripped before CGU partitioning |
| P2 | **moved an existing item within the file** (`copy_frame_is_oversized`) — same in-file-motion class as the extraction, not strippable | **0 lines** |

Neither Rust hashes nor `.llvm.` suffixes moved. This does **not** contradict
Codex — its perturbation was evidently a different class — but it does mean
r2's blanket `.llvm.` strip was solving a problem that does not arise for *this*
change class, at the cost of sensitivity. Recorded in §2c-bis with both results,
because "I could not reproduce the motivating observation" is a fact a reviewer
of the gate needs.

## F10 (MINOR) — "102 identical lines" was never true

r1 and r2 both said the two copy-fallback arms "normalise to 102 identical
lines". Re-derived: **102-line blocks agreeing on 100 of 102 lines** (the
enclosing `None => match` and its closing `},`). Corrected in §1d with the
correction called out inline. The claim was directionally right and the
conclusion unchanged, but a plan that has now been wrong about a measured
number twice (§5-A LOC arithmetic in r2, this in r3) should stop rounding in
prose.

## F11 (MINOR) — an executable `break` sits in the "escape-free" region and the plan did not mention it

Codex found it: `:661`, inside `for frame in segmented { … }` (loop :641–688).
It exits only the inner segmentation loop and resumes at :689 in the same
region, so the escape-free claim **holds precisely** — but a reader running the
plan's own grep command will hit it, and an unexplained hit reads as a hole in
the analysis. Now recorded explicitly in §1b alongside the 11 comment-match line
numbers Codex enumerated.

---

## What survived this pass unchanged

The decomposition analysis. Across three rounds and two reviewers, **no defect
has been found in**: the escape-free interior, the four-value export set, the
`Option` control-flow correspondence for both waterfill phases, the `root`-only
state ownership, the Phase-1 NLL borrow floor, or the rejection of the
#4404-shaped arm split. Every correction in three rounds has landed on the
measuring apparatus. §8a makes that the plan's headline risk finding rather than
a footnote, and it is the reason r3 ships the smaller increment.

## Residual discomfort

Tier 2 of the new classifier has a synthetic proof and a negative control but
has never processed a real failure. If the pattern in §8a holds, that is where
round four's defect will be found.
