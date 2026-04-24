# Engineering style for xpf

This file describes the coding and review personality the project has
settled on. It is checked into the repo so new contributors — human or
agent — internalise it before touching code or reviews. It is terser and
more opinionated than `CLAUDE.md`; keep it that way.

Read this file in full before:

- writing non-trivial code in `userspace-dp/` or any hot path
- reviewing a PR
- opening a PR that claims a performance improvement

## First principles

1. **Latency is sacred.** Memory is cheap. Microseconds on the packet
   path are not. When two approaches trade bytes for branches, take the
   one that's branchless at the hot path.

2. **Correctness first, performance second, convenience last.**
   Defensive code that catches a class of bugs at build time beats tests
   that catch one instance. Favour `const _: () = assert!(...)` over
   `#[test]` pins for invariants that must not drift.

3. **One source of truth for every formula.** If two code paths compute
   the same denominator, they WILL drift. Centralise via a helper the
   first time you notice the duplication. The #704 bug was two gates
   computing "active flow count" differently.

4. **Honest framing always.** If live data doesn't support the PR's
   hypothesis, update the PR body. Don't bury it in a changelog. Don't
   hide behind "tests pass".

5. **Narrow scope.** Bug fix and behaviour choice do not ride in the
   same PR. If a reviewer flags a "maybe we should also" concern, file
   a tracking issue and cross-reference it. Don't silently expand
   scope.

6. **All code changes go through a PR.** No direct pushes to `master`
   for code — not for one-line fixes, not for hotfixes, not for revert
   commits. The PR flow is where reviewers catch what tests miss,
   where live data gets contrasted against the hypothesis, and where
   the commit message and PR body become the permanent record of why
   the change was made. Skipping it to "save time" is how regressions
   land. Docs-only maintenance skills that explicitly direct-push
   (e.g. `/sync-history`) are the only exception and must be declared
   in their `SKILL.md`.

## Workflow for every change

Every non-trivial change follows this ordering. It's the target going
forward — recent PRs have been close but not uniform, and the point of
writing it down is so the next agent can cite "step N" without having
to re-derive the pattern. Cross-references point to sections that carry
the mechanics, so this section is sequencing only.

1. **Issue first.** File a GitHub issue (or pick up an existing one)
   before writing code. Body: problem, hypothesis, acceptance criteria.
   The PR later references it by number in the title.

2. **Plan.** Read the existing code, then write a short plan under
   `docs/pr/<N>-<name>/plan.md` (the `<N>-<name>` prefix follows the
   existing convention documented in `docs/pr/README.md`) or the
   plan-mode scratch file: goal, approach, alternatives rejected, files
   touched, test strategy. No code yet.

3. **Hostile plan review with Codex (`gpt-5.5`).** Spawn via the
   `codex-rescue` agent; brief it to *critique*, not validate.
   **Terminal artifact:** Codex returns `PLAN YES` (or equivalent) AND
   every raised concern has a written disposition in the plan doc
   (applied, or rejected with reason). If Codex pushes back twice on
   the same point, assume it's right until you can show otherwise —
   "Codex stopped objecting" is not agreement. If you and Codex are
   stuck, stop and ask the user.

4. **Hostile architecture review** — same agent, same terminal rule —
   when the change touches a boundary: new BPF map, new protocol
   field, new syscall, cross-dataplane coordination, config/CLI
   surface. Skip this step for pure-local changes.

5. **Code.** Edit existing files; keep the diff scoped to the plan.
   Follow "Hot-path coding discipline" and "API shape discipline"
   below. Scope creep → separate issue + separate PR.

6. **Unit tests that reproduce the failure mode** — see the "Test
   strength" bullet under "Review discipline" below for what counts as
   a strong test.

7. **Hostile code review with Codex.** Same terminal rule: Codex
   returns `MERGE YES` (or equivalent) AND every finding has a written
   disposition. Fixes go into the same branch before push.

8. **Deploy + feature validation.** Unit tests pass ≠ firewall works.
   Run at minimum:

   | What changed | Deploy | Validation | Pass criteria |
   |---|---|---|---|
   | Any change | `make test-deploy` (standalone) | ping between zones | 0% loss |
   | Any change | `make test-deploy` | `iperf3 -P 16 -t 30 -p 5203` → 172.16.80.200 | ≥ 23 Gbit/s, no regression vs previous run |
   | Admission / DSCP / scheduler / queueing | above + re-apply CoS (`./test/incus/apply-cos-config.sh <target>`) | `show class-of-service interface` | targeted counter (`flow_share`, `buffer`, `ecn_marked`) moves in the predicted direction — see [`cos-validation-notes.md`](cos-validation-notes.md) |
   | NAT / screens / filter / VLAN / IPsec | above | exercise that feature end-to-end from a test host | session / hit counters advance; negative case drops |
   | HA / VRRP / session sync / fabric | `make cluster-deploy` | `make test-failover` + `make test-ha-crash` | 0 / very low packet loss across failover/failback, both nodes converge |

   When a validation lane can't be run in the test env, say so
   explicitly in the PR body with the reason. Never claim success for
   a check that wasn't executed.

9. **PR open + review + merge** — see "PR discipline" and "Merging"
   below for the body template and mechanics. At this stage: Copilot
   and Codex review; every comment gets a disposition reply; squash
   merge once CI is green and findings are resolved.

## Hot-path coding discipline

### Allocations

- **Never allocate per packet.** `Vec::push` that may grow, `VecDeque`
  that returns from a function, `Box::new` inside a `while let Some`
  loop — all land on the allocator.
- **Drain into caller-provided buffers.** Prefer
  `drain_into(&mut out: VecDeque<T>)` over `drain() -> VecDeque<T>`.
  Caller reuses its buffer across polls.
- **Pre-size everything.** `VecDeque::with_capacity(expected)` at
  construction. Fixed-cap rings (`[T; N]`) where the upper bound is
  known statically.
- **Drop policy on full: drop-newest.** Dropping the head of a queue
  evicts a packet that was already close to being serviced and
  extends tail latency. Dropping the incoming packet loses a packet
  that has travelled zero further than the sender. Prefer drop-newest
  unless there's a specific reason otherwise, and document the
  rationale at the drop site.

### Atomics

- **Pick orderings deliberately.** `Relaxed` for counters. `Acquire` /
  `Release` for publish/subscribe slot patterns. `AcqRel` only when
  both sides of a CAS need ordering. If you're reaching for
  `SeqCst` — stop and re-read the algorithm.
- **No `Mutex<VecDeque>` on the hot path.** Use lock-free primitives
  (Vyukov bounded MPMC, SPSC ring, or hand-rolled MPSC). If a mutex
  is unavoidable, isolate it to a slow path.
- **Cache-pad cross-core atomics.** Producer CAS on `head` + consumer
  store on `tail` share a cache line → every op invalidates the
  other core. Split into `#[repr(align(64))] CachePadded<T>` for
  primitives whose job is cross-core coordination.

### Branches

- **Prefer branchless arithmetic.** `saturating_add`,
  `saturating_mul`, `.max()`, `.min()`, `.clamp()`, and
  `bool as u64` conversions generate predictable code.
- **Make hot-path branches predictable.** Config-time booleans
  (`flow_fair`, `exact`) that don't change at runtime give the
  branch predictor a free win. Lift them to early returns at the
  top of hot functions.
- **Don't early-return on rare errors; account for them.** Error
  paths should bump a counter and continue, not unwind. TCP doesn't
  stop because one packet didn't fit; the scheduler shouldn't
  either.

### Compile-time guards

- `const _: () = assert!(condition)` at module level is free. Use
  it for structural invariants: power-of-two sizes, fast-retransmit
  floors, maximum values that fit in a narrower type.
- A `#[test]` that asserts `CONST >= N` runs only on `cargo test`.
  A `const _: () = assert!` runs on every `cargo build`. Prefer
  the latter for values that must not drift.

## API shape discipline

- **Signatures encode contracts.** If a function must not reallocate,
  take `&mut VecDeque<T>` not `-> VecDeque<T>`. If a function expects
  the consumer to hold the "SC" half of an MPSC invariant, mark it
  `unsafe` and document the invariant at the call site.
- **Helpers over duplication, always.** The moment you write the same
  formula in two places, even if they look right today, extract it.
  This is a future-correctness guarantee, not a style choice.
- **Operator-visible units match operator config.** Tests that exercise
  admission boundaries use the same units the operator types. If the
  operator writes `buffer-size 125k` and that parses to 125000 bytes,
  the fixture is `buffer_bytes: 125_000`, not `125 * 1024`. Don't mix
  KB and KiB.

## Overflow / failure policy

| Scenario | Policy |
|---|---|
| Bounded queue, producer push on full | Return `Err(T)` so the caller can decide. In the admission-path wrapper, drop-newest + bump overflow counter. |
| Bounded queue, consumer drain | Never fails. Loop until `pop()` returns `None`. |
| Invariant violation at config time | `panic!` with context. Not recoverable; crash-start is safer than running with a wrong invariant. |
| Invariant violation at runtime (rare, driver bug) | Bump a dedicated counter, continue. Crashing the dataplane on a single misbehaved packet punishes every other flow. |
| "Path not found" at config apply | Warn + continue if the path is a best-effort cleanup; fail hard if the path is load-bearing. Don't let `|| true` mask the load-bearing case. |

## Review discipline

### Reviewing (adversarial by design)

- **Be antagonistic in service of quality.** Reviewers who default to
  "LGTM" let regressions land. The architect/reviewer role exists to
  hold a deliberately high bar.
- **Separate severity from style.** Correctness bugs, perf cliffs, and
  API contract issues are Medium+. Terminology drift, rustdoc rendering,
  redundant no-ops are Low. Call the severity explicitly; it tells the
  author what to do first.
- **Concrete code shape, not vague complaints.** "Consider centralising
  the formula" is less useful than a five-line snippet showing the
  exact helper signature. If you want a specific change, show it.
- **Test strength matters.** A regression test that leaves state at
  `0` before the final assertion is an arithmetic-consistency check,
  not a regression guard. Tests must recreate the failure mode.
  Counter-factual assertions that reconstruct the pre-fix formula and
  prove it *would* fail are the strongest pin.
- **Split behaviour choices out of bug fixes.** If a reviewer spots
  "while you're here, we should also clamp...", that's a separate PR
  or a follow-up issue. Don't let scope creep hide behind
  "review feedback".
- **Trust but verify.** An agent's commit summary describes what it
  intended. Read the diff. Re-run the tests on the updated head before
  approving.

### Responding to review (as author)

- **Apply review items by severity, fastest first.** Cleanup-level
  items (docs, naming) land in the same push. Medium items get their
  own commit if they're substantive. Design questions get a reply
  asking for the decision before coding.
- **Don't silently defer.** If a reviewer raises a concern you don't
  act on, reply with why, and file a tracking issue. The next
  reviewer should not have to re-discover the concern.
- **Update the PR body when live data disagrees.** If the hypothesis
  turns out to be partly wrong, rewrite the summary. Keep both the
  before data and the after data visible. Future readers need the
  honest picture.

## PR discipline

### Title

- Imperative. `userspace-dp: lock-free redirect inbox eliminates cross-
  producer mutex (#706)`, not "Removed mutex".
- Issue reference in parentheses at the end. Multiple if the PR closes
  multiple.

### Body

- **Summary**: 3–6 bullets. What changed and why.
- **Hot-path shape** (for perf PRs): explicit about added instructions,
  allocations, atomics. "One `saturating_mul` + one `max` per
  admission (~2–3 ns)" is the right specificity.
- **Test plan**: checkbox list. What tests were added, what was run.
- **Live data** (for PRs that claim to move a metric): before/after
  table. If the metric doesn't move, say so.
- **Deferred**: named follow-ups with tracking issue numbers. Not
  "TODO later".
- **Refs**: every related issue.

### Commit messages

- Same shape as PR titles. Imperative, prefixed with the subsystem.
- Body paragraphs explain *why*, not *what*. The diff shows what.
- No emoji. No marketing. No "Makes the code better".

### Merging

- **Every code change lands via PR.** Even revert commits. Even
  "obviously right" one-line fixes. Even cherry-picks from someone
  else's branch. If you find yourself typing `git push origin master`
  for anything except a docs-only maintenance skill that explicitly
  does that (see first principle #6), stop — open a PR.
- Squash-merge, single commit per PR on master. Commit message is the
  PR title.
- Do not merge with failing tests. Do not `--no-verify` to skip hooks.
- Close referenced issues with a pointer to the merge commit and the
  specific follow-up issues if any part was deferred.

## Project-specific reminders

These are not "style" but are worth keeping next to the rest because
they repeatedly bite:

- **Deploy wipes CoS config.** After `cluster-setup.sh deploy`, re-run
  `./test/incus/apply-cos-config.sh <target>` before running iperf3
  for any #706 / #707 / #708 / #709 / #718 validation.
- **Always `source ~/.sshrc` before `git push`.** The user's SSH agent
  config lives there.
- **172.16.80.200 is the iperf3 test endpoint.** Not 172.16.50.x.
- **Use `cli`, not `xpfctl`.** The remote CLI binary is `cli`.
- **Primary is fw0 on RG0 in the loss userspace cluster.** Apply config
  changes to the primary; sync takes care of the secondary.
- **Before claiming a CoS admission-path PR moves a metric, read the
  counters.** `show class-of-service interface` surfaces `flow_share`,
  `buffer`, and `ecn_marked` drop counts per queue since #724. See
  [`cos-validation-notes.md`](cos-validation-notes.md) for the
  methodology, the decision tree mapping counter patterns to fixes,
  and the current test-env limitation that blocks ECN end-to-end
  validation. Iterating on admission logic without reading these
  counters is how #721/#722 landed dormant on the live workload
  (#725).

## Tone signals (patterns that have worked)

- "The honest fix is..." → frame the real engineering tradeoff, not
  the easy one.
- "I would either ... or ..." → offer options in reviews, don't
  dictate.
- "I would not silently land ..." → insist on explicit agreement for
  operator-visible changes.
- "Behaviour choice, not a bug fix" → scope discipline in one phrase.
- "Does not recreate the old failure mode" → test-strength review in
  one phrase.
