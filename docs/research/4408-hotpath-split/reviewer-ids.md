# #4408 plan-review reviewer ledger

Base: `origin/master` `dd23119aa7a6ea5bd118b2f788faa1cf68ce7a42`
Branch: `research/4408-hotpath-split`

| Round | Reviewer | Verdict | Artifact |
|---|---|---|---|
| r1 | Claude SMR | **PLAN-NEEDS-REVISION** → PLAN-READY after folding F1+F2 | `claude-smr-plan-r1.md` |
| r2 | Codex | **PLAN-NEEDS-MAJOR** — waterfill survives; Option B's dispatch half blocked on churn + unverified cp1/cp2 + NAT64 coverage | leader-run; verdict relayed, quoted in plan §5-A / §5-B′ |
| r2→r3 | Claude SMR | **PLAN-READY on the narrowed scope (Option B′)** — 4 findings, one MAJOR (F8, gate false-negative) | `claude-smr-plan-r2.md` |
| — | AGY | *not dispatched* | AGY permission-blocked in headless mode (returns nothing usable) |

## Convergence status

**2-of-3 on the narrowed scope.** Codex and Claude SMR agree that the waterfill
split ships and that the dispatch de-dup does not ship in this pass; r3 is
written to that line. AGY has not reviewed. Per
`feedback_codex_infra_must_retry` the bar is all three, or 2-of-3 with the third
documented as unavailable — AGY's unavailability is a permission block, not an
infra outage, so **the leader owns whether 2-of-3 is sufficient here.** No
convergence beyond what is stated in this table is claimed anywhere in these
docs.

## Scoping exception (recorded)

Both rounds ran under an explicit leader scoping exception: produce the plan doc
+ a hostile Claude SMR pass, then stop and report. The Codex leg is run by the
leader, who owns convergence.

## Constraints observed

- Worktree only (`.claude/res4408`); the main checkout was never touched.
- No production source edited; `docs/research/4408-hotpath-split/` only —
  matching the `research/4404-polldesc-decompose` precedent (`374b257d7`), which
  likewise touched no `_Log.md`. Per-edit `_Log.md` entries are owed at
  `/engineer` time when production files change.
- **No cluster/incus tooling run** (`make test-failover`, `cluster-setup.sh`,
  `apply-cos-config.sh` all untouched) — the cluster is a shared locked resource
  and the leader schedules all smoke. The §7.5 throughput leg is therefore
  *specified*, not executed.
- Local release builds only, for the §2b/§2c/§2c-bis symbol + call-edge
  measurements. No deploy.

### r3 probe worktree (created, used, removed)

The §2c-bis stability probes needed a *second* binary built from a perturbed
`dispatch/mod.rs`. To avoid editing production source in the deliverable
worktree — which a queued Codex gate may be reading
(`feedback_never_mutate_a_worktree_under_review`) — the probes ran in a
throwaway detached worktree `.claude/res4408probe` at `175d8efdd`:

1. P1 — appended a dead `#[inline(always)] fn`; built; extracted the edge set.
2. P2 — reverted, then moved an existing item within the file; built; extracted.
3. `git worktree remove --force`; scratch dirs deleted.

Nothing from the probe worktree was committed or pushed. `res4408` was clean
throughout (`git status --short` empty). An out-of-tree `cp -a` of just
`userspace-dp/` was tried first and abandoned: it fails to link outside the repo
(duplicate `crc32` between the vendored `libelf.a` and `libz.a`), and the
**control build with no probe edit failed identically** — confirming the failure
was the copy environment, not the probe.

## Rerunnable evidence

Every numeric claim in `plan.md` has a command in the doc. The four a reviewer
should rerun first:

1. **The duplication** (plan §1d) — the `sed`/`diff` pair. Expect 102-line
   blocks agreeing on 100 of 102 lines.
2. **The escape-free interior** (plan §1b) — the `awk … | grep` over :589–1295.
   Expect 11 comment-only hits; the executable `break` at :661 is documented
   separately in §1b and will not appear in that grep's output as a `break`.
3. **The call-edge baseline** (plan §2c) — reproduces
   `callgraph-baseline-dd23119aa.txt` (**51 raw edges**, no normalisation).
   *Changed in r3: r2 checked in 49 normalised edges; see §2c-bis for why
   normalising the Rust hash was a false-negative blind spot.*
4. **The Tier-1-vs-r2-rule proof** (plan §2c-bis) — the synthetic instantiation
   swap plus the `.llvm.` relabel negative control, both runnable against the
   checked-in baseline with no build required.
