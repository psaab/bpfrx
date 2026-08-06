# #4408 plan-review reviewer ledger

Base: `origin/master` `dd23119aa7a6ea5bd118b2f788faa1cf68ce7a42`
Branch: `research/4408-hotpath-split`

| Round | Reviewer | Task ID | Verdict | Artifact |
|---|---|---|---|---|
| r1 | Claude SMR | (in-conversation) | **PLAN-NEEDS-REVISION** → PLAN-READY after folding F1+F2 | `claude-smr-plan-r1.md` |
| r1 | Codex | *not dispatched* | — | leader owns this leg; all Codex lanes occupied at research time |
| r1 | AGY | *not dispatched* | — | AGY permission-blocked in headless mode (returns nothing usable) |

## Scoping exception (recorded)

This research pass ran under an explicit leader scoping exception: produce the
plan doc + a hostile Claude SMR pass, then stop and report. Codex + AGY legs and
convergence are owned by the leader. **This is a 1-of-3 pass, not a converged
plan-review** — the skill's normal bar (all three of Codex + AGY + Claude SMR
agree, or 2-of-3 with documented Codex-infra retries per
`feedback_codex_infra_must_retry`) has **not** been met and no convergence is
claimed anywhere in these docs.

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
- One local `cargo build --release` (58 s, in-worktree `target/`) to produce the
  §2b/§2c symbol + call-edge measurements. No deploy.

## Rerunnable evidence

Every numeric claim in `plan.md` has a command in the doc. The three that a
reviewer should rerun first:

1. **The 102-line duplication** (plan §1d) — the `sed`/`diff` pair.
2. **The escape-free interior** (plan §1b) — the `awk … | grep` over :589–1295.
3. **The call-edge baseline** (plan §2c) — reproduces
   `callgraph-baseline-dd23119aa.txt` (49 normalised edges).
