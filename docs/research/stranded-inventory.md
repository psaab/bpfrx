# Stranded `research/*` branch inventory

**Read-only inventory. No branch was pushed, merged, deleted, or opened as a PR.**

Commissioned after #4408 turned up a twice-reviewed PLAN-READY document sitting on
`research/4408-hotpath-split` with no PR ever opened — invisible to `gh pr list`
and to master's `docs/research/`, so every future lane would have re-derived it.
The question this answers: how many more are there, and which are worth reading?

Measured at master `d77583fe56750dd1ae915a453bd73803574f268b`.

## Method, and one trap worth recording

```bash
git ls-remote origin 'refs/heads/research/*'                  # 217 branches
gh api 'repos/psaab/xpf/pulls?state=all&per_page=100' --paginate   # 3242 PRs
```

Cross-referenced locally. No per-branch `gh` call — 217 of those time out.

**`gh pr list --limit 1000` returns exactly 1000 and is silently truncated.** The
repository has **3242** PRs, so a `--limit 1000` cross-reference misses ~69% of
them and would report branches as stranded whose PR simply fell outside the
window. The paginated `gh api` form is the only complete one. This is the same
class as the `gh pr/issue list` 30-item default cap, one order of magnitude up.

Two further refinements the obvious method gets wrong:

- **A branch carrying a plan doc is not evidence of stranded content.** These
  branches are cumulative — a branch cut in August contains every research doc
  written since May, so `docs/research/**` file counts run to 445 and mean
  nothing. The real test is the set difference against master: files present on
  the branch and **absent from master**.
- **"No PR on the research branch" is not "the work was lost."** In 157 of 213
  cases an implementation merged under a `fix/*` / `refactor/*` prefix carrying
  the same issue number. Only the doc went unmerged.

## Result

| disposition | count | meaning |
|---|---|---|
| **STRANDED-PLAN** | **18** | issue OPEN, plan docs never merged — the #4408-shaped class |
| **UNKNOWN** | **6** | no issue number in the branch name; needs a human read |
| **SUPERSEDED** | **32** | issue closed, or content already on master |

Of 217 `research/*` branches: 4 have a PR on the branch itself, 157 have an
implementation merged elsewhere under the same issue number, and **56** have
neither — the table below.

## STRANDED-PLAN — issue OPEN, plan never merged — 18

The #4408-shaped class: an open issue whose research was written, never merged, and is
invisible to `gh pr list` and to master's `docs/research/`. **Worth reading, not ready to
execute** — a converged plan's verdicts expire. `master moved` is the commit count since the
branch diverged: a *risk proxy*, not a measurement of whether the plan's target files changed.
#4408's plan survived a 3,000-commit gap only because its two target files turned out
byte-identical, and that was checked rather than assumed. Do the same before trusting any row.

| issue | branch | tip | plan | unmerged docs | master moved | last commit |
|---|---|---|---|---|---|---|
| #1703 (OPEN) | `research/1703-wireguard-ubiquiti-interop` | `8ed3d49ea` | yes | 6 | 8539 | 2026-05-30 |
| #1958 (OPEN) | `research/1958-substrate-binding` | `df2235787` | yes | 10 | 7388 | 2026-06-17 |
| #1958 (OPEN) | `research/1958-refresh` | `4abad367c` | yes | 16 | 6908 | 2026-06-20 |
| #4785 (OPEN) | `research/4785-ipip-inbound-decap` | `e80f4627d` | yes | 3 | 2586 | 2026-07-09 |
| #5278 (OPEN) | `research/5278-loopback-grpc-rbac` | `bd7a754c7` | yes | 2 | 1794 | 2026-07-11 |
| #5883 (OPEN) | `research/5883-peer-forward-trust` | `15470b445` | yes | 1 | 1350 | 2026-07-16 |
| #5865 (OPEN) | `research/5865-session-schema` | `2125c5518` | yes | 6 | 1210 | 2026-07-16 |
| #5858 (OPEN) | `research/5858-input-filter-invalidation` | `16f5eb8ee` | yes | 7 | 1162 | 2026-07-16 |
| #5798 (OPEN) | `research/5798-frag-assoc-authority` | `10a591da8` | yes | 2 | 1066 | 2026-07-18 |
| #4960 (OPEN) | `research/4960-apply-txn` | `ad300b881` | yes | 6 | 967 | 2026-07-18 |
| #6169 (OPEN) | `research/6169-heartbeat-epoch` | `4baa14c78` | yes | 14 | 524 | 2026-07-23 |
| #6177 (OPEN) | `research/6177-reth-twoowner` | `1df2657fd` | yes | 12 | 524 | 2026-07-23 |
| #6371 (OPEN) | `research/6371-rgactive-fence` | `131b4015b` | yes | 17 | 520 | 2026-07-23 |
| #6461 (OPEN) | `research/6461-blind-rst` | `0b9af421d` | yes | 331 | 285 | 2026-07-31 |
| #6744 (OPEN) | `research/6744-kimi-review-003` | `4eb850285` | yes | 50 | 78 | 2026-08-05 |
| #6746 (OPEN) | `research/6746-zero-rg-window` | `8a48e4b16` | yes | 6 | 78 | 2026-08-04 |
| #6749 (OPEN) | `research/6749-armed-state` | `352a9869c` | yes | 114 | 78 | 2026-08-04 |
| #6751 (OPEN) | `research/6751-nopat-admission` | `466d767e5` | yes | 141 | 78 | 2026-08-04 |

## UNKNOWN — no issue number derivable from the branch name — 6

Named by topic or review round rather than issue. These are exactly what a
`refs/heads/research/<issue>*` lookup cannot find. The `dirs` they carry are listed in the
notes below.

| issue | branch | tip | plan | unmerged docs | master moved | last commit |
|---|---|---|---|---|---|---|
| — | `research/external-review-triage` | `8865333ae` | yes | 5 | 8609 | 2026-05-28 |
| — | `research/cpu-headroom-p48-cpu-headroom` | `0fdda93f0` | yes | 8 | 8287 | 2026-06-03 |
| — | `research/1917b-inplace-upgrade-mechanism` | `6b6e86de4` | yes | 3 | 7584 | 2026-06-16 |
| — | `research/agy-review-011` | `a135ba63e` | yes | 3 | 7361 | 2026-06-17 |
| — | `research/upgrade-hardening-review-011` | `96d8c2a8e` | yes | 6 | 7361 | 2026-06-17 |
| — | `research/review-015-triage` | `71727dd4c` | yes | 4 | 7104 | 2026-06-20 |

## SUPERSEDED — issue closed, or content already on master — 32

The issue reached a terminal state by another route (an implementation merged under a
`fix/*` / `refactor/*` prefix, or the issue was closed). The docs are a historical artifact.
Not a recovery target.

| issue | branch | tip | plan | unmerged docs | master moved | last commit |
|---|---|---|---|---|---|---|
| #937 (CLOSED) | `research/937-ingress-xdp-redirect` | `c7351b402` | no | 0 | 8988 | 2026-05-06 |
| #1648 (CLOSED) | `research/1648-startup-neigh-race` | `9dfc993a0` | yes | 23 | 8607 | 2026-05-29 |
| #1648 (CLOSED) | `research/1648-bringup-readiness` | `ce4d03b5e` | yes | 6 | 8602 | 2026-05-29 |
| #1608 (CLOSED) | `research/1608-phase4c` | `cf4050816` | yes | 9 | 8593 | 2026-05-29 |
| #1692 (CLOSED) | `research/1692-3g6g-guarantee-instr` | `4a14aeac7` | yes | 8 | 8552 | 2026-05-30 |
| #1742 (CLOSED) | `research/1742-same-queue-xsk-fanout` | `7c04f0733` | yes | 6 | 8311 | 2026-06-01 |
| #1748 (CLOSED) | `research/1748-mlx5-flow-rebalance` | `9784ad382` | yes | 8 | 8287 | 2026-06-01 |
| #1750 (CLOSED) | `research/1750-reliable-flow-feed` | `499e9116b` | yes | 11 | 8287 | 2026-06-02 |
| #1751 (CLOSED) | `research/1751-count-balance` | `65a70501d` | yes | 8 | 8287 | 2026-06-02 |
| #1754 (CLOSED) | `research/1754-tx-wake-kick` | `85320d00e` | yes | 5 | 8276 | 2026-06-03 |
| #1756 (CLOSED) | `research/1756-core-isolation` | `90af5197c` | yes | 4 | 8276 | 2026-06-03 |
| #1758 (CLOSED) | `research/1758-reassert-correctness` | `17169a6d7` | yes | 4 | 8276 | 2026-06-03 |
| #1766 (CLOSED) | `research/1766-fairness-char` | `0ae04d127` | yes | 107 | 8246 | 2026-06-04 |
| #1825 (CLOSED) | `research/1825-daemon-restructure` | `510e5cef5` | yes | 9 | 8115 | 2026-06-10 |
| #1849 (CLOSED) | `research/1849-overhead-comp` | `4368ccb8b` | yes | 5 | 8021 | 2026-06-10 |
| #1920 (CLOSED) | `research/1920-poll-descriptor-split` | `d5e3fa04d` | yes | 4 | 7395 | 2026-06-17 |
| #2002 (CLOSED) | `research/2002-config-ast-import-cycle` | `45789ab20` | yes | 1 | 7150 | 2026-06-19 |
| #2004 (CLOSED) | `research/2004-daemon-multiqueue-import-cycle` | `71e62e401` | yes | 1 | 7150 | 2026-06-19 |
| #2002 (CLOSED) | `research/2002-2004-import-cycles` | `f79c6b923` | yes | 2 | 7133 | 2026-06-19 |
| #1987 (CLOSED) | `research/1987-dhcp-consolidation` | `1d8e85a36` | yes | 2 | 7074 | 2026-06-19 |
| #1987 (CLOSED) | `research/1987-dhcp-consolidate` | `4733f59a2` | yes | 5 | 6869 | 2026-06-20 |
| #2117 (CLOSED) | `research/2117-port22-no-rst` | `f3cab73e1` | yes | 5 | 6869 | 2026-06-20 |
| #2274 (CLOSED) | `research/2274-feeds-materialize` | `4e497894f` | yes | 2 | 6491 | 2026-06-21 |
| — | `research/ddns-world-class` | `53e652cfa` | yes | 0 | 5973 | 2026-06-24 |
| #3620 (CLOSED) | `research/3620-intrazone` | `59b9ae9bc` | yes | 5 | 4469 | 2026-07-01 |
| #3617 (CLOSED) | `research/3617-mirror-clone` | `c2b42f033` | yes | 5 | 4455 | 2026-07-01 |
| #3611 (CLOSED) | `research/3611-junos-host-self-zone` | `5a83a2f5b` | yes | 4 | 4449 | 2026-07-01 |
| #3630 (CLOSED) | `research/3630-default-policy-repr` | `a5f5d76aa` | yes | 5 | 4445 | 2026-07-01 |
| #4478 (CLOSED) | `research/4478-ipip-decap-zone` | `59ab9ff66` | yes | 4 | 2589 | 2026-07-09 |
| #5177 (CLOSED) | `research/5177-nat64-embedded-port` | `d70fab019` | yes | 3 | 1735 | 2026-07-11 |
| #5562 (CLOSED) | `research/5562-snapshot-coherence` | `ebe2e0039` | yes | 4 | 1735 | 2026-07-11 |
| #5145 (CLOSED) | `research/5145-dnat-first-match` | `6dcb5712b` | yes | 5 | 1230 | 2026-07-16 |

<!-- counts: {'SUPERSEDED': 32, 'STRANDED-PLAN': 18, 'UNKNOWN': 6} -->

---

## Notes on individual rows

### The one that is immediately actionable

**`research/4785-ipip-inbound-decap` (#4785, OPEN, `e80f4627d`, 3 unmerged docs).**
This is the **half 2** research — inbound decap — for the very issue whose half 1
(reject `mode ipip` at commit) shipped as PR #6861. The half-1 plan's own text
says *"half 2 of #4785 implements the decap stage; when it lands this gate is
removed, not relaxed"*, and the research for that half has been sitting unmerged
since 2026-07-09. Anyone picking up half 2 would otherwise start from scratch.
Read it before dispatching that work.

### Resolved by inspection, and why the branch name defeated the lookup

Three UNKNOWN rows carry docs whose directory name names an issue the *branch*
does not:

| branch | carries | issue state |
|---|---|---|
| `research/cpu-headroom-p48-cpu-headroom` | `docs/research/1752-cpu-headroom/` | #1752 **CLOSED** |
| `research/review-015-triage` | `2049-dynamic-address-enforcement`, `2051-activate-deactivate-edit-command` | #2049 **CLOSED**, #2051 **CLOSED** |
| `research/1917b-inplace-upgrade-mechanism` | `1917b-inplace-upgrade-mechanism` | #1917 **CLOSED** |

All three are SUPERSEDED once the number is recovered. They are listed under
UNKNOWN in the table above because a *mechanical* `refs/heads/research/<issue>*`
lookup cannot find them — which is precisely the discovery gap this inventory
exists to measure. The doc *path* is the reliable key, not the branch name.

The remaining three UNKNOWN rows (`agy-review-011`, `external-review-triage`,
`upgrade-hardening-review-011`) are review-round triage output, not per-issue
plans, and carry no issue number anywhere. They need a human read to disposition.

### Staleness — read this before trusting any STRANDED-PLAN row

`master moved` is a **risk proxy, not a verdict**. It counts commits master has
advanced since the branch diverged, which says nothing directly about whether the
plan's *target files* changed. #4408's plan survived a ~3,000-commit gap intact
because both of its target files turned out byte-identical across that range —
and that was **checked**, not assumed. The corresponding check for any row here
is:

```bash
git diff --stat <plan's stated base SHA> origin/master -- <the plan's target files>
```

Empty output means the line numbers still hold. Anything else means the map has
moved and the plan is a starting point rather than a specification.

By that measure the rows most likely to have decayed are the oldest: **#1703**
(WireGuard/Ubiquiti interop, 8,539 commits, 2026-05-30) and the two **#1958**
branches (~7,000). The four most recent — #6744, #6746, #6749, #6751, all 78
commits behind — are almost certainly still accurate.

### Outliers worth a glance

- **`research/6461-blind-rst` — 331 unmerged files.** An order of magnitude more
  than any other row. Either a large genuine body of work or an artifact of how
  that branch was cut; worth one look before anyone assumes either.
- **`research/6749-armed-state` (114)** and **`research/6751-nopat-admission`
  (141)** are the next largest, both 2026-08-04 and only 78 commits behind.
- **`research/1958-refresh`** carries docs under `1958-substrate-binding`, i.e.
  it is a second pass over the same directory as its sibling branch. The two
  should be read together, newer first, not treated as independent.

## What this inventory does NOT claim

- **It does not say any STRANDED-PLAN row is correct, converged, or ready.** It
  says the content exists, is unmerged, and belongs to an open issue. A plan's
  verdicts expire; three of #4408's five rounds found defects in its own gate.
- **It does not verify the target files of any row except #4408.** That check is
  per-plan and is the reader's first job.
- **It took no action.** No PR opened, no branch merged, pushed, or deleted.
