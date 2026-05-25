# #1531 — Retire DPDK recommendations in docs

## Status

DRAFT v2 — addressing round-1 plan-review findings

## Round-1 verdicts

- Codex (`task-mpkqiyaz-98eky6`): PLAN-NEEDS-MINOR
  - Finding 1: tombstones need a direct migration target
    (`set system dataplane-type userspace` + link to
    `userspace-dp/README.md`), not only an issue pointer.
  - Finding 2: Chain C coordination should be explicit; the VPP
    assessment doc has a live pointer to the decision doc that
    Chain C would otherwise miss.
- Antigravity (`adversarial-review-mpkqjayf-dhx00a`): PLAN-NEEDS-MAJOR
  - Finding 1: wholesale deletion of architecture content during
    Phase 1 / 2 creates an operator-visible "code present, docs
    gone" window. Keep architecture under a clear
    `## Historical Design Details (Retired)` section until
    Phase 3 of #1525 deletes the code.
  - Finding 2: VPP "revisit trigger" content has lasting value —
    reframe against userspace-dp's encrypted-tunnel limits rather
    than delete.
  - Finding 3: `docs/vpp-dataplane-assessment.md:3-5` points at
    the rewritten decision doc; bring it into this PR's scope.
  - Finding 4: tombstones need concrete migration CLI + a markdown
    link to `userspace-dp/README.md`.

The two reviews converge on the same operator-experience fixes plus
the architectural-content-retention point. v2 takes all four
Antigravity findings and both Codex findings.

## Issue framing

Issue #1531 reports that two operator-facing docs on master still
recommend DPDK as a live or recommended dataplane backend:

- `docs/dataplane-decision-dpdk-vs-vpp.md` — line 9 names DPDK "the
  better next dataplane path than VPP" and Option A "Continue DPDK
  backend evolution (recommended)" at line 60.
- `docs/dpdk-dataplane.md` — opens with a multi-page architecture
  plan describing DPDK as "an alternative to the current XDP/TC eBPF
  pipeline" with throughput tables, implementation plan, timeline.

This blocks #1526 (DPDK Phase 1, commit-time reject of
`system dataplane-type dpdk`). If #1526 ships first, the operator
experience is: docs tell them to use DPDK, daemon refuses DPDK,
operator files a doc bug.

#1525 is the DPDK retirement umbrella; this PR is its docs blocker
slice. Phase 4 of the umbrella sweeps the broader docs corpus
(`README.md`, `CLAUDE.md`, `docs/feature-gaps.md`, etc.) — that
remains out of scope for this PR (a separate Chain C agent owns it).

## Honest scope/value framing

Documentation rewrite — zero code, zero binary change. Value is
operator-experience correctness: prevent the doc/daemon contradiction
once #1526 lands. There is no perf gain to weigh against churn.

If reviewers conclude the doc work should be deferred entirely
(e.g. wait until Phase 3 of #1525 deletes the source, then delete
the docs in one stroke), that is a legitimate PLAN-KILL. v2 rejects
this because #1526 needs the docs landing first.

## What's already shipped / partially relevant

- `CLAUDE.md` already carries the #1373 (legacy eBPF) deprecation
  notice at the top. Same shape works for DPDK; will be carried by
  Chain C (#1529) in the broader sweep, not this PR.
- `docs/dpdk-dataplane.md:7-12` already contains a brief #1475
  "deferred" note. Too small, too far down, and predates the #1525
  retirement (#1475 was the defer; #1525 supersedes with retire).
- `userspace-dp/README.md` exists and is the migration target.
- `docs/vpp-dataplane-assessment.md:3-5` points at the decision
  doc — round-1 surfaced this as a same-PR co-fix.

## Concrete design (v2)

The v2 design preserves the historical architecture content under a
clearly marked retirement banner rather than deleting it. This:

- closes the round-1 Antigravity "code present, docs gone" hazard
  during Phases 1 / 2 of the umbrella (source stays in tree).
- preserves deep-anchor inbound links to the architectural sections
  (low risk but free to preserve).
- preserves the VPP revisit-trigger material in reframed form so
  the architectural reasoning for encrypted-tunnel limits is not
  lost from the repo.

### `docs/dataplane-decision-dpdk-vs-vpp.md` (rewrite)

Structure (top to bottom):

1. **Top-of-file retirement banner.** Bold block quote at the very
   top, before everything else:

   ```
   > **Status: Retired.** The DPDK dataplane is being retired under
   > umbrella issue #1525. The userspace AF_XDP dataplane
   > (`userspace-dp/`) is now the primary/default backend. Migrate
   > with `set system dataplane-type userspace`, or simply omit
   > `system dataplane-type` (userspace is the default). See
   > [`userspace-dp/README.md`](../userspace-dp/README.md) for the
   > active design.
   ```

2. **Current state (2026-05).** ~5 lines summarizing:
   - DPDK is retired under #1525.
   - userspace-dp is the primary/default backend.
   - The DPDK source under `dpdk_worker/` and
     `pkg/dataplane/dpdk/` remains in-tree until Phase 3 of #1525
     deletes it; commit-time rejection of
     `system dataplane-type dpdk` lands in Phase 1 (#1526).
   - VPP was never implemented in xpf; no current plan to add one.

3. **VPP revisit trigger (reframed).** ~5 lines:
   ```
   ### Revisit trigger for VPP
   Re-open VPP assessment if all are true:
   - Encrypted tunnel (IPsec / WireGuard) throughput becomes a
     primary product driver. AF_XDP cannot inspect decrypted
     IPsec or WireGuard payloads — only TC BPF hooks see inner
     packets after kernel crypto. VPP's WireGuard plugin and IPsec
     pipeline avoid that bottleneck.
   - Throughput goals materially exceed what userspace AF_XDP
     can deliver on target hardware.
   - Team is willing to own VPP integration and long-term
     plugin/API maintenance.
   ```

4. **Historical Decision (Retired).** A clearly marked section at
   the bottom, with explicit `> **Retired** — preserved for
   reference only.` banner. Contains the original "DPDK vs VPP"
   comparison, option A/B comparison, recommendation, and
   execution plan text — wrapped in the retirement banner so a
   search-engine reader cannot mistake it for current direction.
   The historical text is moved verbatim; only the banner is added.

### `docs/dpdk-dataplane.md` (rewrite)

Structure (top to bottom):

1. **Top-of-file retirement banner.** Same shape as the decision
   doc:

   ```
   > **Status: Retired.** This document was an architecture plan
   > for a DPDK-based xpf dataplane. The DPDK dataplane is being
   > retired under umbrella issue #1525. The userspace AF_XDP
   > dataplane (`userspace-dp/`) is now the primary/default backend.
   > Migrate with `set system dataplane-type userspace`, or simply
   > omit `system dataplane-type` (userspace is the default). See
   > [`userspace-dp/README.md`](../userspace-dp/README.md) for the
   > active design.
   ```

2. **Current state (2026-05).** ~5 lines summarizing:
   - DPDK is retired under #1525.
   - In-tree code under `dpdk_worker/` and
     `pkg/dataplane/dpdk/` remains until Phase 3 of #1525 deletes
     it.
   - Builds with `-tags dpdk` are not supported for production.
   - Commit-time rejection of `system dataplane-type dpdk` lands
     in Phase 1 (#1526).
   - Pointer to `docs/dataplane-decision-dpdk-vs-vpp.md` (also a
     retirement notice).

3. **Historical Design Details (Retired).** A clearly marked
   section at the bottom, with explicit `> **Retired** — preserved
   for reference only.` banner. Contains the original architecture
   plan, pipeline diagrams, RX-mode tables, timeline, file
   structure, decision points — moved verbatim under the
   retirement banner.

### `docs/vpp-dataplane-assessment.md` (header-only update)

Lines 3-5 currently read:

```
Note: This is a deep VPP-focused assessment. For the current project-level
decision and recommendation between DPDK and VPP, see
`docs/dataplane-decision-dpdk-vs-vpp.md`.
```

Replace with:

```
> Note: this VPP assessment was written when DPDK was a live in-tree
> backend candidate. Both DPDK and the dataplane-decision document
> are now retired (DPDK retirement: #1525; userspace AF_XDP is the
> current/default backend in `userspace-dp/`). This assessment is
> kept for the architectural reasoning around encrypted-tunnel
> acceleration, which is still relevant; nothing else in this file
> should be read as current direction.
```

Body of the VPP assessment is NOT touched in this PR. Phase 4 /
Chain C may sweep further; this PR just fixes the inbound pointer.

### Why preserve historical sections inline rather than rely on git history

Round-1 Antigravity finding 1: the in-tree DPDK source survives
Phases 1-2 of #1525 (Phase 1 is the commit reject, Phase 2 is the
boot-path decouple, Phase 3 is the source removal). An operator
who needs to understand a stored DPDK config — or who wants to
build with `-tags dpdk` for archaeology — has nothing in the repo
to read if the architecture content is deleted from the doc.
Preserving the content in a clearly-marked Historical section
solves this without ambiguity about current direction (the banner
at the top is the first thing readers see).

When Phase 3 of #1525 deletes `dpdk_worker/` and
`pkg/dataplane/dpdk/`, that PR can choose to delete the
"Historical" sections as well (their referent is gone). That is
out of scope here.

### Files NOT touched in this PR

- `README.md`, `CLAUDE.md` — Phase 4 sweep, Chain C / #1529.
- `docs/feature-gaps.md`, `docs/userspace-dataplane-gaps.md`,
  `docs/phases.md`, `docs/bugs.md`,
  `docs/active-active-new-connections.md`,
  `docs/refactoring-audit.md`, `docs/perf-ranked-backlog.md`,
  `docs/cross-worker-flow-fairness-research.md` — Phase 4 sweep,
  Chain C.
- `dpdk_worker/README.md` — Phase 3 (source removal).
- Body of `docs/vpp-dataplane-assessment.md` (lines 7+) — Phase
  4. Only the inbound-pointer header is fixed.

### Chain C coordination

Plan v2 adds an explicit Chain C handoff: this PR's commit message
and PR body call out the same-PR doc files (the two named + the
VPP assessment header) and explicitly list the broader-sweep files
as Chain C's surface. If Chain C lands first and touches the VPP
assessment header, this PR's vpp-assessment change will conflict
and a clean rebase resolves to "Chain C wins, this PR was right
to scope minimally." If this PR lands first, Chain C inherits a
consistent surface for the broader sweep.

## Public API preservation

N/A — documentation only. No code, no tests, no API surfaces touched.

## Hidden invariants the change must preserve

1. **No broken doc links.** Any other doc file linking into the
   three touched files (`dpdk-dataplane.md`,
   `dataplane-decision-dpdk-vs-vpp.md`,
   `vpp-dataplane-assessment.md`) must still resolve. v2's
   preserve-historical-sections approach makes deep-anchor links
   continue to resolve.
2. **No CI hooks key on doc strings.** `grep` makefiles, hooks,
   `.github/workflows/`, scripts for substrings of the changed
   text before final commit.
3. **The retirement message survives independent reading.** Anyone
   who lands on any of these files from a search engine must
   understand, in the first screen of text, that DPDK is retired
   and where to look instead. v2's top-of-file banner is bolded,
   block-quoted, contains the migration CLI command, and links
   the active design doc.
4. **No promise about VPP roadmap.** v2 preserves the revisit
   trigger but reframes it against the limitations of the new
   default backend (userspace AF_XDP's kernel-crypto boundary for
   IPsec / WireGuard), not against DPDK. This is honest about the
   ongoing tradeoff that does not vanish with DPDK retirement.
5. **#1525 reference is durable.** Both rewrites link the umbrella
   by number, not by title-as-of-today.
6. **Cross-doc consistency.** The retirement banner shape is
   identical across all three touched files so a search-engine
   reader gets the same top-of-file truth.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | NONE | No code or binary change. |
| Lifetime / borrow-checker | NONE | No code. |
| Performance regression | NONE | No code. |
| Architectural mismatch | LOW | v2's preserve-historical approach addresses round-1 Antigravity's main finding. |
| Cross-PR coordination | LOW | Chain C may sweep other doc files in parallel. v2 explicitly scopes the VPP-assessment header into this PR; if Chain C also touches it, rebase resolves cleanly. |
| Stale inbound pointers from third-party assessment doc | RESOLVED | v2 brings `docs/vpp-dataplane-assessment.md:3-5` into scope. |
| Search-engine reader misreads "Historical" section as current | LOW | The retirement banner is at the very top; the Historical section also has its own retirement banner; both use the same bold block-quoted format. |

## Test plan

Documentation PR — the smoke matrix is mandated by the user as a
discipline gate, not because docs can break the dataplane. The full
matrix runs anyway:

- `git grep -i 'recommend\|primary\|secondary' docs/dpdk-dataplane.md docs/dataplane-decision-dpdk-vs-vpp.md` outside the "Historical" section returns no live DPDK recommendations.
- `git grep -F -- "docs/dataplane-decision-dpdk-vs-vpp.md" docs/` shows the updated inbound-pointer line from `docs/vpp-dataplane-assessment.md`.
- `git grep -F -- "dpdk-dataplane.md" docs/` shows updated cross-pointer between the two touched files.
- `make build` clean.
- `make test` clean.
- `cargo build` + `cargo test --release` clean (Rust side unchanged; gated for completeness).
- Deploy on `loss:xpf-userspace-fw0/fw1`.
- Pass A (CoS disabled, fixture-aligned tear-down):
  - v4 push, v4 reverse, v6 push, v6 reverse single-stream.
  - v4 and v6 `-P 12 -R` multi-stream — line rate, 0 retrans.
- Pass B (CoS re-applied via `apply-cos-config.sh`):
  - Per-class 5201-5206 × v4/v6 × push/reverse = 24 measurements.
- No retrans regressions vs master baseline.

## Out of scope (explicitly)

- README/CLAUDE.md sweep — Chain C / #1529.
- Broader `docs/*` sweep — Chain C / #1529.
- Body of `docs/vpp-dataplane-assessment.md` (anywhere past
  line 5) — Phase 4.
- `dpdk_worker/README.md` deletion — Phase 3 source removal.
- Adding a code-side commit-time reject for `dataplane-type dpdk` —
  Chain A PR #2 (#1526).
- Deleting `dpdk_worker/` source — Phase 3 of #1525.
- Removing the blank import in `cmd/xpfd/main.go` — Phase 2 of
  #1525.
- Touching the canary `dpdkBackendImportAllowlist` — Phase 2 of
  #1525.

## Open questions for adversarial review (round-2)

1. **Is the "Historical Design Details (Retired)" section the right
   tradeoff?** v2 preserves the architectural content inline.
   The alternative is to delete it now and rely on git history.
   Antigravity round-1 came down strongly on preserve; Codex
   round-1 explicitly endorsed wholesale-delete. v2 takes the
   preserve path because the source code is staying in-tree until
   Phase 3. If reviewers think this is over-cautious — the in-tree
   code IS NOT going to receive any updates and the architecture
   doc is purely historical — flag PLAN-NEEDS-MINOR with a clear
   counter-example.

2. **Should the migration CLI hint show
   `set system dataplane-type userspace` AND/OR mention the
   "omit the line entirely" path?** v2 mentions both. A reviewer
   may want only one (less surface to read).

3. **Is the reframed VPP revisit trigger honest about
   userspace-dp's actual encrypted-tunnel performance?** v2 says
   "AF_XDP cannot inspect decrypted IPsec or WireGuard payloads
   — only TC BPF hooks see inner packets after kernel crypto."
   That is a verifiable claim from the existing VPP assessment
   doc (`docs/vpp-dataplane-assessment.md:26-31`). Double-check.

4. **Does the VPP-assessment header update create a regression?**
   The replacement says "nothing else in this file should be
   read as current direction." That is strong language. If
   parts of the body ARE still current direction (e.g. the
   hybrid XDP + VPP topology), the new header understates it.
   Reviewer may want the wording weakened.

5. **Does this PR coordinate correctly with Chain C?** v2 says
   the PR body will explicitly list the same-PR doc files and
   the broader-sweep files. If Chain C is currently dispatched
   and its plan touches `docs/vpp-dataplane-assessment.md:3-5`
   too, we should coordinate via PR comment, not silently
   conflict.

6. **Does anything in CI key off strings in these docs?** v2's
   test plan greps for this; surface results in the PR body.
   Plan-review round-1 did not flag any. Verified by grep
   absence is good enough.

7. **Should the Historical sections cite their own retirement
   date?** v2 currently uses a generic "preserved for reference
   only" banner. Adding "as of 2026-05" pins the snapshot in
   time. Marginal.
