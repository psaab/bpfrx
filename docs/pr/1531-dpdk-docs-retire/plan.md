# #1531 — Retire DPDK recommendations in docs

## Status

DRAFT v1 — pending adversarial plan review

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
operator files a doc bug. Documentation has to land first or together
with the reject.

#1525 is the DPDK retirement umbrella; this PR is its docs blocker
slice. Umbrella also has Phase 4 (broader doc sweep across README,
`docs/feature-gaps.md`, etc.); that is explicitly NOT in this PR's
scope. This PR touches exactly the two files #1531 names.

## Honest scope/value framing

Pure documentation rewrite — zero code, zero binary change. Value is
operator-experience correctness: prevent the doc/daemon contradiction
once #1526 lands. There is no perf gain to weigh against churn.

If reviewers conclude that a pointer-only stub is insufficient for the
operator landing on these docs from a search engine in isolation,
PLAN-NEEDS-MAJOR is acceptable. If reviewers conclude the rewrite is
overcautious (e.g. should KEEP the DPDK architecture content as
historical reference under a clear "retired" banner instead of
deleting it), that is also a legitimate verdict to push back on.

PLAN-KILL is appropriate if reviewers identify that the docs should
NOT change in this PR (e.g. they should be deleted outright as part of
Phase 3 of #1525, not rewritten as retirement notes). This is unlikely
— #1531 explicitly asks for the rewrite/banner — but is allowed.

## What's already shipped / partially relevant

- `CLAUDE.md` already carries the #1373 (legacy eBPF) deprecation
  notice at the top. The same shape will work for DPDK.
- `docs/dpdk-dataplane.md` line 7-12 already contains a brief #1475
  "deferred" note. It is too small and too far down to be the first
  thing the operator sees, and it predates the #1525 retirement
  decision (#1475 was the defer; #1525 supersedes with retire).
- #1525 umbrella is filed and visible to anyone clicking through.

## Concrete design

### `docs/dataplane-decision-dpdk-vs-vpp.md`

Reduce to a short retirement notice (~30 lines). Drop the
"recommendation," "execution plan," and "option A vs B" sections
entirely. Keep just:

1. Title + retirement banner at the very top (block quote, bold) with
   `Status: Retired` and `Supersedes: 2026-03-02 active decision`.
2. One paragraph: "DPDK has been retired under #1525. The userspace
   AF_XDP dataplane (`userspace-dp/`) is the primary/default backend
   and the only one with active development."
3. One paragraph: "VPP was assessed against DPDK in this document
   when DPDK was a live backend candidate. With DPDK retired the
   comparison is moot. There is no current plan to add a VPP
   backend; if one becomes interesting, a fresh decision document
   will be filed at that time."
4. One-line pointer to `docs/dpdk-dataplane.md` (which will become a
   retirement notice of its own) and to #1525.

The old recommendation, option comparison, execution plan, and
revisit trigger sections are removed wholesale. An operator
search-engine-landing on this file sees within the first screen of
text that the document is retired and where to look for the current
truth.

### `docs/dpdk-dataplane.md`

Reduce to a short retirement notice (~25 lines). Drop the
architecture plan, pipeline diagrams, code snippets, RX-mode tables,
timeline, file structure, and decision points. Keep just:

1. Title + retirement banner at the very top (block quote, bold) with
   `Status: Retired`.
2. One paragraph: "This document was an architecture plan for a
   DPDK-based xpf dataplane. The DPDK dataplane is being retired
   under #1525 (see umbrella for phase plan and rollback path).
   The userspace AF_XDP dataplane (`userspace-dp/`) is now the
   primary backend for high-throughput / low-latency targets."
2. One paragraph that captures the historical context the operator
   may have come looking for: "The in-tree code under
   `dpdk_worker/` and `pkg/dataplane/dpdk/` remains until Phase 3
   of #1525 deletes it. Builds with `-tags dpdk` are not supported
   for production. Commit-time rejection of `system dataplane-type
   dpdk` lands in Phase 1 (#1526)."
3. One-line pointer to `docs/dataplane-decision-dpdk-vs-vpp.md`
   (also a retirement notice) and to #1525.

The architecture content (Phase 1-5, RX modes, comparison with XDP,
file structure) is removed wholesale. It is preserved in git history
for archaeology; nothing actionable is lost.

### Cross-doc consistency

Both docs use the same banner format and the same "retired under
#1525" wording so a search-engine landing on either yields the same
top-of-file truth.

### Why rewrite rather than banner-only

The issue's acceptance criteria offer "rewrite (preferred), or
(minimum acceptable) prepend a bold two-paragraph retirement banner."
The minimum-acceptable path leaves the body of each doc still
recommending DPDK; an operator who skims past the banner could still
end up wrong. The rewrite path is strictly better and the work is
small. Choosing the preferred path.

### Files NOT touched in this PR

- `README.md`, `CLAUDE.md` — Phase 4 sweep (#1529-equivalent under
  umbrella). The Chain C agent owns this.
- `docs/feature-gaps.md`, `docs/userspace-dataplane-gaps.md`,
  `docs/phases.md`, `docs/bugs.md`,
  `docs/active-active-new-connections.md`,
  `docs/refactoring-audit.md`, `docs/perf-ranked-backlog.md`,
  `docs/cross-worker-flow-fairness-research.md` — Phase 4 sweep.
- `dpdk_worker/README.md` — defer to Phase 3 (source removal).
- `docs/vpp-dataplane-assessment.md` — out of scope. If it
  recommends DPDK as an alternative, that's a separate cleanup.

## Public API preservation

N/A — documentation only. No code, no tests, no API surfaces touched.

## Hidden invariants the change must preserve

1. **No broken doc links.** Any other doc file linking into the two
   touched files must still resolve. `grep` for inbound links and
   verify they still make sense pointing at a retirement notice.
2. **No CI hooks key on doc strings.** `grep` makefiles, hooks,
   `.github/workflows/`, scripts for substrings of the deleted text.
3. **The retirement message survives independent reading.** Anyone
   who lands on either file from a search engine must understand,
   in the first screen of text, that DPDK is retired and where to
   look instead.
4. **No promise about VPP roadmap.** The decision doc as it stands
   describes a "revisit trigger" for VPP. The retirement notice
   must NOT carry that forward — it would be a stale promise. Use
   "if it becomes interesting, a fresh decision doc will be filed
   at that time" instead.
5. **#1525 reference is durable.** Both docs link the umbrella by
   number, not by title-as-of-today.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | NONE | No code or binary change. |
| Lifetime / borrow-checker | NONE | No code. |
| Performance regression | NONE | No code. |
| Architectural mismatch | LOW | This is the right doc work; risk is that the rewrite-vs-banner choice is overcautious or undercautious, both surfaced for plan-review challenge. |
| Cross-PR coordination | LOW | Chain C (#1529) may sweep other doc files in parallel. As long as Chain C does not touch the two files this PR touches, there is no conflict. Both PRs will rebase cleanly if the other lands first. |

## Test plan

Documentation PR — the smoke matrix is mandated by the user as a
discipline gate, not because docs can break the dataplane. The full
matrix runs anyway:

- `git grep -i 'recommend\|primary\|secondary' docs/dpdk-dataplane.md docs/dataplane-decision-dpdk-vs-vpp.md` returns no live DPDK recommendations.
- `git grep -i 'dpdk' docs/dpdk-dataplane.md docs/dataplane-decision-dpdk-vs-vpp.md | grep -v -i 'retired\|retirement\|historical'` returns only ambient mentions (file titles, umbrella refs) — no live recommendation.
- `make build` clean.
- `make test` clean (Go suite — should be unchanged by a docs PR).
- `cargo build` + `cargo test` clean (Rust suite — should be unchanged).
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
- `dpdk_worker/README.md` deletion — Phase 3 source removal.
- Adding a code-side commit-time reject for `dataplane-type dpdk` —
  PR #2 of this chain (#1526).
- Deleting `dpdk_worker/` source — Phase 3 of #1525.
- Removing the blank import in `cmd/xpfd/main.go` — Phase 2 of
  #1525.
- Touching the canary `dpdkBackendImportAllowlist` — Phase 2 of
  #1525.

## Open questions for adversarial review

1. **Should the rewrite delete the historical architecture content
   wholesale, or preserve it under a "Historical (retired)" section
   in the same file?** Git history preserves it either way. The PR
   chooses wholesale deletion to keep the doc short and the
   retirement message unambiguous. If a reviewer believes the
   architecture content has lasting reference value (e.g. someone
   may want to compare userspace-dp's design choices against the
   original DPDK plan), pushing back here is legitimate.

2. **Is "retired under #1525" sufficient pointer text, or should the
   doc also link directly to `userspace-dp/README.md` / the
   userspace-dataplane CLAUDE.md section, so the operator gets a
   migration target without clicking through to the umbrella?** PR
   currently does the former; reviewer may want the latter.

3. **Should the VPP comparison content be deleted from the
   decision doc, kept as a footnote, or migrated to
   `docs/vpp-dataplane-assessment.md`?** PR currently deletes it
   from the decision doc and does not touch the VPP assessment
   doc. Migration would be cleaner but creates Chain-C-style
   scope creep.

4. **Does the retirement notice need to reproduce the migration
   command (`set system dataplane-type userspace` or the omit-it
   path) so the operator gets the answer in-file, or is "see #1525
   for migration" sufficient?** PR currently does the latter. The
   former would duplicate text that #1526 will surface in the
   commit-error message itself.

5. **Does anything in CI key off strings in these docs?** PR has
   not yet verified this; it is in the test plan, but a reviewer
   may want to see the grep output before signing off. (Plan-review
   round-1 will run the grep and surface results.)

6. **Are there other docs that link into these two files by deep
   anchor (e.g. `#power-management-interrupt-driven-mode`)?
   Deleting the anchor will silently break the link.** PR will
   `grep -F` for the section anchors before final commit.

7. **Should both docs be deleted outright instead of rewritten as
   retirement notices?** The umbrella's Phase 3 says "delete or
   rewrite as historical notes." The PR chooses rewrite-as-notice
   to keep the file path alive (other docs, possibly external
   references, link to it). A reviewer may argue for outright
   deletion + redirect via a stub — that's harder to verify and
   no clearer to the operator, but it's a legitimate alternative.
