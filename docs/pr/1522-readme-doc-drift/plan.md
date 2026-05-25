# #1522 — Package README doc-drift sweep before final eBPF source removal

Status: DRAFT v3 — rebased onto current master (`d237cceb`) and
further scope-reduced via the same AGY principle that pruned the
three `bpf/*/README.md` banner edits in v2.

## Plan history

- v1: 5 file edits — `dpdk_worker/README.md`, `bpf/xdp/README.md`,
  `bpf/tc/README.md`, `bpf/headers/README.md`, `pkg/logging/README.md`.
- v2: AGY adversarial-review-mpkub795-6e2gou returned
  PLAN-NEEDS-MINOR; pruned the three `bpf/*/README.md` banner edits
  because #1476 will mechanically delete the entire `bpf/` tree.
  Down to 2 files: `dpdk_worker/README.md` + `pkg/logging/README.md`.
  AGY adversarial-review-mplbvcsb-kxkn6q returned PLAN-READY on v2.
- v3 (this revision): rebased onto current master and noticed that
  the deletion sweep for `dpdk_worker/` lives in **#1528** (issue
  body: "`dpdk_worker/` does not exist", listing
  `dpdk_worker/README.md` in the deletion list). By the same
  principle AGY applied in v2 (do not edit a README that a sibling
  retirement PR will mechanically delete), `dpdk_worker/README.md`
  must also be pruned. That leaves **1 file** in scope:
  `pkg/logging/README.md`. Master's own CLAUDE.md callout
  `> DPDK dataplane retired in #1525. ... removed in #1527/#1528.`
  makes this scope reduction unambiguous.

## Issue framing

Issue #1522 (surfaced during #1451 scope-and-plan work) asks for a
pure-docs sweep across in-tree package READMEs and module docs so that
every place describing the dataplane architecture is consistent with the
deprecation notice at the top of `CLAUDE.md`:

> The Rust AF_XDP userspace dataplane is now the primary/default
> target for dataplane development, validation, and omitted runtime
> configuration. The legacy eBPF dataplane remains in-tree for
> explicit compatibility and regression coverage during the staged
> retirement.

This sub-issue is a **BLOCKER on #1476** (the final mechanical removal
of legacy BPF source, generated artifacts, and build hooks): the
deletion PR review will fail if package READMEs still describe the
deleted path as primary. The issue body specifically calls out:

- `pkg/dataplane/` README — was the heaviest drift candidate.
- `pkg/conntrack/README.md:13` — was documenting the old
  `NewGC(dp dataplane.DataPlane, ...)` signature.
- `CLAUDE.md` "BPF Pipeline (14 programs, tail calls)" section
  describing the legacy pipeline without flagging it as deprecated.
- Likely additional drift to be enumerated in the first sweep.

## Honest scope/value framing

This is a **pure-docs PR**. The win is: unblock #1476 by removing
documentation that contradicts the AF_XDP-primary reality, while
preserving the bpf/* and dpdk_worker/ READMEs as accurate descriptions
of the still-in-tree (and still-buildable) backends.

Absolute scale (v3): **1 README file edited** (down from 5 in v1,
2 in v2). The single edit is a one-token reframe in
`pkg/logging/README.md` line 46 — "...as eBPF ring-buffer events"
becomes "...as the legacy eBPF ring-buffer events do". Zero
source/code change, zero build/test impact beyond what doc-touches
imply. Defensible reviewer verdict could be PLAN-KILL on the grounds
that one-token framing is below the noise floor; counter-argument is
that the entire #1522 issue exists to scrub framing drift, and this
is the only legitimate non-deletion-path drift on master after #1537
landed.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (For a docs-only PR the only
relevant equivalent is "the drift is already addressed by #1537/#1534"
or "this overlaps an in-flight PR".)

## What's already shipped / partially covered

Three doc-sweep PRs landed on master immediately before this sub-issue:

- **#1529 / PR #1537 (merged)** — top-level `README.md`, `CLAUDE.md`,
  and the bulk of `docs/*.md`. Also touched `pkg/dataplane/README.md`
  and `pkg/daemon/README.md` directly, both of which now carry the
  #1373 deprecation banner inline.
- **#1531 / PR #1534 (merged)** — `docs/dataplane-decision-dpdk-vs-vpp.md`,
  `docs/dpdk-dataplane.md`, `docs/vpp-dataplane-assessment.md`, and
  `userspace-dp/README.md`.
- **#1525 / PR #1538 (merged)** — `_Log.md` entries and assorted
  inline-DPDK annotations.

**Survey result on master (commit `c5c52a14`, the master tip at the
time of the v1 survey; current master tip after rebase is `d237cceb`
which adds #1517/#1532/#1536/#1537/#1549 — none of those touch the
pkg/logging/README.md drift this PR addresses)** — running
`grep -niE 'eBPF|XDP|TC egress|tail.call|primary|cilium/ebpf|bpf2go|legacy'`
across all 54 in-tree package-level READMEs:

- **Already updated by #1537/#1534**: `pkg/dataplane/README.md`,
  `pkg/daemon/README.md`, `userspace-dp/README.md`. Each has the
  #1373 deprecation banner inline and frames eBPF as the legacy /
  retirement-pending path. No further work on these in this sweep.
- **bpf/README.md** — already has the #1373 deprecation banner.
- **userspace-dp/src/afxdp/README.md** — already says
  "Primary #1373 AF_XDP forwarding path".
- **pkg/conntrack/README.md:13** — already shows the new
  `NewGC(provider RuntimeDomainProvider, interval) *GC` signature
  on master. **Acceptance criterion #2 is already met** — the issue
  body was stale on this point. No further work needed.

## Remaining drift (the only file this PR will touch)

| File | Drift | Proposed edit |
|---|---|---|
| `pkg/logging/README.md` | Line 46: "...so it gets the same name resolution, callback fanout, local writers, and syslog delivery as eBPF ring-buffer events." The framing makes eBPF events the canonical reference. | Tighten to "...as the legacy eBPF ring-buffer events do." This keeps the technical accuracy (the eBPF path still emits ring-buffer events and the userspace path normalises into the same fanout) but stops reading as if eBPF is the canonical baseline. |

That's **1 file**. The pruned-from-scope set:

- `bpf/xdp/README.md`, `bpf/tc/README.md`, `bpf/headers/README.md`
  — pruned in v2 per AGY adversarial-review-mpkub795-6e2gou.
  #1476 deletes the entire `bpf/` tree.
- `dpdk_worker/README.md` — pruned in v3 by the same principle.
  #1528 deletes the entire `dpdk_worker/` tree (its issue body
  explicitly lists `dpdk_worker/README.md` in the deletion set
  and master's `CLAUDE.md` callout already states "DPDK dataplane
  retired in #1525. ... removed in #1527/#1528").

Everything else surveyed on master (`d237cceb`) either already
carries the deprecation banner (`pkg/dataplane/README.md`,
`pkg/daemon/README.md`, `bpf/README.md`, `userspace-dp/README.md`),
already matches the current source signature
(`pkg/conntrack/README.md` — `NewGC(provider RuntimeDomainProvider,
interval) *GC`), or describes dual-backend status renderers / cross-
cutting code where the "eBPF backend" mention is a factual present-
tense reference to a still-shipping code path
(`pkg/fwdstatus/README.md:14,33`, `pkg/monitoriface/README.md:34`).

## Concrete design

One plain Markdown edit. No source code, no tests added, no
generated files touched. Concrete proposed text:

### pkg/logging/README.md (line 46)

Before:
```
syslog delivery as eBPF ring-buffer events.
```

After:
```
syslog delivery as the legacy eBPF ring-buffer events do.
```

## Public API preservation

N/A — pure docs. Zero Go/Rust/C code touched.

## Hidden invariants this change must preserve

1. **`retirement_boundary_canary_test.go` text-pinned strings** —
   the canary at `pkg/dataplane/retirement_boundary_canary_test.go`
   line 28 pins specific token-list substrings in
   `docs/pr/1373-retire-ebpf-dataplane/README.md` only. **This PR
   touches none of those pinned paths.** The pinned-tokens list at
   line 1792 and the shim-escape token list at line 1821 reference
   the umbrella retirement README, not package READMEs. Risk = 0.
2. **No `// go:generate README.md` patterns** — verified via
   `grep -rn "go:generate" pkg/ bpf/ userspace-dp/ cmd/ dpdk_worker/`:
   no README is autogenerated from source comments. Editing a README
   does not require a matching source change.
3. **bpf/* and dpdk_worker/ READMEs untouched** — v2 left
   `bpf/xdp/README.md`, `bpf/tc/README.md`, `bpf/headers/README.md`
   alone (#1476 will delete the tree). v3 additionally leaves
   `dpdk_worker/README.md` alone (#1528 will delete the tree per its
   issue body and master's `CLAUDE.md` callout).
4. **Preserve the new `NewGC` signature in pkg/conntrack/README.md** —
   on master it already matches source; do not regress it.

## Risk assessment

| Risk class | Level | Why |
|---|---|---|
| Behavioral regression | NONE | No code touched. |
| Lifetime / borrow-checker | NONE | No Rust touched. |
| Performance regression | NONE | No code touched. |
| Architectural mismatch (#961 / #946-Phase-2 pattern) | NONE | Pure docs reframe, not a refactor. |
| Canary text-pin regression | LOW | This PR does not touch `docs/pr/1373-retire-ebpf-dataplane/README.md`. Validated by reading the canary at line 28 and the token lists at lines 1792 and 1821. |
| Overlap with #1529/#1537 or #1531/#1534 | LOW | This PR's file list does not intersect either merged PR's file list. Confirmed by `gh pr view 1537 --json files` and `gh pr view 1534 --json files` against this plan's edit list. |
| Misframing live legacy code as already-deleted | LOW | The banners say "being retired" and "still ships for compatibility", consistent with the existing `CLAUDE.md` and `pkg/dataplane/README.md` wording. The per-stage body text is preserved verbatim. |

## Test plan

For a pure-docs PR per skill discipline:

- `git diff --stat` confirms only `*.md` files touched. Smoke is
  skipped per skill rules.
- `make test` Go suite still passes (sanity, not a contract — no
  code change should change test outcomes).
- Specifically run `go test ./pkg/dataplane/... -run RetirementBoundary`
  to confirm the canary tests still pass (defensive verification that
  none of the pinned text strings were inadvertently touched).
- No Cargo test impact expected.

## Out of scope (explicitly deferred)

- **Source removal of `bpf/`** — that's #1476's job.
- **Removing the `bpf/`, `bpf/headers/`, `bpf/xdp/`, `bpf/tc/` READMEs
  entirely** — would be premature; the legacy path still ships and
  contributors may need its docs. Deletion belongs in or after #1476.
- **Rewriting `pkg/dataplane/README.md` lines 8-11** — that paragraph
  ("Abstract dataplane interface plus the legacy eBPF backend") was
  already touched by #1537; it now reads as a factual description of
  the package's surface. Further wordsmithing is out of scope.
- **Touching `CLAUDE.md`** — already covered by #1537. Re-touching it
  would conflict with that merged PR's scope.
- **Touching `docs/*.md`** — already covered by #1537 / #1534. Same
  scope-conflict rationale.
- **Adding a doc-lint canary that fails if the deleted path is
  described as primary after #1476 lands** (acceptance criterion #4) —
  this is most naturally done as part of #1476 itself, because the
  canary needs to know exactly which files exist and what they say
  on the target state. Adding such a canary now would either pin
  text that #1476 will then delete (forcing #1476 to also touch the
  canary), or pin text in still-shipping legacy READMEs that #1476
  is supposed to delete (causing #1476's deletion to break the
  canary). Defer to #1476 by design.
- **Sweeping `userspace-dp/src/*/README.md`** for further polish —
  those READMEs all already say "AF_XDP", "userspace", or "primary"
  consistently with the deprecation notice. No drift found in survey.

## Open questions for adversarial review (v3)

1. **Should `pkg/logging/README.md` line 46 reframe be dropped?** The
   technical claim — userspace events flow through the same fanout as
   eBPF ring-buffer events — is accurate and the framing is mild.
   Argument to drop: this is below the noise floor for a pre-deletion
   sweep. Argument to keep: it's a one-token fix that costs nothing,
   and after the v3 scope reduction it is the only legitimate drift
   on master that isn't owned by a sibling deletion PR.
2. **Should the PR just be CLOSED as NO-OP and the BLOCKER label
   moved to "#1522 is satisfied by #1537+#1525 already"?** The
   1-file scope is so narrow this becomes plausible. Counter: the
   #1522 issue's first acceptance criterion explicitly lists
   `pkg/logging`-style "primary"-flavored framing among the targets,
   and shipping the one fix closes the issue rather than relabelling
   it. Reviewer call.
3. **Should this sweep ALSO add an explicit "retained for
   compatibility" heading to `pkg/dataplane/README.md`** (acceptance
   criterion #1's "legacy references either delete or move under
   explicit 'retained for compatibility' headings")? #1537 already
   added the deprecation banner; the body paragraph reads as factual.
   Argument to do it: literal acceptance-criterion compliance.
   Argument not to: re-touching a file #1537 already shaped invites
   merge churn and the deprecation banner at the top already
   satisfies the spirit. Reviewer call.

## Plan v2 → v3 changelog

- Rebased onto current master (`d237cceb`).
- Removed `dpdk_worker/README.md` from the edit list. #1528 is OPEN
  and its issue body explicitly lists `dpdk_worker/README.md` in the
  deletion set; master `CLAUDE.md` already states "DPDK dataplane
  retired in #1525. ... removed in #1527/#1528". Same principle AGY
  used to prune the three `bpf/*/README.md` edits in v2.
- Edit list reduced from 2 files to 1: `pkg/logging/README.md`.
- Updated "Concrete design", "Hidden invariants", "Open questions",
  and the scope-and-value paragraphs to reflect the new 1-file scope.
- Open question #2 surfaces the legitimate alternative verdict: close
  #1522 as NO-OP and treat the master state as already satisfying the
  acceptance criteria via #1537+#1525.

## Plan v1 → v2 changelog

- Removed `bpf/xdp/README.md`, `bpf/tc/README.md`, and
  `bpf/headers/README.md` from the edit list per AGY
  adversarial-review-mpkub795-6e2gou PLAN-NEEDS-MINOR. #1476 will
  mechanically delete these files; editing them now is churn that
  #1476 will reverse.
- Edit list reduced from 5 files to 2: `dpdk_worker/README.md` and
  `pkg/logging/README.md`.
- Updated "Concrete design", "Hidden invariants", "Open questions",
  and the scope-and-value paragraphs to reflect the new 2-file scope.

## Plan-review iteration policy

Per skill discipline: if Codex and Antigravity disagree, iterate the
plan to address the more-hostile reviewer's findings. If both say
PLAN-KILL, stop and update this doc with the KILL verdict.

For a 5-file pure-docs sweep, PLAN-KILL is plausible if either
reviewer argues the work is below the noise floor and should fold
into #1476. That's a legitimate verdict — note it and stop.
