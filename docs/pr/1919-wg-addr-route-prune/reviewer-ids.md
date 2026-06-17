# Reviewer ID ledger — #1919 implementation (PR #1950)

Branch: engineer/1919-wg-addr-route-prune off origin/master @ ee3f336d3
Plan: docs/research/1919-wg-addr-route-prune/plan.md (3-way PLAN-READY r3)

| Round | Reviewer | Task ID / artifact | Verdict |
|---|---|---|---|
| r1 | Codex | foreground `codex exec` (gpt-5.5, xhigh); /tmp/codex-1919-r1c.out | NEEDS-CHANGES (2 Major) |
| r1 | AGY | `adversarial-review-mqhunvnb-c4r6ht` (empty — wrong cwd); re-run CLI from worktree, /tmp/agy-1919-r1.out | MERGE-READY |
| r1 | Claude SMR | in-conversation hostile pass | MERGE-READY |
| r1 | Copilot | PR #1950 automated review | pending |
| r2 | Codex | re-review after fixes | pending |

## r1 Codex findings (both fixed in commit a0f0a5ef1)

- **MAJOR #1** (tunnel.go reconcileLinkAddrsLocked): on an AddrList
  enumeration failure, a configured fe80 mid-removal fell to the AddrAdd
  pass (EEXIST in real netlink), was dropped from newApplied, and so was
  re-classified as foreign on the next pass → leaked forever on a later WG
  prune. FIX: preserve prior applied LINK-LOCAL ownership into newApplied
  on AddrList failure. Regression:
  TestWireguardLinkLocalOwnershipSurvivesAddrListFailure (verified RED
  without fix).
- **MAJOR #2** (tunnel.go Apply WG prune loop): a same-name WG→non-WG
  mode transition let the WG prune race the non-WG apply path; on an
  AddrDel failure the name persisted in wgConfigured and a later Apply
  AddrDel'd the active non-WG address mid-commit. FIX: skip WG prune for
  names in the current non-WG `desired` set (handoff). Regression:
  TestWireguardToNonWGSameNameNoPruneRace (verified RED without fix).

## r1 AGY note

First MCP dispatch ran with cwd=/home/ps/git/bpfrx (main repo, not the
worktree) so origin/master...HEAD was empty → 0-byte result. Re-run via
the agy CLI with --add-dir on the worktree + the branch diff inline.
MERGE-READY on the fixed code (all 8 hostile axes walked, both new
regression tests confirmed non-vacuous).
