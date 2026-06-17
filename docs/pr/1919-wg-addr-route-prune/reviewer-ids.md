# Reviewer ID ledger — #1919 implementation (PR #1950)

Branch: engineer/1919-wg-addr-route-prune off origin/master @ ee3f336d3
Plan: docs/research/1919-wg-addr-route-prune/plan.md (3-way PLAN-READY r3)

## Code-review rounds (Codex single global slot, foreground `codex exec`)

| Round | Reviewer | Artifact | Verdict |
|---|---|---|---|
| r1 | Codex | /tmp/codex-1919-r1c.out (gpt-5.5 xhigh) | NEEDS-CHANGES (2 Major) |
| r1 | AGY | agy CLI from worktree; /tmp/agy-1919-r1.out | MERGE-READY |
| r1 | Claude SMR | in-conversation hostile pass | MERGE-READY |
| r1 | Copilot | PR #1950 automated (1 comment: EEXIST log nit) | COMMENTED |
| r2 | Codex | /tmp/codex-1919-r2.out | NEEDS-CHANGES (1 Major) |
| r3 | Codex | /tmp/codex-1919-r3.out | NEEDS-CHANGES (1 Major) |
| r4 | Codex | /tmp/codex-1919-r4.out | NEEDS-CHANGES (1 Major) |
| r5 | Codex | /tmp/codex-1919-r5.out | NEEDS-CHANGES (1 Major) |
| r6 | Codex | /tmp/codex-1919-r6.out | NEEDS-CHANGES (1 High) |
| r7 | Codex | /tmp/codex-1919-r7.out | MERGE-READY (no findings) |
| r8 | Codex | /tmp/codex-1919-r8.out (post-EEXIST) | MERGE-READY (no findings) |
| final | AGY | /tmp/agy-final2.out (full final code) | MERGE-READY |
| final | Claude SMR | in-conversation | MERGE-READY |
| final | Copilot | EEXIST nit addressed in d4ca91325; re-review requested | resolved |

## Convergence: all four MERGE-READY on the final state (Codex r8, AGY
final, Claude SMR, Copilot nit addressed).

## Finding trail (every Codex finding fixed + RED-verified regression test)

- **r1 MAJOR #1** reconcileLinkAddrsLocked dropped applied link-local
  ownership on AddrList failure → fe80 reclassified foreign + leaked on
  later WG prune. FIX: preserve applied LL ownership on AddrList failure.
  Test: TestWireguardLinkLocalOwnershipSurvivesAddrListFailure.
- **r1 MAJOR #2** same-name WG→non-WG prune race (prune deletes the active
  non-WG address mid-Apply). FIX: skip WG prune for names in non-WG
  `desired`. Test: TestWireguardToNonWGSameNameNoPruneRace.
- **r2 MAJOR** WG→non-WG handoff + later transient non-WG removal
  LinkByName dropped ownedNames → orphaned link. FIX: non-WG removal loop
  retains on transient (isLinkNotFound gate). Test:
  TestNonWGRemovalTransientLookupRetained.
- **r3 MAJOR** inverse non-WG→WG: retained ownedNames left an active WG
  link → later Apply LinkDel'd it. FIX: wgDesired-handoff guard (drop
  ownedNames, keep nothing for retry). Test:
  TestNonWGToWireguardSameNameNoOwnedRetention.
- **r4 MAJOR** inverse handoff dropped appliedAddrs → configured fe80
  reclassified foreign + leaked. FIX: preserve appliedAddrs (drop only
  appliedRI). Test strengthened with configured + autoconf fe80.
- **r5 MAJOR** legacy GRE→WG with incompatible-link LinkDel failure
  orphaned the stale GRE link. FIX: re-retain ownedNames on the WG-apply
  error. Test: TestLegacyToWireguardSameNameIncompatibleLinkDelFailureRetained.
- **r6 HIGH** the r5 retain was too broad → a healthy WG link's
  transient+create failure re-tracked it → later removal LinkDel'd the
  live wgN. FIX: scope re-retain to errWGIncompatibleLinkRetained
  sentinel. Test: TestWireguardCreateFailureDoesNotRetainOwnership.
- **Copilot** AddrAdd EEXIST warned noisily after AddrList failure. FIX:
  errors.Is(unix.EEXIST) → record applied + log Debug.

## Documented residual (both reviewers accept, address-leak-safe)

The create-EEXIST variant of the GRE→WG transition (transient LinkByName
+ stale GRE present + LinkAdd EEXIST) can leave the stale GRE LINK
orphaned — but AGY confirmed the no-ADDRESS-leak invariant still holds
(the WG prune deletes the addresses). Full restart-time + multi-instance
teardown is #1434 scope.
