# Claude SMR / independent fallback plan review - round 14

The Claude Code CLI was attempted against the immutable checkout but failed
before analysis with the account monthly-spend-limit error. No Anthropic-model
verdict is claimed. The verdict below is from a separately identified,
non-Anthropic independent SMR-method fallback.

**Independent fallback verdict: PLAN-NEEDS-MAJOR**

Review target: detached, locked, clean checkout at
`df53c23111385e84178d4025788468e82b58d31a`.

## Findings

1. **BLOCKER - tail coalescing destroys NAT reservation dependencies.** Given a
   baseline `B -> tuple T`, the valid tail `Delete(B,T)`, `Open(A,T)`,
   `Open(B,U)` coalesces to `Open(A,T)` then `Open(B,U)`. The receiver still
   owns `B/T` when it checks `A/T`, so authoritative repair rejects valid source
   truth. Preserve release-before-reuse dependencies or apply each coalesced
   final-state batch as one atomic allocator transaction.
2. **BLOCKER - coordinator inventory confuses local tunnel state with peer
   authority.** Local tunnel entries deliberately carry `SyncImport`, and
   `SyncImport` satisfies `origin.is_peer_synced()`. The proposed coordinator
   inventory therefore includes local auxiliary rows and can reconcile them as
   stale peer state. Introduce distinct authoritative provenance plus an
   exhaustive origin-transition matrix.
3. **BLOCKER - shim-map migration is both required and declared preserved/out of
   scope.** Workstream I requires `userspace_sessions_v2`, while public API,
   invariant, and out-of-scope sections still say pinned map specifications and
   migrations do not change. Reconcile those contracts.

Workstreams A-H and J-M had no blocker. Workstream I was blocked by these three
findings. Final checkout verification remained detached and clean; staged and
unstaged diffs were empty and the reviewer modified no files.
