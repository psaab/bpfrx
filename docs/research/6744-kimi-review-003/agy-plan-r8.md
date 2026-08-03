# Hostile AGY Design Review: Issue #6744 Research Round 8

**Environment & Scope**
- `pwd`: `/home/ps/git/xpf-worktrees/6744-plan-r8-review`
- Exact HEAD: `bebffd32c7a0c2956a7eabbf584a92c6604ec5b2`
- Repository status: `nothing to commit, working tree clean`
- Write scope: `NONE`

---

## 1. Executive Summary & Audit Verification

Revision 8 of `docs/research/6744-kimi-review-003/plan.md` closes all 14 findings flagged by Codex and the SMR fallback in Round 7. Every workstream (A through M) has been re-derived from base source code in [`pkg/config/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/config/), [`pkg/snmp/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/snmp/), [`pkg/ddns/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/ddns/), [`pkg/daemon/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/daemon/), [`pkg/configstore/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/configstore/), and [`userspace-dp/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/userspace-dp/). 

No material design choice remains delegated to implementation. State machine boundaries, lock scopes, tear-down sequences, and error paths are explicitly bounded.

---

## 2. Detailed Workstream Verification (A – M)

### Workstream A: Isolate `vipWarnedIfaces` Synchronization (K003-16)
- **Source Context**: [`pkg/daemon/daemon.go:L701`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/daemon/daemon.go#L701), [`pkg/daemon/daemon_ha_vip.go:L224`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/daemon/daemon_ha_vip.go#L224).
- **Concurrency & Lock Scope**: Introduces a leaf mutex `vipWarningMu` separate from `directVIPMu`. `resetVIPWarnings()`, `markVIPWarning()`, and `clearVIPWarning()` lock only during map lookup/mutation. `vipWarningMu` is never held across netlink RPCs, logging, or sleeps, eliminating the deadlocks caused by recursive `directVIPMu` acquisition.

### Workstream B: Reject Empty Security Identities Before Normalization (K003-07)
- **Source Context**: [`pkg/config/ast.go`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/config/ast.go), `runPreWalkGates`.
- **Malformed-State & Preflight**: Added `validateNonEmptySecurityIdentities(root *ConfigTree)` immediately after `expandInterfaceRanges(tree)` in `runPreWalkGates`. Empty zone names (`""`), empty `from-zone`/`to-zone` keys, and empty policy names are rejected fail-closed in both strict and tolerant paths. Peer-effective preflight via `compilePeerEffectiveHardGateView` forces hard checks on both nodes (0 and 1) before promoting strict commits.

### Workstream C: Enforce SNMPv3 Configured Security Intent (K003-13)
- **SNMP AST-Equivalent Compatibility**: Resolves Round 7 Codex Finding #1. In the parser AST ([`pkg/config/ast.go`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/config/ast.go)), `system { snmp { ... } }`, `set system snmp ...`, and top-level `snmp ...` produce identical, provenance-free nodes. Revision 8 accepts all three AST-identical forms while emitting a nonsecret deprecation warning for `system/snmp`.
- **Nonsecret Conflict Carrier**: `SNMPSourceObservation` and `SNMPv3UserRejection` contain field names, paths, and flags only (`Identity`, `Field`, `Path`, `Present`, `Empty`, `Conflict`). Secrets are compared strictly in memory during initial folding and never copied into warnings, JSON/YAML projections, reconcile hashes, or logs.
- **Structured Client Deny Semantics**: Resolves Round 7 Codex Finding #2. `clients <prefix> [restrict]` is parsed as a structured tuple `(prefix, restrict)`, not a generic leaf-list. Duplicates with matching canonical prefixes resolve with `restrict=true` (deny) winning over unrestricted allow.
- **Two-Belt Runtime/Compiler Pipeline**: `EvaluateV3Users` enforces strict protocol combinations. `SNMPConfig.RejectedV3Users` dominates typed evaluation, ensuring compiler-rejected identities cannot be resurrected by runtime objects. UDP/161 process startup requires `!isProcessDisabled && (validCommunityCount > 0 || evaluation.Installed > 0)`.

### Workstream D: Restore Flowless ICMP Global Admission (K003-01)
- **Source Context**: [`userspace-dp/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/userspace-dp/). Passes `icmp_type` byte to `host_inbound_gated_lo0_action` only when `extra.l4_present` is true (non-first fragments retain 0 and stay fail-closed). Zero memory allocations added on the packet processing path.

### Workstream E: Bind DDNS Withdrawal to Record Ownership (K003-03)
- **Expected-Surface Compatibility**: Resolves Round 7 Codex Finding #3. Introduces explicit `ownedRecordSurface` enum (`ownedRecordSurfaceLease`, `ownedRecordSurfaceInterface`) passed into `loadDDNSState` / `loadStateOrDegrade` from production constructors (`NewProductionManager` / `NewSurfaceAManager`). Defines complete Surface-A and Surface-B validation matrices.
- **Canonical Surface-A Identity**: Surface-A identity `surfaceAIdentity` requires `Address`, `SubnetID`, `OwnerID`, `ClientID`, `PTRName` to be empty; `PTRPending=false`; `AddrText` parseable; canonical lowercase FQDN without trailing dot; and `surfaceAName(scope.FQDN) == row.FQDN`.
- **Claim-Only Before Authority Order**: Resolves Round 7 Codex Finding #4. For stale Surface-B rows, teardown order is strictly:
  1. Validate row matrix.
  2. Perform same-surface and lock-free cross-surface co-owner check (#6015). If co-owner exists, durably release ONLY the Surface-B row with 0 provider I/O.
  3. ONLY for the last claimant, select delete authority (`lastLiveUpdater` with matching `fpb1` -> previous cycle `prevFP` -> fixed test mode -> no authority).
- **Post-Reconcile Anchor Lifetime**: Rotates `lastLiveUpdater`/`lastLiveFP` post-reconcile. If any retained row still requires the old fingerprint, the old anchor is preserved for subsequent retries rather than making unsafe multi-generation guesses.

### Workstream F: Explicit and Atomic `LoadOverride` Format Handling (K003-09)
- **Exact #6548 Boundary**: Resolves Round 7 Claude/SMR Finding #4 and Codex Finding #10. Explicitly excludes `pkg/cli` terminal `readline.ErrInterrupt` handling, leaving it assigned to #6548. Focuses strictly on Store, REST, gRPC, and non-interrupted local loads.
- **Atomic Candidate Swap**: `classifyOverride` pre-scans for comments, flat set verbs (`set`, `deactivate`), or hierarchical containers. Disallows destructive `delete`/`activate` in flat override. Replays onto a detached candidate tree; swaps candidate and updates generation/dirty state only after 100% parse and validation success.

### Workstream G: Validate Persisted AST Shape and Retain Compiler Belts (K003-04)
- **ReadConfirm PrevTree Bounds**: Resolves Round 7 Claude/SMR Finding #3. Invokes `ValidatePersistedTreeShape(tree)` inside `DB.ReadConfirm` immediately after validating `PrevTree != nil` and before returning the record to `recoverPendingConfirmLocked`. Prevents malformed JSON AST nodes from reaching compiler walks without altering the broader commit-confirm transaction design.
- **Safe `Name()` Compiler Idiom**: Adds `afName := afNode.Name()` (`Keys[1]` if `len(Keys) >= 2`) to prevent index out of bounds panics on corrupted AST nodes.

### Workstream H: Share Exact Route-Map Expansion Cardinality (K003-08)
- **Source Context**: [`pkg/config/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/config/), [`pkg/frr/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/frr/). Centralizes `PrefixListFamilies` and sequence counting in `pkg/config`. Calculates single and composed route-map sequence counts including multi-family prefix lists, OR dimensions, and exact 1-terminal-sequence reservation (`RouteMapHighestSequence` saturated at `10 * (termCount + 1)` vs 65535 limit).

### Workstream I: Align Accepted RG IDs with Dataplane Capacity (K003-10)
- **Honest RG Preflight**: Resolves Round 7 Codex Finding #5. Mandates freezing config and choosing the unredacted source artifact prior to rolling upgrades. Preflight executes `xpfd check-config -node-id 0 <file>` and `xpfd check-config -node-id 1 <file>`. Manual `/engineer 6744` sign-off acknowledges file-content preflight scope.
- **Stale Pinned-Slot Fencing**: Resolves Round 7 Codex Finding #6. Compares bound RG inventory against new inventory before map replay. Removed and newly introduced slots (including process start where old inventory is empty) are explicitly fenced via `clearHAOwnerSlotFailClosed` (`rg_active[id]=0`, `ha_watchdog[id]=0`) before publishing the new inventory.
- **Linearizable Config/Session Install Gate**: Resolves Round 7 Claude/SMR Finding #1. `configInstallGate` synchronizes `beginSessionInstall` and `beginConfigApply`. `beginSessionInstall` checks `applying`, `baselinePending`, and `acceptedEpoch` under mutex. `beginConfigApply` sets `applying` and blocks until `inFlight == 0` before running policy sweeps, guaranteeing session installs cannot land after a sweep.
- **Split BulkStart Reset**: Resolves Round 7 Claude/SMR Finding #2 & Codex Finding #7. `resetRecvGen` / `BulkStart` resets ONLY per-key session generations and sequence numbers; it never resets config authority (`lastRecvConfigGen`), `acceptedEpoch`, apply state, or recovery debt.
- **Outbound Bulk Barrier & Invalid Receive-Bulk Behavior**: Resolves Round 7 Codex Finding #8. Outbound bulk uses `bulkSendMu` producer gate: session updates append to a deferred journal and an in-band barrier token is enqueued. Send loop flushes pre-barrier sessions before writing BulkStart/snapshot/BulkEnd, then flushes deferred updates. Invalid receive-bulk discards state, skips stale reconciliation, emits no ACK, and schedules resync.
- **Generation-Tracked Type-29 Debt**: Resolves Round 7 Codex Finding #9. Refused protected installs increment `debtGeneration`. Post-apply/reconnect issues additive length-zero `syncMsgBulkRequest` (type 29). Only a valid matching BulkEnd advances `completedDebt`. Older peers ignore type 29 while unready debt remains visible.

### Workstream J: Merge Repeated Global Address-Book Containers (K003-06)
- **Source Context**: [`pkg/config/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/config/). `compileGlobalAddressBooks` merges all top-level `address-book` and nested `global` blocks into `sec.AddressBook` preserving first-seen order and object-level union rules.

### Workstream K: Retain Routing Ownership on Transient Lookup Errors (K003-11)
- **Source Context**: [`pkg/routing/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/routing/). Interface/tunnel tracking entries are removed from `ownedNames` ONLY upon successful netlink deletion or confirmed `isLinkNotFound(err)`. Transient netlink errors retain ownership for subsequent reconciliation retries.

### Workstream L: Centralize Lifecycle Action Applicability (K003-14 / K003-15)
- **Source Context**: [`pkg/logging/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/logging/). Exhaustive allowlist `eventHasForwardingAction` (`POLICY_DENY`, `SCREEN_DROP`, `FILTER_LOG`). `SESSION_OPEN` and `SESSION_CLOSE` normalize to `name="n/a"`, `binary=0xff`, `applicable=false`. System slog, syslog, trace, and SSE text omit `action=`; APIs and JSON surfaces render `"n/a"`.

### Workstream M: Reject Unsupported Nested Zone-Policy Containers (K003-05)
- **Source Context**: [`pkg/config/`](file:///home/ps/git/xpf-worktrees/6744-plan-r8-review/pkg/config/). `validateSecurityPolicyContainerShapes` validates that `security policies from-zone` entries strictly match the canonical combined key format `["from-zone", <src>, "to-zone", <dst>]`. Nested `from-zone X { to-zone Y }` trees are rejected fail-closed in strict and tolerant compile paths.

---

## 3. Findings & Categorization

### Blockers
*None.* Revision 8 eliminates all unsafe state transitions and race conditions identified in Round 7.

### Optional Polish
1. **Type-29 Observability**: Add a counter metric tracking type-29 resync requests coalesced during active bulk transfers.
2. **DDNS Diagnostic Trace**: Log a debug message when a Surface-B row teardown executes a claim-only co-owner release without DNS I/O.

---

## 4. Final Verdict

PLAN-READY
