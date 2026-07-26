# Claude SMR hostile plan-review — round 39 (plan v39 @ `801c9dd3e`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r38's SMR
returned PLAN-READY; r39 re-verifies the v39 folds of Codex's 4M/1m
against the real code and attacks the enforceable barrier's blast
radius and the offline repair shape's operability. All line numbers
re-verified against the worktree.

## A. Fold verification (r38 findings → v39)

### 1. Codex M1 (enforceable peer-stop barrier) — FOLDED

The observability gap is real (the apply flag and queue are
private, `cluster/sync.go:594-616`; the public surfaces expose
only cumulative/history data, `cluster/sync.go:191-228`,
`cluster/status.go:340-356` — no operator predicate can fence
peer-driven syncs). The peer stop is the right barrier: the
SyncApply path is peer-PUSHED (the local `handleConfigSync`
receiver only delivers what the peer sends,
`daemon_ha_sync.go:534-578,909-912` — re-verified), so a stopped
peer deterministically fences reconnect-, promotion-, and
reconciler-driven syncs (`daemon_ha_sync.go:417-430,500-522,
926-956`). FOLDED.

### 2. Codex M2 (abandoned-D repair shape) — FOLDED, with nit m1

The conflation was real: a tombstone FAILURE leaves the ORIGINAL
pending record, and a pending-shaped offline repair of a DEAD
record can bind at the next boot (legacy-empty or same-content
`GuardedHash` — the #5835 binding rules at
`store_persist.go:149-165,171-255`) and replay the resolved
window. The fold (never pending-shaped; REMOVE or write
`Resolved: true`) is correct — but see m1: hand-authoring a
full-field tombstone is an unrealistic operator instruction when
removal is always available. FOLDED.

### 3. Codex M3 (deadline-split recovery) — FOLDED

The split verifies: still-pending → re-arm for the ORIGINAL
remaining interval (`store_persist.go:231-253` — the deadline is
carried in the record) and confirm away with a bare `commit`
(cancels the timer, `store_commit.go:729-748`); already-expired
→ `Load` already reverted (`store_persist.go:171-228`), bare
`commit` returns "no pending confirmed commit"
(`store_commit.go:729-746`), so the operator re-commits the
intended config. FOLDED.

### 4. Codex M4 (H-class recovery path) — FOLDED

Premise re-verified: `clusterTopologyCommitPreflight` rejects a
standalone→cluster commit when `d.cluster == nil`
(`cluster_topology_preflight.go:59-97` — the HA runtime is
boot-only-constructed, and its own error text names the
recovery: "restart xpfd into the clustered configuration"). The
xpf.conf boot import (`bootstrapFromFile`) is the day-0 path
that commits the seed. FOLDED.

### 5. Codex m1 (deadline surface) — FOLDED

The audit journal carries no deadline field
(`pkg/configstore/journal/journal.go:59-80` — re-verified the
entry schema) and confirm.json may be encrypted
(`db.go:199-216`); the startup journald log line
(`store_persist.go:254-255`) is the only surface. FOLDED.

## B. Fresh attacks on the v39 delta

**Attack 1 (CONSIDERED-AND-CLOSED) — the peer stop's blast
radius.** The peer's own xpfd stop abandons the PEER's
process-local debts symmetrically — the same benign boot
re-derivation (the peer's boot re-classifies into the same
terminal states; the records involved are the same dead-or-live
shapes with the same remedies). The peer restart order: a peer
restarted while the local node is still down for the offline
repair pushes SyncApply to a down receiver — the delivery fails
and the peer marks the node out-of-sync; the 30-second
reconciler converges on the next reconnect. The only clean
ordering rule is cosmetic: restart the peer AFTER the local
boot classification completes (avoids one sync failure cycle).
The cluster converges either way. CLOSED — not a defect.

**Attack 2 (SUCCEEDED as nit m1) — the Resolved:true
hand-authoring burden is unrealistic.** The machinery's
synthesized tombstone carries a full pinned shape (`Resolved:
true`, `FirstCommit=false` load-bearing for the old reader,
`HashBasis="canonical-v1"`, `Deadline`, `GuardedHash`,
`PrevTree`, `ArmID` — the r22-r24 pins). Asking an operator to
hand-author that record so the Resolved-first check drops it
cleanly on BOTH readers is error-prone to the point of being a
trap — and it is never necessary: REMOVAL is always available
(always live-safe, offline too, and the record is dead by
construction so its crash-recovery value is nil). The runbook
should prefer REMOVAL in every case and present the
`Resolved: true` shape only as documentation of the machinery's
own tombstone form — never as an operator-authoring
instruction. MINOR.

## C. Findings

### MAJOR (0)

None. All four r38 majors fold on independent verification; the
remediation protocol's barrier and repair shapes are now
enforceable and correctly bounded.

### MINOR (1)

**m1.** The offline repair guidance should prefer REMOVAL in
every case (always live-safe, offline too, and the dead record
has no crash-recovery value); the `Resolved: true` tombstone
shape is documented as the machinery's own synthesized form —
the full pinned field set is an unrealistic operator-authoring
burden and should not be an operator instruction.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the
prefer-removal guidance). A v40 containing only this pin is
PLAN-READY by inspection from me.
