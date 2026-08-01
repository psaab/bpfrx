# Claude SMR hostile plan-review — round 49 (plan v49 @ `6a6401af0`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r48's SMR
raised the missing re-activation step (folded in v49 — IS part of
Codex M3); r49 re-verifies the v49 folds of Codex's 5M/2m against the
real code and attacks the two new procedure fragments (the two-digest
discipline and the intended-holder-first choreography) for internal
consistency with the older pins they touch. All line numbers
re-verified against the worktree.

## A. Fold verification (r48 findings → v49)

### 1. Codex M1 (epoch contract unified) — FOLDED

Grep-verified: every live site — the normative counter paragraph,
the (3) re-check, the §5.1 inventory, and the JOIN-COHERENCE (h) leg
— now reads advanced WITH the provisional pre-enqueue reservation,
NEVER rolled back, with nil/full attempts moving the epoch without
the counter; the (h) leg asserts the nil/full advance is permanent.
The two remaining "successful reservation" hits are the revision
history's description OF the r47 defect (the problem statement, not
the rule). One authoritative algorithm. FOLDED.

### 2. Codex M2 (apply-failure predicate executable) — FOLDED

The existing-surface gap verifies exactly (compile health is
compile-scoped, `daemon.go:871-880`, `daemon_health.go:79-125`;
`ConfigsApplyFailed` is SessionSync-callback-scoped,
`sync.go:110-119`, `sync_conn_config.go:351-379`; the background
wrappers at `daemon_apply.go:49-86`). The v49 spec — a
process-lifetime failure counter + last-outcome flag, initialized
BEFORE the restarted process's boot apply, instrumented centrally at
every full-apply entry, rendered beside ActiveApplied, predicate
failure-count==0 AND last-outcome-success — is executable, and §9
carries the sticky same-text regression. FOLDED.

### 3. Codex M3 (quiesce no longer permanent) — FOLDED

The quiesce's config change is admitted (`store_command.go:111-129`,
`config/inactive.go:5-10`), the pre-quiesce digest is captured before
(1a), and the procedure ends with the re-activation commit +
re-verification against the pre-quiesce digest — the two-digest
discipline is coherent: post-restart verification compares the
fence-time (post-quiesce) digest; the re-activation verification
compares the pre-procedure digest. FOLDED.

### 4. Codex M4 (two-node verified quiesce) — FOLDED

All four sub-claims verify: authority-only sync + ConfigSync
suppression (`daemon_apply_commit.go:578-601`,
`daemon_ha_sync.go:336-370`); the promoted-secondary writable commit
with syncPeer=false (`daemon_ha.go:438-450`,
`daemon_apply_tail.go:446-455`); the persist-then-abort window
leaving the durable tree deactivated while the live engine retains
policies (`daemon_apply.go:282-309,404-409`,
`daemon_apply_tail.go:194-202`); and the #5679 deferred error as the
loud signal (`daemon_apply_dataplane.go:145-159`). The per-node
deactivation with each commit's success required closes the fence.
FOLDED.

### 5. Codex M5 (intended-holder-first choreography) — FOLDED, with nit m2

The choreography (restart the intended-config holder first; its Load
classifies before cluster comms, `daemon_run.go:157-177,393-398`;
ensure it is RG0 authority; only then the other node) resolves the
read-only-secondary-with-encrypted-artifact contradiction. FOLDED —
but see m2: it textually collides with the r39 local-first pin.

### 6-7. Codex m1 + m2 — FOLDED

The acceptance residual (iii) window now runs from the FIRST sub-read
in both copies, and the re-baseline rule carries the termination
clause (after the second re-baseline with a still-advancing epoch,
the stopped path is UNAVAILABLE — fail-closed — and the operator
fences the ingress source or uses live removal). FOLDED.

## B. Fresh attacks on the v49 delta

**Attack 1 (SUCCEEDED as nit m1) — the re-capture rule does not name
the pre-quiesce digest.** The v49 text's re-capture rule ("any commit
that lands anyway forces a re-capture") sits in (1b) and covers the
fence-time pair, but a commit landing between the pre-quiesce capture
and the (1a) quiesce commit invalidates the PRE-QUIESCE digest — and
the final re-activation verification compares against exactly that
digest. One clause: the re-capture rule covers BOTH captures (a
commit landing anywhere before the moratorium re-takes whichever
digest it invalidates). MINOR.

**Attack 2 (SUCCEEDED as nit m2) — intended-holder-first collides
textually with the r39 local-first pin.** The r39 pin reads "START
THE LOCAL xpfd first" (plan.md:4411) and the v49 choreography reads
"restart the INTENDED-CONFIG HOLDER first"; when the intended holder
is the peer, the two rules name different nodes. The reconciliation
is real and safe — each node's `Load` classification completes
before ITS OWN cluster comms regardless of start order, so a
peer-first start preserves the classification protection on both
nodes (the peer's pushes to the local land only after the local's
Load, because the local's comms start only after its Load) — but the
plan must SAY it: the governing rule is intended-holder-first, with
the plain repair case (holder == local) being the r39 pin's case.
One clause. MINOR.

**Attack 3 (FAILED) — the quiesce commit's own sync re-arms the
peer.** The quiesce commit (from the authority, sync enabled) pushes
the deactivated config to the peer; the peer applies it — which is
exactly the desired two-node quiesce — and any apply failure raises
synchronously and shows at the peer's (2a) preflight. No new hole.
FAILED.

**Attack 4 (FAILED) — the process-lifetime failure counter and the
pre-fence window.** The predicate consults the counter only
POST-restart (initialized before the boot apply); a pre-fence apply
failure is the operator's own visible commit failure during (1a) —
loud at the commit result. The predicate's domain is not undercut.
FAILED.

**Attack 5 (FAILED) — the termination clause's "second re-baseline"
is arbitrary.** It is, but the clause is fail-closed (unavailable,
not unsafe), and any live ingress on a stopped-peer fabric is itself
an incident worth stopping for. The threshold's exact value is an
operator-judgment detail, not a correctness hole. FAILED.

## C. Findings

### MAJOR (0)

None. All seven r48 findings fold on independent verification; the
procedure now reads as one coherent ordered protocol.

### MINOR (2)

**m1.** The re-capture rule must cover BOTH digest captures — a
commit landing between the pre-quiesce capture and the (1a) quiesce
commit invalidates the pre-quiesce digest that the final
re-activation verification compares against.

**m2.** Reconcile intended-holder-first with the r39 local-first pin
(plan.md:4411): the governing rule is intended-holder-first (the
plain repair case, holder == local, IS the r39 case), and the pin's
protection is per-node (each node's Load completes before its own
cluster comms), so a peer-first start in the recovery case preserves
it.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the re-capture rule's
scope and the restart-order reconciliation). A v50 containing only
these two pins is PLAN-READY by inspection from me.
