# Claude SMR hostile plan-review — round 60 (plan v60 @ `e8e8beabd`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r59's SMR
raised the additive-QUEUED pin (folded in v60 as part of Codex M4);
r60 re-verifies the v60 folds of Codex's 5M/2m against the real code
and attacks the generation-tag/seqlock relationship and the
re-registration's coverage of in-flight arms. All line numbers
re-verified against the worktree.

## A. Fold verification (r59 findings → v60)

### 1. Codex M1 (actuated-state authority check) — FOLDED

The actuation-lag construction verifies (`election.go:337-395`
publishes before the daemon consumes; `rg_state.go:250-263` +
`daemon_ha.go:340-371,809-848` keep rg_active/VRRP-master live past
a demotion; `status.go:12-25` + `heartbeat_manager.go:306-355` mix
instants). The v60 check — exactly one node with RG0 ACTIVE AND VRRP
MASTER — reads the actuated state (the RG active state and VRRP
mastership are both rendered by the cluster/VRRP status paths), and
a lagging actuation reads as not-yet-settled — fail-closed. FOLDED.

### 2. Codex M2 (full-form fence + deep outcome) — FOLDED

The full-form fence (`runCtx.Err()` OR `stopping`) covers the
signal-driven-teardown-early window (the runCtx is cancelled at
signal time, before `runShutdownSequence` publishes `stopping`,
`daemon_run_shutdown.go:50-64,214-230`), and the per-mutation
re-check covers a teardown beginning mid-body. The deep outcome
reporting (`errors.Join` over every `ensureFabricIPVLAN` operation +
the KIND check, `daemon_ha_fabric.go:29-53,72-93,102-148`) closes
the partial/wrong-kind success paths. FOLDED.

### 3. Codex M4 + fold-3 (the QUEUED model, actually placed) — FOLDED

The v59 honest-fold failure is repaired: the QUEUED model now sits
in the §5.1 normative text (generation-tagged publications, the
per-attempt queued set, the canceled-acquisition retirement at
`daemon_apply_commit.go:172-175`, the atomic queued-to-running
transition at admission, the process-lifetime placement at
`store.go:302-319` / `daemon.go:1046-1054`), not just the revision
prose. Grep-verified present in the normative sections. FOLDED.

### 4. Codex M5 (residual (vi) withdrawn) — FOLDED

The total re-registration rule is stated at both live sites; with
every arm registered at launch, the manager's debt ledger is
complete, and the mint-boundary re-registration omits nothing.
FOLDED.

### 5. Codex m1 + m2 — FOLDED

The §5.1 changed-file inventory now carries
`daemon_apply_interfaces.go` + `daemon_ha_fabric.go`, and the
acceptance post-reactivation predicate carries the no-pending +
authority terms. FOLDED.

## B. Fresh attacks on the v60 delta

**Attack 1 (SUCCEEDED as nit m1) — the generation tag and the
seqlock version are not related.** The snapshot now carries a
seqlock version (per-publication, ordering reads) AND per-attempt
generation tags (ordering attempts), and the v60 text never says
whether they share a counter. They are necessarily distinct — an
attempt has multiple publications (QUEUED → running → terminal), so
the seqlock version must increment per publication while the
generation is per-attempt — and the contract should say so: a
publication writes (attempt-generation, fields) under the generation
guard, then bumps the seqlock version; the reader's retry is on the
version only. One clause. MINOR.

**Attack 2 (SUCCEEDED as nit m2) — the total re-registration misses
in-flight arms' completion paths.** An arm registered-and-launched
under token T carries T into its completion; the mint-boundary
re-registration adds its (T', arm-ID) entry — but the in-flight
arm's eventual completion still carries T, which the registration
rule then IGNORES as stale — leaving the re-registered entry pending
forever: a false-RED wedge (fail-closed, but permanent until the
next attempt). The retoken transaction must also RETOKEN THE LIVE
ARMS' COMPLETION PATHS (the manager retokens its outstanding work at
the transaction, so their completions publish under T'), or the
re-registered entry must accept the old token's completion for the
carried-forward arm. One clause. MINOR.

**Attack 3 (FAILED) — the actuated check flap window.** A post-check
flap is ordinary cluster operation (RG failover is a supported
runtime event); the check's job is to catch the recovery
choreography's persistent dual-primary, which it does at the
settled read. FAILED.

**Attack 4 (FAILED) — the KIND check rejects a legitimate
pre-existing overlay.** The existing-link acceptance with the kind
check fails the arm only when the kind mismatches — a
fabric-created IPVLAN matches by construction; a foreign same-name
link with the wrong kind SHOULD fail it (fail-closed). FAILED.

## C. Findings

### MAJOR (0)

None. All five r59 majors and both minors fold on independent
verification; the QUEUED model is genuinely placed this time.

### MINOR (2)

**m1.** State the two-counter relationship: the seqlock version is
per-publication (orders reads), the attempt generation is
per-attempt (orders attempts); a publication writes
(generation, fields) under the guard, then bumps the version.

**m2.** Cover the in-flight arms in the retoken transaction: the
manager retokens its outstanding work at the transaction (so
completions publish under the new token), or the carried-forward
registration accepts the old token's completion — else a
re-registered in-flight arm wedges the predicate false-red.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the two-counter
relationship and the in-flight retoken rule). A v61 containing only
these two pins is PLAN-READY by inspection from me.
