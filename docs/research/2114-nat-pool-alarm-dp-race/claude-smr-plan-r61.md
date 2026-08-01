# Claude SMR hostile plan-review — round 61 (plan v61 @ `d79c01d40`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r60's SMR
raised the two-counter relationship and the in-flight retoken rule
(folded in v61 — IS parts of Codex M3 and M5); r61 re-verifies the
v61 folds of Codex's 7M/4m against the real code and attacks the
queued-entry migration chain and the alias walk depth. All line
numbers re-verified against the worktree.

## A. Fold verification (r60 findings → v61)

### 1. Codex M1 + AGY M1 (multi-term actuated predicate, per-node reads) — FOLDED

The topology point verifies (RG0 has no VRRP instance,
`vrrp/manager.go:929-936`, `vrrp.go:128-142,170-173`), as does the
ACTIVE+BACKUP-loser construction (demotion resigns VRRP before
clearing rg_active, `rg_state.go:250-263`,
`daemon_ha.go:340-371,809-848`). The v61 predicate — exactly one
rg_active, exactly one VRRP MASTER where applicable, both on the
intended node, the loser explicitly inactive — closes the
conjunction hole, and the per-node reads work with the runbook's
existing practice (the peer's state is read via the peer's own
localhost status per the r42 fold; each node's own surface exposes
its rg_active and VRRP mastership). FOLDED.

### 2. Codex M2 (teardown-serialized callback lease) — FOLDED

The join-set membership is implementable: the callback registers in
a WaitGroup at fire and Done at exit, and the shutdown's join waits
for it before the dataplane teardown; the callback's body is
bounded netlink work and the 5s bound remains the safety net —
consistent with the existing drain discipline
(`daemon_run_shutdown.go:50-64,214-230`). FOLDED.

### 3. Codex M3 + M4 + AGY M3/m1 (three identities + fieldwise merge) — FOLDED

The impossibility is resolved: the enqueue-reservation sequence
tags the pre-admission QUEUED publication; the admission token
mints at admission with the queued entry migrating atomically; the
seqlock version is the third counter (per-publication, both sides).
The fieldwise merge — the failure count accumulates regardless of
generation; the per-attempt fields are generation-guarded — covers
every field of the predicate's state (the count, lastOK, the
queued set, the pending set). FOLDED.

### 4. Codex M5 + AGY M2 + SMR m2 (completion alias) — FOLDED, with nit m1

The alias closes the single-supersession identity mismatch.
FOLDED — but see m1: the multi-supersession alias walk is not
pinned.

### 5. Codex M6 (debt-ledger lock) — FOLDED

The separation is implementable: the debt state the status loop
mutates (`pendingWorkerArm` et al.) moves under the ledger lock,
taken briefly and never across IPC; the 120s `requestLocked` stays
under `m.mu` alone; the lock order (applySem → ledger lock, `m.mu`
never nested with the ledger lock) is consistent with every existing
call path. FOLDED.

### 6. Codex M7 (type+mode check) — FOLDED

The L2-mode requirement verifies (`daemon_ha_fabric.go:56-62`), and
the v61 rule validates type AND mode and replaces a mismatched
existing link. FOLDED.

### 7. Codex m1-m4 — FOLDED

The `pendingHAStateClear` debt joins the arm inventory
(`manager.go:227-236`, `manager_ha.go:98-151`); the §9 callback
legs now cover the early fence, the teardown join, and the
per-operation aggregation; the acceptance residual reference reads
(iv)-(v) with the (vi) withdrawal; and the §5.1 inventory gains
`daemon_apply.go` for the QUEUED wrappers. FOLDED.

## B. Fresh attacks on the v61 delta

**Attack 1 (SUCCEEDED as nit m1) — the alias walk across successive
supersessions.** A completion for token A arriving after A→B and
B→C supersessions must resolve through two aliases; the v61 text
records the alias pair but never says whether the map walks or
collapses. One clause: at each supersession the alias map is
REWRITTEN so every outstanding alias points at the NEW current
token (collapse-at-supersession), keeping the resolution depth at
one. MINOR.

**Attack 2 (FAILED) — a canceled waiter's migration tombstone.** A
canceled waiter never admits, so no migration occurs; its queued
entry retires at cancellation per the (iii) rule; nothing migrates
or tombstones. FAILED.

**Attack 3 (FAILED) — two waiters migrating out of order.** The
semaphore admits one at a time, in wait order; each migration is
atomic at its admission; the queue order is the admission order.
FAILED.

**Attack 4 (FAILED) — the ledger lock vs the status loop's own
ordering.** The status loop takes the ledger lock only for debt
mutations, briefly, and never while holding `m.mu` across IPC — the
two locks never nest, so no ordering cycle exists. FAILED.

## C. Findings

### MAJOR (0)

None. All seven r60 majors and all four minors fold on independent
verification.

### MINOR (1)

**m1.** Pin collapse-at-supersession for the alias map: at each
mint-boundary supersession, every outstanding alias is rewritten to
point at the NEW current token, so a completion carrying any older
token resolves in one step regardless of how many supersessions
intervened.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the alias-collapse
pin). A v62 containing only this pin is PLAN-READY by inspection
from me.
