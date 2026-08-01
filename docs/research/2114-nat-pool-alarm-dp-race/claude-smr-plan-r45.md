# Claude SMR hostile plan-review — round 45 (plan v45 @ `e10902e5c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r44's SMR
returned PLAN-READY with five documented failed attacks; Codex r44
then found 5M/2m — including the verified-undispatched window my
attack-1 had judged covered-by-composition (Codex was right that the
CLAIM was false even where the COMPOSITION is safe; the v45 withdrawal
is the honest fix). r45 re-verifies the v45 folds of Codex's 5M/2m
against the real code and attacks the v45 delta — including the new
session-dead gate's own ordering. All line numbers re-verified against
the worktree.

## A. Fold verification (r44 findings → v45)

### 1. Codex M1 (session-liveness gate) — FOLDED, with nit m1

The leak is real as stated: Stop returns past the 5s cap
(`sync_conn.go:349-385`) with the consumer gone
(`sync_conn_config.go:325-330`); a surviving reader's reserve+send
into the still-open queue (`sync.go:847-857`) creates an unretirable
token. The v45 gate (session-dead flag published at Stop START, before
the drain; a dispatch observing it drops without reserving) closes the
steady-state case — but see m1: the check+reserve is not pinned
ATOMIC against the drain, and a reservation already in flight when the
flag publishes can still enqueue after the drain.

### 2. Codex M2 (instantaneous-join withdrawal) — FOLDED, with nit m2

All three verified-undispatched windows re-verified: the
verify-to-dispatch pause (`sync_conn_read.go:84-93`), the handshake
`pendingFrame` (`sync_auth.go:352-369`), and the writer-failure
Down-publication with a runnable reader (`sync_conn_config.go:234-248`
→ `handleDisconnect`, `sync_conn.go:480-497`). The v45 composition
claim — (2c) drains, (3) re-reads the counter, post-(3) is residual
(iii) — is the honest statement of where the fence's safety lives.
FOLDED — but see m2: two surviving sentences still claim the
instantaneous property the withdrawal just abandoned.

### 3. Codex M3 (disabled-sync subclass) — FOLDED

Verified: `ConfigSync` is set true only when the
`configuration-synchronize` child exists (`compiler_system.go:
1872-1874`), default false (`types_chassis.go:113`); the reconciler
skips on `!cfg.Chassis.Cluster.ConfigSync` (`daemon_ha_sync.go:
461-465`). The preemption-then-disabled interleaving leaves neither
side pushing, exactly as Codex described; the v45 text names it and
pins detection (the intended-config comparison) plus the manual
re-convergence action. FOLDED.

### 4. Codex M4 (durability sync pins every affected node) — FOLDED

The post-rename barrier is the resolved target's parent-directory
fsync (`fsatomic.go:354-366`); residual (iii)'s failure can be the
peer's; the peer's restart can load the visible content and have
equality suppress the rewrite (`daemon_apply.go:49-70`,
`daemon_ha_sync.go:550-568`). The v45 text requires the directory
sync on BOTH nodes before EITHER restart. FOLDED.

### 5. Codex M5 (done predicate is the full aggregate) — FOLDED

`ConfigPersistDegraded()` today aggregates `persistDegraded ||
confirmRemoveDegraded` (`store_persist.go:342-352`), and the plan's
x14 work extends the aggregate over the mask, ConfirmRecordState, and
ConfigWriteUnverified; a restart-time push can promote+apply while its
write fails (`store.go:687-689,738-769`). The v45 predicate — the
aggregate clean on BOTH nodes — subsumes the previously named fields.
FOLDED.

### 6. Codex m1 (off-node digest) — FOLDED

Redaction verified on both surfaces (`grpcapi/server_config.go:
347-356`, `api/config.go:304-312` — secrets masked on every raw-AST
render). The v45 capture-before-fence canonical digest sidesteps the
redaction class entirely. FOLDED.

### 7. Codex m2 (direct-injection tests) — FOLDED

Verified `sync_config_gen_test.go:226-237` enqueues
`configApplyItem{gen: 2, ...}` directly (and :256-267 likewise), as
does `sync_config_epoch_sweep_race_6284_test.go:104-108`; an
unconditional dequeue defer would underflow. The v45 inventory pins
the migration. I grepped for other direct sends — these are the only
`configApplyCh <-` sites outside the production dispatch path. FOLDED.

## B. Fresh attacks on the v45 delta

**Attack 1 (SUCCEEDED as nit m1) — the gate's check+reserve is not
atomic against the drain.** Constructed interleaving: a reader
observes the flag LIVE, reserves, and is descheduled; Stop publishes
dead and runs the one-shot drain (nothing buffered — the reservation
exists but the item is not yet enqueued); the reader wakes and its
non-blocking send SUCCEEDS into the still-open queue; no consumer
remains and the drain already ran — the node-lifetime counter leaks
+1 and a later (2c) drain can hang. The design intent is right; the
plan must pin that the liveness check and the reservation are ONE
atomic step (a single critical section or a sealed state word) and
that the teardown drain runs under the SAME exclusion — so a token is
either never created (dead observed atomically) or always drained
(created before the drain's exclusion began). MINOR.

**Attack 2 (SUCCEEDED as nit m2) — surviving instantaneous-join
claims contradict the withdrawal.** `plan.md:3967-3968` still says
"`outstanding == 0` is a true join with no false-idle window", and
`plan.md:4005-4008` still calls the counter "the all-ingress join
covering pre-install, superseded, and post-cap readers" — both
unscoped, both written before the r44-M2 withdrawal that sits a
screenful earlier. The honest scope: the counter is a true join OVER
DISPATCHED FRAMES (no false-idle within that domain); the
verified-undispatched residual is handled by the composition
((2c)+(3)+residual (iii)), not by the counter alone. One-sentence
scoping fix at both sites. MINOR.

**Attack 3 (FAILED) — the (2a) preflight's counter read after the
withdrawal.** The preflight is a cleanliness GATE, not a join: a peer
counter read of zero that precedes a late peer-side dispatch lands in
residual (iii)'s (2a)-(2b) window — already admitted and bounded. The
withdrawal removes a claim, not a protection. FAILED.

**Attack 4 (FAILED) — the re-push after a gated drop.** A dispatch
dropped by the session-dead gate is on a DEAD session; the peer's
next push after comms restart arrives on the NEW session and reserves
freshly through the same path. No double-count, no loss (the drop
alarms). FAILED.

**Attack 5 (FAILED) — the (3)-re-check TOCTOU against the gate.** A
dispatch racing (3)'s read either reserved before the read (the read
sees >0) or after (residual (iii)'s admitted post-(3) window). The
gate does not change the live-session arithmetic. FAILED.

## C. Findings

### MAJOR (0)

None. All seven r44 findings fold on independent verification; the
fence is now honestly stated as a composition with a gated,
reservation-ordered, node-lifetime counter.

### MINOR (2)

**m1.** Pin the liveness check + reservation as ONE atomic step
(single critical section or sealed state word) with the teardown
drain under the same exclusion — a reservation in flight across the
flag publication can otherwise enqueue after the drain and leak the
token the gate exists to prevent.

**m2.** Scope the two surviving instantaneous-join claims
(`plan.md:3967-3968`, `plan.md:4005-4008`) to DISPATCHED frames —
the counter is a true join over dispatched frames; the
verified-undispatched residual is handled by the composition — so
the doc stops contradicting the r44-M2 withdrawal it carries.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the gate-atomicity pin
and the withdrawal-consistency scoping). A v46 containing only these
two pins is PLAN-READY by inspection from me.
