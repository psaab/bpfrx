# Claude SMR hostile plan-review — round 46 (plan v46 @ `f379489f8`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r45's SMR
raised the gate-atomicity and withdrawal-consistency nits (both folded
in v46 — the atomicity gap was independently Codex M1 + AGY M1); r46
re-verifies the v46 folds of Codex's 5M/4m against the real code and
attacks the two new mechanisms the folds introduced (the critical
section and the monotonic-epoch witness). All line numbers re-verified
against the worktree.

## A. Fold verification (r45 findings → v46)

### 1. Codex M1 + AGY M1 + SMR m1 (gate serialization) — FOLDED

The interleaving enumeration now closes: with check+reserve+enqueue
as ONE critical section serialized against Stop's dead-publication
and drain (the drain holding the same exclusion), a reader either
observes dead atomically (drop, no token) or completes its
check+reserve+enqueue before the drain's exclusion begins (the drain
retires the buffered token). The preempted-between-observe-and-send
reader of r45 cannot exist: the observe and the send are inside the
same section. The §9 seam moves to after the live
observation/reservation, which is the only placement that exercises
the race. FOLDED.

### 2. Codex M2 (sticky epoch witness) — FOLDED, with nit m1

The level-vs-sticky gap is real (a clean dispatch-apply-retire pulse
returns the level to zero), and the v46 answer — (3) also compares
the monotonic epoch against the (2c) observation — is the right
shape: `lastAppliedConfigGen` advances only on a SUCCESSFUL apply
(`recordAppliedConfigGen` gated on `OnConfigReceived` returning nil,
`sync_conn_config.go:280-288,345-360`), so it is the exact witness
for the pulse Codex described, and `ConfigsReceived` is the
conservative one (moves at receipt, `sync_conn_read.go:298-324`).
FOLDED — but see m1: both quantities are PROVIDER-SCOPED
(`SessionSync` fields), and the plan just pinned the counter
node-lifetime without saying the same for the epoch.

### 3. Codex M3 (residual wording) — FOLDED

Both copies now read "whose APPLY lands between the preflight and the
stop, REGARDLESS of when the frame was received" with the
`sync_conn_read.go:84-93` / `sync_auth.go:352-369` citations.
Grep-verified: normative and acceptance agree. FOLDED.

### 4. Codex M4 (ActiveApplied in the done predicate) — FOLDED

`ActiveApplied()` is false exactly in the promote→apply-failed
window (`store.go:797-809` — nil active or empty/mismatched
`appliedDigest`), which is the state every persistence field misses.
Both done predicates now require it on both nodes. FOLDED.

### 5. Codex M5 (executable disabled-sync recovery) — FOLDED

Verified the surfaces: no unconditional operator push exists
(`syncConfigToPeer` gates on authority, `pushConfigToPeer` gates on
ConfigSync, `daemon_ha_sync.go:336-370`); `SetClusterReadOnly`
rejects mutations on the secondary (`store.go:344-354`); `load
override`/`load merge` are real config-mode CLI commands
(`cli_config.go:160-170`); and the cleartext Show* SSOT backs the DR
archive (`grpcapi/server_config.go:349-352`,
`config/ast_redact.go:185`). The v46 procedure — capture the complete
unredacted artifact off-node before the fence; authority-side
load+commit — is operator-executable with existing commands. FOLDED.

### 6-9. Codex m1-m4 — FOLDED

The surviving instantaneous-join claims are scoped (grep-verified:
the counter is now "a true join OVER DISPATCHED FRAMES"; both
"gap-free" sites are qualified; the witness is REGISTERED-reader
scoped). The post-(3) closure wording no longer claims next-boot
reclassification. The digest's executable surface is pinned onto the
cluster-status RPC with the untouched-scoping amended. The test
inventory is the complete 17 sends (my own grep confirms exactly
these 17 `configApplyCh <-` sites across the three files). FOLDED.

## B. Fresh attacks on the v46 delta

**Attack 1 (SUCCEEDED as nit m1) — the epoch witness is
provider-scoped while the counter is node-lifetime.** The v46 text
pins the counter in node-lifetime state but names
`lastAppliedConfigGen` / `ConfigsReceived` — both `SessionSync`
fields — as the (3) witness without pinning THEIR lifetime. A
transport-changing apply mid-fence (the `daemon_apply_tail.go:
238-255` comms restart) replaces the provider and the fresh
provider's epoch reads seed/zero: the (3) comparison then
false-positives (conservative — the operator re-baselines, safe) —
but the plan should not rely on the operator noticing a reset: pin
the epoch witness as exposed from NODE-LIFETIME state alongside the
counter (a comms restart must not reset it), exactly as the counter
is pinned. MINOR.

**Attack 2 (FAILED) — the critical section deadlocks.** The pinned
section is leaf: a flag read, an atomic Add, and a non-blocking
channel send — no nested `s.mu` acquisition (Go mutexes are not
reentrant, and the section takes none), no blocking call.
`s.mu` holders (`handleDisconnect`, `installConn`, `Stats`) wait
briefly; no lock ordering cycle exists because the section acquires
nothing while held. FAILED.

**Attack 3 (FAILED) — the epoch false-positive wedges the fence.**
`ConfigsReceived` moves on stale-skipped and queue-full-dropped
receipts (no state change), so (3) can fail without any apply — but
the peer is stopped at (2b), no new frames arrive, the value
settles, and the operator's re-read converges. Conservative, never
wedging; and `lastAppliedConfigGen` — the precise witness — moves
only on clean applies. FAILED.

**Attack 4 (FAILED) — the pendingFrame vs the dead gate.** A
legacy/unkeyed peer's pending frame dispatches through
`handleMessage` → the same gated check+reserve+enqueue; a post-Stop
dispatch observes dead and drops. No bypass. FAILED.

**Attack 5 (FAILED) — drain/defer double-retirement.** An item
buffered when the drain runs is retired by the drain and never
reaches the (already exited) consumer; an item dequeued before the
cancel is retired by the consumer's defer. Mutually exclusive per
token. FAILED.

## C. Findings

### MAJOR (0)

None. All nine r45 findings fold on independent verification; the
composition — gated critical-section counter, registered-reader
witness, sticky epoch comparison, honestly-worded residuals, and the
full done predicate — now states exactly what it guarantees.

### MINOR (1)

**m1.** Pin the epoch witness's lifetime: the monotonic config-sync
epoch used at (3) is exposed from NODE-LIFETIME state alongside the
counter (a comms restart / provider replacement must not reset it) —
the named quantities today are `SessionSync` fields, and a mid-fence
transport-changing apply would reset them under the fence.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the epoch-witness
lifetime pin). A v47 containing only this pin is PLAN-READY by
inspection from me.
