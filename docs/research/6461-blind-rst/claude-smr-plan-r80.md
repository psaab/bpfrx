# Claude SMR hostile plan-review — round 80 (v9.9.54.34 @ fc5d81416)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.34 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.34-as-committed** — seven precision pins (all nit-level; no
LOW or above — the arc's first all-nit SMR round). All seven r79
Codex folds are operative; the pre-lookup intent, the RootRef +
two-copy ABI, the CLEANING state, the floor-first merge, the
ordered supersession, and the mint linearization verify against the
code citations.

## Finding 1 (nit — the lookup's generation must be captured in the transfer's critical section)

The B1 fold's intent→permit transfer has a one-level-up race: the
lookup returns the RG3 entry, and BEFORE the transfer CAS lands,
RG3's drain can observe no holder and lift. The fold must state
the coupling it implies: the returned entry's drain generation is
captured in the SAME critical section as the transfer (the
transfer validates the drain's generation against the lookup's
captured generation — a lift between lookup and transfer fails
the transfer and the packet drops), and the entry is usable only
after the transfer completes (the materialize uses the entry only
post-transfer — never between lookup and transfer).

## Finding 2 (nit — the two-copy reader rule is prefer-A, version-monotonic per reader)

The B2 fold's two copies need their deterministic reader rule:
the reader PREFERS copy A if A's checksum validates, else B; A is
always written first (the writer's order is A-then-B, so a valid
A is always the newest complete copy); and a single reader's
consecutive reads are version-MONOTONIC (B(old) → A(new) →
A(new) — never back to old once A validates), so a flow's
consecutive packets cannot oscillate between two cohort states.

## Finding 3 (nit — the progress update is written only on delete success; a persistent delete failure aborts to the latch)

The B3 fold's per-domain progress record is a lie if
`bpf_map/mod.rs:600`'s error-discarding delete fails silently.
State: the progress update is written ONLY on confirmed delete
success; a persistent delete failure (kernel-side error) holds
the CLEANING state operator-visible and retries under the
teardown-failed latch's deadline — after the latch's bound the
state escalates to operator-required (never a silent lie, never
an unbounded silent retry).

## Finding 4 (nit — the merge is one journaled unit at the receiver; the resume replays it)

The H4 fold's floor-first merge needs its crash rule: the floor
sync's application is ONE journaled unit at the receiver (the
floor-first step and the covered-Active retirements together);
a crash mid-merge resumes by REPLAYING the unit (clearing an
already-cleared record is a no-op, so the second half clears
exactly), and no new active record is admitted until the unit
completes (the pipeline's ordering holds across the resume by
construction).

## Finding 5 (nit — the cover-set enumeration is transactional with the recording; the recursion terminates by generation order)

The H5 fold's G2 cover-naming has an enumeration race: a G1.5
issued between the enumeration and G2's recording would be
silently uncovered. State: the enumeration and the recording are
ONE store CAS (G2's record plus its covered-set land atomically);
a predecessor arriving after the CAS is NOT covered by G2 (it is
newer than G2's cover-set, so it supersedes G2 in turn by the
same rule); and the recursion terminates because every record
covers only OLDER generations (a strict generation order — never
a cycle).

## Finding 6 (nit — the mint lease's safety argument is exactly-once minting, not sync completion)

The M7 fold's peer-contact lease needs its safety argument stated
plainly: the lease guarantees AT MOST ONE minter at a time (only
the holder mints); the config sync then carries the mint to the
peer; and a partition forming mid-sync leaves the peer WITHOUT
the RG (absence, never divergence — the peer's runtime has no
RG3, no fence references it, and the healing sync completes the
state). The lease's job is exactly-once minting; the sync's job
is propagation; a failed propagation is detectable and safe by
the absence argument.

## Finding 7 (nit — the GLOBAL intent registry has a per-worker deadline and dead-packet cleanup)

The B1 fold's global intent (registered at entry, transferred
after the lookup) needs its own lifecycle edge: a packet that
dies between registration and lookup completion leaves an intent
leaked in the global registry. State: the global intent carries
a per-worker deadline (a dead packet's intent is reaped by the
registering worker's own sweep — the same worker-liveness
discipline as every other leased state in this plan), and the
registry is per-worker (no cross-worker contention on the hot
path).

## Bottom line

The v9.9.54.34 fold set closes the r79 set in the prescribed
direction, and the round's overlap was again exact (Codex B3 =
AGY T1 on the CLEANING state; Codex H4 = AGY T2 on the floor-first
merge; Codex H5 = SMR F1 on the ordered supersession; Codex M7 =
SMR F4 on the mint linearization). This is the arc's first
all-nit SMR round: the remaining pins are "state the invariant
that makes the fold auditable," not new mechanism. Whether that
reads as convergence-nigh or as the next round's seven straws is
the reviewers' call — every pin above is one sentence.
