# Claude SMR hostile plan-review — round 48 (plan v48 @ `3b1b98330`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r47's SMR
raised the capture-ordering and encrypted-fallback nits (both folded in
v48 — IS Codex M3 + M5); r48 re-verifies the v48 folds of Codex's
5M/2m against the real code and attacks the two new mechanisms the
folds introduced (the never-rollback epoch and the automation
quiesce). All line numbers re-verified against the worktree.

## A. Fold verification (r47 findings → v48)

### 1. Codex M1 (epoch publication) — FOLDED

The race was real: a post-send epoch increment can publish after a
fast consumer applies and retires, and (3) would read the stale epoch
with a zero counter. The v48 rule — the epoch advances WITH the
provisional pre-enqueue reservation, inside the same critical
section, BEFORE the send becomes receivable, and never rolls back —
closes it by construction: at any (3) read, every completed
reservation has already moved the epoch. The never-rollback
arithmetic cannot wedge the drain: a nil/full attempt moves only the
epoch (a conservative false-positive the re-baseline rule covers —
the stopped peer lets the epoch settle), never the counter. Leg (f)
now asserts the epoch's visibility at the seam. FOLDED.

### 2. Codex M2 (rebuttal withdrawn + apply-failure term) — FOLDED

The counterexample verifies exactly: `onDHCPAddressChange` re-enters
`applyConfig` on the same text (`daemon_dhcp.go:73-90`) to build
address-scoped host-inbound enforcement for the new address
(`daemon_dhcp.go:231-245`); an nft failure retains the prior kernel
generation (`daemon_nft.go:262-272`); the early return skips
`MarkActiveApplied` without touching the old digest
(`daemon_apply.go:56-70`) — H(T) still matches while the new address
lacks enforcement. The v48 term — no dataplane apply failure since
the post-restart bringup on either node, tracked in the daemon's
health state and rendered beside ActiveApplied — closes it; the
counter is process-lifetime, so the predicate is count==0 at
done-time and needs no baseline capture. FOLDED.

### 3. Codex M3 (capture ordering) — FOLDED

The stale-capture construction was verified in r47
(`store_commit.go:427-461,503-524`; `store_persist.go:21-55`). The
v48 (1a)/(1b) placement — quiesce automation, THEN capture, AFTER
the window resolution and the moratorium — is present in both the
normative runbook and the acceptance copy (grep-verified they agree),
with the re-capture rule for any commit that lands anyway. FOLDED.

### 4. Codex M4 (automation moratorium) — FOLDED, with nit m1

The autonomous-commit path is exactly as Codex described
(`engine.go:920-948` → `commitAndApply`,
`daemon_apply_tail.go:446-455`, no peer sync), and deactivation is
effective immediately: the deactivate commit's apply calls
`Engine.Apply` with the emptied policy list (`engine.go:393-405`,
wired at `daemon_apply_tail.go:478`), and an in-flight event
serializes under `applySem` — so after the quiesce commit completes,
no autonomous commit can fire. My grep found no other autonomous
commit source (rpm feeds the engine; feeds/ip-monitoring/dhcpserver
do not commit). FOLDED — but see m1: the runbook never re-activates
the automation.

### 5. Codex M5 (encrypted fallback origin-node pin) — FOLDED

The key derivation is per-node (`crypto.go:457-480` — independently
random at creation), the destination's Load AEAD-authenticates with
its OWN key (`crypto.go:307-356,443-455`), so an encrypted body
fails closed on a different authority. Both copies now pin the
file-level restore to the origin node in the encrypted case, with
the cleartext-body file portable and the operator's text primary.
The origin-node restore keeps the origin's key and the committed
marker (`db.go:105-130`). FOLDED.

### 6. Codex m1 (preflight proof boundary) — FOLDED

Residual (iii)'s window now runs from the FIRST sub-read in both
copies; the post-restart closure is the named handler. FOLDED.

### 7. Codex m2 (opaque-artifact wording) — FOLDED

Both copies name the magic-header framing + possibly-encrypted JSON
body (`envelope.go:78-99`, `db.go:445-450`) and the byte-for-byte
preservation. FOLDED.

## B. Fresh attacks on the v48 delta

**Attack 1 (SUCCEEDED as nit m1) — the automation is never
re-activated.** The v48 quiesce deactivates `event-options` before
the capture, and the post-restart verification compares against the
captured POST-DEACTIVATE digest — so the whole predicate can pass
with the box's event-options automation silently OFF. The runbook's
final step must re-activate event-options (a normal commit AFTER the
verification passes) and re-verify the digest against the
re-activated intent — otherwise the fence's side effect becomes the
running state. One clause. MINOR.

**Attack 2 (FAILED) — the deactivate commit perturbs the fence.** It
lands BEFORE the moratorium and the capture; its peer sync (when
enabled) applies at the peer and raises any debt SYNCHRONOUSLY,
visible at the peer's (2a) preflight; the captured digest correctly
describes the post-quiesce intent. FAILED.

**Attack 3 (FAILED) — an in-flight event during the
deactivate-apply.** The engine's remediation and the deactivate
commit both serialize under `applySem`
(`daemon_apply_tail.go:446-455`); whichever lands second sees the
other's result, and after the quiesce commit completes the policy
list is empty (`engine.go:393-405`). FAILED.

**Attack 4 (FAILED) — the epoch false-positive wedges the drain.** A
nil/full attempt moves the epoch without the counter; the peer is
stopped so no new attempts arrive; the epoch settles; the
re-baseline-and-repeat pass converges. FAILED.

**Attack 5 (FAILED) — the origin-node restore resurrects a superseded
record.** The restore copies the origin's `active.json` — the ACTIVE
config, not a confirm record; the confirm-record machinery
(confirm.json and its debts) is untouched by the file copy, and the
post-restart predicate re-checks the full state. FAILED.

## C. Findings

### MAJOR (0)

None. All seven r47 findings fold on independent verification; the
fence is now a publication-ordered counter+epoch pair, an ordered
capture, an automation moratorium, and an honestly-scoped fallback.

### MINOR (1)

**m1.** Name the re-activation step: after the post-restart
verification passes, the operator re-activates `event-options` (a
normal commit) and re-verifies the digest against the re-activated
intent — otherwise the fence's quiesce side effect becomes the
running state and the box's automation is silently off.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the re-activation
step). A v49 containing only this pin is PLAN-READY by inspection
from me.
