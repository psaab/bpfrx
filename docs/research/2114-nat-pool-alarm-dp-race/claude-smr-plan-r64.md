# Claude SMR hostile plan-review — round 64 (plan v64 @ `6488af4ac`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r63's SMR
raised the arm-ID-reuse leg (folded in v64 — IS Codex M3's testing
half); r64 re-verifies the v64 folds of Codex's 5M/1m against the
real code and attacks the applySem-hold/drain ordering and the
epoch-reset's re-registration path. All line numbers re-verified
against the worktree.

## A. Fold verification (r63 findings → v64)

### 1. Codex M1 + M5 (daemon-scope gate, no new wait) — FOLDED

The budget proof is right: the existing sequential worst-case waits
(5s apply drain + 3s aggregator + 3s IPsec join + 2s HA clear + 5s
session-sync stop) already total at least 23s against
`TimeoutStopSec=20` (`test/incus/xpfd.service:11`), so any new
sequential wait was disallowed. The v64 answer — the callback holds
applySem through its body (it already acquires it at fire per the
v58 closure), so the EXISTING 5s apply drain
(`daemon_run_shutdown.go:50-58`) already waits for it, and the
close-admission step only flips a flag — adds no wait. The
daemon-scope ownership answers the `d.dp`-cleared stranding
(`daemon_run_naming.go:230-235`). FOLDED.

### 2. Codex M2 (manager-epoch discipline) — FOLDED

Both halves verify as necessary: the reset alone (Teardown clears
`xskBoundNotified` + `OnXSKBound`, `manager.go:421-433,478-482`)
lets epoch B re-register on its re-armed apply
(`daemon_apply_interfaces.go:98-109` — SetOnXSKBound runs in the
interfaces step when deferred overlays exist), but a callback
launched pre-Teardown could still fire post-Teardown if the
bootstrap Teardown does not drain applySem — which is exactly what
the lifecycle-generation guard covers (a fire in a later manager
epoch abandons on the mismatch). The two halves compose; neither
alone suffices. FOLDED.

### 3. Codex M3 (alias purge on every retirement path) — FOLDED

The neutral/cancellation exits (`manager_worker_arm_5134.go:42-54`)
now invoke the purge, and the (h2n) ARM-ID-REUSE leg exists (a
delayed duplicate completion against a reused arm ID is ignored,
with the purge verified at every retirement path). FOLDED.

### 4. Codex M4 (queued-empty in the remaining copies) — FOLDED

Grep-verified: the term now stands in the §5.1 convergence
definition, both post-reactivation summaries, and the rendering
inventory. FOLDED.

### 5. Codex m1 (bounded wording) — FOLDED

The absolute claim now reads as the bounded form (waits up to the
five-second bound; may overlap ONE already-entered mutation).
FOLDED.

## B. Fresh attacks on the v64 delta

**Attack 1 (FAILED) — the callback/drain ordering.** The callback
acquires applySem, then checks the fence. If it acquires before the
drain publishes `stopping`, its work completes and the drain waits
for its release (bounded netlink body) — no overlap. If it acquires
after the publication, the fence reads stopping and it abandons.
If the publication lands between its acquire and its check, the
check sees stopping and it abandons. Every order is safe. FAILED.

**Attack 2 (FAILED) — epoch B never re-registers.** The re-armed
epoch's boot apply runs the interfaces step, which calls
SetOnXSKBound when deferred overlays exist
(`daemon_apply_interfaces.go:98-109`); after a Teardown the XSK is
down, so the re-arm rebinds, the one-shot fires, and the freshly
registered callback runs. When no deferred overlays exist, no
callback is needed. FAILED.

**Attack 3 (FAILED) — the reset racing an in-flight callback at
Teardown.** The callback holds applySem; the bootstrap Teardown
follows the drain, which waits for applySem holders; so the
callback completes before the Teardown's reset runs, and the
generation guard covers any post-Teardown fire. FAILED.

**Attack 4 (FAILED) — the generation guard rejects a legitimate
same-epoch fire.** The guard compares the callback's captured
manager epoch to the current one; a same-epoch fire matches and
proceeds. FAILED.

## C. Findings

### MAJOR (0)

None. All five r63 majors and the minor fold on independent
verification; the budget proof and the epoch discipline both hold.

### MINOR (0)

None. The v64 delta is tight: the folds are placed (grep-verified),
the wordings are bounded, and the referenced legs exist.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR — four documented fresh attacks
all FAILED on code evidence; the fold verification is independent,
not a rubber stamp: each fold was re-derived from the cited code,
and the two strongest attacks against the v64 delta — the
callback/drain ordering and the epoch-reset re-registration — were
walked to their safe orderings).
