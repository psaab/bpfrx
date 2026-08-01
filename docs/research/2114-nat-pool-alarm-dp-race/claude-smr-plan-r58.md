# Claude SMR hostile plan-review — round 58 (plan v58 @ `77720748d`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r57 was
the ruling round: Codex ruled (A) with the verified M4/M5 live-state
argument, AGY ruled (B), and this reviewer ruled (B) then revised to
the hybrid on Codex's evidence. r58 re-verifies the v58 hybrid folds
against the real code and attacks the residuals' degradation
directions and the acceptance copy's consistency. All line numbers
re-verified against the worktree.

## A. Fold verification (the hybrid folds → v58)

### 1. Codex M5 (OnXSKBound stale closure) — FOLDED by construction

The hazard verifies exactly: the closure captures the installing
apply's `deferredOverlays` (`daemon_apply_interfaces.go:98-109`),
launches via `go m.OnXSKBound()` on the one-shot flag
(`maps_sync.go:451-456`), and runs outside applySem, writing fabric
IPVLAN state (`daemon_ha_fabric.go:41-54,99-148`). The v58 closure —
at fire time the callback takes `applySem` and re-derives the
deferred-overlay set from the CURRENT config, abandoning on mismatch
— removes the stale-capture mutation by construction: the closure
can only ever create the current config's overlays, and the applySem
hold means no apply can interleave between the fire-time read and
the creation. No residual window remains (the only cost is the
goroutine waiting behind an in-flight apply — bounded and harmless).
FOLDED.

### 2. Codex M4 (rollback outcome classification) — FOLDED

The branch walk (`daemon_apply_commit.go:630-708`) matches the v58
enumeration: the stale-timer return (`:645-649`) is NEUTRAL; the
nil-target bootstrap-teardown failure (`:651-683`,
`bootstrap.go:314-320,356-370`), the apply failure, and the
session-clear failure (`:697-708`) are FAILURE — the last being the
load-bearing one (stale-authorization forwarding,
`daemon_policy_invalidate.go:242-280`). Every branch publishes
through the boundary; the §9 rollback-fork legs assert a failed
rollback can never read green. FOLDED.

### 3. M1 residual (receiver rejection / dual-primary suppression) — degradation VERIFIED

The rejection leaves the peer's active TEXT different from the
authority's intent — digest-visible by definition. The one case the
digest cannot see (text matches but enforcement differs) is the
apply-health predicate's domain, not the digest's — and the
rejection never reaches the peer's apply machinery at all (the
frame is refused before apply). The bracket catches the divergence;
the re-drive's newest-wire-gen push recovers it; the post-procedure
suppression tail is correctly attributed to the pre-existing #5863
semantics and owned by the ACK follow-up. VERIFIED as a bounded
residual.

### 4. M2/M3 residuals (provider/authority publication races) — degradation VERIFIED

Both produce at worst a stale or rejected push — a peer-side text
divergence, digest-visible, re-drive-recoverable. VERIFIED.

### 5. M6 residual (debt-transfer transaction) — degradation VERIFIED

The false-green direction is closed by the per-arm-ID registration:
a completion retires only its own (token, arm-ID) registration; a
duplicate or unregistered completion is ignored; a stranded arm
stays pending — false-RED (predicate unblessed), never false-green.
VERIFIED as fail-closed.

## B. Fresh attacks on the v58 delta

**Attack 1 (SUCCEEDED as nit m1) — the acceptance copy's residual
enumeration lacks (iv)-(vi).** The v58 residuals landed in the
normative fence section (plan.md:5311-5340) and the revision entry,
but the formal acceptance copy's residual list still enumerates only
the deadline / D-kind / residual-(iii) shapes. The rounds' own
history (r43 M4, r47 m1, r48 m1, r56 M7) is that normative/acceptance
drift is always eventually flagged — fold the reference now. MINOR.

**Attack 2 (FAILED) — the callback's applySem acquisition
deadlocks.** The closure fires from the manager's status loop
(outside applySem) and takes applySem; the apply path never waits on
the callback, so no lock cycle exists. The worst case is the
goroutine parking behind a long apply — bounded, and the closure's
work is not latency-critical. FAILED.

**Attack 3 (FAILED) — the NEUTRAL classification masks a real
no-op-needed case.** The stale-timer no-op means the window already
resolved — nothing to roll back — so NEUTRAL (no outcome published
as success or failure) is the correct classification; the predicate
is not consulted against a no-op. FAILED.

**Attack 4 (FAILED) — the residual net misses a same-text
enforcement divergence.** That case (text matches, enforcement
differs) is the apply-health predicate's domain (the tri-state plus
the per-arm registration), not the digest bracket's — and the two
compose in the done predicate, which ANDs them. FAILED.

## C. Findings

### MAJOR (0)

None. The hybrid's by-construction closures verify, and each named
residual's degradation direction checks out against the code.

### MINOR (1)

**m1.** Carry residuals (iv)-(vi) into the formal acceptance copy's
residual enumeration (currently only the normative fence section
has them), so the two normative texts agree — the exact drift class
flagged in r43/r47/r48/r56.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
hybrid ruling does not change the packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the acceptance-copy
residual enumeration). A v59 containing only this pin is PLAN-READY
by inspection from me.
