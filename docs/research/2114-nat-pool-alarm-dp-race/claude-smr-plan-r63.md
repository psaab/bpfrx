# Claude SMR hostile plan-review — round 63 (plan v63 @ `5d9ab6ebb`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r62's SMR
raised the acceptance queued-empty term (folded in v63 — IS Codex
fold-3, and the fold was verified placed this time); r63 re-verifies
the v63 folds of Codex's 3M/2m against the real code and attacks the
gate's bootstrap re-arm interleaving and the alias-retirement race.
All line numbers re-verified against the worktree.

## A. Fold verification (r62 findings → v63)

### 1. Codex M1 (augment, not replace) — FOLDED

Both terms now stand in the acceptance copy (the election-settled
term retained AND the multi-term actuated predicate), matching the
normative copy. Grep-verified. FOLDED.

### 2. Codex M2 (shutdown-only close/join API) — FOLDED

The owner/API is implementable: a named close-admission/join call in
`runShutdownSequence` ahead of the subsystem teardown
(`daemon_run_shutdown.go:214-230`), with Teardown never closing the
gate — so the bootstrap re-arm (`bootstrap.go:470-475`) retains an
open gate. The disposition is now honestly bounded to one in-flight
netlink call, and the §9 timeout-inside-mutation leg exists (h2m).
FOLDED.

### 3. Codex M3 (alias retirement) — FOLDED, with nit m1

The retirement rule — every reverse alias targeting a registration
is removed atomically when that registration completes or terminally
retires — closes the A/X→B/X→C/X false-green construction, and the
completion-races-retirement interleave is safe under the ledger
lock (either the completion wins and the retirement+alias-cleanup
follows, or the retirement wins and the completion arrives
unregistered and is ignored — both orders correct). FOLDED — but
see m1: the referenced §9 regression has no named leg.

### 4. Codex fold-3 (queued-empty actually placed) — FOLDED

Grep-verified: "no QUEUED reservation outstanding" now appears in
the normative predicate AND the acceptance predicate (and the
revision entry), with the identity ordering. The scripting-loss
repair is real this time. FOLDED.

### 5. Codex fold-2 (honest disposition + timeout leg) — FOLDED

The disposition text now bounds the overlap to one in-flight
netlink call, and the (h2m) timeout-inside-mutation leg exists.
FOLDED.

### 6. Codex fold-6 + m1 + m2 — FOLDED

The second 120s instance is corrected (grep: zero "120s round"
survivors); the §9 LINKDEL INJECTION leg exists; and the actuated
surfaces are named (`show chassis cluster data-plane statistics`
for `rgN active=`, `status_sections.go:329-335`;
`show security vrrp` for mastership, `cmd/cli/show_security.go:
601-625`) — no new renderer needed, verified against the surfaces.
FOLDED.

## B. Fresh attacks on the v63 delta

**Attack 1 (SUCCEEDED as nit m1) — the referenced arm-ID-reuse
regression has no named leg.** The v63 text references "the §9
arm-ID-reuse/stale-duplicate regression" (plan.md:6847) but §9's
legs enumerate no such case — the h2m legs cover LinkDel and
timeout-inside-mutation, and h2j/h2k/h2l cover the earlier
mechanisms, but no leg exercises a delayed duplicate completion
against a reused arm ID. One clause: the leg joins (h2l). MINOR.

**Attack 2 (FAILED) — a pre-teardown callback fires during the
re-armed epoch.** The gate never closes on Teardown, so a callback
launched pre-teardown can fire during the re-armed epoch — but its
fire-time body takes applySem and re-derives the CURRENT config's
overlays (the v58 closure), so it can only ever create the
re-armed config's own overlays. Safe by construction. FAILED.

**Attack 3 (FAILED) — the completion/retirement race.** Under the
ledger lock the two serialize; either the completion retires the
registration (aliases cleaned after) or the retirement wins and the
completion arrives unregistered and is ignored. Neither order
produces a stale alias or a lost live registration. FAILED.

**Attack 4 (FAILED) — the named actuated surfaces lie about the
loser's state.** The loser's explicit inactivity reads on the
loser's OWN surface (its `rgN active=false` plus its VRRP state),
which is exactly what the per-node read discipline checks. FAILED.

## C. Findings

### MAJOR (0)

None. All three r62 majors and both minors fold on independent
verification.

### MINOR (1)

**m1.** Name the §9 arm-ID-reuse/stale-duplicate leg (referenced at
plan.md:6847 but absent from the leg enumeration): a delayed
duplicate completion against a reused arm ID must be ignored, with
the alias cleanup verified at the retirement.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the named
arm-ID-reuse leg). A v64 containing only this pin is PLAN-READY by
inspection from me.
