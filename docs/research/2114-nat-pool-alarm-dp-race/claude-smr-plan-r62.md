# Claude SMR hostile plan-review — round 62 (plan v62 @ `fbe9369a8`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r61's SMR
raised the alias-collapse pin (folded in v62 — IS Codex M4); r62
re-verifies the v62 folds of Codex's 5M/3m against the real code and
attacks the admission gate's two-lock shape and the per-node actuated
read surfaces. All line numbers re-verified against the worktree.

## A. Fold verification (r61 findings → v62)

### 1. Codex M1 (acceptance carries the actuated predicate) — FOLDED

The acceptance copy now carries the multi-term actuated predicate
(exactly one rg_active, exactly one VRRP MASTER where applicable,
both on the intended node, the loser explicitly inactive, read
per-node) — the two copies agree. FOLDED.

### 2. Codex M2 (admission gate + join disposition) — FOLDED

The gate closes the Add-races-Wait construction: the gate check,
the registration, and the launch form one section taken as `m.mu`
THEN ledger lock (the canonical nesting from the M5 fold), so the
shutdown's close (taking the ledger lock) cannot interleave mid-
section; and the close FIRST, join SECOND ordering means no
callback can launch after the close. The 5s disposition is honest:
a callback past the join abandons at each per-mutation fence check,
bounding the overlap to one in-flight netlink call. FOLDED.

### 3. Codex M3 (queued-empty term + identity ordering) — FOLDED, with nit m1

The inheritance rule (the admission token inherits its
reservation's position) gives a total order across both namespaces:
the reservation sequence is the canonical order, and every
publication's precedence is well-defined. FOLDED — but see m1: the
acceptance copy's predicate lacks the queued-empty term.

### 4. Codex M4 (alias collapse) — FOLDED

The collapse-at-supersession rule (every outstanding alias
rewritten to the new current token) resolves any older token in one
step and bounds the map (aliases retire with their registrations;
retry debt's indefinite liveness,
`manager_worker_arm_5134.go:38-96`, accumulates nothing). FOLDED.

### 5. Codex M5 (canonical nesting) — FOLDED

The `m.mu` THEN ledger-lock section for decision+flag+registration+
launch matches the existing call paths (the decision state is
`m.mu`-held today, `maps_sync.go:353,451-456`; the debt mutations
move to the briefly-taken ledger lock); the reverse nesting is
forbidden and the ledger lock never crosses IPC
(`process_control.go:31-56,85-103,129-142`). No path takes them in
the reverse order today. FOLDED.

### 6. Codex m1/m2/m3 — FOLDED

`LinkDel` joins the aggregation (`daemon_ha_fabric.go:52-53`) and
the inventory summary now reads type+mode; the §9 HA-clear-debt
legs exist; the deadline evidence reads 3s small-request / ~67s
max-snapshot (`process_control.go:31-56,85-103,129-142`). FOLDED.

## B. Fresh attacks on the v62 delta

**Attack 1 (SUCCEEDED as nit m1) — the acceptance predicate lacks
the queued-empty term.** The v62 "no QUEUED reservation
outstanding" term landed in the normative predicate
(plan.md:5491-5496) and the revision entry, but the acceptance
copy's predicate (plan.md:8344-8349) still reads failure-count ==
0 AND no-pending AND last-outcome-success without the queued set —
the normative/acceptance drift class again. One clause. MINOR.

**Attack 2 (FAILED) — a launch slips between the gate check and the
registration.** The gate check, registration, and launch are one
section under (`m.mu`, ledger lock) per the M5 nesting rule; the
shutdown's close takes the ledger lock and cannot interleave.
FAILED.

**Attack 3 (FAILED) — the per-node actuated surfaces don't exist.**
They do: the userspace status sections render `rg<ID>
active=<bool>` (`format/status_sections.go:329-335`, via
`server_show_cluster_text.go:138-147`) and the VRRP instance state
is exposed via `show security vrrp` (`server_nat.go:341-367`,
`cmd/cli/show_security.go:601-625`) — each read per-node on each
node's own localhost. FAILED.

**Attack 4 (FAILED) — the admission gate's own teardown ordering.**
The shutdown closes the gate before joining; a launch racing the
close either reserves before it (and is joined) or sees the closed
gate (and never launches). The section's atomicity makes the
interleave impossible. FAILED.

## C. Findings

### MAJOR (0)

None. All five r61 majors and all three minors fold on independent
verification.

### MINOR (1)

**m1.** Carry the queued-empty term into the acceptance copy's
predicate (plan.md:8344-8349) — the normative copy has it
(plan.md:5491-5496); the acceptance copy reads failure-count == 0
AND no-pending AND last-outcome-success without it.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the acceptance
queued-empty term). A v63 containing only this pin is PLAN-READY by
inspection from me.
