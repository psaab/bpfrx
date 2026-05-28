# Claude SMR plan-review r3 — #1614 v5

Reviewer: Claude (SMR — network scheduling / shaper semantics / AF_XDP
queue physics / CPU microarchitecture / Junos CoS contract).

Target: plan v5 SHA `f742b3ff3`.

Method: hostile-verify against my r1 (F1+F2+F3) + r2 (F4 + S8 + S9 +
S10) findings, plus Codex r2 + AGY r2 findings, plus the new Phase 0
empirical evidence (reverse-simul 22.72 G PASSED, generator CPU
20-58% idle).

Verdict: **PLAN-READY**.

## Findings disposition

### F1 (r1) — Scheduler reading was wrong as framed

v3+ adopted the convergent SMR/AGY/Codex math-walked reading of
rate-proportional via per-visit quantum. v5 §3 carries the correct
mechanism description AND quotes the actual constants
(`COS_GUARANTEE_VISIT_NS = 200_000`, `COS_GUARANTEE_QUANTUM_MAX_BYTES
= 512 KB`) with the corrected `Sum of quantums = 2626.5 KB`.

CLOSED.

### F2 (r1) — R8 generator-bottleneck risk

Phase 0 empirically PASSED on 2026-05-27. Reverse aggregate 22.72 G
received with all 11 classes simultaneous; generator CPU 20-58%
idle. The firewall is empirically confirmed the bottleneck, the
plan's §1 problem statement is grounded, and v5's §4 Phase 0
header now reflects the PASSED state.

CLOSED with evidence.

### F3 (r1) — ECN-WRED 75-100% was a REGRESSION

v3+ replaced with CoDel-style sojourn-time AQM. v5 §4 A3 documents
the RTT-aware tuning rule (`max(5ms, 1.5 × RTT)`) and reframes A3
as an experimental gate with smoke-driven three-way disposition
(meet / partial-gain / revert). This is the right disposition for
a first-deployment AQM mechanism.

CLOSED.

### F4 (r2) — v3 algorithm internally inconsistent

v4 + v5 specified the clean two-phase waterfill with explicit
unhonored set + Phase 2 over unhonored-only. v5 ADDED the explicit
early-return for proportional mode / fraction=0 per AGY r2 #1.

CLOSED.

### S8 (r2) — Phase 0 sequencing as separate gate

v4 + v5 §4 header has the Phase 0 BLOCKING note. v5 updates the
status to PASSED.

CLOSED.

### S9 (r2) — Rename to match Junos doc

v4 renamed `strict-exact` → `guarantee-rate`. AGY r2 §A confirmed
the renamed knob walks coherently at 0.0 / 0.4 / 0.7 / 1.0.

CLOSED.

### S10 (r2) — CoDel target vs per-queue tuning

v4 introduced per-queue `codel-target` knob. v5 ADDED the
RTT-aware tuning rule + experimental-gate disposition.

CLOSED.

## v5 closure of Codex r2 + AGY r2 findings

| Reviewer | Finding | Closure in v5 |
|----------|---------|---------------|
| AGY r2 #1 | Proportional mode divergence | §4 A1.1 explicit early-return branch |
| AGY r2 #2 | Priority-low min-share coupling | §4 A2 cap_eff subtraction before A1 |
| AGY r2 #3 | CoDel 5ms ≤ RTT collision | §4 A3 RTT-aware tuning rule + experimental gate |
| Codex r2 #2 | fraction=0.0 not bit-for-bit | Same as AGY r2 #1 (converged) |
| Codex r2 #3 | CoDel claim unproven | §4 A3 reframed as experimental gate |
| Codex r2 #4 | §3 quantum sum arithmetic | §3 corrected to 2626.5 KB |
| Codex r2 (priority-low aside) | Coupling | Same as AGY r2 #2 (converged) |

All findings closed.

## New findings (hostile-verify against v5)

None. The plan is internally consistent. The trade-offs are
operator-visible (`guarantee-rate <fraction>` opt-in;
`codel-target 0` disables CoDel). The default behavior is
bit-for-bit current scheduler. The wire-protocol both-sides
paths are verified (AGY r2).

## Net empirical grounding

- Phase 0 PASSED: firewall is bottleneck.
- All convergent reviewer findings (3 reviewers × 2-3 rounds
  each) closed in v5.
- Algorithm walks reproducible at fractions 0.0, 0.4, 0.7, 1.0.
- Default preserves current behavior.
- Wire-protocol paths verified at exact file/line.

## Decision

**PLAN-READY.** Implementation can proceed against plan v5 SHA
`f742b3ff3`. Recommend single PR with all four mechanisms
(A1+A2+A3+A4) plus the simul-load smoke harness. Expect 8-12
hours wall clock. The new smoke harness becomes a permanent
member of the matrix.

Code-review will run a 4-of-4 hostile-verify (Codex + AGY +
Copilot + Claude SMR) against the actual implementation.
