# #1917 increment A (PR #1931) reviewer ledger

## Reviewer task IDs
- **AGY adversarial-review**: `adversarial-review-mqgp1s04-v0pg6j`
- **Codex review**: agent `a484eb170fe45ba4b` (forwarded to Codex runtime
  session `a8c1b014-...`, slug `logical-gliding-bee`)
- **Copilot**: requested on PR #1931
- **Claude SMR**: in-conversation hostile review

## Round-1 verdicts
- **AGY**: NEEDS-REVISION (7 findings, no KILL) — all dispositioned, fixes in
  `bffb3207a`.
- **Codex**: NEEDS-REVISION — symlink guards + bake sort + trap + description
  (= AGY's set) PLUS HIGH: missing ExecStartPre verifier gate (fixed
  `aeaee013b`). One CRITICAL was a Codex-sandbox read-only-fs limitation, not
  a code defect (make deb builds clean locally).
- **Claude SMR**: hostile review folded into the implementation (mtime sort,
  metapackage-divergence doc, /etc/xpf never-touched, fail-closed postinst).

## Fixes
- `bffb3207a`: postinst `[ ! -L ]` + `ln -sfnT`; bake mtime-sort + deb-extract
  pre-gate; control description + drop adduser; Makefile trap.
- `aeaee013b`: ExecStartPre=verify-dataplane in the packaged unit.

## Re-review
- Re-review requested on the updated diff after the two fix commits.

## Round-2 verdicts
- **Codex r2** (agent a350baec750858dc1): MERGE-READY — all r1 fixes verified, no new defects.
- **AGY r2** (adversarial-review-mqgpjqoz-gyin2d): NEEDS-REVISION — (1) CRITICAL Makefile signal-mask, (2) fragile sed ExecStartPre. Both fixed in `00dc252ef`.

## Round-3 confirmation (dispatched on HEAD 00dc252ef)
- **Codex r3**: agent a7ad3f1a3cb0dcc7a
- **AGY r3**: adversarial-review-mqgpvijr-sn3022

## Copilot
- Quota-unavailable ("reached their quota limit"). Fallback: Codex + AGY + Claude SMR + boot/verify validation.

## End-to-end validation
- Bake from .deb -> image boots; Scenario A (factory boot + in-guest verify-dataplane) PASS, B (valid day-0) PASS, C (invalid day-0 fallback) PASS; `bake complete`.
