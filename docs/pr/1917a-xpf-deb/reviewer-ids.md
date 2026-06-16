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
