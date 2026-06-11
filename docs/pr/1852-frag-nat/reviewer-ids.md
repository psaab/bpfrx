# #1852 reviewer task IDs

## Research (PLAN-READY v3.1, converged) — branch research/1852-frag-nat

Codex (flock /tmp/xpf-codex.lock):
- r1 task-mq8wfs3n-c5eg6a — PLAN-NEEDS-REVISION
- r2 task-mq8wsliq-uqsza3 — PLAN-NEEDS-REVISION
- r3 task-mq8x1be1-15jar6 — PLAN-NEEDS-REVISION (doc-precision)
- r4 task-mq8x6rg5-9fagl9 — PLAN-READY

AGY (result: .../gemini-abiswas97-gemini/state/jobs/<id>.result.md):
- r1 adversarial-review-mq8whg97-ifovwq — PLAN-NEEDS-REVISION ("Proceed with Path A, do NOT kill")
- r2 adversarial-review-mq8wssym-b57kae — PLAN-NEEDS-REVISION (GRE/tunnel helper trap)
- r3 adversarial-review-mq8x1hg9-q6lfxw — PLAN-READY

Claude SMR: research branch docs/research/1852-frag-nat/claude-smr-plan-r{1,2,3}.md

## Implementation review — this PR (#1857)

Codex (flock /tmp/xpf-codex.lock):
- r1 task-mq8ybiw9-1v4b2q — CHANGES-REQUESTED (H1 raw_frame after GRE decap; H2 forced tunnel L4 recompute ignores fragment gate)
- r2 task-mq8yszdq-gnhoq4 — MERGE-READY (both High findings resolved; no remaining blocking finding)

AGY:
- r1 adversarial-review-mq8ybrtd-79dsvh — confirmed the packet_frame (GRE-decap) fix; sound
- r2 adversarial-review-mq8yszot-7d8yg8 — MERGE-READY ("changes are sound"); debug-run failures (concurrent_recovery, inplace_*) are known-flaky, out of scope

Copilot: INFRA-BLOCKED — "unable to review … quota limit" (both review attempts). Documented per the Copilot-infra-blocked exception; gate met by Codex + AGY + Claude SMR.

Claude SMR: docs/pr/1852-frag-nat/claude-smr-impl-r1.md — MERGE-READY

## Convergence

MERGE-READY at head 27bfda1e5 — Codex r2 + AGY r2 + Claude SMR r1 all
MERGE-READY; Copilot quota-blocked (documented). NOT merged — parent runs
serialized cluster smoke before merge.
