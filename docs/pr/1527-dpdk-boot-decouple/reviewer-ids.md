# Reviewer task / job IDs — PR #1535 (#1527 boot-path decouple)

## Plan review (v2)

- Codex plan review: `task-mpkqsgf5-j2yag1` — PLAN-NEEDS-MINOR (resolved in v2/v3)
- Antigravity plan review: `adversarial-review-mpkqkzkm-qfa19j` — PLAN-READY

## Code review — commit 47a4278c (original push)

- Codex code review: `task-mpkrohgl-dow3kd` — MERGE-NEEDS-MINOR (sequencing + plan cleanup; resolved in v3 + a00d9111)
- Copilot inline review on PR: posted 2026-05-25T05:32:08Z with 1 inline comment on `dataplane.go:155-164` (fatal-at-startup brick-restart concern). Addressed by `a00d9111`.

## Code review — commit a00d9111 (force-push 2026-05-25)

- Codex hostile code review: `task-mpkrwbtk-pd6nnw` — MAJOR
  - (1) NPE on `OnFenceReceived` when `d.dp == nil` after soft-fallback
  - (2) Stale docs prose at `docs/pr/1373-retire-ebpf-dataplane/README.md:66,85` (canary still passes)
- Antigravity adversarial review: `adversarial-review-mpkrwmkk-2k24v4` — MAJOR
  - Same NPE finding (independently identified)
- Copilot: re-triggered (issue-comment 4531824507), original `47a4278c` review was already addressed by `a00d9111`

## Code review — commit 878bcbdd (force-push 2026-05-25)

Resolves Codex+Antigravity MAJOR (NPE on fence callback) via nil guard in
`pkg/daemon/daemon_ha_sync.go:676-679`. Docs prose update deferred to Chain C
(#1529) — canary `TestRetirementBoundaryDocsMentionDPDKPolicy` still PASS.

- Codex re-review: `task-mpks5yrq-4h7ia5` — DISPATCHED
- Antigravity re-review: `adversarial-review-mpks62um-g47sg4` — DISPATCHED
- Copilot re-trigger: issue-comment 4531855093

Verification scope (see prompt for full list): (a) blank-import removal completeness,
(b) NewRuntimeDataPlane reject placement vs EffectiveType, (c) errors.Is wrapping
chain, (d) empty allowlist canary behavior, (e) docs-token canary integrity,
(f) build + tests without -tags dpdk, (g) daemon_run.go soft-fallback correctness
(d.dp = nil safety, branch ordering), (h) scope-creep into #1528, (i) restart-race
adversarial probe.
