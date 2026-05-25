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

- Codex re-review: `task-mpks5yrq-4h7ia5` — MERGE-READY (1 NIT: structure the
  nil-dp fence slog.Warn with kv fields; fixed in fe82ac74)
- Antigravity re-review: `adversarial-review-mpks62um-g47sg4` — MERGE-READY
- Copilot re-trigger: issue-comment 4531855093

## Code review — commit fe82ac74 (force-push 2026-05-25)

Includes the second-agent commits `e7f199f1` (panic guards on TypeDPDK
registration + cleanup), `ee83e972` (allowlist comment refresh), `8c475d4a`
(StartFIBSync stale ref fix), plus my `fe82ac74` (structured slog kv on
nil-dp fence warning, addresses Codex NIT).

- Codex re-re-review: `task-mpksgyz9-45ib7t` — MERGE-READY with NIT
  (stale FIB sync comment at `daemon_run.go:326`; fixed in `9b4e9e24`)
- Antigravity re-re-review: `adversarial-review-mpksh5km-1mf7rz` — MERGE-READY
- Copilot re-trigger: issue-comment 4531892202 → Copilot fresh review on `d5fa4838`
  returned 3 inline findings (compiler_system error string, fence log ordering,
  plan v3/v4 inconsistency); all 3 fixed in `9aa96c3e` + `dd959112`.

## Parallel session reviews captured

- Codex `task-mpksf0nq-eeuxc3` (other agent, on `ee83e972`): MERGE-NEEDS-MINOR.
  Findings: (1) error string vs validator (fixed in `9aa96c3e`), (2) plan
  sequencing inconsistency (fixed in `dd959112`), (3) plan whitespace NIT
  (acknowledged out-of-scope).

## Code review — commit dd959112 (final convergence)

Final round addresses all 3 remaining Copilot inline findings on the prior
SHA plus the Codex `task-mpksf0nq-eeuxc3` minor findings.

- Codex final re-review: `task-mpksus16-sel08z` — DISPATCHED
- Antigravity final re-review: `adversarial-review-mpksuwyo-tlgd91` — DISPATCHED
- Copilot final re-trigger: issue-comment 4531937401

Verification scope (see prompt for full list): (a) blank-import removal completeness,
(b) NewRuntimeDataPlane reject placement vs EffectiveType, (c) errors.Is wrapping
chain, (d) empty allowlist canary behavior, (e) docs-token canary integrity,
(f) build + tests without -tags dpdk, (g) daemon_run.go soft-fallback correctness
(d.dp = nil safety, branch ordering), (h) scope-creep into #1528, (i) restart-race
adversarial probe.
