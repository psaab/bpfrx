# #1476 Plan and Code Review IDs

Track Codex + Antigravity task IDs across plan-review and code-review
rounds. Append a row per dispatch.

## Plan review

| Round | Reviewer | Task ID | Verdict | Notes |
|-------|----------|---------|---------|-------|
| r1 | AGY (adversarial) | adversarial-review-mplecplf-v3q393 | PLAN-NEEDS-MINOR | 2 findings: Makefile clean glob nukes retained shim; dataplane_boot_test must be rewritten for retirement-reject |
| r1 | Codex (gpt-5.2-codex) | bash:bl82qwbhq (local) | infra-fail | model not supported for ChatGPT account; retry below |
| r1b | Codex (gpt-5.5) | bash:ba71kfn0k (local) | PLAN-NEEDS-MAJOR | 6 findings (1,2,3,4,5,8): Manager.Load() interface break, make clean nukes shim, retained-helper under-list, nat_port_counters misclass, loader_stub canary gaps, TypeEBPF test migration |
| r2 | AGY (adversarial) | adversarial-review-mpleu3yh-ppf34j | PLAN-NEEDS-MINOR | 4 missing retained helpers: userspaceBindingsMaxEntriesDriftError, userspaceIngressIfacesMaxEntriesDriftError, userspaceShimMaxSessions, userspaceShimMaxNATPools |
| r2 | Codex (gpt-5.5) | bash:b6lqkxdnp (local) | PLAN-NEEDS-MAJOR | 5 findings: stale §5 Manager.Load() row; F3 still under-listed (overlap with AGY r2); shim_loader_boundary_test path hardcode (NEW); F4 stale drop-pin text; non-daemon ebpf-warning tests will fail (NEW) |
| r3 | AGY (adversarial) | adversarial-review-mplfqxg2-tsn5wi | PLAN-READY | 1 cosmetic nit: risk-table line 721 "4" → "5" (absorbed into v4) |
| r3 | Codex (gpt-5.5) | local pid 1246138 | PLAN-NEEDS-MAJOR | 6 findings, all stale-text drift / doc-sweep gaps; no new operational issues. Fixed in v4. |
| r4 | AGY (adversarial) | adversarial-review-mplgsx14-bcoj2x | PLAN-READY | r3 findings all closed; one Phase-B critical: extend rewriteRetiredDataplaneType to run in Store.SyncApply() (absorbed into §4.6) |
| r4 | Codex (gpt-5.5) | local pid 1251897 | PLAN-READY | all r3 findings closed; no new issues |

## Code review (Phase B)

| Round | Reviewer | Task ID | Verdict | Notes |
|-------|----------|---------|---------|-------|
| r1 | AGY (adversarial) | adversarial-review-mpmacktl-2gvwd4 | MERGE-READY | r4 Store.SyncApply finding closed; loader extraction byte-for-byte correct; canaries pass |
| r1 | Codex (gpt-5.5) | local pid 1519323 | MERGE-NEEDS-MAJOR | 5 findings (F1 apply-groups bypass MAJOR; F2-F4 MINOR caller-aware warn / gRPC code / stale prose; F5 NIT escape-hatch text). All fixed in 8c88cc38. |
| r2 | AGY (adversarial) | adversarial-review-mpmawzis-qr062e | MERGE-READY | r1 findings verified closed; 5x flake on apply-groups tests clean; no new issues at 8c88cc38 |
| r2 | Codex (gpt-5.5) | local pid 1546202 | MERGE-NEEDS-MAJOR | 3 findings: F1 MAJOR split-stanza walk (FindChild returns only first) → fixed at f815c357; F2 MINOR nested-groups deferred (not reachable today); F3 NIT stale BPFRX_LEGACY_LOADER_RETIRED comment → fully stripped at f815c357 |
| r3 | AGY (adversarial) | adversarial-review-mpmbbqsv-y9m5lu | MERGE-READY | r2 findings all closed; full test suite green; out-of-scope observation: pkg/configstore/crypto.go has the same FindChild first-match pattern in masterPasswordPRF — separate hardening issue, not blocking #1476 |
| r3 | Codex (gpt-5.5) | local pid 1564863 | MERGE-READY | r2 findings all closed; 5 INFO observations; no new MAJOR/MINOR/NIT findings |

## Copilot

| Round | Comment URL | Status |
|-------|-------------|--------|
| r1 | https://github.com/psaab/xpf/pull/1558#pullrequestreview-4361330619 | STUCK — "exceeds maximum number of lines (20,000)"; 3-of-4 Copilot-stuck exception applies per `feedback_copilot_two_bots` |
