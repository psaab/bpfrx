# #1711 reviewer task IDs

## Plan review round 1 (v1, gRPC-only)
- Codex: `task-mpta3t25-pi958d` — PLAN-NEEDS-MAJOR (twin CLI + REST out of scope)
- AGY: `adversarial-review-mpta4os9-m2em4w` — PLAN-NEEDS-MAJOR (same: 3 boundaries)
- Claude SMR: PLAN-NEEDS-MAJOR — local CLI runs simulator in-process, gRPC-only insufficient

Convergent verdict: expand to all three boundaries (gRPC + local CLI + REST).

## Code review round 2 (PR #1721, three-boundary impl)
- Codex: `task-mptayaxl-m5m8ks` — MERGE-NEEDS-MAJOR
  - HIGH: two more simulator copies missed (cli_request.go testPolicy,
    server_show_firewall.go showTestPolicy via ShowText)
  - HIGH: branch stale (forked before #1709/#1712/#1713/#1714) → rebase
  - MEDIUM: CLI/REST positive tests only check err==nil/status
  - Minor: nil-config bypasses validation (contract nit, not the bug)
- AGY: `adversarial-review-mptayhsi-15ez9v` — MERGE-NEEDS-MAJOR
  - Found the 4th caller (cli_request.go testPolicy); confirmed
    discriminator + contracts + no scope creep otherwise

Resolution (v3): fixed both extra copies, rebased onto current master,
strengthened positive tests to assert the actual match verdict.
