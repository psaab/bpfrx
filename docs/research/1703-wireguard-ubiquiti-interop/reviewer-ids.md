# #1703 WireGuard/Ubiquiti interop — reviewer task-id ledger

## Round 1
- Codex: codex-companion job bhawxbc0b (adversarial-review) — 3 findings (1 high, 2 medium), no KILL
- AGY: adversarial-review-mpt4mdo2-kc907i — PLAN-NEEDS-MAJOR, 2 findings (frag reassembly, handshake heap-alloc)
- Claude-SMR: claude-smr-plan-r1.md — PLAN-READY w/ 3 nits

## Round 2
- Claude-SMR: claude-smr-plan-r2.md — PLAN-READY (all r1 findings closed)
- Codex: (round-2 pending)
- AGY: (round-2 pending)

## Round 3
- Codex: codex-companion round-3 job (adversarial-review) — 1 finding: S2 must not assert peer `latest handshake` (key-confirmation gated). Closed in r4.
- Claude-SMR: claude-smr-plan-r4.md — PLAN-READY (Codex r3 closed)

## Round 2 (detail)
- Codex r2 job: 1 finding (S2/S3 gating) — closed in r3
- AGY r2 job adversarial-review-mpt4vk82-e97hod: lost (searched wrong worktree path; infra artifact, not a verdict)
- AGY r2 RETRY job adversarial-review-mpt53bi2-4xnrt9: (pending)

## CONVERGENCE (all three PLAN-READY)
- Codex round-4: PLAN-READY ("r4 closes the S2 deadlock... No material findings")
- AGY round-2 retry adversarial-review-mpt53bi2-4xnrt9: PLAN-READY (O1+O2 closed, sequence validated)
- Claude-SMR r4 (claude-smr-plan-r4.md): PLAN-READY
