# #1673 README refresh — reviewer task IDs

## Plan review round 1 (commit ab1969a18)
- Codex: task-mprf5ryd-dlymqg (INFRA-FAIL) → retry task-mprf7b19-t0c1oe
- AGY: adversarial-review-mprf5ygi-4buyc1
- Claude SMR: inline (this conversation)

## Code review round (PR)
- Codex: TBD
- AGY: TBD
- Copilot: TBD
- Claude SMR: inline

## Code review round (PR #1674 @ 3085e4085)
- Codex: task-mprflsx5-ji4376 (full-access retry; prior plan attempts infra-blocked)
- AGY: adversarial-review-mprfm2fi-6wailn
- Copilot: @copilot review posted (comment 4580001899) + reviewer requested
- Claude SMR: inline

## Code review verdicts (final @ b90c564c7)
- AGY r1 (3085e4085): MERGE-NEEDS-MINOR — Priority Work stale (job adversarial-review-mprfm2fi-6wailn)
- AGY r2 (d5aeb49c8): MERGE-NEEDS-MINOR — 3 Mixed-Boundary rows stale (job adversarial-review-mprfq94i-pde4zi)
- AGY r3 (b90c564c7): MERGE-READY (job adversarial-review-mprg6neb-htfhok)
- Copilot r1 (3085e4085): COMMENTED — Priority Work contradiction (fixed)
- Copilot re-reviews requested after d5aeb49c8 + b90c564c7
- Codex: INFRA-BLOCKED all 4 dispatches (codex-linux-sandbox cannot spawn — environment fault, retries honored)
- Claude SMR: MERGE-READY (every claim verified file:line; both doc-guards 5/5; acceptance rg empty)

## Round 4: legacy-mechanism-attribution fix (d77d87b1e)
- Parent reviewer found README:144 (MSS clamp "ingress XDP + egress TC") + README:140 (SYN cookie "XDP-generated") attributing live capabilities to retired eBPF mechanism. Both fixed to userspace AF_XDP dataplane (features preserved, verified vs code).
- AGY: adversarial-review-mprgg00t-tyo9xf
- Copilot: re-review requested
- Broadened mechanism scan now clean (all hits legacy-qualified or removed).
