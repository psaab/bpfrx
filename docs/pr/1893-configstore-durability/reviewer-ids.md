# Reviewer task IDs — #1893/#1894

## Plan round 1 (v1 d02edf30d)
- Codex: task-mqal7v2u-8adha1 (session 019ebaab-5c5d-7f71-a187-f039d868a395) — PLAN-NEEDS-MAJOR, 7 findings, all sustained+adopted
- AGY: adversarial-review-mqal37pw-ehzagk — PLAN-NEEDS-MAJOR; findings A2/A3 sustained, A4 REFUTED (reviewed stale main checkout ecdc16f2e, not worktree 0c4f92354)
- Claude SMR: in-conversation — adopted slot-1-durable + SyncDir, ENOTDIR test, AST canary, temp-sweep in NewDB

## Code round 1 (PR #1900, d02276728)
- Codex: task-mqamuw8f-l8iivi (session 019ebad5-656d-7f83-9c83-c9c3ad15d88b) — NEEDS-CHANGES, 1 High: newly-created durable-state dirs not durable (no parent fsync after MkdirAll in NewDB / dhcp saveDUID). Fixed in cfc353613 (fsatomic.MkdirAllDurable). All other adoption checks passed (constructor callers, stage ordering, hot paths zero-fsync, canary meaningful).
- AGY: adversarial-review-mqamn437-f3k3lx — DEGENERATE (empty result, truncated log); retry adversarial-review-mqan33cv-17vcl4.
- Copilot: review attempt 1 = quota-limited ("user ... reached their quota limit"); retry 1 re-requested 08:01Z.
- Claude SMR: in-conversation — power-loss trace through WriteFileDurable stages verified (write→fchmod→fchown→fsync(tmp)→close-check→rename→fsync(resolved parent)); master.key loss closed (durable write + durable .configdb creation post-cfc353613); boot error message live-validated on fw1 (precise ENOTDIR error, exit 1, no panic, no file-only line). Noted (Low, non-blocking): crash-leaked `.xpf.conf.N.tmp-*` temps in /etc/xpf are not swept at boot (only .configdb is) — rare, commit-paced crash window, documented class in fsatomic README.

## Live validation (PR #1900)
- Lock cell "1893 fail-closed validation (PR #1900)" on loss userspace cluster: deploy d02276728 both nodes, commit/revert probe + rollback list clean, fw1 fail-closed ENOTDIR journal evidence captured, restore + CoS re-applied, both nodes active, node0 primary takeover-ready. Evidence: PR #1900 comment.
