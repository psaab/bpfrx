# PR #1876 (#1865) reviewer task-id ledger

## Plan rounds (research phase — research/1865-wg-telemetry branch)
- r1: Codex task-mqa0ade4-1mtshv NEEDS-MAJOR; AGY adversarial-review-mqa09l7f-a4rixg NEEDS-MAJOR (f1 refuted); SMR NEEDS-MINOR
- r2: Codex task-mqa0pcn3-347u73 PLAN-READY; AGY adversarial-review-mqa0ovaw-q6zx2t PLAN-READY (f1 withdrawn); SMR PLAN-READY

## Code round 1 (head a8c98cb1f)
- Codex: session 019eb8da-9214-7c21-88b2-631f057cbe43 — NEEDS-CHANGES
  (F1 name-fallback chain incomplete; F2 'initiations sent' wording) — codex-code-r1.md
- AGY: adversarial-review-mqa32eme-2ia15q — MERGE-READY — agy-code-r1.md
- Claude SMR: claude-smr-code-r1.md — MERGE-READY (worked traces A/B; cosmetic keepalive dedup applied)
- Copilot: quota-limited (retry 1 documented)

## Code round 2 (head 65a84eecc — Codex F1+F2 folded)
- pending

## Code round 2 (head 832514fdc)
- Codex: session 019eb8ee-30ea-7851-bd4c-e52d1c2a600d — NEEDS-CHANGES
  (ONLY trailing whitespace in the copied round-1 review-record .md
  files; both code folds verified correct; residual note: no direct
  Rust unit test for the interface_label fallback — accepted as a
  coverage gap, the fallback is exercised by compile + the live
  name-resolution evidence) — codex-code-r2.md
- AGY: adversarial-review-mqa3r7h5-ajp16u — MERGE-READY (deltas safe;
  interface_label non-secret in Debug) — agy-code-r2.md
- Claude SMR: re-attest MERGE-READY (delta audit: interface_label is
  an interface-name string, Debug-safe; fallback tier ordering
  ifindex_to_name first preserves today's primary path; wording pin
  updated; whitespace fix is docs-only)

## Code round 3 (whitespace fix)
- pending Codex re-attest
