# #1638 reviewer task IDs

Branch: `pr/1638-rm-scaffold`
Plan commit (v1): `47afcc044cf37db6e3e7bc71e0fd8e69fb413515`

## Plan review (round 1)

| Reviewer | Task ID | Verdict |
|---|---|---|
| Codex | task-mprtmbvy-y1tl33 | PLAN-NEEDS-MINOR (both minors addressed in plan v2) |
| AGY | adversarial-review-mprtmgza-yldl69 | PLAN-READY |
| Claude SMR | inline | PLAN-READY |

Codex r1 minors: (1) §3.2 wording overstated "no read-sites" — build_rule_side_arc
reads book.prefixes_v4/v6 to feed the dead arrays (still dead). Fixed.
(2) test deletion not blanket-safe — test_policy_rule_v3_any4_any6_tokens has
live match-any assertions (only any4/any6 coverage). Preserved in slimmed form.

## Code review (round 1)

| Reviewer | Task ID | Verdict |
|---|---|---|
PR: #1676. Code HEAD: 7faf07d4ef97d915278e560640cc79999cf7db20

| Codex (r1) | task-mpru34qd-akn2s3 | INFRA-BLOCKED (missing codex-linux-sandbox) — retried |
| Codex (r2) | task-mpruhdgi-ge37ev | INFRA-BLOCKED AGAIN (sandbox runner absent; "Failed to create unified exec process") |
| AGY | adversarial-review-mpru39ju-blnzhx | MERGE-READY |
| Copilot | COMMENTED (0 inline comments) | clean |
| Claude SMR | inline | MERGE-READY |

Codex sandbox (`codex-linux-sandbox`) is absent from the plugin cache in this
environment — both code-review attempts failed before any shell command could
launch. Per feedback_codex_infra_must_retry, Codex was retried once; the retry
confirmed a persistent (not transient) environment breakage. Merge gate stands
on AGY MERGE-READY + Copilot clean + Claude SMR MERGE-READY (3-of-4); the
parent decides whether to wait for Codex infra recovery or merge.
