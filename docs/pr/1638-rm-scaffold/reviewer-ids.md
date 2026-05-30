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

| Codex | task-mpru34qd-akn2s3 | (pending) |
| AGY | adversarial-review-mpru39ju-blnzhx | (pending) |
| Copilot | (requested) | (pending) |
| Claude SMR | inline | (pending) |
