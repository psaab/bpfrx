# #1918 / PR #1947 — reviewer task IDs

Real ICMP liveness probe for tunnel keepalive.

## Round 1

| Reviewer | ID | Verdict | Notes |
|----------|----|---------|-------|
| Codex | `019ed45c-9636-7f23-99e3-66c82177728f` (agent `a2de27069d925925a`) | CHANGES-REQUESTED | Two HIGH: (1) transient LinkByName treated as absent → drains live runner + EEXIST; (2) WriteTo ENOBUFS misclassified as Dead. Both fixed in `22e4c6b72`. |
| AGY | `adversarial-review-mqhptss6-qglj26` | CLEAN (no findings) | Verified all 4 axes: commit-after-success, drain+linkGen+no-deadlock, errno classification, Seq+nonce. |
| Claude SMR | (in-conversation) | clean | Reviewed reuse-vs-recreate gen bump, startup posture, nonce-per-tick cost, LinkDel-failure window — acceptable. |
| Copilot | pending | | |

## Round 2 (post-Codex-fix re-review @ 22e4c6b72)

| Reviewer | ID | Verdict |
|----------|----|---------|
| Codex | `019ed464-af4c-7623-8619-a57e0280bb9f` (agent a6b204b6499b62719) | MERGE-READY — both r1 HIGH fixes correct, no new bugs |
| AGY | `adversarial-review-mqhq593d-l5lmox` | CLEAN — fixes safe; flagged the same probe-reason actionability gap Copilot did (fixed in 9da9e14cc) |
| Copilot | (review on PR) | 4 comments: probe-reason actionability ×2, KeepaliveUp tri-state doc, missing v6 test — all fixed in 9da9e14cc |

## Round 3 (final rev @ 9da9e14cc — Copilot fixes)

| Reviewer | ID | Verdict |
|----------|----|---------|
| Codex | `a8bb8219fdfa9ed20` | MERGE-READY — delta verified, no new issues |
| AGY | (covered by r2 — its sole improvement note WAS the reason plumbing, now implemented) | clean |
| Claude SMR | in-conversation | clean |
| Copilot | re-requested @ 9da9e14cc | pending |
