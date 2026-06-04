# #1760 collision-counter reviewer task IDs

Branch: engineer/1760-collision-counter
Plan v1 SHA: bb4f6bf70b96534152cfab31ffb0a2764a022ae7

## Plan review round 1
- Codex: (foreground, see below)
- Gemini: (background, see below)
- Gemini r1: task-mpypb0y6-jkewb9

## Plan review round 1 verdicts
- Codex r1: PLAN-NEEDS-MINOR — 3 findings folded into plan v2 (stale line
  numbers 1217->1357, missing coordinator/status.rs:372 hop, metric
  semantics = "displacement events"). Confirms nat_reverse_index is the
  correct single site; #1760 stays open.
- Gemini r1 (task-mpypb0y6-jkewb9): PLAN-READY — argues value-guarded
  removal makes proxy near-precise; zero hot-path cost; no borrow hazard;
  serde parity correct; not an architectural smuggle.
- Claude SMR: concur PLAN-READY; keep honest "displacement events / upper
  bound" label (residual noise: failed-guard GC removal, HA upsert_synced).

Verdict: PLAN-READY v2.

## Code review round 1 (PR #1762, head 190d9a368)
- Gemini r1: task-mpyqdh0o-obvlzv (background)
- Codex r1: foreground

## Code review round 1 verdicts (PR #1762)
- Codex r1: MERGE-NEEDS-MINOR — only finding: protocol.go gofmt drift
  (fixed in d77faa928). Everything else verified correct. -> MERGE-READY.
- Gemini r1 (task-mpyqdh0o-obvlzv): MERGE-READY (reviewed head 190d9a368;
  gofmt-only follow-up doesn't affect any finding).
- Claude SMR: MERGE-READY.
- Copilot: requested via API, polling.
