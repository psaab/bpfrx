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
