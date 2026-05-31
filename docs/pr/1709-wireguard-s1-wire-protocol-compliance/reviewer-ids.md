# #1709 WireGuard S1 — reviewer task IDs

Record Codex / AGY / Gemini task-ids here so continuations can fetch by id
(per feedback_codex_session_loss_continuation).

## Plan review round 1 (plan v2 @ 2b51e4b4d)
- Codex: task-mpt6qx4i-i04py6 — PLAN-NEEDS-MAJOR
- AGY: adversarial-review-mpt6r70o-ebe5a4 — PLAN-NEEDS-MAJOR
- Claude-SMR: in-conversation — PLAN-NEEDS-MINOR (plan §SMR-R1)

## Plan review round 2 (plan v3 @ b9e8bb00a) — CONVERGED PLAN-READY
- Codex: task-mpt72t96-tcx9m8 — PLAN-NEEDS-MINOR (KAT-naming text fix; folded v4)
- AGY: adversarial-review-mpt7315l-j522br — PLAN-READY (+2 impl caveats; folded v4)
- Claude-SMR: PLAN-NEEDS-MINOR (round-1, resolved v3/v4)
- Outcome: plan v4 cleared to implement (§v4-round2)

## Code review round 1 (PR #1716 @ ce8f21899)
- Codex: task-mpt8dpg6-jeyqqr — MERGE-NEEDS-MAJOR (2 majors + 1 medium in consume_response/parse)
- AGY: adversarial-review-mpt8e2ef-0bjiij — MERGE-NEEDS-MINOR (pending_by_peer leak; reviewed pre-fix code)
- Claude-SMR: in-conversation — removed dead peer_index field
- Fixes pushed @ bd80112a5 (consume_response reservation rework, restore-on-fail, strict type)

## Code review round 2 (PR #1716 @ bd80112a5)
- Codex re-review: task-mpt8qqkg-lcclp2 — MERGE-NEEDS-MAJOR (consume_response still dropped pending lock before Noise read; per-peer abort could remove in-flight reservation mid-read)
- Copilot: re-requested; found reconcile-drain-pending gap + MAC1-KAT-comment (fixed @ 76f78b443)
- Claude-SMR: confirmed no double reconcile_lock acquisition

## Code review round 3 (PR #1716 @ 3f6dda484)
- Fix: entire handshake completion now under reconcile_lock (install_session_locked / reserve_pending_locked / clear_reservation_locked lock-free cores)
- Codex re-review: task-mpt93h8p-uwj8eg — MERGE-NEEDS-MAJOR (TOCTOU: create_initiation pre-lock peer check vs locked reserve)
- AGY re-review: adversarial-review-mpt93sxe-c3756h — MERGE-READY (race closed, no deadlock, no leak, WG-compliant)
- Claude-SMR: verified no path re-takes reconcile_lock (no deadlock)

## Code review round 4 (PR #1716 @ b890ef84d)
- Fix: reserve_pending_locked re-checks peer under lock (TOCTOU closed)
- Codex round-4: task-mpt9czff-17zab2 — MERGE-NEEDS-MINOR (TOCTOU code fix correct; test ineffective + stale comment)

## Code review round 5 (PR #1716 @ a334ba129 → 6d80369fc → b52f50545)
- Fixes: deterministic TOCTOU regression (mutation-verified) + exact-length parse (WrongLength) + plan-deviations note + doc nits
- Codex: task-mpt9ueve-h7qwsr — MERGE-NEEDS-MINOR (docs-only) → task-mpt9y6p7-bnijrw — **MERGE-READY** (no findings)
- AGY: MERGE-READY (round-3, code unchanged in substance since)
- Copilot: COMMENTED; all substantive findings addressed (parse-length, stale comments, HMAC, O(peers), return-order, entry-count)
- Claude-SMR: byte-exact framing + KATs reproduced from blake2 first-principles; snow payload==timestamp verified; no deadlock; race-free

## MERGE GATE: clean 4-of-4 (Codex MERGE-READY, AGY MERGE-READY, Copilot addressed, Claude-SMR verified). No cluster smoke — S1 is wire-protocol + tests, no datapath change.
