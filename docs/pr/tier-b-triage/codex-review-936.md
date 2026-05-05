# Codex round-1 PLAN review — #936 single-issue closure plan

Task ID: task-mosuvuzs-xbvx9a
Codex session ID: 019df904-828e-7840-903a-f9c98d78c1f7

---

**Verdict: PLAN-NEEDS-MINOR**

Findings:

1. The close is substantively different from "stays open," but only as backlog state. Implementation state is identical: no work until opt-in. That is still useful because it removes a non-actionable values decision from active triage.

2. The reframe mostly fixes the v4 overreach. It avoids "declined by default," "wontfix," and "superseded by #937." That faithfully applies the corrected framing.

3. Tweak the reopen trigger. "User posts a comment" is discoverable, but GitHub will not auto-reopen. Make the trigger operational: "Comment here confirming the ~43% aggregate-throughput trade-off is acceptable for the target workload/topology; that comment is sufficient for triage to reopen." Prefer comment-on-#936 over "file a fresh issue," which fragments the trail.

4. Remove or soften the #937/#776 claim. For a single-issue #936 closure, saying #937 is "currently blocked on shared-UMEM availability per #776" imports a separate contested dependency and risks misleading future readers. Use: "If this trade-off is not acceptable, track the non-stalling alternative in #937."

Suggested close wording:

> Closing as inactive pending explicit user opt-in. This is not declined, not wontfix, and not superseded by #937. The issue body documents the trade-off: per-flow CoV may approach 0 by stalling fast workers, but the degenerate 1+3 case caps aggregate at ~5.3 Gb/s instead of ~9.3 Gb/s, about a 43% hit. Reopen trigger: comment here confirming that trade-off is acceptable for the target workload/topology; that is sufficient to make the design actionable again.

After those tweaks, close.

---

# Gemini Pro 3 — failed (rate-limit, 7th today)
