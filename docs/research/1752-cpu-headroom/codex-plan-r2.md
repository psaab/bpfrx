# Codex r2 (foreground) — #1752 plan v3 @ decbf7a91 — PLAN-READY

All 5 r1 blockers confirmed resolved (Path B HA safety §5/§7; crypto DEK
causality §2/Finding3; CoS ~19% CPU anchor §3; driver RX "Partly" §2; Path A
gated §4). Path E acceptable — source-verified update_session removes+restores
(session/mod.rs:813/838) with index/slab churn in remove_entry/restore_entry
(:1119/:1176); sub-profile + differential-test gates are the right guardrails.
Non-blocking nit (fixed in v4): stale fw0/HA wording in §6 + open-Q4.

(Background jobs would not persist this session — Codex companion reported
"No jobs recorded" twice; verdict obtained via foreground task.)
