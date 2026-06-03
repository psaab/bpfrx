# AGY r1 — #1752 plan @ 75a21e4e5 — PLAN-NEEDS-MAJOR

Concurs with Codex on Path B HA-node safety, Path A deprioritization, CoS Gb/s.

NEW code-grounded finding (verified by Claude against session/mod.rs):
- The ~4.5% "session churn" is NOT connection churn. `update_session`
  (session/mod.rs:803) and `upsert_synced_with_origin` (:742) perform full
  `remove_entry`(:1119)+`restore_entry`(:1176) cycles — tearing down/rebuilding
  key_to_handle, forward-NAT index, owner-RG index and slab slot — on every
  packet of an established flow, only to bump last_seen/expires. In-place
  `get_mut` recaptures ~4.5%. → v3 adds this as Path E (recommended first code
  win, lowest kill-risk).

Open questions raised → resolved in v3:
- HA strongSwan experiment safety → no HA-node config A/B (Path B non-invasive).
- Path A deprioritize vs C/D → Path A gated; E+B first.
- Session churn → Path E added with differential-test gate.
