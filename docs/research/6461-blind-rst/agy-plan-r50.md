VERDICT: PLAN YES

### Q1 (completion matrix): SOUND
- **Evidence**: `docs/research/6461-blind-rst/plan.md:4004-4028`
  - **(a) repair-vN pairs**: Applied `JOURNAL_END` clears receiver inbound/readiness (`plan.md:4014-4016`, `4049-4050`); matching full-triple `JOURNAL_ACK` clears sender outbound/cold-prime (`plan.md:4016-4017`, `4050-4052`). Neither `BulkEnd` nor bare `BulkAck` discharges a negotiated repair obligation.
  - **(b) legacy→new full bulk**: The legacy `BulkEnd` readiness path (`pkg/cluster/sync_conn_read.go:241-247` → `daemon_ha_sync.go:90-100`) is retained for unnegotiated legacy senders (`plan.md:4018-4021`). The "never discharges" rule applies strictly to negotiated repair-era bulks.
  - **(c) new→legacy INSTALL-only prime**: No repair obligation is armed (`plan.md:4021-4027`). Cold-prime clears on successful lossless emission (fire-and-forget), and the legacy peer converges via its own invalidation/aging semantics.
- **Attack Analysis**:
  - *New→legacy cold-prime with no obligation armed*: Nothing gates readiness on the legacy peer's state because the prime is fire-and-forget and clears upon emission (`plan.md:4023-4025`).
  - *Legacy→new bulk with an outstanding repair obligation*: The legacy `BulkEnd` path is restricted to unnegotiated peers (`plan.md:4017-4021`). A legacy `BulkEnd` frame cannot clear or discharge a negotiated `repair-vN` obligation, ensuring the completion paths remain isolated without cross-contamination.

---

### Q2 (mixed-version negotiation): SOUND
- **Evidence**: `docs/research/6461-blind-rst/plan.md:3936-3970`, `pkg/cluster/sync_auth.go:372-376`, `pkg/cluster/sync_protocol.go:470-497`
  - **Legacy HELLO prefix**: Preserved byte-for-byte (`sync_auth.go:345-347`). v1 peers read nonces from `payload[2:34]` (`sync_auth.go:376`).
  - **v1 Proof Selection**: Either peer being v1 selects the v1 nonce-only proof over the legacy prefix bytes (`plan.md:3943-3946`).
  - **Capability Handling on v1-Proof**: Capabilities requiring transcript auth (e.g. `reset-vN` and `RESET_GEN`/`RESET_ACK`) are masked (`plan.md:3950-3955`). Non-masked capabilities like `repair-vN` are post-authenticated.
- **Attack Analysis**:
  - *v1 HELLO Parser & Trailing Fields*: `pkg/cluster/sync_auth.go:372-376` checks `len(payload) < 34` and extracts `payload[2:34]`, ignoring trailing bytes for HELLO frames. Note that `pkg/cluster/sync_protocol.go:470-497` is length-gated decoding of *session* frame payloads (`decodeSessionV4Payload`), not HELLO frames.
  - *Concrete Meaning of "Post-Authenticated"*: Because the v1 `AUTH_PROOF` only signs the 32-byte nonce (`sync_auth.go:389`) rather than the trailing HELLO capability bytes, capability bits in HELLO arrive unauthenticated. Post-authentication means capabilities like `repair-vN` are established and verified via authenticated protocol frames sent *after* the authenticated frame wrapper installs (`sync_auth.go:406`).

---

### Q3 (convergence sweep): SOUND
- **Evidence**: `docs/research/6461-blind-rst/plan.md:469-580` (§5.2), `plan.md:3892-4068` (§5.8)
  - §5.2 ensures anchors update only at RX-worker final admission on committed non-close packets (`plan.md:476-490`, `571-573`) using serial max sequence sliding (`plan.md:575-580`). Closing frames (RST/FIN) never update anchors (`plan.md:571-573`), preventing blind RST/FIN demote DoS.
  - §5.8 consolidates additive identity tails (`origin_process_nonce`, `flow_incarnation_id`, `stable_rule_id_hash`, `admission_config_version`, `persistent_nat`, `persistent_nat_permit`) (`plan.md:3895-3920`), eliminating identity aliasing, SNAT mid-flow swaps, and tuple reissue races under live sessions.
  - Together with the capability-conditioned completion matrix (`plan.md:4004-4028`), the complete stack closes all failure modes in the issue's class (blind RST/FIN demote DoS, SNAT mid-flow swap, HA state desynchronization, tuple release/reissue under a live session, deadlock, and availability regression).

---

### NEW TRACES FOLDED OPEN IN v9.9.45
None. The v9.9.45 revisions clarify transcript installation gating (`plan.md:3976-3979`) and formalize the capability-conditioned completion matrix (`plan.md:4004-4028`), fully closing all previously open traces without introducing new edge cases.
AGY EXIT: 0
