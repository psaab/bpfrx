VERDICT: PLAN YES

### Q1 (Obligation Downgrade)
**SOUND**
- **Evidence:** `plan.md:4107-4132`
- **Analysis:** Obligations are keyed by `(creation protocol, both peer incarnations)`. When a peer flaps between v2 and legacy, the legacy incarnation's completion cannot touch or clear the v2-incarnation obligation because the keys differ. Each flap to v2 re-arms the negotiated path, discharging on the next negotiated repair or holding until the takeover fence backstop (`plan.md:4118-4123`).
- **Post-Reset Prime:** Defined explicitly as the fresh incarnation-scoped close-both + cold-prime cycle (the legacy baseline's own reset) whose completion is the lossless INSTALL-only emission (`plan.md:4125-4128`).

---

### Q2 (Pre-Auth Regression)
**SOUND**
- **Evidence:** `plan.md:1405-1440`
- **Analysis:** Pre-auth admissions carry a provisional pending slot tied to their setup admission generation. Unauthenticated pre-auth admissions die at the handshake deadline via connection closure, and the provisional set is strictly bounded by the admission slot limit (`sync_admission.go:66`), preventing leakage or resource exhaustion by stalled connections (`plan.md:1421-1426`).

---

### Q3 (v1-Proof Capabilities + Byte-Exact Formula)
**SOUND**
- **Evidence:** `plan.md:3985-4042`
- **Analysis:** 
  - **Downgrade Race:** Feature states are strictly per-connection (`plan.md:3992-3996`). Reconnection forces a complete re-negotiation (`HELLO`, `PROOF`, `WRAPPER`, `CONFIRM`), eliminating cross-connection state memory races.
  - **Formula Ambiguity:** The transcript order is unambiguous (`plan.md:4029-4042`). `AUTH_PROOF_v2 = HMAC(key, tag_v2 || role || prover_record || verifier_record)` uses fixed 1-byte role flags (`0x01` dialer / `0x02` acceptor), u16-LE length prefixes, and explicit binding where `prover_record` is the sender's own HELLO and `verifier_record` is the received peer HELLO. Both sides compute identical inputs despite distinct per-side nonces.

---

### Q4 (Convergence Sweep)
**SOUND**
- **Evidence:** `plan.md:1395-1440`, `plan.md:3980-4150`, `plan.md:4250-4290`
- **Analysis:** Combining §5.2 and §5.8 provides an end-to-end closed state machine across dataplane demote gates, HA state sync, incarnation fencing, transition CAS with setup generation, per-connection capability masking, and obligation lifecycle bounds under downgrades and restarts. No reachable availability or correctness regressions remain open within this issue class.

---

### New Traces Folded Open in v9.9.47/v9.9.48
1. **v2 ↔ Legacy Peer Flapping with Outstanding Repair Obligation** (`plan.md:4108-4123`): Resolved by keying obligations by `(creation protocol, both peer incarnations)` so legacy completions cannot prematurely clear negotiated repair obligations.
2. **Delayed Pre-Auth Handshake Incarnation Regression** (`plan.md:1406-1427`): Resolved by incorporating the setup admission generation into the transition CAS to prevent a delayed pre-auth setup from demoting a newer, authenticated peer incarnation.
3. **Dialer/Acceptor HMAC Input Discrepancy Under Per-Side Nonces** (`plan.md:4034-4040`): Resolved by standardizing dialer-first u16-LE length-prefixed raw HELLO records with explicit `prover_record` / `verifier_record` mapping.
AGY EXIT: 0
