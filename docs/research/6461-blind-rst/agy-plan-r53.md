VERDICT: PLAN YES

### Q1 (byte grammar): SOUND
**File:Line Evidence:** `plan.md:4065-4079`, `plan.md:4085-4093`, `plan.md:4823-4831`
- `plan.md:4065-4071`: Defines `term(x) = u16-LE(len) || exact raw payload bytes` as transmitted, excluding wire frame headers (`readSyncFrameRaw` returns payload separately at `pkg/cluster/sync_auth.go:289-310`).
- `plan.md:4071-4079`: Capability record layout is fully specified: field order `(node_id, process_incarnation, capacity, capacity_config_generation, capability bits)`, fixed widths `u32/u64/u64/u64/u32`, LSB-first bit assignment table (`bit 0` = identity-enforcement, `bit 1` = lease-input, `bit 2` = repair-vN, `bit 3` = reset-vN, `bit 4` = heartbeat-ack-capable, `bits 5-31` reserved-zero), little-endian integers, no padding.
- `plan.md:4085-4093`, `plan.md:4823-4831`: Requires complete normative test constant triples `(input, key, output)` pinning every single field value and HMAC key bytes for both dialer (`prover_role 0x01`) and acceptor (`prover_role 0x02`), leaving no unpinned fields for conforming implementations to diverge on.

---

### Q2 (v1 capability contract): SOUND
**File:Line Evidence:** `plan.md:3416-3422`, `plan.md:4008-4019`, `plan.md:4041-4049`, `plan.md:4140-4146`, `plan.md:4820-4823`, `plan.md:4836-4844`
- `plan.md:3416-3422`, `plan.md:4140-4146`: Clarifies that the HELLO capabilities word is **advertisement only** (selects transcript version and advertises candidate capabilities).
- `plan.md:4008-4019`, `plan.md:4041-4049`, `plan.md:4836-4844`: On any `v1-proof` connection, **every capability is disabled by default**. No capability (whether `reset-vN`, `repair-vN`, or identity enforcement) becomes active except via matching authenticated same-connection `CAPABILITY_CONFIRM` frames. All legacy phrases allowing capability activation without a same-connection `CONFIRM` have been explicitly superseded in v9.9.51.

---

### Q3 (convergence sweep): SOUND
**File:Line Evidence:** `plan.md:2819-2975` (§5.2), `plan.md:3927-3965` (§5.8)
- **Tuple release/reissue & SNAT swap:** `plan.md:2819-2975` enforces the `PortAllocator` migration gate (RW permits), stable allocation-slot indirection (`Arc` slot retargeting A→B atomically), and token-drop-free write spans with lock-free deferred release queues to prevent deadlocks and prevent tuple reissues or ghost allocations during config/rule reorders.
- **HA State Desynchronization & Blind RST/FIN demote:** `plan.md:3927-3965` mandates additive identity tails `(origin_process_nonce, flow_incarnation_id, stable_rule_id_hash, admission_config_version, persistent_nat, persistent_nat_permit)` on `INSTALL/Open` and `(origin_process_nonce, flow_incarnation_id)` on `DELETE`, together with capability-negotiated repair protocol bounds (`JOURNAL_END` / `JOURNAL_ACK` sequenced discharge).
- The combined mechanism in §5.2 and §5.8 fully covers all reachable failure modes in this issue class without residual hazards or deadlocks.

---

### New Traces Folded Open in v9.9.51
None. The stated mechanisms in v9.9.51 and v9.9.52 completely close all previously identified race conditions and specification gaps without opening new residual traces.
AGY EXIT: 0
