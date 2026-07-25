# AGY hostile plan review — round 11 — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only, scoped sections). Scope: plan v8.2. Transcript: .scratch/r11-agy-out1.txt (verbatim below).

---

### Defensive Firewall DoS-Hardening Design Review (Issue #6461, Plan v8.2)

#### Question (1): Emission Predicate & Packet-Driven Seed Sites
**Verdict: UNSOUND**
- **Evidence:** 
  - `userspace-dp/src/afxdp/session_glue/mod.rs:1100-1115` (`materialize_shared_session_hit`) and `userspace-dp/src/afxdp/shared_ops.rs:857-865` pass the triggering packet's `tcp_flags` into `upsert_synced_with_origin` and `install_with_protocol_with_origin`.
  - `userspace-dp/src/session/install.rs:179-180` & `L399-400` set `closing` and `reset` directly from `tcp_flags` at entry allocation time **before** pre-packet validation executes.
  - If an unvalidated/blind RST or FIN packet triggers materialize or reverse synth, the entry is seeded with sticky `closing=true` or `reset=true` (`marked=true`). When pre-packet validation subsequently refuses the packet, `marked` remains `true` for the lifetime of the entry.
  - Upon reap, the emission predicate `!is_reverse && !is_transient_seed && owner_gate && (locally_born || closing || reset)` evaluates `marked` to `true` and emits an authoritative Close delta for an unvalidated close, violating the mark rules.

---

#### Question (2): TTL Sweep & SNAT Pool-Port Release Path
**Verdict: UNSOUND**
- **Evidence:**
  - `userspace-dp/src/afxdp/worker/loop_body/mod.rs:1491-1506` releases SNAT/NAT64 pool port reservations (`release_source_nat_allocation` and `release_nat64_allocation`) at **worker entry reap** (`t = expires_after`).
  - For `expires_after = 86,400s` (24h) and $K \ge 4$, the shared alias lingers in the coordinator table until alias purge at $K \times \text{expires\_after}$ ($\ge 4$ days).
  - The SNAT pool port is freed ~3 days before the alias is purged and can be reallocated to a new, unrelated session. If a packet matches the lingering alias during this 3-day window, `materialize_shared_session_hit` (`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1118`) rematerializes the dead session, creating a stale-alias port collision and traffic misdirection hazard.

---

#### Question (3): Plan-Text Contradictions (v8.2 vs Leftover Text)
**Verdict: UNSOUND**
- **Evidence:**
  - `docs/research/6461-blind-rst/plan.md:648-653` (§5.2 rule 5) specifies the normative v8.2 delta gate predicate as `!is_reverse && !is_transient_seed && owner_gate && (locally_born || marked)`.
  - `docs/research/6461-blind-rst/plan.md:1148-1151` (§7 Close authority bullet) omits `&& (locally_born || marked)` from the delta gate formula.
  - `docs/research/6461-blind-rst/plan.md:1173-1175` (§7) retains leftover v7/v8 text stating the gate relies on `non-peer-synced` origin checks rather than owner-RG and sticky mark state.
  - `docs/research/6461-blind-rst/plan.md:642` (§5.2) states `SharedPromote` emits a Close delta "at ANY expiry, marked or not", contradicting the line 653 requirement that `marked` must be set for non-locally-born entries.
