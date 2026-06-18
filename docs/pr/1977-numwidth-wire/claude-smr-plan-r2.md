# Claude SMR — #1977 NUM_WIDTH plan review, round 2

**Verdict: PLAN-READY.**

v2 folds every r1 finding, and I verified the two load-bearing items myself:

- **Chokepoint (r1):** `buildFlowSnapshot`/`buildFlowExportSnapshot` are the sole
  pre-wire constructor (called only from `buildSnapshot`), so Layer A covers all
  input paths. Confirmed by Codex r1 #6 + AGY r1 + me.
- **Inventory completeness (r2, Q1):** the two missed fields (`TCPMSSAllTCP`,
  `SamplingRate`) are folded → 11. I cross-checked ALL other request-side `int`
  json fields: topology/NAT/CoS use Rust **signed** types (`vlan_id`/`mtu`/
  `ttl`/`ifindex`/`parent_ifindex`/`queue` = `i32`, NAT timeouts `i64`); the only
  other unsigned request-side field is `address_count: usize`, a builder-computed
  count that is never negative/out-of-range. ⇒ 11 is the complete
  reachable-FATAL set.
- **Overflow cap (Codex r1 #3):** session timeouts capped at `MaxDurationSeconds`
  (= `MaxInt64/1e9` ≈ 9.2e9) — `× 1e9` stays within u64, so Rust
  `from_seconds`'s unchecked multiply is safe. Correct.
- **SamplingRate:** reachable via `inst.InputRate` (flow.go:56); Layer A caps
  `>u32max` and keeps `<=0→1`. Correct.
- **Layer B deferred:** sound — the target schema nodes are `children: nil`, so
  commit-time validation needs a separate schema-expansion design; Layer A alone
  closes the safety hole on all paths. Layer B is operator UX, tracked as a
  follow-up.

Coercion semantics are safe fail-open (MSS→0 incl GRE-out-0⇒MTU-derived; port
skip-and-continue; u32/u64 caps). Ship Layer A.
