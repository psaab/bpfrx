---
status: PLAN-KILLED — both reviewers concur (Codex PLAN-KILL, Gemini Pro 3 PLAN-KILL); plan v1 retained verbatim below for traceability
issue: https://github.com/psaab/xpf/issues/761
phase: Dense-slot indirection for ifindex-keyed hot-path BPF maps
---

## KILL decision (2026-05-05)

Plan v1 reviewed by Codex (`task-mos41ah2-rf9s8j`) and Gemini
Pro 3 (`task-mos41n65-19lsvd`). Both verdicts saved verbatim
in `codex-review.md` + `gemini-review.md`. Converging
findings:

1. **Fatal slot-instability flaw (Gemini #3)**: the proposed
   "sorted-by-name" non-recycling slot derivation contradicts
   itself. If the live interface set is `[eth1, eth2]` (slots
   0,1) and the operator adds VLAN `eth1.5`, the sorted list
   becomes `[eth1, eth1.5, eth2]` — `eth2`'s slot shifts from
   1 → 2, instantly misrouting traffic AND invalidating all
   existing data-plane state for `eth2` on both HA nodes.
   Slot IDs must be monotonic and immutable; the plan's
   derivation isn't.

2. **Cost-benefit wrong (Codex #1, Gemini #1)**: ~0.7-1.0 %
   plausible CPU savings on a non-bottleneck path while
   `__memmove_evex_unaligned_erms` (13.43 %, #776) and
   `poll_binding_process_descriptor` (9.45 %, #777) are an
   order of magnitude bigger. #781's structural pipeline
   stall is also much higher upside.

3. **`tx_ports` already DEVMAP, not DEVMAP_HASH (Codex #2)**:
   the plan assumed DEVMAP_HASH and counted it as one of the
   "4 hashes per packet". Reality at
   `bpf/headers/xpf_maps.h:376` shows `BPF_MAP_TYPE_DEVMAP`.
   #814 also explicitly bans DEVMAP_HASH. So the savings
   model overcounts.

4. **Plan misses `userspace_bindings` (Codex #3)**: #814
   explicitly deferred slot indirection for
   `USERSPACE_BINDINGS` (currently indexed by `ifindex × 16`
   in `pkg/dataplane/userspace/maps_sync.go:520` +
   `userspace-xdp/src/lib.rs:392`) to #761 — but the plan
   doesn't address it. Architectural miss.

5. **u16 keys invalid for ARRAY/DEVMAP (Codex #4)**: BPF
   array/devmap indexes must be 32-bit. The plan says
   `slot_id u16` repeatedly. `pkt_meta` can cache u16 but
   every map lookup needs u32.

6. **Update ordering unsafe (Codex #6)**: writing
   `ifindex_to_slot` before populating the hot-path maps
   creates a transient window where new slots resolve to
   empty arrays/devmap entries → pass/drop/wrong-output
   behavior. Needs a real two-phase generation protocol.

7. **Memory math wrong (Codex #7)**: `iface_counter_value` is
   32 bytes (not 16 as the plan said). At MaxSlots=256, CPUs=64
   the PERCPU_ARRAY is 512 KiB, not 256 KiB. Still acceptable
   but the plan's numbers are wrong.

8. **MaxSlots=256 too small (Codex #9, Gemini #6)**: codebase
   has `MAX_LOGICAL_INTERFACES = 512` and userspace ingress
   includes VLAN children + parents. With non-recycling and
   high churn (container veth, dynamic tunnels, frequent
   config reloads), 256 exhausts quickly. Should be ≥ 1024.

9. **Stage 0 gate too loose (Codex #8, Gemini #4)**: 0.5 % is
   within measurement noise. Codex wants ≥ 1 %; Gemini wants
   3-5 % for a refactor of this magnitude.

10. **Net savings model unrealistic (Gemini #5)**: replacing
    5 HASH probes with 1 HASH + 4 ARRAY probes keeps the
    `bpf_map_lookup_elem` helper-call overhead. At small
    interface counts the HASH probes are L1d-hot zero-collision.
    Add `pkt_meta` reads/writes for slot caching + slot_generation
    branch and the net could be zero or negative.

### Decision

Plan v1 killed. Per the project's KILL discipline:

- Plan doc retained verbatim (this file) so future readers
  see the rejected v1 and the kill rationale.
- Both reviewer reports filed in this directory.
- Issue #761 closed-as-killed with a comment summarizing the
  findings.
- If #761 is ever revisited, prerequisites (per Codex
  recommendation):
  - Stage-0 measurement showing ≥ 1.0 % NET CPU opportunity
    (after counting the new ifindex_to_slot probe + slot_generation
    guard cost).
  - Include `userspace_bindings` (deferred from #814) in scope.
  - Use a transaction-safe persistent slot ledger (name → slot
    with tombstones), NOT sorted-by-name derivation.
  - Two-phase generation protocol for cross-node update.
  - u32 keys in BPF map definitions.

(Plan v1 follows verbatim below.)

---

## 1. Issue framing

PR #759 (fix for #756) converted 5 ifindex-keyed BPF maps from
`ARRAY` (sized `MAX_INTERFACES = 1024`) to `HASH` /
`DEVMAP_HASH` to handle long-lived VMs where kernel ifindex
grows past 1024:

- `tx_ports` (DEVMAP_HASH, redirect target lookup)
- `redirect_capable` (HASH, native-XDP gate)
- `mirror_config` (HASH, mirror per-interface)
- `interface_counters` (PERCPU_HASH, RX/TX byte counter)
- `userspace_ingress_ifaces` (HASH, the userspace-XDP ingress
  gate)

The conversion fixed the overrun bug, but every per-packet
hot-path now hashes on these maps instead of doing O(1) array
indexing. #761 proposes a **slot-id indirection**: assign a
dense `u16` slot to each registered ifindex, look it up once
on a small hash map (`ifindex_to_slot`), then keep the
hot-path maps as ARRAYs keyed by slot.

The issue explicitly says **"measure first"**.

## 2. Honest scope/value framing

### Measurement

Fresh perf data on master HEAD `b029e91c` under sustained
P=12 -R iperf3 load:

- **`htab_map_hash` aggregate: 1.42 % of CPU**
  (call-graph rooted at the XDP redirect program
  `bpf_prog_006786fd3dd58763_F` → `__htab_map_lookup_elem` →
  `htab_map_hash`)

The XDP program references 14 maps total; of those 5 are
ifindex-keyed HASH (the #761 targets):

| Map | Type | Purpose |
|---|---|---|
| `userspace_ingress_ifaces` | HASH | XDP ingress gate (per-packet) |
| `redirect_capable` | HASH | Native-XDP redirect gate (per-packet) |
| `mirror_config` | HASH | Mirror per-interface (per-packet, mostly miss) |
| `interface_counters` | PERCPU_HASH | RX/TX byte counter (per-packet) |
| `tx_ports` | DEVMAP_HASH | Redirect target lookup (per-packet) |

Other hash maps in the same XDP program — `userspace_session`,
`userspace_trace`, `dnat_table` — are NOT ifindex-keyed and
would NOT benefit from slot indirection. So the 1.42 %
aggregate splits between the 5 ifindex maps and the 3 other
hash maps. **Plausible upper bound on #761's savings: ~0.7-1.0
% of CPU**.

### Value

At ~1 % CPU saved on a path that's not the dominant bottleneck
(`__memmove_evex_unaligned_erms = 13.43 %` is 10× bigger;
`poll_binding_process_descriptor = 9.45 %` is 9× bigger), this
is a small win. Triple-review on this plan should be open to
PLAN-KILL if reviewers think the refactor cost (slot allocator,
HA failover persistence, BPF + Go restructure) outweighs the
~0.7-1.0 % savings.

The case **for** doing #761:
- DEVMAP_HASH is known to be slower than DEVMAP for redirects
  (ARRAY-style). The savings could be larger than 1 % if the
  current measurement underestimates because of NUMA / cache
  effects.
- Slot indirection is a one-time refactor; the hot-path stays
  ARRAY-keyed forever after.
- The slot allocator pattern is reusable for future ifindex-keyed
  hot-path maps.

The case **against**:
- 1 % savings on a path that's CURRENTLY meeting the
  ≥22 Gbps gate is marginal.
- The slot allocator is non-trivial: must persist across
  daemon restart, survive HA failover, handle interface
  rename, recycle freed slots.
- Real risk of slot/ifindex consistency bugs (slot 5 maps to
  the wrong ifindex after a recycle, redirects go to the
  wrong NIC).
- `interface_counters` is PERCPU_HASH; converting to
  PERCPU_ARRAY changes its memory model (per-CPU per-slot
  array → fixed memory cost regardless of how many interfaces
  are registered).

If reviewers conclude the upside isn't worth the refactor
risk, **PLAN-KILL is acceptable** — close #761 with the
measurement evidence as the rationale.

## 3. What's already shipped / partially batched

- PR #759 already established that the maps work as HASH /
  DEVMAP_HASH; the unit-test surface for sparse-ifindex
  correctness exists.
- The Rust userspace-XDP program (`xdp_userspace_p`) and the
  Go-side eBPF program (`xpf_xdp.o`) both reference these
  maps; #761 has to update both.
- No prior slot-id or interface-registration abstraction
  exists in the daemon. We'd be introducing a new control-
  plane concept.

## 4. Concrete design — STAGED

### Stage 0: precise per-map attribution (DO THIS FIRST)

Before writing any production code, measure exactly how much
of the 1.42 % aggregate `htab_map_hash` comes from each of the
5 ifindex-keyed maps vs the 3 non-ifindex hash maps. Methods:

- Option A: `bpftool prog profile id <prog_id> duration 30
  cycles` per-program — gives BPF-level instruction sample
  attribution.
- Option B: kernel tracepoints `bpf:bpf_map_lookup_elem`
  filtered by map_id, count over a 30 s sustained iperf3 run.
- Option C: temporary code-mod to add `bpf_printk` (or
  `bpf_get_ktime` deltas) around the map lookups in a
  development build, exec measure, revert.

Output: precise per-map µs/packet breakdown. **PLAN-KILL gate**:
if the 5 ifindex maps collectively account for < 0.5 % of CPU,
close #761 NEEDS-NO-FIX. If ≥ 0.5 %, proceed to Stage 1.

### Stage 1: slot-id allocator (Go control plane)

Add to `pkg/dataplane/`:

```go
// SlotAllocator assigns dense [0, MaxSlots) IDs to ifindex.
// Persists across daemon restart via the existing config
// store. Survives HA failover by re-deriving from the active
// config (slot N = position of ifindex in the sorted list of
// registered interfaces). NOT recycled within the daemon's
// lifetime — slot is freed only when the interface is removed
// from config; if the same ifindex re-appears later, it gets
// the next free slot, not the old one.
type SlotAllocator struct {
    mu    sync.Mutex
    slots map[int32]uint16  // ifindex → slot
    next  uint16
}
const MaxSlots = 256  // 4× current 64 typical iface count
```

Lookup ordering:
- Compile time: walk InterfaceConfig in sorted-by-name order;
  assign slots 0..N-1.
- Runtime: control plane writes `ifindex_to_slot` map entries
  before any hot-path map. A new BPF helper
  `cos_iface_slot_lookup(ifindex)` does the one hash probe
  per packet and caches via `pkt_meta->iface_slot` u16 field
  for downstream stages.

### Stage 2: convert hot-path maps from HASH to ARRAY

Five maps to convert in `bpf/headers/xpf_maps.h`:

| Map | Old type | New type | New key | Memory delta |
|---|---|---|---|---|
| `userspace_ingress_ifaces` | HASH | ARRAY | `slot_id u16` | +0 (was already 1024-sized) |
| `redirect_capable` | HASH | ARRAY | `slot_id u16` | +0 |
| `mirror_config` | HASH | ARRAY | `slot_id u16` | +0 |
| `interface_counters` | PERCPU_HASH | PERCPU_ARRAY | `slot_id u16` | +(MaxSlots × CPUs × 16B) ≈ +20 KB |
| `tx_ports` | DEVMAP_HASH | DEVMAP | `slot_id u16` | +0 |

Plus one new map:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_INTERFACES);  // sparse ifindex
    __type(key, __u32);                   // ifindex
    __type(value, __u16);                 // slot_id
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ifindex_to_slot SEC(".maps");
```

### Stage 3: BPF callsite migration

Each of `inc_iface_rx/tx`, `bpf_redirect_map(&tx_ports, ...)`,
`redirect_capable` gate, `mirror_config` check,
`USERSPACE_INGRESS_IFACES` lookup needs to:

1. Look up slot from ifindex via `ifindex_to_slot` (one HASH
   hit per packet, O(1) thereafter).
2. Cache slot in `pkt_meta->iface_slot` so subsequent stages
   reuse without re-lookup.
3. Use the ARRAY map with the cached slot.

The slot lookup itself is a single `htab_map_hash` call —
~1 in, ≥4 out per packet. **Net savings = 4 hashes - 1 hash
= 3 hashes per packet ≈ 0.5-1.0 % CPU** (matches the
measurement upper bound).

### Stage 4: HA failover + persistence

Slot IDs must be **deterministic** across daemon restart and
HA peer compile. Approach: derive slot from the
config-compile-time sorted-by-name order. If both nodes
compile the same config, they derive the same slot map.
Slot drift on config change: tracked via a `slot_generation`
u32 in the iface_zone_map (existing pattern from
`fib_gen_map`); BPF programs check generation before trusting
cached slots.

### Stage 5: tests

- BPF verifier acceptance on `make generate`.
- Go `pkg/dataplane/slot_allocator_test.go`: deterministic
  assignment, cross-restart consistency, max-slot overflow.
- Per-map regression tests: existing `tx_ports` /
  `redirect_capable` etc. unit tests must pass against the
  ARRAY-keyed variants.
- Smoke matrix per `triple-review` SKILL.md.
- A/B perf measurement: pre-#761 master vs. branch with
  perf-stat-cycle counters showing the absolute reduction in
  `htab_map_hash` time.

## 5. Public API preservation

- No public-API method signatures change.
- `bpftool map show` will display different map types — the
  control-socket / status surfaces that introspect maps need
  to handle ARRAY entries instead of HASH entries.
- Snapshot format unchanged — slot IDs are derived, not
  serialized.

## 6. Hidden invariants the change must preserve

- **ARRAY index ranges**: slot must be `< MaxSlots`. Verifier
  needs explicit `slot < MaxSlots` bounds check on every
  lookup. Mask via `slot & (MaxSlots - 1)` if MaxSlots is a
  power of 2 (we'd pick 256 = 2⁸).
- **Slot/ifindex consistency**: a stale slot that points at
  the wrong ifindex after a recycle would silently misroute
  redirects. The `slot_generation` check is the safety net.
- **Deploy wipes CoS / restart consistency**: deploys restart
  the daemon. Slots must re-derive identically. The
  sorted-by-name approach gives this.
- **HA peer compile**: both nodes must agree on slot
  assignments for cross-binding state to make sense. Same
  fix as restart.
- **PERCPU_HASH → PERCPU_ARRAY memory growth**: from
  1024 entries × CPUs to MaxSlots × CPUs. With MaxSlots=256,
  CPUs=64, value=16 B → 256 KB per snapshot. Acceptable.

## 7. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | **MED** | Slot recycling bugs would silently misroute redirects to the wrong NIC. Mitigation: slot_generation guard + comprehensive A/B regression tests. |
| Lifetime / borrow-checker | **LOW** | Plain control-plane allocator + BPF map indirection. |
| Performance regression | **LOW** | Stage 0 measurement gates whether this proceeds at all. If the upper bound is < 0.5 % CPU, we close NEEDS-NO-FIX. If ≥ 0.5 %, the slot lookup adds ONE hash probe but removes ≥4 — net positive. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **MED** | Slot indirection IS a real well-known pattern (Linux netdev uses an ifindex→ndo→port mapping internally), so it maps to the codebase reality. But the cost-benefit ratio is the question — a refactor with 1 % savings on a not-currently-bottleneck path may be over-engineering. |
| HA / cross-restart consistency | **MED** | Slot derivation must be byte-identical across nodes and restarts. Fix shape is "sorted by name" → tested via deterministic-assignment unit tests. Not free though. |

## 8. Test plan

### Stage 0 (gating measurement)

- `bpftool prog profile id <xdp_userspace_p_id> duration 30
  cycles` on a sustained P=12 -R iperf3 run. Output:
  per-instruction sample distribution.
- Expected: count cycles attributable to map_lookup helper
  calls for the 5 ifindex-keyed map ids.
- **Gate**: if cumulative cycles for the 5 ifindex maps >
  0.5 % of total program cycles, proceed; else close
  NEEDS-NO-FIX.

### Stages 1-4 (only if Stage 0 gate passes)

- `make generate` clean.
- `cargo build --release` clean.
- `cargo test --release` 974+ pass.
- New tests:
  - `pkg/dataplane/slot_allocator_test.go`:
    `TestSlotAllocatorDeterministicAssignment` — same config
    in → same slot map out.
  - `TestSlotAllocatorRestartConsistency` — destroy + recreate
    allocator from same config → identical slot map.
  - `TestSlotAllocatorMaxSlotsOverflow` — registering 257
    interfaces with MaxSlots=256 → error.
  - BPF unit tests via `cilium/ebpf` map RW for each converted
    map — confirm slot-keyed access works.
- Smoke matrix Pass A + Pass B 30 measurements (CoS-disabled
  + per-class CoS).
- A/B perf comparison:
  - Pre-#761 baseline: capture `htab_map_hash` cost via
    `perf record -F 99 -a -g sleep 30` during P=12 -R.
  - Post-#761: same measurement, expect proportional drop.
  - Acceptance: cumulative `htab_map_hash` cost drops by ≥
    50 % of the Stage 0 measured ifindex-map share.

## 9. Out of scope (explicitly)

- Conntrack session table (not ifindex-keyed; HASH stays).
- DNAT table (HASH stays).
- App-id / forwarding-class / scheduler-map config maps —
  not on the per-packet hot path.
- DPDK pipeline parity — the DPDK CoS path doesn't share
  these maps; #761 is userspace-dp only.
- Slot recycling within the daemon's lifetime — slots only
  freed on interface removal from config; re-added ifindex
  gets a fresh slot.

## 10. Open questions for adversarial review

1. **Operator value**: is ~1 % CPU on a not-currently-bottleneck
   path worth the refactor cost (slot allocator, HA persistence,
   BPF + Go callsite audit, regression risk)? PLAN-KILL is
   acceptable if reviewers think no.
2. **Stage 0 gate threshold**: plan picks 0.5 % CPU as the
   minimum-to-proceed threshold. Reviewers may want it tighter
   (1 %) or looser (0.2 %).
3. **MaxSlots = 256**: rationale = 4× typical iface count
   (~64). Reviewers may want 1024 (matches old MAX_INTERFACES
   for memory-equivalence) or 128 (tighter cap).
4. **Slot recycling**: plan picks "never recycle within
   lifetime, slot freed only on interface removal". Reviewers
   may want active recycling on interface removal +
   re-add. Recycling adds the slot-stale-pointer hazard the
   current proposal avoids.
5. **Stage 0 method**: proposed `bpftool prog profile`. Could
   also use BPF tracepoints or modified-build instrumentation.
   Reviewers may push for a particular approach.
6. **Slot generation guard cost**: every BPF map lookup gains
   a `slot_generation` check. Adds 1 array load + 1 compare per
   packet. ~2 ns. Eats into the savings.
7. **Cache effects**: HASH probes hit the same memory
   repeatedly (working-set fits in L1d). ARRAY accesses are
   strictly stride-1 by slot, also L1d-friendly. The savings
   may be smaller than the htab_map_hash drop alone — depends
   on whether the HASH probes are pulling in extra cache lines
   for collision chains.
8. **Relationship to #781**: #781's structural pipeline stall
   (rx_xsk_buff_alloc_err, tx_xsk_full) dwarfs this 1 %.
   Should reviewers prioritize #781 over #761?
