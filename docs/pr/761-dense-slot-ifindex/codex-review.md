**Verdict: PLAN-KILL as written.** Keep Stage 0 only as a measurement exercise, but do not approve Stage 1+ from this plan.

Findings:

1. **Cost-benefit is not defensible.** The plan admits only ~0.7-1.0% plausible CPU upside while `memmove`, RX polling, and #781-class AF_XDP stalls are an order of magnitude larger. A slot allocator plus HA invariants plus 5-map migration is too much risk for a non-bottleneck path.

2. **The savings model is stale.** The plan says `tx_ports` is `DEVMAP_HASH` and counts it as a hash removal, but the pinned tree has `tx_ports` as plain `BPF_MAP_TYPE_DEVMAP` already in [xpf_maps.h](/home/ps/git/bpfrx/.claude/worktrees/761-dense-slot-ifindex/bpf/headers/xpf_maps.h:376). #814 also makes “do not use DEVMAP_HASH” non-negotiable. So “4 hashes - 1 hash” is overstated.

3. **The plan omits `userspace_bindings`, the existing dense ifindex array problem.** #814 explicitly deferred slot indirection for `USERSPACE_BINDINGS` to #761, but this plan converts `userspace_ingress_ifaces` and leaves `userspace_bindings` indexed by `ifindex * 16` in [maps_sync.go](/home/ps/git/bpfrx/.claude/worktrees/761-dense-slot-ifindex/pkg/dataplane/userspace/maps_sync.go:520) and [lib.rs](/home/ps/git/bpfrx/.claude/worktrees/761-dense-slot-ifindex/userspace-xdp/src/lib.rs:392). That is an architectural miss.

4. **The proposed key type is invalid for ARRAY/DEVMAP.** The plan repeatedly says new key is `slot_id u16`. BPF array/devmap indexes must be 32-bit keys. `u16` can be cached in `pkt_meta`, but every lookup/redirect must use a bounded `u32`.

5. **Slot lifetime rules contradict HA/restart determinism.** “Sorted-by-name” compacts after removal; “non-recycling” preserves holes. Those cannot both be true across daemon restart or peer compile unless a persistent name-to-slot ledger with tombstones exists. The plan does not specify one.

6. **Update ordering is unsafe.** The plan says write `ifindex_to_slot` before hot-path maps. That publishes new slots before arrays/devmap/counters are populated, creating transient pass/drop/wrong-output behavior. This needs a real two-phase generation protocol, not a hand-waved guard.

7. **Memory math is wrong.** `iface_counter_value` is 32 bytes, not 16 bytes, in [xpf_common.h](/home/ps/git/bpfrx/.claude/worktrees/761-dense-slot-ifindex/bpf/headers/xpf_common.h:572). `256 * 64 * 32 = 512 KiB`, not 256 KiB, and not ~20 KiB.

8. **Stage 0 gate is too loose and under-specified.** `0.5%` CPU is below the refactor’s risk threshold, especially after adding one hash probe plus generation checks. I would require at least `1.0%` measured net CPU opportunity, or a demonstrated throughput/latency improvement, before any allocator work.

9. **MaxSlots=256 is not justified.** The code has `MAX_LOGICAL_INTERFACES=512`; userspace ingress includes VLAN children and parents. If this design survived, `512` or `1024` is safer, and the memory cost is still modest.

10. **#781 should win priority.** The documented `rx_xsk_buff_alloc_err` and `tx_xsk_full` evidence is far more operator-visible than shaving sub-1% hash overhead.

Recommended replacement: close this implementation plan, keep a narrow Stage 0 measurement note, and only reopen #761 if attribution proves a clearly net-positive target, including `userspace_bindings`, with a transaction-safe slot ledger design.

Codex session ID: 019df654-67d9-7201-a2a2-e5a0d8062642
Resume in Codex: codex resume 019df654-67d9-7201-a2a2-e5a0d8062642
