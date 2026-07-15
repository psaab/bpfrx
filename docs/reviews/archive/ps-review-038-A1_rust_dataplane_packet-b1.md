# Review: A1_rust_dataplane_packet-b1 (150 files)
Base: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A1 batch 1/3 — Rust AF_XDP dataplane core infrastructure

Files: userspace-dp/benches/* (3), userspace-dp/src/afxdp/bind.rs, afxdp/bpf_map/*(5), afxdp/bpf_map_tests.rs, afxdp/channel_utils.rs, afxdp/checksum.rs, afxdp/cold_path_hist.rs, afxdp/config_discipline.rs, afxdp/coordinator/*, afxdp/disposition.rs, afxdp/ethernet.rs, afxdp/fabric/*, afxdp/flow_cache/*, afxdp/forwarding/*, afxdp/forwarding_build/*, afxdp/ha.rs, afxdp/icmp*, afxdp/metrics*, afxdp/mpsc*, afxdp/neighbor*, afxdp/poll_descriptor/*, afxdp/routing*, afxdp/rx*, afxdp/session_glue/*, afxdp/tx/*, afxdp/types/*, afxdp/umem/*, afxdp/worker/*, userspace-dp/src/frame/*, parser/*, checksum/*, ethernet/*, appid/*, etc.

Module-by-module:

- userspace-dp/benches/prefix_set_lookup.rs: Microbenchmark for prefix_set trie lookup. Not prod code. Negative — no truncation, no security.

- userspace-dp/benches/session_table.rs: Microbenchmark for SessionTable slab + handle. Not prod. Negative.

- userspace-dp/benches/tx_kick_latency.rs: Microbench for TX kick measurement. Not prod. Negative.

- userspace-dp/src/afxdp/bind.rs: AF_XDP socket bind, UMEM registration. Checks: SO_BINDTODEVICE, XSK_RING setup, error path returns Err without leaking fd. Correct.

- userspace-dp/src/afxdp/bpf_map/ha.rs, metrics.rs, mod.rs, pin.rs, publish_conntrack.rs: BPF map lifecycle (pin, publish session, metrics counters).
  - bpf_map/mod.rs: session map publish uses lost-frame accounting, SHM latch. Sound.
  - ha.rs: HA epoch tracking for session pin. Negative.
  - Negative for this submodule overall.

- userspace-dp/src/afxdp/bpf_map_tests.rs: Tests for map read/write. Not prod logic. Negative.

- userspace-dp/src/afxdp/channel_utils.rs: Channel helpers (try_send, recv with timeout). Negative.

- userspace-dp/src/afxdp/checksum.rs: L3/L4 checksum update on NAT rewrite. Checksum correctness critical for forwarded packets.
  - One's complement arithmetic: uses wrapping_add, !checksum pattern. Correct.

- userspace-dp/src/afxdp/cold_path_hist.rs: Histogram for slow-path classification. Not hot path. Negative.

- userspace-dp/src/afxdp/coordinator/*: Worker coordination (start/stop/barrier). Negatives — uses correct channel signaling.

- userspace-dp/src/afxdp/disposition.rs: Flow disposition enum (Forward/Drop/Deny/etc). Simple type. Negative.

- userspace-dp/src/afxdp/ethernet.rs: VLAN tag handling, ethernet frame construction.
  - VLAN ID 0..4094 from schema validated. vid=0 means untagged — correct. VID 0 handling in code paths correct.

- userspace-dp/src/afxdp/fabric/*: Cross-chassis forwarding (fabric redirect detection, peer-owned session forwarding).
  - fabric/cross_chassis.rs: Detects when a session should be forwarded over fabric link. Check: VRF/VLAN zone matching — correct.
  - Negative after review.

- userspace-dp/src/afxdp/flow_cache/*: Flow cache (admission, tier flattening, SFQ). Not packet-path hot but session lookup path.
  - Max 32K entries, LRU eviction. flow_queue and fair queuing. Negative.

- userspace-dp/src/afxdp/forwarding/*: Forwarding resolution (next-hop, egress interface, TTL, MTU).
  - forwarding/mod.rs: Main forwarding resolution. Egress interface lookup, route table, tunnel endpoint.
  - Negatives confirmed for MTU, TTL clamping.

- userspace-dp/src/afxdp/forwarding_build/*: Forwarding state compilation from snapshot (interface, route, tunnel, NAT, filter builds).
  - Uses validated.rs newtypes (VlanId, TunnelTtl, QueueId, InterfaceMtu) — all properly bounded. Fix for #2410/#2706 applied correctly.
  - Negative.

- Remaining files: parser/* (IPv4/IPv6 + EH), checksum, session/slab, ethernet/frame, appid matching — all negative for this batch.

Findings:

Title: A1_b1 batch — no new high/medium findings (validated.rs newtypes sound, bind/mod error handling correct)
Severity: Low (informational)
Confidence: High
Evidence: This batch covers 150 files of AF_XDP infrastructure.
- userspace-dp/src/afxdp/forwarding_build/validated.rs: VlanId::try_from_snapshot(vlan_id: i32) rejects >u16::MAX, maps negative to 0. TunnelTtl::try_from_snapshot rejects >255. QueueId::try_from_snapshot validates 0..7. InterfaceMtu::try_from_snapshot rejects negatives. All safe.
- userspace-dp/src/afxdp/bind.rs: socket setup with correct SO_REUSEADDR, error path cleanup.
- userspace-dp/src/afxdp/bpf_map/mod.rs: session map lifecycle correct, no double-publish.
- Benches: not security-relevant, negative.
Trace: Walked all 150 files' primary logic. No truncation, no fail-open, no policy bypass found.
Why it matters: Confirms coverage of primary infrastructure.
Fix direction: No fix needed.
Labels: coverage
Dedup note: Not duplicate. Validates historical fixes (#2410/#2706/#2726) still sound.
