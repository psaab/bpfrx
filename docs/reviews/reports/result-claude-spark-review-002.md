# Triage result — claude-spark-review-002 (verified vs origin/master bf3c57a7f)

Reviewer auto-parsed 12 findings: 4 MATERIAL (all A1 Rust-dataplane u16 length
casts) + 8 NEG. Coordinator verification (this file) against origin/master tip:

## The 4 "MATERIAL" → LOW-MATERIALITY / defense-in-depth (unreachable-for-wrap)

All 4 casts EXIST on origin/master (symbol-exists gate ✓), NOT already-fixed —
but the real+material gate FAILS: the u16 truncation is unreachable in the
single-frame AF_XDP model.

1. checksum.rs:357 `checksum16_ipv4` `payload.len() as u16` (IPv4 pseudo-header
   length) — the payload is one frame's L4 segment. IPv4 `total_len` is itself a
   u16 (≤65535) → L4 segment ≤65515 < 65536 → `as u16` cannot wrap. NEG-material.
2. mod.rs:1631/1657/1712 `segment.len() as u16` (IPv4 pseudo-header for TCP/UDP
   checksum) — same IPv4-total_len u16 bound → cannot wrap. NEG-material.
3. inject.rs:73/142 `frame_len.min(u16::MAX) as u16` / `.min(u16::MAX as u32)` —
   this is a SATURATING cap, not a silent truncation; and frame_len ≤ the UMEM
   frame size (~2-9 KB) << 64K, so it never even saturates. NEG (defensive).
4. tcp.rs:578/615 SYN-cookie reply `total_len as u16` / `tcp_len as u16` — the
   reply is a crafted SYN-ACK (no payload, ~40-60 B). Cannot wrap. NEG-material.

Why unreachable: AF_XDP processes individual frames from the UMEM, each ≤ the
configured frame size (~2-9 KB); no single "payload"/"segment" reaches 64K. An
IPv6 jumbogram (RFC 2675, >64K) cannot fit a single ≤9 KB frame, and the
dataplane does not reassemble >64K datagrams. So NO input path delivers a >64K
length to these casts today.

Latent (defense-in-depth): if the UMEM frame size ever grows past 64K, or GRO
super-frames / IPv6-jumbogram reassembly are ever added, an unchecked `as u16`
would silently wrap a checksum/length field. Worth hardening pre-emptively (the
codebase already uses validated narrowing newtypes VlanId/TunnelTtl/QueueId/
InterfaceMtu for exactly this — extend the pattern to these length casts).
Filed as ONE low-materiality defense-in-depth cohort (below individual-file bar).

## The 8 NEG — confirmed genuine non-issues
host-inbound default-deny correctly enforced; IPv6 ext-header over-limit
fail-closed; flowless non-first-fragment policy enforced; CoS drain
slice_mut_unchecked guarded by explicit end>len; validated narrowing newtypes
prevent truncation; bdp_floor_bytes→0 documented acceptable; flow_bucket_pending
u32 saturation defensive; GRE decap ihl/tcp_len within bounds. No file.

## Outcome
0 individually-filed material; 1 low-materiality defense-in-depth cohort issue
(the 4 u16 length casts). Matches the reviewer's anticipated correct outcome.
