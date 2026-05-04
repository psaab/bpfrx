# #964 Step 3 — Cache-line pack `SessionEntry`

Status: **KILLED v2 — Codex round-2 PLAN-KILL + Gemini round-2 PLAN-KILL (both converged)**

## Why this plan was killed

Round 2 saw both reviewers independently return PLAN-KILL after
v2's honest accounting laid out the real cost/benefit:

- **Codex** (task-moqlf19v-ywqnp5): caught that v2 incompletely
  removed ifindex-narrowing references (still cited in v2 body
  at 3 spots), the size target is missed by v2's own estimate
  (130 vs target ≤128), `Some(0)` port handling "silently drop
  rewrite in release" recreates the collision, MAC zero
  sentinel needs an audit of intentional `[0; 6]` uses in
  tunnel/egress code paths, and event-stream ifindex round-trip
  isn't value-preserving for full i32 because the wire format
  already casts to i16. **Verdict**: kill unless there's a
  committed memory-constrained deployment requirement.

- **Gemini** (task-moqlfgnj-cl5738): flipped from v1 PLAN-READY
  to PLAN-KILL after the honest accounting. Memory savings
  7-94 MB are "non-trivial but small compared to typical
  ~500 MB RSS." CPU cost ~25ns slow-path overhead plausibly
  erases ~half of Step 1's reverse-NAT win. 30+ callsite churn
  for marginal gains.

### The methodology working as designed

This is the second PLAN-KILL outcome from the /triple-review
methodology (after #946 Phase 2 — same framing: a plausible-
sounding refactor whose honest accounting doesn't justify the
work). The methodology is doing its job:

1. v1 had inflated memory savings (16 MB claim) and missed
   sentinel collision audits.
2. v2 corrected the math (7-94 MB realistic) and added the
   audits, which surfaced the actual costs.
3. Both reviewers, given the honest accounting, agreed the
   gain doesn't justify the work.

Killing at v2 (~6 hours of plan iteration) is much cheaper
than discovering this after a 1500-LOC PR + 5 rounds of code
review.

### Recommendation for #964 going forward

#964 has 4 stated goals (slab, integer handles, intrusive
indices, cache-line packing). Step 1 (slab + integer handles)
shipped as PR #1182 with 2.2× faster reverse-NAT lookup +
~40% memory reduction at full table.

- **Step 2** (intrusive `next_node` indices) is the natural
  remaining increment. Builds on Step 1's slab.
- **Step 3** (cache-line packing) is hereby PLAN-KILLED with
  this v2.
- **Step 4** (was Step 4 in the issue): subsumed into
  Step 1's cache-locality wins (records already contiguous).

Issue #964 should be closed once Step 2 ships; Step 3 will be
rejected at the v2 PLAN-KILL.

---

## Original v1 plan body retained for the record

## v2 changes (Codex round-1 findings)

### 1. ifindex narrowing DROPPED entirely

Codex caught: i16 max is 32767, NOT 65535 (the plan v1 said
"i16 max ~65535"). Saturating ifindex is silent forwarding
corruption. xpf already uses i32 ifindexes throughout
(forwarding.rs:197) and they feed real TX/egress paths.

**v2 keeps `ifindex: i32`** for all 5 ifindex fields
(local_ifindex, egress_ifindex, tx_ifindex, fib_ifindex,
*plus session_glue's ingress/egress_ifindex). The 10 bytes
v1 claimed to save are gone.

Updated SessionEntry size estimate: ~120 → ~130 bytes
(still 2 cache lines).

### 2. HA wire-format premise corrected

Codex caught: `SessionDelta` is NOT directly serde-serialized.
The wire path uses two distinct codecs:
- **JSON status export** (`session_delta.rs:59`) via
  `SessionDeltaInfo` — already converts ports/MACs/ifindexes
  to its own representation.
- **Event stream binary codec** (`event_stream/codec.rs:59`)
  — has its own sentinel conventions: NAT ports `0`, MACs
  zero-filled, ifindexes cast to `i16` (codec.rs:89).

This means the HA wire format ALREADY uses the same sentinel
conventions v1 proposed for the slab! The packed slab type
just needs to encode/decode unambiguously to/from these
existing wire formats, not to/from a fictional direct serde
roundtrip.

v2 mandatory test additions:
- `unpacked SessionDecision → packed slab → unpacked → SessionDeltaInfo (JSON)` round-trip.
- `unpacked SessionDecision → packed slab → unpacked → event_stream codec → unpacked` round-trip.
- HA sync import (`upsert_synced_with_origin`) round-trip.

### 3. Sentinel port=0 collision: ICMP

Codex caught: ports use 0 legitimately for ICMP tuple shape
(`frame/inspect.rs:225`). `NatDecision` is protocol-agnostic;
a `Some(0)` rewrite_*_port for an ICMP session would map to
None under the v1 sentinel scheme.

v2 strategy: **reject `Some(0)` at PackedNatDecision
construction**, with an explicit `From<NatDecision>` that
asserts (debug) and treats `Some(0)` as an error case (in
release: silently drop the rewrite). NAT pool allocator
already avoids port 0 for TCP/UDP (`nat.rs:200`); ICMP
sessions don't have rewrite_*_port set.

Document the invariant: "PackedNatDecision MUST NOT carry a
zero port as Some(0); NAT slot allocators are responsible for
allocating non-zero ports for TCP/UDP, and ICMP sessions
leave rewrite_*_port unset."

### 4. MAC zero sentinel: explicit normalization on import

Codex caught: Rust JSON/session-sync parsing accepts
`"00:00:00:00:00:00"` as `Some([0;6])` (`helpers.rs:234`).

v2 strategy: **normalize all-zero MAC to None at import**.
Add explicit normalization in `helpers.rs::deserialize_mac`:
all-zero bytes → `None`, all other patterns → `Some(...)`.
This silently drops zero-MAC packets from peer imports, but
that's already a corrupt input — a real MAC is never
00:00:00:00:00:00.

### 5. Public API materialization for iterators

Codex caught: `iter_with_origin` passes `&SessionMetadata`
(by reference). v1 plan said "From conversions preserve all
30+ callsites" but didn't say HOW for ref-passing iterators.

v2 explicit pattern:
```rust
pub fn iter_with_origin(&self, mut f: impl FnMut(&SessionKey,
    SessionDecision, &SessionMetadata, SessionOrigin)) {
    for (key, handle) in &self.key_to_handle {
        if let Some(record) = self.entries.get(*handle as usize) {
            // Materialize a local unpacked metadata for the
            // callback — its lifetime is bounded by the loop body.
            let unpacked_metadata: SessionMetadata =
                record.entry.metadata.clone().into();
            let unpacked_decision: SessionDecision =
                record.entry.decision.into();
            f(key, unpacked_decision, &unpacked_metadata,
              record.entry.origin.into());
        }
    }
}
```

This adds a clone+pack-roundtrip per iteration, but iterators
are slow-path (status export, HA sync, GC).

### 6. RSS model honest re-estimation

Codex caught: 16 MB savings only show up at full table; HA
shared maps store unpacked `SyncedSessionEntry`, sometimes
cloned into multiple indices (`shared_ops.rs:621`).

Honest v2 RSS estimate:
- **Per-worker SessionTable slab**: N workers × 131072 ×
  120 bytes saved = N × 15.7 MB.
- **HA shared maps**: unchanged (stay unpacked).
- **Default deployment**: 6 workers (per `bpfrxd` config) →
  ~94 MB total savings AT FULL TABLE on a 6-worker deployment.

If sessions don't fill (typical deployment loads <10K
concurrent sessions per worker), savings scale down
proportionally: ~10K × 6 workers × 120 bytes = ~7 MB savings.

**Realistic scale of memory win: 7-94 MB depending on load.**
This is small compared to xpfd's typical RSS (~500 MB) but
non-trivial on memory-constrained deployments.

### Net effect of v2 changes

The sum of v2's corrections:
- Drops ifindex narrowing → loses 10 bytes/entry → packed
  size goes from 120 → 130 bytes.
- Adds explicit sentinel rejection in From conversions →
  ~5ns extra pack/unpack cost.
- Adds 3 mandatory round-trip tests → catches sentinel bugs
  pre-merge.

If reviewers conclude the realistic 7-94 MB memory win still
doesn't justify the churn (touching 30+ callsites + 5ns
extra pack/unpack on top of the original 10-20ns), **v2
remains a PLAN-KILL candidate.**

## Issue framing

#964's Step 3 goal: "A `SessionEntry` should fit inside 1-2 cache
lines (64-128 bytes) and contain everything needed to make a
forwarding decision without secondary pointer-chasing."

The issue's stated cache-line goal is **64-128 bytes**, NOT
"≤64 bytes." A 1-cache-line target (64 bytes) is unrealistic
given the data SessionEntry must carry; a 1-2 cache-line
target (≤128 bytes) is realistic with packing.

## Honest scope/value framing

This is the most speculative #964 step. The honest framing:

- **L1d cache-line argument is weak.** L1d is 32-48 KB per core
  on modern x86; 131072 sessions × 256 bytes/session = 32 MB —
  already orders of magnitude beyond L1d. The "fit in 1-2
  cache lines" goal helps **prefetcher efficiency on linear
  walks** (GC, iter), not working-set fit.
- **#965 wheel made GC O(1)**, so the linear walk over the
  session map went away. The prefetcher win is only on
  bench-style stress (full-table iter, e.g. drain_deltas
  bulk).
- **Memory pressure** is real for high-session-count
  deployments. Halving SessionEntry's footprint at 1M sessions
  saves ~100 MB, which matters on memory-constrained edge
  devices.
- **No fast-path benefit.** Flow-cache hits bypass
  SessionTable on session-hit ACK packets.
- The session table is **already in slab storage** post-Step 1
  (PR #1182), so each `SessionRecord` is contiguous —
  prefetching adjacent records is already cheap. The
  remaining win is per-record size reduction.

If the reviewers conclude the perf gain is too small to justify
the churn, **PLAN-KILL is an acceptable verdict.** This step's
primary value is memory pressure relief at high session counts;
if that's not a real concern for this codebase's deployments,
the plan should be killed.

## Current `SessionEntry` size

Estimated layout (Rust 1.83 default repr, 64-bit x86_64):

| Field | Type | Size |
|-------|------|------|
| `decision: SessionDecision` | (see below) | ~140 |
| `metadata: SessionMetadata` | (see below) | ~50 |
| `origin: SessionOrigin` | enum (1 byte + padding) | 8 |
| `install_epoch: u64` | | 8 |
| `last_seen_ns: u64` | | 8 |
| `expires_after_ns: u64` | | 8 |
| `closing: bool` | | 1 + 7 pad |
| `wheel_tick: u64` | | 8 |
| **Total** (with padding) | | **~240 bytes** |

`SessionDecision = ForwardingResolution + NatDecision`:

ForwardingResolution (~80 bytes):
- disposition: enum (1 byte + 3 pad)
- local_ifindex / egress_ifindex / tx_ifindex: 3× i32 (12)
- tunnel_endpoint_id: u16 + 6 pad
- next_hop: Option<IpAddr> (32 bytes — IpAddr is 24-byte enum + 1 tag + padding)
- neighbor_mac: Option<[u8;6]> (~8)
- src_mac: Option<[u8;6]> (~8)
- tx_vlan_id: u16 + 6 pad

NatDecision (~80 bytes):
- rewrite_src: Option<IpAddr> (32)
- rewrite_dst: Option<IpAddr> (32)
- rewrite_src_port: Option<u16> (4)
- rewrite_dst_port: Option<u16> (4)
- nat64: bool (1)
- nptv6: bool (1) + padding to 80

So a single `SessionEntry` is ~240 bytes — **3-4 cache lines**.
The `SessionRecord { key, entry }` is ~290 bytes total.

## Step 3 design — packing tactics

The compact representation reduces SessionEntry to **~120 bytes**
(2 cache lines), achievable without complex bit-packing tricks:

### 1. Pack `Option<IpAddr>` → `PackedIp`

`IpAddr` is 24 bytes (Ipv6 size + tag) + Option = 32 bytes. A
custom enum `PackedIp { None, V4(Ipv4Addr), V6(Ipv6Addr) }`
with `repr(C)` would be 17 bytes (16-byte v6 + 1-byte tag),
padded to 20-24. Better: store as `[u8; 16]` with a separate
`family: u8` (None=0, V4=1, V6=2) — total 17 bytes, padded to
24. Or even better:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct PackedIp {
    /// IPv6: full 16 bytes. IPv4: bytes [0..4] hold v4 address,
    /// remaining bytes are zero. None: all bytes zero AND family=0.
    pub(crate) bytes: [u8; 16],
    /// 0 = None, 4 = IPv4, 6 = IPv6.
    pub(crate) family: u8,
}
```

17 bytes raw, 24 bytes with alignment. Saves ~8 bytes per IpAddr.
Three IpAddr fields × 8 bytes = 24 bytes saved.

### 2. Pack `Option<u16>` ports → sentinel u16

Port 0 is reserved (RFC 6335 §6) — never a legitimate L4
src/dst port. Encode `None` as 0, `Some(p)` as p. 2 bytes vs
4. Two ports × 2 bytes = 4 bytes saved.

### 3. Pack `Option<[u8;6]>` MACs → sentinel `[u8;6]`

All-zeros MAC = None. (Real MACs are never all-zero except for
unset/uninitialized state.) 6 bytes vs 8. Two MACs × 2 bytes
= 4 bytes saved.

### 4. Narrow `ifindex` from `i32` to `i16`

Linux `ifindex` is theoretically `int` but in practice well
below 65535 for any realistic deployment. xpf's existing
`ifindex_to_zone_id` uses i32 keys — we keep that interface
unchanged but store i16 internally. Compile-time-checked
narrowing: if any caller passes a value > i16::MAX, we
saturate to a reserved sentinel and log.

3× i32 → 3× i16 saves 6 bytes.

### 5. Pack flags

Combine `closing`, `fabric_ingress`, `is_reverse` into a single
`flags: u8` bitfield. Saves ~16 bytes (3 bools × ~8 bytes
padded → 1 byte).

### Resulting SessionEntry size

| Field | Original | Packed | Δ |
|-------|----------|--------|---|
| 3× Option<IpAddr> | 96 | 72 | -24 |
| 2× Option<u16> | 8 | 4 | -4 |
| 2× Option<[u8;6]> | 16 | 12 | -4 |
| 5× ifindex (i32→i16) | 20 | 10 | -10 |
| 3× bool flags | ~24 | 1 | -23 |
| 4× u64 timestamps | 32 | 32 | 0 |
| origin enum | 8 | 1 | -7 |
| disposition enum | 4 | 1 | -3 |
| zone IDs (u16) | 8 | 4 | -4 |
| owner_rg_id i32 | 4 | 4 | 0 |
| Other (vlan, padding, nat64_reverse) | ~20 | ~20 | 0 |
| **Total estimated** | **~240** | **~120** | **-120 (~50%)** |

At 131072 sessions: ~131072 × 120 = ~15.7 MB of slab vs
~31.5 MB pre-pack. **Saves ~16 MB.**

## Public API preservation

**This is the trickiest part of Step 3.** SessionEntry's
fields are accessed via:

- `lookup_with_origin` returns SessionLookup{decision, metadata}.
- `find_forward_nat_match` returns ForwardSessionMatch{key,
  decision, metadata}.
- `iter_with_origin` yields (key, decision, metadata, origin).
- 30+ other methods access decision.resolution.next_hop /
  decision.nat.rewrite_src / metadata.is_reverse / etc.

If we change `decision: SessionDecision` to a packed
representation, callers expecting `Option<IpAddr>` semantics
break.

**v1 plan**: introduce a `PackedSessionDecision` /
`PackedSessionMetadata` pair, with `From` conversions to/from
the unpacked `SessionDecision` / `SessionMetadata`. Internal
slab storage uses packed; public API methods materialize
unpacked on the way out. This costs ~ZERO on the slow path
(SessionTable::lookup is cache-miss territory anyway), but
adds a memcpy + repack on every read.

**Open question for review**: is this the right interface, or
should the public API change to expose the packed types directly
(forcing all 30+ callsites to migrate)?

## Hidden invariants

- **HA sync compatibility**: SessionDelta serializes
  `SessionDecision` via serde. The wire format must NOT
  change (HA peer compat). Packing must be internal-only;
  serde uses the unpacked types.
- **NatDecision::reverse / merge** semantics: these methods
  build new NatDecisions. Must work transparently against the
  packed type.
- **Sentinel collision risk**: port 0 is reserved by IANA but
  some BPF code paths may set port=0 explicitly. Audit all
  sites that write rewrite_*_port to ensure 0 is never a
  legitimate "set this port to 0" value.
- **MAC sentinel collision**: all-zeros MAC = None means no
  session can have neighbor_mac == 00:00:00:00:00:00. This is
  reasonable (multicast, broadcast, locally-administered MACs
  can't be all-zero) but warrants explicit verification.
- **ifindex narrowing**: if the kernel ever returns ifindex
  > 65535, the saturation path must NOT corrupt forwarding —
  fail loud, not silent.

## Risk assessment

- **Behavioral regression risk**: MEDIUM. Sentinel encoding
  for port/MAC/IP changes the meaning of "0" in those fields;
  any code path that checks `port == 0` as a non-None value
  breaks. Audit required.
- **Borrow-checker / lifetime risk**: LOW. Packed types are
  Copy + plain data.
- **Performance regression risk**: MEDIUM. The pack/unpack
  roundtrip on every SessionLookup/SessionMatch return path
  adds ~10-20 ns per slow-path lookup. The ~50ns
  reverse-NAT win from Step 1 could be erased.
- **Architectural mismatch risk** (#946 Phase 2 / #961 dead-end
  pattern): LOW. Step 3 is purely internal storage layout;
  no cross-packet state semantics change.
- **HA wire-format risk**: LOW if internal-packing-only
  approach is chosen; HIGH if public API is changed. v1
  picks internal-packing.

## Test plan

- `cargo build` clean (0 new warnings).
- 952+ cargo tests pass — particularly `session/tests.rs`,
  `nat/tests.rs`, and HA sync round-trip tests.
- 5/5 `wheel_pops_expired_entry_from_bucket` flake check.
- 30 Go test packages pass.
- `make test-failover` (this touches HA-relevant data
  structures via SessionDelta serialization).
- Deploy on loss userspace cluster.
- v4 + v6 smoke against `172.16.80.200` /
  `2001:559:8585:80::200`.
- Per-class CoS smoke (5201-5206).
- **MANDATORY**: extend the existing
  `userspace-dp/benches/session_table.rs` microbench with:
  - Lookup latency (post-pack, including pack→unpack
    roundtrip cost).
  - Insert latency.
  - SessionEntry size assertion: `static_assert!(size_of::
    <SessionEntry>() <= 128, "SessionEntry must fit in 2 cache lines");`

## Out of scope

- Step 2 of #964 (intrusive `next_node` indices) — defer.
- Changing SessionTable's public API to expose packed types
  to callers.
- Any change to `SessionKey` (already 50 bytes; sufficient).
- Wheel migration to handles (out of scope for #964 entirely).

## Open questions for adversarial review

1. **Is the perf justification sound?** Memory savings ~16 MB
   at 131072 sessions; no L1-i benefit; potential ~10-20ns
   pack/unpack overhead on slow-path lookup. Is the memory
   win worth the churn + potential lookup regression?
2. **Sentinel port=0 collision**: are there code paths that
   set rewrite_*_port = 0 as a real "set port 0" value
   (vs None)? Spot-check NAT pool allocator + HA sync paths.
3. **Sentinel MAC=00:00:00:00:00:00 collision**: any code
   that sets neighbor_mac to all-zeros as a real MAC?
4. **Internal-pack vs public-API-change**: v1 chooses
   internal-pack with From conversions. Is that the right
   interface, given the 30+ callsites that read decision.* /
   metadata.*? The pack/unpack roundtrip cost is real.
5. **HA wire format**: if SessionDelta's serde format is
   strictly tied to SessionDecision/SessionMetadata, and we
   keep those unpacked, is there a risk the slab and the
   wire diverge? How do we test the round-trip?
