# userspace-dp/

> #1373 status (complete): the eBPF dataplane retirement is done. This Rust
> AF_XDP dataplane is the only runtime forwarding path. The legacy BPF source
> (`bpf/xdp/*.c`, `bpf/tc/*.c`) was deleted in #1476; the eBPF backend is
> hard-rejected at commit by the config compiler (`ErrEBPFDataplaneRetired`,
> `pkg/config`) and at runtime by the dataplane factory
> (`ErrEBPFBackendRetired`, `pkg/dataplane`).

Standalone Rust AF_XDP dataplane that mirrors the BPF pipeline
(screen → zone → conntrack → policy → NAT → forward) but in userspace.
Runs as a separate `xpf-userspace-dp` binary the Go daemon spawns over a
Unix-socket control protocol.

This crate is the only runtime dataplane backend: an empty / omitted
`system dataplane-type` resolves to userspace in
`pkg/dataplane.EffectiveType`. Operators can still pin the selection
explicitly with `set system dataplane-type userspace`. The legacy eBPF
backend is retired (#1373/#1476) and hard-rejected (commit: `pkg/config`
compiler; runtime: `pkg/dataplane` factory);
the DPDK backend is retired under #1525.

## Crate entry

`src/main.rs` — argv parsing, then `server::lifecycle::run()`.

## Top-level layout

| Path | Purpose |
|------|---------|
| `src/afxdp/` | Core dataplane: workers, UMEM, RX/TX rings, frame parsing, session glue. |
| `src/server/` | Control-socket lifecycle and request dispatch. |
| `src/session/` | Session table (slab + Fx-hash indices) + timer wheel. |
| `src/filter/` | Junos-style firewall filter compiler + engine + policer. |
| `src/event_stream/` | Push-based binary session-delta stream to the daemon. |
| `src/bin/` | Helper binaries (`fairness-eval`). |
| `src/nat.rs`, `src/nat64.rs`, `src/nptv6.rs`, `src/policy.rs`, `src/screen.rs`, `src/slowpath.rs`, `src/fairness.rs` | Single-file feature modules consumed by the worker hot path. |

## Architecture

One worker thread per RSS queue. Each worker owns its AF_XDP socket,
UMEM (12K+ RX/TX frames, 256-byte headroom), RX/TX/fill/completion rings,
a per-worker reverse-NAT cache, and a per-worker session table view.

The hot path is the `worker_loop` (in `src/afxdp/worker/`), which polls
all bindings in batch (`RX_BATCH_SIZE=64`, up to `MAX_RX_BATCHES_PER_POLL=4`
per tick). Per descriptor: parse → screen → session lookup → NAT/policy
decision → forwarding build → enqueue TX or recycle.

## External interfaces

- **Unix socket** (`/tmp/xpf-userspace-dp.sock`): newline-delimited text
  protocol — `BIND`, `CONFIG`, `SESSION_INJECT`, `STATUS`, `STOP`, etc.
- **AF_XDP rings** (kernel ↔ userspace): RX/TX/fill/completion.
- **BPF maps** (shared with the XDP shim): session table mirror,
  conntrack, NAT pools, heartbeat.
- **Sysctl tuning**: writes `/proc/sys/net/core/rmem_default` and
  `rmem_max` (see `userspace-dp/src/server/lifecycle.rs`); enables
  NAPI busy-poll in `BusyPoll` mode.

## Critical invariants

These invariants are enforced in code (`const_assert`s and runtime
checks). `docs/per-5-tuple/state.md` documents the AF_XDP UMEM ownership
ceiling; the batch and heartbeat constants are pinned in
`userspace-dp/src/afxdp/mod.rs`. They aren't mirrored into CLAUDE.md —
that file's authoritative content covers Go, BPF, and Rust-helper
logging rules, not these specific hot-path constants.

- AF_XDP UMEM ownership is per-queue. A flow that hashes to queue N is
  *physically tied* to worker N — there is no cross-worker descriptor
  sharing. This is why every "rebalance flows across workers" design
  has been plan-killed; see `docs/per-5-tuple/state.md` for the formal
  ceiling.
- `RX_BATCH_SIZE = 64` is paired with the L1d footprint (≤14 KB
  working set per batch) in `userspace-dp/src/afxdp/mod.rs`. A
  `const_assert` enforces it; don't bump it without re-validating.
- `TX_BATCH_SIZE = 64` is paired with the CoS guarantee quantum in
  `userspace-dp/src/afxdp/mod.rs`. Changing requires re-running the
  `guarantee_phase_*` tests.
- Generic-XDP fallback consumes UMEM frames permanently on mlx5; the
  XDP shim redirects `XDP_PASS` to a cpumap stage that frees the frame
  immediately.
- Producer-ring writers (`WriteTx` / `WriteFill` in
  `userspace-dp/src/xsk_ffi.rs`) are **append-safe across multiple
  `insert()` calls on one reservation**: each `insert()` writes at
  `base_idx + written + n` and is bounded by the *remaining*
  reservation (`reserved - written`), so a second `insert()` appends
  after the first instead of overwriting it, and `commit()`/`Drop`
  submit the accumulated `written` count over distinct, initialized
  slots. libxdp masks the slot index against the ring size, so the
  unwrapped sum is correct. (Fixed in #2383 — the prior `base_idx + n`
  indexing was latent because every callsite did exactly one `insert()`
  per reservation; the early-out described below cuts the wasted tail of
  that retry loop (#2481); the #2374 fill-ring suffix retry re-`reserve`s a
  fresh `WriteFill` per NAPI iteration rather than re-inserting, so it
  never tripped the hazard.)
- The bringup fill-ring NAPI-trigger loop in `prime_fill_ring_offsets`
  (`userspace-dp/src/afxdp/bind.rs`) early-outs once the ring is fully
  primed (`remaining == total`) instead of always running the full
  `FILL_PRIME_MAX_ITERS` (20) cap (#2481). It still runs **at least one**
  iteration so the NAPI kick that posts the RX WQEs always fires, and a
  transiently-full ring keeps retrying the deferred suffix up to the cap;
  only the wasted tail (up to 19 × 1 ms poll per queue, ~320 ms of
  avoidable serial bringup latency across 16 queues) is cut. The
  iteration driver `drive_fill_prime_loop` is a pure seam so the early-out
  is unit-tested (fail-on-revert) without a bound `DeviceQueue`.
- **Slow-path control-queue rate limiter** (`src/slowpath.rs`,
  `RateLimiter`): the reinjector that punts firewall-local / control
  traffic to the kernel via the TUN device protects the control queue
  with a dual **token bucket** (packets/s and bytes/s). Tokens accrue
  continuously at the configured rate and the bucket caps at one second
  of tokens, so the admitted rate is smooth across time and the burst in
  ANY interval is bounded by the configured per-second rate. This
  replaced a fixed 1-second window (#2912) that zeroed its counters on
  the boundary and therefore permitted up to **2x** the rate in a short
  interval straddling a window edge (full budget at the end of window N
  plus a full budget at the start of window N+1). `allow_at(now, len)` is
  the clock-injectable core so the boundary behaviour is unit-tested
  fail-on-revert without sleeping; `allow(len)` is the production wrapper.
- **dnat_table reverse-NAT lifecycle (#2979)**: when an SNAT'd session
  installs, the worker poll path calls `publish_dnat_table_entry`
  (`src/afxdp/checksum.rs`) to write a DYNAMIC (flags=0) reverse-NAT
  record into `dnat_table` / `dnat_table_v6` so the embedded-ICMP handler
  can reverse-NAT inbound ICMP errors (PMTUD / traceroute) back to the
  original source. Those maps are `BPF_MAP_TYPE_HASH`,
  `max_entries = MAX_SESSIONS`, `BPF_F_NO_PREALLOC` — **NOT LRU**, so
  nothing self-evicts. The session Close/expiry handler
  (`flush_session_deltas` in `src/afxdp/session_delta.rs`) therefore MUST
  delete the matching entry via `delete_dnat_table_entry`, alongside the
  `session_map` / conntrack cleanup, or every closed SNAT session leaks
  one entry until the map fills and new reverse-NAT publishes fail (the
  #2244 capacity error). The delete key is derived from the SAME
  `dnat_v4_key_bytes` / `dnat_v6_key_bytes` helpers the publish path uses,
  so it byte-matches the insert key exactly (a mismatched key would leave
  the leak). The delete keys ONLY on the forward key + nat decision (the
  Close delta is gated on `!is_reverse`), is a no-op for non-SNAT flows
  (no `rewrite_src` → no key), and ENOENT on an absent key is benign.
  Compiler-managed STATIC DNAT-config entries (flags=1) are never
  published or deleted by this path. Fail-on-revert: the wiring test
  `close_delta_deletes_dnat_table_entry_for_snat_flow` plus the key-SSOT
  tests in `src/afxdp/tests.rs`.
- **Source-NAT pool subnet expansion (#3049)**: a source-NAT pool
  address entry may be a bare IP, a host CIDR (`/32`, `/128`), or a
  subnet CIDR (e.g. `203.0.113.0/28`). Junos uses the FULL prefix range
  for a source-NAT pool, so `parse_source_nat_rules_with_previous`
  (`src/nat/source.rs`) enumerates every address in the prefix
  (network..=broadcast inclusive) via `expand_pool_address`, populating
  `pool_addresses_v4` / `pool_addresses_v6` so the port allocator
  round-robins / hashes across the whole range. The pre-#3049 code
  stripped the mask and kept only the network host, silently collapsing
  a `/28` (16 addresses) to one — severe pool/port exhaustion with no
  signal. A single-host prefix still yields exactly one address. An
  over-broad prefix whose host count exceeds `MAX_POOL_PREFIX_HOSTS`
  (65536; covers up to a v4 `/16` or v6 `/112`) is rejected as an
  invalid pool (`SourceNatFailureReason::InvalidPool`) — fail-closed, so
  the operator gets a clear signal rather than a clamped or OOM pool.
  Fail-on-revert: `pool_snat_subnet_expands_full_cidr_range`,
  `pool_snat_host_cidr_yields_single_address`, and
  `pool_snat_overbroad_prefix_marks_invalid` in `src/nat/tests.rs`.
- `HEARTBEAT_GRACE_PERIOD_NS = 6 s` is defined in
  `userspace-dp/src/afxdp/mod.rs` but currently `#[allow(dead_code)]`
  — reserved for future XDP-shim heartbeat gating logic. Workers
  write the heartbeat immediately on bind today
  (`userspace-dp/src/afxdp/worker/mod.rs`), so there is no live
  6-second grace window.

## Subdir READMEs

See `src/afxdp/README.md`, `src/server/README.md`, `src/session/README.md`,
`src/filter/README.md`, `src/event_stream/README.md`, `src/bin/README.md`.
