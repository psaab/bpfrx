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
  per reservation; the #2374 fill-ring suffix retry re-`reserve`s a
  fresh `WriteFill` per NAPI iteration rather than re-inserting, so it
  never tripped the hazard.)
- `HEARTBEAT_GRACE_PERIOD_NS = 6 s` is defined in
  `userspace-dp/src/afxdp/mod.rs` but currently `#[allow(dead_code)]`
  — reserved for future XDP-shim heartbeat gating logic. Workers
  write the heartbeat immediately on bind today
  (`userspace-dp/src/afxdp/worker/mod.rs`), so there is no live
  6-second grace window.

## Subdir READMEs

See `src/afxdp/README.md`, `src/server/README.md`, `src/session/README.md`,
`src/filter/README.md`, `src/event_stream/README.md`, `src/bin/README.md`.
