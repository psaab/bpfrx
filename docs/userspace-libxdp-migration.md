# Userspace AF_XDP libxdp Migration Notes

## Scope

This document records the work that got the userspace AF_XDP dataplane from
the old `xdpilone` path to the current production `libxdp` bridge on
`master`.

Important clarification:

- this was not a migration to a packaged `libxdp-rs` crate
- production code uses a custom Rust FFI layer plus a small C bridge around
  `libxdp` and `libbpf`

Current production files:

- [xsk_ffi.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/xsk_ffi.rs)
- [xsk_bridge.c](/home/ps/git/codex-bpfrx/userspace-dp/csrc/xsk_bridge.c)
- [bind.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/bind.rs)

Related GitHub issue:

- `#253` Userspace AF_XDP libxdp migration postmortem

## Executive summary

The original migration failed because the first implementation treated
`libxdp` as if it were a drop-in implementation of `xdpilone`.

That assumption was wrong in five places:

1. RX availability semantics
2. producer reservation semantics
3. cancel-on-drop semantics
4. shared vs non-shared socket lifecycle
5. UMEM fill/completion ownership

The work that followed split into three categories:

1. wrapper correctness fixes
2. build and deploy fixes
3. runtime liveness and startup containment around the new wrapper

The wrapper-level migration itself was eventually made to work on `master`.
Later dataplane failures were not all migration bugs. Many were runtime or
manager lifecycle bugs around the wrapper.

## Baseline before the migration

Before `libxdp`, the userspace helper used `xdpilone` directly. The surrounding
code and mental model assumed:

- `available()` could be inferred from raw ring pointers
- producer ring reserve behavior matched existing caller expectations
- abandoning an in-flight reservation naturally restored ring capacity
- the shared socket lifecycle was the normal path
- UMEM fill/completion ownership matched the old library layout

Those assumptions were good enough under `xdpilone`. They were not valid under
`libxdp`.

## Exact timeline

### 2026-03-23: initial bridge lands

- `375be885` `feat: replace xdpilone with libxdp C bridge for AF_XDP`

What changed:

- added [xsk_bridge.c](/home/ps/git/codex-bpfrx/userspace-dp/csrc/xsk_bridge.c)
- added [xsk_ffi.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/xsk_ffi.rs)
- rewired the AF_XDP bind/open path in
  [bind.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/bind.rs)

Why it was necessary:

- Rust could not directly use the `xsk.h` inline helper surface cleanly
- production needed an AF_XDP path tied to the actual `libxdp`/`libbpf` stack

What was still wrong:

- the wrapper preserved the old `xdpilone` API shape
- the underlying `libxdp` semantics were still being interpreted as if they
  matched `xdpilone`

### 2026-03-23: liveness problems appear immediately

- `e83d4d3a` `fix: XSK liveness gate + auto-swap to eBPF pipeline when XSK broken`
- `4ddf371f` `fix: persist XSK liveness failure across config reconciles`

What this tells us:

- a successful bind was not enough to prove AF_XDP was live
- runtime containment had to be added around the new wrapper very early

This was important, but it did not fix wrapper semantics. It only reduced blast
radius when the wrapper or runtime failed.

### 2026-03-24: deployability fix

- `cb96e824` `fix: statically link libxdp/libbpf/libelf/zlib/zstd in userspace helper`

Why:

- the helper runs on firewall VMs and could not rely on target-side shared
  library compatibility

This was required to ship the bridge, but it was not the core dataplane
correctness fix.

### 2026-03-24: startup gating grows more conservative

- `67fb76eb` `fix: optimistic ctrl enable with 10s XSK liveness probe`
- `5e61e439` `fix: default to eBPF pipeline, probe-upgrade to userspace shim`

Why:

- the bridge could bind but still fail to prove live receive behavior
- the manager started treating userspace as an upgrade path rather than the
  default immediate path

Again, these are runtime mitigations, not proof that the wrapper was correct.

### 2026-03-24: RX availability semantics fixed

- `f76be868` `fix: RingRx::available() must use cached ring state, not raw pointers`

What was wrong:

- the wrapper implemented RX "available" from raw producer/consumer pointers
- `libxdp` RX behavior depends on cached ring state

Observed consequence:

- `available()` could report empty even when `peek()` would see packets
- workers could skip RX work incorrectly

Where this lives:

- [xsk_ffi.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/xsk_ffi.rs)

Lesson:

- AF_XDP ring helpers must match the actual library semantics, not just the
  mmap layout

### 2026-03-24: cached-state sync workaround attempted

- `adc8bde7` `fix: RingRx::available() cached state sync + disable XSK probe`

This was part of stabilizing the aftermath of the RX semantics bug. It is worth
recording because it shows that the team was still distinguishing wrapper
problems from probe-state problems at this point.

### 2026-03-24: producer reservation semantics fixed

- `1cf18591` `fix: XSK fill ring starvation and TX stuck-at-zero in libxdp FFI`

What was wrong:

- `libxdp` reserve is all-or-nothing
- the dataplane expected partial progress

Observed consequence:

- fill ring starvation
- TX stuck at zero

What had to change:

- partial-reserve behavior was implemented in the wrapper
- cancellation semantics were added for partially used or abandoned
  reservations

Where this lives:

- [xsk_ffi.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/xsk_ffi.rs)
- [xsk_bridge.c](/home/ps/git/codex-bpfrx/userspace-dp/csrc/xsk_bridge.c)

This is one of the most important migration fixes. Without it, the rest of the
dataplane was making invalid assumptions about ring progress.

### 2026-03-24: repeated lifecycle containment around XSK restart

- `10fbb2c6` `fix: PrepareLinkCycle stops XSK workers before link DOWN + re-enable probe`
- `bff3fa71` `fix: disable XSK BEFORE link cycle to prevent UMEM segfault`
- `dede165e` `fix: defer forwarding arm until 60s post-boot to prevent XSK segfault`
- `5464af93` `fix: always compile with xdp_main_prog + 60s probe delay`

What this phase means:

- even with wrapper fixes underway, restart and link-cycle stability was still
  poor
- the manager and deploy path had to become more defensive

These commits did not prove the bridge was wrong. They showed that runtime
ownership and restart behavior around the bridge was still not settled.

### 2026-03-24: non-shared socket path becomes the real answer

- `93af5fde` `fix: use xsk_socket__create (non-shared) to match working C test`
- `c5a28b32` `Revert "fix: use xsk_socket__create (non-shared) to match working C test"`
- `0be3e4c1` `fix: use xsk_socket__create (non-shared) to fix __xsk_setup_xdp_prog segfault`

What happened:

- the first bridge path used `xsk_socket__create_shared`
- that aligned better with the old mental model, but not with the stable
  runtime behavior on this stack
- the shared path hit `__xsk_setup_xdp_prog` faults during delete/link-cycle
  handling

What finally landed:

- the production bridge now uses plain `xsk_socket__create`

Why this matters:

- "shared UMEM exists conceptually" was not enough reason to keep using the
  shared socket lifecycle
- the stable path won over the more symmetric-looking path

### 2026-03-24: UMEM ownership is corrected by the non-shared path

This was part of the same non-shared fix set, not a standalone commit with its
own message.

What changed:

- the socket path now uses the UMEM fill/completion rings directly
- bind-time ownership had to reflect that
- queue objects had to take real ownership of fill/completion state

Why:

- the old code still assumed the earlier library ownership model

This is why the migration cannot be described as "swap one AF_XDP library for
another." The ownership model changed with it.

### 2026-03-25: rollback to xdpilone, then re-enable libxdp

- `a7b2c030` `revert: restore xdpilone for AF_XDP, remove libxdp C bridge`
- `80309f23` `Revert "revert: restore xdpilone for AF_XDP, remove libxdp C bridge"`

Why this matters:

- the migration was unstable enough that it was temporarily backed out
- later, once the core fixes were understood, the rollback was itself reverted

This separates two claims that should not be conflated:

- "the initial libxdp migration attempt was broken"
- "the final libxdp bridge can never work"

Only the first claim was proven.

### 2026-03-25: branch-only follow-up work after the main fixes

These commits were valuable follow-up work during investigation, but they did
not all land on `master`:

- `efbbafdc` `chore: update stale libxdp socket lifecycle comments`
- `bcde50c5` `test: port xsk repro to libxdp wrapper`
- `fa1b6b72` `userspace: restore XSK liveness probe gating`
- `02abeaa0` `userspace: fix XSK liveness startup gate`
- `713b6cf9` `userspace: fail XSK liveness on idle active owner`
- `d352d327` `userspace: restore XSK liveness probe gating`
- `45278e7d` `userspace: fix XSK liveness startup gate`
- `bb349387` `userspace: fail XSK liveness on idle active owner`

These matter because they show what the next unresolved layer was:

- not wrapper semantics anymore
- runtime liveness, startup gating, and restart behavior

## What landed on master

As of current `master`, the important landed facts are:

1. Production AF_XDP uses the custom `libxdp` bridge, not `xdpilone`.
2. RX availability uses cached ring semantics.
3. producer reserve and cancel-on-drop behavior were repaired.
4. non-shared `xsk_socket__create` is the active socket lifecycle.
5. UMEM ownership follows the non-shared model.
6. manager-side runtime gating exists because bind success alone was not enough
   to prove liveness.

## What did not land cleanly on master

Current `master` still has artifacts from the migration era:

- [test/xsk-repro/main.rs](/home/ps/git/codex-bpfrx/test/xsk-repro/main.rs)
  still imports `xdpilone`
- [test/xsk-repro/Cargo.toml](/home/ps/git/codex-bpfrx/test/xsk-repro/Cargo.toml)
  still depends on `xdpilone`
- [test/xsk-repro/README.md](/home/ps/git/codex-bpfrx/test/xsk-repro/README.md)
  is still framed around the older `xdpilone` vs `libbpf` comparison
- [xsk_ffi.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/xsk_ffi.rs)
  still contains stale `create_shared` wording in comments
- [bind.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/bind.rs)
  still describes the bind path as `xsk_socket__create_shared`

So the runtime path moved on, but the repro and comments did not fully keep up.

## What the migration fixed

The migration-level work fixed:

- wrong RX availability semantics
- wrong producer reserve expectations
- missing cancel-on-drop handling
- the unstable shared socket lifecycle
- the old UMEM ownership assumptions
- deployability through static linking

Those are the items that were actually required to make the bridge viable.

## What the migration did not fix

The migration-level work did not automatically solve later userspace dataplane
issues such as:

- startup liveness gating
- restart and rebind behavior
- manager/helper ownership and control-state timing
- zero-copy restart behavior on `mlx5`
- HA/failover state publication
- cold-start neighbor synchronization

Those are runtime system problems around the wrapper. They are not proof that
the final bridge semantics were still wrong.

## Practical lessons

### 1. Do not treat AF_XDP libraries as interchangeable

Any future AF_XDP library swap needs an explicit review checklist for:

- RX cached-ring semantics
- producer reserve behavior
- cancellation semantics
- socket creation lifecycle
- UMEM ownership

### 2. Keep the minimal repro aligned with production

A standalone repro only helps if it exercises the current production wrapper.

If production uses the custom `libxdp` FFI, then a repro that still uses
`xdpilone` is useful only as historical comparison, not as the primary
production diagnostic.

### 3. Separate wrapper bugs from runtime lifecycle bugs

After the core wrapper fixes landed, later failures had to be triaged as one
of:

- wrapper/FFI bug
- manager lifecycle bug
- helper startup bug
- kernel/driver restart behavior

Those are different layers and need different evidence.

### 4. Keep comments aligned with the runtime

The stale `create_shared` wording on `master` caused confusion later because it
described an obsolete lifecycle while the code was already on non-shared
create.

For this path, stale comments are not harmless.

## Recommended follow-up

1. Port [test/xsk-repro/main.rs](/home/ps/git/codex-bpfrx/test/xsk-repro/main.rs)
   and [test/xsk-repro/Cargo.toml](/home/ps/git/codex-bpfrx/test/xsk-repro/Cargo.toml)
   to the current [xsk_ffi.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/xsk_ffi.rs)
   path on `master`.
2. Update [test/xsk-repro/README.md](/home/ps/git/codex-bpfrx/test/xsk-repro/README.md)
   so it matches the production implementation and the current failure modes.
3. Clean stale `create_shared` wording in:
   - [xsk_ffi.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/xsk_ffi.rs)
   - [bind.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp/bind.rs)
4. Keep treating any remaining zero-copy restart issue as a separate runtime
   investigation unless it reproduces in the minimal wrapper repro.

## Reference commits

- `375be885` `feat: replace xdpilone with libxdp C bridge for AF_XDP`
- `e83d4d3a` `fix: XSK liveness gate + auto-swap to eBPF pipeline when XSK broken`
- `4ddf371f` `fix: persist XSK liveness failure across config reconciles`
- `cb96e824` `fix: statically link libxdp/libbpf/libelf/zlib/zstd in userspace helper`
- `67fb76eb` `fix: optimistic ctrl enable with 10s XSK liveness probe`
- `5e61e439` `fix: default to eBPF pipeline, probe-upgrade to userspace shim`
- `f76be868` `fix: RingRx::available() must use cached ring state, not raw pointers`
- `adc8bde7` `fix: RingRx::available() cached state sync + disable XSK probe`
- `1cf18591` `fix: XSK fill ring starvation and TX stuck-at-zero in libxdp FFI`
- `10fbb2c6` `fix: PrepareLinkCycle stops XSK workers before link DOWN + re-enable probe`
- `bff3fa71` `fix: disable XSK BEFORE link cycle to prevent UMEM segfault`
- `93af5fde` `fix: use xsk_socket__create (non-shared) to match working C test`
- `c5a28b32` `Revert "fix: use xsk_socket__create (non-shared) to match working C test"`
- `dede165e` `fix: defer forwarding arm until 60s post-boot to prevent XSK segfault`
- `5464af93` `fix: always compile with xdp_main_prog + 60s probe delay`
- `0be3e4c1` `fix: use xsk_socket__create (non-shared) to fix __xsk_setup_xdp_prog segfault`
- `a7b2c030` `revert: restore xdpilone for AF_XDP, remove libxdp C bridge`
- `80309f23` `Revert "revert: restore xdpilone for AF_XDP, remove libxdp C bridge"`
- `efbbafdc` `chore: update stale libxdp socket lifecycle comments`
- `bcde50c5` `test: port xsk repro to libxdp wrapper`
- `fa1b6b72` `userspace: restore XSK liveness probe gating`
- `02abeaa0` `userspace: fix XSK liveness startup gate`
- `713b6cf9` `userspace: fail XSK liveness on idle active owner`
- `d352d327` `userspace: restore XSK liveness probe gating`
- `45278e7d` `userspace: fix XSK liveness startup gate`
- `bb349387` `userspace: fail XSK liveness on idle active owner`
