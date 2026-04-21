# #814 — Raise MAX_INTERFACES so dataplane compile survives high kernel ifindex

## Problem statement

On `loss:xpf-userspace-fw1`, `xpfd` fails the first compile call at
startup and never spawns `xpf-userspace-dp`. fw1 cannot carry
traffic; fw0 is carrying everything; HA failover is one-way.

Journalctl on fw1 (quoted from issue #814):

    Apr 21 14:07:11 xpf-userspace-fw1 xpfd[138494]: level=WARN
      msg="failed to compile dataplane"
      err="compile zones: add tx port fab0: update: key too big for map: argument list too long"
      attempt=1 ever_ok=false

`ip -o link` on fw1 shows `fab0` at ifindex **2561**. `MAX_INTERFACES`
is **2048** (`bpf/headers/xpf_common.h:143`). `tx_ports` is a
`BPF_MAP_TYPE_DEVMAP` sized `MAX_INTERFACES`
(`bpf/headers/xpf_maps.h:372-377`), so
`bpf_map_update_elem(tx_ports, 2561, ...)` returns `E2BIG`. The
error bubbles up at `pkg/dataplane/compiler_iface.go:436-438`
(`dp.AddTxPort`) and aborts snapshot apply before
`ensureProcessLocked`, so `ever_ok` never flips and the helper is
never forked.

This is the exact recurrence `bpf/headers/xpf_maps.h:363-366`
anticipated:

> "The ifindex-above-cap case #759 was fixing is only realistic on
> long-lived namespaces where ifindex has drifted past MAX_INTERFACES.
> When that becomes a live concern again, the fix is to raise
> MAX_INTERFACES rather than reintroduce DEVMAP_HASH."

This is the **second** recurrence on this axis. The first was
#756/#759 where `ifindex hit 3651` on bpfrx-fw1 (`git show 7611f276`).
The plan below includes call-site cap checks plus a preflight so the
next recurrence fails loudly with a named interface rather than
needing journalctl archaeology.

## Non-negotiables (PR #767 lessons)

1. **Do NOT convert `tx_ports` to `BPF_MAP_TYPE_DEVMAP_HASH`.**
   PR #759 did this; PR #767 reverted it because `DEVMAP_HASH` broke
   mlx5 SR-IOV native XDP on kernel 7.0.0-rc7+ (ping RTT 0.4 ms →
   300 ms / 33% loss, iperf3 0 bps, `DBG SEG_MISS` per frame — see
   `bpf/headers/xpf_maps.h:343-371`). This map stays `BPF_MAP_TYPE_DEVMAP`.
2. **No other map type changes.** The four other ifindex-keyed maps
   (`interface_counters`, `redirect_capable`, `mirror_config`,
   `userspace_ingress_ifaces`) are already HASH flavours post-#759.
   Only `max_entries` (and the derived aya Array size
   `BINDING_ARRAY_MAX_ENTRIES`) is in scope.
3. **Test cluster is userspace only.** `loss:xpf-userspace-fw0` /
   `-fw1`. Never validate on `bpfrx-fw0/1`
   (`docs/development-workflow.md:188-194`).

## Complete ifindex inventory

| # | Map / index | Type | File:line | Value size | ifindex magnitude matters? |
|---|-----|------|-----------|-----------|---|
| 1 | `interface_counters` | `PERCPU_HASH` + `NO_PREALLOC` | `bpf/headers/xpf_maps.h:310-316` | 32 B | No (sparse) |
| 2 | `tx_ports` | `DEVMAP` (dense) | `bpf/headers/xpf_maps.h:372-377` | 8 B (`struct bpf_devmap_val` = 2×u32; `pkg/dataplane/xpfxdpmain_x86_bpfel.go:58-64`, `/usr/include/linux/bpf.h:6540-6545`) | **YES — key < max_entries** |
| 3 | `redirect_capable` | `HASH` + `NO_PREALLOC` | `bpf/headers/xpf_maps.h:383-389` | 1 B | No (sparse) |
| 4 | `mirror_config` | `HASH` + `NO_PREALLOC` | `bpf/headers/xpf_maps.h:816-822` | 8 B | No (sparse) |
| 5 | `userspace_ingress_ifaces` (aya) | `HashMap<u32, u8>` | `userspace-xdp/src/lib.rs:272-273` | 1 B | No (sparse) |
| 6 | **`userspace_bindings` (aya)** | **`Array<UserspaceBindingValue>` (dense)** | Declared `userspace-xdp/src/lib.rs:263-267`; index math at `userspace-xdp/src/lib.rs:381-386` and at `pkg/dataplane/userspace/maps_sync.go:519, 541, 909, 946` | **8 B** (`userspace-xdp/src/lib.rs:138-143`) | **YES — index < BINDING_ARRAY_MAX_ENTRIES** |

Row 6 detail: `USERSPACE_BINDINGS` is an aya `Array` (dense,
preallocated) with `max_entries = 1024 × 16 = 16384`, indexed as
`ifindex × BINDING_QUEUES_PER_IFACE + queue_id`. The dataplane
computes that index in four Go places (`maps_sync.go:519, 541, 909,
946`), including an alias path that uses raw snapshot
`iface.Ifindex`. On fw1 `fab0` at ifindex 2561: `2561 × 16 = 40976`,
which overflows the 16384 cap. Simply bumping `MAX_INTERFACES`
without also raising `BINDING_ARRAY_MAX_ENTRIES` would just relocate
the `E2BIG` from `AddTxPort` to `update userspace_bindings idx=...`.

### Two paths considered for row 6

**Path A — slot indirection (redesign).** Replace raw `ifindex` in
the index formula with a dense-slot id resolved through an
`ifindex_to_slot` HashMap. `USERSPACE_BINDINGS` would stay at 16384
entries and be indexed by `slot × 16 + queue`. Clean, bounded,
matches the direction issue #761 filed for the C-side ifindex maps.
Cost: reshapes the BPF verifier-visible lookup, needs a slot
allocator wired through the XDP shim, needs a fallback when a slot
isn't yet assigned, increases verifier complexity. **Out of scope
for a "bump a constant" PR.** Linked to issue #761 as the proper
long-term fix; tracked as follow-up. With the call-site cap checks
introduced by this PR (below), Path A is no longer a "must do next
if it recurs a third time" gate — we can just bump the constant
again because the failure now names the interface at the call site.

**Path B — raise the cap.** Keep the `ifindex × 16 + queue` shape.
Set `BINDING_ARRAY_MAX_ENTRIES = MAX_INTERFACES × BINDING_QUEUES_PER_IFACE`
so the two constants cannot drift.

**Recommended: Path B** for this PR.

### Wiring the Rust-side constant to the C-side constant (to be added by this PR)

Chosen approach: option (a) — `pkg/dataplane/build-userspace-xdp.sh`
will `export MAX_INTERFACES=$(awk '/^#define MAX_INTERFACES /{print
$3}' "${REPO_ROOT}/bpf/headers/xpf_common.h")` immediately before
invoking `cargo build`. `userspace-xdp/src/lib.rs` will replace the
literal at line 62 with `env!("MAX_INTERFACES")`-derived consts. No
`build.rs` is added: the crate consumes the env var via `env!()` at
compile time.

Sketch of the Rust side (to be written):

    const MAX_INTERFACES: u32 = match u32::from_str_radix(
        env!("MAX_INTERFACES"), 10) { Ok(v) => v, Err(_) => panic!() };
    const BINDING_QUEUES_PER_IFACE: u32 = 16;
    const BINDING_ARRAY_MAX_ENTRIES: u32 =
        MAX_INTERFACES * BINDING_QUEUES_PER_IFACE;

The `const` math is evaluated at compile time; the literal bakes
into `userspace_xdp_bpfel.o` via `Array::with_max_entries(...)`.

A Go-side load-time assertion will be added in
`pkg/dataplane/loader_ebpf.go` (the real load site, next to the
existing `userspaceSpec, err := loadRustUserspaceXDP()` at line 196
and the `ebpf.NewCollectionWithOptions(userspaceSpec, *opts)` at
line 220). The assertion will check
`userspaceSpec.Maps["userspace_bindings"].MaxEntries == uint32(MAX_INTERFACES * 16)`
and `userspaceSpec.Maps["userspace_ingress_ifaces"].MaxEntries == uint32(MAX_INTERFACES)`
before collection creation. A drifted embedded object fails there
rather than silently at first overflowing ifindex.

## Target value for MAX_INTERFACES

### aya map memory model

`HashMap::with_max_entries(N, 0)` at
`~/.cargo/registry/.../aya-ebpf-0.1.1/src/maps/hash_map.rs:24-31,
51-54` passes `flags = 0` to `build_def`, which yields
`BPF_MAP_TYPE_HASH`. With `flags = 0` the kernel default-preallocates
(i.e. **not** `BPF_F_NO_PREALLOC`). `userspace_ingress_ifaces` is
therefore a default-preallocated `BPF_MAP_TYPE_HASH` whose kernel
bookkeeping scales with `max_entries`, not populated count.

aya `Array::with_max_entries` compiles to `BPF_MAP_TYPE_ARRAY`,
which is always preallocated. For `USERSPACE_BINDINGS`:
`N × sizeof(UserspaceBindingValue) = N × 8 B` of verifier-visible
payload.

### Verified payload floor + estimated hash overhead

Payload math (exact, sourced):

| Map | Entries @ 65536 | Per-entry | Payload |
|---|---|---|---|
| `tx_ports` (DEVMAP) | 65536 | 8 B (`bpf_devmap_val`) | **512 KiB** |
| `USERSPACE_BINDINGS` (aya Array × 16 queues) | 65536 × 16 = 1,048,576 | 8 B (`UserspaceBindingValue`) | **8 MiB** |
| **Verified payload total** | | | **~8.5 MiB** |

Beyond the payload, `userspace_ingress_ifaces` as a preallocated
`BPF_MAP_TYPE_HASH` at `max_entries = 65536` carries hash allocator
bookkeeping (`kernel/bpf/hashtab.c` `htab_map_alloc` — not cited
line-for-line here; not derived in this plan). The order of
magnitude is **single-digit to low double-digit MiB** on realistic
kernels and CPU counts. Total worst-case footprint added by this PR
is therefore payload (~8.5 MiB) + hash bookkeeping (bounded to tens
of MiB on realistic kernels). Not material on a firewall-class VM
that already reserves larger footprints for the session map.

Pre-change baseline (`max_entries = 2048` for C-side, `1024 × 16`
for the aya Array, `1024` for aya HashMap) is roughly an order of
magnitude smaller by the same math.

### Evidence for the value choice

- fw1 today: `fab0` at ifindex 2561 (this issue).
- bpfrx-fw1 historical high: ifindex 3651 (`git show 7611f276` body:
  "on bpfrx-fw1 ifindex hit 3651 (fab0, fab1, vrf-sfmix)").
- Growth driver: uncontrolled namespace/veth churn on long-lived
  userspace-fw VMs (incus/k8s). Rate is not controlled by this
  codebase.
- Two recurrences on the same axis in ~half a year.

**Decision: MAX_INTERFACES = 65536.**

Reasoning:
- The last two incidents hit at 3651 and 2561. `8192` is ~2.24×
  the higher — the same "barely enough" shape that failed once
  already.
- At 65536 the added footprint is tens of MiB worst-case on a VM
  that already reserves larger footprints elsewhere. Not material.
- 65536 is the natural stopping point for an ifindex cap. The next
  doubling is explicit "not sizing for worst case" territory.
- Ends the "pick something defensible" churn on this axis.

**Derived: `BINDING_ARRAY_MAX_ENTRIES = 65536 × 16 = 1,048,576`**
(via the `env!` wiring above, not hard-coded separately).

**Derived: aya `userspace_ingress_ifaces` max_entries = 65536**
(kept on the same axis so a single knob governs the dataplane).

## Call-site cap checks + preflight (Round 2 MEDIUM — in this PR)

Codex is right that a one-time preflight is insufficient: the bindings
`Update()` path is reachable long after initial compile from
`applyHelperStatusLocked` callers at
`pkg/dataplane/userspace/manager.go:343, 857, 889, 914, 939, 956,
981, 1008`, `pkg/dataplane/userspace/process.go:316, 360, 1027`, and
`pkg/dataplane/userspace/manager_ha.go:63, 106, 376, 457`. New
interfaces can appear via netlink events and HA reconcile at any of
those sites. The plan therefore takes option (a): **wrap every
`Update()` into a dense-ifindex-keyed map with an in-line cap
check**, and keep the compile-time preflight only as a bonus
early-warning gate.

### Call-site cap checks (to be added)

`tx_ports` site:

- `pkg/dataplane/loader.go:330-344` (`AddTxPort`). Add a cap check
  before `tm.Update(uint32(ifindex), val, ebpf.UpdateAny)` at line
  340: if `uint32(ifindex) >= MAX_INTERFACES`, return
  `fmt.Errorf("AddTxPort: ifindex %d exceeds tx_ports cap %d (raise MAX_INTERFACES in bpf/headers/xpf_common.h)", ifindex, MAX_INTERFACES)`.

`userspace_bindings` sites (all compute `idx = ifindex * bindingQueuesPerIface + queue` or
`childIfindex * bindingQueuesPerIface + queue`):

- `pkg/dataplane/userspace/maps_sync.go:519` — primary bindings
  apply. Wrap the `Update` at line 524.
- `pkg/dataplane/userspace/maps_sync.go:541` — aliased-child apply.
  Wrap the `Update` at line 546.
- `pkg/dataplane/userspace/maps_sync.go:909` — watchdog repair
  primary path. Wrap the `Update` at line 927.
- `pkg/dataplane/userspace/maps_sync.go:946` — watchdog repair alias
  path. Wrap the `Update` further below (corresponding line in that
  block).

At each site, compare `idx` against `BINDING_ARRAY_MAX_ENTRIES`
(re-exported to Go from a shared constants file; see step 3a below).
On violation: return (for the apply sites) or log-and-skip (for the
watchdog repair sites — the watchdog is repair-only and must not
unwind) a structured error with `ifindex`, `queue`, `idx`, and
`cap`.

### Preflight (bonus, early-warning)

`func (m *Manager) preflightCheckIfindexCaps() error` added to
`pkg/dataplane/loader.go` next to `seedInterfaceCounter`. It
enumerates `netlink.LinkList()`, compares each `attrs.Index` against
`MAX_INTERFACES`, and returns a named-interface error on violation.

**Call site:** inside `dataplane.Manager.Compile()` itself (the real
entry invoked from `pkg/daemon/daemon.go:1809` as `d.dp.Compile(cfg)`).
Putting the preflight inside `Compile()` means every compile call
fires it — not just the first. There is no `compileDataplane`
symbol; the previous plan referenced a non-existent function and
this is corrected.

Size estimate: ~80 lines of Go across the call-site wrappers +
preflight + unit tests.

Risk of not including this in the PR: third recurrence requires the
same journalctl archaeology as the first two. With this in place,
the third recurrence (if it happens) will log the exact offending
interface and `idx`.

## Execution matrix

Budget: single commit, one-hour wall-clock.

**Preconditions (hard gate before step 1):**

- Dedicated worktree; `git status --porcelain` empty. Do not reuse
  the agent worktree pool. `make generate` rewrites many generated
  files and pre-existing drift would be silently absorbed into the
  commit.

| Step | Action | Files expected to change | Gate |
|------|--------|---------------|------|
| 1 | Bump C constant | `bpf/headers/xpf_common.h` (line 143: `2048 → 65536`) | Compiles via `make build` |
| 2 | Wire `MAX_INTERFACES` env into Rust build and use it | `pkg/dataplane/build-userspace-xdp.sh` (add `export MAX_INTERFACES=$(awk ...)` before `cargo build`); `userspace-xdp/src/lib.rs` (replace line 62 literal with `env!()`-derived consts; bump `userspace_ingress_ifaces` to `MAX_INTERFACES`) | `bash pkg/dataplane/build-userspace-xdp.sh` succeeds; resulting object inspected programmatically (step 5 review discipline) |
| 3 | Add call-site cap checks + preflight | `pkg/dataplane/loader.go` (`AddTxPort` wrapper + `preflightCheckIfindexCaps`); `pkg/dataplane/userspace/maps_sync.go` (four sites at 519/541/909/946); export of `MAX_INTERFACES` and `BINDING_ARRAY_MAX_ENTRIES` to Go (see 3a) | `go test ./pkg/dataplane/... ./pkg/daemon/...` passes |
| 3a | Provide Go-visible constants | Either (i) hand-mirror in a `pkg/dataplane/constants.go` with a `//go:generate` tie to the C header, or (ii) reuse the bpf2go-generated `xpfXdpMainSpecs` struct if accessible. Pick (i) for this PR; the mirror is validated by step 4's load-time assertion against the embedded `MaxEntries`. | build succeeds |
| 4 | Wire preflight into every `Compile()` call; add load-time `MaxEntries` assertion | `pkg/dataplane/compiler.go` (line 265 — `func (m *Manager) Compile(cfg *config.Config) (*CompileResult, error)` — call `preflightCheckIfindexCaps()` first thing on entry); `pkg/dataplane/loader_ebpf.go` (assert `userspaceSpec.Maps["userspace_bindings"].MaxEntries` and `.Maps["userspace_ingress_ifaces"].MaxEntries` post-`loadRustUserspaceXDP()` / pre-`ebpf.NewCollectionWithOptions`, line 196-220) | unit test |
| 5 | Regenerate BPF artifacts | `make generate` (= `go generate ./pkg/dataplane/...` which runs the directives in `pkg/dataplane/loader.go:20-34` in order: **line 20** `xpfXdpMain` → **line 21** `bash build-userspace-xdp.sh` → **lines 22-34** the rest of the bpf2go directives for the C programs) | Diff limited to the enumerated artifact list below. |
| 6 | Commit (one commit, one trailer) | all of the above | `git status` clean after commit |
| 7 | Deploy to **fw0** | n/a | Gate A |
| 8 | Deploy to **fw1** | n/a | Gate B |
| 9 | HA failover exercise | n/a | Gate C |

Note on codegen order: `bash build-userspace-xdp.sh` is the
**second** `go:generate` directive (line 21). The first is `xpfXdpMain`
(line 20). All 13 remaining `xpf*` bpf2go directives follow at lines
22-34. This matches
`pkg/dataplane/loader.go:20-34` as observed.

**Expected regenerated files (enumerated):**

From `pkg/dataplane/loader.go:20-34` + `build-userspace-xdp.sh`, the
artifacts `make generate` (re)writes are **29 files total**: 14
`xpf*_x86_bpfel.go` + 14 `xpf*_x86_bpfel.o` + `userspace_xdp_bpfel.o`.
Verified via `ls pkg/dataplane/*_bpfel.*`. Enumerated explicitly so
the hard-stop diff-scope rule does not miss half of them:

    pkg/dataplane/userspace_xdp_bpfel.o      # from build-userspace-xdp.sh (line 21)
    pkg/dataplane/xpfxdpmain_x86_bpfel.go
    pkg/dataplane/xpfxdpmain_x86_bpfel.o
    pkg/dataplane/xpfxdpscreen_x86_bpfel.go
    pkg/dataplane/xpfxdpscreen_x86_bpfel.o
    pkg/dataplane/xpfxdpzone_x86_bpfel.go
    pkg/dataplane/xpfxdpzone_x86_bpfel.o
    pkg/dataplane/xpfxdpconntrack_x86_bpfel.go
    pkg/dataplane/xpfxdpconntrack_x86_bpfel.o
    pkg/dataplane/xpfxdppolicy_x86_bpfel.go
    pkg/dataplane/xpfxdppolicy_x86_bpfel.o
    pkg/dataplane/xpfxdpnat_x86_bpfel.go
    pkg/dataplane/xpfxdpnat_x86_bpfel.o
    pkg/dataplane/xpfxdpforward_x86_bpfel.go
    pkg/dataplane/xpfxdpforward_x86_bpfel.o
    pkg/dataplane/xpfxdpnat64_x86_bpfel.go
    pkg/dataplane/xpfxdpnat64_x86_bpfel.o
    pkg/dataplane/xpfxdpcpumap_x86_bpfel.go
    pkg/dataplane/xpfxdpcpumap_x86_bpfel.o
    pkg/dataplane/xpftcmain_x86_bpfel.go
    pkg/dataplane/xpftcmain_x86_bpfel.o
    pkg/dataplane/xpftcconntrack_x86_bpfel.go
    pkg/dataplane/xpftcconntrack_x86_bpfel.o
    pkg/dataplane/xpftcnat_x86_bpfel.go
    pkg/dataplane/xpftcnat_x86_bpfel.o
    pkg/dataplane/xpftcscreenegress_x86_bpfel.go
    pkg/dataplane/xpftcscreenegress_x86_bpfel.o
    pkg/dataplane/xpftcforward_x86_bpfel.go
    pkg/dataplane/xpftcforward_x86_bpfel.o

### Hard-stop diff scope (allowed-diff allowlist)

A diff is expected inside **exactly** this set; anything outside is a
hard stop and must be investigated before committing.

Production files (steps 1-4):
- `bpf/headers/xpf_common.h`
- `pkg/dataplane/build-userspace-xdp.sh`
- `userspace-xdp/src/lib.rs`
- `pkg/dataplane/loader.go`
- `pkg/dataplane/loader_ebpf.go`
- `pkg/dataplane/userspace/maps_sync.go`
- `pkg/dataplane/constants.go` (new, for 3a) OR whatever existing
  constants file is reused
- `pkg/dataplane/compiler.go` (declares `func (m *Manager) Compile(cfg *config.Config) (*CompileResult, error)` at line 265 — the `preflightCheckIfindexCaps()` call is added here as the first statement of the method body)

Test files that must change (enumerated from
`grep -rn 'userspace_bindings\|BINDING_ARRAY_MAX_ENTRIES\|MAX_INTERFACES\|tx_ports' --include='*_test.go' pkg/`,
run against current tree):
- `pkg/dataplane/userspace/manager_test.go` — the inject at
  `:148-158` uses `MaxEntries: 256`; this test needs to either (a)
  stay at a small size and have the new load-time assertion gated
  behind a test-mode flag, or (b) bump to the real value. Prefer
  (a): the inject helper is test-only scaffolding and should not
  require production-sized maps. Add a `testing.T`-aware bypass or
  reference-entries argument.
- New unit test files for the preflight function and for the four
  call-site wrappers.

Regenerated artifacts: the 29 files enumerated above.

Any diff outside this union is a hard stop.

### Review discipline (post-`make generate`)

Do not rubber-stamp "whatever `make generate` spat out." Concretely:

- For **every** regenerated `.o` (both the C-side `xpf*_x86_bpfel.o`
  files and the Rust-side `userspace_xdp_bpfel.o`), verify map
  `MaxEntries` programmatically via `ebpf.LoadCollectionSpecFromReader`
  on the embedded object. Do NOT rely on inspecting the wrapper `.go`
  files — those only embed the `.o` blob as `_BytesBpfel`. The
  authoritative `max_entries` value lives in the `.o` ELF `.maps`
  section. A `.o` built against the old constant with a `.go`
  wrapper regenerated against the new constant would pass a
  naive text check and still fail at runtime.
- C-side assertions: for each `xpf*_x86_bpfel.o`, assert
  `spec.Maps["tx_ports"].MaxEntries == 65536`,
  `spec.Maps["redirect_capable"].MaxEntries == 65536`,
  `spec.Maps["mirror_config"].MaxEntries == 65536`,
  `spec.Maps["interface_counters"].MaxEntries == 65536`.
- Rust-side: assert `spec.Maps["userspace_bindings"].MaxEntries == 1048576`
  and `spec.Maps["userspace_ingress_ifaces"].MaxEntries == 65536`
  on `userspace_xdp_bpfel.o`. This is the same API the new
  production-side load-time assertion uses, so the review
  double-checks both the artifact and the assertion. (The
  previously-planned `llvm-objdump -h` command does not expose
  `max_entries` and is dropped.)

## Validation gates

### A. fw0 no-regression (after step 7)

Hard gates (sourced from `docs/development-workflow.md:201-215`):

- `systemctl is-active xpfd` returns `active` on fw0; no restart
  loop in `journalctl -u xpfd -n 200`.
- `ls -l /run/xpf/userspace-dp.sock` exists.
- `pidof xpf-userspace-dp` returns non-empty.
- `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203` passes with **0
  retransmits** (continuous-gate rule).
- `journalctl -u xpfd | grep -c 'SEG_MISS'` shows zero new hits
  versus the pre-deploy baseline.
- `dmesg | grep -iE 'mlx5|bpf|oom'` shows nothing new.

Observational (not pass/fail): 12-flow `iperf3 -P 12 -t 20 -p 5203`
throughput delta, recorded in the PR write-up.

### B. fw1 compile succeeds (after step 8)

- `journalctl -u xpfd` on fw1 shows `ever_ok=true` (or absence of the
  `failed to compile dataplane` WARN).
- `/run/xpf/userspace-dp.sock` exists within 30 s of xpfd start.
- `pidof xpf-userspace-dp` returns non-empty on fw1.
- `dmesg | grep -iE 'bpf|mlx5|oom|allocation failure'` nothing new.
- No `SEG_MISS` on fw1.

### C. HA failover (after B)

- Drive failover fw0 → fw1 via the `failover-test` skill. Run
  `iperf3 -c 172.16.80.200 -P 4 -t 30 -p 5203` across the transition.
- Hard gate: forwarding continues on fw1; post-convergence sustained
  retrans = 0. Transition retrans is observational.
- Hard gate: `xpfctl session list --count` on fw1 > 0 post-failover
  (BulkSync populated).
- Drive failback fw1 → fw0. Same checks.

## Rollback

Single commit, single revert:

    git revert <SHA>

Flips `MAX_INTERFACES` back to 2048, unwinds the aya wiring, removes
the call-site checks and preflight, and regenerates artifacts as
part of the revert commit.

Redeploy fw0, then fw1. Behaviour returns to pre-change (fw1 fails
to compile, fw0 continues).

Revert triggers (any one):

- fw0 dataplane fails to compile after deploy.
- Any `SEG_MISS` on fw0, or iperf3 retrans > 0 on the `-P 4 -t 5`
  continuous gate.
- fw1 still fails to compile with `key too big for map` — implies a
  missed map; halt and re-audit the inventory.
- OOM or BPF map creation failure in dmesg on either node.

## Hard stops (HALT execution, do not merge)

- Any `SEG_MISS` log line on fw0 after deploy.
- `iperf3` retransmits > 0 on fw0 on the `-P 4 -t 5` continuous gate.
- `make generate` produces a diff outside the allowed-diff allowlist.
- fw1 still reports `key too big for map` after the bump.
- `MaxEntries` mismatch caught by the load-time assertion.

## Deferrals

- **Path A slot-indirection redesign** for `USERSPACE_BINDINGS` and
  for `tx_ports`. Proper long-term shape; belongs with issue #761.
  With the call-site cap checks in this PR, Path A is no longer
  "must do next on recurrence" — a third recurrence can be handled
  by bumping the constant again (the cap checks name the interface
  at the call site).
- **Automated ifindex-churn regression test (H2)** — veth-flood
  harness that forces ifindex > `MAX_INTERFACES`. Deferred; file
  follow-up.
- **DPDK worker's separate `MAX_INTERFACES = 256`** at
  `dpdk_worker/tables.h:24`. Different build path, different
  dataplane. Out of scope.

## Out of scope

- Any change to `BPF_MAP_TYPE` on `tx_ports` (stays `DEVMAP`).
- Any other map type or flag changes.
- Any change to `MAX_ZONES`, `MAX_POLICIES`, `MAX_SESSIONS`, etc.
- DPDK worker constants.
- `bpfrx-fw0/1` cluster (forbidden test surface).

## Summary for Codex (adversarial prep)

This PR will change:

1. One C integer literal: `MAX_INTERFACES 2048 → 65536`
   (`bpf/headers/xpf_common.h:143`).
2. The Rust side's `MAX_INTERFACES` will be *derived* from the C
   header via an `export MAX_INTERFACES=...` line added to
   `pkg/dataplane/build-userspace-xdp.sh` before `cargo build`, and
   consumed from `userspace-xdp/src/lib.rs` via `env!("MAX_INTERFACES")`.
   No `build.rs` is added. `BINDING_ARRAY_MAX_ENTRIES` and
   `userspace_ingress_ifaces` `max_entries` both flow from that.
3. ~80 lines of new Go across:
   - `AddTxPort` cap check (`pkg/dataplane/loader.go:330-344`).
   - Four call-site cap checks in
     `pkg/dataplane/userspace/maps_sync.go` at lines 519, 541, 909,
     946.
   - `preflightCheckIfindexCaps` in `pkg/dataplane/loader.go`, wired
     into every `dataplane.Manager.Compile()` call (the method body
     at `pkg/dataplane/compiler.go:265`, invoked from
     `pkg/daemon/daemon.go:1809`).
   - Load-time `MaxEntries` assertion in
     `pkg/dataplane/loader_ebpf.go` at lines 196-220.
4. The regenerated bpf2go artifacts enumerated in step 5 of the
   execution matrix, and nothing else.

Memory cost (payload verified; hash overhead estimated):

- `tx_ports`: 16 KiB → 512 KiB (+496 KiB, preallocated).
- `USERSPACE_BINDINGS`: 128 KiB → 8 MiB (+~7.9 MiB, preallocated aya
  Array).
- `userspace_ingress_ifaces`: preallocated `BPF_MAP_TYPE_HASH` grows
  from `max_entries 1024 → 65536`; added footprint is hash
  bookkeeping overhead, bounded to tens of MiB on realistic kernels.
- NO_PREALLOC C-side HASH maps: no change.
- Total verified payload: **~+8.5 MiB**. Plus bookkeeping overhead
  on the one prealloc HashMap. Not material on firewall-class VMs.

Risks:

1. mlx5 regression (#767 lesson) — mitigated by *not* changing map
   types; this is a `max_entries` delta only.
2. Silent drift between the C-side `MAX_INTERFACES` and the aya-side
   `BINDING_ARRAY_MAX_ENTRIES` — mitigated by the `env!()` wiring
   (compile-time tie) plus the load-time `MaxEntries` assertion on
   the embedded object.
3. Missed ifindex-keyed map — mitigated by the six-row inventory
   plus the call-site cap checks (every `Update()` into a
   dense-ifindex-keyed map is guarded) plus the compile-time
   preflight.
