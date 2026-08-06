# pkg/dataplane

> Deprecation notice (#1373): the legacy eBPF backend in this package is being
> retired in favor of the Rust AF_XDP userspace dataplane. Phase 1 updates
> active docs and migration targeting only; no BPF source, loader code, or
> bindings are removed in this phase.

Abstract dataplane interface plus the legacy eBPF backend. Compiles the typed
config from `pkg/config` into BPF-map entries (zones, policies, NAT,
filters, applications), attaches the 14 BPF programs (9 XDP + 5 TC), and
exposes session iteration to GC, the CLI, and the metrics surface.

Pluggable: the legacy eBPF backend registers through `RegisterBackend` for
the old `DataPlane` surface (DPDK retired #1525; removed in #1527/#1528).
Runtime backends register through `RegisterRuntimeBackend`; daemon startup now
selects `userspace.Boot()` directly for the default and explicit userspace
paths and falls through to `NewRuntimeDataPlane` for every other effective
type. Today the operator-facing cases on that branch are the explicit legacy
eBPF rollback and retired-DPDK sentinel; unknown/custom types still surface the
legacy factory's error path verbatim. During the #1381 migration, the userspace
runtime constructor returns `LegacyDataPlaneAdapter`: the userspace `Manager`
itself still does not implement the BPF-shaped `DataPlane`, but daemon status,
CLI, and cluster-sync callers that have not moved to domain interfaces still
receive a temporary compatibility handle.

DPDK retirement (#1525): the historical #1475 policy that retained DPDK as
a separately supported DPDK-build backend is no longer in force. The
`pkg/dataplane/dpdk` bridge, the `cmd/xpfd/main.go` blank registration
import, and the canary allowlist entries were removed in #1527/#1528. The
[`docs/pr/1373-retire-ebpf-dataplane/README.md`](../../docs/pr/1373-retire-ebpf-dataplane/README.md)
"DPDK Backend Retired (#1525)" section now describes the remaining
Phase 1 reject machinery (commit-time `ErrDPDKDataplaneRetired`,
`TypeDPDK` sentinel, runtime `ErrDPDKBackendRetired`) which is kept
for one release cycle to preserve the operator-friendly migration
message for stored-config rolling upgrade.

The userspace backend's status wire format is mirrored here for CLI/API
consumers. CoS queue status includes queue-scoped drain-phase counters so
operators can separate guarantee bytes, surplus bytes, and non-exact bytes
sent while exact queues were still backlogged.

## Shim artifact: pinned toolchain + verifier gates (#1864)

`userspace_xdp_bpfel.o` (the retained Rust AF_XDP shim, built from
`userspace-xdp/`) is **git-tracked and embedded into xpfd via
go:embed** — it is the deployable artifact. `make build` never needs
`make generate`; only regenerate when `userspace-xdp/` source changes.

Why this is guarded: on 2026-06-10 a `make generate` with a drifted
Rust nightly produced an object that exceeded the kernel verifier's
1M processed-insn cap (`BPF program is too large. Processed 1000001
insn`) and put BOTH HA cluster nodes into config-only mode. The
upstream rustc/LLVM change in (nightly-2026-05-23, nightly-2026-05-27]
altered `u64::saturating_sub` lowering in a way that defeats verifier
state pruning; a year-old nightly fails differently — the safe
toolchain set is an interval, so the build pins the toolchain AND
verifies every candidate empirically.

Guard layers (`build-userspace-xdp.sh`):

1. **Toolchain pin** — `userspace-xdp/rust-toolchain.toml` is the
   single source of truth (`channel = "nightly-YYYY-MM-DD"` +
   rust-src). The script parses it strictly (exactly one channel key
   in `[toolchain]`, format-validated) and refuses to build with a
   missing toolchain, printing the exact `rustup toolchain install`
   line. bpf-linker is version-pinned too (it embeds its own LLVM);
   the script version-checks the exact PATH-resolved binary cargo
   executes.
2. **Verify-then-install** — the cargo output is loaded through the
   real kernel verifier (`cmd/shimverify`: anonymous maps, no pins,
   no attach, plus the same `validateUserspaceShimSpec` checks the
   daemon runs) BEFORE the tracked `.o` is touched. REJECT or missing
   privileges (root / passwordless sudo) ⇒ tracked object untouched,
   nonzero exit, actionable message. There is no unverified-install
   path. `RUST_BPF_TOOLCHAIN=...` overrides the pin for bisects, but
   installing an unpinned object additionally requires
   `XPF_SHIM_ALLOW_UNPINNED_INSTALL=1`.
3. **Deploy pre-flight** — `xpfd verify-dataplane` runs the same
   verify-only load against the object embedded in the invoked
   binary (exit 0 PASS / 3 verifier REJECT / 1 other).
   `test/incus/cluster-setup.sh deploy_vm()` pushes the new binary to
   a temp path and runs this BEFORE stopping the old daemon — a
   REJECT refuses the deploy with the old dataplane still forwarding.

   The shared `validateUserspaceShimSpec` gate this runs also performs
   an **ABI compatibility check** (#5307): for every required pinned map
   it compares the embedded shim's `Type`, `KeySize`, `ValueSize`,
   `MaxEntries`, and `Flags` — the exact fields cilium/ebpf's
   `MapSpec.Compatible` flags with `ErrMapIncompatible` at load —
   against BOTH the Go-side expected shape (dnat_table and dnat_table_v6,
   from `userspaceShimSharedMapSpecs`) AND the RUNNING daemon's **live
   pinned maps** (read-only via `ebpf.LoadPinnedMap` + shape
   accessors). The ABI-checked inventory (`userspaceABICheckedPinnedMaps`)
   is the UNION of the shim-declared PinByName maps
   (`userspacePinnedShimMaps`) AND the Go-created/replaced shared maps
   (`userspaceShimSharedMapSpecs`) — deduplicated — matching the
   required-pins set (`userspaceRequiredShimPins`). Before #5484 it
   covered only the PinByName group, so state-bearing shared maps the
   shim does NOT declare — `sessions_v6`, `dnat_table_v6`, and the HA /
   per-CPU maps (`rg_active`, `ha_watchdog`, `session_id_gen`, the
   `*_counters`) — were never pre-flighted: an incompatible live pin for
   one of them passed a green pre-flight and then failed
   `ErrMapIncompatible` in `loadUserspaceShimSharedMaps` AFTER the old
   daemon was stopped, stranding the node. Because this runs while the
   old daemon is still up (its pins live), an ABI-incompatible map is
   now caught HERE and the deploy is refused — instead of the pre-#5307
   behavior where a green pre-flight let the deploy proceed, the old
   daemon was stopped, and the new daemon's `NewCollectionWithOptions`
   (or the shared-map load) then failed `ErrMapIncompatible`, stranding
   the node fail-closed (config-only). A map with no pin yet (fresh
   node / first load) skips the live-pin arm — only the expected-value
   checks apply, so a clean node never false-fails. The disposable
   counter map `userspace_fallback_stats` is intentionally excluded:
   `reconcileDisposableCollectionPin` resets it on an intended shape
   change (#4113), so ABI-checking it here would re-brick that upgrade.

   **Remediation message split (#5363):** the two ABI arms print
   *different* operator guidance because they diagnose different faults.
   An **embedded-vs-Go-SSOT drift** (`validateUserspaceShimSpecWith`
   expected-shape arms + `validateSharedMapExpectedABI` +
   the `userspace_bindings`/`userspace_ingress_ifaces` drift errors) means
   the embedded shim binary drifted from its Go-side source contract, so
   it prints `userspaceShimGenerateRemediation` — "Re-run `make
   generate-userspace-xdp`." A **live-pin mismatch**
   (`validateUserspaceShimLivePins`) is the OPPOSITE situation: it compares
   this build's embedded shim against the RUNNING (old) daemon's pinned
   map, so the pin is ALWAYS the stale side. The embedded shim is the
   intended, un-broken target, so `make generate` is the WRONG action;
   instead it prints `userspaceShimStalePinRemediation`, directing a FULL
   dataplane reload (stop xpfd so the old pin is released, then start it to
   load the new shim). A rolling deploy cannot cross a genuine shim-map ABI
   change because the new map can only be pinned after the stale pin is
   released.

   **CPUMAP MaxEntries is CPU-sized, not a stale-pin signal (#5364):**
   `userspace_cpumap` is a `BPF_MAP_TYPE_CPUMAP`. The shim declares it as
   `CpuMap::with_max_entries(256, 0)` — a template MAX — but cilium/ebpf's
   `MapSpec.fixupMagicFields` clamps a CPUMAP's `MaxEntries` to
   `nr_possible_cpus` before it creates OR ABI-compares the map, so a fresh
   daemon ALWAYS pins it at `nr_possible_cpus` (16 on the loss VMs), never
   256. Because `MapSpec.Compatible` (the exact `ErrMapIncompatible` check
   this pre-flight predicts) runs the identical clamp, the real PinByName
   load compares `nr_possible_cpus == nr_possible_cpus` and succeeds. The
   pre-flight therefore resolves the reference `MaxEntries` through
   `livePinRefABI`, which applies the same clamp for a CPUMAP — so the old
   "`cpumap=16` pin vs embedded `cpumap=256` shim" diff (mischaracterized as
   a stale 16→256 ABI bump, which false-rejected EVERY rolling
   cluster-deploy) is no longer produced. The relaxation is scoped to the
   `MaxEntries` axis of the CPUMAP only: no other ABI-checked shim map is
   CPU-count-sized (per-CPU ARRAY/HASH maps keep their declared `MaxEntries`
   and replicate the VALUE per-CPU; XskMap keeps its declared size), so every
   other map keeps a strict `MaxEntries` check, and a genuine cpumap
   Type/KeySize/ValueSize/Flags break still yields the full-reload
   remediation.

   **Residual (documented, not caught here):** a *same-size* Go/Rust
   value **field reorder** — identical `KeySize`/`ValueSize`/`Type`/
   `Flags` but a different field layout — is invisible to this
   spec-level ABI comparison (and to `ErrMapIncompatible` itself). That
   class stays covered by the build-time kernel-verifier gate above +
   the cross-language struct-parity tests (`bpf/headers/*.h` vs the Go
   mirrors and the userspace-dp parity tests), NOT the deploy
   pre-flight.
4. **Tests** — root-gated `TestVerifyEmbeddedUserspaceShim` catches a
   bad tracked artifact in privileged `make test`;
   `TestVerifyUserspaceShimShrinkEquivalence` proves the verify-only
   hash-map MaxEntries shrink (memory hygiene for live-node
   pre-flights) never changes the verifier verdict, using the
   preserved incident object in `testdata/`. The #5364 cpumap
   CPU-count-clamp handling is covered by
   `TestCPUMapLivePinPossibleCPUAccepted` (a CPU-sized cpumap live pin is
   accepted, not false-rejected), `TestCPUMapLivePinGenuineBreakStillRejected`
   (a genuine cpumap ValueSize break is still rejected), and
   `TestNonCPUMapMaxEntriesStillStrict` (no other map's MaxEntries check is
   weakened).
5. **Source→object freshness gate (#4977)** — the four layers above bind
   the *toolchain* and the object's *verifier behavior*, but none proves
   the git-tracked `.o` corresponds to CURRENT `userspace-xdp/**` source.
   Because `make build` never runs `make generate` and `make test` never
   rebuilds the shim, a logic-only edit to the Rust source (a
   packet-steering or security fix) that is not followed by `make
   generate` + committing the regenerated `.o` would ship the STALE
   object while source review and `make test` stay green. The gate closes
   that gap:
   - `pkg/dataplane/userspace_xdp_manifest.json` records a SHA-256 of the
     tracked object AND of every freshness-relevant build input — every
     `userspace-xdp/src/**/*.rs`, `Cargo.toml`, `Cargo.lock`,
     `rust-toolchain.toml`, BOTH the crate-local `userspace-xdp/.cargo/
     config.toml` and the repo-root `.cargo/config.toml` (cargo loads
     ancestor configs, so a root-level BPF-target rustflags edit could
     change the object), `bpf/headers/xpf_common.h` (its `MAX_INTERFACES`
     `#define` is awk-extracted by the recipe and sizes the shim binding
     array + maps), and the `build-userspace-xdp.sh` recipe itself (it
     embeds the bpf-linker pin). The header is hashed directly so the gate
     is fail-CLOSED: the header->Go max_entries parity canary
     (`TestMaxInterfacesMatchesCHeader`) `t.Skip`s when the header is
     absent, so leaning on it alone left a hole. It deliberately EXCLUDES
     only cargo's `target/` (build artifacts) and `.gitignore`.
   - `build-userspace-xdp.sh` regenerates the manifest (via
     `cmd/shim-manifest` → `dataplane.WriteUserspaceXDPManifest`)
     immediately after the verifier-gated install, so the manifest stays
     in LOCKSTEP with the object it describes and can never record a
     source hash newer than the object that source produced.
   - `TestUserspaceXDPShimObjectMatchesSourceManifest` (a plain, non-root
     `make test` test) recomputes the manifest from the working tree and
     fails when it drifts — editing a shim source, adding a new `.rs`
     module, or swapping the `.o` without `make generate` all go RED with
     a message pointing back to `make generate`.
     `TestUserspaceXDPManifestCoversTrackedShimInputs` additionally guards
     the input SET so a manifest hand-edit cannot drop or invent entries.

**Recovery runbook** (symptom: `load Rust xdp_userspace collection:
... BPF program is too large. Processed 1000001 insn`, daemon in
config-only mode):

```
git checkout -- pkg/dataplane/userspace_xdp_bpfel.o
make build
# redeploy; do NOT run make generate until the toolchain matches the pin
```

**Pin-bump procedure**: edit `userspace-xdp/rust-toolchain.toml` (and
`PINNED_BPF_LINKER_VERSION` in `build-userspace-xdp.sh` if bumping the
linker), run `make generate` (the verifier gate must PASS), commit the
regenerated `.o` together with the pin change, and require a clean
`git diff --exit-code pkg/dataplane/userspace_xdp_bpfel.o` after a
pinned re-run (builds are bit-for-bit reproducible for a given pin)
plus a cluster smoke before merge. `make generate` also refreshes
`userspace_xdp_manifest.json` in the same step (the recipe is a hashed
input, so a linker-pin bump moves the manifest too), so commit the
regenerated object and manifest together — the #4977 freshness gate
then stays green.

## Entry points

- `DataPlane` — `dataplane.go`. Legacy BPF-shaped interface kept for the
  legacy eBPF compiler and compatibility adapters (DPDK retired #1525). New
  daemon-facing code should not add methods here.
- DPDK backend deleted in #1528 (umbrella #1525). The `pkg/dataplane/dpdk`
  package no longer exists.
- `RuntimeDataPlane`, `ConfigSink`, `SessionStore`, `Telemetry`,
  `HAController`, and `LinkController` — `apply.go` and `session_store.go`.
  These are the split-domain interfaces used by daemon startup and runtime
  subsystems. `ConfigSink.ApplyConfig` is the daemon's apply-time
  compile/config entry point; userspace AF_XDP does not need to implement the
  legacy BPF-shaped `Compile` method just to receive committed config.
- `NewRuntimeDataPlane(dpType)` — `dataplane.go`. Runtime-domain constructor
  kept for the explicit legacy eBPF rollback, the retired-DPDK sentinel, and
  compatibility/test seams such as the userspace runtime registry round-trip.
  The daemon's default and explicit userspace boot path now goes through
  `userspace.Boot()` via `pkg/daemon/buildRuntimeDataPlane()`. The current
  userspace constructor still returns a compatibility adapter around
  `*userspace.Manager` until the remaining status/session-sync callers stop
  requiring `DataPlane`.
- `Manager` — `loader.go`. eBPF implementation.
- `New() *Manager` — `loader.go`.
- `Compile(cfg *config.Config) (*CompileResult, error)` — multi-phase
  lowering to BPF map entries. Phases live in `compiler.go`: zone IDs,
  screen profile IDs, **validate-before-mutate pre-pass**, zones, address
  book, applications, policies, NAT, static NAT, NAT64 prefixes, NPTv6,
  screen profiles, default policy, flow timeouts, firewall filters, flow
  config, port mirroring.
  - The pre-pass (`compiler_validate_4960.go`, #4960) re-runs the fallible
    HOST-PURE phases against a discarding dataplane BEFORE the zones phase
    performs the first destructive host netlink mutation, so a config that
    passes `commit check` but trips a later phase is REJECTED with nothing
    mutated instead of half-applied with no undo path. It can therefore fail
    the whole compile on its own. It is additive — every real phase keeps its
    position — but it does change WHICH error an operator sees when a config
    carries more than one fault. Precedence is the pre-pass ROW ORDER, because
    the pre-pass returns on the first failing row. An unknown screen-profile
    reference is no longer a zones-phase fault at all: it is a pre-pass row
    (`zone screen references`) sitting EARLIER in the table than
    `firewall filter protocols`, so it is the error reported when a config
    carries both. Read the order off `validationPhases` rather than trusting this
    sentence — the previous wording had the two the wrong way round. That file
    states what the pre-pass
    does and does not cover; the coverage table is not the whole compile.
- `CompileResult` — `compiler.go`. Zone/policy/NAT/app IDs, compiled
  policy-scheduler rule slots, and the per-interface networkd configs.
- Session iteration: `IterateSessions`, `BatchIterateSessions`,
  `IterateSessionsV6`, `BatchIterateSessionsV6`.
- Full-table clear (`clear security flow session all`): `ClearAllSessions`
  and `ClearAllSessionsChunked`. The table holds up to ~10M sessions per
  family, so the clear is both cooperative (yields between batches — #4719)
  and **bounded** (#5304): it collects at most `sessionClearSnapshotChunk`
  keys, deletes that chunk (+ its dynamic DNAT entries) via chunked
  `BPF_MAP_DELETE_BATCH`, then re-scans for the next chunk — peak key-slice
  memory is O(chunk), not O(table). Deleting every collected key before the
  next scan makes the loop converge (every key present at start is removed).
  `ClearAllSessionsChunked` invokes an optional per-chunk callback so the
  userspace wrapper (`userspace.Manager.ClearAllSessions`) can issue its
  authoritative Rust-helper delete on each bounded chunk instead of building
  a second full-table key snapshot of its own — the two coexisting full-table
  snapshots (wrapper v4+v6 + shim v4+v6 + DNAT lists) were the ~1 GB RSS spike
  that #5304 removed. In userspace mode the Rust helper is AUTHORITATIVE (it
  owns packet forwarding; the BPF table is a read model), so the wrapper's
  `ClearAllSessions` propagates a helper-delete IPC failure as a non-nil error
  rather than losing it in a log line (#5881): a failed authoritative
  revocation must not report success while the helper keeps forwarding under
  the "cleared" session. The bpf mirror's partial (v4, v6) counts are still
  returned alongside that error — the same non-atomic clear-all reporting
  contract the API handlers honor for a mid-clear mirror failure (#5882). A
  mirror-side error still takes precedence. The batch delete path
  (`BatchDeleteSessions{,V6}`) keeps the #5096 best-effort contract — the
  periodic session sync and GC delta reconcile a transient helper miss — so it
  discards the helper-delete error; only the operator clear-all propagates it.
- Session domain adapters: `SessionStoreOf`, `TelemetryOf`, and
  `NewDataPlaneSessionStore`. The generic `DataPlane` adapter preserves the
  batch-iteration fast path and centralizes cluster/GC companion ownership:
  cluster-synced forward installs create reverse and DNAT companions and roll
  back session writes if companion creation fails. Iteration callers that
  already have the session value must delete through `DeleteKnown*` or
  `DeleteBatchKnown*` so reverse/DNAT cleanup uses the authoritative
  iterator value, preserves persistent-NAT bindings, and keeps the batched
  map-delete fast path. `DeleteWithCompanions*` is retained for key-only
  HA delete messages.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/api`, `pkg/grpcapi`, `pkg/conntrack`.

## Dependencies

`appid`, `config`, `networkd`.

## BPF verifier and kernel constraints

These are the project's recurring traps. Read CLAUDE.md for the
authoritative list; quick recap:

- Branch merges lose packet range — re-read `ctx->data` / `ctx->data_end`
  after any branch.
- 512-byte combined stack across call frames — push large locals into
  scratch maps; mark big helpers `__noinline`.
- Variable-offset packet pointers lose range when `var_off` is wide
  (0xffff). Use a constant offset from a validated pointer.
- Mask `meta->l3_offset` (u16) with `& 0x3F` before packet-pointer
  arithmetic so the verifier can track the range (commit `66833c5`).
- `__u16` causes sign-extension (`smin=-32768`) — fails for packet-pointer
  math.
- Pointer bitwise OR is rejected (`if (sv4 || sv6)` where both are
  pointers triggers a compiler `|=` on pointer registers). Use separate
  null checks.
- xdp_zone fails the verifier on kernel 6.12 (NAT64 complexity); passes
  on 6.18+.

## SR-IOV / driver constraints

- iavf (VF) has no native XDP — generic mode only, ~16% CPU loss.
  i40e/ice on the PF have native XDP.
- `bpf_redirect_map` requires `ndo_xdp_xmit` on the target. Mixing native
  + generic interfaces in a redirect set silently drops.
- Workaround: per-interface `redirect_capable` flag in `bpf/xdp/xdp_forward.c`.
  Non-native interfaces fall back to `XDP_PASS` (kernel forwarding).
- The lab uses PF passthrough (i40e) on the WAN interface; all other
  interfaces are virtio with native XDP. Per-VF passthrough would need
  generic XDP and hit the iavf cliff.

## Flow export ownership

Flow export (NetFlow v9 / IPFIX) is owned by `pkg/flowexport` on the
**control plane**, driven by `pkg/logging.EventReader` SESSION_CLOSE
events. The userspace dataplane does NOT emit flow packets. The Rust
dataplane once carried a dead `FlowExporter` plus a write-only
`flow_export_config` field that emitted nothing; both were removed in
#2130. The Go→Rust `flow_export` snapshot wire field is retained as
reserved/ignored (the helper deserializes and drops it) to preserve the
#1977 decode-safety tests and avoid a wire-protocol break.

## Byte order

Use `binary.NativeEndian.Uint32(ip4)` for `__be32` BPF fields, **not**
`BigEndian`. cilium/ebpf serializes map values in native endian; the IP
bytes are already in network order on the wire.

## Arm-coverage proof (#5275, observe-only)

`armproof.go` computes whether the dataplane is genuinely armed for the
surfaces the current config requires. **It gates nothing.** It reports what a
gating build would have decided (`ArmCoverageReport.WouldGate`) so the
divergence rate can be measured across real deployments before the gate is ever
load-bearing — the eventual fix refuses to publish ownership, forwarding and
route/VIP advertisement until the proof passes.

Why a measurement phase: "armed" today is weaker than the proof.
`attachUserspaceShimXDP` treats a **native** XDP attach failure as a warning —
it detaches and re-attaches in generic (skb) mode, and only a *generic* failure
returns an error. A box therefore reports itself armed while running the whole
shim on the fallback path.

**Which stage this measures.** The plan's §5 takes the *final* proof after the
last mutation that can invalidate it — networkd, the RETH MAC link-cycle, and
the AF_XDP rebind / deferred-worker reapply. This proof runs inside
`CompileUserspaceShim`, i.e. at the **preliminary** attachment stage: it proves
the attach-point **inventory** and *reports* the program instance each tracked
`bpf_link` carries — it does **not** verify that instance is the shim's (see
the residual below) — and cannot see XSK binding readiness. The number it emits
is therefore the *preliminary-stage* divergence rate, a lower bound on the
gate's — not the gate's own rate.

Each surface resolves to exactly one of four kinds. The decisions below are
stated deliberately, not left to emerge from how the readback happens to be
written, because a later "tighten the proof" change would otherwise flip a
supported deployment to fail-closed with nobody intending it. Each is pinned by
a test in `armproof_5275_test.go`.

| Kind | Meaning |
|---|---|
| `direct` | A shim instance is attached here. **Native and generic both count.** |
| `delegated` | No attach is expected here by design; the **parent** covers it, and the parent is a required surface that itself classified `direct`. |
| `skipped` | The **compiler** declined to arm this surface and the compile still succeeded. A **third, distinct unknown**: neither proven covered nor proven forwarding-without-policy. `WouldGate` deliberately excludes it — see below. |
| `uncovered` | Nothing here and no proven delegate — including a failed readback, and a declined surface whose netdev was not proven down. |

- **Generic (skb-mode) counts as armed.** It still steers packets to
  userspace-dp and still enforces policy, at roughly 16% CPU overhead from the
  per-packet `sk_buff`. #5275 exists to prevent a *policy-free* kernel, and a
  fallback box is not policy-free. iavf SR-IOV VFs have no native XDP support at
  all, so this is a supported steady state — failing it closed would brick a
  supported deployment to prevent a condition that is not occurring.
- **The attach mode is read from the kernel, never from compile bookkeeping.**
  The native→generic fallback happens once and the resulting `m.xdpLinks` entry
  survives every later compile, so `AttachXDP` short-circuits on "already
  attached" and a per-compile record is empty from compile #2 onward while the
  box is still on skb-mode. Sourcing the flag from such a record would log "went
  native" on every commit after the first, on precisely the population this
  phase exists to count.
- **VLAN sub-interfaces are delegated, and the delegation is resolved.** Under
  the userspace shim a VLAN child is never attached (both attach loops skip it;
  it is recorded in `Manager.VlanSubInterfaces`) because the parent's XDP sees
  VLAN-tagged frames before kernel VLAN demuxing, and attaching the child breaks
  IPv6 NDP under generic-mode `XDP_PASS`. Policy is enforced — at a different
  attach point. A proof demanding an instance on every mapped attach point would
  fail every VLAN deployment; one that skipped VLAN children would pass a
  surface whose coverage was never checked. So the parent must be a **required**
  surface that itself classified `direct`, or the child reads as uncovered — a
  link that merely happens to be tracked is not enough, because an
  enabled→disabled commit leaves the old parent link in place while the parent
  is admin-DOWN and about to be torn down.
- **The delegate's `ParentIndex` is only read once the child is proven to be an
  802.1Q device.** vishvananda/netlink folds `IFLA_LINK` into
  `LinkAttrs.ParentIndex` in the *common* attribute loop, for every link kind —
  and what `IFLA_LINK` means is per-kind: a macvlan/ipvlan's lower device, a
  tunnel's bound device, and, the sharp one, a **veth's peer**, which for a
  cross-namespace pair is an ifindex in the *foreign* namespace that can
  numerically alias any local interface. Both branches that can make a child
  read as covered — the proven-down promotion to `skipped` and the delegation to
  a covered required parent — would then let an unrelated local interface answer
  for it, and both directions are **under**-counts that hide a live forwarding
  surface with no shim. It is reachable: `ensureVLANSubInterface` adopts *any*
  existing device named `<phys>.<vid>` without checking its kind, the ifindex is
  recorded as a delegated child, the userspace attach loop skips it, and the
  unmanaged sweep will not remove it because the name's prefix before `.` is a
  managed interface. So `coverDelegated` requires `Link.Type() == "vlan"`
  (`vlanLinkKind`) and otherwise reports `uncovered` with `Via` left zero —
  naming a bogus parent would repeat the same confusion in the log.
- **…and only once the parent is proven to be in THIS namespace.** The kind
  belt is necessary, not sufficient: a genuine 802.1Q device whose `real_dev`
  was left in another namespace keeps kind `"vlan"` and keeps a `ParentIndex`
  that now names an ifindex *over there*, aliasing local ifindexes just as
  freely. `coverDelegated` therefore also requires
  `LinkAttrs.NetNsID == netnsIDLocal` (`-1`). The kernel emits
  `IFLA_LINK_NETNSID` exactly when `link_net != dev_net`, and netlink seeds
  `-1` and overwrites it only from that attribute, so `-1` means "local
  parent". The test is `!= -1`, **not** `> 0`: a foreign parent's nsid is
  commonly **zero** (measured), and netlink parses the wire `s32` unsigned
  (`int(native.Uint32(...))`), so a wire `-1` arrives as `4294967295` — which
  `!= -1` still rejects, conservatively.
  - An earlier revision of this document claimed such an orphan is forced
    admin-DOWN, that `LinkSetUp` fails `ENETDOWN`, and that it is therefore not
    a live surface. **That was wrong**, and the experiment behind it only
    reproduced because it left the foreign `real_dev` DOWN. Re-measured: with
    the `real_dev` down, `LinkSetUp` does fail (rc=2, `ENETDOWN`, oper=down);
    bring it **up in its own namespace** and the orphan comes up
    (`up|broadcast|running`, oper=up) and forwards. `vlan_dev_open` refuses only
    while the `real_dev` is down.
- One limit is stated rather than assumed: the checks bind the *kind* and the
  parent's *namespace*, not the *configured* parent — an adopted VLAN stacked on
  a different local device delegates to that device, which stays honest because
  the parent's XDP really does see its tagged frames. The adoption itself is a
  separate production defect; these belts only stop the proof from laundering it
  into a covered count.
- **A surface the compiler declined to arm is not silently absent.**
  `compiler_iface.go` soft-skips **four** ways, each leaving the compile
  *successful* and the surface out of `pendingXDP`: the interface was not found,
  the VLAN child could not be created, the interface is administratively
  disabled, and — one frame up in `programZoneMaps` — the zone slot is nil. Each
  records an `UnarmedSurface`. The first three also emit a compiler-side `slog`
  line; the nil zone slot emits none, so the proof's own per-surface line is the
  only place it becomes visible.
  - `skipped` is **not** a claim that nothing forwards. It is the third unknown:
    the compiler did not look, so the proof cannot say. `WouldGate` excludes it
    because a clean `disable` is a legitimate operator action and folding every
    one into would-gate would swamp the measurement this phase exists to take.
    **The gating PR must decide** what a declined surface means to a gate; PR1
    only has to stop hiding it.
  - A VLAN child whose parent was declined and **proven down** inherits
    `skipped`, not `uncovered`. `compiler_iface.go` appends the child ~130 lines
    *above* the `isDisabled` check and never appends a disabled parent, so a
    clean `set interfaces ge-0-0-2 disable` leaves `ge-0-0-2.50` in the required
    set with its delegate outside it. Reading that as uncovered would drive
    would-gate on a legitimate operator action, on precisely the interface shape
    both reference deployments run (`reth0.50`/`reth0.80` on the loss cluster,
    VLAN 50 on the standalone VM) — an inflated baseline is the failure this
    phase exists to prevent. A VLAN device cannot pass traffic while its real
    device is DOWN, so a proven-down parent proves the child is not forwarding
    either. If the parent's `LinkSetDown` *failed*, the child rides a netdev that
    may still be up, zoned and XDP-less, so it stays `uncovered`.
  - The sharp case is promoted: a `disable` whose `netlink.LinkSetDown` fails
    (or whose link never resolved, so the down was never attempted) leaves the
    netdev up, still address-reconciled, still in a zone, still forwarded
    through, with no XDP — reported `uncovered`. `disabledSurfaceRecord` makes
    that judgement, split out so it is unit-testable; producing the condition
    needs `CAP_NET_ADMIN`, deciding what it *means* does not.
  - Absence is not assumed from an error nobody read. `net.InterfaceByName`
    reports a genuine absence and a netlink **dump failure** through the same
    `*net.OpError`; a dump failure proves nothing about whether the netdev
    exists, so `missingInterfaceRecord` treats a wrapped `syscall.Errno` as
    possibly-still-forwarding.
  - The nil zone slot is recorded at **zone** level (`zone:<name>`) and stays
    `skipped`: `zone.Interfaces` is precisely the deref the nil guard prevents,
    so its surfaces are unknowable there. It is an enumeration gap the
    measurement can now see — and it is reachable on the HA config-sync path,
    where the rate was previously biased optimistic.
  - One record per surface, keyed on `(Name, Ifindex)`. `mapZoneInterface` runs
    once per *zone reference* and the per-phys dedup sits below the skips, so an
    interface named by two zones would otherwise be counted twice; a repeat
    sighting never downgrades the classification. The key is why the record must
    name the **configured** surface: `mapZoneInterface` resolves `reth0.50` to
    its parent *before* the lookup, so filing a missing child under the parent's
    name folds every child of one absent parent — and the parent's own record —
    into a single entry, while a parent that resolves yields one record per
    surface. `missingInterfaceRecord` therefore takes the VLAN id and names
    `<parent>.<vid>`, keeping the parent in the reason.
- **`XDP_ATTACHED_MULTI` counts as generic.** It means programs are attached in
  more than one mode, and it is reachable — `attachUserspaceShimXDP` discards
  `DetachXDP`'s error on the native-fallback path. Reading it as native would
  undercount the slow-path population, the same direction as the defect that
  moved the flag to the kernel.
- **Residual: the program instance is reported, not verified.**
  `xdpLinkProgramID` accepts **any** readable program id. It does not compare
  it against `m.programs[m.XDPEntryProgram()]` — the program `AttachXDP`
  installs — and does not check `Info.XDP().Ifindex` against the ifindex being
  proved. A `direct` verdict therefore means *an instance exists here and this
  is its id*, not *the shim covers this surface*. It is sound today only by an
  invariant held **elsewhere**: every writer of `m.xdpLinks` installs
  `m.programs[m.XDPEntryProgram()]` (`AttachXDP`'s fresh attach and its
  pinned-link `Update` reuse, plus `swapXDPEntryProg`, which updates the links
  and only then renames the entry program), post-#1476 `m.programs` has a single
  shim writer with the legacy entry program never loaded, and nothing outside the
  package can reach a tracked link (`Program(name)` is a read-only getter;
  `m.xdpLinks` has no accessor). So a mismatch is not a state this tree can
  produce, and adding the comparison to a *diagnostic* would measure nothing
  while adding a new way to report a false `uncovered` — an unreadable expected
  program. **The gating PR must add it**: a build that withholds ownership,
  forwarding and route/VIP advertisement cannot rest its refusal on an invariant
  upheld by its callers, and it has to decide the direction this phase has no
  evidence for — whether an unreadable expected program fails closed. Plan
  §13/D1 carries the same split.

`CoverageUncovered` is deliberately the zero value: an unpopulated entry must
read as *not* covered, so a partially-built report can only ever be more
conservative.

**Observe-only, stated exactly.** The proof writes no Go state — not the
`Manager`, and not the `CompileResult` it is proving (link resolution uses the
non-memoising `peekLinkByIndex`, not `cachedLinkByIndex`). It does read live
kernel and bpf state, and the cost is per surface *kind* rather than uniform: a
`direct` surface with a tracked link costs one `RTM_GETLINK` for the attach mode
plus one bpf_link info call for the program identity, and nothing at all when no
link is tracked; a `delegated` surface costs at most one `RTM_GETLINK` to
resolve its parent and never a bpf_link call, because it reuses the parent's
already-computed classification; a declined surface is rendered from its
recorded struct and costs nothing.

**One summary line per compile, not per apply.** A single daemon apply compiles
twice on the RETH deferred-MAC path (`reapplyAfterDeferredMAC`), so the apply
generation is folded into the stage label (`stage=post-attach#7`) to keep the
two records apart. The summary line is emitted even when the proof enumerated
nothing, carrying `ran=true`: suppressing it would make "nothing to arm", "the
proof never ran" and "this build has no proof" identical in a log archive.
Beyond the summary, `uncovered` surfaces add one `WARN` each and `skipped`
surfaces one `INFO` each — a fully-covered box stays at the single line, and
the two levels are deliberate: `WARN` is the would-gate set, while a skip's
dominant member is a clean `disable`, so logging it at `WARN` would train
operators to ignore both.
