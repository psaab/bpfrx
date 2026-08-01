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
6. **Verifier-headroom tripwire (#4555)** — every layer above is BINARY:
   the object loads or it does not. That is exactly how the shim came to
   sit at 990,796 of 1,000,000 processed insns (0.92% headroom) with all
   five gates green, until a routine change to the IPv6 extension-header
   walk hit the 1M wall and had to be redesigned around the budget. So
   `shimverify` now also reads the verifier's own accounting
   (`LogLevelStats` → `processed N insns (limit M)`) and refuses a
   candidate that LOADS but leaves less than
   `UserspaceShimMinVerifierHeadroomPct` (3%) unused.
   - **Exit codes**: `0` PASS, `3` verifier REJECT, `4` loads but below
     the floor, `5` loads but headroom could NOT be measured, `2` usage,
     `1` other. The recipe has an arm for each.
   - **Unmeasurable is a failure, deliberately.** If the running kernel's
     log carries no recognisable stats line the floor cannot be applied,
     and passing there would switch the gate off at the one moment
     headroom is unknown — reproducing the blind spot it exists to close.
   - **Override**: `XPF_SHIM_ALLOW_LOW_HEADROOM=1` covers both refusals,
     mirroring `XPF_SHIM_ALLOW_UNPINNED_INSTALL`. It is threaded through
     the `sudo` hop explicitly (sudo scrubs the environment, so it would
     otherwise be a silent no-op). Consuming it prints a loud banner
     naming the object and the reason; a run that did NOT need it but has
     it set prints a staleness note, because the variable lives in the
     ambient environment and a value exported once would otherwise
     disarm the gate forever.
   - 3% is a tripwire, not a performance target: it says "the next change
     here will not fit" while there is still room to plan.

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
  screen profile IDs, zones, address book, applications, policies,
  NAT, static NAT, NAT64 prefixes, NPTv6, screen profiles, default
  policy, flow timeouts, firewall filters, flow config, port
  mirroring.
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

### IPv6 extension-header walk: the shim's budget is nearly spent (#4555)

The shim's `parse_ipv6` extension-header loop is fully unrolled, so every
iteration duplicates each arm body and its `read_bytes` range
re-validation. It is the single largest consumer of the 1M processed-insn
verifier cap, and the pre-#4555 shim sat at **990,796 of 1,000,000 — under
1% headroom**. Measured on the pinned toolchain via `cmd/shimverify`
(kernel 7.0), varying only `MAX_EXT_HDRS` and whether the generic arm
carries the full #4517 type set:

| `MAX_EXT_HDRS` | #4517 types (135/139/140/253/254) | verdict | processed insns |
|---|---|---|---|
| 6 | no (pre-#4555) | PASS | 990,796 |
| 6 | yes | PASS | 874,873 |
| 7 | no | **REJECT** | — |
| 7 | yes (current) | PASS | 947,188 |
| 8 | no | **REJECT** | — |
| 8 | yes | **REJECT** | 1,000,001 |

Two things to carry away:

- **8 is unreachable.** Do not "just bump it to match userspace" — the
  candidate does not load, and `make generate` fails closed at the #1864
  verify-then-install gate (the tracked `.o` is left untouched).
- **The bound and the type set are coupled.** Widening the generic arm to
  the full #4517 set is what makes bound 7 affordable: folding five more
  next-header values into one shared arm body prunes more verifier state
  than the five extra compares cost. Bound 7 with the narrow set is
  rejected; with the wide set it passes with 5.3% headroom.

**Parity relation.** `MAX_EXT_HDRS` (shim) and `MAX_IPV6_EXT_HEADERS`
(`userspace-dp/src/afxdp/frame/inspect.rs`) are ITERATION counts whose
loops exit differently, so they are deliberately NOT equal:

- the shim spends one iteration per extension header and exits by
  EXHAUSTION carrying the last declared next-header value straight into
  `parse_l4` (no post-loop over-limit check) — it resolves chains of up to
  `MAX_EXT_HDRS` extension headers;
- `walk_ipv6_ext_chain` needs one FURTHER iteration to return the terminal
  and folds exhaustion into the fail-closed `OverLimit` verdict
  (#2292/#4743) — it resolves up to `MAX_IPV6_EXT_HEADERS - 1`.

So the correct condition is `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1`
(7 and 8): both walkers resolve 0..=7 extension headers and both refuse 8
or more.

**The two mismatch directions are not symmetric.** Only shim-BELOW-userspace
is fail-closed: the shim's unresolved chain leaves the extension-header type
in `ParsedPacket::protocol` with `parse_l4`'s catch-all ports 0/0, so the
session key misses and the packet is redirected to userspace for full
policy — it costs that flow the XDP fast path permanently, nothing more.
Shim-ABOVE-userspace is the direction never to take: the shim would stamp a
full 5-tuple and `l4_offset` for a chain `walk_ipv6_ext_chain` refuses with
`OverLimit`, and hand that meta to consumers that trust it. Independently of
that argument, bound 8 does not load — see the table above.

**`parsed.protocol` is not only a session-key ingredient.** It also drives
pre-session dispatch that terminates in the shim: ESP and non-native GRE to
`cpumap_or_pass` (kernel XFRM / tunnel decap), WireGuard-to-firewall via
`wg_steer_to_kernel`, ICMPv6 NDP 133-137 via `pass_local_control`. Widening
the walked type set therefore re-routes packets between the XSK path and the
kernel path — `IPv6 → Mobility → ESP` reached userspace over XSK before
#4555 and now goes to the kernel stack, matching how `DestOpt → ESP` already
behaved and how userspace-dp classifies the same chain. On the userspace
side `meta.protocol` feeds NAT64 translation and L4 checksum recomputation
(`frame/mod.rs`), so walk agreement matters well beyond telemetry.

`tests_shim_ext_parity.rs` in userspace-dp fails on drift in either the
resolvable chain length or the walked type set. Because it models the shim
from source rather than executing it (the shim is `no_std`, built for
`bpfel-unknown-none`), it pins the loop header, requires the loop body to
contain nothing but the `match protocol` block, and compares each arm body
by whitespace-normalised token equality — a substring test let an altered
advance, or a prepended `if opt[1] == 0 { break; }`, pass green.

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
