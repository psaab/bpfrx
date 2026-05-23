# #1476 Legacy BPF Source-Removal Manifest

Status: manifest-only preparation for #1476. This document records the
intended deletion boundary for the later source-removal PR. No source,
generated object, loader hook, or Makefile generation path is deleted by this
slice.

## Dependency Order

The removal path must land in this order:

1. #1494 canary: merge the userspace shim boundary canaries so the retained
   Rust XDP shim cannot silently grow legacy fallback behavior.
2. #1493 loader split: make userspace startup load only the retained Rust XDP
   shim and the shared AF_XDP maps it requires, without calling the legacy
   `loadAllObjects()` graph.
3. #1451 surface shrink: finish moving runtime and operator callers off the
   legacy eBPF-shaped `dataplane.DataPlane` surface, leaving no source-removal
   dependency on the root legacy manager.
4. #1476 deletion: remove the legacy BPF source, generated artifacts, and stale
   build hooks listed here.
5. #1477 final evidence: publish userspace-only validation artifacts for the
   exact #1476 deletion candidate.

## Delete Manifest

### Legacy BPF Root Docs

Delete the root legacy BPF tree README with the source tree it describes:

- `bpf/README.md`

### Legacy XDP Source

Delete these legacy ingress dataplane programs after the dependency order above
is satisfied:

- `bpf/xdp/xdp_conntrack.c`
- `bpf/xdp/xdp_cpumap.c`
- `bpf/xdp/xdp_forward.c`
- `bpf/xdp/xdp_main.c`
- `bpf/xdp/xdp_nat.c`
- `bpf/xdp/xdp_nat64.c`
- `bpf/xdp/xdp_policy.c`
- `bpf/xdp/xdp_screen.c`
- `bpf/xdp/xdp_zone.c`
- `bpf/xdp/README.md`

### Legacy TC Source

Delete these legacy egress dataplane programs after #1493 proves userspace
startup no longer needs TC program objects or the `tc_progs` tail-call map:

- `bpf/tc/tc_conntrack.c`
- `bpf/tc/tc_forward.c`
- `bpf/tc/tc_main.c`
- `bpf/tc/tc_nat.c`
- `bpf/tc/tc_screen_egress.c`
- `bpf/tc/README.md`

### Generated Legacy bpf2go Artifacts

Delete every tracked legacy `xpf*` bpf2go Go wrapper and embedded object. The
current tree has 14 generated Go/object pairs:

- `pkg/dataplane/xpftcconntrack_x86_bpfel.go`
- `pkg/dataplane/xpftcconntrack_x86_bpfel.o`
- `pkg/dataplane/xpftcforward_x86_bpfel.go`
- `pkg/dataplane/xpftcforward_x86_bpfel.o`
- `pkg/dataplane/xpftcmain_x86_bpfel.go`
- `pkg/dataplane/xpftcmain_x86_bpfel.o`
- `pkg/dataplane/xpftcnat_x86_bpfel.go`
- `pkg/dataplane/xpftcnat_x86_bpfel.o`
- `pkg/dataplane/xpftcscreenegress_x86_bpfel.go`
- `pkg/dataplane/xpftcscreenegress_x86_bpfel.o`
- `pkg/dataplane/xpfxdpconntrack_x86_bpfel.go`
- `pkg/dataplane/xpfxdpconntrack_x86_bpfel.o`
- `pkg/dataplane/xpfxdpcpumap_x86_bpfel.go`
- `pkg/dataplane/xpfxdpcpumap_x86_bpfel.o`
- `pkg/dataplane/xpfxdpforward_x86_bpfel.go`
- `pkg/dataplane/xpfxdpforward_x86_bpfel.o`
- `pkg/dataplane/xpfxdpmain_x86_bpfel.go`
- `pkg/dataplane/xpfxdpmain_x86_bpfel.o`
- `pkg/dataplane/xpfxdpnat64_x86_bpfel.go`
- `pkg/dataplane/xpfxdpnat64_x86_bpfel.o`
- `pkg/dataplane/xpfxdpnat_x86_bpfel.go`
- `pkg/dataplane/xpfxdpnat_x86_bpfel.o`
- `pkg/dataplane/xpfxdppolicy_x86_bpfel.go`
- `pkg/dataplane/xpfxdppolicy_x86_bpfel.o`
- `pkg/dataplane/xpfxdpscreen_x86_bpfel.go`
- `pkg/dataplane/xpfxdpscreen_x86_bpfel.o`
- `pkg/dataplane/xpfxdpzone_x86_bpfel.go`
- `pkg/dataplane/xpfxdpzone_x86_bpfel.o`

The eventual deletion PR must rerun the manifest canary before and after the
delete. If any additional tracked `pkg/dataplane/*_bpfel.go`,
`pkg/dataplane/*_bpfel.o`, `pkg/dataplane/*_bpfeb.go`, or
`pkg/dataplane/*_bpfeb.o` file exists and is not explicitly retained, it must
be added to this section before deletion.

### Legacy Build Hooks

Remove or rewrite these build hooks in the deletion PR:

- `pkg/dataplane/loader.go`: remove the legacy bpf2go `go:generate`
  directives that target `bpf/xdp/*.c` and `bpf/tc/*.c`.
- `pkg/dataplane/loader_ebpf.go`: remove references to the generated
  `xpfXdp*` and `xpfTc*` loader types once #1493 has supplied the userspace
  shim bootstrap path.
- `pkg/dataplane/loader_stub.go`: remove the stale ignored generated-binding
  stub if no replacement uses it.
- `Makefile`: remove the legacy `generate-legacy-bpf` target, stop using broad
  generation to rebuild deleted programs, and remove unused legacy BPF
  variables such as `BPF_CFLAGS` if no remaining target consumes them.
- `Makefile clean`: narrow the generated-artifact cleanup so it no longer
  erases retained shim artifacts.

### Legacy Tests and Active Docs

Do not blanket-delete `pkg/dataplane` tests. The deletion PR should remove or
rewrite only tests that directly exercise the deleted legacy loader, generated
legacy objects, XDP/TC attach graph, or stale generation commands. Tests for
shared structs, userspace map sync, retained shim loading, and runtime boundary
canaries must stay unless they are replaced by narrower userspace-only tests.

Active docs and workflow references that describe legacy bpf2go generation as
the normal path must be rewritten. Historical plans under `docs/archived/`,
`docs/issues/`, and old `docs/pr/*` directories may keep legacy references when
they are clearly historical. Current docs must not instruct developers to run a
deleted XDP/TC generation path.

## Retain Manifest

These paths are not part of the #1476 legacy source deletion:

- `userspace-xdp/`: Rust source for the retained AF_XDP entry shim.
- `pkg/dataplane/userspace_xdp_bpfel.o`: retained embedded Rust XDP shim
  object.
- `pkg/dataplane/userspace_xdp_rust.go`: retained Go embed/load wrapper for the
  Rust shim object.
- `pkg/dataplane/build-userspace-xdp.sh`: retained shim-only build script until
  a replacement generation path exists.
- `test/xsk-repro/`: AF_XDP/XSK lab tooling, not the legacy forwarding
  dataplane.
- `pkg/dataplane/userspace/`: userspace manager, map sync, status, and shim
  tests.
- `pkg/dataplane/runtime/`: runtime-facing contracts that must stay independent
  from BPF artifacts.

Retain `bpf/headers/*.h` until each shared constant, struct, and helper
dependency is either moved to a userspace-owned schema or explicitly retired:

- `bpf/headers/xpf_common.h`
- `bpf/headers/xpf_conntrack.h`
- `bpf/headers/xpf_helpers.h`
- `bpf/headers/xpf_maps.h`
- `bpf/headers/xpf_nat.h`
- `bpf/headers/xpf_trace.h`
- `bpf/headers/README.md`

The headers are not all dead with the XDP/TC source. The current tree still
uses or cites them for `MAX_INTERFACES`, Go constants, userspace shim build
inputs, userspace-dp struct parity tests, and DPDK shared-memory parity. A
future PR may move these definitions, but that is a separate reviewed boundary.
`xpf_helpers.h` and `xpf_trace.h` have weaker current non-legacy consumers than
the struct/constant headers; keep them conservatively until the deletion PR can
prove they are orphaned after the legacy source is removed.

## Proof Required Before Deletion

Before the #1476 deletion PR removes any source or generated artifact, it must
show all of the following:

- #1494 is merged and the userspace shim boundary canaries pass.
- #1493 is merged and userspace startup no longer calls `loadAllObjects()`,
  `loadXpfXdpMain()`, any legacy XDP/TC tail-call loader, or the legacy
  `xdp_main_prog`/`tc_main_prog` program-map bootstrap.
- #1451 has shrunk the root `dataplane.DataPlane` compatibility surface so API,
  gRPC, CLI, status, monitor, logging, cluster sync, conntrack GC, and daemon
  runtime paths do not require the legacy eBPF manager.
- DPDK remains confined to its documented backend policy or has its own explicit
  migration result; userspace-only source removal must not delete DPDK-required
  shared definitions by accident.
- `go test ./pkg/dataplane -run 'Test.*Manifest|Test.*Boundary|Test.*UserspaceXDP' -count=1`
  passes with this manifest and the then-current canaries.
- `go generate -n -run '^//go:generate bash build-userspace-xdp\.sh$' ./pkg/dataplane`
  selects only the retained shim build.
- A post-delete `rg` scan finds no production references to deleted generated
  symbols such as `xpfXdp*`, `xpfTc*`, `loadXpfXdp*`, or `loadXpfTc*`.
- A post-delete `rg` scan finds no active workflow instruction that still
  requires legacy `bpf/xdp`, `bpf/tc`, or bpf2go generation.
- The full userspace test gate and the #1477 cluster validation bundle pass on
  the exact deletion candidate.

## Adversarial Review Checklist

Reviewers of the deletion PR should explicitly check these failure modes:

- retained shim artifacts are not included in the deletion list or removed by
  `make clean`;
- tracked generated legacy artifacts are all covered by this manifest, and no
  untracked `_bpfel`/`_bpfeb` leftovers are hiding outside Git;
- stale `go:generate`, `make generate`, `make clean`, README, and development
  workflow references are removed or rewritten;
- DPDK policy remains explicit and no DPDK-only shared struct dependency is
  lost as collateral damage;
- `bpf/headers/*.h` consumers have either been moved to a userspace-owned
  source of truth or are still retained intentionally; and
- historical docs remain historical, while active docs no longer describe the
  deleted legacy dataplane as the normal build or rollback path.
