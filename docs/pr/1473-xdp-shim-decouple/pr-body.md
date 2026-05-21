## Summary

- Remove the userspace XDP shim tail-call dependency on `xdp_main_prog`.
- Keep `xdp_userspace_prog` as the userspace-mode XDP entry program.
- Make degraded userspace runtime behavior explicit: compat and strict modes
  pass only proven local/control traffic and fail closed for non-local transit.
- Stop requiring `userspace_fallback_progs` / `xdp_main_prog` during userspace
  bootstrap and lifecycle paths.
- Publish `userspace_ctrl.enabled=1` only after the userspace binding and
  local/control maps have been refreshed.
- Keep local/control and interface-NAT address maps non-empty across refreshes
  by adding desired keys before deleting stale keys.
- Force `userspace_ctrl.enabled=0` on enabled-path publication failures so stale
  bindings or metadata cannot stay live after a partial update.
- Route degraded IP local/control delivery through `cpumap_or_pass` when cpumap
  is available; direct `XDP_PASS` remains only for non-IP local L2 frames such
  as ARP/LLDP.
- Keep degraded local/control classification inline in `xdp_userspace_prog` so
  the kernel verifier sees the packet-bound proof for nested GRE parsing.

## Validation

- PASS: `pkg/dataplane/build-userspace-xdp.sh`
- PASS: `go test ./pkg/dataplane/userspace ./pkg/dataplane`
- PASS: object-symbol audit shows no standalone
  `is_degraded_local_or_control` BPF subprogram:
  ```bash
  llvm-objdump -t pkg/dataplane/userspace_xdp_bpfel.o |
    rg 'is_degraded|classify_native|xdp_userspace|parse_l4'
  ```

## Smoke Artifact

Cluster smoke was run from this worktree on
`loss:xpf-userspace-fw0/fw1`.

- Artifact root: `/tmp/pr1481-smoke-20260521-100909`
- Deployed head: `8dd77a94ddbbf797469ca2a15e8104b213eefaf7`
- Deploy note: `GOFLAGS=-buildvcs=false` was needed because this `/tmp`
  worktree sits under a stray `/tmp/.git` that breaks Go VCS stamping. The
  Makefile still supplied explicit version and commit `-ldflags`.
- Runtime: `userspace-ha-validation.sh` reported `runtime mode: supported`
  and armed userspace forwarding on `loss:xpf-userspace-fw0`.

Baseline validation:

| Cell | Avg Gbps | Peak Gbps | Retransmits | Result |
| --- | ---: | ---: | ---: | --- |
| IPv4 push | 23.303 | 23.424 | 2 | PASS |
| IPv6 push | 23.070 | 23.184 | 2 | PASS |

CoS-off v4/v6 push and reverse:

| Cell | Avg Gbps | Peak Gbps | Retransmits | Result |
| --- | ---: | ---: | ---: | --- |
| v4 push | 23.392 | 23.476 | 1 | PASS |
| v4 reverse | 23.069 | 23.189 | 69 | PASS |
| v6 push | 20.953 | 21.523 | 1 | PASS |
| v6 reverse | 22.309 | 22.533 | 0 | PASS |

CoS-on bounded smoke after `apply-cos-config.sh --symmetric`, using the
uncapped class on port `5211`:

| Cell | Avg Gbps | Peak Gbps | Retransmits | Result |
| --- | ---: | ---: | ---: | --- |
| v4 push p5211 | 8.470 | 8.822 | 3,658 | PASS |
| v4 reverse p5211 | 7.973 | 8.349 | 8,979 | PASS |
| v6 push p5211 | 7.875 | 8.398 | 1,603 | PASS |
| v6 reverse p5211 | 8.558 | 8.601 | 37,573 | PASS |

The CoS-on run is a bounded dataplane smoke, not the full #1373 12-class
fairness qualification gate. It proves the shim loads, arms, and carries
v4/v6 push and reverse traffic with CoS enabled without collapse.

The Go tests add privileged XDP test-run coverage for:

- ctrl-disabled transit drops with `transit_drop`
- ctrl-disabled local/control delivery
- binding-not-ready transit drop versus local/control delivery
- ctrl publication remaining disabled if binding map publication fails
- fail-closed ctrl disable after a previously-live publication failure
- local and interface-NAT address map add-before-remove behavior on refresh
  failure
- cpumap delivery for degraded IP local/control and ICMPv6 NDP
- degraded ESP delivery to interface-NAT local addresses
- direct pass-through limited to non-IP local L2 frames

In unprivileged local environments, the XDP test-run cases skip at the BPF
memlock/capability gate; the manager ordering regression still compiles with
the package test run.

Refs #1473.

## Remaining Blocker

This PR decouples userspace runtime operation from the legacy `xdp_main_prog`
fallback path, but it does not remove the broader legacy eBPF loader
dependency. The userspace manager still uses the existing `dataplane.Manager`
for shared BPF maps, XDP attachment plumbing, TC egress state, and generated
object loading. Fully removing `xdp_main_prog` from the userspace load graph
requires a separate loader/map-bootstrap split so userspace can load only the
retained shim and the shared maps it still needs.
