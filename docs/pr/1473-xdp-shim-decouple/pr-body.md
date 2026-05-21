## Summary

- Remove the userspace XDP shim tail-call dependency on `xdp_main_prog`.
- Keep `xdp_userspace_prog` as the userspace-mode XDP entry program.
- Make degraded userspace runtime behavior explicit: compat and strict modes
  pass only proven local/control traffic and fail closed for non-local transit.
- Stop requiring `userspace_fallback_progs` / `xdp_main_prog` during userspace
  bootstrap and lifecycle paths.
- Publish `userspace_ctrl.enabled=1` only after the userspace binding and
  local/control maps have been refreshed.
- Keep local/control address maps non-empty across refreshes by adding desired
  keys before deleting stale keys.
- Force `userspace_ctrl.enabled=0` on enabled-path publication failures so stale
  bindings or metadata cannot stay live after a partial update.
- Route degraded IP local/control delivery through `cpumap_or_pass` when cpumap
  is available; direct `XDP_PASS` remains only for non-IP local L2 frames such
  as ARP/LLDP.

## Validation

- PASS: `pkg/dataplane/build-userspace-xdp.sh`
- PASS: `go test ./pkg/dataplane/userspace ./pkg/dataplane`

## Local Smoke Artifact

Cluster smoke on `loss:xpf-userspace-fw0/fw1` was not run from this worktree.
The local artifact for this PR is the rebuilt userspace XDP object plus the Go
test matrix above. The Go tests add privileged XDP test-run coverage for:

- ctrl-disabled transit drops with `transit_drop`
- ctrl-disabled local/control delivery
- binding-not-ready transit drop versus local/control delivery
- ctrl publication remaining disabled if binding map publication fails
- fail-closed ctrl disable after a previously-live publication failure
- local address map add-before-remove behavior on refresh failure
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
