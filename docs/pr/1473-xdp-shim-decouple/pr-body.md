## Summary

- Remove the userspace XDP shim tail-call dependency on `xdp_main_prog`.
- Keep `xdp_userspace_prog` as the userspace-mode XDP entry program.
- Make degraded userspace runtime behavior explicit: compat mode uses kernel
  pass-through from the shim, while strict mode fails closed.
- Stop requiring `userspace_fallback_progs` / `xdp_main_prog` during userspace
  bootstrap and lifecycle paths.

## Validation

- PASS: `pkg/dataplane/build-userspace-xdp.sh`
- PASS: `go test ./pkg/dataplane ./pkg/dataplane/userspace`

Refs #1473.

## Remaining Blocker

This PR decouples userspace runtime operation from the legacy `xdp_main_prog`
fallback path, but it does not remove the broader legacy eBPF loader
dependency. The userspace manager still uses the existing `dataplane.Manager`
for shared BPF maps, XDP attachment plumbing, TC egress state, and generated
object loading. Fully removing `xdp_main_prog` from the userspace load graph
requires a separate loader/map-bootstrap split so userspace can load only the
retained shim and the shared maps it still needs.
