# pkg/cli

Interactive Junos-style CLI: readline-driven REPL with tab completion, `?`
help, prefix matching, `| match` filtering, and command history. Used by
both the daemon-local CLI (xpfd in TTY mode) and the remote CLI
(`cmd/cli`) once it has a gRPC connection.

## Entry points

- `CLI` — `cli.go`. The REPL engine.
- `New(...)` — `cli.go`. Takes ~10 injected managers (configstore,
  dataplane, cluster, frr, dhcp, …). The package has no globals.
- The readline command tree is compiled from `pkg/cmdtree` at REPL
  start; add a new command in `pkg/cmdtree/tree.go` and it shows up
  here, in the remote CLI, and in gRPC tab completion automatically.
- Per-injection setters: `SetForwardingSampler`, `SetRPMResultsFn`,
  `SetFeedsFn`, `SetLLDPNeighborsFn`, `SetVRRPManager`,
  `SetApplyConfigFn`, `SetCommitFns`, …. All on `*CLI`.

## Callers

`cmd/cli` (remote client), `cmd/xpfd` (when stdin is a TTY).

## Dependencies

`appid`, `cluster`, `cmdtree`, `config`, `configstore`, `dataplane`,
`dhcp`, `dhcprelay`, `feeds`, `frr`, `ipsec`, `lldp`, `logging`, `routing`,
`rpm`, `vrrp`.

## Gotchas

- TTY detection uses `unix.IoctlGetTermios(fd, TCGETS)`, **not**
  `os.ModeCharDevice` — `/dev/null` matches `ModeCharDevice` and would
  trick the latter into starting an interactive session in a systemd unit.
- Commits prefer the daemon's atomicity primitive: `commitFn` and
  `commitConfirmedFn` hold the apply semaphore across `store.Commit()` and
  the dataplane apply. This serializes CLI commits with HTTP/gRPC
  commits (#846). Falls back to `store.Commit()` + `applyConfigFn` only
  when the daemon hookups are absent (test/standalone).
- `fwdSampler` (forwarding CPU stats) can be `nil` — every show handler
  null-checks it.
- Session filters (`session_filter.go`) serve BOTH show and clear. The
  clear path must call `validate()` (unknown zone/pool names are
  command errors — an inert filter degrades into clear-nothing or, via
  `hasFilter()`, clear-ALL) and `populateIfaceMaps()` (interface
  matching needs the zone/egress maps; only show built them before
  #1827 PR-3). Peer-forwarded clears go through
  `buildPeerClearRequest` — every filter dimension must be carried,
  because an empty `ClearSessionsRequest` means clear-all to the peer.
  Key ports are network byte order (`ntohs` before comparing) and
  dataplane IPv4 NAT fields decode with NativeEndian (`uint32ToIP`).
- `show security match-policies` (`showMatchPolicies`) and `test policy`
  (`testPolicy`) are THIN adapters over the single shared policy simulator
  `pkg/policymatch` (#3042) — the same matcher the REST and gRPC surfaces
  use. The pre-#3042 hand-written CLI matchers (the removed
  `matchPolicyAddr`/`matchPolicyApp`/`matchSingleApp` in `cli_helpers.go`)
  scanned only zone-pair policies, hard-coded a `default deny` message, and
  missed predefined apps, multi-level application-sets, literal CIDRs,
  `any-ipv4`/`any-ipv6`, and source/destination exclusion — so the
  diagnostic could report the OPPOSITE of what the dataplane enforces.
  `policymatch.Match` now honors the configured `default-policy` and reports
  whether a global policy matched. #3104: `show security match-policies` and
  `test policy` thread live per-scheduler active-state
  (`c.policyInactiveFn()` → `policymatch.Query.PolicyInactiveFn`) so a
  scheduler-inactive policy is skipped like the runtime. #3414: `policyInactiveFn()`
  is now ALWAYS non-nil — with no live state (no provider / early boot) it binds
  a nil state map, which fails closed so scheduled policies are simulated as
  INACTIVE (matching the dataplane's nil-state => dropped) rather than certified
  as-if-active.
