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

## Request / diagnostic command files (#4653)

The operational request and diagnostic handlers were historically one
1300-line `cli_request.go` grab-bag. They are split by command family into
sibling files (same package, so unexported helpers stay reachable):

- `cli_request.go` — the `handleRequest` dispatch shell plus the small
  `request dhcp` / `request protocols` handlers.
- `cli_request_ping.go` — `ping` / `traceroute` and their `diagcmd` argv
  builders (`buildPingArgv`, `buildTracerouteArgv`).
- `cli_request_testcmd.go` — `test policy` / `test routing` /
  `test security-zone` (the `policymatch` adapters).
- `monitor_traffic.go` — `monitor` dispatch + `monitor traffic` tcpdump
  wrapper (joins the sibling `monitor.go` / `monitor_interface.go`).
- `cli_request_chassis.go` — `request chassis cluster failover` /
  `data-plane`.
- `cli_request_system.go` — `request system reboot|halt|power-off|zeroize`
  and `software` / `configuration` / `dynamic-dns`.
- `cli_request_security.go` — `request security ipsec|policies|wireguard`.

The security-sensitive `--` end-of-options separators in the diagcmd/tcpdump
argv builders (#2084 / #4524 / #4527) moved verbatim.

Fail-open hardening (#4883): `parseMonitorTrafficArgs` (`monitor_traffic.go`)
rejects an empty/unrecognized `matching` predicate instead of launching an
UNFILTERED capture, and the `monitor security flow` writer goroutine
(`monitor.go`) clears `active/cancel/sub` and records `lastErr` when the trace
writer fails — so a disk-full/rotation error no longer wedges the monitor
Active (surfaced by `show monitor security flow`).

## `show interfaces` render files (#4654)

The `show interfaces` presenters were historically one 1396-line
`cli_show_interfaces.go`, where the RETH/member display logic repeated
across the summary/terse/detail/extensive modes and drifted (the #4328
family of fixes). They are split per render mode plus a shared
RETH/kernel-query helper file (same package, so the unexported helpers
stay reachable). Pure code motion — the netlink/sysfs query order and the
visible output are byte-identical:

- `cli_show_interfaces.go` — the `showInterfaces` dispatch + summary
  renderer, `showInterfacesRethMemberSummary`, and `showTunnelInterfaces`.
- `cli_show_interfaces_terse.go` — `showInterfacesTerse` (the tabular
  `show interfaces terse` view, cluster-peer aware).
- `cli_show_interfaces_detail.go` — `showInterfacesDetail` plus
  `showInterfacesRethDetail`, the synthesized bondless-reth aggregate /
  absent-member block reused by the extensive view.
- `cli_show_interfaces_extensive.go` — `showInterfacesExtensive` /
  `showInterfacesExtensiveFiltered`.
- `cli_show_interfaces_stats.go` — `showInterfacesStatistics` and
  `showVlans` (the two small tabular summaries).
- `cli_show_interfaces_shared.go` — the shared RETH/kernel-query helpers
  `dhcpLease`, `rethMemberLinkState`, `rethMemberAttrs`, and `baseIfName`,
  so the four render modes resolve reth link state / member attrs / lease
  data through one place and can no longer drift.

## `show services` / `show class-of-service` presenters (#4655)

The service-status presenters were historically one 868-line
`cli_show_services.go` that mixed unrelated service families —
CoS, DDNS, DHCP (client/relay/server), SNMP, LLDP, and port
mirroring — so different owners edited one bucket. They are split
per service family into sibling files (same package, so the
unexported `showConfigRedacted`/`userspaceDataplaneStatus` helpers
and injected `*Fn` hooks stay reachable). Pure code motion — every
presenter's rendered output is byte-identical:

- `cli_show_services.go` — the `handleShowServices` dispatch shell
  plus the presenters with no dedicated family file:
  `showRPMProbeResults`, `showIPMonitoringStatus`,
  `showApplicationIdentificationStatus`, `showSchedulers`.
- `show_services_cos.go` — the `show class-of-service` dispatch
  (`handleShowClassOfService`, `parseCoSClassifierArgs`),
  `showClassOfServiceInterface`, and `showInterfacesQueue` (the
  live CoS runtime queue view).
- `show_services_ddns.go` — the two dynamic-DNS presenters:
  `showServicesDynamicDNS` (Surface A router/interface-address)
  and `showDHCPDynamicDNS` (DHCP-server DDNS).
- `show_services_dhcp.go` — the DHCP client/relay/server family:
  `showDHCPLeases`, `showDHCPClientIdentifier`, `showDHCPRelay`,
  and `showDHCPServer`.
- `show_services_snmp.go` — `showSNMP` and `showSNMPv3`.
- `show_services_lldp.go` — `showLLDP` and `showLLDPNeighbors`.
- `show_services_mirror.go` — `showPortMirroring` (SPAN).

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
  as-if-active. #3628: the usage/help text these commands print when
  from-zone/to-zone are missing is the shared SSOT constant
  `policymatch.MatchPoliciesUsage` / `TestPolicyUsage`, so the four surfaces
  (local + remote CLI, show + test) advertise the SAME selectors the parsers
  accept — `source-port`, `destination-port`, `icmp-type`, `icmp-code`, and
  `protocol` by name OR 0-255 number — instead of the stale, drifted
  `protocol <tcp|udp>`-only subset that hid the ICMP / source-port / non-TCP-UDP
  selectors from operators.
- #3674: the local `test policy` (`testPolicy`) output now renders the SAME
  identity fields `show security match-policies` (`showMatchPolicies`) already
  prints over the shared `policymatch.Result` — the stable runtime **Policy ID**
  (the RT_FLOW / session-table / audit ID from the #3667 `RuntimePolicyIDs`
  SSOT), the **Rule ID** (#3668 stable inventory join key), the **Scope**
  (`zone-pair (from-zone …, to-zone …)` or `global (match from-zone …, to-zone
  …)`, rendered through the shared `matchScopeZone` helper so an unset global
  scope reads `any`), and the policy **Description**. Both are thin adapters over
  the one simulator, so a `test policy` verdict now correlates with the runtime
  policy and identifies which scoped/global rule fired — previously the request
  path printed only name + action (and, for a global match, name + action with no
  scope), making it the poorest of the four match-policies surfaces. The
  rendering is shared via `printPolicyMatchIdentity`; it is a display-only change,
  no schema/wire impact.
- #4497 (avo-001 F3): the local `test policy` (`testPolicy`) query echo now
  surfaces the queried **ICMP/ICMPv6 type and code** in the trailing tuple
  annotation. A `test policy … protocol icmp icmp-type 8 icmp-code 0` verdict
  ends with `… [icmp type 8 code 0]` (previously the bare `[icmp]`), so the
  operator reads the exact ICMP packet the simulator matched — the type/code the
  parser already threads into `policymatch.Query.ICMPType/ICMPCode` (#3284) and
  matches against an icmp-type-constrained application (junos-ping = type 8).
  The annotation is rendered by the shared `formatQueryProtoTail` helper; a
  non-ICMP query prints the bare `[proto]` exactly as before. Display-only; no
  schema/wire impact.
