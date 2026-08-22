# pkg/nftables

Manages nftables rules via the netlink API (no shell-out to `nft`). It
installs the RST-suppression rule (HA failover correctness) AND, since
#6387 PR-2, the host-inbound / lo0 / fence rulesets via netlink — plus
the counter READERS the observability surface scrapes.

## Entry points

### RST suppression (`rst_suppress.go`)
- `InstallRSTSuppression()` — atomic delete-then-create within a single
  netlink batch, so there is no window where the old table is gone but
  the new one isn't installed.
- `RemoveRSTSuppression()`.

### Host-inbound / lo0 / fence installer (#6387 PR-2 additive, PR-3 CUTOVER)
The `Installer` interface (`netlink_installer.go`) is the concrete
injection seam covering every kernel-touching host-inbound / lo0 / fence
operation. Since #6387 PR-3 it is the PRODUCTION path: `pkg/daemon`
(`daemon_nft_netlink.go`) drives it via the `nftInstaller` package var
instead of the exec-`nft` package vars (`nftApplyPayload` /
`nftDeleteTable`, now retained only as the parity-CI ORACLE), so a node
needs the kernel `nf_tables` MODULE but no `nft` BINARY:

- `InstallHostInbound(HostInboundSpec)` — the real host-inbound table
  (#3070/#3333): ct-state / ESP-AH / ICMP-accept + counters / WireGuard,
  per-zone service accepts + default-deny drops, junos-host DENY
  subchains (#4146), the addressed-but-unzoned catch-all (#4420).
- `InstallColdBootFence(FenceSpec)` — the #5644 cold-boot fail-closed
  fence (mandatory admits + address drops, no service accepts).
- `InstallGapFence(GapFenceSpec)` — the #5789 additive coverage-gap fence.
- `InstallLo0(Lo0FilterSpec)` — the lo0 loopback input filter (#3445/#3392).
- `DeleteTable(name)` — idempotent teardown (fail-closed on a real error).

`NewNetlinkInstaller()` returns the production netlink implementation.
Each method is ONE atomic `Flush()` transaction; on any error the kernel
retains the previous table untouched (the `nft -f -` atomicity, #H4). The
delete-then-recreate is existence-check-first, so an absent table on cold
boot does NOT abort the batch (#12.2). Table names `xpf_hostinbound` (prio
10) / `xpf_hostinbound_gap` (prio 11) / `xpf_lo0` (prio 0) and the named
counters are unchanged from the exec-`nft` path, so the readers below and
operator `nft list` output are identical.

**Status (PR-2 of 3):** ADDITIVE — the daemon still shells to `nft`. PR-3
wires the apply path to this `Installer` and ports the 14 fail-closed
tests onto its single failure-injection seam (a fake `Installer` that
returns an error). The `build*Payload` string builders in `daemon_nft.go`
are RETAINED as the parity-test ORACLE, not deleted.

**Parity CI (the point of PR-2, the security gate).** The netlink build
must be bit-for-bit equivalent to the exec-`nft` oracle or a
dropped/widened/weakened rule is a host-inbound fail-open on the PRIMARY
host path. Three test layers pin this:
- **T1 kernel ruleset-parity** (`pkg/daemon/daemon_nft_netlink_parity_test.go`,
  package `daemon` because it drives the unexported oracle builders):
  renders the oracle `nft -f -` text and the netlink ruleset into ONE
  private netns (self-isolated via `unshare -rn` re-exec so a forked `nft`
  shares it and the host ruleset is never touched), dumps `nft list table`
  of both, normalizes (strip handles, sort set elements, but NEVER reorder
  rules) and DIFFS. It ALSO compares the PER-RULE `iifname` scope read
  byte-for-byte via netlink (`iifnameScopeByRule`) — NOT a global union —
  because google/nftables v0.3.0 renders anonymous string-set elements
  empty in `nft list`, so a scope move/widen between a narrow IKE/ident
  per-interface exemption and the broad zone deny that preserves the union
  is invisible to the text diff and a union check (#6405). Mutation-
  sensitivity sub-cases (widened daddr, dropped `saddr !=`, weakened
  verdict, dropped unzoned deny, dropped counter, and an iifname
  exemption-widen that preserves the global union) assert the netlink dump
  or per-rule iifname scope DIVERGES from the oracle. A dedicated
  `lo0_unrepresentable_port_fails_closed` sub-case asserts BOTH sides fail
  CLOSED on a port token nft cannot resolve. **Runs where `nft` exists;
  SKIPs with a logged reason otherwise** (no silent caps).
- **T1b golden expr** (`netlink_golden_test.go`): per-construct
  `[]expr.Any` asserted against goldens DERIVED FROM nft-text semantics
  (netfilter constant values), never captured from the builder (the
  equivalence-tautology trap). Runs everywhere (no kernel).
- **Kernel-load + counter-readback** (`netlink_kernel_test.go`): loads the
  construct-complete matrix into a real netns and asserts the named
  `CounterObj`s read back UNCHANGED through the counter readers below.
  Needs `CAP_NET_ADMIN`; SKIPs otherwise.

### Capability probe (`netlink_capability.go`, #6387 §12.5)
- `ProbeNFTablesAvailable()` — functional probe (NOT `/proc/modules`; the
  module may be built-in). Returns the distinct `ErrNFTablesUnavailable`
  when the kernel nf_tables subsystem is absent, so PR-3 raises the CF
  monitor-failure with an explicit reason.
- `IsNFTablesUnavailable(err)` — classifies that distinct signal.
- PR-3 wiring: on a netlink install failure `pkg/daemon` (`tagNftInstallErr`)
  probes and, when the subsystem is unavailable, tags the returned error
  with `ErrNFTablesUnavailable` (one-time distinct operator log + the CF
  monitor-failure reason via `Manager.SetConfigSyncHealth`). The probe NEVER
  downgrades the H7 fail-closed contract — the real install still runs and its
  error still fails the commit closed.

### Counter readers
`ReadLo0Counters` / `ReadHostInboundDenyCounters` /
`ReadHostInboundAcceptCounters` / `ReadHostInboundJunosHostDenyCounters` —
scrape the named counter objects back via netlink for the Prometheus
surface. The installer's `CounterObj`s are read by these unchanged.

`ReadHostInboundDenyCounters` additionally returns a `HostInboundTableState`
(#5719), because an empty row set alone cannot tell three kernel states apart:

| state | `inet xpf_hostinbound` | named counter objects | is a `0` authoritative? |
|---|---|---|---|
| `HostInboundTableAbsent` | absent | — | YES — no enforcement, no denies |
| `HostInboundTableCounterless` | **present, DROPping** | **none** | **NO** — the #5644 cold-boot fence |
| `HostInboundTableCounted` | present | >=1 | YES — including counters that read 0 |

The `Counterless` state is the #5644 M37 cold-boot fail-closed fence, which
`InstallColdBootFence` renders with catch-all DROPs and deliberately NO named
counters (see the invariant note on `buildHostInboundFenceNetlink`): the kernel
can be actively dropping host-bound traffic with nothing to scrape, so the
caller must mark that zero non-authoritative instead of publishing it
(`pkg/api` sets `host_inbound_kernel_denies_unavailable` and bumps
`xpf_counter_read_errors_total`). The discriminator is "the table carries no
named counter OBJECT", not "no DENY counter": a real generation always declares
the three #4759 ICMP/ND accept counters, so a legitimate junos-host
program-only ruleset (which installs no per-zone catch-all DROP, hence no deny
counter) still reads `Counted`. On a non-nil error the state is the zero value
and carries no meaning — check the error first. `classifyHostInboundDenyObjects`
is the pure object-walk seam that makes the present-table half of this testable
without a kernel; `TestFenceTableReadsCounterless` proves all three states
against the real kernel under `CAP_NET_ADMIN`.

## Callers

`pkg/daemon` (installer/probe wiring lands in PR-3), `pkg/api`
(counter readers), `pkg/dataplane/userspace` (RST suppression).

## Dependencies

External: `github.com/google/nftables`. Internal: `pkg/config`,
`pkg/appid`, `pkg/dataplane` (DSCP/protocol/service SSOT re-used by the
netlink builders so the only oracle-vs-netlink difference is the
rendering-to-kernel step). It does NOT import `pkg/dataplane/userspace`
(which imports `pkg/nftables` — a cycle); the daemon converter copies
those types into the self-contained spec structs in `netlink_spec.go`.

## Gotchas

- Issue #450: deleting the RST table without immediate atomic recreate
  gives the kernel a window to send RSTs for connections owned by the peer
  during HA failover. The atomic delete+add via `Flush()` is the fix.
- Anonymous INTERVAL sets set `AutoMerge` so overlapping/adjacent CIDR
  members (e.g. a lo0 `{ 10.0.0.0/8, 10.0.1.0/24 }`) merge in-kernel like
  nft rather than EEXIST-failing the install (a false fail-closed).
- ICMP type/code sets MUST use the 1-byte `icmp_type`/`icmp_code`
  datatype; a 2-byte `inet_service` key is a hard kernel EINVAL (lookup
  register width must equal the set key width).
- IPv6 DSCP spans the low nibble of byte 0 and the high nibble of byte 1
  of the v6 header — a 2-byte payload + `Bitwise{0x0fc0}` (§12.3), NOT the
  IPv4-TOS byte.
- The junos-host `iifname { a, b }` anonymous set stores byte-correct
  16-byte NUL-padded keys, but google/nftables v0.3.0 does not emit the
  `NFTA_SET_USERDATA` nft's `list` uses to render string-typed anonymous
  sets, so `nft list` shows `{ "", "" }`. The scope is still enforced
  correctly (verified) — the T1 parity test canonicalizes the iifname-set
  text and compares the decoded element bytes PER RULE (`iifnameScopeByRule`),
  NOT as a global union: a scope move/widen between the narrow IKE/ident
  per-interface exemption and the broad zone deny that preserves the union
  is a fail-open a union check misses (#6405).
- lo0 filter ports and DSCP are RESOLVED numerically at build time via the
  same SSOT the compile path uses (`config.ResolveFilterPortRange`,
  `dataplane.DSCPValues`) — the same resolution nft applies to the raw
  token the oracle emits (`ssh` -> 22). A token that cannot be represented
  numerically FAILS the build CLOSED (`parsePortTokens`/`lo0DSCPs` error ->
  `nlPlan.fail` -> the install aborts, prior ruleset retained), mirroring
  the oracle whose raw token `nft -f -` rejects. NEVER drop the predicate
  and widen a port/DSCP-constrained rule to match-all (the #6405 fail-open).
- lo0 filter ADDRESSES take the same posture (#6512): `filterFamilyAddrs`
  returns an error on a token that is neither a valid address nor a valid
  prefix, so the plan fails and the install aborts with the prior ruleset
  retained. Dropping the token per-token installed a NARROWED positive list
  (a `discard` enforcing a smaller set than authored, the rest falling
  through to the implicit accept) or a WIDENED except list — and an except
  list narrowed to EMPTY takes `lo0AddrScope`'s empty-except arm, which
  drops the predicate entirely and makes the direction match every address.
  "Empty" means "match everything" for an except set, so skipping a bad
  entry is never the fix here. Wrong-family literals and the `any`/empty
  placeholders are still dropped — those match the userspace matcher.
  Pinned by `netlink_lo0_addrs_6512_test.go`.
- Table name `xpf_dp_rst`, family `INet` (covers both IPv4 and IPv6 in
  one table — don't split it without rethinking the atomic batch).
