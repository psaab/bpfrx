# #6387 — Host-inbound nftables install via netlink + config-sync apply-failure monitor-failure

## 1. Status

- **Status:** PLAN — research only. No production code, no PR. Deliverable is
  this doc.
- **Issue:** #6387 (`bug`, `security`) — cluster standby stuck `Transfer ready:
  no`, `applied config gen=0`, because config-sync APPLY hard-fails on the
  host-inbound nftables step when the node has no `nft` binary.
- **Base:** branch `fix/6387-hostinbound-netlink` at master `764f2ebf5`.
- **Scope of this plan:** the two durable fixes the issue ranks #1 and #2:
  1. migrate the host-inbound / lo0 nftables installation from `exec nft -f -`
     to the `github.com/google/nftables` netlink API (removes the `nft`-binary
     single point of failure), and
  2. surface a persistent config-apply failure as a Config-Sync (`CF`)
     monitor-failure / degraded health instead of a silent permanent
     `Transfer ready: no`.
- **Explicitly out of scope:** provisioning `nftables` onto every node / baking
  it into the appliance image (issue #6388, the immediate unblock). This plan is
  the design that makes that provisioning gap non-fatal.

## 2. Issue framing (root cause, verified)

The standby (fw1) receives every config-sync payload and successfully applies
the dataplane snapshot + FRR, but the apply's host-inbound nftables sub-step
shells out to `nft -f -` (`pkg/daemon/daemon_nft.go:32`, the `nftApplyPayload`
package var). fw1 has no `nftables` package, so the exec returns *"nft:
executable file not found in $PATH"*.

The chain of consequence (all on the worktree copy, matches the issue's
`origin/master` analysis):

1. `applyHostInboundFilter` (`daemon_nft.go:260`) wraps the exec error:
   `apply host-inbound nftables filter: %w`. The lo0 teardown
   (`applyLo0Filter`, `:120`) and cold-boot fence (`:503`) fail identically.
2. `applyTailReconciles` joins `hostInboundErr` and `lo0Err` **fatally** into
   the commit result (`daemon_apply_tail.go:89`, `:82`, joined at `:168`
   `errors.Join(...)`), per the #3333/#3392 fail-closed contract.
3. `handleConfigSync` → `syncAndApply` returns the error
   (`daemon_ha_sync.go:544`, `:578`); it is wired as `OnConfigReceived`
   (`daemon_ha_sync.go:910`).
4. `configApplyLoop` sees `OnConfigReceived != nil` return non-nil, bumps
   `s.stats.ConfigsApplyFailed` and `continue`s
   (`sync_conn_config.go:143`) — it never reaches
   `recordAppliedConfigGen(item.gen)` (`:164`).
5. `lastAppliedConfigGen` stays 0 forever; `ConfigStale()` =
   `PeerConfigGen > AppliedConfigGen` = true (`sync.go:260`);
   `ReadyForManualFailover()` = false (`sync.go:271`); status renders
   `Transfer ready: no (standby config stale: applied gen=0 behind peer
   committed gen=...)`.

This is fail-closed-by-design (host-inbound is kernel-nftables PRIMARY
host-protection enforcement, #3333/#3392) colliding with a provisioning gap.
Merely making the host-inbound error non-fatal would trade the availability
trap for a **silent security fail-open** on the standby — the issue rejects that
in isolation, and so does this plan.

## 3. Honest scope & value

**Value.** High. This is the durable fix for a real availability trap that also
carries a latent security gap: on a crash failover (`Takeover ready: yes`, NOT
`ConfigStale`-gated by design, `sync.go:263-272`) fw1 would be promoted and
forward per its applied policy but with **no kernel host-inbound self-protection
fence installed** — the identical missing-`nft` failure, now on the master. Fix
#1 closes both the availability trap and that self-protection gap. Fix #2 turns
a silent un-failover-able standby into an operator-visible degraded-health
signal.

**Cost / risk.** This is security-sensitive HA code. `daemon_nft.go` is 2166 LOC
and emits a large, subtle nftables ruleset (three tables, named counters,
per-zone default-deny, junos-host DENY subchains, an atomic-replace idiom, a
cold-boot fence, and a #5789 additive coverage-gap fence). A netlink rewrite
that silently drops or widens **one** rule is a control-plane fail-open on the
PRIMARY host path. The migration is only acceptable if it is proven
**bit-for-bit ruleset-equivalent** to the current `nft -f -` output.

> **PLAN-KILL is acceptable if the netlink migration cannot be proven
> ruleset-equivalent to the current `nft -f -` output.** A host-inbound
> fail-open is strictly worse than the availability trap this fixes, and the
> availability trap already has a benign unblock (provision `nftables`, #6388).
> If the parity test (§9) cannot be made to catch a dropped/weakened rule, do
> not ship the migration.

**Favorable facts that de-risk it (see §4):** the netlink path is already proven
in-tree (RST-suppression, and every host-inbound/lo0 counter *reader* already
uses netlink), and the full ruleset **is** netlink-expressible with the
`google/nftables` v0.3.0 primitives already vendored.

## 4. What's already shipped (precedent we build on)

- **RST-suppression is the netlink template** — `pkg/nftables/rst_suppress.go`
  (204 LOC) installs an `inet` table via `nftables.New()` /
  `c.AddTable`/`AddChain`/`AddRule`/`c.Flush()`, does an atomic
  delete-then-create in ONE `Flush()` batch (the same race-free idiom
  host-inbound needs), and lists/deletes via `ListTablesOfFamily`/`DelTable`. It
  is invoked from the live dataplane path
  (`pkg/dataplane/userspace/maps_sync.go:1219`), so **netlink nftables is
  already exercised on the cluster nodes** — the kernel `nf_tables` subsystem is
  reachable there today.
- **Every host-inbound / lo0 counter READER is already netlink** —
  `ReadLo0Counters` (`pkg/nftables/lo0_counters.go:86`),
  `ReadHostInboundDenyCounters` (`host_inbound_counters.go:143`),
  `ReadHostInboundAcceptCounters`, `ReadHostInboundJunosHostDenyCounters` all
  use `nftables.New()` + `GetObjects` + `*nftables.CounterObj`. Only the
  *writer* shells out to `nft`. Migrating the writer to netlink makes both sides
  consistent, and counters created as `CounterObj` are read back by the existing
  readers **unchanged** — this is what removes most of the observability risk
  (§7, §8).
- **`pkg/nftables` is already the "no shell-out to nft" package** — its
  README.md line 3: *"Manages nftables rules via the netlink API (no shell-out
  to `nft`)."* The host-inbound/lo0 writers belong here by that package's own
  contract.
- **The fail-closed contract we must preserve:** #3333 (host-inbound apply/
  teardown failure fails the commit closed, `3cc03e880` lineage), #3392 (same
  for lo0), #5644 cold-boot fail-closed fence (`3cc03e880`), #5789 additive
  coverage-gap fence + retained-generation covered-set (`6540cbd1f`), #5790
  (teardown-failure must not clear `hostInboundEnforced` over a live table).
  These are the invariants §7 pins.
- **Library capability audit (`github.com/google/nftables` v0.3.0, vendored):**
  every construct is expressible — `expr.Ct` (state/direction), `expr.Meta`
  (NFPROTO/L4PROTO/IIFNAME), `expr.Payload` (network + transport header),
  `expr.Bitwise`, `expr.Cmp`, anonymous+interval `Set`/`expr.Lookup`,
  `expr.Reject` (tcp-reset AND icmpx admin-prohibited), `expr.Log`,
  `expr.Exthdr` (IPv6 frag present), `CounterObj`/`NamedObj` +
  `expr.Objref` (named-counter reference), `expr.Verdict`
  (accept/drop/return/jump). Confirmed present in the module cache. **No
  construct forces a residual exec-`nft`.**

## 5. Concrete design

### 5.1 Fix #1 — netlink host-inbound / lo0 installer

**Placement.** New netlink installers live in `pkg/nftables` (the package whose
contract is already "netlink, no nft shell-out"), reusing the table-name
constants already there (`Lo0TableName = "xpf_lo0"`,
`HostInboundTableName = "xpf_hostinbound"`; add
`HostInboundGapTableName = "xpf_hostinbound_gap"`). The `daemon_nft.go` builders
that compute *what* to install (views, unzoned sets, junos-host programs, filter
terms) stay in `pkg/daemon`; only the *rendering-to-kernel* step changes from
"build text → `nftApplyPayload`" to "build expr set → netlink `Flush`".

**Atomic-replace idiom (mirrors rst_suppress + the current nft-text).** For each
table, in ONE `*nftables.Conn`:

```
c := nftables.New()                         // or nftables.New(nftables.AsLasting()...)
c.DelTable(&Table{Family: INet, Name: T})   // no-op-safe: table may be absent (see §7)
t := c.AddTable(&Table{Family: INet, Name: T})
c.AddObj(&CounterObj{Table: t, Name: cn})   // per named counter, declared once
ch := c.AddChain(&Chain{Name:"input", Table:t, Type:ChainTypeFilter,
                        Hooknum:ChainHookInput, Priority:ref(PRIO), Policy:ref(Accept)})
for each rule: c.AddRule(&Rule{Table:t, Chain:ch, Exprs: []expr.Any{...}})
err := c.Flush()                            // single atomic netlink transaction
```

`Flush()` sends the whole batch as one `nf_tables` transaction: the kernel
commits all-or-nothing, so on any error the PREVIOUS table is retained untouched
— the exact atomicity `nft -f -` gave us (§7 invariant H4). The
`DelTable`-then-`AddTable` in the same batch removes the old chain **and its
named counter objects** (the reason the current code uses delete+recreate rather
than `flush table`, `daemon_nft.go:146-168`).

**Teardown (`nftDeleteTable` replacement).** Replace the idempotent
add-then-delete `nft` payload with: `ListTablesOfFamily(INet)`; if present,
`DelTable` + `Flush`; absent → no-op nil (mirrors rst_suppress
`RemoveRSTSuppression` / `rstTableExists`). This drops the "add-then-delete so
the delete always has a target" trick entirely — netlink just checks existence
first. A genuine kernel/permission failure still returns an error so the
fail-closed teardown paths (`daemon_nft.go:315/331/425`) keep their semantics.

**Construct-by-construct nft-text → netlink expr mapping.** Every construct the
three payload builders emit, and its `google/nftables` equivalent:

| nft-text construct (source) | netlink expr construction |
|---|---|
| `table inet X` atomic replace (`build*Payload`) | `DelTable`+`AddTable` in one `Flush` |
| `chain input { type filter hook input priority P; policy accept; }` | `AddChain{Type:Filter, Hooknum:ChainHookInput, Priority:&P, Policy:&Accept}` (P = `nftLo0FilterPriority` 0 / `nftHostInboundPriority` 10 / `nftHostInboundGapPriority` 11) |
| `counter <name> {}` declaration (`daemon_nft.go:983`) | `AddObj(&CounterObj{Table,Name})` (read back today by `GetObjects`) |
| `counter name "<name>"` reference | `expr.Objref{Type: NFT_OBJECT_COUNTER(1), Name}` |
| `ct state established,related accept` (`:1030`) | `Ct{Key:CtKeySTATE,Reg:1}` → `Bitwise{Mask: ESTABLISHED|RELATED = 6}` → `Cmp{Neq,0}` → `Verdict{Accept}` |
| `ct state established,related ct direction reply accept` (`:1014`) | above + `Ct{Key:CtKeyDIRECTION}` → `Cmp{Eq, reply=1}` |
| `meta l4proto { 50, 51 } accept` (ESP/AH, `:1042`) | `Meta{Key:L4PROTO,Reg:1}` + anonymous constant `Set{KeyType:InetProto}` + `Lookup{SetName,SourceRegister:1}` → accept |
| `icmpv6 type { 1,2,3,4 } counter name "X" accept` (`:1085`) | `Meta{L4PROTO}`+`Cmp{Eq,58}` guard, `Payload{TransportHeader,off 0,len 1}`, constant `Set`+`Lookup`, `Objref`, `Verdict{Accept}` |
| `icmp type { destination-unreachable, time-exceeded, parameter-problem }` (`:1087`) | `Meta{L4PROTO}`+`Cmp{Eq,1}`, `Payload{Transport,0,1}`, set `{3,11,12}`, objref, accept (named ICMP types resolve to numbers on the wire — no name lost) |
| `udp dport <spec> accept` (WG, `:1123`) | `Meta{L4PROTO}`+`Cmp{Eq,17}`, `Payload{Transport,off 2,len 2}`, `Cmp`/`Set`+`Lookup`, accept |
| `<fam> daddr <set> <service-match> accept` per-zone (`:1343`) | `Meta{NFPROTO}` guard (ip vs ip6), `Payload{NetworkHeader, daddr off 16/24, len 4/16}` + `Cmp`/interval-`Set`+`Lookup`, then the service L4 match, accept |
| `<fam> daddr <set> counter name "<zone_fam>" drop` catch-all (`:1351`) | nfproto guard + network-daddr match + `Objref` + `Verdict{Drop}` |
| `<fam> daddr <set> drop` fence (`:556`, `:687`) | nfproto guard + network-daddr match + `Verdict{Drop}` (no objref — fences carry no counters) |
| `iifname "<n>"` / `iifname { ... }` (junos-host, `:1191`) | `Meta{Key:IIFNAME,Reg:1}` + `Cmp` (16-byte NUL-padded name) or constant `Set`+`Lookup` |
| `<fam> saddr != <permit-set>` subtraction (`:1212/1221`) | network-saddr `Cmp{Neq}` or `Lookup{Invert:true}` against a constant set |
| `reject with tcp reset` (`:1172`, `:1999`, ident-reset `:1376`) | `Meta{L4PROTO}`+`Cmp{Eq,6}` guard + `Reject{Type: NFT_REJECT_TCP_RST(1)}` |
| `reject with icmpx type admin-prohibited` (`:2000`) | `Reject{Type: NFT_REJECT_ICMPX_UNREACH(2), Code: NFT_REJECT_ICMPX_ADMIN_PROHIBITED(3)}` (icmpx auto-selects v4/v6, family-agnostic — matches the current one-pair-for-both-passes design) |
| lo0 `th sport/dport [!=] <spec>` (`:1755`) | `Payload{TransportHeader, off 0/2, len 2}` + `Cmp` (Eq/Neq) or interval `Set`+`Lookup` |
| lo0 `meta l4proto {numbers}` (`:1747`) | `Meta{L4PROTO}` + `Cmp`/set (numeric protocol numbers, already resolved by `appid.ProtocolNumber`) |
| lo0 `ip/ip6 dscp <v>` (`:1786`) | `Payload{Network, TOS/traffic-class byte}` + `Bitwise{Mask 0xfc, Rshift 2}` + `Cmp`/set (numeric, already resolved by `nftDSCPValue`) |
| lo0 `icmp[v6] type/code <set>` (`:1822/1825`) | l4proto guard + `Payload{Transport, off 0 (type)/1 (code), len 1}` + `Cmp`/set |
| lo0 `tcp flags & (mask) == req` (`:1873`, `nftTCPFlagsMatch`) | `Payload{Transport, off 13, len 1}` + `Bitwise{Mask: req|forbidden}` + `Cmp{Eq, req}` |
| lo0 `ip frag-off & 0x1fff != 0` (`:1886`) | `Payload{Network, off 6, len 2}` + `Bitwise{Mask 0x1fff}` + `Cmp{Neq,0}` |
| lo0 `exthdr frag exists` (v6, `:1884`) | `Exthdr{Type: 44 (frag), Op: ExthdrOpIpv6, ... present}` + `Cmp` |
| lo0 `log prefix "xpf-lo0 <term>: "` (`:1937`) | `expr.Log{Key: prefix bit, Data: []byte(prefix)}` |
| verdicts `accept`/`drop` (`:2027/2032/2038`) | `Verdict{Accept}` / `Verdict{Drop}` |

**Anonymous sets.** `{ a, b, c }`, address sets, and CIDR/port ranges become
constant anonymous `Set`s (`Anonymous:true, Constant:true`, `Interval:true` for
ranges/prefixes) added in the same batch and referenced by `expr.Lookup`. This
is the one place the netlink form is materially more verbose than the text; the
parity test (§9) is what guarantees it stays faithful.

**Injection seam preserved (critical for the 14 fail-closed tests, §6/§9).**
The current tests stub the package var `nftApplyPayload` / `nftDeleteTable` to
inject apply/teardown failures (14 `_test.go` files). The netlink installer MUST
expose an equivalent seam — e.g. package vars
`installNftTable = func(*nftables.Conn plan) error` and
`deleteNftTable = func(family, name string) error` (or a small interface) that
the fail-closed tests override to return an error — so the #3333/#3392/#5644/
#5789/#5790 fail-closed assertions still bind without a live kernel.

### 5.2 Fix #2 — config-apply failure as a `CF` monitor-failure / degraded health

The `CF Config Sync monitoring` code is **already reserved** in the status
legend (`pkg/cluster/status.go:30`) but **nothing raises it today**.
`ConfigsApplyFailed` only appears in verbose `FormatInformation()`
(`status.go:334-336`). `rg.MonitorFails []string` (`manager.go:51`) already
drives the `Monitor-failures` column (`status.go:61-63`) AND flips
`Node health` → `degraded` (`status.go:161`: `len(rg.MonitorFails) > 0`). So the
rendering surface exists; only a producer is missing.

**Signal source.** `configApplyLoop` (`sync_conn_config.go:111`) is the single
ordered consumer, with a clean failure edge (`:143`, `ConfigsApplyFailed.Add(1)`)
and success edge (`:164`, `recordAppliedConfigGen`). Add hysteresis
(reuse `DefaultMonitorFailThreshold = 3` philosophy): raise after N consecutive
apply failures, clear on the first success.

**Wiring.** Add a `SessionSync` callback (e.g.
`OnConfigApplyHealth func(failing bool, lastErr string)`) set by the daemon next
to `OnConfigReceived` (`daemon_ha_sync.go:910`), fired from `configApplyLoop`.
The daemon translates it into a new `cluster.Manager` entry point.

**Recommended rendering — dedicated field, NOT a `MonitorFails` sentinel
(annotate-only, zero election impact):**
- Add `RedundancyGroupState.ConfigSyncFailing bool` + `ConfigSyncFailReason
  string` (`manager.go` RG struct), set via a new
  `Manager.SetConfigSyncHealth(rgID, failing, reason)` mirroring `SetRGReady`
  (`readiness.go:12`).
- `FormatStatus` folds `"CF"` into the Monitor-failures column when the flag is
  set; `FormatInformation`'s `localHealth` loop (`status.go:160-165`) also tests
  it → `Node health: degraded`; add a `Config sync: failing (<reason>)` detail
  line near the existing `Configs apply-failed:` counter.
- **Why a dedicated field, not the `"CF"`-in-`MonitorFails` shortcut:**
  `reconcileMonitorDebtsLocked` (`election.go:547-586`) DELETES any
  `MonitorFails` entry that is neither a configured interface-monitor nor
  `isIPMonitorName`-true, on **every** `UpdateConfig` — a `"CF"` sentinel would
  be wiped on the next commit. A dedicated field sidesteps that clobber AND can
  never perturb `Weight`/election (a config-apply failure is node-global; it
  must not demote priority, only annotate health). RG mapping: raise on all
  configured data RGs (or RG0) — node-global, exactly how `Node health` is
  already computed across RGs.
- **Do NOT gate failover on this flag.** Manual failover is already correctly
  gated by `ConfigStale()` (§7 H8). Fix #2 is diagnosability only — it must not
  add a second, redundant gate that could refuse a legitimate crash takeover.

## 6. Public API preservation

- **No gRPC / proto / REST change.** `show chassis cluster status` /
  `information` gain a `CF` annotation and a `Config sync:` line; the wire
  formats and RPCs are unchanged.
- **Metric names unchanged.** `xpf_lo0_counter_hits_total`,
  `xpf_host_inbound_kernel_denies_total`, the accept counters, and the
  junos-host deny counters keep their names and semantics — the counter
  *objects* are the same `CounterObj`s, now written via netlink and read by the
  unchanged netlink readers (§4).
- **Table/chain/priority names unchanged.** `xpf_lo0` (prio 0) < `xpf_hostinbound`
  (prio 10) < `xpf_hostinbound_gap` (prio 11); chain `input`; policy accept.
  Operators' `nft list table inet xpf_hostinbound` (where `nft` exists) sees the
  same table.
- **Daemon internal seam:** `nftApplyPayload` / `nftDeleteTable` package vars are
  replaced by an equivalent netlink injection seam (§5.1). The `build*Payload`
  string functions are RETAINED as the parity-test oracle (§9), not deleted.
- **`SessionSync.OnConfigReceived` signature unchanged;** fix #2 adds a new
  optional callback, so a nil callback (no daemon wiring) is a no-op — legacy /
  test construction is unaffected.

## 7. Hidden invariants (must all hold post-migration)

- **H1 — bit-exact ruleset parity.** The netlink-installed ruleset must be
  semantically identical to the current `nft -f -` output for every input: no
  dropped rule, no widened match (a set that admits more than intended), no
  narrowed match (a drop that over-blocks). Pinned by the §9 parity test.
- **H2 — priority ordering.** `xpf_lo0`(0) < `xpf_hostinbound`(10) <
  `xpf_hostinbound_gap`(11) — the operator's explicit lo0 filter evaluates
  before the zone default-deny backstop, and the gap fence last (`daemon_nft.go:57-102`,
  `nft_chain_priority_test.go`). Netlink `Chain.Priority` must carry these exact
  values.
- **H3 — counter declaration/reference agreement.** A rule may reference a
  counter only if the `CounterObj` is added in the same batch; declared-once
  dedup (`daemon_nft.go:930/983`) must be preserved or the transaction is
  rejected (kernel equivalent of nft's "File exists" / "undeclared object").
- **H4 — atomic transaction = the nft `-f -` atomicity.** `DelTable`+full
  rebuild must be in ONE `Flush()`. On failure the PREVIOUS table is retained
  untouched (nf_tables aborts the whole transaction). This is what makes the
  #5789 retained-generation logic (`daemon_nft.go:362-408`) still correct: a
  failed real install leaves the exact prior generation in the kernel.
- **H5 — teardown fail-closed.** A teardown that cannot remove a live table must
  return an error AND must NOT clear `hostInboundEnforced` /
  `hostInboundCoveredAddrs` (#5790, `daemon_nft.go:315-334`). Only a *successful*
  teardown clears them.
- **H6 — cold-boot & coverage-gap fences.** `installHostInboundColdBootFence`
  (#5644) and `installHostInboundGapFence` (#5789) must install their fence
  tables via netlink with the SAME address scoping and mandatory-admit posture
  (`hostInboundFenceMandatoryAdmits`), and the `hostInboundCoveredAddrs` set must
  track exactly what the fence covers, so a day-2 appeared-address gap is still
  detected.
- **H7 — the fail-closed contract stays fail-closed.** `applyHostInboundFilter` /
  `applyLo0Filter` must still return their error into the `errors.Join` at
  `daemon_apply_tail.go:168`. The migration removes the *cause* of the common
  failure (missing `nft`) but must NOT relax the contract — a genuine netlink
  install failure (kernel refuses the ruleset) must still fail the commit closed.
  **This is the line the issue draws: fix the failure mode, do not fail open.**
- **H8 — manual-failover gate unchanged.** `ConfigStale()` /
  `ReadyForManualFailover()` (`sync.go:260-273`) semantics are untouched; fix #2
  only annotates health, it does not add or remove a failover gate.
- **H9 — no kernel-module regression.** Netlink still requires the kernel
  `nf_tables` module; the migration removes the userspace *binary* dependency,
  not the kernel subsystem. §11 Q6 examines module-load guarantees. (RST
  suppression already proves the module is reachable on the cluster nodes.)

## 8. Risk table

| Class | Risk | Likelihood | Mitigation |
|---|---|---|---|
| **Security (fail-open)** | Netlink builder silently drops/widens a host-inbound rule → host-bound service reachable with no deny on the PRIMARY path. | Medium (large surface) | §9 ruleset-parity test that diffs a `nft list ruleset` dump of the netlink install vs the current text install; build fails on any diff. **PLAN-KILL trigger if the test can't catch a fail-open.** |
| **Security (atomicity)** | Non-atomic install leaves a partial ruleset (input path momentarily open). | Low | H4: single `Flush()` transaction; test that a mid-batch error retains the prior table (inject a bad expr). |
| **Behavioral** | Counter reset / metric gap; `reconcileMonitorDebtsLocked` wipes a `CF` sentinel; CF flag flaps on transient failure. | Low–Med | Counter objects unchanged + read by existing netlink readers; fix #2 uses a dedicated field (not a `MonitorFails` sentinel) + N-failure hysteresis. |
| **Performance** | Per-commit netlink batch vs one `exec`. | Negligible | Host-inbound apply is a commit-time / DHCP-render event, not a hot path; netlink is faster than fork+exec+atomic-parse. No allocation on the packet path. |
| **Architectural** | 2166-LOC file + 11 golden-text tests + 14 fail-closed tests must not be invalidated wholesale; one giant PR is unreviewable. | Med | Keep the text builders as the parity oracle; preserve the injection seam; decompose (§11 Q2) into netlink-lib PR → wire-in PR → CF-monitor PR. |

## 9. Test plan

**T1 — ruleset-parity test (the critical one; gates the whole migration).**
For a matrix of representative configs (empty zone / default-deny; multi-service
zone; `system-services all`; `protocols all`; ident-reset; unzoned addresses;
junos-host DENY program with IKE/ident shields; WireGuard listen port;
dual-stack; a full lo0 firewall filter exercising saddr/daddr sets, port ranges,
`th sport/dport !=`, dscp, icmp type+code, tcp-flags, frag, log, count, reject,
discard, fall-through):
1. Render the **current** `nft -f -` payload (`buildHostInboundFilterPayload` /
   `buildLo0FilterPayload` / the two fence builders) and load it via `nft -f -`
   into a fresh network namespace (or a distinct table name).
2. Install the **netlink** ruleset into a second fresh namespace / table.
3. `nft list ruleset` (or netlink read-back via `GetRules`/`GetObjects`) both,
   **normalize** (rename tables to a common name, canonicalize set ordering /
   element formatting / handle numbers), and **diff**.
4. **Any diff fails the build** — a dropped or weakened rule cannot merge.

This test needs `nft` + root + netns, so it is **tool-gated** (SKIP when `nft`
or `CAP_NET_ADMIN` absent, like the existing `*PayloadParses` tests) — but it
runs in dev/CI and on fw0 where `nft` exists, which is exactly where equivalence
must be proven before production nodes run netlink-only. Call out the SKIP
explicitly (memory rule: no silent caps). A pure-unit companion (T1b) builds the
netlink `[]expr.Any` for each rule and asserts against a golden expr fixture, so
a regression is caught even where the kernel test skips.

**T2 — fail-closed regression (both fixes).** With the netlink injection seam
stubbed to return an error: assert `applyHostInboundFilter` / `applyLo0Filter`
still return non-nil and the error still reaches the `errors.Join` tail (H7);
assert the cold-boot fence (#5644) and coverage-gap fence (#5789) still fire and
still fail the commit if the fence itself fails; assert a teardown failure does
NOT clear `hostInboundEnforced` (#5790, H5). These port the 14 existing
`nftApplyPayload`-stub tests onto the new seam.

**T3 — CF monitor-failure regression.** Wire `OnConfigReceived` to return an
error, drive `configApplyLoop` N times, and assert: `lastAppliedConfigGen` stays
pinned (existing #4151 behavior), `ConfigsApplyFailed` increments, AND the new
`ConfigSyncFailing` flag is raised → `FormatStatus` shows `CF` /
`FormatInformation` shows `Node health: degraded` + `Config sync: failing`.
Then one success clears it. Assert the flag is NOT wiped by an intervening
`UpdateConfig` (the `reconcileMonitorDebtsLocked` hazard).

**T4 — `make test-failover` on the loss userspace cluster (mandatory).** This is
HA/failover-critical code. After the fix, provision fw1 to the failing state and
confirm: commit on fw0 → fw1 advances `applied gen` and reports `Transfer ready:
yes`; a manual `failover redundancy-group N node 1` succeeds with zero-drop
mastership transfer. Also verify the migrated host-inbound ruleset enforces on
the real node (untrust→host SSH allow/deny per zone) via captured traffic, not
just curl-200 (memory rule).

## 10. Out of scope

- **Provisioning `nftables` onto every node / baking it into the appliance
  image — issue #6388.** That is the immediate operational unblock and is
  orthogonal to this durable fix; this plan is what makes that gap non-fatal.
- **Retiring the host-inbound kernel chain in favor of a pure userspace-dp
  LocalDelivery enforcement** — the XDP shim shunts host-bound traffic to the
  kernel before userspace-dp, so the kernel chain is the PRIMARY path; replacing
  it is a separate, much larger design.
- **The #4404-style items** referenced in the campaign backlog are N/A here.
- **Changing `ConfigStale()` / manual-failover gating** — deliberately untouched
  (H8); fix #2 is diagnosability only.

## 11. Open questions for plan review (≥6)

1. **Full expressibility confirmation.** §5.1 maps every construct to a
   `google/nftables` primitive and the library audit (§4) found no gap — but is
   there a subtle construct (e.g. `icmpx` reject family-agnosticism across the
   inet table's ip/ip6 passes, or the `th` transport-agnostic port match without
   an l4proto guard) that behaves differently under netlink than under the nft
   text parser? The parity test must specifically cover these. **If any single
   construct is not faithfully expressible, does the whole migration PLAN-KILL,
   or do we keep that one construct on exec-`nft` (defeating the purpose on a
   node with no `nft`)?**
2. **One PR or decomposition?** Recommendation: **decompose** into (A) a
   `pkg/nftables` netlink host-inbound/lo0 installer library + the parity test
   (purely additive, daemon still uses exec-`nft`), (B) wire the daemon apply
   path to the netlink installer + port the 14 fail-closed tests, (C) the CF
   monitor-failure surfacing (independent of #1, could even land first as an
   immediate diagnosability win). Is a 3-PR split right, or should (C) fold into
   (B)?
3. **Does the parity test actually catch a fail-open?** Is `nft list ruleset`
   normalization + diff sensitive enough to catch a widened set (e.g. a `/24`
   where a `/32` was intended) or a missing `saddr !=` subtraction, or do we need
   a semantic (per-packet verdict) equivalence check on top of a textual diff?
4. **Observability parity.** Beyond counter names (unchanged, §6): does removing
   exec-`nft` change anything operators rely on — e.g. `nft monitor` trace
   output, journald `NFLOG`/`log prefix` formatting from `expr.Log` vs
   nft-rendered `log`, or the exact `nft list` text an operator greps? Confirm
   `expr.Log` produces the same journald line as the text `log prefix`.
5. **Fix #2 field vs sentinel, and RG scope.** Confirm the dedicated
   `ConfigSyncFailing` field (not a `"CF"`-in-`MonitorFails` sentinel) is the
   right call given the `reconcileMonitorDebtsLocked` clobber, and decide which
   RG(s) a node-global config-apply failure annotates (all configured data RGs,
   or RG0 only). Confirm CF must be weight-0 / election-neutral.
6. **Kernel `nf_tables` module guarantee.** When the `nftables` *package* is
   absent but the *kernel* `nf_tables` module is present, does the first
   `nftables.New()`/`Flush` autoload the module, or must we ensure it is loaded
   (modprobe / built-in)? If a node lacks the kernel module entirely, netlink
   fails the same way the missing binary did — so is the true durable fix "netlink
   + a module-presence preflight that raises the CF monitor-failure" rather than
   netlink alone? (RST-suppression already succeeding on the nodes is evidence
   the module is present, but is that guaranteed on every supported base, or
   incidental?)
7. **Hysteresis threshold for CF.** Should the CF monitor-failure raise
   immediately on the first apply failure (fast operator signal) or after N
   consecutive failures (avoid flapping on a transient RG0-primary rejection,
   which `configApplyLoop` already treats as a non-fatal retry)? The same gen
   re-pushes on every reconnect, so a first-failure raise could be noisy.
