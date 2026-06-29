# Userspace Dataplane: Current Capability Gate

This document tracks the current admission boundary on `master` for the Rust
AF_XDP userspace dataplane. It is not a full bug tracker and it is not a
historical branch plan. For active debugging entry points, use
[`userspace-debug-map.md`](userspace-debug-map.md).

Last updated: 2026-05-29

## Deprecation Context

Issue #1373 retired the legacy eBPF dataplane; the staged retirement is
complete. The Rust AF_XDP userspace dataplane is the only runtime forwarding
path and the effective default when `system dataplane-type` is omitted. The
#1476 source-removal phase deleted the legacy BPF source (`bpf/xdp/*.c`,
`bpf/tc/*.c`), the bpf2go bindings, and the legacy loader targets; the only
retained eBPF artifacts are the userspace XDP shim and the shared
`bpf/headers/*.h` map/struct bootstrap. Explicit `system dataplane-type ebpf`
is hard-rejected: the strict commit validator returns `ErrEBPFDataplaneRetired`
and the runtime factory returns `ErrEBPFBackendRetired`. The parser still
accepts the `ebpf` token so that `load merge`/`load override` of a
pre-retirement config does not syntax-error during a rolling upgrade, but
`commit check` then fails and the remediation is
`set system dataplane-type userspace`.

DPDK is retired (#1525). The DPDK backend, `dpdk_worker/`, and
`pkg/dataplane/dpdk/` are removed in #1527/#1528. The historical
`#1475` policy that confined DPDK's root `DataPlane` dependency to
`pkg/dataplane/dpdk` and the `cmd/xpfd/main.go` registration import
applied pre-retirement; this document focuses on the userspace
AF_XDP dataplane retirement gate, not DPDK.

## Implemented In The Current Runtime

These capabilities exist in the current Rust userspace dataplane code path:

| Feature | Current state | Notes |
|---------|---------------|-------|
| Stateful forwarding | Implemented | Per-worker sessions plus shared session tables |
| Zone + global policies | Implemented | Address and application terms are pre-expanded by the daemon |
| Policy schedulers | Implemented; live HA evidence captured | Scheduled-policy `scheduler_name` and `inactive` bits are published in userspace snapshots, old helper protocol mismatches disarm forwarding, missing policy-scheduler references are commit errors, and Rust hit counters survive active/inactive snapshot rebuilds by stable rule ID. The 2026-05-19 #1378 live artifact set is accepted by `test/incus/policy_scheduler_validate.py` for `lan->wan/scheduled-allow`. |
| Application matching | Implemented | Protocol + port terms, including expanded multi-term apps |
| Source NAT (interface mode) | Implemented | IPv4 and IPv6 egress interface rewrite |
| Source NAT (pool mode) | Implemented with scoped caveats | IPv4/IPv6 pool address and port allocation. Global `source address-persistent` uses a seeded non-cryptographic FxHash (`rustc_hash`) over the source IP (userspace-v2; #2349 replaced the prior SHA-256 selector — load distribution, not security) and is stable only within the AF_XDP backend, pool family, pool order, and pool size. The mapping is computed live, never persisted or HA-synced, so the only contract is same-source→same-pool-address within a process lifetime (and identical across nodes running the same binary). Legacy eBPF uses C-word IPv4 modulo / IPv6 lane-XOR selection (DPDK retired #1525), so new-flow pool address parity is not promised across retained backend transitions. Pool-mode rules with missing pools, empty pools, invalid port ranges, malformed addresses, no address for the packet family, or exhausted live translated tuples fail-closed at the `poll_descriptor.rs` source-NAT call sites before session creation or forwarding, with recent-exception reasons such as `source_nat_pool_missing`, `source_nat_pool_empty`, `source_nat_pool_invalid_port_range`, and `source_nat_pool_exhausted`. Per-pool `persistent-nat` now has snapshot fields and runtime lease reuse to a translated tuple, keyed by the source tuple `(protocol, source IP, source port)` scoped by the full three-way Junos `persistent-nat permit` enum (#2823, generalizing the #2397 binary `permit-any-remote-host` flag): `any-remote-host` keys the lease by the source tuple ALONE (`remote = None`), so any remote host:port reuses the mapping; `target-host` folds in the remote destination IP only (`remote = (destination IP, 0)` — the destination PORT is dropped), so a second flow from the same source to a NEW remote PORT on the SAME remote host reuses the binding while a different remote host gets a distinct lease; `target-host-port` folds in the full remote endpoint `(destination IP, destination port)`, so a different remote port keys to a distinct lease and gets a fresh mapping. The enum rides the wire as `persistent_nat_permit` (string); the legacy `persistent_nat_permit_any_remote_host` bool is still emitted for skew against an older helper, which falls back to it (`true`→`any-remote-host`, `false`→`target-host-port`). The default mode (when `persistent-nat` is configured with no explicit `permit`) is `target-host-port`, byte-identical to the pre-#2823/#2819 disabled-flag `(destination IP, destination port)` keying. Before #2397 the disabled-flag mode was silently a no-op; before #2823 only the two endpoints of the enum (`any-remote-host` and the `target-host-port`-equivalent disabled flag) were reachable — `target-host` (IP-only scope) could not be selected. Persistent source-NAT is a required helper-protocol gate: committing a persistent-NAT config against a helper whose `ConfigSnapshotProtocolVersion` is below the requirement disarms forwarding and ABORTS the commit (`ErrPersistentSourceNATProtocolIncompatible`, same required-gate class as the policy scheduler; #2138). An already-persisted or peer-synced persistent-NAT config is still admitted on a too-old helper (lenient-load #1960): the boot apply uses the void `applyConfig` wrapper (logs `Warn`, swallows) and the peer config-sync receiver logs `Error` and returns, both disarming the helper rather than bricking the node — only the operator-facing commit path surfaces the abort. The lease table is bounded in helper memory, survives compatible in-process snapshot refreshes, and expires after the configured inactivity timeout once no live flow uses the lease. It does not consult Go `PersistentNATTable` and does not survive helper restart. The closed #1449 contract gates HA behavior explicitly: HA configs that reference persistent source-NAT pools are not admitted because leases are not synchronized, and status reports `userspace persistent-nat source pool leases are not HA-synchronized`. Userspace status, CLI summary, and Prometheus expose live-flow, used-port, persistent-lease, allocation, reuse, and exhaustion counters for admitted non-HA pools. The operator SHOW path reports the actual three-way permit mode (#3193): `show security nat source persistent-nat-detail` renders a `Permit: <mode>` line (`any-remote-host` / `target-host` / `target-host-port`) per binding, and the source-NAT pool status table carries a `Permit` column; both replace the pre-#3193 binary any-remote-host flag, which collapsed `target-host` and `target-host-port` to the same output. The mode rides the status wire as `persistent_nat_permit` (string) on `SourceNatPoolStatus`, falling back to the legacy `persistent_nat_permit_any_remote_host` bool for an older helper. |
| Destination NAT | Implemented | Pre-expanded tuple snapshots from Go. Per-rule translation hits are counted (see Source NAT note; #2218). |
| Static NAT | Implemented | Bidirectional 1:1 translation. Per-rule translation hits are counted (see Source NAT note; #2218). |
| NAT per-rule translation hits | Implemented (#2218; counter-ID stability #2255) | Each SNAT/DNAT/static-NAT rule carries a compiler-assigned `counter_id` (non-zero; 0 = no counter) stamped onto its snapshot (`CompileResult.NATCounterIDs` → `SourceNATRuleSnapshot`/`DestinationNATRuleSnapshot`/`StaticNATRuleSnapshot.counter_id`). **The `counter_id` is STABLE across compiles (#2255): `assignNATCounterID` DERIVES it as a 32-bit FNV-1a hash of the type-namespaced `dataplane.NATCounterKey` (the rule's identity), not a sequential position counter. A rule therefore keeps the same id across a config reorder or the removal/re-add of an unrelated rule, so the helper's cumulative numeric-keyed store stays correctly attributed BY CONSTRUCTION — a reused config slot can no longer inherit a different rule's prior count (the pre-#2255 sequential-reset id was reused across a reorder, mis-attributing in `show security nat ... rule` Translation hits). The wide 32-bit id space makes a distinct-key hash collision negligible (~8e-6 at the 256-rule cap); the rare in-compile collision is resolved deterministically (re-hash with a `#N` suffix) so every rule still gets a unique id, reproduced identically on every compile. The JSON wire is unchanged — a JSON number is integer-width agnostic, so widening the Go/Rust `counter_id` field u16→u32 needed no `protocol_wire_v1.json` regen.** The Rust dataplane holds an `Arc<NatRuleCounter>` per rule (lock-free atomic packets+bytes, `NatCounterStore` keyed by the `u32` `counter_id`, mirroring `PolicyCounterStore`) and increments it ONCE per committed translated forward flow on the cold (session-miss) path — past every SNAT-rollback door, so a refused/rolled-back allocation is not counted. `NatCounterStore::reconcile_ids` retains only the ids present in the new snapshot and drops the rest; because ids are identity-bound, a retained id always refers to the SAME rule it did before. The fast (established-flow) path adds no work. Counts are reported per `counter_id` in `ProcessStatus.nat_rule_counters` and mirrored by the Go control plane into the sparse `bpfShim` NAT offset map (`Manager.SetNATRuleCounterOffset`, `map[uint32]CounterValue`), so `Manager.ReadNATRuleCounter` and `show security nat source/destination/static rule` report the live total. `ReadNATRuleCounter` keys that sparse offset map directly and no longer indexes the legacy 256-entry `nat_rule_counters` BPF array (a hash id ≥ `MaxNATRuleCounters` would fail that bounded `Lookup`); the Rust forwarder never WROTE that array (the #1476 eBPF retirement dropped the XDP increment), so it only ever held zeros and dropping the lookup changes no observable value — the legacy `snat_value.counter_id` BPF struct field is now vestigial in the userspace runtime. The compiler keys each `counter_id` by NAT TYPE (`dataplane.NATCounterKey` → `snat/`, `dnat/`, `static/` prefix on `ruleset/rule`) so a rule name reused across source-, destination-, and static-NAT gets distinct counters instead of colliding on one slot. The counter is PER-FLOW (one packet + its byte length per new translated flow), not per-transit-packet — before #2218 it was a perpetual 0 (the #1476 eBPF retirement dropped the legacy per-packet XDP increments). Counts are node-local (not cluster-aggregated) and reset on helper restart. `clear security nat source/destination rule` (and `clear`-all) drops BOTH the helper store and the Go offset: `userspace.Manager.ClearNATRuleCounters` zeroes the `bpfShim` offset map AND sends the `clear_nat_counters` IPC so the helper `NatCounterStore` resets — without the IPC the helper's cumulative-since-start total would be re-mirrored on the next 1/s status poll (`SetNATRuleCounterOffset` overwrites absolutely) and the cleared value would snap back within ≤1s. |
| NAT64 | Implemented | Forward and reverse translation with reverse-session state. Each successful v6↔v4 translation (both directions, counted at the single forward-candidate site since NAT64 flows are non-cacheable) bumps a per-binding `nat64_translations` counter that the Go control plane sums into `GlobalCtrNAT64Xlate`; surfaced by `show security flow statistics` ("NAT64 translations"), the userspace status summary, the gRPC `Nat64Translations` field, and the `xpf_nat64_translations_total` Prometheus metric (#2161 — the counter previously read 0 even while translated traffic flowed). Inbound security policy is evaluated on the POST-translation tuple (v6 source matched in the IPv6 ingress zone, real internal IPv4 destination matched in the destination zone) via the cross-family `(V6 src, V4 dst)` policy arm (#2358), consistent with the same-family DNAT/static-DNAT/NPTv6 post-translation matching (#2345); NAT64 policy is authored against the real IPv4 host, not the synthetic NAT64 prefix. |
| NPTv6 | Implemented | Stateless prefix translation |
| Firewall filters | Implemented | Filter snapshots and evaluation in Rust |
| Flow export | Implemented | Userspace flow export snapshot and runtime |
| Three-color policers | Implemented with caveats | srTCM/trTCM runtime, forwarding-path and flow-cache-hit metering, red drops for `then discard`, status/CLI/Prometheus counters, and compatible in-process snapshot continuity. Unsupported color-aware, non-`discard`, and malformed snapshots now fail closed in Rust if they bypass Go admission. Sharded state, HA/restart continuity decision, full non-drop action propagation, and integration evidence remain production hardening work, not active feature-gap blockers. |
| TCP MSS clamping | Implemented | Flow snapshot fields are delivered and used in Rust |
| Embedded ICMP NAT reversal | Implemented | Includes reverse-session repair paths |
| Configurable session timeouts | Implemented | Snapshot-driven global per-protocol timeouts in `session.rs`. Per-application `inactivity-timeout` (#3227) rides `PolicyApplicationSnapshot.inactivity_timeout` and is stamped on the admitted session (`SessionMetadata.inactivity_timeout_ns`) so the conntrack GC ages an app-matched flow out on the app's idle window instead of the global timeout, restoring legacy-eBPF `appTimeout` parity; first matching policy rule + first matching app term wins, where "first" is CONFIG order — the application terms are emitted in the order the apps appear in the policy `match application` list and, within an application-set, the configured member order, NOT alphabetical name order (#3298; the Rust matcher is first-writer-wins on the exact port, so a lexical sort would have let the alphabetically-first overlapping app's timeout win instead of the operator-listed-first one); closing/RST reap windows are unaffected. #3301 carries the per-application timeout (plus the admitting `policy_id` and the #3073 `policy_counter_idx`) on the cross-node HA session-sync wire (SESSION_OPEN delta in seconds + `SessionSyncRequest.inactivity_timeout`), so a peer-PROMOTED session is correctly aged/attributed/counted after failover instead of degrading to the global timeout / policy 0 / no counter; the receiver re-applies it via `app_inactivity_timeout_ns`, and an old peer that omits the additive `serde(default)` fields falls back to the pre-#3301 behavior (rolling-upgrade safe). |
| VLAN handling | Implemented | Ingress VLAN tracking and egress tagging |
| Route and neighbor lookup | Implemented | Per-table routes, neighbor cache, next-table support |
| HA state ingestion | Implemented | Helper receives RG active/watchdog state |
| Session delta export | Implemented | Rust helper exports open/close deltas back to Go |

## Remaining Explicit Configuration Gates

These are the explicit configuration gates that still hold after the
feature-gap closeout. The earlier source-removal evidence caveats are
retrospective: the #1373 feature-gap audit (#1374-#1381) and the #1477
final-validation artifact set are closed. The explicit gates live in
[`pkg/dataplane/userspace/manager.go`](../pkg/dataplane/userspace/manager.go).

| Feature/config shape | Userspace status | Tracker / disposition |
|----------------------|-------------|--------------------|
| Unsupported policy shapes | Gated | Address/application expansion must succeed for userspace. #2124: an application term whose protocol the matcher cannot represent (sctp/esp/ah/vrrp/igmp/pim/egp now parse and are canonicalized to their IANA number; anything else, or a malformed port, is unrepresentable) fails `expandUserspacePolicyApplications`. On a failed expansion the daemon emits a reserved `__unsupported__` sentinel term so the Rust matcher rejects the whole snapshot via `SnapshotIntegrityError` (keeping the previous good state) — an action-agnostic fail-closed that never turns a permit into match-any nor a deny into a pass. The SAME mechanism now covers unrepresentable ADDRESSES symmetrically (#3261): a policy naming an undefined address-book name, or a static book whose value is a non-literal (Junos dns-name / wildcard-address / range that resolves to no prefix), emits a reserved `__unsupported_address__` literal (stamped onto BOTH the v3 book-id/literal and legacy address shapes) which the Rust preflight rejects as `SnapshotIntegrityError::UnrepresentableAddress`. Before #3261 the address side had NO sentinel/reject backstop, with TWO distinct fail-opens: (a) an address-book entry whose value is a Junos dns-name / wildcard-address / range-address compiles to `Value==""`, and `expandBookNameToCIDRs` USED to widen `""` to `0.0.0.0/0` + `::/0` (match-any) — so a `deny <dns-name-book>` installed an overbroad DENY-ALL and a `permit` WIDENED to permit-any; (b) an undefined book name, or a book MIXING a literal member with a non-literal member, silently dropped the bad token, collapsing/narrowing the side to MatchNone so a `deny <bad-address>` matched nothing and fell through. The fix: `expandBookNameToCIDRs` now skips an empty value (contributes nothing, never `0.0.0.0/0`; explicit `any` still widens), and address representability is decided by a STRUCTURAL, content-independent check (`nameRepresentable`): a name is representable only if every recursively-resolved member is a feed-bound name, an Address whose value parses to a concrete prefix (CIDR / bare IP / `any`), or an AddressSet all of whose members are representable. ANY unrepresentable member (empty/unparseable value, undefined reference) taints the whole name → the `__unsupported_address__` sentinel → whole-snapshot reject. The check is feed-AWARE: a dynamic-address feed name (#2049) is representable, an empty feed is MatchNone BY DESIGN (overlay key present) and is NOT rejected, and a set that merely CONTAINS a feed member is not falsely rejected. The Go-side policy simulator (`pkg/policymatch`) mirrors the empty-value→match-nothing change for `show security match-policies` parity. The content-rejection signal (`PolicyContentRejected`) is therefore computed from the ACTUAL built snapshot rules' sentinels (`collectPolicyContentRejections`), NOT from the cfg-only capability gate, so a healthy feed policy does not false-positive. **#3261 refinement (the keep-armed contract):** unrepresentable policy *content* (this class, application OR address) is now treated DISTINCTLY from a genuinely-unsupported dataplane *semantic*. It is recorded in `snap.Capabilities.PolicyContentRejected` and does **NOT** set `ForwardingSupported=false` / does NOT disarm the helper. Disarming would `XDP_PASS` transit to the kernel and BYPASS the integrity reject — a system-level fail-OPEN. Instead the helper stays armed, publishes the sentinel snapshot, and the helper's non-mutating integrity preflight rejects it: a running node RETAINS the previous-good policy state; a fresh boot whose first-ever snapshot is bad lands on the default-deny `PolicyState` (never kernel-forwarded). The deny-rule case stays fail-CLOSED (the whole-snapshot reject keeps a dropped `deny BAD` term from letting blocked traffic fall through to a later permit). The reject is observable: `ProcessStatus.LastSnapshotRejectReasons`, a one-shot `slog.Warn` on the transition, and the `xpf_userspace_policy_content_rejected` 0/1 gauge surface the deliberate Go/Rust skew (`ForwardingSupported=true` while the helper rejected the snapshot). **#3376 (reason specificity):** each reason now names the SCOPE-qualified rule identity (`from-zone->to-zone/name`, or `global/name` — `global(from->to)/name` when the global rule carries zone context) plus the offending SIDE and the exact configured token(s): `source-address "<book>"`, `destination-address "<book>"`, `application "<app>"`. `collectPolicyContentRejections` reads the build-time-only offending-token lists captured by `buildOneRuleSnapshot` (`offendingAddressTokens` / `offendingApplicationTokens`); these are unexported, NOT serialized, so the wire snapshot is unchanged. Before #3376 a reason keyed only on the bare `name` was ambiguous across duplicate policy names in distinct zone pairs / global scope and reduced every cause to "an application" / "an address", forcing a hand-audit of every token on the security-sensitive keep-armed path. It is in-band recoverable: the config still loads via `CompileConfigLenient`, so the operator edits out the offending application/address and re-commits. The ONE narrow disarm kept for this class is keyed on the helper's snapshot protocol version: an OLDER local helper that predates the integrity preflight cannot be trusted to reject the sentinel, so `disarmBeforeUnsupportedPublishLocked` disarms only when `ConfigSnapshotProtocolVersion < ProtocolVersion`. GENUINELY-unsupported semantics with no fail-closed snapshot representation (color-aware three-color policers, SYN-cookie screen material, persistent SNAT under HA) still set `ForwardingSupported=false` and still disarm — that legitimate path is unchanged. |
| Screen behavior requiring SYN cookies | Supported | Closed feature-gap (#1374); #1477 final validation closed |
| HA with per-pool source NAT `persistent-nat` | Gated | Closed/documented contract: helper-memory persistent-NAT leases are not HA-synchronized, so HA configs that reference persistent source-NAT pools are not admitted |
| Port mirroring | Supported | Closed feature-gap (#1376); #1477 final validation closed |

Port mirroring now has snapshot/wire plumbing plus a bounded runtime slice
that samples and queues discardable full-L2 mirror clones with drop counters.
Runtime coverage includes the pending-forward path, self-target flow-cache
mirror surface, deferred neighbor-resolution retry path, CoS-bound reserve
handling, and mirror-specific counter attribution. The
`deriveUserspaceCapabilities()` gate has been removed; #1376 is closed for the
feature-gap audit, and the #1477 final-validation artifact set is closed.
Any further mirror-fidelity and pressure-survival work is production hardening,
not a retirement blocker.

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Userspace now publishes a snapshot key when cluster-synced root encrypted-password material exists, mints/validates cookies against the Unix wall-clock epoch, sends bounded SYN-ACK and validated-ACK RST replies through the AF_XDP TX path, and reports challenge/no-secret/SYN-ACK/ACK-RST/budget/valid/invalid/bypass counters. Active SYN-cookie screen profiles require that secret material at userspace capability admission; missing secret material also fails closed at runtime. #1374 is closed for the feature-gap audit; the final live HA/flood proof was delivered with the closed #1477 validation set. |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Live kernel-owned/tunnel-control cases use cpumap or pass-through; degraded helper/XSK states pass only proven local/control traffic and drop non-local transit |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed |
| DataPlane control-plane contract | Userspace manager no longer embeds the legacy `dataplane.DataPlane`; a userspace `LegacyDataPlaneAdapter` owns old-interface compatibility. Operator metadata reads in API/gRPC/CLI/daemon now use `LastApplyResult()` instead of `LastCompileResult()`, with a canary preventing those surfaces from regressing to compile-result metadata. GC and HA session sync use `SessionStore`/`Telemetry`. The manager still holds a named userspace shim manager for XDP/map bootstrap state. API/gRPC/CLI session/counter readers plus daemon control paths still name root `pkg/dataplane` session/counter types (e.g. `SessionKey`, `CounterValue`); those imports are tracked as the intentional, documented allowlist in `pkg/dataplane/retirement_boundary_canary_test.go` and move to a domain package as that type-relocation work continues. This is post-retirement interface cleanup, not a retirement blocker |
| DPDK backend | Retired in #1525. The historical #1475 backend-local exception for its root `DataPlane` dependency applied pre-retirement; #1527 removes the registration import and #1528 deletes the package. |
| Dataplane event logging | Session open/close/update are emitted by userspace. Policy-deny, screen-drop, logged routing-instance filter hits, non-PBR input filter logs, output filter logs, cached output-filter hits, and lo0 filter logs now enqueue RT_FLOW frames through the non-blocking Rust event-stream producer with existing per-event rate-limit/loss accounting. Go decode/status handling feeds raw userspace RT_FLOW frames through the same `EventReader.ProcessRawEvent` syslog/local-log path as eBPF, with a deterministic UDP syslog fanout harness for policy deny, screen drop, and filter log. Policy-deny events now carry the snapshot's compiled numeric policy ID; filter-log events carry filter/term/action identity from the matched compiled term. #1379 is closed for the feature-gap audit; the final live cluster syslog proof was delivered in the closed #1477 validation set. |
| `show system buffers` | Userspace helper-status rendering covers AF_XDP UMEM/TX capacity, CoS queued-byte capacity, helper-published session-table and flow-cache capacity, active-session footer, neighbor counts, and worker queue pressure counters. The Phase 5 denominator decision is explicit: session-table and flow-cache values become fill percentages only from Rust-owned helper fields; neighbor-cache entries remain counters until Rust owns a bounded neighbor-cache capacity. Formatter tests pin that dynamic counts cannot move into the utilization table without real denominators. |

## Retirement History (closed)

The #1373 eBPF retirement is complete. This section is a record of the closed
removal phases, not pending work.

The #1374-#1381 feature-gap audit is closed. #1377 closed source-NAT pool
retirement; its SNAT follow-ups #1448, #1449, and #1450 are closed as
documented contracts: helper restart resets helper-local persistent-NAT
leases, HA configurations with persistent source-NAT pools are gated because
leases are not synchronized, and new-flow pool-address parity is not promised.

| Issue | Removal phase (closed) |
|-------|--------------------|
| #1451 | Closed the eBPF-retirement removal-phase blocker: the userspace manager no longer embeds the legacy `dataplane.DataPlane`, runtime backend selection and forwarding are off the legacy surface, and the operator surfaces moved to apply-result metadata + `SessionStore`/`Telemetry`. Remaining root `pkg/dataplane` session/counter *type* imports in API/gRPC/CLI/daemon are the documented canary allowlist (`retirement_boundary_canary_test.go`) and are post-retirement interface cleanup, not a retirement blocker. |
| #1473 / #1493 | Split shim-only generation and the userspace shim loader/bootstrap from the legacy in-kernel forwarding loader so the retained shim survives while the legacy XDP/TC programs were removed. |
| #1476 | Removed legacy BPF source, generated artifacts, and build hooks, preserving the retained AF_XDP userspace shim path. |
| #1477 | Published the final userspace-only validation artifact set (cluster, screen/flood, CoS, HA, degraded-path evidence). |

#1474 is closed: omitted `system dataplane-type` selects userspace, and
explicit `system dataplane-type ebpf` is now hard-rejected (commit-time
`ErrEBPFDataplaneRetired`, runtime `ErrEBPFBackendRetired`); the
deprecation-warning surface that preceded the hard reject is gone.

The current canonical fallback contract is in the "Actual Fallback Mechanisms"
section below, which already reflects the post-#1476 hard reject.

## What This Document Does Not Mean

A feature being "implemented" here means the runtime has code for it. It does
not guarantee:

- that every configuration shape using the feature is currently admitted
- that every path is already hardened for HA failover
- that current performance is at parity with the legacy dataplane
- that there are no active correctness bugs in the forwarding path

Those are separate questions. Use:

- [`userspace-ha-validation.md`](userspace-ha-validation.md)
- [`userspace-perf-compare.md`](userspace-perf-compare.md)
- [`userspace-debug-map.md`](userspace-debug-map.md)

## Actual Fallback Mechanisms

There are two distinct fallback boundaries:

1. **Compile-time / reconcile-time gate**
   - The Go manager chooses the userspace runtime path by default.
     Explicit legacy eBPF selection (`set system dataplane-type ebpf`)
     was retired in #1476: the strict commit validator now hard-rejects
     it with `ErrEBPFDataplaneRetired`, and the runtime factory returns
     `ErrEBPFBackendRetired`. The deprecation-warning surface that
     preceded the hard reject is gone.
   - The Go manager keeps `xdp_userspace_prog` as the userspace-mode
     XDP entry. Capability gates for genuinely-unsupported *semantics*
     (class ii: color-aware policers, SYN-cookie material, persistent
     SNAT under HA) disarm helper forwarding rather than swapping
     userspace runtime traffic into the (now-deleted) `xdp_main_prog`.
     Unrepresentable policy *content* (class i) does NOT disarm (#3261):
     it relies on the helper integrity reject (previous-good retained /
     fresh-boot default-deny) so it never fails open to the kernel.

2. **Runtime XDP decision**
   - Even when `xdp_userspace_prog` is active, the XDP shim can still:
     - redirect to AF_XDP
     - send kernel-owned traffic to cpumap / kernel
     - pass proven local/control traffic while helper/XSK is degraded
     - drop degraded non-local transit in both compat and strict modes
     - count those drops as `transit_drop` in `degraded_path_counters`; the
       pinned BPF map keeps the internal compatibility name
       `userspace_fallback_stats` until the mixed-version boundary is retired

## Priority Work

The #1373 retirement (including the #1451 removal-phase blocker, the
#1473/#1493 userspace XDP shim split, the #1476 source removal, and the
#1477 validation artifact set) is complete. Residual root `pkg/dataplane`
session/counter *type* imports in the operator surfaces are post-retirement
interface cleanup tracked by the canary allowlist, not a retirement blocker.
The highest-value remaining work on `master` is correctness, operational
hardening, and performance optimization on the active AF_XDP userspace
forwarding path — for example CoS regression work (#1614) and cold-path
hardening (#1608).

Keep #1377, #1448, #1449, and #1450 closed. SNAT helper-restart reset
behavior, HA persistent-lease gating, and cross-backend selector divergence
remain documented userspace contract limits, not active #1373/#1451 blockers.
