# Codex refactor audit 173

- Agent: codex
- Repo: `/home/ps/git/codex-bpfrx`
- HEAD after required `git pull --rebase`: `6c9d1dd0bfe3`
- Audit file: `../do-review-refactor-audit.txt`
- Scope: monolithic-code/refactor-debt campaign only. No repository source files were edited.

## Duplicate suppression read

Read prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, `/tmp/fable-review*.md`, and `/tmp/opus-review*.md` with focused `rg` searches for refactor/modularity/hot-path terms and exact candidate names. I intentionally did not refile these already-covered items:

- `pkg/config/compiler.go` / `compileExpanded`: already in `/tmp/ps-review-011.md`, `/tmp/agy-review-171.md`, and open #4406.
- `pkg/config/compiler_validate_warn.go`: already in `/tmp/codex-review-171.md`.
- `pkg/config/compiler_nat.go`, `compiler_system.go`, `compiler_services.go`: already in `/tmp/agy-review-171.md` and `/tmp/codex-review-171.md`.
- `pkg/api/metrics_descriptors.go` and `metrics_userspace.go`: already in `/tmp/codex-review-171.md`.
- `pkg/vrrp/instance.go`: already in `/tmp/codex-review-171.md`.
- `userspace-dp/src/afxdp/tx/dispatch/mod.rs` broad `enqueue_pending_forwards` monolith: already named as F-126 in `/tmp/fable-review-166.md`.
- `userspace-dp/src/policy.rs`, AppID splits, `SnapshotIntegrityError`, `try_match_rule`, and the cold parser: already covered in prior codex/ps/fable reports.
- NAT64 broad split, screen/screen-extract, WireGuard engine cold reconcile, neighbor/neighbor_resolver, `policymatch.go`, and `cold_path_hist.rs` broad/negative results: already covered in prior reports.

## Module checklist

Inspected or assigned to subagents: Rust AF_XDP hot path (`poll_descriptor`, `poll_stages`, `tx/dispatch`, `tx/rings`, `umem`, `types/cos`, `session`, `event_emit`, `event_stream`, `slowpath`, `wg_control`, `frame/build`, `frame/rewrite`), Go userspace dataplane control/snapshot files (`process.go`, `policies.go`, `nat.go`, `filters.go`, `zones.go`, `manager.go`, `maps_sync.go`), Go config/control-plane candidates (`compiler*.go`, `schema_validators.go`, `configstore`, `routing/tunnel.go`, `eventengine`, `ipmon`, `dhcp`, `dhcprelay`, `snmp`, `frr`, `cmdtree`, CLI). Large-file inventory after rebase included:

| File | LOC | Disposition |
| --- | ---: | --- |
| `pkg/config/compiler.go` | 4370 | duplicate prior finding |
| `userspace-dp/src/afxdp/poll_stages.rs` | 3024 | new test-extraction finding, broad split duplicate |
| `pkg/config/compiler_validate_warn.go` | 2932 | duplicate prior finding |
| `userspace-dp/src/session/mod.rs` | 1959 | new hot/cold metadata finding |
| `pkg/routing/tunnel.go` | 1877 | new plan/apply lock-scope finding |
| `pkg/config/compiler_services.go` | 1821 | duplicate prior finding |
| `pkg/dhcp/dhcp.go` | 1800 | new lease-FSM finding |
| `userspace-dp/src/afxdp/types/cos.rs` | 1786 | new do-not-split layout finding |
| `userspace-dp/src/event_stream/mod.rs` | 1693 | new event-stream decomposition finding |
| `userspace-dp/src/slowpath.rs` | 1659 | new slow-path TUN/I/O split finding |
| `pkg/snmp/agent.go` | 1519 | new SNMP protocol/agent split finding |
| `pkg/dhcprelay/relay.go` | 1545 | new relay split finding |
| `pkg/dataplane/userspace/process.go` | 1208 | new userspace manager split finding |
| `pkg/dataplane/userspace/policies.go` | 1432 | new policy/address-book split finding |
| `pkg/dataplane/userspace/nat.go` | 1286 | new userspace NAT snapshot split finding |

## High confidence findings

### 1. `schema_validators.go` is a cross-domain validator grab bag

- Severity: Low maintainability, medium review-cost impact. Build-cost impact is limited but every validator edit recompiles unrelated validators.
- Confidence: High.
- Refactor class: A, mechanical/safe.
- Evidence: `pkg/config/schema_validators.go` is 1159 LOC. It starts generic scalar validation at `:28`, then mixes CoS tail grammar, IP/CIDR validators, RBAC/crypt hashes, PCI/MAC/device-map, DDNS, syslog, and scheduler time/date. Representative shape: `func validateRPM...` style domain helpers are not localized by domain; the file is one package-level pile of leaf validators.
- Proposed decomposition: `schema_validators_scalar.go`, `schema_validators_cos.go`, `schema_validators_ip.go`, `schema_validators_system.go`, `schema_validators_routing.go`.
- Hot-path preservation analysis: Config commit/completion path only. Keep exported validator names and registration sites unchanged. No dataplane path, allocation, or inlining risk.
- Tests + gate: `go test ./pkg/config -run 'Schema|Validator|Validate|CoS|DDNS|DeviceMap|Scheduler'` plus full `go test ./pkg/config`.
- Why it matters: A DDNS or scheduler leaf change should not require reviewing unrelated routing, crypt, and CoS validators.
- Fix direction: Pure file split by domain first; no behavior changes in the same PR.
- Labels: `refactor`, `config`, `schema`, `validators`, `cold-path`.
- Dedup note: Prior reports contain validator bugs, but I found no exact prior split for `schema_validators.go`.

### 2. Configstore commit/rollback code mixes durability phases

- Severity: Medium maintainability and review-cost impact; high correctness risk if refactored carelessly.
- Confidence: Medium-high.
- Refactor class: B/C, requires ordering guardrails.
- Evidence: `pkg/configstore/store.go:60` has `Store` owning active/candidate/compiled config, DB/journal, degraded retry, commit-confirm timers, lock/session state. `pkg/configstore/store_commit.go:63` starts `CommitWithDescription`; `:195` `CommitConfirmed`; `:409` `PromoteRollback`; `:645` `saveRollbackFiles`.
- Proposed decomposition: keep public `Store`; extract `commit_state.go` for confirm timers and `rollback_files.go` for rollback persistence; add a shared promote-after-persist helper used by plain and confirmed commits.
- Hot-path preservation analysis: Control-plane persistence only. The guardrail is semantic: persist-before-promote, history ordering, journal writes, and degraded retry behavior must remain byte-for-byte equivalent.
- Tests + gate: `go test ./pkg/configstore -run 'Commit|Confirmed|Rollback|Persist|Durability|Journal'`; full `go test ./pkg/configstore`.
- Why it matters: Persistence ordering is safety-critical and currently reviewed through long interleaved phase blocks.
- Fix direction: Type/helper extraction first; no write-order changes in the first PR.
- Labels: `refactor`, `configstore`, `commit`, `rollback`, `durability`.
- Dedup note: Prior findings covered configstore bugs; I found no exact commit/rollback phase decomposition.

### 3. `pkg/dataplane/userspace/process.go` is the operational recovery catch-all

- Severity: Medium maintainability, medium review-cost, low build-cost impact.
- Confidence: High.
- Refactor class: A, mechanical/safe.
- Evidence: 1208 LOC. `ensureProcessLocked` starts at `process.go:26`; control RPC at `:262`; status loop at `:503`; NAPI bootstrap at `:703`; neighbor probing at `:773`; link-cycle orchestration at `:1094`.
- Proposed decomposition: `process_lifecycle.go`, `control_client.go`, `status_watchdog.go`, `napi_bootstrap.go`, `neighbor_probe.go`, `link_cycle.go`.
- Hot-path preservation analysis: Go control path only. Preserve `Manager.mu` caller-held contracts and control request ordering; do not change timeout semantics in the split PR.
- Tests + gate: `go test ./pkg/dataplane/userspace -run 'Process|Control|Status|Binding|LinkCycle|Neighbor|NAPI'`.
- Why it matters: Helper restart, ctrl disable/enable, status publication, and link cycling should be reviewable independently.
- Fix direction: Mechanical file moves first, then later lock-scope work if needed.
- Labels: `refactor`, `go-usdp-core`, `control-plane`.
- Dedup note: Prior reports covered specific bugs in this file; I found no exact file-boundary split.

### 4. `policies.go` combines policy lowering, runtime IDs, address books, representability, and rejections

- Severity: Medium maintainability and review-cost impact.
- Confidence: High.
- Refactor class: A, mechanical/safe.
- Evidence: 1432 LOC. Policy snapshot build at `pkg/dataplane/userspace/policies.go:115`; runtime slot allocation at `:307`; address-book table build at `:749`; recursive book expansion at `:997`; representability parity at `:1118`.
- Proposed decomposition: `policy_snapshot.go`, `policy_ids.go`, `addressbook_snapshot.go`, `addressbook_representability.go`, `policy_rejections.go`, `policy_scheduler.go`.
- Hot-path preservation analysis: Cold snapshot build only. Preserve stable IDs, sentinel strings, content hashes, and emitted ordering exactly.
- Tests + gate: `go test ./pkg/dataplane/userspace -run 'Policy|AddressBook|Content|Scheduler|Reject'`.
- Why it matters: Policy ID stability and address-book fail-closed semantics are separate invariants but currently share a large edit surface.
- Fix direction: Extract address-book content/representability helpers first, then policy slot/scheduler helpers.
- Labels: `refactor`, `go-usdp-programs`, `policy`, `address-book`.
- Dedup note: Prior findings cite policy/address bugs; the broad split itself was not already filed.

### 5. `nat.go` is a multi-family userspace NAT snapshot compiler

- Severity: Medium maintainability and review-cost impact.
- Confidence: Medium-high.
- Refactor class: A, mechanical/safe.
- Evidence: 1286 LOC. Source NAT builder at `pkg/dataplane/userspace/nat.go:136`; static/NPT handling at `:611`; destination NAT at `:772`; NAT64 at `:1202`; NPTv6 at `:1245`.
- Proposed decomposition: `nat_snapshot_source.go`, `nat_snapshot_destination.go`, `nat_snapshot_static.go`, `nat_snapshot_nat64.go`, `nat_snapshot_common.go`.
- Hot-path preservation analysis: Cold snapshot build. Do not change snapshot structs, JSON tags, emitted ordering, or fail-closed sentinel behavior.
- Tests + gate: `go test ./pkg/dataplane/userspace -run 'NAT|Nat|DNAT|SNAT|NAT64|Nptv6'`.
- Why it matters: Source and destination NAT now carry separate fail-closed L4/app/address-name rules; symmetry and divergence are hard to review in one file.
- Fix direction: Extract by NAT family; leave address-name and port-range lowering shared.
- Labels: `refactor`, `go-usdp-programs`, `nat`.
- Dedup note: Prior refactors focus on `pkg/config/compiler_nat.go`; this is the userspace snapshot builder.

### 6. `filters.go` packs every filter match axis and policer snapshotting together

- Severity: Medium review-cost impact.
- Confidence: Medium.
- Refactor class: A, mechanical/safe.
- Evidence: `pkg/dataplane/userspace/filters.go:58` lowers address, protocol, port, DSCP, TCP flags, ICMP, fragment, and flex-match terms; `:433` exports prefix-list lowering; `:548` adds policer snapshots.
- Proposed decomposition: `filters_snapshot.go`, `filters_addr.go`, `filters_l4.go`, `filters_qos.go`, `filters_flex.go`, `policers_snapshot.go`.
- Hot-path preservation analysis: Cold snapshot build. Preserve wire fields and fail-closed marker behavior exactly.
- Tests + gate: `go test ./pkg/dataplane/userspace -run 'Filter|PrefixList|Policer|Flex|DSCP|ICMP|TCPFlags'`.
- Why it matters: Filter regressions tend to be axis-specific; the split makes per-axis parity and fail-closed review tighter.
- Fix direction: Extract pure helper blocks by match axis.
- Labels: `refactor`, `go-usdp-programs`, `filters`.
- Dedup note: Prior reports cover filter semantic bugs, not this builder decomposition.

### 7. `zones.go` fuses host-inbound enforcement, observability, override resolution, IDs, and quarantine

- Severity: Medium maintainability and review-cost impact.
- Confidence: Medium.
- Refactor class: A, mechanical/safe.
- Evidence: 1137 LOC. Host-inbound view build at `pkg/dataplane/userspace/zones.go:96`; addressless-zone observability at `:362`; ambiguity reporting at `:633`; interface override map at `:781`; zone snapshots at `:855`; collision quarantine at `:991`.
- Proposed decomposition: `zone_host_inbound.go`, `zone_observability.go`, `zone_interfaces.go`, `zone_snapshot.go`, `zone_quarantine.go`.
- Hot-path preservation analysis: Cold build/control path. Preserve stable zone ID and quarantine ordering byte-for-byte.
- Tests + gate: `go test ./pkg/dataplane/userspace -run 'Zone|HostInbound|Addressless|Ambiguous|Collision'`.
- Why it matters: Enforcement and observability must not drift, but they are interleaved in one file.
- Fix direction: Move observability helpers after host-inbound extraction; then move ID/quarantine logic.
- Labels: `refactor`, `go-usdp-programs`, `zones`, `host-inbound`.
- Dedup note: Prior reports cover zone bugs and addressless observability. This is a broader file-boundary refactor, not a repeat of a specific bug.

### 8. `routing/tunnel.go` holds the lock across planning and netlink apply

- Severity: Medium maintainability, medium lock-contention risk, medium review-cost impact.
- Confidence: High.
- Refactor class: C, performance-positive via lock-scope narrowing.
- Evidence: `pkg/routing/tunnel.go:277` holds `t.mu` for `Apply`; that path computes diffs, calls netlink delete/add/list/address operations, starts/stops keepalives, and can run bounded `ip link` exec at `:753`.
- Proposed decomposition: `BuildTunnelPlan(prevState, desired)`, `ApplyTunnelPlan(linkOps, plan)`, and short locked `CommitTunnelState(result)`.
- Hot-path preservation analysis: Commit-time path, not packet forwarding. Preserve keepalive generation counters and commit state under the existing mutex; do not add locks to keepalive ticks.
- Tests + gate: Fake `linkOps` plan tests for GRE, WG handoff, address pruning, VRF claim; `go test ./pkg/routing -run 'Tunnel|Wireguard|Keepalive' -race`.
- Why it matters: Slow and failure-prone kernel effects under one lock are hard to unit-test and reason about.
- Fix direction: Introduce plan structs with golden tests first, then move netlink calls behind an executor.
- Labels: `refactor`, `routing`, `lock-scope`, `test-seam`.
- Dedup note: Prior findings cover tunnel correctness; I found no exact plan/apply lock-scope split.

### 9. `eventengine.Engine` mixes policy runtime, matcher, queue, and config mutation

- Severity: Medium maintainability and review-cost impact.
- Confidence: Medium-high.
- Refactor class: A/B, mechanical seams with concurrency guardrails.
- Evidence: `pkg/eventengine/engine.go:343` policy reconciliation; `:565` queue supersession; `:642` worker transaction; `:887` plan parsing; `:939` matching/window logic.
- Proposed decomposition: `runtime_set.go`, `matcher.go`, `planner.go`, `action_queue.go`, `worker.go`.
- Hot-path preservation analysis: RPM event path only. Preserve `eventIndex` and `regexCache` built at Apply time; `HandleEvent` should still evaluate indexed policies and enqueue preclassified actions.
- Tests + gate: Existing eventengine tests plus package-private matcher/actionQueue tests; `go test ./pkg/eventengine -race`.
- Why it matters: Recent correctness fixes concentrated cooldown, staleness, queue ordering, and config mutation invariants in one type.
- Fix direction: Move pure planner/matcher first, then queue, leaving `Engine` as orchestration shell.
- Labels: `refactor`, `eventengine`, `god-manager`, `test-seam`.
- Dedup note: `/tmp/codex-review-159.md` covered eventengine correctness, not this decomposition.

### 10. `ipmon.Engine` should separate health FSM, overlay resolver, actuator, and status projection

- Severity: Medium maintainability and review-cost impact.
- Confidence: High.
- Refactor class: A/B, mechanical with lock-order guardrails.
- Evidence: `pkg/ipmon/ipmon.go:374` `Apply`; `:522` overlay resolution; `:651` status projection; `:822` debounce/throttle actuator loop.
- Proposed decomposition: `policy_fsm.go`, `overlay_builder.go`, `actuator_loop.go`, `status_projector.go`.
- Hot-path preservation analysis: Control-plane only. Keep RPM transition handling lock-bounded and preserve resolver lock order.
- Tests + gate: FSM transition tests, overlay winner/unresolved/suppressed tests, actuator retry timing; `go test ./pkg/ipmon -race`.
- Why it matters: Dirty generation, applied overlay, resolver lock order, and status honesty are coupled through comments today.
- Fix direction: Extract the pure overlay builder first.
- Labels: `refactor`, `ipmon`, `overlay`, `state-machine`.
- Dedup note: Recent ipmon fixes are accounted for; this split is not a stale correctness duplicate.

### 11. `dhcp.Manager` duplicates lease-renewal lifecycle across v4 and v6 loops

- Severity: Medium maintainability and review-cost impact.
- Confidence: High.
- Refactor class: B, state-machine extraction.
- Evidence: `pkg/dhcp/dhcp.go:150` manager state; DHCPv4 acquire/renew/rebind loop at `:683`; v4 exchange at `:877`; DHCPv6 loop at `:1096`; v6 exchange at `:1273`.
- Proposed decomposition: shared `lease_fsm.go` parameterized by `Exchange`, `Commit`, `Abandon`, and clock; protocol adapters own packet build/parse.
- Hot-path preservation analysis: Timer-driven control plane. Preserve `commitLease` and hook firing order; avoid holding `m.mu` across protocol exchanges.
- Tests + gate: Table-driven FSM tests for acquire fail, renew success, renew NAK, rebind success, cancel; `go test ./pkg/dhcp -race`.
- Why it matters: Lifecycle fixes must currently be duplicated carefully across two independent loops.
- Fix direction: Extract v4 first behind existing seams, then adapt v6.
- Labels: `refactor`, `dhcp`, `state-machine`, `test-seam`.
- Dedup note: Prior reports cover DHCP bugs; I found no reusable lease-FSM refactor duplicate.

### 12. `event_emit.rs` fuses unrelated cold event builders and a large test tail

- Severity: Low-medium maintainability and review-cost impact.
- Confidence: High.
- Refactor class: A, mechanical/safe.
- Evidence: Production emitters cover policy deny at `userspace-dp/src/afxdp/event_emit.rs:138`, host-inbound at `:230`, screen drop/alarm at `:279`, filter log at `:459`; tests start at `:597` and dominate the file.
- Proposed decomposition: `event_emit/policy.rs`, `event_emit/host_inbound.rs`, `event_emit/screen.rs`, `event_emit/filter.rs`, `event_emit/wire.rs`, with per-module tests.
- Hot-path preservation analysis: Cold telemetry/log paths. Do not add allocation, change rate-limit entry points, or move timestamp conversion to a later stage.
- Tests + gate: Move existing tests unchanged; `cargo test --manifest-path userspace-dp/Cargo.toml event_emit` plus event-stream codec/status tests.
- Why it matters: RT_FLOW semantics are audit-sensitive; unrelated wire contracts are interleaved.
- Fix direction: Mechanical file split first, behavior changes later if any.
- Labels: `refactor`, `event-stream`, `logging`, `cold-path`.
- Dedup note: Prior event findings focus on logging correctness/rate limiting, not this cohesion split.

### 13. `poll_stages.rs` hides 2K+ LOC of tests under a hot stage module

- Severity: Low maintainability and review-cost impact.
- Confidence: High.
- Refactor class: A, mechanical/safe.
- Evidence: `userspace-dp/src/afxdp/poll_stages.rs` is 3024 LOC. Hot `#[inline]` stage logic such as `stage_screen_check` sits around `:365`, while `mod tests` begins at `:887` and runs to EOF.
- Proposed decomposition: Move the test module to `poll_stages/tests.rs` via `#[cfg(test)] #[path = "poll_stages/tests.rs"] mod tests;`.
- Hot-path preservation analysis: Test-only move. No production codegen, inlining, allocation, or dispatch changes.
- Tests + gate: `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::poll_stages`.
- Why it matters: Reviews of hot stage logic should not carry a 2K-line fixture tail.
- Fix direction: Mechanical test extraction only.
- Labels: `refactor`, `tests`, `userspace-dataplane`, `hot-path-safe`.
- Dedup note: Prior reports cover broad `poll_stages` stage seams; I found no exact test co-location finding.

### 14. Session lookup clones cold metadata and a counter `Arc` on the hit path

- Severity: Medium maintainability, medium performance risk.
- Confidence: Medium-high.
- Refactor class: C, performance-positive hot/cold split.
- Evidence: `userspace-dp/src/session/mod.rs:332` `SessionEntry` mixes hot liveness/counter data with HA/log/export fields. `userspace-dp/src/session/entry.rs:24` `SessionMetadata` carries log flags, policy IDs, inactivity timeout, NAT64 info, and `Option<Arc<PolicyRuleCounter>>`. `lookup_with_origin` returns `metadata.clone()` on hits around `userspace-dp/src/session/lookup.rs:176`.
- Proposed decomposition: `SessionHotMeta` copied on every hit and `SessionColdMeta` for log/export/HA-only data; consider a compact `SessionHit` return that avoids cold clones and unnecessary `Arc` refcount churn.
- Hot-path preservation analysis: Must not add table probes, allocation, lock, trait object, or extra pointer chase to policy hit counting. Pin `size_of::<SessionEntry>()` and diff assembly for `lookup_with_origin`.
- Tests + gate: Session lookup/expiry tests, policy hit-counter tests, HA sync/promote tests, flow-cache policy-counter replay, plus perf/session-hit comparison.
- Why it matters: Reducing hot-entry footprint and avoiding cold metadata cloning can improve dcache behavior and reviewability.
- Fix direction: Benchmark size/clone cost first, then introduce hot/cold metadata with compile-time layout guards.
- Labels: `refactor`, `session`, `hot-cold-split`, `performance`.
- Dedup note: Prior reports discuss session-cache invalidation and counter binding; this is specifically metadata layout/clone cost.

## Medium confidence findings

### 15. `event_stream/mod.rs` mixes sender API, I/O loop, replay buffer, control frames, and drain semantics

- Severity: Medium maintainability and review-cost impact.
- Confidence: Medium.
- Refactor class: B, requires queue/backpressure guardrails.
- Evidence: 1693 LOC. `EventStreamSender` starts at `userspace-dp/src/event_stream/mod.rs:368`; worker handle at `:484`; `io_thread_main` at `:938`; replay at `:1007`; connected loop at `:1116`; control frames at `:1231`; drain handling at `:1368`; replay push/pop at `:1619`/`:1669`.
- Proposed decomposition: `event_stream/sender.rs`, `worker.rs`, `io_loop.rs`, `replay.rs`, `control.rs`, `drain.rs`, leaving `mod.rs` as API/re-export shell.
- Hot-path preservation analysis: Event production is not per-packet forwarding but may be called from hot-ish telemetry paths. Preserve bounded-channel backpressure, lossless queue budget release, replay eviction ordering, and no extra allocation on fast send.
- Tests + gate: Event-stream unit tests, HA export/event-stream tests, control-frame drain tests, lossless queue budget regression tests.
- Why it matters: Queue budget accounting and backpressure behavior are easy to break when replay/control/drain code is interleaved.
- Fix direction: Move pure replay/control helpers first, then I/O loop.
- Labels: `refactor`, `event-stream`, `backpressure`, `rust`.
- Dedup note: Prior reports cover event-stream correctness bugs, not the module split.

### 16. `slowpath.rs` fuses TUN setup, worker lifecycle, rate limiting, sync writes, io_uring writes, and sysctls

- Severity: Medium maintainability, medium review-cost impact.
- Confidence: Medium.
- Refactor class: B, requires I/O correctness guardrails.
- Evidence: 1659 LOC. `SlowPathReinjector` at `userspace-dp/src/slowpath.rs:294`; worker at `:401`; sync write helpers at `:461`; atomic/nonblocking writes at `:491`/`:572`; io_uring at `:630`; TUN open/setup at `:685`; rp_filter/sysctl/ioctl helpers at `:737` onward.
- Proposed decomposition: `slowpath/reinjector.rs`, `worker.rs`, `write_sync.rs`, `write_uring.rs`, `tun_setup.rs`, `sysctl.rs`.
- Hot-path preservation analysis: Slow path, but still packet-carrying. Preserve zero-copy assumptions for queued bytes, io_uring user_data uniqueness, no new per-packet heap copy, and fallback ordering.
- Tests + gate: existing slowpath tests, io_uring stale-CQE tests, TUN setup fakes where possible; perf not primary, correctness is.
- Why it matters: A single file now hides both safety-critical I/O mechanics and ordinary interface setup.
- Fix direction: Extract TUN/sysctl setup first; split write engines only with unchanged tests and explicit stale-CQE guard coverage.
- Labels: `refactor`, `slowpath`, `io_uring`, `tun`.
- Dedup note: Prior reports cover io_uring bugs; this is a file responsibility split.

### 17. `wg_control.rs` should split socket/CMSG plumbing from the WireGuard control FSM

- Severity: Medium maintainability and review-cost impact.
- Confidence: Medium.
- Refactor class: B, requires ordering and crypto-path guardrails.
- Evidence: 2280 LOC. Public `wg_control_loop` at `userspace-dp/src/afxdp/coordinator/wg_control.rs:121`; core loop at `:332`; attempt machine at `:653`/`:698`; socket bind at `:919`; send/recvmsg/CMSG parsing at `:1004`/`:1127`/`:1176`; inbound dispatch at `:1307`; encap/TUN send at `:1523`.
- Proposed decomposition: `wg_control/loop.rs`, `attempt.rs`, `socket.rs`, `cmsg.rs`, `inbound.rs`, `tun.rs`, `keepalive.rs`.
- Hot-path preservation analysis: WG control thread is not the AF_XDP forwarding loop but owns crypto and TUN movement. Preserve handshake expiry ordering, replay/cookie checks, no extra allocation on packet receive, and no trait-object dispatch in the control loop.
- Tests + gate: WG engine/control tests, native WG/GRE validation, `objdump`/`cargo asm` diff for receive/dispatch hot arms if moved.
- Why it matters: Socket/CMSG boilerplate and state-machine security ordering should not be reviewed in one 2.2K LOC file.
- Fix direction: Move socket/CMSG helpers first because they are mostly isolated.
- Labels: `refactor`, `wireguard`, `control-loop`, `rust`.
- Dedup note: Prior reports cover WG correctness and `engine.rs` splits; this is the coordinator control-loop decomposition.

### 18. `pkg/frr/policy_render.go` combines BFD, protocol rendering, route maps, filters, and policy options

- Severity: Medium review-cost impact.
- Confidence: Medium.
- Refactor class: A, mechanical/safe.
- Evidence: 1827 LOC. BFD section starts at `pkg/frr/policy_render.go:350`; `generateProtocols` at `:481`; route-filter rendering at `:1125`; policy-options rendering at `:1326`.
- Proposed decomposition: `render_bfd.go`, `render_protocols.go`, `render_routemaps.go`, `render_route_filters.go`, `render_policy_options.go`.
- Hot-path preservation analysis: Render/apply-time only. Preserve output ordering and exact string rendering; use golden tests.
- Tests + gate: `go test ./pkg/frr -run 'Policy|RouteMap|BFD|OSPF|BGP|RIP|ISIS'`; golden render fixtures.
- Why it matters: FRR output drift is easy when unrelated routing protocols and policy renderers live in one file.
- Fix direction: Mechanical move with no string changes, verified by golden output.
- Labels: `refactor`, `frr`, `routing`, `render`.
- Dedup note: Prior reports cover specific FRR correctness bugs; I found no exact render-file decomposition.

### 19. `pkg/snmp/agent.go` is a protocol stack, agent runtime, OID database, and BER codec in one file

- Severity: Medium review-cost and maintainability impact.
- Confidence: Medium.
- Refactor class: A/B, mechanical with wire-format guardrails.
- Evidence: 1519 LOC. Agent config/runtime starts at `pkg/snmp/agent.go:228`; UDP serve loop at `:454`; packet dispatch at `:519`; v2c at `:564`; GET/GETNEXT/BULK at `:697`/`:722`/`:747`; OID values at `:833`; BER encoding/decoding at `:1179` onward.
- Proposed decomposition: `agent_runtime.go`, `pdu_v2c.go`, `oid_table.go`, `if_table.go`, `ber.go`, `traps_queue.go`.
- Hot-path preservation analysis: Management-plane only. Preserve BER wire bytes and max-response trimming exactly; no packet dataplane involvement.
- Tests + gate: SNMP unit tests, BER round-trip tests, GET/GETNEXT/BULK golden responses, trap queue tests.
- Why it matters: Wire codec changes and agent runtime changes should not share one review surface.
- Fix direction: Extract BER codec first with byte-for-byte tests, then OID tables.
- Labels: `refactor`, `snmp`, `observability`, `ber`.
- Dedup note: Prior reports cover SNMP correctness, not this file split.

### 20. `pkg/dhcprelay/relay.go` mixes manager reconciliation, socket lifecycle, session loops, reply validation, L2 delivery, and Option 82

- Severity: Medium maintainability and review-cost impact.
- Confidence: Medium.
- Refactor class: B, requires packet/security guardrails.
- Evidence: 1545 LOC. `Manager` at `pkg/dhcprelay/relay.go:293`; `Apply` at `:627`; `runRelaySession` at `:846`; server response handling at `:1245`; reply delivery at `:1389`; Option 82 helpers at `:1514`.
- Proposed decomposition: `manager.go`, `session.go`, `sockets.go`, `reply_validate.go`, `delivery_l2.go`, `option82.go`.
- Hot-path preservation analysis: DHCP relay packet path, but low-rate control traffic. Preserve source-server allowlist checks, hop-count, giaddr, broadcast/L2 delivery behavior, and no widened locks around packet loops.
- Tests + gate: DHCP relay unit tests for server allowlist, Option 82, broadcast/unicast delivery, restart/reconcile; `go test ./pkg/dhcprelay -race`.
- Why it matters: Security-sensitive reply validation sits beside session and socket lifecycle machinery.
- Fix direction: Extract Option 82 and reply validation first, then session/socket lifecycle.
- Labels: `refactor`, `dhcp-relay`, `packet-path`, `security`.
- Dedup note: Prior reports cover DHCP relay bugs; this is the responsibility split.

### 21. `pkg/cmdtree/tree.go` fuses static operational/config trees with completion/help algorithms

- Severity: Low-medium build-cost and review-cost impact.
- Confidence: Medium.
- Refactor class: A, mechanical/safe.
- Evidence: 1548 LOC. `OperationalTree` begins at `pkg/cmdtree/tree.go:134`; dataplane config knobs at `:1075`; `ConfigTopLevel` at `:1098`; completion walker at `:1202`; desc/help rendering at `:1379` and `:1456`.
- Proposed decomposition: `tree_operational.go`, `tree_config.go`, `completion.go`, `help.go`, `dynamic_values.go`.
- Hot-path preservation analysis: CLI only. Preserve completion ordering, prefix matching, and help output byte-for-byte.
- Tests + gate: CLI/cmdtree completion golden tests; `go test ./pkg/cmdtree ./pkg/cli`.
- Why it matters: Adding one command currently reviews beside completion algorithms and the entire static tree.
- Fix direction: Move static tree literals first, leave completion functions intact.
- Labels: `refactor`, `cli`, `cmdtree`, `completion`.
- Dedup note: Prior CLI reports cite permission/command bugs, not this file split.

## Low confidence / do-not-split findings

### 22. `umem/mod.rs` is ugly, but `BindingLiveState` layout must not be split casually

- Severity: Low maintainability, high performance risk if done wrong.
- Confidence: High.
- Refactor class: D, do-not-split naively.
- Evidence: 1319 LOC. `WorkerUmem`/pool live near `userspace-dp/src/afxdp/umem/mod.rs:35`; `BindingLiveState` spans roughly `:266-752`, mixing hot pending-TX admission/queues around `:740` with cold status strings and telemetry.
- Proposed decomposition: At most move the whole live-state cluster to `umem/live_state.rs`; do not split storage into `Arc<Hot>` / `Arc<Cold>` until a layout design exists.
- Hot-path preservation analysis: A naive struct split adds pointer chasing and may move false-sharing boundaries. Any real hot/cold split needs `repr(align(64))`, `size_of`/`align_of` guards, and perf under redirect load.
- Tests + gate: UMEM tests, redirect-inbox tests, `perf stat` under cross-worker redirect load.
- Why it matters: Field locality is load-bearing even if the file is unpleasant.
- Fix direction: File extraction only first; measured layout work later.
- Labels: `refactor`, `umem`, `do-not-split`, `cache-locality`.
- Dedup note: Prior reports cover specific pending-TX false-sharing/RMW bugs; this is the broader negative refactor result.

### 23. `tx/rings.rs` is cohesive ring ownership code

- Severity: Informational.
- Confidence: High.
- Refactor class: D, do-not-split.
- Evidence: 415 LOC. The file scope is exactly completion drain, fill submit, RX/TX wake: `reap_tx_completions` at `userspace-dp/src/afxdp/tx/rings.rs:20`, `drain_pending_fill` at `:93`, `maybe_wake_rx` at `:154`, `maybe_wake_tx` at `:237`, tests at `:335`.
- Proposed decomposition: None.
- Hot-path preservation analysis: Keeping ring operations together preserves single-owner frame lifecycle and avoids extra boundaries around fill/completion ownership.
- Tests + gate: Existing ring tests, TX/CoS transmit tests, iperf validation for fill/completion starvation.
- Why it matters: Over-splitting would obscure single-free/single-owner invariants.
- Fix direction: Leave as-is unless a future ring API introduces a second responsibility.
- Labels: `refactor`, `rings`, `do-not-split`, `umem-ownership`.
- Dedup note: Prior reports touch ring callers; I found no exact negative finding for this file.

### 24. `FlowFairState` is a deliberate large data-oriented structure

- Severity: Medium if split incorrectly.
- Confidence: High.
- Refactor class: D, do-not-split storage.
- Evidence: `userspace-dp/src/afxdp/types/cos.rs:922` declares `FlowFairState`; hot parallel bucket arrays/queues start around `:969`. The constructor comments and `new_boxed` pattern avoid stack materialization for a large scheduler state.
- Proposed decomposition: Move methods into `flow_fair/accounting.rs`, `flow_fair/init.rs`, `flow_fair/rr.rs` if needed, but leave storage layout intact.
- Hot-path preservation analysis: Separately boxed arrays or trait-backed buckets would add pointer chasing and fragment scheduler locality. Preserve `#[inline]`, unsafe initialization invariants, and constructor equivalence tests.
- Tests + gate: Flow-fair, queue_ops, v_min, CoS fairness/iperf gates; add `size_of` and constructor equivalence tests if code moves.
- Why it matters: This looks like a monolith because it is large, but the storage layout is a performance feature.
- Fix direction: Code organization split only, not data layout.
- Labels: `refactor`, `cos`, `do-not-split`, `data-layout`, `hot-path`.
- Dedup note: Prior reports cover CoS correctness/fairness; this is the layout-preservation warning.

### 25. `frame/build` and `frame/rewrite` already have the right codegen split

- Severity: Informational.
- Confidence: High.
- Refactor class: D, do-not-split further.
- Evidence: `userspace-dp/src/afxdp/frame/build/mod.rs` is 192 LOC and documents orchestrator/family helper codegen in its header; `userspace-dp/src/afxdp/frame/rewrite/mod.rs` is 135 LOC. IPv4/IPv6 family files are already small and responsibility-oriented.
- Proposed decomposition: None for production hot code. Only cfg-only debug/log helpers should move if they grow.
- Hot-path preservation analysis: Further splitting risks lost inline or code-size duplication. Current shape keeps family helpers concrete and small.
- Tests + gate: Frame differential/property tests, `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::frame`; `cargo asm`/`objdump -d` if touched.
- Why it matters: This is a negative result: not every large surrounding frame module needs more split work.
- Fix direction: Preserve current boundaries.
- Labels: `refactor`, `frame-build`, `frame-rewrite`, `do-not-split`, `codegen`.
- Dedup note: Prior reports mention frame bugs; this records the exact negative refactor result for build/rewrite.

## Suggested issue split

1. Go cold mechanical batch: `schema_validators.go`, userspace `process.go`, `policies.go`, `nat.go`, `filters.go`, `zones.go`.
2. Go state-machine/lock-scope batch: configstore commit/rollback, `routing/tunnel` plan/apply, eventengine, ipmon, DHCP FSM, DHCP relay, SNMP agent.
3. Rust cold/event batch: `event_emit`, `event_stream`, `slowpath`, `wg_control`.
4. Rust hot-path guardrail batch: session hot/cold metadata benchmark/design, `poll_stages` test extraction.
5. Explicit do-not-split tracking: UMEM live-state layout, TX rings, FlowFairState storage, frame build/rewrite codegen boundaries.

Do not file duplicates for the excluded prior findings unless the new issue clearly narrows the scope to the decomposition above and links the prior report as context.
