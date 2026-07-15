Base commit: 34f1c7eccc509ee844d62b01aebae556fba41c41
Output path: /tmp/codex-review-171.md
Audit type: refactor/modularity coverage campaign with hot-path preservation gates.

## Duplicate Suppression Summary

Read prior review files under /tmp for codex, agy, fable, opus, and ps review reports. Suppressed or avoided duplicating:

- Prior broad `userspace-dp/src/policy.rs` split and `SnapshotIntegrityError` dumping-ground reports. This report only calls out narrower parser/matcher seams.
- Prior flow-cache replay, cached/live evaluator, TTL/filter replay, VLAN key, and session lifecycle generation findings.
- Prior CoS queue-service correctness/perf bugs around waterfill, exact queue ownership, and phase fairness. This report treats queue-service shape as refactor debt and keeps the hot-path guardrails explicit.
- Prior `compiler_validate_strict.go` monolith reports. Current base has already split it into per-domain strict validators.
- Prior DDNS Surface A correctness findings around provider identity, per-family withdraw, and backend clobbering. This report limits DDNS to residual module boundaries.
- Prior REST/metrics and CLI presenter split work. This report names only residual monoliths that still exist after those splits.
- Prior daemon/ipmon lifecycle and cluster sync correctness findings. This report is about structural split points and lock-scope guardrails.

## File-Size / Shape Inventory

Large files and shapes inspected after excluding generated protobuf and target directories:

- `userspace-dp/src/afxdp/tests.rs`: 13408 LOC.
- `userspace-dp/src/nat/tests.rs`: 8685 LOC.
- `userspace-dp/src/filter/tests.rs`: 7923 LOC.
- `userspace-dp/src/afxdp/frame/tests.rs`: 7556 LOC.
- `userspace-dp/src/policy_tests.rs`: 6757 LOC.
- `pkg/dataplane/userspace/manager_test.go`: 6664 LOC.
- `userspace-dp/src/session/tests.rs`: 6490 LOC.
- `pkg/frr/frr_test.go`: 5909 LOC.
- `pkg/config/parser_security_test.go`: 5774 LOC.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs`: 5759 LOC.
- `pkg/config/parser_ast_test.go`: 5550 LOC.
- `userspace-dp/src/afxdp/session_glue/tests.rs`: 5509 LOC.
- `userspace-dp/src/screen/tests.rs`: 5121 LOC.
- `userspace-dp/src/afxdp/forwarding_build/tests.rs`: 4818 LOC.
- `pkg/cluster/sync_test.go`: 4654 LOC.
- `userspace-dp/src/afxdp/tx/cos_classify_tests.rs`: 4617 LOC.
- `userspace-dp/src/afxdp/cos/queue_service/tests.rs`: 4384 LOC.
- `pkg/config/compiler.go`: 4336 LOC.
- `userspace-dp/src/afxdp/forwarding/tests.rs`: 4245 LOC.
- `userspace-dp/src/policy.rs`: 4224 LOC.
- `pkg/dataplane/userspace/protocol.go`: 2901 LOC, 77 structs.
- `pkg/config/compiler_validate_warn.go`: 2919 LOC, `ValidateConfig` about 1357 LOC.
- `userspace-dp/src/afxdp/poll_stages.rs`: 3024 LOC.
- `userspace-dp/src/afxdp/forwarding/mod.rs`: 2671 LOC.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs`: 2058 LOC.
- `userspace-dp/src/nat64.rs`: 2047 LOC.
- `userspace-dp/src/session/mod.rs`: 1959 LOC.
- `pkg/api/metrics_descriptors.go`: 1867 LOC, `newCollector` about 1858 LOC.
- `pkg/api/metrics_userspace.go`: 1819 LOC.
- `pkg/dhcp/dhcp.go`: 1800 LOC.
- `pkg/vrrp/instance.go`: 2250 LOC.
- `pkg/daemon/daemon_run.go`: 2320 LOC.
- `pkg/daemon/daemon_apply.go`: 1883 LOC.
- `pkg/ddns/surface_a.go`: 1841 LOC.

## File-By-File Inspection Log

- Rust hot path: `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, `poll_stages.rs`, `forwarding/mod.rs`, `worker/loop_body/mod.rs`, `cos/queue_service/mod.rs`, `session/mod.rs`, `nat64.rs`, `frame/inspect.rs`, `cold_path_hist.rs`.
- Rust control/protocol: `policy.rs`, `screen/extract.rs`, `screen/mod.rs`, `screen/tests.rs`, `afxdp/wg/engine.rs`, `afxdp/wg/cookie.rs`, `afxdp/wg/tests.rs`, `protocol/{binding,control,snapshot,tests}.rs`, `server/{helpers,lifecycle,handlers}.rs`.
- Go config/policy: `pkg/config/compiler.go`, `compiler_validate_warn.go`, `compiler_nat.go`, `compiler_system.go`, `compiler_services.go`, `compiler_class_of_service.go`, `compiler_firewall.go`, `schema_walk.go`, `ast_groups.go`, `pkg/policymatch/policymatch.go`.
- Go dataplane/control: `pkg/dataplane/userspace/{manager.go,maps_sync.go,protocol.go,eventstream.go}`, `pkg/daemon/{daemon_run.go,daemon_apply.go,daemon_ha_sync.go}`, `pkg/cluster/{sync_protocol.go,failover.go}`.
- API/CLI/services: `pkg/api/{metrics_descriptors.go,metrics_userspace.go,sessions.go,show_text.go}`, `pkg/grpcapi/{server_show.go,server_sessions.go}`, `pkg/cli/{cli_show_interfaces.go,cli_show_flow.go}`, `pkg/dhcp/dhcp.go`, `pkg/vrrp/instance.go`, `pkg/ddns/surface_a.go`.
- Negative results: `userspace-dp/src/afxdp/cold_path_hist.rs`, `userspace-dp/src/afxdp/frame/inspect.rs`, and `pkg/cluster/failover.go` are large but have enough layout/locking coupling that naive splitting should be avoided.

## High Confidence Findings

### 1. AF_XDP worker loop still fuses packet polling with cold maintenance

- Title: AF_XDP worker loop still fuses packet polling with cold maintenance.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails, potentially C performance-positive if cold outlining reduces i-cache pressure.
- Evidence: `userspace-dp/src/afxdp/worker/loop_body/mod.rs` is 1767 LOC; `worker_loop` is about 1265 LOC. It includes config refresh, screen/session timeout refresh, cold-path slot zeroing, HA/session delta export, session GC, BPF/NAT/flow-cache cleanup, conntrack refresh, fabric refresh, telemetry, idle regulation, and the actual binding poll loop.
- Proposed decomposition: Keep the per-binding poll body inline, then extract cold taken bodies into `worker/loop_body/config_refresh.rs`, `session_deltas.rs`, `maintenance.rs`, and `telemetry.rs`.
- Hot-path preservation analysis: No call boundary before the per-tick ArcSwap check or the per-binding `poll_binding` path. Mark cold maintenance helpers `#[cold] #[inline(never)]`; keep the hot poll path allocation-free and free of dynamic dispatch.
- Tests + gate: `cargo test --manifest-path userspace-dp/Cargo.toml worker::loop_body`; full userspace cargo test; failover smoke; objdump or cargo-asm diff on `worker_loop` and poll fast path.
- Why it matters: Every new maintenance hook currently competes with packet-loop locality and makes it easy to add cold work on the hot path.
- Fix direction: First extract session-delta flush and reaping helpers, then config refresh, then telemetry/debug blocks. Keep behavior identical and land as code-motion PRs.
- Labels: refactor, rust, hot-path, x-hpc, userspace-dp.
- Dedup note: Prior reports covered flow-cache replay and binding worker issues; this is the remaining worker-loop maintenance fusion.

### 2. `poll_descriptor/mod.rs` remains a hot-path packet-processing god module

- Title: `poll_descriptor/mod.rs` remains a hot-path packet-processing god module.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/afxdp/poll_descriptor/mod.rs` is 5759 LOC. Comments at lines 1-16 state it was extracted from `afxdp.rs` and that further extraction was blocked by mutable-locals coupling. It still mixes session-hit policy, session-miss install, NAT tracking, local delivery, reject replies, conntrack publish, debug counters, and buffer recycling.
- Proposed decomposition: Create `poll_descriptor/{session_hit,session_miss,local_delivery,forward_commit,debug_cold}.rs` with a narrow `DescriptorContext` carrying explicit mutable state.
- Hot-path preservation analysis: This is packet hot path. No heap allocation, trait objects, or map lookups should be introduced. Helpers must remain same-crate and inline only where codegen proves equivalent.
- Tests + gate: Existing AF_XDP poll descriptor tests; policy/filter/reject tests; cargo-asm or objdump diff for `poll_binding_process_descriptor`; perf branch/i-cache counters on policy-heavy traffic.
- Why it matters: The mutable-locals coupling is now documented as a blocker but has become a permanent review hazard for core forwarding.
- Fix direction: Extract cold/debug/logging first, then isolate session-hit and session-miss paths with a small context struct, one path per PR.
- Labels: refactor, rust, hot-path, x-hpc, packet-processing.
- Dedup note: Prior reports found specific bugs inside this file; this finding is the structural split needed to keep future fixes reviewable.

### 3. `poll_stages.rs` is a stage bag with repeated screen and ingress classification logic

- Title: `poll_stages.rs` is a stage bag with repeated screen and ingress classification logic.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/afxdp/poll_stages.rs` is 3024 LOC. The file header says stages 5-11 were extracted while stages 12+ remain inline elsewhere. It currently combines L2 learning, native GRE, flow parsing, fabric ingress, screen checks, SYN-cookie ACK handling, and IPsec hooks. `stage_screen_check` and `stage_screen_syn_cookie_ack_on_session_miss` repeat logical-ifindex/zone/screen resolution logic.
- Proposed decomposition: Split into `poll_stages/{l2_learn,gre,flow_parse,fabric,screen,ipsec}.rs`, with shared inline screen-context resolution helpers.
- Hot-path preservation analysis: The stage chain is hot. Shared helpers must be allocation-free and same-crate inlineable; no new dynamic stage registry or trait-dispatch pipeline.
- Tests + gate: Screen tests, native GRE tests, IPsec smoke, AF_XDP stage tests, cargo-asm diff around screen stage entry points.
- Why it matters: Repeated zone/screen resolution is exactly the kind of code that drifts across SYN, ACK, flowless, and tunneled paths.
- Fix direction: Extract the screen stage pair first, backed by a common `ScreenStageContext`; then split GRE/fabric/IPsec cold or specialized branches.
- Labels: refactor, rust, hot-path, screen, userspace-dp.
- Dedup note: Not a duplicate of previous SYN-flood correctness findings; this is stage-level structure and repeated resolver logic.

### 4. Forwarding module mixes fabric, HA, neighbor, tunnel, MSS, and ICMP behavior

- Title: Forwarding module mixes fabric, HA, neighbor, tunnel, MSS, and ICMP behavior.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/afxdp/forwarding/mod.rs` is 2671 LOC. It includes route metadata, fabric redirect/preference, logical ifindex and HA resolution, neighbor handling, NAT interplay, MSS clamp/tunnel MTU/GRE/WireGuard logic, and ICMP time-exceeded support.
- Proposed decomposition: `forwarding/{fabric,ha,neighbors,mss,tunnel,classification,icmp}.rs`, keeping `mod.rs` as the public forwarding decision facade.
- Hot-path preservation analysis: This is packet path. Keep forwarding decisions as concrete functions with no allocation or trait dispatch. Preserve cache-local `ForwardingDecision` and metadata construction.
- Tests + gate: Forwarding tests, GRE/WG native smoke, MSS clamp tests, HA failover, perf branch/i-cache comparison for transit forwarding.
- Why it matters: Fabric and tunnel feature additions now land beside unrelated neighbor and MSS code, increasing blast radius.
- Fix direction: Extract the MSS/tunnel helpers first because they have clear inputs/outputs, then fabric/HA resolution with explicit invariants.
- Labels: refactor, rust, hot-path, forwarding, x-hpc.
- Dedup note: Prior findings flagged specific MSS/GRE parity gaps; this is the module split that contains future tunnel and fabric changes.

### 5. CoS queue service remains a 2k LOC scheduler monolith

- Title: CoS queue service remains a 2k LOC scheduler monolith.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/afxdp/cos/queue_service/mod.rs` is 2058 LOC. It contains the hot drain orchestration, exact selector, non-exact selector, waterfill policy, surplus settlement, submit path, wakeup tick, and DSCP rewrite. The file comments define a hot call chain that should stay inline.
- Proposed decomposition: `queue_service/{orchestrator,selection,waterfill,surplus,settle,submit,wakeup,dscp}.rs`.
- Hot-path preservation analysis: This is scheduler hot path. Preserve inline call chain, avoid new allocations, keep atomics and ownership state unchanged, and assembly-diff `drain_shaped_tx`/selector paths.
- Tests + gate: CoS queue-service tests, fairness tests, userspace CoS smoke, perf counters under shaped load.
- Why it matters: CoS is algorithmically dense; policy changes in waterfill or surplus sharing should not be reviewed in the same file as TX submit and DSCP rewrite.
- Fix direction: Move cold/test-only helpers first, then exact/non-exact selector code with cargo-asm guardrails.
- Labels: refactor, rust, hot-path, cos, x-hpc.
- Dedup note: Prior reports covered CoS bugs. This is residual structural debt after those fixes.

### 6. NAT64 implementation fuses state parsing, header walking, translation, ICMP mapping, checksum, and frame construction

- Title: NAT64 implementation fuses state parsing, header walking, translation, ICMP mapping, checksum, and frame construction.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/nat64.rs` is 2047 LOC. It includes snapshot/config parsing, IPv6 extension header walking, v6-to-v4 and v4-to-v6 translation, ICMP type/code maps, checksum recompute helpers, and frame builders.
- Proposed decomposition: `nat64/{state,headers,translate,icmp,checksum,frame}.rs`.
- Hot-path preservation analysis: Translation is hot when NAT64 is active. Keep `_into` writers allocation-free, preserve checksum incremental behavior, and avoid abstraction over packet buffers.
- Tests + gate: NAT64 tests, checksum vectors, fragmented/extension-header tests, perf smoke for NAT64 traffic if available.
- Why it matters: NAT64 correctness depends on several protocol subdomains. The current file makes ICMP changes and header walker changes look like one feature.
- Fix direction: Extract ICMP maps and frame builders first, then state parsing, then translation helpers with assembly/perf checks.
- Labels: refactor, rust, nat64, hot-path.
- Dedup note: Prior reports focused on NAT64 correctness gaps; this is the safe module boundary.

### 7. Policy cold parser pipeline lives inside the hot policy module

- Title: Policy cold parser pipeline lives inside the hot policy module.
- Severity: High.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `userspace-dp/src/policy.rs` is 4224 LOC. `parse_policy_state_with_counters` starts at line 2519 and is about 523 LOC, fusing default-policy parse, ID uniqueness, zone universe, address-book compilation, rule parsing, application compilation, indexes, and counter-map setup.
- Proposed decomposition: `policy/parser/{defaults,identity,books,rules,index}.rs`, with the public entry point re-exported unchanged.
- Hot-path preservation analysis: Parser runs on snapshot apply, not per-packet evaluation. Keep `PolicyState`, rule matchers, and prefix-set hot types unchanged.
- Tests + gate: Policy parser tests, apply-snapshot failure tests, full Rust policy tests. Verify `rg parse_policy_state_with_counters` shows no packet path callers.
- Why it matters: Security fail-closed preflight is dense and hard to review while sharing a file with packet matchers.
- Fix direction: Extract identity/address-book checks first, then per-rule compilation, then index insertion.
- Labels: refactor, rust, policy, cold-path.
- Dedup note: Not the broad `policy.rs` split already reported; this is the cold parser pipeline specifically.

### 8. Screen packet extractor is a 305 LOC hot parser spanning IPv4, IPv6, fragments, and TCP options

- Title: Screen packet extractor is a 305 LOC hot parser spanning IPv4, IPv6, fragments, and TCP options.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/screen/extract.rs` has `extract_screen_info` starting at line 42 and spanning about 305 LOC. It initializes packet info, parses IPv4 IHL/options/source-route, walks IPv6 extension headers/fragments, and extracts TCP seq/ack/MSS.
- Proposed decomposition: Private helpers `parse_ipv4_screen_fields`, `walk_ipv6_screen_headers`, `scan_ipv4_source_route_options`, and `extract_tcp_screen_fields`.
- Hot-path preservation analysis: This is security hot path. No allocation, no packet copy, no trait dispatch, no new `Vec`. Validate inlining with cargo-asm or objdump.
- Tests + gate: Move extractor tests to `screen/extract_tests.rs`; run screen tests and screen dataplane smoke.
- Why it matters: Truncated-header and source-route fail-closed invariants are easier to break when every protocol family is in one branchy function.
- Fix direction: Extract TCP option parsing first, then IPv4 option scan, then IPv6 extension walking.
- Labels: refactor, rust, screen, hot-path, x-hpc.
- Dedup note: Not the prior SYN-flood enforcement finding; this is packet-field extraction.

### 9. WireGuard engine fuses cold peer reconciliation with hot encap/decap

- Title: WireGuard engine fuses cold peer reconciliation with hot encap/decap.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/afxdp/wg/engine.rs` is 1763 LOC. It owns peer table, AllowedIPs, session demux, handshake construction, `reconcile_peers` around line 832, `encap_inner` around line 1206, and `try_decap` around line 1386.
- Proposed decomposition: Convert to `wg/engine/mod.rs`; move cold config reconciliation to `engine/reconcile.rs`; move transport hot path to `engine/transport.rs`; keep types in `mod.rs` unless imports become cleaner.
- Hot-path preservation analysis: `try_encap`, `encap_inner`, and `try_decap` must remain concrete monomorphized methods with no trait objects, boxes, or extra shared locks.
- Tests + gate: WG test subset, native GRE/WG validation, failover smoke if status/HA touched, objdump/cargo-asm diff for encap/decap.
- Why it matters: WG transport is latency-sensitive; config reconciliation and crypto fast path need separate review surfaces.
- Fix direction: Move `reconcile_peers` first with no hot code motion; move transport functions only after codegen baseline.
- Labels: refactor, rust, wireguard, hot-path, x-hpc.
- Dedup note: Not a WG correctness bug finding; this is hot/cold structure.

### 10. Server `refresh_status` is a 311 LOC telemetry aggregator under control state

- Title: Server `refresh_status` is a 311 LOC telemetry aggregator under control state.
- Severity: High.
- Confidence: High.
- Refactor class: A mechanical/safe, with possible C follow-up if lock scope shrinks.
- Evidence: `userspace-dp/src/server/helpers.rs` has `refresh_status` starting at line 16 and spanning about 311 LOC. It updates binding status, WG/GRE liveness, writer status, neighbor telemetry, generated replies, worker runtime, queue summaries, policy/NAT/filter counters, event-stream stats, and fabric diagnostics.
- Proposed decomposition: `server/status/{runtime_liveness,neighbor,worker,security,event_stream,fabric}.rs`, with `refresh_status` as a thin orchestrator.
- Hot-path preservation analysis: Control/status path only, but avoid new expensive AFXDP traversals and preserve `XPF_DEBUG_NEIGHBOR_KEYS` gating.
- Tests + gate: Rust server tests and status fixture tests; no dataplane perf gate needed for pure code motion.
- Why it matters: Status telemetry is growing quickly and can easily add blocking or expensive calls under shared control state.
- Fix direction: Extract assignment blocks by status family, then consider off-lock snapshots only as a separate PR.
- Labels: refactor, rust, server, telemetry.
- Dedup note: Not the prior export-under-lock finding; this is the general status aggregator.

### 11. Go userspace protocol file is a 77-struct wire god file

- Title: Go userspace protocol file is a 77-struct wire god file.
- Severity: High.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/dataplane/userspace/protocol.go` is 2901 LOC. It mixes control requests, full config snapshots, NAT/policy/route DTOs, process status, flow-worker debug rows, HA state, and slow-path status.
- Proposed decomposition: `protocol/control.go`, `protocol/snapshot.go`, `protocol/security.go`, `protocol/nat.go`, `protocol/status.go`, `protocol/ha.go` within the same Go package, preserving exported type names.
- Hot-path preservation analysis: Cold control-plane wire types. Preserve JSON tags, `omitempty`, numeric widths, and compatibility comments exactly.
- Tests + gate: `go test ./pkg/dataplane/userspace`; Go/Rust protocol compatibility tests; snapshot decode canaries.
- Why it matters: Wire-shape drift is hard to see when unrelated status and snapshot DTOs share one huge file.
- Fix direction: Move structs by wire family without renaming exported types; add source-level canaries for key JSON tags.
- Labels: refactor, go, protocol, wire-compat.
- Dedup note: Prior reports cited individual fields; this is the file-level decomposition.

### 12. Userspace map/status sync holds many responsibilities under `Manager.mu`

- Title: Userspace map/status sync holds many responsibilities under `Manager.mu`.
- Severity: High.
- Confidence: High.
- Refactor class: C performance-positive if it shortens lock scope; otherwise B requires guardrails.
- Evidence: `pkg/dataplane/userspace/maps_sync.go` has `applyHelperStatusLocked` around line 326 and about 451 LOC. It fuses ctrl gate calculation, XSK liveness, callback firing, stale-session cleanup, binding map sync, ingress/local/interface-NAT sync, counter fold-in, and status recording.
- Proposed decomposition: `status_ctrl_gate.go`, `status_bindings.go`, `status_liveness.go`, `shim_maps_ingress.go`, `shim_maps_local.go`, `counter_sync.go`.
- Hot-path preservation analysis: This is control path, but it programs BPF maps consumed by the shim. Preserve ctrl fail-closed ordering, native endian map keys, and avoid widening lock hold time.
- Tests + gate: `go test ./pkg/dataplane/userspace -run 'Status|Binding|Local|Counter|Forwarding'`; userspace failover smoke.
- Why it matters: Map sync is safety-critical. Smaller locked helpers make fail-closed ordering reviewable.
- Fix direction: Extract helpers with explicit "caller holds m.mu" contracts; defer actual lock-scope changes to a second PR.
- Labels: refactor, go, userspace-dp, control-plane.
- Dedup note: Prior local-address prune bug is fixed; this is the broader map/status sync split.

### 13. Userspace event stream is a transport, ACK, dispatch, and decoder god object

- Title: Userspace event stream is a transport, ACK, dispatch, and decoder god object.
- Severity: High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `pkg/dataplane/userspace/eventstream.go` is 1155 LOC. It contains socket accept/read/write, callback registry, pending-frame queue, ACK state, drain fence, binary decoders, and per-event counters.
- Proposed decomposition: `eventstream/{transport,ack,pending,dispatch,decode,counters}.go`.
- Hot-path preservation analysis: Not packet hot path, but HA/session events can be high-churn. Preserve decoder allocation profile, sequence/ACK ordering, and avoid extra goroutines in `readLoop`.
- Tests + gate: `eventstream_test.go`, cross-type gap/order tests, HA bulk sync smoke.
- Why it matters: ACK monotonicity and gap handling are easy to regress when transport and dispatch state live in one file.
- Fix direction: Split decoders and counters first, then ACK/pending state with tests.
- Labels: refactor, go, ha, userspace-dp.
- Dedup note: Prior sequence-gap bugs are not repeated here; this is module isolation.

### 14. Daemon apply pipeline is a 1100+ LOC ordered reconcile chain

- Title: Daemon apply pipeline is a 1100+ LOC ordered reconcile chain.
- Severity: High.
- Confidence: High.
- Refactor class: C performance-positive if it narrows lock/commit critical sections; otherwise B.
- Evidence: `pkg/daemon/daemon_apply.go` has `applyConfigLocked` starting at line 546 and running to line 1672. It reconciles SNMP, bootstrap exit, VRFs, tunnels, xfrmi, bonds, fabric IPVLAN, RETH MAC worker deferral, networkd/DHCP/LLDP/RPM/IPMon, cluster, RSS, and host tunables in one function.
- Proposed decomposition: `daemon/apply/{bootstrap,links,dataplane,services,ha_sync,tunables}.go`, with an explicit ordered pipeline object.
- Hot-path preservation analysis: Control path, but commit latency and HA apply ordering matter. Preserve the existing early-return and `compileErrorMustAbortApply` behavior; do not move SNMP before/after abort gates casually.
- Tests + gate: `go test ./pkg/daemon`; commit/apply tests; userspace HA failover; bootstrap/lifeline tests.
- Why it matters: The order is the contract. Encoding that as named pipeline phases would make future ordering changes auditable.
- Fix direction: Extract phase helpers without reordering, then add a table/commented phase list that documents abort points.
- Labels: refactor, go, daemon, control-plane.
- Dedup note: Prior daemon bugs targeted individual lifecycle issues; this is the apply pipeline structure.

### 15. Prometheus descriptor constructor is a single 1858 LOC literal

- Title: Prometheus descriptor constructor is a single 1858 LOC literal.
- Severity: High.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/api/metrics_descriptors.go` is 1867 LOC and `newCollector` is about 1858 LOC. It initializes global, session, screen, NAT, system, scheduler, worker, CoS, cold-path, fairness, binding, WireGuard, and flow-export descriptors in one function.
- Proposed decomposition: Keep `newCollector` as assembler; move descriptor groups to `metrics_descriptors_{global,system,userspace_cos,sessions,wireguard,flowexport}.go`.
- Hot-path preservation analysis: Metrics scrape/control path only. Preserve descriptor names, help text, label order, and one-time registration. Do not create descriptors per scrape.
- Tests + gate: `go test ./pkg/api/...`; descriptor coverage tests; metrics tests; `go build ./...`.
- Why it matters: Prometheus label order and names are API. A domain split makes drift easier to catch.
- Fix direction: Pure code motion by descriptor family with exact string preservation.
- Labels: refactor, go, api, metrics.
- Dedup note: Prior REST/metrics split did not split this constructor.

### 16. Userspace metrics emitter is a 1819 LOC dumping ground

- Title: Userspace metrics emitter is a 1819 LOC dumping ground.
- Severity: High.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/api/metrics_userspace.go` is 1819 LOC. `collectUserspaceStatus` intentionally fetches one `Status()` result then fans out to 26 emitters. Emitters cover fabric, reject, CoS, runtime, buffers, events, NAT, fairness, neighbor, WireGuard, policy rejection, zone collisions, and cold path.
- Proposed decomposition: `metrics_userspace_status.go` plus `metrics_userspace_{cos,fairness,sessions_nat,wireguard,fabric_reject,worker}.go`.
- Hot-path preservation analysis: Scrape path only. Preserve the single `Status()` call per scrape and pass the status object to helpers; never re-fetch per metric family.
- Tests + gate: `go test ./pkg/api/...`; CoS/fairness metrics tests; descriptor coverage.
- Why it matters: It is easy to add a second control-socket status call or alter label cardinality when all emitters share one large file.
- Fix direction: Split one family per PR, with tests checking descriptor and emitted label stability.
- Labels: refactor, go, api, metrics, userspace-dp.
- Dedup note: This is residual after metrics file splitting, not the older pre-split `metrics.go` issue.

## Medium Confidence Findings

### 17. `SessionEntry` and `SessionTable` mix hot packet fields with cold HA/accounting/config state

- Title: `SessionEntry` and `SessionTable` mix hot packet fields with cold HA/accounting/config state.
- Severity: Medium-High.
- Confidence: Medium.
- Refactor class: C performance-positive, but B requires guardrails.
- Evidence: `userspace-dp/src/session/mod.rs` is 1959 LOC. `SessionEntry` around lines 332-447 includes hot flow/NAT/accounting fields plus HA, logging, and cold metadata. `SessionTable` around lines 489-530 includes slab, indexes, deltas, timeouts, opening overrides, counters, and session-limit maps.
- Proposed decomposition: Split modules into `session/{entry,table,timeout,delta,limits}` and consider hot/cold field separation only after layout tests.
- Hot-path preservation analysis: Session lookup/update is hot. Do not reorder fields or split structs without size/offset/perf measurements. Pure file split is safe; layout split needs a dedicated benchmark.
- Tests + gate: Session tests, HA session sync tests, NAT tests, cargo-asm/perf for session lookup/update.
- Why it matters: The table has become both allocator and HA replication ledger, which makes packet-path changes riskier.
- Fix direction: Start with module split only, then separately evaluate hot/cold layout.
- Labels: refactor, rust, session, hot-path, x-hpc.
- Dedup note: Prior reports found session lifecycle bugs; this is structural, and field-layout changes are explicitly guarded.

### 18. WireGuard cookie module mixes responder, rate limiter, initiator, and tests

- Title: WireGuard cookie module mixes responder, rate limiter, initiator, and tests.
- Severity: Medium.
- Confidence: Medium.
- Refactor class: A mechanical/safe.
- Evidence: `userspace-dp/src/afxdp/wg/cookie.rs` is 1435 LOC. Production code includes responder cookie checker, secret rotation, load detection, global reply budget, per-source token bucket, initiator cookie state, random-source policy, and about 580 LOC of inline tests.
- Proposed decomposition: `wg/cookie/{mod,responder,rate_limit,initiator,tests}.rs`.
- Hot-path preservation analysis: WG cookie path is handshake/control path, not per-record transport. Preserve mutex granularity, RNG fail-closed behavior, and secret zeroization.
- Tests + gate: WG cookie tests, handshake tests, full WG tests.
- Why it matters: Crypto/DoS invariants are safer when responder and initiator state are reviewed separately.
- Fix direction: Move tests first, then initiator state, then rate-limiter structs behind unchanged `CookieChecker` methods.
- Labels: refactor, rust, wireguard, crypto.
- Dedup note: Not the WG cookie DoS correctness finding; assumes that behavior remains.

### 19. On-demand neighbor resolver mixes hot enqueue, netlink codec, resolver loop, and tests

- Title: On-demand neighbor resolver mixes hot enqueue, netlink codec, resolver loop, and tests.
- Severity: Medium.
- Confidence: Medium.
- Refactor class: B requires guardrails.
- Evidence: `userspace-dp/src/afxdp/neighbor_resolver.rs` is 1512 LOC. It includes worker-facing nonblocking enqueue, netlink request building, reply parsing, NUD/rate-limit decisions, counters, the resolver loop, and live-thread tests.
- Proposed decomposition: `neighbor_resolver/{handle,netlink,decision,loop,tests}.rs`.
- Hot-path preservation analysis: `NeighborResolver::enqueue` is worker-facing and must remain inline, nonblocking, and allocation-free beyond the existing caller-provided string. Netlink `Vec` buffers stay on the resolver thread.
- Tests + gate: Neighbor resolver tests, negative-neighbor tests, failover smoke.
- Why it matters: Netlink parsing changes should not share a file with worker hot enqueue logic.
- Fix direction: Extract netlink codec and decision helpers first; keep enqueue in `handle.rs`.
- Labels: refactor, rust, neighbor, hot-path.
- Dedup note: Prior neighbor split notes targeted monitor/dump code, not this resolver.

### 20. Warning validator remains a 2919 LOC control-plane monolith

- Title: Warning validator remains a 2919 LOC control-plane monolith.
- Severity: Medium-High.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/config/compiler_validate_warn.go` is 2919 LOC; `ValidateConfig` is about 1357 LOC and dispatches AppID, auth/login, DHCP, interface parity, junos-host, firewall, DDNS, routing, and CoS warning logic.
- Proposed decomposition: `compiler_warn_{dispatch,security,interfaces,firewall,ddns,routing,cos}.go`.
- Hot-path preservation analysis: Commit/apply advisory path only; no dataplane hot path. Preserve warning order and exact text where tests depend on it.
- Tests + gate: `go test ./pkg/config -run 'Warn|Warning|Advisory|ValidateConfig'`; full config tests.
- Why it matters: Warning-only compatibility behavior is subtle and should not be reviewed in a single massive dispatcher.
- Fix direction: Split helpers by domain with dispatcher preserving current order.
- Labels: refactor, go, config, warnings.
- Dedup note: Not the old strict-validator monolith; that was already split.

### 21. Policy-match simulator fuses selector parsing, matching, address/app expansion, and rendering

- Title: Policy-match simulator fuses selector parsing, matching, address/app expansion, and rendering.
- Severity: Medium.
- Confidence: High.
- Refactor class: A mechanical/safe with parity guardrails.
- Evidence: `pkg/policymatch/policymatch.go` is 1579 LOC. It validates selector inputs, parses CLI args, walks transit/global/junos-host policy tiers, expands address books and feeds, mirrors AppID behavior, and renders text.
- Proposed decomposition: `selector.go`, `result.go`, `match.go`, `host.go`, `address.go`, `application.go`, `render.go`.
- Hot-path preservation analysis: Control-plane simulator only, but it mirrors Rust policy hot path. No semantic changes to runtime tier order or address/app behavior.
- Tests + gate: `go test ./pkg/policymatch`; CLI/REST/gRPC match-policy tests.
- Why it matters: Simulator parity failures can mislead operators about whether traffic will be allowed or denied.
- Fix direction: Split parser/rendering first, then matching helpers with golden tests.
- Labels: refactor, go, policy, vsrx-parity.
- Dedup note: Prior reports found semantic bugs; this is the module decomposition.

### 22. System compiler file mixes login/auth, userspace dataplane, shared-UMEM artifacts, SNMP, schedulers, and chassis

- Title: System compiler file mixes login/auth, userspace dataplane, shared-UMEM artifacts, SNMP, schedulers, and chassis.
- Severity: Medium.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/config/compiler_system.go` is 1869 LOC. It includes `compileSystem`, userspace dataplane knobs, shared-UMEM JSON artifact reading/normalization, SNMP parsing, scheduler windows, and chassis cluster parsing.
- Proposed decomposition: `compiler_system_{core,login,dataplane,shared_umem,snmp,schedulers,chassis}.go`.
- Hot-path preservation analysis: Compile path only. Keep artifact file I/O out of any dataplane loop and preserve secret redaction behavior.
- Tests + gate: Config system tests, SNMP tests, scheduler/chassis tests, full config package.
- Why it matters: Unrelated system features currently share one file, increasing review blast radius.
- Fix direction: Move SNMP/shared-UMEM/scheduler sections first because they have clearer boundaries.
- Labels: refactor, go, config, system.
- Dedup note: Prior reports cited individual bugs here; not a prior monolith split in this scope.

### 23. Services compiler mixes RPM, DHCP, feeds, IP monitoring, sampling, event-options, and bridge domains

- Title: Services compiler mixes RPM, DHCP, feeds, IP monitoring, sampling, event-options, and bridge domains.
- Severity: Medium.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/config/compiler_services.go` is 1808 LOC. It alternates between RPM validation, DHCP server/relay parsing, dynamic-address feed parsing, IP monitoring route resolution, forwarding-options, sampling, event policy parsing, and bridge domains.
- Proposed decomposition: `compiler_{rpm,dhcp,dynamic_address,ipmonitoring,forwarding_options,event_options,bridge_domains}.go`.
- Hot-path preservation analysis: Compile path only, but typed config feeds dataplane snapshots. Preserve output structs and validation order.
- Tests + gate: `go test ./pkg/config -run 'RPM|DHCP|DynamicAddress|IPMonitoring|Sampling|EventOptions|Bridge'`.
- Why it matters: Service features have different owners and validation domains; one file encourages accidental coupling.
- Fix direction: Split by top-level Junos service domain with no behavior changes.
- Labels: refactor, go, config, services.
- Dedup note: Prior service parser bugs are separate from this structural split.

### 24. Show-text dispatch and rendering are still duplicated across REST and gRPC

- Title: Show-text dispatch and rendering are still duplicated across REST and gRPC.
- Severity: Medium.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/grpcapi/server_show.go` has a 496 LOC `ShowText` dispatcher; `pkg/api/show_text.go` has a 302 LOC REST handler. They duplicate topic parsing/rendering around security, DHCP, NAT, interfaces, cluster, logs, and flow topics.
- Proposed decomposition: Create a shared `pkg/showtext` registry with topic matchers, dependency declarations, and render functions. REST/gRPC wrappers remain thin.
- Hot-path preservation analysis: Operator text path only. Preserve topic names, error codes, context propagation, log path sanitization, tail clamping, and command timeouts.
- Tests + gate: `go test ./pkg/grpcapi/... ./pkg/api/...`; show-text golden tests.
- Why it matters: Operator commands are API. Duplicate dispatchers drift and create inconsistent REST/gRPC output.
- Fix direction: Extract one read-only registry, then migrate REST and gRPC handlers one topic group at a time.
- Labels: refactor, go, api, grpc, cli-surface.
- Dedup note: Prior gRPC/REST file splits left this registry duplication intact.

### 25. Session surfaces duplicate pagination, filtering, projection, and clear logic across REST, gRPC, and CLI

- Title: Session surfaces duplicate pagination, filtering, projection, and clear logic across REST, gRPC, and CLI.
- Severity: Medium.
- Confidence: High.
- Refactor class: A mechanical/safe with control-path performance guardrails.
- Evidence: `pkg/api/sessions.go` is 1291 LOC, `pkg/grpcapi/server_sessions.go` is 1408 LOC, and `pkg/cli/cli_show_flow.go` is 1240 LOC. They duplicate cursor setup, filter parsing, v4/v6 matching, page-token codec, rendering, and delete/clear companion handling.
- Proposed decomposition: Introduce `pkg/sessionview` with filter parsing, page-token codec, entry projection, egress-interface resolver, and callback-based iteration adapters.
- Hot-path preservation analysis: Not packet path, but scans can be large. Preserve callback iteration and page-size caps; do not force full materialization for CLI streaming.
- Tests + gate: REST/gRPC/CLI session tests, pagination tests, clear-session reverse/DNAT companion tests.
- Why it matters: Divergent session views make troubleshooting and operator automation unreliable.
- Fix direction: Extract common filter and token codec first, then projection helpers, then clear semantics.
- Labels: refactor, go, sessions, api, cli.
- Dedup note: Distinct from prior shared policy-view mapper; this is session-view duplication.

### 26. DHCP client file mixes public lease state, lifecycle, protocol exchanges, parsers, netlink apply, and prefix delegation

- Title: DHCP client file mixes public lease state, lifecycle, protocol exchanges, parsers, netlink apply, and prefix delegation.
- Severity: Medium.
- Confidence: High.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/dhcp/dhcp.go` is 1800 LOC. It includes lease types, manager lifecycle, `runDHCPv4`, `runDHCPv6`, v4/v6 exchanges, reply parsing, netlink address apply/remove, and PD helpers.
- Proposed decomposition: `lease.go`, `manager.go`, `client_v4.go`, `client_v6.go`, `parse_v4.go`, `parse_v6.go`, `address.go`, `pd.go`.
- Hot-path preservation analysis: DHCP control traffic only. Preserve T1/T2 timers, retry loops, callbacks outside `m.mu`, and durable DUID behavior.
- Tests + gate: `go test ./pkg/dhcp/...`; DHCPv6 IA_NA, renew, commit, classless route, and address apply tests.
- Why it matters: DHCPv4, DHCPv6 IA_NA, and PD have different protocol invariants and should not share one file.
- Fix direction: Split parsers first, then clients, then address apply.
- Labels: refactor, go, dhcp, control-plane.
- Dedup note: `_Log.md` documents DHCPv6 bug fixes, not this file split.

### 27. VRRP instance is a same-package god struct and state-machine file

- Title: VRRP instance is a same-package god struct and state-machine file.
- Severity: Medium-High.
- Confidence: High.
- Refactor class: B requires guardrails.
- Evidence: `pkg/vrrp/instance.go` is 2250 LOC. `vrrpInstance` spans about 148 struct lines and mixes config, timers, atomics, sockets, test seams, RX counters, and event hooks. The file also contains backup/master state machine, AF_PACKET/raw sockets, TX adverts, VIP/GARP/NA, and gateway probes.
- Proposed decomposition: Same package only: `instance_state.go`, `instance_run.go`, `instance_rx.go`, `instance_tx.go`, `instance_vip.go`, `instance_garp.go`.
- Hot-path preservation analysis: Not forwarding hot path, but failover timing sensitive. Do not add channels, goroutines, locks, timer behavior changes, or struct field reordering.
- Tests + gate: `go test -race ./pkg/vrrp/...`; packet checksum tests; HA failover smoke.
- Why it matters: VRRP state-machine timing and packet RX/TX are too important to review in one 2k LOC file.
- Fix direction: Pure code motion by function group, no struct split in the first pass.
- Labels: refactor, go, vrrp, ha.
- Dedup note: No prior campaign item found for this exact same-package split.

### 28. DDNS Surface A manager remains a broad engine module

- Title: DDNS Surface A manager remains a broad engine module.
- Severity: Medium.
- Confidence: Medium.
- Refactor class: A mechanical/safe.
- Evidence: `pkg/ddns/surface_a.go` is 1841 LOC. It defines scope/state/orphan types, manager state, reconcile pass, scope publish/withdraw, backend classification, orphan alarms, backoff, stats, and status views.
- Proposed decomposition: `surfacea/{scope,state,reconcile,publish,withdraw,orphan,status,backend_resolve}.go` under `pkg/ddns` or `pkg/ddns/surfacea` if import cycles stay clean.
- Hot-path preservation analysis: DDNS is control-plane. Preserve HA gate semantics, provider identity fingerprints, no-backend behavior, and provider I/O outside manager mutex.
- Tests + gate: DDNS Surface A tests, provider identity/orphan tests, HA gate tests.
- Why it matters: Surface A has accumulated complex safety behavior. Splitting by publish/withdraw/orphan/status reduces future provider-change regressions.
- Fix direction: Move status/stats and type definitions first, then publish/withdraw helpers, then reconcile pass helpers.
- Labels: refactor, go, ddns, control-plane.
- Dedup note: Prior DDNS reports were correctness-focused; this is the residual module boundary.

## Low Confidence Findings And Negative Results

### 29. Giant Rust integration test files obscure ownership and slow refactors

- Title: Giant Rust integration test files obscure ownership and slow refactors.
- Severity: Medium for review cost, low runtime risk.
- Confidence: Medium.
- Refactor class: A mechanical/safe.
- Evidence: `userspace-dp/src/afxdp/tests.rs` is 13408 LOC, `screen/tests.rs` is 5121 LOC, `afxdp/wg/tests.rs` is 3806 LOC, `protocol/tests.rs` is 2334 LOC, and many other test files exceed 2k LOC.
- Proposed decomposition: Split tests next to production seams: `afxdp/tests/{bind,icmp_embed,poll_descriptor,flow_cache,worker}.rs`, `screen/tests/{stateless,extract,rate,syncookie,scan,fabric}.rs`, `wg/tests/{transport,reconcile,rekey,handshake}.rs`, `protocol/tests/{status,snapshot,cos,wg}.rs`.
- Hot-path preservation analysis: Test-only. Risk is losing coverage, not runtime. Preserve test names and shared fixtures.
- Tests + gate: The moved tests themselves plus full `cargo test --manifest-path userspace-dp/Cargo.toml`.
- Why it matters: Production splits remain hard to review when tests stay in catch-all files.
- Fix direction: Land test-only file moves one directory at a time before production refactors.
- Labels: refactor, tests, rust.
- Dedup note: Prior reports flagged individual test gaps; this is structural test layout.

### 30. `cold_path_hist.rs` should not be naively split

- Title: `cold_path_hist.rs` should not be naively split.
- Severity: Medium if split incorrectly.
- Confidence: High.
- Refactor class: D do-not-split.
- Evidence: `userspace-dp/src/afxdp/cold_path_hist.rs` is 1866 LOC but largest production functions are modest. The module intentionally keeps TSC sampling, slot maps, seqlock atomics, and `#[repr(C)]` worker counter layout together.
- Proposed decomposition: Only split tests or small debug helpers. Keep production layout, constants, and offset assertions together unless a dedicated design proves layout preservation.
- Hot-path preservation analysis: Sampling overhead and cacheline layout are the contract. Splitting could hide field order and seqlock invariants.
- Tests + gate: Existing cold-path tests, size/offset tests, perf sampling overhead check.
- Why it matters: This is a data-oriented module where locality and const assertions outweigh file-size aesthetics.
- Fix direction: File an issue that marks it as D-class, preventing drive-by "split because big" refactors.
- Labels: refactor, rust, do-not-split, x-hpc.
- Dedup note: This is a negative result, not a duplicate of binding-worker layout findings.

### 31. `frame/inspect.rs` parser locality should be preserved; only debug helpers are safe to peel out

- Title: `frame/inspect.rs` parser locality should be preserved; only debug helpers are safe to peel out.
- Severity: Medium if split incorrectly.
- Confidence: High.
- Refactor class: D do-not-split, with a small A-class optional debug split.
- Evidence: `userspace-dp/src/afxdp/frame/inspect.rs` is 1769 LOC, but it holds cohesive packet parser invariants: Ethernet/L3/L4 offsets, declared length bounds, fragment flowless behavior, ICMP pseudo-port, IPv6 extension header walk, and metadata fallback. `decode_frame_summary` is a debug string path and is the safer extraction seam.
- Proposed decomposition: Keep hot parser helpers together; optionally move `decode_frame_summary` to `frame/inspect/debug.rs`.
- Hot-path preservation analysis: Parser is hot. Avoid spreading endian/length invariants across modules unless codegen and tests prove no regression.
- Tests + gate: Frame inspect tests, TCP parser tests, cargo-asm/perf if any hot helper moves.
- Why it matters: Parser correctness is security-critical; over-splitting can make bounds checks less visible.
- Fix direction: Only extract debug summary path initially.
- Labels: refactor, rust, do-not-split, parser, hot-path.
- Dedup note: Prior inventory called this cohesive; this records the explicit D-class guardrail.

### 32. Cluster failover file is a lock-domain module and should mostly stay together

- Title: Cluster failover file is a lock-domain module and should mostly stay together.
- Severity: Medium if split incorrectly.
- Confidence: High.
- Refactor class: D do-not-split.
- Evidence: `pkg/cluster/failover.go` is 876 LOC. File comments document one manual-failover locking domain. It keeps manual failover, batch failover, transfer-commit override maps, grace windows, and heartbeat override helpers beside each other.
- Proposed decomposition: Only move pure formatting helpers if desired. Keep failover state, transfer commit, and heartbeat override logic co-located.
- Hot-path preservation analysis: Heartbeat handling calls locked override helpers. Splitting could obscure `m.mu` ownership or widen lock scope.
- Tests + gate: `go test ./pkg/cluster -run 'Failover|Transfer|Heartbeat|Fence'`; failover smoke.
- Why it matters: The coupling is real and intentional; a mechanical split here could reduce correctness.
- Fix direction: Add an engineering-style note or issue marking this as D-class.
- Labels: refactor, go, ha, do-not-split.
- Dedup note: Distinct from prior `sync_conn.go` HA sync state-machine findings.

## Suggested Issue Split

1. Rust AF_XDP hot-path split campaign: worker loop, poll descriptor, poll stages, forwarding, with assembly/perf gates.
2. Rust CoS queue-service module split with cargo-asm and shaped-traffic smoke gates.
3. Rust NAT64 module split: state, headers, translation, ICMP, checksum, frame.
4. Rust policy/screen/WG split: policy cold parser, screen extractor, WG engine hot/cold, WG cookie module.
5. Rust server/protocol/status split: server status refresh, protocol status DTOs, event emitters, giant test files.
6. Go userspace control-plane split: protocol DTOs, map/status sync, eventstream, manager facade.
7. Go daemon/cluster split: apply pipeline, HA comms startup, sync protocol codec, with cluster failover marked D-class.
8. Go config compiler split: warning validators, system, services, CoS, firewall, schema walker, apply-groups.
9. Operator/API surface split: metrics descriptors, userspace metrics emitters, show-text registry, sessionview shared package, CLI interface display.
10. Control service split: DHCP client modules, VRRP same-package split, DDNS Surface A engine split.
11. D-class guardrail issues: cold-path histogram, frame inspect hot parser locality, cluster failover lock-domain module.

## Validation Notes

- Main checkout was rebased with `git pull --rebase`; base is `34f1c7eccc509ee844d62b01aebae556fba41c41`.
- Main worktree was clean after the audit.
- One subagent ran `go test ./pkg/config ./pkg/policymatch` successfully during its read-only slice.
- No repository source files were modified for this audit.
