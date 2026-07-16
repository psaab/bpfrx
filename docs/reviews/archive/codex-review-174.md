# Codex refactor audit 174

Base: `/home/ps/git/codex-bpfrx` on `master` at `e87d57e2d55784482c8285112d5cd941fc5a2df5`.

I ran `git pull --rebase` first. It fast-forwarded from `6c9d1dd0bfe3` to `e87d57e2d557`.

Scope: `../do-review-refactor-audit.txt`. This is a monolithic-code/refactor-debt audit only. I did not edit repo source files and did not call `gh`. The report below suppresses duplicates against prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, `/tmp/fable-review*.md`, and `/tmp/opus-review*.md`.

## Module checklist

- Rust AF_XDP hot path: `poll_descriptor`, `poll_stages`, `frame`, `tx/dispatch`, `worker`, `umem`, CoS queueing, WG frame path.
- Rust control and observability: `event_stream`, `slowpath`, `neighbor`, `neighbor_dispatch`, `cold_path_hist`.
- Rust policy/session/NAT/filter/screen: `policy`, `session`, `nat`, `filter`, `screen`.
- Go userspace dataplane control: `pkg/dataplane/userspace`, especially post-split `manager`, `format`, `maps_sync`, process/policy/NAT/zone split files.
- Go CLI/API/gRPC surfaces: local CLI, remote CLI, REST show/session APIs, gRPC diagnostics/session APIs.
- Go daemon/services: `pkg/daemon`, `pkg/routing`, `pkg/frr`, `pkg/vrrp`, `pkg/dhcp`, `pkg/dhcprelay`, `pkg/ddns`, `pkg/snmp`.
- Go config/control plane: post-split `pkg/config`, `pkg/configstore`, command tree, schema validators.

## Duplicate and closed items suppressed

- The old `pkg/config/compiler.go` phase-monolith finding is closed on master. The compiler now delegates through `runPreWalkGates`, `compileSections`, `resolveDerivedConfig`, `runEarlyStrictAndFolds`, `runUniformGates`, and `runTailGates`.
- The old `schema_validators.go` monolith is closed. Domain validator files now exist and `schema_walk.go` is cohesive.
- The old userspace `process.go`, `policies.go`, `nat.go`, and `zones.go` monoliths are largely closed by the recent splits.
- I did not re-file the broad `poll_descriptor/mod.rs`, `forwarding/mod.rs`, `policy.rs`, `session/mod.rs`, `compiler_validate_warn.go`, `protocol.go`, `maps_sync.go`, `manager_ha.go`, `event_emit.rs`, `pkg/frr/policy_render.go`, `pkg/snmp/agent.go`, `pkg/dhcprelay/relay.go`, `pkg/routing/tunnel.go`, API session surfaces, or broad giant-test-file findings where prior reports already gave equivalent decomposition plans.

## High-confidence findings

### 1. `event_stream/codec.rs` is a wire-format monolith mixing HA sync, RT_FLOW telemetry, constants, encode, and decode

- Severity (maintainability + build-cost + review-cost impact): Medium. A wire-field change forces review of unrelated frame families.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): B requires-guardrails.
- Evidence: `userspace-dp/src/event_stream/codec.rs` is 1,165 LOC. Constants start at `:15`, `DataplaneEventKind` at `:156`, `EventFrame` encoders at `:263`, RT_FLOW close encoding at `:565`, generic decode at `:1042`.
- Proposed decomposition: `event_stream/codec/wire.rs` for constants/header/address helpers, `codec/session_sync.rs` for session open/close/update frames, `codec/rt_flow.rs` for RT_FLOW and security telemetry frames, `codec/decode.rs` for decoders. Keep `codec.rs` as a re-export shell.
- Hot-path preservation analysis: Preserve stack `[u8; 256]`, byte offsets, endian writes, and monomorphic functions. No `Vec`, trait objects, or boxed frame builders. Mark tiny moved helpers `#[inline]` where current codegen depends on it.
- Tests + gate: Move paired codec tests and run `cargo test -p xpf-userspace-dp event_stream::codec`.
- Why it matters: This is a wire contract file; HA session sync and telemetry should not collide in one review surface.
- Fix direction: Move constants/helpers first, then session-sync encoders, then RT_FLOW encoders, then decoder/tests.
- Labels: `refactor`, `event-stream`, `wire-format`, `hot-path`, `x-hpc`.
- Dedup note: Prior reports covered event-stream I/O and correctness; I did not find this codec-family split.

### 2. `event_stream/codec_tests.rs` should split with codec frame families

- Severity (maintainability + build-cost + review-cost impact): Low-medium. 995 LOC of byte-layout tests mix constants, RT_FLOW, HA sync frames, generic dataplane events, and flag encoding.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `codec_tests.rs:240` pins frame type constants, `:260` RT_FLOW close, `:499` session-create RT_FLOW, `:614` HA session-open wire, `:927` header-only frames.
- Proposed decomposition: `codec_tests/{constants.rs,session_sync.rs,rt_flow.rs,dataplane_event.rs}` matching the production codec split.
- Hot-path preservation analysis: Test-only. Keep byte-offset assertions byte-for-byte.
- Tests + gate: `cargo test -p xpf-userspace-dp event_stream::codec`.
- Why it matters: The codec split needs tests colocated with the frame family they protect.
- Fix direction: Land after or alongside finding 1.
- Labels: `refactor`, `tests`, `event-stream`, `wire-format`.
- Dedup note: Prior codec notes were correctness oriented, not test-module decomposition.

### 3. `event_stream/tests.rs` is a 2,313-line integration-test dumping ground

- Severity (maintainability + build-cost + review-cost impact): Medium. One control-frame regression requires scanning 52 tests across unrelated stream behavior.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: RT_FLOW tests at `userspace-dp/src/event_stream/tests.rs:121`, replay/budget at `:650`, ACK parsing at `:1490`, drain fence at `:1765`, stuck-reader backpressure at `:1908`, pause/control payloads at `:2083`.
- Proposed decomposition: `event_stream/tests/{rt_flow.rs,replay_budget.rs,control_frames.rs,drain.rs,backpressure.rs,helpers.rs}`.
- Hot-path preservation analysis: Test-only; no production codegen impact. Preserve helper visibility and identical control-frame fixtures.
- Tests + gate: `cargo test -p xpf-userspace-dp event_stream`.
- Why it matters: These tests pin lossless/session-sync invariants and should be feature-scoped.
- Fix direction: Move helpers first, then one cluster per PR.
- Labels: `refactor`, `tests`, `event-stream`.
- Dedup note: Prior broad event-stream findings did not include this test split.

### 4. `cos/queue_service/tests.rs` is a 4,384-line scheduler regression warehouse

- Severity (maintainability + build-cost + review-cost impact): Medium-high. It mixes 85 CoS scheduler tests.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: Guarantee/surplus selection at `userspace-dp/src/afxdp/cos/queue_service/tests.rs:24`, drain/equal-flow tests at `:1211`, waterfill at `:2415`, sojourn/submit at `:3234`, non-exact shared lease at `:3909`.
- Proposed decomposition: `queue_service/tests/{selector_guarantee.rs,waterfill.rs,drain_entry.rs,sojourn.rs,submit_accounting.rs,scratch_recycle.rs,shared_nonexact.rs}`.
- Hot-path preservation analysis: Test-only. Do not touch `queue_service/mod.rs` hot selectors or introduce production helpers for test convenience.
- Tests + gate: `cargo test -p xpf-userspace-dp cos::queue_service`.
- Why it matters: CoS scheduler regressions are latency-sensitive; each invariant needs a small home.
- Fix direction: Introduce the `tests/` submodule and move waterfill, submit/accounting, selector/drain clusters separately.
- Labels: `refactor`, `tests`, `cos`, `hot-path`, `x-hpc`.
- Dedup note: Prior reports covered production CoS queues, not this test-module split.

### 5. `cos/queue_ops` tests are split by file size, not scheduler invariant

- Severity (maintainability + build-cost + review-cost impact): Medium. 5,801 LOC across three files still mixes MQFQ, V_min, promotion, benches, cap-aware selection, and rollback.
- Confidence: Medium-high.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `pop_tests.rs` is 2,060 LOC, MQFQ golden vector at `:280`, rollback at `:1472`; `v_min_tests.rs` is 1,992 LOC, V_min publish at `:33`, hard cap at `:644`, rejoiner at `:1814`; `tests.rs` is 1,749 LOC, bench at `:934`, promotion at `:1310`, cap-aware selector at `:1586`.
- Proposed decomposition: `queue_ops/tests/{mqfq_order.rs,mqfq_rollback.rs,v_min_publish.rs,v_min_hardcap.rs,v_min_rejoin.rs,best_effort_promotion.rs,cap_aware.rs,benches.rs}`.
- Hot-path preservation analysis: Test-only. Keep production `queue_ops` untouched and do not add trait indirection.
- Tests + gate: `cargo test -p xpf-userspace-dp cos::queue_ops`.
- Why it matters: These tests guard MQFQ/V_min fairness and tail-latency behavior.
- Fix direction: Move by invariant, preserve test count and names where practical.
- Labels: `refactor`, `tests`, `cos`, `mqfq`, `x-hpc`.
- Dedup note: Not a duplicate of production CoS split findings.

### 6. `umem/tests.rs` mixes redirect inbox, latency histograms, cacheline layout, V_min scratch flush, and active-flow debug state

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: 1,765 LOC. Redirect inbox at `userspace-dp/src/afxdp/umem/tests.rs:35`, latency buckets at `:125`, cacheline isolation at `:359`, TX kick latency at `:987`, V_min scratch flush at `:1337`, active-flow debug fixtures at `:1498`.
- Proposed decomposition: `umem/tests/{redirect_inbox.rs,owner_profile.rs,latency_hist.rs,tx_kick.rs,v_min_flush.rs,debug_state.rs}`.
- Hot-path preservation analysis: Test-only, but preserve layout assertions exactly. Do not split `BindingLiveState` storage as part of this work.
- Tests + gate: `cargo test -p xpf-userspace-dp afxdp::umem`.
- Why it matters: UMEM layout and latency counters are sensitive; scoped tests make future layout changes reviewable.
- Fix direction: Move cacheline/layout and latency tests first, then debug-state fixtures.
- Labels: `refactor`, `tests`, `umem`, `x-hpc`.
- Dedup note: Prior reports warned not to split UMEM hot storage; this is only test organization.

### 7. TCP segmentation should split by phase, not by forwarding policy

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: Medium-high.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): B requires-guardrails.
- Evidence: `userspace-dp/src/afxdp/frame/tcp_segmentation.rs` is 933 LOC. `segment_forwarded_tcp_frames_from_frame` starts at `:12` and combines MTU/tunnel admission, parsing, segment allocation, IPv4/IPv6 checksum/NAT handling, and tunnel encapsulation; tests start at `:354`.
- Proposed decomposition: Keep one public entrypoint; extract private same-crate helpers for admission/context parsing, IPv4 emission, IPv6 emission, and final tunnel encapsulation. Move tests to `tcp_segmentation/tests.rs`.
- Hot-path preservation analysis: Over-MSS segmentation is packet-path code. Preserve allocation count, avoid traits/dynamic dispatch, keep helpers private and inline-friendly, and do not add packet copies.
- Tests + gate: `cargo test -p xpf-userspace-dp afxdp::frame::tcp_segmentation`; add checksum/NAT/tunnel-mode equivalence and allocation/copy checks.
- Why it matters: Checksum, tunnel, and MTU fixes are hard to review independently in the current function.
- Fix direction: Extract pure context/admission helpers first, then IPv4/IPv6 segment emission, then tests.
- Labels: `refactor`, `frame`, `tcp-segmentation`, `hot-path`, `x-hpc`.
- Dedup note: Prior reports covered concrete checksum/WG issues, not this phase split.

### 8. Do not split WG production encapsulation; move only the test bulk

- Severity (maintainability + build-cost + review-cost impact): Low-medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): D do-not-split for production, A mechanical for tests.
- Evidence: `userspace-dp/src/afxdp/frame/wg.rs` is 1,561 LOC, but production is roughly `:1-603` and tests start at `:605`. `wg_encap_frame` starts at `:305`; underlay resolution helpers are adjacent.
- Proposed decomposition: Move tests to `frame/wg_tests.rs` and optional fixtures to `frame/wg_test_support.rs`; leave production encap intact unless a future change passes a pre-resolved underlay context.
- Hot-path preservation analysis: Production split risks hiding the single-underlay-lookup invariant and inviting duplicate FIB lookups. Test extraction has no codegen impact.
- Tests + gate: WG frame tests, especially the single outer route resolve canary.
- Why it matters: The file looks large because of tests; splitting the wrong part would make a sensitive encapsulation path riskier.
- Fix direction: Extract tests only.
- Labels: `refactor`, `frame`, `wireguard`, `do-not-split`, `hot-path`, `x-hpc`.
- Dedup note: Prior WG findings covered duplicate-underlay correctness; this is a structural guardrail.

### 9. `reject_reply.rs` hides cold production reply code behind a 1,700+ LOC test tail

- Severity (maintainability + build-cost + review-cost impact): Low-medium.
- Confidence: Medium-high.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` is 2,174 LOC. Production helpers occupy roughly `:36-413`; tests start at `:416`. Cold entrypoints include `enqueue_policy_reject_reply`, `enqueue_filter_reject_reply`, `enqueue_deny_reply`, `deny_reply_and_emit`, and `enqueue_reject_reply`.
- Proposed decomposition: Move tests to `poll_descriptor/reject_reply_tests.rs` and optional `reject_reply_test_support.rs`; leave production synthesis in place.
- Hot-path preservation analysis: Test-only extraction. If production moves later, preserve `#[cold] #[inline(never)]` and avoid importing reject helpers into hot forwarding modules.
- Tests + gate: Reject-reply, policy-reject, filter-reject, VLAN/logical-ifindex, budget, and counter tests.
- Why it matters: The current file size masks the fact that production code is small and cold.
- Fix direction: Mechanical test-module extraction first.
- Labels: `refactor`, `tests`, `poll-descriptor`, `reject-reply`, `hot-path-safe`.
- Dedup note: Prior reports covered reject behavior bugs, not this extraction.

### 10. `pkg/cli/cli_request.go` is a request/diagnostic command grab bag

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: 1,328 LOC. Ping starts at `pkg/cli/cli_request.go:23`, policy test at `:174`, monitor traffic at `:700`, chassis failover at `:803`, system actions at `:1047`, WireGuard keygen at `:1315`.
- Proposed decomposition: `cli_diag.go`, `cli_test_policy.go`, `cli_monitor_traffic.go`, `cli_request_chassis.go`, `cli_request_system.go`, `cli_request_security.go`, `cli_request_protocols.go`, `cli_request_dhcp.go`.
- Hot-path preservation analysis: CLI cold path. Preserve argv construction exactly for `diagcmd` and `tcpdump`; no dataplane effect.
- Tests + gate: `go test ./pkg/cli`, plus targeted request/monitor/test-policy tests.
- Why it matters: Maintenance verbs, diagnostics, and simulators currently conflict in one file.
- Fix direction: Move pure helpers first, then handlers by command family.
- Labels: `refactor`, `cli`, `cold-path`.
- Dedup note: Prior findings covered specific parser bugs here; I found no file-level split finding.

### 11. `pkg/cli/cli_show_interfaces.go` fuses interface renderers, RETH logic, kernel probes, and VLAN/tunnel views

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: 1,396 LOC. Dispatch at `:62`, zone/logical maps at `:115-180`, RETH detail at `:698`, terse output at `:796`, extensive output at `:1108`, statistics at `:1297`, VLANs at `:1329`.
- Proposed decomposition: `cli_show_interfaces_dispatch.go`, `summary.go`, `detail.go`, `terse.go`, `reth.go`, `extensive.go`, `stats.go`, `tunnel.go`, plus shared RETH/kernel helpers.
- Hot-path preservation analysis: CLI cold path. Preserve netlink/sysfs query ordering and visible output.
- Tests + gate: `go test ./pkg/cli -run 'ShowInterfaces|Reth|Interface'`.
- Why it matters: RETH/member display logic is repeated across modes and drifts easily.
- Fix direction: Extract shared inventory/resolution helpers, then one renderer per PR.
- Labels: `refactor`, `cli`, `interfaces`, `cold-path`.
- Dedup note: Prior reports covered specific `show interfaces` bugs, not this structural split.

### 12. `pkg/cli/cli_show_services.go` mixes unrelated service presenters

- Severity (maintainability + build-cost + review-cost impact): Low-medium.
- Confidence: Medium-high.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: 868 LOC. CoS starts at `pkg/cli/cli_show_services.go:23`, `show services` dispatch at `:77`, DDNS at `:133`, DHCP relay at `:430`, DHCP server at `:510`, DHCP DDNS at `:621`, SNMP at `:696`, LLDP at `:776`, port mirroring at `:839`.
- Proposed decomposition: `cli_show_cos.go`, `cli_show_services_ddns.go`, `cli_show_dhcp.go`, `cli_show_snmp.go`, `cli_show_lldp.go`, `cli_show_port_mirroring.go`, `cli_show_rpm_ipmon.go`.
- Hot-path preservation analysis: CLI cold path; preserve output byte-for-byte where tests pin it.
- Tests + gate: `go test ./pkg/cli`.
- Why it matters: Service owners currently edit the same presenter bucket.
- Fix direction: Start with `show class-of-service`, then DHCP/SNMP/LLDP/DDNS presenters.
- Labels: `refactor`, `cli`, `show-command`, `cold-path`.
- Dedup note: Domain bugs were reported before; this mixed presenter split was not.

### 13. `FormatStatusSummary` mixes aggregation and rendering

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `pkg/dataplane/userspace/format/status.go` is 1,073 LOC. `FormatStatusSummary` starts at `:103` and runs through helper-heavy rendering before `FormatFairnessRSS` at `:713`.
- Proposed decomposition: Keep `FormatStatusSummary` public; extract status aggregate structs/builders and per-section renderers for generated replies, NAT/source pools, TX, slow path, workers, event stream.
- Hot-path preservation analysis: Control-plane formatting only. Preserve one pass over bindings, deterministic order, omit-zero behavior, and avoid extra status fetches.
- Tests + gate: `go test ./pkg/dataplane/userspace/format -run 'FormatStatusSummary|SYNCookie|FlowWorker|Bindings'`.
- Why it matters: Operator output and status aggregation change for different reasons and should not share a 600-line function body.
- Fix direction: Extract aggregation model first, then move renderers.
- Labels: `refactor`, `userspace-format`, `status`, `cold-path`.
- Dedup note: Prior status findings were correctness issues, not this split.

### 14. CoS formatter should split view-model construction from text rendering

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `pkg/dataplane/userspace/format/cos.go` is 865 LOC. `cosQueueView` starts at `:23` and carries many fields; `FormatCoSInterfaceSummary` at `:96` interleaves config joins, runtime joins, rendering, histograms, owner profiles, drain shaping, and waterfill output.
- Proposed decomposition: `cos_view.go` for interface/queue view construction and runtime indexing; `cos_render.go` for orchestration; focused render helpers for queues, histograms, and units.
- Hot-path preservation analysis: Formatting only. Preserve single view construction per interface and avoid repeated scans of runtime snapshots.
- Tests + gate: `go test ./pkg/dataplane/userspace/format -run 'FormatCoSInterfaceSummary|FormatSojournNS'`.
- Why it matters: This formatter sits on top of hot CoS telemetry; view construction and presentation should drift independently.
- Fix direction: Extract `cosRuntimeIndex` and queue view construction before moving render blocks.
- Labels: `refactor`, `userspace-format`, `cos`, `cold-path`.
- Dedup note: Prior CoS reports focused on scheduler/metrics, not Go formatter structure.

### 15. `manager_test.go` remains a 6,782-line userspace dataplane test dumping ground

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical, test-only.
- Evidence: `pkg/dataplane/userspace/manager_test.go` is 6,782 LOC and spans policy counters, helper IPC, HA/session sync, snapshots, NAT, routes, tunnels, CoS, counters, watchdogs, and process-adjacent behavior.
- Proposed decomposition: `manager_policycounters_test.go`, `manager_session_sync_test.go`, `manager_ha_test.go`, `manager_status_test.go`, `manager_snapshot_test.go`, `manager_maps_test.go`, `manager_process_test.go`, shared fixtures in `manager_test_helpers_test.go`.
- Hot-path preservation analysis: Test-only. Preserve root/eBPF gating and helper IPC setup.
- Tests + gate: Full `go test ./pkg/dataplane/userspace`.
- Why it matters: The production userspace manager was split, but the tests did not follow the module boundaries.
- Fix direction: Move shared fixtures first, then one subsystem test cluster per PR.
- Labels: `refactor`, `tests`, `userspace-dataplane`.
- Dedup note: Prior reports inventoried this size but did not give this subsystem split.

### 16. `pkg/grpcapi/server_diag.go` mixes diagnostics, streaming monitors, peer proxying, zeroize, and system actions

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: 1,602 LOC. Ping/traceroute at `pkg/grpcapi/server_diag.go:74`, packet-drop monitor at `:202`, interface monitor at `:459`, peer proxy at `:625`, zeroize helpers at `:819`, `SystemAction` at `:1176`.
- Proposed decomposition: Diagnostic command execution, packet-drop monitor, interface monitor, peer proxy helpers, zeroize helpers, and system-action dispatcher files.
- Hot-path preservation analysis: Operator RPC path. Preserve streaming cancellation, `WaitDelay`, pipe close behavior, subscription buffering, and peer-proxy recursion metadata.
- Tests + gate: gRPC diag, monitor, stream, zeroize, and system-action tests.
- Why it matters: Long-lived streams and destructive system actions should not be one review unit.
- Fix direction: Same-package extraction around RPC families; keep public RPC methods thin.
- Labels: `refactor`, `grpcapi`, `diagnostics`, `cold-path`.
- Dedup note: Prior reports covered specific `MonitorInterface`/zeroize bugs, not this split.

### 17. `pkg/daemon/daemon_ha_userspace.go` combines delta conversion, event-stream handling, queue draining, export, and failover readiness

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: Medium-high.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): B requires-guardrails.
- Evidence: 1,123 LOC. Conversion helpers start at `pkg/daemon/daemon_ha_userspace.go:98`, polling sync at `:494`, event-stream callbacks at `:570`, queue/drain at `:767`, export at `:898`, demotion/readiness at `:913`.
- Proposed decomposition: Conversion helpers, stream subscription/callback handling, queue/drain logic, export RPC assembly, failover readiness/barrier handling.
- Hot-path preservation analysis: HA control path can be high-rate under churn. Preserve delta slice behavior, ACK/withhold semantics, and current lock separation around `userspaceDeltaSyncMu` and demotion prep.
- Tests + gate: Daemon HA/userspace/session-event tests under race plus failover smoke.
- Why it matters: ACK semantics and failover barriers are hard to review while interleaved with wire conversion helpers.
- Fix direction: Pure same-package extraction with comments on ACK and demotion barrier invariants.
- Labels: `refactor`, `daemon`, `userspace-ha`, `locking`.
- Dedup note: Prior reports cover event-stream correctness; this is a module-boundary split.

### 18. Remote CLI `cmd/cli/show.go` is a 2,100-line umbrella for security, flow, NAT, interfaces, protocols, system, and text proxying

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: Medium-high.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `cmd/cli/show.go` dispatches at `:14`; services at `:340`, security at `:386`, zones at `:531`, policies at `:659`, flow sessions at `:943`, NAT at `:1120`, events at `:1557`, interfaces at `:1672`, protocols at `:1770`, system at `:1848`, text proxy at `:2043`.
- Proposed decomposition: `show/dispatch.go`, `show/security.go`, `show/flow.go`, `show/nat.go`, `show/interfaces.go`, `show/protocols.go`, `show/system.go`, `show/text.go`.
- Hot-path preservation analysis: Remote CLI cold path. Preserve gRPC request shapes and output formatting; no dataplane effect.
- Tests + gate: Remote CLI show tests plus gRPC show/session tests.
- Why it matters: Remote CLI has repeatedly drifted from local CLI behavior; feature-scoped files make parity reviews tractable.
- Fix direction: Move pure renderers by topic, then dispatch.
- Labels: `refactor`, `cli`, `grpc-cli`, `cold-path`.
- Dedup note: Prior reports covered specific parsers and output bugs in this file, not the umbrella split.

### 19. `tx/dispatch/dispatch_tests.rs` should split by TX failure/recycle/PTB/CoS invariant

- Severity (maintainability + build-cost + review-cost impact): Medium.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs` is 1,564 LOC. Segmentation tests start at `:155`, shared recycle at `:353`, enqueue failure at `:687`, PTB path at `:1085`, shared exact CoS at `:1321`.
- Proposed decomposition: `dispatch/tests/{segmentation.rs,shared_recycle.rs,enqueue_failure.rs,ptb.rs,cos_shared_exact.rs,helpers.rs}`.
- Hot-path preservation analysis: Test-only. Do not split `tx/dispatch/mod.rs` further as part of this; that production split is already tracked separately.
- Tests + gate: `cargo test -p xpf-userspace-dp afxdp::tx::dispatch`.
- Why it matters: TX dispatch regressions are packet-loss regressions; test clusters should name the invariant they protect.
- Fix direction: Move fixtures first, then one invariant cluster per PR.
- Labels: `refactor`, `tests`, `tx`, `hot-path`.
- Dedup note: Prior reports covered production `enqueue_pending_forwards`, not this test split.

## Medium-confidence findings

### 20. `format/buffers.go` mixes system buffer formatting, row construction, counter taxonomy, and compatibility fallback

- Severity (maintainability + build-cost + review-cost impact): Low-medium.
- Confidence: Medium.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): A mechanical.
- Evidence: `pkg/dataplane/userspace/format/buffers.go` is 773 LOC. Structured rows at `:137`, text formatting at `:181`, row builders at `:226`, CoS rows at `:365`, counter rows at `:407`, sample collection/fallback at `:541` and `:664`.
- Proposed decomposition: Buffer row builders, sample/fallback normalization, labels/counter taxonomy, and text rendering.
- Hot-path preservation analysis: Control-plane formatting. Preserve row order, zero suppression, and a single normalized sample set reused by structured and text paths.
- Tests + gate: `go test ./pkg/dataplane/userspace/format -run 'FormatSystemBuffers|StructuredSystemBufferRows'`.
- Why it matters: CLI/gRPC/REST buffer status already had parity bugs; a shared row model would reduce future drift.
- Fix direction: Extract sample normalization first, then structured rows, then text renderer.
- Labels: `refactor`, `userspace-format`, `buffers`, `cold-path`.
- Dedup note: Prior buffer findings were behavior/parity issues, not this formatter split.

### 21. `pkg/daemon/daemon_run.go` keeps boot, runtime wiring, and teardown in one lifecycle script

- Severity (maintainability + build-cost + review-cost impact): High.
- Confidence: Medium. Prior reports covered many daemon lifecycle bugs; this exact extraction plan still appears unfiled, but it is adjacent to known daemon debt.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): B requires-guardrails.
- Evidence: `pkg/daemon/daemon_run.go` is 2,329 LOC. `Run` starts at `:175` and spans roughly to `:1859`, wiring config load, subsystem construction, API/gRPC/CLI start, event loops, HA/runtime startup, and shutdown ordering.
- Proposed decomposition: Startup phases, control-surface wiring, subsystem constructors, and shutdown orchestration in same-package files; keep `Run` as a short ordered lifecycle script.
- Hot-path preservation analysis: Cold path but ordering-sensitive. Preserve resolver/setup before compile, naming before dataplane, callbacks before probes, apply cancellation before teardown, and HA/session/VRRP shutdown order.
- Tests + gate: Daemon lifecycle tests plus cluster/deploy startup/shutdown smoke.
- Why it matters: The function is too large to review ordering changes safely.
- Fix direction: Mechanical extraction first with phase-boundary comments, no behavior changes.
- Labels: `refactor`, `daemon`, `lifecycle`, `class-B`.
- Dedup note: Suppress if an existing issue was opened from older daemon lifecycle reports; otherwise this is the remaining file-level lifecycle split.

## Explicit refactor negatives

### A. Do not naively split `screen/scan.rs`

- Severity (maintainability + build-cost + review-cost impact): Low.
- Confidence: High.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): D do-not-split.
- Evidence: `userspace-dp/src/screen/scan.rs` is 1,213 LOC, but constants, bounded eviction, `ScanCore<T>`, `check`, cleanup, and tests share one invariant: bounded attacker-influenced scan work.
- Proposed decomposition: Do not split production scan core. If churn grows, move tests only.
- Hot-path preservation analysis: Scan checks run on attacker-influenced flowless/session-miss paths; abstraction could obscure bounded-work costs.
- Tests + gate: Existing scan bounded eviction, cleanup, decoy flood, and exact-count behavior tests.
- Why it matters: LOC alone is misleading here.
- Fix direction: Leave production structure intact.
- Labels: `refactor`, `screen`, `do-not-split`, `hot-path`.
- Dedup note: Prior screen findings cover correctness; this is a negative.

### B. Do not split `neighbor.rs::trigger_kernel_arp_probe` into abstract per-family/socket traits

- Severity (maintainability + build-cost + review-cost impact): Low maintainability gain, medium operational risk.
- Confidence: Medium.
- Refactor class (A mechanical / B requires-guardrails / C performance-positive / D do-not-split): D do-not-split.
- Evidence: `userspace-dp/src/afxdp/neighbor.rs:158` couples CAP_NET_RAW fallback, `SO_BINDTODEVICE`, IPv6 checksum setup, link-local `sin6_scope_id`, `sendto`, rare error logging, and fd close.
- Proposed decomposition: If `neighbor.rs` becomes a directory, move this helper whole to `neighbor/probe.rs`; do not split into trait objects or shell-command probes.
- Hot-path preservation analysis: Warm/cold path affects MissingNeighbor recovery latency. Avoid heap allocation, dynamic dispatch, and extra syscall wrappers.
- Tests + gate: Neighbor probe tests plus live MissingNeighbor recovery.
- Why it matters: The exact syscall/fallback sequence is the invariant.
- Fix direction: Move whole helper only as part of the already-known neighbor directory split.
- Labels: `refactor`, `neighbor`, `do-not-split`.
- Dedup note: Prior findings cover broad `neighbor.rs`; this is a narrower guardrail.

## Quota result

New non-duplicate findings reported: 21.

Not counted as new because they are duplicates or closed: old compiler phase split, schema validator split, old userspace `process/policies/nat/zones` monoliths, broad `poll_descriptor`, `forwarding`, `policy`, `session`, `maps_sync`, `manager_ha`, `frr/policy_render`, `snmp/agent`, `dhcprelay/relay`, broad `routing/tunnel`, and broad API session surface splits.
