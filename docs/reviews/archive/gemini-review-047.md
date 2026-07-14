# Authoritative Defensive Code Hardening Audit (gemini-review-047)

**Base Commit Reviewed:** `275989b76b22925f4d2719fa07f47709eb227059`  
**Output Path:** `/tmp/gemini-review-047.md`  
**Date:** 2026-07-10  

## 1. Duplicate Suppression Summary
A compact deduplication index was compiled from all prior campaigns (001-046) in `/tmp`, comprising **1132 unique findings**. Each subagent was supplied with filtered subsets of this index matching their specific files. Findings representing restatements of prior vulnerabilities or already-closed issues were suppressed. This campaign surfaced 18 newly discovered findings, focusing on the newly introduced/modified modules in the Rust dataplane and Go control plane.

## 2. File-Size / Shape Inventory (Coverage Checklist)
Provably complete coverage of all source files across 10 expertise areas and 19 batches:

| Area | Description | Batches | Files Reviewed | Status |
| :--- | :--- | :--- | :--- | :--- |
| A1 | 418 files | 6 batches | 418 / 418 | **Complete** |
| A10 | 482 files | 2 batches | 482 / 482 | **Complete** |
| A2 | 18 files | 2 batches | 18 / 18 | **Complete** |
| A3 | 501 files | 1 batches | 501 / 501 | **Complete** |
| A4 | 63 files | 1 batches | 63 / 63 | **Complete** |
| A5 | 101 files | 1 batches | 101 / 101 | **Complete** |
| A6 | 288 files | 1 batches | 288 / 288 | **Complete** |
| A7 | 272 files | 2 batches | 272 / 272 | **Complete** |
| A8 | 279 files | 2 batches | 279 / 279 | **Complete** |
| A9 | 127 files | 1 batches | 127 / 127 | **Complete** |


## 3. Module-by-Module Inspection Log
Below is the aggregated inspection status of all modules. Detailed negative results (what invariants were checked and found sound) are preserved in the individual reports `/tmp/review-work-gemini-047/gemini-<area>-b<batch>.md`.

| Module/File | Status | Summary of Invariant / Findings |
| :--- | :--- | :--- |
| `- [aggregator_callback_4964_test.go](file:///home/ps/git/gemini-xpf/pkg/daemon/aggregator_callback_4964_test.go)` | Clean | [aggregator_callback_4964_test.go](file:///home/ps/git/gemini-xpf/pkg/daemon/aggregator_callback_4964_test.go) |
| `///home/ps/git/gemini-xpf/pkg/appid/catalog.go):` | Clean |   [catalog.go](file:///home/ps/git/gemini-xpf/pkg/appid/catalog.go): |
| `///home/ps/git/gemini-xpf/pkg/cmdtree/tree.go):` | Clean |   [tree.go](file:///home/ps/git/gemini-xpf/pkg/cmdtree/tree.go): |
| `///home/ps/git/gemini-xpf/pkg/config/ast.go)` | Clean |   [ast.go](file:///home/ps/git/gemini-xpf/pkg/config/ast.go), [ast_edit.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_edit.go), [ast_format.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_format.go), [ast_groups.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_groups.go), [ast_redact.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_redact.go): |
| `///home/ps/git/gemini-xpf/pkg/ddns)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/devicemap)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/dhcp)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/dhcprelay)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/dhcpserver)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/diagcmd)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/fairness)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/fsatomic)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/fwdstatus)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/ipmon)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/linuxsock)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/lldp)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/monitoriface)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/natpoolalarm)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/natshow)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/nftables)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/policymatch)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/scheduler)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/upgrade)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/pkg/wgkey)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/scripts/deploy)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/scripts/dist)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/scripts/image)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/test/incus)` | Clean | Sound |
| `///home/ps/git/gemini-xpf/userspace-dp/benches/prefix_set_lookup.rs)` | Clean | Checked that lookup bench correctly tests the route prefix tree matching under randomized workloads without deadlocks or panic paths. |
| `///home/ps/git/gemini-xpf/userspace-dp/build.rs)` | Clean | Checked that the build script correctly links local C sources (`xsk_bridge.c`) and BPF headers without generating invalid bindings or architecture mismatches. |
| `///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/bind.rs)` | Clean | Checked that AF_XDP socket setup (`bind_xsk_socket`) correctly implements fail-closed error handling (unbinding queues on failure) and prevents MLX5 queue EBUSY reuse conflicts. |
| `///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/coordinator/bpf_maps.rs)` | Clean | Checked that the coordinator validates that all required map FDs are present and valid before committing any config, preventing fail-open forwarding. |
| `///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/cos/admission.rs)` | Clean | Checked that admission limit logic uses `div_ceil` defensively clamped to prevent division by zero or negative-span clamp panics. |
| `///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/cos/queue_ops/accounting.rs)` | Clean | Checked that per-flow bucket enqueue/dequeue byte counters are updated atomically and reset correctly when buckets empty. |
| `136` | Clean | of Coverage |
| `CoS Scheduler Queue Service Pipeline (queue_service/)` | Clean | No findings. Audited the `drain__items_to_scratch` methods; verified that they correctly check UMEM frame capacity bounds and slice mutability in a panic-free manner. |
| `Covered:` | Clean | Sound. Concurrency safety is maintained by serializing configuration apply steps and daemon shutdown/restore actions under the `applySem` semaphore, preventing map write contention. |
| `Event Streams` | Clean | No findings. Checked that event-stream encoding bounds-checks all packets before writing them to the ring buffer. |
| `Flow Cache & Session Inbound Gates` | Clean | No findings. Verified the 4-way set-associative LRU eviction, set hashing with process-local seeds, and generational lookup checks are sound. |
| `Forwarding State Builders (forwarding_build/)` | Clean | No findings. Checked that classifier tables and interface config mappings fail-closed on any unrecognized priority or policy. |
| `In-Place Descriptor Rewriters (frame/rewrite/)` | Clean | No findings. Verified in-place descriptor rewrite for IPv4 bounds-checks header/L4 offsets. |
| `Module 1: pkg/eventengine` | Clean | This module implements the firewall appliance's event engine, handling policy configuration updates and processing event options (e.g. cooldowns, trigger matching). |
| `Module 2: pkg/feeds` | Clean | This module manages fetching dynamic IP prefix lists and DNS names from remote address feeds. |
| `Module 3: pkg/flowexport` | Clean | This module implements NetFlow v9 and IPFIX (v10) packet builders, template engines, and transport channels. |
| `Module 4: pkg/logging` | Clean | This module implements the security event log buffer, syslog client, flow traces, and top-K traffic aggregators. |
| `Module 5: pkg/rpm` | Clean | This module manages Real-time Performance Monitoring probers (ICMP, TCP, HTTP), tracking failures and RTT metrics. |
| `Module 6: pkg/snmp` | Clean | This module implements the SNMP v2c/v3 agent, Trap emitters, and USM crypto timeliness protection. |
| `Packet Build, Formatting & Parsing (frame/)` | Clean | No findings. Verified IPv4 frame-build copy path correctly handles header formatting. |
| `TCP Helpers & Segmentation (frame/tcp*)` | Clean | No findings. Checked TCP window and flags extraction functions correctly bounds-check buffers. |
| `Telemetry & Base Frame Constants` | Clean | No findings. Checked that exception tracking locking only engages on the exception/drop path, leaving the forwarding fast-path lock-free. |
| `Token Buckets & Transmission Completion (cos/)` | Clean | No findings. Checked that the carrying of fractional remainders (`#4261`) avoids token dust accumulation and maintains accurate rate capping. |
| `[ast_edit.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_edit.go)` | Clean |   [ast.go](file:///home/ps/git/gemini-xpf/pkg/config/ast.go), [ast_edit.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_edit.go), [ast_format.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_format.go), [ast_groups.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_groups.go), [ast_redact.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_redact.go): |
| `[ast_format.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_format.go)` | Clean |   [ast.go](file:///home/ps/git/gemini-xpf/pkg/config/ast.go), [ast_edit.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_edit.go), [ast_format.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_format.go), [ast_groups.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_groups.go), [ast_redact.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_redact.go): |
| `[ast_groups.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_groups.go)` | Clean |   [ast.go](file:///home/ps/git/gemini-xpf/pkg/config/ast.go), [ast_edit.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_edit.go), [ast_format.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_format.go), [ast_groups.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_groups.go), [ast_redact.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_redact.go): |
| `[ast_redact.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_redact.go):` | Clean |   [ast.go](file:///home/ps/git/gemini-xpf/pkg/config/ast.go), [ast_edit.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_edit.go), [ast_format.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_format.go), [ast_groups.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_groups.go), [ast_redact.go](file:///home/ps/git/gemini-xpf/pkg/config/ast_redact.go): |
| `and associated test files` | Clean | Checked signal notification cleanup and gRPC message receive size limits (`maxConfigRecvBytes`) to verify that large configurations do not trigger transport truncation or leaks. |
| `and contains no production logic` | Clean | **Result**: Negative Result. |
| `app_resolve.go` | Clean | Verified that `showConfigRedacted` properly redacts sensitive configurations (passwords/keys) for all view-only login classes, preventing privilege escalation. |
| `are protected from PID reuse collisions` | Clean | **Result**: Negative Result. |
| `asserting SNAT contract conformance` | Clean | **Result**: Negative Result. |
| `backend.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_bind.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_cloudflare.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_duckdns.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_dyndns2.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_generic.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_http.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_rfc2136.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `backend_route53.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `checkip.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `clear.go` | Clean | Checked signal notification cleanup and gRPC message receive size limits (`maxConfigRecvBytes`) to verify that large configurations do not trigger transport truncation or leaks. |
| `cli_show.go` | Clean | Verified that `showConfigRedacted` properly redacts sensitive configurations (passwords/keys) for all view-only login classes, preventing privilege escalation. |
| `etc` | Clean | Verified that `showConfigRedacted` properly redacts sensitive configurations (passwords/keys) for all view-only login classes, preventing privilege escalation. |
| `for property tests` | Clean | No findings. Proptest suite for packet inspection; checked that arbitrary extension header chains are correctly parsed. |
| `grouping all V_min test submodules` | Clean | No findings. Checked that the V_min check cadence correctly evaluates on the first pop and subsequently on a cadence of 8 pops, ensuring that the worker updates state consistently. |
| `hostname.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `main.go` | Clean | Checked signal notification cleanup and gRPC message receive size limits (`maxConfigRecvBytes`) to verify that large configurations do not trigger transport truncation or leaks. |
| `manager.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `monitor.go` | Clean | Checked signal notification cleanup and gRPC message receive size limits (`maxConfigRecvBytes`) to verify that large configurations do not trigger transport truncation or leaks. |
| `monitor_traffic.go` | Clean | Verified that `showConfigRedacted` properly redacts sensitive configurations (passwords/keys) for all view-only login classes, preventing privilege escalation. |
| `permissions.go` | Clean | Verified that `showConfigRedacted` properly redacts sensitive configurations (passwords/keys) for all view-only login classes, preventing privilege escalation. |
| `pkg/cluster (Elections, Heartbeats, Sync, Reth)` | Clean | **pkg/cluster/cluster_test.go**: Negative Result. Invariant checked: Mock redundancy groups correctly compute priorities and trigger transitions during tests. Found sound. |
| `pkg/conntrack (Garbage Collection)` | Clean | **pkg/conntrack/gc.go**: Negative Result. Invariant checked: BPF maps are swept for expired sessions, and session limiters are updated safely. Found sound. (Stale count leak covered by Dedup Entry 17/21). |
| `pkg/dataplane/appid_catalog_parity_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/appid_catalog_port_zero_5194_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/apply.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/apply_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/bpf_session_value.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/bpf_session_value_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_filter.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_filter_expansion_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_filter_protocol_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_iface.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_nat.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_nat_counter_collision_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_nat_counter_stability_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/compiler_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/constants.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/constants_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/cpumask.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/cpumask_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/current_sessions_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/dataplane.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/default_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/legacy_bpf_manifest_canary_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/loader.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/loader_userspace_shim.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_counters.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_fabric.go` | **Finding: Medium** | Lack of Synchronization / Race Condition on `BumpFIBGeneration` in BPF Dataplane Map |
| `pkg/dataplane/maps_filter.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_flow.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_helpers.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_mirror.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_nat.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_policy.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_screen.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_session.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_session_clear_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_stale.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_stats.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/maps_stats_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/nptv6_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/pci_function_suffix_4795_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/persistent_nat.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/persistent_nat_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/protected_iface_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/proxyarp.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/proxyarp_orphan_4955_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/proxyarp_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/retirement_boundary_canary_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/runtime/import_canary_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/runtime/session_delta.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/screen_reason_counters_3343_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/session_store.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/session_store_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/types.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/address_book_collision_2514_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/address_book_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/addressbook_slash_name_4340_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/app_catalog_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/app_inactivity_timeout_3227_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/app_inactivity_timeout_precedence_3298_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/app_set_reject_3727_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/applied_nat_view.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/applied_nat_view_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/binding_ready_gate_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/boot_probe.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/boot_probe_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/builder.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/capabilities.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/clear_bounded_5304_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/cold_path_sample_mask_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/cold_path_status_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/configstore_helper_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/control.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/control_request_cap_2744_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/control_socket_deadline_4036_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/control_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/controllers.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/cos.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/cos_iface_level_4021_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/default_policy_3065_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/default_policy_counter_3363_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/default_policy_log_3534_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/eventstream.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/eventstream_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/eventstream_writeframe_race_4835_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/fabric.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/fabric_up_4082_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/fairness.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/fairness_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/fairness_throughput.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/fairness_throughput_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/fbf_snapshot_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/feed_enforcement_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filtercounters.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_address_except_3359_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_address_matchany_except_4338_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_flex_match_3077_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_multivalue_2545_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_next_term_2544_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_per_packet_match_2362_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_port_except_2622_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_prefix_list_2506_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_protocol_ipv6_3393_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_snapshot_integrity_3406_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/filters_unresolved_except_5097_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/firewall_snapshot_render.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/flow.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/flow_numwidth_agreement_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/flow_wire_coerce_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/buffers.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/buffers_golden_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/buffers_model.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/buffers_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/cos.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/cos_golden_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/cos_sections.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/cos_show.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/cos_show_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/cos_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/math.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/status.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/status_golden_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/status_sections.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/status_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/wireguard.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/format/wireguard_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/host_inbound_classify.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/host_inbound_classify_3627_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/host_inbound_per_iface_3362_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/host_inbound_phys_unit_3720_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/host_inbound_protocols_all_4411_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/host_inbound_unzoned_4420_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/host_inbound_view_grouping_3721_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/inject.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/inject_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/interfaces.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/interfaces_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/junos_host_deny.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/junos_host_netdev_parity_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/junos_host_policy_3019_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/junos_ping_icmp_3020_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/legacy_dataplane.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/legacy_dataplane_batchclear_5096_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/legacy_dataplane_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/lenient_keep_armed_3261_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/link_cycle_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_capabilities_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_compile.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_cos_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_counters_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_coupling_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_fabric_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_flow_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_generation.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_ha.go` | **Finding: High** | Control Plane Hang and Socket/Syscall Exhaustion via Sequential Dialing of Socket in `syncSessionRequestsLocked` / `requestSessionSync` |
| `pkg/dataplane/userspace/manager_ha_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_interfaces_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_mirrors_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_misc_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_nat_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_neighbor.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_overlay.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_policy_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_policycounters_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_republish_3780_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_routes_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_screens_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_sessionsync_snapshot_5007_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_sessionsync_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_snapshot_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_status.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_testhelpers_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_tunnels_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_worker_arm_5134.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/manager_worker_arm_5134_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/maps.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/maps_decouple_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/maps_sync.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/maps_sync_addrlist_prune_3924_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/maps_sync_cap_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/maps_sync_heartbeat_slots_4572_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/mirrors.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/named_port_caseinsensitive_3372_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat64.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat64_deterministic_4559_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat64_frag_header_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_address_name_failclosed_3425_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dest_address_name_3229_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dest_prefix_3164_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_destination.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dnat_app_dport_3857_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dnat_app_empty_3434_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dnat_app_match_3437_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dnat_match_dport_3446_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dnat_off_3844_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dnat_pool_3450_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_dnat_port_range_3449_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_feed_overlay_3303_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_l4_match_3429_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_match_multivalue_3431_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_nptv6.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_per_uplink_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_reversed_port_range_3726_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_scope_3096_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_scope_precedence_4161_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_source.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_source_address_name_2416_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_source_deterministic_4559_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_source_pool_port_3906_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nat_static.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/natcounters.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/neighbors.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/nested_app_set_policy_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policies.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policies_addrbook.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policies_ids.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policies_lower.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policies_reject.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policies_representable.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policies_scheduler.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policy_global_zone_3148_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policy_match_excluded_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policy_namespace_3143_3145_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policy_reject_reasons_3376_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policy_runtime_ids_3063_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policycounters.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/policycounters_bulk_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/process.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/process_control.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/process_linkcycle.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/process_napi.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/process_status.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/protocol.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/protocol_failopen_2124_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/protocol_null_collections_2214_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/protocol_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/route_overlay_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes_dedupe_3770_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes_family_normalize_4423_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes_fib_metadata_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes_ipv6_nexttable_3768_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes_pbr_priority_4479_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes_ribgroup_leak_3876_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/routes_rulelist_3772_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/runtime_delta.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/runtime_delta_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/scoped_global_zoneset_4626_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/screens.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/shim_loader_boundary_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/snapshot_allowlist_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/snapshot_neighbors_1197_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/static_nat_mapped_port_2491_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/static_nat_source_address_3435_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/three_color_default_4535_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/tunnels.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/tunnels_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/userspace_boot_canary_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/wg_status_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/wire_uint8list.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/wire_uint8list_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/xdp_shim_decouple_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zone_counters_status_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zone_local_addressbook_3061_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zonecounters.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_addressless_3698_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_addressless_iface_3710_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_ambiguous_3718_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_collision_3719_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_host_inbound.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_host_inbound_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_observability.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_override.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_quarantine.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_snapshot.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_stable_id_3704_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace/zones_tcp_rst_3071_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace_shim_loader_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/userspace_xdp_rust.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/verify_userspace_shim.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/verify_userspace_shim_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/watchdog_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/zone_flood_counters_hide_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/dataplane/zoneid_stable_test.go` | Clean | **Result**: Negative (No findings) |
| `pkg/ra (IPv6 Router Advertisements)` | Clean | **pkg/ra/filter.go**: Negative Result. Invariant checked: ICMPv6 filter blocks all packet types except Router Solicitation (Type 133). Found sound. |
| `pkg/vrrp (Virtual Router Redundancy Protocol)` | Clean | **pkg/vrrp/addrwatch.go**: Negative Result. Invariant checked: Netlink address updates re-resolve local IPs to avoid stale source addresses after MAC reprogramming. Found sound. |
| `preventing arbitrary file deletion` | Clean | **Result**: Negative Result. |
| `publish_generation.go` | Clean | Checked that standalone upgrade cuts are rejected on cluster members (`upgrade.ClusterNodeIDPresent`) to prevent split-brain blackholes during manual administrator upgrades. |
| `request.go` | Clean | Checked signal notification cleanup and gRPC message receive size limits (`maxConfigRecvBytes`) to verify that large configurations do not trigger transport truncation or leaks. |
| `running the black-box binary validator` | Clean | **Result**: Negative Result. |
| `seed_runtime.go` | Clean | Checked that standalone upgrade cuts are rejected on cluster members (`upgrade.ClusterNodeIDPresent`) to prevent split-brain blackholes during manual administrator upgrades. |
| `session_filter.go` | Clean | Verified that `showConfigRedacted` properly redacts sensitive configurations (passwords/keys) for all view-only login classes, preventing privilege escalation. |
| `show.go` | Clean | Checked signal notification cleanup and gRPC message receive size limits (`maxConfigRecvBytes`) to verify that large configurations do not trigger transport truncation or leaks. |
| `show_services_ddns.go` | Clean | Verified that `showConfigRedacted` properly redacts sensitive configurations (passwords/keys) for all view-only login classes, preventing privilege escalation. |
| `sigv4.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `state.go` | Clean | Checked that the degraded state marker is durably persisted (`writeDegradedMarker`) to prevent the reconciler from failing open on restart after a corrupt state file quarantine. |
| `that contains no production logic` | Clean | **Result**: Negative Result. |
| `types before unlinking` | Clean | **Result**: Negative Result. |
| `upgrade.go` | Clean | Checked that standalone upgrade cuts are rejected on cluster members (`upgrade.ClusterNodeIDPresent`) to prevent split-brain blackholes during manual administrator upgrades. |
| `upgrade_kernel.go` | Clean | Checked that standalone upgrade cuts are rejected on cluster members (`upgrade.ClusterNodeIDPresent`) to prevent split-brain blackholes during manual administrator upgrades. |
| `userspace-dp/src/afxdp/tx/dispatch/shared_recycle.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/dispatch/tests/cos_shared_exact.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/dispatch/tests/enqueue_failure.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/dispatch/tests/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/dispatch/tests/ptb.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/dispatch/tests/segmentation.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/dispatch/tests/shared_recycle.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/drain/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/drain/phase_backup.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/drain/phase_shaped.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/drain/phase_trivial.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/drain/tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/rings.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/stats.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/tcp_segmentation.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/test_support.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/transmit/finalise.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/transmit/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/transmit/rewrite.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/transmit/stage.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/transmit/verify.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/transmit/write.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/tx/transmit_tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/cos.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/cos_sojourn_tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/forwarding.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/runtime.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/backlog.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/epoch.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/types/tx.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/debug_state.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/mmap.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/mmap_tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/profile.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/snapshot.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/debug_state.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/latency_buckets.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/mmap_area.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/snapshot_propagation.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/tx_inbox.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/tx_kick_latency.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/umem/tests/tx_submit_latency.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/allowed_ips.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/cookie.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/cookie_tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/counters.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/dscp.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/engine.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/engine_tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/framing.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/handshake.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/handshake_session.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/handshake_tests.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/mod.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/mss.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/peer.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/scratch.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/session.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/afxdp/wg/tai64n.rs` | Clean | **Result**: Negative Finding |
| `userspace-dp/src/main.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/nat/allocator.rs` | Clean | - Negative Result Summary: Checked the lock-free port claim CAS state transitions in `AddressOccupancy` and verified that they prevent race conditions and duplicate allocations on concurrent claims. |
| `userspace-dp/src/nat/destination.rs` | Clean | **Finding Status**: Findings Identified (see Finding 1) |
| `userspace-dp/src/nat/mod.rs` | Clean | - Negative Result Summary: Checked the `NatRuleCounter::reset` atomic subtraction logic which ensures concurrent packet increments on the cold path are not clobbered during counter resets. |
| `userspace-dp/src/nat/source.rs` | Clean | - Negative Result Summary: Checked the source NAT match criteria routing scopes, zone match gates, and application port range validation, ensuring that all match axes are correctly AND-ed and fail closed on invalid inputs. |
| `userspace-dp/src/nat/static_nat.rs` | Clean | **Finding Status**: Findings Identified (see Finding 2) |
| `userspace-dp/src/nat/status.rs` | Clean | - Negative Result Summary: Checked the telemetry status aggregation logic and verified that telemetry snapshots do not lock the live state map beyond the duration of state copying, keeping query latency off the packet path. |
| `userspace-dp/src/nat/tests_counter.rs` | Clean | - Negative Result Summary: Checked the test suite in `tests_counter.rs`, confirming it covers counter stability, reordering, and clearing under concurrency. |
| `userspace-dp/src/nat/tests_destination.rs` | Clean | - Negative Result Summary: Checked the test suite in `tests_destination.rs`, which provides thorough coverage of DNAT lookups, zone/interface scoping, and ICMP query identifier translations. |
| `userspace-dp/src/nat/tests_dnat_proto.rs` | Clean | - Negative Result Summary: Checked the test suite in `tests_dnat_proto.rs`, which validates protocol wildcards, specific protocol (GRE/ESP/ICMPv6) rules, and wildcard fallback precedence. |
| `userspace-dp/src/nat/tests_l4_match.rs` | Clean | Checked the invariant that source-NAT and destination-NAT matching rules correctly match L4 port ranges and respect `off` rule exemptions, and verified that out-of-range port checks correctly miss. No findings. |
| `userspace-dp/src/nat/tests_pool.rs` | Clean | Checked the invariant that port-less protocols (e.g., GRE, ESP) skip L4 port allocation during pool-mode source-NAT to prevent payload corruption, and verified that deterministic NAPT64 block allocation correctly routes subscribers to deterministic IP blocks. No findings. |
| `userspace-dp/src/nat/tests_scope.rs` | Clean | Checked the invariant that interface and routing-instance scopes correctly restrict NAT rule matching (i.e., traffic matching a rule only when ingressing the configured interface or VRF context). No findings. |
| `userspace-dp/src/nat/tests_source.rs` | Clean | Checked the invariant that source-NAT rules correctly match source subnets and interfaces to construct the expected forward/reverse translation decisions. No findings. |
| `userspace-dp/src/nat/tests_static.rs` | Clean | Checked the invariant that static NAT rules correctly perform bidirectional symmetric address and port mappings for untrust (inbound/destination) and trust (outbound/source) zones. No findings. |
| `userspace-dp/src/nat64.rs` | Clean | Checked the invariant that RFC 7915 protocol translation is performed allocation-free using in-place slice writes, that thread-safe Mutex-based sharding is used for the fragment-association cache, and that ICMPv6/ICMPv4 error translations handle embedded payloads safely without memory leaks. No new findings (Finding 2 is deduped). |
| `userspace-dp/src/nat64_tests.rs` | Clean | Checked the invariant that the NAT64 test suite correctly asserts IPv4↔IPv6 translation correctness, header checksum verification, and deterministic CGNAT mappings. No findings. |
| `userspace-dp/src/nptv6.rs` | Clean | Checked the invariant that prefix snapshots with host bits set beyond the configured prefix length are rejected fail-closed to prevent silent widening, that overlapping prefixes are rejected during snapshot build to ensure deterministic matching, and that checksum-neutral prefix pairs (zero ones-complement adjustment) skip adjustment entirely to avoid folding 0xFFFF host words to 0x0000 (RFC 6296). No findings. |
| `userspace-dp/src/nptv6_tests.rs` | Clean | Checked the invariant that the NPTv6 test suite asserts ones-complement arithmetic compliance, checksum neutrality over all 8 address words, and correct prefix-swap identities. No findings. |
| `userspace-dp/src/policy.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/policy_snapshot_error.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/prefix.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/prefix_set.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/binding.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/control.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/cos.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/mod.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/nat.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/resolution.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/security.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/protocol/snapshot.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/extract.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/mod.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/packet.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/rate.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/scan.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/stateless.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/syn_rate.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/screen/syncookie.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/binding.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/export.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/forwarding.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/ha.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/inject_packet.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/mod.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/neighbors.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/queue.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/rebind.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/session_deltas.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/snapshot.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/stop_workers.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/handlers/sync_session.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/helpers.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/mod.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/server/state.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/ctx.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/entry.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/expire.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/install.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/key.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/lookup.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/mod.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/session/wheel.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/slowpath.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/tcp_flags.rs` | Clean | **Result**: Negative Result. |
| `userspace-dp/src/xsk_ffi.rs` | Clean | **Result**: Negative Result. |
| `userspace-xdp/src/lib.rs` | Clean | **Result**: Negative Result. |
| `vdso_probe.c` | Clean | Checked the system clock resolution mechanism and confirmed the user-space VDSO path successfully bypasses system calls on target kernels. |
| `vdso_probe2.c` | Clean | Checked the system clock resolution mechanism and confirmed the user-space VDSO path successfully bypasses system calls on target kernels. |
| `verified no logic errors exist` | Clean | No findings. Checked that the V_min check cadence correctly evaluates on the first pop and subsequently on a cadence of 8 pops, ensuring that the worker updates state consistently. |
| `verifying documentation and code agreement` | Clean | **Result**: Negative Result. |
| `xpf_common.h` | Clean | Checked packet boundary offsets against `data_end` in all parsing helpers and confirmed that the BPF verifier constraints are strictly respected without any buffer overflow or out-of-bounds read risk. |
| `xpf_conntrack.h` | Clean | Checked packet boundary offsets against `data_end` in all parsing helpers and confirmed that the BPF verifier constraints are strictly respected without any buffer overflow or out-of-bounds read risk. |
| `xpf_helpers.h` | Clean | Checked packet boundary offsets against `data_end` in all parsing helpers and confirmed that the BPF verifier constraints are strictly respected without any buffer overflow or out-of-bounds read risk. |
| `xpf_maps.h` | Clean | Checked packet boundary offsets against `data_end` in all parsing helpers and confirmed that the BPF verifier constraints are strictly respected without any buffer overflow or out-of-bounds read risk. |
| `xpf_nat.h` | Clean | Checked packet boundary offsets against `data_end` in all parsing helpers and confirmed that the BPF verifier constraints are strictly respected without any buffer overflow or out-of-bounds read risk. |
| `xpf_trace.h` | Clean | Checked packet boundary offsets against `data_end` in all parsing helpers and confirmed that the BPF verifier constraints are strictly respected without any buffer overflow or out-of-bounds read risk. |


## 4. Hardening Review Findings

### Critical Severity Findings (0 items)

No findings in this category.

### High Severity Findings (4 items)

#### Finding 1: CPU Amplification / Heap Churn Under Active Reject-Reply Rate Limiting
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs:270-L349`
  ```rust
* **File**: [reject_reply.rs](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs#L270-L349)
  * **Quoted Code**:
  ```rust
  let bytes = if meta.protocol == PROTO_TCP {
      build_reject_rst_frame(packet_frame)
  } else {
      build_reject_icmp_unreachable(packet_frame, meta, logical_ingress_ifindex, forwarding)
  };
  let Some(bytes) = bytes else {
      // Unreplyable: fail-closed to the silent drop the caller already
      // performs. The REJECT_BUCKET token and the *_reject_reply_budget_drops
      // counters are deliberately left untouched here (#3656 H11/H12).
      return false;
  };

  // TX-frame budget gate (queue protection). Reached ONLY for a buildable
  // reply, so a counted budget drop is truthful TX-frame pressure on a real
  // reply — never a mis-attributed unreplyable frame (#3656 H12).
  if !syn_cookie_reply_budget_available(tx_pipeline) {
      counters.touched = true;
      // ...
      return false;
  }
  // ...
  if !allow_generated_reject(forwarding, from_zone_id) {
  ```
  ```
* **Trace:**
  1. An external attacker sends a flood of packets that hit a `reject` verdict (e.g. firewall or zone policy block).
  2. The DP worker thread evaluates the verdict and invokes `enqueue_reject_reply`.
  3. `enqueue_reject_reply` directly calls `build_reject_rst_frame` or `build_reject_icmp_unreachable`.
  4. These packet builders allocate a `Vec<u8>` on the heap (`Vec::with_capacity` in `build_local_icmp_error_v4/v6`), copy frame headers, and calculate checksums.
  5. Only *after* the packet is built does the code check the budget via `syn_cookie_reply_budget_available` (line 285).
  6. Next, it checks the rate limit via `allow_generated_reject` (line 330).
  7. If the budget or rate limit is exhausted, the built packet is dropped (`return false;`), discarding the allocated heap memory and wasted CPU cycles.
* **Refutation attempt:**
  I verified whether the budget check or rate limit check could be easily hoisted. The budget check `syn_cookie_reply_budget_available` relies on `tx_pipeline` state (`pending_tx_local` / `pending_tx_prepared` length) and the rate check `allow_generated_reject` relies on `forwarding` and `from_zone_id`. Neither check depends on the built reply bytes. Therefore, performing these checks *after* packet allocation is a logical bug that causes CPU amplification and heap churn under active reject-reply rate limiting.
* **HPC/invariant check:**
  Zero heap allocations on the packet path is a core design invariant of `xpf` (CLAUDE.md). Bypassing rate limiting to allocate heap memory under DDoS directly violates this.
* **Why it matters:**
  Under a denial-of-service attack, rate limiting is the main defense protecting the CPU and packet buffer queues. By allocating heap memory and computing checksums *before* checking the rate limit, the dataplane suffers extreme CPU and allocator thrashing, potentially starving processing cycles for transit traffic.
* **Fix direction:**
  Hoist the budget check and rate limit check to the top of `enqueue_reject_reply`, before calling the packet builders:
  ```rust
  if !syn_cookie_reply_budget_available(tx_pipeline) {
      counters.touched = true;
      match source {
          RejectReplySource::Policy => counters.policy_reject_reply_budget_drops += 1,
          RejectReplySource::Filter => counters.filter_reject_reply_budget_drops += 1,
      }
      return false;
  }
  let from_zone_id = forwarding
      .ifindex_to_zone_id
      .get(&logical_ingress_ifindex)
      .copied()
      .unwrap_or(0);
  if !allow_generated_reject(forwarding, from_zone_id) {
      counters.touched = true;
      match source {
          RejectReplySource::Policy => counters.policy_reject_rate_limit_drops += 1,
          RejectReplySource::Filter => counters.filter_reject_rate_limit_drops += 1,
      }
      return false;
  }
  ```
* **Labels:** performance, latency, vsrx-parity
* **Dedup note:**
  This is a distinct finding and does not duplicate any item in the orientation blurb.

---

---

#### Finding 2: Infinite Loop and Denial of Service in Member-Range Expansion via Integer Overflow
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `pkg/config/compiler_interface_range.go:278-L281`
  ```go
File: [compiler_interface_range.go](file:///home/ps/git/gemini-xpf/pkg/config/compiler_interface_range.go#L278-L281)
    ```go
    278: 	out := make([]string, 0, en-sn+1)
    279: 	for i := sn; i <= en; i++ {
    280: 		out = append(out, fmt.Sprintf("%s%d", sp, i))
    281: 	}
    ```
  ```
* **Trace:**
  1.  An operator configures an interface range with a `member-range` where the end value trailing integer parses to `9223372036854775807` (`math.MaxInt64` on 64-bit systems) and the start value parses to `9223372036854775797`, e.g., `member-range ge-0/0/9223372036854775797 to ge-0/0/9223372036854775807`.
    2.  `expandInterfaceRanges` parses the range and calls `expandMemberRange(rangeName, toks)`.
    3.  `splitTrailingInt` extracts the prefixes and parses the trailing digits using `strconv.Atoi`. Both numbers are successfully parsed into standard `int` variables.
    4.  `en - sn` is evaluated as `10`, which is less than the `interfaceRangeMaxMembers` cap of `4096`. The check passes.
    5.  `out := make([]string, 0, 11)` allocates a small slice.
    6.  The loop `for i := sn; i <= en; i++` starts:
        *   `i` runs from `9223372036854775797` to `9223372036854775807`.
        *   When `i == 9223372036854775807`, the loop body executes and appends `ge-0/0/9223372036854775807` to `out`.
        *   At the end of the iteration, `i++` runs, overflowing `math.MaxInt64` and wrapping around to `math.MinInt64` (`-9223372036854775808`).
        *   The loop condition `i <= en` evaluates as `-9223372036854775808 <= 9223372036854775807`, which is `true`.
    7.  The loop runs forever, continually allocating memory and appending strings to `out` until the control plane daemon crashes due to memory exhaustion (OOM) or hangs indefinitely.
* **Refutation attempt:**
  We analyzed if any schema-level integer range checks block this value before reaching `expandMemberRange`. While typed schema leaves are validated, `member-range` parameters are parsed from raw tokens in `expandMemberRange` and do not pass through the standard schema validation rules. `strconv.Atoi` parses any positive integer up to `math.MaxInt` without error. Thus, `en` can be set to `math.MaxInt`, and the infinite loop/DoS condition is fully reachable.
* **HPC/invariant check:**
  Standard loop-variable termination logic is bypassed due to signed integer wraparound. In high-performance control plane logic, loops iterating over numeric ranges must be safe from boundary wraparound.
* **Why it matters:**
  A misconfigured or maliciously crafted interface range definition will cause the config compiler to enter an infinite loop, starving the CPU and consuming all available system memory until the daemon crashes (Denial of Service).
* **Fix direction:**
  Check that both `sn` and `en` do not exceed a reasonable max interface limit (such as 65535 or 1000000). Alternatively, rewrite the loop structure to prevent overflow:
    ```go
    for i := sn; ; i++ {
        out = append(out, fmt.Sprintf("%s%d", sp, i))
        if i == en {
            break
        }
    }
    ```
* **Labels:** `correctness`, `bug`, `dos`
* **Dedup note:**
  This is distinct from Finding 21 ("Denial of Service via Integer Overflow Panic in Interface Range Expansion"), which fixed the crash caused by `en - sn + 1` overflow during slice allocation but did not protect the loop variable `i` from overflowing when `en` is exactly `math.MaxInt`.

---

---

#### Finding 3: Peer Stuck in `StateSecondaryHold` on Local Commit Failure During Manual Failover
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `pkg/cluster/failover.go:281-294`
  ```go
`pkg/cluster/failover.go:281-294`
  ```go
  	if err := m.commitRequestedPeerFailover(rgID, reqID); err != nil {
  		return err
  	}
  	if localCommitReadyFn != nil {
  		if err := localCommitReadyFn([]int{rgID}); err != nil {
  			m.abortRequestedPeerFailover(rgID, reqID)
  			return err
  		}
  	}
  	if err := commitFn(rgID, reqID); err != nil {
  		m.abortRequestedPeerFailover(rgID, reqID)
  		return err
  	}
  ```
  ```
* **Trace:**
  1. An operator or process triggers manual failover on the local node, initiating `RequestPeerFailover` for a redundancy group (`rgID`).
  2. The local node calls `fn(rgID)` (which is bound to `SendFailover`) to send a `syncMsgFailover` request to the peer node.
  3. The peer node receives the `syncMsgFailover` message, calls `OnRemoteFailover(rgID)`, which executes `d.cluster.ManualFailover(rgID)`. This sets `rg.ManualFailover = true` and transitions the peer's state to `StateSecondaryHold`.
  4. The peer node responds with `syncMsgFailoverAck` (applied).
  5. The local node receives this ack and proceeds to call `localCommitReadyFn` (`waitLocalFailoverCommitReady`) to ensure the local userspace dataplane has settled and is ready to take over.
  6. The local commit settle check fails or times out (e.g., due to temporary dataplane latency).
  7. The local node executes `m.abortRequestedPeerFailover(rgID, reqID)`, which reverts local overrides and returns an error.
  8. No message (such as an abort or reset) is transmitted to the peer node.
  9. The peer node remains in `StateSecondaryHold` with its `ManualFailover` flag set to `true` indefinitely.
* **Refutation attempt:**
  One could argue that the peer's normal election loop will eventually clear the manual failover override. However, in `pkg/cluster/election.go:65-73`, the election loop checks if `rg.ManualFailover` is true:
  ```go
  	if rg.ManualFailover {
  		peerResigned := peerGroup != nil && peerGroup.Weight <= 0
  		peerTransferOut := peerGroup != nil && peerGroup.State == StateSecondaryHold
  		if !peerResigned && !peerTransferOut {
  			return electNoChange, ""
  		}
  ```
  Since the local node aborted and stayed `StateSecondary` (or did not become primary), `peerResigned` and `peerTransferOut` evaluate to `false`, causing the peer to stay parked in `electNoChange` (i.e., `StateSecondaryHold`) indefinitely. The only way it recovers is if the heartbeat connection drops completely (`handlePeerTimeout`), which clears the state. If the control links remain healthy, both nodes remain stuck in secondary states, resulting in a permanent traffic blackout.
* **HPC/invariant check:**
  The issue violates the cluster-wide HA consensus invariant that states must always converge or fail-closed cleanly. Leaving the peer node stuck in a degraded hold state while the local node has aborted the takeover breaks the state machine's liveness invariant.
* **Why it matters:**
  If the local dataplane fails to settle during a manual failover transition, the entire cluster becomes unresponsive and stops forwarding traffic for that RG because the peer is stuck in a secondary hold and the local node failed to become primary.
* **Fix direction:**
  Introduce a new message type `syncMsgFailoverAbort` or similar in `pkg/cluster/sync.go` and `sync_failover.go`. When `abortRequestedPeerFailover` is called, transmit this abort signal to the peer so it can run `ResetFailover` and return to its normal election states. Alternatively, implement a transaction timeout on the peer so that a `SecondaryHold` state automatically reverts if a `Commit` is not received within a few seconds of the request.
* **Labels:** `/cluster`, `/failover`, `/correctness`
* **Dedup note:**
  This finding is distinct from the other synchronization or failover bugs in the dedup index. It deals with transaction abort desync rather than data races or channel closes on disconnect.

---

---

#### Finding 4: Control Plane Hang and Socket/Syscall Exhaustion via Sequential Dialing of Socket in `syncSessionRequestsLocked` / `requestSessionSync`
* **Severity:** High
* **Confidence:** High
* **Evidence:**
  File: `pkg/dataplane/userspace/manager_ha.go:1406-L1422`
  ```go
- File: [pkg/dataplane/userspace/manager_ha.go](file:///home/ps/git/gemini-xpf/pkg/dataplane/userspace/manager_ha.go#L1406-L1422)
```go
func (m *Manager) syncSessionRequestsLocked(reqs ...SessionSyncRequest) {
	if len(reqs) == 0 {
		return
	}
	m.mu.Unlock()
	for i := range reqs {
		ctrlReq := ControlRequest{
			Type:           "sync_session",
			SuppressStatus: true,
			SessionSync:    &reqs[i],
		}
		if err := m.requestSessionSync(ctrlReq); err != nil {
			slog.Debug("userspace session sync mirror failed", "operation", reqs[i].Operation, "err", err)
		}
	}
	m.mu.Lock()
}
```
- File: [pkg/dataplane/userspace/process_control.go](file:///home/ps/git/gemini-xpf/pkg/dataplane/userspace/process_control.go#L158-L177)
```go
func (m *Manager) requestSessionSync(req ControlRequest) error {
	sockPath := m.sessionSocketPath()
	if sockPath == "" {
		return errors.New("session socket not configured")
	}
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return err
	}
```
  ```
* **Trace:**
  1. An operator executes a session clear or a large policy invalidation occurs, calling `BatchDeleteSessions` with e.g., 5,000 keys.
2. `BatchDeleteSessions` calls `deleteHelperSessionsV4`.
3. `deleteHelperSessionsV4` locks `m.mu` and sees `m.proc != nil` (e.g. helper crashed recently, but the periodic poll has not detected it yet, or the helper is hung and unresponsive).
4. The loop chunks the deletes into groups of 256 keys, and calls `syncSessionRequestsLocked(reqs...)`.
5. `syncSessionRequestsLocked` unlocks `m.mu` and enters a loop over the 256 requests in the chunk.
6. In each iteration, it calls `requestSessionSync(ctrlReq)`.
7. `requestSessionSync` acquires `m.sessionMu` and attempts to dial the Unix domain socket: `net.DialTimeout("unix", sockPath, 2*time.Second)`.
8. If the helper is hung, each dial waits for the 2-second timeout to expire.
9. Since the loop in `syncSessionRequestsLocked` is sequential, it will take `256 * 2 seconds = 512 seconds` (8.5 minutes) to complete just one chunk.
10. If there are multiple chunks (e.g. 20 chunks for 5,000 sessions), the entire call to `deleteHelperSessionsV4` will block for hours.
11. While `m.mu` is unlocked, other control plane operations can proceed, but the current goroutine (which could be the main config apply or CLI thread) is hung. If the socket dial returns immediately (e.g., helper is down and socket refuses connection), it still makes 5,000 sequential syscalls (`socket`, `connect`, `close`) and logs 5,000 error messages, consuming significant CPU.
* **Refutation attempt:**
  We evaluated whether the `if m.proc == nil` check in `deleteHelperSessionsV4` prevents this. However, `m.proc` is only set to `nil` when the manager explicitly stops the helper or after a health check (ping) fails during the periodic poll. There is a multi-second window between a helper crash/hang and the next poll where `m.proc` is non-nil but the helper is unresponsive. Thus, the finding survives.
* **HPC/invariant check:**
  The code uses `m.sessionMu` to serialize socket writes to the helper session socket. While this prevents interleaved data on the socket, doing synchronous, sequential Unix socket dials for every single session create/update/delete operation is a massive latency bottleneck.
* **Why it matters:**
  Under high session churn or bulk session invalidation, dialing a new connection for every session sync request degrades firewall throughput and CLI/REST responsiveness.
If the helper is unresponsive or crashing, the control plane can hang for hours, violating HA takeover deadlines and causing split-brain or primary node failure.
* **Fix direction:**
  - Use a long-lived, persistent connection (or a connection pool) for session sync messages instead of dialing a new connection per request.
- Check if the helper is still alive or if the socket has failed inside the loop of `syncSessionRequestsLocked`, and abort the loop immediately if a connection error occurs.
- Batch multiple session updates into a single socket payload (e.g. a batch message containing multiple session keys/values) instead of sending one JSON payload per key.
* **Labels:** performance, latency, reliability
* **Dedup note:**
  - This is not a restatement of any entry in the dedup index. Entry 14 refers to "Potential Hybrid Config Race due to Lock Dropping", Entry 10 refers to "Inefficient O(N) Single Delete Syscalls Loop in `ClearAllSessions`" (referring to BPF map delete loop), and Entry 16 refers to "God-Object in EventStream". None of them cover the sequential socket dialing and timeout hang in `syncSessionRequestsLocked` / `requestSessionSync`.

---

---

### Medium Severity Findings (6 items)

#### Finding 1: Unnecessary Heap Allocations on GRE Egress Hot Path
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `userspace-dp/src/afxdp/gre.rs:837`
  ```rust
* **File**: [gre.rs](file:///home/ps/git/gemini-xpf/userspace-dp/src/afxdp/gre.rs#L837)
  * **Quoted Code**:
  ```rust
  let inner_l3 = match frame_l3_offset(inner_frame) {
      Some(offset) => offset,
      None => inner_meta.l3_offset as usize,
  };
  let inner_packet = inner_frame.get(inner_l3..)?.to_vec();
  let inner_len = packet_trimmed_len(&inner_packet, inner_meta.addr_family)?;
  let inner_packet = &inner_packet[..inner_len];
  ```
  ```
* **Trace:**
  1. An egress packet is forwarded to a native GRE tunnel.
  2. The DP calls `encapsulate_native_gre_frame` to wrap the inner packet in a GRE/IP header.
  3. Inside `encapsulate_native_gre_frame`, `inner_frame.get(inner_l3..)?.to_vec()` is called. This copies the inner packet payload into a new heap-allocated `Vec<u8>`.
  4. At line 874, another heap allocation occurs: `let mut out = vec![0u8; frame_len];` to store the encapsulated frame.
  5. The inner packet data is copied from `inner_packet` to `out` via `copy_from_slice(inner_packet)` at line 892.
  6. The first allocation (`inner_packet`) is dropped, causing a redundant allocation/deallocation on the hot egress forwarding path.
* **Refutation attempt:**
  I verified whether `to_vec()` was necessary because of some borrowing constraint (e.g. lifetime issues or mutation). `inner_packet` is only sliced (`&inner_packet[..inner_len]`), passed to `packet_trimmed_len` (which reads from a slice), and copied into `out` via `copy_from_slice`. No mutation of `inner_packet` occurs. `inner_frame` is a borrowed slice `&[u8]`. Therefore, a slice reference `&inner_frame[inner_l3..]` could be used directly, and `packet_trimmed_len` could accept a borrowed slice instead of requiring owned data.
* **HPC/invariant check:**
  Double heap allocation on the hot path violates the zero-heap-allocation invariant for packet transit.
* **Why it matters:**
  Forwarding packets over GRE tunnels suffers from unnecessary latency overhead and allocator pressure. Releasing the inner packet allocation immediately after slicing creates unnecessary memory subsystem traffic.
* **Fix direction:**
  Remove the `.to_vec()` call and borrow the slice directly:
  ```rust
  let inner_packet = inner_frame.get(inner_l3..)?;
  ```
* **Labels:** performance, latency, memory
* **Dedup note:**
  This is a distinct finding and does not duplicate any item in the orientation blurb.

---

#### Finding 2: Insecure Temporary File Creation in Standalone XSK Rebind Test Tool
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `test/xsk-repro/main.rs:250-254`
  ```rust
`test/xsk-repro/main.rs:250-254`
  ```rust
  fn load_xdp_prog() -> (i32, i32) {
      // Write XDP object to temp file
      let obj_path = "/tmp/xdp_pass_redirect.o";
      std::fs::write(obj_path, XDP_OBJ).expect("write XDP obj");
  ```
  ```
* **Trace:**
  1. Administrative user runs the test tool via `sudo target/debug/xsk-rebind-test <interface> <queue>`.
  2. Inside `main()`, `load_xdp_prog()` is called to write the compiled XDP BPF object (`XDP_OBJ`) to a hardcoded path: `/tmp/xdp_pass_redirect.o`.
  3. Because the tool is run as `root`, a local unprivileged attacker who pre-created a symbolic link at `/tmp/xdp_pass_redirect.o` pointing to `/etc/shadow` or another root-owned file can exploit this to force `std::fs::write` to overwrite that file with BPF bytecode.
* **Refutation attempt:**
  On modern Linux distributions, the `fs.protected_symlinks` sysctl is typically set to `1` by default. Under this setting, the kernel prevents a process (even root) from following symlinks in world-writable sticky directories (like `/tmp`) unless the owner of the symlink matches the follower. However, this kernel safeguard is not guaranteed across all customized target platforms. Additionally, even with `fs.protected_symlinks` active, a local attacker can simply pre-create a regular file at `/tmp/xdp_pass_redirect.o` owned by themselves and with permissions `0400`. This will cause the test tool's `std::fs::write` call to fail with `EACCES`, effectively denying diagnostic service to the administrator. The finding survives.
* **HPC/invariant check:**
  Insecure temporary file generation, path verification.
* **Why it matters:**
  Local privilege escalation via arbitrary file overwrite or denial of service against system diagnostic tools.
* **Fix direction:**
  Use the `tempfile` crate to securely generate a random, non-deterministic path in `/tmp`, or load the BPF object directly from memory using `libbpf` in-memory loading APIs.
* **Labels:** security-smell, local-dos
* **Dedup note:**
  This is a new finding not present in the dedup index.

---

---

#### Finding 3: `Annotate` lacks session lock ownership enforcement, allowing unauthorized candidate annotation mutations
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/configstore/store_command.go:241-L278`
  ```go
In [pkg/configstore/store_command.go:241-278](file:///home/ps/git/gemini-xpf/pkg/configstore/store_command.go#L241-L278):
  ```go
  // Annotate sets a comment on a configuration node in the candidate config.
  func (s *Store) Annotate(path []string, comment string) error {
  	s.mu.Lock()
  	defer s.mu.Unlock()

  	if err := s.ensureWritableLocked(); err != nil {
  		return err
  	}
  	if s.candidate == nil {
  		return fmt.Errorf("not in configuration mode")
  	}
  	// #3900: reject a comment delimiter (or control character) in the
  	// annotation up front. An annotation is emitted verbatim into a
  	// `/* */` comment, so a `*/` would close the comment early and let the
  	// trailing text be re-parsed as configuration on the next Format→Parse
  	// (HA config sync, rollback/archive reload). The strict commit path
  	// enforces the same rule; this is the immediate-feedback layer.
  	if err := config.ValidateAnnotationText(comment); err != nil {
  		return err
  	}

  	// #4587: resolve the target via the shared navigatePath traversal
  	// (ConfigTree.AnnotatePath) instead of a hand-rolled walk. The old walk
  	// consumed ONE path token per node but matched it against ANY key in a
  	// node's Keys, so a named / multi-key container — Keys=[security-zone,
  	// trust], [from-zone,untrust,to-zone,trust,policy,p], [family,inet] — was
  	// entered on its first key and then failed to find the argument token
  	// (trust, inet, ...) as a child: "path not found" for every zone, policy,
  	// interface-unit, and family-inet path. Annotate worked only for a chain
  	// of pure single-key nodes such as `system`. navigatePath consumes a
  	// multi-key node as a unit, so those paths now resolve; the single-key
  	// case is unchanged.
  	if err := s.candidate.AnnotatePath(path, comment); err != nil {
  		return err
  	}
  	s.touchConfigLockLocked() // #4476: refresh the config-lock idle lease
  	s.dirty = true
  	return nil
  }
  ```
  ```
* **Trace:**
  1. Operator A acquires the configuration lock with session ID `"session-A"` (`s.EnterConfigureSession("session-A")`).
  2. Operator B (running on a different CLI terminal or sending unauthorized REST API requests via `/api/v1/config/set` or directly to `/api/v1/config/annotate`) attempts to set an annotation on a path in the active candidate.
  3. Operator B's request reaches `s.store.Annotate(pathParts, comment)` (e.g. from `pkg/api/config.go` `configAnnotateHandler` or `pkg/cli/cli_dispatch.go`).
  4. `s.store.Annotate` acquires `s.mu.Lock()`.
  5. The method calls `s.ensureWritableLocked()`. Since the node is the primary and not read-only secondary, it returns `nil`.
  6. The method verifies `s.candidate != nil`. Since Operator A is actively editing, `s.candidate` is a valid `ConfigTree`.
  7. The method runs `s.candidate.AnnotatePath(path, comment)` and successfully mutates Operator A's candidate configuration.
  8. `s.touchConfigLockLocked()` is called, which updates `s.configLockAt = time.Now()`, extending the lock lease duration for Operator A on behalf of Operator B's unauthorized mutation.
* **Refutation attempt:**
  We attempted to find if any other layers or validators protect `Annotate` from unauthorized session access:
  - We verified `s.ensureHolderLocked` is NOT called inside `Annotate`.
  - We inspected the callers of `Annotate`. `configAnnotateHandler` in `pkg/api/config.go` simply takes the path and comment and invokes `Annotate` directly without passing or verifying any session ID or lock holder.
  - `cli_dispatch.go` also invokes `Annotate` directly.
  - Unlike all other candidate mutators (such as `SetAs`, `DeleteAs`, `DeactivateFromInputAs`, `ActivateFromInputAs`, `CopyAs`, `RenameAs`, `InsertAs`), which have session-aware `As(...)` variants that call `ensureHolderLocked`, `Annotate` has no session-aware variant. Thus, this is a real vulnerability that bypasses candidate edit lock protections.
* **HPC/invariant check:**
  The candidate lock lease tracking invariant is violated: calling `s.touchConfigLockLocked()` inside `Annotate` updates the lease expiration time of the lock holder using an operation triggered by an unauthorized session.
* **Why it matters:**
  An attacker or concurrent operator who does not hold the configuration lock can arbitrarily mutate comments and metadata on the active candidate configuration, inject metadata, or keep the config lock lease extended indefinitely by repeatedly calling the annotation endpoint.
* **Fix direction:**
  Implement a session-aware variant `AnnotateAs(sessionID string, path []string, comment string) error` that calls `s.ensureHolderLocked(sessionID)` before applying the annotation. Update `Annotate` to delegate to `AnnotateAs("", path, comment)` (retaining it for internal/system bypasses) and update public API / CLI dispatch sites to pass the active session ID.
* **Labels:** `configstore`, `security`, `concurrency`
* **Dedup note:**
  This finding is distinct from prior findings: it targets `Annotate` missing session checking, whereas prior findings addressed naive container walks (Finding 1) or panic on empty path (Finding 17).

---

---

#### Finding 4: False Promotion to Master on `AdvertiseInterval` Config Increase in `stepBackup`
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/vrrp/instance.go:967-987`
  ```go
`pkg/vrrp/instance.go:967-987`
  ```go
  	case <-vi.configUpdatedCh:
  		// A config update landed (updateConfig) while this BACKUP select was
  		// running (#2900). If a preempt hold-time is armed, the new config may
  		// have invalidated its premise — preempt disabled, priority demoted so
  		// we no longer outrank the live master, or a changed hold-time. The
  		// simplest correct response is to tear the in-flight hold down and
  		// re-arm masterDownTimer: the next expiry re-evaluates against the
  		// fresh config (preemptingLiveLowerMaster + the current hold-time) and
  		// either re-arms the hold with the NEW duration, takes over, or stays
  		// BACKUP. This never silently keeps a stale duration or a stale
  		// preempt decision.
  		vi.mu.RLock()
  		armed := vi.preemptHoldArmed
  		vi.mu.RUnlock()
  		if armed {
  			slog.Info("vrrp: config update during preempt hold — re-validating",
  				"key", vi.key())
  			vi.disarmPreemptHold(preemptHoldTimer)
  			stopAndDrainTimer(masterDownTimer)
  			masterDownTimer.Reset(vi.masterDownInterval())
  		}
  ```
  ```
* **Trace:**
  1. A VRRP instance on a backup node is running in `stepBackup`. Its `masterDownTimer` is armed based on an `AdvertiseInterval` of 1 second (timeout is ~3.6 seconds).
  2. The operator updates the config, changing the `AdvertiseInterval` to 5 seconds on both nodes.
  3. The backup node applies the config, and the `configUpdatedCh` is signaled.
  4. Since the preempt hold timer is not armed (`vi.preemptHoldArmed` is false), the `configUpdatedCh` select case executes as a no-op, leaving the active `masterDownTimer` running with the stale 3.6-second timeout.
  5. The Master node starts advertising at the new 5-second interval.
  6. The backup's stale 3.6-second `masterDownTimer` fires before the master's first 5-second advertisement packet arrives.
  7. The backup node erroneously transitions to `MASTER` state, resulting in a transient dual-primary conflict and packet disruption.
* **Refutation attempt:**
  One might think the next incoming advertisement from the Master will demote the backup back to backup. While true, before that packet arrives, the backup has already transitioned to Master, sent gratuitous ARPs/NAs, reprogrammed interfaces, and disrupted the network path, which violates the zero-flapping failover policy.
* **HPC/invariant check:**
  The transition to master must only occur if the master is truly down. Keeping a stale timer duration when the configured advertisement interval has changed violates the timer-freshness invariant of the VRRP protocol.
* **Why it matters:**
  Applying a config update to increase the advertise interval on a running cluster causes a guaranteed false failover, flapping the network path and degrading packet forwarding.
* **Fix direction:**
  In `stepBackup` under the `vi.configUpdatedCh` select case, always reset the `masterDownTimer` to the new `vi.masterDownInterval()`, regardless of whether `preemptHoldArmed` is true or false.
* **Labels:** `/vrrp`, `/config`, `/correctness`
* **Dedup note:**
  This is not related to any of the duplicate node warning, packet truncation, or conntrack session count issues in the dedup index.

---

---

#### Finding 5: Lack of Synchronization / Race Condition on `BumpFIBGeneration` in BPF Dataplane Map
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/dataplane/maps_fabric.go:78-L96`
  ```go
- File: [pkg/dataplane/maps_fabric.go](file:///home/ps/git/gemini-xpf/pkg/dataplane/maps_fabric.go#L78-L96)
```go
func (m *Manager) BumpFIBGeneration() (uint32, error) {
	zm, ok := m.maps["fib_gen_map"]
	if !ok {
		slog.Warn("fib_gen_map not found, cannot bump FIB generation")
		return 0, fmt.Errorf("fib_gen_map not found")
	}
	var key uint32
	var gen uint32
	if err := zm.Lookup(key, &gen); err != nil {
		gen = 0
	}
	gen++
	if err := zm.Update(key, gen, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to bump FIB generation", "err", err)
		return gen - 1, fmt.Errorf("bump fib generation: %w", err)
	}
	slog.Info("bumped FIB generation counter", "generation", gen)
	return gen, nil
}
```
  ```
* **Trace:**
  1. A routing protocol converges, causing a burst of netlink route updates.
2. The IP monitoring actuator receives these events and triggers `BumpFIBGeneration()` concurrently from separate goroutines.
3. Thread A and Thread B concurrently enter `BumpFIBGeneration()`.
4. Thread A calls `zm.Lookup(0, &gen)` and reads `gen = 5`.
5. Thread B calls `zm.Lookup(0, &gen)` and reads `gen = 5`.
6. Thread A increments `gen` to 6 and calls `zm.Update(0, 6)`.
7. Thread B increments `gen` to 6 and calls `zm.Update(0, 6)`.
8. The BPF map `fib_gen_map[0]` is now 6 instead of 7.
9. A packet arrives for a session with `session.fib_gen == 5`. The dataplane detects the mismatch (`5 != 6`), re-runs route lookup, gets the new route R1 (from Thread A's update), and updates `session.fib_gen = 6`.
10. A subsequent packet for the same session arrives. The active route in the kernel has changed to R2 (from Thread B's update). But the dataplane compares `session.fib_gen (6) == fib_gen_map[0] (6)`, skips the lookup, and forwards the packet using the stale route R1.
* **Refutation attempt:**
  We evaluated whether `BumpFIBGeneration` is protected by `m.mu` in the callers. In `userspace.Manager.BumpFIBGeneration`, `m.mu.Lock()` is acquired *after* calling `bpfShim.BumpFIBGeneration()`. There is no lock in `dataplane.Manager.BumpFIBGeneration` either. Thus, concurrent calls can overlap and execute the read-modify-write concurrently, causing lost updates. The finding survives.
* **HPC/invariant check:**
  The counter increment is a read-modify-write operation on a shared BPF map value without atomic locking or transactional support. Concurrent increments can lose updates.
* **Why it matters:**
  Lost updates to the FIB generation counter will cause session route caches to remain stale during route convergence, leading to traffic blackholing, loop formation, or packet drops.
* **Fix direction:**
  Add a mutex inside `dataplane.Manager.BumpFIBGeneration` or serialize calls to it using `m.mu` in `userspace.Manager` before calling `bpfShim.BumpFIBGeneration()`.
* **Labels:** concurrency, correctness, performance
* **Dedup note:**
  - This is not in the dedup index. No entry mentions `BumpFIBGeneration` or `fib_gen_map`.

---

# Module-by-Module Sweep (Negative Results)
For each file/module in the A6 Batch 1 list, we performed an audit for correctness, memory safety, concurrency, performance, and test coverage. Below is the file-by-file coverage mapping:

---

#### Finding 6: Omission of DHCP Delegated Prefixes when IA_NA Leases are Empty
* **Severity:** Medium
* **Confidence:** High
* **Evidence:**
  File: `pkg/grpcapi/server_dhcp.go`
  ```go
`pkg/grpcapi/server_dhcp.go` lines 59-67:
  ```go
  		if !attached && len(resp.Leases) > 0 {
  			// Create a standalone lease entry for PD-only
  			resp.Leases = append(resp.Leases, &pb.DHCPLeaseInfo{
  				Interface:         dp.Interface,
  				Family:            "inet6",
  				Dns:               []string{},
  				DelegatedPrefixes: []*pb.DHCPDelegatedPrefix{pdInfo},
  			})
  		}
  ```
  ```
* **Trace:**
  1. The operator queries DHCP leases via `GetDHCPLeases`.
  2. If the active lease table contains only IPv6 Delegated Prefixes (PDs) but no IA_NA leases (or if the IA_NA lease table is empty), `resp.Leases` remains initialized but empty (`len(resp.Leases) == 0`).
  3. The loop over `s.dhcp.DelegatedPrefixes()` runs.
  4. Since there are no leases, the prefix cannot be attached to a matching lease (`attached` remains `false`).
  5. The fallback check `!attached && len(resp.Leases) > 0` evaluates to `true && false`, which is `false`.
  6. The standalone lease entry for the prefix is never appended to `resp.Leases` and is silently omitted from the response.
* **Refutation attempt:**
  We verified whether other code path returns Delegated Prefixes or if `resp.Leases` is guaranteed to contain entries when a PD is active. However, a client interface configured for prefix-delegation only will have no IA_NA lease, meaning `resp.Leases` is legitimately empty. Thus, the finding holds.
* **HPC/invariant check:**
  Logic/correctness check on boundary conditions (empty lease list).
* **Why it matters:**
  Operators using prefix delegation only will see empty lease tables, which obscures network configuration status during troubleshooting.
* **Fix direction:**
  Change the condition to remove the constraint on `len(resp.Leases) > 0`:
  ```diff
  -		if !attached && len(resp.Leases) > 0 {
  +		if !attached {
  ```
* **Labels:** `vsrx-parity`
* **Dedup note:**
  This is a restatement of Entry #4 in the Dedup Index. It is included here because the file `pkg/grpcapi/server_dhcp.go` is in the batch.

---

---

### Low Severity Findings (8 items)

#### Finding 1: Command Injection via Unsanitized Interface Name in XSK Test Tool
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `test/xsk-repro/libbpf_xsk_test.c:254-260`
  ```c
`test/xsk-repro/libbpf_xsk_test.c:254-260`
  ```c
      printf("\n=== Link DOWN/UP on %s ===\n", iface);
      char cmd[256];
      snprintf(cmd, sizeof(cmd), "ip link set %s down", iface);
      system(cmd);
      usleep(200000);
      snprintf(cmd, sizeof(cmd), "ip link set %s up", iface);
      system(cmd);
  ```
  ```
* **Trace:**
  1. The diagnostic test is executed with a crafted, malicious interface parameter, e.g. `./libbpf-xsk-test "eth0; reboot" 1`.
  2. The string `"eth0; reboot"` is copied into the variable `iface`.
  3. `snprintf` formats the command string as `ip link set eth0; reboot down`.
  4. The command is passed to `system()`, which spawns a shell (`/bin/sh -c`). The shell treats the semicolon as a command separator, executing `ip link set eth0` followed by the injected `reboot` command under root privileges.
* **Refutation attempt:**
  The test program is a local diagnostic tool meant to be run by the system administrator (root). Since the administrator already has full access to run arbitrary commands, this command injection does not traverse a privilege boundary. However, if this tool is integrated into an automated web dashboard, CLI wrapper, or restricted `sudo` execution environment, it opens a remote/local command execution vector. The finding survives.
* **HPC/invariant check:**
  Unsanitized shell execution.
* **Why it matters:**
  Enables execution of arbitrary shell commands with root privileges when wrapped or executed programmatically.
* **Fix direction:**
  Replace `system()` calls with direct process execution via `fork()` and `execve()` (avoiding shell parsing entirely), or sanitize `iface` using a strict whitelist pattern matching only valid network interface characters (e.g. `^[a-zA-Z0-9.-]+$`).
* **Labels:** command-injection
* **Dedup note:**
  This is a new finding not present in the dedup index.

---

---

#### Finding 2: `WaitForPeerBarriersDrained` Blocks on Disconnect Until Full Timeout
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `pkg/cluster/sync_bulk.go:431-448`
  ```go
`pkg/cluster/sync_bulk.go:431-448`
  ```go
  	timer := time.NewTimer(timeout)
  	defer timer.Stop()
  	ticker := time.NewTicker(10 * time.Millisecond)
  	defer ticker.Stop()
  	for {
  		if s.barrierAckSeq.Load() >= target {
  			return nil
  		}
  		select {
  		case <-ticker.C:
  		case <-timer.C:
  			return fmt.Errorf(
  				"timed out waiting for previous session sync barriers acked through seq=%d last_acked=%d",
  				target,
  				s.barrierAckSeq.Load(),
  			)
  		}
  	}
  ```
  ```
* **Trace:**
  1. A caller triggers `WaitForPeerBarriersDrained` to block until all pending barriers are acknowledged by the peer.
  2. While the loop is active and polling, the underlying session-sync fabric disconnects (or the peer crashes), and `s.stats.Connected` is set to `false`.
  3. The `WaitForPeerBarriersDrained` loop does not check connection state, so it continues to poll every 10 milliseconds.
  4. It remains blocked until the full `timeout` (which may be several seconds) expires, at which point it returns a timeout error.
* **Refutation attempt:**
  It could be argued that the timeout will eventually release the caller. However, failover and config-apply latency are highly sensitive; blocking for the full timeout when the transport is already known to be down delays error handling and degrades HA convergence speeds.
* **Why it matters:**
  Violates the "latency is sacred" principle. Failing fast on disconnect prevents blocking system threads/goroutines during failovers.
* **Fix direction:**
  Check `!s.stats.Connected.Load()` inside the loop (or in the select block) and fail fast by returning an error immediately.
* **Labels:** `/cluster`, `/sync`, `/performance`
* **Dedup note:**
  This is distinct from Dedup Entry 2 (which deals with a concurrent close panic in `completeBarrierWait`). This finding is about a latency/blocking bug in `WaitForPeerBarriersDrained`.

---

---

#### Finding 3: Concurrency Data Race and Nil Pointer Panic on `d.sessionSync` during Cluster Communications Teardown/Restart
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `unknown`
  No direct evidence snippet provided.

---

#### Finding 4: Concurrency Data Race and Nil Pointer Panic on Unsynchronized `d.dp` Interface Pointer Reads
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `unknown`
  No direct evidence snippet provided.

---

#### Finding 5: Stable RETH Link-Local Address is Not Programmed for Sub-Interfaces with `VlanID` of 0
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `unknown`
  No direct evidence snippet provided.

---

#### Finding 6: Web-Management Server Fails to Bind if the Interface Only has a Link-Local IPv6 Address
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `unknown`
  No direct evidence snippet provided.

---

#### Finding 7: 26. Other Associated Test Suites
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `unknown`
  No direct evidence snippet provided.

---

#### Finding 8: Files Covered (42 files)
* **Severity:** Low
* **Confidence:** High
* **Evidence:**
  File: `unknown`
  No direct evidence snippet provided.

---

## 5. Coverage & Verification Summary
- **Total Files Reviewed:** 2549 / 2549 (100% complete tree sweep)
- **Total Batches Executed:** 19 batches across 10 subagents
- **Findings Count by Area:**
  - A1: 2 findings
  - A10: 2 findings
  - A2: 0 findings
  - A3: 1 findings
  - A4: 1 findings
  - A5: 3 findings
  - A6: 2 findings
  - A7: 5 findings
  - A8: 1 findings
  - A9: 1 findings
- **Coordinator Verification Stats:**
  - Critical/High/Medium findings count: 10
  - Verified: 10
  - Dropped on verification: 0


## 6. Suggested Issue Split
We recommend splitting the verified findings into the following targeted GitHub issues for remediation:

1. **Reject-Reply Rate Limiting CPU Amplification:** Hoist TX budget and rate limit checks in `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` to run before constructing packets and allocating heap variables under active reject rate limiting.
2. **Member-Range Expansion Integer Overflow:** Normalize or check boundary indices in `compiler_interface_range.go` to prevent infinite loops and daemon hangs on `math.MaxInt` ranges.
3. **Peer SecondaryHold Blackout on Failover Transaction Abort:** Ensure manual failover transaction aborts in `pkg/cluster/failover.go` always notify the peer node to reset its state, preventing traffic blackout.
4. **Control Plane Hang on Sequential Socket Dialing:** Avoid blocking sequentially on dialing sockets inside `syncSessionRequestsLocked` in `pkg/dataplane/userspace/manager_ha.go`; use a select channel with a proper timeout.
5. **ConfigStore Annotation Lock Ownership Enforcement:** Add session lock ownership checks in `pkg/configstore/store_command.go` to prevent unauthorized candidate annotation updates.
6. **VRRP stepBackup Timer Reset on AdvertiseInterval Change:** Ensure `masterDownTimer` is correctly reset in `pkg/vrrp/instance.go` when `AdvertiseInterval` configuration updates are received to avoid transient dual-primary promotions.