# Engineering Log — #1827 PR-1 (engineer/1827-ipmon-pr1)

- **Timestamp**: 2026-06-10 12:00
  - **Action**: Read binding spec docs/research/1827-multiwan/plan.md @ 883cdb7f1 in full; surveyed pkg/rpm, pkg/routing, pkg/config, pkg/daemon, pkg/frr, pkg/dataplane/userspace seams. Verified early: PublishRouteOverlaySnapshot reuses the existing apply_snapshot control message + unchanged RouteSnapshot schema (UpdatePolicyScheduleState precedent at manager.go:688) — zero Rust, zero wire changes.
  - **File(s)**: none (survey)

- **Timestamp**: 2026-06-10 12:30
  - **Action**: PR-1a config surface — RPMTest.DestinationInterface/NextHop fields, probe-pin band constants (ProbeTableBase 7000/count 50, fwmark 0x1000, rule prio 50), `target address` canonical form, schema leaves, validateRPMTest next-hop checks, validateRPMProbePinsStrict (cap + RI table collision) wired into strict accumulator.
  - **File(s)**: pkg/config/types_system.go, pkg/config/compiler_services.go, pkg/config/schema.go, pkg/config/compiler.go

- **Timestamp**: 2026-06-10 12:45
  - **Action**: PR-1a pin plumbing — new probePinManager (fwmark rules band 50-99, pinned onlink host routes in tables 7000-7049, clear pass), BuildProbePins deterministic assignment, ResolveProbeInterface; facade ApplyProbePins/ClearProbePins.
  - **File(s)**: pkg/routing/probe_pin.go, pkg/routing/routing.go

- **Timestamp**: 2026-06-10 13:00
  - **Action**: PR-1a real ICMP echo prober (raw socket via injectable icmpListenFunc seam, id/seq/peer matching, 3s timeout, v4+v6), probeDialer with SO_BINDTODEVICE (destination-interface > vrf fallback) + SO_MARK for all probe types, Transition hook (SetTransitionCallback), SetRethMap, marks from BuildProbePins.
  - **File(s)**: pkg/rpm/icmp.go, pkg/rpm/rpm.go

- **Timestamp**: 2026-06-10 13:15
  - **Action**: PR-1a daemon wiring — config-hash-gated reconcileRPM (step 17b of applyConfigLocked), eager rpm.New(), startup ClearProbePins leak-clear, removed one-shot RPM start block.
  - **File(s)**: pkg/daemon/daemon_rpm.go, pkg/daemon/daemon.go, pkg/daemon/daemon_run.go, pkg/daemon/daemon_apply.go

- **Timestamp**: 2026-06-10 13:30
  - **Action**: PR-1a tests (pin assignment/same-target-two-uplinks/cap/band-cleanup-on-restart; prober seam pass/v6/timeout/foreign-reply/sockopts; transition hook; flat-set+hierarchical parse; validation rejections; reconcileRPM hash gating) + README updates (pkg/rpm, pkg/routing). All green.
  - **File(s)**: pkg/routing/probe_pin_test.go, pkg/rpm/icmp_test.go, pkg/config/parser_rpm_pin_test.go, pkg/daemon/daemon_rpm_test.go, pkg/rpm/README.md, pkg/routing/README.md

- **Timestamp**: 2026-06-10 13:50
  - **Action**: PR-1b config surface — IPMonitoringConfig/Policy/PreferredRoute + RouteOverlayEntry types, compileIPMonitoring (dual AST, line-merge), setSchema stanza, validateIPMonitoringStrict (probe-exists, ≥1 route, family match, RI exists + forwarding-type rejection). Tests: flat-set + hierarchical + 8 rejection cases.
  - **File(s)**: pkg/config/types_system.go, pkg/config/compiler_services.go, pkg/config/compiler.go, pkg/config/schema.go, pkg/config/parser_ipmonitoring_test.go

- **Timestamp**: 2026-06-10 14:10
  - **Action**: PR-1b engine + actuator + overlay consumers — pkg/ipmon engine (FAIL/recover FSM, hold-down, winner resolution, debounce 1s + throttle 3s coalescing, publish gating); FRR PreferredRoutes distance-1 render (emission step 7, renumbered contract); buildRouteSnapshots overlay param (whole-entry replacement); Manager.SetRouteOverlay + PublishRouteOverlaySnapshot (apply_snapshot reuse, duplicate-skip, no Compile); daemon assembleFRRConfig extraction (sole FullConfig constructor), actuateRouteOverlay (publish-before-bump), reconcileIPMon, §4.4 HA gating (filterRPMForHAGating, reconcileIPMonGating on RG transitions). Tests across pkg/ipmon, pkg/frr, pkg/dataplane/userspace, pkg/daemon.
  - **File(s)**: pkg/ipmon/{ipmon,display,ipmon_test}.go, pkg/frr/{manager,config_render,preferred_routes_test}.go, pkg/dataplane/userspace/{routes,builder,manager,legacy_dataplane,route_overlay_test,manager_test}.go, pkg/daemon/{daemon_ipmon,daemon_ipmon_test,daemon_rpm,daemon_apply,daemon_run,daemon,daemon_ha}.go

- **Timestamp**: 2026-06-10 14:30
  - **Action**: PR-1b observability + docs — show services ip-monitoring status (cmdtree + local CLI + remote CLI + gRPC topic, shared ipmon.FormatStatus renderer), Prometheus xpf_ipmon_policy_failed/transitions_total/routes_applied (+ descriptor-coverage canary fixture), docs/multi-wan.md, pkg/ipmon/README.md, pkg/frr/README.md, pkg/daemon/README.md, CLAUDE.md feature line.
  - **File(s)**: pkg/cmdtree/tree.go, pkg/cli/{cli,cli_show_services}.go, cmd/cli/show.go, pkg/grpcapi/{server,server_show,server_show_security_text}.go, pkg/api/{server,metrics,metrics_descriptors,metrics_system,metrics_descriptor_coverage_test}.go, docs/multi-wan.md, pkg/ipmon/README.md, pkg/frr/README.md, pkg/daemon/README.md, CLAUDE.md
