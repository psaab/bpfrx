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
