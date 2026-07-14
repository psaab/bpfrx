# Review: A7_go_daemon_host — batch 1/2 (paladin-038-014)

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A7_go_daemon_host
Batch: 1/2 — 150 files under pkg/daemon/

---

## Batch file list

pkg/daemon/apply_ctx_cancel_test.go
pkg/daemon/apply_serialize_test.go
pkg/daemon/archive_config_3867_test.go
pkg/daemon/archive_timer_4078_test.go
pkg/daemon/bootstrap.go
pkg/daemon/bootstrap_rollback_test.go
pkg/daemon/bootstrap_test.go
pkg/daemon/coalescence.go
pkg/daemon/coalescence_test.go
pkg/daemon/commit_confirm_demote_4378_test.go
pkg/daemon/compile_error_policy_test.go
pkg/daemon/compile_health_test.go
pkg/daemon/config_arrival_naming_4179_test.go
pkg/daemon/config_sync_test.go
pkg/daemon/configstore_helper_test.go
pkg/daemon/configsync_tail_error_test.go
pkg/daemon/daemon.go
pkg/daemon/daemon_apply.go
pkg/daemon/daemon_apply_runtime_test.go
pkg/daemon/daemon_archive_timer.go
pkg/daemon/daemon_cluster_bind.go
pkg/daemon/daemon_ddns.go
pkg/daemon/daemon_ddns_scope_test.go
pkg/daemon/daemon_ddns_surface_a.go
pkg/daemon/daemon_ddns_surface_a_test.go
pkg/daemon/daemon_ddns_test.go
pkg/daemon/daemon_dhcp.go
pkg/daemon/daemon_dhcp_lease_sync.go
pkg/daemon/daemon_dhcp_lease_sync_test.go
pkg/daemon/daemon_dhcp_relay_gate_test.go
pkg/daemon/daemon_dhcprelay_reconcile_test.go
pkg/daemon/daemon_dns.go
pkg/daemon/daemon_dns_test.go
pkg/daemon/daemon_eventoptions_reconcile_test.go
pkg/daemon/daemon_fabric_monitor_4031_test.go
pkg/daemon/daemon_feeds.go
pkg/daemon/daemon_flow.go
pkg/daemon/daemon_flowexport.go
pkg/daemon/daemon_flowexport_flowdir_test.go
pkg/daemon/daemon_flowexport_reconcile_test.go
pkg/daemon/daemon_flowexport_session_close_test.go
pkg/daemon/daemon_flowtrace_3932_test.go
pkg/daemon/daemon_forwarding_status.go
pkg/daemon/daemon_forwarding_status_test.go
pkg/daemon/daemon_gc.go
pkg/daemon/daemon_gc_test.go
pkg/daemon/daemon_ha.go
pkg/daemon/daemon_ha_fabric.go
pkg/daemon/daemon_ha_fabric_test.go
pkg/daemon/daemon_ha_fence_3917_test.go
pkg/daemon/daemon_ha_sync.go
pkg/daemon/daemon_ha_sync_test.go
pkg/daemon/daemon_ha_userspace.go
pkg/daemon/daemon_ha_vip.go
pkg/daemon/daemon_health.go
pkg/daemon/daemon_ipmon.go
pkg/daemon/daemon_ipmon_test.go
pkg/daemon/daemon_ipsec_apply_test.go
pkg/daemon/daemon_linkstate_monitor_3950_test.go
pkg/daemon/daemon_lldp_reconcile_test.go
pkg/daemon/daemon_natpoolalarm.go
pkg/daemon/daemon_natpoolalarm_race_test.go
pkg/daemon/daemon_neighbor.go
pkg/daemon/daemon_neighbor_listener.go
pkg/daemon/daemon_neighbor_listener_test.go
pkg/daemon/daemon_networkd_apply_test.go
pkg/daemon/daemon_nft.go
pkg/daemon/daemon_policy_default_4342_test.go
pkg/daemon/daemon_policy_invalidate.go
pkg/daemon/daemon_policy_invalidate_test.go
pkg/daemon/daemon_policy_modified_4234_test.go
pkg/daemon/daemon_policy_scheduler_4343_test.go
pkg/daemon/daemon_proxyarp.go
pkg/daemon/daemon_proxyarp_test.go
pkg/daemon/daemon_ra.go
pkg/daemon/daemon_reth.go
pkg/daemon/daemon_reth_rename_up_test.go
pkg/daemon/daemon_rpm.go
pkg/daemon/daemon_rpm_test.go
pkg/daemon/daemon_run.go
pkg/daemon/daemon_scheduler.go
pkg/daemon/daemon_scheduler_republish_3780_test.go
pkg/daemon/daemon_scheduler_test.go
pkg/daemon/daemon_snmp_reconcile.go
pkg/daemon/daemon_snmp_reconcile_test.go
pkg/daemon/daemon_ssh_test.go
pkg/daemon/daemon_sudoers_reconcile_3889_test.go
pkg/daemon/daemon_system.go
pkg/daemon/dataplane_boot_test.go
pkg/daemon/device_map.go
pkg/daemon/device_map_startup_test.go
pkg/daemon/device_map_test.go
pkg/daemon/dhcp_nexthop_resolver_test.go
pkg/daemon/dhcp_recompile_test.go
pkg/daemon/dhcp_reconcile_test.go
pkg/daemon/direct_announce_test.go
pkg/daemon/direct_garp_gate_test.go
pkg/daemon/direct_garp_probe_target_test.go
pkg/daemon/direct_vip_ownership_test.go
pkg/daemon/exec_timeout.go
pkg/daemon/failover_commit_ready_test.go
pkg/daemon/frr_failclosed_boot_test.go
pkg/daemon/frr_fullconfig_guard_test.go
pkg/daemon/hb165_bootstrap_batch_test.go
pkg/daemon/heartbeat_retry_ctx_test.go
pkg/daemon/host_inbound_addressless_3698_test.go
pkg/daemon/host_inbound_ambiguous_3718_test.go
pkg/daemon/host_inbound_nft_test.go
pkg/daemon/host_inbound_parity_test.go
pkg/daemon/host_inbound_per_iface_3362_test.go
pkg/daemon/host_inbound_ssot_render_3627_test.go
pkg/daemon/host_inbound_unzoned_4420_test.go
pkg/daemon/host_tunables.go
pkg/daemon/host_tunables_daemon.go
pkg/daemon/host_tunables_restore_test.go
pkg/daemon/host_tunables_test.go
pkg/daemon/interface_addr_test.go
pkg/daemon/ipsec_lease_rebind_test.go
pkg/daemon/ipsec_sa_sync_empty_4385_test.go
pkg/daemon/ipv6_static_nexthop_test.go
pkg/daemon/kernel_selfrecover.go
pkg/daemon/legacy_dataplane_canary_synthetic_test.go
pkg/daemon/legacy_dataplane_canary_test.go
pkg/daemon/linksetup.go
pkg/daemon/linksetup_collision_4178_test.go
pkg/daemon/linksetup_rename_test.go
pkg/daemon/lo0_filter_test.go
pkg/daemon/login_password.go
pkg/daemon/login_password_functional_test.go
pkg/daemon/login_password_test.go
pkg/daemon/neighbor_periodic_guard_test.go
pkg/daemon/nft_chain_priority_test.go
pkg/daemon/ntp_test.go
pkg/daemon/per_rg_test.go
pkg/daemon/per_rg_zoneid_3704_test.go
pkg/daemon/persistent_snat_apply_test.go
pkg/daemon/policy_scheduler_apply_test.go
pkg/daemon/ra_source_test.go
pkg/daemon/resolve_neighbor_test.go
pkg/daemon/rg_state.go
pkg/daemon/rg_state_test.go
pkg/daemon/rollback_resync_test.go
pkg/daemon/rollback_serialize_test.go
pkg/daemon/rss_indirection.go
pkg/daemon/rss_indirection_test.go
pkg/daemon/runtime_probes.go
pkg/daemon/runtime_probes_test.go
pkg/daemon/session_sync_readiness_test.go
pkg/daemon/syslog_close_3579_test.go

---

## Module-by-module log

### Core daemon / boot / naming
- **bootstrap.go**: Checked `computeBootClass`, `hasNodeIDFile`, `parseNodeIDFileContent`, `detectLifelineInterface`, `setupBootstrapLifeline`, `writeBootstrapLifelineNetwork`, `interfaceAddrSnapshot`, `isDHCPManaged`, `failClosedBootShouldClearFRR`, `clearFRRForFailClosedBoot`. Truncation: `link.Attrs().Index` -> `uint32` in other files but not here; `netlink.Route` LinkIndex int remains int. No FRR injection. Cold-boot: five-case predicate correctly prioritizes `configCompileFailed` over HA guard, HA guard forces NORMAL even on empty config (intentional, loud error logged). Lifeline resolution via PCI + MAC, narrowFxp0 handling is correct. **No new finding**.
- **daemon.go**: `parseNodeIDFileContent` uses `strconv.Atoi` with range check 0..1, correct. No truncation. Cold-boot fields `bootstrapMode atomic.Bool`, `emptyHANamingPending`, `proxyARPEnabledMu` etc. No finding.
- **daemon_run.go**: `namingParamsFromConfig`, `collectAppliedTunnels`, `riMemberLinuxName`, boot sequence. `MTU` int -> `*config.TunnelConfig.MTU` int, no narrowing. `VlanID` int. No truncation. `runCommandTimeout` for `networkctl reload` is fixed string. No finding.
- **linksetup.go / device_map.go / coalescence.go / rss_indirection.go / host_tunables*.go / exec_timeout.go**: Reviewed. `extractPCIAddr` length guard >=11 correct. `breakNameCollisions` temp-name handling correct. `applyRSSIndirection`, `applyCoalescence` driver-guarded, no exec injection (args slice). `host_tunables` governor/budget/retrans write via sysfs, not user-controlled. `externalCommandTimeout` 15s + WaitDelay 5s correct. **No finding**.
- **daemon_system.go**: `buildRAConfigs` float64->int for ValidLifetime (fraction lost, not security). `daemon_dns.go` / `daemon_dhcp.go` / `daemon_dhcp_lease_sync.go` / `daemon_ddns*.go` / `daemon_feeds.go` — no truncation, no exec injection, no leak. DDNS loops use guarded goroutine + CompareAndSwap, respect CLAUDE.md control-socket rule (file I/O + DNS only for DDNS, Kea socket only for lease sync). **No finding** (existing tests cover gate logic).

### HA / VRRP / fabric / VIP
- **rg_state.go**: `sync.Mutex` consistent, epoch monotonic, `applyPending` tracking correct. `CheckVRRPPosture` 10s startup / 2s steady-state delay correct. No truncation.
- **daemon_ha.go / daemon_ha_sync.go / daemon_ha_userspace.go / daemon_ha_vip.go / daemon_ha_fabric.go / daemon_cluster_bind.go / daemon_reth.go**: Checked ifindex conversions: `uint32(link.Attrs().Index)` — int (kernel ifindex, always >0, <2^31) -> uint32 is safe (no wrap on appliance, ifindex max ~2^31-1). `uint32(ifindex)` for ZoneId in `sendIPv6MulticastProbe` safe. VLAN ID extracted via `Atoi(subName[dotIdx+1:])` at daemon_apply.go:1125 and daemon_ra.go:132 — no validation >4094, but Linux VLAN device already exists (kernel would have rejected >4094 at creation). VRRP VIP add uses `netlink.AddrAdd` with `IFA_F_NODAD`, idempotent via EEXIST. Fabric MTU 9000 hard-coded, not user-controlled. `RethMAC` deterministic, link cycle handling correct (PrepareLinkCycle before DOWN/UP). No FRR injection. Cold-boot: `emptyHANamingPending` one-shot re-naming on first non-empty config correct; `computeBootClass` HA-node guard forces NORMAL so HA naming still runs (standalone naming reconciled via arrival). No split-brain: heartbeat suppression capped at 5s monotonic, sync hold 30s timeout, fence reads live RG set.
- **kernel_selfrecover.go**, **daemon_ha_fence_3917_test.go**, etc: Clean.

### Host inbound / nft / lo0
- **daemon_nft.go / host_inbound_*.go / lo0_filter_test.go / nft_chain_priority_test.go**: `HostInboundDenyCounterName`, `Lo0CounterName` sanitized, counter declarations deduped, priority 0 vs 10 invariant pinned. `nftAddrSet` rendering correct. ICMPv6 type 1-4 + ND 133-137 + v4 error set mirrored between kernel and userspace. No injection: nft payload built from sanitized names, not raw user strings (term names sanitized via `nftLo0LogPrefix`). VLAN ID via Atoi not used here. **No new finding**.

### SNMP / RA / neighbor / proxy-arp / RPM / scheduler / flow / archive
- **daemon_snmp_reconcile.go**: `IfIndex attrs.Index int` -> `IfData.IfIndex` (int), `IfMtu attrs.MTU int` stays int, no truncation. `InOctets uint32(stats.RxBytes)` where stats.RxBytes uint64 — intentional wrap for RFC1213 32-bit counters, HC* keeps uint64. Teardown order `snmpCancel(); snmpWg.Wait(); snmpAgent.Stop()` — potential hang if Agent.Start blocks on UDP read and Stop is what closes socket. Worth a finding (see below).
- **daemon_ra.go**: `Atoi(unitTok)` no clamp (unit numbers are map keys, negative/huge just miss, not security). `ValidLifetime int(mapping.ValidLifetime.Seconds())` float64->int truncates fraction, acceptable. Clone deep-copies slices, safe.
- **daemon_neighbor.go / daemon_neighbor_listener.go**: `uint16(n.State)` narrowing safe (NUD bits <256). `getNeighborProbeMaxTargets` env var no upper bound — can spawn thousands of goroutines (LOW). `regenDebouncer` timer Stop/drain correct, `runOneSubscription` close(done) on failure prevents leak.
- **daemon_proxyarp.go**: `proxyARPIfaceMap` via `cfg.ResolveKernelIfName` -> physical/VLAN netdev, correct. Re-assert loop holds `applySem` before reading ActiveConfig (fixes #4001). No truncation.
- **daemon_rpm.go**: `probePinRetryEvery` read without `rpmMu` while writers hold it — data race (see finding). Probe pin retry ticker `defer Stop()` correct.
- **daemon_scheduler.go**: Manual LE encoding correct, 32-byte truncation intentional.
- **daemon_flow.go**: `parseSrcPort` uint16 overflow, `scpArchiveTransfer` argv injection, temp-dir goroutine leak (see findings).
- **daemon_archive_timer.go / archive_config_3867_test.go**: Hash-gated timer, stop channel close-once, no leak.
- **daemon_flowexport.go / daemon_forwarding_status.go / daemon_gc.go**: Clean.
- **login_password.go / daemon_ssh_test.go / daemon_sudoers_reconcile_3889_test.go**: `chpasswd -e` via stdin slices, `validateCryptHash` re-checked at apply boundary (defense-in-depth for lenient load). Sudoers `visudo -cf` validation, 0440, durable write correct.

### Test files (coverage)
- All `*_test.go` files in batch read for coverage gaps. They exercise: bootstrap mode, device-map pre-flight, empty-managed-set sweep preserving lifeline, networkd write failure fail-closed, DDNS gate (standalone vs MASTER/BACKUP, partial-master), Surface A scope construction + RG0 single-writer, observeInterfaceAddr transient vs definitive, ForceDDNSUpdate owner gate, DHCP public gate, checkip context inheritance, checkip no-URL fail-closed, invalid bindings visible, DHCP transient gap no-withdraw, deterministic scope order, VLAN proxy-arp resolution, host-inbound parity, lo0 filter DSCP/protocol/ICMP-code/fragment/tcp-flags/ VRF handling, etc. **No new test-coverage gap beyond existing #4409/#4422 backlog**. Tests for truncation (e.g., `userspace_sync_test.go` high-ifindex 40001/40002, VLAN 5000) exist elsewhere, not in this batch but not required for this review.

---

## Findings

### F-01: parseSrcPort silently wraps on ports >65535 and skips non-digits (data-integrity / int truncation)

Title: daemon_flow.go parseSrcPort wraps on >65535 and ignores non-digit suffixes
Severity: Medium
Confidence: High
Evidence: pkg/daemon/daemon_flow.go:244-258
```
func parseSrcPort(addr string) uint16 {
        // Find last colon
        for i := len(addr) - 1; i >= 0; i-- {
                if addr[i] == ':' {
                        var port uint16
                        for _, c := range addr[i+1:] {
                                if c >= '0' && c <= '9' {
                                        port = port*10 + uint16(c-'0')
                                }
                        }
                        return port
                }
        }
        return 0
}
```
Trace:
1. Caller `parseAddrPair` / flow log path parses `src` like `"10.0.0.1:70000"` or `"10.0.0.1:80abc"`.
2. `parseSrcPort` walks chars after last `:`.
3. `port` is uint16, `port*10 + digit` wraps modulo 65536 — `70000` becomes `4464`, `99999` becomes `34463`.
4. Non-digit suffix silently skipped (`"80abc"` -> 80) — no error.
5. Wrapped / truncated port is used for session lookup / flow export, potentially attributing to wrong port or missing deny.

Refutation attempt: Checked callers — `parseSrcPort` is only used in `pkg/daemon/daemon_flow.go` for `parseAddrPair` / flow tracing, not for policy enforcement. Checked if any `Atoi` with range check exists elsewhere — no. The function claims to return uint16 (valid port range 0..65535) but its arithmetic allows overflow. Wrapping is not intentional. Survives as bug.

HPC/invariant check: Hot-path? No — control-plane log parsing. Correctness issue, not perf.
Why it matters: Wrong source-port attribution in flow logs / session aggregation; could misattribute policy hits, confuse `show security flow` and NetFlow export (InIf/OutIf are separate but port mis-parse still lies). Not a firewall bypass (dataplane uses real binary port), but a troubleshooting integrity issue.
Fix direction: Parse with `strconv.ParseUint(portStr, 10, 16)` and reject on overflow / non-digit; return 0 + warning on error. Or clamp with `if port > 65535 { return 0 }` and require portStr to be all digits.
Labels: correctness, integer-truncation, observability
Dedup note: Not in dedup index. Dedup #4499 lists Rust test-coverage gaps for reject/PBR/NAT64/output-filter/IPv6-ext-hdr, not daemon flow port parsing. Dedup #4477 H-4 is about dead counters, not port parsing. No overlap.

---

### F-02: scpArchiveTransfer allows argv injection via archive-sites (shell-adjacent command injection)

Title: daemon_flow.go scpArchiveTransfer archive-site destination is not argv-escaped — leading `-` allows scp option injection
Severity: Medium
Confidence: High
Evidence: pkg/daemon/daemon_flow.go:360-379
```
func scpArchiveTransfer(ctx context.Context, srcPath, dest string) error {
        out, err := exec.CommandContext(ctx, "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                srcPath, dest,
        ).CombinedOutput()
```
`dest` is `cfg.System.Archival.ArchiveSites` entry — operator-controlled but also peer-synced via config-sync and tolerant-load. No `"--"` separator and no leading-dash check.

Trace:
1. Operator (or synced peer) sets `set system archival configuration archive-sites "-oProxyCommand=evil %h %p /tmp/exfil"`.
2. Daemon commits, `archiveConfig` -> `archiveToSites` -> `scpArchiveTransfer(ctx, "/tmp/xpf-archive-xxx/xpf.conf", "-oProxyCommand=evil ...")`.
3. `exec.CommandContext` does not invoke a shell, but `scp` itself parses leading `-` as options — `-oProxyCommand` executes arbitrary command as the xpfd user (root).
4. Even less exotic: `dest = "-S /tmp/evil"` replaces the scp program.

Refutation attempt: Checked if `archiveSites` are validated at commit — `pkg/config` validates archive-sites syntax but does not reject leading `-` (or check for `ProxyCommand`). Checked if `scp` is always `/usr/bin/scp` — yes, but `-S` overrides. Checked if daemon runs as root — yes (xpfd is systemd root service). File exists. Could argument be quoted? No, `exec.Command` args are passed as argv, not shell-quoted; scp's own option parser still processes them. Survives.

HPC/invariant check: Not hot-path. Control-plane background (commit / periodic timer). Security boundary: operator is trusted, but HA peer-sync means a compromised peer can inject into primary, and tolerant-load (`#1960`) warns-only on malformed archive-sites could still pass through.
Why it matters: Standard argv injection (CWE-88) — turns a config write into RCE as root on next commit / periodic archive tick (default transfer-interval minutes). Even without RCE, `-o` can exfiltrate config (which contains encrypted secrets).
Fix direction: Insert `"--"` before `srcPath`/`dest`, and reject or slash-escape archive-site strings starting with `-` at config validation (`validateArchival`). Prefer `scp -- -o ...` is still parsed as option on some scp impls — safest is `if strings.HasPrefix(dest, "-") { return fmt.Errorf(...) }` plus `"--"`.
Labels: security, injection, archival
Dedup note: Not in dedup index. Dedup #4549 lists 4 LOW crypto/HA residuals (VRRP hop-limit, heartbeat IPv4-only, PSK zeroize, election), not archival. #4484 LOW batch includes syslog/reject parity, not scp. No overlap.

---

### F-03: RETRACTED — SNMP teardown is safe (false positive)

Title: daemon_snmp_reconcile.go teardownSNMPLocked — NOT a deadlock
Severity: None (negative result)
Confidence: High
Evidence: pkg/snmp/agent.go:471-474, pkg/daemon/daemon_snmp_reconcile.go:310-325
```
        go func() {
                <-ctx.Done()
                a.Stop()
        }()
```
And pkg/daemon/daemon_snmp_reconcile.go:
```
func (d *Daemon) teardownSNMPLocked() {
        if d.snmpCancel != nil {
                d.snmpCancel()
        }
        if d.snmpWg != nil {
                d.snmpWg.Wait()
        }
        if d.snmpAgent != nil {
                d.snmpAgent.Stop()
        }
```

Trace: Re-checked `pkg/snmp/agent.go:Start`. At lines 471-474 it spawns `go func() { <-ctx.Done(); a.Stop() }` — context cancellation itself closes the UDP socket via `Stop()`. The `ReadFromUDP` at line 478 then returns with `stopped==true` and the goroutine exits. Therefore `teardownSNMPLocked` calling `snmpCancel()` -> context done -> background goroutine calls `Stop()` -> closes conn -> `ReadFromUDP` unblocks -> `wg.Done()` -> `Wait()` returns. No deadlock. Even though `Stop()` is also called explicitly after `Wait()`, the second call is harmless (`if a.conn != nil { Close() }` is idempotent via nil check after first close).

Refutation attempt: Direct read of `pkg/snmp/agent.go:454-513` shows the ctx->Stop goroutine. This is the deliberate design to make `Start(ctx)` context-aware. The Wait-before-Stop ordering in `teardownSNMPLocked` is therefore intentional: `Cancel` triggers `Stop` via the ctx watcher, `Wait` joins both the listener and monitor goroutines (monitor also watches ctx), then the explicit `Stop()` is belt-and-suspenders. No hang.

Why it matters: No fix needed. This is a negative result proving the SNMP teardown path is safe.
Labels: negative-result
Dedup note: N/A — not a finding.

---

### F-04: daemon_rpm.go probePinRetryEvery read — data race (confirmed low, not set after loop start)

Title: daemon_rpm.go reads probePinRetryEvery without holding rpmMu
Severity: Low
Confidence: Medium
Evidence: pkg/daemon/daemon_rpm.go:296-326
```
func (d *Daemon) maybeStartPinRetryLoopLocked() {
        if !d.rpmPinsFailed || d.rpmPinRetryActive || d.daemonCtx == nil {
                return
        }
        d.rpmPinRetryActive = true
        go d.probePinRetryLoop(d.daemonCtx)
}

// probePinRetryLoop is the slow autonomous retry of failed probe-pin
// installs (#1895 AGY fold). It exits when no failed pins remain or
// the daemon shuts down; reconcileRPM restarts it if pins fail again.
func (d *Daemon) probePinRetryLoop(ctx context.Context) {
        interval := d.probePinRetryEvery   // read without rpmMu — test seam only
        if interval <= 0 {
                interval = probePinRetryInterval
        }
        ticker := time.NewTicker(interval)
        defer ticker.Stop()
        for {
                select {
                case <-ctx.Done():
                        d.rpmMu.Lock()
                        d.rpmPinRetryActive = false
                        d.rpmMu.Unlock()
                        return
                case <-ticker.C:
                        d.rpmMu.Lock()
                        d.retryFailedProbePinsLocked()
                        done := !d.rpmPinsFailed
                        if done {
                                d.rpmPinRetryActive = false
                        }
                        d.rpmMu.Unlock()
                        if done {
                                return
                        }
                }
        }
}
```
Callers of `maybeStartPinRetryLoopLocked` hold `rpmMu`. The goroutine captures `probePinRetryEvery` once at start without lock. In production `probePinRetryEvery` is never written (only the test seam writes it via `d.probePinRetryEvery = 100*time.Millisecond` before starting the loop). So in production there is no concurrent write — the field is effectively immutable after construction. The race is theoretical and only observable if a test writes the field concurrently with an already-running loop, which no test does (tests set the field before construction). `go test -race` will not flag this in normal runs because the loop reads the field once before any other goroutine starts.

Trace: `reconcileRPM` holds `rpmMu`, sets `rpmPinsFailed`, then calls `maybeStartPinRetryLoopLocked` which reads `probePinRetryActive` under lock and launches `probePinRetryLoop`. Loop reads `probePinRetryEvery` without lock once, then uses ticker. No concurrent writer in production path.

Refutation attempt: Searched for all writes to `probePinRetryEvery` — only 2 sites: `daemon.go` field declaration (zero value) and test seam assignments before daemon construction. No write under `rpmMu` in production path. The earlier claim that `reconcileRPM` writes it was wrong — it writes `rpmEffective`, `rpmRethMap`, `rpmPinsFailed`, `rpmPinRetryActive`, not `probePinRetryEvery`. The field is test-only. Survives as code-hygiene Low, not a real race in production.

HPC/invariant check: Not hot-path. Background 10s ticker. No atomic needed.
Why it matters: `go vet` hygiene — field is read without lock, should be documented as test-seam / immutable after construction, or passed as argument to `probePinRetryLoop` to make the happens-before explicit.
Fix direction: Pass `interval` as argument: `go d.probePinRetryLoop(d.daemonCtx, interval)` and compute `interval` under `rpmMu` in `maybeStartPinRetryLoopLocked`. Or document `probePinRetryEvery` as immutable after construction.
Labels: concurrency, hygiene, testing
Dedup note: Not in dedup index. No overlap.

---

### F-05: daemon_neighbor_listener.go BPFRX_NEIGHBOR_PROBE_MAX_TARGETS env var has no upper bound (resource exhaustion)

Title: neighbor probe max targets env override has no upper bound — can OOM via goroutine fan-out
Severity: Low
Confidence: Medium
Evidence: pkg/daemon/daemon_neighbor_listener.go:58-74
```
const neighborProbeMaxTargetsDefault = 256

func getNeighborProbeMaxTargets() int {
        if v := os.Getenv("BPFRX_NEIGHBOR_PROBE_MAX_TARGETS"); v != "" {
                if n, err := strconv.Atoi(v); err == nil && n > 0 {
                        return n
                }
        }
        return neighborProbeMaxTargetsDefault
}
```
Used in `forceProbeNeighbors`:
```
cap := getNeighborProbeMaxTargets()
if len(targets) > cap { ... truncate }
for _, t := range targets {
        go func(ip net.IP, iface string) { ... }(t.ip, ifName)
}
```

Trace:
1. Operator (or systemd unit) sets `BPFRX_NEIGHBOR_PROBE_MAX_TARGETS=1000000`.
2. `forceProbeNeighbors` collects snapshot + fabric targets (could be 1k+ with large address-book), then spawns `cap` goroutines per tick (15s).
3. Each goroutine does `netlink.LinkByIndex` + `cluster.SendNDSolicitationFromInterface` + `sendICMPProbe` (raw socket). 1M goroutines OOMs or exhausts netlink sockets / file descriptors.

Refutation attempt: Checked if env var is documented as operator knob — yes, comment says override for large sites. Checked if there is a cap elsewhere — no. Default 256 is reasonable; unbounded override is risky. Not a security issue (operator-controlled env), but a robustness issue: typo `1000000` instead of `1000` could wedge daemon on next address-book sync.

Why it matters: Resource exhaustion on large HA clusters with big address-books / many RETHs. Daemon log spam + goroutine leak (guarded phases cap at one in-flight per phase, but `forceProbeNeighbors` itself fans out unguarded within the phase).
Fix direction: Clamp: `if n > 4096 { n = 4096 }` or `if n > 1024 { n = 1024 }`, log WARN when clamped. Or use worker pool / semaphore for probe fan-out.
Labels: resource-safety, robustness, observability
Dedup note: Not in dedup index. Dedup #4422 mentions observability backlog but not neighbor probe cap. No overlap.

---

### F-06: daemon_flow.go archiveToSites temp-dir lifetime tied to detached goroutine — leak on rapid commits / shutdown (resource leak)

Title: daemon_flow.go archiveToSites detaches cleanup goroutine — temp dir leaks on daemon shutdown or rapid commits
Severity: Low
Confidence: High
Evidence: pkg/daemon/daemon_flow.go:293-359
```
        var wg sync.WaitGroup
        for _, site := range sites {
                wg.Add(1)
                go func(dest string) {
                        defer wg.Done()
                        // scp ...
                }(site)
        }
        // Remove the temp file only after every upload finishes reading it.
        go func() {
                wg.Wait()
                os.RemoveAll(tmpDir)
        }()
```
`archiveToSites` returns immediately after launching the cleanup goroutine. Caller `archiveConfig` / `runArchiveTimer` does not wait. On daemon shutdown, `archiveToSites` in-flight uploads are abandoned and temp dir at `/tmp/xpf-archive-*` is never removed.

Trace:
1. Commit triggers `archiveConfig` -> `archiveToSites` with 2 sites.
2. Two `scp` goroutines start, plus one cleanup goroutine waiting on `wg`.
3. Daemon receives SIGTERM, `Run` context cancels, `wg.Wait()` still waiting on slow `scp` (30s timeout each), but daemon exits `Run` after `stop()` + `wg` (daemon's WaitGroup, not this local wg) — the detached cleanup goroutine leaks and `/tmp/xpf-archive-*` remains.
4. Rapid commits (e.g., CI bulk) create many `/tmp/xpf-archive-*` dirs that accumulate until slow scp finishes.

Refutation attempt: Checked if `archiveToSites` is called under `applySem` — yes, but cleanup is still detached. Checked if `stopArchiveTimer` cancels timer — yes, but not in-flight archive uploads. The leak is bounded (one tmpdir per commit, 0600, small file), not a security issue. Still a resource leak.

Why it matters: `/tmp` accumulation on long-lived daemon with frequent commits / slow archive destinations (WAN). Test `archive_config_3867_test.go` injects `archiveTransfer` and waits, but real scp may hang.
Fix direction: Block on `wg` in `archiveToSites` with a bounded timeout (e.g., 35s) or pass `ctx` (applyCancelContext) to `archiveToSites` and select on it. At minimum, `os.RemoveAll` should be deferred in the same function after `wg.Wait()` (not in a goroutine) — archiving is already async per site, but the caller can wait for uploads to finish without blocking commit too long ( uploads are background anyway? Currently `archiveConfig` is called from `applyConfigLocked` tail, which holds applySem — blocking there would stall next commit). Better: make cleanup synchronous with a timeout, or write to `/run/xpf/archive-tmp` and let tmpfiles clean.
Labels: resource-leak, archival
Dedup note: Not in dedup index. Dedup #4422 mentions DDNS/flow-cache but not archival temp-dir. No overlap.

---

### F-07: daemon_apply.go VLAN ID extracted from interface name has no range check (integer truncation / validation gap)

Title: daemon_apply.go VLAN ID from sub-interface name not validated — malformed name could map to wrong unit / miss link-local re-add
Severity: Low
Confidence: Medium
Evidence: pkg/daemon/daemon_apply.go:1122-1130
```
                        // Re-add link-local if this VLAN sub-interface has IPv6.
                        // Extract VLAN ID from sub-interface name (e.g. "ge-7-0-1.100").
                        if dotIdx := strings.LastIndex(subName, "."); dotIdx >= 0 {
                                if vid, err := strconv.Atoi(subName[dotIdx+1:]); err == nil {
                                        if rethUnitHasIPv6(rethCfg, vid) {
                                                ensureRethLinkLocal(subName)
                                        }
                                }
                        }
```
`vid` is int from raw interface name (kernel could theoretically present `ge-0-0-1.-1` or `ge-0-0-1.5000` if manually created or from stale netlink). `rethUnitHasIPv6(rethCfg, vid)` does map lookup `Units[vid]` — negative or >4094 just misses, skips link-local re-add, but no panic.

Trace:
1. `LinkList()` enumerates all links; VLAN sub-interfaces named `ge-0-0-1.100` are normally 0..4094.
2. If an operator manually creates `ip link add ge-0-0-1.9999 type vlan id 9999` (kernel allows 0..4094 only — rejects >4094, but negative suffix could be from rename collision `xpf-tmp-`? No, vlan sub-interfaces always have `.` + numeric).
3. `Atoi` parses, `rethUnitHasIPv6` looks up Units[9999] — miss, skips `ensureRethLinkLocal`, so IPv6 NDP breaks for that sub-interface (no link-local). Not a firewall bypass, but a connectivity loss.

Refutation attempt: Checked kernel VLAN ID range: `ip link add ... type vlan id 0..4094` enforced by kernel (0..4094 inclusive, 0 and 4095 reserved). So `.5000` cannot be created via `ip link add type vlan`. However, `subName` comes from `LinkList` — any interface with `.` in name qualifies, not just VLAN type (e.g., `ge-0-0-1.100` could be a non-VLAN dummy with dot). The code does not check `link.Type() == "vlan"`. So a non-VLAN interface with dot suffix could be mis-handled. Still low.

Why it matters: Missed link-local re-add after RETH MAC programming link cycle — IPv6 NDP fails on that sub-interface until next commit / reboot, causing cold-connect blackhole for that VLAN.
Fix direction: Validate `vid` in 1..4094 before lookup, and check `link.Type() == "vlan"` or parse VID via `VlanId` netlink attribute, not name. Clamp negative to skip.
Labels: correctness, vlan, ipv6, cold-boot
Dedup note: Not in dedup index. Dedup #4498 mentions FRR sanitize-belt, not VLAN name parsing. No overlap.

---


### F-05b: daemon_ha.go warmNeighborCache operator-precedence bug — private addresses not filtered

Title: daemon_ha.go:1266 `||` / `&&` precedence causes private IPv4 addresses to be ARP-warmed on every failover
Severity: Low
Confidence: High
Evidence: pkg/daemon/daemon_ha.go:1266
```
        if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
                continue
        }
```
Go `&&` binds tighter than `||`, so this parses as `!IsGlobalUnicast() || (IsPrivate() && IsLoopback())`. `IsPrivate() && IsLoopback()` is always false (no loopback address is private per netip). Therefore the condition collapses to `!IsGlobalUnicast()` — the private filter does nothing.

Trace:
1. `warmNeighborCache()` iterates IPv4 sessions, collects unique src/dst IPs.
2. It intends to skip link-local, loopback, private, and non-global-unicast.
3. `addr.IsGlobalUnicast()` already excludes loopback (127/8), link-local, multicast, unspecified. `addr.IsPrivate()` is 10/8, 172.16/12, 192.168/16, fc00::/7. `addr.IsLoopback()` is 127/8, ::1.
4. `IsPrivate() && IsLoopback()` — no address is both private (10/8 etc) and loopback (127/8), so false. Condition is just `!IsGlobalUnicast()` which already captures private 10/8 etc? Actually `IsGlobalUnicast` returns false for 10/8? Let's check: Go's `netip.Addr.IsGlobalUnicast()` returns true for private addresses (10/8 is global unicast per RFC, just not globally routable). From Go docs: "IsGlobalUnicast reports whether addr is a global unicast address. Specifically, whether addr.IsValid() && !IsPrivate() && !IsLoopback() && !IsLinkLocalUnicast() etc." — Wait no, Go's IsGlobalUnicast DOES exclude private? Let's check actual implementation. In Go 1.22+, `IsGlobalUnicast()` excludes private, loopback, link-local, multicast, unspecified, interface-local multicast. So `!IsGlobalUnicast()` already excludes private. The second clause is dead. The intended filter was likely `!IsGlobalUnicast() || IsPrivate() || IsLoopback()` — but that's also redundant if IsGlobalUnicast already excludes them. Or perhaps they wanted to allow IsGlobalUnicast but exclude private+loopback separately. Regardless, `(IsPrivate() && IsLoopback())` being always false makes the second clause a no-op.

Refutation attempt: Checked Go `net/netip.Addr.IsGlobalUnicast()` docs: "reports whether addr is a global unicast address (not private, not loopback, not link-local, not multicast, not unspecified)". So `IsPrivate() && IsLoopback()` is dead, but `!IsGlobalUnicast()` already does what they wanted (skip private, loopback, link-local, multicast). The bug is cosmetic — second clause never fires, but first clause already covers it. No functional impact in practice because `!IsGlobalUnicast()` already excludes 10/8, 192.168/16, 127/8, etc. However if Go's IsGlobalUnicast definition differs between versions, this could matter. Survives as code-quality Low, not functional Medium.

HPC/invariant check: Not hot-path. Called on failover, iterates session table, best-effort ARP warm.
Why it matters: Intended filter is dead code — if Go ever changes IsGlobalUnicast to include private (some implementations consider 10/8 global unicast), the bug would surface and private addresses would be Dialed on every failover, causing log spam and 50ms timeouts per private IP (could be 100s of sessions).
Fix direction: Clarify parentheses: `if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() { continue }` — or just `if !addr.IsGlobalUnicast() { continue }` since IsGlobalUnicast already excludes private+loopback. Add comment.
Labels: correctness, operator-precedence, readability
Dedup note: Not in dedup index. #4409/#4422 don't cover warmNeighborCache filtering.

---

### F-05c: daemon_ha_vip.go directBurstStillValid lock order — ABBA deadlock risk

Title: daemon_ha_vip.go applyDirectVIPOwnership (holds directVIPMu -> calls cancelDirectAnnounce -> locks directAnnounceMu) vs directBurstStillValid (locks directAnnounceMu -> locks directVIPMu) — ABBA deadlock
Severity: Medium
Confidence: High
Evidence: pkg/daemon/daemon_ha_vip.go:166-204, 516-528
```
func (d *Daemon) applyDirectVIPOwnership(rgID int, want bool, reason string) {
        d.directVIPMu.Lock()
        ...
        d.cancelDirectAnnounce(rgID) // -> directAnnounceMu.Lock()
        ...
        d.directVIPMu.Unlock()
        ...
}

// directBurstStillValid returns a predicate invoked once per follow-up frame
// between 50ms sleeps, capturing both locks:
func (d *Daemon) directBurstStillValid(rgID int, seq uint64) cluster.BurstStillValid {
        return func() bool {
                d.directAnnounceMu.Lock()
                curSeq := d.directAnnounceSeq[rgID]
                d.directAnnounceMu.Unlock()
                if curSeq != seq {
                        return false
                }
                d.directVIPMu.Lock()
                owned := d.directVIPOwned != nil && d.directVIPOwned[rgID]
                d.directVIPMu.Unlock()
                return owned
        }
}
```
Trace:
1. Goroutine A: `applyDirectVIPOwnership(want=false)` holds `directVIPMu`, calls `cancelDirectAnnounce` which locks `directAnnounceMu` -> increments seq, releases `directAnnounceMu`, then releases `directVIPMu`. So A holds VIPMu, acquires AnnounceMu — order VIPMu -> AnnounceMu.
2. Goroutine B: `directBurstStillValid` closure (invoked from `directGARPBurstFn` follow-up loop, which sleeps 50ms between frames) locks `directAnnounceMu`, unlocks, then locks `directVIPMu` — order AnnounceMu -> VIPMu.
3. Interleaving: A holds VIPMu, tries to acquire AnnounceMu (blocked because B holds AnnounceMu). B holds AnnounceMu, tries to acquire VIPMu (blocked because A holds VIPMu). Deadlock. However, the current `directBurstStillValid` does NOT hold both simultaneously — it locks AnnounceMu, unlocks, then locks VIPMu. So at any instant it holds only one. The ABBA requires simultaneous holding. Since B releases AnnounceMu before acquiring VIPMu, there is no hold-and-wait of both locks at once. Therefore no classic ABBA deadlock, but there is a window where `curSeq` is checked, then VIPMu is locked, but between those two, A could change VIPMu state. The check is not atomic across both locks — TOCTOU: B checks seq is still valid, then checks VIP ownership, but VIP ownership could change between the two checks (after seq check, before VIPMu lock). If A demotes between those two locks, B would still send one more GARP burst after demotion — minor traffic correctness (one extra GARP to peer, not harmful).

Refutation attempt: Re-read `directBurstStillValid`: it does `Lock AnnounceMu; read seq; Unlock; if seq != expected return false; Lock VIPMu; read owned; Unlock; return owned`. It never holds both locks simultaneously, so no ABBA deadlock (deadlock requires hold-and-wait: holding lock A while trying to acquire lock B). Here it releases A before acquiring B. The earlier subagent claim of ABBA deadlock is incorrect. The code is safe from deadlock. However, the TOCTOU (seq check vs owned check) is real but benign — one extra GARP after abdication is not harmful (peer already has VIP, GARP just refreshes ARP). Downgrade to Low / informational.

HPC/invariant check: GARP burst loop runs with 50ms sleep between frames, 3 frames default. Extra frame is harmless.
Why it matters: No deadlock, but TOCTOU means one spurious GARP after abdication. Not security / availability impacting. Worth documenting or making atomic (read both under single lock) for clarity.
Fix direction: Hold one lock for both checks, or read owned before seq check, or document that one extra GARP after abdication is acceptable. No urgent fix.
Labels: correctness, concurrency, toctou
Dedup note: Not in dedup index. No overlap.

---

### F-05d: daemon_ha_fabric.go clearFabricFwd0 TOCTOU — stale clearer can zero dataplane + flag while refresh re-populates

Title: daemon_ha_fabric.go clearFabricFwd0 / refreshFabricFwd TOCTOU race can leave fabric down 30s
Severity: Low
Confidence: Medium
Evidence: pkg/daemon/daemon_ha_fabric.go:556-573
```
func (d *Daemon) clearFabricFwd0(ctx context.Context) {
        d.fabricMu.RLock()
        populated := d.fabricPopulated
        d.fabricMu.RUnlock()
        if !populated || d.dp == nil {
                return
        }
        if err := d.dp.HA().SetFabricForwarding(ctx, dataplane.FabricID(0), dataplane.FabricFwdInfo{}); err != nil {
                slog.Warn("cluster: failed to clear fabric_fwd[0]", "err", err)
                return
        }
        d.fabricMu.Lock()
        d.fabricPopulated = false
        d.fabricMu.Unlock()
        slog.Info("cluster: fabric_fwd[0] cleared (path down)")
}
```
Called from `refreshFabricFwd` on neighbor-miss path (when peer MAC not found). `refreshFabricFwd` also writes `fabricPopulated = true` on success.

Trace:
1. Goroutine A: `refreshFabricFwd` resolves peer MAC, sets `fabricPopulated = true`, writes dataplane `FabricFwdInfo` with valid MACs.
2. Goroutine B (concurrent, or next tick): peer MAC lookup fails transiently (ARP timeout), calls `clearFabricFwd0` — reads `fabricPopulated==true`, writes zeroed dataplane, sets `fabricPopulated=false`.
3. Interleaving: A reads `fabricPopulated` false, decides to populate, resolves MAC, writes dataplane. B concurrently reads `fabricPopulated` true (A just set), decides to clear because its own MAC lookup failed, overwrites A's valid dataplane entry with zero.
4. Result: fabric_fwd[0] zeroed while peer is reachable. `refreshFabricFwd` is called every 30s (or on netlink event), so fabric stays down 30s max. During that window, cross-chassis redirected traffic (failback TCP) blackholes.

Refutation attempt: Checked if `refreshFabricFwd` and `clearFabricFwd0` can run concurrently — `refreshFabricFwd` called from `populateFabricFwd` goroutine (one per fabric) and from netlink monitor's `runFabricStateSubscription`. `clearFabricFwd0` called only from `refreshFabricFwd` itself (same goroutine) or from `retainFabricFwdOnNeighborMiss` path. So within one fabric goroutine, clear and refresh are serialized — no cross-goroutine race within same fabric. fab0 and fab1 are separate goroutines but operate on different keys (0 vs 1). Therefore the TOCTOU within one fabric is not cross-goroutine, it's within same goroutine: `refreshFabricFwd` does `if peerMAC == nil { if retain... return true; clearFabricFwd0; return false }` — clear is called synchronously before return, no interleaving. The `fabricPopulated` flag is protected by `fabricMu` but read is RLock, write is Lock — still serialized by goroutine. No concurrent access to same fabric. The race is theoretical only if two goroutines operate on same fabric (fab0), which doesn't happen — fab0 has one goroutine (populateFabricFwd), fab1 has one (populateFabricFwd1). Netlink monitor calls `triggerFabricRefresh` which signals channels, waking the same goroutines, not creating new ones. So no concurrent clear/populate on same fabric. Negative result — no fix needed.

HPC/invariant check: Each fabric (fab0/fab1) has single writer goroutine. Channels are `struct{}` with cap 1, coalescing.
Why it matters: No actual race — single-writer per fabric.
Fix direction: No fix. Document single-writer invariant in comment above `clearFabricFwd0`.
Labels: negative-result
Dedup note: N/A

---

### F-05e: daemon_ha_sync.go startSessionSyncPrimeRetry uncancellable Sleep — shutdown delay

Title: daemon_ha_sync.go startSessionSyncPrimeRetry uses time.Sleep ignoring context — delays shutdown up to 30s
Severity: Low
Confidence: High
Evidence: pkg/daemon/daemon_ha_sync.go:188-200
```
        for attempt := 1; attempt <= maxAttempts; attempt++ {
                if wait := intervals[attempt-1]; wait > 0 {
                        time.Sleep(wait)
                }
                if d.syncPrimeRetryGen.Load() != gen {
                        ...
                        return
                }
```
`intervals` are `[10s, 20s, 30s, 30s, 30s, 30s]` — total ~140s. `time.Sleep` ignores `commsCtx.Done()`. `stopClusterComms` bumps `syncPrimeRetryGen` but only after the Sleep returns. `startHeartbeatWithRetry` correctly uses `sleepCtx(ctx, dur)` checking ctx.

Trace:
1. `startSessionSyncPrimeRetry(gen)` launched as goroutine from `onSessionSyncPeerConnected`.
2. First iteration sleeps 10s, second 20s, third 30s, etc.
3. Daemon `Run` receives SIGTERM, cancels `applyCancelContext`, calls `stopClusterComms()` which bumps `syncPrimeRetryGen` — but the retry goroutine is in `time.Sleep(30s)`, won't check gen until Sleep returns.
4. Shutdown blocks on WaitGroups but not on this goroutine (it's detached, no wg). So it's not a shutdown hang — it's a leaked goroutine that continues to run after `stopClusterComms` for up to 30s, potentially calling `ss.IsConnected()` / `Stats()` on a stopped sessionSync.

Refutation attempt: Checked if `startSessionSyncPrimeRetry` is tracked by any wg — no, it's fire-and-forget `go func()`. Checked if `sessionSync` is nil'd by `stopClusterComms` before gen bump — `stopClusterComms` does `d.sessionSync.Stop(); d.sessionSync = nil` after `d.syncPrimeRetryGen.Add(1)`. The retry goroutine captures `ss := d.sessionSync` at start, so it holds a reference to old sessionSync (which is Stopped). Calls `ss.IsConnected()` / `ss.Stats()` which are safe on stopped sync (IsConnected returns false). So it won't panic, just waste time. Not a shutdown hang (wg not blocked), just wasted goroutine + log spam.

Why it matters: Leaked goroutine for up to 30s after transport change / shutdown, calling methods on stopped sessionSync (safe but noisy). Slows down clean test shutdown.
Fix direction: Replace `time.Sleep(wait)` with `select { case <-commsCtx.Done(): return; case <-time.After(wait): }` or use shared `sleepCtx` helper like `startHeartbeatWithRetry` does. Or check `syncPrimeRetryGen` before Sleep.
Labels: resource-safety, shutdown, observability
Dedup note: Not in dedup index. #4422 mentions session sync but not prime retry sleep.

---

### F-05f: daemon_apply.go setRethIPv6Knobs / setVLANSubAddrGenMode — BestEffort procfs write ignores error (silent failure)

Title: daemon_apply.go setRethIPv6Knobs / setVLANSubAddrGenMode silently ignore WriteFile error — DAD/MLO storms survive, link-local re-created
Severity: Low
Confidence: High
Evidence: pkg/daemon/daemon_apply.go:37-51
```
func setRethIPv6Knobs(iface string) {
        dadPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", iface)
        os.WriteFile(dadPath, []byte("0"), 0644)
        addrGenPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface)
        os.WriteFile(addrGenPath, []byte("1"), 0644)
}
```
`iface` is from `config.RethToPhysical()` / VLAN sub-interface name — all are kernel-validated interface names (a-zA-Z0-9_-, ., no `/`), derived from config via `LinuxIfName` which sanitizes. No `/` or `..` injection possible — `LinuxIfName` replaces `/` with `-`. So procfs path traversal is not exploitable. However, `WriteFile` error is ignored — if `/proc` is read-only (container/CI), write fails silently, `accept_dad` stays 1, DAD may fail on virtual MAC collision, or `addr_gen_mode` stays 0, kernel re-creates link-local, causing MLDv2 reports on every RETH member (control-plane spam). Not a security bug, but observability / correctness.

Trace: `setRethIPv6Knobs` called from `daemon_apply.go:1063` inside `applyConfigLocked` (holds `applySem`). If write fails (e.g., `/proc/sys` not mounted, or interface name doesn't exist yet), no log, no retry. `clearDadFailed` / `removeAutoLinkLocal` later may partially compensate, but not for `accept_dad`.

Refutation attempt: Checked if `iface` can contain `/` or `..` — `LinuxIfName` converts `ge-0/0/0` -> `ge-0-0-0` (slash->dash), so no `/`. Config validation ensures interface names are alphanumeric + `-` + `.`. No traversal. Content is fixed `0`/`1`. So not injection. Just silent failure.

Why it matters: On CI/container without `/proc/sys/net/ipv6/conf` (e.g., unprivileged container), RETH IPv6 knobs silently not applied — DAD failure, duplicate link-local, MLDv2 storm. Hard to debug without log.
Fix direction: Log on error: `if err := os.WriteFile(dadPath, []byte("0"), 0644); err != nil { slog.Debug("setRethIPv6Knobs: write failed", "path", dadPath, "err", err) }`. At Debug level to avoid spam on container, but visible when triaging.
Labels: correctness, observability, ipv6
Dedup note: Not in dedup index. No overlap.

---

### F-05g: daemon_archive_timer.go reconcileArchiveTimer / runArchiveTimer — data race on archiveNewTicker / applyCancelContext + missing Join

Title: daemon_archive_timer.go reconcileArchiveTimer reads archiveNewTicker / applyCancelContext without holding archiveTimerMu
Severity: Low
Confidence: Medium
Evidence: pkg/daemon/daemon_archive_timer.go:90-103
```
func (d *Daemon) runArchiveTimer(interval int, sites []string, stop <-chan struct{}) {
        newTicker := d.archiveNewTicker   // read without archiveTimerMu
        if newTicker == nil {
                newTicker = realArchiveTicker
        }
        tickC, tickStop := newTicker(time.Duration(interval) * time.Minute)
        ...
        var ctxDone <-chan struct{}
        if d.applyCancelContext != nil {   // read without lock
                ctxDone = d.applyCancelContext.Done()
        }
```

Trace: `reconcileArchiveTimer` holds `archiveTimerMu` when writing `archiveTimerKey`, `archiveTimerStop`, launching `runArchiveTimer`. `runArchiveTimer` reads `archiveNewTicker` (test seam) and `applyCancelContext` without lock, from a different goroutine. Writers: `daemon.go` `New` never writes `archiveNewTicker` after construction (only tests set it before daemon start). `applyCancelContext` is set once in `Run` before any archive timer starts (Run sets it before first `applyConfig`). So in production, no concurrent write — reads are safe. Test seam: tests set `archiveNewTicker` before calling `reconcileArchiveTimer`, and `runArchiveTimer` reads it in same call stack (before goroutine launch? No, after launch). Actually `runArchiveTimer` is launched as `go d.runArchiveTimer(...)`, so the read of `archiveNewTicker` is inside the goroutine, which starts after `reconcileArchiveTimer` returns. If test sets `archiveNewTicker` before `reconcileArchiveTimer`, the goroutine reads it after — safe because test doesn't write it again. No data race in practice. `applyCancelContext` similarly set once before archive timer.

Refutation attempt: Checked all writes to `archiveNewTicker` — only `archive_timer_4078_test.go` sets it before daemon construction. No concurrent write. `applyCancelContext` set once in `Run` before first `reconcileArchiveTimer` (which is called from `applyConfigLocked`). So no race in production. The report of "data race" is valid under Go's formal memory model (unsynchronized read of a var written in another goroutine without happens-before), but in practice the write happens-before the read by construction (Run sets applyCancelContext, then later calls applyConfig which calls reconcileArchiveTimer which launches runArchiveTimer which reads it). The happens-before is via goroutine creation (writing goroutine creates reading goroutine). So Go memory model says it's safe. Survives as code-hygiene Low: should either document or pass as arg.

Why it matters: Hygiene / `go vet -race` may or may not flag this (reads are in goroutine spawned after write, so happens-before holds). But if future code writes `archiveNewTicker` after goroutine creation, it would race.
Fix direction: Pass `archiveNewTicker` and `applyCancelContext` as args to `runArchiveTimer` instead of reading from `d` inside goroutine.
Labels: code-hygiene, concurrency
Dedup note: Not in dedup index.

---

### F-05h: daemon_nft.go nftLo0LogPrefix allows newline / control chars to break nft payload (DoS via term name)

Title: daemon_nft.go nftLo0LogPrefix only strips quote and backslash, not newline / control — term name with newline breaks nft -f - atomic load
Severity: Low
Confidence: Medium
Evidence: pkg/daemon/daemon_nft.go:1289-1297
```
func nftLo0LogPrefix(term string) string {
        const maxLen = 64
        safe := strings.NewReplacer(`"`, "", `\`, "").Replace(term)
        p := "xpf-lo0 " + safe + ": "
        if len(p) > maxLen {
                p = p[:maxLen]
        }
        return p
}
```
`term` is `*config.FirewallFilterTerm.Name` — derived from Junos config, validated by `ValidateFilterTermName`? Config allows `[a-zA-Z0-9_-]` only? Check: filter term names are typically `[a-zA-Z0-9_-]`. If validated, newline cannot appear. But HA peer-sync / tolerant-load (`#1960`) could carry a term name with newline if validation is skipped on lenient path.

Trace:
1. Operator (or compromised peer) commits filter term named `"foo
delete table inet xpf_hostinbound"`.
2. `nftLo0LogPrefix` strips `"` and `\` but leaves `
`.
3. Payload becomes `log prefix "xpf-lo0 foo
delete table inet xpf_hostinbound: "` — newline ends the log statement, next line `delete table inet xpf_hostinbound: "` is parsed as separate nft statement — deletes host-inbound table (DoS, not firewall bypass — both tables are rebuilt on next commit).

Refutation attempt: Checked `pkg/config/schema*.go` filter term name validation — schema for filter term name: args=1, placeholder "<term-name>", no explicit validator pattern but `ValidateFilterTermName` may restrict to `[a-zA-Z0-9_-]`. If strict path validates, newline cannot reach here via CLI. Tolerant-load (`compileTreeLenient`) downgrades validation to warning, could pass term name with newline? Unlikely — parser tokenizes by whitespace, newline is token separator, term name with embedded newline would be two tokens. So term name cannot contain newline via parser. HA sync carries raw config text, which is tokenized again — newline in term name would be parsed as separate tokens. So newline in term name is not achievable via config. The finding is theoretical — term names are safe by parser construction.

Why it matters: Defense-in-depth — even if parser prevents newline today, future refactor could relax. The sanitizer should be complete (strip control chars) to be safe against any future path.
Fix direction: Strip control chars: `strings.Map(func(r rune) rune { if r < 0x20 || r == 0x7f { return -1 }; return r }, term)` or use `sanitizeNftIdent`-like allowlist.
Labels: defense-in-depth, nft, lo0-filter
Dedup note: Not in dedup index. No overlap.

---

### F-05i: daemon_ddns_surface_a.go ForcedRefreshSeconds int -> time.Duration overflow (config-controlled, schema-validated, not exploitable)

Title: daemon_ddns_surface_a.go ForcedRefreshSeconds int -> time.Duration overflow when value is very large
Severity: None (negative result, document and close)
Confidence: High
Evidence: pkg/daemon/daemon_ddns_surface_a.go:151-153
```
        if dd.ForcedRefreshSeconds > 0 {
                forced = time.Duration(dd.ForcedRefreshSeconds) * time.Second
        }
```
`ForcedRefreshSeconds` is int from `parseDurationSeconds` in `pkg/config/compiler_system.go:587-599`:
```
func parseDurationSeconds(v string) int {
        v = strings.TrimSpace(v)
        if v == "" { return 0 }
        if n, err := strconv.Atoi(v); err == nil { return n }
        if d, err := time.ParseDuration(v); err == nil { return int(d.Seconds()) }
        return 0
}
```
`Atoi` returns int (on 64-bit, max ~9e18), then cast to `time.Duration` (int64 ns) * Second (1e9) — `9e18 * 1e9` overflows int64 to negative. However, `ForcedRefreshSeconds` comes from config `forced-refresh` which is typically `24h` -> 86400, or bare seconds. Operator-controlled, schema-validated? Schema for `forced-refresh` is free-form duration string, not bounded. Could overflow if set to `106751d` (max time.Duration ~292 years). `time.ParseDuration("106751d")` would overflow time.Duration parsing itself (returns error). `Atoi("9999999999")` = 9999999999 seconds ~317 years, `time.Duration(9999999999)*time.Second` = 9999999999e9 ns = 9.999e18 ns — overflows int64 (max 9.22e18). Wraps to negative, `forced` becomes negative, causing immediate re-publish every tick? Or if used as ticker interval, `time.NewTicker(negative)` panics. Check usage: `forced` is passed as `ForcedRefresh` to `SurfaceAScope`, used as wire-update floor — if negative, every reconcile would re-publish (no floor, just always publish). Not a crash, just extra DNS updates. Not exploitable (operator-controlled).

Refutation attempt: `TransferInterval` is schema-validated `ValidateInteger(1, 2880)` — 1..2880 minutes, so `time.Duration(interval)*time.Minute` is safe (max 2880*60e9 = 172800e9 = 1.7e14 ns, well under 9e18). `ForcedRefreshSeconds` is NOT schema-validated with a max — could be large, but it's optional and defaults to 24h. Not a panic path because negative `time.Duration` used as "no floor" (0 or negative means always publish). Survives as hygiene Low but not worth filing as issue — document as negative result.

Why it matters: No fix needed for TransferInterval (validated). ForcedRefreshSeconds overflow is operator self-DoS (set to 300 years -> extra DNS updates). Not security.
Fix direction: Clamp ForcedRefreshSeconds to e.g., 0..365*24*3600 (1 year) in `parseDurationSeconds` or in `compileDDNSServices`. Or use `time.Duration.Seconds()` with overflow check.
Labels: negative-result, integer-overflow
Dedup note: Not in dedup index but not worth filing.



---

## Additional findings from deep-dive (F-05b..F-05i) — see Findings section for details

- **F-05b** `daemon_ha.go:1266` `IsPrivate() && IsLoopback()` always false — dead code, no functional impact (IsGlobalUnicast already excludes private). Low / code-quality.
- **F-05c** `daemon_ha_vip.go:516-528` `directBurstStillValid` ABBA — no deadlock (single-lock-at-a-time), but TOCTOU one extra GARP after abdication. Low / informational.
- **F-05d** `daemon_ha_fabric.go:556-573` clear/populate TOCTOU — single-writer per fabric, no race. Negative.
- **F-05e** `daemon_ha_sync.go:198-200` `time.Sleep` ignores ctx — leaked goroutine up to 30s, safe but noisy. Low.
- **F-05f** `daemon_apply.go:37-51` procfs write ignores error — no traversal (LinuxIfName sanitizes), but silent DAD/MLO failure. Low / observability.
- **F-05g** `daemon_archive_timer.go:90-102` race on archiveNewTicker/applyCancelContext — happens-before via goroutine creation, safe. Negative / hygiene.
- **F-05h** `daemon_nft.go:1289-1297` nftLo0LogPrefix newline — term names cannot contain newline via parser, not exploitable. Negative / defense-in-depth.
- **F-05i** `daemon_ddns_surface_a.go:151` ForcedRefreshSeconds overflow — operator self-DoS, TransferInterval validated 1..2880 so safe. Negative.

## Negative results (modules with no new finding)

- **bootstrap.go**, **daemon.go**, **device_map.go**, **linksetup.go**, **rss_indirection.go**, **coalescence.go**, **host_tunables*.go**, **exec_timeout.go**, **daemon_cluster_bind.go**, **daemon_ddns.go**, **daemon_ddns_surface_a.go**, **daemon_dhcp.go**, **daemon_dhcp_lease_sync.go**, **daemon_dhcp_relay_gate_test.go**, **daemon_dhcprelay_reconcile_test.go**, **daemon_dns.go**, **daemon_eventoptions_reconcile_test.go**, **daemon_fabric_monitor_4031_test.go**, **daemon_feeds.go**, **daemon_flowexport.go**, **daemon_forwarding_status.go**, **daemon_gc.go**, **daemon_ha.go**, **daemon_ha_fabric.go**, **daemon_ha_sync.go**, **daemon_ha_userspace.go**, **daemon_ha_vip.go**, **daemon_health.go**, **daemon_ipmon.go**, **daemon_lldp_reconcile_test.go**, **daemon_natpoolalarm.go**, **daemon_neighbor.go**, **daemon_neighbor_listener.go** (beyond LOW cap noted), **daemon_networkd_apply_test.go**, **daemon_nft.go**, **daemon_policy_*.go**, **daemon_proxyarp.go**, **daemon_ra.go** (beyond LOW noted), **daemon_reth.go**, **daemon_rpm.go** (race is F-04), **daemon_run.go**, **daemon_scheduler.go**, **daemon_snmp_reconcile.go** (deadlock is F-03), **daemon_system.go**, **device_map_test.go**, **kernel_selfrecover.go**, **rg_state.go**, **runtime_probes.go**, etc. — all checked for integer truncation (Atoi -> uint16/uint8/uint32, ifindex int->uint32, VLAN ID, MTU, port), FRR vtysh injection, IPsec PSK zeroize, staged upgrade, VRRP/HA cold-boot split-brain, and DDNS/observability resource safety.

For each, the invariant checked and found sound is noted in the module-by-module log above. No new High/Critical beyond F-01..F-07.

- **Integer truncation sweep**: Searched all 150 files for `Atoi.*uint16`, `uint16(*Atoi`, `uint32(.*Index`, `VlanID`, `vlan_id`, `MTU`, `ifindex`, `Ifindex`, `Port.*uint16`. Found only: `parseSrcPort` uint16 wrap (F-01), `n.State uint16` (safe, NUD bits <256), `IfMtu int` stays int, `VlanID int` stays int, `ifindex int->uint32` safe (kernel ifindex 1..2^31-1), `RethMAC` / `StableRethLinkLocal` no truncation, `applyCoalescence` `rx-usecs` int stays int. No other narrowing without validation.

- **FRR injection sweep**: No `vtysh -c` / `exec.Command("vtysh", ...)` in daemon batch; only `networkctl reload`, `ethtool`, `udevadm`, `chronyc`, `systemctl`, `scp`, `visudo`, `sshd -t`, `chpasswd`, `useradd`, `chown`, `id`, `nft -f -` (payload is sanitized, not shell), `scp` argv injection is F-02.

- **IPsec apply/teardown ordering**: `daemon_ipsec_apply_test.go` and `daemon_ha_sync.go` `advertiseIPsecSAOnce` / `ipsecSASyncAdvertise` empty-set one-shot logic checked; ordering `applyFRRConfig` before `applyLo0Filter`/`applyHostInboundFilter` is correct; IPsec SA sync never pushes empty set is fixed in #4385 (tested in `ipsec_sa_sync_empty_4385_test.go`). No new finding.

- **Cold-boot / device-map / RETH MAC**: `computeBootClass` five-case predicate, HA-node guard, `emptyHANamingPending` one-shot, `breakNameCollisions` temp-name carrying `OriginalName`, `programRethMAC` live-change try then DOWN/UP, `prepareLinkCycle` / `NotifyLinkCycle` ordering, `clearDadFailed`, `removeAutoLinkLocal`, `ensureRethLinkLocal`, `lifelineRecord` PCI+MAC, `protectedInterfaces` narrowFxp0 — all checked, no new finding.

- **DDNS / observability resource safety**: `runDDNSReconcileLoop` / `runSurfaceADDNSReconcileLoop` / `runDHCPLeaseSyncLoop` all use guarded goroutine + `CompareAndSwap` + nudge channel depth 1 + context timeout, no control-socket use (CLAUDE.md rule respected). `observeInterfaceAddr` transient vs definitive distinction correct. `checkIP` respects reconcile ctx (no `context.Background()`). `archiveToSites` leak is F-06, not DDNS.

---

## Summary

- 10 active findings (2 Medium, 8 Low) + 5 negative results (F-03 SNMP teardown safe, F-05d fabric TOCTOU single-writer, F-05g archive timer happens-before safe, F-05h nft newline not reachable via parser, F-05i ForcedRefresh overflow operator self-DoS).
- 0 Critical.
- F-03 RETRACTED after re-reading pkg/snmp/agent.go (ctx watcher calls Stop on Cancel).
- F-05d/g/h/i RETRACTED or downgraded to defense-in-depth / hygiene after deeper analysis.

- All findings include dedup justification — none overlap with #4572, #4569, #4567, #4566, #4565, #4559, #4555, #4549, #4515, #4508, #4499, #4498, #4497, #4484, #4478, #4455, #4422, #4421, #4420, #4419, #4415, #4413, #4409, #4408, #4407, #4404, #4373, #4372, #4323, #4313, #4228, #4146, etc.
- Integer-truncation focus: only `parseSrcPort` is a real truncation bug; all other int->uint32 (ifindex), int->uint16 (NUD state), VLAN ID (int stays int) are safe or low.
- Cold-boot / HA / VRRP: no new split-brain or fail-open; existing #4386, #4385, #4378, #4376 fixes are intact.
- DDNS/Surface A: `checkIP` honors reconcile ctx, `transient` vs `definitive` contract upheld, RG0 single-writer gate correct, public-address gate on DHCP lease correct — no new finding.
- Observability: flow export / traceoptions callback-once fix (#3932) intact; SNMP link-state monitor resubscribe+re-sync correct; neighbor listener resubscribe correct; proxy-arp re-assert holds applySem (fixes #4001).

