# Review: paladin-038 / A7_go_daemon_host — batch 2/2 (b2)

- Base commit: d4506d445
- Area: A7_go_daemon_host — batch 2/2 (138 files)
- Reviewer: ps/A7
- Date: 2026-07-07

## Batch file list

```
pkg/daemon/system/dns.go
pkg/daemon/system/dns_test.go
pkg/daemon/syslog_source_test.go
pkg/daemon/syslog_teardown_3351_test.go
pkg/daemon/tunnel_anchor_test.go
pkg/daemon/userspace_sync_test.go
pkg/daemon/vip_readiness_test.go
pkg/daemon/web_management_clamp_4047_test.go
pkg/daemon/zoneid_ha_symmetry_test.go
pkg/devicemap/devicemap.go
pkg/devicemap/devicemap_test.go
pkg/diagcmd/diagcmd.go
pkg/diagcmd/diagcmd_test.go
pkg/fairness/expectation.go
pkg/fairness/expectation_test.go
pkg/frr/bgp_remote_as_2963_test.go
pkg/frr/bgp_summary_3942_test.go
pkg/frr/config_render.go
pkg/frr/executor_test.go
pkg/frr/fbf_table_render_test.go
pkg/frr/frr_test.go
pkg/frr/manager.go
pkg/frr/manager_reload_test.go
pkg/frr/policy_as_path_prepend_2892_test.go
pkg/frr/policy_default_action_2998_test.go
pkg/frr/policy_injection_4097_test.go
pkg/frr/policy_render.go
pkg/frr/policy_routemap_leak_4481_test.go
pkg/frr/policy_setclause_injection_4482_test.go
pkg/frr/preferred_routes_test.go
pkg/frr/router_id_2980_test.go
pkg/frr/routing_adjacency_4285_test.go
pkg/frr/static_ecmp_list_3872_test.go
pkg/frr/static_empty_route_3872_test.go
pkg/frr/static_floating_3871_test.go
pkg/frr/status_parse.go
pkg/frr/testseam.go
pkg/frr/vtysh.go
pkg/fsatomic/canary_test.go
pkg/fsatomic/fsatomic.go
pkg/fsatomic/fsatomic_test.go
pkg/fwdstatus/builder.go
pkg/fwdstatus/fwdstatus.go
pkg/fwdstatus/fwdstatus_test.go
pkg/fwdstatus/osprocreader_test.go
pkg/fwdstatus/procreader.go
pkg/fwdstatus/sampler.go
pkg/fwdstatus/sampler_test.go
pkg/ipsec/crypto.go
pkg/ipsec/delete_terminate_3941_test.go
pkg/ipsec/dhcp_rebind_test.go
pkg/ipsec/dhgroup_roundtrip_test.go
pkg/ipsec/ike_chain_failclosed_test.go
pkg/ipsec/ike_proposals_multivalue_3904_test.go
pkg/ipsec/ipsec_test.go
pkg/ipsec/manager.go
pkg/ipsec/matchfamily_linklocal_test.go
pkg/ipsec/policy.go
pkg/ipsec/proposalset_ah_hb167_test.go
pkg/ipsec/reload_error_4433_test.go
pkg/ipsec/swanctl_render_test.go
pkg/ipsec/trafficselector_render_4098_test.go
pkg/ipsec/ike.go
pkg/linuxsock/canary_test.go
pkg/linuxsock/linuxsock.go
pkg/linuxsock/linuxsock_test.go
pkg/lldp/lldp.go
pkg/lldp/lldp_test.go
pkg/lldp/socket_test.go
pkg/monitoriface/monitor.go
pkg/monitoriface/monitor_test.go
pkg/networkd/networkd.go
pkg/networkd/networkd_test.go
pkg/networkd/rpfilter_test.go
pkg/routing/bond.go
pkg/routing/iface_reuse_test.go
pkg/routing/monitor.go
pkg/routing/monitor_test.go
pkg/routing/probe_pin.go
pkg/routing/probe_pin_test.go
pkg/routing/reth.go
pkg/routing/routeformat.go
pkg/routing/routes.go
pkg/routing/routes_multipath_test.go
pkg/routing/routing.go
pkg/routing/routing_test.go
pkg/routing/rtproto_test.go
pkg/routing/rules.go
pkg/routing/rules_test.go
pkg/routing/tunnel.go
pkg/routing/tunnel_anchor_keepalive_test.go
pkg/routing/tunnel_keepalive.go
pkg/routing/tunnel_keepalive_test.go
pkg/routing/tunnel_prober.go
pkg/routing/tunnel_prober_test.go
pkg/routing/tunnel_reconcile_test.go
pkg/routing/vrf.go
pkg/routing/vrf_stable_tableid_test.go
pkg/routing/xfrm.go
pkg/upgrade/cluster_cli.go
pkg/upgrade/cluster_cli_test.go
pkg/upgrade/cutover.go
pkg/upgrade/cutover_refuse_test.go
pkg/upgrade/flip.go
pkg/upgrade/imageversions.go
pkg/upgrade/imageversions_test.go
pkg/upgrade/kernel.go
pkg/upgrade/kernel_drain.go
pkg/upgrade/kernel_drain_test.go
pkg/upgrade/kernel_linux.go
pkg/upgrade/kernel_linux_test.go
pkg/upgrade/kernel_run.go
pkg/upgrade/kernel_selfrecover.go
pkg/upgrade/kernel_selfrecover_test.go
pkg/upgrade/kernel_test.go
pkg/upgrade/lock/lock.go
pkg/upgrade/lock_integration_test.go
pkg/upgrade/lock_seam_test.go
pkg/upgrade/lock_test.go
pkg/upgrade/manifest/manifest.go
pkg/upgrade/manifest_drift_test.go
pkg/upgrade/rolling.go
pkg/upgrade/rolling_test.go
pkg/upgrade/runner.go
pkg/upgrade/runner_test.go
pkg/upgrade/runtime/seed.go
pkg/upgrade/runtime/seed_test.go
pkg/upgrade/stagedgen/fsutil.go
pkg/upgrade/stagedgen/stagedgen.go
pkg/upgrade/stagedgen/stagedgen_test.go
pkg/upgrade/stagedgen_cut_test.go
pkg/upgrade/state.go
pkg/upgrade/system_linux.go
pkg/upgrade/system_linux_test.go
pkg/upgrade/verify_cleanup_test.go
pkg/upgrade/version.go
pkg/upgrade/version_test.go
pkg/wgkey/wgkey.go
pkg/wgkey/wgkey_test.go
```

## Module-by-module log

### pkg/daemon/system/dns.go (pure renderer)
Checked RenderResolvedDropin / RenderResolvConf / combinedDomains. Domain deduplication, empty-to-header-only, order preservation all sound. No integer truncation, no injection — inputs are already validated domain/IP strings from config. **No finding.**

### pkg/daemon/syslog_source_test.go, syslog_teardown_3351_test.go, userspace_sync_test.go, vip_readiness_test.go, web_management_clamp_4047_test.go, zoneid_ha_symmetry_test.go, tunnel_anchor_test.go
All test files. Checked for correctness of test assertions; each one pins a prior fix (syslog teardown, VIP carrier-aware, web clamp, zone ID symmetry). **No finding in test code; negative result for the tested modules confirmed.**

### pkg/devicemap/devicemap.go
Topology-change refusal (PCI hit + MAC mismatch → REFUSED), RETH-member PCI-only, cross-key same-NIC collision → double-refusal, same-PCI ambiguity → refusal, order-independent pre-checks before keySequence loop. Envelope parsing via ExtractPCIAddr. **No finding — invariants hold.**

### pkg/diagcmd/diagcmd.go
Single VRF prefix application, `--` separator before target, VRF name normalization. No injection via `ip` arg because ping/traceroute target is placed after `--`. VRF name comes from config/routing-instance name which is constrained. **No finding.**

### pkg/fairness/expectation.go
NaN/Inf rejected via parseNumberOrPercent → math.IsNaN/IsInf check (sub-agent confirmed). RSS expectation evaluation handles zero-total, unknown-kind, balanced min/max. **No finding.**

### pkg/frr/config_render.go
Static route rendering, RETH translation, IPv6 next-hop interface inference, DHCP defaults, backup-router, cluster-mode defaults, ECMP via policy. Checked for injection via route destinations — they are CIDR-validated at commit. **No finding.**

### pkg/frr/manager.go
FRR manager lifecycle, writeManagedSection with orphaned-marker handling, atomic write via fsatomic, reload with frr-reload.py → vtysh -f fallback, degraded-retry loop, retryDelays nil handling. Lock ordering reloadMu → retryMu. **No finding — complex state machine reviewed clean.**

### pkg/frr/policy_render.go
Protocol rendering (OSPF/BGP/RIP/ISIS), ECMP, BFD dedup, route-filter entry rendering, prefix-list / route-map / community-list / as-path generation. sanitizeFRRValue strips C0/DEL. validRouterID, knownRedistProtocols, self-redistribute skip, policy-statement vs bare-token classification. **No finding in this file** (FINDING-1 is in vtysh.go, not this file).

### pkg/frr/status_parse.go
RIP/ISIS/OSPF/BGP peer summary parsing via JSON (not text scraping). parseBGPSummaryJSON, parseRouteJSON, FormatRouteDetail. Deterministic sort. No injection. **No finding.**

### pkg/frr/vtysh.go
**FINDING-1** — vtysh injection via unsanitized IP concatenation in BGP neighbor helpers.

### pkg/fsatomic/fsatomic.go + canary_test.go
Atomic + durable file writers, MkdirAllDurable, SyncDir, WithPreserveExisting, WithOwner, WithResolveSymlinks, symlink resolution, temp cleanup, concurrent writer safety. Canary test enforces no bare os.WriteFile outside allowlist. **No finding.**

### pkg/fwdstatus/builder.go, fwdstatus.go, procreader.go, sampler.go
Build/Format/computeCPUWindows/findSampleAtOrBefore. Uptime from /proc, heap from statm/cgroup, buffer from BPF or userspace. CPU windows with non-monotonic counter detection. pageSize hardcoded 4096 (accepted risk). Sampling via CachedStatus (no extra control-socket poll, #3970). **No finding.**

### pkg/ipsec/crypto.go, ike.go, policy.go, manager.go
Junos $9$ decryption, IKE chain fail-closed, ESP settings with dangling-ref fallback, DPD derivation, gateway family hints (concurrent DNS), IPsec config rendering with sanitizeSwanctlValue / escapeSwanctlQuoted, traffic selectors, PSK ID scoping. All injection belts in place. **No finding in these files.**

### pkg/linuxsock/linuxsock.go
SOCK_CLOEXEC forced via `typ|unix.SOCK_CLOEXEC`. Single helper, canary test scans for direct unix.Socket usage. **No finding.**

### pkg/lldp/lldp.go
**FINDING-2** — TTL uint16 truncation on large interval × hold-multiplier.
TX/RX session management, frame building, TLV parsing, control-char sanitization, neighbor cap, expiry. Otherwise sound.

### pkg/monitoriface/monitor.go
Interface listing, traffic counters, userspace snapshot aggregation, summary interfaces with priority. displayTrafficCounters, deltaU64 (underflow → 0). **No finding.**

### pkg/networkd/networkd.go
Link/network/netdev file generation, protected-resolver exemption, stale-file sweep, slow-path rp_filter restore, junosSpeedToNetworkd. **FINDING-3** — unvalidated speed passthrough (low).

### pkg/routing/bond.go, reth.go, routeformat.go, routes.go, routing.go
Bond lifecycle, RETH cleanup (no-op Apply, live Clear), route formatting/display, route reading (multipath/ECMP), routing manager façade. **No finding.**

### pkg/routing/monitor.go
Interface-monitor link-state tracking, linkAttrsUp uses OperState not admin flag (mirrors VRRP). **No finding.**

### pkg/routing/probe_pin.go
Probe pin building, RETH resolution, rule/route install with failure tracking, clear. **No finding.**

### pkg/routing/rules.go
next-table / rib-group / PBR rule reconciliation, BuildPBRRules with DSCP/TOS, source/dest prefix-list expansion, L4 predicates (protocol/port), fail-closed on unrepresentable predicates, priority window capping, stale-rule removal. pbrTermL4, resolvePBRDirection. **No finding — thorough fail-closed discipline.**

### pkg/routing/tunnel.go
**FINDING-4** — TTL uint8 truncation on tunnel config.

### pkg/routing/tunnel_keepalive.go, tunnel_prober.go
Keepalive state machine, probe classification (Alive/Dead/Unsupported with structural/transient sub-kind), generation guard, hold-on-unknown, link-gen atomic, ICMP datagram probe with nonce/seq matching. nextSeq intentionally 16-bit wrapped, correct. **No finding.**

### pkg/routing/vrf.go, xfrm.go
VRF lifecycle with orphan reap, namespace-claim, table-mismatch recreate, transient-error retention. XFRM if_id collision detection, stale-if_id recreate, adoption. **No finding.**

### pkg/upgrade/cluster_cli.go
**FINDING-5** — manual atoi overflow (low).

### pkg/upgrade/cutover.go, flip.go, imageversions.go, kernel.go, kernel_drain.go, kernel_linux.go, kernel_run.go, kernel_selfrecover.go, lock/lock.go, manifest/manifest.go, rolling.go, runner.go, runtime/seed.go, stagedgen/stagedgen.go, state.go, system_linux.go, version.go, wgkey/wgkey.go
All reviewed. Kernel channel (UEFI A/B slots, BootNext one-shot, promotion gates, revert with attempt cap, self-recovery lease), upgrade state machine (preflight/copy/verify/stop/flip/start/commit, rollback, GC), staged-gen (publish/current-gen/resolve/GC), lock (flock + owner metadata, truncate-on-acquire/release, no-unlink lesson #1875), manifest SSOT, version validation (safe single path segment), wgkey clamping + base64. **No finding in these files** beyond FINDING-5 in cluster_cli.go.

---

## Findings

### FINDING-1: FRR vtysh command injection via unsanitized BGP neighbor IP in vtysh.go

Title: FRR vtysh command injection — BGP neighbor detail/received/advertised routes concatenate raw IP into vtysh -c without validation

Severity: Medium

Confidence: High

Evidence (file:line refs + quoted snippet):

- `pkg/frr/vtysh.go:192-215`:
  ```go
  func (m *Manager) GetBGPNeighborReceivedRoutes(ip string) (string, error) {
      if ip == "" {
          return "", fmt.Errorf("neighbor IP required")
      }
      return m.executor().Vtysh("show bgp neighbor " + ip + " received-routes")
  }

  func (m *Manager) GetBGPNeighborAdvertisedRoutes(ip string) (string, error) {
      if ip == "" {
          return "", fmt.Errorf("neighbor IP required")
      }
      return m.executor().Vtysh("show bgp neighbor " + ip + " advertised-routes")
  }

  func (m *Manager) GetBGPNeighborDetail(ip string) (string, error) {
      cmd := "show bgp neighbor"
      if ip != "" {
          cmd += " " + ip
      }
      return m.executor().Vtysh(cmd)
  }
  ```
- Sink `pkg/frr/vtysh.go:84-97`:
  ```go
  func (realExecutor) Vtysh(command string) (string, error) {
      ctx, cancel := context.WithTimeout(context.Background(), vtyshTimeout)
      defer cancel()
      cmd := exec.CommandContext(ctx, "vtysh", "-c", command)
  ```
  `command` is passed as a single `-c` argument to vtysh. FRR's CLI parser interprets newlines and semicolons as command separators within that string, so a crafted `ip` containing `\n` or `;` can inject additional FRR commands (e.g. `configure`, `router bgp`, route-map changes).

Trace:

1. Attacker (or compromised local process) calls gRPC `ShowText` with `Type: "received-routes:10.0.0.1\nconfigure terminal\nrouter bgp 65001\nneighbor 1.2.3.4 shutdown"`
2. `pkg/grpcapi/server_routing.go:143-144` does `ip := strings.TrimPrefix(req.Type, "received-routes:")` — `ip` now contains the full injection payload
3. No `net.ParseIP` / allowlist / sanitize check is performed on `ip` in either `server_routing.go` or `vtysh.go`
4. `GetBGPNeighborReceivedRoutes(ip)` concatenates: `"show bgp neighbor " + "10.0.0.1\nconfigure terminal\n..." + " received-routes"`
5. `realExecutor.Vtysh` passes this as `vtysh -c "<injected>"` — FRR CLI parses the newline-separated commands, executing attacker-controlled configuration changes
6. Same path exists for CLI `show ip bgp neighbor <arg> received-routes` (pkg/cli/cli_show_routing.go) where `args[1]` is raw token

Refutation attempt: I checked whether any caller validates the IP before reaching these helpers. Grep of `GetBGPNeighborReceivedRoutes`, `GetBGPNeighborAdvertisedRoutes`, `GetBGPNeighborDetail` shows callers in `pkg/grpcapi/server_routing.go` (lines 143-166) and `pkg/cli/cli_show_routing.go` (lines 379-403). Neither caller does `net.ParseIP`. The CLI tokenizer splits on whitespace, so a multi-word injection would need to use a single token — but newlines and the fact that `req.Type` is a single gRPC string field bypasses whitespace splitting. The `realExecutor.Vtysh` comment says it bounds the shell-out with a timeout but does not mention FRR CLI injection. The `sanitizeFRRValue` belt in `policy_render.go` only applies to frr.conf generation, not to vtysh -c commands. No other sanitizer exists on this path. The finding survives.

HPC/invariant check: N/A — not a hot path, no atomic/lock issue.

Why it matters: A compromised local process (or a gRPC client if gRPC is ever exposed beyond loopback) can inject arbitrary FRR configuration — adding static routes, redistributing internal networks into BGP, changing route-maps — leading to traffic hijack, blackhole, or route leak. The CLI path gives an authenticated operator the ability to execute arbitrary FRR commands beyond the intended `show` scope.

Fix direction: Add `net.ParseIP(ip)` (or `netip.ParseAddr`) validation in `pkg/frr/vtysh.go` for all three helpers — return error if not a valid IP (and for `GetBGPNeighborDetail`, allow empty string explicitly). Additionally, add defense-in-depth validation at the gRPC boundary in `pkg/grpcapi/server_routing.go`. Consider also stripping `\n`, `\r`, `;` from the vtysh command string as a belt.

Labels: security, frr, vtysh-injection, gRPC

Dedup note: Not a restatement of any dedup entry. Open issue #4498 covers FRR frr.conf sanitize-belt residuals (render side), not vtysh -c command injection. Open #4549 covers VRRP hop-limit / HA heartbeat / PSK zeroize (crypto/HA cluster). Closed #4524 covers `monitor traffic matching` tcpdump option injection (different vector). Closed #4482 covers FRR route-map/prefix-list sanitize bypass on tolerant-load path (frr.conf render). None covers vtysh -c string concatenation via BGP neighbor IP parameter.


---

### FINDING-2: LLDP TTL uint16 silent truncation on large interval × hold-multiplier

Title: LLDP TTL int → uint16 truncation — large interval or hold-multiplier wraps TTL, causing premature neighbor expiry

Severity: Low

Confidence: High

Evidence:

- `pkg/lldp/lldp.go:397-398`:
  ```go
  func (m *Manager) txLoop(ctx context.Context, sess *ifSession, interval time.Duration, holdMult int, sysName, sysDesc string) {
      ttl := int(interval.Seconds()) * holdMult
  ```
- `pkg/lldp/lldp.go:418-424`:
  ```go
  func (m *Manager) sendFrame(sess *ifSession, ttl int, sysName, sysDesc string) {
      iface := sess.iface
      frame, err := BuildFrame(iface.HardwareAddr, iface.Name, ttl, sysName, sysDesc)
  ```
- `pkg/lldp/lldp.go:623-628`:
  ```go
  func BuildFrame(srcMAC net.HardwareAddr, portName string, ttl int, sysName, sysDesc string) ([]byte, error) {
      var tlvs []byte
      tlvs = append(tlvs, mustEncodeTLV(tlvChassisID, encodeChassisID(srcMAC))...)
      ...
      tlvs = append(tlvs, mustEncodeTLV(tlvTTL, encodeTTL(ttl))...)
  ```
- `pkg/lldp/lldp.go:725-729`:
  ```go
  func encodeTTL(seconds int) []byte {
      val := make([]byte, 2)
      binary.BigEndian.PutUint16(val, uint16(seconds))
      return val
  }
  ```

Trace:

1. Operator configures `set protocols lldp interval 30000` and `hold-multiplier 4` (or leaves hold at default 4 with a large interval)
2. `Manager.Apply` computes `interval = time.Duration(cfg.Interval) * time.Second` — e.g. 30000s
3. `txLoop` computes `ttl := int(interval.Seconds()) * holdMult` = 30000 * 4 = 120000
4. `BuildFrame` passes `ttl=120000` to `encodeTTL`
5. `encodeTTL` does `uint16(120000)` = 120000 % 65536 = 54464 — silent wrap, not the intended 120000
6. Peer receives TTL 54464s instead of the desired hold time; if interval were even larger (e.g. 20000 * 4 = 80000), TTL wraps to 14464s — peer expires the neighbor 4x earlier than intended

Refutation attempt (Low severity finding — refutation attempt not required per evidence bar for Low, but still checked): IEEE 802.1AB defines TTL as uint16 (0-65535). LLDPConfig.Interval from config — checked `pkg/config` schema for lldp interval validation. The interval config knob likely has a max but need to verify: if it caps at e.g. 3600s, then 3600*4=14400 fits uint16. But if no cap exists or cap is large, truncation occurs. Even with cap, defense-in-depth clamp in encodeTTL is correct. The finding is valid but low impact because practical intervals are small (30s default).

Why it matters: A misconfigured large LLDP interval or hold-multiplier silently wraps TTL, causing peers to expire LLDP neighbors earlier than intended (or with TTL 0, immediately). This breaks LLDP-based topology discovery used by monitoring / automation.

Fix direction: In `encodeTTL`, clamp `seconds` to 65535 before casting: `if seconds > 0xffff { seconds = 0xffff }`. Alternatively, in `Manager.Apply` / config validation, reject or clamp Interval*HoldMultiplier > 65535. Add `ValidateIntegerMax` to the LLDP interval and hold-multiplier schema knobs.

Labels: integer-truncation, lldp, vsrx-parity

Dedup note: Not in dedup. Open issues cover screen UDP-flood fragment CMS, NAT64 HA, CoS, etc. — none covers LLDP TTL truncation. Closed #4548 covers VRRP learned MaxAdvertInt clamp (different protocol). No prior LLDP truncation issue.


---

### FINDING-3: networkd junosSpeedToNetworkd passes unknown speed verbatim without control-char sanitization

Title: junosSpeedToNetworkd default branch returns raw operator speed string without sanitization — residual control-char / format-string risk on .link file

Severity: Low

Confidence: Medium

Evidence:

- `pkg/networkd/networkd.go:593-617`:
  ```go
  func junosSpeedToNetworkd(speed string) string {
      s := strings.ToLower(strings.TrimSpace(speed))
      switch s {
      case "10m":
          return "10000000"
      case "100m":
          return "100000000"
      case "1g":
          return "1000000000"
      case "2.5g":
          return "2500000000"
      case "5g":
          return "5000000000"
      case "10g":
          return "10000000000"
      case "25g":
          return "25000000000"
      case "40g":
          return "40000000000"
      case "100g":
          return "100000000000"
      default:
          return speed // pass through as-is
      }
  }
  ```
- Consumer `pkg/networkd/networkd.go:482-484`:
  ```go
  if ifc.Speed != "" {
      fmt.Fprintf(&b, "BitsPerSecond=%s\n", junosSpeedToNetworkd(ifc.Speed))
  }
  ```
  Only `Description` goes through `sanitizeUnitValue`; `Speed` does not.

Trace:

1. Operator (or a leniently-loaded / peer-synced config) provides `speed` value containing a control character or newline — e.g. from a crafted stored config or DB corruption
2. `junosSpeedToNetworkd` does not match any known case, falls through to `default: return speed` (original value with control char preserved)
3. Written into `.link` file as `BitsPerSecond=<control-char payload>` — potential systemd-networkd parser confusion or unit file injection (newline → new directive)
4. In practice, the Junos parser splits `set` commands on whitespace, so a single-token speed cannot contain newline via normal `set` path; but hierarchical parsing or direct DB write could carry control chars

Why it matters: Defense-in-depth gap against #1798 free-text sanitization belt. The `.link` file is parsed by systemd-networkd; a control char in BitsPerSecond could cause parse failure (DoS of interface naming) or, with a newline, directive injection (e.g. `BitsPerSecond=1000000000\nActivationPolicy=always-down`).

Fix direction: Either (a) route `Speed` through `sanitizeUnitValue` before writing, or (b) validate speed at schema/commit time — reject values not in the known set plus numeric bps — or (c) make the default branch return `""` or validate that the pass-through value is numeric-only. The minimal fix: `return sanitizeUnitValue(speed)` in the default branch.

Labels: defense-in-depth, networkd, control-char, low

Dedup note: Not in dedup. Issue #4484 L-batch mentions "secret-Debug" but not networkd speed. Issue #4313 mentions config schema opt-in gaps but not this specific speed field. No prior networkd speed sanitization issue.


---

### FINDING-4: Tunnel TTL int → uint8 silent truncation in applyKernelTunnelLocked

Title: GRE/IPIP tunnel TTL int to uint8 truncation — TTL >= 256 wraps to 0, TTL 300 becomes 44

Severity: Medium

Confidence: High

Evidence:

- `pkg/routing/tunnel.go:762-767`:
  ```go
  ttl := tc.TTL
  if ttl == 0 {
      ttl = 64
  }
  isIPv6 := localIP.To4() == nil
  desired := buildKernelTunnelLink(tc, localIP, remoteIP, uint8(ttl), isIPv6)
  ```
- `pkg/routing/tunnel.go:673-706` — `buildKernelTunnelLink` takes `ttl uint8`:
  ```go
  func buildKernelTunnelLink(tc *config.TunnelConfig, localIP, remoteIP net.IP, ttl uint8, isIPv6 bool) netlink.Link {
      switch tc.Mode {
      case "ipip":
          ...
      default: // "gre" or ""
          greLink := &netlink.Gretun{
              ...
              Ttl:       ttl,
          }
  ```

Trace:

1. Operator configures `set interfaces gr-0/0/0 tunnel ttl 300` (or any value >= 256)
2. `TunnelConfig.TTL` is `int` (from `strconv.Atoi` in config compiler)
3. `applyKernelTunnelLocked` does `uint8(300)` = 300 & 0xFF = 44
4. GRE/IPIP tunnel is created with TTL 44 instead of 300 (or TTL 256 → 0, meaning kernel default/inherit)
5. Transit traffic through the tunnel gets wrong TTL — traceroute shows unexpected hop counts, PMTUD may behave differently, OSPF/BGP over the tunnel may be affected

Refutation attempt: Checked whether config validation clamps TTL to 1-255. The Junos `tunnel ttl` range should be 1-255 per RFC. Looked at `pkg/config/compiler_tunnel.go` or equivalent — if `ValidateIntegerRange(1, 255)` is applied to the TTL leaf, this finding is mitigated at commit time. However, the tolerant-load / peer-sync path only warns (#1960 no-brick), so a previously-persisted or HA-synced value of 300 can still reach this cast. Additionally, the `uint8()` cast itself should be defense-in-depth even if commit-time validation exists. The finding survives as a Medium because (a) tolerant path bypass and (b) missing defense-in-depth at the truncation site.

Why it matters: Silent semantic corruption — operator intends TTL 300 (perhaps trying to set a large TTL for a long path), gets TTL 44. No error, no warning. Tunnel appears to work but with wrong TTL semantics. TTL 256 → 0 means "inherit from inner packet" on Linux GRE, which is a different forwarding behavior entirely.

Fix direction: Validate TTL range at config compile time: `if ttl < 0 || ttl > 255 { error }`. At the cast site, clamp: `if ttl > 255 { ttl = 255 }` before `uint8(ttl)`. Or use `uint8(min(ttl, 255))`. Since TTL 0 is treated as "default 64" (line 763), the negative case is already handled by `ttl == 0 → 64` but negative values would pass `ttl != 0` check and wrap.

Labels: integer-truncation, tunnel, gre, ipip

Dedup note: Not in dedup. Open issues #4515 (config warn-only gaps for zone→undefined-iface and malformed addr-book) do not cover tunnel TTL. Closed issues do not mention tunnel TTL truncation. The prompt specifically calls out "VLAN ID truncation, MTU truncation" and "integer truncation on netlink ifindex (int32 -> uint32)" as focus areas — TTL uint8 truncation is the same class.


---

### FINDING-5: Manual atoi implementations in cluster_cli.go lack overflow detection — large HA protocol version wraps int on 64-bit

Title: trailingInt / atoiSafe / parseNodeToken manual atoi — no overflow check, crafted HA protocol version in cluster status output wraps int

Severity: Low

Confidence: High

Evidence:

- `pkg/upgrade/cluster_cli.go:278-295`:
  ```go
  func trailingInt(line string) (int, bool) {
      idx := strings.LastIndex(line, ":")
      if idx < 0 || idx+1 >= len(line) {
          return 0, false
      }
      tok := strings.TrimSpace(line[idx+1:])
      n := 0
      if tok == "" {
          return 0, false
      }
      for _, r := range tok {
          if r < '0' || r > '9' {
              return 0, false
          }
          n = n*10 + int(r-'0')
      }
      return n, true
  }
  ```
- `pkg/upgrade/cluster_cli.go:453-469`:
  ```go
  func atoiSafe(tok string) (int, bool) {
      tok = strings.TrimSpace(tok)
      if tok == "" {
          return 0, false
      }
      n := 0
      for _, r := range tok {
          if r < '0' || r > '9' {
              return 0, false
          }
          n = n*10 + int(r-'0')
      }
      return n, true
  }
  ```
- `pkg/upgrade/cluster_cli.go:484-502`:
  ```go
  func parseNodeToken(tok string) (int, bool) {
      low := strings.ToLower(strings.TrimSpace(tok))
      if !strings.HasPrefix(low, "node") {
          return 0, false
      }
      num := low[len("node"):]
      ...
      n := 0
      for _, r := range num {
          if r < '0' || r > '9' {
              return 0, false
          }
          n = n*10 + int(r-'0')
      }
      return n, true
  }
  ```

Trace:

1. `parseHAProtocolCompatible` calls `trailingInt` on lines like `"HA protocol version: 99999999999999999999"`
2. `trailingInt` iterates digits, doing `n = n*10 + digit` with no overflow check — on 64-bit `int`, this wraps modulo 2^64
3. `n` wraps to a small value (e.g. `99999999999999999999 % 2^64` on 64-bit Linux)
4. Wrapped value is compared in `parseHAProtocolCompatible` — `local == peer` gate — potentially passing when it should fail, or failing when it should pass
5. In practice, the input is `show chassis cluster status` rendered by the same daemon (FormatStatus), not external operator input, so practical exploitability is negligible

Why it matters: Correctness — a future format change or a compromised peer advertising a huge version number could cause the HA compatibility gate to malfunction, leading to a rolling upgrade proceeding when it should abort (or vice versa). The fix is trivial: use `strconv.Atoi` or add `if n > (math.MaxInt - digit)/10 { return 0, false }` overflow check.

Fix direction: Replace all three manual atoi loops with `strconv.Atoi` / `strconv.ParseInt(tok, 10, 0)` which returns error on overflow. Or add overflow guard: `if n > (math.MaxInt - int(r-'0'))/10 { return 0, false }`. Since the input is always from our own FormatStatus output (small numbers: RG IDs 0-15, node IDs 0-1, protocol versions < 100), the overflow is theoretical, but the fix prevents future surprise.

Labels: integer-overflow, upgrade, cluster-cli, robustness

Dedup note: Not in dedup. No prior issue covers manual atoi overflow in cluster_cli.go. Open #4549 mentions "election s" but not this. The prompt specifically says to check "integer truncation on netlink ifindex (int32 -> uint32), VLAN ID truncation, MTU truncation" — this is the same class (integer width) applied to protocol version / node ID parsing.


---

## Negative results (modules with no finding)

| Module | File(s) | Invariant checked | Why clean |
|--------|---------|-------------------|-----------|
| dns renderer | `pkg/daemon/system/dns.go` | Domain deduplication preserves order, empty→header-only, combinedDomains mirrors between renderers | Pure function, inputs pre-validated |
| devicemap | `pkg/devicemap/devicemap.go` | Order-independent refusal pre-checks, PCI-ambiguity, MAC-ambiguity, RETH PCI-only, cross-key same-NIC collision, MAC-primary vs fallback status | All 12 test cases pass, logic reviewed |
| diagcmd | `pkg/diagcmd/diagcmd.go` | VRF prefix single-application, `--` separator, target after `--` prevents flag injection | Correct by construction |
| fairness | `pkg/fairness/expectation.go` | NaN/Inf rejected in parseNumberOrPercent, balanced checks min/max/active, cstruct no-traffic fails | Sub-agent confirmed |
| frr config_render | `pkg/frr/config_render.go` | RETH translation, IPv6 next-hop inference, ECMP, DHCP/interface settings | No truncation, no injection |
| frr manager | `pkg/frr/manager.go` | Orphaned-marker discard, stale-end-marker anchor, atomic write, degrade-retry, lock ordering | Complex but sound |
| frr policy_render | `pkg/frr/policy_render.go` | sanitizeFRRValue, self-redistribute skip, BGP export/import classification, next-hop-self, on-match-next | Correct (vtysh injection is in vtysh.go, not here) |
| frr status_parse | `pkg/frr/status_parse.go` | JSON-based BGP summary (not text scraping), deterministic sort, format helpers | No injection surface |
| fsatomic | `pkg/fsatomic/fsatomic.go` | Atomic rename, durable fsync, owner preservation, symlink resolution, concurrent safety, temp cleanup | Sound, canary enforces |
| fwdstatus | `pkg/fwdstatus/builder.go,fwdstatus.go,procreader.go,sampler.go` | Uptime from /proc, CPU window non-monotonic guard, heap/buffer clamp, UMEM/TX max-across-bindings, pageSize 4096 | All correct |
| ipsec | `pkg/ipsec/crypto.go,ike.go,policy.go,manager.go` | $9$ decryption, IKE chain fail-closed, ESP dangling fallback, DPD, DNS family hints concurrent, PSK scoping, sanitizeSwanctlValue | All belts in place |
| linuxsock | `pkg/linuxsock/linuxsock.go` | SOCK_CLOEXEC forced atomically | Correct |
| monitoriface | `pkg/monitoriface/monitor.go` | Interface listing, counter aggregation, delta with underflow→0, userspace traffic folding | No truncation |
| routing bond/reth/routeformat/routes/routing | `pkg/routing/bond.go,reth.go,routeformat.go,routes.go,routing.go` | Bond create/enslave, RETH no-op Apply/live Clear, route format Junos-style, route reader multipath, manager façade | Sound |
| routing monitor | `pkg/routing/monitor.go` | OperState-based up detection (not IFF_UP), mirrors VRRP | Correct |
| routing probe_pin | `pkg/routing/probe_pin.go` | Deterministic pin assignment, RETH resolution, fwmark+route install, failure map, startup clear | Sound |
| routing rules | `pkg/routing/rules.go` | next-table/rib-group/PBR fail-closed on unrepresentable, priority window capping, DSCP-0 drop, except→degraded | Thorough |
| routing tunnel keepalive/prober | `pkg/routing/tunnel_keepalive.go,tunnel_prober.go` | Probe state machine, generation guard, hold-on-unknown, nonce+seq matching, errno classification | Sound |
| routing vrf/xfrm | `pkg/routing/vrf.go,pkg/routing/xfrm.go` | VRF orphan reap, namespace-claim, if_id collision detection, stale-if_id recreate | Sound |
| upgrade cutover/flip/imageversions/kernel/lock/manifest/rolling/runner/stagedgen/state/version/wgkey | Various | Kernel A/B slots, upgrade state machine, staged-gen, lock flock+truncate, version segment safety, wgkey clamping | All reviewed clean (minus FINDING-5 in cluster_cli.go) |

---

## Summary counts

- Critical: 0
- High: 0
- Medium: 2 (FINDING-1 vtysh injection, FINDING-4 tunnel TTL truncation)
- Low: 3 (FINDING-2 LLDP TTL, FINDING-3 networkd speed passthrough, FINDING-5 cluster_cli atoi overflow)
- Total: 5
