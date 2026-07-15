# Paladin 038 — A10_go_services_cli_deploy batch 2/3 review

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Area: A10_go_services_cli_deploy
Batch: 2/3 (150 files)

## File list (this batch)

```
pkg/cli/testpolicy_srcport_test.go
pkg/cli/usage_matchpolicies_3628_test.go
pkg/cli/zone_flood_counters_hide_test.go
pkg/ddns/backend.go
pkg/ddns/backend_bind.go
pkg/ddns/backend_bind_test.go
pkg/ddns/backend_cloudflare.go
pkg/ddns/backend_cloudflare_test.go
pkg/ddns/backend_dualstack_withdraw_3738_test.go
pkg/ddns/backend_duckdns.go
pkg/ddns/backend_duckdns_test.go
pkg/ddns/backend_dyndns2.go
pkg/ddns/backend_generic.go
pkg/ddns/backend_http.go
pkg/ddns/backend_http_sourcebind_2846_test.go
pkg/ddns/backend_http_test.go
pkg/ddns/backend_rfc2136.go
pkg/ddns/backend_rfc2136_test.go
pkg/ddns/backend_route53.go
pkg/ddns/backend_route53_test.go
pkg/ddns/checkip.go
pkg/ddns/checkip_sourcebind_failclosed_3733_test.go
pkg/ddns/checkip_test.go
pkg/ddns/durability_test.go
pkg/ddns/hostname.go
pkg/ddns/manager.go
pkg/ddns/manager_inc2_test.go
pkg/ddns/manager_test.go
pkg/ddns/scope_test.go
pkg/ddns/sigv4.go
pkg/ddns/sigv4_test.go
pkg/ddns/spine_fixes_test.go
pkg/ddns/state.go
pkg/ddns/surface_a.go
pkg/ddns/surface_a_hostname_2779_test.go
pkg/ddns/surface_a_http_test.go
pkg/ddns/surface_a_httpcache_2904_test.go
pkg/ddns/surface_a_httpcache_reap_2956_test.go
pkg/ddns/surface_a_lockio_test.go
pkg/ddns/surface_a_observe_lockio_3736_test.go
pkg/ddns/surface_a_provider_change_3735_test.go
pkg/ddns/surface_a_rfc2136_test.go
pkg/ddns/surface_a_sourcebind_failclosed_4437_test.go
pkg/ddns/surface_a_test.go
pkg/ddns/surface_a_withdraw_backoff_2813_test.go
pkg/dhcp/classless_routes_test.go
pkg/dhcp/commit.go
pkg/dhcp/commit_test.go
pkg/dhcp/dhcp.go
pkg/dhcp/dhcp_test.go
pkg/dhcp/dhcpv6_iana_test.go
pkg/dhcp/gateway_hook_test.go
pkg/dhcp/reconcile.go
pkg/dhcp/reconcile_test.go
pkg/dhcp/renew.go
pkg/dhcp/renew_test.go
pkg/dhcp/test_seams.go
pkg/dhcprelay/delivery_test.go
pkg/dhcprelay/l2send_linux.go
pkg/dhcprelay/l2send_test.go
pkg/dhcprelay/relay.go
pkg/dhcprelay/relay_giaddr_linux.go
pkg/dhcprelay/relay_giaddr_linux_test.go
pkg/dhcprelay/relay_test.go
pkg/dhcprelay/sockopt_linux.go
pkg/dhcpserver/ddns.go
pkg/dhcpserver/ddns_integration_test.go
pkg/dhcpserver/ddns_leases.go
pkg/dhcpserver/ddns_leases_test.go
pkg/dhcpserver/dhcpserver.go
pkg/dhcpserver/dhcpserver_test.go
pkg/dhcpserver/expired_leases_test.go
pkg/dhcpserver/lease_sync.go
pkg/dhcpserver/lease_sync_test.go
pkg/dhcpserver/reservations_test.go
pkg/dhcpserver/test_seams.go
pkg/natshow/dest.go
pkg/natshow/natshow.go
pkg/natshow/natshow_test.go
pkg/natshow/persistent.go
pkg/natshow/source.go
pkg/natshow/static.go
pkg/policymatch/app_junos_ping_3348_test.go
pkg/policymatch/app_set_failclosed_3727_test.go
pkg/policymatch/content_reject_4394_test.go
pkg/policymatch/display_action_3375_test.go
pkg/policymatch/empty_zone_4411_test.go
pkg/policymatch/excluded_addr_3356_test.go
pkg/policymatch/excluded_response_3668_test.go
pkg/policymatch/global_scope_regression_4365_test.go
pkg/policymatch/global_zone_filter_3357_test.go
pkg/policymatch/host_inbound_token_3627_test.go
pkg/policymatch/host_inbound_verdict_msg_3627_test.go
pkg/policymatch/icmp_test.go
pkg/policymatch/junos_host_test.go
pkg/policymatch/policymatch.go
pkg/policymatch/policymatch_test.go
pkg/policymatch/port_omitted_3330_test.go
pkg/policymatch/port_test.go
pkg/policymatch/protocol_omitted_3323_test.go
pkg/policymatch/protocol_test.go
pkg/policymatch/route_drop_4373_test.go
pkg/policymatch/scheduler_test.go
pkg/policymatch/scope_id_3331_test.go
pkg/policymatch/scoped_global_zonelocal_test.go
pkg/policymatch/selector_args_3696_test.go
pkg/policymatch/selector_args_dup_3709_test.go
pkg/policymatch/simulator_output_parity_3685_test.go
pkg/policymatch/srcport_omitted_3415_test.go
pkg/policymatch/undefined_zone_3355_test.go
pkg/policymatch/usage_3628_test.go
pkg/policymatch/wildcard_scoped_test.go
pkg/policymatch/zone_detail_summary.go
pkg/policymatch/zone_detail_summary_test.go
pkg/policymatch/zone_local_display_3358_test.go
scripts/deploy/test_xpf_deploy_correctness.py
scripts/deploy/test_xpf_deploy_disk.py
scripts/deploy/test_xpf_deploy_gate.py
scripts/deploy/test_xpf_deploy_nicorder.py
scripts/deploy/test_xpf_deploy_robustness.py
scripts/deploy/xpf-deploy.py
scripts/dist/publish.py
scripts/dist/sign.py
scripts/image/bake.py
scripts/image/make_config_drive.py
scripts/image/test_bake_sign_ordering.py
scripts/image/test_validate_scenarios.py
scripts/image/validate.py
scripts/iperf-json-metrics.py
scripts/mtr_report_check.py
scripts/test_mtr_report_check.py
scripts/userspace_ha_validation_matrix_test.py
test/incus/cluster_status_parse.py
test/incus/cluster_status_parse_test.py
test/incus/cold-path-flooder/src/main.rs
test/incus/cos_be_contention_validate.py
test/incus/cos_be_contention_validate_test.py
test/incus/cos_port_grid_test.py
test/incus/fairness_cov.py
test/incus/fairness_cov_test.py
test/incus/fairness_equal_flow_capture.py
test/incus/fairness_multi_sample.py
test/incus/fairness_multi_sample_test.py
test/incus/fairness_surplus_giveback_validate.py
test/incus/fairness_surplus_giveback_validate_test.py
test/incus/iperf3_sum_parse.py
test/incus/iperf3_sum_parse_test.py
test/incus/mouse_latency_aggregate.py
test/incus/mouse_latency_aggregate_test.py
test/incus/mouse_latency_orchestrate.py
```

## Module-by-module log

### pkg/cli/*_test.go (3 files)
- testpolicy_srcport_test.go: exercises `test policy` src-port parsing. Checked that ParsePort validation is exercised via CLI path, no new logic. Negative.
- usage_matchpolicies_3628_test.go: pins usage string contains new selectors. Negative — display-only.
- zone_flood_counters_hide_test.go: checks screen flood counters hidden. Negative.

### pkg/ddns (all non-test + tests)
- backend.go: record construction, DNSUpdater interface, nopUpdater. Checked exact-RR discipline, no truncate. Negative — sound.
- backend_bind.go: source-address / interface / VRF binding. Checked dialer.Control merges source bind + SO_BINDTODEVICE, family gate sourceMatchesDialFamily, #2901 fix. Negative — correct, dual-stack safe.
- backend_cloudflare.go: zone resolution, listRecords, Upsert/Delete with prevAddr value-specific replace (#3739), content-scoped delete (#2770). Checked PrevAddr handling, auth header not logged. Negative.
- backend_duckdns.go: token in query param, scrubbed via doRequest, sibling guard, domain reduction. Checked duckdnsDomain case-insensitive strip. Negative.
- backend_dyndns2.go: endpoint resolution, hostless rejection (#3737), offline=YES withdraw, sibling guard. Checked Hostname() vs Host usage. Negative — correct.
- backend_generic.go: template expansion, token-bounded success matcher (#2838 fix), delete unsupported. **One low finding**: authority parsing allows ":8080" (empty host with port) — see F-01.
- backend_http.go: shared HTTP client, bindCacheKey NUL-separated, reap closes idle conns, scrubURLError strips query/userinfo, doRequest fail-closed on bind error via callers. Checked cache invalidation, size bound. Negative.
- backend_rfc2136.go: DHCID computation, self-owned vs lease path, TSIG, source bind, unsigned warn once, value-specific replace. Checked rcodeError typed, isPTRSkippable, exchange TCP retry context derivation. Negative — extensive, sound.
- backend_route53.go: SigV4 signing, UPSERT/DELETE, normalizeHostedZoneID, r53DeleteAlreadyGone marker strings. Checked buildChangeBatch TTL, XML header, error surfacing. Negative.
- checkip.go: validateCheckIPURL scheme/host gate, IsPublicAddr special-purpose tables, allowlist parsing, regex permissive but gated. Checked CheckIPBound fail-closed (#3733). Negative.
- hostname.go: deriveFQDN, finalizeFQDN zone containment, firstSanitizedLabel, sanitizeLabel LDH + max 63/253. Checked relabel on foreign TLD, empty domain handling. Negative.
- manager.go: reconcileOnceLocked 2-pass (delete-before-add), blockedIdentity/Address/FQDN maps, gatedScope per-RG stop-writing-never-withdraw (#2664), untrusted family fail-safe, degraded fail-closed (#2650), write-ahead durability (#2662), dhcidSharedWithOther (#2700), scopeFor family fallback. Checked familyOwnsRecords, resolveFamilyUpdater per-family independence (#2663). Negative — complex but correct.
- sigv4.go: canonicalURI per-segment escape, canonicalQuery sorted, signedHeaders, payload hash, signingKey derivation. Checked host header handling, empty path -> "/". Negative — matches AWS docs, pinned by sigv4_test.go.
- state.go: ddnsState load with corrupt/unsupported version classification, quarantine, save deterministic sort, scopePrefix zero-scope -> "" preserving pre-P1b key, ownedRecordKey, withScope nil for zero. Negative.
- surface_a.go: SurfaceAManager reconcile with lock release around providerIO/observeIO (#2778/#3736), change-detect + forced-refresh + error backoff per-op tagging (#4423), seedFromStore restart baseline (#3734), provider identity fingerprint + orphan alarm (#3735), backendFingerprint length-prefixed non-secret, siblingFamilyOwned (#3738), effectiveKey FQDN fold (#2903). Checked forceRefresh one-shot latch, degraded fail-closed, reap live set. Negative — very thorough.

### pkg/dhcp (8 files)
- dhcp.go: Manager lifecycle, Start atomic check-and-register, finishClient successor guard, Renew wait on done, getDUID cache + persist, leaseFromACKv4 mask reject (/0), classlessStaticRoutes RFC3442 supersede, runDHCPv4/runDHCPv6 T1/T2 loops, selectIANAAddress deterministic (#4383 fix), parseV6Reply stateless vs stateful, discoverIPv6Router NTF_ROUTER retry, applyAddress netlink, scheduleRecompile debounce, DeriveSubPrefix. Checked int->uint32 lease time (opts.LeaseTime int -> uint32) — schema bounds to 1.., trunc risk negligible. Checked DUID LLT time uint32(time.Since(epoch).Seconds()) — overflow after 2106, acceptable. Negative overall.
- commit.go: renewalTimers divide-first (leaseTime/8*3) avoiding overflow (#4526 fix), leaseContentChanged includes ClasslessRoutes, delegatedPrefixesChanged, commitLease prev address removal + fireGatewayChange outside mu + scheduleRecompile only on content change. Negative — correct.
- reconcile.go: fingerprintV4/V6, configFingerprintLocked, Reconcile diff on config identity only (#1793), prune maps to prevent Renew resurrection, stops collected outside lock. Negative.
- renew.go: buildV4RenewRequest (ciaddr set, no RequestedIP/ServerID), v4RenewDest unicast vs broadcast, buildV6RenewMessage IA_NA+IA_PD echo, RENEW includes server DUID, REBIND omits. Negative.

### pkg/dhcprelay (8 files)
- relay.go: computeDesired deterministic sort (#2348), relaySpec.equal, Manager.Apply diff stop/start without EADDRINUSE, runRelay session loop, runRelaySession giaddr resolve with retry, ifindex capture, client/server conn setup, l2Sender fail-soft, cancel watcher, ifindex drift + giaddr readdr watcher tolerant on resolve failure, handleServerResponses source validation (#4163) + unknown-src warn-once, deliverReply matrix (#2076), clientRequestRelayable includes INFORM/DECLINE but not RELEASE, resolveMaxHopCount, HopCount check before increment (>= not wrap), readBufSize 65535 (#3012). **One finding**: l2send totalLen uint16 truncation — see F-02.
- l2send_linux.go: AF_PACKET TX, per-send ifindex/MAC re-resolve, MTU guard, buildL2Reply hand-rolled eth/ip/udp, ipv4Checksum, htonsLocal. Checked DF flag, TTL, checksum, udp checksum 0 legal, closeOnce idempotent. **Finding F-02** details below. Negative otherwise.
- relay_giaddr_linux.go: netlink-backed primaryIPv4Lister with IFA_F_SECONDARY, fallback portable. Negative.
- sockopt_linux.go: setReusePort, setBindToDevice, setBroadcast via RawConn.Control. Negative.

### pkg/dhcpserver (10 files)
- dhcpserver.go: Manager Apply generation-ordered supersession (#1835 F2), async mailbox latest-wins, staleApplySkips, leaseSyncEnabled knob, kea config generation with stableGroups/stablePools (#2668), subnetInterface, warnAmbiguousV4SubnetSelection, canonicalMAC, keaExpiredLeasesMap nil/disabled omit (#1387 H1), parseLeaseCSV per-record lenient (#2154) + dedup + state/expire filter (#2085), generateKea4/6Config. Checked:
  - stableGroups sort makes subnet_id stable across reloads of unchanged config, but group rename still shifts IDs (see F-03 low). 
  - parseLeaseCSV FieldsPerRecord=-1 tolerant.
  - systemctlTimeout 15s.
  Negative otherwise.
- ddns_leases.go, lease_sync.go: SyncLease Remaining int from int64, splitV4/V6 identity, keaLeaseTypeToString/stringToKeaLeaseType inverse pair (#2268), splitV6Identity IAID parse error vs 0 (#2379), readSyncLeases fallback memfile, SeedSyncLeases re-anchor Remaining to now_local + Remaining (clock-skew safe), writeMemfile4/6 with csvField escape, writeMemfileAtomic chown to _kea. Checked int64->int Remaining truncation on 32-bit (not relevant on amd64). Negative.
- ddns.go (old shim): confirms NewManager wiring, degraded handling. Negative.

### pkg/natshow (6 files)
- natshow.go, dest.go, source.go, static.go, persistent.go: shared renderers, Reader interface, nil guard, IsLoaded check. Negative — pure display.

### pkg/policymatch (29 files)
- policymatch.go: 5-tier precedence (exact, from-any/to-any merged, both-any, global scoped, default), host-inbound separate path (matchJunosHost) with NO transit fallback, zoneKnown id 0 gate (#3355), globalScopeMatches, GlobalPolicyAppliesToZonePair, routeDropClass + advisory (#4373), contentRejected whole-snapshot fail-closed (#3727/#4394), scheduler gate (#3104) via PolicyInactiveFn, address matching with v4Empty/v6Empty both-families empty fail-closed (#3356/#2008/#3023), feed-aware expandBookName, portMatches, matchApp matchSingleApp protocol-less fail-closed, ICMP type/code (#3284), dst-port fail-closed on omitted (#3330), src-port fail-closed (#3415), excluded flag display, ParseSelectorArgs strict (#3696/#3709) duplicate/unknown/missing-value error, ParsePort/ParseICMPValue via ParseCanonicalUint (#3679). Negative — extensive, matches Rust policy.rs semantics.
- zone_detail_summary.go: ZoneDetailPolicySummary evaluation order, runtimeIDs span-accumulated, scheduler inactive display, policySetID advancing on nil (#3476), global tier via GlobalPolicyAppliesToZone. Negative.

### scripts/deploy (6 files)
- xpf-deploy.py: deploy/incus/libvirt, preflight fail-before-mutate, virtio-first ordering check (#H-22), NIC naming positional, day-0 ISO build with check-config, memory_mb parsing, pci_parts validation, Runner.run via run_capture, verify_signatures on fetch, watermark anti-rollback with _ver_key numeric split, _acquire_lease flock serialized, _clear_lease holder-guarded, kernel-roll drain confirmed, reboot detection, mixed-base gate _gate_mixed_base exact mirror of Go GateMixedBaseSwap with _u16 validation, image-roll lease ordering canonical sorted to avoid deadlock, holder sanitization. Checked TOCTOU in fetch_one (write .tmp then replace) — safe. Checked sign.verify_image_artifact per-file hash — safe. Negative overall — thorough.
- test_xpf_deploy_*.py: unit tests for nicorder, gate, correctness, disk, robustness. Negative.

### scripts/dist (2 files)
- sign.py: write_manifest duplicate basename reject, sign_manifest empty passphrase stdin, verify_signature, parse_manifest path traversal reject ("/", "\", "", ".", ".."), duplicate reject, digest 64-hex check, verify_and_read TOCTOU-safe copy-into-0700-tmp + verify copy + read copy (#1924 §5.2), verify_manifest_map parses verified bytes, verify_image_artifact per-file hash vs manifest entry. Negative — secure.
- publish.py: list_versions fail-closed on unsigned manifest, gate_images verify_manifest_map (TOCTOU-safe), per-file hash, orphan image artifact sweep, nested image artifact reject, unexpected file default-deny (HB165 H-5), symlink reject (dir + file), install.sh presence + placeholder key + marker + signature, archive_pubkey placeholder reject, _is_allowed_publish_file, gate_latest per-channel signature + TOCTOU-safe verify_and_read, gate_apt InRelease per-suite verify with ephemeral GNUPGHOME, pooled .deb placeholder keyring check, _gate_key_agreement fingerprint cross-check (installer vs keyring vs signer), dispatch. Negative — fail-closed, thorough.

### scripts/image (5 files)
- bake.py: RUNTIME_PACKAGES sync with debian/control, SYSCTL, GRUB_DROPIN init_on_alloc=0, SSHD_DROPIN, APT_UPDATE error-on=any + retry, discover_base_release pinned 26.04 (#1943), fetch_base re-verify cache against upstream SHA256SUMS, virt_customize single-kernel purge + hold + showhold per-package verify, frr-pythontools + growpart hard-assert, A/B UEFI slots, xpf-grow-root, seal removes /etc/xpf/.configdb etc, validate_gate_step before sign_manifest_step (#4017), finalize_artifacts ordering invariant, proto_lines best-effort, manifest with version fields. Negative — careful.
- make_config_drive.py: build_config_drive with xpfd check-config, _iso_tool, stage temp dir, volume label xpf-config. Negative.
- validate.py: Harness lifecycle, ensure_network, verify_signatures binds both qcow2+metadata to single manifest (AGY-A3), import_image, launch with extra_nics for cluster naming, drop/cleanup, _wait, scenario_a..qemu, _qemu_img_verdict format+virtual-size floor, _kver_ge, maybe_reexec_incus_admin sg quoting. Negative.
- test_bake_sign_ordering.py, test_validate_scenarios.py: pin ordering invariants. Negative.

### scripts (3 files)
- iperf-json-metrics.py, mtr_report_check.py, userspace_ha_validation_matrix_test.py: parsing + validation helpers. Negative.

### test/incus (14 files)
- cluster_status_parse.py, fairness_*.py, iperf3_sum_parse.py, mouse_latency_*.py, etc.: parsing, CoV, multi-sample, surplus giveback, BE contention. Checked for int truncation — Python int unlimited, no overflow. Negative — harness logic.

---

## Findings

### F-01: ddns generic backend allows empty-host with port (`http://:8080`) as valid url-template

Title: Generic DDNS url-template validation allows empty host when authority is `:port` — accepted at construction, fails only at first publish
Severity: Low
Confidence: Medium
Evidence:
  File: /home/ps/git/avacado-xpf/pkg/ddns/backend_generic.go:109-138
  ```go
  func validateGenericURLTemplate(tmpl string) error {
      i := strings.Index(tmpl, "://")
      if i < 0 {
          return fmt.Errorf("url-template %q must be an http(s) URL (no scheme)", config.RedactURL(tmpl))
      }
      scheme := tmpl[:i]
      if !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
          return fmt.Errorf("url-template %q must be an http(s) URL", config.RedactURL(tmpl))
      }
      // Authority: between "://" and the first '/', '?' or '#'. Strip any userinfo
      authStart := i + len("://")
      authEnd := len(tmpl)
      for j := authStart; j < len(tmpl); j++ {
          if c := tmpl[j]; c == '/' || c == '?' || c == '#' {
              authEnd = j
              break
          }
      }
      authority := tmpl[authStart:authEnd]
      if at := strings.LastIndex(authority, "@"); at >= 0 {
          authority = authority[at+1:]
      }
      if authority == "" {
          return fmt.Errorf("url-template %q has no host", config.RedactURL(tmpl))
      }
      return nil
  }
  ```
Trace:
  1. Operator configures `backend generic` with `url-template http://:8080/update?host=%h&ip=%i` (typo — omitted hostname, only port).
  2. `validateGenericURLTemplate` parses scheme `http`, authority `:8080`. `authority != ""` so returns nil — accepted at commit and at backend construction (`newGenericBackend`).
  3. On first reconcile, `renderGenericURL` produces `http://:8080/update?host=...`. `http.NewRequest` parses it — `url.Parse` succeeds with Host `:8080`, Hostname `""`.
  4. The HTTP client dials `:8080` which fails / connects to unexpected host, or the request fails at `doRequest`. The error surfaces as a transient publish failure, retried with backoff, never flagged as a construction-time config error.

  Contrast with dyndns2 path which correctly rejects empty host:
  ```
  pkg/ddns/backend_dyndns2.go:121: if u.Hostname() == "" { return "", fmt.Errorf(... "has no host") }
  ```

Refutation attempt: Checked whether `http.NewRequest` or `url.Parse` would reject `http://:8080` earlier with a clear error. `url.Parse("http://:8080")` returns `Host=":8080"`, `Hostname()=""`, no error. `http.NewRequest` does not reject. The dyndns2 code explicitly checks `Hostname() == ""` to catch `:8080`. The generic path only checks `authority == ""`, so `:8080` passes. It is not caught by the later `validateCheckIPURL`-style check because generic validation is string-based deliberately (to allow `%h/%i/%u/%p` placeholders).

HPC/invariant: N/A.

Why it matters: A typo `http://:8080` is accepted as valid config, commits clean, and only surfaces as a perpetual transient DDNS publish failure with backoff. The operator gets no commit-time warning, and the failure looks like a provider outage rather than a misconfiguration.

Fix direction: In `validateGenericURLTemplate`, after stripping userinfo, split authority on `:` to extract host part, or use `net.SplitHostPort` tolerant parsing, and require the host part non-empty. E.g.:

  ```go
  host := authority
  if strings.Contains(host, ":") {
      h, _, err := net.SplitHostPort(host)
      if err == nil {
          host = h
      } else {
          // no port, but contains colon — could be IPv6 literal or malformed
          if strings.HasPrefix(authority, "[") {
              // bracketed IPv6 — extract inside brackets
          }
      }
  }
  if host == "" {
      return fmt.Errorf("url-template %q has no host", config.RedactURL(tmpl))
  }
  ```

  Mirror the dyndns2 `u.Hostname() == ""` check where possible (after expanding placeholders to dummy values for parsing).

Labels: ddns, generic-backend, validation

Dedup note: Not in dedup index. Checked #4309 (relay overrides), #4308 (ARP), #3733 (checkip sourcebind), #4437 (surface_a sourcebind), #2841 (generic URL validation — this is a residual gap in #2841's own fix: it added scheme+host validation but the host check is `authority == ""` which misses `:port`).

---

### F-02: dhcprelay l2send buildL2Reply total length truncates to uint16 on jumbo DHCP packets

Title: `buildL2Reply` IPv4 total-length field truncates when DHCP payload exceeds 65527 bytes → malformed IPv4 header
Severity: Low
Confidence: High
Evidence:
  File: /home/ps/git/avacado-xpf/pkg/dhcprelay/l2send_linux.go:164-189
  ```go
  func buildL2Reply(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP,
      payload []byte) []byte {
      udpLen := udpHeaderLen + len(payload)
      totalLen := ipv4HeaderLen + udpLen
      frame := make([]byte, ethHeaderLen+totalLen)

      // ...

      // --- IPv4 header (20 bytes), starts at offset 14 ---
      ip := frame[ethHeaderLen : ethHeaderLen+ipv4HeaderLen]
      ip[0] = 0x45 // Version 4, IHL 5 (20 bytes)
      ip[1] = 0x00 // DSCP/ECN
      binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
      // ...
      binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
  ```
  `totalLen` and `udpLen` are `int` from `len(payload)` (up to 65535 from `readBufSize`). `uint16(totalLen)` truncates when `totalLen > 65535`.

Trace:
  1. Client sends a DHCP packet with a very large option set (classless static routes, many vendor options, or jumbo MTU) — `n` up to 65535 bytes (readBufSize).
  2. Relay receives it on client listener: `n, _, _ := conn.ReadFrom(buf)` where `buf` is `[65535]byte`.
  3. Server replies with `YourIPAddr` + similar large options, `pkt.ToBytes()` ≈ 65535 bytes.
  4. `handleServerResponses` → `deliverReply` → `sendReply` with `payload` = server reply (≈ 65535 bytes).
  5. `buildL2Reply`: `udpLen = 8 + 65535 = 65543` → `uint16(65543) = 8` (wraps). `totalLen = 20 + 65543 = 65563` → `uint16(65563) = 28`. The IPv4 header claims total length 28, UDP length 8, but frame is actually `14+65563` bytes. Client receives malformed packet, drops it. The relay then falls through? No — `sendReply` returns nil (no error from `Sendto` because kernel sends the malformed frame), so `deliverReply` counts `repliesL2Unicast++` and returns true — the caller thinks delivery succeeded but client got garbage.

Refutation attempt: Checked whether MTU guard prevents this. `sendReply` has:
  ```go
  l3Size := ipv4HeaderLen + udpHeaderLen + len(payload)
  if iface.MTU > 0 && l3Size > iface.MTU {
      return fmt.Errorf("reply L3 size %d exceeds MTU %d on %s", l3Size, iface.MTU, ...)
  }
  ```
  On a typical interface MTU 1500, a 65535-byte payload would be `l3Size=65563 > 1500` → returns error → caller falls back to broadcast. So on normal MTU, the truncation is never reached because MTU guard fires first. However, on a jumbo MTU (9000) or if MTU is 0 (unknown / not set), the guard does not fire and truncation occurs. Also `iface.MTU` could be 65535 on some tunnel/VRF setups. The truncation is latent but reachable on non-standard MTU.

HPC/invariant: `uint16(totalLen)` truncation, `uint16(udpLen)` truncation. IPv4 total length field is 16-bit by spec (max 65535), so a payload that makes totalLen > 65535 is inherently unrepresentable in IPv4. The correct behavior is to refuse L2 path and fall back to broadcast/kernel-fragmented path when `totalLen > 65535`.

Why it matters: On jumbo-MTU or MTU-unknown interfaces, a large DHCP reply (e.g., PXE boot with many options) would be L2-unicast with a truncated IPv4 length, causing the client to drop it. The relay counts it as success, so no retry via broadcast. The client would never get its lease, appearing as a DHCP failure only on specific MTU configs.

Fix direction: In `buildL2Reply` (or `sendReply` before calling it), check if `totalLen > 65535` or `udpLen > 65535` and return an error to trigger broadcast fallback:

  ```go
  if totalLen > 65535 || udpLen > 65535 {
      return nil, fmt.Errorf("reply too large for IPv4 (%d bytes)", totalLen)
  }
  ```

  Or in `sendReply` before `buildL2Reply`:
  ```go
  if l3Size > 65535 {
      return fmt.Errorf("reply L3 size %d exceeds IPv4 max 65535", l3Size)
  }
  ```

  The MTU guard already exists; adding the IPv4-max guard is a one-line extension.

Labels: dhcprelay, l2-unicast, integer-truncation, mtu, pxe

Dedup note: Not in dedup index. Checked #4309 (relay max-hop-count), #4308 (gratuitous-arp etc), #2076 (L2 unicast feature). None mention IPv4 length truncation. #3012 mentions readBufSize 65535 but does not discuss L2 path truncation.

---

### F-03 (Low, informational): dhcpserver subnet_id stability across group rename

Title: `stableGroups` sorts by group name for deterministic subnet_id, but renaming a DHCPServerGroup changes every subnet's ID and remaps live Kea memfile leases to wrong subnets
Severity: Low
Confidence: Medium
Evidence:
  File: /home/ps/git/avacado-xpf/pkg/dhcpserver/dhcpserver.go:718-739
  ```go
  func stableGroups(groups map[string]*config.DHCPServerGroup) []*config.DHCPServerGroup {
      names := make([]string, 0, len(groups))
      for name := range groups {
          names = append(names, name)
      }
      sort.Strings(names)
      out := make([]*config.DHCPServerGroup, 0, len(names))
      for _, name := range names {
          out = append(out, groups[name])
      }
      return out
  }
  ```
  And subnet_id assignment:
  ```go
  subnetID := 1
  for _, group := range stableGroups(cfg.DHCPLocalServer.Groups) {
      for _, pool := range stablePools(group.Pools) {
          sub := keaSubnet4{ ID: subnetID, ... }
          subnetID++
  ```

Trace:
  1. Operator has groups `alpha` (subnet 10.0.1.0/24, subnet_id=1) and `beta` (subnet 10.0.2.0/24, subnet_id=2). Kea memfile binds leases by subnet_id.
  2. Operator renames `alpha` → `zeta` (no address change). `stableGroups` now orders `beta` (id=1), `zeta` (id=2) — IDs swapped.
  3. Kea reloads config: memfile lease `10.0.1.5` with `subnet_id=1` now binds to `beta`'s subnet (10.0.2.0/24). The lease is mis-bound; client renew may fail or get wrong options.

Refutation attempt: Checked whether Kea itself re-binds leases by subnet prefix rather than ID on reload. Kea's memfile loader does use subnet_id to locate the subnet; if ID not found, it may try to match by interface or prefix, but the documented behavior is ID-based. The code comment in `stableGroups` says "the SAME logical subnet always gets the SAME subnet_id across reloads of an unchanged config" — true for unchanged config, but not for group rename. Group rename is a valid operator action. Is there a better key? Subnet prefix itself is stable across group renames (`stablePools` sorts by subnet string within group, but group order is by name). A global sort by subnet prefix across all groups would be fully stable.

HPC/invariant: N/A.

Why it matters: Renaming a DHCP server group (a cosmetic change) silently remaps live leases to wrong subnets, causing clients to get NAK or wrong pool on renew. The failure is silent and appears only after the rename commit.

Fix direction: Option 1 — assign subnet_id by sorting ALL pools globally by subnet prefix (not by group name then pool). Option 2 — document that group rename changes subnet IDs and requires lease file clear. Option 1 is more robust: collect all pools with their group context, sort by subnet prefix globally, assign IDs. Or use a hash of subnet prefix as ID (Kea requires int, but hash mod 2^31 could work, though collision risk). The current `stableGroups` + `stablePools` is stable for unchanged group names but not for renames.

Labels: dhcpserver, kea, subnet-id, rename, stability

Dedup note: Not in dedup index. Checked #2668 (stableGroups/stablePools deterministic ordering) — this finding is a follow-up gap in #2668: it made IDs stable across reloads of same config but not across group renames. Not previously filed.

---

### F-04: Negative results (required per contract)

#### DDNS module — negative results
- `pkg/ddns/backend_bind.go`: Dual-stack source bind with `sourceMatchesDialFamily` checked — family mismatch skips bind, SO_BINDTODEVICE always applied. No goroutine leak (no goroutine spawned). No integer truncation (port 53 is constant, timeout is time.Duration).
- `pkg/ddns/backend_cloudflare.go`, `backend_duckdns.go`, `backend_dyndns2.go`, `backend_route53.go`: All validate endpoint URL at construction, reject empty host (except F-01 residual), fail closed to nopUpdater on missing credential. No secret leak (Reveal() only at construction, never in error/log). No TOCTOU.
- `pkg/ddns/backend_http.go`: `httpClientCache` mutex protects map, `reap` closes idle conns under lock, `closeIdleConns` seam for test, `bindCacheKey` NUL-separated prevents collision (interface "a\x00b" vs "a"+"\x00"+"b"). `scrubURLError` strips query/userinfo. No finding.
- `pkg/ddns/checkip.go`: `validateCheckIPURL` requires http(s) scheme + non-empty host, case-insensitive. `IsPublicAddr` covers special-purpose v4/v6 plus stdlib predicates. `parseCheckIPBody` allowlist skip correct. No integer truncation.
- `pkg/ddns/hostname.go`: `sanitizeLabel` trim dashes after truncation, `sanitizeFQDN` drops empty labels, `finalizeFQDN` zone containment via suffix check on sanitized forms, `firstSanitizedLabel` skips empty labels. No panic on empty input (returns error). No finding.
- `pkg/ddns/manager.go`: Degraded fail-closed, per-family independence (#2663), per-RG gate (#2664) with double-check on owned records (direct `scopeAdmits` re-eval for steady-state partial demotion), write-ahead durability (#2662), dual-stack DHCID sharing (#2700), untrusted family mass-delete fail-safe, nil gate standalone. No goroutine leak (no goroutines spawned in manager). Ownership store never deletes non-owned. Negative.
- `pkg/ddns/sigv4.go`: Minimal signer pinned by tests, canonical request ordering correct, host header handling, empty path → "/". No secret in error. Negative.
- `pkg/ddns/state.go`: Load classifies corrupt vs unreadable (quarantine only on corrupt/unsupported, not on transient IO), save deterministic sort, `scopePrefix` zero-scope → "" preserves pre-P1b key, `withScope` nil for zero. Negative.
- `pkg/ddns/surface_a.go`: Lock discipline providerIO/observeIO releases mu around 15s wire op, panic-safe via defer, seedFromStore restart baseline prevents write storm, orphan alarm idempotent, backendFingerprint non-secret length-prefixed, siblingFamilyOwned computed under lock, effectiveKey FQDN fold, forceRefresh one-shot, degraded fail-closed. No goroutine leak (no new goroutines). Negative.

#### DHCP module — negative results
- `pkg/dhcp/dhcp.go`: Start atomic check-and-register prevents Renew vs Reconcile race, finishClient successor guard prevents slow old defer clobbering new client's lease, DUID persistence durable via fsatomic, leaseFromACKv4 mask validation rejects /0 and non-contiguous, classlessStaticRoutes RFC3442 supersede, selectIANAAddress deterministic longest preferred-lifetime, DHCPv4 NAK revocation (#3956), DHCPv6 stateless mode Information-Request, path MTU etc. No integer overflow (LeaseTime int seconds fits uint32 for any practical lease). Negative.
- `pkg/dhcp/commit.go`: renewalTimers divide-first avoids overflow (#4526 already fixed), leaseContentChanged includes ClasslessRoutes, commitLease prev address removal, fireGatewayChange outside mu, scheduleRecompile debounce, delegatedPrefixesChanged order-sensitive but harmless. Negative.
- `pkg/dhcp/reconcile.go`: Fingerprint excludes lease state (#1793), prune option maps even for deregistered clients (Codex fix), stops outside lock, Start inside Reconcile performs desired-set check atomically. Negative.
- `pkg/dhcp/renew.go`: buildV4RenewRequest correct RFC2131 (ciaddr set, no RequestedIP/ServerID), v4RenewDest unicast vs broadcast, buildV6RenewMessage IAID from MAC last 4 bytes matches acquisition, IA_PD hint not merged on renew. Negative.

#### DHCPRelay module — negative results
- `pkg/dhcprelay/relay.go` (excluding F-02): computeDesired deterministic sort, relaySpec.equal includes maxHopCount, Manager.Apply diff without EADDRINUSE, runRelay session loop with drift/readdr, resolveGIAddrWithRetry bounded cancelable, handleServerResponses source validation (#4163) + warn-once, deliverReply matrix, clientRequestRelayable, hop count check before increment (no uint8 wrap), readBufSize 65535 (#3012). No integer truncation in hop count (uint8 compare safe because resolveMaxHopCount returns 1..16, HopCount uint8 0..255, check `>=` before `++`). Negative otherwise.
- `pkg/dhcprelay/l2send_linux.go` (excluding F-02): AF_PACKET TX, per-send re-resolve, MTU guard, closeOnce, nil guard, src/dst MAC len checks, src/dst IP To4 checks, ipv4Checksum, htonsLocal via BigEndian/NativeEndian. No finding otherwise.
- `pkg/dhcprelay/relay_giaddr_linux.go`, `sockopt_linux.go`: Netlink primaryIPv4Lister with IFA_F_SECONDARY, SO_REUSEPORT/BINDTODEVICE/BROADCAST via RawConn.Control. Negative.
- `pkg/dhcprelay/delivery_test.go`, `l2send_test.go`, `relay_test.go`: Unit tests for delivery matrix, L2 frame bytes, relay lifecycle. Negative — tests exist and pass.

#### DHCPServer module — negative results
- `pkg/dhcpserver/dhcpserver.go` (excluding F-03): Generation-ordered supersession, async mailbox latest-wins monotonic gen guard, stableGroups/stablePools deterministic, ambiguous v4 subnet warning, canonicalMAC colon-lowercase, keaExpiredLeasesMap nil/disabled omit, parseLeaseCSV per-record lenient + dedup + correct, clearFamilyLocked fail-closed, writeKeaConfig AtomicGenerated. No DHCP IP exhaustion bug (Kea handles pool depletion). No finding otherwise.
- `pkg/dhcpserver/lease_sync.go`: Clock-skew-safe Remaining (expire - now_sender, re-anchored at seed), lease type inverse pair total, splitV6Identity IAID parse error vs 0, read fallback memfile, seed conflict -> update idempotent, writeMemfile chown to _kea with fsatomic.WithOwner no post-rename window. No TOCTOU in lease sync (control socket + memfile are Kea-owned). Negative.
- `pkg/dhcpserver/ddns_leases.go`, `ddns.go`: Lease parsing, DDNS identity encoding. Negative.

#### NATShow / PolicyMatch / CLI tests — negative results
- `pkg/natshow/*`: Display-only, nil guards, no policy enforcement. Negative.
- `pkg/policymatch/policymatch.go` (full): 5-tier precedence, host-inbound separate, zoneKnown id 0 gate, global scope matching, route-drop advisory, content-rejected fail-closed, scheduler gate, address excluded logic with v4Empty&&v6Empty both-families check, feed-aware, ICMP type/code, port omitted fail-closed, protocol omitted fail-closed, selector args strict, etc. All checked against dedup entries (#4394, #4365, #3355, #3356, #3357, #3727, #3104, #3330, #3415, #3323, #3696, #3709, #3685, #4373). No new bug found — extensive correctness, matches Rust policy.rs.
- `pkg/policymatch/zone_detail_summary.go`: Tier ordering, policySetID advance on nil, runtimeIDs, scheduler inactive, modifiers. Negative.
- `pkg/cli/*_test.go`, `pkg/policymatch/*_test.go` (25 test files): Pins for display, parity, edge cases. All negative — tests validate existing fixes, no new logic.

#### Scripts — negative results
- `scripts/deploy/xpf-deploy.py`: Verified preflight fail-before-mutate, virtio-first ordering, NIC naming positional, day-0 ISO validation, memory_mb, pci_parts strict DDDD:BB:DD.F, fetch TOCTOU-safe (.tmp + replace), per-file hash verification, watermark anti-rollback with numeric _ver_key, _acquire_lease flock + holder guard, kernel-roll drain confirmed + revert detection + half-roll lease hold, image-roll mixed-base gate exact mirror with _u16 range check, _gate_mixed_base fail-closed on missing/unknown/out-of-range. Negative — thorough, no new TOCTOU or scheme bypass found.
- `scripts/dist/sign.py`: TOCTOU-safe verify_and_read (copy to 0700 tmp, verify copy, read copy), parse_manifest path traversal reject, duplicate reject, digest validation. Negative.
- `scripts/dist/publish.py`: Fail-closed gates, orphan sweep top-level + nested, unexpected file default-deny, symlink reject, install.sh checks, archive key checks, key-agreement cross-check, latest.json per-channel, apt InRelease per-suite, pooled deb placeholder check. Negative.
- `scripts/image/bake.py`: Pinned 26.04, base re-verify, single-kernel purge + hold per-package verify, frr-pythontools + growpart hard-assert, A/B slots, seal, validate-before-sign (#4017), proto_lines best-effort. Negative.
- `scripts/image/validate.py`: Single-manifest bind (AGY-A3), qemu-img format+virtual-size floor, boot leg with serial capture, TOCTOU-safe manifest selection. Negative.
- `test/incus/*.py` (10 files): Parsing, CoV, multi-sample, BE contention, iperf3 sum, mouse latency. Python int unlimited, no truncation. Negative.

---

## Summary

Three low-severity findings in this batch (no critical/high):

| # | File | Severity | Title |
|---|------|----------|-------|
| F-01 | `pkg/ddns/backend_generic.go:109` | Low | Generic url-template allows empty host with `:port` |
| F-02 | `pkg/dhcprelay/l2send_linux.go:164` | Low | L2 reply IPv4 total-len truncates to uint16 on jumbo DHCP (>65535) |
| F-03 | `pkg/dhcpserver/dhcpserver.go:718` | Low (info) | Subnet_id shifts on group rename — live Kea leases mis-bound |

All other modules in this 150-file batch are **negative** — the code already handles the known dedup-index issues, fail-closed on malformed inputs, and correctly implements the documented invariants (DDNS never-delete-non-owned, DHCP renewal RFC-correct, relay hop-limit before increment, policy simulator parity with Rust, deploy TOCTOU-safe fetch, image sign-before-publish ordering, etc.).

No new critical/high security or data-plane bypass issues found. No VRRP/HA cold-boot, dataplane integer-truncation into Rust u16/u8, or DDNS goroutine-leak issues found in this batch — the relevant Go->Rust truncation sites are in `pkg/dataplane/userspace` (not in this batch), and DDNS managers use no background goroutines (reconcile is synchronous, driven by daemon's singleflight).
