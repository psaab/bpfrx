# xpf firewall deep audit — A10: Services (DHCP/DDNS/simulator) + CLI/show + build/deploy — ps-review-037-A10-b1

Base: d4506d4450e23f9a3fc572206b3c82f6b6c99029 (master HEAD)
Date: 2026-07-07
Reviewer: A10 subagent (protocol + tooling generalist)
Output: /tmp/ps-review-037-A10-b1.md

## Orientation

xpf: stateful firewall, Junos config syntax, Rust AF_XDP userspace dataplane (only runtime). A10 scope: pkg/dhcp/ (dhcp.go, commit.go, renew.go, reconcile.go), pkg/dhcprelay/ (relay.go, relay_giaddr_linux.go, l2send_linux.go), pkg/dhcpserver/ (dhcpserver.go, ddns_leases.go), pkg/ddns/ (manager.go, surface_a.go, backend_rfc2136.go, backend_http.go, backend_cloudflare.go, backend_duckdns.go, backend_dyndns2.go, backend_route53.go, backend_generic.go, backend_bind.go, checkip.go, state.go, sigv4.go), pkg/policymatch/ (policymatch.go), pkg/cli/ (cli.go, cli_dispatch.go, cli_request.go, cli_show.go, cli_show_security.go, permissions.go, monitor.go, monitor_interface.go), scripts/deploy/xpf-deploy.py, scripts/dist, scripts/image.

## Dedup (do NOT re-report)

- CLOSED: #4562, #4556 cli/api LOW, #4555 XDP EH (OPEN LOW), #4549 LOW batch, #4548, #4547, #4546, #4544, #4543, #4541, #4540 monitor keyword (includes monitor_traffic_keyword_4540_test.go), #4539, #4535, #4534, #4526 DHCP renewalTimers overflow (CLOSED), #4525 RA randomAdvInterval (CLOSED), #4524 monitor injection (HIGH CLOSED), #4521, #4519, #4518, #4517, #4514, #4487/#4453/#4400, #4399/#4438, #4392, #4388, #4384, etc.
- OPEN (skip unless new): #4559 deterministic NAT, #4555, #4549, #4548, #4533, #4515, #4512, #2387, #4146, #3226, #2852, #2562, #4478, #4455, #4313, #4498, #4508, #4499, #4497, #4484 L-batch (L-1 REST audit-gap etc.), #4422-#4404, etc.
- Prior: /tmp/ps-review-018..036 — 14 files on master

---

## FINDING A10-01: CLI monitor traffic count negative/unbounded

**Title:** CLI `monitor traffic count` accepts negative values and unbounded large values via Atoi without range check

**Severity:** Low

**Confidence:** Medium

**Evidence:**

- `pkg/cli/cli_request.go:519-559`:
```go
        case "count":
            if i+1 >= len(args) || monitorTrafficKeywords[args[i+1]] {
                return "", "", "", fmt.Errorf("monitor traffic: 'count' requires a value")
            }
            i++
            count = args[i]
            if _, cerr := strconv.Atoi(count); cerr != nil {
                return "", "", "", fmt.Errorf("monitor traffic: 'count' requires a numeric value, got %q", count)
            }
```
`strconv.Atoi` accepts `-1`, no sign check, no upper bound.

- `pkg/cli/cli_request.go:586-591`:
```go
func buildMonitorTrafficArgv(iface, filter, count string) []string {
    cmdArgs := []string{"tcpdump", "-i", iface, "-n", "-l"}
    if count != "0" {
        cmdArgs = append(cmdArgs, "-c", count)
    }
```
Passes `-1` / `999999999` to `tcpdump -c`.

- Contrast `pkg/cli/monitor.go:868-876`:
```go
            v, err := strconv.Atoi(args[i])
            if err != nil || v < 1 || v > 8192 {
                fmt.Println("error: count must be 1..8192")
                return nil
            }
```
`monitor security packet-drop` correctly bounds 1..8192; `monitor security flow file size` 10240..1073741824, `files` 2..1000.

**Trace:** `handleMonitorTraffic` → `parseMonitorTrafficArgs` (Atoi no range) → `buildMonitorTrafficArgv` → `exec.CommandContext(ctx, "tcpdump", "-i", iface, "-n", "-l", "-c", count, "--", filter...)` → tcpdump error for `-1` (opaque) or long-running capture for huge count hogging AF_PACKET CPU, hiding XDP-redirect traffic (warning already printed).

**Refutation attempt:** Not High (Low), no refutation required.

**HPC check:** `monitor traffic` runs tcpdump (AF_PACKET) per operator request, not dataplane hot path, but huge count pins CPU and can delay operator's own incident response.

**Why it matters:** Poor UX (`count -1` → "invalid packet count" from tcpdump not CLI), operator self-DoS with `count 1000000000`. Inconsistent with sibling commands which bound.

**Fix direction:**
```go
v, err := strconv.Atoi(count)
if err != nil || v < 0 { return error }
if v > 1000000 { return error } // or 8192 like packet-drop, keep 0=unlimited
```
Allow 0 = unlimited (existing). Reject negative explicitly.

**Labels:** `low`, `cli`, `integer`, `monitor`, `ux`

**Dedup note:** #4540 (monitor keyword) fixed missing-value/keyword swallowing but not numeric range/negative residual. Not in #4556, #4549.

---

## FINDING A10-02: Deploy day-0 ISO world-readable secret leak

**Title:** `xpf-deploy.py build_config_drive` day-0 ISO 0o644 world-readable contains config.Secret leaves

**Severity:** Medium

**Confidence:** High

**Evidence:**

- `scripts/deploy/xpf-deploy.py:314-333`:
```python
    stage = tempfile.mkdtemp(prefix="xpf-day0-")
    try:
        shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
        os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
        ...
        if mkiso == "xorriso":
            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
                    "-J", "-r", "-o", iso, stage]
        else:
            argv = [mkiso, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", iso, stage]
        run_capture(argv)   # creates iso with umask 0o022 → 0o644
        print(f"==> built day-0 drive {iso} (label xpf-config)")
```
`tempfile.mkdtemp` mode 0o700 safe for staging dir, but final `iso = os.path.join(os.getcwd(), f"{ap['name']}-day0.iso")` created by xorriso/genisoimage inherits umask (typically 0o022 → 0o644) in CWD which may be world-readable (shared builder home). ISO contains `xpf.conf` which embeds `system root-authentication`, `security ike policy pre-shared-key`, `system login`, `snmp community`, `ddns tsig-secret`, `dynamic-dns provider api-token/password`, etc.

**Trace:** `deploy_incus` / `deploy_libvirt` → `build_config_drive` (creates 0o644 ISO in CWD) → `incus config device add ... day0 disk source=iso` / `virt-install --disk path=iso,device=cdrom` → ISO persists after deploy until `destroy` deletes it; world-readable window for exfil on shared build host / CI cache. Other UID: `isoinfo -R -i fw1-day0.iso -x /xpf.conf` → IKE PSKs.

**Refutation attempt (High):** Not High (Medium). Could argue builder is single-user. Mitigated: CI runners, shared jump hosts, university labs are multi-user; ISO persists. Staging dir 0o700 mitigates `/tmp` attack but not final ISO. Even if host is single-user, backup/snapshot leaks.

**HPC check:** Deploy tooling, not dataplane hot path; no perf impact.

**Why it matters:** Day-0 `xpf.conf` is most secret-bearing file (root password hash, IKE PSKs, SNMP communities, DDNS TSIG, provider tokens). Leaking via world-readable ISO violates secret-at-rest contract. Persists until `destroy`.

**Fix direction:** After `run_capture(argv)`, `os.chmod(iso, 0o600)`. Also change staging `xpf.conf` to `0o600` defense-in-depth (dir 0o700 currently protects but `0o644` is misleading). Or run mkisofs with `umask 0o077` wrapper / `install -m 0600` equivalent.

**Labels:** `medium`, `deploy`, `secret-leak`, `python`, `build`

**Dedup note:** New; not in #4484 L-batch (L-1 REST audit-gap etc.), not in prior deploy reviews (fable-165 H-21..H-30). #1924 signing covers image, not day-0 ISO.

---

## NEGATIVE FINDINGS (verified correct, no bug)

### N-A10-01 — DHCPRelay giaddr primary selection

**Evidence:** `pkg/dhcprelay/relay_giaddr_linux.go:22-74` netlink `IFA_F_SECONDARY` aware, `selectPrimaryIPv4` prefers non-secondary. `pkg/dhcprelay/relay.go:437-507` `defaultIfaceResolver` via seam. Correct, #2849.

### N-A10-02 — DHCPRelay HopCount loop protection

**Evidence:** `pkg/dhcprelay/relay.go:1144-1156` check `>= maxHopCount` before `HopCount++`, no wrap. `resolveMaxHopCount` 1..16 clamp. Correct, #4309.

### N-A10-03 — DHCPRelay source allow-list

**Evidence:** `pkg/dhcprelay/relay.go:1220-1292` `allow []net.IP` built once, `replySourceAllowed` via `net.IP.Equal`, drop+count, warn-once. Tests `delivery_test.go:704-894`. Correct, #4163.

### N-A10-04 — DHCPRelay delivery matrix + NAK/FORCERENEW

**Evidence:** `pkg/dhcprelay/relay.go:1386-1452` NAK force-broadcast, alwaysBroadcast, flag1 broadcast, yiaddr L2+fallback, ciaddr unicast. Tests `TestDeliverReply_Matrix`, `TestDeliverReply_Nak_AlwaysBroadcast`, `TestHandleServerResponses_NakForwarded`, `TestHandleServerResponses_ForceRenewForwarded`. Correct, #2076/#2606/#2645.

### N-A10-05 — DHCP renewal timers overflow fix

**Evidence:** `pkg/dhcp/commit.go:55-65` `t2Remaining = leaseTime/8*3` divide-first, no overflow. Test `commit_test.go:76-79` `0xFFFFFFFF * time.Second`. Correct, #4526.

### N-A10-06 — DHCP degenerate mask reject

**Evidence:** `pkg/dhcp/dhcp.go:948-964` `bits !=32 || ones==0` reject 0.0.0.0/0 and non-contiguous. Test `renew_test.go:460-536`. Correct, #4101.

### N-A10-07 — DHCP NAK revocation

**Evidence:** `pkg/dhcp/dhcp.go:770-796` immediate `abandonLeaseAfterNAK`, `finishClient` dereg. Tests `renew_test.go:285-440`. Correct, #3956.

### N-A10-08 — DHCP classless routes RFC3442 / option 121 supersedes option 3

**Evidence:** `pkg/dhcp/dhcp.go:994-1084` `classlessStaticRoutes` present → ignore option 3. Tests `classless_routes_test.go`. Correct, #4118.

### N-A10-09 — DDNS PrevAddr self-owned exact-RR, Cloudflare value-specific

**Evidence:** `pkg/ddns/backend_rfc2136.go:818-842` exact-RR delete prev + Insert atomic. `pkg/ddns/surface_a.go:1206-1212` threads `rec.PrevAddr` from `prevOwned.AddrText` (not empty Address). `pkg/ddns/backend_cloudflare.go:217-260` lists all, PATCH prevContent else POST, never recs[0] foreign clobber. Correct, #3739 H11 + #3734/M02.

### N-A10-10 — DDNS KeepForwardDHCID / SiblingFamilyOwned dual-stack guards

**Evidence:** `backend_rfc2136.go:940-986` keepDHCID omits DHCID from Remove but keeps prerequisite. `backend_duckdns.go:162-172` skip clear, `backend_dyndns2.go:178-192` skip offline. Tests `backend_dualstack_withdraw_3738_test.go` 4 FAIL-ON-REVERT. Correct, #2700/#3738.

### N-A10-11 — DDNS IsPublicAddr / checkip martian filter

**Evidence:** `checkip.go:151-221` specialPurposeV4/V6 tables + stdlib predicates, `IsPublicAddr` exported for `staticUnitAddr` #2776, `parseCheckIPBody` skips `!IsPublicAddr` + `isAllowlisted`. Correct.

### N-A10-12 — DDNS credential redaction

**Evidence:** `backend_http.go:301-318` `scrubURLError` strips query+userinfo. `backend_generic.go:104-138` `validateGenericURLTemplate` uses `RedactURL`, template-aware. `backend_generic.go:174-183` avoids raw URL in error. `readCappedBody` 64KiB. Correct, #2841/#2781.

### N-A10-13 — DDNS checkip source-bind fail-closed

**Evidence:** `checkip.go:69-100` `CheckIPBound` fail-closed on `bindErr!=nil`. Tests `checkip_sourcebind_failclosed_3733_test.go` 3 tests. `surface_a.go:497-549` fail-closed propagates to nopUpdater. Correct, #3733/#4437.

### N-A10-14 — DDNS httpClientCache reuse + reap

**Evidence:** `backend_http.go:107-224` `httpClientCache.clientFor` keyed on binding, error not cached, `reap` closes idle. Tests `surface_a_httpcache_2904_test.go` + `surface_a_httpcache_reap_2956_test.go`. Correct, #2904/#2956.

### N-A10-15 — DDNS backends withdraw / Publish

**Evidence:** duckdns Upsert ip/ipv6 Delete clear sibling-skip; dyndns2 Upsert hostname+myip Delete offline sibling-skip; generic validate/render/whole-token #2838 Delete keeps ownership; route53 UPSERT/DELETE SigV4 idempotent `r53DeleteAlreadyGone`. Correct, #2770/#2772/#2838/#2841.

### N-A10-16 — DDNS state durability / degraded / write-ahead

**Evidence:** `state.go:326-402` fail-closed corrupt/unsupported → degraded+quarantine, save sorted fsync 0600. `manager.go:310-347` `loadStateOrDegrade`. `surface_a.go:1153-1324` write-ahead before wire, `providerIO` unlock, racing-op revalidation. Correct, #2650/#2662/#2778/#2971.

### N-A10-17 — Policy simulator parity

**Evidence:** `policymatch.go:791-939` routeDrop defer, content-rejection early, `RuntimePolicyIDs`, junos-host separate gate, `zoneKnown` #3355, tiers exact/single-wildcard merged #3090/both-any/global #3148/default-policy. `349-473` `ParseSelectorArgs` strict unknown/missing/duplicate #3709 + per-value canonical #3679/#3116/#3108/#3284. `85-184` `ValidatePort`/`ParsePort`/`ParseICMPValue`/`ValidateProtocol`. `694-710` `routeDropClass` nil dst = wildcard. `941-1020` `matchJunosHost`. Correct, #3042/#3090/#3104/#3116/#3284/#3355/#3414/#3627/#3679/#3696/#3709/#3727/#4394.

### N-A10-18 — CLI test policy / show match-policies same SSOT

**Evidence:** `cli_request.go:173-290` `testPolicy` `ParseSelectorArgs` + `policymatch.Match` with `feedOverlay` + `policyInactiveFn`. `cli_show_security.go` same. No shadow matcher. Correct, #3042.

### N-A10-19 — CLI monitor traffic injection closed

**Evidence:** `cli_request.go:586-610` `"--"` before filter, `626-652` `monitorFilterOptionToken` peels leading `'`/`"` then `tok[0]=='-' && len>1`, `644-652` `validateMonitorFilter`, `571-579` `stripSurroundingQuotes`. Tests `monitor_traffic_injection_4524_test.go` + `monitor_traffic_quotestrip_4556_test.go` + `monitor_traffic_keyword_4540_test.go`. Correct, #4524 HIGH CLOSED + #4556 N-01.

### N-A10-20 — CLI permissions / redaction / monitor_interface VMIN/VTIME / trace rotation

**Evidence:** `permissions.go:27-53` unknown class deny, custom class `MappedPermissions` #4304, `showConfigRedacted` unknown→true #4099, `monitor traffic`→`PermControl` #4067, `request system reboot`→`PermMaint` #4108. `monitor_interface.go:56-99` VMIN=0/VTIME=1 #3985. `monitor.go:76-114` `rotateTraceFile` fail-closed, `openTraceFile` O_NOFOLLOW 0600 #3378/#3379. Correct.

### N-A10-21 — Deploy safe: yaml.safe_load, ssh shlex.quote, fetch verify, NIC order, preflight, signing

**Evidence:** `xpf-deploy.py:265` `yaml.safe_load`. `1049-1083` `_node_exec` `shlex.quote` per argv, no `--` before remote. `877-965` verifies every artifact vs manifest+sig, anti-rollback `_ver_key` numeric-split rc10>rc9, `os.replace(dst+".tmp",dst)` atomic in CWD. `212-259` virtio-before-hardware check. `404-468` preflight fail-before-mutate. Correct, fable-165 H-21..H-30, #1924.

### N-A10-22 — Misc integer / truncation false positives verified

**Evidence:** `pkg/dhcp/dhcp.go:585-590` DUID-LLT uint32 wraps 2136 acceptable, persisted. `pkg/dhcp/commit.go:55-65` divide-first. `pkg/dhcprelay/relay.go:1514-1527` ifname max 15 <255. `pkg/ddns/state.go:146-164` ScopeKey prefix fixed order, sanitized.

---

## Summary

2 actionable, rest NEGATIVE:

- **A10-01 Low:** `monitor traffic count` accepts `-1` and unbounded → reject negative, cap (e.g. 1..8192, allow 0 unlimited). Residual of #4540.
- **A10-02 Medium:** `xpf-deploy.py` day-0 ISO 0o644 world-readable leaks secrets → `chmod 0o600` ISO + staging `xpf.conf`.

No new High. Strong defense-in-depth verified: DDNS ownership (PrevAddr exact-RR, Cloudflare value-specific, DHCID/sibling guards), DHCP safety (mask reject, NAK revocation, classless RFC3442, renewal overflow fix), policy simulator strictness+parity, CLI injection closed, permissions/redaction, deploy signing/NIC order/preflight.
