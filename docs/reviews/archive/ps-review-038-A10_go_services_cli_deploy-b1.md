# Review A10_go_services_cli_deploy — batch 1/3
Base: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Batch files: 150 (bpf/headers/*, cmd/cli/*, cmd/shimverify/*, cmd/xpfd/*, pkg/cli/*)

## Module-by-module log

### bpf/headers (6 files) — retained Rust AF_XDP shim parity headers
- xpf_common.h: constants, struct pkt_meta (u32 pkt_len fix #860), zone/META_FLAG/screen/host-inbound defines. MAX_EXT_HDRS=6 retained. Checked against userspace-dp MAX_IPV6_EXT_HEADERS=8 — known open #4555, not re-reported.
- xpf_conntrack.h: session_key/value v4/v6, TCP state machine, timeout defaults. Struct sizes checked — no truncation.
- xpf_helpers.h: parse_ethhdr/vlan, parse_iphdr/ipv6hdr (MAX_EXT_HDRS loop bound 6), checksum partial handling, flow timeout table, zone counters. No new bug.
- xpf_maps.h: legacy eBPF map defs (HASH/ARRAY/RINGBUF etc) retained for build parity only. MAX_ZONES 64, MAX_SESSIONS 10M etc. No runtime path in batch.
- xpf_nat.h: NAT rewrite v4/v6, embedded ICMP rewrite, NPTv6 translate. l3_offset/l4_offset bounds 64/128, pkt_len u32, emb_ip_off u16 — safe. No truncation beyond verifier mask &0x3F (correct).
- xpf_trace.h: debug trace macros, BPFRX_TRACE=0 disabled. No runtime effect.

Negative: No new policy enforcement bug in headers; all bounds checks present. Integer sizes align with Rust side per publish_conntrack parity tests.

### cmd/cli (15 test files + 6 impl)
- clear.go: port validation 1-65535 correct (Atoi then range check before uint32 cast) — safe.
- main.go: ping count/size, traceroute, handleCommit, rollback (#3447 fix verified). Dispatch respects rl==nil non-TTY guard (#1563). No truncation beyond int->int32 for proto Count (5 default, user controlled, server validates).
- monitor.go: remote monitor; handleMonitorSecurityPacketDrop (see Finding F1) — Atoi without range check before uint32. Protocol/server validates but UX gap.
- request.go, shared.go: rollback strict parse (#3447), pipe handling, extractPipe LastIndex correct. No truncation.
- show.go: parseFlowSessionArgs validates zone ParseUint 32, ports Atoi 1-65535 before uint32, limit int32 >=1. showZones per #3654/#3683 renders split host-inbound + global/default tiers correctly. showPoliciesFiltered per #3357 scoped-global filter correct.
- main_test.go, nontty_test.go, policymatch_dup_3709_test.go, query_strictness_3696_test.go, request_wireguard_test.go, rollback_3447_test.go, show_*_test.go, testpolicy_*_test.go, usage_matchpolicies_3628_test.go: test coverage for #3447/#3654/#3669/#3683/#3696/#3709 — all assertions match impl, no missing edge.

### cmd/shimverify
- main.go: build-time verifier gate, exits 3 on REJECT, 2 usage, 1 other. Takes single arg path, no validation needed (operator tool). No TOCTOU.

### cmd/xpfd (5 files)
- main.go: check-config path — Stat then ReadFile with IsRegular + size cap 4MiB, re-checks size after read (comment notes Stat advisory). TOCTOU symlink swap mitigated by RO-mounted day-0 drive; closest open issue is deploy TOCTOU but not in batch scope. Cold-path mask validation (pow2-1) correct.
- publish_generation.go: host-wide upgrade lock serializes against cut, GC protects pinned journal generation. Correct.
- seed_runtime.go: first-install idempotent Seed, --capability-check side-effect-free retained for old postrm compat (#1985). Correct.
- upgrade.go / upgrade_kernel.go: thin dispatch to pkg/upgrade — flag parsing, lock acquire, exit codes 0/1/2/3 correct. No truncation.

### pkg/cli (100+ files)
- app_resolve.go: resolveAppName (see Finding F2) — uint16(v)==dstPort without range validation on v.
- apply.go, apply_syslog_zonemap_3704_test.go: StableZoneID collision handling via QuarantinedZoneNames correct (#3719).
- chrony.go, cli.go, cli_config.go, cli_dispatch.go, cli_helpers.go, cli_request_policies_check.go, cli_show*.go, cli_show_security*.go, completion.go, host_inbound_display_*.go, link.go, monitor*.go, peer.go, permissions.go, proto.go, session_display.go, session_filter.go: no high/med policy bypass found. See detailed checks below:
  - session_filter.go: ports Parse Atoi 1-65535 before uint16 — safe; proto numeric 1-255 validated; zone name->ID via cr.ZoneIDs with validate() failing unknown zone (no clear-all).
  - session_display.go: VlanID int 0-4094 -> uint16 safe; Number int -> uint16 safe within 0-65535.
  - monitor.go: trace file sanitizeTraceFilename (bare basename, no /,\, no . / ..), openTraceFile O_NOFOLLOW, 0600, regular-file check — secure (#3378). rotateTraceFile GC enforces maxFiles, fails closed on rename error (#3379). parseMonitorTrafficArgs keyword guard prevents interface/matching/count swallowing (#4540). validateMonitorFilter rejects -w/-z option smuggling with leading-quote peel (#4556). Correct.
  - permissions.go: showConfigRedacted true for non-super-user, PermAll bypass, unknown class fail-closed redacted. requiredPermission gates monitor traffic PermControl and request failover PermMaint with prefix resolution — correct (#4067/#4108).
  - cli_show_security_zones.go: explicit any vs wildcard, lifeline set, policy tiers via ZoneDetailPolicySummary SSOT — correct.
  - cli_show_security_screen.go: ScreenEnabledCheckList SSOT (#3327) prevents drift, per-reason table (#3343) includes port-scan/ip-sweep/session-limit.

---

## Findings

### F1 — cmd/cli remote monitor packet-drop: missing client-side port range validation (defense-in-depth UX)

Title: Remote monitor packet-drop accepts out-of-range port without client error, relying on server rejection
Severity: Low
Confidence: High
Evidence: `/home/ps/git/avacado-xpf/cmd/cli/monitor.go:294-324`
```go
case "source-port":
    if i+1 < len(args) {
        i++
        if v, err := strconv.Atoi(args[i]); err == nil {
            req.SourcePort = uint32(v)
        }
    }
case "destination-port":
    if i+1 < len(args) {
        i++
        if v, err := strconv.Atoi(args[i]); err == nil {
            req.DestinationPort = uint32(v)
        }
    }
```
Trace: operator types `monitor security packet-drop source-port 70000` → remote CLI parses 70000 → uint32(70000) → gRPC MonitorPacketDropRequest → server Validate rejects with InvalidArgument (per server_packet_drop_validation_3382_test.go:84-85 "source-port over 65535") → operator sees opaque gRPC error instead of immediate local diagnostic. Local CLI (`pkg/cli/monitor.go:511-528`) uses `ParseUint(...,10,16)` which rejects >65535 locally with "invalid source-port".
Refutation attempt: N/A (Low)
HPC/invariant check: N/A
Why it matters: Inconsistent surfaces (local strict, remote lenient) confuse operators; negative testing of port filters in docs/tests would see different behavior.
Fix direction: Mirror local CLI: use `strconv.ParseUint(v,10,16)` or `Atoi` + `1..65535` range check with explicit error before building request, matching `pkg/cli/monitor.go` and `cmd/cli/clear.go` pattern.
Labels: cli, integer-truncation, ux
Dedup note: Not in dedup index. Checked #4540 (interface keyword), #4005 (matching), #4556 (quote strip), #3382 (server validation exists but this is client-side parity). Distinct from #4569/#4567 network truncation.

### F2 — app_resolve.go: uint16 truncation without range guard on destination-port string

Title: resolveAppName truncates arbitrary int to uint16 before comparison, false-matching crafted port strings
Severity: Low
Confidence: Medium
Evidence: `/home/ps/git/avacado-xpf/pkg/cli/app_resolve.go:74-78`
```go
} else {
    if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort {
        return name
    }
}
```
Trace: config contains `application foo destination-port 70000` (invalid but compiler may not reject if app not validated elsewhere) → resolveAppName("tcp", 4464) called for session display → Atoi 70000 → uint16(70000)=4464 → matches dstPort 4464 → wrong app name displayed as "foo" instead of correct or "". Range variant: "65536" → uint16=0 → matches dstPort 0 (ICMP? / zero port) causing mislabel.
Refutation attempt: Checked config compiler — application destination-port likely validated elsewhere, so 70000 would normally be rejected at commit. However resolveAppName is display-only, not dataplane, and is called from `pkg/cli/session_filter.go` via AppID? No — session_filter uses different path (appid.SessionMatches). This path is only for human-readable app name in show outputs, not enforcement. Therefore no policy bypass, only display confusion.
Why it matters: Mis-identified application in `show security flow session` / zone display erodes operator trust during incident response; violates principle of not silently truncating.
Fix direction: Validate `v >=1 && v <=65535` before `uint16(v)==dstPort`, or use `ParseUint(portStr,10,16)` and compare directly. Mirror pattern already used elsewhere (`session_filter.go:146-147`).
Labels: display, integer-truncation
Dedup note: Not in dedup index. Checked #4569 (fragment DENY), #4555 (ext hdr), #4572 (workers overflow). Distinct — this is app name display, not dataplane enforcement.

### F3 — Informational: ping/traceroute count/size negative accepted client-side (minor)

Title: Remote ping count/size accepts negative Atoi without local rejection
Severity: Low (informational)
Confidence: High
Evidence: `/home/ps/git/avacado-xpf/cmd/cli/main.go:294-300`
```go
if v, err := strconv.Atoi(args[i]); err == nil {
    req.Count = int32(v)
}
```
Trace: `ping 10.0.0.1 count -5` → Atoi -5 → int32(-5) → proto allows int32, server may interpret as 0 or loop. Same for size.
Why it matters: Minor UX, not security.
Fix: Reject count<=0, size<=0 locally like clear.go does.
Labels: cli, low
Dedup note: Not in dedup index.

---

## Negative results (required)

- **bpf/headers xpf_common.h/xpf_maps.h**: No integer overflow in MAX_* constants; MAX_SESSIONS 10M fits 32-bit; MAX_INTERFACES 65536 fits uint32; policy counts 4096*256=1,048,576 fits array. Checked against dedup #4572 (workers*32 overflow) — different module (heartbeat map), not in headers.
- **bpf/headers xpf_helpers.h parse_ipv6hdr**: MAX_EXT_HDRS=6 loop bound verified; mismatch with userspace 8 is open #4555 — intentionally not re-reported per instruction.
- **bpf/headers xpf_nat.h**: l3_offset/l4_offset bounds 64/128 prevent verifier escape; nat64_translate 16-byte memcpy uses __u8[16] not truncated.
- **cmd/cli/clear.go, show.go**: Port validation 1-65535 present, prevents uint16 truncation (contrast with F1). Zone ID ParseUint 32 → uint32 correct.
- **pkg/cli/session_filter.go**: Port validation 1-65535 before uint16 cast — correct pattern, no truncation.
- **pkg/cli/monitor.go**: Port ParseUint 16-bit — correct, no truncation; O_NOFOLLOW, sanitize, 0600 — secure.
- **pkg/cli/session_display.go VLAN**: VlanID 0-4094 fits uint16, Number similar — safe truncation.
- **cmd/xpfd main.go check-config**: Size cap 4MiB + post-read re-check mitigates TOCTOU growth; IsRegular mitigates FIFO/char-dev; symlink swap still possible but day-0 RO-mount mitigates. No new deploy TOCTOU beyond documented advisory.
- **cmd/xpfd publish_generation/seed_runtime/upgrade**: Locking, atomic publish, GC protection, capability-check idempotence — no TOCTOU or scheme bypass found.
- **Zone policy display parity**: cmd/cli/show.go and pkg/cli/cli_show_security_zones.go both correctly render [zone-pair]/[global]/[default] tiers, scoped-global per-rule filtering via GlobalPolicyAppliesToZone, any vs * normalization via matchScopeZone — matches local/gRPC surfaces. Tests in show_zones_tiers_3683_test.go, show_zones_hostinbound_3654_test.go, show_policies_scoped_global_3357_test.go all pass.
- **Application matching**: pkg/cli/app_resolve.go aside from F2 truncation, range handling for "8080-8090" correct (Atoi lo/hi then int(dstPort) in range). Builtin table complete.
- **Default deny/permit**: showMatchPolicies renders server-provided Action ("permit (default)" vs hard-coded deny) per #3283, host-inbound SSOT HostInboundShowLine per #3655 — correct.
- **DDNS/observability resource safety**: No goroutine leak on hostname flip, no DHCP exhaustion in batch (DHCP manager not in batch), monitor trace writer bounded by maxSize/maxFiles, rotate fails closed — safe.

## Dedup index cross-check

Checked all 50+ open entries and 70+ closed entries. Findings F1/F2/F3 do not match:
- #4555 (ext hdr 6 vs 8) — headers mismatch acknowledged, not re-reported.
- #4572 (workers*32 overflow) — different counters.
- #4569/#4567 (fragment bypass) — dataplane policy, not CLI.
- #4515 (zone→undefined-iface warn-only) — config compiler, not CLI.
- #4540 (monitor traffic interface keyword) — related but different token (interface vs port).
- #3382 (server packet-drop validation) — server fix exists, this is client parity gap.
