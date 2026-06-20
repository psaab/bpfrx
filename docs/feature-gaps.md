# xpf vs Juniper vSRX Feature Gap Analysis

Last updated: 2026-05-24

> #1373 dataplane note: the Rust AF_XDP userspace dataplane is the
> primary/default target for new dataplane work. Rows that mention only eBPF
> describe legacy/regression coverage unless userspace is explicitly named.
> The authoritative retirement gate for userspace-vs-legacy behavior is
> [`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

> [!IMPORTANT]
> DPDK retired in #1525. References below to "eBPF and DPDK" or
> "eBPF, DPDK, and userspace" parity describe the pre-retirement
> state; the DPDK backend is removed in #1527/#1528.

## Summary

| Category | Fully Missing | Partially Implemented | Parse-Only | Total Gaps |
|----------|--------------|----------------------|------------|------------|
| Security Policies (Unified/Advanced) | 7 | 1 | 0 | 8 |
| Application Security (AppSecure) | 8 | 1 | 0 | 9 |
| IDP/IPS | 8 | 0 | 0 | 8 |
| Content Security (UTM) | 6 | 0 | 0 | 6 |
| SSL/TLS Inspection | 4 | 0 | 0 | 4 |
| Advanced Threat Prevention | 5 | 1 | 0 | 6 |
| User/Identity Firewall | 5 | 0 | 0 | 5 |
| NAT Enhancements | 5 | 0 | 0 | 5 |
| Screen/IDS Enhancements | 4 | 2 | 0 | 6 |
| Security Flow Enhancements | 5 | 0 | 0 | 5 |
| ALG Enhancements | 9 | 0 | 0 | 9 |
| Security Logging Enhancements | 0 | 0 | 0 | 0 |
| PKI / Certificates | 3 | 1 | 0 | 4 |
| Routing Enhancements | 10 | 3 | 0 | 13 |
| VPN Enhancements | 9 | 0 | 0 | 9 |
| HA Enhancements | 0 | 2 | 0 | 2 |
| Firewall Filter Enhancements | 2 | 0 | 0 | 2 |
| QoS / Class of Service | 2 | 4 | 0 | 6 |
| Multi-Tenancy | 4 | 0 | 0 | 4 |
| Management & Automation | 12 | 2 | 0 | 14 |
| Interface Enhancements | 1 | 1 | 0 | 2 |
| System Enhancements | 5 | 0 | 0 | 5 |
| Miscellaneous | 6 | 0 | 0 | 6 |
| **TOTAL** | **119** | **18** | **0** | **137** |

**Implementation status key:**
- **Fully Missing**: No config parsing or runtime support
- **Partially Implemented**: Some aspects work but incomplete
- **Parse-Only**: Config is parsed into AST/types but has no runtime effect

---

## 1. Security Policies (Unified/Advanced)

xpf has zone-based policies with source/dest address, application match, permit/deny/reject actions, logging, counting, and schedulers. Match also supports the family-scoped wildcards `any-ipv4` / `any-ipv6` (normalized to `0.0.0.0/0` / `::/0` at compile time) and the `source-address-excluded` / `destination-address-excluded` modifiers (invert the per-side match in the dataplane), per #2008 H11/H2. The `any-ipv4` / `any-ipv6` wildcards are family-scoped on BOTH the v3 and legacy dataplane parse paths — they match only their own family and never leak across to the opposite family. A policy match address that is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP is hard-rejected at commit (a typo cannot silently ship); the dataplane additionally fails CLOSED on an unexpectedly empty `*-address-excluded` set (defense in depth — an empty excluded set denies rather than inverting into match-all). These gaps represent vSRX-specific advanced policy features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Unified Policies** | `security policies ... match dynamic-application` | Single policy combining L3/L4 + L7 app + URL category + user identity match conditions. Foundation for modern SRX policy management. | High | Missing (requires AppID) |
| **Dynamic Application Match** | `security policies ... match dynamic-application junos:FTP` | Match on L7-detected application identity within security policy | High | Missing (requires AppID) |
| **URL Category Match** | `security policies ... match url-category ...` | Match web traffic by URL category (shopping, social-media, etc.) | Medium | Missing |
| **Source Identity Match** | `security policies ... match source-identity ...` | Match on authenticated user identity (AD user/group) in policy | Medium | Missing (requires user-id) |
| **Application Services in Policy** | `security policies ... then permit application-services` | Attach UTM, IDP, SSL-proxy, AppFW, ICAP redirect, SecIntel to policy action | High | Missing |
| **Policy Rematch** | `security policies policy-rematch` | Re-evaluate existing sessions when policy changes | Medium | Missing |
| **Policy Scheduling (time ranges)** | `schedulers scheduler ...` | Time-based policy activation/deactivation with start/stop dates | Low | Userspace propagation landed in #1396. #1378 is closed: scheduler state, hit-counter survival, strict missing-scheduler behavior, deterministic evidence validation, and live HA artifact capture are complete for userspace. |
| **Reject Action with Profile** | `security policies ... then reject profile ...` | Custom ICMP/TCP-RST reject messages, redirect URLs for blocked content | Low | Missing |

---

## 2. Application Security (AppSecure)

The AppSecure suite is a major differentiator for the vSRX as an NGFW. xpf now has real end-to-end AppID plumbing for L3/L4 application-catalog classification: the control plane ships the `(protocol, port-range) → app_id` catalog to the userspace dataplane in the config snapshot (`app_catalog`), the dataplane stamps the matched `app_id` on each new conntrack session at create time, and `show security flow session` resolves it back to the application name (#2008 M5). It still does not have a full Junos L7 DPI/signature engine.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Application Identification (AppID)** | `services application-identification` | L7 DPI engine using signatures, heuristics, pattern matching. Identifies 4000+ apps regardless of port/protocol. Foundation for all AppSecure features. | High | Partial — L3/L4 catalog classification only; L7 DPI / signature engine is **not implemented**. The userspace dataplane stamps the matched catalog `app_id` on each session (#2008 M5) so `show security flow session` reports the real application; with the knob enabled, a session matching no catalog entry resolves to `UNKNOWN` (honest) instead of a built-in port guess. Full contract: [docs/services-application-identification.md](services-application-identification.md); operator-facing status: `show services application-identification status`. (#653) |
| **Application Tracking (AppTrack)** | `security application-tracking` | Log and report on applications traversing the device. Generates AppTrack log messages per session with app name, bytes, duration. | Medium | Missing |
| **Application Firewall (AppFW)** | `security application-firewall ...` | (Legacy, replaced by unified policies) Policy enforcement based on detected app identity | Medium | Missing |
| **Application QoS (AppQoS)** | `class-of-service application-traffic-control` | QoS rate-limiting and marking based on detected application | Medium | Missing |
| **Application Quality of Experience (AppQoE)** | `N/A (service suite / policy integration)` | Monitor application quality and user experience, correlate application behavior to network quality, and feed optimization / reporting workflows. Called out as part of the vSRX Content Security Bundle feature set. | Low | Missing |
| **Advanced Policy-Based Routing (APBR)** | `security advance-policy-based-routing profile ...` | Route traffic to different routing instances based on L7 application identity. Profile with rules matching apps/groups to routing-instance. Applied per-zone. | Medium | Missing (xpf has filter-based PBR but not L7-aware) |
| **Application Signature Package** | `request services application-identification download` | Downloadable/updatable signature database, predefined app groups (junos:social-networking, junos:web:streaming, etc.) | Medium | Missing |
| **Application System Cache** | `services application-identification application-system-cache` | Cache app identification results for faster classification of subsequent connections from same source | Low | Missing |
| **Custom Application Signatures** | `services application-identification application ... signature ...` | User-defined L7 signatures with byte patterns for custom/proprietary applications | Low | Missing |

---

## 3. Intrusion Detection & Prevention (IDP/IPS)

IDP is a core NGFW feature supported on vSRX with subscription license. xpf has no IDP engine.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **IDP Policy** | `security idp idp-policy ...` | Policy with rulebases (IPS, exempt) containing match conditions and actions (close-client, close-server, drop, notify, ignore) | High | Missing |
| **Signature Database** | `security idp security-package` | 15,000+ predefined attack signatures, automatic updates from Juniper | High | Missing |
| **Protocol Anomaly Detection** | `security idp idp-policy ... rulebase ips rule ... match attacks predefined-attack-groups` | Detect non-RFC-compliant protocol behavior (65+ protocol decoders, 500+ contexts) | High | Missing |
| **Custom Attack Objects** | `security idp custom-attack ...` | User-defined signatures with regex patterns, protocol contexts, severity levels | Medium | Missing |
| **Dynamic Attack Groups** | `security idp dynamic-attack-group ...` | Auto-grouping based on severity, category, application, CVSS score filters | Medium | Missing |
| **IDP Sensor Configuration** | `security idp sensor-configuration ...` | Tuning parameters: flow-level vs packet-level, performance vs accuracy | Low | Missing |
| **Recommended Policy** | `security idp active-policy recommended` | Pre-built policy curated by Juniper Security Team | Low | Missing |
| **IDP SSL Inspection** | (deprecated in favor of SSL proxy) | Inspect encrypted traffic using loaded RSA private keys | Low | Missing |

---

## 4. Content Security (UTM)

UTM features require subscription license on vSRX. xpf has no content inspection engine.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Antivirus** | `security utm feature-profile anti-virus ...` | Signature-based AV scanning (Avira engine on vSRX 3.0). File-based and express modes for HTTP, FTP, SMTP, POP3, IMAP. | Medium | Missing |
| **Web Filtering (EWF)** | `security utm feature-profile web-filtering juniper-enhanced ...` | Enhanced Web Filtering: 90+ URL categories, cloud-based categorization, safe search enforcement | Medium | Missing |
| **Anti-Spam** | `security utm feature-profile anti-spam ...` | SMTP spam filtering using Sophos/SBL block lists, real-time blocklist checks | Low | Missing |
| **Content Filtering** | `security utm feature-profile content-filtering ...` | Block/permit by MIME type, file extension, protocol command, embedded object type | Low | Missing |
| **UTM Custom Objects** | `security utm custom-objects ...` | MIME patterns, filename extensions, URL patterns, URL categories for UTM matching | Low | Missing |
| **UTM Policies** | `security utm utm-policy ...` | Named UTM profiles that aggregate AV, web-filter, anti-spam, content-filter and attach to security policies via `application-services utm-policy` | Medium | Missing |

---

## 5. SSL/TLS Inspection

SSL proxy is supported on vSRX 3.0 and enables inspection of encrypted traffic for IDP, AppFW, UTM, etc.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SSL Forward Proxy** | `services ssl proxy profile ... actions ...` | MITM decryption of outbound TLS: terminate client session, establish new session to server, inspect cleartext. Applied via security policy `application-services ssl-proxy`. | Medium | Missing |
| **SSL Reverse Proxy** | `services ssl proxy profile ... protect-server ...` | Decrypt inbound TLS for server protection. Load server's private key to terminate sessions. | Low | Missing |
| **SSL Decryption Mirroring** | `services ssl proxy ... decryption-mirror ...` | Mirror decrypted traffic to analysis tool/SPAN port | Low | Missing |
| **Certificate Management for SSL** | `security pki ... ; services ssl proxy root-ca ...` | Root CA generation, trusted CA stores, certificate exemptions per URL category, allowlisting by domain | Medium | Missing |

---

## 6. Advanced Threat Prevention (ATP)

ATP Cloud integration provides cloud-based threat analysis. xpf has dynamic
address feeds which partially overlap with SecIntel. As of #2049 these feeds
are ENFORCED: a policy/NAT rule referencing a feed-backed `address-name` now
has the live feed prefixes overlaid into the userspace dataplane's address
book (the `apply_snapshot` the AF_XDP helper enforces), and a feed refresh
republishes the snapshot. Previously the prefixes were fetched and shown but
never reached the forwarding path.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SecIntel Threat Feeds** | `services security-intelligence profile ...` | Cloud-curated threat intelligence feeds: C&C servers, attacker IPs, malicious URLs, infected hosts. Applied via security policy. | Medium | Partial (xpf dynamic address feeds are fetched, refreshed, and now ENFORCED via policy/NAT address-name bindings (#2049); SecIntel-format profile integration is still missing) |
| **Malware Sandboxing** | `services advanced-anti-malware policy ...` | Cloud-based sandbox analysis of unknown files (ATP Cloud). File submission, verdict caching. | Low | Missing |
| **Encrypted Traffic Insights** | `services ssl ... encrypted-traffic-insights ...` | Detect malware in encrypted traffic without decryption using TLS metadata analysis (JA3 fingerprints, certificate characteristics) | Low | Missing |
| **GeoIP Filtering** | `security intelligence ... geoip ...` | Block/allow traffic by geographic location of source/destination IP | Medium | Missing |
| **DNS Security** | `services security-intelligence profile ... category dns ...` | DNS request inspection, domain sinkholing, DNS tunneling detection | Medium | Missing |
| **Adaptive Threat Profiling** | `services security-intelligence profile ... adaptive-threat-profiling ...` | Automated threat intelligence generation from local traffic patterns | Low | Missing |

---

## 7. User/Identity Firewall

User-based policy enforcement integrating with directory services. Not implemented in xpf.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Integrated User Firewall** | `services user-identification active-directory-access ...` | Policy enforcement based on user identity. Reads AD event logs, LDAP queries for user-IP mapping. | Medium | Missing |
| **Captive Portal** | `services user-identification ... ; security policies ... then permit firewall-authentication web-redirect` | Web-based authentication portal for unauthenticated users. Redirect HTTP to login page. | Medium | Missing |
| **Pass-Through Authentication** | `security policies ... then permit firewall-authentication pass-through` | Transparent auth: prompt for credentials via FTP/Telnet/HTTP without redirect | Low | Missing |
| **User Role-Based Policies** | `security policies ... match source-identity role-name` | Security policies matching on user roles/groups from AD/LDAP directory | Medium | Missing |
| **JIMS Integration** | `services user-identification identity-management ...` | Juniper Identity Management Service for user-IP mapping from multiple auth sources | Low | Missing |

---

## 8. NAT Enhancements

xpf has SNAT (interface + pool, address-persistent, source-nat off bypass), DNAT (with pools, hit counters, source-address-name match, protocol-only match, port rewriting, multi-port matching), static 1:1, NAT64, and exemption rules. These are additional NAT features from the vSRX.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Proxy ARP for NAT** | `security nat proxy-arp interface ... address ...` | Auto-reply ARP for NAT pool addresses on same subnet as ingress interface. Required when SNAT pool or DNAT addresses are on same L2 segment. | High | **Done** -- Proxy ARP neighbor entries for NAT addresses with GARP on addition. Config: `set security nat proxy-arp interface <iface> address <addr>` with range support. |
| **Proxy NDP for NAT** | `security nat proxy-ndp interface ... address ...` | IPv6 equivalent of proxy ARP for NAT64/static NAT addresses | Medium | Missing |
| **Twice NAT** | Combination of SNAT + DNAT rule-sets matching same traffic | Simultaneous source and destination translation in single flow. | Medium | **Done** -- Combined SNAT+DNAT flows now preserve both translations in one session path. Static DNAT is keyed by ingress zone with wildcard fallback for SNAT return-path entries across eBPF and userspace (DPDK retired #1525). Userspace post-DNAT SNAT matching now evaluates destination filters against the translated destination, and session/gRPC visibility preserves both NAT legs. |
| **DNS ALG with NAT** | `security alg dns enable` | DNS payload rewriting when NAT changes embedded IP addresses (A/AAAA record doctoring) | Medium | Missing |
| **Overflow Pool** | `security nat source pool ... overflow-pool ...` | Fallback to interface NAT or another pool when primary SNAT pool is exhausted | Low | Missing |
| **Address Pooling (paired/no-paired)** | `security nat source pool ... address-pooling paired` | Per-pool override of global address-persistent: paired ensures same source always maps to same pool address; no-paired allows round-robin | Low | Missing |
| **Port Randomization Control** | `security nat source pool ... port-randomization disable` | Disable random port selection in SNAT (use sequential instead). Enabled by default. | Low | **Done** -- `port-randomization disable` now compiles for source pools and is enforced in XDP SNAT allocators (DPDK retired #1525). |
| **Deterministic NAT (Port Block Allocation)** | `security nat source pool ... port deterministic ...` | Predictable port mapping for logging compliance. Each source gets fixed port block. | Low | **Done** (`74e1d17`, `439cd3f`) -- IPv4 CGNAT + IPv6 NAPT64 deterministic allocation, address ranges, pool-utilization-alarm, Prometheus gauge |
| **NAT Pool Utilization Alarm (runtime consumer)** | `security nat source pool-utilization-alarm raise-threshold/clear-threshold` | Raise a `show security alarms` entry + NAT syslog event when a source pool's port utilization crosses the raise threshold; clear below the clear threshold. | Low | **Done** (#2079) -- 10s daemon monitor over the helper's last-applied NAT pool snapshot (`dp.AppliedNATView()`), transition-gated raise/clear with hysteresis, both `show security alarms` render sites + structured `RT_NAT` syslog, commit-time threshold validation. Previously parsed+stored with NO consumer (silent no-op). Deterministic pools skipped (block-based utilization is a follow-up). |

---

## 9. Screen/IDS Enhancements

xpf implements 11 screen checks (land, syn-flood, ping-death, teardrop, rate-limiting, ip-sweep, winnuke, syn-frag, syn-fin, no-flag, fin-no-ack) plus per-IP session limiting. These are additional vSRX screen options.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Session Limiting (source-ip)** | `security screen ids-option ... limit-session source-ip-based N` | Limit max concurrent sessions from single source IP (1-8M). Prevents session table exhaustion. | High | **Done** -- GC sweep counts active sessions per source IP, pushes to BPF LRU maps, xdp_screen enforces limits on TCP SYN. |
| **Session Limiting (dest-ip)** | `security screen ids-option ... limit-session destination-ip-based N` | Limit max concurrent sessions to single destination IP | High | **Done** -- Same mechanism as source-ip limiting but per destination IP. |
| **TCP Port Scan Detection** | `security screen ids-option ... tcp port-scan threshold N` | Detect TCP port scanning by counting unique destination ports per source within time window | Medium | Partial (threshold parsed but detection algorithm may be incomplete) |
| **UDP Port Scan Detection** | `security screen ids-option ... udp port-scan threshold N` | Same as TCP port scan but for UDP | Medium | Missing |
| **UDP Sweep Detection** | `security screen ids-option ... udp udp-sweep threshold N` | Detect UDP sweeps (same port, many destinations) | Low | Missing |
| **TCP Sweep Detection** | `security screen ids-option ... tcp tcp-sweep threshold N` | Detect TCP sweeps (same port, many destinations) | Low | Missing |
| **IP Block Fragment** | `security screen ids-option ... ip block-frag` | Block all IP fragments unconditionally | Low | Partial (fragment checks exist but not unconditional block option) |
| **IPv6 Extension Header Filtering** | `security screen ids-option ... ip ipv6-extension-header ...` | Filter/block specific IPv6 extension headers (hop-by-hop, routing, destination, fragment, mobility, no-next) | Medium | Missing |

---

## 10. Security Flow Enhancements

xpf has TCP session timeouts (established, initial, closing, time-wait), UDP/ICMP timeouts, TCP MSS clamping (IPsec, GRE in/out), allow-dns-reply, allow-embedded-icmp, GRE performance acceleration, and flow traceoptions (packet-filter source-prefix / destination-prefix / `protocol` — M8/#2008).

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SYN Flood Protection Mode** | `security flow syn-flood-protection-mode syn-cookie` | Global SYN flood protection mode: syn-cookie (stateless) or syn-proxy (stateful). Different from per-screen syn-flood thresholds. | Medium | Legacy eBPF done (`8cbf31a`) with BPF helpers, validated_clients LRU, and 4 counters. Userspace SYN-cookie runtime is wired for #1374 with bounded SYN-ACK/RST replies and status counters; final #1477 source-removal evidence still needs to include the SYN-cookie HA/flood artifacts for the exact deletion candidate. `syn-proxy` mode is not implemented. |
| **TCP Strict SYN Check** | `security flow tcp-session strict-syn-check` | Require SYN as first packet for TCP session creation (drop mid-stream pickup) | Medium | **Config-only (#2078)** — the legacy eBPF SYN gate (`2114333`) was retired with the eBPF dataplane (#1373/#1476). The userspace AF_XDP dataplane has no TCP state machine and does not enforce syn-check; the related `no-syn-check` knob is parsed and committed but inert. Commit emits an accepted-only advisory. |
| **TCP No-SYN-Check** | `security flow tcp-session no-syn-check` | Allow mid-stream TCP session pickup (useful after failover or asymmetric routing) | Medium | **Config-only (#2078)** — the legacy BPF `flow_config` `tcp_flags` bit (`2114333`) was retired with the eBPF dataplane (#1373/#1476). The userspace dataplane does not enforce syn-check, so this opt-out is inert. Accepted-but-not-enforced; commit emits an advisory. Intentional parity gap (see #2008 M9). |
| **TCP No-SYN-Check in Tunnel** | `security flow tcp-session no-syn-check-in-tunnel` | Allow mid-stream pickup specifically for tunneled traffic (IPsec, GRE) | Low | **Config-only (#2078)** — the legacy per-interface `IFACE_FLAG_TUNNEL`/`META_FLAG_TUNNEL` path (`2114333`) was eBPF; retired with the dataplane (#1373/#1476). No tunnel-decap session-create signal exists on the userspace path, so the knob is inert. Accepted-but-not-enforced; commit emits an advisory. |
| **TCP RST Invalidate Session** | `security flow tcp-session rst-invalidate-session` | Immediately invalidate session on TCP RST instead of waiting for timeout | Medium | **Config-only (#2078)** — the legacy eBPF teardown (`2114333`, timeout=0/last_seen=0 on RST) was retired with the dataplane (#1373/#1476). The userspace dataplane shortens the session to a 30s closing timeout on RST/FIN but does not invalidate immediately and does not honor this opt-in. Accepted-but-not-enforced; commit emits an advisory. Design rationale: `docs/active-active-new-connections.md` (suppress RST→CLOSED, keep this as the opt-in override). |
| **Force IP Reassembly** | `security flow force-ip-reassembly` | Force reassembly of all IP fragments before processing (protects against fragment-based evasion) | Medium | Missing |
| **Route Change Timeout** | `security flow route-change-timeout N` | Session timeout (6-1800s) applied when route changes to nonexistent route. Prevents sessions hanging on dead routes. | Low | Missing |
| **Aggressive Session Aging** | `security flow aging early-ageout N; high-watermark N; low-watermark N` | Accelerate session timeout when session table exceeds watermark threshold | Medium | **Done** (`2114333`) — Go-side GC watermark hysteresis, early-ageout overrides per-session timeout. |
| **ICMP Session Sync** | `security flow sync-icmp-session` | Synchronize ICMP sessions between HA cluster nodes | Low | Missing |
| **Multicast Session Timeout** | `security flow multicast-session ...` | Custom timeout values for multicast flow sessions | Low | Missing |
| **Preserve Incoming Fragment Size** | `security flow preserve-incoming-fragment-size` | Maintain original fragment sizes through the device instead of reassemble-and-re-fragment | Low | Missing |

---

## 11. ALG Enhancements

xpf has ALG disable flags for DNS, FTP, SIP, TFTP. The vSRX supports many more ALGs.

The `security alg <proto> disable` knobs reach the userspace dataplane via
`FlowSnapshot.alg_disable_flags` (#2008 H3/H4): the bitfield is packed by
`pkg/dataplane/userspace.algDisableFlags` (DNS=0x01, FTP=0x02, SIP=0x04,
TFTP=0x08) and read in the session-create path by
`alg_type_for_session` (`userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs`).
A session on a well-known ALG service port (DNS UDP/53, FTP TCP/21, SIP
UDP+TCP/5060) is tagged with its ALG type in the conntrack `alg_type` field
*unless* that ALG is disabled, in which case it is tagged `none`. This matches
the Junos semantics of `alg disable` — the ALG is turned **off**, traffic is
**never dropped**. (xpf does not yet implement the active ALG transforms
themselves — payload doctoring / dynamic pinholes — so a non-disabled ALG only
sets the type; see "DNS ALG with NAT" below.)

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **H.323 ALG** | `security alg h323 ...` | VoIP: H.323 session tracking, media pinhole management, NAT for H.245/RAS | Low | Missing |
| **MGCP ALG** | `security alg mgcp ...` | VoIP: Media Gateway Control Protocol session awareness | Low | Missing |
| **SCCP ALG** | `security alg sccp ...` | VoIP: Skinny Client Control Protocol (Cisco) session tracking | Low | Missing |
| **MSRPC ALG** | `security alg msrpc ...` | Microsoft RPC dynamic port tracking (Active Directory, Exchange) | Medium | Missing |
| **SunRPC ALG** | `security alg sunrpc ...` | Sun/ONC RPC dynamic port tracking (NFS, NIS) | Low | Missing |
| **PPTP ALG** | `security alg pptp ...` | Point-to-Point Tunneling Protocol GRE call tracking | Low | Missing |
| **RTSP ALG** | `security alg rtsp ...` | Real-Time Streaming Protocol media pinhole management | Low | Missing |
| **RSH ALG** | `security alg rsh ...` | Remote Shell protocol dynamic port tracking | Low | Missing |
| **IKE-ESP NAT** | `security alg ike-esp-nat enable` | IKE/ESP NAT traversal assistance (non-standard NAT-T) | Low | Missing |

---

## 12. Security Logging Enhancements

xpf has security logging with mode (stream/event), format, streams with host/port/severity/facility/category/source-address. These are additional features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Structured Syslog Format** | `security log format structured` | Machine-parseable key-value syslog format (RT_FLOW_SESSION_CREATE, etc.) with standardized field names | Medium | Done (vSRX-compatible RT_FLOW format with `[junos@2636.1.1.1.2.129 ...]` SD wrapping) |
| **Binary Log Format** | `security log format binary` | High-performance compact binary log format for off-box collectors — self-framing records (magic+version+length) over UDP/TCP/TLS and local file | Low | Done |
| **Transport Protocol Selection** | `security log stream ... transport protocol tcp/tls` | Send security logs over TCP or TLS instead of UDP for reliable delivery | Medium | Done (TCP and TLS transport implemented) |
| **Per-Policy Logging** | `security policies ... then log session-init session-close` | xpf has this but may not fully support all log fields (app-name, nat-*, nested-app, etc.) | Medium | Done (all key fields: policy-name, app, ingress-iface, client/server split, close-reason, session-id) |
| **Log Event Mode** | `security log mode event` | Route security logs through eventd (control plane) for on-box processing, slower but allows local processing | Low | Done (event mode writes to local file) |
| **Session Aggregation Logs** | `security log ... report` | Aggregate session logs for top-N reporting (top talkers, top applications) | Low | Done (session aggregation reporting implemented) |
| **Log Profile** | `security log profile <name> { stream-name; default-profile; category ... }` | Named log-routing profile targeting a stream, with a default-profile designation (#2008 H7) | Low | Done (compiled to `LogConfig.Profiles`; `stream-name` cross-referenced at commit. Per-stream routing is already a Junos superset, so no dispatch change; `category field-extra-name` accepted but not yet used to alter emitted SD) |

---

## 13. PKI / Certificates

xpf uses strongSwan for IPsec. Basic certificate-auth IKE generation exists, but Junos PKI lifecycle management is still not implemented.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **CA Profile Management** | `security pki ca-profile ... ca-identity ... enrollment url ...` | CA certificate profiles with SCEP/CMPv2 enrollment, revocation checking (CRL/OCSP) | Medium | Missing |
| **Local Certificate Management** | `security pki local-certificate ...` | Generate CSRs, load certificates, auto-enrollment, renewal tracking | Medium | Missing |
| **CRL Management** | `security pki ca-profile ... revocation-check crl ...` | Certificate revocation list download, caching, periodic refresh | Low | Missing |
| **Certificate-Based IPsec** | `security ike gateway ... local-certificate ...` | IPsec authentication using X.509 certificates instead of PSK | Medium | Partial (gateway `local-certificate` and pubkey auth compile into swanctl, but xpf still lacks Junos PKI/local-certificate object lifecycle management) |

---

## 14. Routing Enhancements

xpf has static routes, generate/aggregate routes, ECMP, VRFs, GRE tunnels, IPIP tunnels (IPv4+IPv6), rib-groups, next-table route leaking, PBR, qualified-next-hop with interface (link-local IPv6), per-instance `rib <name>.inet6.0` IPv6 static routes, and FRR integration (OSPF, BGP, IS-IS, RIP, LLDP). These are additional routing features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **BFD** | `protocols ospf area ... interface ... bfd-liveness-detection ...` | Bidirectional Forwarding Detection for sub-second failure detection on routing adjacencies. FRR supports BFD natively. | High | **Done** -- OSPF BFD with interval/multiplier via FRR profiles, IS-IS BFD support with optional interval/multiplier, BGP BFD multiplier configurable. |
| **Graceful Restart** | `routing-options graceful-restart` | Non-stop routing during control plane restart. Keep forwarding while protocols reconverge. FRR supports GR. | Medium | Missing (FRR has GR but xpf doesn't configure it) |
| **Aggregate Routes** | `routing-options aggregate route ...` | Aggregate (summary) routes with policy control, different from generate routes in contributing route behavior | Medium | Partial (generate routes implemented but aggregate semantics differ) |
| **Martian Addresses** | `routing-options martians ... allow/exact/orlonger` | Configure additional martian (reserved) address filtering or allow specific martians | Low | Missing |
| **Forwarding Table Export** | `routing-options forwarding-table export ...` | Apply routing policy to routes exported from routing table to forwarding table. Used for ECMP load-balancing policy. | Medium | Partial (parsed but not fully wired to FRR) |
| **Multipath** | `routing-options multipath` | Protocol-independent load balancing for L3 VPN next-hops | Low | Missing |
| **Maximum ECMP Paths** | `routing-options maximum-ecmp N` | Limit number of ECMP paths installed in forwarding table | Low | Missing |
| **Nonstop Routing** | `routing-options nonstop-routing` | Maintain routing state during Routing Engine switchover | Low | Missing |
| **Multicast (PIM/IGMP)** | `protocols pim ...; protocols igmp ...` | PIM-SM/SSM/DM multicast routing, IGMP group management. vSRX supports multicast. | Medium | Missing |
| **L2 Learning** | `protocols l2-learning ...` | MAC learning and forwarding for transparent/bridge mode | Low | Missing |
| **Source Routing / SRv6** | `source-routing ...` | Segment Routing v6 for traffic engineering | Low | Missing |
| **MPLS / LDP** | `protocols mpls ...; protocols ldp ...` | MPLS label switching. Note: disables flow-based security on SRX. | Low | Missing |
| **Dynamic Tunnels** | `routing-options dynamic-tunnels ...` | Auto-created GRE tunnels for MPLS-over-GRE | Low | Missing |
| **Routing Policy Enhancements** | `policy-options policy-statement ... from protocol bgp ... then metric-type 2` | xpf has basic policy-statements. Missing: `from route-filter-list`, `from interface`, `from neighbor`, `then tag`, `then as-path-prepend`, `then community add/delete/set` | Medium | Partial (basic from/then exists, several match/action types missing) |

---

## 15. VPN Enhancements

xpf has IPsec via strongSwan with IKE proposals, gateways, VPNs, XFRM interfaces, NAT-T, DPD modes, local/remote identity, local-certificate auth generation, DF-bit, establish-tunnels, and traffic selectors. These are additional VPN features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SSL VPN / Juniper Secure Connect** | `security remote-access ...` | Client-based SSL VPN for remote access (Windows, Mac, Android, iOS). Web portal login. | Medium | Missing |
| **Remote Access IPsec VPN** | `security ike / ipsec + remote-access or access-profile workflow` | Road-warrior / client remote-access IPsec VPN distinct from site-to-site tunnels. The deployment guide explicitly calls out remote-access IPsec VPN support in addition to site-to-site. | Medium | Missing |
| **Dynamic VPN** | `security dynamic-vpn ...` | Simplified IPsec remote access with web-based client provisioning and access profiles | Medium | Missing |
| **AutoVPN** | `security ike gateway ... dynamic ...` | Auto-provisioned hub-and-spoke IPsec VPN. Hub accepts dynamic spoke connections using DNS names or any. | Medium | Missing |
| **ADVPN** | `security ipsec vpn ... advpn ...` | Auto Discovery VPN: dynamic spoke-to-spoke tunnels created on demand in hub-and-spoke topology | Low | Missing |
| **Group VPN (GVPNv2)** | `security group-vpn ...` | Group key management for multipoint VPNs with single SA for multiple endpoints | Low | Missing |
| **IPsec Traffic Selectors** | `security ipsec vpn ... traffic-selector ...` | Per-tunnel traffic selectors (proxy-IDs) defining which traffic enters the tunnel | Medium | Done (named `traffic-selector` entries compile into multiple child SAs and are reflected in runtime status parsing) |
| **PowerMode IPsec** | `security flow power-mode-ipsec` | VPP + Intel AES-NI acceleration for IPsec throughput. vSRX 3.0 feature. | Low | Missing |
| **IPsec SA Lifetime (kilobytes)** | `security ipsec proposal ... lifetime-kilobytes N` | Rekey based on data volume in addition to time-based lifetime | Low | Missing |
| **Dual-Stack IPsec Tunnels** | Multiple st0 units with inet+inet6 families | Parallel IPv4+IPv6 tunnels over single XFRM interface | Low | Missing |

---

## 16. HA Enhancements

xpf has a broad chassis cluster implementation with redundancy groups, RETH (VRRP-backed, virtual MAC), heartbeat, configurable per-RG gratuitous-arp-count, weight-based failover, session sync (RTO, per-RG aware), config sync, IP monitoring, election logic, VRRP, active/active per-RG service management, fabric forwarding, and ISSU. Remaining gaps are tracked below.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **In-Service Software Upgrade (ISSU)** | `request system software in-service-upgrade ...` | Upgrade software without traffic interruption using cluster failover | Low | Done (`ForceSecondary()` drains all RGs to peer, operator replaces binary + restarts) |
| **NAT State Synchronization** | `chassis cluster ... nat-state-synchronization` | Sync NAT translation table entries between cluster nodes for seamless failover | Medium | Done (session sync via RTO protocol includes SNAT/DNAT flags and NAT addresses in session_value struct) |
| **IPsec SA Synchronization** | `chassis cluster ... ipsec-session-synchronization` | Sync IPsec Security Associations between nodes. Avoids tunnel re-establishment after failover. | Medium | Done (primary sends active connection names every 30s; new primary re-initiates via `swanctl --initiate`) |
| **Active/Active Mode** | `chassis cluster redundancy-group N node 0 priority N node 1 priority N` (both nonzero) | Both nodes forward traffic simultaneously for different RGs. Per-RG VRRP service management, per-RG session sync with zone→RG mapping. | Medium | Done (per-RG service mgmt, per-RG session sync, per-RG election all implemented and tested) |
| **Redundant Ethernet (reth) Runtime** | `interfaces reth0 redundant-ether-options ...` | Bondless RETH via VRRP on physical member interfaces, virtual MAC per node (`02:bf:72:CC:RR:NN`), programRethMAC, VIP reconciliation, fabric forwarding (including embedded ICMP redirect for mtr/traceroute through secondary), `.link` files with OriginalName matching, session sync across nodes | Medium | Done (fully implemented and validated in cluster testing) |
| **Primary/Preferred Address per Interface** | `interfaces ... unit ... family inet address ... primary/preferred` | Select which address is used as source for traffic originated by the device. Syslog source address prefers PrimaryAddress, networkd orders primary first. | Low | Done (syslog source address + networkd ordering) |
| **vSRX Dual Fabric Syntax Compatibility (`fab0` + `fab1`)** | `interfaces fab0/fab1 fabric-options member-interfaces ...` | Native vSRX HA syntax models two fabric links. Requires multi-fabric transport/data-plane (not single `fabric-interface`). | High | Partial (parser/compiler/runtime support `fab0` + `fab1` syntax, dual-fabric sync transport, CLI visibility, and eBPF/userspace fabric forwarding; ~~DPDK dual-fabric parity~~ — DPDK retired #1525, moot) |
| **Fabric Link Redundancy** | `chassis cluster ... fabric-options member-interfaces` | Multiple fabric links between cluster nodes for data forwarding resilience. Linux bond/failover behavior should be consistent across runtime and networkd. | Low | Partial (networkd generation and runtime bond mode are inconsistent) |

---

## 17. Firewall Filter Enhancements

xpf has firewall filters with source/dest addresses, prefix-lists (with except), DSCP, protocol, dest/source ports, ICMP type/code, TCP flags, fragment match, actions (accept/reject/discard), routing-instance, log, count, forwarding-class, loss-priority, DSCP rewrite, and IPv6 traffic-class matching.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Policer (Rate Limiting)** | `firewall policer ... bandwidth-limit N burst-size-limit N` | Token-bucket rate limiter applied to filter terms or interfaces. Single-rate two-color, three-color policers. | High | Partial for #1373: legacy eBPF/~~DPDK~~ (DPDK retired #1525) token-bucket policer support existed; userspace supports the admitted filter path and the color-blind `then discard` three-color slice. #1375 is closed; unsupported color-aware/non-drop behavior and broader Junos parity remain production/future parity work, not active #1373 source-removal blockers. |
| **Three-Color Policer** | `firewall three-color-policer ...` | RFC 2697/2698 metering with green/yellow/red marking based on CIR/CBS/EBS or CIR/PIR | Medium | Legacy eBPF/~~DPDK~~ (DPDK retired #1525) done; userspace AF_XDP supports color-blind `then discard` with compatible snapshot continuity. #1375 is closed; remaining color-aware/non-drop action parity plus integration, failover, and performance hardening are production/future parity work, not active #1373 source-removal blockers. |
| **Interface Policer** | `firewall policer ... logical-interface-policer` | Aggregate rate limiting across all protocol families on a logical interface | Low | Missing |
| **Interface ARP Policer (H9)** | `interfaces <if> unit <n> family inet\|inet6 policer arp <name>` | Per-logical-interface ARP rate limiter | Low | Reject-at-commit (#2008 H9): xpf has no per-interface ARP policer, so the stanza is hard-rejected at commit/commit-check (lenient warning on load/peer-sync per #1960) instead of being silently dropped. Real enforcement is a net-new dataplane subsystem. |
| **Interface Static MAC (H10)** | `interfaces <if> [unit <n>] mac <addr>` | Static MAC-address override on a logical/physical interface | Low | Reject-at-commit (#2008 H10): the interface MAC is read-only (cluster RETH MAC is computed deterministically per node via `programRethMAC`), diverging from this Junos override. Hard-rejected at commit (lenient warning on load/peer-sync) instead of silently dropped. |
| **Flexible Match Conditions** | `firewall filter ... term ... from flexible-match-range ...` | Match on arbitrary byte offsets within packet header for custom protocol matching | Low | Missing |
| **Firewall Filter on lo0** | `interfaces lo0 unit 0 family inet filter input ...` | Host-bound traffic filtering — config parsed, compiled to filter IDs, evaluated natively in xdp_forward for host-bound packets, plus kernel nftables fallback | Medium | Done |

---

## 18. QoS / Class of Service

Note: The vSRX deployment guide markets CoS as part of the standard feature set, but the user guide also calls out important CoS limitations on vSRX, such as the lack of high-priority SPC queue support. xpf now has a userspace-only CoS path with forwarding-class parsing, scheduler-map binding, interface-bound DSCP classifier attachment, egress shaping, timer-wheel deferred eligibility, and guarantee/surplus queue scheduling, but it is still materially narrower than Junos CoS.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Forwarding Classes** | `class-of-service forwarding-classes queue <num> <name>;` | Define custom forwarding class names mapped to queue numbers | Low | Done |
| **Scheduler Maps** | `class-of-service scheduler-maps ...` | Associate forwarding classes with schedulers (bandwidth %, priority, buffer) | Low | Done |
| **Schedulers** | `class-of-service schedulers ...` | Define per-queue scheduling parameters (transmit rate, priority, drop profile) | Low | Partial (userspace supports transmit-rate, `transmit-rate exact`, priority, buffer-size, `surplus-sharing` (#915 — non-Junos extension that opts an `exact` queue into surplus-phase participation while keeping its per-queue rate as a guarantee floor), and `equal-flow-enforcement` (#1304 — non-Junos opt-in, mutually exclusive with `surplus-sharing`, that lets shared exact v8 leases suppress faster workers toward the slowest sampled per-active-SFQ-bucket grant rate); the fuller Junos scheduler/drop-profile model remains missing) |
| **BA Classifiers** | `class-of-service classifiers dscp ...` | Classify incoming traffic by DSCP/802.1p into forwarding classes and loss priorities | Low | Partial (userspace supports DSCP and 802.1p classifier definitions plus interface attachment as fallback queue selectors, but not loss-priority enforcement and not broader non-userspace BA classifier parity) |
| **Rewrite Rules** | `class-of-service rewrite-rules dscp ...` | Rewrite outgoing DSCP/802.1p values. | Low | Partial (userspace supports DSCP rewrite-rule definitions plus interface attachment on shaped egress interfaces, and firewall filters can also set DSCP rewrite directly; 802.1p rewrite and broader parity are still missing) |
| **WRED Drop Profiles** | `class-of-service drop-profiles ...` | Weighted Random Early Detection congestion avoidance per queue | Low | Missing |
| **Traffic Shaping** | `class-of-service interfaces ... shaping-rate ...` | Per-interface output rate shaping | Low | Partial (userspace-only egress shaping with bounded guarantee service, strict-priority surplus selection, same-priority weighted DWRR, non-`exact` surplus borrowing, timer-wheel deferred eligibility, deterministic queue-owner spreading, and per-shaped-egress-interface shared-root budget leasing across queue owners/workers on that same interface; not full Junos CoS parity) |
| **Interface CoS Binding** | `class-of-service interfaces ... scheduler-map ...` | Bind scheduler-map and classifiers to specific interfaces | Low | Partial (userspace supports scheduler-map binding plus DSCP / 802.1p classifier and DSCP rewrite-rule attachment on shaped interfaces, but broader non-userspace semantics are still missing) |

---

## 19. Multi-Tenancy

Logical systems and tenant systems are supported on vSRX starting from Junos 20.1R1.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Logical Systems (LSYS)** | `logical-systems ...` | Partition device into independent virtual firewalls. Each LSYS has own zones, policies, routing instances, NAT, address books. | Medium | Missing |
| **Tenant Systems (TSYS)** | `tenants ...` | Lightweight multi-tenancy. Single routing instance per tenant but supports higher tenant count. | Medium | Missing |
| **Security Profiles** | `system security-profile ...` | Resource limits per LSYS/TSYS: max sessions, NAT rules, policies, zones, VPNs | Low | Missing |
| **Inter-LSYS Traffic** | `logical-systems ... security policies from-zone ... to-zone ...` | Security policies between logical systems via logical tunnel (lt) interfaces | Low | Missing |

---

## 20. Management & Automation

xpf has gRPC (48+ RPCs), REST API, Junos-style CLI (local + remote), Prometheus metrics, config commit/rollback, and event-options. These are additional management features.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **NETCONF/YANG** | `system services netconf ...` | Standards-based config management (RFC 6241). Enables Ansible, Salt, Terraform, ncclient integration. XML-based RPC. | High | Missing |
| **Configuration Groups** | `groups { name { ... } }; apply-groups name` | Template inheritance for config reuse. Apply common settings to multiple stanzas without duplication. | Medium | Done (general-purpose groups/apply-groups with inheritance priority, `apply-groups-except`, `${node}` variable support, `CompileConfigForNode()` for HA per-node config) |
| **Deactivate Without Delete (`inactive:`)** | `inactive: <statement>` (set via `deactivate <path>`) | Mark any statement deactivated without deleting it: retained in the config DB, shown in `show configuration`, survives commit/reboot, re-enableable — but excluded from compilation/application. The config-management equivalent of commenting code out. | Medium | Done — parse/persist/display/strip (#2008 H1, `pkg/config` `Node.Inactive` + centralized `WithoutInactive` strip before group-expand/compile and schema-validate; re-emitted by all five serializers + `show \| compare`). Reached today by loading config text containing `inactive:`; the `activate` / `deactivate` CLI verbs are a separate increment. |
| **Commit Scripts** | `system scripts commit ...` | Pre-commit validation scripts (SLAX/Python) that enforce config standards and generate warnings/errors | Low | Missing |
| **Op Scripts** | `system scripts op ...` | Custom operational commands via SLAX/Python scripts | Low | Missing |
| **RADIUS Authentication** | `system radius-server ...; system authentication-order radius` | External RADIUS authentication for management access (SSH, CLI, web) | Medium | Missing |
| **TACACS+ Authentication** | `system tacplus-server ...; system authentication-order tacplus` | External TACACS+ authentication with per-command authorization | Medium | Missing |
| **SNMP v3 USM** | `snmp v3 usm local-engine user ...` | Full SNMPv3 with authentication (SHA/MD5) and privacy (AES/DES). xpf parses v3 users but runtime may be incomplete. | Medium | Partial (parsed, needs runtime verification) |
| **SNMP Traps/Notifications** | `snmp trap-group ... targets ...` | SNMP trap generation on events (link up/down, auth failure, etc.). xpf parses trap-groups and sends linkUp/linkDown. | Medium | Partial — SNMPv2c linkUp/linkDown implemented (`pkg/snmp/traps.go` `buildLinkTrap` / `NotifyLinkUp` / `NotifyLinkDown`, OIDs `1.3.6.1.6.3.1.1.5.4` / `.5.3`, sent over UDP/162 to configured targets, wired from `pkg/daemon/daemon_flow.go`). Missing trap classes: authentication-failure, cold/warm-start, HA role change, and policy/security alarms. |
| **J-Web / Full Web GUI** | `system services web-management ...` | Full web-based management UI with dashboard, wizards, monitoring, policy editor. xpf has basic REST API. | Low | Missing |
| **XML/JSON Config Export** | `show configuration | display xml/json` | Export configuration in XML or JSON format for automation tooling | Low | Missing |
| **Junos Telemetry Interface (JTI)** | `services analytics / streaming telemetry` | Push-model streaming telemetry for counters, sensors, and analytics pipelines. Explicitly listed as supported on vSRX in the feature tables. | Low | Missing |
| **Cloud-init / Metadata User-Data Bootstrap** | `N/A (deployment/bootstrap workflow)` | Initialize a vSRX instance from validated Junos configuration passed through cloud metadata or config-drive user-data. Extensively documented for OpenStack, AWS, and GCP. | Medium | Missing |
| **Bootstrap ISO Provisioning** | `N/A (deployment/bootstrap workflow)` | Provision first-boot configuration from a bootstrap ISO image attached as a virtual disk. Documented in the deployment guide for KVM and VMware workflows. | Low | Missing |
| **Junos Space / Security Director** | N/A (external management platform) | Centralized multi-device policy management. Not applicable as a feature of xpf itself. | Low | Missing (N/A) |
| **Rescue Configuration** | `request system configuration rescue save` | Saved fallback configuration that can be loaded on boot if active config fails | Low | Missing |

---

## 21. Interface Enhancements

xpf manages all interfaces with .link/.network files, supports VLANs, tunnel interfaces (GRE, IP-IP, XFRM), DHCP, VRRP, MTU, speed/duplex, disable, per-interface sampling (input/output, per-family), forwarding-options sampling instances with inline-jflow, and per-interface firewall filters.

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **Link Aggregation (LAG/ae)** | `interfaces ae0 ...; interfaces ge-0/0/0 gigether-options 802.3ad ae0` | Bundle physical links into aggregate ethernet for bandwidth and redundancy. Different from reth. | Medium | Done (LACP/802.3ad parsing + bond/netdev generation + member enslaving) |
| **Transparent Mode (L2 Bridging)** | `interfaces ... family ethernet-switching; bridge-domains ...` | Layer 2 bridge mode where firewall acts as transparent inline device. Zone-based policies still apply. MAC learning table. | Medium | Missing |
| **Flexible VLAN Tagging** | `interfaces ... flexible-vlan-tagging; encapsulation flexible-ethernet-services` | Q-in-Q (802.1ad), flexible VLAN push/pop/swap operations. xpf has basic 802.1Q single-tag. | Low | Done (flexible-vlan-tagging + flexible-ethernet-services + inner-vlan parsing/wiring) |
| **Interface Bandwidth** | `interfaces ... bandwidth ...` | Set logical interface bandwidth for OSPF cost calculation and traffic-engineering | Low | Done (parsed and rendered into FRR interface bandwidth) |
| **IRB Interfaces** | `interfaces irb unit N family inet address ...; bridge-domains bd0 { vlan-id-list ...; routing-interface irb.0; }` | Integrated Routing and Bridging: kernel Linux bridge per bridge-domain, IRB addresses on bridge device, zone assignment, .netdev/.network generation | Medium | Done (config parsing, compiler, networkd bridge/member/IRB generation, zone resolution) |
| **Point-to-Point** | `interfaces ... unit ... point-to-point` | Mark interface as point-to-point (affects OSPF network type, ND behavior) | Low | Done (parsed and emitted as FRR OSPF point-to-point where applicable) |
| **Primary/Preferred Address** | `interfaces ... unit ... family inet address ... primary/preferred` | Control which address is used for sourced traffic. Syslog source and networkd ordering implemented; not yet used for all device-originated traffic. | Low | Partial (syslog source + networkd ordering, not all traffic) |
| **Interface Description** | `interfaces ... description "..."` | xpf parses descriptions. Verify they appear in `show interfaces` output. | Low | Done (description displayed in interface output paths) |

---

## 22. System Enhancements

xpf has hostname, domain-name, domain-search, timezone, name-servers, NTP, services (SSH with root-login and key-exchange/`KexAlgorithms`, web-management, DNS), syslog, SNMP, login users/classes (including per-user `authentication encrypted-password` for console login — #1944, see [docs/system-login.md](system-login.md)), root-authentication, archival, internet-options, backup-router, DHCP server (Kea), and ~~DPDK~~ config (DPDK retired #1525, removed in #1527/#1528).

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **SSH Key Exchange** | `system services ssh key-exchange ...` | Restrict the SSH key-exchange (KEX) algorithms the firewall offers | Medium | Done (H5/#2008 — repeatable leaf rendered to the sshd `KexAlgorithms` drop-in, `pkg/daemon/daemon_system.go`; drop-in lifecycle hardened in #2062 — removing/emptying the ssh stanza removes the `/etc/ssh/sshd_config.d/xpf.conf` drop-in and reloads so sshd reverts to base-image defaults, and a reload failure after a write reverts the drop-in to its prior content/removes it so a bad config never breaks the next sshd restart) |
| **RADIUS Server Config** | `system radius-server ... port ... secret ...` | RADIUS server definitions for AAA (authentication, authorization, accounting) | Medium | Missing |
| **TACACS+ Server Config** | `system tacplus-server ... port ... secret ...` | TACACS+ server definitions for per-command authorization | Medium | Missing |
| **Authentication Order** | `system authentication-order [radius tacplus password]` | Control order of authentication methods for management access | Medium | Missing |
| **Auto-Image Upgrade** | `system autoinstallation ...` | Zero-touch provisioning for initial deployment | Low | Missing |
| **Time Zone (wired)** | `system time-zone ...` | xpf applies the configured timezone to the system runtime | Low | Done (daemon updates `/etc/localtime` and `/etc/timezone`) |
| **NTP Threshold Action** | `system ntp threshold ... action ...` | Action when NTP offset exceeds threshold (accept or reject large time jumps) | Low | Done (maps to chrony `logchange` for `accept` and `logchange` + `maxchange` for `reject`, and is shown in operational output) |
| **Master Password** | `system master-password ...` | Encrypted password storage with master key for config secrets | Low | Done (active/candidate/rollback config trees are encrypted at rest with a node-local master key derived using the configured PRF) |
| **DNS Proxy** | `system services dns dns-proxy ...` | DNS proxy/caching server on firewall for client DNS resolution | Low | Missing |
| **DHCP Dynamic DNS** | `system services dhcp-local-server dynamic-dns ...` | Publish forward A/AAAA + reverse PTR records for active DHCP leases and clean them on expire/release/reassign/config-removal | Medium | Done (#1387 — inc-1 config + reconciler + never-delete-non-owned store; inc-2 LIVE RFC 2136 backend via miekg/dns, always-on daemon reconcile loop, NODE-LEVEL HA single-writer gate (MASTER for ≥1 RG), `xpf_dhcp_ddns_*` metrics + `show system services dhcp-server dynamic-dns`; live Kea→DNS e2e + `make test-failover`-with-DDNS are lab-gated. See [pkg/dhcpserver/README.md](../pkg/dhcpserver/README.md)). Deferred: Kea D2 backend, explicit forward-zone/reverse-zone/publish-ptr leaves |

---

## 23. Miscellaneous Features

| Feature | Junos Config Path | Description | Priority | Status |
|---------|-------------------|-------------|----------|--------|
| **802.1X Network Access Control** | `protocols dot1x ...` | Port-based network authentication on access ports | Low | Missing |
| **SCTP Protocol Support** | `security policies ... match application junos-sctp` | SCTP-aware firewall with multi-homing and stream tracking | Low | Missing |
| **Geneve Flow Infrastructure / AWS GWLB** | `security tunnel-inspection ... profile ... geneve ...` | Geneve tunnel decapsulation/encapsulation, VNI and vendor-TLV-based policy attachment, and AWS GWLB metadata handling for tunnel-endpoint and transit-router deployment modes. The current repo has no runtime Geneve/GWLB implementation beyond design references. | Low | Missing |
| **VPLS** | `routing-instances ... instance-type vpls` | Virtual Private LAN Service for L2 VPN | Low | Missing |
| **Storm Control** | `forwarding-options storm-control ...` | Broadcast/multicast storm protection | Low | Missing |
| **TAP Mode** | `security forwarding-options ... tap-mode` | Passive monitoring mode (copy of traffic, no inline blocking) | Low | Missing |

---

## Priority Tiers

### Tier 1 - High Priority (Core NGFW / Common vSRX Features)
Features most commonly used in production vSRX deployments:

1. ~~**Proxy ARP/NDP for NAT**~~ - **Done** (proxy ARP with GARP; proxy NDP still missing)
2. ~~**Session Limiting (source/dest-ip)**~~ - **Done** on the legacy BPF path (GC sweep + BPF LRU maps + xdp_screen enforcement); userspace admission is tracked in `userspace-dataplane-gaps.md`.
3. ~~**Firewall Filter Policers**~~ - **Legacy done** (token bucket: single-rate, two-rate RFC 2698, single-rate-3c RFC 2697; eBPF + ~~DPDK~~ (DPDK retired #1525)). Userspace supports the color-blind `then discard` three-color slice; #1375 is closed. Remaining color-aware/non-drop and broader Junos parity work is production/future parity, not active #1373 source-removal work.
4. ~~**BFD**~~ - **Done** (OSPF/IS-IS/BGP BFD via FRR profiles)
5. **NETCONF/YANG** - Industry-standard management, enables automation tooling
6. **Unified Policies / AppID** - Foundation of modern NGFW (long-term, high complexity)
7. **IDP/IPS** - Core NGFW feature differentiator (consider Suricata/Snort integration)

### Tier 2 - Medium Priority (Enterprise Features)
Features commonly requested in enterprise deployments:

8. **RADIUS/TACACS+ Authentication** - Enterprise AAA integration
9. **SSL VPN / Remote Access VPN** - Remote worker connectivity
10. **Remote Access IPsec VPN** - Road-warrior IPsec parity beyond site-to-site tunnels
11. ~~**Aggressive Session Aging**~~ - **Done** (GC high/low-watermark early-ageout behavior)
12. **Graceful Restart** - Non-stop routing (FRR already supports)
13. ~~**Twice NAT**~~ - **Done** (zone-aware static DNAT + post-DNAT SNAT matching + both-leg session visibility)
14. **Transparent Mode (L2)** - Inline transparent firewall deployment
15. ~~**Link Aggregation (LAG)**~~ - **Done**
16. **PKI / Certificate-Based IPsec** - Certificate-based VPN authentication
17. **SecIntel / GeoIP** - Threat intelligence integration
18. **Captive Portal / User Firewall** - User-based access control
19. **Logical Systems (LSYS)** - Multi-tenancy

### Tier 3 - Low Priority (Specialized / Niche)
Features for specific use cases or carrier deployments:

20. Content Security (UTM) - AV/web-filtering (consider ClamAV/rspamd)
21. SSL Proxy - TLS inspection (consider mitmproxy integration)
22. Multicast (PIM/IGMP)
23. MPLS/LDP
24. EVPN/VXLAN
25. Geneve / AWS GWLB - cloud overlay and load-balancer insertion workflows
26. Junos Telemetry Interface (JTI) - push telemetry / analytics pipelines
27. Cloud-init / Bootstrap ISO - cloud and first-boot deployment parity
28. AppQoE
29. DS-Lite/6rd/MAP-E
30. GTP Firewall
31. SD-WAN
32. PowerMode IPsec
33. Class of Service - partial/limited on vSRX, still materially broader than xpf today

---

## Parse-Only Features Summary

These features have config parsing in xpf but no runtime effect.

Note: This includes parse-only knobs that are outside the core category gap
table, so this list count can be higher than the category-level Parse-Only total.

| # | Config Path | Type | Notes |
|---|------------|------|-------|
| 1 | `system license autoupdate url` | SystemConfig.LicenseAutoUpdate | No licensing system |

## Runtime Follow-Up Features Summary

No feature rows currently carry open #1373 runtime follow-up work. Closed
contracts such as #1378 remain documented in their feature rows as closeout
evidence, not as active eBPF source-removal blockers.

---

## Implementation Suggestions for Top Gaps

### Proxy ARP for NAT (Tier 1) -- DONE
- Proxy ARP neighbor entries for NAT addresses with GARP on addition
- Config: `set security nat proxy-arp interface <iface> address <addr>` with address range support

### Session Limiting (Tier 1) -- DONE
- GC sweep counts active sessions per source/destination IP, pushes to BPF LRU maps
- xdp_screen enforces limits on TCP SYN
- Config: `set security screen ids-option <name> limit-session source-ip-based <N>` / `destination-ip-based <N>`

### Firewall Filter Policers (Tier 1) -- PARTIAL; #1375 CLOSED
- Token bucket policer with single-rate two-color, two-rate three-color (RFC 2698), and single-rate three-color (RFC 2697) modes
- eBPF parity (DPDK retired #1525); userspace supports the color-blind `then discard`
  three-color slice
- #1375 is closed. Remaining color-aware/non-drop behavior and broader Junos
  parity are production/future parity work, not active #1373 source-removal
  blockers.

### BFD (Tier 1) -- DONE
- OSPF BFD with interval/multiplier via FRR profiles
- IS-IS BFD support with optional interval/multiplier
- BGP BFD multiplier configurable (was hardcoded to 3)

### NETCONF (Tier 1)
- Consider using `openconfig/gnmic` or `netopeer2` for NETCONF server
- Map to existing gRPC RPCs for config get/set
- YANG models can be generated from existing config types

---

## #2008 vSRX config-parity closures (Increment 1, batch 1)

Quick-win gaps from the `#2008` parity audit (stored-but-unenforced / schema
drift) closed in `fix/2008-quickwins-batch1`:

- **M4 `security policy-stats system-wide`** — DONE. Per-policy hit
  counter collection (`collectPolicyCounters` in `pkg/api/metrics_counters.go`)
  is now gated on `cfg.Security.PolicyStatsEnabled`. Previously the flag
  compiled into typed state but counters were always collected; Junos only
  maintains per-policy stats when the knob is enabled (default off).
- **H14 `security flow power-mode-disable`** — DONE (threaded). The parsed
  `cfg.Security.Flow.PowerModeDisable` now reaches the dataplane via
  `FlowSnapshot.PowerModeDisable` (`pkg/dataplane/userspace/protocol.go` +
  `buildFlowSnapshot`) and the Rust `FlowSnapshot`/`ForwardingState`
  (`power_mode_disable`, mirroring `gre_acceleration`). vSRX power-mode is an
  express datapath; the userspace dataplane has a single forwarding path, so
  the flag is carried for config truth/parity and does not currently switch
  packet behavior (there is no express/regular split to select between).
- **M9 `security flow tcp-session no-sequence-check`** — DONE (typed). Added
  the schema child (`pkg/config/schema_security.go`), the
  `TCPSessionConfig.NoSequenceCheck` field (`pkg/config/types_security.go`),
  and the compiler case (`pkg/config/compiler_security.go`), at full parity
  with the existing `no-syn-check` / `rst-invalidate-session` presence flags.
  Like those siblings it is typed-config only: the userspace AF_XDP dataplane
  performs no TCP sequence-number window validation today, so there is nothing
  to skip. The field gives commit-time validation + completion and is the seam
  a future sequence-checking dataplane would read. As of #2078 the whole
  `tcp-session` presence-flag family (`no-syn-check`,
  `no-syn-check-in-tunnel`, `rst-invalidate-session`, `no-sequence-check`)
  emits a single accepted-only commit advisory so an operator is not silently
  misled into believing any of these knobs has runtime effect; research #2078
  converged PLAN-KILL on enforcement (the dataplane has no TCP state machine,
  proportionality favours warn-and-document for these LOW, rarely-used knobs).
- **H6 residual — `system login user <name> class` enum validation** — DONE.
  RBAC was already enforced (`pkg/cli/permissions.go`); the remaining hole was
  that the `class` leaf accepted any string at commit and `config-viewer` was
  missing. Added `ValidateEnum` on the `class` schema leaf
  (`pkg/config/schema_system.go`) with the allowed set derived from
  `LoginClassPermissions` (`config.ValidLoginClasses()`), and added a
  `config-viewer` RBAC entry (PermView) so the schema enum and the runtime RBAC
  table cannot drift. Mirrors the SNMP `authorization` enum leaf. See
  `docs/system-login.md`.

## #2008 vSRX config-parity closures (Increment 2)

Tier-2 gaps from the `#2008` parity audit researched in
`docs/research/2008-tier2/plan.md`:

- **M7 `event-options policy attributes-match`** — DONE (literal → regex).
  Junos `attributes-match "<event>.<attribute> matches <pattern>"` is a regex
  match; xpf previously did literal string equality
  (`pkg/eventengine/engine.go` `attributesMatch`). The matcher now treats the
  pattern as an RE2 regex (unanchored = substring, like Junos), compiled once
  at `Apply()` time and cached by pattern string so the event hot path never
  recompiles. Commit-time validation rejects an uncompilable pattern
  (`config.ValidateEventAttributesMatch` via `CompileConfig`,
  `pkg/config/event_options_match.go`). The parse/validate seam
  (`config.ParseEventAttributesMatch`) is shared between the compiler and the
  engine so they cannot drift. **Behavior-change note:** this is NOT
  behavior-preserving for a stored literal containing regex metacharacters —
  but regex IS the correct Junos behavior. The supported attribute set stays
  `test-owner` / `test-name` (the only fields on `rpm.Event`); widening the
  field surface is deferred until more attributes are exposed. See
  `pkg/eventengine/README.md`.
- **H13 Stage 1 `forwarding-options allow-dataplane-sleep`** — DONE
  (schema + field + commit warning). The leaf was previously accepted as a
  no-schema-match fall-through and silently dropped by
  `compileForwardingOptions`. Stage 1 adds the typed presence-flag schema leaf
  (`pkg/config/schema_routing.go`), the `ForwardingOptionsConfig.AllowDataplaneSleep`
  field (`pkg/config/types_system.go`), compiler extraction
  (`pkg/config/compiler_services.go`), and a commit warning that the knob is
  accepted but the idle-yield runtime is not yet implemented (the userspace
  workers busy-poll), mirroring the `persist-groups-inheritance` /
  `dns-proxy` accepted-but-unenforced warnings. Stage 2 (actual worker
  idle-yield) is lab-gated and deferred per the research doc — the busy-poll
  cold-start latency sensitivity (#1782) is the reason it needs explicit
  validation before enabling.
