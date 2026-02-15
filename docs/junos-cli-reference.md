# Junos CLI Output Format Reference

Captured from vSRX 24.4R1-S2.9 chassis cluster (node0: vsrx-ernie, node1: vsrx-bert) at 172.16.100.1.
User: claude (read-only, no config/log permission).

This document preserves exact spacing, column widths, headers, and separators for replicating
Junos output formatting in bpfrx.

---

## Table of Contents

1. [Cluster Header Format](#cluster-header-format)
2. [Security: Flow Sessions](#security-flow-sessions)
3. [Security: Flow Session Summary](#security-flow-session-summary)
4. [Security: Flow Statistics](#security-flow-statistics)
5. [Security: Policies](#security-policies)
6. [Security: Policies Detail](#security-policies-detail)
7. [Security: Policies Hit-Count](#security-policies-hit-count)
8. [Security: Global Policies](#security-global-policies)
9. [Security: Zones](#security-zones)
10. [Security: NAT Source Rule All](#security-nat-source-rule-all)
11. [Security: NAT Destination Rule All](#security-nat-destination-rule-all)
12. [Security: NAT Source Summary](#security-nat-source-summary)
13. [Security: Screen IDS](#security-screen-ids)
14. [Security: ALG Status](#security-alg-status)
15. [Security: IPsec SAs](#security-ipsec-security-associations)
16. [Security: IPsec SAs Detail](#security-ipsec-security-associations-detail)
17. [Security: IKE SAs](#security-ike-security-associations)
18. [Security: Log](#security-log)
19. [Interfaces: Terse](#interfaces-terse)
20. [Interfaces: Detail](#interfaces-detail)
21. [Interfaces: Extensive](#interfaces-extensive)
22. [System: Uptime](#system-uptime)
23. [System: Memory](#system-memory)
24. [System: Processes Summary](#system-processes-summary)
25. [System: Version](#system-version)
26. [Chassis Cluster: Status](#chassis-cluster-status)
27. [Chassis Cluster: Interfaces](#chassis-cluster-interfaces)
28. [Routing: Route Table](#routing-route-table)
29. [Routing: Route Summary](#routing-route-summary)
30. [Routing: BGP Summary](#routing-bgp-summary)
31. [Routing: ARP](#routing-arp)
32. [Pipe Filters](#pipe-filters)
33. [Configuration Display](#configuration-display)

---

## Cluster Header Format

Every show command on a cluster prefixes output with per-node headers:

```
node0:
--------------------------------------------------------------------------
<output for node0>

node1:
--------------------------------------------------------------------------
<output for node1>
```

- The separator line is exactly 74 dashes.
- Blank line before each `nodeN:` header (except first).
- Active node shows full output; standby may show less data.

---

## Security: Flow Sessions

**Command:** `show security flow session`

Filters: `protocol tcp|udp|icmp`, `source-prefix X.X.X.X/N`, `destination-prefix X.X.X.X/N`,
`destination-port NNN`, `application-firewall`, etc.

```
Session ID: 17179902569, Policy name: allow-everything-out-not-logged/270, HA State: Active, Timeout: 18, Session State: Valid
  In: 192.168.99.201/18277 --> 76.214.233.95/722;icmp, Conn Tag: 0x0, If: reth1.1000, Pkts: 1, Bytes: 84,
  Out: 76.214.233.95/722 --> 50.220.171.30/11623;icmp, Conn Tag: 0x0, If: reth0.0, Pkts: 0, Bytes: 0,
```

### Format Details

- **Session header line:** Comma-separated key-value pairs, no fixed column widths.
  - `Session ID: <u64>`
  - `Policy name: <name>/<index>` (policy name slash policy index number)
  - `HA State: Active|Backup`
  - `Timeout: <seconds>`
  - `Session State: Valid|Invalid`
- **In/Out lines:** Indented 2 spaces.
  - `In: <src_ip>/<src_port> --> <dst_ip>/<dst_port>;<proto>, Conn Tag: 0x0, If: <interface>, Pkts: <N>, Bytes: <N>, `
  - Note the trailing comma+space after Bytes value.
  - Protocol is appended after dst_port with semicolon separator: `443;tcp`, `722;icmp`
  - For ICMP: port field is the ICMP ID.
  - `Conn Tag: 0x0` always present.
- **TCP sessions** show src/dst port normally: `52207 --> 192.73.252.65/443;tcp`
- **ICMP sessions** show ICMP ID as port: `18277 --> 76.214.233.95/722;icmp`
- **Session trailer:** `Total sessions: <N>` at the end of each node's output.
- Blank line between sessions.
- **NAT visible in Out line**: translated addresses appear in Out (SNAT changes src in Out, DNAT changes dst in In pre-NAT vs Out post-NAT).

### TCP Session with NAT Example

```
Session ID: 249108372496, Policy name: allow-everything-out-not-logged/240, HA State: Backup, Timeout: 7022, Session State: Valid
  In: 172.16.100.201/52207 --> 192.73.252.65/443;tcp, Conn Tag: 0x0, If: reth1.100, Pkts: 0, Bytes: 0,
  Out: 192.73.252.65/443 --> 50.220.171.30/2772;tcp, Conn Tag: 0x0, If: reth0.0, Pkts: 0, Bytes: 0,
```

Note: On backup node, Pkts/Bytes are 0 (no traffic flowing through it).

### Brief Format

**Command:** `show security flow session brief`

On vSRX 24.4, `brief` produces the **same format** as the regular session output (no tabular view).
This differs from SRX hardware platforms where `brief` may produce a condensed tabular format.
bpfrx currently implements a tabular brief view which is a useful enhancement over vSRX behavior.

---

## Security: Flow Session Summary

**Command:** `show security flow session summary`

```
Unicast-sessions: 3231
Multicast-sessions: 0
Services-offload-sessions: 0
Failed-sessions: 0
Sessions-in-drop-flow: 0
Sessions-in-use: 3680
  Valid sessions: 3230
  Pending sessions: 0
  Invalidated sessions: 450
  Sessions in other states: 0
Maximum-sessions: 4194304
```

### Format Details

- Key-value with colon separator, value right after colon+space.
- Sub-items indented 2 spaces (Valid/Pending/Invalidated/Other).
- `Maximum-sessions: 4194304` (4M max on vSRX).

---

## Security: Flow Statistics

**Command:** `show security flow statistics`

```
    Current sessions: 5545
    Packets received: 53426518218
    Packets transmitted: 53091802103
    Packets forwarded/queued: 40436060
    Packets copied: 1208046
    Packets dropped: 293072009
    Services-offload packets processed: 0
    Fragment packets: 21545
    Pre fragments generated: 0
    Post fragments generated: 0
```

### Format Details

- Every line indented 4 spaces.
- Key-value with colon separator.
- All numbers right-aligned (no fixed width, just the number).

---

## Security: Policies

**Command:** `show security policies`

```
Default policy: deny-all
Default policy log Profile ID: 0
Pre ID default policy: permit-all
Default HTTP Mux policy: permit-all
From zone: trust, To zone: trust
  Policy: default-permit, State: enabled, Index: 4, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: any
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: permit
  Policy: default-deny, State: enabled, Index: 5, Scope Policy: 0, Sequence number: 2, Log Profile ID: 0
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: any
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: reject, log
From zone: guest, To zone: lan
  Policy: allow-airgroup, State: enabled, Index: 8, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: airgroup-devices
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: permit, log
```

### Format Details

- **Zone header:** `From zone: <name>, To zone: <name>` (no indentation).
- **Policy line:** 2-space indent, comma-separated: `Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>, Log Profile ID: 0`
- **Policy fields:** 4-space indent, `<Key>: <value>`.
- **Action line:** `Action: permit` or `Action: reject, log` or `Action: deny, log`.
- Multiple addresses shown as named address entries.

### Filtering

- `show security policies from-zone lan to-zone Internet-ATT` shows only that zone pair.

---

## Security: Policies Detail

**Command:** `show security policies detail from-zone lan to-zone Internet-ATT`

```
Policy: log-control4, action-type: permit, services-offload:not-configured , State: enabled, Index: 23, Scope Policy: 0
  Policy Type: Configured
  Sequence number: 1
  From zone: lan, To zone: Internet-ATT
  Source vrf group:
    any
  Destination vrf group:
    any
  Source addresses:
    host_control4_core5_adu(global): 172.16.1.38/32
    host_control4_ca10(global): 172.16.1.10/32
  Destination addresses:
    any-ipv4(global): 0.0.0.0/0
    any-ipv6(global): ::/0
  Application: any
    IP protocol: 0, ALG: 0, Inactivity timeout: 0
      Source port range: [0-0]
      Destination ports: [0-0]
  Source identity feeds:
    any
  Destination identity feeds:
    any
  Per policy TCP Options: SYN check: No, SEQ check: No, Window scale: No
  Session log: at-create, at-close
```

### Format Details

- **Policy header:** No indent. `Policy: <name>, action-type: permit, services-offload:not-configured , State: enabled, Index: <N>, Scope Policy: 0`
  - Note: space before comma after `not-configured `.
- **Policy fields:** 2-space indent.
- **Address entries:** 4-space indent. Format: `<name>(global): <prefix> ` (trailing space).
  - `(global)` suffix for global address-book entries.
- **Application block:** 2-space indent for app name, 4-space for protocol details, 6-space for ports.
  - `IP protocol: tcp|udp|0, ALG: 0, Inactivity timeout: <seconds>`
  - `Source port range: [<low>-<high>]`
  - `Destination ports: [<low>-<high>]` or just `<port>` for single port.
- **Session log:** `Session log: at-create, at-close` (only present if logging configured on policy).

---

## Security: Policies Hit-Count

**Command:** `show security policies hit-count`

```
Logical system: root-logical-system
Index   From zone        To zone           Name           Policy count  Action
1       all-zone         all-zone          default-policy 0             Deny
2       all-zone         all-zone          default-http-mux 0           Permit
3       junos-host       dmz               allow-junos-host-to-dmz 18939 Permit
5       junos-global     junos-global      icmpv6-allow   934734        Permit
6       junos-global     junos-global      default-log-deny 299946      Deny
```

### Format Details

- Tabular output with column headers.
- Columns: Index (left-aligned, ~8 wide), From zone (~17 wide), To zone (~18 wide), Name (variable), Policy count (right-justified before Action), Action (left-aligned).
- Spacing is not strictly fixed-width -- names can overflow into adjacent columns.
- Actions: `Permit`, `Deny`, `Reject`.

---

## Security: Global Policies

**Command:** `show security policies global`

```
Global policies:
  Policy: icmpv6-allow, State: enabled, Index: 524, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
    From zones: any
    To zones: any
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any-ipv6
    Destination addresses: any-ipv6
    Applications: junos-icmp6-all
    Source identity feeds: any
    Destination identity feeds: any
    Action: permit
  Policy: default-log-deny, State: enabled, Index: 525, Scope Policy: 0, Sequence number: 2, Log Profile ID: 0
    From zones: any
    To zones: any
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: any
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: deny, log
```

### Format Details

- Same as regular policies but with `Global policies:` header.
- Uses `From zones:` and `To zones:` (plural) instead of `From zone:` / `To zone:`.

---

## Security: Zones

**Command:** `show security zones`

```
Security zone: ATH-SAAB-VPN-HUB
  Zone ID: 24
  Send reset for non-SYN session TCP packets: Off
  Policy configurable: Yes
  Interfaces bound: 4
  Interfaces:
    st0.2
    st0.3
    st0.4
    st0.5
  Advanced-connection-tracking timeout: 1800
  Unidirectional-session-refreshing: No

Security zone: untrust
  Zone ID: 8
  Send reset for non-SYN session TCP packets: Off
  Policy configurable: Yes
  Screen: untrust-screen
  Interfaces bound: 0
  Interfaces:
  Advanced-connection-tracking timeout: 1800
  Unidirectional-session-refreshing: No

Security zone: junos-host
  Zone ID: 2
  Send reset for non-SYN session TCP packets: Off
  Policy configurable: Yes
  Interfaces bound: 0
  Interfaces:
  Advanced-connection-tracking timeout: 1800
  Unidirectional-session-refreshing: No
```

### Format Details

- **Zone header:** `Security zone: <name>` (no indent).
- **Fields:** 2-space indent.
- `Zone ID: <N>` -- auto-assigned numeric ID.
- `Send reset for non-SYN session TCP packets: On|Off`
- `Policy configurable: Yes  ` (trailing spaces)
- `Screen: <screen-name>` -- only present if screen is bound to zone.
- `Interfaces bound: <N>` -- count of bound interfaces.
- `Interfaces:` header, then each interface indented 4 spaces.
- Empty `Interfaces:` line with no entries if none bound.
- Blank line between zones.

---

## Security: NAT Source Rule All

**Command:** `show security nat source rule all`

```
Total rules: 14
Total referenced IPv4/IPv6 ip-prefixes: 16/28
source NAT rule: source-as-bci
  Rule set                   : bci-to-internet
  Rule Id                    : 1
  Rule position              : 1
  From zone                  : guest
                             : lan
  To zone                    : Internet-BCI
  Match
    Source addresses         : 0.0.0.0         - 255.255.255.255
    Destination addresses    : 0.0.0.0         - 255.255.255.255
  Action                        : bci_pool
    Persistent NAT type         : N/A
    Persistent NAT mapping type : address-port-mapping
    Inactivity timeout          : 0
    Max session number          : 0
    Persistent NAT block session: disabled
  Translation hits           : 0
    Successful sessions      : 0
  Number of sessions         : 0
```

### Format Details

- **Header:** `Total rules: <N>` and `Total referenced IPv4/IPv6 ip-prefixes: <N>/<N>`.
- **Rule header:** `source NAT rule: <name>` (no indent).
- **Fields:** 2-space indent, fixed-width label column (~27 chars) padded with spaces, then `: <value>`.
- **Multi-zone:** Continuation lines use spaces up to the colon: `                             : lan`.
- **Match block:** `Match` header alone, then 4-space indent for source/dest addresses.
  - Address ranges: `<start_ip>         - <end_ip>` (spaces padded to ~16 char width for first IP).
  - Multiple ranges shown on continuation lines with same spacing.
- **Action block:** `Action                        : <pool_name|interface|off>`.
  - Sub-fields at 4-space indent under Action.
- **Counters:** `Translation hits`, `Successful sessions`, `Number of sessions` at 2-space indent.
- Action `off` means NAT is explicitly disabled for that rule.

---

## Security: NAT Destination Rule All

**Command:** `show security nat destination rule all`

```
Total destination-nat rules: 23
Total referenced IPv4/IPv6 ip-prefixes: 17/9
Destination NAT rule: firehouse-syslog
  Rule set                   : internet-in-dmz-dnat
  Rule Id                    : 1
  Rule position              : 1
  From zone                  : Internet-ATT
                             : Internet-BCI
    Destination addresses    : 108.85.109.0    - 108.85.109.0
    Destination port         : 514             - 514
  Action                     : host_syslog_container
  Translation hits           : 18564
    Successful sessions      : 18491
  Number of sessions         : 1
```

### Format Details

- Same structure as source NAT but with `Destination NAT rule:` header.
- **Destination port ranges:** `<low>             - <high>` (padded).
- Multiple port ranges on separate lines.
- **Application match:** `Application              : configured` (instead of port).
- **IP protocol match:** `IP protocol              : icmp6` or `47` (for GRE).
- **Source address match:** `Source addresses         : <address-book-name>` (named, not expanded).

---

## Security: NAT Source Summary

**Command:** `show security nat source summary`

```
Total port number usage for port translation pool: 64512
Maximum port number for port translation pool: 201326592
Total pools: 1
Pool                 Address                  Routing              PAT  Total
Name                 Range                    Instance                  Address
bci_pool             50.247.115.21-50.247.115.21 default           yes  1

Total rules: 14
Rule name : source-as-bci
    Rule set  : bci-to-internet
    Action    : bci_pool
    From      : guest                 To : Internet-BCI
Rule name : source-as-bci
Rule name : source-as-bci
    From      : lan
```

### Format Details

- **Pool table:** Fixed columns: Pool Name (~21), Address Range (~25), Routing Instance (~21), PAT (~5), Total Address.
- **Rule summary:** `Rule name : <name>` (note spaces around colon).
  - Sub-fields at 4-space indent: `Rule set  :`, `Action    :`, `From      :`, `To :`.
  - Continuation rules share the rule name but show additional From/To zones.
  - Zone names padded to fixed width (~22 chars).

---

## Security: Screen IDS

**Command:** `show security screen ids-option <screen-name>`

```
Screen object status:

Name                                       value
  IP tear drop                               enabled
  TCP SYN flood attack threshold             200
  TCP SYN flood alarm threshold              1024
  TCP SYN flood source threshold             1024
  TCP SYN flood destination threshold        2048
  TCP SYN flood timeout                      20
  ICMP ping of death                         enabled
  IP source route option                     enabled
  TCP land attack                            enabled
```

### Format Details

- Header: `Screen object status:` followed by blank line.
- Column headers: `Name` (left-aligned, ~43 chars) and `value` (left-aligned).
  - Header uses trailing spaces for padding.
- Each entry: 2-space indent, name padded to ~43 chars, then value padded.
- Values: `enabled` or numeric thresholds.

---

## Security: ALG Status

**Command:** `show security alg status`

```
ALG Status:
  DNS      : Disabled
  FTP      : Disabled
  H323     : Enabled
  MGCP     : Enabled
  MSRPC    : Enabled
  PPTP     : Enabled
  RSH      : Disabled
  RTSP     : Enabled
  SCCP     : Enabled
  SIP      : Enabled
  SQL      : Disabled
  SUNRPC   : Enabled
  TALK     : Enabled
  TFTP     : Enabled
  IKE-ESP  : Disabled
  TWAMP    : Disabled
```

### Format Details

- Header: `ALG Status:`.
- Each line: 2-space indent, name (~9 chars left-aligned), ` : ` separator (space-colon-space), value.
- Values: `Enabled` or `Disabled` (capitalized).
- **Note:** NOT per-node output (no node0/node1 headers). This is a single global output.

---

## Security: IPsec Security Associations

**Command:** `show security ipsec security-associations`

```
  Total active tunnels: 6     Total Ipsec sas: 6
  ID    Algorithm       SPI      Life:sec/kb  Mon lsys Port  Gateway
  <131073 ESP:aes-gcm-128/None 94337ff7 1932/ unlim - root 500 50.233.235.222
  >131073 ESP:aes-gcm-128/None b941875f 1932/ unlim - root 500 50.233.235.222
  <131074 ESP:aes-cbc-256/sha256 b95afaf0 3029/ unlim - root 500 104.193.170.172
  >131074 ESP:aes-cbc-256/sha256 ca3156de 3029/ unlim - root 500 104.193.170.172
```

### Format Details

- **Summary line:** `  Total active tunnels: <N>     Total Ipsec sas: <N>` (2-space indent).
- **Column header:** `  ID    Algorithm       SPI      Life:sec/kb  Mon lsys Port  Gateway   ` (2-space indent).
- **Each SA:** 2-space indent.
  - Direction: `<` (inbound) or `>` (outbound) prefix, no space before ID.
  - ID: SA index.
  - Algorithm: `ESP:<enc>/<auth>` e.g. `ESP:aes-gcm-128/None`, `ESP:aes-cbc-256/sha256`.
  - SPI: 8-char hex.
  - Life: `<seconds>/ unlim` or `<seconds>/<kbytes>`.
  - Mon: `-` (monitoring off) or status.
  - lsys: `root`.
  - Port: `500` or `4500`.
  - Gateway: remote peer IP.
- Inbound/outbound pairs share the same ID.

---

## Security: IPsec Security Associations Detail

**Command:** `show security ipsec security-associations detail`

```
ID: 131073 Virtual-system: root, VPN Name: BV-FIREHOUSE
  Local Gateway: 50.220.171.30, Remote Gateway: 50.233.235.222
  Local Identity: ipv4_subnet(any:0,[0..7]=0.0.0.0/0)
  Remote Identity: ipv4_subnet(any:0,[0..7]=0.0.0.0/0)
  Version: IKEv1
  DF-bit: copy, Copy-Outer-DSCP Disabled, Bind-interface: st0.0
  Port: 500, Nego#: 959, Fail#: 0, Def-Del#: 0 Flag: 0x600a29
  Multi-sa, Configured SAs# 1, Negotiated SAs#: 1
  Tunnel events:
    Sat Feb 14 2026 20:53:59 -0800: IPSec SA negotiation successfully completed (25 times)
    Sat Feb 14 2026 17:02:56 -0800: IKE SA negotiation successfully completed (56 times)
  Direction: inbound, SPI: 94337ff7, AUX-SPI: 0
                              , VPN Monitoring: -
    Hard lifetime: Expires in 1858 seconds
    Lifesize Remaining:  Unlimited
    Soft lifetime: Expires in 1285 seconds
    Mode: Tunnel(0 0), Type: dynamic, State: installed
    Protocol: ESP, Authentication: None, Encryption: aes-gcm (128 bits)
    Anti-replay service: counter-based enabled, Replay window size: 64
  Direction: outbound, SPI: b941875f, AUX-SPI: 0
                              , VPN Monitoring: -
    Hard lifetime: Expires in 1858 seconds
    Lifesize Remaining:  Unlimited
    Soft lifetime: Expires in 1285 seconds
    Mode: Tunnel(0 0), Type: dynamic, State: installed
    Protocol: ESP, Authentication: None, Encryption: aes-gcm (128 bits)
    Anti-replay service: counter-based enabled, Replay window size: 64
```

### Format Details

- **SA header:** `ID: <N> Virtual-system: root, VPN Name: <name>` (no indent).
- **Fields:** 2-space indent.
- **Tunnel events:** 4-space indent, timestamp format: `<Day> <Mon> <DD> <YYYY> <HH:MM:SS> <TZ>: <event> (<N> times)`.
- **Direction blocks:** 2-space indent for header, 4-space for details.
  - `Direction: inbound|outbound, SPI: <hex>, AUX-SPI: 0`
  - Second line is continuation with VPN Monitoring.
  - Sub-fields: Hard lifetime, Lifesize, Soft lifetime, Mode, Protocol, Anti-replay.

---

## Security: IKE Security Associations

**Command:** `show security ike security-associations`

```
Index   State  Initiator cookie  Responder cookie  Mode           Remote Address
10827715 UP    ccb95f0882a044a8  67c1a3d54ae8f069  IKEv2          174.70.192.83
10827718 UP    f737bec6d2d877ff  9cb755d0c21be9c3  IKEv2          172.3.77.209
10827726 UP    0f33732903bd3ed7  ed31e2cf6088415f  Main           50.233.235.222
```

### Format Details

- **Column header:** `Index   State  Initiator cookie  Responder cookie  Mode           Remote Address   `
- **Index:** Left-aligned ~9 chars.
- **State:** `UP` or `DOWN`, ~7 chars.
- **Cookies:** 16-char hex each, ~18 chars.
- **Mode:** `IKEv2` or `Main` (for IKEv1), ~15 chars.
- **Remote Address:** IP address.

---

## Security: Log

**Command:** `show security log`

```
error: permission denied: log
```

**Note:** Requires specific permissions. The `claude` user did not have access. On a fully privileged
session, this would show structured security log events. The format is known from documentation:

```
<timestamp> <hostname> RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.0.1.102" source-port="54321" destination-address="10.0.2.102" destination-port="80" connection-tag="0x0" nat-source-address="10.0.1.102" nat-source-port="54321" nat-destination-address="10.0.2.102" nat-destination-port="80" nat-connection-tag="0x0" src-nat-rule-type="N/A" src-nat-rule-name="N/A" dst-nat-rule-type="N/A" dst-nat-rule-name="N/A" protocol-id="6" policy-name="trust-to-untrust-permit" source-zone-name="trust" destination-zone-name="untrust" session-id-32="1234" packets-from-client="0" bytes-from-client="0" packets-from-server="0" bytes-from-server="0" elapsed-time="0" application="UNKNOWN" nested-application="UNKNOWN" username="N/A" roles="N/A" packet-incoming-interface="trust0.0" encrypted="UNKNOWN"]
```

The `show configuration security log` was also permission-denied.

---

## Interfaces: Terse

**Command:** `show interfaces terse`

```
Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   aenet    --> reth0.0
gr-0/0/0.0              up    up   inet     10.255.192.22/30
gr-0/0/0.1              up    up   inet     10.255.192.34/30
                                   inet6    fc00::e/126
                                            fe80::8/64
ge-0/0/1                up    down
reth0                   up    up
reth0.0                 up    up   inet     50.220.171.30/30
                                   inet6    2001:559:800c:1900::881a/126
                                            fe80::210:dbff:feff:1000/64
lo0                     up    up
lo0.0                   up    up   inet
                                   inet6    fe80::86c1:c10f:fc03:5100
```

### Format Details

- **Column header:** `Interface               Admin Link Proto    Local                 Remote`
- **Column positions (0-indexed):**
  - Interface: 0-23 (24 chars)
  - Admin: 24-28 (5 chars, `up` or `down`)
  - Link: 30-33 (4 chars)
  - Proto: 35-42 (8 chars, `inet`, `inet6`, `aenet`, `tnp`)
  - Local: 44-64 (21 chars)
  - Remote: 66+
- **Continuation lines** for additional addresses: same column positions, blank Interface/Admin/Link.
- `aenet    --> reth0.0` for aggregated ethernet member links.
- **Pipe filters work:** `show interfaces terse | except down` removes down interfaces.

---

## Interfaces: Detail

**Command:** `show interfaces <name> detail`

```
Physical interface: reth0, Enabled, Physical link is Up
  Interface index: 128, SNMP ifIndex: 501, Generation: 131
  Description: Comcast Gigabit Pro
  Link-level type: Ethernet, MTU: 1514, Speed: 1Gbps, ...
  Device flags   : Present Running
  Interface flags: SNMP-Traps Internal: 0x4000
  Current address: 00:10:db:ff:10:00, Hardware address: 00:10:db:ff:10:00
  Last flapped   : 2026-01-13 15:40:40 PST (4w4d 05:41 ago)
  Statistics last cleared: Never
  Traffic statistics:
   Input  bytes  :       26021579096863              8442760 bps
   Output bytes  :       32458307878019             86493408 bps
   Input  packets:          20655442875                 2006 pps
   Output packets:          24187455940                 7723 pps
  Ingress queues: 8 supported, 4 in use
  Queue counters:       Queued packets  Transmitted packets      Dropped packets
    0                                0                    0                    0
  Egress queues: 8 supported, 4 in use
  Queue counters:       Queued packets  Transmitted packets      Dropped packets
    0                       2707422561           2707422561                    0
  Queue number:         Mapped forwarding classes
    0                   best-effort

  Logical interface reth0.0 (Index 93) (SNMP ifIndex 525) (Generation 158)
    Flags: Up SNMP-Traps 0x4004000 Encapsulation: ENET2
    Statistics        Packets        pps         Bytes          bps
    Bundle:
        Input :   20655442875       2006 26021579096863      8442760
        Output:   24184316839       7721 32454800570987     86491176
    Security: Zone: Internet-Gigabit-Pro
    Allowed host-inbound traffic : dhcp ike ping ssh traceroute dhcpv6
    Flow Statistics :
    Flow Input statistics :
      Self packets :                     38653109
      ICMP packets :                     23960745
      VPN packets :                      15299304
      Multicast packets :                3192
      Bytes permitted by policy :        26016665651961
      Connections established :          158020411
    Flow Output statistics:
      Multicast packets :                0
      Bytes permitted by policy :        32452687300274
    Flow error statistics (Packets dropped due to):
      Address spoofing:                  0
      No route present:                  14603
      No SA for incoming SPI:            0
      Policy denied:                     632620
      TCP sequence number out of window: 3129
    Protocol inet, MTU: 1500
      Flags: Sendbcast-pkt-to-re, Is-Primary, Sample-input, Sample-output
      Addresses, Flags: Primary Preferred Is-Default Is-Preferred Is-Primary
        Destination: 50.220.171.28/30, Local: 50.220.171.30, Broadcast: 50.220.171.31
    Protocol inet6, MTU: 1500
      Flags: Is-Primary, Sample-input, Sample-output
      Addresses, Flags: Is-Default Is-Preferred Is-Primary
        Destination: 2001:559:800c:1900::8818/126, Local: 2001:559:800c:1900::881a
```

### Format Details

- **Physical header:** `Physical interface: <name>, Enabled, Physical link is Up|Down`
- **All fields:** 2-space indent under physical, 4-space under logical.
- **Traffic stats:** Right-aligned numbers with rate (bps/pps) on same line.
  - Counter name padded to ~14 chars, colon, then number right-aligned ~20 chars, rate ~20 chars.
- **Flow statistics:** Under logical interface, indented further.
  - `Flow Input statistics :` and `Flow Output statistics:` headers.
  - `Flow error statistics (Packets dropped due to):` header.
  - Each counter: 6-space indent, name padded, colon, right-aligned number.
- **Protocol blocks:** `Protocol inet, MTU: 1500` and `Protocol inet6, MTU: 1500`.
  - Address entries under each protocol.

---

## Interfaces: Extensive

**Command:** `show interfaces <name> extensive`

Same as `detail` but adds:

```
  Dropped traffic statistics due to STP State:
   Input  bytes  :                    0
   Output bytes  :                    0
   Input  packets:                    0
   Output packets:                    0
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0, Resource errors: 0
  Output errors:
    Carrier transitions: 1, Errors: 0, Drops: 0, MTU errors: 0, Resource errors: 0
```

### Format Details

- Includes STP drop stats, Input/Output error counters.
- Error fields are comma-separated on one line.
- Otherwise identical to `detail` output.

---

## System: Uptime

**Command:** `show system uptime`

```
Current time: 2026-02-14 21:22:05 PST
Time Source:  NTP CLOCK
System booted: 2026-01-13 15:47:21 PST (4w4d 05:34 ago)
Last configured: 2026-02-14 19:49:01 PST (01:33:04 ago) by ps
 9:22PM  up 32 days,  5:35, 0 users, load averages: 6.38, 5.88, 5.88
```

### Format Details

- Key-value pairs with timestamp format: `YYYY-MM-DD HH:MM:SS TZ`.
- Relative time in parentheses: `(4w4d 05:34 ago)` or `(01:33:04 ago)`.
- Last line is BSD-style uptime: `<time>  up <days> days, <hours>:<mins>, <users> users, load averages: <1m>, <5m>, <15m>`.
- `Time Source:  NTP CLOCK ` (trailing space).
- node1 also shows `Protocols started:` line.
- `Last configured:` includes ` by <username>`.

---

## System: Memory

**Command:** `show system memory`

```
System memory usage distribution:
        Total memory: 16715220 Kbytes (100%)
     Reserved memory:  454076 Kbytes (  2%)
        Wired memory: 13798816 Kbytes ( 82%)
       Active memory:   95164 Kbytes (  0%)
     Inactive memory: 1579984 Kbytes (  9%)
        Cache memory:       0 Kbytes (  0%)
         Free memory:  785412 Kbytes (  4%)
Pid     VM-Kbytes(  %  ) Resident(  %  ) Process-name
      0         0(00.00)        0(00.00) [kernel]
      1         0(00.00)        0(00.00) /sbin/init
  17402  14018780(83.87)  12968400(77.59) srxpfe
```

### Format Details

- Header: `System memory usage distribution:`.
- Memory lines: right-aligned label (variable indent), then `: <number> Kbytes (<percent>%)`.
- Process table: `Pid` (right-aligned 7), `VM-Kbytes(  %  )` (right-aligned), `Resident(  %  )`, `Process-name`.
- Numbers formatted with right-alignment within parenthesized percentages.

---

## System: Processes Summary

**Command:** `show system processes summary`

```
last pid: 21215;  load averages:  5.19,  5.63,  5.78  up 32+05:35:30    21:22:51
584 threads:   11 running, 540 sleeping, 1 zombie, 32 waiting
CPU: 84.2% user,  0.0% nice,  1.9% system,  0.2% interrupt, 13.7% idle
Mem: 93M Active, 1543M Inact, 13G Wired, 307M Buf, 766M Free
Swap: 1024M Total, 1024M Free

  PID USERNAME    PRI NICE   SIZE    RES STATE    C   TIME    WCPU COMMAND
17402 root        -52   r0    13G    12G CPU4     4 773.3H 100.00% srxpfe{lcore-worker-4}
17402 root        -52   r0    13G    12G CPU2     2 773.3H 100.00% srxpfe{lcore-worker-2}
   11 root        187 ki31     0B    80K RUN      0 530.0H  66.36% idle{idle: cpu0}
```

### Format Details

- First 5 lines are FreeBSD `top` header format.
- Process table columns: PID (right-aligned 5), USERNAME (left-aligned 12), PRI (right-aligned 4), NICE (right-aligned 5), SIZE (right-aligned 7), RES (right-aligned 7), STATE (left-aligned 9), C (right-aligned 2), TIME (right-aligned 8), WCPU (right-aligned 7), COMMAND.
- TIME format: `<hours>.<tenths>H` for hours, `<min>:<sec>` for minutes.
- WCPU: percentage with 2 decimal places.
- Thread names in curly braces: `srxpfe{lcore-worker-4}`.

---

## System: Version

**Command:** `show version`

```
Hostname: vsrx-ernie
Model: vSRX
Family: junos-es
Junos: 24.4R1-S2.9
JUNOS hsm [20250306.002422_builder_junos_244_r1_s2]
JUNOS OS Kernel 64-bit XEN [20250128.8676a19_builder_bsd15_244]
JUNOS modules [20250306.002422_builder_junos_244_r1_s2]
...
```

### Format Details

- First 4 lines are key-value with colon separator: `Hostname:`, `Model:`, `Family:`, `Junos:`.
- Remaining lines are package names with version in brackets: `JUNOS <package> [<version>]`.
- Per-node output in cluster.

---

## Chassis Cluster: Status

**Command:** `show chassis cluster status`

```
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    GR  GRES monitoring             HW  Hardware monitoring
    IF  Interface monitoring        IP  IP monitoring
    LB  Loopback monitoring         MB  Mbuf monitoring
    NH  Nexthop monitoring          NP  NPC monitoring
    SP  SPU monitoring              SM  Schedule monitoring
    CF  Config Sync monitoring      RE  Relinquish monitoring
    IS  IRQ storm

Cluster ID: 1
Node   Priority Status               Preempt Manual   Monitor-failures

Redundancy group: 0 , Failover count: 1
node0  100      secondary            no      no       None
node1  1        primary              no      no       None

Redundancy group: 1 , Failover count: 1
node0  100      secondary            no      no       None
node1  1        primary              no      no       None

Redundancy group: 4 , Failover count: 1
node0  0        secondary            no      no       IF
node1  0        primary              no      no       IF
```

### Format Details

- **Monitor failure codes legend:** 4-space indent, 2-char code, 2 spaces, description. Two columns per line.
- **Cluster ID:** `Cluster ID: <N>`.
- **Column header:** `Node   Priority Status               Preempt Manual   Monitor-failures`
  - Node: 7 chars, Priority: 9 chars, Status: 21 chars, Preempt: 8 chars, Manual: 9 chars, Monitor-failures: variable.
- **RG header:** `Redundancy group: <N> , Failover count: <N>` (note space before comma).
- **Node entries:** Fixed columns matching header.
  - Status: `primary`, `secondary`, `hold`, `lost`, `disabled`.
  - Monitor-failures: `None` or failure code(s) like `IF`.
- Blank line between redundancy groups.

---

## Chassis Cluster: Interfaces

**Command:** `show chassis cluster interfaces`

```
Control link status: Up

Control interfaces:
    Index   Interface   Monitored-Status   Internal-SA   Security
    0       em0         Up                 Disabled      Disabled

Fabric link status: Up

Fabric interfaces:
    Name    Child-interface    Status                    Security
                               (Physical/Monitored)
    fab0    ge-0/0/7           Up   / Up                 Disabled
    fab1    ge-7/0/7           Up   / Up                 Disabled

Redundant-ethernet Information:
    Name         Status      Redundancy-group
    reth0        Up          1
    reth1        Up          2
    reth3        Down        4

Redundant-pseudo-interface Information:
    Name         Status      Redundancy-group
    lo0          Up          0

Interface Monitoring:
    Interface         Weight    Status                    Redundancy-group
                                (Physical/Monitored)
    ge-7/0/0          255       Up  /  Up                 1
    ge-0/0/0          255       Up  /  Up                 1
    ge-7/0/6          255       Down  /  Down             4
```

### Format Details

- **Sections:** Control, Fabric, Redundant-ethernet, Redundant-pseudo-interface, Interface Monitoring.
- Each section has its own column headers.
- `Status` shows `(Physical/Monitored)` as sub-header on the next line for fabric/monitoring.
- Status format: `Up   / Up` or `Down  /  Down` (variable spacing around `/`).
- Fixed-width columns within each section.
- Trailing spaces after values for column padding.

---

## Routing: Route Table

**Command:** `show route table inet.0`

```
inet.0: 72 destinations, 78 routes (72 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[Static/5] 4d 07:44:55
                       to table Comcast-GigabitPro.inet.0
10.0.100.0/24      *[BGP/170] 02:27:21, MED 0, localpref 100
                      AS path: 65500 I, validation-state: unverified
                    >  to 192.168.255.5 via st0.1
10.5.1.0/24        *[Direct/0] 1d 11:31:02
                    >  via reth1.51
10.5.1.1/32        *[Local/0] 1d 11:31:02
                       Local via reth1.51
192.168.0.0/24     *[Direct/0] 1d 11:31:02
                    >  via reth1.1
                    [Direct/0] 1d 11:31:02
                    >  via reth1.1
```

### Format Details

- **Table header:** `<table>: <N> destinations, <N> routes (<N> active, <N> holddown, <N> hidden)`.
- **Legend:** `+ = Active Route, - = Last Active, * = Both`.
- **Route format:**
  - Prefix: left-aligned, padded to ~19 chars.
  - Active marker: `*` (both active + last active), `+` (active only), `-` (last active only), or blank.
  - Protocol/preference in brackets: `[Static/5]`, `[BGP/170]`, `[Direct/0]`, `[Local/0]`.
  - Age: `4d 07:44:55` or `1d 11:31:02` or `02:27:21`.
  - BGP attributes: `, MED 0, localpref 100` and `AS path: 65500 I, validation-state: unverified`.
- **Next-hop lines:** Indented ~20 chars.
  - `>  to <nexthop> via <interface>` (best next-hop, `>` marker).
  - `   to table <table>` (route leak/table reference).
  - `   Local via <interface>` (local route).
- **Multiple routes** for same prefix: continuation with different protocol block.
- Blank line after table header legend.

---

## Routing: Route Summary

**Command:** `show route summary`

```
Router ID: 10.5.1.1

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 1014 at 2026-02-12 10:56:49 / 1013
    RIB routes                   : 1074 at 2026-02-12 11:07:40 / 1065
    FIB routes                   : 871 at 2026-02-13 09:49:44 / 838
    VRF type routing instances   : 0 at 2026-01-13 15:39:20

inet.0: 72 destinations, 78 routes (72 active, 0 holddown, 0 hidden)
              Direct:     34 routes,     28 active
               Local:     35 routes,     35 active
                 BGP:      8 routes,      8 active
              Static:      1 routes,      1 active

ATT.inet.0: 62 destinations, 68 routes (62 active, 0 holddown, 0 hidden)
              Direct:     33 routes,     27 active
               Local:     34 routes,     34 active
     Access-internal:      1 routes,      1 active
```

### Format Details

- **Router ID line.**
- **Highwater marks:** 4-space indent, label padded to ~35 chars, `: <N> at <timestamp> / <N>`.
- **Per-table summary:** Table header same as route table.
  - Protocol lines: right-aligned protocol name (~21 chars), `: <N> routes, <N> active`.
  - Numbers right-aligned within ~6 chars.

---

## Routing: BGP Summary

**Command:** `show bgp summary`

```
Threading mode: BGP I/O
Default eBGP mode: advertise - accept, receive - accept
Groups: 6 Peers: 6 Down peers: 0
Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
inet.0
                       8          8          0          0          0          0
inet6.0
                       1          0          0          0          0          0
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
192.168.255.1         65909       2714       2676       0      51    20:20:46 Establ
  inet.0: 3/3/3/0
  inet6.0: 0/0/0/0
192.168.255.5         65500        302        329       0     110     2:28:38 Establ
  inet.0: 2/2/2/0
```

### Format Details

- **Header lines:** Key-value pairs.
- **Table summary:** `Table` (left, ~15), `Tot Paths` (~10), `Act Paths` (~10), `Suppressed` (~11), `History` (~8), `Damp State` (~11), `Pending` (~8).
  - Table name on first line, counts on continuation line below.
- **Peer table header:** `Peer` (~25), `AS` (~8), `InPkt` (~10), `OutPkt` (~10), `OutQ` (~7), `Flaps` (~7), `Last Up/Dwn` (~12), `State|#Active/...`.
- **Peer entries:**
  - IP left-aligned ~25 chars.
  - AS right-aligned ~5 chars.
  - Counts right-aligned in their columns.
  - State: `Establ` (truncated `Established`), `Active`, `Connect`, `Idle`.
  - Per-table summary: 2-space indent, `<table>: <active>/<received>/<accepted>/<damped>`.

---

## Routing: ARP

**Command:** `show arp no-resolve`

```
MAC Address       Address         Interface                Flags
6a:56:98:81:8e:2d 10.5.1.160      reth1.51                 none
86:73:ed:47:e8:67 10.5.1.192      reth1.51                 none
4c:96:14:51:39:ae 30.17.0.2       fab0.0                   permanent
Total entries: 384
```

### Format Details

- **Column header:** `MAC Address       Address         Interface                Flags`
- **Columns:**
  - MAC Address: 17 chars (xx:xx:xx:xx:xx:xx), left-aligned + 1 space.
  - Address: 16 chars, left-aligned.
  - Interface: 25 chars, left-aligned.
  - Flags: `none`, `permanent`.
- **Footer:** `Total entries: <N>`.
- `no-resolve` flag prevents DNS lookups for addresses.
- **Note:** NOT per-node output. Single output (from active node).

---

## Pipe Filters

### `| match <pattern>`

Filters output to lines matching the pattern (case-sensitive grep):

```
> show route | match 0.0.0.0
0.0.0.0/0          *[Static/5] 4d 07:45:39
0.0.0.0/0          *[Access-internal/12] 4w4d 05:42:19, metric 0
0.0.0.0/0          *[Static/5] 4w4d 05:42:26
```

### `| except <pattern>`

Filters out lines matching the pattern (inverse grep):

```
> show interfaces terse | except down
```

Removes all lines containing "down" (case-sensitive).

### `| count`

Counts lines in output:

```
> show security flow session | count
Count: 12345 lines
```

(Note: this is slow on large outputs like full session tables.)

### `| no-more`

Disables pagination (like `| less` in Unix). Essential for non-interactive SSH.

### `| last <N>`

Shows last N lines:

```
> show log messages | last 20
```

### Combined Filters

Pipe filters can be chained:

```
> show route | match 0.0.0.0 | count
```

---

## Configuration Display

### `show configuration`

Permission was denied for the `claude` user on this vSRX. The standard format is:

```
security {
    log {
        mode stream;
        format sd-syslog;
        source-address 192.168.99.1;
        stream syslog-server {
            severity info;
            format sd-syslog;
            host {
                192.168.99.252;
                port 514;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy permit-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                    log {
                        session-init;
                        session-close;
                    }
                }
            }
        }
    }
}
```

### `show configuration | display set`

Flat set format:

```
set security log mode stream
set security log format sd-syslog
set security log source-address 192.168.99.1
set security log stream syslog-server severity info
set security log stream syslog-server format sd-syslog
set security log stream syslog-server host 192.168.99.252
set security log stream syslog-server host port 514
```

### `| display set | match <pattern>`

```
> show configuration | display set | match log
```

---

## Notes for bpfrx Implementation

### Key Differences to Address

1. **Cluster headers:** bpfrx is single-node, so no `node0:/node1:` headers needed (unless cluster mode).
   In cluster mode, should replicate the `nodeN:` + 74-dash separator format.

2. **Session format:** bpfrx currently has a different format. Should match:
   - `Session ID: <id>, Policy name: <name>/<index>, HA State: Active, Timeout: <N>, Session State: Valid`
   - `  In: <src>/<port> --> <dst>/<port>;<proto>, Conn Tag: 0x0, If: <iface>, Pkts: <N>, Bytes: <N>, `
   - Note the trailing comma+space on In/Out lines.

3. **Policy format:** bpfrx should use the 2-space/4-space indent hierarchy.
   - `From zone:` header with no indent.
   - Policy entries at 2-space indent with comma-separated metadata.
   - Field values at 4-space indent.

4. **NAT rules:** The field-label alignment (padding to ~27 chars before colon) is distinctive.
   Multi-zone continuation lines align at the colon position.

5. **Route table:** The `*[Protocol/preference]` format with `>` best-nexthop marker is critical.
   Age format: `Xd HH:MM:SS` for days, `HH:MM:SS` for hours, or `Xw Xd HH:MM:SS` for weeks.

6. **Interface terse:** Fixed column positions are important for pipe filter compatibility.

7. **BGP summary:** `Establ` is truncated from `Established`. The per-table `active/received/accepted/damped`
   format under each peer is distinctive.

8. **Screen IDS:** Simple two-column table with name and value.

9. **ALG status:** Single global output (not per-node), 2-space indent.

10. **IPsec SAs:** `<`/`>` direction markers, algorithm format `ESP:<enc>/<auth>`.

11. **Policy hit-count:** Tabular format with Index, From zone, To zone, Name, Count, Action columns.

12. **Security log:** Structured syslog format (SD-SYSLOG) with `RT_FLOW` event types.
    Key fields: source-address, source-port, destination-address, destination-port,
    nat-source-address, nat-source-port, nat-destination-address, nat-destination-port,
    protocol-id, policy-name, source-zone-name, destination-zone-name, session-id-32.

### Trailing Spaces / Padding

Junos often pads values with trailing spaces to maintain column alignment. This is visible
in fields like `Policy configurable: Yes  ` and in tabular outputs. While not strictly
necessary for correctness, matching this improves compatibility with scripts that parse
fixed-width columns.
