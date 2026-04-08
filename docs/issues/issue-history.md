# bpfrx Issue History

Complete record of all issues filed and resolved.
Total: 378 issues (364 closed, 14 open)

---

## #6 — test auth check [CLOSED] (closed 2026-03-01)

auth check

---

## #7 — Interface-mode SNAT can select wrong source IP on snat_egress lookup miss [CLOSED] (closed 2026-03-01)

## Summary
`source-nat interface` can still emit the wrong source IP when `(fwd_ifindex, egress_vlan_id)` lookup in `snat_egress_ips` misses.

## Why this is a bug
In interface mode, `nat_pool_alloc_iface_v4()`/`nat_pool_alloc_iface_v6()` are expected to use the egress interface IP.
If lookup misses, both functions **fall back to generic pool allocation**:

- `bpf/xdp/xdp_policy.c:395-396`
- `bpf/xdp/xdp_policy.c:483`

That generic pool is populated with all to-zone interface addresses collected by the compiler, not the actual egress interface:

- `pkg/dataplane/compiler.go:1828-1833`
- `pkg/dataplane/compiler.go:1933-1952`

So a miss can select an IP that belongs to a different interface/VRRP role, which matches observed "wrong SNAT IP from wrong interface" behavior.

## Impact
- Random/intermittent connection failures depending on selected pool IP.
- Return traffic can be asymmetric or blackholed during failover and mixed-interface zones.

## Suggested fix
- In interface mode, treat missing `snat_egress_ips` entry as allocation failure (drop/counter), not pool fallback.
- Add a dedicated counter/trace for egress-key misses.
- Keep fallback only for explicit non-interface mode.


---

## #8 — IPv4 DNAT-before-fabric helper uses fixed L3/L4 offsets [CLOSED] (closed 2026-03-01)

## Summary
`apply_dnat_before_fabric_redirect()` IPv4 path uses fixed header offsets instead of parser-provided offsets.

## Why this is a bug
The IPv4 helper currently does:

- `iph = data + sizeof(struct ethhdr)`
- `l4 = iph + sizeof(struct iphdr)`

at:

- `bpf/xdp/xdp_zone.c:325`
- `bpf/xdp/xdp_zone.c:334`

This ignores parsed `meta->l3_offset` / `meta->l4_offset` and ignores variable IPv4 header length (`ihl`).

That can rewrite/checksum the wrong bytes when offsets are not the minimal fixed layout (notably IPv4 options).

## Impact
- Incorrect DNAT-before-fabric rewrite on IPv4 packets with non-minimal header layout.
- Can cause bad L4 checksum/port rewrite before fabric redirect, leading to drops on peer node.

## Suggested fix
- Mirror the IPv6 helper pattern and use `meta->l3_offset` / `meta->l4_offset` with bounds checks.
- Avoid deriving L4 as `iph + sizeof(struct iphdr)` in this helper.


---

## #9 — IPv4 DNAT-before-fabric skips port-only DNAT due dst-IP short-circuit [CLOSED] (closed 2026-03-01)

## Summary
`apply_dnat_before_fabric_redirect()` IPv4 path returns early when destination IP is unchanged, so port-only DNAT is skipped.

## Why this is a bug
Current early-return condition:

- `if ((void *)(iph + 1) > _de || iph->daddr == meta->dst_ip.v4) return;`
- `bpf/xdp/xdp_zone.c:326-328`

Port-only DNAT (same IP, translated destination port) still requires L4 destination port + checksum update before fabric redirect.

The IPv6 helper already documents this exact pitfall and avoids it:

- `bpf/xdp/xdp_zone.c:264-266`

## Impact
- Port-forward rules that keep destination IP but change destination port can fail during fabric redirect paths.
- Peer may receive packet with stale destination port and fail session/NAT matching.

## Suggested fix
- Remove the `iph->daddr == meta->dst_ip.v4` short-circuit.
- Compute `need_addr` and `need_port` separately; always process port rewrite when needed.


---

## #10 — Host-inbound filtering defaults to allow for unknown services [CLOSED] (closed 2026-03-01)

## Summary
Host-inbound enforcement currently allows unrecognized services by default, even when `host-inbound-traffic` is configured.

## Why this is a bug
`host_inbound_flag()` returns 0 for unknown protocols/ports with explicit "allowed by default" comments:

- `bpf/headers/bpfrx_helpers.h:915-916`
- `bpf/headers/bpfrx_helpers.h:966`

`xdp_forward` only denies when `flag != 0` and the bit is not allowed:

- `bpf/xdp/xdp_forward.c:96-101`

So any service not mapped to a `HOST_INBOUND_*` bit bypasses host-inbound deny logic.

## Impact
- Zone host-inbound policy is not default-deny for unknown services.
- Unexpected control-plane exposure for protocols/ports without explicit mapping.

## Suggested fix
- Treat unknown service (`flag == 0`) as deny when `host_inbound_flags` is configured and not `HOST_INBOUND_ALL`.
- Keep explicit allow-list behavior by expanding `host_inbound_flag()` mappings as needed.


---

## #11 — CLI: show security flow session nat-only is advertised but not parsed [CLOSED] (closed 2026-03-01)

## Summary
`show security flow session nat-only` is advertised in command completion/tree but not recognized by the flow-session filter parser.

## Repro
1. Run: `show security flow session nat-only`
2. Compare with: `show security flow session nat`

## Actual
- `nat-only` token is ignored (no NAT-only filtering applied).
- Only undocumented `nat` token enables `f.natOnly = true`.

## Expected
- `nat-only` should set NAT-only filtering (or tree/help should stop advertising it).

## Evidence
- Command tree advertises `nat-only`: `pkg/cmdtree/tree.go:266` and `pkg/cmdtree/tree.go:498`.
- Parser only accepts `nat`: `pkg/cli/cli.go:2977`.


---

## #12 — CLI: show security policies global does not return global-only view [CLOSED] (closed 2026-03-01)

## Summary
`show security policies global` is documented and present in command tree, but handler does not implement global-only behavior.

## Repro
Run: `show security policies global`

## Actual
- The `global` token is not special-cased in `handleShowSecurity`.
- Command falls through to default policy rendering and can include zone-pair policies, not just global policies.

## Expected
- Output should match the documented `Global policies:` section and show only global policies.

## Evidence
- Reference command and expected structure: `docs/junos-cli-reference.md:299`.
- `global` exists in tree: `pkg/cmdtree/tree.go:158`.
- Handler only special-cases `hit-count`, `detail`, `brief`: `pkg/cli/cli.go:1187`, `pkg/cli/cli.go:1191`, `pkg/cli/cli.go:1194`.
- Default path prints zone-pair policies first, then globals: `pkg/cli/cli.go:1253` and `pkg/cli/cli.go:1296`.


---

## #13 — CLI: show security ipsec security-associations detail is ignored [CLOSED] (closed 2026-03-01)

## Summary
`show security ipsec security-associations detail` is documented, but the current IPsec show handler ignores `detail` and always prints the non-detailed format.

## Repro
Run: `show security ipsec security-associations detail`

## Actual
- `showIPsec` checks only `args[0] == "security-associations"` and emits one format.
- Additional arg `detail` is ignored.

## Expected
- `detail` should invoke a detailed SA formatter aligned with Junos reference.

## Evidence
- Reference detail command: `docs/junos-cli-reference.md:590`.
- Current handler path: `pkg/cli/cli.go:5557` through `pkg/cli/cli.go:5584`.


---

## #14 — CLI: show interfaces <name> extensive is not implemented [CLOSED] (closed 2026-03-01)

## Summary
The reference command `show interfaces <name> extensive` is not supported. Current implementation only supports `show interfaces extensive` (all interfaces) or `show interfaces <name> detail`.

## Repro
Run: `show interfaces ge0 extensive`

## Actual
- `showInterfaces` does not route `<name> extensive` to a per-interface extensive renderer.
- Command is treated as generic interface listing filter path.

## Expected
- `<name> extensive` should render extensive output for the specified interface.

## Evidence
- Reference command: `docs/junos-cli-reference.md:793`.
- Current dispatch supports only top-level `extensive` and `<name> detail`: `pkg/cli/cli.go:5944` and `pkg/cli/cli.go:5953`.


---

## #15 — CLI: show route destination modifiers exact/longer/orlonger are unsupported [CLOSED] (closed 2026-03-01)

## Summary
`show route <destination> exact|longer|orlonger` modifiers from the reference are not parsed/handled.

## Repro
Run examples:
- `show route 10.0.0.0/24 exact`
- `show route 10.0.0.0/16 longer`
- `show route 10.0.0.0/16 orlonger`

## Actual
- Route handler only treats a single argument as destination lookup.
- Additional modifier argument causes fallback to generic `showRoutes()` output.

## Expected
- Parse and apply `exact`, `longer`, and `orlonger` semantics.

## Evidence
- Reference modifiers: `docs/junos-cli-reference.md:1107` through `docs/junos-cli-reference.md:1115`.
- Current parser handles destination only when `len(args)==1`: `pkg/cli/cli.go:5184`.
- Destination formatter currently has no modifier parameter: `pkg/routing/routing.go:796`.


---

## #16 — Routing: show route <prefix> CIDR matching logic is narrower than documented [CLOSED] (closed 2026-03-01)

## Summary
CIDR destination lookup semantics are incorrect for `show route <prefix>`.

## Repro
Run: `show route 10.0.0.0/8`

## Actual
- `FormatRouteDestination` checks `routeNet.Contains(destNet.IP)`.
- For CIDR input, this matches routes containing the network's first IP only (e.g. `10.0.0.0`), not all routes contained within/equal to `10.0.0.0/8`.

## Expected
- For CIDR input, include routes where route prefix is within (or equal to) requested prefix, matching reference behavior.

## Evidence
- Reference behavior: `docs/junos-cli-reference.md:1112`.
- Current implementation: `pkg/routing/routing.go:800` and `pkg/routing/routing.go:822`.


---

## #17 — CLI: top-level show bgp summary alias missing [CLOSED] (closed 2026-03-01)

## Summary
The reference command is `show bgp summary`, but CLI only supports `show protocols bgp summary`.

## Repro
Run: `show bgp summary`

## Actual
- Top-level `show` dispatcher has no `bgp` case.
- BGP summary exists only under `show protocols`.

## Expected
- Support `show bgp summary` alias for Junos parity.

## Evidence
- Reference command: `docs/junos-cli-reference.md:1157`.
- No top-level `case "bgp"` in `handleShow`: `pkg/cli/cli.go:961` onward.
- Existing implementation under protocols: `pkg/cli/cli.go:5383` and `pkg/cli/cli.go:5392`.


---

## #18 — CLI pipe filters are case-insensitive but Junos reference is case-sensitive [CLOSED] (closed 2026-03-01)

## Summary
Pipe filters `| match`, `| except`, and `| find` are implemented case-insensitively, but reference behavior is case-sensitive.

## Repro
Run (example):
- `show interfaces terse | match DOWN`

## Actual
- Pattern and each line are lowercased before comparison.
- This matches regardless of case.

## Expected
- Case-sensitive matching for `match` and `except` (and consistent behavior for `find`).

## Evidence
- Reference notes case-sensitive behavior: `docs/junos-cli-reference.md:1221` and `docs/junos-cli-reference.md:1238`.
- Current implementation lowercases both pattern and line: `pkg/cli/cli.go:616`, `pkg/cli/cli.go:623`, `pkg/cli/cli.go:630`.


---

## #19 — CLI: show security flow session summary uses non-Junos output schema [CLOSED] (closed 2026-03-01)

## Summary
`show security flow session summary` output does not follow the Junos summary schema in the reference.

## Repro
Run: `show security flow session summary`

## Actual
- Prints custom sections (`Session summary`, IPv4/IPv6/NAT, by protocol, by zone pair).
- Always appends `Total sessions: N` line.

## Expected
- Junos-style counters:
  - `Unicast-sessions`, `Multicast-sessions`, `Services-offload-sessions`, `Failed-sessions`, etc.
  - Indented sub-lines for valid/pending/invalidated/other.

## Evidence
- Reference schema: `docs/junos-cli-reference.md:125` through `docs/junos-cli-reference.md:145`.
- Current summary formatter: `pkg/cli/cli.go:3343` through `pkg/cli/cli.go:3370`.


---

## #20 — CLI: show security flow session format diverges from Junos reference [CLOSED] (closed 2026-03-01)

## Summary
`show security flow session` output format materially differs from Junos reference.

## Repro
Run: `show security flow session`

## Actual
- Header uses `Policy:`/`State:`/`Age:`/`Idle:` fields in custom format.
- Session ID printed from local counter (`count`) instead of dataplane session ID.
- Output uses separate `NAT:` lines and omits Junos-style `Out:` line format with `Conn Tag`, `If`, packet/byte fields on In/Out lines.

## Expected
- Match reference structure:
  - `Session ID: <id>, Policy name: <name>/<index>, HA State: <...>, Timeout: <...>, Session State: <...>`
  - `In:` and `Out:` lines with `Conn Tag`, interface, packet/byte counters, trailing comma.

## Evidence
- Reference format: `docs/junos-cli-reference.md:72` through `docs/junos-cli-reference.md:101`.
- Current formatter: `pkg/cli/cli.go:3203` through `pkg/cli/cli.go:3226` and `pkg/cli/cli.go:3313` through `pkg/cli/cli.go:3336`.


---

## #21 — CLI: show arp no-resolve syntax and output format do not match reference [CLOSED] (closed 2026-03-01)

## Summary
`show arp no-resolve` command/format diverges from reference: parser ignores `no-resolve`, and output schema is different.

## Repro
Run: `show arp no-resolve`

## Actual
- Top-level show handler always calls `showARP()` and does not parse/validate `no-resolve`.
- Output includes non-reference summary/state columns (`Total entries (...)`, per-interface counts, `State` column).

## Expected
- Accept/validate `no-resolve` syntax and emit Junos-style ARP table layout.

## Evidence
- Reference command + expected table: `docs/junos-cli-reference.md:1193`.
- `handleShow` ARP path ignores args: `pkg/cli/cli.go:1108`.
- Current ARP formatter behavior: `pkg/cli/cli.go:10044` through `pkg/cli/cli.go:10103`.


---

## #22 — CLI: show system processes summary is not implemented (raw ps output only) [CLOSED] (closed 2026-03-01)

## Summary
`show system processes summary` is documented, but CLI ignores `summary` and always executes raw `ps aux --sort=-rss` output.

## Repro
Run: `show system processes summary`

## Actual
- `handleShowSystem` routes any `processes` invocation directly to `showSystemProcesses()`.
- `showSystemProcesses()` shells out to `ps aux --sort=-rss`.

## Expected
- Parse `summary` and render Junos-like summary/top output (or return explicit syntax guidance if unsupported).

## Evidence
- Reference command and expected format: `docs/junos-cli-reference.md:870`.
- Dispatch ignores sub-args: `pkg/cli/cli.go:7024`.
- Implementation: `pkg/cli/cli.go:9992`.


---

## #23 — CLI: show security policies default output format does not match Junos reference [CLOSED] (closed 2026-03-01)

## Summary
`show security policies` output format diverges from Junos reference layout.

## Repro
Run: `show security policies`

## Actual
- Uses custom `Rule: ... (id: ...)` and `Match: src=%v dst=%v app=%v` lines.
- Does not emit Junos-style policy metadata line (`Policy: <name>, State: enabled, Index: ...`).

## Expected
- Emit Junos hierarchy with:
  - `From zone: X, To zone: Y`
  - 2-space `Policy:` metadata lines
  - 4-space field lines (`Source addresses`, `Destination addresses`, `Applications`, etc.)

## Evidence
- Reference format: `docs/junos-cli-reference.md:176` through `docs/junos-cli-reference.md:220`.
- Current formatter: `pkg/cli/cli.go:1263` through `pkg/cli/cli.go:1290`.


---

## #24 — CLI: show security log output format is not Junos RT_FLOW style [CLOSED] (closed 2026-03-01)

## Summary
`show security log` output is a custom event line format, not Junos SD-SYSLOG/RT_FLOW style described in the reference.

## Repro
Run: `show security log`

## Actual
- Emits internal event-buffer lines like `SESSION_CLOSE` / `SCREEN_DROP` with custom key ordering.
- Appends `(<n> events shown)` footer.

## Expected
- Structured Junos-like security log output (RT_FLOW style fields) for parity mode/reference compatibility.

## Evidence
- Reference expectation (RT_FLOW SD-SYSLOG example): `docs/junos-cli-reference.md:658` through `docs/junos-cli-reference.md:669`.
- Current formatter: `pkg/cli/cli.go:5814` through `pkg/cli/cli.go:5925`.


---

## #25 — CLI: show security zones output format diverges from Junos reference [CLOSED] (closed 2026-03-01)

## Summary
`show security zones` output format is custom and differs from the Junos reference block format.

## Repro
Run: `show security zones`

## Actual
- Zone header is `Zone: <name>`, optional `(id: N)`.
- Includes custom sections (`Traffic statistics`, `Policy summary`, global address-book list) not in reference output.
- Does not emit the expected `Security zone: <name>` field ordering.

## Expected
- Emit Junos-style zone blocks with canonical fields/order:
  - `Security zone: <name>`
  - `Zone ID`, `Send reset...`, `Policy configurable`, `Interfaces bound`, `Interfaces`, etc.

## Evidence
- Reference format: `docs/junos-cli-reference.md:336` through `docs/junos-cli-reference.md:383`.
- Current formatter: `pkg/cli/cli.go:1622` through `pkg/cli/cli.go:1681` (and additional custom sections through `pkg/cli/cli.go:1804`).


---

## #26 — CLI: show security policies hit-count column layout does not match reference [CLOSED] (closed 2026-03-01)

## Summary
`show security policies hit-count` table format differs from Junos reference columns.

## Repro
Run: `show security policies hit-count`

## Actual
- Table columns are `From zone`, `To zone`, `Policy`, `Action`, `Packets`, `Bytes`.
- Missing Junos `Index`, `Name`, `Policy count` layout and logical-system header.

## Expected
- Junos-style hit-count table with index and policy-count schema from reference.

## Evidence
- Reference table: `docs/junos-cli-reference.md:276` through `docs/junos-cli-reference.md:292`.
- Current formatter header and rows: `pkg/cli/cli.go:1415` and `pkg/cli/cli.go:1446`.


---

## #27 — CLI: show security policies detail output diverges from Junos reference schema [CLOSED] (closed 2026-03-01)

## Summary
`show security policies detail ...` output structure is not aligned with the Junos detail format in the reference.

## Repro
Run: `show security policies detail from-zone <z1> to-zone <z2>`

## Actual
- Starts with `Policy: <from> -> <to>, State: enabled` wrapper.
- Uses a custom nested `Match`/`Then` block format.
- Omits key Junos fields and ordering from the reference detail output.

## Expected
- Junos-style detail entries with header:
  - `Policy: <name>, action-type: ... , State: enabled, Index: ...`
  - Followed by canonical `Policy Type`, `Sequence number`, zone line, address/application blocks, etc.

## Evidence
- Reference detail format: `docs/junos-cli-reference.md:230` through `docs/junos-cli-reference.md:270`.
- Current formatter: `pkg/cli/cli.go:1490` through `pkg/cli/cli.go:1538`.


---

## #28 — CLI: show security alg status command/format parity gaps [CLOSED] (closed 2026-03-01)

## Summary
`show security alg status` parity gaps:
- Command tree/completion does not expose `status` subkeyword.
- Output format/content diverges from reference (`ALG Status:` header, capitalized Enabled/Disabled, fuller ALG list).

## Repro
Run:
- `show security alg status`
- `show security alg`

## Actual
- `alg` is treated as terminal command; extra `status` token is ignored.
- Output header is `ALG (Application Layer Gateway) status:`.
- Only a small subset of ALG names is shown, and values are lowercase `enabled/disabled`.

## Expected
- Support/document `show security alg status` explicitly and match reference table style.

## Evidence
- Reference command and format: `docs/junos-cli-reference.md:526` through `docs/junos-cli-reference.md:553`.
- Command tree lacks `status` child under `alg`: `pkg/cmdtree/tree.go:243`.
- Dispatcher routes `alg` directly: `pkg/cli/cli.go:1371`.
- Current formatter output: `pkg/cli/cli.go:8577` through `pkg/cli/cli.go:8599`.


---

## #29 — Routing: show route summary missing Junos Highwater Mark section [CLOSED] (closed 2026-03-01)

## Summary
`show route summary` omits the Junos-style Highwater Mark section documented in the reference.

## Repro
Run: `show route summary`

## Actual
- Formatter prints `Router ID` and per-table protocol counts only.
- No Highwater Mark block (RIB/FIB/VRF watermark lines).

## Expected
- Include Highwater Mark section (or clearly document intentional non-parity mode).

## Evidence
- Reference summary includes Highwater Mark block: `docs/junos-cli-reference.md:1121` through `docs/junos-cli-reference.md:1130`.
- Current summary formatter lacks this section: `pkg/routing/routing.go:854` through `pkg/routing/routing.go:872`.


---

## #30 — Compiler: policy expansion can overflow MaxRulesPerPolicy and spill into adjacent sets [CLOSED] (closed 2026-03-01)

## Summary
`compilePolicies` does not enforce `MaxRulesPerPolicy` (256) after application expansion, so large policy/app expansions can write rules past the policy-set boundary.

## Why this is a bug
- Rule storage is flattened as `idx = policySetID*MaxRulesPerPolicy + ruleIndex`.
- If `ruleIndex >= 256`, writes spill into the next policy-set slot range.
- The compiled `PolicySet.NumRules` still advertises the large count, but BPF evaluation loops only to `MAX_RULES_PER_POLICY` per set, creating inconsistent behavior.

## Evidence
- No cap before setting `NumRules` and writing rule indexes:
  - `pkg/dataplane/compiler.go:1450`
  - `pkg/dataplane/compiler.go:1504`
  - `pkg/dataplane/compiler.go:1572`
  - `pkg/dataplane/compiler.go:1621`
- Flattened index math:
  - `pkg/dataplane/maps.go:41`
- Max per-set constant:
  - `pkg/dataplane/types.go:331`
- BPF loop bound:
  - `bpf/xdp/xdp_policy.c:1190`

## Repro idea
1. Create a single zone-pair policy-set where one policy expands to >256 app terms (or many policies whose expanded total >256).
2. Commit config and inspect `policy_rules` map indexes.
3. Observe writes into indexes belonging to subsequent policy sets.

## Expected
Compiler should hard-fail when expanded rules exceed `MaxRulesPerPolicy` (or split deterministically with explicit semantics).


---

## #31 — Compiler: NAT rule counter IDs can exceed nat_rule_counters capacity [CLOSED] (closed 2026-03-01)

## Summary
NAT rule counter IDs are allocated monotonically with no bound check, but the `nat_rule_counters` map has a fixed max of 256 entries.

## Why this is a bug
- Compiler increments `result.nextNATCounterID` per SNAT rule (including expanded address pairs sharing same ID) without validating capacity.
- `CounterID` is stored in SNAT rule values and used as lookup key in BPF.
- Once counter IDs exceed map capacity, lookups fail and counters stop incrementing for those rules.

## Evidence
- Counter allocation with no cap:
  - `pkg/dataplane/compiler.go:1700`
  - `pkg/dataplane/compiler.go:2011`
- Map capacity constant:
  - `pkg/dataplane/types.go:415`
  - `bpf/headers/bpfrx_common.h:150`
- Runtime counter lookup by key:
  - `bpf/xdp/xdp_policy.c:1291`
  - `bpf/xdp/xdp_policy.c:1566`

## Expected
Compiler should fail once configured NAT rule counters exceed `MAX_NAT_RULE_COUNTERS` (or add deterministic reuse/indexing strategy).


---

## #32 — Compiler: NAT64 auto-assigned source pools ignore map-write failures and pool-capacity limits [CLOSED] (closed 2026-03-01)

## Summary
NAT64 auto-assigned source-pool path does not check map update errors and does not enforce NAT pool ID capacity before incrementing.

## Why this is a bug
When a NAT64 rule references a source pool that SNAT did not allocate, compiler auto-assigns a new pool ID and writes pool IP/config entries. In this path:
- `SetNATPoolIPV4`, `SetNATPoolIPV6`, and `SetNATPoolConfig` errors are ignored.
- `result.NextPoolID` is incremented with no explicit guard against `MAX_NAT_POOLS` (32).

This can yield a successful compile with partially missing pool programming.

## Evidence
- Auto-assign and increment without bound check:
  - `pkg/dataplane/compiler.go:2545`
  - `pkg/dataplane/compiler.go:2546`
- Ignored map write errors:
  - `pkg/dataplane/compiler.go:2575`
  - `pkg/dataplane/compiler.go:2578`
  - `pkg/dataplane/compiler.go:2584`
- Pool capacity in dataplane:
  - `bpf/headers/bpfrx_common.h:148`

## Expected
- Hard-fail when `NextPoolID` reaches pool capacity.
- Propagate all map update errors in the NAT64 auto-assignment path.


---

## #33 — Compiler: static NAT mixed IPv4/IPv6 rules are not rejected [CLOSED] (closed 2026-03-01)

## Summary
`compileStaticNAT` accepts mixed-family rules (IPv4<->IPv6) and routes them through the IPv6 path instead of rejecting them.

## Why this is a bug
Current branch condition is:
- IPv4 path only when **both** `extIP` and `intIP` are IPv4.
- Otherwise it falls into IPv6 path.

So a mixed rule like `match 203.0.113.10` + `then 2001:db8::10` is treated as IPv6 static NAT rather than a validation error.

## Evidence
- Family branch logic:
  - `pkg/dataplane/compiler.go:2317`
  - `pkg/dataplane/compiler.go:2329`

## Expected
Compiler should reject mixed-family static NAT rules explicitly (require v4->v4 or v6->v6).


---

## #34 — Compiler: DNAT CIDR inputs lose mask semantics (compiled as single IP) [CLOSED] (closed 2026-03-01)

## Summary
DNAT compiler accepts CIDR inputs but drops prefix semantics by converting them to a single host key.

## Why this is a bug
`rule.Match.DestinationAddress` and `pool.Address` are parsed with `net.ParseCIDR`, but only the IP part is used when building DNAT keys/values. Any configured mask/range semantics are ignored.

## Evidence
- CIDR parse result mask is discarded:
  - `pkg/dataplane/compiler.go:2112`
  - `pkg/dataplane/compiler.go:2124`
- DNAT key uses exact destination IP only:
  - `pkg/dataplane/compiler.go:2208`
  - `pkg/dataplane/compiler.go:2210`

## Impact example
`destination-address 203.0.113.0/24` compiles as exact match for only `203.0.113.0`, not the /24.

## Expected
Either:
- reject non-host CIDRs explicitly for DNAT entries, or
- implement proper prefix/range matching semantics.


---

## #35 — Compiler: port-mirroring interface lookup skips LinuxIfName normalization [CLOSED] (closed 2026-03-01)

## Summary
`compilePortMirroring` resolves interfaces using raw configured names and does not normalize Junos-style names to Linux names.

## Why this is a bug
Elsewhere in dataplane compilation, interface references are normalized via `config.LinuxIfName(...)`. Port mirroring uses `net.InterfaceByName(inst.Output)` / `net.InterfaceByName(inputIface)` directly, so names like `ge-0/0/0` are likely to fail lookup on Linux (`/` not valid in kernel ifname).

## Evidence
- Raw lookup without normalization:
  - `pkg/dataplane/compiler.go:3861`
  - `pkg/dataplane/compiler.go:3871`
- Existing normalization helper:
  - `pkg/config/types.go:8`

## Expected
Normalize configured interface names with `config.LinuxIfName` before `net.InterfaceByName` in port-mirroring compilation.


---

## #36 — Performance: policy evaluation scans rules linearly with per-rule map lookups [CLOSED] (closed 2026-03-01)

## Summary
XDP policy evaluation performs a linear scan over rules with a map lookup per rule on every new-flow packet.

## Why this hurts performance
On the hot path (`xdp_policy_prog`), every packet entering policy evaluation:
1. resolves policy-set,
2. iterates rules from `0..num_rules`,
3. does `bpf_map_lookup_elem(&policy_rules, &rule_idx)` per iteration,
4. runs address/protocol/port/app checks.

This is O(N rules) per packet for the selected zone pair, with map lookup overhead inside the loop.

## Evidence
- Rule loop and per-rule map lookup:
  - `bpf/xdp/xdp_policy.c:1186`
  - `bpf/xdp/xdp_policy.c:1190`
  - `bpf/xdp/xdp_policy.c:1195`
- Two-level design currently relies on flat array lookups per rule:
  - `bpf/headers/bpfrx_maps.h:133`

## Improvement ideas
- Add protocol/app buckets (compile-time index) to reduce candidate set before full match checks.
- Add fast-path cache for recent `(zone-pair, proto, dst-port, app-id)` -> rule-id decisions.
- Consider pre-materialized compact per-policy-set rule slices to minimize per-packet map lookups.


---

## #37 — Performance: replace hot-path zone_pair_policies hash lookup with array indexing [CLOSED] (closed 2026-03-01)

## Summary
`zone_pair_policies` is implemented as a hash map and looked up on every packet, even though zone IDs are bounded and indexable.

## Why this hurts performance
The policy entry lookup is on the hot path for every packet and currently performs hash lookups for:
- `(ingress_zone, egress_zone)`
- optional fallback `(0,0)`

Given bounded zone IDs (`MAX_ZONES`), this can be represented as array indexing to avoid hashing and pointer chasing.

## Evidence
- Hot-path lookups:
  - `bpf/xdp/xdp_policy.c:1104`
  - `bpf/xdp/xdp_policy.c:1108`
- Current map type is HASH:
  - `bpf/headers/bpfrx_maps.h:170`
- Key space is bounded by zones:
  - `bpf/headers/bpfrx_maps.h:171`

## Improvement ideas
- Replace `zone_pair_policies` with an ARRAY keyed by flattened index: `from_zone * MAX_ZONES + to_zone`.
- Reserve index `0` (or explicit sentinel) for global fallback semantics.


---

## #38 — Performance: SNAT compile repeats pool parse/map writes for every referencing rule [CLOSED] (closed 2026-03-01)

## Summary
SNAT compile path reparses and rewrites the same source NAT pool for every rule referencing that pool.

## Why this hurts performance
In pool mode, even when a pool ID already exists, compiler still:
- reparses all pool addresses,
- rebuilds pool config/deterministic fields,
- rewrites all pool IP slots and pool config map entries.

With many rules sharing a pool, compile cost scales with `rules * pool_size` instead of `pool_size + rules`.

## Evidence
- Existing-ID branch does not skip pool parse/write work:
  - `pkg/dataplane/compiler.go:1882`
  - `pkg/dataplane/compiler.go:1890`
- Pool IP/config writes executed per rule:
  - `pkg/dataplane/compiler.go:1951`
  - `pkg/dataplane/compiler.go:1959`
  - `pkg/dataplane/compiler.go:1967`

## Improvement ideas
- Cache compiled pool material by pool name/ID within a compile pass.
- Only write pool IP/config once per unique pool, then reference pool ID from rules.


---

## #39 — Performance: SNAT rule matching does linear hash-probing in XDP hot path [CLOSED] (closed 2026-03-01)

## Summary
Dynamic SNAT rule selection does linear probing over hash map entries per packet/new flow.

## Why this hurts performance
For both IPv4 and IPv6 permit paths, SNAT selection iterates `rule_idx` and does hash lookups against `snat_rules` / `snat_rules_v6` until match/break. This multiplies map lookup cost by number of SNAT rules per zone-pair.

## Evidence
- IPv4 SNAT iteration:
  - `bpf/xdp/xdp_policy.c:1272`
  - `bpf/xdp/xdp_policy.c:1275`
- IPv6 SNAT iteration:
  - `bpf/xdp/xdp_policy.c:1547`
  - `bpf/xdp/xdp_policy.c:1550`
- SNAT maps are HASH keyed by `(from_zone,to_zone,rule_idx)`:
  - `bpf/headers/bpfrx_maps.h:452`
  - `bpf/headers/bpfrx_maps.h:476`
  - `bpf/headers/bpfrx_maps.h:533`

## Improvement ideas
- Maintain per-zone-pair rule-count/offset and store rules in array-backed layout for O(1) sequential access without hash lookups.
- Add compile-time prefilter dimensions (e.g., src/dst addr-id buckets) to reduce candidate scans.


---

## #40 — Performance: compile interface setup relies on repeated ethtool subprocess calls [CLOSED] (closed 2026-03-01)

## Summary
Compile path shells out to `ethtool` per interface (`-k` check and potentially `-K` / `-s`), adding process-spawn overhead on every compile.

## Why this hurts performance
Compilation currently performs external command execution in interface loops. With many interfaces, commit/compile latency includes repeated process startup and text parsing costs.

## Evidence
- rxvlan state check invokes subprocess:
  - `pkg/dataplane/compiler.go:3822`
- per-interface rxvlan off command in compile loop:
  - `pkg/dataplane/compiler.go:587`
  - `pkg/dataplane/compiler.go:588`
- speed/duplex application also shells out:
  - `pkg/dataplane/compiler.go:3837`

## Improvement ideas
- Move ethtool state handling to netlink/ethtool API bindings (no subprocess).
- Cache known-offload/speed state per interface and only apply on actual config deltas.


---

## #41 — Performance: compiler does repeated interface/link lookups without per-pass caching [CLOSED] (closed 2026-03-01)

## Summary
Compiler repeatedly resolves the same interfaces/links/addresses with `net.InterfaceByName` and `netlink.LinkBy*` across multiple loops instead of caching per compile pass.

## Why this hurts performance
Large interface configs and multi-zone references cause repeated syscall-heavy lookups during a single compile:
- zone compilation
- SNAT interface-mode egress collection
- filter and mirroring assignment paths

## Evidence
- Repeated lookups in zone compile loop:
  - `pkg/dataplane/compiler.go:497`
  - `pkg/dataplane/compiler.go:598`
  - `pkg/dataplane/compiler.go:676`
- Additional repeated lookups in SNAT interface-mode path:
  - `pkg/dataplane/compiler.go:1778`
  - `pkg/dataplane/compiler.go:1815`
  - `pkg/dataplane/compiler.go:2886`

## Improvement ideas
- Build a compile-pass interface cache (name -> ifindex, link attrs, v4/v6 addresses).
- Reuse cached entries across zone/NAT/filter/mirroring compilation steps.


---

## #42 — Performance: application port-range expansion causes O(range) compile/map-write overhead [CLOSED] (closed 2026-03-01)

## Summary
Application compile path fully expands destination port ranges into per-port map entries, which can explode compile time and map writes for wide ranges.

## Why this hurts performance
`parsePorts("low-high")` allocates and returns every port in the range, then compiler writes one `SetApplication` entry per port (and per protocol variant).

Large ranges (e.g., `1-65535`) create massive compile-time work and memory churn.

## Evidence
- Port-range expansion to full slice:
  - `pkg/dataplane/compiler.go:3057`
  - `pkg/dataplane/compiler.go:3068`
- Per-port map writes:
  - `pkg/dataplane/compiler.go:1265`
  - `pkg/dataplane/compiler.go:1266`

## Improvement ideas
- Represent destination port ranges natively (low/high) in app tables/rules instead of enumerating each port.
- Add guardrails/warnings for very large port-range expansions until range-native path exists.


---

## #43 — Performance: firewall filter evaluation does linear per-rule map lookups in both XDP ingress and TC egress [CLOSED] (closed 2026-03-01)

## Summary
Firewall filter evaluation remains a linear term scan with per-term map lookups, and this logic runs in both ingress and egress datapaths.

## Why this hurts performance
For each filtered packet, the program iterates terms and does `bpf_map_lookup_elem(&filter_rules, &idx)` for each candidate. This affects:
- XDP ingress (`evaluate_firewall_filter`),
- TC egress (`evaluate_firewall_filter_output`),
- host-bound lo0 filter path (`evaluate_filter_by_id`).

## Evidence
- Input filter loop:
  - `bpf/headers/bpfrx_helpers.h:1113`
  - `bpf/headers/bpfrx_helpers.h:1122`
- Output filter loop:
  - `bpf/headers/bpfrx_helpers.h:1327`
  - `bpf/headers/bpfrx_helpers.h:1336`
- lo0-by-id loop:
  - `bpf/headers/bpfrx_helpers.h:1507`
  - `bpf/headers/bpfrx_helpers.h:1516`
- Called from hot stages:
  - `bpf/xdp/xdp_main.c:133`
  - `bpf/xdp/xdp_cpumap.c:80`
  - `bpf/tc/tc_forward.c:22`

## Improvement ideas
- Precompile filter terms into protocol/port buckets to reduce candidates.
- Add a small fast-path decision cache keyed by `(ifindex,family,proto,ports,dscp)` for repeated traffic patterns.
- Consider compact contiguous per-filter slices to reduce per-term map lookup overhead.


---

## #44 — Performance: avoid duplicate iface_zone_map lookup across xdp_screen -> xdp_zone pipeline [CLOSED] (closed 2026-03-01)

## Summary
Ingress zone lookup is performed in `xdp_screen` and then repeated again in `xdp_zone` for the same packet.

## Why this hurts performance
Every packet that traverses the normal pipeline pays at least two hash lookups against `iface_zone_map` before policy/conntrack work starts.

## Evidence
- First lookup in screen stage:
  - `bpf/xdp/xdp_screen.c:655`
  - `bpf/xdp/xdp_screen.c:660`
  - `bpf/xdp/xdp_screen.c:665`
- Second lookup in zone stage:
  - `bpf/xdp/xdp_zone.c:440`
  - `bpf/xdp/xdp_zone.c:445`
  - `bpf/xdp/xdp_zone.c:451`
- Map type is HASH:
  - `bpf/headers/bpfrx_maps.h:105`

## Improvement ideas
- Carry resolved ingress zone/iface metadata from screen to zone in `pkt_meta` (or a compact cached struct) and skip the second lookup on the common path.
- Keep fallback lookup only for special cases (e.g., zone-encoded fabric source MAC handling).


---

## #45 — Performance: remove unnecessary atomic RMW on per-CPU global counters in XDP/TC hot paths [CLOSED] (closed 2026-03-01)

## Summary
`inc_counter()` uses `__sync_fetch_and_add` on `global_counters`, which is a `BPF_MAP_TYPE_PERCPU_ARRAY`.

## Why this hurts performance
Per-CPU map slots are CPU-local. Using atomic RMW on every counter increment adds unnecessary instruction cost on nearly every packet path (RX/TX drops, host-inbound, NAT64, screen events, etc.).

## Evidence
- Atomic increment helper:
  - `bpf/headers/bpfrx_helpers.h:679`
  - `bpf/headers/bpfrx_helpers.h:683`
- Backing map is per-CPU:
  - `bpf/headers/bpfrx_maps.h:283`
- Widely used on hot paths:
  - `bpf/xdp/xdp_main.c:176`
  - `bpf/xdp/xdp_forward.c:226`
  - `bpf/tc/tc_main.c:71`

## Improvement ideas
- Replace atomic increments on per-CPU counters with direct increments (`(*ctr)++`) in helper(s).
- Keep atomics only where values are shared across CPUs (e.g., non-percpu hash entries).


---

## #46 — Performance: xdp_zone failover branches perform repeated FIB lookups and duplicate post-FIB work [CLOSED] (closed 2026-03-01)

## Summary
`xdp_zone` can execute multiple expensive `bpf_fib_lookup` calls for the same packet in fabric-forward/failover branches, with duplicated post-FIB resolution logic.

## Why this hurts performance
On some failover paths, a packet may do:
1. initial FIB lookup,
2. secondary main-table relookup for `META_FLAG_FABRIC_FWD`,
3. tertiary main-table relookup in unreachable/blackhole branch,
while repeatedly resolving VLAN parent and egress zone.

This adds extra helper cost on already expensive error/failover paths.

## Evidence
- Initial FIB lookup:
  - `bpf/xdp/xdp_zone.c:811`
- Secondary lookup path:
  - `bpf/xdp/xdp_zone.c:1001`
- Tertiary lookup path:
  - `bpf/xdp/xdp_zone.c:1214`
- Duplicated post-FIB VLAN/zone resolution blocks:
  - `bpf/xdp/xdp_zone.c:815`
  - `bpf/xdp/xdp_zone.c:1004`
  - `bpf/xdp/xdp_zone.c:1219`

## Improvement ideas
- Factor a shared helper for “FIB success -> resolve VLAN parent + zone + meta update”.
- Consolidate fabric-forward relookup decisions so at most one fallback relookup is attempted per packet.
- Cache `fabric_fwd` info once per packet and reuse across branches.


---

## #47 — Performance: tc_forward mirror sampling uses expensive modulo + atomic per packet [CLOSED] (closed 2026-03-01)

## Summary
TC port mirroring sampling uses modulo on a per-packet counter and atomic increment in the forwarding hot path.

## Why this hurts performance
When mirroring is enabled with `rate > 1`, every packet hits:
- map lookup for `mirror_counter`,
- `__sync_fetch_and_add` on per-CPU counter,
- `% rate` division check.

Integer division/modulo is relatively expensive in BPF JITed code, and atomic RMW is unnecessary for per-CPU counters.

## Evidence
- Sampling path and modulo:
  - `bpf/tc/tc_forward.c:83`
  - `bpf/tc/tc_forward.c:90`
- Atomic increment on per-CPU counter:
  - `bpf/tc/tc_forward.c:89`
- `mirror_counter` is per-CPU array:
  - `bpf/headers/bpfrx_maps.h:759`

## Improvement ideas
- Replace atomic increment with direct increment for per-CPU counter.
- For sampling, prefer cheaper approaches (`bpf_get_prandom_u32` threshold, or bitmask for power-of-two rates).
- Cache mirror settings in meta earlier if possible to avoid extra map access in TC forward.


---

## #48 — Performance: reduce repeated flow_config_map lookups in XDP/TC conntrack paths [CLOSED] (closed 2026-03-01)

## Summary
`flow_config_map` (single-entry array) is looked up repeatedly in conntrack/state-update paths instead of once per packet/context.

## Why this hurts performance
Several hot functions perform multiple lookups to the same `flow_config_map[0]` for RST handling, MSS clamp, and embedded ICMP checks. These are avoidable map lookups on frequent traffic.

## Evidence
- Repeated lookups in XDP conntrack hit handlers:
  - `bpf/xdp/xdp_conntrack.c:73`
  - `bpf/xdp/xdp_conntrack.c:105`
  - `bpf/xdp/xdp_conntrack.c:207`
  - `bpf/xdp/xdp_conntrack.c:234`
- Repeated lookups in zone fast-path CT update:
  - `bpf/xdp/xdp_zone.c:58`
  - `bpf/xdp/xdp_zone.c:160`
- Additional lookups in TC conntrack path:
  - `bpf/tc/tc_conntrack.c:112`
  - `bpf/tc/tc_conntrack.c:187`

## Improvement ideas
- Lookup `flow_config_map[0]` once in stage entry and pass pointer/derived flags into helper paths.
- Cache frequently used booleans from flow config in `pkt_meta` when entering pipeline.


---

## #49 — Performance: NAT64 paths do heavy full-payload checksum scans [CLOSED] (closed 2026-03-01)

## Summary
NAT64 translation paths perform full L4 checksum scans with long bounded loops (up to 750 words) on packet hot paths.

## Why this hurts performance
For NAT64 traffic, checksum handling can require scanning much of the payload:
- Forward 6->4 TCP/UDP checksum recompute loops,
- Reverse 4->6 finalization for CHECKSUM_PARTIAL before translation.

These loops are significantly heavier than incremental delta updates and can dominate NAT64 packet cost.

## Evidence
- 6->4 TCP checksum loop:
  - `bpf/xdp/xdp_nat64.c:293`
- 6->4 UDP checksum loop:
  - `bpf/xdp/xdp_nat64.c:329`
- 4->6 path calls CHECKSUM_PARTIAL finalization:
  - `bpf/xdp/xdp_nat64.c:522`
- Finalization helper loop (up to 750 iterations):
  - `bpf/headers/bpfrx_helpers.h:372`

## Improvement ideas
- Prefer incremental checksum transformations where feasible instead of full payload summation.
- Gate full recompute paths more aggressively (only when truly required).
- Evaluate whether additional metadata can skip redundant checksum work across NAT64 subpaths.


---

## #50 — Performance: evaluate DEVMAP array instead of DEVMAP_HASH for XDP redirect hot path [CLOSED] (closed 2026-03-01)

## Summary
XDP forwarding redirects through `tx_ports` implemented as `BPF_MAP_TYPE_DEVMAP_HASH`, even though interface fanout is bounded and the path is latency-sensitive.

## Why this hurts performance
`bpf_redirect_map(&tx_ports, ...)` runs on every fast-path forwarded packet. Hash-backed devmap lookups add hashing/pointer-chasing overhead compared to array-backed devmap indexing.

## Evidence
- Redirect hot path:
  - `bpf/xdp/xdp_forward.c:264`
- Current map type:
  - `bpf/headers/bpfrx_maps.h:307`
- Interface cardinality appears bounded:
  - `bpf/headers/bpfrx_common.h:143`

## Improvement ideas
- Evaluate replacing `BPF_MAP_TYPE_DEVMAP_HASH` with `BPF_MAP_TYPE_DEVMAP` using compact compiler-assigned port indices.
- Keep an indirection map from ifindex->port-slot if sparse host ifindex values must be supported.


---

## #56 — Failover: IPv4 pre-fabric DNAT rewrite is not CHECKSUM_PARTIAL-safe [CLOSED] (closed 2026-03-01)

## Summary
`apply_dnat_before_fabric_redirect()` in `xdp_zone.c` updates IPv4 L4 checksums with `csum_update_2/4` unconditionally, while the normal NAT path is `CHECKSUM_PARTIAL`-aware.

This creates a failover-specific checksum inconsistency: packets redirected over fabric before `xdp_nat` can carry incorrect TCP/UDP checksums under generic XDP / partial checksum contexts, leading to random connection drops or handshake failures.

## Code References
- IPv4 pre-fabric rewrite uses unconditional checksum updates:
  - `bpf/xdp/xdp_zone.c:335-349`
  - `bpf/xdp/xdp_zone.c:356-371`
- IPv6 path explicitly guards incremental L4 updates on `!meta->csum_partial`:
  - `bpf/xdp/xdp_zone.c:272-299`
- Main NAT rewrite path is checksum-partial-aware for IPv4:
  - `bpf/headers/bpfrx_nat.h:142-190`

## Why this is risky during failover
During active/active transitions, `apply_dnat_before_fabric_redirect()` is hit in fast redirect branches before `xdp_nat`. If checksum handling diverges from the regular NAT path, some flows can fail only during RG movement, matching the observed “random” failover-time drops.

## Proposed fix
- Make IPv4 pre-fabric rewrite mirror `nat_rewrite_v4()` semantics:
  - Skip L4 incremental port checksum updates when `meta->csum_partial`.
  - Use partial checksum update helpers for pseudo-header address changes where applicable.
- Add regression coverage for DNAT + fabric redirect with `CHECKSUM_PARTIAL` packets.

## Acceptance criteria
- No checksum regressions in DNAT traffic across failover/failback.
- Existing normal NAT path behavior unchanged.


---

## #57 — HA fabric: fib_ifindex selection can remain 0 and break main-table re-FIB [CLOSED] (closed 2026-03-01)

## Summary
`refreshFabricFwd()` picks `fabric_fwd_info.fib_ifindex` via a heuristic (first UP, non-VRF, non-veth, non-slave link). If no candidate matches, `fib_ifindex` remains `0`.

When `fib_ifindex==0`, BPF re-FIB paths fall back to the fabric ingress ifindex (VRF member), which is exactly the l3mdev/TBID mismatch path that can route transit traffic through the wrong table during failover.

## Code References
- Heuristic selection and potential `fib_ifindex=0`:
  - `pkg/daemon/daemon.go:3641-3657`
  - logged in `pkg/daemon/daemon.go:3668-3671`
- BPF fallback to ingress if `fib_ifindex` absent:
  - `bpf/xdp/xdp_zone.c:999-1001`
  - `bpf/xdp/xdp_zone.c:1170-1175`

## Why this matters
This reintroduces intermittent wrong-table lookups in exactly the active/active fabric transit path, producing hard-to-reproduce failover drops.

## Proposed fix
- Fail closed when `fib_ifindex` cannot be resolved (warn loudly + avoid partial programming), OR
- Add deterministic selection of a known data-plane ifindex from active RG interfaces, not opportunistic `LinkList()` order.
- Re-resolve aggressively on link/routing changes until non-zero.

## Acceptance criteria
- `fabric_fwd.fib_ifindex` is always valid in cluster active/active mode.
- No re-FIB path uses fabric VRF ingress as TBID lookup anchor for main-table transit decisions.


---

## #58 — DPDK parity gap: zone-encoded fabric redirect decode is still TODO [CLOSED] (closed 2026-03-01)

## Summary
`dpdk_worker/zone.c` detects the zone-encoded MAC prefix used by eBPF active/active new-connection forwarding, but does not actually decode/apply it yet (explicit TODO).

This leaves DPDK without parity for the active/active “new connection through split RG” fix path.

## Code References
- Placeholder block:
  - `dpdk_worker/zone.c:42-60`

## Impact
In DPDK mode, new connections during RG split/failover can still fail even though eBPF path is fixed.

## Proposed fix
- Implement the TODO:
  - Decode ingress zone from MAC byte 5.
  - Set `meta->ingress_zone` and `meta->routing_table=254`.
  - Bypass normal zone lookup for zone-encoded packets.
- Add active/active split tests in DPDK path matching eBPF coverage.

## Acceptance criteria
- DPDK active/active behavior matches eBPF for new connection establishment during RG split/failover.


---

## #59 — HA fabric: peer MAC resolution is IPv4-only (no NDP path) [CLOSED] (closed 2026-03-01)

## Summary
`refreshFabricFwd()` resolves the fabric peer MAC only via `NeighList(..., FAMILY_V4)` and logs ARP-specific wait messages.

If the fabric peer is configured with IPv6 (or NDP-only reachability), `fabric_fwd` cannot be populated/refreshed reliably, causing cross-chassis redirect failures during RG transitions.

## Code References
- IPv4-only neighbor query:
  - `pkg/daemon/daemon.go:3613-3615`
- ARP-specific wait log:
  - `pkg/daemon/daemon.go:3628-3630`

## Impact
When `fabric_fwd` isn’t updated, active/active failover paths that depend on fabric redirect can intermittently drop packets/new connections until another mechanism recovers.

## Proposed fix
- Resolve neighbor MAC based on peer address family:
  - Use `FAMILY_V4` for IPv4 peers.
  - Use `FAMILY_V6` for IPv6 peers.
- Update logs to avoid ARP-only wording.
- Add test coverage for IPv6 fabric peer addresses.

## Acceptance criteria
- `fabric_fwd` updates correctly for both IPv4 and IPv6 fabric peers.
- No regression for existing IPv4 deployments.


---

## #60 — Failover: sessionless FABRIC_FWD re-FIB failure falls through to XDP_PASS (kernel leak path) [CLOSED] (closed 2026-03-01)

## Summary
In `xdp_zone` FABRIC_FWD sessionless handling, when main-table re-FIB fails (`rc2 != SUCCESS`), code falls through to `XDP_PASS` and increments host-inbound counters.

This can leak transit packets into the kernel path during active/active transitions, where they may be dropped or mis-handled (including unexpected TCP behavior) instead of being explicitly dropped or retried via controlled fabric logic.

## Code References
- Sessionless FABRIC_FWD re-FIB:
  - `bpf/xdp/xdp_zone.c:993-1019`
- Failure fallback to kernel pass:
  - `bpf/xdp/xdp_zone.c:1020-1029`

## Why this is risky
During RG movement windows, transient route state is expected. Punting unresolved fabric-transit packets to kernel broadens behavior surface and can manifest as random connection loss.

## Proposed fix
- For `META_FLAG_FABRIC_FWD` transit packets, prefer explicit `XDP_DROP` (with counter) on re-FIB failure instead of `XDP_PASS`.
- Keep `XDP_PASS` only for clearly host-local/control-plane traffic paths.
- Add dedicated counters to distinguish controlled failover drops from host-inbound traffic.

## Acceptance criteria
- No FABRIC_FWD transit packet takes ambiguous kernel fallback on failed re-FIB.
- Failover behavior is deterministic and observable via dedicated counters.


---

## #61 — xdp_zone: sessionless FABRIC_FWD NO_NEIGH path falls through to XDP_PASS/host-inbound [CLOSED] (closed 2026-03-01)

## Summary
In `xdp_zone`, sessionless packets that arrived via plain fabric redirect (`META_FLAG_FABRIC_FWD`) can still leak into the host path when `bpf_fib_lookup()` returns `BPF_FIB_LKUP_RET_NO_NEIGH`.

## Code Path
- `bpf/xdp/xdp_zone.c:1019-1092`
- `NO_NEIGH` branch:
  - `nn_has_session == 0`
  - `try_fabric_redirect_with_zone()` and `try_fabric_redirect()` both return `-1` on anti-loop for fabric ingress
  - `sv4/sv6 == NULL`, so session-specific guard drops do not run
  - falls through to host-inbound accounting + `XDP_PASS`

## Why this is a problem
For `FABRIC_FWD` transit traffic, this path should not be treated as host-bound local delivery. Passing to kernel can cause the same class of failover damage the recent `FABRIC_FWD_DROP` fix was intended to prevent (RSTs/unpredictable local stack behavior instead of deterministic transit handling).

## Expected behavior
When `META_FLAG_FABRIC_FWD` is set and the `NO_NEIGH` recovery paths fail for a sessionless packet, do **not** fall through to host-inbound `XDP_PASS`. Drop cleanly (and count separately), or use a dedicated transit retry path.


---

## #62 — xdp_zone: UNREACHABLE/BLACKHOLE FABRIC_FWD branch still leaks to host path when main-table re-FIB misses [CLOSED] (closed 2026-03-01)

## Summary
`xdp_zone` now drops sessionless `FABRIC_FWD` packets on re-FIB failure in the `SUCCESS` path, but the analogous `UNREACHABLE/BLACKHOLE/PROHIBIT` branch still falls through to host-path handling when re-FIB in table 254 fails.

## Code Path
- `bpf/xdp/xdp_zone.c:1109-1168`
  - For `rc in {UNREACHABLE, BLACKHOLE, PROHIBIT}` and `!bh_has_session`
  - On `META_FLAG_FABRIC_FWD`, performs second lookup via `setup_main_table_fib()`
  - If `rc3 != SUCCESS`, there is no explicit drop/return
- Fallthrough continues to host-path tail (`bpf/xdp/xdp_zone.c:1270-1274`) and `XDP_PASS`

## Why this is a problem
This is the same leak class fixed in the `SUCCESS`/sessionless `FABRIC_FWD` path: transit packets can still enter local kernel handling during failover windows, causing non-deterministic drops/RST behavior.

## Expected behavior
Mirror the hardened behavior used at `bpf/xdp/xdp_zone.c:1000-1016`:
- If `META_FLAG_FABRIC_FWD` re-FIB in table 254 fails, increment a dedicated drop counter and return `XDP_DROP`.
- Avoid host-inbound `XDP_PASS` fallthrough for transit `FABRIC_FWD` packets.


---

## #63 — cluster refreshFabricFwd: fallback fib_ifindex selection is non-deterministic and may pick wrong routing context [CLOSED] (closed 2026-03-01)

## Summary
When the fabric interface is a VRF member, `refreshFabricFwd()` falls back to the first UP non-VRF/non-veth/non-slave link from `netlink.LinkList()`. This can pick an arbitrary interface (e.g., management/overlay), not a deterministic dataplane context for main-table re-FIB.

## Code Path
- `pkg/daemon/daemon.go:3648-3673`
  - If `link.Attrs().MasterIndex != 0`, set `info.FIBIfindex = 0`
  - Iterate all links and pick the first candidate

## Why this is a problem
`FIBIfindex` is used to avoid l3mdev/VRF mismatch in `BPF_FIB_LOOKUP_TBID` main-table re-lookups for fabric transit. Using an arbitrary interface can still trigger wrong policy-routing context and route misses during failover transitions.

Symptoms can present as intermittent/random connection drops when active RG ownership changes.

## Expected behavior
Choose `fib_ifindex` deterministically from dataplane configuration (or the interface tied to table 254 routing intent), not from first-link iteration order. If no valid dataplane ifindex is available, fail loudly with actionable diagnostics.


---

## #64 — DPDK zone-encoded fabric decode returns too early and lacks fabric-ingress validation [CLOSED] (closed 2026-03-01)

## Summary
The DPDK zone-encoded MAC detection path exits `zone_lookup()` immediately after setting `ingress_zone` and `routing_table`, and it does not verify that the packet actually arrived on the fabric interface.

## Code Path
- `dpdk_worker/zone.c:42-57`
  - Detects `02:bf:72:fe:00:ZZ`
  - Sets `meta->ingress_zone` and `meta->routing_table = 254`
  - `return;`

## Problems
1. Early return skips the rest of `zone_lookup()`:
   - pre-routing DNAT handling
   - host-bound exception checks
   - FIB lookup
   - egress zone resolution
2. No ingress-if validation:
   - Any ingress packet with crafted source MAC prefix can force zone decode behavior.

## Expected behavior
Match XDP semantics:
- Only treat zone-encoded MAC as valid on fabric ingress.
- Set decoded zone/routing table, then continue normal pipeline/FIB resolution instead of returning early.


---

## #65 — DPDK active/active: zone-encoded fabric validation compares port_id against kernel ifindex [CLOSED] (closed 2026-03-01)

## Summary
The new DPDK zone-encoded fabric validation can fail to match real fabric packets because it compares different interface identity spaces:

- dataplane ingress value: DPDK `port_id`
- control-plane populated value: Linux kernel `ifindex`

This can prevent zone-decoded new-connection handling from triggering in DPDK active/active failover paths.

## Evidence
- `dpdk_worker/parse.c:199`
  - `meta->ingress_ifindex = pkt->port;` (DPDK port id)
- `pkg/dataplane/dpdk/dpdk_cgo.go:1169`
  - `shm.fabric_ifindex = info.Ifindex` (Linux ifindex from netlink)
- `dpdk_worker/zone.c:60-62`
  - validation requires `meta->ingress_ifindex == ctx->shm->fabric_ifindex`

Given the above, validation can be false even on real fabric ingress.

## Why this matters
When this check fails, zone-encoded packets are treated as normal ingress and do not follow the intended active/active new-connection behavior. That can reintroduce policy-zone mismatch or failover drops in DPDK mode.

## Suggested fix
Store and compare in one identity domain:
- either populate `fabric_ifindex` as DPDK `port_id`, or
- introduce/use an explicit ifindex↔port mapping in shared memory and normalize before comparison.

Also add a test that injects a zone-encoded packet on fabric and verifies the decode path is hit.


---

## #66 — HA failover race: cluster/VRRP handlers apply rg_active side effects from stale transitions [CLOSED] (closed 2026-03-01)

## Summary
`watchClusterEvents` and `watchVRRPEvents` both call into `rgStateMachine`, but they apply `rg_active` and blackhole side effects outside the state-machine lock, and transition epochs are not checked before applying. This allows stale transition results to be committed after newer state was already computed by the other goroutine.

## Evidence
- Two independent goroutines perform state-machine updates + side effects:
  - `pkg/daemon/daemon.go:3778-3812` (`watchClusterEvents`)
  - `pkg/daemon/daemon.go:3898-3934` (`watchVRRPEvents`)
- State machine has an epoch meant for stale-update detection:
  - comment: `pkg/daemon/rg_state.go:21-22`
  - transition carries epoch: `pkg/daemon/rg_state.go:144`
- But handlers do not validate epoch/current state before applying side effects.

## Why this matters
During failover/failback bursts, cluster and VRRP events can interleave. A stale handler can:
- write outdated `rg_active`
- inject/remove blackhole routes for an older state

This can produce transient mismatches (`rg_active` vs routing state), which matches observed "random" connection drops during role movement.

## Suggested fix
Serialize side-effect application per RG or gate applies by epoch:
- after `SetCluster`/`SetVRRP`, re-check current epoch (and desired active) before calling `UpdateRGActive`, `injectBlackholeRoutes`, `removeBlackholeRoutes`.
- alternatively, enqueue transitions to a single per-RG worker that performs side effects in order.

Add a concurrency test that injects interleaved cluster+VRRP transitions and asserts final `rg_active`/blackhole state is consistent without relying on periodic reconcile.


---

## #68 — HA mode: disable hitless restart semantics by default [CLOSED] (closed 2026-03-02)

## Problem
In HA (`chassis cluster`) mode, the daemon currently preserves dataplane state for hitless restart. That behavior is useful for standalone upgrades, but in HA it can keep forwarding active on a node whose control plane is down/hung, which increases split-brain risk during failover.

### Current behavior in code
- `pkg/daemon/daemon.go` keeps state intentionally on shutdown:
  - comments and behavior at `pkg/daemon/daemon.go:799-809` preserve routes/addresses/BPF and call `d.dp.Close()` (non-destructive).
- `pkg/dataplane/loader.go` `Close()` explicitly leaves pinned maps/links active:
  - `pkg/dataplane/loader.go:340-355`.

In HA mode, this means a failed/ wedged node can keep stale forwarding posture until external recovery happens.

## Proposal
When HA mode is enabled (`cfg.Chassis.Cluster != nil`):
1. Disable hitless-restart semantics by default.
2. On daemon shutdown/failure path, perform fail-closed teardown for dataplane ownership state (at least clear `rg_active`, and preferably full `Teardown()` if safe).
3. Keep current hitless behavior for non-HA standalone mode.
4. Add a config flag to explicitly opt back into hitless behavior in HA only if an operator really wants it.

## Why
In HA, correctness and deterministic failover are more important than preserving local forwarding through daemon restarts.

## Acceptance criteria
- In HA mode, stopping or crashing `bpfrxd` on a node does **not** leave it forwarding traffic as active owner.
- Peer failover converges without prolonged dual-active forwarding.
- Standalone mode still supports hitless restart behavior.
- Regression test covers HA daemon-stop/crash path and validates no stale forwarding from the stopped node.


---

## #69 — SessionSync: stale receive goroutine can tear down the active peer connection [CLOSED] (closed 2026-03-02)

## Problem
`SessionSync` can drop a healthy, newly-established sync connection when an older receive goroutine exits.

## Code path
- `acceptLoop()` and `connectLoop()` both replace `s.conn` and start a new `receiveLoop`:
  - `pkg/cluster/sync.go:500-527`
  - `pkg/cluster/sync.go:559-583`
- `receiveLoop()` always defers `handleDisconnect()`:
  - `pkg/cluster/sync.go:607-610`
- `handleDisconnect()` unconditionally closes `s.conn` (the current shared pointer), not the specific connection that failed:
  - `pkg/cluster/sync.go:878-887`

If conn A is replaced by conn B, when conn A's goroutine exits it calls `handleDisconnect()` and closes conn B.

## Impact
- Sync connection flaps under simultaneous inbound/outbound connect races.
- Session/config sync interruptions during failover windows.
- Increased chance of missing state during role transition.

## Proposal
Make disconnect handling connection-specific:
1. Pass the current `conn` into `handleDisconnect(conn)`.
2. Under lock, only clear/close if `s.conn == conn`.
3. Ignore stale receive-loop exits for already-replaced connections.

## Acceptance criteria
- Replacing an old connection with a new one does not cause the new one to be closed by stale goroutines.
- No self-induced disconnect oscillation when both nodes connect around the same time.
- HA failover tests with forced reconnect churn keep `SessionSync` connected.


---

## #70 — SessionSync: BulkSync should honor per-RG ownership (same as sweep) [CLOSED] (closed 2026-03-02)

## Problem
`BulkSync()` ignores RG ownership filtering and sends all sessions, while incremental sweep correctly filters by `ShouldSyncZone()`.

## Code path
- Incremental sweep filters by zone->RG ownership:
  - `pkg/cluster/sync.go:291-307` (`ShouldSyncZone(...)`)
- `BulkSync()` iterates and sends all v4/v6 sessions with no ownership check:
  - `pkg/cluster/sync.go:431-485`

In active/active HA, a node can send sessions for RGs where it is not currently primary.

## Impact
- Non-authoritative/stale sessions can be reinstalled on the peer during reconnect.
- Session state can drift after failover/failback when a returning node bulk-syncs old entries.
- Can delay clean recovery of new connections by reviving dead tuples.

## Proposal
Align `BulkSync()` with sweep semantics:
1. Send only forward entries (`IsReverse == 0`).
2. Apply `ShouldSyncZone(val.IngressZone)` filtering in bulk path.
3. In active/active, each node only bulk-syncs sessions for RGs it currently owns.

## Acceptance criteria
- During reconnect, a secondary does not push sessions for RGs it does not own.
- Bulk sync payload matches ownership policy used by incremental sync.
- Failover/failback does not resurrect stale sessions from the non-owner.


---

## #71 — SessionSync: Bulk transfer needs authoritative stale-entry reconciliation [CLOSED] (closed 2026-03-02)

## Problem
Session bulk sync is additive only; it does not reconcile stale entries that should be removed after disconnect/reconnect.

## Code path
- `BulkSync()` sends current sessions but no "authoritative snapshot" generation marker beyond start/end framing:
  - `pkg/cluster/sync.go:431-485`
- Receiver handles `syncMsgBulkStart/syncMsgBulkEnd` as timing markers only:
  - `pkg/cluster/sync.go:828-840`
- Received session timestamps are rebased to local "now":
  - `pkg/cluster/sync.go:675-677`, `733-737`

If delete messages were missed while disconnected, stale sessions can persist and get refreshed by later bulk sync traffic.

## Impact
- Dead sessions can survive reconnect much longer than intended.
- Tuple conflicts can block or delay new connection establishment after failover.
- Recovery may appear "stuck" even after control-plane reconverges.

## Proposal
Make bulk sync authoritative per sync epoch:
1. Add bulk generation/epoch ID.
2. Mark received entries with generation.
3. On bulk end, remove local synced entries not seen in the current generation (or clear+reinstall safely).
4. Scope cleanup by ownership/RG to avoid deleting local-authoritative entries.

## Acceptance criteria
- After reconnect bulk sync, peer session table matches sender snapshot for synced ownership scope.
- Sessions deleted while disconnected do not linger indefinitely.
- Post-failover new flows are not blocked by stale replicated tuples.


---

## #72 — HA failover: add peer fencing path on heartbeat timeout [CLOSED] (closed 2026-03-02)

## Problem
On heartbeat timeout, HA election promotes the local node but does not fence/quarantine the peer. If the peer is control-plane dead but dataplane still forwarding, split-brain forwarding can persist.

## Code path
- Heartbeat timeout marks peer lost and re-elects locally:
  - `pkg/cluster/cluster.go:761-791`
- No peer fencing action is invoked in this path (power off, interface quarantine, explicit dataplane disable on peer).

## Impact
- Dual-active forwarding risk in crash/hang scenarios.
- Hard-to-recover flow damage during failover (duplicates/RST/cwnd collapse).
- HA correctness depends on peer fully dying, which is not always true for partial failures.

## Proposal
Add optional peer fencing flow for HA mode:
1. Fencing hook triggered on peer heartbeat timeout (configurable action/backend).
2. Track fencing state in cluster events/history.
3. Optionally gate full active ownership until fence acknowledged (policy-dependent).
4. Expose operational status via CLI/API (`show chassis cluster ...`).

## Acceptance criteria
- Heartbeat timeout can trigger deterministic fencing workflow.
- In simulated hung-peer tests, local takeover does not leave prolonged dual-active forwarding.
- Operators can observe fence attempts/results in runtime status.


---

## #73 — HA tests: add hard-crash/hung-node failover coverage [CLOSED] (closed 2026-03-02)

## Problem
Current HA failover tests exercise clean-ish reboot/manual transitions but not hard crash or hung-kernel scenarios that can leave forwarding ambiguous.

## Code path / test gap
- `test/incus/test-failover.sh` uses `reboot` to trigger failover:
  - `test/incus/test-failover.sh:141-143`
- No coverage for:
  - kernel panic / forced stop behavior
  - daemon wedged or stopped while dataplane remains attached
  - post-crash recovery of both existing and new TCP flows

## Impact
- Regressions in real crash behavior can pass CI.
- Reported "iperf never recovers" scenarios are hard to reproduce deterministically.

## Proposal
Add HA chaos failover tests:
1. Hard-stop/panic scenario (e.g., forced VM stop or sysrq panic in test env).
2. Daemon-stop scenario in HA mode (with and without hitless semantics).
3. Assertions for:
   - takeover latency
   - existing stream survival/recovery behavior
   - new connection establishment during/after takeover
4. Include multi-cycle runs (not only single transition).

## Acceptance criteria
- CI test reproduces crash-like failover conditions deterministically.
- Test reports explicit recovery SLOs (time-to-first-successful-new-connection, sustained throughput recovery).
- HA regressions in crash path fail fast in test suite.


---

## #74 — Investigation: transient 10-30s loss to 172.16.100.247 after deploy restart [CLOSED] (closed 2026-03-02)

## Problem
After deploy restart in HA environment, traffic from `cluster-lan-host` to `172.16.100.247` can fail for ~10-30 seconds, then recover on its own.

## Symptom
- `ping 172.16.100.247` from `cluster-lan-host` times out immediately after restart.
- Outage self-resolves without manual intervention.
- This points to transient convergence/race rather than permanent misconfiguration.

## Context
- Likely in ARP/neighbor/FIB convergence path during restart/failover handoff.
- Related known areas: NO_NEIGH handling, neighbor warmup timing, VRRP transition timing, blackhole/rg_active ordering, fabric_fwd refresh.

## Investigation scope
1. Capture neighbor table state (`ip neigh`) on both nodes across LAN/WAN/fabric during the outage window.
2. Capture packets (ARP + ICMP + relevant routed path) on ingress/egress interfaces during the first 30s after restart.
3. Correlate with:
   - VRRP state events
   - cluster state transitions
   - `rg_active`/blackhole route state
   - `fabric_fwd` programming/refresh
4. Verify whether `warmNeighborCache()` includes and successfully primes this exact destination path in restart scenarios.

## Expected outcome
- Root-cause the transient 10-30s gap.
- Add deterministic fix and regression test so restart does not cause temporary loss to `172.16.100.247`.

## Docs
- Investigation note added to `docs/bugs.md` under:
  - `Transient post-deploy connectivity loss to 172.16.100.247 (OPEN INVESTIGATION)`


---

## #75 — HA restart: neighbor prewarm runs before VRRP VIP ownership, causing 10-30s transient WAN loss [CLOSED] (closed 2026-03-02)

## Root cause
Transient `cluster-lan-host -> 172.16.100.247` loss (~10-30s) after deploy restart is caused by **neighbor prewarm running too early** in HA startup.

### Evidence in code
1. In HA/VRRP-backed RETH, networkd uses a link-local placeholder address (not the WAN/LAN VIP) until VRRP MASTER adds real VIPs:
   - `pkg/dataplane/compiler.go:766-768`
   - `pkg/dataplane/compiler.go:873-876`
   - `pkg/dataplane/compiler.go:927-930`

2. Initial proactive neighbor resolution runs during `applyConfig()` **before** VRRP instances are updated:
   - `pkg/daemon/daemon.go:1485-1489` (`d.resolveNeighbors(cfg)`)
   - VRRP instance update happens later at `pkg/daemon/daemon.go:1526-1533`.

3. Periodic neighbor resolver does not run immediately; first retry is after 15s:
   - `pkg/daemon/daemon.go:1943-1954` (`time.NewTicker(15 * time.Second)` with no initial call).

### Why this produces ~10-30s self-heal
- Early `resolveNeighbors()` runs while VRRP VIP ownership/connected routes are not ready for the active RETH path.
- Neighbor priming may miss WAN next-hop during this window.
- First successful retry happens on periodic ticks (15s cadence), so user-visible outage falls in ~10-30s band.

## Impact
- Immediate post-restart internet connectivity from LAN can fail transiently.
- Behavior is nondeterministic (depends on timing of VRRP MASTER transition vs resolver runs).

## Proposed fix
1. In cluster mode, defer initial `resolveNeighbors()` until after VRRP state is established (or trigger on VRRP MASTER event).
2. Make periodic neighbor resolver run once immediately at goroutine start, then every 15s.
3. Add restart regression test:
   - Restart daemon(s)
   - Probe `cluster-lan-host -> 172.16.100.247` continuously
   - Assert no multi-second warmup gap (or at least bounded below current behavior).

## Related
- Investigation issue: #74


---

## #76 — HA race: SessionSync has unsynchronized concurrent conn writers and short-write hazards [CLOSED] (closed 2026-03-02)

## Problem
`SessionSync` has multiple concurrent writers to the same TCP connection with no serialization, and write paths do not handle short writes. This can corrupt message framing (`BPSY` header + payload), causing intermittent sync disconnects and state loss during HA churn.

## Code evidence
- `writeMsg()` performs two separate `conn.Write` calls (header then payload):
  - `pkg/cluster/sync.go:958-971`
- `sendLoop()` also writes directly to `conn` (`conn.Write(msg)`) with no shared write lock:
  - `pkg/cluster/sync.go:586-603`
- Keepalive writes from receive goroutine via `writeMsg()`:
  - `pkg/cluster/sync.go:620-629`
- Other goroutines write directly via `writeMsg()` (`QueueConfig`, `SendFailover`, `QueueIPsecSA`):
  - `pkg/cluster/sync.go:389-407`, `410-428`, `929-947`

There is no single-writer goroutine or write mutex guarding these paths.

## Why this is a race
- Two goroutines can interleave writes at message boundaries.
- Because `writeMsg()` splits header/payload into separate writes, another writer can inject bytes between them.
- Framing parser (`receiveLoop`) can then see bad magic/length and disconnect.

## Additional correctness gap
- Write paths ignore short writes (`n < len`) unless an error is returned.
- `sendLoop` and `writeMsg` should enforce full writes.

## Proposed fix
1. Serialize all outbound sync traffic through a single writer path (one goroutine or a connection write mutex).
2. Use `io.WriteFull`/equivalent to guarantee full header+payload writes.
3. Route keepalive/config/failover/IPsec writes through the same serialized channel.
4. Add stress test with concurrent queue + keepalive + bulk sync writes.

## Acceptance criteria
- No frame corruption under concurrent sync traffic.
- No spurious disconnects due to malformed/partial messages under HA failover stress.
- Unit/integration tests cover concurrent writer scenarios.


---

## #77 — HA race: fixed 10s VRRP sync-hold timeout can release before bulk sync completes [CLOSED] (closed 2026-03-02)

## Problem
VRRP sync-hold release on startup is driven by a fixed 10s timer, not guaranteed completion of bulk session sync. Under large session tables or slow reconnect, preemption can resume before state is fully installed.

## Code evidence
- Startup enables sync hold for fresh daemon starts:
  - `pkg/daemon/daemon.go:3457-3463` (`SetSyncHold(10 * time.Second)`)
- Hold is released either on bulk sync callback OR timeout:
  - bulk callback: `pkg/daemon/daemon.go:3465-3468`
  - timeout release path: `pkg/vrrp/manager.go:90-93`

Timeout path unconditionally calls `ReleaseSyncHold()` even if sync is incomplete.

## Impact
- Returning high-priority node can preempt early without full session state.
- Existing flows may reset/drop during takeover despite sync feature being enabled.
- Behavior is load-dependent (worse with larger session sets).

## Proposed fix
1. Make sync-hold release condition-driven (bulk sync completion + optional minimum installed-session threshold), not purely timer-driven.
2. Keep timeout as safety fallback, but transition to degraded mode with explicit warning and optional preempt suppression policy.
3. Expose sync-hold reason/state in CLI/API to aid diagnosis.

## Acceptance criteria
- In large-session restart tests, preemption does not occur before bulk sync completion unless operator-configured fallback policy allows it.
- Early-timer release can no longer silently bypass session-protection intent.
- Observability clearly shows why sync hold was released.


---

## #78 — HA race: reconnect config sync can accept stale secondary config (authority not enforced) [CLOSED] (closed 2026-03-02)

## Problem
Reconnect config-sync path can push/apply config without validating sender authority (RG0 primary). This allows stale secondary config to be accepted during reconnect races.

## Code evidence
- On peer reconnect, callback pushes config based on uptime heuristic:
  - `pkg/daemon/daemon.go:3447-3454`
- `pushConfigToPeer()` is explicitly unconditional (no primary check):
  - `pkg/daemon/daemon.go:3310-3328`
- Receiver applies any incoming config:
  - `pkg/daemon/daemon.go:3331-3349`

`syncConfigToPeer()` has primary gating, but reconnect path bypasses it by design.

## Impact
- During reconnect churn, stale node can overwrite peer config.
- Config source-of-truth can become nondeterministic if nodes diverged.
- Creates race between role transitions and config propagation.

## Proposed fix
1. Add authority metadata to config sync messages (sender node ID, RG0 role/epoch).
2. Accept config only from currently authoritative source (RG0 primary / newest epoch).
3. Replace reconnect "push from stable node" heuristic with pull/request from current primary.
4. Add tests for split/reconnect where nodes have divergent config snapshots.

## Acceptance criteria
- Secondary/stale node cannot overwrite primary config during reconnect.
- Config convergence is deterministic and role-authoritative.
- Reconnect tests with divergent configs always converge to primary's config.


---

## #79 — HA readiness: fabric_fwd population is passively delayed and race-prone at startup [CLOSED] (closed 2026-03-02)

## Problem
`fabric_fwd` readiness during startup/failover is passive and delayed: first refresh waits 2s, and peer-MAC resolution only checks existing neighbor cache (no active probe). This can leave cross-chassis redirect unavailable during early HA transitions.

## Code evidence
- Initial population loop waits before first attempt:
  - `pkg/daemon/daemon.go:3562-3568`
- MAC resolution is passive (`NeighList`) and returns false if entry absent:
  - `pkg/daemon/daemon.go:3618-3637`
- Periodic drift correction is every 30s:
  - `pkg/daemon/daemon.go:3577-3585`

No active ARP/NDP solicitation is triggered for fabric peer when missing.

## Impact
- Early failover windows may lack working fabric redirect metadata.
- New/existing flows relying on fabric redirect can drop until neighbor entry appears.
- Recovery timing becomes nondeterministic (depends on incidental neighbor activity).

## Proposed fix
1. Attempt immediate `refreshFabricFwd()` (no initial 2s delay).
2. On missing peer neighbor, actively trigger ARP/NDP probe on fabric interface.
3. Use faster startup retry cadence until first success, then fall back to 30s drift interval.
4. Add HA startup/failover test that validates fabric redirect readiness time budget.

## Acceptance criteria
- `fabric_fwd` map is populated quickly and deterministically after startup/failover.
- Missing neighbor entry no longer waits for incidental traffic.
- Cross-chassis redirect path is available within defined startup SLA.


---

## #80 — HA correctness: periodic neighbor warmup uses stale startup config snapshot [CLOSED] (closed 2026-03-02)

## Problem
Periodic neighbor prewarm uses a config snapshot captured at daemon startup and does not track later active-config changes.

## Code evidence
- Periodic runner is started with `cfg := d.store.ActiveConfig()` once:
  - `pkg/daemon/daemon.go:564-575`
- Loop reuses that captured `cfg` forever:
  - `pkg/daemon/daemon.go:1945-1954`

If config changes via commit/sync (NAT pools, static routes, address-book hosts, etc.), periodic prewarm may miss new targets or keep probing removed ones.

## HA impact
- After config sync/failover churn, NO_NEIGH risk persists for newly introduced forwarding targets.
- Warmup behavior diverges from actual active config, causing intermittent first-packet drops/resets.

## Proposed fix
1. On each tick, fetch current `d.store.ActiveConfig()` instead of using a stale pointer.
2. Optionally trigger immediate prewarm after successful config apply/sync events.
3. Add tests where config changes after startup and verify periodic warmup covers new targets.

## Acceptance criteria
- Periodic neighbor warmup always reflects current active config.
- New NAT/route/address-book targets are warmed without daemon restart.
- Removed targets are no longer probed indefinitely.


---

## #81 — HA startup bug: heartbeat/session-sync retry exhaustion can permanently disable cluster comms [CLOSED] (closed 2026-03-02)

## Problem
Cluster comms startup uses fixed retry budgets (30 attempts x 2s) for heartbeat and session sync. If retries exhaust during slow interface/VRF bring-up, HA comms never recover until daemon restart.

## Code evidence
- Heartbeat startup retries then gives up permanently:
  - `pkg/daemon/daemon.go:3375-3399`
- Session sync startup retries then gives up permanently:
  - `pkg/daemon/daemon.go:3407-3425`
  - `pkg/daemon/daemon.go:3496-3511`

After these goroutines return, there is no long-lived supervisor to retry later.

## HA impact
- Node can remain in degraded/no-heartbeat state indefinitely after boot races.
- Failover/ownership decisions may be wrong or delayed because control channels never start.
- Requires manual daemon restart to recover.

## Proposed fix
1. Replace fixed retry loops with persistent supervisor loops tied to daemon lifetime.
2. Add backoff + jitter, but never permanently stop retrying while daemon is running.
3. Expose health status for heartbeat/session-sync startup state in CLI/API.

## Acceptance criteria
- Delayed interface/VRF readiness no longer permanently disables HA comms.
- Heartbeat/session sync eventually come up without manual restart.
- Status output clearly indicates retrying vs connected states.


---

## #82 — HA startup race: initial BulkSync may be skipped before dataplane wiring [CLOSED] (closed 2026-03-02)

## Problem
Initial bulk session sync can be missed at startup due to a race: `SessionSync.Start()` may connect and attempt `BulkSync()` before dataplane is wired, then never re-run full sync after dataplane becomes ready.

## Code evidence
- `SessionSync.Start()` launches connect/accept goroutines that call `BulkSync()` on connect:
  - `pkg/cluster/sync.go:165-199`
  - `pkg/cluster/sync.go:520-527`
  - `pkg/cluster/sync.go:579-582`
- `BulkSync()` returns error when dataplane is nil:
  - `pkg/cluster/sync.go:432-435`
- Dataplane is wired only after `Start()` returns in async startup path:
  - `pkg/daemon/daemon.go:3497-3527`

If early `BulkSync()` fails before `SetDataPlane()`, existing sessions at that moment may never be fully replicated unless a reconnect happens.

## HA impact
- Returning node may preempt with incomplete replicated state.
- Existing flows can reset/drop after failover despite sync being "connected".
- Recovery depends on incidental reconnect timing.

## Proposed fix
1. Defer first `BulkSync()` until dataplane is ready (or queue a guaranteed post-SetDataPlane bulk sync).
2. Add explicit one-shot cold-sync trigger immediately after `SetDataPlane()`.
3. Gate sync-hold release on confirmed successful cold sync, not just connection state.

## Acceptance criteria
- On startup, exactly one successful cold sync always occurs after dataplane is ready.
- Existing sessions present before startup are replicated without requiring reconnect.
- HA failover tests verify cold-sync completeness under startup races.


---

## #83 — HA race: session delete sync is not per-RG ownership-safe in active/active [CLOSED] (closed 2026-03-02)

## Problem
Delete sync path is not scoped by per-RG ownership in active/active mode. Non-owner nodes can enqueue delete messages and peers apply them unconditionally.

## Code evidence
- GC delete callbacks send deletes when node is primary for *any* RG:
  - `pkg/daemon/daemon.go:303-313`
- No per-zone/per-RG ownership check is applied for deletes (unlike session sweep which uses `ShouldSyncZone`).
- Receiver applies delete messages without ownership validation:
  - `pkg/cluster/sync.go:774-800`
  - `pkg/cluster/sync.go:802-826`

## HA impact
- In active/active churn, a stale/non-owner node can delete sessions on the owner peer.
- Can cause random flow drops/resets during failover/failback cycles.
- Behavior is timing-dependent and hard to reproduce deterministically.

## Proposed fix
1. Carry ownership metadata for delete messages (e.g., ingress zone / RG / owner epoch).
2. Send deletes only when local node owns the session’s RG.
3. On receiver, reject deletes from non-authoritative owner for that RG.
4. Add stress test with active/active failover churn and session deletions.

## Acceptance criteria
- Non-owner nodes cannot remove owner sessions via sync deletes.
- Delete sync semantics match per-RG ownership model used by create/session sweep paths.
- Active/active stress tests show no ownership-violating deletes.


---

## #84 — HA race: VRRP event watcher uses background context and outlives shutdown lifecycle [CLOSED] (closed 2026-03-02)

## Problem
`watchVRRPEvents` is launched with `context.Background()` and is not part of coordinated shutdown. Combined with an event channel that is never closed, this creates goroutine lifecycle leaks and shutdown-order races.

## Code evidence
- Watcher started with background context:
  - `pkg/daemon/daemon.go:579`
- Watcher exits only on `ctx.Done()` or closed event channel:
  - `pkg/daemon/daemon.go:3873-3939`
- VRRP manager stop does not close `eventCh`:
  - `pkg/vrrp/manager.go:59-81` (instances cleared/stopped, manager cancel, but channel remains open)

## HA impact
- Event watcher can outlive intended daemon lifecycle.
- During shutdown, VRRP stop events may race with dataplane/cluster teardown handling.
- Harder to guarantee deterministic fail-closed behavior during process stop.

## Proposed fix
1. Run `watchVRRPEvents` on daemon `ctx` (not background).
2. Include watcher in shutdown waitgroup.
3. Define clear manager/event channel shutdown semantics (close channel or explicit stop signal).

## Acceptance criteria
- No goroutine leaks for VRRP watcher across start/stop cycles.
- Shutdown ordering is deterministic and race-free for VRRP->rg_active transitions.
- Tests validate clean watcher termination.


---

## #85 — HA reliability: sync queue overflow drops critical control messages without replay [CLOSED] (closed 2026-03-02)

## Problem
Session sync send queue overflow drops critical message types (deletes/config/failover/IPsec sync) without replay/ack semantics.

## Code evidence
- `queueMessage` drops on full channel (`default` case):
  - `pkg/cluster/sync.go:345-362`
- Replay mechanism (`syncBackfillNeeded`) only helps sweep-created session adds:
  - `pkg/cluster/sync.go:283-334`
- Delete/config/failover/IPsec paths rely on one-shot queue/write and can be lost:
  - deletes: `pkg/cluster/sync.go:377-387`
  - config: `pkg/cluster/sync.go:389-407`
  - failover: `pkg/cluster/sync.go:410-428`
  - IPsec SA: `pkg/cluster/sync.go:929-947`

## HA impact
- Lost delete messages leave stale sessions/NAT reverse entries.
- Lost failover request can stall operator-initiated role move.
- Lost config/IPsec messages create control-plane drift.

## Proposed fix
1. Prioritize/partition queues by message class (control vs data).
2. Add retry/ack semantics for critical control messages.
3. Add replay strategy for deletes (not only session creates).
4. Expose queue drop counters by message type.

## Acceptance criteria
- Queue pressure cannot silently drop critical HA control messages.
- Delete/config/failover delivery is reliable under stress.
- Tests inject queue saturation and verify eventual consistency.


---

## #86 — HA race: dropped cluster events are not repaired for VRRP control actions [CLOSED] (closed 2026-03-02)

## Problem
When cluster events are dropped (full event channel), recovery path only reconciles `rg_active`/blackhole state and does **not** replay VRRP control actions (`ResignRG`, priority restore, forced MASTER). This can leave VRRP and cluster state diverged under churn.

## Code evidence
- Dropped cluster events trigger `onEventDrop` callback:
  - `pkg/cluster/cluster.go:523-531`
- Daemon wires this callback to `triggerReconcile()`:
  - `pkg/daemon/daemon.go:212-214`
- `reconcileRGState()` only reconciles `rg_active` + blackhole routes:
  - `pkg/daemon/daemon.go:3974-4071`
- VRRP control actions exist only in event-driven handler:
  - `pkg/daemon/daemon.go:3745-3764` (`ResignRG`, `UpdateRGPriority`, `ForceRGMaster`)

If the event carrying a primary/secondary transition is dropped, those VRRP actions are never replayed.

## HA impact
- Cluster says Secondary while VRRP may remain MASTER (or wrong priority).
- Active/active ownership can drift and create prolonged forwarding inconsistencies.
- Reconcile loop reports state "correct" because it observes stale VRRP state as authoritative input.

## Proposed fix
1. Add periodic VRRP-vs-cluster reconciliation for control actions (not just `rg_active`).
2. On reconcile pass, enforce expected VRRP posture from authoritative cluster state.
3. Keep event path fast, but make reconciliation able to repair missed VRRP transitions.

## Acceptance criteria
- Dropped cluster events no longer leave persistent VRRP role/priority drift.
- Under forced event-channel saturation, states self-heal without manual intervention.
- Tests cover dropped transition events and verify eventual convergence.


---

## #87 — HA bug: heartbeat/session-sync endpoints are one-shot and not reconfigured on runtime config changes [CLOSED] (closed 2026-03-02)

## Problem
HA transport endpoints (heartbeat + session sync) are started once at daemon boot and are not reconfigured when cluster control/fabric settings change via config apply/sync.

## Code evidence
- `startClusterComms()` is called once during daemon startup:
  - `pkg/daemon/daemon.go:267-270`
- Heartbeat/session sync startup + endpoint binding occur inside that one-shot path:
  - heartbeat: `pkg/daemon/daemon.go:3370-3399`
  - session sync: `pkg/daemon/daemon.go:3402-3530`
- `StartHeartbeat()`/`sessionSync.Start()` call sites are only in startup path:
  - `pkg/daemon/daemon.go:3385`, `3497`
- Runtime config apply updates cluster state/config but does not restart comms endpoints:
  - `pkg/daemon/daemon.go:1603-1605`

## HA impact
- Changes to `control-interface`, `peer-address`, `fabric-interface`, or `fabric-peer-address` may not take effect until daemon restart.
- Nodes can continue using stale sync/heartbeat sockets after commit/config-sync.
- Creates split behavior between configured and actual HA transport state.

## Proposed fix
1. Detect HA transport config deltas on apply/sync.
2. Restart/rebind heartbeat and session-sync endpoints safely when these fields change.
3. Expose current bound transport endpoints in status output.

## Acceptance criteria
- HA transport endpoint changes apply without daemon restart.
- Post-commit runtime state matches active config for heartbeat/sync bindings.
- Regression tests cover transport endpoint reconfiguration.


---

## #88 — HA safety bug: manual failover can self-blackhole when peer is already down [CLOSED] (closed 2026-03-02)

## Problem
`ManualFailover()` can force local node to `Secondary` with weight 0 even when peer is already down/unreachable, creating a self-inflicted traffic blackhole until manual reset.

## Code evidence
- `ManualFailover()` unconditionally sets:
  - `ManualFailover=true`
  - `Weight=0`
  - `State=Secondary`
  - `pkg/cluster/cluster.go:405-423`
- Single-node election explicitly skips `ManualFailover` groups:
  - `pkg/cluster/cluster.go:255-257`
- Default CLI command path invokes `ManualFailover()` directly (without `node <id>` peer-request path):
  - `pkg/cli/cli.go:11631-11660`

If peer is already dead and operator runs `request chassis cluster failover redundancy-group <N>`, local node can resign with no live peer to take over.

## HA impact
- Immediate avoidable outage on that RG.
- Recovery requires explicit operator reset (`request ... failover reset ...`).
- High-risk operational footgun during incident handling.

## Proposed fix
1. Guard `ManualFailover()` against `!peerAlive` by default (return error or require explicit `force`).
2. Improve CLI UX to steer operators toward `node <local>`/`node <peer>` semantics with peer liveness checks.
3. Emit explicit warning/event when manual failover is requested without a healthy peer.

## Acceptance criteria
- Manual failover cannot silently blackhole traffic when peer is down.
- Operator receives clear actionable error/warning.
- Existing valid manual failover workflows remain functional when peer is alive.


---

## #89 — HA race: stale session-sync receive loops can disconnect a newer active connection [CLOSED] (closed 2026-03-02)

## Problem
`SessionSync` can tear down a newly-established peer connection when an older `receiveLoop` exits.

## Code evidence
- Each accepted/dialed connection starts its own `receiveLoop` with `defer s.handleDisconnect()`:
  - `pkg/cluster/sync.go:607-610`
- Connection handoff overwrites `s.conn` on every new accept/dial:
  - accept path: `pkg/cluster/sync.go:501-507`
  - connect path: `pkg/cluster/sync.go:560-566`
- `handleDisconnect()` closes **whatever is currently in `s.conn`**, not the specific conn that failed:
  - `pkg/cluster/sync.go:878-886`

Failure sequence:
1. conn A is active (`receiveLoop(A)` running)
2. conn B is established and assigned to `s.conn`
3. `receiveLoop(A)` exits (expected) and calls `handleDisconnect()`
4. `handleDisconnect()` closes conn B (the new active conn)

## HA impact
- Session sync connection flaps during normal reconnect/race scenarios.
- Bulk sync, deletes, and failover control messages can be interrupted/lost.
- Promotes non-deterministic failover behavior under transport churn.

## Proposed fix
1. Make disconnect handling connection-specific (`handleDisconnectConn(conn)`), and only clear/close if `conn == s.conn`.
2. Ensure accept/connect handoff cannot let stale goroutines close the new connection.
3. Add tests for dual-connection handoff (A→B) ensuring B remains connected when A exits.

## Acceptance criteria
- Stale `receiveLoop` exit cannot close the currently active connection.
- Rapid reconnect/dual-connect scenarios converge to one stable connection.
- Regression test reproduces old failure and passes with fix.


---

## #90 — HA protocol bug: session-sync writes are unsynchronized and can corrupt frames [CLOSED] (closed 2026-03-02)

## Problem
Session sync message writes are not serialized and are not short-write safe, which can corrupt protocol framing under load.

## Code evidence
- Background data path writes from `sendLoop`:
  - `pkg/cluster/sync.go:586-603`
- Control paths write directly to the same `net.Conn` concurrently (`writeMsg`):
  - config: `pkg/cluster/sync.go:389-408`
  - failover: `pkg/cluster/sync.go:410-429`
  - IPsec SA: `pkg/cluster/sync.go:929-947`
  - bulk sync: `pkg/cluster/sync.go:431-485`
- `writeMsg` performs two separate writes (header then payload), so interleaving with other writers can splice frames:
  - `pkg/cluster/sync.go:958-971`
- `sendLoop` uses `conn.Write(msg)` once and ignores short writes (`n < len(msg)` with nil error):
  - `pkg/cluster/sync.go:598`

## HA impact
- Peer can observe malformed headers/magic mismatches and disconnect.
- Control messages (failover/config) can be corrupted during heavy session replication.
- Causes intermittent sync instability and failover unpredictability.

## Proposed fix
1. Enforce a single serialized writer path for all message classes (data + control + bulk).
2. Implement full-write semantics (`writeFull`) and treat short writes as retry/error.
3. Add stress tests with concurrent queue traffic + config/failover sends and verify no framing errors.

## Acceptance criteria
- No concurrent unsynchronized writes to the sync TCP stream.
- All sends are full-frame writes or explicit errors/retries.
- Under concurrency stress, receiver never logs bad magic/truncated frame due to writer interleaving.


---

## #91 — HA startup race: SESSION_OPEN sync callback can be skipped permanently [CLOSED] (closed 2026-03-02)

## Problem
Near-real-time `SESSION_OPEN` sync callback registration is racey and may never be installed.

## Code evidence
- Callback is only added once, conditionally, during event reader setup:
  - `pkg/daemon/daemon.go:336-379`
  - guarded by `if d.sessionSync != nil`
- `d.sessionSync` is created asynchronously later in `startClusterComms()` goroutine:
  - `pkg/daemon/daemon.go:3405-3431`
- No later path re-adds the callback after `d.sessionSync` becomes non-nil.

If event-reader init runs before session-sync startup (common when fabric IP/VRF waits), incremental `SESSION_OPEN` replication never gets wired for the process lifetime.

## HA impact
- Only periodic sweep replication remains; short-lived sessions can be missed.
- Slower/less complete convergence after failover under bursty traffic.
- Increased probability of random connection drops during ownership transitions.

## Proposed fix
1. Register the callback unconditionally and check `d.sessionSync` dynamically inside handler, or
2. Add callback when `sessionSync` is created (idempotent registration).
3. Add startup-order test where sessionSync starts late and verify callback still fires.

## Acceptance criteria
- `SESSION_OPEN` callback is always active regardless of startup ordering.
- Late sessionSync initialization does not disable incremental session replication.
- Tests cover both early and late sessionSync startup sequences.


---

## #92 — HA election bug: stale peer RG entries persist across heartbeats [CLOSED] (closed 2026-03-02)

## Problem
Peer RG state from heartbeat is append/update-only; RGs missing from a newer heartbeat are never pruned, leaving stale peer state in elections.

## Code evidence
- `handlePeerHeartbeat()` updates entries present in packet but does not clear missing RG IDs:
  - `pkg/cluster/cluster.go:721-728`
- Election logic distinguishes `peerGroup == nil` as "peer has no RG info" and can promote local primary:
  - `pkg/cluster/election.go:100-104`

Because stale `peerGroups[rgID]` entries persist, local election can keep using outdated peer weight/state for RGs the peer no longer advertises.

## HA impact
- Incorrect primary/secondary decisions after RG add/remove/reconfigure.
- Possible prolonged secondary state when local should promote (or vice versa).
- Debug output (`show chassis cluster`) can report stale peer RG data.

## Proposed fix
1. Rebuild/replace `peerGroups` on each heartbeat packet (authoritative snapshot semantics).
2. Keep explicit timeout-based clear for full peer loss, but also prune per-packet deltas.
3. Add test: peer heartbeat transitions from RG set `{0,1}` to `{0}` and verify RG1 stale state is removed.

## Acceptance criteria
- `peerGroups` reflects exactly the latest heartbeat payload.
- Election behavior for removed RGs matches `peerGroup == nil` path.
- Regression tests cover RG removal without full peer timeout.


---

## #93 — HA drift bug: reconcile loop does not repair RA/DHCP service ownership after dropped VRRP events [CLOSED] (closed 2026-03-02)

## Problem
Dropped VRRP events can leave per-RG service ownership (RA/DHCP) stale because reconciliation only repairs `rg_active`/blackhole state.

## Code evidence
- RA/DHCP ownership changes are event-driven only:
  - on MASTER: `applyRethServicesForRG()` at `pkg/daemon/daemon.go:3915`
  - on BACKUP: `clearRethServicesForRG()` at `pkg/daemon/daemon.go:3934`
- Dropped VRRP/cluster events trigger reconcile via `triggerReconcile()` callbacks:
  - `pkg/daemon/daemon.go:212-214`, `229-231`, `3965-3972`
- `reconcileRGState()` repairs only rg_state/`rg_active` and blackhole routes:
  - `pkg/daemon/daemon.go:3974-4071`
  - no RA/DHCP service reconciliation in this path.

## HA impact
- Node can have correct forwarding state but wrong control-plane services after event drops.
- Risks dual-service or missing-service behavior (RA/DHCP) during churn.
- Produces hard-to-debug split behavior where dataplane and service ownership disagree.

## Proposed fix
1. Extend reconciliation to assert per-RG service ownership from authoritative VRRP state snapshot.
2. Make service apply/clear idempotent so reconcile can safely enforce desired state.
3. Add forced event-drop tests validating eventual RA/DHCP convergence.

## Acceptance criteria
- Dropped VRRP events cannot leave persistent RA/DHCP ownership drift.
- Reconcile pass converges both dataplane (`rg_active`) and per-RG services.
- Tests simulate event channel saturation and verify eventual consistent service state.


---

## #94 — HA lifecycle race: cluster watcher/comms use pre-signal context and can outlive shutdown cancel [CLOSED] (closed 2026-03-02)

## Problem
Some HA goroutines are started with the pre-signal parent context and are not tied to the shutdown context canceled by `stop()`.

## Code evidence
- HA goroutines started before signal context wrapping:
  - `go d.watchClusterEvents(ctx)` at `pkg/daemon/daemon.go:219`
  - `d.startClusterComms(ctx)` at `pkg/daemon/daemon.go:269`
- Later, `ctx` is replaced with `signal.NotifyContext(...)`:
  - `pkg/daemon/daemon.go:276-281`
- Shutdown calls `stop()` (cancels the new child context only):
  - `pkg/daemon/daemon.go:761-763`

Result: early goroutines use the original parent context and can outlive normal shutdown cancellation semantics.

## HA impact
- Lifecycle leaks/races during teardown/restart paths.
- Non-deterministic shutdown ordering for HA control goroutines.
- Harder to guarantee clean fail-closed behavior under repeated restart/failover testing.

## Proposed fix
1. Create the signal-aware context before launching HA goroutines.
2. Ensure all long-lived HA loops use that context (or an explicit daemon-owned cancel context).
3. Add shutdown tests that assert all HA goroutines exit deterministically.

## Acceptance criteria
- No HA control goroutine remains running after shutdown.
- Context cancellation path is single-source and consistent.
- Restart tests show stable lifecycle without leaked HA loops.


---

## #96 — VRRP startup sync-hold race allows preempt-before-sync on node rejoin [CLOSED] (closed 2026-03-02)

## Summary
When a node restarts and rejoins an HA cluster, VRRP preemption suppression (`sync hold`) can be applied too late or can be unintentionally bypassed. This allows a returning high-priority node to preempt before session state is synchronized, causing transient connection drops during failover/rejoin.

## Observed behavior
- New daemon startup can still preempt early, despite sync hold intended behavior.
- Existing VRRP instances can keep or regain `preempt=true` while hold is active.
- Re-arming sync hold can leave a stale timer active, releasing hold earlier than intended.

## Root causes
1. Startup ordering race: sync hold is enabled in `startClusterComms()` (async, after initial config apply), but VRRP instances are created earlier in `applyConfig()`.
2. `SetSyncHold()` only affected instances created later; it did not suppress preempt on already-running instances.
3. `UpdateInstances()` in-place updates could re-enable `cfg.Preempt` during active hold.
4. `SetSyncHold()` did not stop/replace an existing hold timer when called again.

## Expected behavior
- On fresh clustered startup (with fabric sync configured), hold should be active **before** first VRRP instance creation/update.
- While hold is active, all instances should have effective `preempt=false` (existing + updated + newly created), while preserving configured desired preempt for restore.
- Re-arming hold should replace the prior timer, not race with it.

## Suggested fix
- Enable startup sync hold right after VRRP manager init in `Run()`, before first `applyConfig()`/`UpdateInstances()`.
- Make `SetSyncHold()` suppress preempt immediately on existing instances.
- In `UpdateInstances()`, keep effective `preempt=false` when hold is active and preserve configured `desiredPreempt`.
- Stop and replace any prior sync-hold timer when setting hold again.

## Acceptance criteria
- Regression tests cover:
  - sync hold applies to existing instances
  - existing-instance updates do not break hold
  - timer re-arm replaces old timer and does not early-release hold
- During restart/rejoin with active peer, returning node does not preempt until bulk sync completion (or hold timeout fallback).


---

## #98 — HA neighbor warmup skips interface-qualified static next-hops with Junos interface names [CLOSED] (closed 2026-03-02)

## Summary
`resolveNeighbors()` skips interface-qualified static next-hops when the configured interface name is in Junos form (`ge-0/0/1`, `reth0.50`) instead of Linux form (`ge-0-0-1`, resolved member VLAN). This breaks proactive ARP/NDP warmup in HA and increases NO_NEIGH drops right after failover.

## Why this matters
During HA takeover, we rely on proactive neighbor resolution so first packets do not hit `BPF_FIB_LKUP_RET_NO_NEIGH`. If interface-qualified next-hops are skipped, the new active node can still cold-drop traffic for several seconds.

## Root cause
In [`pkg/daemon/daemon.go`](pkg/daemon/daemon.go), `resolveNeighbors()` does:

- `addByName(nh.Address, nh.Interface)` for static routes ([`pkg/daemon/daemon.go:1913`](pkg/daemon/daemon.go#L1913), [`pkg/daemon/daemon.go:1930`](pkg/daemon/daemon.go#L1930))
- `netlink.LinkByName(ifName)` directly in `addByName` ([`pkg/daemon/daemon.go:1891-1899`](pkg/daemon/daemon.go#L1891-L1899))

`nh.Interface` is parsed from config in Junos naming, and may also be a RETH logical name. `LinkByName` then fails silently, so the target is never probed.

## Repro
1. Configure static route with interface-qualified next-hop, e.g. IPv6 link-local:
   - `set routing-options static route ::/0 next-hop fe80::1 interface reth0.50`
2. Trigger HA failover/restart.
3. Observe missing neighbor prewarm for this next-hop and transient NO_NEIGH drops in first traffic window.

## Expected
`resolveNeighbors()` should normalize/resolve interface names before `LinkByName`:
- Resolve RETH/logical names to active Linux member interface
- Apply Junos→Linux name normalization (`config.LinuxIfName`)
- Handle VLAN subinterfaces consistently

## Acceptance criteria
- Interface-qualified static route next-hops are successfully probed in HA for both v4/v6 routes.
- Neighbor warmup logs include those targets after failover.
- Failover test with interface-qualified next-hop no longer shows first-packet NO_NEIGH loss for that route.


---

## #99 — HA sync protocol still vulnerable to short-write frame truncation [CLOSED] (closed 2026-03-02)

## Summary
Session sync still assumes a single `Write()` sends a full frame. Both `writeMsg()` and `sendLoop` ignore short writes, which can truncate protocol frames under backpressure and desynchronize the stream.

## Why this matters
HA correctness depends on reliable session/config/failover/fence replication. A short write can send a partial frame header/payload, causing receiver parse errors (`bad magic`, truncated payload) and disconnect/reconnect churn exactly during failover windows.

## Root cause
- `sendLoop` writes queued messages with one `conn.Write(msg)` and ignores returned byte count:
  - [`pkg/cluster/sync.go:687`](pkg/cluster/sync.go#L687)
- `writeMsg` builds framed messages and also does single `conn.Write(buf)` with no full-write loop:
  - [`pkg/cluster/sync.go:1188-1195`](pkg/cluster/sync.go#L1188-L1195)

This is unsafe for stream sockets: `Write` may return `n < len(buf)` with `err == nil`.

## Expected
All sync writes must be full-frame writes (or fail):
- use `io.Copy`/`writeFull` style loops until all bytes are sent
- treat short write as error if full payload cannot be sent
- keep serialization via `writeMu`

## Acceptance criteria
- Add unit tests with a mock `net.Conn` that intentionally short-writes.
- Session/config/failover/fence writes either send full frames or return error.
- No truncated frames observed in protocol tests under forced short-write behavior.


---

## #100 — HA heartbeat can truncate with large monitor payloads and trigger false peer loss [CLOSED] (closed 2026-03-02)

## Summary
Heartbeat monitor payloads are variable-length but the receiver uses a fixed 512-byte UDP read buffer. Large monitor sets can truncate heartbeats, causing parse errors and false peer-loss failovers.

## Why this matters
In larger deployments with many interface-monitor entries, heartbeats can exceed 512 bytes. Truncated datagrams are treated as invalid heartbeats, incrementing errors and potentially driving `peer heartbeat timeout` despite a healthy peer.

## Root cause
- Hard-coded max heartbeat read size: [`pkg/cluster/heartbeat.go:24`](pkg/cluster/heartbeat.go#L24)
- Receiver allocates `buf := make([]byte, maxHeartbeatSize)` and reads datagrams into it:
  - [`pkg/cluster/heartbeat.go:296-307`](pkg/cluster/heartbeat.go#L296-L307)
- Encoder allows unbounded monitor payload growth (per-monitor name length + count) with no size guard:
  - [`pkg/cluster/heartbeat.go:83-127`](pkg/cluster/heartbeat.go#L83-L127)

## Expected
Heartbeat transport should be robust for configured monitor scale:
- either increase read budget to safe MTU size and enforce bounded encode size
- or cap/compact monitor section while always preserving RG election-critical fields
- receiver should not flap peer state due monitor-section truncation

## Acceptance criteria
- Add test building a heartbeat with large monitor payload (>512 bytes).
- Receiver continues to process RG state correctly without false timeout.
- Monitor-section overflow behavior is explicit (bounded, dropped, or segmented) and documented.


---

## #101 — HA failover recovery delayed by fixed 10s VRRP posture mismatch timer [CLOSED] (closed 2026-03-02)

## Summary
VRRP posture reconciliation uses a fixed 10s mismatch delay, which can prolong cluster/VRRP divergence during failover incidents and manifest as 10-12s connectivity disruptions.

## Why this matters
When cluster state and VRRP state diverge (dropped events, delayed resign, missed MASTER transition), failover correctness waits for the posture fixer. A fixed 10s hold is too long for production failover targets and aligns with observed transient outage windows.

## Root cause
- Hard-coded posture mismatch delay: [`pkg/daemon/rg_state.go:208`](pkg/daemon/rg_state.go#L208)
- Reconcile loop applies correction only after this delay:
  - [`pkg/daemon/daemon.go:4295-4319`](pkg/daemon/daemon.go#L4295-L4319)

Current behavior is conservative to avoid fighting transient startup/sync-hold states, but it also delays real corrective action for sustained mismatches.

## Expected
Use context-aware posture correction timing:
- keep longer suppression during explicit sync-hold/startup windows
- use faster correction for steady-state failover mismatch (e.g. post-timeout/manual failover paths)
- target sub-second to low-second correction for real mismatch, not 10s+

## Acceptance criteria
- Add tests for sustained mismatch correction latency in non-sync-hold steady-state.
- Demonstrate faster correction than 10s in failover scenarios without reintroducing startup flapping.
- Document posture delay policy (when long vs short delays apply).


---

## #102 — HA fail-closed gap: ungraceful daemon failures can leave stale forwarding active [CLOSED] (closed 2026-03-02)

## Summary
HA fail-closed behavior is currently tied to graceful daemon shutdown. Unclean failures (`SIGKILL`, panic, deadlock) can leave stale dataplane forwarding active until external detection/election catches up.

## Why this matters
Failover testing includes hard-crash and hung-daemon cases. If userspace dies without running shutdown hooks, local BPF state can continue forwarding with stale ownership, increasing split-brain or blackhole windows.

## Current behavior
Graceful path clears `rg_active` and tears down dataplane in HA mode:
- [`pkg/daemon/daemon.go:828-889`](pkg/daemon/daemon.go#L828-L889)

But this path is not executed for ungraceful termination.

## Gap
No dataplane-side liveness deadline/watchdog enforces fail-closed when control plane stops making progress.

## Expected
Add an HA liveness mechanism so forwarding ownership fails closed even on ungraceful bpfrxd failure:
- userspace heartbeat timestamp map checked in XDP/TC fast path, or
- systemd watchdog/fencing integration that deterministically disables local forwarding state

## Acceptance criteria
- In HA mode, killing bpfrxd ungracefully (`kill -9`) on primary stops local forwarding ownership within a bounded small window.
- Peer takeover proceeds without prolonged dual-forwarding behavior.
- Behavior is covered by automated HA crash/hung-node test assertions.


---

## #103 — HA startup: block primary takeover until interfaces/VRRP are ready and hold timer expires [CLOSED] (closed 2026-03-02)

## Summary
On startup/rejoin, RG election can promote this node to `primary` before local interfaces/VRRP are actually ready. This can activate forwarding early and cause transient loss/blackhole during HA transitions.

## Why this is a bug
The current flow has no strict readiness gate before takeover:

- Election can promote on peer-loss/no-peer-info with `weight > 0`:
  - `pkg/cluster/election.go:82-105`
  - `pkg/cluster/election.go:121-127`
- Interface monitor skips missing interfaces (treated as "belongs to peer"), so local readiness can be overestimated:
  - `pkg/cluster/monitor.go:255-260`
- VRRP instance creation skips missing interfaces instead of failing readiness:
  - `pkg/vrrp/manager.go:223-227`
- VRRP posture check returns OK when no VRRP instances exist for RG:
  - `pkg/daemon/rg_state.go:228-233`
- Cluster event path can set `rg_active=true` and remove blackholes on primary transition before VRRP/interface readiness is proven:
  - `pkg/daemon/daemon.go:3988-4005`

Also, `StateSecondaryHold` exists but does not appear to be actively used as a startup/takeover gating state in election transitions.

## Proposed fix
Implement a strict per-RG readiness gate and enforce a hold timer before takeover:

1. Define readiness contract (must all be true):
- Required monitored/member interfaces for RG exist and are operationally up.
- Required VRRP instances for RG are created/running.
- Optional: fabric/session-sync readiness if configured as required for this RG.

2. Add takeover hold state/timer:
- Keep RG in `secondary-hold` until readiness is continuously true for `takeover_hold_time`.
- If readiness drops, reset timer and stay in hold.

3. Block activation while not ready:
- Do not allow cluster election to transition to effective primary forwarding while in hold.
- Do not call `UpdateRGActive(..., true)` / blackhole removal until readiness+hold pass.

4. Treat missing local-required interfaces as not-ready (not silently skipped).

5. Surface observability:
- CLI/status should show RG readiness reasons and remaining hold timer.

*(truncated — 47 lines total)*


---

## #104 — HA same-L2: add strict single-owner VIP mode to stop duplicate NA ownership churn [CLOSED] (closed 2026-03-02)

## Summary
In same-L2 HA deployments, we are seeing repeated IPv6 duplicate-owner warnings during failover windows:

`ICMPv6: NA: 02:bf:72:01:01:01 advertised our address ...`

This points to VIP ownership overlap (or repeated ownership re-advertisement) that is acceptable in some topologies but not in strict shared-L2 environments where only one owner should advertise at a time.

## Relevant code paths
- Per-node RETH MACs on shared L2: `pkg/cluster/reth.go` (`RethMAC` format `02:bf:72:CC:RR:NN`)
- Unified activation rule: `pkg/daemon/rg_state.go` (`rg_active = clusterPri || anyVrrpMaster`)
- Cluster event activation ordering: `pkg/daemon/daemon.go` (`watchClusterEvents`)
- MASTER NA/GARP emission:
  - `pkg/vrrp/instance.go` (`becomeMaster` -> `sendGARP`)
  - `pkg/cluster/garp.go` (`SendGratuitousIPv6Burst`)

## Proposed fix (execution plan)
1. Add topology/ownership mode knob
- Add an explicit strict single-owner mode (global or per-RG) for same-L2 deployments.
- Keep current overlap behavior as default for non-shared-L2 deployments.

2. Strict-mode activation semantics
- For strict-mode RGs, derive desired forwarding from VRRP ownership only (`anyVrrpMaster`), not `clusterPri || anyVrrpMaster`.
- Maintain existing behavior for default mode.

3. NA/GARP dedupe and dampening
- Send NA/GARP once per actual BACKUP->MASTER epoch.
- Suppress duplicate bursts from reconciliation unless VIP state changed.
- Add minimum resend interval to prevent burst storms under flap.

4. Observability
- Add logs/counters for strict-mode gating and NA/GARP suppression decisions.

5. Validation
- Same-L2 failover/failback test ensuring no sustained duplicate-owner NA events.
- Repeated transition stress test for connectivity stability.
- Confirm non-strict mode behavior unchanged.

## Acceptance criteria
- Strict mode: no sustained duplicate VIP ownership advertisements on shared-L2 during transitions.
- No persistent connectivity loss under repeated HA transitions.

*(truncated — 45 lines total)*


---

## #107 — HA syntax parity: implement vSRX dual-fabric (fab0 + fab1) architecture [CLOSED] (closed 2026-03-03)

## Summary

We need true vSRX HA syntax compatibility for dual fabric interfaces (`fab0` + `fab1`) as seen in `vsrx.conf`.

Today bpfrx can parse interface stanzas for `fab0`/`fab1`, but core HA transport/data-plane still assumes a single fabric endpoint (`fabric-interface`/`fabric-peer-address`), which is not equivalent to vSRX dual-fabric behavior.

Reference doc added:
- `docs/next-features/vsrx-fabric-fab0-fab1-syntax-compat.md`

## Evidence in current code

- Single fabric in cluster config model:
  - `pkg/config/types.go` (`FabricInterface`, `FabricPeerAddress`)
- Chassis compile path reads one fabric transport tuple:
  - `pkg/config/compiler.go` (`fabric-interface`, `fabric-peer-address`)
- Runtime HA comms is single-fabric:
  - `pkg/daemon/daemon.go` (`startClusterComms`, `clusterTransportKey`, `populateFabricFwd` single iface/peer)
- CLI/Show model is single-fabric:
  - `pkg/cluster/cluster.go` (`InterfacesInput` has one `FabricInterface`)
  - `pkg/cli/cli.go` and `pkg/grpcapi/server.go` populate one value
- eBPF fabric forwarding state is singleton:
  - `bpf/headers/bpfrx_maps.h` (`fabric_fwd` map `max_entries = 1`)
- DPDK parity is singleton:
  - `dpdk_worker/shared_mem.h` (`fabric_port_id` scalar)
  - `pkg/dataplane/dpdk/dpdk_cgo.go` writes one fabric port
- Bond mode inconsistency in current fabric handling:
  - `pkg/dataplane/compiler.go` emits `active-backup`
  - `pkg/routing/routing.go` creates runtime bond as `802.3ad`

## Required architectural changes

1. Introduce multi-fabric HA transport model
- Replace single fabric fields with a list/struct model for fabric links.
- Preserve backward compatibility by mapping legacy single-fabric config into a one-link list.

2. Build a fabric transport manager
- Manage link health for `fab0` and `fab1`.
- Select active sync transport and fail over without cluster restart.
- Expose per-link health/counters.


*(truncated — 64 lines total)*


---

## #110 — HA private-rg-election: gate RG promotion on session sync readiness [CLOSED] (closed 2026-03-04)

## Problem
In `private-rg-election` (and `no-reth-vrrp`) mode, RG promotion can occur before session bulk-sync is complete. That creates takeover without full conntrack/NAT state and can drop established sessions during failover.

## Why this happens
- In reconcile readiness, VRRP readiness is forced to true when `isNoRethVRRP()` is true.
- `isNoRethVRRP()` returns true for both `NoRethVRRP` and `PrivateRGElection`.
- Election takeover gate (`SetRGReady` / `takeoverHoldTime`) therefore does not include sync readiness in private mode.
- Sync completion callback exists (`OnBulkSyncReceived`), but it only releases VRRP hold; private mode has no equivalent gating path.

## Code refs
- `pkg/daemon/daemon.go:4643`
- `pkg/daemon/daemon.go:4650`
- `pkg/daemon/daemon.go:5220`
- `pkg/cluster/election.go:217`
- `pkg/daemon/daemon.go:3812`

## Impact
- New primary may forward with incomplete synced state.
- Existing TCP flows can reset or blackhole briefly on failover.

## Expected behavior
In private RG election mode, promotion should be blocked until required sync readiness is met (or explicitly degraded with clear operator signal/timeout reason).

## Acceptance criteria
1. RG readiness in private mode includes sync readiness state (bulk sync done / sync connected policy).
2. Promotion is gated until readiness holds for configured takeover hold time.
3. If degraded-timeout fallback is allowed, reason is visible in status/logs.
4. Add regression test covering failover before/after bulk sync completion in private mode.


---

## #111 — HA mode check mismatch: startup sync-hold logic ignores private-rg-election semantics [CLOSED] (closed 2026-03-04)

## Problem
Startup sync-hold enablement logic is inconsistent with private election mode:
- Code enables VRRP sync-hold when `!cc.NoRethVRRP`.
- But private mode is also treated as no-RETH-VRRP elsewhere via `isNoRethVRRP()` (`NoRethVRRP || PrivateRGElection`).

This creates mode-dependent behavior drift and makes startup sequencing/error handling ambiguous in `private-rg-election`.

## Code refs
- `pkg/daemon/daemon.go:261`
- `pkg/daemon/daemon.go:5220`

## Impact
- Private election mode can take a different startup path than intended.
- Harder to reason about synchronization guarantees and readiness state.
- Can mask failover/session continuity bugs due to inconsistent gating semantics.

## Expected behavior
Mode checks should be consistent for all RETH VRRP-disabled modes (`NoRethVRRP` and `PrivateRGElection`), with explicit sync-gating behavior defined for private mode.

## Acceptance criteria
1. Replace inconsistent one-off checks with a single source of truth for mode behavior.
2. Define and document sync-hold/readiness behavior for private mode.
3. Add unit tests for startup behavior matrix:
   - default VRRP mode
   - `no-reth-vrrp`
   - `private-rg-election`


---

## #112 — private-rg-election gap: knob exists but no dedicated fast per-RG private advert protocol yet [CLOSED] (closed 2026-03-04)

## Problem
`private-rg-election` currently suppresses RETH VRRP, but there is no separate fast per-RG private advertisement/mastership protocol implemented yet.

Current implementation relies on existing heartbeat/election path only.

## Evidence in code
- Config knob exists: `private-rg-election`.
  - `pkg/config/ast.go:1478`
  - `pkg/config/compiler.go:6079`
- RETH VRRP is disabled for this mode.
  - `pkg/vrrp/vrrp.go:75`
- No `rg_advert`/private mastership transport implementation present.
- Heartbeat remains UDP 4784 path.
  - `pkg/cluster/heartbeat.go:15`
  - `pkg/daemon/daemon.go:3675`

## Impact
- Failover and split-brain resolution are heartbeat-timer bound in private mode.
- Session continuity during transient control-link disturbances can be worse than expected versus fast VRRP contention resolution.

## Expected behavior
Either:
1. Implement the private per-RG advertisement/mastership protocol (control-link unicast), or
2. Explicitly document that `private-rg-election` is currently a mode alias for direct VIP ownership on heartbeat election only, with current timing/risks.

## Acceptance criteria
1. Add clear runtime status/CLI indicator for active election mechanism.
2. If protocol is implemented:
   - per-RG advertisement sender/receiver on control link
   - deterministic dual-active resolution based on advertised state/priority/tie-break
   - tests for transient split and convergence timing
3. If protocol is not implemented yet:
   - update docs/config help to avoid misleading expectation.


---

## #113 — HA dual-active resolution: add winner-side ownership reaffirm (GARP/NA) [CLOSED] (closed 2026-03-04)

## Problem
When non-preempt dual-active is resolved by making one node yield, only the yielding node necessarily emits transition side-effects. The winning node can remain primary without an explicit ownership reaffirm (GARP/NA burst), leaving stale upstream ARP/NDP state longer than necessary.

## Code refs
- Dual-active resolution logic:
  - `pkg/cluster/election.go:161`
  - `pkg/cluster/election.go:163`
- Events are emitted only on local state change:
  - `pkg/cluster/election.go:239`
- GARP/NA in direct mode is tied to local primary transition paths:
  - `pkg/daemon/daemon.go:4379`
  - `pkg/daemon/daemon.go:4751`

## Impact
- Possible longer convergence of upstream neighbor caches after split/merge.
- Transient packet loss or asymmetric forwarding can persist after state converges.

## Expected behavior
On detected dual-active resolution, ensure the winner can proactively reaffirm ownership (rate-limited GARP/NA/probe), even if winner's state did not change.

## Acceptance criteria
1. Add a safe trigger path for winner-side ownership reaffirm on dual-active resolution.
2. Ensure reaffirm is rate-limited to avoid GARP storms.
3. Add test coverage for dual-active resolve path verifying both:
   - loser demotes,
   - winner ownership reaffirm is emitted exactly once (or within configured damping window).


---

## #114 — HA: move session/config sync transport to control link (fxp1) [CLOSED] (closed 2026-03-04)

## Problem
Session/config sync currently runs over the fabric interfaces (`fab0` / optional `fab1`) on port 4785, not over the control link.

In HA operation, this couples critical control-plane state convergence (session sync/config sync failover continuity) to fabric link health and fabric data-plane behavior.

## Current behavior (code refs)
- Heartbeat/election uses control link (`control-interface` + `peer-address`) on UDP 4784:
  - `pkg/daemon/daemon.go:3675`
  - `pkg/cluster/heartbeat.go:15`
- Session sync uses fabric addresses on 4785:
  - `pkg/daemon/daemon.go:3733`
  - `pkg/daemon/daemon.go:3734`
  - `pkg/daemon/daemon.go:3767`
  - `pkg/daemon/daemon.go:3769`
- Docs reflect fabric transport:
  - `docs/sync-protocol.md:8`

## Requested change
Move session/config sync transport to the control link (`control-interface`/`peer-address`) so HA control-plane liveness and state convergence share the same dedicated control path.

## Why
- Reduces dependence on fabric path behavior for control-plane state continuity.
- Aligns with architecture intent: control traffic on control link, data-plane forwarding on fabric.
- Simplifies failure-domain reasoning during failover testing.

## Acceptance criteria
1. Session/config sync can bind/connect over control link addresses (primary mode).
2. Existing fabric-based mode remains optional or is explicitly deprecated with migration path.
3. CLI/status exposes active sync transport (control vs fabric).
4. Test coverage for failover continuity with control-link sync (including link flap/restart cases).
5. Update docs (`sync-protocol.md`, HA docs) to match behavior.


---

## #115 — HA private-rg-election: include VIP ownership in takeover readiness gate [CLOSED] (closed 2026-03-04)

## Problem
In `private-rg-election` / `no-reth-vrrp` mode, takeover readiness only checks interface monitors and treats VRRP readiness as always true. It does **not** validate that VIP ownership can actually be established (VIP add success / VIP present on interfaces).

A node can be elected primary (`rg_active=true`) while VIP add is failing or delayed, causing traffic to fail after failover.

## Code refs
- Readiness path:
  - `pkg/daemon/daemon.go:4643`
  - `pkg/daemon/daemon.go:4650`
- Promotion side effects (direct VIP add after election):
  - `pkg/daemon/daemon.go:4382`
  - `pkg/daemon/daemon.go:4751`
- Mode alias:
  - `pkg/daemon/daemon.go:5220`

## Impact
- Primary role can be asserted before dataplane entry point (VIP ownership) is actually in place.
- Long-lived and new flows may blackhole during/after failover.

## Expected behavior
In private mode, RG readiness should include a VIP ownership preflight/verification signal (or fail/hold until VIPs are present).

## Acceptance criteria
1. Add private-mode readiness component that verifies required VIPs are installable/present.
2. Block promotion until VIP readiness is true for hold-time duration.
3. Surface readiness reason in cluster status when blocked by VIP ownership failure.
4. Add regression test where VIP add initially fails (interface not ready), then recovers without permanent failover outage.


---

## #116 — HA regression: chained hard-reset failover (fw0 crash/rejoin -> fw1 crash) stalls recovery [CLOSED] (closed 2026-03-04)

## Problem
Current HA coverage does not include a chained hard-reset scenario that mirrors field failures:
1. fw0 primary, long-running iperf flow active
2. hard reset fw0 (`echo b > /proc/sysrq-trigger`), failover to fw1
3. fw0 returns, rejoins/syncs as secondary
4. hard reset fw1, traffic should fail over back to fw0

Reported behavior: second failover can stall and traffic does not recover.

## Why this matters
This is a realistic HA sequence for panic/reboot events. Passing one-direction failover is insufficient if reverse failover after rejoin fails.

## Related areas in code
- Cluster heartbeat/election and timeout promotion:
  - `pkg/cluster/heartbeat.go`
  - `pkg/cluster/election.go`
- Direct VIP ownership paths (private mode):
  - `pkg/daemon/daemon.go:4379`
  - `pkg/daemon/daemon.go:4408`
  - `pkg/daemon/daemon.go:4747`
- Session sync reconnect/bulk sync:
  - `pkg/daemon/daemon.go:3812`
  - `pkg/cluster/sync.go`

## Requested change
Add automated HA regression test for chained hard-reset failover/failback with long-lived traffic, and gate releases on it.

## Acceptance criteria
1. Add reproducible test harness/script for chained crash sequence (fw0 crash -> recover -> fw1 crash).
2. Include traffic continuity assertions for:
   - established long-lived TCP flow behavior
   - new connection recovery behavior after second crash
3. Capture and assert cluster status transitions and sync status during each phase.
4. Test runs in CI/nightly or documented stress target.


---

## #117 — HA session-sync: concurrent bulk writers can interleave epochs and trigger false stale deletes [CLOSED] (closed 2026-03-04)

## Problem
`SessionSync.BulkSync()` is not serialized as a transaction. It is invoked from both connection paths:

- `acceptLoop()` calls `BulkSync()` (`pkg/cluster/sync.go:673`)
- `connectLoop()` calls `BulkSync()` (`pkg/cluster/sync.go:742`)

Within `BulkSync()`, each frame write takes and releases `writeMu` per message (`pkg/cluster/sync.go:549-551`, `567-569`, `591-593`, `606-608`).

That means two concurrent `BulkSync()` calls (or `BulkSync()` + `sendLoop`) can interleave frame sequences on the same TCP stream, e.g.:

- `BulkStart(A)`
- `BulkStart(B)`
- sessions from A/B interleaved
- `BulkEnd(A)` / `BulkEnd(B)`

Receiver state is single-global (`bulkInProgress`, `bulkRecvV4`, `bulkRecvV6`) in `handleMessage()` (`pkg/cluster/sync.go:1009-1017`) and stale reconciliation runs on each `BulkEnd` (`pkg/cluster/sync.go:1020-1023`).

## HA impact
Interleaved bulk epochs can produce non-authoritative `bulkRecv*` sets and trigger false stale deletion during `reconcileStaleSessions()`, causing random flow drops around failover/rejoin.

## Proposal
1. Enforce one active bulk transfer per connection (transaction lock/state machine).
2. Add bulk epoch ID in `BulkStart/BulkEnd`; ignore stale/mismatched `BulkEnd`.
3. Optionally pause incremental send-path frames while bulk is in progress (or sequence them through one ordered stream with explicit epoch boundaries).
4. Add stress tests that intentionally race `acceptLoop`/`connectLoop` bulk triggers and verify no interleaving-induced stale deletes.

## Acceptance criteria
- At most one active bulk epoch is processed per connection.
- Receiver never reconciles stale sessions from mixed/interleaved bulk sets.
- Reconnect/failover stress test shows stable session continuity.


---

## #118 — HA session-sync: stale reconciliation should use BulkStart ownership snapshot [CLOSED] (closed 2026-03-04)

## Problem
Stale-session reconciliation scopes deletions using *current* ownership at `BulkEnd` time:

- `reconcileStaleSessions()` checks `ShouldSyncZone(val.IngressZone)` while deleting stale entries (`pkg/cluster/sync.go:1113`, `1147`).

`ShouldSyncZone()` depends on live RG primary state (`pkg/cluster/sync.go:318-333`). If RG ownership changes between `BulkStart` and `BulkEnd`, reconciliation scope no longer matches the ownership context that existed when the bulk transfer began.

## HA impact
During failover/recovery churn, a mid-bulk RG transition can:

- delete sessions that should now be locally authoritative, or
- skip deleting peer-owned stale sessions.

Both cases can surface as transient random drops or sticky stale state after role transitions.

## Proposal
1. Snapshot zone/RG ownership context at `syncMsgBulkStart`.
2. Use that snapshot (not live `ShouldSyncZone`) during `reconcileStaleSessions()`.
3. If ownership changes materially before `BulkEnd`, abort reconcile for that epoch and require a fresh bulk.
4. Add unit tests that flip `IsPrimaryForRGFn` results between `BulkStart` and `BulkEnd`.

## Acceptance criteria
- Reconcile decisions are deterministic for a given bulk epoch.
- Ownership flips during a bulk do not cause false stale deletes.
- Tests cover ownership-flip-in-bulk behavior for both v4/v6.


---

## #119 — HA session-sync: delete/session deltas are dropped while disconnected with no replay journal [CLOSED] (closed 2026-03-04)

## Problem
Incremental session updates are best-effort and silently dropped when disconnected:

- `queueMessage()` returns false immediately when `Connected=false` (`pkg/cluster/sync.go:420-423`).
- `QueueDeleteV4/V6()` and `QueueSessionV4/V6()` do not persist or retry dropped messages (`pkg/cluster/sync.go:440-460`).

`syncSweep()` can replay *new sessions* via Created-time window, but there is no equivalent replay path for missed deletes during disconnect windows.

## HA impact
If the active node is disconnected from peer sync and sessions age out/delete locally, the standby can retain stale tuples until a later full bulk + reconcile. In crash/failover windows before that reconcile, stale state can interfere with takeover continuity.

## Proposal
1. Add a bounded delete-journal (or generic delta journal) that survives transient disconnects and flushes on reconnect.
2. Trigger immediate post-reconnect delta flush before/with bulk sync.
3. Add metrics for dropped queued updates by message type (`session_v4/v6`, `delete_v4/v6`).
4. Add tests for disconnect -> deletes happen -> reconnect -> standby converges without waiting for periodic full-cycle cleanup.

## Acceptance criteria
- Delete events generated while disconnected are eventually delivered or explicitly reconciled on reconnect.
- No silent permanent loss of delete deltas.
- Convergence latency after reconnect is bounded and observable.


---

## #120 — cluster/session-sync: Stats() copies atomic fields (go vet copylocks failure) [CLOSED] (closed 2026-03-04)

## Problem
`SessionSync.Stats()` returns `SyncStats` by value:

- `func (s *SessionSync) Stats() SyncStats { return s.stats }` (`pkg/cluster/sync.go:196-198`)

`SyncStats` embeds `sync/atomic` typed fields, which must not be copied after first use.

`go vet` reports:

```
pkg/cluster/sync.go:197:9: return copies lock value: github.com/psaab/bpfrx/pkg/cluster.SyncStats contains sync/atomic.Uint64 contains sync/atomic.noCopy
```

## Impact
This is undefined/unsupported usage of atomic wrappers and can lead to subtle correctness hazards in stats reads, plus persistent vet failures.

## Proposal
1. Change API to avoid copying atomic fields (e.g. return pointer to internal stats, or return a plain snapshot struct with primitive values).
2. Update `SyncStatsProvider` and callers (`pkg/cluster/cluster.go`) accordingly.
3. Add/keep vet in CI for this package to prevent regressions.

## Acceptance criteria
- `go vet ./pkg/cluster/...` is clean.
- No code path copies structs containing atomic typed fields.
- Stats callers still get consistent read-only values.


---

## #121 — fabric: clear stale fabric_fwd entry when fab0/fab1 neighbor or link goes invalid [CLOSED] (closed 2026-03-06)

## Problem
`refreshFabricFwd()` / `refreshFabricFwd1()` return `false` when the fabric link disappears or the peer neighbor entry is missing, but they never write a zeroed `FabricFwdInfo` back to the dataplane.

Because `try_fabric_redirect()` and `try_fabric_redirect_with_zone()` always prefer key `0` (`fab0`) when `ifindex != 0`, a once-valid `fab0` entry can remain armed indefinitely after the path dies. The dataplane keeps redirecting traffic into dead `fab0` instead of falling back to `fab1`.

## Code
- `pkg/daemon/daemon.go:4183`
- `pkg/daemon/daemon.go:4312`
- `bpf/headers/bpfrx_helpers.h:1962`
- `bpf/headers/bpfrx_helpers.h:2019`

## Impact
- existing-session fabric redirect can blackhole after a fabric flap
- new-connection zone-encoded fabric redirect can blackhole the same way
- dual-fabric fallback is ineffective when stale `fab0` state survives

## Suggested fix
On any hard failure that invalidates a fabric path (link missing/down, neighbor unresolved, interface removed), explicitly write `FabricFwdInfo{Ifindex:0}` for that key so the dataplane can fall back to the other fabric or stop redirecting.

---

## #122 — fabric: refreshFabricFwd programs dead links because it never checks oper-state [CLOSED] (closed 2026-03-06)

## Problem
`refreshFabricFwd()` and `refreshFabricFwd1()` only verify that the interface exists and has a MAC address. They do not verify `OperState`, carrier, or administrative up/down state before publishing the path into `fabric_fwd`.

If the kernel still has a stale ARP/NDP entry for the peer, the code can keep publishing a dead fabric interface as redirect-capable. Combined with the hard preference for `fab0`, this creates avoidable blackholes.

## Code
- `pkg/daemon/daemon.go:4183`
- `pkg/daemon/daemon.go:4312`

## Impact
- redirect path may stay pinned to a dead fabric interface
- dual-fabric failover can be delayed or bypassed entirely

## Suggested fix
Treat non-UP / no-carrier fabric interfaces as invalid and clear the corresponding `fabric_fwd` entry. Consider rejecting `OperUnknown` too unless there is a strong reason to trust it for these HA links.

---

## #123 — dual-fabric session sync uses one replaceable conn and can flap between fab0/fab1 [CLOSED] (closed 2026-03-06)

## Problem
`NewDualSessionSync()` exposes two peer addresses, but the runtime still models sync as a single mutable `s.conn` plus a single `Connected` bit. Any inbound or outbound connection on either fabric closes and replaces the current connection.

There is no notion of preferred active path, no stickiness to `fab0`, and no protection against reconnect races where both links are healthy but different goroutines replace each other.

## Code
- `pkg/cluster/sync.go:645`
- `pkg/cluster/sync.go:679`
- `pkg/cluster/sync.go:1179`

## Impact
- unnecessary disconnect/reconnect churn on dual-fabric clusters
- repeated bulk syncs after harmless reconnect races
- HA status cannot tell which physical fabric is actually carrying sync

## Suggested fix
Track per-fabric connections explicitly and pick an active transport with deterministic preference/failover rules instead of replacing a single global conn opportunistically.

---

## #124 — fabric: no event-driven refresh on link/neigh changes leaves up to 30s redirect blackholes [CLOSED] (closed 2026-03-06)

## Problem
The fabric forwarding cache is refreshed immediately at startup, then on a 30 second ticker. `RefreshFabricFwd()` is documented for link-state and neighbor changes, but I only found it called from HA failover / VRRP transitions. There is no netlink subscription or neighbor-change trigger for fabric health.

That means a dead `fab0` can remain programmed for up to 30 seconds even if `fab1` is healthy.

## Code
- `pkg/daemon/daemon.go:4136`
- `pkg/daemon/daemon.go:4297`
- `pkg/daemon/daemon.go:4383`
- callers only in `pkg/daemon/daemon.go:4539`, `:4684`, `:4705`

## Impact
- transient or sustained fabric failures create long redirect blackholes
- dual-fabric failover is much slower than necessary

## Suggested fix
Add netlink-driven refresh for fabric link and neighbor state changes, and use the periodic timer only as a safety net.

---

## #125 — dual-fabric: peer gRPC/monitor path is still single-address and does not fail over to fab1 [CLOSED] (closed 2026-03-06)

## Problem
The new dual-fabric work only dual-homes session sync. Peer RPC/monitor access is still single-address:
- daemon stores one `syncPeerAddr`
- fabric gRPC listener starts only on the primary sync IP
- peer dialing uses one `FabricPeerAddrFn`

If session sync fails over to `fab1` but `fab0` is down, peer monitor / CLI proxy RPCs can still target dead `fab0`.

## Code
- `pkg/daemon/daemon.go:3910`
- `pkg/daemon/daemon.go:3914`
- `pkg/grpcapi/server.go:71`
- `pkg/grpcapi/server.go:8493`
- `pkg/cli/cli.go:143`

## Impact
- cluster peer queries fail even when dual-fabric sync recovered
- operator visibility during failover is worse exactly when needed most

## Suggested fix
Make the peer RPC path dual-address-aware, with listener/dial fallback aligned to the active sync transport or independent failover logic.

---

## #126 — dpdk: fabric redirect support is only partial; no DPDK equivalent of try_fabric_redirect found [CLOSED] (closed 2026-03-06)

## Problem
The Go dataplane layer now exposes `UpdateFabricFwd()` / `UpdateFabricFwd1()` for DPDK and writes `fabric_port_id` / `fabric1_port_id`. In the DPDK worker, I found those IDs used for validating incoming zone-encoded fabric traffic, but I did not find a DPDK equivalent of the BPF `try_fabric_redirect()` / `try_fabric_redirect_with_zone()` helpers that actually perform cross-chassis redirect.

## Code
- `pkg/dataplane/dpdk/dpdk_cgo.go:1164`
- `pkg/dataplane/dpdk/dpdk_cgo.go:1185`
- `dpdk_worker/zone.c:42`
- BPF reference behavior: `bpf/headers/bpfrx_helpers.h:1962` and `:2019`

## Impact
- DPDK HA behavior appears materially behind eBPF for fabric redirect
- dual-fabric / active-active expectations may be wrong when dataplane=`dpdk`

## Suggested fix
Either implement real DPDK fabric redirect parity or explicitly mark the feature unsupported in DPDK mode so HA testing does not assume it works.

---

## #127 — fabric IPVLAN: existing fab0/fab1 overlay skips address reconciliation on reapply [CLOSED] (closed 2026-03-06)

## Problem
`ensureFabricIPVLAN()` returns immediately when the IPVLAN already exists on the correct parent. In that path it only brings the link up and never reconciles addresses.

This means fabric IP changes can leave stale addresses on `fab0`/`fab1` until some later networkd action happens to correct them. Because session sync startup resolves `syncIface` addresses directly from `fab0`/`fab1`, the daemon can observe and use stale fabric addresses during startup/redeploy.

## Code
- `pkg/daemon/daemon.go:1474`
- `pkg/daemon/daemon.go:4175`
- early return without address reconciliation at `pkg/daemon/daemon.go:4188`
- sync transport resolves overlay address at `pkg/daemon/daemon.go:3920`

## Impact
- stale fabric IPs can survive reapply
- sync/gRPC listeners may bind the wrong address after config changes
- failover testing becomes nondeterministic after repeated deploys

## Suggested fix
When the IPVLAN already exists on the correct parent, reconcile its address set instead of returning immediately. Also remove stale addresses no longer present in config.

---

## #128 — fabric IPVLAN: stale fab0/fab1 overlays are never cleaned up when config changes [CLOSED] (closed 2026-03-06)

## Problem
The new fabric overlay path added `CleanupFabricIPVLANs()`, but I did not find any caller. `applyConfig()` creates `fab0`/`fab1` IPVLAN interfaces when `LocalFabricMember` is set, but there is no symmetric cleanup when the config switches away from IPVLAN fabric mode or removes one of the fabric interfaces.

## Code
- creation in `pkg/daemon/daemon.go:1474`
- cleanup helper defined in `pkg/daemon/daemon.go:4236`
- no callers found for `CleanupFabricIPVLANs()`

## Impact
- stale `fab0`/`fab1` links can survive config changes
- old fabric IPs and VRF bindings can leak into later HA runs
- status and troubleshooting become misleading because orphaned overlays still exist

## Suggested fix
Call cleanup during config transitions and/or reconcile the exact desired overlay set declaratively so removed fabric overlays are deleted automatically.

---

## #129 — fabric IPVLAN: populateFabricFwd probes ARP/NDP on parent while fabric IP lives on overlay [CLOSED] (closed 2026-03-06)

## Problem
The new overlay design puts the sync IP on `fab0`/`fab1` (IPVLAN child), but `startClusterComms()` now resolves `fabric_fwd` against the physical parent via `resolveFabricParent()`. `probeFabricNeighbor()` and `refreshFabricFwd()` then run `ping -I <parent>` and `netlink.NeighList(parentIfindex, ...)` against the parent device.

That is a risky mismatch: the L3 identity lives on the IPVLAN child, not the parent. If ARP/NDP state is associated with the child interface, active probing and neighbor discovery on the parent will not populate `fabric_fwd` reliably.

## Code
- sync transport binds overlay address from `fab0`/`fab1`: `pkg/daemon/daemon.go:3920`
- `fabric_fwd` population switched to parent: `pkg/daemon/daemon.go:4114`
- parent resolution: `pkg/daemon/daemon.go:4248`
- neighbor probe on chosen interface: `pkg/daemon/daemon.go:4149`
- neighbor lookup on chosen interface: `pkg/daemon/daemon.go:4180`

## Impact
- peer MAC learning can fail or become timing-dependent in IPVLAN fabric mode
- `fabric_fwd` may never populate even though session sync is up on the overlay
- active/active and failback redirect paths can blackhole after the fabric redesign

## Suggested fix
Revisit the overlay/parent split explicitly: either learn neighbors from the overlay interface and translate to the parent for dataplane redirect, or prove that ARP/NDP state is guaranteed to exist on the parent in this topology and add tests for it.

---

## #130 — compiler: vSRX fab0/fab1 auto-detect still collapses to a single runtime fabric interface [CLOSED] (closed 2026-03-06)

## Problem
The new fabric syntax support resolves `LocalFabricMember` for `fab0`/`fab1`, but auto-detection only fills `Cluster.FabricInterface`. It never auto-populates `Fabric1Interface`, and the parser tests explicitly encode that node0 gets `FabricInterface=fab0` with `Fabric1Interface=""`.

That means a `vsrx.conf`-style config with both `fab0` and `fab1` defined still compiles into a single-fabric runtime unless the operator also uses the custom `fabric1-interface` knob.

## Code
- auto-detect logic in `pkg/config/compiler.go:140`
- only `FabricInterface` is populated at `pkg/config/compiler.go:160`
- parser test codifies single-fabric result at `pkg/config/parser_test.go:15700`

## Impact
- vSRX-compatible `fab0` + `fab1` syntax is only partially honored
- dual-fabric runtime paths (`Fabric1Interface`, dual sync transport, secondary `fabric_fwd`) remain disabled in auto-detected configs
- operators can think both fabrics are active when the runtime is still single-fabric

## Suggested fix
Either auto-populate both runtime fabric slots from `fab0`/`fab1` syntax, or reject/flag the config loudly so the operator knows the second fabric is not actually active.

---

## #131 — HA session-sync: established flows are never refreshed after SESSION_OPEN [CLOSED] (closed 2026-03-06)

The current HA session-sync path only replicates session state when the flow opens, plus bulk sync on reconnect. Long-running flows can sit on the standby with stale TCP state / timeout / last-seen until failover.

Why this matters:
- A long-running `iperf3` stream can be created long before an RG move.
- The standby may still hold the opening snapshot of the session instead of the current state when takeover happens.
- That is the wrong model for stateful failover; established flows need refresh, not just create-time replication.

Code evidence:
- Near-real-time sync only fires on `SESSION_OPEN` in `pkg/daemon/daemon.go:425-468`.
- The periodic sweep only sends sessions whose `Created >= lastSweepTime`, so it replays newly-created sessions, not already-established ones: `pkg/cluster/sync.go:516-550`.
- Bulk sync is reconnect-driven (`pkg/cluster/sync.go:747-829`), so normal RG moves do not trigger a fresh full transfer.
- The wire format carries `TCPState`, `LastSeen`, and `Timeout`, but those values are only refreshed when a session is sent at open/bulk time: `pkg/cluster/sync.go:1560-1708`, `pkg/cluster/sync.go:1775-1945`.

Likely impact:
- Standby can retain pre-established TCP state (for example `SYN_SENT` / `SYN_RECV`) for flows that are actually deep into an `ESTABLISHED` transfer.
- Standby also misses updated inactivity timestamps and timeout adjustments for already-running flows.

Suggested fix direction:
- Add incremental update replication for existing sessions, not just create/delete.
- At minimum, periodically resync active forward sessions based on `LastSeen` or recent packet activity rather than `Created`.
- Include a test that starts a long-lived TCP flow, waits well past session creation, moves the RG, and verifies the stream survives.


---

## #132 — HA rg_active: a redundancy group becomes active when any VRRP instance flips MASTER [CLOSED] (closed 2026-03-06)

`rg_active` is currently group-wide, but the state machine marks the whole RG active as soon as any one RETH VRRP instance in that RG becomes MASTER.

Why this matters:
- A redundancy group can own multiple RETH interfaces.
- During failover, one interface can reach MASTER before the others.
- The daemon then removes blackhole routes and enables `rg_active` for the whole RG even though some member interfaces are still BACKUP.
- That can expose partially-transitioned ownership and break in-flight traffic during RG moves.

Code evidence:
- The RG state machine derives desired active state from `anyMasterLocked()`, not all-master, in both normal and strict modes: `pkg/daemon/rg_state.go:199-205`.
- `watchVRRPEvents()` updates `rg_active` and removes blackholes immediately on the first MASTER event for the RG: `pkg/daemon/daemon.go:5017-5043`.
- The codebase already distinguishes ALL-master for some per-RG decisions via `AllVRRPMaster()` / `snapshotRethMasterState()`, which shows the difference is intentional elsewhere: `pkg/daemon/daemon.go:4784-4799`.

Likely impact:
- The dataplane can start treating the RG as locally active before every interface in that RG is actually owned here.
- Cross-chassis redirect suppression then happens too early for interfaces still transitioning.

Suggested fix direction:
- Either make RG activation require all relevant VRRP instances to be MASTER before clearing blackholes for that RG,
- or move from group-wide `rg_active` to interface/subnet ownership so partially transitioned RGs are represented accurately.
- Add a test with an RG containing multiple RETH interfaces whose MASTER events arrive at different times.


---

## #133 — private-rg-election: sync readiness is never reset for a fresh peer rejoin [CLOSED] (closed 2026-03-06)

In private-RG / no-RETH-VRRP mode, `syncReady` is used as the readiness gate for takeover, but it appears to be latched true forever after the first successful bulk sync (or startup timeout).

Why this matters:
- A node can reconnect to a peer, or a peer can reboot and rejoin, without requiring a fresh bulk sync before takeover is allowed again.
- That defeats the point of the readiness gate and can let a node become primary on stale session state.

Code evidence:
- `SetSyncReady()` is the only setter and just flips the global bool: `pkg/cluster/cluster.go:184-193`.
- Current call sites I found only ever set it to true:
  - startup timeout fallback in `pkg/daemon/daemon.go:307-308`
  - bulk-sync completion in `pkg/daemon/daemon.go:4064-4068`
- I did not find any `SetSyncReady(false)` path on sync disconnect, cluster comms restart, or peer reconnect.

Suggested fix direction:
- Reset `syncReady=false` whenever the sync transport fully disconnects or cluster comms are restarted.
- Only release it again after a fresh `BulkEnd` (or an explicit timeout decision for that reconnect cycle).
- Ideally track readiness per reconnect epoch instead of as a one-way global latch.


---

## #134 — cluster: takeover hold timer is edge-triggered and may never promote when the timer expires [CLOSED] (closed 2026-03-06)

The takeover readiness gate checks elapsed hold time during election, but election is only re-run when readiness changes or some unrelated cluster event happens. There is no timer-driven re-evaluation when `ReadySince + takeoverHoldTime` is reached.

Why this matters:
- An RG can become ready, fail the hold-time check, and then stay secondary indefinitely.
- Promotion only happens later if some other event happens to kick election again.
- During planned RG moves this can look like traffic blackholing until an unrelated heartbeat/monitor update arrives.

Code evidence:
- `SetRGReady()` only triggers re-election when the boolean flips (`wasReady != ready`): `pkg/cluster/cluster.go:220-255`.
- The actual hold-time gate is checked inside election with `IsReadyForTakeover(m.takeoverHoldTime)`: `pkg/cluster/election.go:213-224`.
- I do not see any timer or scheduler that re-runs election at hold expiry.

Suggested fix direction:
- Schedule a per-RG election wakeup for `ReadySince + takeoverHoldTime`.
- Or run a lightweight periodic election tick while an RG is ready-but-still-held.
- Add a regression test that sets an RG ready once, waits past the hold time without any other events, and verifies promotion happens automatically.


---

## #135 — monitor interface: fab0/fab1 samples the IPVLAN overlay instead of the physical fabric parent [CLOSED] (closed 2026-03-06)

`monitor interface fab0` / `fab1` does not reflect actual wire-level fabric forwarding after the fabric IPVLAN rework.

Why this matters:
- The HA dataplane forwards cross-chassis traffic on the physical fabric member.
- `fab0`/`fab1` are now IPVLAN overlays used for IP addressing/session-sync.
- Operators expect `monitor interface fab0/fab1` to reflect what is actually going across the fabric link.
- Today it mostly reports overlay/control traffic instead of the physical fabric dataplane.

Code evidence:
- The daemon creates `fab0`/`fab1` as IPVLAN L2 overlays and states that BPF attaches to the parent: `pkg/daemon/daemon.go:1501-1503`, `pkg/daemon/daemon.go:4219-4222`.
- The fabric forwarding path explicitly resolves the physical parent because BPF runs there: `pkg/daemon/daemon.go:4155-4159`, `pkg/daemon/daemon.go:4292-4303`.
- The monitor CLI samples the literal kernel interface name returned from `config.LinuxIfName(cfgName)` with no fabric-parent remap: `pkg/cli/monitor_interface.go:30-45`, `pkg/cli/monitor_interface.go:162-175`.
- The gRPC monitor backend does the same: `pkg/grpcapi/server.go:8658-8677`.

Impact:
- `monitor interface fab0/fab1` is not a trustworthy view of actual fabric forwarding load.
- The output blends overlay/control-plane interface semantics with physical-wire dataplane expectations.

Suggested fix direction:
- For fabric interfaces, decide on one semantic and implement it consistently:
  - either map `fab0`/`fab1` monitor requests to the resolved physical parent for wire-level stats,
  - or explicitly expose separate overlay vs parent monitoring views.
- Update both CLI and gRPC monitor paths together.


---

## #136 — monitor traffic interface fab0/fab1 captures the overlay, not the wire-level fabric path [CLOSED] (closed 2026-03-06)

`monitor traffic interface fab0` / `fab1` currently hands the literal interface name to `tcpdump`, which does not match the post-IPVLAN fabric dataplane model.

Why this matters:
- After the fabric IPVLAN change, `fab0`/`fab1` are overlays used for fabric IP addressing.
- Cross-chassis forwarding in XDP uses the physical parent/member interface.
- Operators using `monitor traffic interface fab0` expect to see the packets actually traversing the fabric link.
- Today they mainly see overlay/session-sync/control-plane traffic, not all dataplane-forwarded packets.

Code evidence:
- `monitor traffic` passes the requested interface name directly to `tcpdump`: `pkg/cli/cli.go:10510-10518`.
- `fab0`/`fab1` are created as IPVLAN overlays: `pkg/daemon/daemon.go:1501-1503`, `pkg/daemon/daemon.go:4219-4222`.
- Fabric forwarding resolves and uses the parent/member device, not the overlay: `pkg/daemon/daemon.go:4155-4159`, `pkg/daemon/daemon.go:4292-4303`.

Impact:
- Packet captures on `fab0`/`fab1` can be misleading during HA troubleshooting.
- An operator may conclude traffic is not using the fabric when it is actually leaving on the parent device.

Suggested fix direction:
- Decide whether `monitor traffic interface fab0/fab1` should mean overlay capture or wire capture.
- If the intended semantic is wire-level monitoring, resolve fabric interfaces to their physical parent before invoking `tcpdump`.
- If both are valuable, add an explicit overlay/parent selector and document the distinction.


---

## #137 — fabric redirect: try_fabric_redirect paths never update per-interface TX counters [CLOSED] (closed 2026-03-06)

Fabric-redirected packets increment the global fabric redirect counter, but they do not increment `interface_counters` TX stats for the egress fabric device.

Why this matters:
- `monitor interface`, `show interfaces`, and any other interface-stat consumers use `ReadInterfaceCounters()` as the authoritative BPF packet/byte counters.
- Cross-chassis forwarded traffic can therefore be under-reported or appear missing even when the dataplane is actively redirecting packets over the fabric.

Code evidence:
- Per-interface TX accounting exists via `inc_iface_tx()`: `bpf/headers/bpfrx_helpers.h:782-786`.
- Normal forward path uses it in `xdp_forward`: `bpf/xdp/xdp_forward.c:171-173`, `bpf/xdp/xdp_forward.c:225-228`.
- The fabric redirect helpers do not call it; they only bump `GLOBAL_CTR_FABRIC_REDIRECT` before `bpf_redirect_map(...)`: `bpf/headers/bpfrx_helpers.h:1981-1995`, `bpf/headers/bpfrx_helpers.h:2046-2058`.
- Userspace readers prefer these BPF interface counters for monitor/show output: `pkg/cli/monitor_interface.go:37-44`, `pkg/grpcapi/server.go:8671-8677`, `pkg/dataplane/maps.go:788-804`.

Impact:
- Even if an operator monitors the correct physical fabric device, the BPF stats path still undercounts redirected traffic.
- This makes HA/fabric troubleshooting misleading.

Suggested fix direction:
- Update both `try_fabric_redirect()` and `try_fabric_redirect_with_zone()` to increment per-interface TX counters (and any other relevant egress accounting) for the selected fabric device before redirect.
- Add a regression test that drives fabric redirect and verifies the interface counter for the chosen fabric link increments.


---

## #138 — fabric observability: tcpdump/monitor traffic is not a reliable view of XDP fabric redirects [CLOSED] (closed 2026-03-06)

When active/active HA is split across nodes, cross-chassis forwarding uses the XDP fabric redirect path. Operators naturally reach for `tcpdump` / `monitor traffic`, but that is not a reliable visibility point for these packets.

Why this matters:
- In the split-RG case, traffic can be crossing the fabric even when `tcpdump` on the named fabric interface shows nothing.
- This makes HA troubleshooting misleading and encourages chasing forwarding bugs that are really observability bugs.

Code evidence:
- Cross-chassis forwarding uses `try_fabric_redirect()` / `try_fabric_redirect_with_zone()` and returns `bpf_redirect_map(...)` directly: `bpf/headers/bpfrx_helpers.h:1981-1995`, `bpf/headers/bpfrx_helpers.h:2046-2058`.
- `monitor traffic` is just a thin wrapper around `tcpdump`: `pkg/cli/cli.go:10480-10528`.
- Fabric interfaces are now IPVLAN overlays for addressing, while the actual dataplane runs on the physical parent/member: `pkg/daemon/daemon.go:1501-1503`, `pkg/daemon/daemon.go:4155-4159`, `pkg/daemon/daemon.go:4219-4222`.
- Repo performance docs explicitly describe the fast path as native XDP + `ndo_xdp_xmit` -> `bpf_redirect_map`: `docs/optimizations.md:17-26`.

Inference from the above:
- The fabric dataplane is using an XDP redirect fast path, while the operational capture tooling relies on packet-socket capture (`tcpdump`).
- That combination does not provide trustworthy on-box visibility for redirected fabric traffic.

Suggested fix direction:
- Add an explicit on-box fabric trace/telemetry mechanism for XDP redirects instead of relying on `tcpdump` semantics.
- At minimum, document that `tcpdump` / `monitor traffic` is not authoritative for XDP fabric redirects.
- Longer term, add redirect trace events or counters keyed by redirect reason/link.


---

## #139 — fabric observability: no per-link redirect counters or trace events for fab0 vs fab1 [CLOSED] (closed 2026-03-06)

The current fabric redirect telemetry is too coarse to debug active/active split-RG behavior. There is only a single global fabric redirect counter, and no per-link trace telling operators whether packets used fab0 or fab1.

Why this matters:
- When one RETH is primary on node0 and another on node1, operators need to know whether traffic is actually traversing the fabric and which link carried it.
- Today, even after fixing interface counter accounting, there is still no fabric-specific telemetry that answers "did this go over fab0 or fab1, and why?"

Code evidence:
- The redirect helpers increment only one global counter, `GLOBAL_CTR_FABRIC_REDIRECT`, for both fab0 and fab1: `bpf/headers/bpfrx_helpers.h:1985`, `bpf/headers/bpfrx_helpers.h:1993`, `bpf/headers/bpfrx_helpers.h:2049`, `bpf/headers/bpfrx_helpers.h:2056`.
- There is no separate per-link counter or ring-buffer event emitted from the fabric redirect path.
- The current telemetry therefore cannot distinguish:
  - fab0 vs fab1 use
  - plain redirect vs zone-encoded redirect
  - redirect reason (inactive RG, BLACKHOLE, NO_NEIGH, hairpin mismatch, etc.)

Impact:
- Active/active HA debugging is harder than it needs to be.
- Operators end up relying on `tcpdump`, which is already a poor fit for the XDP redirect path.

Suggested fix direction:
- Add per-link counters for fab0/fab1 redirects.
- Add reason-specific counters and/or trace events for redirect cause.
- Expose the result in CLI / gRPC so HA troubleshooting does not depend on packet capture alone.


---

## #140 — rpm: hierarchical `target url ...` syntax compiles to the literal string `url` [CLOSED] (closed 2026-03-06)

`vsrx.conf` uses hierarchical RPM URL syntax:

- `vsrx.conf:219` -> `target url http://1.1.1.1;`

Current code does not compile that form correctly:

- `pkg/config/compiler.go` handles RPM targets with `test.Target = nodeVal(prop)`.
- For a hierarchical `target { url ... }` node, that resolves to the literal string `"url"`.

I verified this locally with the current parser/compiler: a config containing `target url http://1.1.1.1;` compiles to `Target == "url"` with no parse or compile error.

Impact:

- HTTP RPM probes from `vsrx.conf` are pointed at the wrong target.
- `event-options` failover logic driven by that probe can make decisions from bad probe results.
- This is silent config drift because the config commits cleanly.

Suggested fix:

- Teach `compileRPM()` to explicitly parse Junos hierarchical target forms such as `target url <url>`.
- Add a parser/compiler test that mirrors the exact `vsrx.conf` syntax.
- Reject unsupported target forms instead of silently compiling the wrong value.


---

## #141 — rpm: `routing-instance` is parsed but ignored at runtime [CLOSED] (closed 2026-03-06)

`vsrx.conf` sets an RPM routing instance:

- `vsrx.conf:221` -> `routing-instance Comcast-GigabitPro;`

Current code parses this into `RPMTest.RoutingInstance`, but runtime probing never uses it:

- Parsed in `pkg/config/compiler.go`.
- Stored in `pkg/config/types.go`.
- `pkg/rpm/rpm.go` uses plain `net.Dialer` / `http.Client` and never binds probes to a VRF, netns, table, or interface selected by `RoutingInstance`.

Impact:

- RPM probes run from the default routing context instead of the configured routing instance.
- Probe state can diverge from the actual uplink or WAN being monitored.
- `event-options` failover actions can trigger on the wrong path health.

Suggested fix:

- Resolve `routing-instance` to the effective VRF/routing table before running the probe.
- Support ICMP, TCP, and HTTP probe types consistently.
- Add integration tests showing different results across two routing instances.


---

## #142 — rpm: `probe-limit` from `vsrx.conf` is silently ignored [CLOSED] (closed 2026-03-06)

`vsrx.conf` contains:

- `vsrx.conf:227` -> `probe-limit 3;`

Current parser/compiler accepts that config with no error, but there is no schema, config field, or runtime behavior for `probe-limit`:

- No `probe-limit` handling in `pkg/config/ast.go` or `pkg/config/compiler.go`.
- No corresponding field in `pkg/config/types.go`.
- No runtime limit enforcement in `pkg/rpm/rpm.go`.

I verified locally that a config with `probe-limit 3;` parses and compiles successfully, but the value is dropped entirely.

Impact:

- Operators get a silent no-op for a knob that exists in `vsrx.conf`.
- That creates config compatibility drift and makes RPM behavior harder to reason about.

Suggested fix:

- Decide the bpfrx semantics for `probe-limit`.
- Either implement it and expose it in show output, or reject it explicitly instead of silently ignoring it.


---

## #143 — dynamic-address: `feed-name { path ... }` and `address-name profile` from `vsrx.conf` are not implemented [CLOSED] (closed 2026-03-06)

`vsrx.conf` uses richer `security dynamic-address` syntax than the current runtime supports:

- `vsrx.conf:1205-1224`
- Multiple `feed-name ... { path ... }` stanzas under one `feed-server`
- `address-name ... { profile { feed-name ...; } }` bindings

Current implementation is much narrower:

- `pkg/config/ast.go` models only `feed-server` under `dynamic-address`.
- `pkg/config/compiler.go` stores a single `FeedServer.FeedName` string and no per-feed `path`.
- There is no type or compiler path for `address-name` / `profile` bindings.

I verified locally with a vsrx-style example that:

- the config parses and compiles without error,
- only the last `feed-name` survives (`feed-cloudflare-ipv6` in my check),
- both `path` values are dropped,
- `address-name` bindings are dropped entirely.

This matters in the real config because policies later reference `cloudflare-ipv4` / `cloudflare-ipv6` as source addresses:

- `vsrx.conf:7185`
- `vsrx.conf:10767`
- `vsrx.conf:12261`
- `vsrx.conf:13704`
- `vsrx.conf:16242`

Impact:

- Dynamic-address objects from `vsrx.conf` do not map into policy-matchable address objects the way vSRX expects.
- Feed path selection is lost.
- Multi-feed servers collapse incorrectly.

Suggested fix:

- Extend the config model for per-feed `path` and `address-name -> profile -> feed-name` bindings.
- Materialize dynamic-address names into the address resolution path used by policy compilation.
- Add parser/compiler tests that mirror the Cloudflare blocks in `vsrx.conf`.


---

## #144 — flow-monitoring: `export-extension app-id/flow-dir` from `vsrx.conf` is ignored or only partially honored [CLOSED] (closed 2026-03-06)

`vsrx.conf` configures flow export extensions in both NetFlow v9 and IPFIX templates:

- `vsrx.conf:168-209`
- `export-extension app-id;`
- `export-extension flow-dir;`

Current handling is incomplete:

- `pkg/config/compiler.go` captures `export-extension` only for IPFIX templates; the version9 template path ignores it.
- `pkg/flowexport/netflow9.go` and `pkg/flowexport/ipfix.go` do not consult configured `ExportExtensions` when building templates.
- `flow direction` is effectively always exported because direction is hard-coded into the templates.
- `applicationId` is never emitted even when `app-id` is configured.

Impact:

- `vsrx.conf` flow export behavior does not match runtime telemetry.
- App-ID export is impossible today.
- The `flow-dir` knob is not actually controlling template contents.

Suggested fix:

- Preserve export-extension settings for both v9 and IPFIX in the compiled config.
- Make template generation conditional on configured extensions.
- Either implement `app-id` export end-to-end or reject it explicitly when AppID is unavailable.


---

## #145 — services: `application-identification` in `vsrx.conf` is still parse-only [CLOSED] (closed 2026-03-06)

`vsrx.conf` enables application identification:

- `vsrx.conf:214` -> `application-identification;`

Current state:

- Parsed as a boolean in `pkg/config/compiler.go`.
- Reflected in show output.
- No L7 identification pipeline exists in dataplane/session handling.

This is already documented in repo docs, but there is no GitHub issue tracking the concrete runtime gap from the active config.

Impact:

- Enabling AppID in `vsrx.conf` has no effect on enforcement or telemetry.
- Dependent features such as `pre-id-default-policy` and App-ID flow export cannot work correctly.

Suggested fix:

- Track AppID state per session.
- Add a classifier path and cache.
- Gate dependent features on actual AppID availability.


---

## #146 — security: `pre-id-default-policy` from `vsrx.conf` is parsed but not wired [CLOSED] (closed 2026-03-06)

`vsrx.conf` configures a pre-ID default policy:

- `vsrx.conf:21125-21133`

Current state:

- Parsed into `SecurityConfig.PreIDDefaultPolicy` in `pkg/config/compiler.go`.
- There is no runtime consumer in dataplane or daemon logic.
- Repo docs already note that this depends on AppID, but there is no GitHub issue tied to the actual config usage.

Impact:

- The configured pre-identification policy has no effect.
- Operators may expect pre-ID logging or default handling that never occurs.

Suggested fix:

- Wire pre-ID state into session classification.
- At minimum, implement the logging-only subset once AppID/pre-ID session state exists.
- Until then, emit an explicit unsupported warning when configured.


---

## #147 — system: `license autoupdate url` from `vsrx.conf` has no runtime behavior [CLOSED] (closed 2026-03-06)

`vsrx.conf` contains:

- `vsrx.conf:98-99` -> `license { autoupdate { url ... } }`

Current state:

- Parsed into `SystemConfig.LicenseAutoUpdate`.
- No runtime consumer or scheduler uses it.
- The repo already has a next-feature doc for this, but there is no GitHub issue tied to the active config.

Impact:

- This is a silent no-op in a real config.
- Operators cannot tell whether license refresh is unsupported or simply failing.

Suggested fix:

- Either implement explicit runtime behavior, or warn loudly that the feature is unsupported.
- Expose status in show output.


---

## #148 — system: `ntp threshold action` from `vsrx.conf` is parsed but ignored [CLOSED] (closed 2026-03-06)

`vsrx.conf` contains:

- `vsrx.conf:109` -> `threshold 400 action accept;`

Current state:

- Parsed into `SystemConfig.NTPThresholdAction`.
- `pkg/daemon/daemon.go` applies NTP by writing chrony source lines only.
- Threshold/action values are never consumed.

Impact:

- The config commits, but the intended time-discipline policy is ignored.
- In HA systems, silently ignoring clock policy can make debugging failover/session-sync behavior harder.

Suggested fix:

- Map threshold/action into an actual runtime behavior, or emit an explicit unsupported warning.
- Show the effective state operationally.


---

## #149 — security flow: `power-mode-disable` from `vsrx.conf` has no runtime effect [CLOSED] (closed 2026-03-06)

`vsrx.conf` enables:

- `vsrx.conf:1249` under `security flow { power-mode-disable; }`

Current state:

- Parsed into `SecurityConfig.Flow.PowerModeDisable` in `pkg/config/compiler.go`.
- Displayed in CLI / gRPC show output.
- No runtime consumer exists in daemon, BPF, or DPDK paths.

Impact:

- Another silent no-op in a real config.
- Operators may believe a power-management behavior was disabled when nothing changed.

Suggested fix:

- Define bpfrx semantics for this knob and implement them, or reject / warn explicitly.


---

## #150 — security: `policy-stats system-wide` from `vsrx.conf` is ignored [CLOSED] (closed 2026-03-06)

`vsrx.conf` enables policy statistics:

- `vsrx.conf:21121-21127` -> `policy-stats { system-wide enable; }`

Current state:

- Parsed into `SecurityConfig.PolicyStatsEnabled` in `pkg/config/compiler.go`.
- There is no runtime consumer of `PolicyStatsEnabled`.
- BPF policy counters are incremented unconditionally in `bpf/xdp/xdp_policy.c`.

Impact:

- The config knob does not control actual behavior.
- bpfrx cannot match vSRX enable/disable semantics for policy stats.

Suggested fix:

- Either wire the flag into counter enablement / reporting behavior, or reject unsupported forms explicitly.


---

## #154 — ike/ipsec: gateway external-interface is parsed but ignored for local_addrs and egress selection [CLOSED] (closed 2026-03-07)

## Summary
`external-interface` is compiled and displayed, but the runtime IPsec generator does not use it for source selection or egress pinning.

## Evidence
- Parser/compiler stores `ExternalIface`: `pkg/config/compiler.go:4097-4100`, `pkg/config/compiler.go:4242-4245`
- Config type carries the field: `pkg/config/types.go:1541`
- swanctl generation only uses `vpn.LocalAddr` / `gateway.LocalAddress`; it never consults `ExternalIface`: `pkg/ipsec/ipsec.go:83-117`
- CLI / gRPC only display the field: `pkg/cli/cli.go:6224-6225`, `pkg/grpcapi/server.go:6765-6766`

## Why this matters
Several gateways in `vsrx.conf` specify `external-interface` without `local-address` (for example `ATH-MARTIS`, `ATH-MINN`, `ATH-CLE` around `vsrx.conf:350-369`). Today those tunnels rely on strongSwan/kernel default source selection instead of Junos-style interface binding.

## Expected behavior
When `external-interface` is configured, bpfrx should either:
- resolve the current address on that interface and set `local_addrs`, or
- otherwise program strongSwan/kernel state so the IKE/IPsec connection is pinned to that interface in a deterministic, Junos-compatible way.

## Current behavior
`external-interface` has no runtime effect.

---

## #155 — ike/ipsec: proposal lifetime-seconds is parsed but never emitted to swanctl [CLOSED] (closed 2026-03-07)

## Summary
Both IKE and ESP proposal `lifetime-seconds` values are parsed and stored, but the strongSwan config generator never uses them.

## Evidence
- IKE proposal lifetime is parsed into `IKEProposal.LifetimeSeconds`: `pkg/config/compiler.go:4041-4044`, `pkg/config/types.go:1500-1506`
- IPsec proposal lifetime is parsed into `IPsecProposal.LifetimeSeconds`: `pkg/config/compiler.go:4187-4190`, `pkg/config/types.go:1517-1524`
- The generator builds proposal strings but never emits any lifetime/rekey setting: `pkg/ipsec/ipsec.go:159-190`, `pkg/ipsec/ipsec.go:278-359`
- `vsrx.conf` uses explicit ESP lifetimes, e.g. `lifetime-seconds 3600` at `vsrx.conf:381-393`

## Why this matters
Tunnels currently run with strongSwan defaults instead of the configured Junos lifetimes, which changes rekey timing and can break interoperability with peers expecting the configured lifetime.

## Expected behavior
Map Junos `lifetime-seconds` to the appropriate strongSwan connection/child lifetime settings for both IKE and ESP rekey behavior.

## Current behavior
Configured lifetime values are silently ignored at runtime.

---

## #156 — ike: dead-peer-detection modes all collapse to a hardcoded dpd_delay = 10s [CLOSED] (closed 2026-03-07)

## Summary
`dead-peer-detection` is parsed, displayed, and stored, but all configured modes currently produce the same runtime behavior: `dpd_delay = 10s`.

## Evidence
- DPD mode is parsed into `DeadPeerDetect`: `pkg/config/compiler.go:4115-4120`, `pkg/config/compiler.go:4260-4265`, `pkg/config/types.go:1544-1549`
- Runtime generation only checks for non-empty DPD and writes one line: `pkg/ipsec/ipsec.go:138-140`
- CLI / gRPC display the configured mode string, which makes it look implemented: `pkg/cli/cli.go:6240-6242`, `pkg/grpcapi/server.go:6780-6782`

## Why this matters
Junos distinguishes at least `always-send`, `optimized`, and `probe-idle`. Collapsing all of them to a single strongSwan setting loses semantics and makes troubleshooting harder because the control plane reports one thing while the runtime does another.

## Expected behavior
Map each Junos DPD mode to explicit strongSwan behavior (`dpd_delay`, `dpd_timeout`, `dpd_action`, and/or idle-only behavior as appropriate), or reject unsupported modes clearly.

## Current behavior
Every non-empty DPD mode becomes the same `dpd_delay = 10s` stanza.

---

## #157 — ike: Junos $9$ pre-shared-key strings are passed verbatim to strongSwan [CLOSED] (closed 2026-03-07)

## Summary
Obfuscated Junos PSKs (`$9$...`) are parsed as literal strings and written directly into `swanctl` secrets. strongSwan will then use the obfuscated blob as the actual PSK.

## Evidence
- IKE policy `pre-shared-key` is parsed verbatim into `pol.PSK`: `pkg/config/compiler.go:4060-4069`
- VPN-level `pre-shared-key` is also stored verbatim: `pkg/config/compiler.go:4332-4333`
- The generator writes whatever string it has into `secret = "..."`: `pkg/ipsec/ipsec.go:231-244`
- `vsrx.conf` contains an obfuscated key at `vsrx.conf:321`

## Why this matters
A config imported from Junos display output can look valid but fail every IKE authentication attempt because bpfrx never de-obfuscates or rejects `$9$` secret material.

## Expected behavior
Either:
- support Junos secret decoding for `$9$...` values before writing `swanctl`, or
- reject/flag obfuscated PSKs at compile/apply time so the operator knows plaintext or another supported secret format is required.

## Current behavior
Obfuscated PSKs are treated as plaintext secrets.

---

## #158 — ike: authentication-method is parsed but swanctl generation hardcodes auth = psk [CLOSED] (closed 2026-03-07)

## Summary
The config parser records IKE proposal `authentication-method`, but runtime swanctl generation always emits `auth = psk` for both local and remote peers.

## Evidence
- IKE proposal stores `AuthMethod`: `pkg/config/types.go:1500-1506`
- Compiler parses `authentication-method`: `pkg/config/compiler.go:4029-4034`
- Runtime auth blocks are hardcoded to PSK: `pkg/ipsec/ipsec.go:143-156`
- There are no IPsec PKI/local-certificate fields in the current runtime config model; this matches the feature-gap doc entry for certificate-based IPsec.

## Why this matters
This is a semantic mismatch: the parser accepts an auth-method knob, but the dataplane/runtime cannot express anything except PSK. It also blocks certificate-based IKE gateways.

## Expected behavior
Either:
- implement auth-method-aware swanctl generation (including certificate-based auth), or
- reject unsupported methods at compile time instead of silently generating PSK auth.

## Current behavior
All IKE gateways become PSK-authenticated regardless of configured auth method.

---

## #159 — ipsec: full traffic-selector syntax is still unsupported; only one local_ts/remote_ts pair exists [CLOSED] (closed 2026-03-07)

## Summary
bpfrx still only models one `local_ts` / `remote_ts` pair per VPN via `local-identity` and `remote-identity`. Junos `traffic-selector` syntax is not represented in the parser or runtime.

## Evidence
- VPN model only has one `LocalID` and `RemoteID` string: `pkg/config/types.go:1554-1563`
- Runtime generation only emits one `local_ts` and one `remote_ts`: `pkg/ipsec/ipsec.go:201-208`
- The feature-gap docs already note this as partial support: `docs/feature-gaps.md:283`
- I did not find schema/compiler support for `security ipsec vpn ... traffic-selector ...`

## Why this matters
More complex peers often require multiple proxy-IDs / traffic selectors per tunnel. Today the parser/runtime can only represent the simplest single-selector case.

## Expected behavior
Add parser/runtime support for Junos `traffic-selector` blocks and map them cleanly to strongSwan child traffic selectors, or reject the syntax clearly.

## Current behavior
Only the single `local-identity` / `remote-identity` path is available.

---

## #164 — perf/xdp: add per-CPU IPv6 established-flow cache in xdp_zone [CLOSED] (closed 2026-03-07)

## Problem
Established IPv6 TCP traffic spends too much CPU in `sessions_v6` hash lookup on the XDP hot path.

## Proposal
Add a small per-CPU exact-flow cache in `xdp_zone` for established IPv6 TCP flows, with bounded batched writeback to the real session map.

## Scope
- XDP only
- IPv6 only
- established TCP only
- bypass on SYN/FIN/RST, NAT64, ALG, predicted sessions

## Acceptance criteria
- eBPF programs load successfully
- long-running IPv6 TCP flows remain correct
- fewer `htab_map_hash` / `lookup_nulls_elem_raw` samples on IPv6 perf runs
- no HA/NAT regressions

Design notes are in `docs/next-features/ipv6-session-fast-path.md`.


---

## #165 — perf/xdp: add IPv6 no-extension-header fast path to parse_ipv6hdr [CLOSED] (closed 2026-03-07)

## Problem
The current IPv6 parser always goes through the generic extension-header walker, even for ordinary TCP/UDP traffic without extension headers.

## Proposal
Add a fast path in `parse_ipv6hdr()` for the common case where the upper-layer protocol is directly in the base IPv6 header, and fall back to the current walker only when extension headers are present.

## Acceptance criteria
- identical behavior for packets with extension headers
- cheaper common-case IPv6 parse path
- no verifier regressions

See `docs/next-features/ipv6-session-fast-path.md`.


---

## #166 — perf/dataplane: split hot and cold IPv6 session state [CLOSED] (closed 2026-03-08)

## Problem
`session_value_v6` mixes hot forwarding fields with counters, reverse keys, timestamps, NAT metadata, and cached FIB state. That increases memory traffic on every lookup.

## Proposal
Split lookup-time hot fields from colder accounting / GC / logging fields so the established IPv6 fast path pulls less data into cache.

## Acceptance criteria
- hot lookup structure shrinks materially
- no session accounting / HA regressions
- measurable reduction in IPv6 steady-state CPU cost

See `docs/next-features/ipv6-session-fast-path.md`.


---

## #167 — perf/observability: expose IPv6 established-flow cache hit and flush counters [CLOSED] (closed 2026-03-07)

## Problem
If we add an IPv6 established-flow cache, we need visibility into whether it is actually helping or just colliding / falling back.

## Proposal
Add counters and CLI/monitor visibility for cache hits, flushes, invalidations, and fallbacks.

## Acceptance criteria
- counters available from the dataplane
- visible in CLI / gRPC stats
- usable during perf investigations

See `docs/next-features/ipv6-session-fast-path.md`.


---

## #168 — perf/dataplane: compact IPv6 session key to reduce hash-map cost [CLOSED] (closed 2026-03-08)

## Problem
`session_key_v6` is 40 bytes, which makes `sessions_v6` lookups materially more expensive than IPv4 in the steady-state hot path.

## Proposal
Design a compact IPv6 session key representation that reduces hash/compare cost without making collisions unsafe.

## Acceptance criteria
- smaller effective IPv6 lookup key
- explicit collision-safety story
- session sync / GC / NAT semantics preserved

See `docs/next-features/ipv6-session-fast-path.md`.


---

## #170 — perf/xdp: reduce IPv6 checksum-partial detection cost in xdp_main [CLOSED] (closed 2026-03-07)

## Problem
After the IPv6 flow-cache and parser improvements, `xdp_main_prog` is still one of the largest remaining IPv6 deltas. A likely remaining contributor is IPv6 `CHECKSUM_PARTIAL` detection in `parse_l4hdr()`, which computes the full IPv6 pseudo-header checksum on every TCP/UDP packet.

## Proposal
Reduce IPv6 checksum-partial detection cost in `xdp_main` / `parse_l4hdr()` without breaking NAT correctness.

Possible directions:
- defer detection until a packet actually needs NAT rewrite
- cache or shortcut the common virtio/native-XDP cases
- add a narrower fast path for ordinary IPv6 TCP/UDP packets

## Acceptance criteria
- no NAT checksum regressions
- lower `xdp_main_prog` self time on IPv6 perf runs
- verifier-safe implementation


---

## #179 — perf/nat: reduce IPv6 nat_rewrite_v6 hot-path cost [CLOSED] (closed 2026-03-08)

## Problem
Recent perf captures still show `xdp_nat_prog` materially more expensive on IPv6 than IPv4:

- IPv4: `xdp_nat_prog` 2.5%
- IPv6: `xdp_nat_prog` 4.3%
- Delta: `+1.8%`

`nat_rewrite_v6()` still pays for:
- 128-bit address compare/copy work
- checksum updates over larger pseudo-header state
- protocol/direction dispatch on every packet

We fixed correctness regressions in the recent IPv6 NAT series, but we have not yet revisited the remaining steady-state cost of the IPv6 rewrite path.

## Scope
Optimize `nat_rewrite_v6()` for the common SNAT path without changing NAT semantics.

Likely candidates:
- specialize common TCP/UDP source-NAT and destination-NAT cases more aggressively
- avoid checksum/address work when fields are already equal on-wire
- precompute or cache translation-direction-specific data where that can be done safely

## Acceptance
- perf re-run shows `xdp_nat_prog` CPU share reduced on the IPv6 iperf path
- IPv6 source NAT and destination NAT lab tests still pass
- checksum-partial/offload behavior stays correct


---

## #180 — perf/xdp: reduce pkt_meta init and parse overhead in xdp_main [CLOSED] (closed 2026-03-08)

## Problem
Recent perf captures still show `xdp_main_prog` as the single largest IPv6 hot symbol even after the screen-bypass work and the ingress screen-flag precompute:

- IPv4: `xdp_main_prog` 11.6%
- IPv6: `xdp_main_prog` 16.1%
- Delta: `+4.5%`

Current master still does per-packet:
- `pkt_meta_scratch` lookup
- large `pkt_meta` memset/init
- separate L3 parse and L4 parse setup
- ingress-stage bookkeeping before the first tail call

The new ingress `screen_flags` shortcut removes two map lookups, but it does not address the remaining metadata-init and parse cost in the `xdp_main` hot path.

## Scope
Investigate and reduce the remaining `xdp_main` cost without reintroducing the earlier IPv6 forwarding regressions.

Likely candidates:
- shrink or stage `pkt_meta` initialization so the hot path does not clear more state than necessary
- combine common-case IPv4/IPv6 TCP/UDP parse work to reduce redundant bounds/setup work
- avoid redoing setup that later stages already overwrite

## Acceptance
- perf re-run shows `xdp_main_prog` CPU share reduced on the IPv6 iperf path
- no regression in IPv4/IPv6 forwarding, NAT, or HA fabric paths
- explicit regression coverage for IPv6 forwarding/NAT before merge


---

## #185 — HA session-sync: per-zone ownership mapping is not safe for active/active zones spanning multiple RGs [CLOSED] (closed 2026-03-08)

## Problem
Per-RG session sync is implemented as a `zone_id -> RG_id` mapping, but session ownership is actually decided from a session's `IngressZone` alone. That is not ownership-safe when a zone contains interfaces from multiple redundancy groups.

## Why this matters
In active/active HA, the same security zone can legitimately contain interfaces that belong to different RGs. In that topology:
- sessions for RG A and RG B share the same `IngressZone`
- sync ownership is reduced to a single RG for that entire zone
- bulk stale reconciliation and incremental sync can send, skip, or delete the wrong sessions on the standby

That is an architectural HA correctness bug, not just an optimization problem.

## Code
- `pkg/cluster/sync.go:489-501` (`ShouldSyncZone`)
- `pkg/daemon/daemon.go:2686-2710` (`buildZoneRGMap`)
- `pkg/dataplane/types.go:30-31` and `:81-82` (`SessionValue{,V6}` store `IngressZone` / `EgressZone`, not owning RG or ingress interface)
- `pkg/cluster/sync.go:1311-1344` and surrounding bulk reconciliation code

## Current behavior
`buildZoneRGMap()` assigns a single RG to each zone by taking the first RETH interface found in that zone. `ShouldSyncZone()` then uses that single RG to decide whether the local node owns all sessions for that zone.

## Impact
- long-lived sessions can be synced to the wrong peer owner
- bulk stale reconciliation can delete valid sessions for another RG that happens to share the same zone
- failover behavior depends on zone layout, not actual RG/interface ownership

## Suggested fix
Move session-sync ownership to a per-interface or per-session RG identity instead of a per-zone approximation. Concretely:
- carry ingress interface or owning RG in synced session state
- derive sync ownership from that field, not from `IngressZone`
- make bulk reconciliation key off the same authoritative owner field

## Notes
This is likely the highest-signal remaining HA design gap in the active/active path.


---

## #186 — HA failover gating: sync readiness is decoupled from fabric redirect readiness [CLOSED] (closed 2026-03-08)

## Problem
In private-RG mode, takeover readiness is gated by session-sync completion (`syncReady`) and VIP interface readiness, but not by whether the cross-chassis fabric redirect path is actually usable.

## Why this matters
Current code syncs sessions on the control link by default, while fabric redirect state is populated separately from `fabric_fwd` neighbor/link resolution. A node can therefore become eligible to take over because control-plane sync is healthy even though the actual data-plane escape hatch is stale or down.

## Code
- `pkg/daemon/daemon.go:4068-4138` (sync transport on control link by default)
- `pkg/daemon/daemon.go:4203-4213` (`syncReady` lifecycle)
- `pkg/daemon/daemon.go:4300-4323` (fabric_fwd population / monitor)
- `pkg/daemon/daemon.go:5394-5425` (readiness gate)

## Impact
- a node can win election with fresh session state but no working fabric forwarding path
- failover can stall in exactly the cases where active/active needs fabric redirect to bridge route/VIP asymmetry
- control-plane health and dataplane failover readiness diverge

## Suggested fix
Add a fabric-readiness component to takeover gating for modes that rely on cross-chassis redirect. At minimum, require the local node to have a valid fabric path programmed when failover semantics depend on fabric redirect for continuity.


---

## #187 — xdp_zone: NO_NEIGH active-active check drops VLAN context and can skip required fabric failover [CLOSED] (closed 2026-03-08)

## Problem
In the `BPF_FIB_LKUP_RET_NO_NEIGH` path, `xdp_zone` checks whether the egress RG is locally active by calling `check_egress_rg_active(fib.ifindex, 0)`. That drops VLAN context.

## Why this matters
`iface_zone_map` is keyed by `{physical_ifindex, vlan_id}`. For VLAN-backed RETH traffic, looking up the egress interface with VLAN 0 can miss the actual RG ownership entry and incorrectly treat the interface as standalone/active.

That means the dataplane can skip fabric redirect exactly in the failover case where the peer owns the VLAN-backed RG.

## Code
- `bpf/xdp/xdp_zone.c:1385-1396`
- `bpf/headers/bpfrx_helpers.h:2150-2158`
- `pkg/dataplane/compiler.go:666-698`

## Current behavior
`check_egress_rg_active()` returns active/standalone when `iface_zone_map` has no entry for `{ifindex, vlan_id}`. In the NO_NEIGH path, the caller passes `vlan_id=0` even though the dataplane's authoritative RG mapping for subinterfaces is stored with the real VLAN ID.

## Impact
- existing sessions can fall back to local kernel routing instead of cross-chassis redirect
- failover is especially wrong on VLAN RETH subinterfaces
- this can present as traffic hanging only for some RGs / VLANs during failover

## Suggested fix
Preserve VLAN context in the NO_NEIGH RG-active check. If `fib.ifindex` is a VLAN subinterface, translate it the same way other paths do before calling `check_egress_rg_active()`.


---

## #188 — HA readiness: RGInterfaceReady treats missing local interfaces as peer-owned and can falsely unblock takeover [CLOSED] (closed 2026-03-08)

## Problem
The readiness gate still treats `LinkByName` failure in `RGInterfaceReady()` as "belongs to the peer" and skips it.

## Why this matters
That assumption is only safe when the interface name is truly remote-only (for example `ge-7/...` on node0). It is not safe for:
- local startup races
- missing VLAN subinterfaces
- failed renames / networkd drift
- local interface config mistakes

In those cases the RG can be marked interface-ready even though the new owner cannot actually receive or own traffic.

## Code
- `pkg/cluster/monitor.go:419-455`

## Current behavior
Any interface monitor whose Linux name does not currently resolve is silently ignored instead of contributing a readiness failure reason.

## Impact
- takeover eligibility can go true before local interfaces actually exist
- failover can move control-plane ownership while the data-plane side is still unready
- this is especially risky in private-RG mode where readiness gating is the main safety net

## Suggested fix
Differentiate "known remote interface" from "expected local interface missing". Missing local interfaces should fail readiness with an explicit reason.


---

## #189 — HA readiness: RGVRRPReady reports ready when an RG has no local VRRP instance [CLOSED] (closed 2026-03-08)

## Problem
`RGVRRPReady()` returns ready for an RG with no local VRRP instance whenever *some other* VRRP instance exists in the manager.

## Why this matters
That means an RG can pass the VRRP readiness gate even when its own RETH/VRRP ownership machinery failed to start or was never instantiated locally.

## Code
- `pkg/vrrp/manager.go:355-372`

## Current behavior
If no instance for `VRID = 100 + rgID` is found, but `len(m.instances) > 0`, the function returns `(true, nil)`.

## Impact
- cluster election can unblock takeover for the wrong RG
- `rg_active` can be asserted while the RG's VIP ownership mechanism is absent
- failover can look superficially successful in cluster state while traffic never moves locally

## Suggested fix
Make readiness RG-specific. Only return ready when:
- the RG is intentionally non-RETH / has no VRRP requirement, or
- at least one matching local instance exists and the daemon has enough state to manage that RG's VIP ownership


---

## #191 — HA IPv6 failover: no NDP probe equivalent to IPv4 gateway ARP probe [CLOSED] (closed 2026-03-08)

## Summary
IPv4 failover has an explicit upstream cache-refresh path after MASTER transition, but IPv6 does not.

Current behavior:
- IPv4 MASTER transition sends GARP plus an explicit gateway ARP probe in `pkg/vrrp/instance.go` and `pkg/daemon/daemon.go`.
- IPv6 MASTER transition only sends unsolicited NA (`SendGratuitousIPv6Burst`).
- `SendNDSolicitation()` exists in `pkg/cluster/garp.go` but is never called.

## Why this matters
IPv6 neighbor convergence is currently weaker than IPv4 during HA failover:
- LAN/WAN peers may not refresh neighbor state as aggressively from unsolicited NA alone.
- There is no IPv6 equivalent of the explicit “poke the gateway/upstream cache” behavior that helped IPv4.
- This becomes more visible because the current RETH design uses per-node MAC/link-local identity.

## Evidence
- `pkg/vrrp/instance.go`: IPv4 path calls `SendARPProbe`, IPv6 path only calls `SendGratuitousIPv6Burst`
- `pkg/daemon/daemon.go`: `directSendGARPs()` sends ARP probe for IPv4, no IPv6 probe
- `pkg/cluster/garp.go`: `SendNDSolicitation()` helper exists but is unused

## Proposed fix
Use `SendNDSolicitation()` on MASTER transition / direct RG activation for likely IPv6 next-hops and possibly other known neighbors, mirroring the IPv4 ARP-probe parity.

## Scope
Low-risk first slice:
- Wire NDP probe only for the obvious failover path
- Keep existing unsolicited NA bursts
- Measure failover improvement before larger router-identity changes


---

## #192 — HA IPv6 failover: per-node RETH MAC/link-local identity makes failover weaker than IPv4 [CLOSED] (closed 2026-03-09)

## Summary
IPv6 HA failover still changes router identity because RETH uses per-node MACs, which means per-node link-local addresses. The code relies on goodbye RA and new RA startup to move the default-router role, but that is fundamentally weaker than IPv4 and does not help on hard crash failover.

## Current behavior
- `pkg/cluster/reth.go` programs per-node RETH MACs (`RethMAC(clusterID, rgID, nodeID)`)
- `pkg/ra/sender.go` sends RA from the interface link-local
- `pkg/ra/ra.go` / `pkg/daemon/daemon.go` send goodbye RA only on graceful withdraw / startup-secondary cleanup
- on a hard fail, the old primary cannot withdraw its router identity
- the new primary starts RA later via per-RG service reconciliation, after VIP move

## Why this matters
IPv4 mostly needs VIP->MAC convergence.
IPv6 needs both:
- VIP neighbor convergence
- default-router identity convergence

With per-node MAC/link-local identities, hosts can retain the dead router's old link-local default route while the new primary advertises a different one.

## Evidence
- `pkg/cluster/reth.go`
- `pkg/ra/sender.go`
- `pkg/ra/ra.go`
- `pkg/daemon/daemon.go` startupGoodbyeRA comments already document that hosts see both nodes as separate IPv6 routers

## Proposed direction
Create an explicit IPv6 failover design for parity with IPv4, covering:
- whether to keep per-node RETH MACs or move to stable active router identity
- whether inactive RG interfaces must be hidden from L2 before shared identity is possible
- whether RA startup/withdraw belongs in the failover critical path
- how to handle hard-fail scenarios where goodbye RA is impossible

This is architectural, not just a small bugfix.


---

## #193 — HA IPv6 failover: failed-neighbor cleanup reprobes IPv4 only [CLOSED] (closed 2026-03-08)

## Summary
`cleanFailedNeighbors()` actively reprobes only IPv4 after deleting `NUD_FAILED` entries. IPv6 just deletes the failed neighbor and waits for later traffic to trigger NDP.

## Current code
In `pkg/daemon/daemon.go`:
- `cleanFailedNeighbors()` deletes both IPv4 and IPv6 failed entries
- but only calls `cluster.SendARPProbe()` for IPv4
- comment explicitly says IPv6 relies on the `XDP_PASS` path to trigger kernel NDP later

## Why this matters
This makes IPv6 recovery weaker than IPv4 during HA failover and after churn:
- a failover/rejoin node can come up with cold or failed IPv6 neighbor state
- IPv4 gets active reprobe
- IPv6 stays reactive and can blackhole until a later packet drives NDP

## Proposed fix
After deleting failed IPv6 neighbors, actively reprobe them using `SendNDSolicitation()` from the correct interface/source address instead of waiting for passive traffic-driven recovery.

## Notes
This should be separate from the larger IPv6 router-identity problem. It is a narrower parity gap with IPv4 and should be fixable independently.


---

## #196 — userspace: SNAT reply traffic black-holed on slow path reinjection [CLOSED] (closed 2026-03-12)

## Problem

When a reverse-NAT reply packet (server → SNAT address) can't be forwarded directly due to a missing neighbor MAC, `maybe_reinject_slow_path` injects the packet into the TUN device **without reversing the NAT**. The kernel sees `dst=firewall's own SNAT IP`, delivers it locally, and the reply never reaches the original client.

### Example flow

1. Forward: client(10.0.61.102) → server(172.16.80.200), SNAT to 172.16.80.8
2. Reply arrives: server(172.16.80.200) → 172.16.80.8
3. Reverse session hit, but forwarding resolution for 10.0.61.102 gives `MissingNeighbor`
4. `maybe_reinject_slow_path` sends raw `{src=172.16.80.200, dst=172.16.80.8}` to TUN
5. Kernel sees `dst=172.16.80.8` (local address), delivers locally — packet black-holed

### How BPF handles this correctly

The eBPF pipeline sets `META_FLAG_KERNEL_ROUTE` and tail-calls back to conntrack for NAT reversal before `XDP_PASS`. The Rust path has no equivalent.

## Impact

**Critical** — This is the most likely primary cause of iperf flow stalls. TCP retransmits cascade, window collapses, throughput drops to zero.

## Fix

Apply reverse NAT rewrite to packets before TUN injection when the session has NAT state. The session's `nat` field already contains the original (pre-NAT) addresses — use them to rewrite src/dst before injecting into the slow path.

## Files

- `userspace-dp/src/afxdp.rs` — `maybe_reinject_slow_path`, `extract_l3_packet`

## Branch

`userspace-dataplane-rust-wip`

---

## #197 — userspace: silent packet drops when frame build returns None [CLOSED] (closed 2026-03-12)

## Problem

`build_forwarded_frame_into_from_frame` returns `None` for several conditions, and the caller silently drops the frame with only an exception counter increment:

- **Missing neighbor MAC** — `decision.resolution.neighbor_mac?` returns None when ARP/NDP hasn't resolved yet
- **TTL=1** — `out[ip_start + 8] <= 1` returns None (BPF generates ICMP Time Exceeded; Rust drops silently)
- **Offset mismatch** — `frame_l3_offset(frame)?` fails on unexpected frame layout

Every `None` propagates to `build_failed = true` which drops the packet with no fallback.

## Impact

**Critical** — For TCP (iperf), every silent drop triggers a retransmission timeout cascade. The BPF pipeline has `NO_NEIGH` → `XDP_PASS` fallback to let the kernel resolve ARP and retry. The Rust path has no equivalent — packets are permanently lost.

## Fix

- On `MissingNeighbor`: fall back to slow-path TUN injection (with NAT applied per #issue-above) or trigger an ARP probe and hold the frame
- On TTL=1: generate ICMP Time Exceeded or fall back to slow path for kernel to generate it
- On offset errors: fall back to slow path rather than silent drop

## Files

- `userspace-dp/src/afxdp.rs` — `build_forwarded_frame_into_from_frame` (~line 5958), callers at ~line 2462

## Branch

`userspace-dataplane-rust-wip`

---

## #198 — userspace: O(n) reverse session repair causes latency spikes under load [CLOSED] (closed 2026-03-12)

## Problem

When reply traffic lands on a different worker than the one that created the forward session, the reverse session entry doesn't exist locally. The code falls back to `repair_reverse_session_from_forward` which calls `find_forward_nat_match` — a **linear scan of ALL sessions** in the worker's local table:

```rust
self.sessions.iter().find_map(|(key, entry)| {
    if entry.metadata.is_reverse { return None; }
    if !reply_matches_forward_nat(key, entry.decision.nat, reply_key) { return None; }
    Some(...)
})
```

With up to 131,072 sessions, this is O(n) per packet. Additionally, the fallback check against `shared_sessions: Arc<Mutex<FastMap<...>>>` has global mutex contention under high packet rates.

## Impact

**High** — Adds milliseconds of per-packet latency during the cross-worker race window at connection startup. This causes TCP window stalls and contributes to iperf throughput collapse.

## Fix

Maintain a secondary hash map keyed by the NAT'd reverse tuple (post-NAT src/dst + ports), populated when forward sessions are installed. This makes reverse session repair O(1) instead of O(n). Also consider replacing the global `Mutex` on `shared_sessions` with a lock-free concurrent map or per-worker sharding.

## Files

- `userspace-dp/src/session.rs` — `find_forward_nat_match` (~line 165)
- `userspace-dp/src/afxdp.rs` — `repair_reverse_session_from_forward` (~line 4155)

## Branch

`userspace-dataplane-rust-wip`

---

## #199 — userspace: port corruption in copy-based forwarding path [CLOSED] (closed 2026-03-29)

## Problem

The forwarding architecture copies RX frames from UMEM into a `Vec<u8>` (`source_frame.to_vec()`), then later builds TX frames from the copy. A race window exists between the NIC overwriting the UMEM frame and the copy, which can capture stale or corrupted data — particularly L4 ports.

**Evidence:** 15+ commits attempted to fix this same class of bug:
- `77b646a` preserve L4 ports in forwarded TCP frames
- `42294c3` preserve live TCP ports in forward build path
- `5960d52` carry live TCP ports into queued TX
- `c6025c0` snapshot source frames for queued forwarding
- `95aa658` keep live TCP tuple stable in forward path
- `cbf90b6` prefer live frame tuple for forward tuples
- `ffe590b` prefer live frame ports for forward tuples
- `61e95f7` prefer session tuple over corrupted frame ports
- `e278521` keep session tuple authoritative in queued forwards

The `enforce_expected_ports` function is a band-aid that overwrites L4 ports with "expected" values, but `authoritative_forward_ports` can itself capture wrong ports if the frame is already corrupted when parsed at `parse_session_flow` time.

## Impact

**High** — Port corruption causes TCP checksum failures (receiver drops silently) or misrouted packets, both leading to iperf stalls.

## Fix

Zero-copy forwarding: instead of copying the frame into a `Vec<u8>`, rewrite it in-place in the UMEM and submit the same UMEM descriptor offset to the TX ring of the egress binding. This eliminates the copy window entirely and removes the allocation overhead.

If zero-copy isn't feasible (cross-binding TX), capture the frame bytes and metadata atomically before releasing the RX descriptor back to the fill ring.

## Files

- `userspace-dp/src/afxdp.rs` — `build_live_forward_request` (~line 2224), `authoritative_forward_ports` (~line 2252), `enforce_expected_ports` (~line 6461)

## Branch

`userspace-dataplane-rust-wip`

---

## #200 — userspace: XDP shim redirects all traffic to userspace (session check unused) [CLOSED] (closed 2026-03-29)

## Problem

The XDP shim (`userspace-xdp/src/lib.rs`) defines `has_live_userspace_session()` which checks the `USERSPACE_SESSIONS` BPF map, and the Rust workers populate this map via `publish_live_session_key`. However, **the function is never called** in the steering decision path.

The current steering logic (~line 409) only checks:
1. `is_local_destination` → `XDP_PASS`
2. `is_icmp_to_interface_nat_local` → `XDP_PASS`
3. Everything else → redirect to AF_XDP userspace

This means ALL non-local traffic gets redirected to the Rust dataplane, including protocols and flows it doesn't support. When the Rust workers are slow (due to O(n) scans, mutex contention), AF_XDP rings overflow. Overflow packets fall back to the legacy BPF pipeline via `fallback_to_main`, creating **two parallel session state machines** for the same flow — causing session confusion, duplicate NAT, and packet corruption.

## Impact

**Medium-High** — Bimodal packet processing (some via Rust, some via BPF) for the same flow creates state divergence. Also unnecessarily loads the Rust dataplane with traffic it can't handle.

## Fix

Add the session check to the steering path so only packets with active userspace sessions get redirected. New connections can still be steered to userspace via an initial policy decision, but unsessioned traffic stays on the BPF fast path.

## Files

- `userspace-xdp/src/lib.rs` — `has_live_userspace_session` (~line 760), steering decision (~line 409)

## Branch

`userspace-dataplane-rust-wip`

---

## #201 — userspace: UMEM frame exhaustion under TX backpressure stalls RX [CLOSED] (closed 2026-03-29)

## Problem

TX frames come from a free list (`binding.free_tx_frames`). When the NIC's TX completion ring drains slowly (HW backpressure, virtio-net batching), the free list empties. The code returns `TxError::Retry`, pushing pending TX requests back to `pending_tx_local`.

However:
1. The ingress RX path continues receiving packets and building more forward requests
2. `pending_tx_local` grows **unboundedly**, consuming memory and increasing latency
3. The fill ring depends on frame recycling from processed RX frames
4. If fill ring depletes (frames stuck in pending TX queues), the NIC can't deliver new RX packets
5. **Complete RX stall** — no new packets processed, no progress possible

## Impact

**Medium** — Under sustained load with any TX backpressure, the system enters a deadlock: TX can't complete (no free frames), RX can't proceed (no fill frames), and pending queues grow until OOM or timeout.

## Fix

1. **Bound `pending_tx_local`**: when the queue exceeds a threshold (e.g. 2x ring size), stop consuming from RX to apply natural backpressure through the fill ring
2. **Separate TX and RX frame pools**: ensure fill ring frames can't be consumed by TX queuing
3. **Drop oldest pending TX on overflow**: better to lose old packets than stall the entire pipeline

## Files

- `userspace-dp/src/afxdp.rs` — `transmit_batch` (~line 3420), fill ring management in `drain_pending_fill`

## Branch

`userspace-dataplane-rust-wip`

---

## #202 — userspace-dp: port authority design fragility causes policy thrashing [CLOSED] (closed 2026-03-12)

## Summary
The port authority logic in `afxdp.rs` has undergone 4 policy flips in one day between frame/session/metadata tuple preference (commits show repeated back-and-forth on whether to use frame index, session handle, or metadata tuple as the canonical authority). This fragility suggests the abstraction doesn't cleanly fit the problem.

## Details
The port authority determines which AF_XDP socket "owns" a frame for TX completion tracking. Repeated changes between:
- Frame-index based ownership
- Session-handle based ownership  
- Metadata tuple (src/dst port + proto) based ownership

Each change fixes one bug but introduces another edge case, suggesting the fundamental model needs rethinking.

## Impact
Policy thrashing can lead to:
- TX completion misattribution (wrong socket gets credit)
- Frame leaks when ownership is ambiguous
- Subtle iperf stall scenarios when frames get stuck in limbo

## Suggested Fix
Consider a single canonical ownership model — likely frame-index based since UMEM frames have a 1:1 relationship with ring slots. Session/metadata should be used for routing decisions, not ownership.

## Branch
`userspace-dataplane-rust-wip`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## #203 — userspace-dp: UMEM frame leak on TxError::Drop in transmit_prepared_batch [CLOSED] (closed 2026-03-12)

## Summary
In `afxdp.rs`, when `transmit_prepared_batch` encounters a `TxError::Drop`, the frames in `scratch_prepared_tx` are orphaned — they are removed from the TX preparation list but never returned to the UMEM free pool.

## Details
The `transmit_prepared_batch` function iterates over `scratch_prepared_tx` items. On `TxError::Drop`, the frame is effectively discarded without being recycled back to UMEM's fill ring or free list. Over time, this leaks UMEM frames.

## Impact
Under sustained traffic with occasional drops (e.g., policy deny, TTL expiry), the UMEM frame pool slowly depletes. Eventually no frames are available for RX fill ring replenishment, causing the AF_XDP socket to stop receiving packets — manifesting as an iperf stall.

## Suggested Fix
On `TxError::Drop`, explicitly return the frame index to the UMEM free pool (or fill ring) so it can be reused for future RX.

## Branch
`userspace-dataplane-rust-wip`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## #204 — userspace-dp: shared_sessions not cleared on stop() persists stale data [CLOSED] (closed 2026-03-12)

## Summary
In the userspace dataplane manager, `shared_sessions` and `shared_nat_sessions` are not cleared when `stop()` is called. Stale session data persists across reconcile cycles, potentially causing incorrect forwarding decisions after a config change or failover.

## Details
When the manager stops workers (e.g., during reconciliation after config commit), it tears down AF_XDP sockets and worker goroutines but leaves the shared session maps populated with entries from the previous cycle. When new workers start, they inherit stale session state that may reference old NAT mappings, defunct interfaces, or removed policies.

## Impact
- Stale NAT reverse index entries can cause packets to be rewritten with old addresses
- Sessions referencing removed interfaces cause TX to non-existent sockets
- After failover, inherited sessions from the old primary may conflict with fresh sessions

## Suggested Fix
Clear `shared_sessions` and `shared_nat_sessions` in `stop()` before tearing down workers, or reinitialize them fresh in `start()`.

## Branch
`userspace-dataplane-rust-wip`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## #205 — userspace-dp: in-place TX path is nearly dead code (same-interface hairpin only) [CLOSED] (closed 2026-03-12)

## Summary
The in-place TX optimization added in commit 9e380eb is nearly dead code — it only fires for same-interface hairpin scenarios (packet arrives on interface X and needs to be forwarded back out interface X). In practice, this almost never happens for firewall traffic.

## Details
The in-place TX path avoids a frame copy by rewriting the packet in the original RX frame and submitting it directly to the TX ring of the same socket. However, the condition for this path requires the egress interface to be the same as the ingress interface. For a firewall that routes between zones/interfaces, this is extremely rare.

## Impact
- Dead code adds complexity and maintenance burden
- The frame management special case for in-place TX creates additional edge cases in the ownership tracking logic
- May interact poorly with the port authority fragility (#202)

## Suggested Fix
Either:
1. Remove the in-place TX path entirely if profiling shows it never fires
2. Extend it to work cross-interface by having sockets share UMEM (requires AF_XDP shared UMEM setup)

## Branch
`userspace-dataplane-rust-wip`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## #206 — userspace-dp: unused mutable slice in validation path [CLOSED] (closed 2026-03-12)

## Summary
In the validation path, a mutable slice is allocated but never actually mutated — it's only read. This is a minor lint/correctness issue.

## Details
A `&mut` borrow is taken on a slice during packet validation, but the slice contents are only inspected (read), never written to. This suggests either:
1. A planned mutation that was never implemented
2. An unnecessary `mut` qualifier

## Impact
Low — this is a code quality issue, not a runtime bug. However, unnecessary `mut` borrows can mask real bugs by allowing unintended mutations in future refactors.

## Suggested Fix
Change `&mut` to `&` (shared reference) if the slice is only read.

## Branch
`userspace-dataplane-rust-wip`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## #253 — Userspace AF_XDP libxdp migration postmortem [CLOSED] (closed 2026-03-31)

## Summary

`master` no longer uses `xdpilone` directly for AF_XDP. It uses a custom Rust FFI + C bridge around `libxdp`.

The migration failed initially because the code treated `libxdp` as a drop-in replacement for `xdpilone`. It is not. The main incompatibilities were ring-state semantics, producer reservation semantics, socket creation behavior, and UMEM ownership.

This issue is the postmortem for that migration and the checklist for any future AF_XDP library swap.

## Current implementation

Relevant files on `master`:

- `userspace-dp/src/xsk_ffi.rs`
- `userspace-dp/csrc/xsk_bridge.c`
- `userspace-dp/src/afxdp/bind.rs`
- `userspace-dp/src/afxdp.rs`

The current path is a custom wrapper over `libxdp`, not a `libxdp-rs` crate.

## What was incompatible with the old `xdpilone` assumptions

### 1. RX availability semantics were different

Problem:
- The initial wrapper implemented `RingRx::available()` by reading raw producer/consumer pointers.
- `libxdp` `peek()` logic uses cached ring state (`cached_prod` / `cached_cons`), not the raw-pointer path.
- That meant `available()` and `receive()` could disagree, and the userspace loop could think RX was empty even while packets were available.

Evidence:
- fixed by `f76be868` `fix: RingRx::available() must use cached ring state, not raw pointers`

Required lesson:
- a wrapper must match `libxdp` ring helper semantics exactly, not approximate them from mmap'd pointers.

### 2. Producer reservation semantics were different

Problem:
- `libxdp` producer reserve is all-or-nothing.
- The old code assumed `xdpilone`-style partial reservation semantics.
- That caused fill-ring starvation and TX stuck-at-zero behavior when the full requested batch was not available.

*(truncated — 129 lines total)*


---

## #266 — userspace event stream helper parses control frames unsafely on partial Unix-stream reads [CLOSED] (closed 2026-03-29)

## Summary
The helper-side event-stream control reader in `userspace-dp/src/event_stream.rs` assumes every `read()` returns one or more complete 16-byte control frames. That is not guaranteed on a Unix stream socket. Partial reads currently discard data and can drop `Ack`, `Pause`, `Resume`, or `DrainRequest` frames.

## Why this matters
Under HA failover load, demotion prep depends on `Pause` / `DrainRequest` / `Ack` working reliably. If the helper misses or truncates a control frame, the daemon can believe the stream is drained or paused while the helper never actually applied that control transition.

## Code
- [userspace-dp/src/event_stream.rs:544](https://github.com/psaab/bpfrx/blob/master/userspace-dp/src/event_stream.rs#L544) allocates a fixed `read_buf`
- [userspace-dp/src/event_stream.rs:695](https://github.com/psaab/bpfrx/blob/master/userspace-dp/src/event_stream.rs#L695) does a plain `read()` into that buffer
- [userspace-dp/src/event_stream.rs:728](https://github.com/psaab/bpfrx/blob/master/userspace-dp/src/event_stream.rs#L728) hands the raw bytes to `process_control_frames(...)`
- [userspace-dp/src/event_stream.rs:737](https://github.com/psaab/bpfrx/blob/master/userspace-dp/src/event_stream.rs#L737) walks the bytes as if complete frames are already present

If `read()` returns fewer than 16 bytes, or returns a partial frame plus the start of another frame, the parser has no accumulation buffer and drops the incomplete data.

## Expected fix
Implement a small framed read buffer on the helper side, like the daemon-side reader already does in `pkg/dataplane/userspace/eventstream.go` with `io.ReadFull`. The helper should not parse control frames until a full header and payload are available.

## Failover impact
This can make HA failover look random under load because pause/drain/ack control transitions become dependent on socket chunking rather than protocol semantics.

---

## #267 — userspace event-stream DrainRequest does not fence a target sequence during demotion prep [CLOSED] (closed 2026-03-29)

## Summary
The new userspace event-stream drain path does not actually request a sequence fence. The daemon sends `DrainRequest` with `seq=0`, and the helper-side drain handler treats that value as the target boundary. As a result, demotion prep can declare the stream drained without proving that all in-flight events up to a meaningful boundary were flushed.

## Why this matters
Graceful RG demotion is using this path as part of the handoff barrier before `PrepareRGDemotion(...)`. If the drain request does not fence a real sequence boundary, the final barrier can run after an incomplete stream flush. That leaves room for session updates to miss the new primary during failover under load.

## Code
Daemon side:
- [pkg/dataplane/userspace/eventstream.go:116](https://github.com/psaab/bpfrx/blob/master/pkg/dataplane/userspace/eventstream.go#L116) `SendDrainRequest(...)` writes `EventTypeDrainRequest` with `seq=0`
- [pkg/daemon/daemon.go:4009](https://github.com/psaab/bpfrx/blob/master/pkg/daemon/daemon.go#L4009) demotion prep relies on `SendDrainRequest(...)` before the final peer barrier

Helper side:
- [userspace-dp/src/event_stream.rs:781](https://github.com/psaab/bpfrx/blob/master/userspace-dp/src/event_stream.rs#L781) treats the control-frame sequence as the drain target
- [userspace-dp/src/event_stream.rs:796](https://github.com/psaab/bpfrx/blob/master/userspace-dp/src/event_stream.rs#L796) exits as soon as the replay buffer already satisfies `>= target_seq`

Because `target_seq` is currently always `0`, this path is not fencing anything meaningful.

## Expected fix
Use a real target sequence for demotion drain, for example the daemon requesting a drain through the highest event sequence it has observed or the helper capturing a pause watermark and draining through that watermark before returning `DrainComplete`.

## Failover impact
This is directly on the graceful failover path and can leave the old owner / new owner handoff incomplete under sustained `iperf3 -P 8` load.

---

## #268 — daemon event-stream ack advances before session event callback finishes [CLOSED] (closed 2026-03-29)

## Summary
The daemon-side userspace event-stream receiver marks a sequence as received before the event callback finishes, and the background ack loop acknowledges that sequence independently. This makes the replay/ack contract unsound: the helper can trim replay state for events that the daemon has not actually finished applying yet.

## Why this matters
The local helper->daemon stream is supposed to be the lower-latency path for userspace session replication. If `Ack` means "read from the socket" instead of "fully handed off to session sync", reconnect/replay can lose events under slow callbacks, demotion prep, or daemon-side stalls.

## Code
- [pkg/dataplane/userspace/eventstream.go:271](https://github.com/psaab/bpfrx/blob/master/pkg/dataplane/userspace/eventstream.go#L271) stores `lastRecvSeq` before invoking `onEvent(...)`
- [pkg/dataplane/userspace/eventstream.go:315](https://github.com/psaab/bpfrx/blob/master/pkg/dataplane/userspace/eventstream.go#L315) runs a separate periodic ack loop
- [pkg/dataplane/userspace/eventstream.go:330](https://github.com/psaab/bpfrx/blob/master/pkg/dataplane/userspace/eventstream.go#L330) sends `Ack` based on `lastRecvSeq` rather than on post-callback completion

That means a slow or blocked `onEvent(...)` can still be acked to the helper.

## Expected fix
Advance the ack watermark only after the event callback has completed and the daemon has accepted responsibility for replaying the event. If the callback path becomes asynchronous, it needs an explicit processed/applied watermark rather than reusing the raw socket receive sequence.

## Failover impact
This weakens the reliability of the new userspace session event stream exactly where failover is most sensitive: reconnect, replay, and quiescence around RG moves.

---

## #269 — graceful demotion currently drops kernel session-open sync events instead of draining them [CLOSED] (closed 2026-03-29)

## Summary
During userspace demotion prep, the daemon pauses the sweep producer but does not drain or journal the kernel-side `SESSION_OPEN` event producer. It simply returns early from the event callback while demotion prep is active. New kernel sessions opened in that window are therefore dropped from the near-real-time sync path.

## Why this matters
Under active failover load, graceful demotion is supposed to stop at a well-defined handoff point. Right now the kernel event producer is not part of that handoff. Events that arrive after demotion prep starts but before the RG move completes are neither synced immediately nor explicitly fenced.

## Code
- [pkg/daemon/daemon.go:721](https://github.com/psaab/bpfrx/blob/master/pkg/daemon/daemon.go#L721) drops ring-buffer `SESSION_OPEN` events when `userspaceDemotionPrepActive()` is true
- [pkg/cluster/sync.go:817](https://github.com/psaab/bpfrx/blob/master/pkg/cluster/sync.go#L817) `PauseIncrementalSync(...)` only pauses the sweep producer
- [pkg/daemon/daemon.go:3998](https://github.com/psaab/bpfrx/blob/master/pkg/daemon/daemon.go#L3998) demotion prep then focuses on userspace export/drain and the peer barrier

This leaves the kernel-side event producer outside the demotion drain contract.

## Expected fix
Either:
- explicitly buffer/journal kernel session-open events during demotion prep and flush them before the final barrier, or
- bring the kernel producer under the same pause/drain protocol as the userspace producer

Relying on the later sweep to recover these opens is too weak for graceful failover handoff.

## Failover impact
This is a direct gap in the current graceful RG move path and can contribute to established-flow loss when new or refreshed kernel sessions appear during demotion prep.

---

## #270 — session sync still double-produces steady-state kernel updates via ring events and LastSeen sweep [CLOSED] (closed 2026-03-29)

## Summary
The current session-sync path still has two independent steady-state kernel producers:

1. the near-real-time `SESSION_OPEN` ring-buffer callback
2. the periodic sweep that republishes sessions whenever `Created` or `LastSeen` crosses the sweep threshold

There is no explicit dedup or precedence between those paths. Under load, this amplifies send-queue pressure and makes quiescence/barrier timing noisier than it needs to be.

## Why this matters
We are trying to make HA failover deterministic under sustained traffic, but the producer model is still partly event-driven and partly sweep-driven. The sweep is not limited to create/delete or material state changes; it republishes based on `LastSeen`, which is a very coarse trigger for HA survivability.

## Code
Event producer:
- [pkg/daemon/daemon.go:715](https://github.com/psaab/bpfrx/blob/master/pkg/daemon/daemon.go#L715) wires `SESSION_OPEN` to immediate `QueueSessionV4/V6(...)`

Sweep producer:
- [pkg/cluster/sync.go:673](https://github.com/psaab/bpfrx/blob/master/pkg/cluster/sync.go#L673) still defaults to a 1-second active sweep interval
- [pkg/cluster/sync.go:755](https://github.com/psaab/bpfrx/blob/master/pkg/cluster/sync.go#L755) republishes sessions when `Created >= threshold || LastSeen >= threshold`

There is no explicit coordination saying "ring event owns create, sweep only reconciles missed events."

## Expected fix
Shift kernel session sync to an event-first model:
- ring/event path owns fresh create/delete delivery
- sweep becomes reconciliation/backstop
- stop using raw `LastSeen` movement as the main steady-state publication trigger

At minimum, document and implement producer precedence so the two paths are not both acting as primary steady-state publishers.

## Failover impact
This does not look like the only failover bug, but it does increase sync queue pressure and makes `WaitForIdle(...)` / barrier-based handoff harder to reason about under `iperf3 -P 8` traffic.

---

## #271 — show security flow sessions walks and sorts the full session table before printing [CLOSED] (closed 2026-03-29)

## Summary
`show security flow sessions` is slow from the CLI because the local implementation in `pkg/cli/cli.go` fully walks the IPv4 and IPv6 session maps, materializes every matching forward session into slices, sorts the entire result set by `SessionID`, and then does additional per-session work while formatting.

## Why this is slow
The current local CLI path does all of this in-process:

- iterate all forward IPv4 sessions
- iterate all forward IPv6 sessions
- append all matches into slices
- sort the full slice(s) by `SessionID`
- perform a reverse-session lookup for each displayed session to merge counters
- resolve application names while rendering

That makes latency scale with total session count instead of the amount of output the operator actually needs.

## Code
Local CLI path:
- [pkg/cli/cli.go:3325](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3325) collects all IPv4 sessions for later sorting
- [pkg/cli/cli.go:3367](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3367) sorts all IPv4 entries
- [pkg/cli/cli.go:3422](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3422) resolves policy/app display during render
- [pkg/cli/cli.go:3476](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3476) repeats the same pattern for IPv6

The reverse-lookup merge is another multiplier:
- [pkg/cli/cli.go:3449](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3449) / adjacent local logic performs reverse/NAT formatting after per-session data gathering
- the same pattern also exists server-side in `GetSessions(...)` for peer fetches

## Expected fix
Move away from full-table CLI materialization. Reasonable options:

1. server-side paged / streaming session listing
2. limit-first traversal for non-summary views
3. avoid full in-memory sort for default output
4. avoid per-entry reverse lookup unless explicitly requested
5. make brief/summary the cheap default and reserve expensive enrichment for detailed mode

## Desired outcome
`show security flow sessions` should return quickly even with large session tables, especially for filtered and non-summary queries.

---

## #272 — show security flow sessions interface filter is currently only a zone filter [CLOSED] (closed 2026-03-29)

## Summary
`show security flow sessions interface <ifname>` does not actually filter sessions by interface. The CLI resolves the interface to a zone ID and then matches any session whose ingress or egress zone equals that zone. On multi-interface zones, this is both incorrect and unnecessarily expensive.

## Why this is wrong
Operators expect an interface filter to answer "what sessions are hitting this interface?" Today it answers "what sessions are in the same zone as this interface?" Those are not the same thing.

## Code
- [pkg/cli/cli.go:3140](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3140) parses `interface` and resolves it to `zoneID`
- [pkg/cli/cli.go:3178](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3178) matches IPv4 sessions by `IngressZone` / `EgressZone`
- [pkg/cli/cli.go:3209](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3209) does the same for IPv6

No actual ingress/egress interface comparison happens in the filter path.

## Expected fix
Add real interface-aware filtering based on the session's resolved ingress and egress interface data. At minimum:

- use the existing `IngressInterface` / `EgressInterface` model in `SessionEntry` consistently
- support both ingress and egress interface matching
- stop collapsing interface filters into zone filters

## Performance impact
This is also a performance issue because a fake interface filter does not prune nearly as much as a true interface filter would. On large zones it still forces the CLI through a wide session-table walk and render path.


---

## #273 — show security flow sessions should display interfaces and zones consistently [CLOSED] (closed 2026-03-29)

## Summary
`show security flow sessions` does not display ingress/egress interfaces and zones consistently across local and peer output, even though the data model already carries both.

## Current gaps
Local detailed CLI output:
- prints `If:` on the `In:` / `Out:` lines
- does **not** print explicit ingress/egress zone names in the detailed session body

Peer detailed output:
- prints `Zone: <ingress> -> <egress>`
- does **not** print ingress/egress interfaces, even though `SessionEntry` already contains them

Brief output:
- prints a single combined zone column
- does not show interfaces at all

## Code
Local detailed rendering:
- [pkg/cli/cli.go:3440](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3440)
- [pkg/cli/cli.go:3461](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3461)

Peer detailed rendering:
- [pkg/cli/cli.go:3742](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3742)
- [pkg/cli/cli.go:3752](https://github.com/psaab/bpfrx/blob/master/pkg/cli/cli.go#L3752)

Available data model fields:
- [pkg/grpcapi/bpfrxv1/bpfrx.pb.go:2430](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/bpfrxv1/bpfrx.pb.go#L2430) `IngressInterface`
- [pkg/grpcapi/bpfrxv1/bpfrx.pb.go:2431](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/bpfrxv1/bpfrx.pb.go#L2431) `EgressInterface`
- [pkg/grpcapi/bpfrxv1/bpfrx.pb.go:2424](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/bpfrxv1/bpfrx.pb.go#L2424) `IngressZoneName`
- [pkg/grpcapi/bpfrxv1/bpfrx.pb.go:2425](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/bpfrxv1/bpfrx.pb.go#L2425) `EgressZoneName`

## Expected fix
Standardize the session display format so every detailed session entry shows:

- ingress zone
- egress zone
- ingress interface
- egress interface

Do this consistently for:

*(truncated — 48 lines total)*


---

## #274 — GetSessions RPC still builds session listings with full-table iteration and per-entry enrichment [CLOSED] (closed 2026-03-29)

## Summary
The `GetSessions` gRPC path is still expensive enough that moving the CLI to RPC would not, by itself, solve `show security flow sessions` latency. The server still iterates the full session table, performs per-session reverse lookups, assembles an in-memory slice, and sorts it before returning.

## Why this matters
The local CLI currently does its own full-table walk. That is one problem. But the server-side path used for peer sessions already has the same shape, so the system lacks a cheap authoritative listing path.

## Code
Server-side session listing:
- [pkg/grpcapi/server.go:896](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/server.go#L896) iterates IPv4 sessions
- [pkg/grpcapi/server.go:930](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/server.go#L930) does reverse-session lookup per included IPv4 session
- [pkg/grpcapi/server.go:944](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/server.go#L944) repeats the same for IPv6
- [pkg/grpcapi/server.go:989](https://github.com/psaab/bpfrx/blob/master/pkg/grpcapi/server.go#L989) sorts the full assembled result slice

## Additional concern
`limit` and `offset` are applied while iterating, but the server still walks the full table to compute `Total` and still builds/sorts the returned slice after expensive enrichment. This is not a streaming or cheap-paging design.

## Expected fix
Add a real server-side session listing strategy for large tables, for example:

- streaming RPC for session rows
- server-side cursor / page token instead of naive offset
- optional enrichment flags so reverse lookup / app resolution are not always paid
- shared local/peer renderer on top of that API so CLI behavior is consistent

## Desired outcome
We should have one authoritative, scalable session-listing path rather than two different full-table walkers (local CLI and peer gRPC) that both become slow on large session tables.'


---

## #275 — GetSessions still relies on full-table iteration and eager enrichment after sort removal [CLOSED] (closed 2026-03-31)

## Summary
Current `master` fixed the worst part of the original `GetSessions` complaint by removing the full-result sort path, but the underlying RPC is still not a scalable listing API.

The remaining problem is narrower:
- `GetSessions` still walks the full session table to compute `Total` and apply filters
- it still does per-entry reverse lookup / counter merge for returned rows
- it still resolves application names while assembling the response
- it still returns a materialized slice instead of a true streaming or cursor-based result

## Why this matters
This is still expensive enough that moving more CLI usage onto `GetSessions` would not make large session listings cheap. We still do not have one authoritative, scalable session-listing path for local and peer use.

## Current code
- `pkg/grpcapi/server.go:793` `GetSessions(...)`
- `pkg/grpcapi/server.go:896` and `pkg/grpcapi/server.go:944` iterate IPv4 and IPv6 sessions
- `pkg/grpcapi/server.go:916` and `pkg/grpcapi/server.go:981` still do per-entry reverse lookup / merge for returned rows
- `pkg/grpcapi/server.go:918` and `pkg/grpcapi/server.go:983` still resolve application names during response assembly

## What changed already
The old full-result sort/materialize complaint from #274 is no longer fully accurate after `ecc5b0d3`. That part is fixed. This follow-up is specifically about the remaining full-table iteration and eager enrichment costs.

## Expected fix
Add a real scalable server-side listing model, for example:
- streaming RPC for session rows
- server-side cursor / page token instead of naive offset
- optional enrichment flags so reverse lookup / app resolution are not always paid
- shared local/peer renderer on top of that API so CLI behavior is consistent

## Desired outcome
`GetSessions` should become the cheap authoritative session-listing path, not just a slightly improved full-table walker.

---

## #276 — userspace demotion prep resumes helper event stream before final barrier completes [CLOSED] (closed 2026-03-31)

## Summary
During graceful userspace RG demotion, the daemon pauses the helper event stream, drains it, and then resumes it immediately before the final peer barrier and `PrepareRGDemotion(...)` complete.

That reopens the helper-side session-delta producer during the exact window that demotion prep is trying to fence.

## Why this matters
The current demotion contract is supposed to establish a quiesced, ordered handoff point before the old owner is demoted. Resuming the helper event stream before the final barrier means new helper-originated deltas can be emitted after the drain watermark but before the demotion handoff actually completes.

Under HA failover load, that reintroduces a race between:
- event-stream drain completion
- new helper deltas
- final peer barrier
- helper `PrepareRGDemotion(...)`

## Code
- `pkg/daemon/daemon.go:4128` starts demotion-prep sync pause
- `pkg/daemon/daemon.go:4132` begins the event-stream pause/drain path
- `pkg/daemon/daemon.go:4149` resumes the helper stream immediately after `DrainRequest`
- `pkg/daemon/daemon.go:4190` only later waits for the final peer barrier
- `pkg/daemon/daemon.go:4193` only then calls `PrepareRGDemotion(...)`

So the helper event stream is resumed before the final barrier and before the helper-side demotion prepare has actually run.

## Expected fix
Keep the helper event stream paused until the final barrier succeeds and `PrepareRGDemotion(...)` has completed, or introduce a stronger fenced watermark proving that post-drain helper deltas cannot race ahead of demotion.

## Failover impact
This weakens the current graceful demotion handoff and can make userspace failover look random under sustained forwarding load even when the new event-stream drain path itself is working.


---

## #277 — helper demotion and session-export waits still hardcode a 2s timeout [CLOSED] (closed 2026-03-31)

## Summary
The Rust helper still hardcodes a 2-second wait for worker acknowledgement in both demotion prepare and owner-RG session export.

The Go daemon-side demotion timeouts were increased to 15s and 30s, but the helper-side waits remain fixed at 2s.

## Why this matters
Under HA failover load, the worker command path is doing real work:
- flow-cache invalidation
- session-key collection
- reverse-session refresh
- delta flush

Those operations can legitimately take longer than 2 seconds on a busy system. When that happens, the helper fails first even though the daemon has already been tuned to allow a longer, bounded handoff window.

## Code
- `userspace-dp/src/afxdp.rs:1179` uses `Duration::from_secs(2)` for `prepare_ha_demotion()`
- `userspace-dp/src/afxdp.rs:1220` uses `Duration::from_secs(2)` for `export_owner_rg_sessions()`
- daemon-side callers now allow much longer windows:
  - `pkg/daemon/daemon.go:4012` manual demotion path uses 15s
  - `pkg/daemon/daemon.go:3987` general demotion path uses 30s

## Expected fix
Use a configurable or caller-provided timeout budget that matches the daemon-side demotion budget, or convert the helper-side wait into a progress-aware bounded wait instead of a fixed 2-second deadline.

## Failover impact
This can still cause demotion/export timeout failures under heavy HA transition load even after the daemon-side timeout tuning landed.


---

## #278 — userspace RG transition pre-switch has no rollback when UpdateRGActive fails [CLOSED] (closed 2026-03-31)

## Summary
`Manager.UpdateRGActive(...)` disables userspace ctrl and swaps the XDP entry program to `xdp_main_prog` before calling `inner.UpdateRGActive(...)`, but it does not roll back that pipeline change if the BPF rg_active update fails.

## Why this matters
The pre-switch is intentional for failover correctness, but it currently has no rollback path. If `UpdateRGActive(...)` fails, the node can be left in the fallback eBPF pipeline with ctrl disabled even though the RG state transition did not actually commit.

That is a partial transition with no recovery in the error path.

## Code
- `pkg/dataplane/userspace/manager.go:2665-2684` disables ctrl and swaps to `xdp_main_prog`
- `pkg/dataplane/userspace/manager.go:2687` calls `m.inner.UpdateRGActive(rgID, active)`
- `pkg/dataplane/userspace/manager.go:2687-2689` returns the error directly with no rollback of ctrl/XDP entry state

The liveness-state reset and HA sync only happen after the successful `UpdateRGActive(...)` call.

## Expected fix
Either:
- stage the pipeline switch only after `UpdateRGActive(...)` succeeds, or
- add an explicit rollback path that restores ctrl/XDP entry state when the rg_active update fails

## Failover impact
A transient rg_active update failure can leave the node stuck in the wrong forwarding pipeline during HA transitions, which is exactly the kind of partial state that makes failover look fragile.


---

## #279 — ctrl re-enable after RG transition is not gated on transitioned-RG convergence [CLOSED] (closed 2026-03-31)

## Summary
Ctrl re-enable after an RG transition is currently gated by generic helper readiness and any RX progress, not by an explicit "transitioned RG state has converged" signal.

The code comments say ctrl is held off so the helper can process HA updates and clean stale flow-cache entries for the transitioned RG, but the actual gate only checks:
- bindings ready
- neighbor generation > 0
- aggregate RX progress for any binding

## Why this matters
Under HA failover, unrelated background RX can satisfy the current liveness probe even if the transitioned RG's synced sessions and flow-cache state have not finished converging. That lets the userspace flow cache come back before the transition-specific helper work is actually complete.

## Code
- `pkg/dataplane/userspace/manager.go:2700-2714` resets liveness state after RG transition and says ctrl should wait for HA processing to settle
- `pkg/dataplane/userspace/manager.go:2973-3039` re-enables ctrl based on aggregate RX progress and generic helper readiness

There is no transition-specific acknowledgement or generation proving that:
- demoted RG state was fully applied
- activated RG synced sessions were re-resolved
- transitioned flow-cache entries were fully invalidated/refreshed

## Expected fix
Add an explicit post-transition convergence signal from the helper/worker path and gate ctrl re-enable on that signal, not just on generic RX liveness.

Examples:
- per-RG transition generation/ack
- helper-reported completion of `DemoteOwnerRG` / `RefreshOwnerRGs`
- a transition-scoped watermark carried back in helper status

## Failover impact
This leaves a gap where ctrl can resume too early under load, reintroducing stale userspace forwarding decisions during the exact HA transition window the eBPF fallback is meant to cover.


---

## #280 — daemon event-stream watermarks survive helper reconnect and stale-drain the next connection [CLOSED] (closed 2026-03-31)

## Summary
The daemon-side userspace event stream does not reset its receive/applied/ack state when the helper reconnects.

If the helper process restarts and its local event-stream sequence restarts from 1, the daemon still carries forward the old:
- `lastRecvSeq`
- `lastAppliedSeq`
- `lastAckSeq`

## Why this matters
That stale sequence state directly feeds demotion drain and ack behavior:
- `SendDrainRequest(...)` uses `lastAppliedSeq` as the drain fence
- the ack loop compares `lastAppliedSeq` to `lastAckSeq`
- `readLoop(...)` seeds `prevSeq` from the prior connection's `lastRecvSeq`

After a helper restart, the daemon can therefore:
- send a stale drain target far above the new helper sequence space
- suppress or distort ack behavior based on the previous connection
- treat a new connection as if it were a continuation of the old sequence stream

## Code
- `pkg/dataplane/userspace/eventstream.go:163-172` accepts a new helper connection without resetting sequence state
- `pkg/dataplane/userspace/eventstream.go:202` seeds `prevSeq` from `es.lastRecvSeq.Load()`
- `pkg/dataplane/userspace/eventstream.go:127-131` fences `DrainRequest` to `lastAppliedSeq`

## Expected fix
Reset daemon-side event-stream watermarks on a fresh helper connection, or explicitly negotiate connection epochs so sequence/drain/ack state cannot bleed across helper restarts.

## Failover impact
A helper restart during or before HA failover can leave the demotion drain path and replay/ack bookkeeping working against stale sequence numbers, which is exactly the wrong place to be unsound.


---

## #281 — HA session refresh paths still scan and clone the full helper session tables [CLOSED] (closed 2026-03-31)

## Summary
The current HA transition helpers still do full-table session cloning/re-resolution on RG activation and demotion-related refresh paths.

That makes transition work scale with the total session table, not just with the sessions owned by the RG being moved.

## Why this matters
These functions run on the userspace helper path during ownership changes. Under sustained forwarding load, a full-table scan/clone/re-resolution step directly competes with the packet path and stretches failover convergence latency.

## Code
Two especially expensive paths:

1. `prewarm_reverse_synced_sessions_for_owner_rgs(...)`
- `userspace-dp/src/afxdp/session_glue.rs:527-535`
- clones all synced forward entries from `shared_sessions`

2. `refresh_live_reverse_sessions_for_owner_rgs(...)`
- `userspace-dp/src/afxdp/session_glue.rs:585-597`
- clones every local session into `candidates` before filtering/refresolving

The second function's own comment says it refreshes all local sessions when an owner RG activates.

## Expected fix
Move these paths toward RG-scoped indexing or incremental ownership tracking so activation/demotion refresh work is bounded by the transitioned RG instead of the whole helper session table.

At minimum:
- avoid cloning the full table up front
- keep per-owner-RG indexes for synced and local sessions
- refresh only the sessions whose owner or dependent reverse state can actually change for the transitioned RG

## Failover impact
This is a direct scaling gap in the current HA transition path and is a plausible contributor to the forwarding stalls still seen during loaded RG moves.


---

## #282 — ctrl re-enable stale-session cleanup stops after fixed delete caps [CLOSED] (closed 2026-03-31)

## Summary
The ctrl re-enable cleanup path flushes stale BPF session state with hard-coded caps:
- `userspace_sessions` stops after 100000 deletes
- `sessions` / `sessions_v6` stop after 200000 deletes per map

That means the cleanup can silently leave stale entries behind in larger tables.

## Why this matters
The code comments are explicit that these stale entries poison the post-transition userspace path:
- stale `userspace_sessions` entries can bypass the helper and keep traffic on the fallback path
- stale BPF conntrack entries can interfere with NAT/session state when ctrl is re-enabled

If the flush stops early, the code can report success while still leaving exactly the stale state it is trying to eliminate.

## Code
- `pkg/dataplane/userspace/manager.go:3058-3073` stops `userspace_sessions` cleanup after 100000 deletions
- `pkg/dataplane/userspace/manager.go:3082-3097` stops conntrack cleanup after 200000 deletions per map

There is no retry, pagination marker, or follow-up pass. The cleanup simply breaks out.

## Expected fix
Make the stale-state cleanup complete and observable:
- continue until the maps are actually empty, or
- chunk the work across multiple passes with explicit progress tracking and a final completion condition

At minimum, surface whether cleanup hit the cap so operators know stale state may still remain.

## Failover impact
Large transition windows or busy systems can accumulate more stale entries than these caps allow, leaving post-failover forwarding poisoned even though ctrl has been re-enabled.


---

## #283 — pendingRGTransition stays set when syncHAStateLocked fails [CLOSED] (closed 2026-03-31)

## Summary
`pkg/dataplane/userspace/manager.go` uses a single boolean `pendingRGTransition` to hold ctrl disabled until `syncHAStateLocked()` completes, but it only clears that flag on the success path.

If `syncHAStateLocked()` fails, the flag stays true indefinitely.

## Why this matters
`applyHelperStatusLocked()` now forces `ctrl.Enabled = 0` whenever `status.Enabled && m.pendingRGTransition`.

That means one failed HA state sync can leave the manager permanently believing an RG transition is still in progress, keeping ctrl disabled on subsequent helper status updates.

## Code
- `pkg/dataplane/userspace/manager.go:2719` sets `m.pendingRGTransition = true`
- `pkg/dataplane/userspace/manager.go:2720-2722` returns on `syncHAStateLocked()` error without clearing it
- `pkg/dataplane/userspace/manager.go:2914-2918` suppresses ctrl enable whenever `pendingRGTransition` is true

## Expected fix
Clear the transition flag in a `defer`, or move to an explicit per-transition token/generation so the error path cannot leave the manager stuck in perpetual transition mode.

## Failover impact
A transient HA-sync error can leave forwarding stuck on the fallback pipeline with ctrl held down long after the actual RG transition failed or completed.


---

## #284 — single global pendingRGTransition bool is not sufficient for multi-RG HA transitions [CLOSED] (closed 2026-03-31)

## Summary
`pendingRGTransition` is a single process-wide boolean, not a per-RG or per-transition generation.

That is too weak for overlapping or back-to-back RG transitions.

## Why this matters
Recent failover changes now rely on `pendingRGTransition` as the gating mechanism that keeps ctrl disabled until HA state convergence. But a single boolean cannot represent:
- multiple RGs moving in one failover sequence
- rapid failover/failback cycles
- one transition finishing while another is still in flight

Any of those can clear or retain the flag at the wrong time.

## Code
- `pkg/dataplane/userspace/manager.go:67` defines `pendingRGTransition bool`
- `pkg/dataplane/userspace/manager.go:2719` sets it true for a transition
- `pkg/dataplane/userspace/manager.go:2723` clears it on success
- `pkg/dataplane/userspace/manager.go:2914-2918` uses that single boolean to block ctrl re-enable globally

## Expected fix
Replace the boolean with transition-scoped state, for example:
- per-RG pending state, or
- a monotonically increasing transition generation acknowledged by helper status

The ctrl gate should depend on whether the current transition generation has been applied, not on a single global bool.

## Failover impact
This can re-enable ctrl too early or hold it down too long during multi-RG or rapid failover sequences, which matches the class of fragile forwarding behavior still being reported.


---

## #285 — promoting node no longer pre-switches out of userspace before RG activation [CLOSED] (closed 2026-03-31)

## Summary
The current activation path no longer pre-switches the promoting node to the eBPF pipeline before `rg_active=1`.

Current code only disables ctrl / swaps to `xdp_main_prog` on demotion, not on activation.

## Why this matters
Standby HA nodes intentionally keep the userspace helper armed so they can handle stale-owner traffic. That means the promoting node can already have live userspace flow-cache state and synced sessions before its RG becomes active.

Without an activation-side pre-switch, the promoting node can still serve packets from stale userspace state before the helper finishes:
- HA state refresh
- synced-session re-resolution
- flow-cache invalidation/refresh for the activated RG

## Code
- `pkg/dataplane/userspace/manager.go:2653-2673` pre-switches only on `!active`
- `pkg/dataplane/userspace/manager.go:2674-2679` explicitly says ctrl disable + eBPF swap is only on demotion now
- standby helpers remain armed by design in `desiredForwardingArmedLocked()` for HA data RGs

## Expected fix
Add an activation-specific transition guard that prevents the promoting node from serving stale userspace flow-cache decisions before activation convergence completes.

That does not necessarily mean reintroducing the exact old startup behavior; it may need a transition-scoped mechanism separate from generic startup liveness.

## Failover impact
This leaves the new owner exposed to stale userspace forwarding state during RG activation, which is a plausible remaining cause of forwarding collapse even after the demotion-side pre-switch fixes landed.


---

## #286 — HA reverse-session refresh still clones the full local session table before filtering [CLOSED] (closed 2026-03-31)

## Summary
The recent `#281` follow-up reduced some HA refresh work, but `refresh_live_reverse_sessions_for_owner_rgs(...)` still clones every local session into a candidate vector before filtering by owner RG.

So the path still does full-table scan + clone work during RG activation.

## Why this matters
The function runs in the userspace helper transition path, under load, while failover convergence is time-sensitive. The current shape still scales with total session table size rather than with the transitioned RG.

## Code
- `userspace-dp/src/afxdp/session_glue.rs:585-597`
- the function builds `candidates` by iterating all sessions and cloning `(key, decision, metadata, origin)` for every entry
- only after that does it filter with owner-RG checks later in the loop

## Expected fix
Do the RG scoping before cloning, or maintain per-owner-RG indexes so the transition path can walk only the sessions that can actually change for the activated/demoted RG.

## Failover impact
This still leaves a full-table helper-side transition cost in the hot failover path and undermines the intent of the recent #281 performance fix.


---

## #287 — reverse-session prewarm now filters too narrowly by forward session owner RG [CLOSED] (closed 2026-03-31)

## Summary
`prewarm_reverse_synced_sessions_for_owner_rgs(...)` now filters synced forward sessions by `entry.metadata.owner_rg_id`, but its own logic and comments say reverse-companion refresh can depend on a newly active client-side egress RG, not only on the forward session's existing owner RG.

That means the new filter can skip sessions whose reverse companion should change because a different RG became active.

## Why this matters
This is exactly the kind of split-RG failback case the comment describes: a reverse companion previously synthesized as `FabricRedirect` can need to flip back to local forwarding when another RG becomes active.

If the forward session's stored `owner_rg_id` is not in the activated set, the new code now skips it entirely.

## Code
- `userspace-dp/src/afxdp/session_glue.rs:520-526` says reverse companions depend on current HA state of the client-side egress RG, not only the forward session owner RG
- `userspace-dp/src/afxdp/session_glue.rs:527-535` now filters only on `owner_rg_set.contains(&entry.metadata.owner_rg_id)`

## Expected fix
The prewarm path needs to key off the RGs that can affect the refreshed reverse resolution, not just the forward session's stored owner RG. If that requires a richer dependency model, the current filter is too aggressive.

## Failover impact
This can leave reverse companions pinned to stale `FabricRedirect` or remote-owner behavior across split-RG activation/failback, which is directly relevant to the forwarding fragility still being debugged.


---

## #288 — userspace pending-neighbor retry ignores non-dynamic neighbor state [CLOSED] (closed 2026-03-31)

## Problem
The userspace helper's buffered first-packet retry path only rechecks `dynamic_neighbors` and ignores the full forwarding neighbor view.

That means a first-hit `MissingNeighbor` packet can stay stranded even when the kernel already has a usable ARP/NDP entry or the forwarding snapshot contains one, as long as no fresh helper `dynamic_neighbors` update lands for that `(ifindex, ip)`.

## Current code
- `retry_pending_neigh()` only looks in `dynamic_neighbors`:
  - `userspace-dp/src/afxdp.rs`
- normal forwarding resolution uses `lookup_neighbor_entry(...)`, which checks:
  - `state.neighbors`
  - then `dynamic_neighbors`
  - `userspace-dp/src/afxdp/forwarding.rs`

So the retry path is strictly narrower than the normal resolution path.

## Why this matters
On the HA userspace cluster after a rolling deploy, the active helper reported:
- `Last resolution: missing_neighbor ... next-hop=172.16.80.200`
- kernel route and ARP were already present on the router for `172.16.80.200`
- cluster-host traffic to `172.16.80.200` still failed

This is exactly the kind of case where the first buffered packet can remain stuck because the helper retry path is not consulting the same neighbor sources as the regular resolution path.

## Live evidence
On March 29, 2026 / March 30, 2026 UTC in `loss-userspace-cluster`:
- `fw0` kernel had:
  - `172.16.80.200 dev ge-0-0-2.80 lladdr ... STALE`
- helper still reported:
  - `Last resolution: missing_neighbor ... next-hop=172.16.80.200`
- failover validator aborted before failover because steady-state `.200` reachability was broken after deploy

Artifact:
- `/tmp/userspace-ha-failover-rg1-20260329-204323`

## Fix direction
Make `retry_pending_neigh()` use the same neighbor lookup semantics as normal forwarding resolution:
- use `lookup_neighbor_entry(forwarding, Some(dynamic_neighbors), ifindex, hop)`
- do not limit retry recovery to the dynamic cache only

## Acceptance

*(truncated — 43 lines total)*


---

## #289 — userspace reply-side redirect is missing for post-deploy SNATed direct-host ICMP [CLOSED] (closed 2026-03-31)

## Problem
After a rolling deploy on the HA userspace cluster, SNATed direct-host ICMP from the LAN can be forwarded out by the userspace dataplane while the reply side never reaches the helper.

This leaves steady-state forwarding broken before failover even starts.

## Live evidence
On March 29, 2026 / March 30, 2026 UTC in `loss-userspace-cluster`:
- `cluster-userspace-host -> 172.16.80.200` failed after deploy
- router-originated `fw0 -> 172.16.80.200` ping succeeded
- helper counters around a 3-packet host ping showed:
  - `RX packets: +3`
  - `Forward candidates: +3`
  - `TX packets: +3`
  - host still got `0/3` replies

That means the forward direction is transmitting, but the reply direction is not making it back through the userspace dataplane.

Related artifact:
- `/tmp/userspace-ha-failover-rg1-20260329-204323`

## Why this points at the reply-side redirect path
The helper transmitted the requests, so this is not just a forward-route or neighbor-miss failure.

The missing side is reply ingress for traffic addressed back to the interface-NAT / SNAT source address (`172.16.80.8` in this case).

The likely fault domain is one of:
- reverse live-session key publication in `publish_live_session_entry(...)`
- reply-side lookup / promotion in `resolve_flow_session_decision(...)`
- XDP pre-redirect classification for interface-NAT destinations in `userspace-xdp/src/lib.rs`
- reply-side ICMP key agreement between the helper and `USERSPACE_SESSIONS`

## Code areas to review
- `userspace-dp/src/afxdp/bpf_map.rs`
- `userspace-dp/src/afxdp/session_glue.rs`
- `userspace-xdp/src/lib.rs`

## Acceptance
- after deploy, `cluster-userspace-host -> 172.16.80.200` succeeds without needing a router-originated warmup ping
- helper RX counters show both request and reply traffic for that flow
- the post-deploy failover gate reaches the actual failover phase instead of failing on the steady-state `.200` baseline

*(truncated — 41 lines total)*


---

## #290 — ordinary XDP reply path lacks reverse-NAT fallback for interface-NAT destinations [CLOSED] (closed 2026-03-31)

## Problem
The ordinary non-GRE XDP entry path has no reply-side reverse-NAT fallback when a packet is destined to an interface NAT IP and the `userspace_sessions` lookup misses.

Current flow in `userspace-xdp/src/lib.rs`:
- `live_userspace_session_action(&parsed)`
- if that misses:
  - `is_icmp_to_interface_nat_local(&parsed)` => pass to kernel
  - `is_local_destination(&parsed) || is_interface_nat_destination(&parsed)` => pass to kernel
  - otherwise redirect to userspace helper

Unlike the native GRE inner-path classifier, the ordinary IPv4/IPv6 path does **not** do a DNAT/reverse-NAT table lookup before deciding to hand reply traffic for NAT interface addresses to the kernel.

## Why this matters
This makes forwarded return traffic fragile under any timing or key-shape gap between:
- helper session creation / reverse-wire key publish to `userspace_sessions`
- first return packet arrival

If the first reply packet misses `userspace_sessions`, it is treated as local-to-the-box traffic because the destination is the interface NAT IP, and it never reaches the userspace dataplane reply path.

## Live evidence
On current `master`, active-owner repro on `fw0`:
- helper logs show forwarded LAN SYN RX and WAN SYN TX:
  - `bpfrx-wan80-tcp: rx ingress_if=5 vlan=0 src=10.0.61.102:44406 dst=172.16.80.200:5201 flags=0x02`
  - `bpfrx-wan80-tcp: tx-submit-prepared ... 172.16.80.8:44406 -> 172.16.80.200:5201 TCP [SYN]`
- helper delta for one failed connect:
  - `RX packets +4`
  - `SNAT packets +4`
  - `TX packets +4`
  - `DNAT packets +0`
  - `Slow path local-delivery +0`
- `userspace_sessions` contains the reverse wire key with redirect action for the flow
- helper never logs any matching WAN reply RX
- kernel `TcpOutRsts` on `fw0` stays flat during the failed connect

This is the exact failure shape where reply-side classification needs a second chance before treating interface-NAT traffic as kernel-local.

## Proposed fix
One of these needs to happen in the ordinary XDP path:
1. Add a reply-side reverse-NAT / DNAT fallback before `is_interface_nat_destination()` sends the packet to the kernel.
2. Add a dedicated pending-reply classification map for newly-created interface-NAT sessions so the first return packet is still redirected to userspace.

*(truncated — 47 lines total)*


---

## #291 — XDP interface-NAT session misses are not surfaced as a distinct counter or trace path [CLOSED] (closed 2026-03-31)

## Problem
The XDP entry path has no dedicated trace/counter for the specific case:
- packet is destined to an interface NAT IP
- `userspace_sessions` lookup misses
- packet is handed to the kernel via the generic local-destination path

There is already a constant for this failure mode in `userspace-xdp/src/lib.rs`:
- `USERSPACE_FALLBACK_REASON_INTERFACE_NAT_NO_SESSION`

But it is not used anywhere in the actual decision tree.

## Why this matters
This made the current forwarding investigation much harder than it needed to be.

Observed live failure shape on `fw0`:
- helper clearly receives the forwarded LAN SYN
- helper clearly emits the SNATed WAN SYN
- helper never sees a reply RX
- `DNAT packets` stays `0`
- kernel `TcpOutRsts` stays flat

From current counters alone, that is almost impossible to distinguish from:
- no reply on wire
- reply arriving on wrong node
- reply being passed to kernel as interface-local
- reply missing `userspace_sessions` and being silently misclassified

## What is missing
- a dedicated fallback counter for interface-NAT session misses
- a dedicated trace stage for that miss path
- optional per-interface or per-destination visibility so operators can tell which NAT IP is failing

## Proposed fix
- actually use `USERSPACE_FALLBACK_REASON_INTERFACE_NAT_NO_SESSION`
- add a distinct trace stage when a packet to an interface NAT IP misses `userspace_sessions`
- surface that counter in userspace dataplane stats / `monitor interface`

## Acceptance criteria
- a failed forwarded reply to a NAT interface address produces an explicit counter and trace reason
- operators can tell the difference between:

*(truncated — 45 lines total)*


---

## #292 — userspace helper TX counters do not fully describe prepared fast-path transmit state [CLOSED] (closed 2026-03-31)

## Problem
Userspace helper TX observability is not good enough to distinguish:
- packet prepared for AF_XDP transmit
- descriptor submitted to TX ring
- packet completed by the kernel/NIC
- packet sent via direct/copy/in-place rewrite path

During the current forwarding repro on active `fw0`:
- helper logs show `bpfrx-wan80-tcp: tx-submit-prepared ...`
- per-connect delta shows `TX packets +4`
- but aggregate stats still show:
  - `Direct TX packets: 0`
  - `Copy-path TX packets: 0`
  - `In-place TX packets: 0`
  - `TX completions: 0`

That makes it hard to prove whether a forwarded packet actually made it onto the AF_XDP TX ring and out to the wire, or only advanced through earlier helper-side bookkeeping.

## Why this matters
This investigation had to fall back to side channels like interface counters and tcpdump because the helper stats do not tell a coherent TX story for prepared fast-path packets.

## Proposed fix
- expose separate counters for:
  - prepared packets queued
  - TX descriptors inserted
  - TX wakeups issued
  - TX completions reaped
- make the existing direct/copy/in-place counters line up with all fast-path transmit paths, including prepared requests
- surface the per-binding version in `monitor interface`

## Acceptance criteria
- for one forwarded host connect, helper stats can answer:
  - how many packets were prepared
  - how many were inserted into the TX ring
  - how many completed
  - which TX mode was used
- no need to infer transmit state indirectly from interface counters


---

## #293 — userspace compiler falls back all interfaces to generic XDP on one attach failure [CLOSED] (closed 2026-03-31)

## Summary
On the userspace cluster, a single native XDP attach failure on `ifindex=4` causes the compiler to downgrade **all** interfaces to generic XDP (`xdpgeneric`). That global downgrade then changes dataplane behavior far beyond the failing interface.

## Evidence
- Repeated daemon log on current `master`:
  - `native XDP not supported, falling back ALL to generic` `ifindex=4` `err="attach XDP to ifindex 4: failed to attach link: create link: invalid argument"`
- After that fallback, all userspace data interfaces show `xdpgeneric` in the guest:
  - `ge-7-0-0`
  - `ge-7-0-1`
  - `ge-7-0-2`
- The failing native attach is on `ge-7-0-0` (`virtio` fabric parent), but the downgrade also affects the `mlx5` LAN/WAN ports.

## Why this is a bug
The current policy is broader than necessary:
- some interfaces genuinely require generic mode
- other interfaces may still support native mode
- global fallback makes helper/bind assumptions brittle and can disable valid fast paths on unrelated interfaces

In this lab, global generic fallback is a key part of the forwarding break because later helper logic still assumes zero-copy is viable on non-virtio NICs.

## Expected behavior
If native attach fails on one interface, only that interface should fall back to generic unless there is a hard technical reason to require a uniform mode across all interfaces.

## Suggested fix
- Change XDP attach fallback from global to per-interface.
- Clear `IfaceFlagNativeXDP` only for interfaces that actually end up generic.
- Keep the existing tunnel/VLAN special cases, but do not downgrade unrelated physical interfaces.

## Repro context
- Cluster: `loss-userspace-cluster`
- Date: 2026-03-30
- Current `master` repeatedly logs the global fallback on restart.


---

## #294 — userspace helper picks zerocopy from driver name instead of actual XDP mode [CLOSED] (closed 2026-03-31)

## Summary
The userspace helper currently chooses AF_XDP bind flags from the NIC driver name, not from the interface's actual XDP attach mode. In the lab, this allowed `mlx5` interfaces running `xdpgeneric` to bind `zerocopy`, which broke steady-state forwarding to `.200`.

## Evidence
Current code path:
- `userspace-dp/src/afxdp/bind.rs`
- `bind_flag_candidates_for_driver()` prefers zerocopy for non-`virtio_net`
- `query_bound_xsk_mode()` later trusts `XDP_OPTIONS_ZEROCOPY`

Live repro on 2026-03-30:
- daemon log repeatedly shows:
  - `native XDP not supported, falling back ALL to generic` on `ifindex=4`
- guest interfaces then show `xdpgeneric`:
  - `ge-7-0-1` (`mlx5_core`)
  - `ge-7-0-2` (`mlx5_core`)
- helper still logged successful zerocopy binds on those interfaces:
  - `libxdp bind(... ) OK ... mode=ZeroCopy flags=0x000c`
- steady-state host -> `172.16.80.200` forwarding failed

A helper-only workaround that forced copy mode on generic non-virtio interfaces restored:
- forwarded ping to `172.16.80.200`
- TCP connect to `172.16.80.200:5201`
- short `iperf3` connectivity

## Why this is a bug
Driver capability is not enough. The bind decision must account for the actual XDP attach mode on that interface.

If an interface is in generic/SKB XDP mode, zerocopy should not be selected just because the NIC is `mlx5`.

## Expected behavior
AF_XDP bind mode selection should use the real interface XDP mode:
- generic/SKB XDP -> copy/auto only
- native/driver XDP -> zerocopy may be attempted

## Suggested fix
- Make helper bind selection mode-aware using actual XDP attach mode, not just driver name.
- Either:
  - pass attach mode to the helper in the snapshot/protocol, or
  - query it directly before binding (for example with `bpf_xdp_query()`/equivalent).
- Add status/debug output so operators can see both:

*(truncated — 48 lines total)*


---

## #297 — manual RG failover still collapses after reverse prewarm with stable ownership and flat session misses [CLOSED] (closed 2026-03-31)

## Summary

Manual `RG1` failover under inherited `iperf3 -P 8` load still collapses even after the latest reverse-session activation prewarm fix removed the earlier large new-owner `session_miss` burst.

## Evidence

Code checkpoint:
- `c84c35c7` `userspace: prewarm reverse sessions for activated RGs`

Artifacts:
- `/tmp/userspace-ha-failover-rg1-20260330-174231`
- `/tmp/manual-oneway-rg1-20260330-174744`

One-way failover summary:
- `68` intervals
- `51` zero-throughput intervals
- peak `20.600 Gbps`
- tail median `0.000 Gbps`

`iperf3` timeline:
- pre-failover: steady around `20 Gbps`
- first bad second: `3.17 Gbps`
- next second onward: sustained `0.00 bits/sec`

Control-plane state during the bad window:
- `node0` remains `RG1 secondary`
- `node1` remains `RG1 primary`
- no ownership flap during the collapse window

Helper/session evidence:
- `fw1 Sessions installed` starts at `151`, later `216`
- `fw0 Session misses` stays flat at `29`
- `fw1 Session misses` stays flat at `27-28`
- `Neighbor misses` stay flat
- `fw1 Slow path local-delivery` only grows slightly (`22 -> 32`)

## Interpretation

The earlier install failure signature is gone. The remaining bug is now more likely in the stale-owner demotion / redirected transport path than in new-owner session installation.


*(truncated — 46 lines total)*


---

## #298 — demotion cleanup immediately deletes shared USERSPACE_SESSIONS entries but leaves worker-local owner-RG sessions until async worker drain [CLOSED] (closed 2026-03-31)

## Summary

During helper `update_ha_state()` demotion, the immediate `USERSPACE_SESSIONS` cleanup only scans `shared_sessions`. Worker-local owner-RG sessions remain in the session map until `WorkerCommand::DemoteOwnerRG` runs asynchronously on each worker.

## Code

Current code in `userspace-dp/src/afxdp.rs`:
- on demotion, `update_ha_state()` immediately deletes matching keys only from `shared_sessions`
- then it enqueues `WorkerCommand::DemoteOwnerRG` to workers

Current worker-side demotion in `userspace-dp/src/afxdp/session_glue.rs`:
- `DemoteOwnerRG` later invalidates flow caches
- marks sessions synced / removes them from the BPF session map
- but only after the async worker command executes

## Why this matters

The code comment explicitly says the immediate cleanup is meant to close the window where demoted traffic still hits `USERSPACE_SESSIONS` and bypasses the eBPF fabric redirect path. That guarantee is incomplete if worker-local owner-RG sessions are still present in the map until later async processing.

## Evidence

This is a code-path gap. The remaining manual failover collapse on March 30, 2026 still happens immediately after the ownership move even after the large new-owner `session_miss` burst was removed.

Artifacts for the surviving failure shape:
- `/tmp/userspace-ha-failover-rg1-20260330-174231`
- `/tmp/manual-oneway-rg1-20260330-174744`

## Next steps

1. Measure how many demoted owner-RG `USERSPACE_SESSIONS` entries remain after the immediate shared-session cleanup and before worker `DemoteOwnerRG` completion.
2. If non-zero, add an explicit immediate worker-local demotion cleanup path or an acked barrier before traffic depends on the eBPF redirect path.
3. Re-test the one-way `RG1` failover artifact under `iperf3 -P 8`.


---

## #302 — Enforce a strict userspace-only forwarding invariant [CLOSED] (closed 2026-04-01)

We need a tracked work item for making `userspace dataplane active` mean that transit forwarding is actually staying on the userspace path rather than silently using eBPF or kernel forwarding.\n\nCurrent gaps called out in the audit:\n- `xdp_userspace_prog` still falls back to `xdp_main_prog` / `XDP_PASS`\n- XSK liveness failure silently swaps the entry program back to eBPF\n- `userspace_sessions` can steer packets to `PASS_TO_KERNEL`\n- stale BPF conntrack / userspace session-map state still interferes with userspace forwarding\n\nThis issue is the umbrella for the strict userspace-only forwarding work.\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.

---

## #303 — Define explicit runtime modes for userspace_strict, userspace_compat, and ebpf_only [CLOSED] (closed 2026-04-01)

The runtime currently overloads `userspace running` to mean several different things. We need explicit runtime modes so operators and validation can distinguish:\n- strict userspace forwarding\n- compatibility mode with eBPF/kernel fallback\n- eBPF-only mode\n\nRequired work:\n- define the mode model in code and status surfaces\n- make attach / swap / health logic report the active mode explicitly\n- stop implying `userspace` when the entry program or fallback behavior is not strict\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/302

---

## #304 — Disallow transit fallback from xdp_userspace_prog into xdp_main_prog or XDP_PASS in strict mode [CLOSED] (closed 2026-04-01)

In strict userspace mode, transit packets must not silently escape to the eBPF pipeline or the kernel forwarding path.\n\nCurrent code paths still do this through `fallback_to_main()`, `cpumap_or_pass()`, and several early fallback branches in `userspace-xdp/src/lib.rs`.\n\nRequired work:\n- classify which packet classes are true control-plane exceptions\n- ban silent transit fallback in strict mode\n- replace silent fallback with explicit drop + counters where strict behavior is required\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/302

---

## #305 — Remove or narrowly scope PASS_TO_KERNEL session actions for strict userspace mode [CLOSED] (closed 2026-04-01)

The userspace session steering map still encodes `PASS_TO_KERNEL` decisions. That makes the current userspace dataplane a hybrid forwarding system even when userspace is active.\n\nRequired work:\n- audit every producer of `PASS_TO_KERNEL` decisions\n- separate true local/control-plane exceptions from transit forwarding\n- ensure strict userspace mode never uses `PASS_TO_KERNEL` for transit\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/302

---

## #306 — Make XSK liveness failure explicit instead of silently swapping back to xdp_main_prog [CLOSED] (closed 2026-04-01)

Today the userspace manager can mark XSK liveness failed and swap the entry program back to `xdp_main_prog`. That preserves forwarding, but it violates a strict userspace invariant and hides the real dataplane mode.\n\nRequired work:\n- decide strict-mode behavior for XSK liveness failure\n- likely fail readiness / fail closed instead of silently preserving transit via eBPF\n- expose the degraded mode in status and validation\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/302

---

## #307 — Expose per-interface entry program and transit fallback counters in status and validation [CLOSED] (closed 2026-04-01)

We need observability that can prove whether the dataplane is actually running in strict userspace mode.\n\nRequired work:\n- expose the attached XDP entry program per interface\n- expose whether any transit fallback counters have incremented\n- make HA / regression validators fail when strict userspace expectations are violated\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/302

---

## #308 — Reduce HA failover toward a MAC-move-only model [CLOSED] (closed 2026-04-01)

We need an explicit architectural queue for the work required to make failover closer to the ideal model: move MACs, send GARP/NA, and keep forwarding without bespoke demotion/activation repair.\n\nThe audit shows the current system still depends on state and ordering outside the continuous session stream:\n- HA runtime / RG ownership state\n- reverse-session synthesis and refresh\n- flow-cache invalidation\n- neighbor and fabric state\n- demotion prep and barrier ordering\n\nThis umbrella tracks the work needed to either replicate or fence that state so failover does not rely on ad hoc handoff logic.\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.

---

## #309 — Enumerate forwarding-relevant state that is not carried in continuous session sync [CLOSED] (closed 2026-04-01)

The repo needs a concrete inventory of every forwarding input that is still outside the continuous HA session stream. That inventory should classify each item as:\n- replicated\n- deterministically derived\n- fenced at cutover\n\nThe audit already identifies likely candidates:\n- HA runtime active/demoting state\n- reverse companion state\n- translated alias state\n- neighbor state\n- fabric-link state\n- flow-cache state / invalidation epoch\n- local-delivery and other filtered session classes\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/308

---

## #310 — Make reverse-companion and translated-alias state deterministic at takeover [CLOSED] (closed 2026-04-01)

Failover currently relies on helper-side reverse-session prewarm / refresh and translated alias promotion around RG activation and demotion. That is a direct reason failover is not just MAC movement.\n\nRequired work:\n- define whether reverse companions and translated aliases should be fully replicated or deterministically reconstructed\n- remove reliance on best-effort activation-time repair where possible\n- prove the new owner can answer inherited traffic immediately after cutover\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/308

---

## #311 — Define an install fence for HA cutover instead of relying on continuous sync alone [CLOSED] (closed 2026-04-01)

The current daemon still needs demotion prep, barriers, quiescence checks, bulk acknowledgements, and final peer barriers before graceful failover. That is proof that continuous session sync alone is not a readiness guarantee.\n\nRequired work:\n- define the exact cutover contract (for example: peer has installed all required state through sequence N)\n- make old-owner demotion and MAC movement depend on that fence\n- remove any remaining handoff logic that only exists because readiness is inferred instead of proven\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/308

---

## #312 — Reduce helper-local cache and non-session dependencies at RG transition [CLOSED] (closed 2026-04-01)

Failover still depends on helper-local state outside the session stream, including flow caches, neighbor state, fabric state, and owner-RG transitions.\n\nRequired work:\n- minimize forwarding-critical worker-local cache state that must be repaired at activation/demotion\n- decide which remaining local dependencies must be replicated versus invalidated versus fenced\n- make the failover validators prove these dependencies are either ready or irrelevant at cutover\n\nSee PR #301 and docs/userspace-forwarding-and-failover-gap-audit.md.\n\nParent: https://github.com/psaab/bpfrx/issues/308

---

## #314 — HA cutover still lacks a helper worker-completion acknowledgment [CLOSED] (closed 2026-04-01)

Current `origin/master` still has no end-to-end acknowledgment that the activated helper has finished applying HA transition work before traffic ownership moves.

Code path:
- `pkg/dataplane/userspace/manager.go:2793-2860` treats `UpdateRGActive(...)` as complete once the helper answers the control request.
- `userspace-dp/src/main.rs:1497-1508` handles `update_ha_state` synchronously only at the control-plane level.
- `userspace-dp/src/afxdp.rs:1157-1191` handles activation by:
  - prewarming reverse synced sessions, then
  - enqueueing `WorkerCommand::RefreshOwnerRGs(...)` to each worker, and then returning.
- `userspace-dp/src/afxdp/session_glue.rs:346-430` shows that `RefreshOwnerRGs(...)` is where forward sessions are actually re-resolved locally and republished.

Why this matters:
- Barriers and continuous sync only prove stream ordering to the peer, not that every worker has finished the local activation work needed for forwarding.
- MAC move can still race stale worker caches / stale synced session resolution.
- That is a direct reason failover is not just MAC move plus GARP/NA on current code.

What to change:
- Add a per-transition sequence and require every worker to ack `RefreshOwnerRGs` / prewarm completion.
- Only mark the RG cutover-ready after those worker acks are collected.

Acceptance signal:
- there is a concrete "activated helper is forwarding-ready" acknowledgment, not just a control-request response.


---

## #315 — Continuous userspace HA sync still omits local-delivery session state [CLOSED] (closed 2026-04-01)

Current `origin/master` intentionally excludes some userspace session classes from continuous HA sync.

Code path:
- `pkg/daemon/daemon.go:3578-3588` returns `false` from `shouldSyncUserspaceDelta(...)` for `Disposition == local_delivery`.
- The same function only syncs stale-owner `FabricRedirect` deltas under a special case.

Why this matters:
- The claim "sessions are continuously synced so failover should only need MAC move + GARP/NA" is not true for the current userspace dataplane.
- Helper-local / local-delivery state is still reconstructed locally rather than being part of the steady-state HA stream.
- Any failover path that depends on interface-NAT or other helper-local delivery semantics still needs more than L2 ownership movement.

What to change:
- Enumerate exactly which `local_delivery` cases are safe and necessary to sync, or
- define a deterministic replacement model for them so takeover does not depend on ad-hoc local reconstruction.

Acceptance signal:
- the failover contract states either "this session class is continuously carried" or "this session class is locally reconstructed in a deterministic, tested way" for every userspace disposition.


---

## #316 — Cluster-synced reverse sessions are still not mirrored into the userspace helper [CLOSED] (closed 2026-04-01)

Current `origin/master` still does not mirror cluster-synced reverse sessions into the Rust userspace helper.

Code path:
- `pkg/cluster/sync.go:1390-1413` creates reverse sessions on the takeover node by calling `SetClusterSyncedSessionV4/V6(...)` for `revVal`.
- `pkg/dataplane/userspace/manager.go:3837-3906` only mirrors sessions into the helper when `shouldMirrorUserspaceSession(val.IsReverse)` is true.
- `shouldMirrorUserspaceSession(...)` returns `isReverse == 0`, so reverse sessions are dropped from the helper mirror path.
- The helper activation path in `userspace-dp/src/afxdp/session_glue.rs:346-349` still claims reverse companions are pre-installed by the Go sync path, but for cluster-synced sessions that is not actually true on the helper side.

Why this matters:
- Continuous session sync is not enough to make failover a MAC-move-only event if the new owner still has to synthesize or repair reverse companions during activation.
- Reverse/translated reply handling remains an activation-time helper concern instead of being fully ready before MAC ownership moves.

What to change:
- Either mirror cluster-synced reverse sessions into the helper explicitly, or
- define a deterministic, acknowledged helper-side reverse install step that finishes before the new owner is treated as cutover-ready.

Acceptance signal:
- takeover no longer depends on activation-time reverse synthesis/refresh for already-synced flows.


---

## #317 — Userspace session sync still depends on activation-time local egress re-resolution [CLOSED] (closed 2026-04-01)

Current `origin/master` still serializes forwarding state using node-local egress details, then throws the local resolution away on install.

Code path:
- `pkg/dataplane/userspace/manager.go:3929-4010` builds session-sync requests using `EgressIfindex`, `TXIfindex`, `NeighborMAC`, `SrcMAC`, and `TXVLANID`.
- `pkg/dataplane/userspace/manager.go:4235-4249` derives those values from local snapshot ifindexes.
- `pkg/cluster/sync.go:1378-1385` and `pkg/dataplane/userspace/manager.go:3837-3893` immediately zero `FibIfindex`, `FibVlanID`, `FibDmac`, `FibSmac`, and `FibGen` on the receiver because the peer's resolved forwarding state is meaningless locally.
- `userspace-dp/src/afxdp/session_glue.rs:360-430` then re-resolves forward sessions during `RefreshOwnerRGs`, with an explicit comment that without this SNAT on the new owner is wrong.

Why this matters:
- The continuously synced session stream is not forwarding-complete.
- The new owner cannot just keep forwarding after MAC move; it still needs local activation-time re-resolution before the synced session is usable.

What to change:
- Stop treating numeric ifindex/MAC state as portable session-sync data.
- Carry a portable egress identity instead (logical interface/tunnel endpoint/next-hop identity), or
- add an explicit local re-resolution/install-ready step and treat failover readiness as incomplete until that finishes.

Acceptance signal:
- synced sessions arrive on the new owner in a form that is either directly usable or explicitly tracked as unresolved until local resolution completes.


---

## #318 — Redesign HA session sync around a portable canonical session record [CLOSED] (closed 2026-04-02)

Current `origin/master` serializes node-local resolved forwarding data into the HA session stream and then discards it on install.

Code points:
- `pkg/dataplane/userspace/manager.go:3959-3999` / `4019-4050` build helper sync requests with `EgressIfindex`, `TXIfindex`, `NeighborMAC`, `SrcMAC`, and `TXVLANID`.
- `pkg/dataplane/userspace/manager.go:3837-3893` zeroes `FibIfindex`, `FibVlanID`, `FibDmac`, `FibSmac`, and `FibGen` on cluster-synced install because the peer's resolved values are not portable.
- `userspace-dp/src/afxdp/session_glue.rs:339-430` then re-resolves forward sessions locally during `RefreshOwnerRGs` to repair them on activation.

That is a structural sign that the HA session record is carrying the wrong abstraction.

What should replace it:
- A portable canonical session record that carries only:
  - flow key
  - NAT state
  - ingress/egress zone identity
  - owner RG / HA metadata
  - fabric-ingress / tunnel identity where needed
- No node-local ifindex, MAC, or cached FIB result in the cross-node schema.
- Local forwarding resolution should be derived immediately on each node from the canonical record and the local forwarding snapshot.

Why this matters:
- It removes activation-time repair work from failover.
- It makes the session stream semantically stable across nodes.
- It reduces the chance of hidden coupling between session sync and local forwarding internals.

Related:
- #314
- #316
- closed #317 captured one symptom of this, but this issue is the schema-level fix.


---

## #319 — Continuously materialize standby helper state instead of repairing sessions on RG activation [CLOSED] (closed 2026-04-02)

Current `origin/master` still makes RG activation do large repair work in the helper:
- `userspace-dp/src/afxdp.rs:1157-1191` prewarms reverse sessions and queues `RefreshOwnerRGs` to every worker.
- `userspace-dp/src/afxdp/session_glue.rs:332-430` re-resolves forward sessions for the activated RGs because synced sessions are not already forwarding-ready locally.

That means the standby is not continuously materialized into a locally-usable runtime state. It is only partially populated, then repaired when ownership flips.

What should replace it:
- On sync import, the standby should build and keep the local runtime form of the session continuously, even while RG is inactive.
- Reverse companions, translated aliases, and local rewrite descriptors should exist before failover.
- Activation should become a cheap ownership epoch flip plus MAC move/GARP/NA, not a worker-wide table scan.

Expected result:
- no `RefreshOwnerRGs` full-table repair path on activation
- no reverse prewarm pass at activation
- failover becomes much closer to "ownership flip + continue forwarding"

Related:
- #314
- #316


---

## #320 — Make HA session producers event-first and reduce sweeps/polling to reconciliation [CLOSED] (closed 2026-04-02)

The current producer side is still more complex than it should be:
- helper event stream exists, but `pkg/daemon/daemon.go:3648-3684` still runs a polling loop and `3793-3833` keeps a polling fallback path
- kernel sync still relies on timer/sweep semantics and queue-idle heuristics for correctness

For a simpler HA design, the steady-state producer model needs to be event-first and reconciliation-second.

What should change:
- userspace helper event stream becomes the single steady-state producer for helper-originated session changes
- kernel session sync becomes event-first for create/delete/material transitions
- sweep remains only as reconciliation for missed events / reconnect recovery / correctness checks

Why this matters:
- lower steady-state work
- fewer transition-time races caused by polling and background queue growth
- easier cutover contract because the event stream sequence can participate directly in applied-sequence fencing

This is not just a performance issue; it is a major simplification prerequisite for making HA cutover predictable.


---

## #321 — Replace HA flow-cache scans and flushes with epoch-based cache validation [CLOSED] (closed 2026-04-02)

Current flow-cache invalidation still depends on explicit scans and flush commands around HA transitions.

Code points:
- `userspace-dp/src/afxdp/types.rs:119-133` invalidates per-RG by scanning every cache entry.
- `userspace-dp/src/afxdp.rs:1143-1149` pushes `FlushFlowCaches` on demotion because per-RG invalidation is not sufficient in all cases.
- `userspace-dp/src/afxdp/session_glue.rs:278-281`, `324-326`, `334-337` repeatedly walk caches for owner-RG invalidation.

That means failover correctness currently depends on imperative cache maintenance rather than cache entries becoming invalid naturally when ownership changes.

What should replace it:
- introduce per-RG / per-resolution epochs
- include those epochs in the runtime session record and flow-cache validation key
- failover bumps epochs; stale cache entries self-miss on next lookup without needing O(n) scans

Expected result:
- no `FlushFlowCaches` command in the HA transition path
- no per-RG cache walk at demotion/activation
- flow cache remains a pure local acceleration layer, not a transition-time state machine participant


---

## #322 — Collapse helper HA session state into one canonical store plus derived indexes [CLOSED] (closed 2026-04-02)

Current helper HA state is spread across multiple overlapping stores:
- `shared_sessions`
- `shared_nat_sessions`
- `shared_forward_wire_sessions`
- worker-local `SessionTable` plus alias indexes

Code points:
- `userspace-dp/src/afxdp.rs:233` / `276` define and carry the shared maps.
- `userspace-dp/src/afxdp.rs:1098-1126` has to demotion-clean all three stores separately.
- `userspace-dp/src/afxdp/session_glue.rs` publishes, refreshes, and deletes through separate alias paths.

This multiplies activation, demotion, delete, and cache-invalidation complexity because HA has to reason about cloned entries instead of one canonical session object with derived indexes.

What should replace it:
- one canonical synced session store keyed by session identity / session ID
- alias indexes that point to the canonical record rather than cloned `SyncedSessionEntry` copies
- a clear split between authoritative record and derived lookup indices

Expected result:
- demotion does not need to walk multiple shared maps
- activation does not need separate prewarm/repair logic for parallel stores
- less risk of alias divergence across forward/reverse/translated representations


---

## #323 — Replace HA demotion drain choreography with an applied-sequence cutover fence [CLOSED] (closed 2026-04-02)

Current graceful demotion is expensive because the system does not have a single cutover-ready notion of "peer has applied all forwarding-relevant state".

Code points:
- `pkg/daemon/daemon.go:4106-4230` performs `WaitForPeerBarriersDrained`, repeated `WaitForIdle` + `WaitForPeerBarrier`, pause/resume of incremental sync, event-stream drain or RPC export/drain fallback, journal flush, then a final barrier.
- `pkg/cluster/sync.go:1962-2005` `WaitForIdle()` literally waits for the sync queue to stop changing before the barrier can mean anything.

That is a symptom of missing applied-sequence semantics, not just missing tuning.

What should replace it:
- every canonical session update should carry a monotonically increasing sequence
- the standby should ack the highest sequence fully imported/materialized locally
- graceful demotion should fence on that applied sequence rather than on idle heuristics + side drains

Expected result:
- no repeated idle polling to prove quiescence
- no export/drain repair pass in the common case
- demotion becomes: stop emitting new owner updates, fence sequence N, wait for peer applied>=N, then move ownership/MACs

Related:
- #314


---

## #324 — Flow cache on new owner caches sessions without NAT decision after failover [CLOSED] (closed 2026-04-01)

## Symptom
After RG failover, the new owner matches 267K session hits but applies SNAT to only 22 packets. TCP streams die because outbound traffic uses the original LAN source IP instead of the SNAT'd WAN IP.

## Root cause (suspected)
The flow cache is populated from the session table lookup, but the NAT decision (`decision.nat.rewrite_src`) is not carried into the flow cache entry. When packets hit the flow cache, they get forwarded without SNAT rewriting.

## Code path
- `userspace-dp/src/afxdp.rs` — flow cache hit path at ~line 2698 returns `cached_decision` which may lack NAT
- `userspace-dp/src/afxdp.rs` — session lookup at ~line 2860 returns full `SessionDecision` including NAT
- `userspace-dp/src/afxdp/types.rs` — `FlowCache` entry stores `FlowCacheEntry` — need to verify it carries NAT

## Evidence
- `SNAT packets: 22` vs `Session hits: 267686` on new owner after failover
- Sessions installed: 321, re-resolved with correct egress via owner_rg_id=0 fix
- Session sync working (81 sent incrementally, bulk sync reliable)
- Flow cache flushed on activation (FlushFlowCaches + RefreshOwnerRGs)

---

## #325 — Send owner_rg_id from sync sender instead of defaulting to 0 [CLOSED] (closed 2026-04-01)

The sender has snapshot access to resolve owner_rg_id via sessionSyncEgressLocked but returns 0 when FibIfindex<=0. Fix: always compute owner_rg_id at send time. Eliminates activation-time re-resolution of RG ownership for synced sessions.

---

## #326 — Resolve synced sessions with local egress on receipt, not just on activation [CLOSED] (closed 2026-04-01)

UpsertSynced only re-resolves when locally_active is true. Shift resolution to every sync receipt so standby sessions are always forwarding-ready. Eliminates RefreshOwnerRGs re-resolution loop.

---

## #327 — Replace flow cache flush with epoch-based invalidation [CLOSED] (closed 2026-04-01)

Add owner_rg_generation to FlowCacheEntry. On demotion, increment RG generation atomically. Cache entries expire on next access when generation mismatches. Eliminates FlushFlowCaches + invalidate_owner_rg scans.

---

## #328 — Unify synced flag into origin-based collision detection [CLOSED] (closed 2026-04-02)

Replace binary synced:bool with synced_generation:u64. Merge refresh_local, promote_synced, refresh_for_ha_activation into one update function. Eliminates dual-guard complexity.

---

## #329 — Pre-populate BPF userspace_sessions map on sync receipt [CLOSED] (closed 2026-04-02)

Publish synced sessions to BPF map at install time, not just at activation. XDP shim checks rg_active before using entry. Eliminates synchronous BPF map deletion loop on demotion.

---

## #330 — Simplify demotion prep to epoch transition [CLOSED] (closed 2026-04-01)

Replace barrier/quiescence/drain choreography with a simple demoting flag + short lease. Rely on continuous sync for session delivery. Eliminates 150-line handshake.

---

## #332 — Userspace-forwarded packets not counted in BPF zone/policy/NAT counter maps [CLOSED] (closed 2026-04-01)

TC egress counters (zone_counters, policy_counters, filter_counters, nat_rule_counters, global_counters) are only incremented by the eBPF pipeline. Userspace-forwarded packets via XSK TX bypass TC entirely, so ReadZoneCounters/ReadPolicyCounters/ReadGlobalCounter return incomplete values. Fix: write userspace counters to the same BPF maps, or merge counters from both sources.

---

## #333 — IterateSessions reads only eBPF conntrack — userspace sessions invisible to GC/ARP warmup [CLOSED] (closed 2026-04-01)

pkg/dataplane/maps.go IterateSessions only reads the BPF sessions map. Userspace helper sessions are in Rust memory only. This means session GC, ARP warmup target collection, and show session commands miss userspace sessions. Fix: extend IterateSessions to also query the helper's session table via control socket, or write userspace sessions to BPF conntrack (partially done in fab9230c but byte order issue remains).

---

## #334 — BPF conntrack writes during ctrl=0 window conflict with userspace sessions [CLOSED] (closed 2026-04-01)

When ctrl is disabled (XSK liveness probe, link cycle, startup), the eBPF pipeline creates BPF conntrack entries. When ctrl re-enables, these stale entries must be flushed (manager.go:3243-3268) because TC egress reads them and applies conflicting NAT. Fix: disable BPF conntrack writes entirely when userspace mode is configured, or add a generation counter to distinguish userspace vs eBPF sessions.

---

## #335 — BPF conntrack entry byte order mismatch prevents zone display for userspace sessions [CLOSED] (closed 2026-04-01)

fab9230c added publish_bpf_conntrack_entry to write userspace sessions to the BPF sessions map for zone/interface display. However sessions don't appear — likely byte order mismatch between Rust BpfSessionKeyV4 port fields (host order) and the C session_key_t (network order). Fix: verify BpfSessionKeyV4 port byte order matches the C struct exactly. Add a debug log on write failure.

---

## #338 — Graceful demotion barrier no longer fences helper and kernel session producers [CLOSED] (closed 2026-04-02)

## Problem
`prepareUserspaceRGDemotionWithTimeout()` no longer fences all session producers before cutover. It only waits for queue barriers on the peer session-sync transport, then proceeds to `PrepareRGDemotion()`.

## Why this is a failover gap
That barrier only proves the peer processed queued sync messages. It does not fence helper event-stream deltas or kernel SESSION_OPEN production outside that queue. During demotion, those producers can still race the cutover window.

## Code
- `pkg/daemon/daemon.go:4120`
- `pkg/daemon/daemon.go:4144`
- `pkg/daemon/daemon.go:4170`

The older pause/drain path is still present in the codebase as primitives, but this demotion flow no longer uses it:
- `pkg/cluster/sync.go:831` (`PauseIncrementalSync`)
- `pkg/cluster/sync.go:1950` (`WaitForIdle`)
- `pkg/dataplane/userspace/eventstream.go:117` (`SendDrainRequest`)

## Consequence
The new owner can take over after a barrier while the old owner is still producing post-barrier deltas outside the fenced path. That keeps failover more complex than a MAC move and can leave inherited flows inconsistent.

## Expected fix direction
Reintroduce a real producer fence for graceful demotion:
- pause incremental producers
- drain helper event stream to a target sequence
- flush any kernel demotion journal
- then use a final cutover fence before `PrepareRGDemotion()`


---

## #339 — Graceful demotion can proceed without confirmed peer bulk readiness [CLOSED] (closed 2026-04-02)

## Problem
Graceful demotion now allows cutover to proceed even when `syncPeerBulkPrimed` is false, as long as a single peer barrier succeeds.

## Why this is a failover gap
A barrier response proves the peer is alive and draining the queue. It does **not** prove the peer has completed bulk baseline sync for takeover.

## Code
- `pkg/daemon/daemon.go:4148`
- `pkg/daemon/daemon.go:4151`
- `pkg/daemon/daemon.go:4154`

Current behavior logs:
> peer barrier succeeded without bulk ack — proceeding with demotion

## Consequence
Demotion can be admitted after reconnect or partial resync before the standby has a confirmed baseline. That creates exactly the kind of “continuously synced, but not actually takeover-ready” window that makes HA brittle.

## Expected fix direction
Do not treat barrier success as a substitute for outbound bulk-ack readiness. Manual failover admission should require confirmed standby bulk readiness, or explicitly enter a stronger fenced/export path that rebuilds that guarantee.


---

## #340 — Daemon acks helper event-stream deltas even when sync-disconnect drops them [CLOSED] (closed 2026-04-02)

## Problem
The daemon-side userspace event stream acks helper deltas even when `handleEventStreamDelta()` drops them because peer session sync is disconnected.

## Why this is a failover gap
That means userspace-originated session events can be removed from helper replay state without ever reaching HA peer sync.

## Code
Event drop path:
- `pkg/daemon/daemon.go:3766`
- `pkg/daemon/daemon.go:3775`
- `pkg/daemon/daemon.go:3779`

Ack path still advances applied seq unconditionally after callback:
- `pkg/dataplane/userspace/eventstream.go:283`
- `pkg/dataplane/userspace/eventstream.go:286`
- `pkg/dataplane/userspace/eventstream.go:301`
- `pkg/dataplane/userspace/eventstream.go:304`

## Consequence
A transient session-sync disconnect on the active node can permanently lose helper delta history from the HA stream, even though the helper thinks the daemon consumed it.

## Expected fix direction
Only advance `lastAppliedSeq` when the callback explicitly accepts/applies the event, or plumb callback errors back into the event-stream reader so dropped events are not acked.


---

## #341 — UpdateRGActive hides helper refresh_owner_rgs timeout and failure [CLOSED] (closed 2026-04-02)

## Problem
`Manager.UpdateRGActive()` can return success even when helper-side `refresh_owner_rgs()` timed out or failed.

## Why this is a failover gap
Go treats RG activation as complete while the helper may still have incomplete reverse/forward re-resolution work.

## Code
Go only logs and continues if explicit refresh fails:
- `pkg/dataplane/userspace/manager.go:2877`
- `pkg/dataplane/userspace/manager.go:2886`
- `pkg/dataplane/userspace/manager.go:2887`

Helper refresh waits 2s, but on timeout only prints and returns `()`:
- `userspace-dp/src/afxdp.rs:1274`
- `userspace-dp/src/afxdp.rs:1323`
- `userspace-dp/src/afxdp.rs:1338`

Control handler never propagates a refresh failure:
- `userspace-dp/src/main.rs:1543`
- `userspace-dp/src/main.rs:1546`

## Consequence
Cluster control can move ownership and MACs while the helper refresh path only partially completed or timed out.

## Expected fix direction
Make helper refresh return an explicit success/failure result to Go, and make `UpdateRGActive()` fail closed when takeover-critical refresh work times out.


---

## #342 — RG activation duplicates helper refresh work through update_ha_state and explicit refresh [CLOSED] (closed 2026-04-02)

## Problem
RG activation currently does duplicate helper refresh work: `update_ha_state()` enqueues `RefreshOwnerRGs`, then Go immediately sends an explicit `refresh_owner_rgs` RPC for the same RG.

## Why this is a failover gap
This makes activation slower and noisier under load and increases the surface area for races, duplicate scans, and inconsistent worker completion timing.

## Code
Activation path in helper already enqueues refresh:
- `userspace-dp/src/afxdp.rs:1195`
- `userspace-dp/src/afxdp.rs:1230`

Go then explicitly sends another refresh request:
- `pkg/dataplane/userspace/manager.go:2872`
- `pkg/dataplane/userspace/manager.go:2880`
- `pkg/dataplane/userspace/manager.go:2886`

## Consequence
Cutover work is duplicated during the most latency-sensitive phase of failover.

## Expected fix direction
Choose one authoritative activation refresh path with a real completion ack. Do not rely on both implicit `update_ha_state()` refresh and explicit RPC refresh.


---

## #343 — Demotion kernel journal path is dead in the current graceful demotion flow [CLOSED] (closed 2026-04-02)

## Problem
The daemon still has a demotion kernel journal and demotion-prep depth, but the current graceful demotion flow no longer enters that journaling state or flushes the journal.

## Why this is a failover gap
Kernel SESSION_OPEN events during demotion are no longer fenced/replayed through the dedicated path that was meant to protect the handoff window.

## Code
Journaling path still exists:
- `pkg/daemon/daemon.go:3931`
- `pkg/daemon/daemon.go:3935`
- `pkg/daemon/daemon.go:3942`

Ring-buffer callback still consults `userspaceDemotionPrepActive()` before journaling:
- `pkg/daemon/daemon.go:751`
- `pkg/daemon/daemon.go:778`

But `prepareUserspaceRGDemotionWithTimeout()` no longer begins demotion-prep pause / journal mode or flushes the journal:
- `pkg/daemon/daemon.go:4120`
- `pkg/daemon/daemon.go:4173`

## Consequence
The code still carries a demotion journal mechanism, but current failover logic no longer uses it. That is dead protection code and a likely regression in handoff safety.

## Expected fix direction
Either restore the journaled demotion path as part of a real producer fence, or delete the dead mechanism and replace it with a single explicit cutover-fence design.


---

## #344 — HA activation is decoupled from actual userspace dataplane enablement [CLOSED] (closed 2026-04-02)

## Problem
HA activation success is currently decoupled from userspace dataplane enablement. After `UpdateRGActive()`, manager logic can still keep `ctrl.Enabled=0` for HA readiness delays and may intentionally rely on the eBPF pipeline during the promoted-owner window.

## Why this is a failover gap
That means cluster ownership change is not equivalent to “the new owner is forwarding in userspace now.” Failover still depends on fallback dataplane behavior instead of a single forwarding plane being ready before cutover.

## Code
Manager explicitly delays ctrl enable in HA mode and documents that the eBPF pipeline carries traffic during that window:
- `pkg/dataplane/userspace/manager.go:3088`
- `pkg/dataplane/userspace/manager.go:3092`
- `pkg/dataplane/userspace/manager.go:3110`
- `pkg/dataplane/userspace/manager.go:3223`
- `pkg/dataplane/userspace/manager.go:3241`

## Consequence
Failover correctness depends on cross-plane behavior during startup/rebind/activation instead of just moving ownership and forwarding packets from the continuously synced userspace state.

## Expected fix direction
Define a single takeover-ready condition that includes helper forwarding enablement, and do not treat RG activation as complete until the promoted owner is actually forwarding on the intended dataplane.


---

## #345 — HA activation still does RG-wide helper refresh scans despite on-receipt standby materialization [CLOSED] (closed 2026-04-02)

## Problem
The helper still performs RG-wide reverse/forward refresh scans on activation even though synced forward sessions are already re-resolved with local egress on receipt.

## Why this is a failover gap
This keeps HA activation expensive and complex. The code is trying to be both “standby is forwarding-ready continuously” and “activation re-resolves a large slice of the session table anyway.”

## Code
On-receipt standby materialization comment and behavior:
- `userspace-dp/src/afxdp/session_glue.rs:453`
- `userspace-dp/src/afxdp/session_glue.rs:461`
- `userspace-dp/src/afxdp/session_glue.rs:478`

Activation still runs full refresh/prewarm passes:
- `userspace-dp/src/afxdp.rs:1214`
- `userspace-dp/src/afxdp.rs:1270`
- `userspace-dp/src/afxdp/session_glue.rs:333`
- `userspace-dp/src/afxdp/session_glue.rs:364`

## Consequence
Failover still depends on activation-time table scans and re-resolution churn instead of just flipping ownership and invalidating cheap caches.

## Expected fix direction
Pick one model:
- either continuously maintain forwarding-ready standby state and only invalidate lightweight caches at cutover,
- or explicitly keep standby state incomplete and treat activation refresh as first-class.

The current hybrid keeps the cost and race surface of both.


---

## #346 — Userspace session mirror failures are swallowed during HA session install [CLOSED] (closed 2026-04-02)

## Problem
Userspace session mirror failures are swallowed in manager session install paths, so cluster sync can report session install success while the helper never received the session.

## Why this is a failover gap
That leaves the kernel/session-sync side and the helper side divergent. HA code then believes the standby is continuously synced, but the userspace dataplane may still be missing takeover-critical state.

## Code
Local session mirror errors are ignored:
- `pkg/dataplane/userspace/manager.go:3943`
- `pkg/dataplane/userspace/manager.go:3961`
- `pkg/dataplane/userspace/manager.go:3993`
- `pkg/dataplane/userspace/manager.go:4011`

Cluster-synced session mirror errors are also ignored:
- `pkg/dataplane/userspace/manager.go:3980`
- `pkg/dataplane/userspace/manager.go:3982`
- `pkg/dataplane/userspace/manager.go:4027`
- `pkg/dataplane/userspace/manager.go:4029`

The helper RPC path can return an error:
- `pkg/dataplane/userspace/manager.go:4205`
- `pkg/dataplane/userspace/manager.go:4211`

But callers intentionally discard it with `_ = ...`.

## Consequence
`SessionSync` can count a session as installed because `SetClusterSyncedSessionV4/V6` returned `nil`, while the helper mirror silently failed. That undermines standby readiness and makes failover look more synchronized than it really is.

## Expected fix direction
Treat helper mirror failures as real install failures for takeover-critical paths, or track/install state separately so readiness is based on both kernel and helper materialization instead of the kernel side alone.


---

## #347 — Failover still depends on post-transition neighbor warm-up sweeps [CLOSED] (closed 2026-04-02)

## Problem
Failover still depends on an explicit post-transition neighbor warm sweep because the first packet after takeover can otherwise miss `bpf_fib_lookup()` with `NO_NEIGH`.

## Why this is a failover gap
If the standby were truly forwarding-ready from continuously synced state, first-packet forwarding should not require a best-effort neighbor-warm pass over the session table.

## Code
The daemon documents and implements this directly:
- `pkg/daemon/daemon.go:7661`
- `pkg/daemon/daemon.go:7664`
- `pkg/daemon/daemon.go:7676`
- `pkg/daemon/daemon.go:7713`

The activation path kicks it asynchronously:
- `pkg/daemon/daemon.go:6794`
- `pkg/daemon/daemon.go:6957`

## Consequence
Takeover is still not just a MAC move plus packet forwarding. Correctness of the first packets after failover depends on a background sweep over existing sessions and best-effort kernel ARP/NDP resolution.

## Expected fix direction
Either maintain neighbor-ready forwarding state continuously on the standby, or make cutover fence on explicit neighbor readiness for the activated RG instead of launching an asynchronous warm-up after ownership flips.


---

## #348 — HA transition still depends on asynchronous fabric_fwd refresh [CLOSED] (closed 2026-04-02)

## Problem
RG transition handlers trigger fabric forwarding map refresh asynchronously, outside the actual cutover fence.

## Why this is a failover gap
Cross-node redirect correctness still depends on `fabric_fwd` being current, but failover does not wait for a post-transition refresh to complete before traffic moves.

## Code
Transition handlers launch refresh asynchronously after activation/deactivation work:
- `pkg/daemon/daemon.go:6808`
- `pkg/daemon/daemon.go:6966`
- `pkg/daemon/daemon.go:6995`

The refresh function itself is best-effort and asynchronous with background neighbor probing:
- `pkg/daemon/daemon.go:6551`
- `pkg/daemon/daemon.go:6570`
- `pkg/daemon/daemon.go:6574`

Readiness only checks a coarse global `fabricPopulated` bit:
- `pkg/daemon/daemon.go:7085`
- `pkg/daemon/daemon.go:7089`
- `pkg/daemon/daemon.go:7092`

## Consequence
HA transition correctness still depends on a background fabric refresh path completing after ownership change instead of the cutover fence proving the redirect fabric state is current.

## Expected fix direction
Make fabric-forwarding readiness part of the transition fence for the affected path, or continuously maintain valid fabric redirect state so ownership change does not need a best-effort post-transition refresh.


---

## #349 — HA watchdog sync is throttled past the helper stale-after threshold [CLOSED] (closed 2026-04-02)

The current userspace HA watchdog cadence is internally inconsistent.

Code:
- `pkg/dataplane/userspace/manager.go:4792-4798` throttles watchdog-only HA sync to the helper to once every `5*time.Second`
- `userspace-dp/src/afxdp.rs:187` sets `HA_WATCHDOG_STALE_AFTER_SECS` to `2`
- helper forwarding logic treats any RG with an older watchdog timestamp as `HAInactive` in:
  - `userspace-dp/src/afxdp/forwarding.rs:1077-1080`
  - `userspace-dp/src/afxdp/session_glue.rs:144-147`

Why this is a bug:
- The manager can intentionally wait 5 seconds before pushing a fresh watchdog timestamp.
- The helper will treat a watchdog timestamp older than 2 seconds as stale and return `HAInactive`.
- That means a healthy active RG can age into `HAInactive` on the helper between watchdog refreshes.

Why this matters:
- This directly undermines the assumption that the helper's HA runtime view is continuously valid.
- It creates avoidable failover and steady-state forwarding fragility because an otherwise active owner can be treated as inactive purely due to timer skew between Go and Rust.

Expected direction:
- Make the watchdog publish cadence strictly faster than the helper stale threshold, or
- stop treating the watchdog as a high-frequency liveness timer in the helper and switch to an explicit epoch/lease model with matching producer semantics.


---

## #350 — GetSessions cursor pagination does not support stable include_peer pagination [CLOSED] (closed 2026-04-02)

`GetSessions` cursor pagination still has a correctness gap when `include_peer=true`.

Code:
- `pkg/grpcapi/server.go:1185-1190` suppresses peer results entirely when `page_token` is present
- `pkg/grpcapi/server.go:1201-1218` forwards a peer request without `PageToken`
- local cursor generation/iteration lives in `pkg/grpcapi/server.go:800-975`

Current behavior:
- first page with `include_peer=true` can include peer sessions
- later pages with `page_token` never include peer sessions at all

Why this is a bug:
- The API shape implies one paginated logical result set.
- Today the first page can be a mixed local+peer view, while subsequent pages silently degrade to local-only.
- That makes pagination unstable and surprising for callers trying to enumerate all sessions with peer inclusion enabled.

Why this matters:
- This is especially confusing for large session tables where callers must paginate.
- It turns `include_peer=true` into a first-page-only hint instead of a real paginated query mode.

Expected direction:
- define peer pagination as its own cursor space and return a combined token, or
- explicitly reject `include_peer=true` with cursor pagination until a stable combined cursor model exists.


---

## #351 — Userspace mirror delete path leaves preinstalled reverse companions behind [CLOSED] (closed 2026-04-02)

The local Go->helper session mirror path pre-installs reverse companions, but the delete path is forward-only.

Code:
- `pkg/dataplane/userspace/manager.go:3945-3961` mirrors a forward session and then also mirrors its reverse companion into the helper for `SetSessionV4`
- `pkg/dataplane/userspace/manager.go:3995-4011` does the same for `SetSessionV6`
- `pkg/dataplane/userspace/manager.go:4037-4053` deletes only the forward key for `DeleteSession` / `DeleteSessionV6`
- helper delete handling in `userspace-dp/src/afxdp/session_glue.rs:524-536` deletes only the requested synced key unless a second delete command is explicitly queued

Why this is a bug:
- For locally mirrored sessions, the helper can end up with both forward and reverse synced entries.
- On teardown, Go only sends a delete for the forward key.
- The reverse companion can remain behind in the helper's synced/shared maps and BPF session map state.

Why this matters:
- Stale reverse companions are exactly the kind of state that makes HA handoff and activation-time refresh logic hard to reason about.
- This diverges from the cluster-sync path, which now installs forward and reverse entries explicitly and therefore has an obvious two-key delete model.

Expected direction:
- either mirror reverse companions only in the cluster-sync path and stop synthesizing them in the local manager path, or
- track/delete the paired reverse companion explicitly when local manager sessions are removed.


---

## #352 — Userspace HA transition path still contains raw stderr debug logging [CLOSED] (closed 2026-04-02)

`origin/master` still has raw `eprintln!` logging in the helper HA transition path.

Concrete examples:
- `userspace-dp/src/afxdp.rs:1112-1121` logs RG state changes directly to stderr
- `userspace-dp/src/afxdp.rs:1163-1167` logs immediate `USERSPACE_SESSIONS` cleanup counts for demoted RGs
- additional transition/debug logging remains around activation and fallback paths in `userspace-dp/src/afxdp.rs`

Why this should be cleaned up:
- these are not test-only logs; they are in live transition code
- they bypass the logging rules that were added later in the same commit window
- raw stderr logging in hot or noisy HA paths makes field debugging harder because intentional structured state changes are mixed with leftover debug output

Expected direction:
- either convert these to the approved structured logging path with clear rate/volume expectations, or
- remove the logs once the transition behavior is covered by tests and counters.


---

## #353 — Remove explicit refresh_owner_rgs RPC — sessions pre-resolved on receipt [CLOSED] (closed 2026-04-02)

UpdateRGActive sends refresh_owner_rgs after update_ha_state, but #326 resolves synced sessions on receipt. The explicit refresh is redundant. Remove lines 2877-2895 in manager.go. Reduces activation by one control socket round trip.

---

## #354 — Skip blackhole route management in userspace mode [CLOSED] (closed 2026-04-02)

Blackhole routes (RTN_BLACKHOLE) are injected/removed on VRRP transitions but the XDP shim + rg_active flag already handles fabric redirect in userspace mode. Skip blackhole syscalls when userspace dataplane is active. Saves 4 route syscalls per failover pair.

---

## #355 — Remove dead code and simplify HA transition bookkeeping [CLOSED] (closed 2026-04-02)

Multiple dead/redundant code paths after HA simplifications: hasAnyInactiveRG (unused), duplicate demotion prep in watchClusterEvents, pendingRGTransitions map (replace with atomic bool), unconditional snapshot sync in statusLoop. Cleanup to reduce cognitive load.

---

## #356 — Throttle statusLoop HA sync for 2s after UpdateRGActive [CLOSED] (closed 2026-04-02)

statusLoop syncs HA state every 1s which races with UpdateRGActive. Skip HA sync in the poll for 2s after an RG transition completes. Reduces duplicate control socket requests during the critical failover window.

---

## #358 — Collapse userspace RG activation into one helper-applied HA generation [CLOSED] (closed 2026-04-02)

## Problem
Userspace RG activation is still modeled as multiple separate operations instead of one applied HA transition:

- Go marks ownership active and pushes `update_ha_state` in `pkg/dataplane/userspace/manager.go:2789-2862`
- the helper separately runs `refresh_owner_rgs()` with its own timeout and ack in `userspace-dp/src/afxdp.rs:1261-1337`
- workers still execute RG-wide reverse and forward refresh scans in `userspace-dp/src/afxdp/session_glue.rs:333-447`

That means activation success depends on more than one state machine and more than one acknowledgment path.

## Why this matters
Failover should be reducible to one cutover operation that says: the helper has applied HA generation N for RG set X and is forwarding-ready. Today the control plane can believe activation succeeded while helper-side repair work is still separate, delayed, or timed out.

This is part of why failover remains hard to reason about and why activation-time repair paths keep resurfacing.

## Simplification target
Collapse activation into one helper-applied HA generation:

- one control request from Go that carries the new HA generation / RG ownership set
- helper applies the state and any required activation work as one transition
- one success/failure ack back to Go once workers have actually applied it
- remove the separate `refresh_owner_rgs()` / worker-scan phase from steady-state failover

## Related
- #314
- #341
- #342
- #344
- #345
- #319


---

## #359 — Collapse helper demotion from prepare-plus-demote into one acknowledged transition [CLOSED] (closed 2026-04-02)

## Problem
Userspace demotion is still split across separate transport and helper phases:

- Go performs barrier-based peer checks in `pkg/daemon/daemon.go:4120-4178`
- the helper then runs `prepare_ha_demotion()` in `userspace-dp/src/afxdp.rs:1340-1365`
- workers execute `PrepareDemoteOwnerRGs` first, and later a separate `DemoteOwnerRG` in `userspace-dp/src/afxdp/session_glue.rs:279-332`

This means the system has to coordinate at least three different notions of “demotion is safe now”.

## Why this matters
A failover handoff should not require a prepare phase, a separate demote phase, and independent transport barriers if the replicated state model is correct. The current split is part of the cost and fragility of failover.

## Simplification target
Collapse helper demotion into one acknowledged transition:

- one demotion command scoped to a cutover generation / applied sequence
- helper performs the minimal state changes needed for handoff atomically
- one ack when the helper has reached the handoff-safe point
- remove the separate `PrepareDemoteOwnerRGs` and `DemoteOwnerRG` phases from normal failover

## Related
- #323
- #338
- #339
- #340


---

## #360 — Replace split active-plus-watchdog HA state with a single applied lease model [CLOSED] (closed 2026-04-02)

## Problem
Helper HA liveness is still represented by more than one mechanism:

- `active` is pushed through `update_ha_state()` in `userspace-dp/src/afxdp.rs:1074-1108`
- watchdog freshness is carried separately and checked in the packet path
- Go refresh cadence and helper stale thresholds are different enough that the helper can transiently treat a healthy RG as inactive

This creates two overlapping concepts of ownership: configured owner and currently-live owner.

## Why this matters
Failover is simpler if there is a single HA lease / generation model that the helper enforces. Separate `active` and watchdog state makes cutover semantics harder to reason about and creates extra failure modes.

## Simplification target
Replace split active-plus-watchdog HA state with one applied lease model:

- one lease / generation per RG
- helper packet path validates the current applied lease directly
- Go refreshes / renews the same lease model instead of a second watchdog channel
- remove duplicated semantics between ownership and liveness state

## Related
- #349
- #344


---

## #363 — Split userspace afxdp coordinator responsibilities out of afxdp.rs [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`userspace-dp/src/afxdp.rs` is still carrying multiple distinct responsibilities in one file:
- coordinator lifecycle and reconcile (`Coordinator::reconcile`, `stop_inner`)
- HA control / apply fencing (`update_ha_state`, `prepare_ha_demotion`, `export_owner_rg_sessions`)
- worker/binding runtime (`BindingWorker`, `poll_binding`, `worker_loop`)
- status/debug/reporting (`recent_exceptions`, `ha_groups`, `refresh_bindings`)
- a large mixed test block starting around `#[cfg(test)] mod tests`

Current size on origin/master: about 8.8k lines. The remaining complexity is not just hot-path forwarding; it is unrelated control/runtime code sharing one compilation unit.

Suggested split:
1. `afxdp/coordinator.rs` for reconcile/lifecycle
2. `afxdp/ha.rs` for HA control/apply/export
3. `afxdp/worker.rs` for `BindingWorker`, `poll_binding`, `worker_loop`
4. `afxdp/status.rs` for status/reporting helpers
5. move the large `afxdp.rs` test cluster into focused test modules adjacent to the production modules

Goal: make HA and worker-runtime changes reviewable without reopening the entire dataplane root file.

---

## #364 — Split frame parsing, rewrite, and protocol builders out of afxdp/frame.rs [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`userspace-dp/src/afxdp/frame.rs` is still a catch-all for multiple unrelated packet concerns:
- tuple/metadata parsing
- forwarded frame build / segmentation
- in-place rewrite and NAT checksum adjustment
- ICMP/ICMPv6 helper packet construction
- ARP/NDP neighbor probes
- checksum primitives
- a very large test block starting around line 4212

Current size on origin/master: about 8.1k lines. This is no longer one coherent module boundary.

Suggested split:
1. `afxdp/frame_parse.rs` for tuple/L3/L4 extraction
2. `afxdp/frame_rewrite.rs` for rewrite + NAT + checksum adjustment
3. `afxdp/frame_build.rs` for forwarded/injected packet builders
4. `afxdp/neighbor_probe.rs` for ARP/NDP probe packet construction
5. protocol-focused test modules instead of the current monolithic test section

Goal: make packet rewrite changes, neighbor-probe changes, and parsing fixes independent review units.

---

## #365 — Break userspace main.rs into snapshot schema, control schema, and server runtime modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`userspace-dp/src/main.rs` is currently mixing three different concerns:
- snapshot/config schema (`ConfigSnapshot`, interface/route/NAT/filter structs)
- control/status wire schema (`ControlRequest`, `ProcessStatus`, `HAGroupStatus`, request/response structs)
- server runtime and control loop (`run`, `handle_stream`, `refresh_status`, queue planning, binding planning)

Current size on origin/master: about 2.8k lines, with most of that being schema and control-loop code rather than dataplane execution. This makes even small API/status changes reopen the whole bootstrap/control server file.

Suggested split:
1. `snapshot.rs` for config snapshot schema
2. `control_protocol.rs` for request/response/status structs
3. `server.rs` for Unix socket control loop and status refresh
4. leave `main.rs` as thin startup / arg parsing / server bootstrap

Goal: reduce coupling between dataplane snapshot schema changes and the helper control server implementation.

---

## #366 — Split event_stream.rs into wire codec and transport state machine modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`userspace-dp/src/event_stream.rs` still mixes two different responsibilities:
- binary wire framing/encoding/decoding (`EventFrame`, encode helpers, header/IP/disposition encoding)
- sender transport lifecycle (connect/reconnect, replay buffer, drain handling, control-frame processing, IO thread)

Current size on origin/master: about 1.3k lines. This file is not enormous, but it is carrying both protocol definition and transport recovery behavior in one module, which makes review harder when changing either.

Suggested split:
1. `event_stream_codec.rs` for frame layout + encode/decode
2. `event_stream_transport.rs` for connection/replay/control handling
3. keep the public facade in `event_stream.rs` thin

Goal: let wire-format changes and reconnect/replay changes evolve independently.

---

## #367 — Break afxdp/types.rs catch-all into cohesive shared type modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`userspace-dp/src/afxdp/types.rs` has become a shared catch-all. It currently combines:
- flow cache types (`FlowCache*`, `RewriteDescriptor`)
- packet metadata / validation (`UserspaceDpMeta`, `ValidationState`)
- forwarding and route model (`ForwardingState`, `EgressInterface`, `FabricLink`, route entries)
- HA runtime state (`HAForwardingLease`, `HAGroupRuntime`)
- worker/runtime control types (`WorkerHandle`, `WorkerCommand`, `BindingPlan`)
- TX request / recycle types

Current size on origin/master: about 1.3k lines. The file is not too large by itself, but it is the dependency hub for multiple unrelated change streams.

Suggested split:
1. `flow_cache_types.rs`
2. `forwarding_types.rs`
3. `ha_types.rs`
4. `worker_types.rs`
5. `tx_types.rs`

Goal: reduce unnecessary recompilation/review overlap and make ownership of shared AF_XDP types explicit.

---

## #368 — Split forwarding.rs into snapshot compilation and runtime resolution modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`userspace-dp/src/afxdp/forwarding.rs` is currently serving two different layers:
- control-plane compilation from `ConfigSnapshot` into `ForwardingState` (`build_forwarding_state`, route/interface parsing, fabric link resolution)
- runtime forwarding decisions (`resolve_forwarding`, HA enforcement, fabric redirect decisions, route lookups, interface-local resolution, MSS clamping, cache validation)

Current size on origin/master: about 3.8k lines. The compile-time snapshot logic and the packet/session runtime logic are different reasons to change the file, but they are still coupled in one module.

Suggested split:
1. `forwarding_build.rs` for snapshot->state compilation
2. `forwarding_lookup.rs` for runtime resolution and route selection
3. `forwarding_ha.rs` for HA/fabric redirect enforcement
4. keep protocol-specific MSS helpers separate if they still belong together

Goal: make snapshot schema changes independent from runtime forwarding/HA changes.

---

## #369 — Split session_glue.rs into shared-session replication, reverse synthesis, and queue-cancel modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`userspace-dp/src/afxdp/session_glue.rs` still mixes several separate concerns:
- shared-session replication and export (`replicate_session_upsert/delete`, `publish_shared_session`, `remove_shared_session`)
- reverse companion synthesis and reverse prewarm (`build_reverse_session_from_forward_match`, `synthesized_synced_reverse_entry`, `prewarm_reverse_synced_sessions_for_owner_rgs`)
- HA/session resolution (`resolve_flow_session_decision`, `enforce_session_ha_resolution`)
- queued-flow cancellation / teardown helpers

Current size on origin/master: about 3.6k lines plus a large in-file test block. This file is acting as the bridge for every session concern, which makes HA work and ordinary session work hard to separate.

Suggested split:
1. `session_replication.rs`
2. `session_reverse.rs`
3. `session_resolution.rs`
4. `session_cancel.rs`
5. split the tests along the same boundaries

Goal: let HA/session-sync changes land without reopening reverse-session construction and TX queue cancellation code in the same patch.

---

## #370 — Split daemon.go into config apply, HA/session-sync, and cluster/fabric modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/daemon/daemon.go` is still the main Go control-plane monolith. It currently mixes:
- daemon bootstrap and run loop
- config application / host-service orchestration (DNS, NTP, syslog, SSH, login, flow trace)
- userspace session-sync and event-stream handling
- graceful demotion and HA failover prep
- cluster transport startup and lifecycle
- fabric state / neighbor probing / fabric forwarding refresh
- RG state machines, VRRP/cluster watchers, VIP move, GARP/GNA, reth services

Current size on origin/master: about 8.2k lines. These are different reasons to modify the file, and the HA path in particular is hard to reason about because it shares a file with unrelated host-service configuration code.

Suggested split:
1. `daemon/run.go` for bootstrap and top-level lifecycle
2. `daemon/config_apply.go` for host/system config application
3. `daemon/session_sync.go` for userspace event-stream + session-sync integration
4. `daemon/ha_failover.go` for demotion/failover/RG transition logic
5. `daemon/fabric.go` for fabric forwarding/refresh/probing
6. `daemon/reth.go` for VIPs, reth services, GARP/GNA, blackhole routes

Goal: make HA/failover changes reviewable without reopening unrelated system-config logic, and vice versa.

---

## #371 — Split grpcapi/server.go by RPC domain instead of one monolithic server file [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/grpcapi/server.go` is currently a 9.7k line catch-all for almost every gRPC method. It mixes:
- config-mode RPCs (`Set`, `Delete`, `Load`, `Commit`, rollback/history)
- operational RPCs for sessions, routes, interfaces, NAT, screen, events, system info
- peer/proxy behavior and pagination logic
- command completion / schema completion
- streaming RPCs (ping, traceroute, monitor packet drop, monitor interface)
- cluster/system actions

This is not one coherent module. Small changes to one RPC family reopen the entire server implementation.

Suggested split:
1. `server_config.go` for config/edit/commit RPCs
2. `server_sessions.go` for session and NAT/session-summary RPCs
3. `server_interfaces.go` for interface/system/route operational RPCs
4. `server_monitor.go` for streaming monitor/ping/traceroute RPCs
5. `server_complete.go` for completion/value-provider logic
6. keep `server.go` for construction/interceptors/shared helpers only

Goal: reduce review blast radius and make RPC ownership explicit by subsystem.

---

## #372 — Split userspace manager.go into helper lifecycle, HA/session sync, and map sync modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/dataplane/userspace/manager.go` is still carrying multiple distinct control-plane responsibilities:
- helper process lifecycle and control socket transport
- snapshot compilation / process bootstrap
- HA state sync and watchdog updates
- userspace session mirror/install/delete paths
- ingress/local-address/interface-NAT BPF map sync
- proactive neighbor resolution and ctrl enable/disable
- status loop / counter sync / fallback stats

Current size on origin/master: about 5.4k lines. The HA/session-sync work is especially hard to review because it is mixed with process lifecycle, map programming, and counter/status code.

Suggested split:
1. `manager_process.go` for helper lifecycle and control RPC plumbing
2. `manager_snapshot.go` for snapshot compilation/bootstrap sync
3. `manager_ha.go` for HA state/watchdog/demotion/update paths
4. `manager_sessions.go` for session mirror/install/delete/export/drain
5. `manager_maps.go` for ingress/local/NAT map sync
6. `manager_status.go` for polling/counters/fallback visibility

Goal: isolate HA/session work from general helper-management and dataplane map-programming code.

---

## #373 — Split config/compiler.go by configuration domain instead of one giant compiler file [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/config/compiler.go` is still a giant domain compiler file. It currently compiles:
- security zones, policies, screens, address books
- interfaces and routing options
- NAT, NAT64, static NAT, NPTv6
- protocols (BGP/OSPF/RIP/ISIS/RA), IKE/IPsec
- firewall filters, system, services, forwarding options, SNMP, policy-options, chassis, event-options, bridge-domains

Current size on origin/master: about 6.7k lines. This is not one bounded compiler concern; it is a directory worth of domain compilers in one file.

Suggested split:
1. `compiler_security.go`
2. `compiler_interfaces_routing.go`
3. `compiler_nat.go`
4. `compiler_protocols.go`
5. `compiler_system_services.go`
6. `compiler_policy_options.go` / `compiler_chassis.go` as needed

Goal: make config-domain changes local and reduce the blast radius of compiler edits.

---

## #374 — Split cluster/sync.go into transport, bulk/barrier, and producer integration modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/cluster/sync.go` is still one file for almost the entire session-sync subsystem. It currently mixes:
- transport framing and connection lifecycle
- send/receive loops and active-fabric connection arbitration
- sweep scheduling and producer integration
- queue/journal management for incremental sync
- barrier / fence / bulk / bulk-ack semantics
- disconnect handling and stale-session reconciliation
- sync stats and formatting

Current size on origin/master: about 2.8k lines. The logic is coherent at a package level, but the file is still serving too many internal roles for one compilation unit.

Suggested split:
1. `sync_transport.go` for connection lifecycle and send/receive loops
2. `sync_bulk.go` for bulk, bulk-ack, barriers, idle/drain waits
3. `sync_incremental.go` for queueing, journals, producers, sweeps
4. `sync_stats.go` for counters/reporting

Goal: let HA transport work, barrier semantics, and producer-policy changes evolve independently.

---

## #375 — Split cli.go into command-family modules instead of a single operational CLI file [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/cli/cli.go` is still a 12.6k line command monolith. It mixes:
- CLI runtime / completion / dispatch
- config-mode command handling
- security flow/session views and clear operations
- NAT, route, protocol, interface, system, chassis, services, firewall, DHCP, SNMP, LLDP, VRRP, test/monitor commands

This file is effectively the entire CLI surface in one compilation unit. Small command-family work reopens the whole operational client.

Suggested split:
1. `cli_runtime.go` for prompt/dispatch/completion
2. `cli_config.go` for config-mode commands
3. `cli_show_security.go`
4. `cli_show_interfaces.go`
5. `cli_show_system.go`
6. `cli_show_routing.go`
7. `cli_request.go`
8. `cli_monitor_test.go` for monitor/test handlers

Goal: keep command-family changes isolated and reduce merge friction in the CLI.

---

## #376 — Split api/handlers.go by REST resource family [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/api/handlers.go` is a smaller but still mixed control-plane file. It currently combines handlers for:
- health/status/global stats
- zones/policies/sessions/session-summary
- NAT/screen/events/interfaces/routes
- config/edit endpoints
- system, DHCP, ping/traceroute, policy matching, system actions

Current size on origin/master: about 2.4k lines. It is essentially the REST equivalent of the gRPC server problem: many operational resource families implemented in one file.

Suggested split:
1. `handlers_status.go`
2. `handlers_sessions.go`
3. `handlers_interfaces_routes.go`
4. `handlers_config.go`
5. `handlers_system.go`

Goal: keep REST handler work scoped by resource family instead of reopening one monolithic HTTP handler file.

---

## #377 — Split dataplane/compiler.go into feature compilers and host-interface setup modules [CLOSED] (closed 2026-04-02)

Audit target: origin/master at 06772bf8

`pkg/dataplane/compiler.go` is still a large mixed compiler/runtime-prep file. It currently mixes:
- top-level dataplane compile orchestration
- interface/link/VLAN resolution and reconciliation
- zones/address book/policy/NAT/filter/flow compilation into dataplane structures
- screen/default policy config
- interface ethtool tuning, RSS, ring/buffer tuning, mirror setup

Current size on origin/master: about 4.7k lines. The dataplane compilation logic and the host-interface preparation logic are different reasons to change the file, but they are still coupled together.

Suggested split:
1. `compile_features.go` for zones/policy/NAT/filter/flow compilation
2. `compile_interfaces.go` for interface/link/VLAN discovery and reconciliation
3. `compile_tuning.go` for ethtool/RSS/buffer/ring tuning
4. keep the top-level orchestration in a thin `compiler.go`

Goal: make dataplane feature compilation independent from host-interface setup and tuning changes.

---

## #389 — Index helper HA session state by owner RG to remove failover-time full-table scans [CLOSED] (closed 2026-04-03)

Helper HA apply is still doing O(all sessions) work on failover because shared session state is not indexed by owner RG.

Code evidence:
- `userspace-dp/src/afxdp/ha.rs:36` walks `shared_sessions` for every demoted RG to delete BPF map keys.
- `userspace-dp/src/afxdp/ha.rs:49` walks `shared_nat_sessions` for the same reason.
- `userspace-dp/src/afxdp/ha.rs:60` walks `shared_forward_wire_sessions` for the same reason.
- `userspace-dp/src/afxdp/session_glue.rs:110` `refresh_live_reverse_sessions_for_owner_rgs()` first collects all session entries and then re-filters by RG after re-resolution.

Why this is a problem:
- failover cost scales with total shared session count instead of only the changed RGs
- activation/demotion still needs repair scans, which keeps HA cutover expensive and timing-sensitive under load
- it also makes it harder to collapse failover down to a single apply fence because the helper must rediscover affected state at transition time

Simpler target:
- maintain derived indexes keyed by owner RG (and alias type if needed) alongside the canonical shared session store
- make demotion and activation operate on only the affected RG index entries
- eliminate whole-table scans from the HA transition path

That should make failover work proportional to the moved RGs instead of the entire replicated session table.

---

## #390 — Replace weight-zero manual failover with an explicit RG transfer protocol [CLOSED] (closed 2026-04-03)

Current manual failover still works by setting `ManualFailover=true`, forcing `Weight=0`, and letting election heuristics make the peer primary.

Code evidence:
- `pkg/cluster/cluster.go:618` `ManualFailover()` sets `Weight=0` and flips local state to secondary.
- `pkg/cluster/election.go:41` contains a 2s time-based deadlock escape to clear `ManualFailover` if both sides have effectively resigned.
- `pkg/cluster/cluster.go:1118` clears `ManualFailover` again on peer loss as another recovery path.

Why this is a problem:
- failover intent is expressed indirectly through election weight mutation instead of an explicit transfer state machine
- rapid failover cycles need time guards and peer-loss cleanup to avoid dual-secondary or self-repromotion behavior
- this makes HA correctness depend on election timing instead of a single acknowledged ownership handoff

Simpler target:
- introduce an explicit per-RG transfer protocol: `prepare -> peer ready -> ownership commit -> announce`
- manual failover should nominate the target owner directly instead of driving election through `Weight=0`
- election should remain for health/peer-loss arbitration, not steady-state manual cutover orchestration

This should reduce the amount of timing-sensitive logic in failover and make cutover easier to reason about.

---

## #391 — Remove NAPI bootstrap from the HA cutover path [CLOSED] (closed 2026-04-02)

`UpdateRGActive()` still starts queue bootstrap work during RG activation instead of requiring the standby dataplane to already be RX-ready before ownership changes.

Code evidence:
- `pkg/dataplane/userspace/manager_ha.go:281` `UpdateRGActive()` calls `bootstrapNAPIQueuesAsyncLocked("ha-update-active")` whenever an RG becomes active.
- The bootstrap implementation in `pkg/dataplane/userspace/manager.go` exists to trigger RX/NAPI activity after bind so zero-copy queues begin consuming fill-ring entries.

Why this is a failover complexity problem:
- activation is still doing startup-style dataplane bring-up work
- that means cutover correctness depends on asynchronous queue bootstrap timing, not just ownership transfer
- if standby readiness were truly continuous, failover would not need to trigger NAPI bootstrap at all

Simpler target:
- prove and maintain RX-liveness continuously on both nodes before they are takeover-ready
- remove NAPI bootstrap from `UpdateRGActive()`
- treat lack of queue readiness as a readiness failure before failover, not work that begins during failover

This reduces HA cutover toward the intended model: move ownership, announce, keep forwarding.

---

## #398 — manual failover still times out while requester is in bulk sync receive [CLOSED] (closed 2026-04-03)

## Summary
Manual failover is still rejected if the requesting node is in active session-sync bulk receive. The new transfer-commit path in #397 works once the cluster is settled, but the pre-failover admission path still blocks on session-sync barrier acknowledgments that are not serviced while the requester is mid-bulk.

## Runtime proof
Validated on `origin/master` at `310a2399` on `loss-userspace-cluster`.

Initial RG0 failover request from `node0` to make `node0` primary:
- command returned: `rpc error: code = FailedPrecondition desc = timed out waiting for peer failover ack for redundancy group 0`
- requester (`fw0`) was still in bulk receive:
  - `cluster sync: bulk receive progress epoch=4 sessions=64`
  - `cluster sync: bulk receive progress epoch=4 sessions=128`
  - `cluster sync: bulk receive progress epoch=4 sessions=192`

Responder (`fw1`) logs show repeated admission retries failing on the peer barrier:
- `cluster: bulk sync not acked yet, verifying peer readiness via barrier`
- `cluster: waiting to admit manual failover ... err="session sync not ready before demotion: peer not responding to barrier: timed out waiting for session sync barrier ack seq=..."`
- final failure:
  - `cluster: remote failover failed ... err="pre-failover prepare for redundancy group 0: session sync not ready before demotion: peer not responding to barrier: timed out waiting for session sync barrier ack seq=9 ..."`

After bulk receive completed on `fw0`:
- `cluster sync: bulk transfer complete epoch=4 sessions=197`
- repeating the same RG0 failover succeeded immediately
- success path logs on `fw0` were:
  - `cluster sync: failover ack received ... status=0`
  - `cluster: primary transition rg=0`
  - `cluster sync: failover commit sent to peer`
  - `cluster sync: failover commit ack received ... status=0`

## Why this matters
#397 removed heartbeat-observed completion from manual failover, but operators can still hit a separate failure mode if they request the move while reconnect bulk sync is still in progress. That leaves manual failover behavior dependent on session-sync bootstrap timing.

## Likely direction
- make session-sync barriers serviceable during bulk receive, or
- make manual failover admission fail fast with an explicit `bulk sync in progress` reason instead of a 30-40s barrier timeout loop, or
- add a dedicated settled/transfer-ready gate distinct from generic session-sync bulk readiness.


---

## #400 — surface manual failover transfer readiness separately from takeover readiness [CLOSED] (closed 2026-04-03)

## Summary
`show chassis cluster status` can report an RG as `Takeover ready: yes` while explicit manual failover is still blocked by unsettled session-sync transfer state.

## Why this matters
During live validation of `#397`, `node0` showed takeover-ready `yes` for `RG0`, but a manual failover request still failed because the node was in active session-sync bulk receive and could not satisfy the peer-side demotion barrier.

That means the readiness model shown to operators is still weaker than the actual preconditions for explicit RG transfer.

## Code evidence
- `pkg/cluster/cluster.go` readiness only reflects the current RG readiness pipeline (`Ready`, `ReadySince`, `ReadinessReasons`).
- `pkg/daemon/daemon_ha.go` manual failover admission has additional session-sync preconditions that are not reflected in RG takeover readiness.
- `pkg/cli/cli.go` `show chassis cluster status` prints the RG readiness model, not manual-failover transfer readiness.

## Simpler target
Add an explicit transfer-ready/readiness reason surface for manual failover so the CLI and APIs can say:
- takeover-ready for election
- transfer-ready for explicit RG failover

Those should not silently diverge.


---

## #403 — Planned failover must not depend on bulk sync — both nodes already have full session state [CLOSED] (closed 2026-04-03)

## Problem

Planned failover (CLI `request chassis cluster failover`) currently fails when bulk sync is in progress because the barrier message gets stuck behind bulk data in the TCP stream. This is fundamentally wrong — planned failover should never need bulk sync because both nodes have been running and syncing sessions in real-time.

The code conflates three distinct cases:

1. **Planned failover** — Both nodes healthy, sessions syncing continuously. Standby already has every session. Should require: one barrier ack (proves peer is current) → flip ownership → done. Must reject if sessions aren't current instead of waiting for bulk.

2. **Unplanned failover** — Primary crashes. Secondary takes over immediately via VRRP timeout regardless of session state. Acceptable to lose some sessions — total outage is worse.

3. **Startup/reconnect** — Node joins cluster (boot, restart, partition recovery). Needs full session table from peer. This is the ONLY case where bulk sync should run.

## Current Behavior

- `prepareUserspaceRGDemotionWithTimeout` sends a barrier, but barrier delivery takes 60-80s when bulk sync is in progress because:
  - `writeBarrierMessage` writes via `writeMu` which `sendLoop` holds during bulk writes
  - Barrier ack from the peer goes through `sendCh` competing with outbound messages
- `syncPeerBulkPrimed` gates failover readiness, but this flag is about startup state, not steady-state sync health
- Manual failover returns "demotion peer barrier failed: timed out" during the 30-120s bulk sync window after reconnect

## Required Changes

### 1. Separate planned failover readiness from bulk sync state

The planned failover path should check:
- Is session sync connected? (TCP link up)
- Has the peer processed all our incremental deltas? (one barrier ack)

It should NOT check:
- `syncPeerBulkPrimed` (startup concern, not failover concern)
- Whether bulk transfer is in progress
- Queue drain state

### 2. Barrier must bypass bulk data in the TCP stream

Barriers are control messages. They must not wait behind bulk session data. Options:
- (a) Write barriers directly on the TCP connection with `writeMu` + short deadline, bypassing `sendCh` and `sendLoop`
- (b) Use a separate TCP connection for barriers/control
- (c) Give barriers priority in `sendCh` (priority channel with barrier lane)


*(truncated — 87 lines total)*


---

## #408 — Remove 2s worker ApplyHAState ack wait from demotion path [CLOSED] (closed 2026-04-03)

The helper's update_ha_state blocks up to 2 seconds waiting for all workers to ack the ApplyHAState command (ha.rs:162-180). This is unnecessary — the BPF session map is already updated synchronously, and the worker ack only confirms internal cache updates. Flow cache uses epoch-based invalidation that works without the ack. Make this fire-and-forget.

---

## #409 — Eliminate double fib_gen bump during RG transition [CLOSED] (closed 2026-04-03)

Both the daemon (daemon_ha.go:2616) and UpdateRGActive (manager.go:348) bump fib_gen. This invalidates ALL flow caches across ALL RGs twice. Should bump once per transition, and ideally only invalidate the affected RG (already done via rg_epoch).

---

## #410 — Blackhole route injection still runs in userspace mode despite #354 skip [CLOSED] (closed 2026-04-03)

Check if blackhole routes are actually being skipped for userspace mode. The userspaceDataplaneActive() guard was added in #354 but the XDP shim should handle inactive RGs via rg_active map. Verify no blackhole syscalls happen during userspace failover — they add 1-10ms per route.

---

## #411 — Pre-failover prepare retry loop has 45s timeout — should fast-fail for planned failover [CLOSED] (closed 2026-04-03)

ManualFailover in cluster.go:676-704 retries preManualFailoverFn every 500ms for up to 45 seconds. For planned failover where both nodes are healthy, this should succeed on first attempt. If it doesn't, fail immediately with a diagnostic error instead of retrying for 45s. The barrier ack proves readiness — no retry loop needed.

---

## #412 — Sessions deleted from XDP map on demotion should be unnecessary if rg_active is checked [CLOSED] (closed 2026-04-03)

On demotion, ha.rs:40-78 deletes ALL sessions for the demoted RG from the USERSPACE_SESSIONS BPF map. This is O(N) synchronous work. If the XDP shim checked rg_active before using a session entry, deletion would be unnecessary — the shim would see rg_active=0 and fall through to slow path. This was the goal of issue #329 (BPF pre-populate with per-RG gating).

---

## #413 — Synced sessions should already be in new owner's BPF session map before activation [CLOSED] (closed 2026-04-03)

Currently, reverse sessions are written to the BPF USERSPACE_SESSIONS map during prewarm_reverse_synced_sessions (activation time). If UpsertSynced wrote to the BPF map at sync-receipt time (not just activation), the map would already be populated before failover. The XDP shim could start redirecting immediately without waiting for prewarm. Requires rg_active gating in the XDP shim (#329).

---

## #414 — CRITICAL: Demoted sessions fall through gap — userspace DP skips fabric redirect, eBPF never invoked [CLOSED] (closed 2026-04-03)

## The Bug

During HA failover, established TCP streams die because demoted sessions are deleted from the USERSPACE_SESSIONS BPF map but the userspace dataplane **does not fabric-redirect them**. The code has a comment saying the eBPF pipeline will handle fabric redirect, but the eBPF pipeline is never invoked for these packets.

## The Sequence

1. Old owner demotes RG1 → deletes ALL sessions from USERSPACE_SESSIONS map (ha.rs:40-78)
2. Packet arrives at old owner (ARP/MAC hasn't moved yet, 10-100ms gap)
3. XDP shim looks up USERSPACE_SESSIONS → **NOT FOUND** (return=0)
4. XDP shim treats it as a **new flow** → redirects to userspace DP via XSK
5. Userspace DP resolves forwarding → gets **HAInactive** (egress RG is inactive)
6. Code at afxdp.rs:3516 has comment: *\"HAInactive fabric redirect is handled by the eBPF pipeline via rg_active checks + try_fabric_redirect()\"*
7. **But the eBPF pipeline was never invoked** — the packet went to userspace DP
8. Packet is dropped or sent to kernel slow path
9. TCP stream sees packet loss → retransmits → window collapses → stream dies

## Why the Comment is Wrong

The comment assumes deleted sessions will hit the eBPF pipeline's \`try_fabric_redirect()\` which checks \`rg_active\` and redirects via fabric. But:

- Sessions were deleted from USERSPACE_SESSIONS (the XDP shim's redirect map)
- When deleted, the XDP shim sees session=0 → treats as new flow → sends to userspace DP
- The packet **never reaches the eBPF pipeline**
- The eBPF pipeline's fabric redirect only works for sessions still in the eBPF conntrack map

## The Fix

**Option A (Quick, recommended):** Make the userspace DP fabric-redirect HAInactive packets directly instead of relying on the eBPF pipeline:

\`\`\`rust
// In afxdp.rs, after HAInactive detection for existing sessions:
if resolution.disposition == ForwardingDisposition::HAInactive
    && !ingress_is_fabric(forwarding, meta.ingress_ifindex)
{
    if let Some(redirect) = resolve_fabric_redirect(forwarding) {
        decision.resolution = redirect;
    }
}
\`\`\`


*(truncated — 59 lines total)*


---

## #417 — Flow cache entries with owner_rg_id=0 bypass epoch invalidation on demotion [CLOSED] (closed 2026-04-03)

## Problem
After failback (fw1→fw0), fw1's flow cache still forwards packets locally even though RG1 was demoted. The flow cache has 97M hits but only 3 sessions were demoted per worker.

## Root Cause
Flow cache entries created from locally-originated sessions have `owner_rg_id=0` because the session's owner RG wasn't resolved when the flow cache entry was built. The epoch-based invalidation checks `entry.rg_epoch != rg_epochs[entry.owner_rg_id]`, but with `owner_rg_id=0` this check is skipped (RG 0 is the control RG, always active).

## Evidence
- fw1 demoted RG1 with 97M forward candidates but only 3 sessions demoted per worker
- FIB gen bumped to 4, but flow cache entries with rg_id=0 don't check RG epochs
- First direction (fw0→fw1) worked because fw0's sessions were synced (with owner_rg_id resolved)
- Reverse (fw1→fw0) failed because fw1's sessions were locally created (owner_rg_id=0)

## Fix
When building a flow cache entry from a locally-created session, resolve the owner_rg_id from the egress interface's RG mapping. Or: when fib_gen bumps, invalidate ALL flow cache entries (not just epoch-matched ones).

## Files
- `userspace-dp/src/afxdp.rs` — flow cache insert path
- `userspace-dp/src/afxdp/flow_cache.rs` — FlowCacheEntry, lookup validation

---

## #418 — Replace bulk session sync with event stream replay on connect [CLOSED] (closed 2026-04-03)

## Problem
Bulk session sync (BulkSync in sync_bulk.go) is fundamentally slow:
1. Iterates BPF session maps in Go
2. Writes each session via TCP with writeMu contention
3. Receiver installs each via control socket to Rust helper
4. Takes 30-120s for ~500 sessions due to control socket contention
5. Creates transfer readiness gates that block planned failover

## Proposed Fix
Use the event stream for startup sync. On peer connect:
1. Active node's Rust helper has all sessions in memory
2. Helper replays all sessions as event stream Open events
3. Go daemon receives them via handleEventStreamDelta (same path as real-time)
4. Go daemon queues them to peer via QueueSessionV4 (same path as incremental)
5. Peer installs them normally

Benefits:
- No BPF map iteration (sessions already in Rust memory)
- No control socket contention (event stream is a separate Unix socket)
- Same code path for startup and steady-state sync
- Transfer readiness is just \"event stream connected + last sequence acked\"
- Bulk sync mechanism can be removed entirely

## Alternative
If full event stream replay is too complex, batch the control socket requests — send 50-100 sessions per request instead of 1.

---

## #420 — event stream replay bulk export can silently drop sessions under load [CLOSED] (closed 2026-04-03)

The new event-stream replay bootstrap path introduced in #419 replaces Go-side `BulkSync()` with `ExportAllSessionsViaEventStream()` on helper connect.

Problem:
- `userspace-dp/src/afxdp/ha.rs::export_all_sessions_to_event_stream()` iterates every shared session and calls the event-stream worker handle.
- The worker handle currently uses `try_send()` on a bounded `sync_channel` with capacity 8192.
- When the channel is full, frames are silently dropped and only a counter is incremented.
- The export path does not check for drops, retry, or force a resync.

Why this matters:
- This path is now the userspace bootstrap path on reconnect.
- A busy node or a large session table can exceed channel capacity during replay.
- Dropped bootstrap events mean the peer starts with an incomplete session set, which directly undermines HA takeover correctness.

Acceptance criteria:
- Bootstrap/replay export must be lossless or must fail loudly and trigger a deterministic fallback.
- Add coverage proving the export path does not silently lose frames when the event queue is saturated.
- Keep the normal worker hot path non-blocking if needed; the fix only needs to harden the explicit replay/export path.


---

## #421 — monitor interface traffic needs a realtime all-interface pps/bandwidth view [CLOSED] (closed 2026-04-03)

`monitor interface` already samples interface counters, but the current implementation is split across the local CLI and gRPC server and the summary path is still weaker than a `bwm-ng`-style operational view.

Problems:
- The monitor sampling / rendering logic is duplicated between `pkg/cli/monitor_interface.go` and `pkg/grpcapi/server.go`.
- Remote `MonitorInterface` streams preformatted text only, which makes extension awkward and leaves the summary view fixed to packet counters.
- The current all-interface summary is not a good answer to "where is traffic flowing right now?" because it does not present per-interface packet rate and bandwidth together in a single realtime table.

Desired outcome:
- One shared sampling path for interface monitor snapshots.
- A realtime all-interface table that shows per-interface RX/TX packet rate and bandwidth in a form similar to `bwm-ng`.
- Keep fabric-overlay parent resolution correct so the numbers reflect wire traffic, not just overlay IP traffic.
- Expose the improved summary via both the local CLI and the gRPC-backed remote CLI.


---

## #423 — monitor interface traffic should add bwm-ng style interactive views and help [CLOSED] (closed 2026-04-03)

`monitor interface traffic` needs a second step beyond the new all-interface realtime table: it should behave more like `bwm-ng` when running interactively so operators can quickly pivot views without restarting the command.

Problems:
- The new realtime table is useful, but it still lacks the interactive `bwm-ng` model the operators are using as the reference.
- There is no in-band help overlay describing the available keys while the monitor is live.
- There is no single-key cycling for unit/view changes such as bytes, bits, packets, and errors, or for rolling between current-rate and accumulated views.
- The refresh interval is fixed instead of being adjustable live.

Desired outcome:
- Add an in-band help panel similar to `bwm-ng` on `h`.
- Add interactive keybindings to cycle unit/view modes while the monitor is running.
- Add live refresh-interval adjustment.
- Keep the local CLI and gRPC-backed remote CLI behavior aligned.


---

## #426 — fabric redirect path bandwidth limits existing TCP streams during failover [CLOSED] (closed 2026-04-03)

## Problem

When RG ownership moves between nodes (planned failover), established TCP streams
that were running at full WAN throughput (~12 Gbps) die because the fabric redirect
path can only sustain ~2 Gbps (copy-mode XSK on virtio fabric parent).

The TCP congestion window is tuned for 12 Gbps (Cwnd=4.14 MB). After failover,
traffic routes through the fabric link. The huge burst overwhelms the copy-mode
XSK binding on the fabric parent interface, causing kernel RX drops (739 out of
13.6M packets = 0.005%). This triggers TCP congestion collapse (Cwnd → 1.41 KB)
and the stream never recovers.

## What works

- New connections in split-RG state: 2.09 Gbps sustained for 30+ seconds
- Ping across fabric: 0% loss
- Barrier for planned failover: succeeds promptly
- Session sync: both event stream and bulk markers work

## Root cause

The fabric parent interface (ge-0-0-0 / ge-7-0-0) is a virtio-net interface
with copy-mode AF_XDP (not zerocopy). Each fabric-redirected packet is memcpy'd
from kernel to user-space UMEM. At high throughput bursts, the copy can't keep
up and the kernel drops frames from the RX ring.

## Potential fixes

1. **Increase virtio ring sizes** on fabric parent to absorb bursts
2. **Zerocopy XSK** on fabric parent (requires hardware support)
3. **Graceful cwnd reduction**: during failover transition, temporarily set a
   lower TCP MSS or trigger ECN to signal TCP to reduce its sending rate
4. **Pacing**: rate-limit fabric redirect output to the sustainable rate
5. **Slow-path fallback for fabric**: route fabric-redirected packets through
   the io_uring slow path instead of XSK TX, avoiding the copy-mode bottleneck

## Test reproduction

```bash
# Deploy and restart

*(truncated — 54 lines total)*


---

## #427 — barrier timeout under high-parallelism session sync (-P8) [CLOSED] (closed 2026-04-04)

## Problem

Planned failover via `request chassis cluster failover` times out on the
pre-demotion barrier when the session sync TCP connection carries heavy
traffic from the bulk sync retry loop. With `-P8` iperf (generating ~500+
synced sessions), the barrier ack takes 30+ seconds because session data
fills the TCP send buffer ahead of the barrier.

The direct-write barrier fix (e0def75d) helps for low session counts but
doesn't solve the case where hundreds of session messages are already
queued in the TCP buffer when the barrier is written.

## Root Cause

`writeBarrierMessage` writes the barrier directly via `writeMu`, but the
TCP send buffer already contains session data from `sendLoop`. The barrier
bytes are appended AFTER the buffered session data. The peer doesn't see
the barrier until it reads through all preceding session messages.

The bulk sync retry loop (`startSessionSyncPrimeRetry`) continuously
pushes sessions through `sendCh` → `sendLoop` → TCP write, keeping the
buffer full.

## Fix

The `DrainSendQueue` + `syncPrimeRetryGen.Add(1)` in the demotion prep
path need to also wait briefly for the TCP send buffer to flush before
writing the barrier. Options:

1. After draining sendCh and stopping the retry loop, call
   `runtime.Gosched()` + brief sleep to let sendLoop finish its current
   write and the kernel flush the TCP buffer
2. Set `TCP_NODELAY` on the sync connection to prevent Nagle buffering
3. Use a dedicated priority TCP connection for barriers (separate from
   session data)

## Reproduction

```bash
iperf3 -c 172.16.80.200 -P 8 -t 60 &

*(truncated — 44 lines total)*


---

## #429 — Flow cache can outlive HA forwarding lease expiry [CLOSED] (closed 2026-04-04)

## Summary
The `3bbcbcd8` flow-cache fast-path removed the per-packet HA validity check on cache hits and now relies on RG epoch invalidation only. That misses the case where an HA forwarding lease simply ages out without an explicit RG epoch bump.

## Why this is a bug
Cached entries on the hot path can continue forwarding with a stale `ForwardCandidate`/`FabricRedirect` decision after `HAGroupRuntime::is_forwarding_active()` would already return false. That means established cached flows can keep using the local fast path after watchdog lease expiry instead of falling back to `HAInactive` and fabric redirect/slow-path re-resolution.

## Affected code
- `userspace-dp/src/afxdp.rs` cache-hit path no longer calls `cached_flow_decision_valid()`
- `userspace-dp/src/afxdp/flow_cache.rs` validates only config/FIB generation plus `owner_rg_epoch`
- `userspace-dp/src/afxdp/types.rs` still models time-based HA leases via `HAForwardingLease::ActiveUntil`

## Expected
Flow-cache hits should self-expire once the owning RG lease has lapsed, even if no explicit demotion/activation epoch bump occurred.

## Audit context
Found while auditing commits added after the April 3, 2026 `master` rebase point (`8386f394..3bbcbcd8`).

---

## #430 — Manual failover barrier no longer preserves session-sync ordering [CLOSED] (closed 2026-04-04)

## Summary
The barrier changes in `55c46fc4`, `5e757452`, and `03dc4cd3` broke the core ordered-barrier guarantee used by planned userspace failover.

## Why this is a bug
`WaitForPeerBarrier()` now writes the barrier directly under `writeMu` after pausing the send loop, and `prepareUserspaceRGDemotionWithTimeout()` drains `sendCh` before issuing the barrier. Together, those changes mean the barrier ack can succeed even though earlier queued session deltas were either skipped or discarded.

That defeats the whole meaning of the demotion barrier: peer ack is supposed to prove the standby already processed all earlier session updates before takeover.

## Affected code
- `pkg/cluster/sync_bulk.go` direct barrier write path
- `pkg/cluster/sync.go` send-loop pause machinery added to support the direct write
- `pkg/daemon/daemon_ha.go` demotion prep calls `DrainSendQueue()` before `WaitForPeerBarrier()`

## Expected
Planned failover barriers must stay in the same FIFO stream as queued session deltas and must never drop queued sync messages to make the barrier arrive faster.

## Audit context
Found while auditing commits added after the April 3, 2026 `master` rebase point (`8386f394..3bbcbcd8`).

---

## #433 — XDP shim fabric redirect bypass for zero-copy cross-chassis forwarding [CLOSED] (closed 2026-04-05)

## Problem

Fabric redirect in the userspace dataplane routes packets through XSK
copy-mode on the virtio fabric parent interface, consuming ~20% CPU
(combined TX + RX on both nodes) for kernel SKB allocation and memcpy.

Current: 4.0 Gbps at -P8 through fabric
Target: closer to the 23 Gbps direct path

See docs/fabric-performance-optimizations.md for full profile data.

## Proposed Fix

Teach the XDP shim to perform fabric redirect at the XDP level using
\`bpf_redirect_map\`, bypassing XSK entirely for fabric-destined packets.
This matches how the eBPF pipeline handles fabric redirect — zero-copy
XDP-to-XDP redirect with no userspace involvement.

### Implementation

1. Add a \`USERSPACE_FABRIC_REDIRECT\` BPF hash map:
   \`{5-tuple} → {fabric_ifindex, dst_mac[6], src_mac[6], nat_rewrite}\`

2. Rust helper writes entries when creating/refreshing sessions that
   resolve to FabricRedirect disposition

3. XDP shim checks the map BEFORE redirecting to XSK:
   - Match: rewrite MACs + apply NAT + \`bpf_redirect_map(fabric_ifindex)\`
   - No match: redirect to XSK as normal

4. The shim must handle NAT rewrite in BPF (the eBPF pipeline already
   has \`apply_nat_ipv4/ipv6\` — can reuse those helpers)

### Benefits

- Eliminates \`__xsk_generic_xmit\` SKB allocation (9.4% CPU on fw0)
- Eliminates copy-mode XSK RX overhead (11.3% CPU on fw1)
- Fabric packets stay in kernel XDP path — zero userspace involvement
- Same behavior as eBPF pipeline's \`try_fabric_redirect\`


*(truncated — 51 lines total)*


---

## #434 — Cached FabricRedirect flow-cache hits ignore apply_nat_on_fabric [CLOSED] (closed 2026-04-04)

## Summary
Cached userspace flow-cache hits for `FabricRedirect` sessions do not consistently honor the cached `apply_nat_on_fabric` decision.

## Impact
When a new session is resolved on the slow path with `apply_nat_on_fabric=false`, later cached hits can still apply NAT:
- the self-target descriptor fast path rewrites IPs/ports because `apply_rewrite_descriptor()` ignores the cached flag
- the cross-binding fallback path forces `build_live_forward_request_from_frame(..., true)` instead of using the cached descriptor value

That can rewrite packets differently from the session decision that originally populated the cache, which is both a correctness bug and extra transient NAT work on the fabric path.

## Fix
- preserve whether a cached descriptor represents a `FabricRedirect`
- make descriptor rewrites skip NAT deltas when `apply_nat_on_fabric=false`
- make cached fallback forwarding requests reuse the cached flag instead of forcing NAT on
- add regression coverage for the descriptor path


---

## #436 — Refresh fabric performance plan for strict userspace NAT path [CLOSED] (closed 2026-04-04)

## Summary
`docs/fabric-performance-optimizations.md` no longer matches the current strict-userspace dataplane.

## Problems
- it describes steady-state fabric transit as a `PASS_TO_KERNEL` -> eBPF pipeline path, but current code keeps transit session hits on AF_XDP/userspace and reserves `PASS_TO_KERNEL` for local-delivery/control-plane cases
- it still lists the old barrier pause/drain optimization as completed even though the ordered barrier work replaced that path
- it does not capture the remaining NAT/performance work that now matters most on the userspace fabric path

## Update the doc to cover
- the current strict-userspace fabric redirect architecture
- why `apply_nat_on_fabric` still matters on the transient/cached userspace fabric path
- next concrete optimizations, including cached fabric NAT decisions, target-binding reuse, and reducing the duplicate HA validation on cache hits


---

## #438 — XDP shim drops ICMP echo replies for interface-NAT addresses [CLOSED] (closed 2026-04-04)

## Problem

Locally-originated traffic (e.g., `ping 1.1.1.1` from the firewall itself) fails because the XDP shim doesn't recognize ICMP echo replies destined for interface-NAT addresses as local-delivery packets.

## Root Cause

`is_icmp_to_interface_nat_local()` in `userspace-xdp/src/lib.rs` only checks for ICMP echo request (type 8) and ICMPv6 echo request (type 128). When the firewall pings an external host:

1. The echo request goes out via kernel routing (bypasses XDP)
2. The echo reply arrives with dst = firewall's interface-NAT IP (e.g., 172.16.50.8)
3. `is_local_destination()` returns false (interface-NAT IPs are excluded by design — transit replies need userspace NAT reversal)
4. `is_icmp_to_interface_nat_local()` returns false (only matches type 8, not type 0)
5. Packet is redirected to XSK instead of being passed to the kernel
6. The kernel never receives the reply

## Fix

Extend `is_icmp_to_interface_nat_local()` to also match ICMP echo reply (type 0) and ICMPv6 echo reply (type 129). The kernel's own conntrack matches the reply to the locally-originated ping process.

## Testing

- `ping -c 3 1.1.1.1` from primary firewall: was 100% loss, now 0%
- `ping6 -c 3 2001:4860:4860::8888`: works
- Transit traffic unaffected

---

## #440 — Slow-path TUN rp_filter reset by networkctl reload breaks local TCP/UDP [CLOSED] (closed 2026-04-04)

## Problem

Locally-originated TCP/UDP traffic from the firewall fails (e.g., DNS queries, HTTP). ICMP works after #438 fix, but all other protocols are broken.

## Root Cause

The Rust helper creates the slow-path TUN (`bpfrx-usp0`) and sets `rp_filter=0` via sysctl. However, the Go daemon later calls `networkctl reload` (when writing `.network` files), which resets all interface sysctls to defaults. The default `rp_filter=2` (loose mode) causes the kernel to drop packets arriving on the TUN whose source reverse route points at a different interface.

Flow: locally-originated TCP SYN goes out via kernel → reply arrives on WAN → XDP shim redirects to XSK → userspace helper resolves LocalDelivery → reinjects via TUN → **kernel drops because rp_filter rejects the packet**.

## Fix

Add `restoreSlowPathRPFilter()` in `pkg/networkd/networkd.go` that re-sets `rp_filter=0` on `bpfrx-usp0` after every `networkctl reload`. Silently no-ops if the TUN doesn't exist (userspace DP not active).

## Testing

- `ping -c 3 1.1.1.1`: 0% loss
- TCP to 1.1.1.1:80: HTTP response received
- `sysctl net.ipv4.conf.bpfrx-usp0.rp_filter` = 0 after deploy
- Transit traffic unaffected

---

## #442 — RST suppression shells out to nft binary instead of using netlink API [CLOSED] (closed 2026-04-04)

The Rust helper's RST suppression uses the `nftables` crate which shells out to the `nft` binary. The VMs don't have `nft` installed, so it fails with:

```
RST_SUPPRESS: failed to apply nftables rules: unable to execute "nft": No such file or directory
```

Move RST suppression to the Go daemon using `github.com/google/nftables` which communicates via the kernel netlink API directly — no external binary needed.

---

## #450 — TCP streams die after RG failover — 3/4 iperf3 streams go to 0 bps [CLOSED] (closed 2026-04-05)

## Observed

During hardened failover testing (`userspace-ha-failover-validation.sh`, 3 cycles, -P4), 3 of 4 iperf3 streams consistently die after each RG move. Only 1 stream survives and recovers.

Throughput pattern:
- Pre-failover (direct path): ~20 Gbps
- After failover (fabric): ~2.5 Gbps (1 surviving stream via fabric)
- After failback: ~5 Gbps (streams partially recover)
- By end of test: ~13 Gbps (fewer live streams)

## Suspected Cause

When RG1 moves from node0 to node1, the kernel on node0 no longer owns the interface-NAT addresses. Incoming TCP data for those connections triggers the kernel's TCP stack to send RST (no matching socket). The RST suppression nftables rules should prevent this, but there may be a race window between the RG demotion and the nftables rules being updated on the old owner.

Additionally, the new owner's kernel may generate RSTs for TCP connections it hasn't seen (the session exists in the userspace helper but not in kernel conntrack).

## Impact

Traffic survives failover (1/4 streams + reachability), but throughput drops significantly from stream death. New connections work fine.

## Artifacts

`/tmp/userspace-ha-failover-rg1-20260404-162505/`

---

## #451 — Neighbor miss spikes >20 after RG failover [CLOSED] (closed 2026-04-05)

## Observed

During failover testing, neighbor misses spike to 25-52 on the new RG owner. The test threshold is 20, causing FAIL.

## Cause

After RG takeover, the new owner needs to resolve ARP/NDP entries for next-hops it hasn't communicated with before. The userspace helper does proactive neighbor resolution, but there's a window where packets arrive before neighbors are resolved.

## Action

Either:
1. Pre-warm neighbor entries on the standby node before failover (proactive ARP for peer's next-hops)
2. Increase the test threshold to 60 (the misses are transient and don't affect traffic recovery)

---

## #452 — Rust helper single-threaded event loop blocks session installs behind main socket requests [CLOSED] (closed 2026-04-05)

## Problem

The Rust userspace-dp helper uses a single-threaded event loop that accepts connections from both the main control socket and the session socket (Phase 3). While processing a request from one socket (e.g., a status poll or snapshot publish), the other socket's requests are blocked.

This causes the session sync barrier to take 46+ seconds under load, because session installs from the HA sync receive loop queue behind main socket requests.

## Current Workaround

Manual failover barrier timeout increased to 60 seconds.

## Proposed Fix

Process session socket requests in a separate thread:

\`\`\`rust
// Spawn a thread for session socket handling
let session_state = state.clone();
thread::spawn(move || {
    for stream in session_listener.incoming() {
        handle_stream(stream, ...session_state...);
    }
});
\`\`\`

This allows session installs to proceed concurrently with main socket requests (snapshot publishes, status polls).

## Impact

Barrier ack latency would drop from 46s to ~1-5s under load, allowing the timeout to be reduced back to 30s.

---

## #456 — All 4 iperf3 streams die after RG failover (4/4 at 0 bps) [CLOSED] (closed 2026-04-05)

## Observed

During hardened failover testing (10-cycle, -P4), all 4 iperf3 streams show 0 bps after RG1 moves from node0 to node1. Previously (#450) only 3/4 died.

Cycle 1 failover passed all other checks (RG moved, target reachable, external IPv4/IPv6 reachable) but all streams show 0 throughput.

## Context

PR #455 (atomic nftables RST suppression) was merged but may not fully cover the race window. The nftables rules suppress kernel-originated RSTs from interface-NAT addresses, but during the transition the demoting node's kernel stack may still process inbound TCP segments and respond with RSTs before the XDP shim redirects all traffic.

## Relationship to #450

This is a continuation of #450. The atomic nftables batch fix reduced but did not eliminate stream death.

## Artifacts
`/tmp/userspace-ha-failover-rg1-20260404-202829/`

---

## #457 — Standby node loses userspace readiness after RG failover [CLOSED] (closed 2026-04-05)

## Observed

During hardened failover testing, after RG1 moves to node1, the standby (node0) loses userspace readiness:
```
FAIL  cycle 1 failover: standby node0 lost userspace readiness
```

The standby should remain armed with ready bindings after demoting an RG — it only lost one RG, not all of them (RG0 and RG2 are still on node0).

## Impact

If the standby loses readiness, it cannot take back the RG quickly if needed. This delays failback recovery.

## Artifacts
`/tmp/userspace-ha-failover-rg1-20260404-202829/`

---

## #458 — Session sync barrier timeout on second failover cycle (sessions_received=0) [CLOSED] (closed 2026-04-05)

## Observed

During hardened failover testing, cycle 1 (failover + failback) succeeds, but cycle 2 failover fails:
```
error: demotion peer barrier failed: timed out waiting for session sync barrier ack
seq=1 sessions_sent=278 sessions_received=0 sessions_installed=0 queue_len=0
```

\`sessions_received=0\` means the local node hasn't received ANY sessions from the peer since daemon start. Combined with queue_len=0 (the barrier was queued successfully), this suggests the sync TCP connection is alive but the peer isn't sending the barrier ack.

## Suspected Cause

After the first failover+failback cycle, the sync connection may be in a degraded state. The TCP connection exists but the peer's receive loop may have stalled or the connection was replaced but the old barrier waiter wasn't cleaned up.

## Artifacts
`/tmp/userspace-ha-failover-rg1-20260404-202829/`

---

## #462 — Phase 2 incremental neighbor updates leave stale snapshot neighbors active in userspace helper [CLOSED] (closed 2026-04-05)

## Summary
The Phase 2 lightweight FIB-bump path switched userspace neighbor refresh from full `apply_snapshot` publishes to `update_neighbors`, but the helper still prefers `forwarding.neighbors` over `dynamic_neighbors` during lookup. As a result, incremental manager neighbor updates do not actually replace or delete the manager-owned neighbors that were seeded by the last snapshot.

## Impact
- Replaced manager neighbors can keep using the old MAC from the last snapshot.
- Deleted manager neighbors can stay forwardable until the next full snapshot rebuild.
- The bug survives the intended `neighbor_replace=true` path because `apply_manager_neighbors()` only touched `dynamic_neighbors`, while `lookup_neighbor_entry()` checks `forwarding.neighbors` first.

## Evidence
- `pkg/dataplane/userspace/manager.go`: `BumpFIBGeneration()` now sends `update_neighbors` instead of rebuilding and republishing a full snapshot.
- `userspace-dp/src/main.rs`: `update_neighbors` calls `guard.afxdp.apply_manager_neighbors(replace, &resolved)`.
- `userspace-dp/src/afxdp.rs`: `apply_manager_neighbors()` only updated `dynamic_neighbors` and `manager_neighbor_keys`.
- `userspace-dp/src/afxdp/forwarding.rs`: `lookup_neighbor_entry()` returns `state.neighbors` before consulting `dynamic_neighbors`.

## Expected
Incremental manager neighbor updates should replace and delete the manager-owned entries in the live forwarding view, not just append to the auxiliary dynamic cache.


---

## #464 — RequestPeerFailover clears local manual failover before the handoff is admitted [CLOSED] (closed 2026-04-05)

## Summary
`RequestPeerFailover()` clears a local `ManualFailover` before it checks transfer readiness or successfully sends the peer-failover request.

## Why this is a bug
If the operator is failing back to a node that is currently held in `secondary-hold`, a rejected or unsent request should leave that explicit transfer-out state intact. Today the function clears `ManualFailover` early, so a failed fail-back attempt mutates local ownership state before the request is admitted.

## Reproduction
1. Put a local RG into `ManualFailover` / `secondary-hold`.
2. Call `RequestPeerFailover()` while local transfer readiness is false, or make the peer-failover send fail.
3. Observe that the call returns an error, but the local RG no longer has `ManualFailover=true`.

## Expected
Preflight rejection or peer-request send failure should not clear the existing local `ManualFailover` hold. The hold should only be released after the peer has explicitly acknowledged the transfer-out request and the local side is committing takeover.

---

## #465 — sync_test still expects barrierAckSeq to reset after total disconnect [CLOSED] (closed 2026-04-05)

## Summary
`pkg/cluster/sync_test.go` still expects `handleDisconnect()` to reset `barrierAckSeq` to `0`, but the runtime code now intentionally keeps both `barrierSeq` and `barrierAckSeq` monotonic across reconnects.

## Why this is a bug
The reconnect fix for barrier sequence reuse relies on monotonic barrier counters. The stale test now fails on `master`, so `go test ./pkg/cluster` is red even though the runtime behavior is correct.

## Expected
The disconnect test should assert that waiters are cleared while both barrier counters remain monotonic, matching the current runtime behavior and reconnect design.

---

## #466 — Session sync still bulk-primes on reconnect and active-fabric changes [CLOSED] (closed 2026-04-05)

## Summary
The sync transport still calls `doBulkSync()` on every first connection after disconnect and on every newly active connection.

## Code
- `pkg/cluster/sync.go:601-629`
- `pkg/daemon/daemon_ha.go:59-72`
- `pkg/daemon/daemon_ha.go:94-105`
- `pkg/daemon/session_sync_readiness_test.go`

## Why this is a bug
Planned failover should not depend on reconnect-triggered bulk transfer. Ordinary reconnects and preferred-fabric flips should preserve continuous sync state; bulk should only be required when a node is actually starting from scratch.

Today the reconnect path still:
1. starts bulk sync on reconnect / active-path switch,
2. clears daemon bulk-primed state on peer disconnect/connect,
3. drops sync readiness until a new bulk completes or the timeout releases it.

That reintroduces long failover admission delays and makes HA readiness depend on transport churn instead of real session-state freshness.

## Expected
Reconnect and active-fabric changes should not trigger bulk by default. Bulk should be requested explicitly only by a node that knows it started from scratch.

---

## #467 — Failed userspace demotion prep stops the peer bootstrap retry loop and never restarts it [CLOSED] (closed 2026-04-05)

## Summary
`prepareUserspaceRGDemotionWithTimeout()` stops the session-sync bulk-prime retry loop before it waits on demotion barriers, but if the barrier wait fails it returns without restarting that retry loop.

## Code
- `pkg/daemon/daemon_ha.go:146-241`
- `pkg/daemon/daemon_ha.go:1127-1174`

## Why this is a bug
If a peer is still waiting for its cold-start bootstrap and a planned demotion/failover attempt fails at the barrier step, the daemon has already advanced `syncPrimeRetryGen` to kill the retry goroutine. Nothing starts it again unless the sync transport disconnects and reconnects.

That can strand the peer in an unprimed state after a failed failover admission attempt.

## Expected
Stopping the retry loop for barrier latency is fine, but a failed demotion prep must resume the retry loop when the peer is still connected and still waiting for our bootstrap ack.

---

## #472 — Kernel crash in mlx5_core ICOSQ recovery during HA failback [OPEN]

## Observed

VM reboots during RG1 failback (node1 → node0). The kernel crashes in the mlx5_core driver's ICOSQ CQE error recovery path:

```
ICOSQ 0x9a2: cc (0x22ef) != pc (0x22fe)
WARNING: drivers/net/ethernet/mellanox/mlx5/core/en/reporter_rx.c:72
  at mlx5e_rx_reporter_err_icosq_cqe_recover
```

## Stack trace

```
mlx5e_rx_reporter_err_icosq_cqe_recover+0x222/0x240 [mlx5_core]
devlink_health_reporter_recover+0x27/0x70
devlink_health_report+0x126/0x220
mlx5e_reporter_icosq_cqe_err+0x8b/0xb0 [mlx5_core]
```

## Context

- Kernel: 6.19.8+deb14-amd64
- NIC: Mellanox ConnectX VF (mlx5_core), PCI passthrough to QEMU VM
- Trigger: RG1 failback while iperf3 -P8 is running
- The crash occurs when XDP programs are swapped during RG activation/demotion
- The ICOSQ (internal completion queue) gets out of sync during the XDP program transition

## Impact

VM reboots, all traffic dies. The surviving peer takes over but the rebooted node needs ~30s to rejoin.

## Workaround

This is a kernel/driver bug, not a bpfrx issue. Possible mitigations:
- Avoid XDP program swaps during failover (keep the same XDP program, change behavior via BPF maps)
- Pin the VF to a specific RG so it doesn't get reattached during failover
- Update to a newer kernel with mlx5 ICOSQ fixes

---

## #473 — XSK bindings map cleared after peer crash but helper reports ready [CLOSED] (closed 2026-04-05)

## Observed

After fw0 crashes (mlx5 kernel panic #472) and reboots, fw1 (which takes over all RGs) stops forwarding transit traffic. The XDP shim shows rx_xdp_redirect=0 — no packets being redirected to XSK.

## Root Cause

The `userspace_bindings` BPF map is all zeros (no registered queues), but the helper's internal status reports all queues as Registered=true, Armed=true, Ready=true. The XDP shim has nothing to redirect to, so all packets get XDP_PASS to the kernel stack, which doesn't forward transit traffic.

The discrepancy appears to occur when:
1. fw0 crashes → fw1 takes over all RGs
2. The sync connection drops and reconnects
3. During reconnection handling, the bindings BPF map gets cleared or overwritten
4. The helper's internal state isn't updated to match

## Reproduction

1. Run iperf3 through the cluster
2. Crash fw0 (or trigger mlx5 kernel panic)
3. fw1 takes over all RGs
4. Transit traffic dies on fw1 despite all RGs being primary
5. `bpftool map dump pinned /sys/fs/bpf/bpfrx/userspace_bindings` shows all zeros
6. `ethtool -S ge-7-0-1 | grep rx_xdp_redirect` shows 0

## Workaround

`systemctl restart bpfrxd` on fw1 re-registers the XSK bindings.

## Expected

XSK bindings should survive peer crash/reconnect. The helper should detect the BPF map mismatch and re-register.

---

## #475 — TCP streams never recover after failover+failback: sessions show Pkts:0 [CLOSED] (closed 2026-04-05)

## Observed

After a clean failover (RG1 node0→node1) then failback (RG1 node1→node0), all iperf3 streams go to 0 bps and never recover. The sessions exist on node0 but show Pkts: 0 on both In and Out directions — no packets match the sessions even though the iperf3 client is still trying to send.

## Key Data

- Sessions exist on node0 after failback with correct flow keys
- All sessions show Pkts: 0, Bytes: 0 (no packets matching)
- iperf3 client shows cwnd: 2-4MB, retrans: 0 (TCP thinks connection is alive)
- New connections (ping) work fine — only pre-existing TCP flows are broken
- Barrier succeeds instantly (no timeout)

## Suspected Root Cause

After failback, node0 has two sources of sessions:
1. **Local sessions** from before the failover (in flow cache with stale FIB data)
2. **Synced sessions** from node1 (with zeroed FIB data from `SetClusterSyncedSessionV4`)

The flow cache on node0 may retain stale entries from before the failover that point to the direct egress path. After failback, these entries should be invalidated by the FIB generation bump during RG activation, but if the flow cache check uses a stale FIB generation, the entries survive and packets match the stale entry instead of the refreshed session.

Alternatively, the duplicate sessions (both `10.0.61.102` and `172.16.80.8` source versions exist) may confuse the session lookup.

## Reproduction

1. Start iperf3 -P4 from LAN host
2. `request chassis cluster failover redundancy-group 1 node 1`
3. Wait 15s
4. `request chassis cluster failover redundancy-group 1 node 0`
5. All streams stay at 0 bps indefinitely

## Not the same as #456

Issue #456 was about streams dying from TCP retransmission timeout (expected). This issue is different: sessions exist with Pkts:0 — the dataplane isn't forwarding ANY packets for these flows, even though the sessions and routes are correct.

---

## #477 — remote monitor interface traffic ignores summary-mode keystrokes [CLOSED] (closed 2026-04-05)

## Problem
The remote CLI `monitor interface traffic` path renders the server stream, but it does not read local stdin in raw mode. Keys like `c`, `p`, `b`, `d`, `r`, and `q` therefore do nothing even though the screen advertises those controls.

## Why it matters
Operators cannot switch views or exit cleanly from the remote summary monitor, which breaks the full-screen workflow used to inspect live forwarding behavior.

## Expected
The remote CLI should support the same summary-mode keys as the local CLI when stdin is an interactive terminal.

---

## #478 — monitor interface traffic summary omits fab/reth aliases [CLOSED] (closed 2026-04-05)

## Problem
`monitor interface traffic` summary mode enumerates live kernel links directly, so it prints raw physical names and can omit configured aliases like `fab0` and `reth0` when those are the names operators actually use to reason about traffic flow.

## Why it matters
This makes summary monitoring harder to use during dataplane and HA debugging because the traffic view does not line up with the configured interface model.

## Expected
Summary mode should prefer configured display aliases when they resolve to the same live physical counter source, without double-counting totals.

---

## #481 — Rapid failover+failback causes barrier disconnect: session sync disconnected during barrier wait [CLOSED] (closed 2026-04-05)

## Observed

When failover and failback are issued back-to-back with no delay (immediate), the first failover's barrier fails with:
```
session sync disconnected during barrier wait seq=22
```

The immediate failback disrupts the sync connection before the first barrier can complete.

## Impact

- The failover doesn't complete cleanly (barrier fails)
- But the failback succeeds and streams recover (13.3 Gbps)
- The cluster ends up in the correct state

With 2-second delays between moves, all 6 moves succeed. The issue only occurs with truly immediate back-to-back moves.

## Root Cause

The failback triggers a new HA state transition on the peer (node1), which causes the sync connection to be torn down and reconnected. The barrier from the first failover is still waiting for an ack when the connection drops.

## Expected

Either:
1. Queue the failback until the failover's barrier completes (serialize RG moves)
2. Or cancel the failover's barrier gracefully when a conflicting failback arrives

## Reproduction

```bash
# Immediate back-to-back (no sleep)
cli -c "request chassis cluster failover redundancy-group 1 node 1"
cli -c "request chassis cluster failover redundancy-group 1 node 0"
```

## Workaround

Add a 2-second delay between failover and failback. With 2s delay, both succeed reliably across 20+ cycles.

---

## #485 — TCP stream survives failover but dies on failback — session re-resolution gap [CLOSED] (closed 2026-04-05)

## Observed

With proactive flow cache preflight (#484) and rate-limited iperf3 (-b 2G, below fabric capacity):

- **Failover (node0→node1)**: Stream SURVIVES. Continuous 1.9-2.1 Gbps through fabric. ✅
- **Failback (node1→node0)**: Stream DIES at t+25s. Goes from 1.74 Gbps → 0. ❌

## Key Progress

The proactive preflight eliminates the forwarding gap during failover. At rates below fabric capacity (3.5 Gbps), streams survive the failover seamlessly.

## Remaining Issue

The failback path (node1→node0) still has a gap where the stream dies. The session on node0 needs to re-resolve from FabricRedirect back to ForwardCandidate (direct forward), but during this transition packets are dropped.

The preflight on node1 marks RG1 as inactive and bumps the epoch. But node1 doesn't have a fabric path to node0 for the return direction — it was the WAN owner, sending directly. After preflight, node1's flow cache says "inactive for WAN" but there's no fabric redirect path FROM node1 TO node0 for the WAN-originated traffic.

## Fix Direction

The failback preflight needs to work differently:
1. On node1 (demoting): preflight marks RG1 inactive → flow cache flushes
2. On node0 (activating): needs to be ready to receive direct-path traffic immediately
3. The gap is between node1's demotion and node0's activation

This may require the activating node to pre-install sessions and neighbors BEFORE the VRRP transition completes.

---

## #490 — userspace HA activation still depends on activation-time session and BPF republish [CLOSED] (closed 2026-04-06)

## Summary
Latest `origin/master` still makes RG activation repair session state in the helper and republish `USERSPACE_SESSIONS` entries at activation time. That means failover/failback is not just moving ownership/MACs between two already-ready firewalls; it still depends on activation-time session/BPF work completing fast enough.

## Evidence
- `userspace-dp/src/afxdp/ha.rs:136-162` runs `prewarm_reverse_synced_sessions_for_owner_rgs(...)` and `republish_bpf_session_entries_for_owner_rgs(...)` during RG activation.
- `userspace-dp/src/afxdp/shared_ops.rs:43-48` documents that reverse prewarm still runs at activation to re-resolve egress using local forwarding state.
- `userspace-dp/src/afxdp/shared_ops.rs:110-120` documents that forward sessions are pushed to workers and synchronously published to `USERSPACE_SESSIONS` during activation to avoid a window where packets hit session misses.
- `userspace-dp/src/afxdp/shared_ops.rs:165-174` documents that activation-time republish is needed because entries were deleted during the previous demotion cycle.
- `userspace-dp/src/afxdp/session_glue.rs:265-319` still refreshes live reverse sessions in `ApplyHAState` on activation/demotion.
- `pkg/dataplane/userspace/manager_ha.go:381-445` double-bumps FIB generation and rebuilds/pushes a fresh snapshot on every HA transition.

## Why this matters
If failback to the original node still requires worker session refreshes, BPF republish, and a post-transition snapshot push to restore forwarding, then the standby is not actually forwarding-ready. Any lag in those activation-time repair paths can still produce the observed "goes to zero on failback" behavior.

## Expected behavior
Both firewalls should already have the sessions, redirect state, and forwarding context needed to carry traffic. Planned failover/failback should reduce to ownership/VIP/MAC movement plus a narrow authority transition, not activation-time session/BPF reconstruction.

## Scope
Audit the current activation-time republish/prewarm paths and either:
- remove them by making standby state continuously ready, or
- explicitly separate true cold-start bootstrap from steady-state HA ownership moves.


---

## #491 — failback still depends on activation-time neighbor install and ARP/NDP warmup [CLOSED] (closed 2026-04-06)

## Summary
Latest `origin/master` still performs neighbor installation and neighbor cache warmup on the activation path so the first packet after failback can forward. That contradicts the target model where both firewalls are always ready and failover/failback should mainly move MAC/VIP ownership.

## Evidence
- `pkg/daemon/daemon_ha.go:1619-1628` handles `OnPrepareActivation` by calling `preinstallSnapshotNeighbors()`, `resolveNeighborsImmediate(...)`, and `warmNeighborCache()`.
- `pkg/daemon/daemon_ha.go:2658-2703` does the same work on cluster-primary activation before forcing VRRP master.
- `pkg/daemon/daemon_ha.go:2869-2878` again pre-installs neighbors and warms the cache when the VRRP path activates an RG.
- `pkg/dataplane/userspace/manager.go:3413-3415` explicitly says `SnapshotNeighbors()` is used so failback does not drop packets during ARP resolution.

## Why this matters
The code is explicitly admitting that failback still depends on activation-time neighbor repair. If adjacency readiness is only established while the RG is activating, then a failback can still stall or drop to zero while ARP/NDP state catches up.

## Expected behavior
Neighbor resolution needed for active forwarding should already be present before ownership flips. Planned failover/failback should not need activation-time neighbor preinstall/warmup on the critical path.

## Scope
Audit whether neighbor state can be maintained continuously for standby ownership targets, and remove or demote activation-time neighbor warmup from the failover critical path.


---

## #492 — userspace demotion-prep producer pause and journal path is never actually activated [CLOSED] (closed 2026-04-06)

## Summary
The daemon contains a demotion-prep design that is supposed to pause background userspace delta producers and journal kernel session opens during the barrier window, but the control bit for that mode is never turned on in production code.

## Evidence
- `pkg/daemon/daemon.go:220-239` declares `userspaceDeltaSyncMu`, `userspaceDemotionPrepDepth`, and the demotion journal state, with comments saying demotion prep pauses producers and stages continuity-critical republish.
- `pkg/daemon/daemon_ha.go:723-725`, `795-797`, `899-900`, and `925-926` all check `userspaceDemotionPrepActive()` and skip delta draining or event handling while demotion prep is active.
- `pkg/daemon/daemon_ha.go:947-948` defines `userspaceDemotionPrepActive()` as `userspaceDemotionPrepDepth.Load() > 0`.
- Repository-wide search only finds `userspaceDemotionPrepDepth` written in `pkg/daemon/userspace_sync_test.go:667`; production code only declares it and reads it.

## Why this matters
The barrier/journal logic appears to assume a protected demotion-prep window, but that window never becomes active in production. So the system still relies on concurrent producers behaving well during demotion prep instead of actually pausing or journaling them as designed.

## Expected behavior
Either:
- the demotion-prep mode should be wired up so the barrier path actually gets the producer pause/journal guarantees its comments describe, or
- the dead mechanism should be removed and the failover design simplified around a smaller, real transition model.

## Scope
Decide whether this mechanism is necessary. If it is, wire it into the actual demotion-prep lifecycle. If it is not, remove the dead branching and simplify the failover path accordingly.


---

## #493 — default rg_active semantics enable forwarding before VIP/MAC ownership moves [CLOSED] (closed 2026-04-06)

## Summary
The default HA state machine still treats `cluster primary` as sufficient to activate forwarding before VRRP/VIP ownership moves. That is a mismatch with the desired design where both nodes are forwarding-ready but traffic ownership should still be established by the MAC/VIP move.

## Evidence
- `pkg/daemon/rg_state.go:13-18` documents the default rule as `rg_active = clusterPri || allVrrpMaster`, including the comment "Cluster Primary alone activates".
- `pkg/daemon/rg_state.go:200-207` implements that same rule.
- `pkg/daemon/daemon_ha.go:2658-2703` documents and implements activation ordering as: set `rg_active` first, then pre-install neighbors, then trigger VRRP master.
- `pkg/daemon/daemon_ha.go:2672-2679` calls `d.dp.UpdateRGActive(...)` before any VRRP ownership move.
- `pkg/daemon/daemon_ha.go:2690-2703` only forces VRRP master after `rg_active` and neighbor prep.

## Why this matters
This means the dataplane can be considered active based on cluster state before the node has actually taken VIP/MAC ownership. In a same-L2 handoff model, that creates extra state transitions and repair windows that should not exist if failover is really just moving ownership to a standby that is already ready.

## Expected behavior
Forwarding readiness and forwarding authority should not diverge this early. If the design target is "just move MACs because both FWs are always ready," then the default activation rule should not enable traffic handling on cluster-primary alone.

## Scope
Revisit whether strict VIP/MAC ownership should be the default for HA activation, or whether the current split authority model should be eliminated/reduced so planned failover is a narrower ownership transition.


---

## #499 — HA RG transitions still force full snapshot and double FIB churn [CLOSED] (closed 2026-04-06)

`origin/master` `c666d333` still does global snapshot/FIB work during every RG ownership change instead of limiting HA transitions to ownership/lease movement.

Evidence:
- [`pkg/dataplane/userspace/manager_ha.go:381`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/dataplane/userspace/manager_ha.go#L381-L442) bumps FIB generation before `update_ha_state`, then bumps again after it, then rebuilds `m.lastSnapshot` and calls `syncSnapshotLocked()`.
- [`pkg/dataplane/userspace/manager.go:2547`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/dataplane/userspace/manager.go#L2547-L2614) still publishes `apply_snapshot` when the content hash changes.
- [`userspace-dp/src/main.rs:392`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/main.rs#L392-L415) handles same-plan `apply_snapshot` by calling `refresh_runtime_snapshot()`.
- [`userspace-dp/src/afxdp.rs:1104`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp.rs#L1104-L1167) rebuilds validation, manager-neighbor keys, and forwarding state from the snapshot.

Why this is a problem:
- HA failover/failback still serializes on control-socket work that is broader than the ownership change itself.
- The transition path still looks like “HA changed, so rebuild helper runtime state again” rather than “both firewalls are already forwarding-ready; only authority moved.”
- This also keeps generation churn and snapshot traffic in the critical path for failback debugging.

Expected direction:
- `UpdateRGActive()` should be able to publish only HA ownership/lease state (and whatever minimal invalidation is truly required), not rebuild and republish a full config snapshot for every RG handoff.


---

## #500 — HA state updates still run worker-wide session refresh scans [CLOSED] (closed 2026-04-06)

The helper still does owner-RG session walks on HA state changes instead of treating shared standby state as already authoritative.

Evidence:
- [`userspace-dp/src/afxdp/ha.rs:78`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp/ha.rs#L78-L99) enqueues `ApplyHAState` work for activated and demoted RGs.
- [`userspace-dp/src/afxdp/session_glue.rs:265`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp/session_glue.rs#L265-L315) handles `ApplyHAState` by refreshing affected owner RGs and demoting matching sessions in place.
- [`userspace-dp/src/afxdp/session_glue.rs:451`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp/session_glue.rs#L451-L545) walks `owner_rg_session_keys()` and re-resolves forwarding per session.
- [`userspace-dp/src/afxdp/shared_ops.rs:311`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp/shared_ops.rs#L311-L338) already lets the packet path fall back to shared synced session state after local misses.

Why this is a problem:
- We still have an HA model where activation/demotion repairs local worker tables during the handoff.
- That keeps O(number-of-sessions-in-owner-RG) work in the transition path even though a shared standby session layer already exists.
- It also makes it harder to reason about correctness because the system has both shared authoritative state and per-worker HA repair state.

Expected direction:
- Reduce `ApplyHAState` toward minimal ownership/lease/cache invalidation and rely more directly on pre-existing shared session state for continuity.


---

## #501 — HA demotion still depends on barrier plus preflight fabric-shift path [CLOSED] (closed 2026-04-06)

`origin/master` still needs an explicit transition-time demotion-prep protocol before VRRP/cluster ownership can move.

Evidence:
- [`pkg/daemon/daemon_ha.go:1138`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/daemon/daemon_ha.go#L1138-L1215) drains pending barriers, waits for a peer barrier, then calls `preflightDemoteRG()` and sleeps 50ms.
- [`pkg/daemon/daemon_ha.go:1122`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/daemon/daemon_ha.go#L1122-L1135) describes the goal as shifting traffic to fabric before demotion.
- [`pkg/dataplane/userspace/manager_ha.go:338`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/dataplane/userspace/manager_ha.go#L338-L355) sends a dedicated `preflight_demote_rg` control request.
- [`userspace-dp/src/afxdp/ha.rs:102`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp/ha.rs#L102-L129) implements that as a lease flip plus RG epoch bump before the real ownership change.

Why this is a problem:
- The failover path still assumes the standby is not already sufficient on its own, so it has to prepare a fabric redirect window during demotion.
- That is exactly the kind of transition-time repair logic we should be removing if both firewalls are meant to be continuously ready to forward.
- The explicit sleep also means failover correctness still depends on timing rather than a simpler steady-state model.

Expected direction:
- The demoted node should not need a separate preflight fabric-shift step to keep sessions alive. Ownership movement should be enough because the peer should already have the authoritative forwarding state needed to continue the flow.


---

## #502 — No-RETH HA promotion still gates on session-sync readiness [CLOSED] (closed 2026-04-06)

The no-RETH/direct HA path still blocks promotion on cluster session-sync readiness instead of only using sync/bootstrap at true cold start.

Evidence:
- [`pkg/daemon/daemon_ha.go:2947`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/daemon/daemon_ha.go#L2947-L2961) sets `vrrpReady = d.cluster.IsSyncReady()` in no-RETH mode and reports `session sync not ready` as a takeover blocker.
- [`pkg/vrrp/manager.go:88`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/vrrp/manager.go#L88-L143) still models startup preemption suppression as a sync-hold released by sync completion or timeout.

Why this is a problem:
- The target model is that bulk/bootstrap is only for starting from scratch.
- After steady-state operation, failover should not be waiting on an abstract sync-ready flag if both sides already have continuous state and can forward immediately.
- Keeping this gate in no-RETH mode preserves a parallel, more startup-like failover path even after the RETH/VRRP side is being simplified.

Expected direction:
- Separate true cold-start bootstrap readiness from steady-state takeover readiness in no-RETH mode, the same way we have been trying to do for planned failover elsewhere.


---

## #503 — HA takeover still waits on ReadySince hold timer before promotion [CLOSED] (closed 2026-04-06)

Cluster promotion still requires the destination RG to stay ready for `TakeoverHoldTime` before ownership can move.

Evidence:
- [`pkg/cluster/cluster.go:60`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/cluster/cluster.go#L60-L78) stores `ReadySince` and gates `IsReadyForTakeover()` on elapsed hold time.
- [`pkg/cluster/cluster.go:203`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/cluster/cluster.go#L203-L205) sets the default hold to 3 seconds.
- [`pkg/cluster/cluster.go:282`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/cluster/cluster.go#L282-L345) starts a timer on the not-ready -> ready transition and only re-runs election after the hold expires.
- [`pkg/cluster/cluster.go:825`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/pkg/cluster/cluster.go#L825-L909) also uses the same hold gate for explicit peer failover requests.

Why this is a problem:
- If both firewalls are truly kept forwarding-ready at all times, the extra hold timer is no longer a safety proof; it is just an added failover/failback delay.
- This is especially visible on failback to the original owner, where the node may already have everything it needs but still cannot claim until the timer ages out.

Expected direction:
- Revisit whether HA readiness should be edge-triggered by actual forwarding state rather than a fixed 3s wall-clock hold once the steady-state always-ready model is in place.


---

## #504 — Immediate synced BPF publish still bypasses worker session admission [CLOSED] (closed 2026-04-06)

The current "always-hot standby" path still programs `USERSPACE_SESSIONS` immediately even when the worker-side session table would refuse the same synced entry.

Evidence:
- [`userspace-dp/src/afxdp/ha.rs:237`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp/ha.rs#L237-L309) publishes synced entries to shared maps and immediately writes the live BPF session map before worker processing.
- [`userspace-dp/src/afxdp/session_glue.rs:317`](https://github.com/psaab/bpfrx/blob/c666d3336a3e90b634e2b684d4aefb0467e81de5/userspace-dp/src/afxdp/session_glue.rs#L317-L327) still computes `allow_replace_local = !is_active`, meaning an active node can reject replacing a live local session.

Why this is a problem:
- XDP redirect state and worker session state can diverge.
- That keeps the hot-standby design dependent on a special-case shortcut rather than one consistent acceptance rule.
- It is also hard to reason about failback bugs when redirect programming can get ahead of actual session admission.

Expected direction:
- Hot standby should not require a separate BPF-map-only fast path that can bypass the worker's own session ownership/admission rules.


---

## #511 — Strict VIP ownership still removes blackholes on cluster-primary before VRRP ownership [CLOSED] (closed 2026-04-06)

## Summary
Current `origin/master` still removes RG blackhole routes on the cluster-primary event even when strict VIP ownership leaves `rg_active=false` until VRRP actually becomes MASTER.

That creates an inactive-but-no-blackhole window during failover/failback, which can send traffic down the wrong path before VIP/MAC ownership has actually moved.

## Evidence
- `pkg/daemon/daemon_ha.go:2573-2592` handles cluster events by calling `s.SetCluster(isPrimary)` and then unconditionally calling `removeBlackholeRoutes(ev.GroupID)` in the `isPrimary` branch.
- In strict VIP ownership mode, `rg_active` is derived from `allVrrpMaster`, not `clusterPri`, in `pkg/daemon/rg_state.go:203-209`.
- So on a cluster-primary event before VRRP MASTER, `CurrentDesired()` can still be `false` while blackholes are already removed.

## Why this matters
Blackhole routes are the inactive-node safeguard that forces return traffic toward the peer/fabric path instead of trying to forward locally. Removing them before the RG is actually active means the standby can stop behaving like a clean standby before it has VIP/MAC ownership.

That is exactly the kind of transition window that can make failback drop to zero even when both helpers are otherwise hot.

## Expected behavior
On the cluster-primary path, blackholes should only be removed once the RG's desired state is actually active on this node. In strict VIP ownership mode that means after VRRP ownership has moved, not merely after cluster election.


---

## #512 — HA status poll still triggers queue and neighbor bring-up after ownership changes [CLOSED] (closed 2026-04-06)

## Summary
Current `origin/master` still starts helper queue/bootstrap and neighbor-resolution work after HA ownership changes, which means failover is not yet a pure ownership handoff between two already-ready firewalls.

## Evidence
- `pkg/dataplane/userspace/manager_ha.go:355-359` still calls `bootstrapNAPIQueuesAsyncLocked("ha-update-active")` and `proactiveNeighborResolveAsyncLocked()` when an RG becomes active.
- `pkg/dataplane/userspace/manager.go:4139-4140` also calls `bootstrapNAPIQueuesAsyncLocked("ha-active-change")` and `proactiveNeighborResolveAsyncLocked()` from the periodic status poll whenever the helper's HA active signature changes.
- `pkg/dataplane/userspace/manager.go:4230+` documents that NAPI bootstrap exists to generate RX/NAPI activity so zero-copy XSK queues begin consuming fill-ring entries.

## Why this matters
If HA ownership changes still kick off queue bring-up and neighbor repair work, then the standby was not actually forwarding-ready before cutover. That keeps failover sensitive to asynchronous bootstrap timing instead of reducing it to VIP/MAC ownership transfer plus narrow authority updates.

## Expected behavior
Queue RX-liveness and neighbor readiness should already be maintained before takeover-ready is reported. HA transitions should not need `ha-update-active` / `ha-active-change` bootstrap work on the critical path.

## Scope
Audit the remaining helper-side bootstrap and neighbor-refresh hooks on HA transitions, and either:
- remove them entirely once readiness is continuously maintained, or
- move them out of the failover critical path and fail readiness earlier instead of starting work during ownership change.


---

## #517 — userspace failover loses synced-session origin on local hits [CLOSED] (closed 2026-04-06)

## Summary
`lookup_session_across_scopes()` drops the original `SessionOrigin` when a peer-synced session has already been materialized into the local `SessionTable`.

## Problem
The local-hit path currently rebuilds a `ResolvedSessionLookup` as if every local hit were a fresh forward-flow lookup. That is wrong for peer-synced entries that were already imported or materialized locally during HA.

On the promoted node, later session-glue paths treat those hits as `ForwardFlow` instead of preserving `SyncImport`/peer-synced origin. That changes the promotion logic and can make the active node handle an already-synced flow as if it were a new local flow.

## Why this matters
During HA failover, the promoted node should preserve the synced-session provenance of an already-present entry. Losing that provenance breaks the intended standby-hot-path behavior and was part of the failover transport-collapse debugging on the loss cluster.

## Expected behavior
Session lookup should preserve `SessionOrigin` for:
- direct local hits on peer-synced entries
- local forward-wire alias hits on peer-synced entries
- shared-map hits

The later promotion/materialization logic should use that preserved origin instead of inferring origin only from `shared_entry.is_some()`.


---

## #518 — cluster sync should not mirror reverse sessions into userspace helper [CLOSED] (closed 2026-04-06)

## Summary
`SetClusterSyncedSessionV4/V6()` mirrors explicit reverse cluster-synced entries into the userspace helper even though the helper already synthesizes the correct reverse companion from the forward synced entry.

## Problem
The cluster sync caller sends forward and reverse entries as separate updates. The Go manager currently mirrors both into the Rust helper on the cluster-synced path.

That is harmful for reverse entries. The helper's locally synthesized reverse companion uses local forwarding and HA state. The explicit reverse cluster update still carries the forward session's NAT/FIB metadata and can overwrite the helper's correct reverse companion with stale or wrong values.

## Why this matters
During HA transitions, the standby/promoted helper should derive reverse forwarding from local state, not replay a peer-derived reverse entry that was serialized for a different dataplane view.

## Expected behavior
Cluster-synced forward entries should still be mirrored into the helper, but explicit reverse entries should stop at the kernel session map and should not overwrite the helper's local reverse companion state.


---

## #520 — RG1-only failover cannot move LAN ownership on the loss userspace cluster [CLOSED] (closed 2026-04-07)

## Summary
`RG1` failover on the loss userspace HA cluster is not a full path handoff. It only moves the WAN side. The LAN gateway ownership stays on `RG2`, so `RG1`-only failover inherently leaves LAN ingress on `node0` and fabric-forwards to `node1`.

## Config evidence
In `docs/ha-cluster-userspace.conf`:
- `reth0` is assigned to `redundancy-group 1`
- `reth1` with `10.0.61.1/24` is assigned to `redundancy-group 2`

That means moving `RG1` alone cannot move the LAN VIP/MAC identity.

## Live failover evidence
From `/tmp/userspace-ha-failover-rg1-20260405-234145` during `RG1 node0 -> node1`:
- old owner LAN RX stayed active: `11,607,881`
- old owner fabric TX: `18,225,187`
- new owner fabric RX: `18,342,238`
- new owner WAN TX: `18,342,488`

During the same handoff, `fw1` still showed `RXPkts 0` on all `ge-7-0-1` bindings, proving the promoted node was not the LAN ingress point for the flow.

## Control experiment
Moving `RG2` by itself immediately added `10.0.61.1/24` to `ge-7-0-1` on `fw1` and emitted the expected GARP/NA bursts there. So LAN ownership does move cleanly, but only when `RG2` moves.

## Why this matters
As long as LAN and WAN ownership are split across separate RGs, `RG1`-only failover/failback cannot be reduced to “both firewalls are always ready, just move MACs.” It remains a split-path HA mode that depends on fabric forwarding during the transition.

## Follow-up options
- couple `RG1` and `RG2` for the loss userspace validation topology
- move the LAN-facing gateway/VIP into the same RG as the WAN side
- teach the validator to treat `RG1`-only failover as a split-path test instead of an immediate full-path move


---

## #524 — userspace HA activation no longer re-prewarms split-RG synced sessions [CLOSED] (closed 2026-04-07)

## Summary
Current `origin/master` no longer invokes the helper's activation-time split-RG session prewarm path, even though the runtime still carries that code and tests rely on it.

## Impact
When an RG becomes active on a standby node, synced sessions already exist in shared state, but their reverse companions and USERSPACE_SESSIONS redirect entries are not recomputed/restored for the newly-active local forwarding topology. In split-RG failover/failback this leaves the promoted node short of immediately-usable reverse/session redirect state and long-lived TCP streams collapse or tail badly after the ownership move.

## Evidence
- `userspace-dp/src/afxdp/shared_ops.rs` still contains `prewarm_reverse_synced_sessions_for_owner_rgs()` and `republish_bpf_session_entries_for_owner_rgs()` with comments saying they run on RG activation.
- `userspace-dp/src/afxdp/session_glue.rs` still has split-RG tests for that activation behavior.
- `userspace-dp/src/afxdp/ha.rs:update_ha_state()` on current master only bumps epochs/logs activation; it never calls either helper.
- Earlier commit `4a9d9fd2` explicitly wired RG activation to those paths, but that runtime call site is gone on current master.

## Desired fix
Restore activation-time reverse prewarm and USERSPACE_SESSIONS republish for activated RGs, without bringing back the removed worker-wide HA refresh/apply scan.


---

## #525 — userspace HA readiness overstates standby session usability [CLOSED] (closed 2026-04-07)

## Summary
Current HA readiness and sync accounting can report the standby as ready even when helper-side session mirroring failed.

## Evidence
- `pkg/dataplane/userspace/manager_ha.go:TakeoverReady()` only checks helper process/enabled state, forwarding armed/supported, mode, and XSK liveness.
- `SetClusterSyncedSessionV4()` / `SetClusterSyncedSessionV6()` install the BPF session first, then treat helper mirroring as best-effort and swallow `syncSession*Locked()` errors with `"userspace: session mirror failed"` debug logs.
- `pkg/cluster/sync.go` increments `SessionsInstalled` when those methods return `nil`, so HA barrier/readiness stats can claim sessions were installed even if the helper never accepted the mirror.

## Impact
A node can satisfy current `TakeoverReady()` and barrier accounting while still lacking immediately-usable helper SessionTable state for some synced flows. That makes "both firewalls are ready immediately" untrue in practice.

## Desired fix
Make helper session usability part of userspace HA readiness and/or stop counting mirrored sessions as installed when helper mirroring fails.


---

## #526 — split-RG userspace fabric transit is lab-limited on loss cluster [CLOSED] (closed 2026-04-07)

## Summary
On the isolated `loss` userspace cluster, split-RG throughput is strongly limited by the lab topology: cross-chassis traffic uses a `virtio` inter-firewall path because the lab does not have enough 25G NICs to dedicate native fabric links for every path.

## Context
This makes split ownership (`RG1` on one node, `RG2` on the other) a continuity/correctness test on `loss`, not a trustworthy throughput benchmark for production HA behavior.

## Evidence
Live tests on 2026-04-06 after deploying the `fix/ha-activation-prewarm` branch:

- split ownership (`RG1=node1`, `RG2=node0`): `iperf3 -c 172.16.80.200 -P 4 -t 20 -J` averaged `2.27 Gbps`, peaked at `2.95 Gbps`, tailed to `0.76 Gbps`, with `6499` retransmits and `2` zero-rate streams
- direct `RG1 node0 -> node1` failover under load no longer produced zero-rate collapse, but throughput still dropped from about `19 Gbps` to about `3.5 Gbps` immediately after the handoff and stayed there while the path remained split
- direct ownership on `node0` is much higher (`15.49 Gbps`, `0` retransmits), so the split-RG result is dominated by the lab fabric path

## Impact
Keep using split-RG on `loss` as a failover continuity and correctness test, but do not treat its throughput as a blocking dataplane performance signal by itself.

## Follow-on
The remaining production-relevant bugs are tracked separately:
- #525 userspace HA readiness overstates standby session usability
- #527 userspace direct forwarding on `node1` underperforms `node0`


---

## #527 — userspace HA direct handoff still stacks stale ownership and local manual state on loss cluster [CLOSED] (closed 2026-04-07)

## Summary
On the `loss` userspace cluster, direct HA handoff was still not behaving like an immediate ownership move between two forwarding-ready firewalls.

Two distinct control-plane bugs were involved:
- direct VIP ownership could remain on the demoted node after the cluster state already said the RG moved
- local manual failover stayed parked in `secondary-hold` even after the peer had already become primary, so later failovers/failbacks ran on top of stale operator hold state

## Evidence
Live testing on 2026-04-06 showed:
- host LAN neighbor `10.0.61.1` could keep the old MAC after ownership change until direct VIP reconciliation ran
- after `request chassis cluster failover redundancy-group 1 node 1` and `... group 2 node 1`, the demoted node still showed `secondary-hold Manual yes` instead of settling to ordinary `secondary`
- repeated failover/failback sequences without `request chassis cluster reset redundancy-group ...` were materially less reliable than the same sequence after a manual reset

## Impact
Even when both RG1 and RG2 should move together, failover was not a clean "move ownership and keep forwarding" transition. The standby/return path had to recover from stale VIP ownership and stale local manual-failover state.

## Desired fix
- reconcile direct VIP ownership from actual cluster ownership on every pass, not only edge-triggered RG activity transitions
- once a local manual transfer-out is confirmed by peer-primary state, settle the demoted node to ordinary `secondary` instead of leaving it parked in `secondary-hold`
- keep later failovers/failbacks working without manual reset commands in between

## Related
- `#525` tracks truthful userspace standby readiness
- `#526` is only the split-RG `virtio` lab limitation and is not the direct-handoff bug


---

## #532 — loss userspace HA no longer returns IPv6 TTL-expired probe responses [CLOSED] (closed 2026-04-07)

## Summary
On April 6, 2026, after deploying `origin/master` `0ac66d53` to the `loss` userspace HA cluster, the steady-state HA validator failed immediately because the deterministic IPv6 TTL-expired probe stopped returning `Time Exceeded`.

## Evidence
Steady-state validator command:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
RUNS=3 DURATION=5 PARALLEL=4 \
PREFERRED_ACTIVE_NODE=0 \
PREFERRED_ACTIVE_RGS="1 2" \
scripts/userspace-ha-validation.sh
```

Failure:

```text
ERROR: ipv6 TTL=1 probe did not return time-exceeded: PING 2607:f8b0:4005:814::200e ... 1 packets transmitted, 0 received, 100% packet loss
```

Manual confirmation from `loss:cluster-userspace-host`:

```bash
ping6 -c 1 -t 1 2607:f8b0:4005:814::200e
```

Result:

```text
1 packets transmitted, 0 received, 100% packet loss
```

This is not generic IPv6 reachability loss:
- `ping6 -c 1 2001:559:8585:80::200` still succeeds
- a paired full-RG IPv6 failover/failback `iperf3 -6 -P4` run still completed with traffic moving end-to-end

## Impact
- `scripts/userspace-ha-validation.sh` cannot complete on the deployed tree because it fails before the throughput gates
- the active userspace path is no longer producing the expected ICMPv6 TTL-expired signal for the first hop


*(truncated — 43 lines total)*


---

## #533 — loss userspace HA validator blocks because standby session-sync idle never drains [CLOSED] (closed 2026-04-07)

## Summary
On April 6, 2026, the stock userspace HA failover validator on `loss` could not get past its pre-traffic idle gate because the standby firewall kept reporting received session installs while `Session delta drained` stayed at `0`.

## Evidence
Failover validator command:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=3 CYCLE_INTERVAL=10 \
scripts/userspace-ha-failover-validation.sh --duration 210 --parallel 4
```

Failure:

```text
FAIL  pre-traffic: session sync did not become idle before timeout (source_sent=367 target_recv=387 target_delta_drained=0)
```

Standby (`fw1`) sync/accounting before the pre-traffic timeout:

```text
Session create received: 266 -> 387
Sessions installed:      387
Session delta pending:   2
Session delta generated: 2
Session delta drained:   0
```

Active (`fw0`) side over the same window:

```text
Session create sent:     246 -> 367
Session delta pending:   3 -> 4
Session delta generated: 85 -> 142
Session delta drained:   82 -> 138
```

So the active side still drains deltas, but the standby side never advances `Session delta drained` even while session installs continue and the validator waits for idle.


*(truncated — 50 lines total)*


---

## #534 — paired full-RG userspace HA handoff remains transport-unstable under load on loss [CLOSED] (closed 2026-04-07)

## Summary
On April 6, 2026, paired full-RG (`RG1` + `RG2`) failover/failback on the `loss` userspace HA cluster still did not behave like a clean ownership move between two forwarding-ready firewalls.

The manual failover commands return quickly and cluster ownership lands where it should, but long-lived TCP quality across the transition is still wildly unstable: retransmits spike, streams hit zero-rate intervals, and identical handoff sequences vary from acceptable to nearly unusable.

## Evidence
Same deployed build and topology, no failover baseline:

```text
IPv4 baseline, 15s, -P4: avg 11.57 Gbps, retransmits 23,778, zero intervals 0
```

Paired full-RG failover/failback runs:

```text
IPv4 run A, 220s: avg 11.73 Gbps, retransmits 376,266, zero_intervals_total 188, zero_streams_total 3
IPv4 run B, 55s:  avg 12.90 Gbps, retransmits 56,849,  zero_streams_total 1
IPv4 run C, 70s:  avg 1.08 Gbps,  retransmits 96,548,  zero_intervals_total 218, zero_streams_total 4
IPv6 run,   70s:  avg 11.62 Gbps, retransmits 67,739,  zero_streams_total 2
```

The same paired-RG move sequence therefore ranged from:
- mostly surviving with heavy retransmits
- to collapsing for most of the run and only recovering to about `1.7-1.9 Gbps`

The operator-visible failover path itself was not the problem in these runs:
- `request chassis cluster failover redundancy-group 1 node 1` and `... group 2 node 1` completed in about `0.17s` to `0.25s`
- the matching failback commands also returned quickly
- cluster ownership ended in the requested state each time

Additional dataplane evidence from the 220s paired run while traffic quality degraded:

```text
fw1 Direct TX no-frame fb: 18,636 -> 21,422 before failover, 23,773 after failover, 42,878 after failback
fw1 Neighbor misses after failover: 34
fw1 Session misses after failover: 310
fw0 Policy denied packets after failover: 741
fw0 Last resolution after failover: ha_inactive ... zones=wan->wan
```


*(truncated — 57 lines total)*


---

## #535 — paired data-RG handoff is still sequential and exposes a split-RG loss window on loss [CLOSED] (closed 2026-04-07)

## Summary
A paired full-data-RG failover/failback on the `loss` userspace cluster is still executed one RG at a time, so every "full" move briefly becomes a split-RG move in the middle.

On this lab, that transient split-RG state is enough to create a measurable packet-loss window on established TCP streams even when the final ownership is correct and both CLI commands return quickly.

## Evidence
Server-only capture run on April 6, 2026:
- artifacts: `/tmp/serveronly-ha-20260406-202637`
- test shape: IPv4 `iperf3 -P4 -t70`, warm for 10s, then `RG1->node1`, `RG2->node1`, later `RG1->node0`, `RG2->node0`
- metrics: `12.39 Gbps` average, `63,748` retransmits, `15` zero intervals

Command timing from that run:
- `RG1 -> node1` at `2026-04-06T20:26:50.034568665-07:00`
- `RG2 -> node1` at `2026-04-06T20:26:51.223239089-07:00`
- `RG1 -> node0` at `2026-04-06T20:27:16.394654872-07:00`
- `RG2 -> node0` at `2026-04-06T20:27:17.578615187-07:00`

Packet-level result from the same server capture:
- stream `39040` had a max gap of `1.491359s`
- stream `39050` had a max gap of `1.488681s`
- both of those gaps occurred during the first handoff window, starting after the `RG1` move and ending after the `RG2` move
- stream `39026` had a max gap of `0.436401s`
- stream `39044` had a max gap of `0.432250s`
- both of those gaps occurred during failback, after the `RG1` move and before the `RG2` move

The same 4-tuples resumed after the gap, with no RSTs:
- no `Flags [R` packets were present for the affected ports in the server capture
- the server instead saw SACK/duplicate-data behavior and the client retransmitted the same sequence ranges on the same ports after the gap

So the transport hit is not a tuple rewrite bug or a new connection. It is an in-flight packet loss window while the supposedly paired move is temporarily split.

## Impact
Even if operators intend to move both data RGs together, the current CLI/API semantics still expose the lab's split-RG transit path during the handoff itself.

That means:
- `#526` still bleeds into "full RG pair" failover testing on `loss`
- long-lived TCP quality depends on how badly that brief split window hits congestion control and retransmission timers
- run-to-run variance in `#534` is expected as long as the pair move is not atomic

## Desired fix

*(truncated — 51 lines total)*


---

## #536 — full data failover still drops packets during VIP/MAC ownership move [CLOSED] (closed 2026-04-07)

## Summary
After replacing the old sequential RG1->RG2 / RG2->RG1 handoff with a single batched data-RG transfer, full data failover/failback on `loss` no longer hits the earlier split-RG blackout window. But there is still a shorter packet-loss burst at the exact ownership move, and on a bad run one TCP stream can fall into long retransmission timeout after failback.

## Evidence
Branch under test: `fix/535-batch-data-rg-failover`

Cleaner batched run with server + WAN capture:
- artifact: `/tmp/manual-ha-data-capture-20260406-205558`
- command path:
  - `request chassis cluster failover data node 1`
  - `request chassis cluster failover data node 0`
- both commands returned:
  - `Manual failover completed for data redundancy groups [1 2] (transfer committed)`
- cluster state after run restored cleanly to `RG1=node0`, `RG2=node0`
- iperf summary:
  - `15.679 Gbps` average
  - `1,416,012` retransmits
  - `0` zero-throughput intervals
  - dips exactly at the handoff windows:
    - failover timestamp `2026-04-06T20:56:09.135820426-07:00`
    - failback timestamp `2026-04-06T20:56:34.322286721-07:00`
    - interval `10-11s`: total `5.18 Gbps`
    - interval `35-36s`: total `4.20 Gbps`

Bad batched run without capture overhead:
- artifact: `/tmp/manual-ha-data-stream-20260406-205351`
- same command path and same successful command output
- iperf summary:
  - `15.632 Gbps` average
  - `601,299` retransmits
  - `34` zero stream intervals on exactly one stream
- the bad stream starts failing immediately after failback:
  - failback timestamp `2026-04-06T20:54:27.255108811-07:00`
  - interval `35.001-36.000`: all streams dip
  - interval `36.000-37.001`: socket `9` drops to `0.0 Gbps`
  - sockets `5/7/11` recover, socket `9` stays at `0.0 Gbps` for the rest of the run
- there were no aggregate zero intervals and no new connections; this is one stream entering a long RTO tail after the move

Additional capture signal from the good run:
- no `Flags [R` packets were present in the server capture

*(truncated — 65 lines total)*


---

## #540 — session sync can stay disconnected after standby restart on loss [CLOSED] (closed 2026-04-07)

## Summary
On the loss userspace cluster, restarting the secondary can leave `show chassis cluster status` stuck at `Transfer ready: no (session sync disconnected)` on the standby even though the primary is otherwise healthy.

## Root cause
Session sync currently treats an established outbound TCP socket as connected until the kernel tears it down. When the passive node restarts, the active node can keep the stale socket long enough that it never redials promptly. Because only one side initiates the session-sync TCP connection, the standby stays disconnected.

A naive silence timeout is not enough by itself because the primary can legitimately see one-way steady-state traffic while the standby is only receiving session updates.

## Reproduction
1. Deploy current master to `loss-userspace-cluster`.
2. Restart `bpfrxd` only on `bpfrx-userspace-fw1`.
3. Observe `show chassis cluster status` on `fw1` report `Transfer ready: no (session sync disconnected)` and no new established `:4785` socket.

## Expected
After a standby restart, the primary should actively prove reverse-path liveness and reconnect session sync without leaving the standby stuck disconnected.

---

## #545 — refactor: split pkg/config/compiler.go (5878 lines) by config domain [CLOSED] (closed 2026-04-07)

**Priority: P1** — Cleanest split, each stanza compiler is independent. Split into ~8 files by Junos domain. See docs/refactoring-audit.md §3.

---

## #546 — refactor: split pkg/daemon/daemon_ha.go (4194 lines, 125 functions) [CLOSED] (closed 2026-04-07)

**Priority: P1** — Most complex file, clear domain boundaries. Split into sync callbacks, userspace session conversion, fabric IPVLAN, VIP ownership. See docs/refactoring-audit.md §7.

---

## #547 — refactor: split pkg/grpcapi/server.go (8411 lines) by RPC domain [CLOSED] (closed 2026-04-07)

**Priority: P1** — Largest file, server_sessions.go already exists as precedent. Split into ~8 files by RPC domain. See docs/refactoring-audit.md §1.

---

## #548 — refactor: split pkg/cli/cli_show.go (7887 lines) by show domain [OPEN]

**Priority: P2** — Split `pkg/cli/cli_show.go` by show domain, but do it only after `#552` extracts shared CLI dispatch/helpers.

Target files:
- `cli_show_security.go`
- `cli_show_nat.go`
- `cli_show_flow.go`
- `cli_show_routing.go`
- `cli_show_interfaces.go`
- `cli_show_system.go`
- `cli_show_cluster.go`
- `cli_show_services.go`

Keep common render/session/filter helpers in shared CLI files. First PR should be move-only with no behavior changes.


---

## #549 — refactor: split pkg/daemon/daemon.go (4506 lines) system config functions [OPEN]

**Priority: P2** — Split `pkg/daemon/daemon.go` by subsystem with a move-only first pass.

Target files:
- `daemon_system.go` for hostname, DNS, NTP, SSH, timezone, syslog, and login
- `daemon_reth.go`
- `daemon_neighbor.go`
- `daemon_flow.go`
- `daemon_nft.go`
- `daemon_cluster_bind.go` for cluster bind-address selection helpers

Keep `Run()` and top-level daemon lifecycle wiring in `daemon.go`.


---

## #550 — refactor: split pkg/dataplane/userspace/manager.go (4772 lines) [OPEN]

**Priority: P2** — Split `pkg/dataplane/userspace/manager.go` in stages.

Recommended sequence:
1. Move pure snapshot builders into `snapshot.go`
2. Move BPF/map synchronization into `maps_sync.go`
3. Move helper/process lifecycle into `process.go`
4. Extract `capability.go` only if it stays small and independent

Keep small shared types/helpers and top-level entrypoints in `manager.go`. First PR should be move-only with no dataplane behavior changes.


---

## #551 — refactor: split pkg/cluster/sync.go remaining protocol/conn/failover paths [OPEN]

**Priority: P2** — Current master already has `sync_bulk.go` and `failover_batch.go`, so this issue is now the remaining split for `pkg/cluster/sync.go`.

Target files:
- `sync_protocol.go` for message constants, header, and encode/decode helpers
- `sync_conn.go` for dial/accept/send/receive/disconnect lifecycle
- `sync_failover.go` for manual failover request/ack/commit/waiters

Leave bulk sync logic in `sync_bulk.go`. First PR should be move-only and preserve wire behavior exactly.


---

## #552 — refactor: split pkg/cli/cli.go (4874 lines) dispatch and handlers [OPEN]

**Priority: P2** — Split `pkg/cli/cli.go` by command-dispatch responsibility before touching `cli_show.go` or `cmd/cli/main.go`.

Target files:
- `cli_dispatch.go`
- `cli_request.go`
- `cli_clear.go`
- `cli_config.go`
- `cli_helpers.go`

This issue should land before `#548` and `#554` so shared parsing and completion logic is not duplicated.


---

## #553 — refactor: split pkg/config/ast.go into groups/edit/format paths [OPEN]

**Priority: P3** — `pkg/config/ast.go` currently mixes tree types/navigation, group expansion, path editing, and formatting.

Split into:
- `ast_groups.go` for apply-groups expansion
- `ast_edit.go` for set/delete/copy/rename/insert path mutation
- `ast_format.go` for hierarchical/set/JSON/XML/inheritance formatting

Keep core types, navigation helpers, and schema-completion helpers in `ast.go`. First PR should be move-only.


---

## #554 — refactor: split cmd/cli/main.go (3623 lines) [OPEN]

**Priority: P3** — Split `cmd/cli/main.go` by remote command family, but do it after `#552` and ideally after `#548` so local and remote command shapes stay aligned.

Target files:
- `show.go`
- `request.go`
- `clear.go`
- `monitor.go`
- one small shared transport/helper file as needed

Keep `main()` and top-level wiring in `main.go`.


---

## #555 — refactor: split pkg/config/parser_test.go by subsystem [OPEN]

**Priority: P3** — `pkg/config/parser_test.go` is too large for only a 2-way split.

Split by subsystem instead:
- `parser_ast_test.go`
- `parser_system_test.go`
- `parser_security_test.go`
- `parser_routing_test.go`
- `parser_services_test.go`
- `parser_cluster_test.go`

Preserve existing test names where possible to keep blame/history easy to follow.


---

## #556 — refactor: reduce userspace-dp/src/afxdp.rs root module [OPEN]

**Priority: P3** — Current master already has many `afxdp/*` submodules. The remaining work is to shrink the root `userspace-dp/src/afxdp.rs`.

Target files:
- `coordinator.rs` for the large `Coordinator` implementation
- `worker.rs` for `BindingWorker` and `worker_loop`
- `tests.rs` (or equivalent) for the in-file `#[cfg(test)] mod tests`

Keep `afxdp.rs` as module wiring, re-exports, and shared top-level constants only. First PR should be move-only with no dataplane behavior changes.


---

## #560 — native GRE local tunnel source loop spins on permanent gr-0-0-0 errors [CLOSED] (closed 2026-04-07)

## Summary
On the loss userspace cluster, the helpers can burn CPU on both firewalls even when the data RGs stay on `fw0`, because the native-GRE local tunnel source loop keeps retrying permanent `gr-0-0-0` file-descriptor failures.

## Live evidence
Before the fix, `show chassis cluster data-plane interfaces` repeatedly reported hard tunnel errors:

- `fw1`: `read_local_tunnel:File descriptor in bad state (os error 77)`
- `fw0`: `write_local_tunnel_delivery:Invalid argument (os error 22)`

At the same time, per-thread `top -H` showed the native-GRE helper thread (`bpfrx-n+`) alive on both nodes and consuming CPU.

A controlled standby delta check showed pure IPv4/IPv6 iperf itself was not the main both-node dataplane path:

- standby `fw1` delta during IPv4 iperf: `RX packets +0`, `TX packets +0`
- standby `fw1` delta during IPv6 iperf: `RX packets +1`, `TX packets +1`

So the reproducible both-firewall CPU issue is the local tunnel source loop, not ordinary HA forwarding.

## Root cause
`local_tunnel_source_loop()` treats permanent local tunnel I/O failures like retryable transient errors. For `gr-0-0-0`, that leaves the thread sleeping briefly and then retrying forever on errors that will never recover.

## Expected
A permanent local tunnel FD failure should retire the local tunnel source thread instead of spinning forever.

## Actual
The helper keeps the thread alive and keeps retrying on permanent `EINVAL` / `EBADF` / `EBADFD` / `ENODEV` / `ENXIO` class failures.


---

## #562 — userspace HA sync leaks transient missing-neighbor seed sessions across failover [CLOSED] (closed 2026-04-07)

## Summary
Transient `MissingNeighborSeed` sessions are still treated like authoritative HA session state. On `loss`, RG1 failover/failback under load can leave some long-lived flows stuck at `0` because the peer learns scratch missing-neighbor sessions instead of only real forward sessions.

## Reproduction
1. Deploy clean `origin/master` `223d9118` to `loss-userspace-cluster`.
2. Run:
   `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env IPERF_TARGET=172.16.80.200 TOTAL_CYCLES=3 CYCLE_INTERVAL=10 scripts/userspace-ha-failover-validation.sh --duration 210 --parallel 4`
3. Observe repeated failback/failover stream collapse and session miss spikes.

Artifact: `/tmp/userspace-ha-failover-rg1-20260407-064553`

## Evidence
During `cycle1` failback, only two iperf forward flows reappear on the active owner as `shared_promote`, while the dead streams repeatedly re-open on the other firewall as `missing_neighbor_seed`:
- survivors: `10.0.61.102:60088` and `10.0.61.102:60104`
- dead streams: `172.16.80.8:60116` and `172.16.80.8:60130`

Examples:
- `/tmp/userspace-ha-failover-rg1-20260407-064553/cycle1-failback-watch07-fw1-dp-interfaces.txt`
- `/tmp/userspace-ha-failover-rg1-20260407-064553/cycle1-failback-watch05-fw0-dp-interfaces.txt`

Current master emits open deltas for `MissingNeighborSeed`, accepts them in userspace session sync, and can re-export them during owner-RG export if they later resolve to a forwarding disposition. That lets a transient neighbor-repair scratch entry escape the local box and pollute HA state.

## Expected
`MissingNeighborSeed` should stay local-only scratch state for neighbor repair. It should not be sent over userspace HA sync and should not be exported as authoritative failover state.


---

## #564 — idle standby userspace XSK liveness never settles takeover-ready on a fully bound standby [CLOSED] (closed 2026-04-07)

## Summary
On the `loss` userspace HA cluster, a fully bound standby can stay stuck at `Takeover ready: no (userspace XSK liveness not proven)` even when it is otherwise healthy. The current idle-probe logic keeps extending the XSK liveness probe forever unless incidental RX arrives.

## Evidence
- validator blocked before explicit RG failover: `/tmp/userspace-ha-failover-rg1-20260407-072056`
- cluster status on standby reported `Transfer ready: yes` but `Takeover ready: no (userspace XSK liveness not proven)`
- after instrumenting the probe path, the standby was fully bound and idle, but the idle-extension loop never converged

## Expected
A fully bound standby with no active data RGs should be able to prove readiness without waiting for incidental traffic.

## Impact
Explicit failover can be blocked indefinitely on an otherwise healthy standby, and standby readiness is overstated/understated depending on incidental packet arrival.

---

## #565 — userspace HA demotion leaves worker-local owner-RG sessions active across failover cycles [CLOSED] (closed 2026-04-07)

## Summary
During repeated userspace HA failover on the `loss` cluster, shared HA state demotes old owner-RG sessions, but each worker's local `SessionTable` keeps those sessions as local entries. On later cycles the stale local entries can be re-exported as fresh deltas and collide with the preserved peer-synced state.

## Evidence
- live failover artifacts: `/tmp/userspace-ha-failover-rg1-20260407-070350`
- one stream survives the first handoff but later cycles collapse again even though shared-map demotion ran
- `SessionTable::demote_owner_rg()` exists but was not used in the worker HA path

## Expected
When HA demotes one or more owner RGs, every worker should demote matching local sessions before any later export/replay path can see them.

## Impact
Repeated failover/failback can resurrect stale owner-RG sessions and destabilize long-lived TCP flows.


---

## #568 — inactive owner still promotes translated peer-synced forward hits into local sessions [CLOSED] (closed 2026-04-07)

## Summary
Repeated RG1 failover on the `loss` userspace HA cluster can still kill one long-lived TCP stream even after standby readiness and worker demotion fixes. The remaining failure is a translated forward-session promotion bug on the inactive owner.

## Evidence
- integrated validation artifact: `/tmp/userspace-ha-failover-rg1-20260407-075136`
- stream `socket 11` / client port `38416` is the only stream with `53` zero-throughput intervals
- the old owner keeps a bogus local translated session for that same flow:
  - `In: 172.16.80.8/38416 --> 172.16.80.200/5201`
  - reverse port is `0`
  - session appears as `Session ID: 1` backup/local noise alongside the correct peer-synced `10.0.61.102/38416 -> 172.16.80.200/5201` entry
- code path: `should_keep_synced_hit_transient()` only suppresses translated synced-hit promotion when ingress is fabric, so a stray non-fabric hit on an inactive owner can still promote translated peer state into a local session

## Expected
Translated peer-synced forward hits on an inactive owner should stay transient regardless of ingress interface. Seeing a stray packet on the old owner must not create or refresh a local translated forward session.

## Impact
One stream can be poisoned across later failover cycles even though ownership moves and general readiness are otherwise healthy.


---

## #570 — inactive owner still installs new LAN->WAN sessions locally after RG failover [CLOSED] (closed 2026-04-07)

## Summary
After RG1 failover on the loss userspace cluster, the old owner can still install brand-new `ForwardFlow` LAN->WAN sessions locally and transmit directly out the WAN binding instead of fabric-redirecting those packets to the new owner.

## Evidence
- Full validator artifact: `/tmp/userspace-ha-failover-rg1-20260407-080630`
- Cycle 1 failover showed `fw0` old-owner LAN RX delta `2072142`, but only `19` packets reached the new owner over fabric and all 4 iperf streams dropped to `0.00 bits/sec`.
- `cycle1-failover-fw0-dp-interfaces.txt` shows old-owner direct forwarding continuing on `ge-0-0-2` after `rg1 active=false`.
- `cycle1-failover-fw0-dp-interfaces.txt` also shows fresh session deltas on the old owner for the 4 iperf flows with `origin=forward_flow`, meaning this is the cold session-install path, not just stale cached state.

## Root cause
In `userspace-dp/src/afxdp.rs`, the new-flow path branches on `resolution.disposition == ForwardCandidate` before applying HA enforcement and fabric redirect conversion. Session-hit paths already run through `enforce_session_ha_resolution()` plus `redirect_session_via_fabric_if_needed()`, but brand-new flows did not, so the inactive owner could still resolve a WAN path locally and install it.

## Expected behavior
On a non-fabric ingress packet whose egress owner RG is inactive locally, new flow installation must use the same HA-enforced resolution as session hits: `HAInactive` should convert to zone-encoded `FabricRedirect`, not local WAN forwarding.


---

## #572 — HA standby can remain WAN-neighbor cold after startup and drop first redirected packets on failover [CLOSED] (closed 2026-04-07)

## Summary
After the stale-owner forwarding fixes, the remaining loss on `loss` HA failover is on the promoted node: the first translated WAN packets sometimes arrive over fabric and hit `missing_neighbor` even though the standby already reports takeover-ready.

## Evidence
- Artifact: `/tmp/userspace-ha-failover-rg1-20260407-082151`
- Cycle 1 failover on `fw1` shows repeated `missing_neighbor` exceptions for translated flows:
  - `172.16.80.8:44630 -> 172.16.80.200:5201`
  - `172.16.80.8:44642 -> 172.16.80.200:5201`
- In the same run, ownership forwarding was otherwise correct:
  - old owner `lan-rx=7879032 fabric-tx=11332204`
  - new owner `fabric-rx=11384709 wan-tx=11385221`
- `Takeover ready: yes` / `Transfer ready: yes` was already true before the move.

## Root cause
The manager only runs proactive neighbor resolution during the helper's first 60 seconds of life. After that, HA standby nodes rely on passive kernel/helper neighbor learning. A long-idle standby can therefore remain forwarding-armed and XSK-ready while still lacking the WAN next-hop entry needed for the first redirected packets after failover.

## Expected
A forwarding-ready HA standby should keep directly-connected next-hop neighbor resolution warm enough that the first redirected WAN packets do not hit `missing_neighbor`.

## Direction
Keep a throttled standby-only neighbor prewarm running after startup while the node is an armed HA standby with data RGs configured. Do not reintroduce activation-time bootstrap work inside `UpdateRGActive()`.


---

## #574 — HA demotion leaves stale USERSPACE_SESSIONS redirect aliases on the old owner [CLOSED] (closed 2026-04-07)

## Summary
When a userspace HA redundancy group demotes, the worker demotion path downgrades the in-memory session origin but does not clear the corresponding `USERSPACE_SESSIONS` BPF redirect aliases on the stale owner.

## Evidence
- Full loss-cluster failover run: `/tmp/userspace-ha-failover-rg1-20260407-083617`
- In `cycle2-failover-post-fw0-dp-interfaces.txt`, the demoted node (`fw0`) still has massive WAN TX on `ge-0-0-2` after `rg1 active=false`.
- The same artifact shows stale-owner session deltas reopening the iperf tuples as `origin=shared_promote` on LAN ingress after failover.
- Helper HA state is already correct at that point: `cycle2-failover-fw0-dp-stats.txt` shows `rg1 active=false`, so this is not just a delayed HA-state update.

## Root cause
`WorkerCommand::DemoteOwnerRGS` returns demoted keys as `cancelled_keys`, but the worker loop only cancels queued flow work for those keys. It does not remove the old node's redirect entries from `USERSPACE_SESSIONS`, so XDP keeps steering packets to the stale owner even though the RG is no longer active there.

## Expected behavior
Demotion should keep the sessions in the standby table, but it must immediately remove the stale owner's BPF redirect aliases so packets stop being redirected to the old node after handoff.


---

## #575 — loss steady-state IPv6 default route falls back to discard via lo [CLOSED] (closed 2026-04-07)

## Summary
Steady-state external IPv6 on the `loss` userspace cluster is currently broken before failover even starts because the intended IPv6 static default route is not being installed, and the fallback discard route wins instead.

## Evidence
- Artifact: `/tmp/ipv6-rg1-repro-20260407-090657`
- `cluster-userspace-host` baseline `ping -6` to the Internet fails 100% before failover.
- `bpfrx-userspace-fw0` config still contains `route ::/0 { next-hop 2001:559:8585:50::1; }`.
- `show route` on `fw0` shows the active route as `::/0 *[Static/20] > to discard via lo`.
- `/etc/frr/frr.conf` on `fw0` contains:
  - `ipv6 route ::/0 2001:559:8585:50::1 5`
  - `ipv6 route ::/0 Null0 250`

## Expected
A configured IPv6 static route with a global next-hop on an on-link subnet should install as the active default route via the correct WAN interface.

## Actual
FRR is being fed a bare global IPv6 next-hop without an interface, the real route does not install on this topology, and the fallback `Null0` route becomes the active `::/0`.


---

## #576 — userspace HA demotion leaves stale BPF redirect aliases on old owner [CLOSED] (closed 2026-04-07)

## Summary
During live `loss` RG1 failover validation, the old owner could keep forwarding traffic locally after demotion because demoted sessions only cancelled queued TX and did not clear their `USERSPACE_SESSIONS` BPF redirect aliases.

## Evidence
- Artifact: `/tmp/userspace-ha-failover-rg1-20260407-085805`
- Before the fix, old-owner traffic could continue hitting local redirect aliases after ownership moved.
- After the local branch fix, the same validator showed the intended path on failover:
  - old owner LAN RX with fabric TX
  - new owner fabric RX with WAN TX
  - `PASS cycle 1 failover: all 4 streams carrying traffic`

## Expected
When a session is demoted off a node during HA handoff, any corresponding `USERSPACE_SESSIONS` BPF redirect aliases on the old owner should be removed immediately so packets cannot keep getting redirected to the local XSK path.

## Actual
Demotion cancelled pending TX but left redirect aliases behind until later churn removed them, so the old owner could continue attracting and processing traffic incorrectly after failover.


---

## #579 — userspace-ha-validation can pick standby helper as active firewall [CLOSED] (closed 2026-04-07)

## Summary
The `userspace-ha-validation.sh` active-node probe can pick a standby helper node as the "active userspace firewall" because it returns the first VM with `Enabled:true`, even if that VM reports all HA groups `active=false`.

## Evidence
- On `loss`, `fw0` reported:
  - `Enabled: true`
  - `Forwarding supported: true`
  - `HA groups: rg0 active=false; rg1 active=false; rg2 active=false`
- At the same time, cluster status clearly showed `node1` as primary for RG1 and RG2.
- The validator still chose `loss:bpfrx-userspace-fw0` as the active userspace firewall and then failed with:
  - `ERROR: unable to detect WAN test interface for loss:bpfrx-userspace-fw0`

## Expected
The validator should identify the active userspace firewall by HA ownership first, then confirm that node's userspace runtime is enabled/ready.

## Actual
The probe scans VMs in fixed order and returns the first one with userspace enabled, which can be a standby helper node.


---

## #580 — standby userspace helper can wedge with XSK bindings stuck busy after restart [CLOSED] (closed 2026-04-07)

## Summary
After the restart/deploy cycle on `loss`, standby `fw0` can get stuck with userspace forwarding armed but no XSK bindings ever becoming ready, which blocks explicit failover back to that node.

## Evidence
- `show chassis cluster status` on `fw0` stays at:
  - `Takeover ready: no (userspace XSK liveness not proven)` for RG1/RG2
- Detailed userspace stats on `fw0` show the helper wedged:
  - `Forwarding armed: true`
  - `Bound bindings: 0/18`
  - `XSK-registered bindings: 0/18`
  - `Ready queues: 0/6`
  - `Ready bindings: 0/18`
- Logs show repeated binding repair and AF_XDP bind failures:
  - `userspace: bindings watchdog repaired stale BPF map entries`
  - `xsk_socket__create_shared(...): Device or resource busy — trying copy-mode`
- Only one `bpfrx-userspace-dp` process is running, so this is not just an orphaned old helper process holding the socket.

## Impact
- `request chassis cluster failover data node 0` is rejected because RG1 is not ready on `node0`.
- HA failover/failback testing cannot proceed reliably after restart/deploy because the standby dataplane never finishes rebinding.

## Expected
A standby helper restart should fully rebind XSKs and become takeover-ready once the helper is armed.

## Actual
The standby helper remains stuck unbound and keeps repairing stale binding state instead of recovering.


---

## #582 — HA readiness can stay false even when standby helper reports all bindings ready [CLOSED] (closed 2026-04-07)

## Summary
Standby HA readiness can remain false even when the userspace helper reports all queues and bindings ready, so explicit failover is rejected despite the standby dataplane already looking forwarding-ready.

## Evidence
Before a manual re-arm on `loss:bpfrx-userspace-fw0`, `show chassis cluster data-plane statistics` reported:
- `Forwarding armed: true`
- `Bound bindings: 18/18`
- `XSK-registered bindings: 18/18`
- `Ready queues: 6/6`
- `Ready bindings: 18/18`

At the same time, `show chassis cluster status` on the same node still reported:
- `Takeover ready: no (userspace XSK liveness not proven)` for RG1 and RG2

The explicit handoff was then rejected with:
- `rpc error: code = FailedPrecondition desc = local redundancy group 1 not ready for explicit failover ... reasons=[userspace XSK liveness not proven]`

## Expected
If the userspace helper has all bindings and queues ready on the standby node, HA readiness should reflect that and allow explicit failover.

## Actual
Cluster readiness can stay stuck at `userspace XSK liveness not proven` even after the helper reports a fully ready standby dataplane.


---

## #584 — RG handoff leaves stale worker-local sessions on demoted owner [CLOSED] (closed 2026-04-07)

## Summary
During a real loss-cluster RG1 failover on the deployed integration build, the old owner keeps the existing iperf sessions in its worker SessionTables after RG1 demotion, but WAN ownership has already moved to the peer. Those stale local hits keep resolving as local WAN sessions instead of falling back to the peer-synced/shared fabric-redirect path, so old-owner LAN ingress mostly stops being forwarded across fabric.

## Evidence
- failover validator artifact: `/tmp/userspace-ha-failover-rg1-20260407-095532`
- `cycle1-failover-fw0-status.txt`: RG1 demoted on node0 while RG2 stays active
- `cycle1-failover-fw0-sessions.txt`: existing iperf sessions still present on fw0 after demotion
- dataplane counters during failover: old-owner LAN RX rises by ~1.6M packets while old-owner fabric TX only rises by 87 packets
- validator result: `4/4 streams at 0.00 bits/sec`, `session miss delta 168`, `50 zero-throughput intervals`

## Suspected root cause
The current userspace HA path demotes shared session replicas on RG handoff, but it no longer demotes or purges worker-local SessionTable entries for the demoted owner RG. Local lookups on the old owner therefore keep hitting stale forward sessions with local WAN resolution instead of re-resolving through the shared/synced split-RG fabric path.

## Expected behavior
When an owner RG demotes, any worker-local sessions owned by that RG must either:
- be demoted to peer-synced/shared state so subsequent hits resolve through fabric redirect, or
- be removed so the next packets miss locally and repopulate from the shared HA state.

This needs to preserve paired-handoff fixes while restoring split-RG continuity on loss.

---

## #586 — HA failover validator idle gate requires counters to stop changing entirely [CLOSED] (closed 2026-04-07)

## Summary
On April 7, 2026, `scripts/userspace-ha-failover-validation.sh` still aborted a real RG1 failover run on `loss` even though session sync was caught up. The standby had received all outstanding session creates and had `Session delta pending: 0`, but the script failed because it requires three cumulative counters to remain identical across consecutive samples.

## Evidence
Artifact: `/tmp/userspace-ha-failover-rg1-20260407-101026`

Failure:
```text
FAIL  pre-failover: session sync did not become idle before timeout (source_sent=60 target_recv=60 target_delta_drained=214)
```

Captured sync snapshots from that same failure:

Source `pre-failover-source-fw0-sync.txt`
- `Session create sent: 60`
- `Session delta pending: 1`

Target `pre-failover-target-fw1-sync.txt`
- `Session create received: 60`
- `Session delta pending: 0`
- `Session delta drained: 214`

At that point the source and target were caught up, and the target had no pending delta work. The validator still failed because `wait_for_session_sync_idle()` only succeeds when `source_sent`, `target_recv`, and `Session delta drained` are all unchanged across consecutive samples.

## Root cause
The current idle gate is checking for total counter stability rather than actual sync quiescence. Under background churn, the cumulative counters can continue increasing in lockstep while the standby remains fully caught up.

## Expected behavior
Treat session sync as idle when the standby is caught up, for example when:
- `source_sent == target_recv`
- standby `Session delta pending == 0`

The gate should not require cumulative counters like `Session delta drained` to stop changing entirely.

---

## #587 — RG1 failover can drop external IPv4 while promoted owner still resolves WAN neighbors late [CLOSED] (closed 2026-04-07)

## Summary
During real `loss-userspace-cluster` HA validation, `RG1 node0 -> node1` can keep IPv6 external reachability up while IPv4 external reachability drops completely on the promoted owner.

## Repro
- deploy the current combined HA validation build to `loss`
- run:
  `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env TOTAL_CYCLES=1 CYCLE_INTERVAL=10 /tmp/bpfrx-pr586/scripts/userspace-ha-failover-validation.sh --rg 1 --source-node 0 --target-node 1 --duration 60 --parallel 4`

## Evidence
Artifact: `/tmp/userspace-ha-failover-rg1-20260407-101426`

Failover result:
- `FAIL cycle1-failover: external IPv4 unreachable (1.1.1.1)`
- `PASS cycle1-failover: external IPv6 reachable (2606:4700:4700::1111)`

`external-cycle1-failover-ipv4.txt`:
- `4 packets transmitted, 0 received, 100% packet loss`

Promoted owner (`cycle1-failover-fw1-dp-stats.txt`):
- `HA groups: rg1 active=true`
- `Last resolution: missing_neighbor ingress-ifindex=4 egress-ifindex=14 next-hop=172.16.80.200 flow=172.16.80.8:55280->172.16.80.200:5201 zones=lan->wan`
- `Neighbor misses: 311`
- `Policy denied packets: 0`

Demoted owner (`cycle1-failover-fw0-dp-stats.txt`):
- `Policy denied packets: 4`
- `Neighbor misses: 147`

## Interpretation
The hard zero-stream collapse is not the current problem in this repro. The promoted owner is active, but IPv4 WAN neighbor readiness is still lagging the ownership move. The current periodic standby maintenance is not enough to guarantee the inherited WAN path is ready at the moment of RG1 promotion.


---

## #588 — Session sync can stick half-open after standby heartbeat-ack timeout [CLOSED] (closed 2026-04-07)

## Summary
Session sync can become asymmetrically disconnected: the standby closes the socket after heartbeat-ack timeout, but the primary keeps an outbound TCP session `ESTAB` with queued data and never forces a reconnect.

## Live evidence
Current `loss` cluster state:
- `fw0` reports `Transfer ready: yes`
- `fw1` reports `Transfer ready: no (session sync disconnected)`

Live TCP state:
- on `fw0`: `ESTAB 10.99.12.1:40416 -> 10.99.12.2:4785` with `Send-Q 132224`
- on `fw1`: no TCP socket on `:4785`

`fw1` journal:
- `cluster sync: heartbeat ack timeout, closing stale connection`
- `cluster sync: fabric 0 disconnected`
- `cluster sync: peer disconnected (all fabrics down)`
- then a reconnect
- then another disconnect ~240ms later

`fw0` journal at the same time shows no corresponding disconnect, only ongoing `sweep synced sessions` logs.

## Interpretation
The current heartbeat-ack timeout only tears down the receiver side. The sender side can remain stuck on a half-open socket with queued writes, so the cluster ends up split-brain on sync connectivity and `Transfer ready` becomes asymmetric.


---

## #590 — RG1 failover still incurs high session-miss burst and throughput tail collapse after reachability-preserving handoff [CLOSED] (closed 2026-04-07)

## Summary
After fixing the promoted-owner IPv4 WAN neighbor readiness gap, real `RG1 node0 -> node1` failover on `loss` no longer loses external IPv4 reachability, but it still shows a large session-miss burst and a severe tail-throughput collapse.

## Repro
Deployed branch: `fix/587-standby-session-neighbor-warmup`
Validator: patched `/tmp/bpfrx-pr586/scripts/userspace-ha-failover-validation.sh`

Command:
`BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env TOTAL_CYCLES=1 CYCLE_INTERVAL=10 /tmp/bpfrx-pr586/scripts/userspace-ha-failover-validation.sh --rg 1 --source-node 0 --target-node 1 --duration 60 --parallel 4`

Artifact: `/tmp/userspace-ha-failover-rg1-20260407-103004`

## What improved
- `cycle1-failover: external IPv4 reachable (1.1.1.1)`
- `cycle1-failover-post: external IPv4 reachable (1.1.1.1)`
- `all 4 streams carrying traffic`
- `0 zero-throughput intervals`
- real old-owner fabric forwarding to new-owner WAN path:
  - `old-owner lan-rx=6656328 fabric-tx=8738852`
  - `new-owner fabric-rx=8711162 wan-tx=8711164`

## What still fails
- `session miss delta 144 (source=67 target=77) exceeds 64`
- `sender throughput 12.212 Gbps`
- `iperf3 interval collapse detected: tail/peak ratio 0.160 below 0.350`
- `sender retransmits 13868`

## Interpretation
The promoted owner is now reachability-correct and keeps the flow alive, so the remaining bug is no longer neighbor convergence or total path loss. The next problem is transport continuity / session-hit quality during the handoff window, visible as a large session-miss burst and a strong post-transition throughput tailoff.


---

## #596 — userspace RST suppression install can fail permanently when bpfrx_dp_rst does not exist [CLOSED] (closed 2026-04-07)

On the loss userspace HA lab, old-owner TCP RST suppression can stay disabled permanently after deploy.

Root cause:
- `InstallRSTSuppression()` always queues `DelTable(inet bpfrx_dp_rst)` before `AddTable(...)`
- when the table does not already exist, the netlink flush fails with ENOENT
- the userspace manager caches the failed install attempt as if it succeeded and does not retry until the NAT address set changes

Live evidence:
- journal spam on both firewalls: `userspace: RST suppression unavailable (nftables error, non-fatal)`
- error text: `nftables flush: conn.Receive: netlink receive: no such file or directory`
- old-owner WAN-side TCP RSTs were present during RG1 failover/failback before the fix

Expected:
- first install should succeed even when the table does not already exist
- failed installs should retry on a backoff instead of staying stuck forever


---

## #597 — explicit RG failback is blocked by heartbeat peerAlive loss even when transfer path is healthy [CLOSED] (closed 2026-04-07)

On the loss userspace HA lab, after RG1 moves to node1, the explicit return transfer back to node0 can fail with `peer not alive — cannot request failover` even though cluster status still reports `Transfer ready: yes`.

Live evidence:
- `request chassis cluster failover redundancy-group 1 node 0` from either node can fail with `peer not alive — cannot request failover`
- `show chassis cluster control-plane statistics` became asymmetric after the first move:
  - node0 heartbeat packets received far below sent
  - node1 still sees node0 as alive
- node1 remained primary for RG1 while the return transfer was rejected

Root cause in code:
- `RequestPeerFailover()` and `RequestPeerFailoverBatch()` hard-require UDP heartbeat `peerAlive`
- they reject before checking whether the explicit peer-transfer RPC path is still available via session sync / commit callbacks
- in this asymmetric state, the transfer channel can still be usable even though the heartbeat bit has dropped on one node

Expected:
- explicit operator failover should rely on the explicit transfer RPC/commit path being available and local transfer readiness being true
- stale heartbeat loss should not by itself block an otherwise healthy explicit return transfer


---

## #598 — standby neighbor warmup fallback resolves reth unit subnets to the base interface instead of the unit interface [CLOSED] (closed 2026-04-07)

Standby neighbor warmup falls back to config subnet matching when kernel route lookup fails, but the fallback currently resolves the base interface name instead of the unit/VLAN interface name.

Example on loss:
- `reth0.80` should resolve to `ge-7-0-2.80`
- the fallback path resolved from the base interface instead, which can miss the actual neighbor table used by the active unit

Why this matters:
- split-RG HA warmup and standby forwarding prep depend on neighbor resolution on the correct unit interface
- resolving the base interface can silently miss the live VLAN/unit neighbor cache and leave forwarding dependent on slower later retries

Expected:
- config-subnet fallback should return the concrete Linux unit interface name for the matching subnet, not the parent/base interface


---

## #602 — tracking: refactor ordering for remaining large-file splits [OPEN]

## Purpose
Track the implementation order for the remaining large-file refactor issues so they land with clean seams and minimal review risk.

## Rules
- First PR for each issue should be move-only with no behavior changes.
- Prefer shared helper extraction before domain file splits.
- Keep top-level entrypoints in the original file unless there is a strong reason to move them.

## Recommended Order
1. [ ] #553 `pkg/config/ast.go` into groups/edit/format paths
2. [ ] #555 `pkg/config/parser_test.go` by subsystem
3. [ ] #549 `pkg/daemon/daemon.go` by subsystem
4. [ ] #551 remaining `pkg/cluster/sync.go` protocol/conn/failover split
5. [ ] #550 `pkg/dataplane/userspace/manager.go` staged split
6. [ ] #552 `pkg/cli/cli.go` shared dispatch/request/clear/config/helpers split
7. [ ] #548 `pkg/cli/cli_show.go` by show domain
8. [ ] #554 `cmd/cli/main.go` by remote command family
9. [ ] #556 reduce `userspace-dp/src/afxdp.rs` root module

## Dependencies
- `#552` should land before `#548` and ideally before `#554`.
- `#551` should only target the remaining `sync.go` responsibilities because `sync_bulk.go` and `failover_batch.go` already exist.
- `#556` should focus on shrinking the root module, not re-splitting already extracted `afxdp/*` files.

## Notes
- The earlier audit doc referenced in some issue bodies is no longer present in this checkout. The child issue scopes have been updated to match current `master`.


---

## #603 — HA status should surface mixed software versions instead of generic session sync disconnected [CLOSED] (closed 2026-04-08)

## Summary

On the `loss` userspace HA cluster, `show chassis cluster status` can report:

- `Takeover ready: yes`
- `Transfer ready: no (session sync disconnected)`

when the real cause is that the two nodes are running different bpfrx builds.

## Live reproduction

Observed on April 7, 2026 on `loss`:

- `fw0`: `bpfrx eBPF firewall userspace-forwarding-ok-20260402-bfb00432-298-ga2f53a50-dirty`
- `fw1`: `bpfrx eBPF firewall userspace-forwarding-ok-20260402-bfb00432-299-gd6a538e1`

In that mixed-build state:

- `fw0` showed `Transfer ready: no (session sync disconnected)`
- `fw1` still showed `Transfer ready: yes`

After deploying the same clean `origin/master` build to both nodes:

- both nodes reported `userspace-forwarding-ok-20260402-bfb00432-305-g51fc6996`
- session sync reconnected
- both nodes returned to `Transfer ready: yes`

So the immediate operator-visible problem was version skew, not a current-master session-sync transport regression.

## Problem

Today HA status does not make software-version mismatch visible. The operator just sees a generic session-sync disconnect reason, which makes this look like a transport/debugging problem instead of a mixed-version deployment problem.

## Desired behavior

- heartbeat should carry local software version metadata
- cluster manager should retain peer software version metadata
- `show chassis cluster status` / detailed cluster info should surface local and peer versions
- userspace transfer readiness should prefer an explicit reason like:
  - `software version mismatch local=<local> peer=<peer>`

*(truncated — 45 lines total)*


---

## #606 — session sync reconnect reapplies identical config and tears down the new sync session [CLOSED] (closed 2026-04-08)

## Summary
On the `loss` userspace HA cluster, restarting the standby on April 8, 2026 caused the primary to reconnect session sync successfully, immediately push config to the returning peer, and then lose the new sync connection again a few seconds later.

This is not software-version skew. Both nodes were on the same build: `userspace-forwarding-ok-20260402-bfb00432-310-g0e2ef566-dirty`.

## What happens
- primary reconnects session sync
- primary pushes config to the returning standby
- standby receives the config and runs a full sync apply even though the active config already matches
- that no-op apply still triggers disruptive management VRF / heartbeat restart work
- the fresh session-sync TCP connection drops shortly after, leaving sync recovery unstable

## Live evidence
From `fw0` on April 8, 2026:
- `cluster: session sync peer connected`
- `cluster: pushing config to reconnected peer`
- `cluster sync: bulk transfer complete`
- about 200ms later: `cluster sync: fabric 0 disconnected`

From `fw1` for the same reconnect:
- `cluster sync: config received from peer`
- `cluster: accepting config sync from peer`
- `cluster: restarting heartbeat after VRF rebind`
- `cluster: config sync applied successfully`

The same pattern repeated across multiple reconnects in the April 7-8, 2026 journals.

## Expected
If the standby already has the same active config, reconnect config sync should be a no-op and must not trigger a disruptive reapply.


---

## #608 — HA: rapid RG movement hits stale-old-owner redirect and helper/fabric handoff bugs [CLOSED] (closed 2026-04-08)

## Observed

Repeated RG1 movement under long-lived userspace traffic exposed several bpfrx-level handoff bugs during HA failover/failback.

These are separate from the known mlx5 kernel crash in #472.

## Repo-level problems found

1. Packets that arrive on the fabric parent NIC can be misclassified as actual fabric-ingress traffic.
   - On this platform the fabric parent ifindex is also a real dataplane ingress interface.
   - During failback, stale traffic hitting the old owner on that parent NIC can skip standby fabric redirect and get dropped as `ha_inactive` instead of being bounced to the active peer.

2. Helper activation can leave control forwarding disabled for one extra cycle even after the activation has already been acked.
   - That produces a transient ctrl-path blackout during RG activation/failback.

3. Transient fabric neighbor lookup misses can clear an already-populated `fabric_fwd` entry.
   - Under rapid RG movement this can temporarily flap readiness even though the last good fabric forwarding info is still usable.

## Evidence

- Live standby dataplane exceptions on the old owner previously showed `ha_inactive` for active RG1 flows arriving on `ge-*-0-0` / the fabric parent ifindex.
- The helper/control-path blackout was reproduced in unit tests around `UpdateRGActive(active=true)` and ctrl map cleanup.
- Fabric forwarding flaps were reproduced when `LinkByName` / neighbor resolution briefly missed but a cached `fabric_fwd` entry already existed.

## Expected

Rapid RG movement should keep the old owner redirecting stale traffic to the active peer, should not unnecessarily drop ctrl forwarding after activation is already acked, and should retain the last valid fabric forwarding state across transient neighbor lookup misses.

## Scope

This issue tracks the bpfrx fixes for those HA handoff bugs. The separate remaining throughput-collapse symptom is tracked independently, and the mlx5 VM panic remains #472.


---

## #609 — IPv6 RG1 failover only recovers ~3.9 Gbps of -P12 traffic before node crash [OPEN]

## Observed

On a clean `loss` userspace HA deployment, long-lived IPv6 traffic does not recover cleanly on the first RG1 failover even when both nodes are healthy and session sync is up before the move.

## Repro

1. Start from a healthy cluster where both nodes report `Takeover ready: yes` and `Transfer ready: yes`.
2. Run:

```bash
iperf3 -c 2001:559:8585:80::200 -t 45 -P 12
```

3. Move RG1 from `node0` to `node1` at 10s.

In the captured repro (`/tmp/rg1-failover-Mz4t.log`):
- `0-10s`: stable around `23.1 Gbits/sec`
- `10-11s`: `6.71 Gbits/sec`
- `11-20s`: only `3.81-3.94 Gbits/sec`
- `21s+`: traffic then falls to zero because the old owner later hits the known mlx5 crash from #472

## Notes

- In the current debug branch, the new owner no longer shows the old `ha_inactive` standby-drop symptom for these flows.
- So this issue tracks the remaining repo-level failover recovery gap that leaves only a subset of the `-P12` streams alive after the first RG move.
- The later VM crash is already tracked separately in #472.

## Expected

After RG1 moves to `node1`, all long-lived streams should recover to normal throughput instead of degrading to a low partial-recovery plateau.


---

## #611 — HA: old primary reclaims RG on transient peer-heartbeat timeout immediately after committed failover [OPEN]

## Summary
After the same committed RG1 manual failover on clean `origin/master` (`ac29c8ff`), the old primary (`fw0`) times out the peer heartbeat about 7 seconds later and unilaterally promotes RG1 back to itself.

## Repro
- Clean master on both nodes: `userspace-forwarding-ok-20260402-bfb00432-316-gac29c8ff`
- Start reverse traffic:
  `iperf3 -c 172.16.80.200 -P 12 -t 12 -R`
- Trigger failover:
  `request chassis cluster failover redundancy-group 1 node 1`

## Evidence
`fw0` journal during the same repro:
- `cluster sync: remote failover request received` rg=1 req_id=1
- `cluster sync: barrier ack received` seq=1 ...
- `cluster: manual failover` rg=1
- `cluster sync: remote failover commit received` rg=1 req_id=1
- `userspace: RG state updated (helper stays in control)` rg=1 active=false
- then ~7 seconds later:
- `cluster: peer heartbeat timeout, marking peer lost`
- `cluster: primary transition` rg=1
- `userspace: RG state updated (helper stays in control)` rg=1 active=true

At that point `show chassis cluster status` again reports `node0` primary for RG1 even though the manual transfer had already committed successfully.

## Impact
The old primary can reclaim the RG during a transient post-transfer heartbeat gap, undoing a successful failover and leaving the dataplane in a split/oscillating state. This lines up with reverse-path flows degrading and then never recovering.


---

## #612 — HA: new primary self-demotes after committed manual failover when post-commit session barrier ack arrives late [OPEN]

## Summary
A committed RG1 manual failover is not sticky on clean `origin/master` (`ac29c8ff`) during reverse-path traffic. The new primary (`fw1`) becomes primary, activates RG1, sends GARP/NA re-announces, then about 9 seconds later demotes itself back to backup because a post-commit demotion barrier waits only 5 seconds for a session-sync ack.

## Repro
- Clean master on both nodes: `userspace-forwarding-ok-20260402-bfb00432-316-gac29c8ff`
- Baseline reverse traffic is healthy:
  `iperf3 -c 172.16.80.200 -P 12 -t 5 -R` -> about `17-18 Gbps`
- Repro:
  `iperf3 -c 172.16.80.200 -P 12 -t 12 -R`
  while issuing
  `request chassis cluster failover redundancy-group 1 node 1`

## Evidence
`fw1` journal:
- `cluster sync: failover ack received` rg=1
- `cluster: primary transition` rg=1
- `userspace: RG state updated (helper stays in control)` rg=1 active=true
- `direct-mode re-announce scheduled` rg=1 reason=cluster-primary bursts=6
- then later:
- `cluster sync: queueing barrier` seq=1 sessions_sent=11 ...
- `reconcile: retrying rg_active apply` rg=1 active=false
- `userspace: RG state updated (helper stays in control)` rg=1 active=false
- `userspace: prepare rg demotion failed` err=`demotion peer barrier failed: timed out waiting for session sync barrier ack ...`
- only after that: `cluster sync: barrier ack received`

The post-commit barrier ack arrives after the demotion path has already reverted the new primary.

## Impact
Manual failover can succeed at the protocol level and still be reverted locally by the new primary under load. Reverse-path TCP collapses from about `20 Gbps` to `4 Gbps` and never recovers because RG ownership oscillates back out from under the dataplane.


---

