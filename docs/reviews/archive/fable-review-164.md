# fable-review-164 — coverage campaign (core firewall behavior focus)

- **Base commit reviewed:** `20480f5175f82b8e80ea39a2c244af3d912f6e73` (master; `git pull --rebase` was blocked by a pre-existing unmerged `_Log.md` in the working tree, so the review ran against the committed HEAD as-is — no repo files were modified).
- **Output path:** `/tmp/fable-review-164.md`
- **Whoami:** fable. Highest existing campaign number across codex/agy/fable was 163; fable already owned 161 and 163, so this run uses the next number, 164.
- **Method:** 11 parallel module reviewers (READ-ONLY), each bound to a shared evidence bar (quoted snippets, runtime traces, fix directions, confidence tiers) and a 256-title dedup index built from all prior `/tmp/{codex,agy,fable}-review-*.md` plus `git log --oneline -250 --no-merges` and `docs/issues/`. The two High findings and the API/config resource-limit Mediums were independently re-verified by the lead against source before inclusion.

## Duplicate suppression summary

Dedup index: 256 unique prior finding titles extracted from `/tmp/codex-review-*.md` (001–163), `/tmp/agy-review-*.md` (138–152), `/tmp/fable-review-{161,163}.md`, cross-checked against recent merges. Explicitly **not** re-reported (already fixed or previously filed):

- Policy display/observability surface (zone-detail summaries, REST/gRPC `policy_id`, match-policies wording, host-inbound display, scheduler-state display) — exhaustively mined by codex-152…163 and fable-163.
- Recently landed fixes suppressed: #4092 (WG TAI64N), #4074 (pool SNAT ICMP id), #4069 (RG prewarm dedup), #4061 (VRRP interval adoption), #4054 (export off-lock), #4051/#4056 (secret redaction/perms), #4041 (direct-TX single-recycle), #4036 (control-socket deadline), #4034/#4031 (config-sync/fabric-monitor), #4027 (interface-range), #4024 (flowless MissingNeighbor policy), #4020 (cluster lock), #4008 (protocol-0 fan-out), #4000 (commit-confirmed), #3996/#3984/#3982/#3979/#3975 (config plumbing), #3962 (screen snapshot order), #3958/#3956/#3954/#3950/#3948/#3947/#3944/#3942/#3939 (assorted), #3527/#3315 (SYN sub-thresholds), #3292/#3019 (junos-host userspace wiring), #3023 (cross-family exclusion), #2419 (bracketed-list collapse).
- Every finding below carries a per-item dedup note naming the closest prior item and why it is distinct.

## Module checklist

| # | Module | Reviewer | Result |
|---|--------|----------|--------|
| 1 | `userspace-dp/src/policy.rs` + poll_descriptor verdict paths + forwarding | rev-policy-rs | 1 Low (test gap); core clean |
| 2 | `pkg/config` policy/application/scheduler compile + `pkg/policymatch` + userspace snapshot projection | rev-policy-go | 3 Low; core clean |
| 3 | security zones + host-inbound enforcement (Go SSOT, nft mirror, Rust host_inbound.rs) | rev-hostinbound | **1 High** + 1 Low |
| 4 | NAT compile + `userspace-dp` NAT execution (SNAT/DNAT/static/NAT64) | rev-nat | 1 Medium + 1 Low |
| 5 | `userspace-dp/src/session` + `pkg/conntrack` + HA session sync + flow cache | rev-session | 1 Medium + 1 Low |
| 6 | screens/IDS compile + `userspace-dp/src/screen` + SYN cookies | rev-screens | 1 Medium + 2 Low |
| 7 | parser/lexer/`pkg/configstore` | rev-config | **1 High** + 1 Medium + 1 Low |
| 8 | `pkg/vrrp` + `pkg/cluster` + IPsec SA sync | rev-ha | 1 Medium + 2 Low |
| 9 | `pkg/frr` + `pkg/routing` + `pkg/networkd` + `pkg/dhcp*` | rev-routing | 1 Medium + 1 Low |
| 10 | `userspace-dp/src/afxdp` core (UMEM/rings/parsing/forwarding, HPC invariants) | rev-afxdp | 1 Low (parity); clean |
| 11 | `pkg/grpcapi` + `pkg/api` + `pkg/logging`/`flowexport`/`feeds`/`eventengine`/`rpm`/snmp | rev-api | 2 Medium + 2 Low |

**Tally: 22 non-duplicate findings — 2 High, 8 Medium, 12 Low.**

## Module-by-module inspection log

1. **Rust policy engine (rev-policy-rs):** Read the snapshot-integrity taxonomy, `PolicyRuleCounter` relaxed-atomic clear-epoch design (#3451/#3448), the per-worker coalescer (#3073), `CompiledApplications`, `AppCatalog::lookup_directional`, tier precedence (exact → from-any/to-any → both-any → global), and the NAT64 (V6 src, V4 dst) evaluation arm. Every enforcement path traced fails closed. Negative result on verdict/counter/asymmetry axes; one NAT64-exclusion test gap.
2. **Go policy compiler (rev-policy-go):** Read `compilePolicy`, zone-local address-book inheritance, `any-ipv4/any-ipv6` normalization order, scheduler compile/eval (#3849/#3988), `pkg/policymatch` parity, and the userspace snapshot projection (`#3261`/`#2124` fail-closed sentinels). No High/Medium enforcement bug; three Low robustness/parity items.
3. **Zones + host-inbound (rev-hostinbound):** Read the token→port classifier across all three surfaces (Go SSOT, nft mirror, Rust), family scoping, dynamic-port sets, per-interface override union, zone screens. Port classification is byte-consistent and test-pinned — **but** the direct host-bound path never reaches the junos-host gate (H-1).
4. **NAT (rev-nat):** Read the port allocator (#3011/#3047), incremental checksums (RFC 1624), `nat64.rs`, and both SNAT/DNAT compile→snapshot paths. DNAT/static tier by scope specificity; SNAT does not (M-1). Execution otherwise clean.
5. **Session lifecycle (rev-session):** Read all nine `session/` files, the timer wheel, per-IP limits, seeded hash indices (#2364), `pkg/conntrack` GC, HA sync codecs (#4069/#4054), and flow-cache admission (#2363). Hash-flood/eviction/arithmetic all sound; the OPENING→ESTABLISHED promotion condition is too weak (M-1).
6. **Screens/IDS (rev-screens):** Read the ids-option compile loop, `SynFloodConfig`, all seven screen runtime modules, SYN-cookie codec + validated cache, CMS sub-threshold sketch, and caller wiring. Crypto and counters sound; fabric-redirected traffic is re-screened on the owner node (M-1).
7. **Parser/configstore (rev-config):** Read lexer, recursive-descent parser, AST clone/format, `SchemaValidate`, and the configstore DB/journal/rollback. DB durability and journal self-heal are solid; the lexer/parser have unbounded recursion (H-1) and swallow unterminated comments (M-1).
8. **HA (rev-ha):** Read `pkg/vrrp` packet marshal/parse + state machine, `pkg/cluster` heartbeat/sync/election/weight arithmetic, IPsec SA codec. Wire decoders and weight math are hardened; the config-sync receiver advances its generation high-water mark before apply (M-1).
9. **Routing/interfaces (rev-routing):** Read `pkg/routing` rules/next-table/GRE-keepalive, `pkg/frr` render + injection sanitizers, `pkg/networkd`, and the DHCP client/relay/Kea paths. FRR injection surface and VLAN-on-RETH handling are hardened; DHCP client installs a server-supplied mask without a lower bound (M-1).
10. **AF_XDP core (rev-afxdp):** Read packet parsing, IPv6 ext-header walkers, the Vyukov MPSC redirect inbox, UMEM/ring/recycle, VLAN in-place rewrite, forwarding/neighbor/PTB generators. Ring wrap, atomic ordering, false-sharing, ext-header bounds all correct. Only a QinQ dual-tag parity gap (Low).
11. **APIs/observability (rev-api):** Read `pkg/feeds` (hardened #3934), `pkg/logging` TLS, `pkg/flowexport` v9, `pkg/eventengine`/`pkg/rpm` (no shell), `pkg/grpcapi`, `pkg/api`. gRPC inherits the 4 MiB recv cap; REST management server has no timeouts (M-1) and no body cap (M-2).

---

# High confidence findings

### H-1. `to-zone junos-host` deny policy is not enforced for direct host-bound traffic — the XDP shim shunts local-destined packets to the kernel, which has no junos-host gate
- Severity: High
- Confidence: High
- Evidence: `userspace-xdp/src/lib.rs:611` — on a session miss, any packet to a firewall-local IP is passed to the kernel, never to the userspace XSK path where the gate lives:
```rust
if is_local_destination(&parsed) {
    record_trace(... USERSPACE_TRACE_STAGE_LOCAL_DESTINATION ...);
    incr_fallback_stat(USERSPACE_FALLBACK_REASON_PASS_TO_KERNEL);
    return Ok(cpumap_or_pass(ctrl));      // → KERNEL, not XSK
}
```
`is_local_destination` (`lib.rs:1347`) is true for every interface IP/VIP in `USERSPACE_LOCAL_V4`, populated unconditionally from all configured + live kernel addresses (`pkg/dataplane/userspace/maps_sync.go`), never filtered by policy. The two `junos_host_local_policy` call sites are both gated on `ForwardingDisposition::LocalDelivery` inside `poll_descriptor/mod.rs` (the XSK path). Verified this run: `grep -rin "junos.host" pkg/daemon/ bpf/` returns **nothing** — the kernel path enforces only nft host-inbound admission + the lo0 filter. Interface-NAT-to-self returns `false` from `is_local_destination` (`lib.rs:1350`) and does reach the gate, cleanly delimiting the gap to plain-interface-IP destinations.
- Trace:
  1. Config: zone `trust` on `ge-0-0-1.0` (10.0.1.10) with `host-inbound-traffic system-services ssh`, plus `security policies from-zone trust to-zone junos-host policy block { match source-address 10.0.1.200; then deny; }`.
  2. Host 10.0.1.200 opens SSH to 10.0.1.10:22; first packet ingresses ge-0-0-1 on native AF_XDP.
  3. Shim: session miss → `is_local_destination(10.0.1.10)` = true → `cpumap_or_pass` → delivered to the **kernel**. No userspace session created.
  4. Kernel `xpf_hostinbound`: `ip daddr 10.0.1.10 tcp dport 22 accept`; `xpf_lo0`: no filter → accept. Packet reaches sshd.
  5. The `to-zone junos-host then deny` policy is never consulted — it exists only in userspace-dp, which never saw the packet. Hit counters stay zero; on vSRX the session is blocked.
- Why it matters: A configured DENY security policy on the management plane is silently unenforced for the primary host-bound path. Operators using the standard vSRX layered model (coarse `host-inbound-traffic` port gate + fine `to-zone junos-host` source/application restriction) get a false sense of security — SSH/NETCONF/SNMP the junos-host policy intends to restrict by source reaches the RE unfiltered.
- Fix direction: Either (a) withhold interface daddrs that are subject to any `to-zone junos-host` policy from `USERSPACE_LOCAL_V4` so they redirect to the XSK and traverse `LocalDelivery`, or evaluate the policy in the shim; or (b) mirror junos-host zone-pair policies into the kernel nft `xpf_hostinbound`/`xpf_lo0` chains (source/app-scoped accept/drop). If neither is intended, reject at strict commit any `to-zone junos-host` policy stricter than the host-inbound gate and document the limitation rather than presenting it as enforced.
- Labels: `bug`, `security`, `enforcement-gap`, `host-inbound`, `vsrx-parity`
- Dedup note: Distinct from closed #3019 (wired junos-host into the userspace `LocalDelivery` path) — this is the *incompleteness* of that fix: the direct-to-interface path never reaches `LocalDelivery` because the shim shunts it to the kernel first. Not #3292 (flowless-arm bypass). No dedup title touches the kernel-shunt bypass; the M05/M07/M10 junos-host items are all display/match-policies wording.

### H-2. Unbounded lexer/parser recursion crashes the daemon on a sub-4 MiB config `load` or HA config-sync (unrecoverable stack overflow)
- Severity: High
- Confidence: High (empirically reproduced by the reviewer)
- Evidence: `pkg/config/lexer.go:103-109` — the tokenizer recurses one stack frame per bracket:
```go
case '[':
    l.advance()
    return l.Next()   // self-recursion, one frame per '['
case ']':
    l.advance()
    return l.Next()
```
`pkg/config/parser.go:180` — recursive descent (`parseStatement`→`parseStatements`→`parseStatement`) with no depth counter; verified this run that `grep -ni "depth\|recursion\|nesting"` over `parser.go`/`lexer.go` returns nothing. Reachable from three unbounded parse entry points: `Store.LoadOverride`/`LoadMerge` and `Store.SyncApply` (the HA peer-sync ingress). gRPC `Load` and REST `POST config` forward straight there; verified this run that **no** `MaxRecvMsgSize` override exists in `pkg/grpcapi` (grpc-go default 4 MiB) and **no** `http.MaxBytesReader` guards the REST body.
- Trace:
  1. Send a `Load`/config-sync payload of ~4,000,000 `[` chars (≈3.81 MiB, under the 4 MiB gRPC default; REST is entirely unbounded).
  2. `NewParser(content).Parse()` → `Lexer.Next()` recurses once per `[`.
  3. Goroutine stack grows past Go's 1 GiB `maxstacksize` → `fatal error: goroutine stack exceeds 1000000000-byte limit`.
  4. This is a `runtime.throw`, not a `panic`; no `recover()` exists in `pkg/config`/`pkg/configstore`, so `xpfd` aborts. Nested `a{a{a{…}` braces trigger the identical crash via `parseStatement`. Reviewer reproduced: 3M brackets survived; 4M brackets (3.81 MiB) → `fatal error: stack overflow`.
- Why it matters: One sub-4 MiB request to the localhost gRPC/REST API — or one hostile/corrupt config from an HA peer over the fabric sync channel — hard-crashes the firewall control plane with no recovery. On a cluster the same content in `SyncApply` can take down the standby.
- Fix direction: (a) make `[`/`]` iterative (loop, not `return l.Next()`); (b) add a nesting-depth counter in `parseStatement`/`parseStatements` (cap ~256) emitting a `ParseError` past the limit; (c) enforce an input-size ceiling before `NewParser` in the three load paths, plus `grpc.MaxRecvMsgSize` and `http.MaxBytesReader`.
- Labels: `bug`, `security`, `dos`, `ha`
- Dedup note: No prior item touches config parser/lexer recursion; issue-history "recursion/stack overflow" entries are the dataplane next-table path (#3768) and syslog re-entrancy — different subsystems.

---

# Medium confidence findings

### M-1. Forward-only ACK promotes a half-open TCP session to ESTABLISHED without a completed handshake, defeating the #3152 half-open reaping
- Severity: Medium
- Confidence: Medium
- Evidence: `userspace-dp/src/session/lookup.rs:109-111`:
```rust
// #3152: promote OPENING -> ESTABLISHED on the first ACK-bearing
// segment after the opening SYN.
if matches!(key.protocol, PROTO_TCP) && has_ack(tcp_flags) {
    entry.established = true;
}
```
`has_ack` tests only the ACK bit; nothing requires a reverse SYN-ACK was ever observed. Once `established`, `session_timeout_ns` (`mod.rs:1774`) returns `tcp_established_ns` (default 300 s) instead of the 20 s `tcp_opening_ns`. The update path (`mod.rs:1125`) is identical.
- Trace:
  1. Attacker sends a bare SYN to a permitted service → OPENING forward entry, 20 s expiry.
  2. Attacker sends a bare ACK on the same 5-tuple → session-hit slow path → snippet promotes `established=true`, expiry recomputed to 300 s.
  3. Server SYN-ACK/RST only touches the *reverse* companion entry; the forward entry is pinned 300 s. Per-IP `session_limit_inc` charges the phantom for the full window.
  4. Repeating with fresh 5-tuples fills `max_sessions` (131072) with 300 s phantoms at a 2-packet cost — 15× the occupancy leverage #3152 was written to bound to 20 s.
- Why it matters: #3152 exists precisely to stop a bare-SYN flood from pinning half-open entries for the established window. Promoting on any forward ACK-bearing segment gives an attacker *better* exhaustion leverage than the bare SYN the mitigation targets, when the SYN-cookie screen is not configured (this is the defense-in-depth layer).
- Fix direction: Gate OPENING→ESTABLISHED on evidence of a bidirectional handshake — track a per-session `saw_reverse_synack` and only promote the forward entry once the reverse SYN-ACK has been observed; or cap `expires_after_ns` for any TCP session that has never seen a reverse-direction packet. Add a `tests.rs` case asserting SYN-then-forward-ACK (no reverse SYN-ACK) does NOT reach the 300 s window.
- Labels: `security`, `resource-exhaustion`, `correctness`, `vsrx-parity`, `test-coverage`
- Dedup note: No prior title touches established-state promotion or the #3152 ACK path; #3152/#3527/#3315 items concern the opening-window timeout *value*, not the promotion condition.

### M-2. Config-sync generation high-water mark advances before the config is applied, silently stranding a diverged standby
- Severity: Medium
- Confidence: High
- Evidence: `pkg/cluster/sync_conn.go` — `admitConfigGen` stores the new generation, then `configApplyLoop` invokes the callback with no error path:
```go
func (s *SessionSync) admitConfigGen(gen uint64) bool {
    last := s.lastAppliedConfigGen.Load()
    if gen != 0 && last != 0 && gen <= last { return false }
    if gen != 0 && gen > last { s.lastAppliedConfigGen.Store(gen) } // advanced HERE
    return true
}
...
if !s.admitConfigGen(item.gen) { s.stats.ConfigsStaleIgnored.Add(1); continue }
if s.OnConfigReceived != nil { s.OnConfigReceived(item.text) }      // no error checked
```
`pkg/daemon/daemon_ha_sync.go:347` `handleConfigSync` returns WITHOUT applying on a transient RG0-primary belief or a `SyncApply` compile/promote failure; `SyncApply` (`daemon_apply.go:299`) promotes the store only on success.
- Trace:
  1. Primary commits C1 (gen N+1), pushes to standby.
  2. Standby `admitConfigGen(N+1)` stores `lastAppliedConfigGen=N+1`, returns true.
  3. `OnConfigReceived(C1)` → `handleConfigSync` returns early (dual-active window, or C1 rejected by a mixed-build ISSU syntax/compile error) → store stays on C0.
  4. Standby now has `lastAppliedConfigGen=N+1` but active config C0 — diverged, with no config-hash reconciliation to detect it.
  5. Primary never re-sends N+1; only a *new* commit (higher gen) or a fabric disconnect heals it. On failover the standby serves stale C0.
- Why it matters: Silent, undetected config divergence — the failure class #4034 fixed on the *sender*, reintroduced on the *receiver* by the #3931 ordering guard. A failover then enforces stale policy/routing.
- Fix direction: Advance `lastAppliedConfigGen` only after a successful apply: make `OnConfigReceived` return an error/bool, store the gen only on success, and count a distinct `ConfigsApplyFailed` alarm on failure so the next re-push of that gen is still admitted.
- Labels: `correctness`, `ha`, `config-sync`, `divergence`
- Dedup note: Distinct from #4034 (primary-side push-on-non-fatal-apply) and #3931 (the ordering feature); this is the receiver-side advance-before-apply gap.

### M-3. Source-NAT rule-set precedence is config-order first-match, not Junos most-specific-scope-wins (interface > zone > routing-instance)
- Severity: Medium
- Confidence: High (code behavior) / Medium (exact vSRX ordering)
- Evidence:
```rust
// nat/source.rs:812 — first match in slice order wins
for rule in rules { if !rule.matches(...) { continue; } ... return SourceNatLookup::Matched(...); }
// nat/source.rs:308 scope_matches — empty scope fields are WILDCARDS, present ones AND-ed
```
```go
// pkg/dataplane/userspace/nat.go:141 — emit rule-sets in config order, no precedence sort
for _, rs := range cfg.Security.NAT.Source { ... out = append(out, ...) }
```
DNAT/static DO tier by specificity (`destination.rs:561`); SNAT is pure first-match, scope-blind.
- Trace:
  1. RS-ZONE (from zone trust → pool P) defined textually before RS-IF (from interface ge-0-0-1 → source-nat off).
  2. Packet ingresses ge-0-0-1 in zone trust → both scopes match (unset side wildcarded).
  3. Matcher iterates emission order, hits RS-ZONE first → applies pool P.
  4. vSRX picks RS-IF (interface more specific) → source-nat off. Result: wrong source address / bypassed exemption.
- Why it matters: A config correct on vSRX yields a different SNAT decision here purely from text ordering, including bypass of a more-specific `then source-nat off`.
- Fix direction: Stamp a scope-specificity tier per SourceNatRule (interface=0, zone=1, routing-instance=2, wildcard=3); stable-sort the emitted SNAT snapshot by (tier, config-order) in `buildSourceNATSnapshots`, or have the Rust matcher pick the most-specific match. Mirror `destination.rs` tiering. Land with the L-9 test.
- Labels: `correctness`, `vsrx-parity`, `nat-source`
- Dedup note: Not covered by any prior title. Closest is #3096 (`ab9c6580e`), which made a scoped rule match only within its scope; it did not order overlapping rule-sets by specificity. Distinct precedence axis.

### M-4. Rate-based flood screens re-run on the owner node for fabric-redirected (already-screened) traffic
- Severity: Medium
- Confidence: Medium
- Evidence: `poll_descriptor/mod.rs:635` runs `stage_classify_fabric_ingress` then `stage_screen_check` with the fabric zone override; `stage_screen_check` (`poll_stages.rs:366-594`) has no `FABRIC_INGRESS_FLAG` guard, and the screen runtime counts every packet:
```rust
// screen/mod.rs:610
if icmp_flood_threshold > 0 && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6) {
    if let Some(counter) = self.icmp_counters.get_mut(zone) {
        if counter.increment(now_secs, icmp_flood_threshold) { return ScreenVerdict::Drop("icmp-flood"); } } }
```
- Trace:
  1. Node B receives a packet on a normal interface for a session owned by A → B runs `stage_screen_check`, ticks B's per-zone flood counters.
  2. B redirects the raw packet to A over the fabric.
  3. A receives it as fabric-ingress; stage 9 sets `ingress_zone_override`; stage 10 re-runs the screen with that zone before A's session fast-path.
  4. A's `icmp/udp/syn` counters for that zone increment on this established-session packet; a high-pps flow with a flood threshold configured crosses it → A returns `Drop`, dropping the exact traffic fabric forwarding exists to protect during failback/asymmetric-routing windows.
- Why it matters: vSRX does not re-apply screens to fabric-forwarded traffic; re-running stateful rate screens on the receiver can screen-drop legitimate established sessions and defeat the fabric-cross-chassis fix.
- Fix direction: In `stage_screen_check`, when `meta.meta_flags & FABRIC_INGRESS_FLAG != 0`, skip the rate-based flood counters (and scan/sweep) — the true ingress node already screened them. Stateless per-packet screens are idempotent and may stay.
- Labels: `correctness`, `ha`, `vsrx-parity`, `fabric`
- Dedup note: No prior title touches the fabric×screen interaction; #3902/#3064 concern flowless-fragment screening.

### M-5. DHCPv4 client installs a server-supplied `/0` (or non-contiguous) subnet mask verbatim, putting the entire IPv4 Internet on-link
- Severity: Medium
- Confidence: High
- Evidence: `pkg/dhcp/dhcp.go` `leaseFromACKv4` (922-937):
```go
mask := ack.SubnetMask()
if mask == nil { mask = net.CIDRMask(24, 32) }        // only the ABSENT case is defended
ones, _ := net.IPMask(mask).Size()
addr, ok := netip.AddrFromSlice(yourIP.To4())
...
lease := &Lease{ ... Address: netip.PrefixFrom(addr, ones) }
```
No lower-bound/contiguity check on `ones`; `net.IPMask.Size()` returns `(0,0)` for a non-contiguous mask. `applyAddress` then does `AddrReplace(link, addr/ones)`.
- Trace:
  1. A DHCP-configured interface (`family inet { dhcp; }`, e.g. WAN or `fxp0`).
  2. Rogue/compromised DHCP server answers with Option 1 = `0.0.0.0` (or any non-contiguous mask).
  3. `ones = 0` → `lease.Address = <addr>/0`; kernel adds a connected `0.0.0.0/0 dev <iface> scope link` route.
  4. Box ARPs for every IPv4 destination instead of routing via the gateway; an ARP-spoofer on the segment (not even the DHCP server) can intercept all egress; normal routing breaks.
- Why it matters: One option in a DHCP reply escalates an attacker from "controls this interface's gateway" to "MITMs/blackholes all IPv4 egress via that interface."
- Fix direction: After `net.IPMask(mask).Size()`, reject `ones == 0` (also covers the non-contiguous `(0,0)` case) — fall back to the class default / `/24` as the absent-mask path does, or drop the ACK. Add unit tests for mask `0.0.0.0` and a non-contiguous mask.
- Labels: `correctness`, `security`, `input-validation`, `dhcp`
- Dedup note: No prior title touches DHCP subnet-mask handling; #3956 is DHCPNAK revocation. Distinct input-validation gap.

### M-6. Management HTTP/HTTPS server sets no read/header/idle timeouts (pre-auth slowloris DoS)
- Severity: Medium
- Confidence: High
- Evidence: `pkg/api/server.go:420` and `:431` — both `http.Server` literals set only `Addr`/`Handler`(/`TLSConfig`); repo-wide grep (re-verified this run) finds no `ReadHeaderTimeout`/`ReadTimeout`/`MaxHeaderBytes` on either:
```go
s.httpServer = &http.Server{ Addr: cfg.Addr, Handler: handler }
s.httpsServer = &http.Server{ Addr: cfg.HTTPSAddr, Handler: handler, TLSConfig: ... }
```
- Trace:
  1. `system services web-management https interface ge-0-0-x` binds `httpsServer` to a non-loopback address.
  2. Attacker opens N connections, dribbles headers one byte at a time.
  3. Header read happens before `authMiddleware`, so auth is irrelevant; each stalled conn pins a goroutine/socket indefinitely → fd/goroutine exhaustion stalls the management plane.
- Why it matters: The control-plane API can be wedged pre-authentication by a trivial slowloris once web-management binds a real interface (a supported config). gosec G112/G114.
- Fix direction: Set `ReadHeaderTimeout` (~10s), plus `ReadTimeout`/`IdleTimeout`/`WriteTimeout` and `MaxHeaderBytes` on both `http.Server` structs in `NewServer`.
- Labels: `security`, `dos`, `hardening`
- Dedup note: No prior title touches HTTP server timeouts/slowloris; feeds #3934 is the outbound fetch path.

### M-7. REST config/system mutation handlers decode request bodies with no size cap (memory-exhaustion OOM)
- Severity: Medium
- Confidence: High
- Evidence: every mutating handler does `json.NewDecoder(r.Body).Decode(&req)` with no `http.MaxBytesReader` (grep re-verified: zero `MaxBytesReader` in `pkg/api`). E.g. `pkg/api/config.go:277`:
```go
func (s *Server) configLoadHandler(w http.ResponseWriter, r *http.Request) {
    var req ConfigLoadRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { ... }
    ... s.store.LoadOverride(req.Content) / LoadMerge / LoadSet ...
```
gRPC by contrast inherits grpc-go's 4 MiB default recv cap, so this is REST-specific.
- Trace:
  1. `POST /api/v1/config/load` (or `/config/set`, `/diagnostics/ping`, `/system/action`) with a ~1 GB JSON body.
  2. `json.Decode` allocates the whole `Content` string, then `LoadMerge`/`LoadSet` parses it (second large allocation) — and see H-2, a crafted body also crashes the parser.
  3. No `Content-Length`/body bound → daemon RSS spikes to OOM-kill. Unauthenticated when web-management binds an interface without `api-auth` (auth is opt-in); otherwise an authenticated availability DoS.
- Why it matters: A single request can OOM the firewall daemon.
- Fix direction: Wrap `r.Body = http.MaxBytesReader(w, r.Body, maxConfigBytes)` in the mutating handlers (or a central middleware); return 413 on overflow. Pairs with H-2's size ceiling.
- Labels: `security`, `dos`, `resource-exhaustion`
- Dedup note: No prior title covers REST request-body size limits; distinct from feed body caps (#3934, outbound).

### M-8. Unterminated `/* */` block comment silently truncates the config with zero parse errors → dropped security policies commit successfully
- Severity: Medium
- Confidence: High (empirically reproduced)
- Evidence: `pkg/config/lexer.go:168-181` (read this run) — the block-comment scanner consumes to EOF and returns **no error** on a missing terminator, in contrast to `readString:223` which returns `TokenError{"unterminated string"}`:
```go
if ch == '/' && l.pos+1 < len(l.input) && l.input[l.pos+1] == '*' {
    l.advance(); l.advance()
    for l.pos+1 < len(l.input) {
        if l.input[l.pos] == '*' && l.input[l.pos+1] == '/' { ...; break }
        l.advance()
    }
    continue   // unterminated: silently swallowed everything to EOF, no error
}
```
- Trace:
  1. `load override` of a file where a `/*` inside `security {` is never closed.
  2. Lexer eats every following byte — including `policies { default-policy { deny-all; } }` — leaving `security` an empty block.
  3. `Parse()` returns `errs=0`; `LoadOverride` accepts; `commit` applies a config missing those policies. Reviewer reproduced: `security` had 0 children, entire policy subtree gone silently.
- Why it matters: One accidental unterminated comment silently deletes an arbitrary tail of the config (potentially default-deny/policies) while `load`+`commit` report success — a fail-open config-loss path with no operator signal. vSRX rejects unterminated comments at parse time.
- Fix direction: Track the comment start line/col; if the loop exits at EOF with no `*/` seen, emit a `TokenError` ("unterminated block comment") so `parseStatements` records a `ParseError` and the load paths reject it — matching unterminated-string behavior.
- Labels: `correctness`, `security`, `vsrx-parity`
- Dedup note: No prior item touches unterminated comments; #3900 concerns annotation-content delimiters, not lexer comment termination.

---

# Low confidence findings

### L-1. NAT64 cross-family (V6 src, V4 dst) exclusion + empty-set fail-closed arm has zero test coverage
- Severity: Low
- Confidence: High
- Evidence: `userspace-dp/src/policy.rs:3889-3921` — the NAT64 arm re-implements the full `*-excluded` inversion and both-families-empty fail-closed guard independently against per-family fields (source→v6, dest→v4). The NAT64 tests (`policy_tests.rs:5673-5782`) exercise only non-excluded match/any/wrong-host; grep of `*_excluded` against the NAT64 fixtures returns nothing.
- Trace: N/A (coverage gap; the arm reads correct today).
- Why it matters: This arm mixes families; a future edit swapping a field would silently make a NAT64 `deny destination-address-excluded <host>` fail open with no test failing. The helper is the sole enforcement plane.
- Fix direction: Add two `nat64_inbound_*_excluded_*` tests: (1) `destination-address-excluded [172.16.80.200/32]` → (V6 src, .200) denies while (V6 src, .201) permits; (2) a v6-only `source-address-excluded` fail-closes for a v6 source.
- Labels: `test-coverage`, `nat64`, `security`, `vsrx-parity`
- Dedup note: No prior title covers the NAT64 exclusion arm.

### L-2. RST/FIN with no sequence validation collapses an established session's timeout (off-path early-reap)
- Severity: Low
- Confidence: Medium
- Evidence: `userspace-dp/src/session/lookup.rs:96-101` — any RST/FIN matching the 5-tuple flips `closing`/`reset`; no TCP sequence check anywhere on this path. Next timeout selection drops to `TCP_RST_TIMEOUT_NS` (2 s) / `TCP_CLOSING_TIMEOUT_NS` (30 s).
- Trace: Attacker who can guess/observe a live 5-tuple injects one spoofed RST → entry flips to 2 s window; if the genuine flow is briefly idle (>2 s) its state is reaped early and endpoints must re-handshake. Active flows survive (last_seen refreshes), so this is degradation not teardown.
- Why it matters: Classic RST-assassination surface. vSRX offers sequence checking / `no-sequence-check`; xpf silently trusts any in-tuple RST.
- Fix direction: Validate RST/FIN sequence against the tracked window before honoring the close (needs seq/window state on the entry), or add a config knob mirroring Junos.
- Labels: `security`, `vsrx-parity`
- Dedup note: #3046/#3489 concern RST-timeout stickiness, not the absence of sequence validation on the trigger.

### L-3. Cluster IP-monitoring accepts any ICMP echo reply — source, ID and sequence are never validated
- Severity: Low
- Confidence: High
- Evidence: `pkg/cluster/monitor.go:390` — the sent echo carries `ID: 0xbf, Seq: 1` but the reply is accepted purely on `parsed.Type == replyType`; the responder address (`_`), ID, and sequence are never compared.
- Trace: N/A. A down monitored target can be reported reachable if any host on the segment (misconfig, proxy, or a spoofer inside the 800 ms window on the unprivileged ping socket) emits an echo reply — suppressing the RG weight demotion and the intended failover.
- Why it matters: Real Junos `ip-monitoring` validates the responder; xpf can miss a genuine failover trigger.
- Fix direction: Compare the parsed body's ID/Seq to the sent values and verify the `ReadFrom` source equals the target; loop until a matching reply or the deadline.
- Labels: `correctness`, `ha`, `monitoring`, `vsrx-parity`
- Dedup note: No prior title touches the cluster ICMP monitor.

### L-4. VRRPv3 IPv4 advertisement checksum omits the RFC 5798 pseudo-header
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/vrrp/packet.go:78/:134` — the IPv4 marshal/parse computes `onesComplementChecksum(buf)` over the VRRP message only (VRRPv2 semantics); the IPv6 path builds a pseudo-header (`vrrpIPv6Checksum`). RFC 5798 §5.2.8 specifies the pseudo-header (next-header 112) for both families.
- Trace: N/A. xpf-to-xpf HA self-interoperates (both ends use the same math); the deviation only bites interop with a strictly RFC-5798 IPv4 VRRP peer (real vSRX / VRRPv3 keepalived), where every advert fails checksum.
- Why it matters: Latent vSRX-parity/interop gap.
- Fix direction: Compute the IPv4 VRRPv3 checksum over an IPv4 pseudo-header (src, dst, zero, proto=112, VRRP length) + message, matching the IPv6 path; update the verify branch together.
- Labels: `correctness`, `vsrx-parity`, `protocol-compliance`
- Dedup note: No prior title touches the VRRP checksum/pseudo-header.

### L-5. `/metrics` bypasses auth and walks the entire v4+v6 session table on every scrape
- Severity: Low
- Confidence: High
- Evidence: `pkg/api/auth.go:20-24` exempts `/metrics`; `pkg/api/metrics_sessions.go:52-63` iterates the full session table each `Collect` (`IterateSessions` + `IterateSessionsV6`); the handler sets no scrape timeout or concurrency limit.
- Trace: web-management bound to an interface → `/metrics` reachable unauthenticated → attacker scrapes in a tight loop → each scrape forces an O(sessions) walk of the AF_XDP maps (millions under load) with no rate limit, competing with the forwarding-sync path.
- Why it matters: Unauthenticated remote amplification of an O(N) scan on the box's largest hot structure.
- Fix direction: Require auth for `/metrics` when bound non-loopback (or gate behind `api-auth`); cache session-count gauges with a short TTL; add `promhttp.HandlerOpts{Timeout, MaxRequestsInFlight}`.
- Labels: `security`, `performance`, `scrape-cost`
- Dedup note: M07 (host-inbound recompute per scrape) is a different data source; this is the session-table walk + unauth exposure angle.

### L-6. API-key / Bearer auth uses non-constant-time map lookups (timing side channel)
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/api/auth.go:35-39` and `:53-56` validate API keys / bearer tokens by plain map lookup (`cfg.APIKeys[key]`), while Basic-auth passwords correctly use `subtle.ConstantTimeCompare` (`:72`); the Basic-auth username check (`cfg.Users[user]`, `:68`) also short-circuits before the constant-time compare.
- Trace: N/A (Low).
- Why it matters: Map-lookup/branch timing can leak whether a submitted key/username prefix is valid to a network-timing attacker on an interface-bound API — inconsistent with the deliberate constant-time password path already present.
- Fix direction: Compare API keys/tokens with `subtle.ConstantTimeCompare` against each configured secret (or hash-then-compare); avoid early-return on username existence.
- Labels: `security`, `hardening`
- Dedup note: No prior title touches API auth timing/constant-time comparison.

### L-7. Policy `match` multi-value leaves are read with an ad-hoc Keys/Children if-else instead of the mandated `firewallMatchValues` SSOT
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/config/compiler_security.go:710-757` reads `source-address`/`destination-address`/`application` as an either/or (`if len(m.Keys) >= 2 { ...Keys[1:] } else { range m.Children }`), whereas every sibling multi-value site (`then log` L810, `default-policy-log` L558, host-inbound `system-services` L462) was deliberately converted to `firewallMatchValues` (`compiler_firewall.go:361`), which reads Keys[1:] **and** Children. CLAUDE.md mandates the SSOT to prevent the #2419-class drop.
- Trace: N/A (latent). No current parser/merge path yields a mixed Keys+Children node for these leaves, so the if-else is correct today; the risk is a future parser change silently dropping all-but-`Keys[1:]` on a security leaf (deny under-match / permit widening).
- Why it matters: `match application`/address are the security-critical leaves; a silent value drop changes verdicts. Aligning with the SSOT removes the latent fail-open.
- Fix direction: Replace the three if-else blocks in `compilePolicy` with `for _, v := range firewallMatchValues(m)` (applying `normalizePolicyAddrToken` for the address leaves).
- Labels: `robustness`, `correctness`, `vsrx-parity`
- Dedup note: Dedup lists #2419 fixes and the `compiler_policy_match` gates, but none cover that `compilePolicy` itself still reads match address/application leaves without `firewallMatchValues`.

### L-8. `apply-groups` silently drops a group-contributed `match application`/address value when the policy already lists any value for that leaf
- Severity: Low
- Confidence: Low
- Evidence: `pkg/config/ast_groups.go:225-232/:287-300` — `mergeNodes` skips a group leaf when `hasMatchingLeaf` finds an existing leaf whose first key matches. So config `match { application junos-http; }` + group `match { application junos-https; }` merges to only `junos-http`.
- Trace: `set groups G ... policy p match application junos-https` + explicit `... match application junos-http` + `apply-groups G` → compiled `p` matches `junos-http` only. If `p` is `then deny`, `junos-https` is not denied and falls through.
- Why it matters: Round focus is "packets that should be denied must be denied." A group-contributed match value being dropped narrows a deny.
- Fix direction: For `multi:true` leaf-list keywords, union group values into the existing leaf's value set rather than skip-on-first-key-match; or, if Junos replace-semantics are intended, document it. (Low confidence: Junos leaf-list inheritance is version-dependent; the xpf drop is certain, the parity verdict is not.)
- Labels: `correctness`, `vsrx-parity`, `groups`
- Dedup note: No prior item touches apply-groups multi-value leaf merge for policy match; #2419 items are parser collapse, not group inheritance.

### L-9. No test exercises overlapping SNAT rule-sets of differing scope specificity
- Severity: Low
- Confidence: High
- Evidence: `nat/tests.rs:465/:429` — single-rule-set scope tests only; DNAT has tier tests (`nat/tests.rs:7304`), SNAT has no analogue.
- Trace: N/A.
- Why it matters: The missing test is exactly the M-3 case; the intended precedence is unpinned and the DNAT-vs-SNAT model inconsistency is invisible.
- Fix direction: Add a `parse_source_nat_rules` test with two overlapping rule-sets in less-specific-first config order, asserting the interface-scoped rule applies; land with M-3.
- Labels: `test-coverage`, `vsrx-parity`, `nat-source`
- Dedup note: No prior item touches SNAT cross-scope precedence testing.

### L-10. `alarm-without-drop` ids-option is hard-rejected — no Junos screen audit/log-only mode
- Severity: Low
- Confidence: High
- Evidence: `pkg/config/compiler_security.go:1020-1027` — the ids-option family switch accepts only `icmp`/`ip`/`tcp`/`udp`/`limit-session`; `alarm-without-drop` becomes an `UnknownLeaf` and is fail-closed rejected at commit. No `AlarmWithoutDrop` field exists in `ScreenProfile`/Rust `ScreenProfile`.
- Trace: N/A (config-time, fail-closed).
- Why it matters: Operators cannot run screens in Junos "alarm-without-drop" audit mode (log the attack, forward the packet) — a standard vSRX threshold-tuning step. Fail-closed, hence Low.
- Fix direction: Add an `alarm-without-drop` bool to `ScreenProfile` (Go + Rust wire); in the runtime convert `ScreenVerdict::Drop` to a log-only event + `Pass` when set (mirror the `syn-flood-alarm` emit path).
- Labels: `feature-completeness`, `vsrx-parity`
- Dedup note: No prior title mentions alarm-without-drop / screen audit mode.

### L-11. IPv4 screen extraction fails OPEN on a too-short L3 header while IPv6 fails closed
- Severity: Low
- Confidence: Low
- Evidence: `screen/extract.rs:68` — the IPv4 arm is guarded by `l3_offset + 20 <= frame.len()` but the else path returns `Ok(defaults)` (is_fragment=false, ip_ihl=5, no source-route), while `extract.rs:137` IPv6 returns `Err(TruncatedIpv6ExtChain)`. With defaults, `check_ping_of_death`/`check_teardrop`/`check_icmp_fragment`/`check_source_route` all early-return, so a truncated IPv4 header bypasses those screens.
- Trace: N/A. Reachability caveat: a padded Ethernet frame (≥60B) always carries a full 20-byte IPv4 header at l3_offset 14/18, so this is only reachable with a runt/malformed capture the NIC would normally drop — hence Low confidence.
- Why it matters: Asymmetric fail-open vs the IPv6 #2146 fail-closed contract.
- Fix direction: Mirror the IPv6 arm — when `addr_family == AF_INET && l3_offset + 20 > frame.len()`, return an `Err` so the caller fail-closes.
- Labels: `correctness`, `defense-in-depth`
- Dedup note: #2146/#2189/#2361 hardened the IPv6 walk; no prior item covers the IPv4 short-header symmetric case.

### L-12. DHCP relay forwards server replies without validating the source against the configured server set
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/dhcprelay/relay.go` `handleServerResponses` (1171-1234) — the server-facing socket is bound to `giaddr:67`, never `connect()`-ed; the reply loop forwards any BOOTREPLY on payload contents alone. The configured `servers` set is known to `runRelaySession` but not passed to `handleServerResponses`, so `srcAddr` is only logged.
- Trace: Any host that can route UDP to `giaddr:67` (off-path spoofer or compromised transit host) sends a forged OFFER/ACK/NAK → the loop forwards it to the client → rogue lease injection or NAK-driven restart.
- Why it matters: A configured relay knows its exact server IP list; not filtering on it widens the trust boundary to anything that can reach `giaddr:67`.
- Fix direction: Pass the resolved `servers` set into `handleServerResponses` and drop replies whose `srcAddr.IP` is not in it (with a counter). Confirm vSRX parity before enforcing, or gate behind a knob.
- Labels: `security`, `hardening`, `dhcp-relay`, `vsrx-parity`
- Dedup note: No prior item touches relay server-source validation; #3960 is giaddr readdress.

---

## Additional low-severity parity/robustness notes (filed for triage, below the 12 headline Lows)

- **Shim drops QinQ / dual-tagged frames as a parse failure** (`userspace-xdp/src/lib.rs:1153`, fail-closed). vSRX supports `flexible-vlan-tagging`; xpf strips only one tag → `drop_degraded_transit(PARSE_FAIL)`. Fix: unwind up to 2 tags (bounded) or document the single-tag limit. Labels: `feature-completeness`, `vsrx-parity`. (rev-afxdp L-1)
- **String-escape decoder asymmetry** (`pkg/config/lexer.go:200-214`, confirmed this run): unknown escapes (`\t`, `\x`) pass through as backslash+char, and a trailing `\` never errors, while `keyEscaper` emits only `\"`/`\\`/`\n`. Fix: document/reject the escape set symmetrically; add a `Format(Parse(x))==x` round-trip test. Labels: `correctness`, `test-coverage`. (rev-config L-1)
- **Scheduler `start-time`/`stop-time` reject `HH:MM`** (`pkg/config/schema_validators.go:981`, `pkg/scheduler/scheduler.go:429`): both require `HH:MM:SS`; validator and runtime agree (no commit/apply split), but Junos commonly accepts `HH:MM`. Fix: accept `15:04` as an alias in both, normalized to `:00`. Labels: `vsrx-parity`, `minor`. (rev-policy-go L-3)

---

## Suggested issue split

**Ship-blockers / near-term (security enforcement + crash-DoS):**
1. **H-1** junos-host deny bypass on the direct host-bound path — highest-priority correctness/security gap; a configured management deny does not fire.
2. **H-2** config parser/lexer unbounded recursion — one sub-4 MiB request or a hostile HA-sync payload hard-crashes xpfd (and the standby). Bundle with **M-7** (REST body cap) and add `MaxRecvMsgSize`; these three share the input-size-ceiling fix.
3. **M-6** management-server slowloris timeouts — small, high-value hardening; pairs with M-7 in an "API resource limits" issue.
4. **M-2** config-sync receiver advance-before-apply — silent HA divergence surfacing on failover.

**Correctness / parity (next):**
5. **M-1** TCP phantom-established exhaustion (+ L-2 RST seq validation) — one "TCP state-tracking hardening" issue.
6. **M-3** SNAT scope precedence (+ **L-9** test) — one "SNAT most-specific-wins" issue.
7. **M-4** fabric×screen re-screening — one "skip rate screens on fabric-ingress" issue.
8. **M-5** DHCP `/0` mask (+ **L-12** relay source validation) — one "DHCP input validation" issue.
9. **M-8** unterminated-comment silent truncation — bundle with H-2 in the parser issue.

**Hardening / test-coverage / parity backlog:**
10. L-3 IP-monitoring reply validation; L-4 VRRPv3 IPv4 pseudo-header; L-5 `/metrics` auth+cost; L-6 constant-time API keys; L-7 policy-match SSOT alignment; L-8 apply-groups multi-value merge; L-1 NAT64 exclusion tests; L-10 alarm-without-drop; L-11 IPv4 short-header fail-open; plus the three parity notes (QinQ, string-escape, scheduler HH:MM).

**Coverage note:** every named module produced either a finding or a documented negative result. The policy-verdict core (Rust `policy.rs`, Go `compilePolicy`/`policymatch`), AF_XDP HPC invariants (rings/UMEM/ext-header parsing), NAT execution (allocator/checksums/NAT64), and the SYN-cookie/CMS screen crypto were each traced and found clean on the correctness/security axis — the residual items there are test-coverage and parity gaps, not live bugs. The two High findings are genuine live enforcement/availability defects, both re-verified against source by the lead.
