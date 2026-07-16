# Fable review 163 — xpf firewall/router internal code-health & hardening campaign

## 1. Base commit reviewed

`20480f5175f82b8e80ea39a2c244af3d912f6e73` (HEAD, up to date with
`origin/master`; `Merge pull request #4095 from psaab/fix/4092-wg-tai64n`).
`git pull --rebase` was a no-op — the checkout already matched origin/master
(0 commits behind). No repository source files were modified; this report is
the only deliverable.

## 2. Output path

`/tmp/fable-review-163.md`

## 3. Duplicate-suppression summary

A combined dedup corpus of **528 prior finding titles** was assembled from all
`/tmp/codex-review-*.md`, `/tmp/agy-review-*.md`, and `/tmp/fable-review-161.md`
files (161 carried 149 High + Medium/Low `F-###` findings; codex reached 163;
agy reached 152). In addition, `docs/issues/issue-history.md` and
`docs/issues/pr-history.md` were grepped per candidate, and every candidate was
re-verified to still exist at HEAD by reading the file — the recent fix stream
(#4092 WG TAI64N, #4074 pool-SNAT ICMP-id, #4085 filter double-count, #4077
pool-util alarm, #4078 archival timer, #4071 GRE keepalive, #4069 prewarm,
#4067 monitor-traffic RBAC) was checked so nothing already fixed is re-filed.

Each finding below carries an explicit **Dedup note** naming the closest prior
title it was checked against. Notable close-but-distinct cases:

- The `show configuration` secret-leak (F1) is the **CLI** residual of F-020,
  which #4051 fixed only for REST + gRPC `ShowConfig`.
- The WG TAI64N reset (F5) is a hole **inside** the #4092 fix, not the original
  F-190 gap that #4092 closed.
- The NAT ICMP-id-0 collision (F9) is the id-0 corner of the RFC 5508 collision
  that #4074 closed for nonzero ids.
- The screen port-scan finding (F11) is a unit/window inversion, distinct from
  the vague `feature-gaps.md:251` completeness note and from #3230 (unset→0).

Whole modules were re-verified clean and reported as negatives (see §5): the
Rust policy verdict engine, the NAT allocator/identifier path, the session
timeout/wheel/GC core, and the AF_XDP umem/ring/sketch cores.

### Finding counts

| Tier | Count |
|------|-------|
| High confidence | 15 |
| Medium confidence | 11 |
| Low confidence (design smell / parity / triage) | 2 |
| **Total non-duplicate** | **28** |

Severity distribution: 3 High, 9 Medium, 16 Low. Two of the High-severity items
(F2 FRR injection, F4 IPsec traffic-selector injection) are config-injection into
a root daemon; the third (F3 CLI secret leak) is a cleartext-secret disclosure to
a view-only login class.

## 4. Module / feature checklist

Ten module groups were each swept for all five categories (a: correctness/
security, b: vSRX feature-completeness, c: performance/latency, d: modularity,
e: test coverage):

1. **rs-policy** — Rust userspace-dp policy verdict engine (`policy.rs`,
   `poll_descriptor/`, `forwarding/host_inbound.rs`); reject-reply / NAT-exception
   verdict interaction; AppCatalog attribution.
2. **go-policy** — Go policy/zone/host-inbound/application compiler
   (`compiler_security.go`, `compiler_applications.go`, `predefined.go`) + the
   userspace snapshot builders.
3. **screens** — screen/IDS (`userspace-dp/src/screen/*`, `compiler_security.go`
   screen path, `screens.go`).
4. **nat** — SNAT/DNAT/static/NAT64 (`userspace-dp/src/nat/*`, `compiler_nat*.go`,
   `userspace/nat.go`).
5. **session** — session table / conntrack (`userspace-dp/src/session/*`,
   `pkg/conntrack/*`, clear/filter path).
6. **ha** — chassis-cluster + VRRP (`pkg/cluster/*`, `pkg/vrrp/*`, fabric hooks).
7. **routing** — FRR / VRF / netlink / networkd / device-map (`pkg/frr/*`,
   `pkg/routing/*`, `pkg/networkd/*`, `pkg/daemon/linksetup.go`).
8. **services** — IPsec/WireGuard/DHCP/RA/API (`pkg/ipsec/*`,
   `userspace-dp/src/afxdp/wg/*`, `pkg/dhcp/*`, `pkg/ra/*`, `pkg/api/*`).
9. **config-core** — parser/schema/configstore/CLI/gRPC surfaces (`pkg/config/*`,
   `pkg/configstore/*`, `pkg/cli/*`, `pkg/grpcapi/*`).
10. **dpcore** — AF_XDP core & HPC invariants (`userspace-xdp/src/lib.rs`,
    `userspace-dp/src/afxdp/*`).

## 5. Module-by-module inspection log

### rs-policy — NEGATIVE on verdict path + 1 Low (round 2)
Verdict engine read end-to-end; **no allow/deny bypass found**. Ruled out and
verified correct: `system-services all` admits all protocols but the kernel nft
chain does identically (`daemon_nft.go:558,612`) so both planes agree;
`junos-global` correctly NOT consulted on the junos-host path (matches Junos);
Go↔Rust named-port tables mirror byte-for-byte (`capabilities.go:460` ↔
`policy.rs:4142`); NAT64 `(V6 src, V4 dst)` cross-family arm fails closed on
empty exclusion sets; flowless fragment app matching fails closed for
port/ICMP-constrained terms; wildcard two-pointer merge preserves config order;
tier precedence exact→from/to-any→both-any→scoped-global→default plus the
junos-host mirror and the #3110 unzoned-id-0 guard all correct; exclusion
inversion + empty-set fail-closed correct in all four L3 arms. Round-2 pivot into
the reject-reply / NAT-exception interaction confirmed **no verdict widening**:
post-DNAT policy eval is zone+tuple-consistent (`mod.rs:1516-1520`), SNAT
exhaustion fails closed (drop, `mod.rs:2537-2550`), and RST/ICMP reject replies
are feasibility-proven before any token/budget spend (#3656) and rate-limited
1:1. AppCatalog attribution is display-only, never a verdict input. **One Low
code-smell surfaced: F27 (`is_trust_flow`).**

### go-policy — 1 Medium parity + 1 Low modularity
Deep pass on `compilePolicy`, address-book representability, application
expansion, ICMP type/code, host-inbound token SSOT, per-interface override union,
zone-local books, runtime policy-ID namespace, global-vs-zone-pair ordering, and
excluded-address semantics — **all verified fail-closed / correct** (dense
per-issue test coverage). The only new correctness-adjacent gap is the **absence
of the predefined application-*set* catalog (F26)**; a dual-AST either/or read in
`compilePolicy` is latent-only (not reachable by valid config) and folded into
the modularity note (F28).

### screens — 3 findings (2 Medium parity/correctness, 1 Low)
SipHash24 cookie MAC, count-min sketch AND/MIN semantics, sliding-window
RateCounter, IPv6 ext-header fail-closed walk, and LAND/ping-of-death/teardrop/
source-route stateless screens all verified clean. New: port-scan/ip-sweep
threshold **unit inversion** (F11), icmp/udp flood **per-zone vs per-destination**
keying (F12), and the syn-dst-cap **ordering** vs the aggregate early-return
(F13, with a code-vs-comment contradiction).

### nat — NEGATIVE + 1 Low
NAT subsystem is exceptionally hardened (nearly every line issue-numbered). The
#4074 ICMP-identifier work is internally consistent; allocation/release key
reconstruction, forward/reverse id plumbing, DNAT/static-DNAT port gating, and
NAT64 wiring all correct; port-exhaustion fails **closed**. One residual: the
#4074 gate treats **ICMP query-id 0** as "no identifier" (F10).

### session — 3 findings (2 Medium, 1 Low test-gap)
Timeout wheel (#965), standby gate (#2120), TCP-window work (#3046/#3152/#3489/
#3527), timeout-overflow backstops (#2441/#3714), seeded hashing (#2364), capacity
fail-closed, GC single-writer discipline, and clear/filter path (#1827/#2733/
#2406) all verified correct. New: half-open→ESTABLISHED promotion on any ACK
(F14), one-directional RST/FIN not propagated to the companion entry (F15), and
the paired test-coverage hole (F16). The "keep-alive with out-of-window packets"
property is the **documented** no-sequence-check posture (#2078) — not re-filed.

### ha — 3 findings (1 Medium interop, 2 Low)
VRRP state machine, skew/master-down math (#4061), track-interface clamps,
GARP epoch/dampener gates (#2081/#2082), election tie-breaks, heartbeat
monotonic staleness, and fabric hooks all verified. Every session-sync
data-race / ordering / config-divergence candidate mapped to an existing corpus
entry (F-096/F-152/F-153/F-156/F-230/F-026) and was dropped. New: **IPv4 VRRPv3
checksum omits the RFC 5798 pseudo-header** (F17), owner-255 + no-preempt never
reclaims (F18), and unauthenticated/plaintext heartbeat + session-sync channels
(F19).

### routing — 1 High injection + 1 Medium parity
`config_render.go` static/DHCP/ECMP paths, `manager.go` reload/degraded-retry
(#1880), `rules.go` next-table/rib-group (F-016/F-174 deduped), VRF/tunnel
stable-table-id, networkd sanitization, and device-map #1956 invariants all
verified clean. New: **community-member / as-path-regex bypass of
`sanitizeFRRValue` → frr.conf injection** (F2) and the Junos-vs-FRR as-path
regex syntax non-translation (F20).

### services — 6 findings (1 High RCE, 2 Medium, 3 Low)
WireGuard framing/handshake/session/timers, RA sender ordering, IPsec $9$/DPD/
delete-terminate/df-bit/auth-alg render, Kea/dhcpserver (typed JSON, no
interpolation) all verified clean. New: **IPsec traffic-selector swanctl
injection → root RCE** (F4), #4092 responder TAI64N high-water reset on config
change (F5), DHCPv4 zero/non-contiguous subnet mask → `YourIP/0` (F6), WG key/PSK
plaintext carriers not zeroized (F21), ESP `default` fallback on dangling
proposal (F22), DHCPv4 ignores classless-static-routes opt 121/249 (F23).
**Coverage caveat:** `pkg/api` received only a thin pass (both sub-agents
exhausted budget); F-155/F-197 confirmed still present, but a dedicated API pass
(SSE/exec goroutine leaks, body-size limits, method/path handling) is
recommended and was NOT completed here — flagged honestly.

### config-core — 5 findings (2 High, 1 Medium, 2 Low)
Commit / commit-confirmed / rollback state machine (#1799/#1817/#3861), lexer
round-trip (F-005 fixed), schema typed-leaf validation, CLI privilege dispatch,
set/delete/load fail-closed (#3442), and the audit journal (v2 metadata-only,
`O_APPEND` + fsync, JSONL-injection-safe) all verified clean. New: **local CLI
`show configuration` not redacted** (F3), **gRPC fabric listener exposes the full
mutating+destructive service unauthenticated** (F1), operator class can
zeroize/reboot (F24), RA `default-lifetime 0` rejected+coerced (F25), destructive
`SystemAction` not audit-journaled (F8).

### dpcore — NEGATIVE on hot-path cores + 2 Low
Packet parser bounds checks, IPv6 ext-header walk, MPSC inbox (Vyukov, cache-
padded, correct Acquire/Release), umem admission accounting, GCRA ICMP rate
limiter, cold-path seqlock histogram, and ARP/NDP anti-spoof parser all verified
correct — no OOB read, no atomic-ordering error, no frame leak beyond filed
F-079/F-142/F-195. New: shim `record_trace` forces a per-packet BPF map insert on
attacker-reachable mcast/bcast paths even when tracing is off (F7), and the shim
`USERSPACE_FALLBACK_STATS` is a shared (non-per-CPU) `Array<u64>` with a
non-atomic RMW → lost counts across CPUs (F12-dp / listed as F13-dp below).

---

## 6. Findings

Field labels are uniform for programmatic parsing: **Title, Severity,
Confidence, Evidence, Trace, Why it matters, Fix direction, Labels, Dedup note.**

## 6.1 High-confidence findings

### F1. gRPC fabric listener registers the full mutating + destructive service with no authentication or authorization
- Severity: High
- Confidence: High
- Evidence: `pkg/grpcapi/server.go:235-258` — `RunFabricListener` builds a server with only `configLockInterceptor` (a lock-reaper, not an auth gate) and calls `pb.RegisterBpfrxServiceServer(srv, s)` — the identical full 48-RPC service registered on the loopback listener at :211. Started on the sync-interface IP in cluster mode (`pkg/daemon/daemon_ha_sync.go:549-561`, `%s:50051` on both fabrics). Destructive RPCs are reachable: `SystemAction{reboot,halt,power-off,zeroize}` (`pkg/grpcapi/server_diag.go:717-768`) plus `Commit`/`Delete`/`Rollback` (`server_config.go:152-252`). The remote client sends no identity (`cmd/cli/main.go` `insecure.NewCredentials()`).
```go
// pkg/grpcapi/server.go:256-258
srv := grpc.NewServer(
    grpc.UnaryInterceptor(s.configLockInterceptor),
)
pb.RegisterBpfrxServiceServer(srv, s)   // FULL mutating+destructive service
```
- Trace:
  1. Cluster mode brings up the fabric listener on the control/sync segment IP (e.g. the loss cluster's `em0` 10.99.x, a shared VLAN — not a dedicated crossover).
  2. Any host on that segment (or a spoofing peer) opens a plaintext gRPC channel to `<peer>:50051`.
  3. It calls `SystemAction{zeroize}` → the daemon deletes `/etc/xpf/*.conf`, rollbacks, BPF pins, networkd files; or `Commit`/`Delete` to rewrite policy. All execute unauthenticated — the login-class RBAC the interactive CLI enforces is entirely bypassed.
- Why it matters: unauthenticated remote factory-reset / reboot / reconfigure of a security appliance from anywhere on the cluster control fabric. The listener's documented purpose is read-only monitor-proxying, but it exposes the entire write surface.
- Fix direction: register a **restricted** service on the fabric listener (monitor/show + explicitly proxied RPCs only), or add a peer-identity interceptor (mTLS cluster cert or bind-to-known-peer-IP allowlist) that rejects every non-whitelisted RPC. Do not put the full server on a network-facing listener.
- Labels: security, ha, grpc, hardening
- Dedup note: closest is F-155 (REST/`pkg/api` non-loopback unauth mutation) — a different subsystem and path. `issue-history` 35307 notes only an unauth `Complete Pos=-1` DoS panic, not this authz gap. Not in the corpus.

### F2. Community members and as-path regexes bypass the FRR value-safety gate — an embedded newline injects arbitrary commands into the frr.conf managed section
- Severity: High
- Confidence: High
- Evidence: `pkg/frr/policy_render.go:1309` and `:1325` render `member` (community-list) and `ap.Regex` (as-path) verbatim, while every free-text field the module deliberately defends (neighbor description :673, BGP password :679, OSPF/RIP/IS-IS auth) is routed through `sanitizeFRRValue` (`:38`, strips C0/DEL incl. newline):
```go
// pkg/frr/policy_render.go:1308-1309
for _, member := range cd.Members {
    fmt.Fprintf(&b, "bgp community-list %s %s permit %s\n", listKind, name, member)
}
// :1324-1325
ap := po.ASPaths[name]
fmt.Fprintf(&b, "bgp as-path access-list %s permit %s\n", name, ap.Regex)
```
The commit-time strict gate `validateFRRAuthValuesStrict` / `frrTokenUnsafeIndex` (`compiler_validate_strict.go:1179,1216`) is applied to **auth secrets only**; the community/as-path validators (`:1108`) check only that a *reference* is defined, never member/regex content. Lexer `readString` (`pkg/config/lexer.go:207`) turns `\n` in a quoted value into a real newline byte.
- Trace:
  1. `set policy-options as-path evil "^1$\n router bgp 65000\n neighbor 6.6.6.6 remote-as 65000"` (or the same via HA config-sync / rollback reload / lenient load, which re-parse stored values).
  2. Lexer yields `ap.Regex` with literal newlines; no strict validator rejects control chars on this leaf.
  3. `generatePolicyOptions` renders it verbatim at `:1325` into the xpf-managed section of `/etc/frr/frr.conf`.
  4. `frr-reload.py` applies the section → the injected `router bgp` / `neighbor` lines execute as real FRR config → rogue BGP session / redistribution → traffic redirection or exfiltration.
- Why it matters: converts config-write access limited to `policy-options` (a scope a Junos RBAC allow/deny-configuration regex can legitimately grant while denying `protocols bgp`) into arbitrary routing-daemon control. Also breaks the project's own #1960 lenient-load "stored bad value stays inert at render" invariant, which `sanitizeFRRValue` enforces for auth/description but not for these two free-text FRR values.
- Fix direction: route `member` and `ap.Regex` through `sanitizeFRRValue` at render, and add a commit-time newline/CR (ideally full `frrTokenUnsafeIndex`) gate over community members and as-path regexes, lenient-downgraded on load/peer-sync.
- Labels: security, frr, config-injection, correctness
- Dedup note: not in corpus. Closest: F-035 (annotation `*/` injection — the comment renderer, different surface), F-005 (backslash round-trip). The #2643 community-list work fixed standard-vs-expanded KIND selection but added no content sanitization.

### F3. Local interactive CLI `show configuration` is not secret-redacted — a read-only / config-viewer login class prints IKE PSKs, SNMP communities, and auth-keys in cleartext
- Severity: High
- Confidence: High
- Evidence: `pkg/cli/cli_show.go` (`case "configuration"`) calls the non-redacted store renderers — `ShowActive()`, `ShowActiveSet()`, `ShowActiveJSON()`, `ShowActiveXML()`, `ShowActiveInheritance()`, and the `ShowActivePath*` variants. Those return `s.active.Format()/FormatSet()/…` with no masking (`pkg/configstore/store_format.go:31-36`). The redacted variants **exist** (`ShowActiveRedacted`, `ShowActiveSetRedacted`, … at `store_format.go:319-351`) and are correctly used by gRPC (`pkg/grpcapi/server_config.go:279-297`) and REST (`pkg/api/config.go:184-217`) after #4051/F-020 — the local CLI was never wired to them.
```
# pkg/cli/cli_show.go (case "configuration") — non-redacted:
fmt.Print(c.store.ShowActiveSet())     // -> active.FormatSet(): cleartext
fmt.Print(c.store.ShowActive())        // -> active.Format(): cleartext
```
- Trace:
  1. A user with login class `read-only` or `config-viewer` (both = `PermView`, `pkg/config/types_system.go:558-563`) SSHes into the appliance CLI.
  2. `checkPermission(["show","configuration"])` → `PermView` → allowed (`permissions.go:63`).
  3. Dispatch → `ShowActiveSet()` → `active.FormatSet()` prints every `security ike … pre-shared-key`, `snmp community`, `system … authentication-key` in cleartext. Junos shows only the encrypted `## SECRET-DATA` / `$9$` form to these classes.
- Why it matters: the interactive CLI is the primary operator surface (the SSH login shell for all classes). #4051 hardened only REST + gRPC; a view-only operator can harvest every firewall secret at HEAD.
- Fix direction: route `cli_show.go` (and the `cli_config.go` candidate / `compare rollback` show paths with the same gap under `PermConfig`) through the `*Redacted` store methods already implemented for gRPC/REST.
- Labels: security, secret-redaction, cli, vsrx-parity
- Dedup note: F-020 is scoped explicitly to "REST /config/show|export|search|show-rollback|compare and gRPC ShowConfig"; #4051 fixed exactly those and missed `pkg/cli`. This is the residual CLI surface, verified unredacted at HEAD.

### F4. IPsec `local_ts` / `remote_ts` traffic selectors are rendered into swanctl.conf unsanitized and uncommit-validated — config-injection into the root keying daemon (updown → root RCE)
- Severity: High
- Confidence: High
- Evidence: `pkg/ipsec/policy.go:176-182` renders the selectors with bare `%s`, unlike the sibling `child.Name` on `:175` which uses `sanitizeSwanctlValue`:
```go
fmt.Fprintf(&b, "      %s {\n", sanitizeSwanctlValue(child.Name))
if child.LocalTS != "" {
    fmt.Fprintf(&b, "        local_ts = %s\n", child.LocalTS)   // RAW
}
if child.RemoteTS != "" {
    fmt.Fprintf(&b, "        remote_ts = %s\n", child.RemoteTS) // RAW
}
```
`effectiveTrafficSelectors` (`policy.go:341-381`) sources these from `traffic-selector local-ip/remote-ip` (and identity fallbacks). A grep of `compiler_validate*strict*.go` for the source leaves shows **no commit validation**, and `lexer.go:207` materializes `\n` in a quoted value.
- Trace:
  1. Commit `set security ipsec vpn v1 traffic-selector ts1 local-ip "10.0.0.0/24\n        updown = /tmp/x.sh"`.
  2. `renderConfig` writes a real newline + `updown = /tmp/x.sh` into the swanctl `children { ts1 { … } }` block; no strict validator rejects it.
  3. charon (running as root) executes the updown script on tunnel up/down → root RCE; alternatively inject `esp_proposals`/`mode`/`mark_*` to silently alter crypto posture.
- Why it matters: config-injection into the root keying daemon on a security appliance, reachable on the normal commit path and via HA reverse-sync / `load override` / a restricted RBAC author who can set selectors but not updown/proposals directly (privilege escalation within the grammar). The module already treats swanctl interpolation as an injection surface (#1798/#2126 sanitize name/id/cert/PSK) — traffic selectors were missed and have zero commit validation.
- Fix direction: run `LocalTS`/`RemoteTS` through `sanitizeSwanctlValue` at render (parity with `child.Name`) and add a strict validator parsing each as CIDR/range and rejecting control chars.
- Labels: security, ipsec, injection, rce, hardening
- Dedup note: distinct from F-035 (annotation `*/`), F-005 (backslash round-trip), F-020 (secret redaction). This is the specific render-omission + validation-absence for `local_ts`/`remote_ts`.

### F5. #4092 responder TAI64N anti-replay high-water resets to zero on every WireGuard config change — the landed anti-replay fix is silently disarmed by a routine commit
- Severity: Medium
- Confidence: High
- Evidence: `userspace-dp/src/afxdp/wg/peer.rs:176-194` claims `greatest_tai64n` "survives config commits (same pubkey → same `Arc<Peer>`)", but `forwarding_build/wg.rs:20` explicitly states "**do NOT call `reconcile_peers`**". A byte-identical config reuses the whole engine `Arc`; any identity change (`wg_peers_eq` compares pubkey/allowed_ips/endpoint/keepalive/**psk**) builds a fresh `WgEngine::new` → fresh `Peer::new` → `greatest_tai64n = [0;12]`, and only the **outgoing** clock is re-seeded (`seed_tai64n_high_water`, #1432). No seed path exists for the incoming high-water.
```rust
// forwarding_build/wg.rs:86
engine.seed_tai64n_high_water(hw);   // OUTGOING clock only; no incoming high-water seed
```
- Trace:
  1. Peer P handshakes → responder records `greatest_tai64n = T_last`.
  2. Operator commits a benign WG change (add allowed-ip, rotate PSK, add a peer) → rebuild branch → P's high-water resets to 0.
  3. An attacker who captured a valid type-1 initiation from P (timestamp `T0 > 0`) replays it; `check_and_update_tai64n(T0)` returns true → responder performs full Noise crypto, installs an unconfirmed `next` session, and emits msg2 — the exact replay #4092 closed. For an offline/responder-only P the window stays open until P next handshakes.
- Why it matters: a security control that landed at HEAD is silently re-opened by a routine operator action, diverging from kernel/wireguard-go (which retain per-peer `last_timestamp` across reconfigure). The asymmetry is the tell — the initiator clock got explicit rebuild-survival plumbing (#1432); the #4092 responder high-water did not.
- Fix direction: mirror #1432 — add `Peer::greatest_tai64n()` / `seed_greatest_tai64n()` and copy each surviving peer's high-water from `prev_engine` into the fresh engine in the rebuild branch (reset only on an actual pubkey change).
- Labels: security, wireguard, anti-replay, vsrx-parity, regression
- Dedup note: not F-190 (the original gap, fixed by #4092) — this is a hole in the landed fix. Not F-191/F-019/F-250/F-271.

### F6. DHCPv4 client installs `YourIP/0` on-link when a rogue or broken server sends a zero or non-contiguous subnet mask
- Severity: Medium
- Confidence: High
- Evidence: `pkg/dhcp/dhcp.go:922-939` guards only `mask == nil`; a present-but-degenerate mask is not checked:
```go
mask := ack.SubnetMask()
if mask == nil { mask = net.CIDRMask(24, 32) }
ones, _ := net.IPMask(mask).Size()   // 0.0.0.0 -> (0,32); non-contiguous 255.255.0.255 -> (0,0)
...
Address: netip.PrefixFrom(addr, ones),   // ones==0 -> addr/0
```
The apply path (`dhcp.go:1549-1555`) does `AddrReplace(link, addr)` with the resulting `YourIP/0`.
- Trace:
  1. xpf runs DHCPv4 on an uplink/mgmt interface (fxp0 bootstrap default).
  2. A rogue/buggy server ACKs with option 1 = `0.0.0.0` (or a non-contiguous mask) → `net.IPMask.Size()` returns `ones = 0`.
  3. Lease becomes `YourIP/0` → the kernel installs a connected route for `0.0.0.0/0` on that interface → all IPv4 forwarding is blackholed/hijacked until the lease is replaced.
- Why it matters: a single crafted ACK from a rogue server blackholes traffic with no operator action — an untrusted-input gap on a WAN/mgmt-facing client. vSRX rejects a mask yielding no host bits.
- Fix direction: after `.Size()`, reject/clamp when `ones == 0` or `bits != 32` (non-contiguous); enforce `0 < ones <= 32`.
- Labels: security, correctness, dhcp, untrusted-input
- Dedup note: no corpus DHCP finding (F-172/173/217/218/219/264) concerns subnet-mask validation or prefix length.

### F7. XDP shim `record_trace` forces a per-packet BPF map insert on the EARLY_FILTER / BINDING_MISSING paths even when tracing is disabled — attacker-influenceable hot-path CPU amplification
- Severity: Low
- Confidence: High
- Evidence: `userspace-xdp/src/lib.rs:1074-1119` (`record_trace`), forcing set at `:1084-1090`; call site at `:555-567`. The `forced` set bypasses the trace-disabled early-out:
```rust
let forced = matches!(stage,
    USERSPACE_TRACE_STAGE_BINDING_MISSING | USERSPACE_TRACE_STAGE_EARLY_FILTER);
if !forced && (ctrl_flags & USERSPACE_CTRL_FLAG_TRACE) == 0 { return; }
...
let _ = USERSPACE_TRACE.insert(&trace_key, &value, 0);   // bpf_map_update per packet
```
- Trace:
  1. Attacker floods UDP/TCP frames whose IPv4 dst is `255.255.255.255` / `224.0.0.0/4` / `169.254.0.0/16` (or IPv6 `ff00::/8` / `fe80::/10`) — `should_fallback_early` (`lib.rs:1324-1345`) returns true.
  2. `record_trace` runs with `stage = EARLY_FILTER` (in `forced`), so the `ctrl_flags & TRACE == 0` early-out is skipped despite tracing being off.
  3. Protocol is UDP/TCP (not ICMP), so the second early-out is skipped too.
  4. Every such packet executes `bpf_ktime_get_ns()` + an avalanche key computation + a `bpf_map_update_elem` (per-bucket lock) on the native-XDP ingress core — once per packet. `BINDING_MISSING` (`:438-459`) forces the same for every transit packet on a transiently-unbound queue during a config-reload window.
- Why it matters: the codebase deliberately keeps disabled features off the per-packet path (the WG-gate comment at `lib.rs:64-74` notes even a bare load+compare "nudged the v6 best-effort path into non-zero retransmits at line rate"). A forced map insert + ktime read per packet is far heavier and is reachable by unauthenticated traffic to well-known multicast/broadcast groups — steady overhead on a router also carrying OSPF/VRRP/mDNS, and a CPU-amplification sink under a crafted flood that no operator toggle can disable.
- Fix direction: gate the `USERSPACE_TRACE.insert` on the `TRACE` flag unconditionally; keep only the counter bump forced. If binding-missing visibility is needed, publish it through the (fixed, see F13) counter array or 1-in-N sample the forced insert.
- Labels: performance, security, dos, dataplane, xdp-shim
- Dedup note: grep for `record_trace`/`EARLY_FILTER` across corpus + issue/pr history = empty. Closest is the event-stream seq-gap work (F-152/F-153) and ICMP-ratelimit (#2472/#2955) — both on the `userspace-dp` helper's cold reply path, a different code path with a different trigger.

### F8. Destructive gRPC `SystemAction` (reboot/halt/power-off/zeroize/clear-config-lock) is not written to the commit audit journal
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/grpcapi/server_diag.go:717-776` — each action only `slog.Warn`s; none call the configstore journal (`pkg/configstore/journal`, which records commit / commit_confirmed / auto_rollback / config_sync / persist_*).
- Trace:
  1. An operator (or, per F1, an unauthenticated fabric client) issues `SystemAction{zeroize}`.
  2. The daemon wipes config + rollbacks + pins and reboots.
  3. The JSONL audit journal has no correlatable entry — only a journald line that does not survive the zeroize.
- Why it matters: zeroize (full config wipe) and reboot are the most destructive operations and leave no tamper-resistant audit record, defeating post-incident attribution.
- Fix direction: emit a `system_action` journal entry (actor, action, timestamp) before executing.
- Labels: audit, observability, security
- Dedup note: F-015/F-211/F-020/F-050/F-087 concern archive/rollback/secret-at-rest, not `SystemAction` audit coverage.

### F9. Pool-SNAT skips ICMP query-id translation when the identifier is 0 — re-opens the RFC 5508 reverse-tuple collision that #4074 closed for nonzero ids
- Severity: Low
- Confidence: High
- Evidence: `userspace-dp/src/nat/source.rs:894` overloads `src_port == 0` as both the flowless-ICMP sentinel and a legal identifier value:
```rust
let icmp_query = matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) && src_port != 0;
```
`parse_flow_ports` (`inspect.rs:1067-1068`) returns `Some((0,0))` for an echo with id 0, so `icmp_query` is false → `port_less` true → the **address-only** path (`source.rs:905`) rewrites the source IP but not the identifier. The test (`nat/tests.rs:3444`) only exercises id `0x1234`, and `tests.rs:3517` pins the `src_port != 0` gate.
- Trace:
  1. Hosts A and B both send an ICMP echo with Identifier 0 to the same target T behind the same pool address P (a single-address pool guarantees co-location).
  2. Both take the address-only path → both egress as `(src=P, id=0)`.
  3. Their reverse tuples `(P, id 0, T)` are identical → reverse `SessionKey` collision (`key.rs:94`) → T's replies are mis-associated between A and B — the exact mis-demux RFC 5508 §3.1 / #4074 prevents.
- Why it matters: identifier 0 is legal (RFC 792) and reachable (`hping3 --icmp-id 0`, custom tools, embedded stacks). The #4074 fix leaves an untested hole at id 0.
- Fix direction: carry an explicit "has-identifier" signal from `parse_flow_ports` (the query-type predicate) into the SNAT path instead of inferring it from `src_port != 0`; or gate `icmp_query` on the ICMP type being identifier-bearing.
- Labels: correctness, nat, icmp, rfc-conformance
- Dedup note: not in corpus; this is the id-0 corner of the collision #4074 closed for nonzero ids, verified live at HEAD.

### F10. IPv4 VRRPv3 advertisement checksum omits the RFC 5798 §5.2.8 IPv4 pseudo-header — breaks interop with any conformant VRRP router
- Severity: Medium
- Confidence: High
- Evidence: `pkg/vrrp/packet.go:74-81` (marshal) and `:133-137` (parse) compute/verify the IPv4 checksum over the VRRP payload only, with no pseudo-header, while the IPv6 path (`vrrpIPv6Checksum`, `:176-205`) correctly prepends the src/dst/length/next-header pseudo-header:
```go
if isIPv6 {
    csum := vrrpIPv6Checksum(srcIP.To16(), dstIP.To16(), buf)
    binary.BigEndian.PutUint16(buf[6:8], csum)
} else {
    csum := onesComplementChecksum(buf)   // VRRP data only — no pseudo-header
    binary.BigEndian.PutUint16(buf[6:8], csum)
}
```
`Marshal(isIPv6, srcIP, dstIP)` already receives the addresses but discards them on the IPv4 leg. (Reclassified to High confidence: both the RFC text and the IPv6 sibling implementation directly evidence the correct algorithm the IPv4 leg omits.)
- Trace:
  1. RFC 5798 §5.2.8 covers the VRRP message **plus** a pseudo-header (upper-layer src/dst, VRRP length, next-header 112) for both families; vSRX/Cisco/keepalived-v3 do IPv4 this way.
  2. xpf marshals an IPv4 RETH advert (e.g. reth1.0 VIP 10.0.61.1) checksumming only the header + VIP.
  3. A conformant peer verifies with the pseudo-header → nonzero residual → advert discarded; symmetrically xpf's `ParseVRRPPacket` rejects a conformant peer's advert.
  4. Mixed cluster (xpf ↔ real vSRX, or joining an existing IPv4 VRRP group) accepts no IPv4 adverts → mutual timeout → dual-master split-brain on the IPv4 VIP. A pure-xpf cluster is self-consistent (both wrong the same way), so it is latent until interop.
- Why it matters: staged migration alongside a genuine vSRX, or joining an existing IPv4 VRRP group, yields silent total advert rejection and split-brain (duplicate MAC/IP, asymmetric forwarding) — the worst VIP failure mode. IPv6 was fixed correctly; IPv4 was left on the VRRPv2 algorithm.
- Fix direction: add an IPv4 pseudo-header (src 4B, dst 4B, zero, protocol 112, VRRP length 2B) to both marshal and parse, mirroring `vrrpIPv6Checksum`; add an interop test that a canonical RFC-5798 IPv4 advert is accepted and xpf output validates under the pseudo-header algorithm.
- Labels: vsrx-parity, interop, correctness, rfc-conformance, ha, test-coverage
- Dedup note: closest priors are F-076 (master-down timing, #4061) and the IPv6-only checksum work in `docs/bug-heartbeat-vrf-rebind-split-brain.md`. No corpus entry mentions the IPv4 checksum computation.

### F11. Port-scan / ip-sweep `threshold` is a distinct-destination count over a fixed 10-second window — Junos `threshold` is a time window in microseconds — so a copied Junos config either disables detection or the default false-drops normal browsing
- Severity: Medium
- Confidence: High
- Evidence: `userspace-dp/src/screen/scan.rs:112` fixes `WINDOW_SECS = 10`; `:286` compares the threshold as a **count** of unique entries (`entry.1.len() as u32 > effective_threshold`). The compiler comment states the divergence outright:
```go
// pkg/config/compiler_security.go:50-62
// Junos flags a port scan / address sweep when one source reaches 10 distinct
// destination ports / addresses within a 5000-microsecond window. This engine
// interprets the threshold as a DISTINCT-DESTINATION COUNT over a fixed
// 10-second window ... feeding 5000 here would be read as a count and clamped
// to the dataplane cap (1023), effectively never firing.
defaultPortScanThreshold = 10
```
`maxScanSweepThreshold = 1023`; `validateScreenScanSweepThresholds` only **warns** above it.
- Trace:
  1. A Junos operator writes `set security screen ids-option x ip ip-sweep threshold 5000` (5000 = the Junos microsecond default). It commits with only an advisory warning.
  2. `screens.go` copies 5000 verbatim; `ScanCore::check` clamps to `1023` and compares `set.len() > 1023` — detection fires only if one source reaches 1024 distinct destinations in 10 s → effectively never. The operator believes ip-sweep is armed; it is inert.
  3. Conversely, an operator enabling the screen with no explicit threshold gets the default `10` over a 10-second window. A single host opening flows to ≥11 distinct destinations in 10 s — a normal web page or fan-out client — trips `ip-sweep` and is dropped. Junos' 5 ms window would never flag it.
- Why it matters: the same numeric config value that arms tight sweep detection on a real SRX either disables it or, at the default, drops legitimate browsing/fan-out — a false sense of protection in one direction and an unpredictable outage in the other.
- Fix direction: interpret `threshold` as Junos does — a fixed detection count (10) crossed within a configurable **time** window (microseconds) — rather than a configurable count over a hardcoded 10 s. At minimum tighten `WINDOW_SECS`, reject (not warn) count-shaped values above the tracker cap, and document the unit.
- Labels: vsrx-parity, correctness, screen, availability
- Dedup note: not in corpus. Closest: `feature-gaps.md:251` (vague "detection algorithm may be incomplete"), distinct from #3230 (unset→0) and #2234/#2227 (tracker bounds). This is the unit/window inversion and its false-positive consequence.

### F12. WireGuard static private key and per-peer PSK transit through plaintext `[u8;32]` `Clone` config carriers, never zeroized on drop
- Severity: Low
- Confidence: High
- Evidence: `userspace-dp/src/afxdp/wg/engine.rs:176-213` — `WgEngineConfig.local_private_key: [u8;32]` and `WgPeerConfig.preshared_key: [u8;32]` are both `#[derive(Clone)]` with no `Zeroize`, even though the module's own runtime copies are wrapped (`engine.rs:345` private key `Zeroizing`, `peer.rs:61` PSK `Zeroizing`). Build sites deref the `Zeroizing` source into the plaintext carrier (`forwarding_build/wg.rs:60,79`).
- Trace:
  1. Every WG-touching commit builds/clones these carriers, copies the key into the engine's `Zeroizing` field, then drops the carrier (and the prior generation) without wiping.
  2. A 32-byte X25519 private key + all PSKs are left in freed heap/stack, recoverable via core dump / heap-spray.
- Why it matters: key-hygiene regression on a security appliance; the module already made the opposite (correct) choice for the runtime copies — the config carriers were missed.
- Fix direction: make both fields `zeroize::Zeroizing<[u8;32]>` (or `ZeroizeOnDrop`), matching the runtime types.
- Labels: security, key-hygiene, wireguard
- Dedup note: not F-087 (`syn_cookie_master_key` serialized to disk) — different keys; this is in-memory non-zeroization of the config carriers.

### F13. XDP shim degraded-path counters (`USERSPACE_FALLBACK_STATS`) are a shared, non-per-CPU BPF `Array<u64>` incremented with a non-atomic read-modify-write — lost updates across concurrent XDP CPUs
- Severity: Low
- Confidence: High
- Evidence: `userspace-xdp/src/lib.rs:377-379` (map decl) and `:1063-1072` (the RMW), 12 call sites; no `PerCpuArray` exists anywhere in the shim:
```rust
#[map(name = "userspace_fallback_stats")]
static USERSPACE_FALLBACK_STATS: Array<u64> =
    Array::with_max_entries(USERSPACE_FALLBACK_REASON_MAX, 0);   // NOT PerCpuArray
...
*ptr = (*ptr).saturating_add(1);   // load; add; store — NOT atomic
```
- Trace:
  1. Native XDP runs one program instance per RX queue on distinct CPUs concurrently (the loss cluster VFs expose 6 combined RX queues → 6 workers).
  2. Two CPUs take a fallback branch for the same `reason` in the same window; both read `v`, compute `v+1`, store `v+1` → one increment lost (classic shared-memory RMW race).
  3. The Go control plane surfaces this as the operator "degraded_path_counters"; the reported counts undercount exactly under the high-load/attack conditions when they matter for triage.
- Why it matters: this is the shim's only visibility into strict-mode drops, heartbeat-stale drops, binding-missing drops, redirect errors, and local passes. Undercounting is invisible and worsens with core count and load. The project made the opposite deliberate choice for the retired eBPF pipeline (issue #45 removed atomic RMW precisely because those counters were on **per-CPU** maps); the retained shim regressed to a shared `Array` while keeping the per-CPU-only-safe non-atomic increment.
- Fix direction: make `USERSPACE_FALLBACK_STATS` a `PerCpuArray<u64>` (Go already sums per-CPU arrays) so the non-atomic increment is CPU-local and correct — matching the #45 resolution — or use an atomic add if it must stay a single `Array`.
- Labels: correctness, observability, dataplane, xdp-shim
- Dedup note: grep `fallback_stats`/`per-cpu` across corpus + issue/pr history = empty. F-231 is a Go-side reconcile heuristic on `userspace-dp` binding counters, a different mechanism. Issue #45 is the closest but reached the opposite (correct-for-per-CPU) conclusion for the retired pipeline.

### F14. Predefined Junos application-sets (junos-ms-rpc, junos-sun-rpc, junos-cifs, junos-routing-inbound) are absent — a canonical vSRX policy referencing one is hard-rejected at commit
- Severity: Medium
- Confidence: High
- Evidence: `pkg/config/predefined.go:11` ships 89 individual apps but **no** predefined application-*set* table — the RPC bundles exist only as protocol-split members (`junos-ms-rpc-tcp`/`-udp`, `junos-sun-rpc-tcp`/`-udp`), while `junos-ms-rpc`, `junos-sun-rpc`, `junos-cifs`, `junos-routing-inbound` are nowhere in the tree. `ResolveApplicationSet` (`:164`) consults only user-defined sets (contrast `ResolveApplication` `:151` which checks the predefined table). The commit gate `appRefError` (`compiler_validate_strict.go:2147`) and the runtime resolver `resolveUserspaceApplicationNames` (`capabilities.go:395`) both hard-fail an unresolved token.
- Trace:
  1. Operator applies a stock vSRX rule: `set security policies from-zone trust to-zone untrust policy allow-rpc match application junos-ms-rpc`.
  2. `validatePolicyMatchApplicationsStrict` → `appRefError("junos-ms-rpc")`: `ResolveApplication` misses (only `-tcp/-udp` defined), `ResolveApplicationSet` misses (no predefined-set table) → hard error → `commit` / `commit check` FAILS.
  3. On the tolerant/HA-sync path the strict gate only warns, but `resolveUserspaceApplicationNames` hits the same miss → `__unsupported__` sentinel → Rust `SnapshotIntegrityError` rejects the whole snapshot. Consistently fail-closed, but the config is unusable.
- Why it matters: a firewall marketed as cloning vSRX with native Junos syntax cannot commit a canonical vSRX policy; every migrated config using these common predefined sets breaks at commit, forcing hand-redefinition. Fail-closed (no security hole) but a direct parity regression.
- Fix direction: add a `PredefinedApplicationSets` table in `predefined.go` seeded with the standard Junos sets, and have `ResolveApplicationSet`/`ExpandApplicationSet` fall back to it (mirroring `ResolveApplication`'s user-then-predefined order). Both the commit gate and the runtime resolver already route through those functions, so one table fixes all surfaces. Add a compile-path test.
- Labels: vsrx-parity, feature-completeness, applications, test-coverage
- Dedup note: closest are F-160 (typo'd application-set member dropped) and M08/M03 (malformed application-set handling) — all about USER-defined sets. None address the absence of the predefined set catalog. No issue/pr-history hit.

### F15. Session test-coverage gap: no test pins that a SYN + bare-ACK (no observed SYN-ACK) must NOT promote to ESTABLISHED, and none covers forward↔reverse companion close-state propagation
- Severity: Low
- Confidence: High
- Evidence: `userspace-dp/src/session/tests.rs:1264-1297` covers only the honest SYN→SYN-ACK→ACK order; `:1061-1171` (#3489 close-window revert) operates on a single entry. A grep for a companion `is_reverse: true` + closing test shows none.
- Trace: F16 and F17 (below) are both invisible to CI — the only promotion test uses the correct handshake, and all close-window tests use one entry. A regression that tightened promotion or added companion propagation has no RED anchor; the current permissive behavior is silently blessed.
- Why it matters: these are exactly the state-machine subtleties (#3152/#3046/#3489) the module guards elsewhere with fail-on-revert tests — the two holes above are the untested corners.
- Fix direction: add (a) a test that SYN then forward bare-ACK with no reverse SYN-ACK keeps the entry OPENING; (b) a test that a RST on one direction reaps both the forward and reverse companion at the short window.
- Labels: test-coverage, tcp-state-machine
- Dedup note: not in corpus; F-140 (flow-cache/session coherence) and F-250 (WG rekey) are unrelated test gaps.

## 6.2 Medium-confidence findings

### F16. Half-open→ESTABLISHED promotion fires on any ACK-bearing segment (no reverse SYN-ACK required) — defeats the #3152 SYN-flood half-open reap with a 2-packet SYN+ACK
- Severity: Medium
- Confidence: Medium
- Evidence: `userspace-dp/src/session/lookup.rs:102-111` (mirror in `mod.rs:1118-1125`, seed in `install.rs:158`):
```rust
if matches!(key.protocol, PROTO_TCP) && has_ack(tcp_flags) {
    entry.established = true;
}
```
`has_ack` is a pure bit test; nothing requires a reverse SYN-ACK was observed or that this is the handshake-completing ACK.
- Trace:
  1. Attacker sends a bare SYN to a permitted 5-tuple → OPENING, `expires_after_ns = tcp_opening_ns` (20 s), 1 slot.
  2. Attacker immediately sends a bare ACK (`0x10`) on the same 5-tuple (slow path — the SYN was non-cacheable).
  3. `lookup.rs:109` sets `established = true`; `:113-134` recomputes `expires_after_ns = tcp_established_ns` (300 s).
  4. No real peer responded; the attacker holds a 300 s session for 2 packets and refreshes it with one packet per <300 s. The #3152 half-open reap is bypassed — the flood is "SYN+ACK" instead of "SYN".
- Why it matters: #3152 exists specifically to bound `max_sessions` pressure from bare-SYN floods; a real vSRX (syn-check default-on) does not mark ESTABLISHED on a client ACK preceding the server SYN-ACK. The per-source syn-flood caps (#3315) blunt a single high-rate source but not a distributed low-rate SYN+ACK flood, which this converts from cheap-and-short (20 s) into cheap-and-long (300 s).
- Fix direction: gate promotion on evidence of a real handshake — only promote when the ACK arrives on the direction opposite the opening SYN (reverse SYN-ACK seen), or track a two-bit handshake state (saw-SYN/saw-SYNACK/saw-ACK) requiring SYN-ACK before ESTABLISHED.
- Labels: security, dos, tcp-state-machine, vsrx-parity
- Dedup note: not in corpus. #2078 documents that the config knobs (no-syn-check) are accepted-only; it does not cover that the #3152 reap is itself bypassable by a 2-packet SYN+ACK. Distinct root cause from F-138 (SYN-flood inlining, a refactor finding).

### F17. TCP closing/reset state is per-entry and never propagated to the forward↔reverse companion — a one-directional RST/FIN reaps only the half that carried it
- Severity: Medium
- Confidence: Medium
- Evidence: `userspace-dp/src/session/lookup.rs:79-101` mutates only the single matched entry; the reverse companion is a separate `SessionEntry` installed at `shared_ops.rs:836-844` under its own `key_to_handle`:
```rust
if matches!(key.protocol, PROTO_TCP) && is_closing(tcp_flags) {
    entry.closing = true;
    entry.reset |= has_rst(tcp_flags);
}
```
`key_to_handle` is probed first (`lookup.rs:37`), so a packet whose wire tuple equals the reverse key resolves the reverse entry directly and updates only it. No path marks the companion closing/reset.
- Trace:
  1. Bidirectional flow established: forward (300 s) + reverse companion (300 s).
  2. Responder sends a RST (unidirectional); its tuple hits the reverse entry → `closing=true, reset=true` → reverse `expires_after_ns = TCP_RST_TIMEOUT_NS` (2 s).
  3. The forward entry never sees the RST → stays `closing=false`, 300 s.
  4. The dead flow's forward half lingers up to 300 s instead of the 2 s #3046 intends. Symmetric for a one-sided FIN vs #3489's 30 s window.
- Why it matters: #3046's own doc cites "let a reset-flood saturate the session table with dead connections" as the thing the 2 s reap prevents; because the companion is never transitioned, the fast-reap is ~50% effective under a reset workload — every RST-closed flow still pins one established-timeout entry. On vSRX a RST invalidates the whole session.
- Fix direction: when a FIN/RST advances one entry into closing/reset, look up and stamp the same state onto its companion (via `reverse_session_key`/`forward_wire_key`), or track close state once per flow on the canonical forward entry and read through from the reverse.
- Labels: correctness, dos, tcp-state-machine, session-lifecycle
- Dedup note: not in corpus. F-154 (flow cache outlives idle-reaped session) and F-230 (forward+reverse mirror non-atomic vs DeleteSession) are different mechanisms; neither concerns close-state propagation between the two entries.

### F18. `icmp flood` / `udp flood` thresholds are enforced as a single per-zone aggregate rate — Junos measures them per destination IP (UDP: per destination IP + port)
- Severity: Medium
- Confidence: Medium
- Evidence: `userspace-dp/src/screen/mod.rs:157-159` keys the counters by zone name only; `:610-627` uses a zone-wide `get_mut(zone)` counter with no per-destination dimension:
```rust
icmp_counters: FxHashMap<String, RateCounter>,   // keyed by ZONE only
udp_counters:  FxHashMap<String, RateCounter>,
...
if let Some(counter) = self.icmp_counters.get_mut(zone) {
    if counter.increment(now_secs, icmp_flood_threshold) {
        return ScreenVerdict::Drop("icmp-flood");
    }
}
```
Contrast: SYN-flood grew per-dst/per-src count-min sub-thresholds (#3315); ICMP/UDP flood did not.
- Trace:
  1. Junos `icmp flood threshold N` / `udp flood threshold N` cap the rate to a single destination (UDP additionally to a destination port); traffic to different destinations counts independently.
  2. xpf holds one `RateCounter` per zone. Two legitimate high-volume services in the same zone (DNS resolver + VoIP endpoint) sum into one counter; their combined benign rate can cross `threshold` and be dropped as a flood though no single destination is flooded.
  3. Symmetrically, an attacker spreading a modest flood across many destinations stays under the per-zone aggregate while no single victim is rate-limited the way the operator expects.
- Why it matters: the operator configures a per-destination protection knob and gets zone-wide aggregate semantics — false-dropping legitimate multi-service zones and failing to deliver the per-victim cap the Junos threshold promises.
- Fix direction: give ICMP/UDP flood the same per-destination substrate the SYN-flood path has (a per-zone destination-keyed count-min sketch of `RateCounter`s, UDP additionally keyed on destination port), keeping the per-zone aggregate as an optional secondary ceiling.
- Labels: vsrx-parity, correctness, screen
- Dedup note: not in corpus. F-138 is SYN-flood refactor debt; F-244/F-259/F-085 concern the flowless-fragment path. No issue/pr-history hit for icmp/udp flood per-destination vs per-zone.

### F19. Per-destination SYN-flood cap (`destination-threshold`) is bypassed exactly when the zone aggregate is over `attack-threshold` with syn-cookie enabled — contradicting the code's own "always runs" invariant
- Severity: Low
- Confidence: Medium
- Evidence: `userspace-dp/src/screen/mod.rs:665-705` returns (mint challenge, or Drop) on the aggregate `over_attack` branch **before** the per-dst check at `:719-728`, which is documented as always-on:
```rust
// (2) per-DESTINATION cap — PRIMARY, always runs (even when cookie-active).
if syn_dst_threshold > 0
    && let Some(sketch) = self.syn_dst_sketch.get_mut(zone)
    && sketch.increment(&pkt.dst_ip, now_secs, syn_dst_threshold)
{ ... return ScreenVerdict::Drop("syn-flood"); }
```
The test `syn_flood_dest_runs_when_cookie_active` (`tests.rs:2146-2184`) pins per-dst enforcement only with `syn_flood_threshold = 100_000` (aggregate never trips); the `over_attack == true` case is untested.
- Trace:
  1. syn-cookie enabled, `attack-threshold 200`, `destination-threshold 2`.
  2. A real-client (non-spoofed) flood targets one backend and pushes the zone aggregate past 200 → `over_attack == true` on each SYN.
  3. Every SYN takes the `if over_attack { … SynCookieChallenge … }` early-return; the per-dst sketch at `:722` is never reached → the per-destination hard-drop never engages.
  4. Clients completing the cookie handshake are admitted to the backend. `destination-threshold`'s purpose — shield a single over-threshold victim even from validated clients — is defeated precisely in the high-load regime it was configured for.
- Why it matters: an operator who sets `destination-threshold` believes a flooded backend is hard-capped regardless of the zone-wide picture; under a large legitimate-looking flood the cap silently stops applying. A concrete code-vs-comment contradiction that will mislead the next maintainer.
- Fix direction: evaluate the per-dst sketch **before** the aggregate `over_attack` early-return (so a per-dst trip hard-drops even while the zone mints cookies), or correct the comment; add a test with a low `syn_flood_threshold` so `over_attack` fires.
- Labels: correctness, screen, defense-in-depth, docs
- Dedup note: not in corpus. F-138 is the refactor-debt note that this logic is inlined; this is a distinct ordering/invariant bug.

### F20. Junos as-path regex is copied to FRR verbatim with no syntax translation
- Severity: Medium
- Confidence: Medium
- Evidence: compile `pkg/config/compiler_routing.go:585,595` (`ap.Regex = entry.Keys[0]` / `child.Keys[2]`) and render `pkg/frr/policy_render.go:1325` pass the Junos regex through unchanged.
- Trace: Junos as-path regexes are space/term-separated over AS numbers (`"^65000 65001$"`, `.* 64500 .*`), whereas FRR as-path access-lists are POSIX EREs over the `_`-delimited AS_PATH string (`^65000_65001$`, `_64500_`). A canonical Junos as-path definition compiles to an FRR regex that matches the wrong thing — `from as-path` route-map matches silently never fire (or fire on wrong routes). Independent of F2; even after control-char handling the semantics are wrong.
- Why it matters: BGP inbound/outbound policy that filters by AS_PATH silently mis-behaves — a route-leak or filter-bypass class on a security appliance.
- Fix direction: translate Junos as-path syntax to FRR (`_` boundaries, term joining) at compile, or at minimum warn at commit that as-path regexes are passed through and must be written in FRR syntax. Medium confidence — FRR's exact tokenization of these lines was not exhaustively confirmed; worth a focused verify.
- Labels: vsrx-parity, frr, routing, correctness
- Dedup note: not in corpus. #2643/#2892 touch community-list kind and as-path-prepend action; neither addresses as-path match regex syntax translation.

### F21. `operator` login class can `request system zeroize` / reboot / halt / power-off — Junos operator lacks maintenance
- Severity: Medium
- Confidence: High
- Evidence: `pkg/cli/permissions.go:67-68` maps all of `request`/`test` → `PermControl`; `pkg/config/types_system.go:558` gives `"operator": {PermView, PermClear, PermControl}`. So operator holds `PermControl` and passes the gate for `request system zeroize`. The destructive verbs exist at `pkg/cmdtree/tree.go:909-912`.
- Trace: operator user runs `request system zeroize` → `parts[0]="request"` → `PermControl` → operator has it → factory-erase proceeds. On Junos the predefined `operator` class lacks `maintenance`, so it cannot reboot or zeroize.
- Why it matters: xpf grants a destructive maintenance verb to a non-super class — a privilege-model divergence from vSRX on a security appliance.
- Fix direction: add a `maintenance`/`PermMaint` permission for `request system {reboot,halt,power-off,zeroize}` (and cluster failover), granted only to super-user; keep benign `request` verbs at `PermControl`. (Placed in the Medium tier as the confidence on the exact vSRX operator-class capability set is High but the fix is a policy decision; severity Medium.)
- Labels: security, rbac, vsrx-parity
- Dedup note: F-023/F-214/F-055 concern monitor-mapping / unknown-user / sudoers, not the `request`→`PermControl` over-grant. Not in corpus.

### F22. Owner (priority 255) with preempt disabled never reclaims mastership from a lower-priority peer — RFC 5798 §6.1 / vSRX owner semantics violated
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/vrrp/track.go:32-48` passes priority 255 through unchanged; `pkg/vrrp/instance.go:1524-1530` resets the master-down timer on any advert when preempt is off:
```go
if !vi.getPreempt() || int(pkt.Priority) >= pri {
    masterDownTimer.Reset(vi.masterDownInterval())
    ...
}
```
- Trace:
  1. Operator configures the address-owner instance: priority 255, `no-preempt`.
  2. Owner reboots; peer (priority < 255) becomes MASTER and holds the VIP.
  3. Owner returns → `StateBackup`; hears the peer's lower-priority advert → `!getPreempt()` true → `masterDownTimer.Reset` on every advert → owner stays BACKUP indefinitely though it owns the VIP.
  4. A real vSRX owner resumes MASTER immediately.
- Why it matters: narrow (requires owner + preempt disabled) but a real RFC 5798 §6.1 deviation and parity gap — the address owner stranded behind a non-owner is exactly what owner semantics prevent.
- Fix direction: treat priority 255 as unconditionally preempting (force effective preempt=true when `cfg.Priority == 255`), or reject/normalize `no-preempt` on an owner at commit.
- Labels: vsrx-parity, rfc-conformance, ha
- Dedup note: not in corpus; "owner priority 255" appears only as a feature-list bullet.

### F23. HA heartbeat and session-sync channels carry authoritative election state + plaintext session data with no cryptographic authentication
- Severity: Low
- Confidence: High (behavior) / Low (exploitability given a dedicated link)
- Evidence: `pkg/cluster/heartbeat.go:134-290` — wire format is a fixed magic (`"BPFX"`), version, and cleartext RG/priority/weight/state; `heartbeat_manager.go:429-439` accepts any packet whose `ClusterID` matches and `NodeID` differs — no HMAC, no shared secret, no nonce:
```go
if int(pkt.ClusterID) != r.mgr.ClusterID() { ... continue }   // only auth gate
if int(pkt.NodeID) == r.mgr.NodeID() { continue }
r.mgr.handlePeerHeartbeat(pkt)   // drives election directly
```
Session-sync runs over an equally unauthenticated `net.Listener` (`sync.go:233-236`, `sync_conn.go:1108`).
- Trace:
  1. Attacker with L2 access to the control segment learns the 16-bit ClusterID (observable in cleartext).
  2. Forge a heartbeat claiming the peer with `Weight=0` → local `electRG` claims PRIMARY; or forge a higher-priority peer → local forced SECONDARY → controlled failover/blackhole.
  3. Session-sync frames (5-tuples, NAT bindings) traverse the same link in cleartext, readable by the same attacker.
- Why it matters: election is attacker-steerable and session metadata is disclosed on the control segment — a defense-in-depth gap. Mitigating factor (why Low severity): a dedicated operator-controlled link matching Juniper's own unauthenticated direct-cable posture; exploitation presumes an already-reachable control fabric. Note this compounds with F1 (the fabric gRPC listener on the same segment).
- Fix direction: optional PSK HMAC (`set chassis cluster control-link authentication-key`) over heartbeat + sync frames with a monotonic/nonce anti-replay field; document the trust assumption if auth stays out of scope.
- Labels: security, ha, hardening, vsrx-parity
- Dedup note: corpus has many security findings but none on heartbeat/session-sync authentication or plaintext session disclosure (F-087 on-disk key; F-050/F-020 at-rest/redaction; F-190/F-191 WG handshake). This is the HA control/sync channel.

### F24. ESP proposals silently fall back to strongSwan `default` suite when a policy's proposal reference dangles with no PFS group
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/ipsec/ike.go:100-170` — the #2073 fallback only preserves crypto intent when `pfsGroup > 0`; otherwise returns the initial `espProposals = "default"`, and `policy.go:182` emits `esp_proposals = default` unconditionally (no `!= ""` guard, unlike the IKE `proposals` line at `:157`).
- Trace: on the tolerant/peer-sync boot path (strict validator downgraded to warn), an ipsec-policy referencing an undefined proposal with no PFS group → 0 built proposals → `"default"` → strongSwan negotiates its built-in ESP suite instead of the operator's intended cipher/integrity. Asymmetric: IKE skips the VPN (#2270 fail-closed), ESP quietly downgrades.
- Why it matters: a dangling reference silently weakens the ESP crypto posture rather than failing closed.
- Fix direction: emit a conservative fixed fallback (e.g. `aes256-sha256`) or skip the child like the IKE path, even at `pfsGroup == 0`.
- Labels: security, ipsec, vsrx-parity
- Dedup note: not F-017 (auth-alg tokens) or the #2073/#2270 validated-reference/IKE cases — residual ESP `pfsGroup==0`→`default` fall-through.

### F25. DHCPv4 client ignores classless-static-routes (option 121 / legacy 249)
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/dhcp/dhcp.go:948-954` extracts only `ack.Router()`; a grep of `pkg/dhcp/*.go` for 121/249/classless returns nothing — only option 3 (default gateway) is honored.
- Trace: a server offers RFC 3442 option 121 (routes + gateway; supersedes option 3 when present) → xpf drops all option-121 routes → missing/wrong routing on a DHCP uplink.
- Why it matters: vSRX honors classless-static-routes; xpf silently ignores them, a functional/parity gap on DHCP uplinks in provider networks that rely on option 121.
- Fix direction: parse option 121/249 in `leaseFromACKv4`, program via the FRR recompile path, honor RFC 3442 precedence over option 3.
- Labels: vsrx-parity, dhcp, feature-gap
- Dedup note: no corpus entry on DHCP route options.

### F26. `router-advertisement default-lifetime 0` is both commit-rejected and runtime-coerced — xpf cannot advertise "not a default router"
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/config/schema_routing.go:442-444` validator `ValidateInteger(1, 65535)` rejects 0 at commit; `pkg/ra/sender.go:670-672` coerces `DefaultLifetime <= 0` → 1800; `pkg/config/types_routing.go:321` bakes `0 = default (1800)`.
- Trace: an operator who wants xpf to advertise prefixes / PREF64 but NOT be an IPv6 default router (RFC 4861 §6.2.1 RouterLifetime 0) cannot express it — commit rejects 0, and even absent the reject the sender floors to 1800.
- Why it matters: on a multi-router LAN xpf always advertises ≥1800 s Router Lifetime, hijacking host default-route selection; Junos accepts `default-lifetime 0`.
- Fix direction: lower the floor to 0 and distinguish unset from explicit 0 in the sender (`*int`/`bool`) so 0 marshals RouterLifetime:0 while absent still defaults 1800.
- Labels: vsrx-parity, rfc-conformance
- Dedup note: distinct from F-232 (≥65536 upper-bound wrap) and F-233/F-075/F-076/F-077.

## 6.3 Low-confidence findings (design smell / parity / triage)

### F27. Leftover test-environment `is_trust_flow` hardcode gates debug logging in the session-miss cold block — floods on any 10.x LAN
- Severity: Low
- Confidence: High (code state) / Low (it is a smell, not a defect)
- Evidence: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1708-1710`:
```rust
let is_trust_flow = meta.ingress_ifindex == 5
    || from_zone == "lan"
    || matches!(flow.src_ip, IpAddr::V4(ip) if ip.octets()[0] == 10);
```
used at `:1828` (`dbg.session_miss <= 10 || is_trust_flow`) and `:3120` (`dbg.policy_deny <= 3 || is_trust_flow`).
- Trace: any flow ingressing on ifindex 5 (the test VM's `fxp0` slot), OR from a zone literally named `lan`, OR with a 10.0.0.0/8 source, bypasses the `dbg.*` rate caps → those debug lines fire on every such packet. On any real deployment where the LAN is 10.x this defeats the intended throttle for the entire trusted side.
- Why it matters: not a verdict/security bug — affects only debug-log volume — but a test-env magic constant baked into the production cold path that can produce exactly the log flooding CLAUDE.md's Logging Rules warn against.
- Fix direction: drop `is_trust_flow` (let the numeric `dbg.*` caps govern), or move it behind `#[cfg(debug_assertions)]` / an explicit trace-filter config leaf rather than a hardcoded topology guess.
- Labels: code-quality, logging, tech-debt
- Dedup note: grep `is_trust_flow`/`ingress_ifindex == 5` across the corpus = no hit. Nearest is the CLAUDE.md logging-flood guidance and F-051-class observability items, none of which touch this heuristic.

### F28. `compiler_security.go` is a 2357-line grab-bag mixing zones / policies / screen / address-book / log / flow / ALG compile plus a dozen strict validators
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/config/compiler_security.go` (2357 lines) hosts `compileSecurity`, `compileZones`, `compilePolicies`/`compilePolicy`, `compileScreen`, `compileAddressBook`, `compileLog`, `compileFlow`, `compileALG`, plus ~15 log/flow-trace/TCP-MSS AST validators. The dual-AST-shape handling (Keys[1:] vs Children) is re-spelled per call site — `compilePolicy`'s match arm uses an either/or read while the strict gates use `firewallMatchValues` (which reads both).
- Trace: N/A (refactor).
- Why it matters: the either/or vs read-both divergence between `compilePolicy` and the strict validators is exactly the shape that produced past fail-opens (the #2419 bracketed-list class); a policy-focused module split with one shared match-value reader would make a future divergence a compile error rather than a silent drop.
- Fix direction: extract `security/{zones,policy,addressbook,flow,alg}.go` from `compiler_security.go` and route `compilePolicy`'s source-address / destination-address / application reads through `firewallMatchValues` so the compiler and the strict gates share one SSOT.
- Labels: refactor, tech-debt
- Dedup note: F-205 (dual-AST-shape grammar duplicated) names the pattern but proposes no module split for the security compiler; F-206 is NAT-specific. This is the security-side analog. Reported honestly for completeness; low value.

## 7. Suggested issue split

Group the 28 findings into these issues for triage/fix:

**A — Config-injection into root daemons (High, ship first):**
- F2 (FRR community/as-path → frr.conf injection) + F20 (as-path syntax) — same file, one PR.
- F4 (IPsec traffic-selector → swanctl/updown RCE).

**B — Management-surface authz & secret exposure (High):**
- F1 (fabric gRPC full service unauth) + F23 (heartbeat/sync unauth) — same control-segment threat model.
- F3 (CLI `show configuration` not redacted).
- F21 (operator can zeroize) + F8 (SystemAction not audited) — RBAC/audit for destructive verbs.

**C — WireGuard hardening (Medium):**
- F5 (TAI64N high-water reset) + F12 (key/PSK not zeroized) — same `wg/` build path.

**D — DHCP client untrusted-input (Medium):**
- F6 (degenerate subnet mask → /0) + F25 (classless-static-routes) — same `leaseFromACKv4`.

**E — Screen/IDS parity & correctness (Medium):**
- F11 (port-scan unit inversion), F18 (icmp/udp per-zone vs per-dst), F19 (syn-dst ordering) — one screen-semantics PR + tests.

**F — TCP session state machine (Medium):**
- F16 (ACK-only promotion) + F17 (companion close propagation) + F15 (paired tests) — one `session/` PR.

**G — VRRP RFC conformance (Medium):**
- F10 (IPv4 pseudo-header checksum) + F22 (owner preempt) — one `pkg/vrrp` PR.

**H — vSRX feature parity (Medium/Low):**
- F14 (predefined application-sets), F26 (RA default-lifetime 0), F24 (ESP default fallback).

**I — Dataplane HPC / observability (Low):**
- F7 (forced trace insert) + F13 (fallback stats per-CPU) — same `userspace-xdp/src/lib.rs`, plus F27 (`is_trust_flow` log smell).

**J — NAT (Low):**
- F9 (ICMP id-0 collision) — extends the #4074 fix.

**K — Refactor/tech-debt (Low):**
- F28 (`compiler_security.go` split with shared match-value reader).

**Coverage caveat carried forward:** `pkg/api` (REST) received only a thin pass
this campaign (budget-limited); F-155/F-197 remain, and a dedicated API pass
(SSE/exec goroutine leaks, request-body size limits, HTTP method/path handling)
is recommended for the next round and was explicitly NOT completed here.
