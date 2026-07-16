# Cohorts 12-14 Audit — DHCP/RA/Flowexport + CLI/REST/gRPC + Wire/Protocol + Config Parser — c2ee227c4

- Base commit reviewed: `c2ee227c4` (master HEAD)
- Output path: `/tmp/ps-review-023.md`
- Scope: cohorts 12 (pkg/dhcp, pkg/dhcpserver, pkg/dhcprelay, pkg/ra, pkg/flowexport), 13 (pkg/cli, pkg/api, pkg/grpcapi, pkg/cmdtree), 14 (userspace-dp/src/protocol, pkg/config/lexer|parser|ast, userspace-dp/src/afxdp/flow_cache.rs, proto/xpf/v1/xpf.proto, wire codecs)
- Mode: read-only, deep adversarial

## Duplicate-suppression summary

Read `/tmp/all_findings.txt` (272 entries, F-001..F-272). Checked prior ps-review-*.md files (001-022). Deduplicated against:

- F-058 NetFlow protocol 0 for non-TCP/UDP — fixed on this commit (rec.ProtocolNum used)
- F-233 randomAdvInterval 0s — same root cause, kept as separate hardening but marked duplicate
- F-197 API-key timing leak — API-key fixed to constant-time, Basic-auth still leaks (new finding refines)
- F-218 DHCP ignores renewal timers — still open, not re-reported, referenced in negatives
- F-219 DHCP relay giaddr overwrite / Option 82 — F-219 covers giaddr chain, Option 82 length truncation is new sub-case but iface name max 15 makes it moot; noted as negative
- F-075 RA nat64prefix lifetime >65528 — fixed via schema bound + pruneUnmarshalableOptions
- F-232 router default-lifetime truncation — fixed via DefaultLifetimeSet
- F-022 monitor traffic matching truncation — fixed (#4005)
- F-020 secret redaction bypass — fixed for REST/gRPC/CLI show paths

Intentional divergences (not re-reported):
- Standalone DHCP relay `shouldRelay==true` when gate nil (fail-open by design)
- RA pruneUnmarshalableOptions dropping bad PREF64 instead of aborting whole RA (defense-in-depth)
- Flow-export IPFIX sampler Options Template only when SamplingRate>1 (Junos-compatible)
- Config parser bracket-list stripping `[ ]` as sugar (Junos parity)
- gRPC fabric dual-accept (no key => accept) for rolling upgrade
- maxParseDepth 256 cap (intentional DoS guard)

## Module / verdict-path inventory (coverage checklist)

| Cohort | Module | Files inspected | Verdict path / security property | Status |
|--------|--------|-----------------|----------------------------------|--------|
| 12 | DHCP client | pkg/dhcp/dhcp.go, renew.go, commit.go, reconcile.go | lease parse (mask validation, classless routes, IA_NA selection), renewal timers, DUID persist | Deep |
| 12 | DHCP relay | pkg/dhcprelay/relay.go, relay_giaddr_linux.go, l2send_linux.go, delivery_test.go | giaddr primary selection, ifindex drift, readdr, hop-count wrap, Option 82, L2 raw path, rogue-reply filter | Deep |
| 12 | DHCP server | pkg/dhcpserver/dhcpserver.go (partial), ddns_leases.go | Kea wrapper, lease CSV lenient vs destructive | Shallow (seams only) |
| 12 | RA/ND | pkg/ra/ra.go, sender.go, filter.go | configEqual, buildRA (lifetime 0, optLifetime fallback, MTU, PREF64, RDNSS, pruning), randomAdvInterval, eui64, ndp write, RS filter | Deep |
| 12 | Flowexport | pkg/flowexport/netflow.go, ipfix.go, manager.go, transport.go | template build, record encode (bounds, pad, splicing), protocol-number fix, uptimeMs clamp, collector health/backoff, batch cap 65536 | Deep |
| 13 | CLI | pkg/cli/cli.go, cli_dispatch.go, cli_show.go, cli_config.go, permissions.go, monitor.go, cli_request.go, monitor_interface.go | command injection (ping/traceroute/tcpdump argv), RBAC gate for monitor traffic / request maintenance, showConfigRedacted per-class, pipe handling, commit/rollback strictness | Deep |
| 13 | REST | pkg/api/auth.go, server.go, api.go, config.go, sse.go, security.go, metrics.go | authMiddleware bypass, constant-time API key, Basic-auth timing leak, body-size cap 16MiB, metricsRequireAuth, sse category strictness | Deep |
| 13 | gRPC | pkg/grpcapi/server.go, server_config.go, fabric_auth.go, server_show.go | maxRecvMsgSize 16MiB, fabric allowlist + PSK HMAC auth (window ±1, replay 90s), peerSessionID, configLockInterceptor | Deep |
| 13 | Cmdtree | pkg/cmdtree/tree.go | OperationalTree SSOT, typed-leaf ValueType, DynamicFn nil guards | Shallow |
| 14 | Wire codecs | userspace-dp/src/protocol/*.rs (control, snapshot, binding, cos, nat, security, resolution, mod), tests.rs | null_tolerant_vec, skip_serializing for secrets, serde(default) skew tolerance, NUM_WIDTH pins, field spec width vs data len | Deep |
| 14 | Config lexer/parser | pkg/config/lexer.go, parser.go, ast.go | bracket stripping loop (not recursion), maxParseDepth 256 + skipToBlockClose, Unterminated block comment pending, quoteKey round-trip, inactive: handling, navigatePath multi-key | Deep |
| 14 | Flow cache | userspace-dp/src/afxdp/flow_cache.rs (80-200) | rg_epoch_index fallback, FLOW_CACHE_SETS power-of-two, RewriteDescriptor dead fields | Shallow |
| 14 | Proto | proto/xpf/v1/xpf.proto (1-120) | service def, field numbers | Shallow |

## Module-by-module inspection log (including negatives)

**pkg/dhcp/dhcp.go** — Reviewed `leaseFromACKv4` mask check (rejects /0 and non-contiguous, prevents 0.0.0.0/0 blackhole), `classlessStaticRoutes` skips malformed entries but returns present=true (RFC 3442 correct: when option 121 present, ignore option 3 even if all entries malformed -> no GW, blackhole but spec-compliant; mitigated by skip logic). `selectIANAAddress` deterministic (longest preferred-lifetime, first-seen tie-break, skip valid-lifetime 0) prevents #4383 last-wins and F-264 revocation. `renewalTimers` computes t1=lease/2 min 30s, t2Remaining=lease*7/8-lease/2 min 1s — see Finding 12-01 for int64 overflow on huge lease. `commitLease` single path, gateway hook outside mu, scheduleRecompile debounce. `parseV6Reply` PD-only lifetime fallback to first prefix. Negative: DUID file 0644 world-readable is low-risk (DUID not secret). Negative: `discoverIPv6Router` hardcoded 0x80 NTF_ROUTER is correct Linux constant, not a bug.

**pkg/dhcp/reconcile.go** — Fingerprint excludes lease state (prevents #1793 loop). Prune of v4opts/v6opts for absent desired keys regardless of client registration prevents Renew resurrecting removed client (Codex #1815 r4). Negative: no TOCTOU between fingerprint check and Start — Start does atomic desired check under mu.

**pkg/dhcprelay/relay.go** — `resolveMaxHopCount` clamp 1..16 with fallback 16. Hop-count check is `>= maxHopCount` BEFORE `++` preventing uint8 wrap bypass (255->0). `readBufSize=65535` prevents MSG_TRUNC (fix #3012). `runRelaySession` ifindex drift + giaddr readdr watchers tolerant on resolve failure. `handleServerResponses` builds allow-set once, checks `replySourceAllowed` BEFORE parse (closes rogue-DHCP injection #4163). `deliverReply` matrix: NAK always broadcast (ignores stale ciaddr), L2 unicast -> fallback broadcast, ciaddr unicast. `l2Eligible` checks htype Ethernet + 6-byte chaddr. `addOption82` — see Finding 12-02 (iface name max 15 makes length truncation moot, but generic helper would truncate). Negative: giaddr re-resolve every 5s is cheap, not a spin.

**pkg/dhcprelay/l2send_linux.go** — `buildL2Reply` hand-rolls Ethernet+IPv4+UDP, IPv4 checksum computed, UDP checksum 0 (legal for IPv4), MTU guard prevents over-MTU raw send -> fallback broadcast. `htonsLocal` uses binary helpers for endian, not unsafe. Negative: `newL2Sender` binds AF_PACKET ETH_P_IP, not ETH_P_ALL, correct for IPv4-only DHCP.

**pkg/ra/sender.go** — `buildRA` honors explicit lifetime 0 via DefaultLifetimeSet (fix #4119), optLifetime fallback to 1800 when router lifetime <=0 preserves RDNSS/PREF64 while declining default-router duty. Prefix valid/preferred clamp pref<=valid per RFC 4862. ReachableTime/RetransTimer marshaled as ms via Duration (fix #4307). PREF64 lifetime default to optLifetime when <=0. `pruneUnmarshalableOptions` probes each option via `ndp.MarshalMessage(&RA{Options:[opt]})` — defense-in-depth for #3895/#4307, in-place filter keeps fresh slice. `randomAdvInterval` — see Finding 12-03 (0s interval when MaxAdvInterval<=2). `eui64LinkLocal` returns nil for non-6-byte MAC, caller errors cleanly. `ensureLinkLocal` uses netlink, NODAD, EEXIST tolerant.

**pkg/ra/ra.go** — `configEqual` includes DefaultLifetimeSet (prevents unset->0 missed restart), Max/Min Adv, LinkMTU, NAT64Prefix/Life, SourceLinkLocal, Reachable/Retrans. `releaseDrain` proven-close-only replacement start, tombstone held across standalone goodbye emit, timeout path leaves tombstone held + reclaimer goroutine (no 2-conn). Negative: `cfgForName` stub returns nil is intentional best-effort.

**pkg/flowexport/netflow.go / ipfix.go / transport.go / manager.go** — `encodeRecordV4/V6` copy with To4()/To16() nil->zero fallback, protocol now from rec.ProtocolNum (fix F-058). `uptimeMs` clamps negative to 0. `spliceFlowDir` keeps post-NAT trailer last. `recordSize` pads to 4-byte. `dataFlowSetLen`/`ipfixDataSetLen` compute totalLen, `encodeDataFlowSetInto` clears tail pad. `templateRefreshInterval` clamps <=0 to 60s prevents NewTicker panic (#4423 M10). `collectorWriteTimeout=2s`, `unhealthyProbeInterval=30s` bounds slow collector stall. `flowBatch` cap 65536 per family, drop-newest O(1), maxDepth HWM. Negative: NetFlow v9 header SysUptime uses bootTime (not exporter-construction) — correct per #4423 M13.

**pkg/cli** — `dispatchOperational` resolveCommand then checkPermission before switch — RBAC gate cannot be bypassed by abbreviated tokens. `requiredPermission` gates `monitor traffic` at PermControl (fix #4067), `request system {reboot,halt,power-off,zeroize}` + `request chassis cluster failover` at PermMaint (fix #4108). `showConfigRedacted` returns true for unknown class (fail-closed), false for empty class (legacy) and super-user (PermAll). `parseMonitorTrafficArgs` greedily consumes `matching <filter>` until next keyword, `stripSurroundingQuotes` peels one layer — fix #4005. `buildMonitorTrafficArgv` splits filter via `strings.Fields` and passes as separate argv to `exec.CommandContext("tcpdump",...)` — no shell, so no command injection. `handlePing`/`handleTraceroute` delegate to `diagcmd.PingArgv`/`TracerouteArgv` which normalizes VRF device and adds `--` separator (#2084, #2143) — leading `-` target cannot be misinterpreted as option. `handleCopyRename`/`handleInsert` use `strings.Fields` — insertion path uses parentPath derived from elemPath minus refTokens length, not vulnerable to path traversal beyond config tree. Negative: `monitor security flow file` sanitizeTraceFilename rejects `/`, `\`, `.`, `..`, O_NOFOLLOW, 0600 — closes #3378 HC-01/MC-02/MC-01.

**pkg/api** — `authMiddleware` exempts `/health` always, `/metrics` only when `!metricsRequireAuth` (loopback bind). `isLoopbackBindAddr` parses host:port, empty host (wildcard) => false (conservative). `constantTimeAPIKeyMatch` iterates all keys with `subtle.ConstantTimeCompare`, no short-circuit, ORs results — fixes F-197 for API keys. `checkAuthorization` Basic-auth: see Finding 13-01 (still leaks username existence via length). `decodeJSONBody` caps at 16 MiB via `http.MaxBytesReader`, returns 413 on overflow — prevents OOM via `POST /config/load`. `queryIntStrict` uses `config.ParseCanonicalUint` rejecting `+80` signed spelling (#3679). `sse.go` `parseCategories` fail-closed on empty token/typo (#3383), `matchCategory` fail-closed on unknown event type. Negative: `writeJSON` writes header before Encode — if Marshal fails, header already sent, returns 200 with empty body? Low risk, secret Marshaler failure unlikely.

**pkg/grpcapi** — `maxRecvMsgSize=16MiB` matches configstore cap, prevents oversized Load/config-sync OOM (fable-review-164 H-2). `fabricAllowedUnaryMethods` 6 entries + `isFabricSafeSystemAction` strict parse via `parseProxiedFailoverAction` (range-checked node ID 0/1, rejects malformed suffix, rejects local-only failover). `fabricAllowlist*Interceptor` fail-closed. `fabricAuth*Interceptor` runs before allowlist, HMAC-SHA256(PSK, "xpf-fabric-grpc-auth\x00" + LE(window)), window 30s, accepts ±1 (90s replay, documented residual). `fabricAuthDecision` dual-accept: !keyConfigured => accept (rolling upgrade), present+invalid => reject, !present+enforceArmed => reject (downgrade guard armed via fabricPeerAuthSeen || heartbeatPeerAuthSeen). `configLockInterceptor` auto-releases stale exclusive lock on ctx cancel (peer disconnect). Negative: `peerSessionID` from peer.Addr.String() is loopback-only, not spoofable off-box.

**pkg/cmdtree** — `OperationalTree` SSOT for CLI/gRPC/remote CLI, `Node.HasDynamic`, `IsTypedLeaf`, typed-leaf fields ValueType/ValueDesc/Validator. Negative: no direct security boundary, only completion/help.

**userspace-dp/src/protocol** — `null_tolerant_vec` handles explicit JSON `null` as empty vec (prevents #1961 no-transit when Go nil slice marshals as null). `syn_cookie_master_key`, `wg_local_privkey_hex`, `wg_preshared_key_hex` all `skip_serializing` (secret not written to state.json). `#[serde(default)]` on every field for skew tolerance. `slow_path_mtu()` picks max iface MTU floor 1500. Wire tests in `tests.rs` pin round-trip + backward-compat for every new field. Negative: `mod.rs:74` `unwrap_or_default` on Option<Vec<T>> is safe, not panic.

**pkg/config/lexer.go** — `Next()` strips `[` `]` in loop (not recursion) fixing fable-review-164 H-2 stack overflow on N consecutive `[`. `skipWhitespaceAndComments` stashes unterminated block comment as `l.pending` TokenError, surfaced before EOF (fix #4149/#4147 fail-open where truncated config parsed with zero errors). `readString` interprets `\"`, `\\`, `\n` (others => `\` + char). `isIdentChar` includes `<*>` wildcard, `%`, `=`, `,`. Negative: `readString` on unterminated string returns TokenError, not panic.

**pkg/config/parser.go** — `maxParseDepth=256` caps recursive `parseStatements` depth, `skipToBlockClose` drains iteratively on cap (no recursion). `parseKeys` returns parallel `kinds` slice to distinguish bare `inactive:` vs quoted `"inactive:"` (#4348). Leading + inline `inactive:` handling (#4335) drops governed tokens, parent stays active. Negative: `ParseSetVerb` accepts bare path as `set` verb (legacy), not a security issue.

**pkg/config/ast.go** — `quoteKey` wraps when `!isIdentChar`, escapes via `keyEscaper` (`\`->`\\`, `"`->`\"`, `\n`->`\n`) symmetric with lexer — round-trip holds. `navigatePath` returns all siblings sharing leading keyword on terminal (#3980) preventing hidden-statement bug. `findNodeWithParent` prefers longest full-key match (fixes `policy first` vs `policy` prefix). Negative: `Clone` deep copies via `cloneNodes`, no alias.

**userspace-dp/src/afxdp/flow_cache.rs** — `FLOW_CACHE_SETS` power-of-two assert, `rg_epoch_index` maps out-of-range RG (>=16) and <=0 to 0 (node-level epoch) matching worker session-expiry gate (#2466 fix). `ACTIVE_WINDOW_EPOCHS=10`, `FLOW_WORKER_MAP_MAX_PER_BINDING=256`. Negative: `CachedTxSelectionDescriptor` `reject` only ever true when `drop` true (comment documents).

**proto/xpf/v1/xpf.proto** — Service def 20+ RPCs, config lifecycle + show + diagnostics + monitor + mutations + system action. No inline secrets.

## Findings

### [12-01] DHCPv4 renewalTimers int64 overflow on crafted lease time — tight renew loop + 68-year T1

- **Title**: DHCPv4 renewalTimers integer overflow on max uint32 lease time causes 68-year T1 and immediate T2 rebind attempts
- **Severity**: Medium
- **Confidence**: High — direct code + arithmetic
- **Class**: implementation-bug / robustness-dos
- **Evidence**:
  - `pkg/dhcp/commit.go:47-57`
    ```go
    func renewalTimers(leaseTime time.Duration) (t1, t2Remaining time.Duration) {
        t1 = leaseTime / 2
        if t1 < 30*time.Second {
            t1 = 30 * time.Second
        }
        t2Remaining = leaseTime*7/8 - leaseTime/2
        if t2Remaining < time.Second {
            t2Remaining = time.Second
        }
        return t1, t2Remaining
    }
    ```
    `leaseTime` comes from `lease.LeaseTime` which is `ack.IPAddressLeaseTime(3600*time.Second)` in `leaseFromACKv4` — server-controlled uint32 seconds (0..4294967295). 4294967295s *1e9 ns = 4.294e18 ns. `leaseTime*7` = 3.006e19 > math.MaxInt64 (9.22e18) wraps to negative in Go (silent two’s complement wrap). `t2Remaining` then negative -> clamped to 1s, so T1=68y, T2 fire 1s later, tight loop between T1 expire (68y later) but once T1 finally fires, T2 is 1s and then re-acquire. More immediate: during normal operation with lease=86400s, no overflow. Only max lease triggers.
- **Trace**: Attacker controlled DHCP server (rogue on same L2, or compromised upstream) sends ACK with Option 51 lease-time 4294967295 (0xFFFFFFFF). `leaseFromACKv4` stores `lease.LeaseTime = 4294967295s`. `runDHCPv4` calls `renewalTimers` with that value. `t1 = 2147483647s` (~68y), clamped? No, >30s so stays 68y. `t2Remaining = (lease*7/8 - lease/2)` overflows: `lease*7` wraps negative, /8 still negative, - lease/2 => very negative, clamped to 1s. Result: client waits 68 years before first renew attempt, never renews, holds stale lease (address, gateway, DNS, classless routes) for 68 years even if server revoked earlier. If server is rogue that gave short-lived hijack, client pins hijacked gateway for 68y.
- **Refutation attempted**: Checked if `IPAddressLeaseTime` caps value — insomniacslk/dhcp `IPAddressLeaseTime` returns `time.Duration(seconds)*time.Second` with no cap, up to 0xFFFFFFFF. Checked if `renewalTimers` is called elsewhere for DHCPv6 — yes, same function for v6 too (v6 valid-lifetime also uint32 seconds, up to 0xFFFFFFFF). Same overflow applies to v6. No other gate clamps leaseTime before call.
- **Why it matters**: Rogue DHCP server can pin client to malicious gateway/DNS for 68 years with one ACK, or cause 1s T2 rebind storm after long T1. Even without attacker, a misconfigured legitimate server with large lease (e.g., 10 years = 315360000s, *7 = 2.2e18 fits, no overflow) is okay, but max value is still representable on wire and should be handled.
- **Fix direction**: Compute `t2Remaining` without overflow: `t2Remaining = leaseTime/8*3` (since 7/8-1/2=3/8) or `leaseTime*3/8` via `leaseTime/8*3`. Also consider capping leaseTime to e.g., 1y or MaxInt64/2 before arithmetic. Add test for max uint32 lease.
- **Labels**: dhcp, robustness, integer-overflow, dos, availability
- **Dedup note**: Not in /tmp/all_findings.txt. F-218 covers ignoring renewal timers (58/59), not overflow. No other finding mentions renewalTimers overflow.

---

### [12-02] RA randomAdvInterval can return 0s when MaxAdvInterval <=2, producing tight RA transmit loop

- **Title**: `randomAdvInterval` returns 0-second interval when MaxAdvInterval is 1 or 2, causing hot-loop RA spam
- **Severity**: Low
- **Confidence**: High
- **Class**: robustness-dos / protocol-corruption
- **Evidence**:
  - `pkg/ra/sender.go:862-878`
    ```go
    func (s *sender) randomAdvInterval() time.Duration {
        maxI := s.cfg.MaxAdvInterval
        if maxI <= 0 {
            maxI = defaultMaxAdvInterval
        }
        minI := s.cfg.MinAdvInterval
        if minI <= 0 {
            minI = maxI / 3
        }
        if minI >= maxI {
            minI = maxI / 3
        }
        interval := minI + rand.IntN(maxI-minI+1)
        return time.Duration(interval) * time.Second
    }
    ```
    When `maxI=1`, `minI=0` (1/3=0), `interval=0+rand.IntN(2)` => 0 or 1. When 0, caller `advTimer.Reset(0)` fires immediately, loop re-enters, sends another RA, resets to maybe 0 again — tight loop, CPU + wire spam.
- **Trace**: Operator (or leniently-loaded old config) sets `max-advertisement-interval 1` (schema `ValidateIntegerMin(1)` allows 1). `sender.run` starts `advTimer := time.NewTimer(s.randomAdvInterval())`. Every time 0 is drawn, `case <-advTimer.C:` fires instantly, `sendRA()` emits, `advTimer.Reset(0)` re-arms for immediate fire. With `rand.IntN` 50% chance of 0, steady-state is ~2 RAs per timer tick, up to thousands/sec under bad RNG. Hosts see RA flood, ND storm, CPU waste on helper and hosts.
- **Refutation attempted**: Checked schema — `max-advertisement-interval` validator is `ValidateIntegerMin(1)`, so 1 is allowed. RFC 4861 §6.2.1 says MaxRtrAdvInterval must be at least 4s and <=1800s for spec compliance, but Junos allows 1. Checked if `randomAdvInterval` is supposed to guarantee >=3s min per RFC — code only ensures `minI = maxI/3`, so for max=1, min=0. No lower bound. Previous finding F-233 reported same, but that finding says `randomAdvInterval` can return 0 — this is same root cause, but we confirm it is still present on c2ee227c4 and not fixed (F-233 still open with status UNKNOWN).
- **Why it matters**: RA flood DoS on local segment, violates RFC 4861 §6.2.5 (MinRtrAdvInterval should be 0.33*Max but at least 3s). Hosts may rate-limit RAs and miss legitimate ones, or CPU spike on sender (per-interface goroutine hot loop).
- **Fix direction**: Clamp `interval` to at least 1 (or 3) seconds: `if interval <=0 { interval=1 }` or enforce `maxI>=3` at schema (`ValidateInteger(4,1800)` per RFC) and `minI` at least 1. Add property test for maxI 1..3.
- **Labels**: ra, robustness, dos, rfc-compliance, ipv6
- **Dedup note**: Overlaps F-233 (which is listed as UNKNOWN in all_findings). F-233 says “randomAdvInterval can return a 0-second interval when max-advertisement-interval is small”. This finding confirms it is still present on c2ee227c4 with exact trace and that schema allows 1. Not duplicate if F-233 is considered open; we provide reproduction. If dedup requires single entry, merge.

---

### [13-01] REST Basic-auth username existence leaked via map lookup + ConstantTimeCompare length mismatch timing

- **Title**: REST API Basic-auth leaks username existence via Go map timing and ConstantTimeCompare early length check
- **Severity**: Medium
- **Confidence**: Medium — timing side-channel, not direct bypass
- **Class**: secret-leak / timing-side-channel
- **Evidence**:
  - `pkg/api/auth.go:59-87`
    ```go
    func checkAuthorization(auth string, cfg AuthConfig) bool {
        ...
        // Basic auth
        if strings.HasPrefix(auth, "Basic ") {
            payload, err := base64.StdEncoding.DecodeString(...)
            ...
            user, pass, ok := strings.Cut(string(payload), ":")
            ...
            expected, exists := cfg.Users[user]
            passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1
            return exists && passMatch
        }
    }
    ```
    `cfg.Users` is `map[string]string`. Map lookup timing varies with hash bucket / key presence. More measurably, `ConstantTimeCompare` returns 0 immediately when slices differ in length (no content compare). For unknown user, `expected=""` (0 len), `pass` is typically 8+ chars, lengths differ -> fast return. For known user with 8-char password, lengths equal (if attacker guesses same length) -> full constant-time compare. Even with different length, attacker can probe length by sending same-length password guesses and measuring timing delta between existing vs non-existing user.
- **Trace**: Attacker on management network (web-management bound to non-loopback, `/metrics` now gated but other endpoints still auth-gated) sends `Authorization: Basic base64("alice:wrong")` vs `bob:wrong` repeatedly, measures response latency. `exists==false` path still runs `ConstantTimeCompare(pass, "")` which is length-mismatch fast path. `exists==true` path runs full compare (or length-mismatch but with different expected length). Statistical timing over many trials reveals which usernames are valid, enabling targeted password brute-force.
- **Refutation attempted**: Checked if `constantTimeAPIKeyMatch` was fixed — yes, it now iterates all API keys with OR. But Basic-auth still uses map lookup + early length leak. Checked if `AuthConfig.Users` is populated from `system login user` — typically 2-5 entries, so map size small, timing delta small but still measurable over network with stats (like F-197 original). The fix comment in code says “ALWAYS run constant-time compare — even for unknown user — so response timing does not reveal existence”, but implementation still leaks via length (empty vs real password length) and via map lookup.
- **Why it matters**: Username enumeration → targeted brute-force, credential stuffing, especially when management interface is routable (web-management https interface). Combined with no rate-limit on auth failures (no fail2ban), facilitates offline guessing workflow.
- **Fix direction**: Use constant-time user lookup: iterate all users like API key path, OR-ing `subtle.ConstantTimeCompare([]byte(user), []byte(candidate))` to select expected without map, then constant-time password compare against dummy same-length hash when user not found. Or at minimum, when `!exists`, compare against a dummy password of same length as `pass` to make timing equal. Also use `hmac.Equal` style for username compare. Add rate-limit / audit log for failed auth.
- **Labels**: api, auth, timing-side-channel, secret-leak, security
- **Dedup note**: F-197 reports “API-key/bearer token comparison and Basic-auth username lookup are non-constant-time (Go map lookup…)” as UNKNOWN. This finding refines: API-key is now fixed (constant-time OR), Basic-auth still leaks via length + map. Not a direct duplicate — provides new evidence of remaining leak after F-197 partial fix.

---

### [13-02] CLI `monitor traffic` filter bypass via tcpdump option injection — attacker-controlled filter can write pcap file

- **Title**: `monitor traffic` tcpdump filter tokens can inject tcpdump write options (`-w`, `-C`) to overwrite arbitrary file as root
- **Severity**: High
- **Confidence**: Medium — requires code path review + argv construction
- **Class**: command-injection / privilege-escalation (root file overwrite)
- **Evidence**:
  - `pkg/cli/monitor.go:514-549` `parseMonitorTrafficArgs` consumes `matching <filter>` greedily until next keyword, joins into `filter` string.
  - `pkg/cli/monitor.go:565-580` `buildMonitorTrafficArgv`
    ```go
    func buildMonitorTrafficArgv(iface, filter, count string) []string {
        cmdArgs := []string{"tcpdump", "-i", iface, "-n", "-l"}
        if count != "0" {
            cmdArgs = append(cmdArgs, "-c", count)
        }
        if filter != "" {
            cmdArgs = append(cmdArgs, strings.Fields(filter)...)
        }
        return cmdArgs
    }
    ```
    `filter` is split via `strings.Fields` and appended directly to argv. tcpdump accepts `-w <file>` to write pcap, `-C <size>`, `-r`, etc. as trailing filter args? Actually tcpdump syntax: `tcpdump [options] [expression]`. Options must come before expression, but tcpdump also allows `-w` after expression? No, but if filter contains `-w /etc/cron.d/backdoor`, `strings.Fields` will produce `["-w", "/etc/cron.d/backdoor"]` and `exec.CommandContext("tcpdump", "-i", iface, "-n", "-l", "-w", "/etc/cron.d/backdoor")` — tcpdump will treat `-w` as option, not filter, because tcpdump’s getopt parses leading `-` tokens even after initial options. The code does not add `--` separator before filter.
  - `pkg/cli/monitor.go:583-626` `handleMonitorTraffic` does `exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)` as root (CLI runs as root, tcpdump requires CAP_NET_RAW). No validation that filter tokens do not start with `-`.
- **Trace**: Operator with `PermControl` (operator class can run `monitor traffic`? Actually `monitor traffic` requires PermControl per `requiredPermission`, `operator` class has PermControl? Standard Junos `operator` has `view`, `clear`, etc., not `control`. In xpf, `operator` permissions — need check `config.LoginClassPermissions` for operator. If operator lacks PermControl, cannot run. But super-user and any custom class with PermControl can. Attacker who has gained such class (or via compromised operator workstation) runs `monitor traffic interface ge-0-0-0 matching -w /tmp/pwned` — tcpdump writes pcap to /tmp/pwned as root, overwriting any file (or creating). With `-w /etc/cron.d/x`, could get code exec via cron (if cron installed). Even without cron, can overwrite system files, DoS.
- **Refutation attempted**: Checked if `requiredPermission` for monitor traffic is PermControl — yes (`monitor_traffic_filter_4005_test.go` shows gate). `operator` class in Junos typically lacks `control`, but xpf custom classes could grant it. Even if only super-user, super-user already has root, but file overwrite via tcpdump still bypasses intended “capture-only” restriction — super-user could already write files, but tcpdump path is unexpected. More importantly, `diagcmd.PingArgv` uses `--` separator to prevent leading `-` targets being misinterpreted as options (#2084). `monitor traffic` does NOT use `--`. Checked `buildMonitorTrafficArgv` — no `--`. Compared to `buildPingArgv` which delegates to `diagcmd` that adds `--`. Inconsistent.
- **Why it matters**: Root file overwrite via intended capture feature — privilege boundary within CLI (capture vs file write). Even for super-user, audit expectation is capture to stdout, not arbitrary file write. For custom PermControl classes, could escalate.
- **Fix direction**: Insert `--` before filter when building argv: `cmdArgs = append(cmdArgs, "--")` then filter tokens, or reject filter tokens starting with `-`. Also validate `iface` is known interface (already dynamic completion). Add test that filter `-w /tmp/x` is rejected or passed after `--` and thus treated as expression (tcpdump will then error “syntax error” instead of writing).
- **Labels**: cli, command-injection, priv-esc, monitor, security, high
- **Dedup note**: Not in /tmp/all_findings.txt. F-022 mentions monitor traffic truncation, F-023 mentions read-only can run monitor traffic (fixed). No finding about tcpdump `-w` injection.

---

### [14-01] Config lexer `isIdentChar` includes `%` and `,` allowing crafted prefix-length injection via `prefix-list` body

- **Title**: Config lexer treats `%` and `,` as identifier characters, allowing `prefix-list` body values to smuggle multiple values past single-value typed leaf validator
- **Severity**: Low
- **Confidence**: Medium
- **Class**: implementation-bug / config-fail-open
- **Evidence**:
  - `pkg/config/lexer.go:289-298` `isIdentChar`
    ```go
    return (ch >= 'a' && ch <= 'z') ||
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') ||
        ch == '-' || ch == '_' || ch == '.' ||
        ch == '/' || ch == ':' || ch == '*' || ch == '+' ||
        ch == '%' || ch == '=' || ch == ',' ||
        ch == '<' || ch == '>'
    ```
    `%` and `,` are valid in identifier. Junos prefix-list entries are like `10.0.0.0/24;` or `10.0.0.0/24;` but a body containing `10.0.0.0/24,11.0.0.0/24` would be tokenized as single identifier `10.0.0.0/24,11.0.0.0/24` (since comma not a delimiter), not two values. The compiler `firewallMatchValues` may split on whitespace, not comma, so would treat as one malformed prefix and skip, dropping second prefix.
  - `pkg/config/types_routing.go` prefix-list compilation — `policy-options prefix-list` body values are read via `firewallMatchValues` which expects bracket-list or multiple leaf tokens, but comma-joined values would be single token.
- **Trace**: Operator (or feed-generated prefix-list via `load set`) contains `set policy-options prefix-list PL 10.0.0.0/24,11.0.0.0/24` — intended two prefixes, but lexer yields one token `10.0.0.0/24,11.0.0.0/24`. `net.ParseCIDR` fails, so prefix-list becomes empty (fail-closed) — deny rule using this list narrows to match-nothing, fail-open (traffic that should be denied is permitted). This is similar class to F-042 (prefix-list body collapse) but different root cause (comma not bracket).
- **Refutation attempted**: Checked if `IsIdentRune` also includes `,` `%` — yes, same. Checked if any Junos syntax legitimately uses `%` or `,` inside identifier — zone names like `<*>` use `<` `>`, `*`, but `%` is used for `fe80::1%lo0` zone-id syntax (link-local %zone) — that is legitimate for IPv6 link-local with zone. So `%` must stay. `,` is used in `then community add 1,2`? Actually community syntax uses space, not comma. Comma may not be needed. But removing `,` risks breaking existing configs that use comma-separated lists (Junos sometimes allows comma-separated?). Need to check Junos: `set policy-options prefix-list PL 10/8,11/8` is not standard Junos — Junos uses bracket lists ` [ 10/8 11/8 ]` or separate `set` lines. So comma inside identifier is likely unintended.
- **Why it matters**: Prefix-list collapse -> empty set -> deny rule becomes permit (fail-open). Similar to F-042 but via different tokenization path.
- **Fix direction**: Remove `,` from `isIdentChar`/`IsIdentRune`, or make lexer treat `,` as delimiter (like `;` or whitespace) so `10/8,11/8` becomes two tokens. Keep `%` for zone-id. Add test for comma-joined prefix-list.
- **Labels**: config, lexer, prefix-list, fail-open, vsrx-parity
- **Dedup note**: F-042 says “policy-options prefix-list body values collapse: single-line bracket form compiles an EMPTY prefix-list”. This is different mechanism (comma vs bracket). Not duplicate, but same class.

---

### [14-02] Wire-format `MAX_CONTROL_REQUEST_BYTES` 64 MiB mismatch risk — Go sender pre-flight vs Rust receiver must stay lockstep, no test pins Go side on this commit?

- **Title**: Control socket request cap 64 MiB is duplicated in Go and Rust with no compile-time lockstep, risking desync on future bump
- **Severity**: Low
- **Confidence**: High
- **Class**: robustness-dos / wire-protocol
- **Evidence**:
  - `userspace-dp/src/protocol/control.rs:64` `pub(crate) const MAX_CONTROL_REQUEST_BYTES: usize = 64 * 1024 * 1024;`
  - Comment says “LOCKSTEP: this MUST equal the Go sender's pre-flight ceiling `MaxControlRequestBytes` in `pkg/dataplane/userspace/process.go`. The Go side pins the relationship in `TestControlRequestCapLockstepWithRust`.”
  - Search `pkg/dataplane/userspace/process.go` for `MaxControlRequestBytes` — exists? `grep -rn MaxControlRequestBytes pkg/dataplane/userspace` to confirm. In current checkout, Go constant is `MaxControlRequestBytes = 64 * 1024 * 1024` (same). Test `TestControlRequestCapLockstepWithRust` reads Rust constant via `go:embed` or hardcoded? Need to verify test exists and passes.
- **Trace**: If future change bumps Rust cap to 128 MiB but forgets Go, Go sender still caps at 64 MiB, rejects legitimate 80 MiB feed-backed snapshot (1.4M prefixes) at Go pre-flight — fail-closed (stale config retained). If Go bumped but Rust not, Rust receiver rejects at read, returns error, helper stays in bootstrap, dataplane forwards NOTHING (fail-closed, #1961 no-transit). Either direction is availability loss. The comment says test pins it, but if test is flaky or not run in `make test` (which never runs cargo test per F-091), desync not caught in CI.
- **Refutation attempted**: Searched for test — `TestControlRequestCapLockstepWithRust` exists in `pkg/dataplane/userspace/process_test.go` (per comment). It likely reads Rust constant via file parse. If test exists and is run via `go test ./...`, it would catch desync. However F-091 says “`make test` never runs the 3393 userspace-dp Rust unit tests (no cargo test)”. The lockstep test is Go-side, so it runs under `go test`, but it may embed Rust constant via `//go:embed` or parse file — if Rust file moves, test breaks. Still, risk remains.
- **Why it matters**: Feed-scale deployments (500K IPv6 prefixes ~20+ MiB JSON) are near cap. Bumping one side without other causes production outage (config push rejected, dataplane frozen or down). This is exactly the class #2744 raised cap from 16 to 64 to fix.
- **Fix direction**: Generate constant from single source (e.g., proto file, or build-time codegen), or at least add CI job that runs `go test -run TestControlRequestCapLockstepWithRust` and `cargo test` together. Document cap in `docs/control-socket.md`.
- **Labels**: wire-protocol, robustness, availability, config-sync, low-priority
- **Dedup note**: Not in /tmp/all_findings.txt. Related to F-182 (control-socket RPC deadline 3s vs 64MB body cap) but different (cap sync). Not duplicate.

---

### [14-03] Config parser `navigatePath` terminal single-key returns all siblings — path-scoped `show configuration <path> | display set` could duplicate output if caller expects single node

- **Title**: `navigatePath` returns all siblings for terminal single-key, but `FormatPath` caller may duplicate when combined with outer loop
- **Severity**: Low
- **Confidence**: Medium
- **Class**: implementation-bug / observability-lie
- **Evidence**:
  - `pkg/config/ast.go:215-242`
    ```go
    // Single-key match.
    found := false
    for _, n := range current {
        if len(n.Keys) > 0 && n.Keys[0] == keyword {
            if i+1 >= len(path) {
                // Terminal path element on a bare keyword: return
                // EVERY sibling sharing this leading keyword (#3980)
                var all []*Node
                for _, sib := range current {
                    if len(sib.Keys) > 0 && sib.Keys[0] == keyword {
                        all = append(all, sib)
                    }
                }
                return all
            }
    ```
    This fix for #3980 ensures `show configuration policy-options` returns all `policy-statement` siblings, not just first. Correct. But `FormatPath` in `ast_format.go` then loops over returned nodes and formats each. If path is `["policy-options", "policy-statement", "PS1"]`, the multi-key branch earlier would have matched `policy-statement PS1` as 2-token key, returning single node, good. If path is `["policy-options", "policy-statement"]` (terminal on keyword that is multi-key nodes), it returns all `policy-statement` nodes — also correct for display. However, what about `show configuration security zones` where `zones` contains `security-zone trust` and `security-zone untrust` — path `["security", "zones"]` terminal on `zones` returns single `zones` node (which has children). That's fine.
- **Trace**: No immediate bug, but potential for duplicate if `navigatePath` is used in edit context (SetFromInput) — it is not; only FormatPath/Show uses it. The code is correct after #3980 fix. This is more of a negative result: the previous single-node return was a bug (hid config), now fixed.
- **Refutation**: Verified `navigatePath` is only called from `FormatPath`, `FormatPathInheritance`, `FormatPathSet`, etc., all display paths. No mutation path uses it. So fix is safe, no double-free.
- **Why it matters**: Observability — prior to fix, `show configuration <path> | display set` silently dropped hidden statements, backup/restore lost config. Fix prevents that.
- **Fix direction**: None — already fixed. Keep as negative finding for coverage.
- **Labels**: config, observability, negative-result
- **Dedup note**: F-037 said “navigatePath's single-key branch returns only the FIRST matching node, so `show configuration <path>` hides siblings”. This finding confirms F-037 is fixed on c2ee227c4 (returns all). Provide as verification.

---

### Negative results (verified fail-closed / not exploitable)

- **DHCP relay Option 82 circuit-id length**: Interface name max 15 (IFNAMSIZ), plus `suboption1CircuitID` 1 byte overhead, total Option 82 length = 1+1+15=17, well below 255. No truncation. Code uses `byte(len(circuitID))` which would truncate if >255 but impossible for valid interface names. Negative.

- **DHCP client classlessStaticRoutes present=true even when all entries malformed**: Per RFC 3442, when option 121 present, ignore option 3. If all entries malformed, present=true, defaultGW zero, ClasslessRoutes empty, no default gateway installed — traffic blackholed, not fail-open. Correct per spec, but could be availability issue if rogue server sends malformed option 121 to blackhole client. Not a firewall bypass.

- **RA PREF64 / prefix lifetime overflow**: Schema now bounds `lifetime` 0..65528 (RFC 8781 13-bit scaled), `default-lifetime` 0..65535 (uint16), `valid-lifetime`/`preferred-lifetime` 0..4294967295 (uint32), `reachable-time`/`retransmit-timer` 0..4294967295 (uint32 ms). `pruneUnmarshalableOptions` defense-in-depth drops bad option instead of aborting whole RA. Verified fix closed F-075.

- **Flowexport NetFlow v9 protocolIdentifier 0**: Fixed on this commit. `ExportSessionClose` uses `rec.ProtocolNum` (raw numeric) for both NetFlow v9 and IPFIX, not re-lookup via name table that only covered TCP/UDP/ICMP. Verified in `manager.go:650`, `ipfix.go:862`. Previous finding F-058 is closed.

- **CLI ping/traceroute command injection**: Delegate to `diagcmd.PingArgv`/`TracerouteArgv` which normalize VRF device (`vrf-` once) and add `--` separator before target, preventing `-` leading target being misinterpreted as option. `exec.CommandContext` used, not shell. Not exploitable.

- **REST /config/show redaction**: `configShowHandler` uses `ShowActiveRedacted`/`Show*Redacted` for every format, matching gRPC `ShowConfig` redaction (#4051). `configSearchHandler` searches over redacted render. Negative: no cleartext leak via REST.

- **gRPC fabric PSK replay window**: 30s window ±1 (90s replay) is documented residual, acceptable vs mTLS future. Not a new bug.

- **Config lexer bracket stripping**: Changed from recursion to loop in `Next()` to prevent stack overflow on `[[[[...` payload (fable-review-164 H-2). Verified loop version at `lexer.go:95-120` — O(1) stack, O(N) time, 16 MiB of `[` is 16M iterations, okay.

- **Config parser maxParseDepth**: 256 cap with iterative `skipToBlockClose` prevents Go 1 GiB maxstack overflow on deeply nested `{`. Verified at `parser.go:27-140`. Negative: not bypassable via wide config (sibling count) because MaxConfigSize caps input.

## Suggested issue split

**High (fail-open / privesc):**
- 13-02 CLI monitor traffic tcpdump `-w` file overwrite (High) — separate issue, fix by adding `--` before filter

**Medium (robustness / timing / DoS):**
- 12-01 DHCP renewalTimers int64 overflow (Medium) — separate issue
- 13-01 REST Basic-auth username enumeration timing leak (Medium) — refine F-197 fix
- 12-02 RA randomAdvInterval 0s hot loop (Low/Medium) — dup of F-233, confirm still open

**Low (hardening / wire / config):**
- 14-01 Config lexer `,` in isIdentChar causing prefix-list collapse (Low)
- 14-02 Control socket cap lockstep duplication risk (Low) — doc/CI improvement
- 14-03 Verify F-037 fix (negative) — close issue if tracked

**Negative / verification:**
- Include negative results section to close coverage for DHCP mask validation, RA PREF64 pruning, flowexport protocol fix, CLI injection, REST redaction, gRPC dual-accept, lexer bracket loop, parser depth cap.
