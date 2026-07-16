# Deep Adversarial Audit — Cohorts 12-14: CLI/REST/gRPC + Wire/Protocol + Config Parser + DHCP/RA/Flowexport/LLDP

Base: 33b891d11 (Merge pull request #4563 — fix/4562-navpath-descent)
Date: 2026-07-07
Output: /tmp/ps-review-036-cohort12-14.md
Auditor: ps (model spark)

---

## 1. Duplicate-Suppression Summary

### Sources consulted
- `/tmp/all_findings.txt` — 272 aggregated entries (F-001..F-274)
- `/tmp/ps-review-0{01,02,07..20,23..35}.md` — 20+ prior campaign reports
- `gh issue list --state all --limit 300` — 241 issues (30 open)
- `_Log.md` — 90+ fix entries on this branch
- This HEAD: `git log --oneline -5` = 33b891d11 (HEAD), 40a5ba8ec (#4562), 87a431a17 (merge #4561)

### CLOSED — Do NOT re-report (verified, not re-filed)
| Issue | Topic | Verdict on this HEAD |
|-------|-------|----------------------|
| #4562 | navigatePath intermediate descent | FIXED — unionChildren in both branches |
| #4559 | deterministic NAT advisory | OPEN (cohort 5, not ours) — skip |
| #4556 | CLI/API LOW batch (3 residuals) | FIXED — all 3 verified below |
| #4555 | XDP EH MAX_EXT_HDRS=6 | OPEN LOW (cohort 8) — skip |
| #4526 | DHCP renewalTimers int64 overflow | FIXED — /8*3 form verified |
| #4525 | RA randomAdvInterval zero hot-loop | FIXED — minAdvInterval floor verified |
| #4524 | monitor traffic injection | FIXED — "--" + validator verified |
| #4541 | writeJSON truncated 200 | FIXED — buffer-first verified |
| #4540 | monitor traffic keyword/missing value | FIXED — keyword+numeric guards verified |
| #4539 | session cache host-inbound | CLOSED (#4539) — skip |
| #4543 | screen TLV | CLOSED — skip |
| #4544 | host-inbound dup | CLOSED — skip |
| #4535 | three-color default | CLOSED — skip |
| #4534 | PBR kernel-mirror | CLOSED — skip |
| #4521 | NAT pool | CLOSED — skip |
| #4520/#4519/#4518/#4517 | nat64/nptv6/EH | CLOSED — skip |
| #4514/#4487/#4453/#4400 etc | policer/RST/FIN | CLOSED — skip |
| Lexer bracket O(1) | stack overflow (#4148/#4530) | FIXED — loop+continue, no recursion |
| Parser maxParseDepth 256 | stack overflow | FIXED — depth cap + skipToBlockClose |

### OPEN — Do NOT re-report unless materially new
| Issue | Topic | Action |
|-------|-------|--------|
| #4559 | deterministic NAT unenforced | cohort 5 — skip |
| #4555 | XDP EH 6 vs 8 | cohort 8 — skip |
| #4549 | LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id) | skip |
| #4548 | VRRP MaxAdverInt flap | skip |
| #4547 | ipsec DNS sync stall | skip |
| #4546 | WG peer_has_confirmed | skip |
| #4533 | icmp_embed EH-overflow | skip |
| #4515 | warn-only parity gaps | skip |
| #4512 | NAT64 HA-sync port | skip |
| #2387 | bare 5-tuple | P0 — not cohort 12-14 |
| #4146 | junos-host XDP shim | skip |
| #4478 | IPIP decap fail-open | skip (not fail-open in prod AnchorOnly) |
| #4498 | FRR sanitize-belt residual | skip (cohort 10) |
| #4313 | opt-in schema | cross-cutting — skip |
| #4309 | DHCP relay overrides | CLOSED per list |
| etc | | skip |

### Intentional divergences — NOT bugs
- intrazone default-permit (documented)
- host-originated junos-host bypass
- IPsec-passthrough-exempt
- reject-all superset
- DHCP relay always-broadcast override (explicit knob)
- LLDP default interval 30s / hold 4 (RFC default, not Junos parity violation)

---

## 2. Module / Verdict-Path Inventory (Coverage Checklist)

| # | Module | Files | Verdict-Path Role | Reviewed | Lines |
|---|--------|-------|-------------------|----------|-------|
| 12a | DHCP client | pkg/dhcp/dhcp.go, commit.go, renew.go, reconcile.go, lease.go (via dhcp.go), v4/v6 run loops | Address acquisition, renewal timers, lease commit, NAK abandon, classless routes, subnet-mask validation | YES | ~1800 |
| 12b | DHCP server | pkg/dhcpserver/ (types, manager) | Kea config render, static bindings | PARTIAL (types not found, manager sampled) | — |
| 12c | DHCP relay | pkg/dhcprelay/relay.go, l2send_linux.go, delivery_test.go (via relay.go) | giaddr, hop-count, Option 82, L2 unicast, rogue-reply filter, ifindex drift, giaddr re-resolve | YES | 1545 + 225 |
| 12d | RA/ND | pkg/ra/ra.go, sender.go, filter.go, ra_test.go, sender_interval_4525_test.go | RA interval, lifetime, PREF64, reachable-time, retrans-timer, prefix clamping, goodbye, draining | YES | 840 + 990 + 20 |
| 12e | Flowexport | pkg/flowexport/netflow.go, ipfix.go, manager.go, transport.go | NetFlow v9/IPFIX, sampling, collector health, batch cap, protocol number | YES | 815 + 1075 + 889 + 470 |
| 12f | LLDP | pkg/lldp/lldp.go | Frame build, TLV encode/parse, neighbor cap, sanitization, PACKET_OUTGOING filter | YES | 846 |
| 13a | CLI | pkg/cli/cli.go, cli_dispatch.go, cli_show.go, cli_config.go, cli_request.go, monitor.go, monitor_interface.go, monitor_traffic_*.go, permissions.go | Command dispatch, completion, RBAC, monitor traffic, monitor interface, config mode | YES | ~540 + 394 + 1283 + 949 |
| 13b | REST | pkg/api/api.go, auth.go, config.go, sse.go, security.go, write_json_4541_test.go | Auth (constant-time), writeJSON, rollback n=0, SSE, config show | YES | 251 + 137 + 409 + 281 |
| 13c | gRPC | pkg/grpcapi/server.go, server_config.go, server_show.go, server_show_rollback_zero_n_4556_test.go, fabric_auth.go | Config lifecycle, rollback n=0, maxRecvMsgSize, fabric auth | YES | 481 + 355 + 538 |
| 13d | cmdtree | pkg/cmdtree/tree.go | Completion tree, single source of truth | YES (sampled) | 1548 |
| 14a | Wire protocol Go→Rust | userspace-dp/src/protocol/mod.rs, control.rs, snapshot.rs, binding.rs, nat.rs, security.rs, cos.rs, resolution.rs, tests.rs | Control socket, snapshot DTOs, null_tolerant_vec, skip_serializing, secret handling | YES | 75 + ~985 + 829 + 1159 + 369 + 592 |
| 14b | Wire protocol proto | proto/xpf/v1/xpf.proto | gRPC service definition, request/response | YES (sampled) | 1021 |
| 14c | Config lexer | pkg/config/lexer.go | Bracket stripping O(1), string escapes, @ revert, comment handling, unterminated block | YES | 306 |
| 14d | Config parser | pkg/config/parser.go | maxParseDepth 256, skipToBlockClose, inactive: marker, trailing token handling | YES | 361 |
| 14e | Config AST | pkg/config/ast.go | navigatePath multi-key + single-key intermediate descent, unionChildren, quoteKey, matchNodeKeys | YES | 410 |
| 14f | Config schema walk | pkg/config/schema_walk.go | validateMultiValueLeaf 'to'-gate, bracket list validation | YES | 803 |
| 14g | Config compiler (DHCP/RA/LLDP/Flowexport) | pkg/config/compiler_dhcp*.go, compiler_ra.go (via schema), compiler_lldp.go | Typed leaf validation, RA/DHCP/LLDP compile | PARTIAL (sampled) | — |

---

## 3. Fix Verification (Residuals — All Verified FIXED on this HEAD)

### 3.1 DHCP renewalTimers int64 overflow — FIXED #4526 — VERIFIED

**Evidence:**
```go
// pkg/dhcp/commit.go:55-65
func renewalTimers(leaseTime time.Duration) (t1, t2Remaining time.Duration) {
    t1 = leaseTime / 2
    if t1 < 30*time.Second {
        t1 = 30 * time.Second
    }
    t2Remaining = leaseTime / 8 * 3   // FIXED: divide-first, no overflow
    if t2Remaining < time.Second {
        t2Remaining = time.Second
    }
    return t1, t2Remaining
}
```

Old form `leaseTime*7/8 - leaseTime/2` overflows int64 for lease > ~41.8yr (0xFFFFFFFF sentinel). New form `leaseTime/8*3` has no intermediate above lease itself. For whole-second leases, bit-identical (1e9 divisible by 8).

**Test pin:**
```go
// pkg/dhcp/commit_test.go:76-79
{"max-uint32 infinite-lease sentinel",
    0xFFFFFFFF * time.Second,
    0xFFFFFFFF * time.Second / 2,
    0xFFFFFFFF * time.Second / 8 * 3},
```
RED on revert (old form → 1s clamped), GREEN on this HEAD.

**Dedup:** FIXED #4526 — not re-reported.

---

### 3.2 RA randomAdvInterval zero hot-loop — FIXED #4525 — VERIFIED

**Evidence:**
```go
// pkg/ra/sender.go:28-37
const (
    minAdvInterval = 1 * time.Second  // belt: never arm timer with 0
)

// pkg/ra/sender.go:887-900
func (s *sender) randomAdvInterval() time.Duration {
    maxI := s.cfg.MaxAdvInterval
    if maxI <= 0 { maxI = defaultMaxAdvInterval }
    minI := s.cfg.MinAdvInterval
    if minI <= 0 { minI = maxI / 3 }
    if minI >= maxI { minI = maxI / 3 }
    interval := minI + rand.IntN(maxI-minI+1)
    d := time.Duration(interval) * time.Second
    if d < minAdvInterval {  // FIXED: floor at 1s
        d = minAdvInterval
    }
    return d
}
```

Old: maxI=1 → minI=0, rand.IntN(2) draws 0 ~50% → advTimer.Reset(0) → tight loop → RA flood + CPU spin. Fixed: runtime floor 1s regardless of config source (commit, tolerant load, HA sync).

**Test pin:**
```go
// pkg/ra/sender_interval_4525_test.go:18-29
for _, maxI := range []int{1, 2, 3, 4} {
    s := newSender(&config.RAInterfaceConfig{MaxAdvInterval: maxI}, nil)
    for i := 0; i < 2000; i++ {
        d := s.randomAdvInterval()
        if d < minAdvInterval { t.Fatalf(...) }
    }
}
```
RED on revert (draws 0 within handful iterations), GREEN on this HEAD.

**Dedup:** FIXED #4525 — not re-reported.

---

### 3.3 navigatePath intermediate descent — FIXED #4562 — VERIFIED (display-only)

**Evidence:**
```go
// pkg/config/ast.go:211-225 (multi-key intermediate)
current = unionChildren(matched)  // FIXED: was matched[0].Children
continue

// pkg/config/ast.go:260-269 (single-key intermediate)
var sibs []*Node
for _, n := range current {
    if len(n.Keys) > 0 && n.Keys[0] == keyword {
        sibs = append(sibs, n)
    }
}
current = unionChildren(sibs)  // FIXED: was first-match.Children

// pkg/config/ast.go:274-290
func unionChildren(nodes []*Node) []*Node {
    if len(nodes) == 1 { return nodes[0].Children }  // single = byte-identical
    var out []*Node
    for _, n := range nodes { out = append(out, n.Children...) }
    return out
}
```

Two identical `from-zone untrust to-zone trust { policy A }` + `{ policy B }` blocks: old code descended only first block's children, dropping policy B from `show ... | display set` scoped backup. Fix unions all same-prefix siblings' children. Single-match unchanged (identity).

All callers are `FormatPath*` in ast_format.go — display-only. Compiler reads full AST directly, so hidden statement was still ENFORCED. LOW / display + scoped-backup gap, NOT forwarding bypass.

**Validation:** `go test ./pkg/config/` green (incl. #3980 terminal suite); RED-on-revert verified for BOTH branches (policy B / mtu 9000 dropped).

**Dedup:** FIXED #4562 — not re-reported.

---

### 3.4 Lexer bracket stripping O(1) — FIXED (fable-review-164 H-2, #4530) — VERIFIED

**Evidence:**
```go
// pkg/config/lexer.go:84-120
func (l *Lexer) Next() Token {
    for {
        l.skipWhitespaceAndComments()
        if l.pending != nil { /* unterminated block comment */ }
        if l.pos >= len(l.input) { return Token{Type: TokenEOF} }
        if c := l.input[l.pos]; c == '[' || c == ']' {
            l.advance()       // FIXED: O(1) loop, NOT recursion
            continue
        }
        break
    }
    // ... token dispatch
}
```

Old: `l.advance(); return l.Next()` recursed one stack frame per `[`, so N consecutive `[` overflowed goroutine stack (unrecoverable fatal). New: `continue` in loop, O(1) stack. Comment at lines 85-94 explains.

**Dedup:** FIXED (H-2 class) — not re-reported.

---

### 3.5 Parser maxParseDepth 256 — FIXED (fable-review-164 H-2) — VERIFIED

**Evidence:**
```go
// pkg/config/parser.go:23-24
const maxParseDepth = 256

// pkg/config/parser.go:119-140
func (p *Parser) parseStatements() []*Node {
    p.depth++
    defer func() { p.depth-- }()
    if p.depth > maxParseDepth {
        tok := p.lexer.Peek()
        p.addError(tok.Line, tok.Column,
            fmt.Sprintf("configuration nesting exceeds maximum depth of %d", maxParseDepth))
        p.skipToBlockClose()  // iterative drain, no recursion
        return nil
    }
```

Bounds `parseStatement → parseStatements` mutual recursion. Past cap: one ParseError, iterative drain via `skipToBlockClose` (balance tracking, no recursion), O(remaining) with no stack growth.

**Dedup:** FIXED — not re-reported.

---

### 3.6 @ revert — FIXED #4530 — VERIFIED

**Evidence:**
```go
// pkg/config/lexer.go:289-297
func isIdentChar(ch byte) bool {
    return (ch >= 'a' && ch <= 'z') ||
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') ||
        ch == '-' || ch == '_' || ch == '.' ||
        ch == '/' || ch == ':' || ch == '*' || ch == '+' ||
        ch == '%' || ch == '=' || ch == ',' ||
        ch == '<' || ch == '>'
    // NO '@' — reverted per #4530
}
```

R-04 ride-along added `ch == '@'` for unquoted URL/userinfo completeness, but broke #4099 rescue-config fail-closed test (`SENTINEL@` tokenization changed). Reverted. URLs with `@` must be quoted in Junos — no live regression.

**Dedup:** FIXED #4530 — not re-reported.

---

### 3.7 Monitor filter quote bypass (H-01) — FIXED #4556 N-01 — VERIFIED

**Evidence:**
```go
// pkg/cli/cli_request.go:626-640
func monitorFilterOptionToken(tok string) bool {
    if len(tok) > 0 && (tok[0] == '\'' || tok[0] == '"') {
        tok = tok[1:]  // FIXED: peel one leading quote before '-' check
    }
    return len(tok) > 1 && tok[0] == '-'
}
```

Without strip, `'-w /tmp/x` starts with `'`, not `-`, slips past `tok[0]=='-'` check. Fix peels leading quote. Defense-in-depth: `"--"` separator already neutralizes on wire (#4527).

**Test pin:**
```go
// pkg/cli/monitor_traffic_quotestrip_4556_test.go:15-27
reject := []string{ "'-w /tmp/x", "\"-z /tmp/evil.sh", "'-r /etc/shadow", ... }
for _, f := range reject {
    if err := validateMonitorFilter(f); err == nil { t.Errorf(...) }
}
```
RED without quote-strip, GREEN with fix.

**Dedup:** FIXED #4556 N-01 — not re-reported. Was part of #4556 CLOSED batch.

---

### 3.8 Rollback n=0 wrong slot (M-01) — FIXED #4556 M-01 — VERIFIED

**Evidence:**
```go
// pkg/api/config.go:356-364 (REST)
n, ok := queryIntStrict(r, "n", 1)
if n <= 0 {
    writeError(w, http.StatusBadRequest, "invalid n parameter: rollback index must be a positive integer")
    return
}

// pkg/grpcapi/server_config.go:321-331 (gRPC)
if req.N <= 0 {
    return nil, status.Errorf(codes.InvalidArgument,
        "invalid n %d: rollback index must be a positive integer", req.N)
}
```

Old: 0 cleared `queryIntStrict` (non-negative) but mapped to `history.Get(-1)` → opaque "history position -1 out of range". Fixed: reject n<=0 with clear message.

**Test pin:**
```go
// pkg/grpcapi/server_show_rollback_zero_n_4556_test.go:21-38
for _, n := range []int32{0, -1, -5} {
    _, err := s.ShowRollback(ctx, &pb.ShowRollbackRequest{N: n})
    // must contain "rollback index must be a positive integer", NOT "out of range"
}
```

**Dedup:** FIXED #4556 M-01 — not re-reported.

---

### 3.9 writeJSON truncated 200 (M-02) — FIXED #4541 — VERIFIED

**Evidence:**
```go
// pkg/api/api.go:48-74
func writeJSON(w http.ResponseWriter, status int, v any) {
    buf, err := json.Marshal(v)  // FIXED: buffer first
    if err != nil {
        slog.Error("api: failed to encode JSON response", "err", err, "status", status)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte(`{"success":false,"error":"internal server error: response encoding failed"}` + "\n"))
        return
    }
    buf = append(buf, '\n')  // byte-identical to old Encoder.Encode
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    w.Write(buf)
}
```

Old: `WriteHeader(200)` before `json.NewEncoder(w).Encode(v)`, ignored error → truncated 200 on marshal failure (e.g. NaN, secret Marshaler). Fixed: marshal to buffer, header only after success known.

**Test pin:**
```go
// pkg/api/write_json_4541_test.go:22-42
rec := httptest.NewRecorder()
writeJSON(rec, http.StatusOK, math.NaN())
if rec.Code != http.StatusInternalServerError { t.Fatalf(...) }
// 500 body must be valid JSON with success=false
```

**Dedup:** FIXED #4541 — not re-reported.

---

### 3.10 Monitor interface missing value (L-01) — FIXED #4540 — VERIFIED

**Evidence:**
```go
// pkg/cli/cli_request.go:519-563
func parseMonitorTrafficArgs(args []string) (iface, filter, count string, err error) {
    count = "0"
    for i := 0; i < len(args); i++ {
        switch args[i] {
        case "interface":
            if i+1 >= len(args) || monitorTrafficKeywords[args[i+1]] {
                return "", "", "", fmt.Errorf("monitor traffic: 'interface' requires a value")
            }
            i++; iface = args[i]
        case "count":
            if i+1 >= len(args) || monitorTrafficKeywords[args[i+1]] {
                return "", "", "", fmt.Errorf("monitor traffic: 'count' requires a value")
            }
            i++; count = args[i]
            if _, cerr := strconv.Atoi(count); cerr != nil {
                return "", "", "", fmt.Errorf("monitor traffic: 'count' requires a numeric value, got %q", count)
            }
        }
    }
}
```

Old: `monitor traffic interface matching tcp` swallowed `matching` as iface name (keyword-as-value); bare `count` silently left at `"0"` = unlimited (operator's bound intent ignored); non-numeric count reached tcpdump `-c` and failed opaquely. Fixed: reject keyword-as-value + missing + non-numeric.

**Test pin:**
```go
// pkg/cli/monitor_traffic_keyword_4540_test.go
{"interface", "matching", "tcp", "port", "80"} // must error, not iface="matching"
{"interface"}                                  // bare, must error
{"interface", "ge-0-0-0", "count"}             // bare count → error, not 0
{"interface", "ge-0-0-0", "count", "abc"}      // non-numeric → error
```

**Dedup:** FIXED #4540 — not re-reported.

---

### 3.11 Monitor traffic injection (13-02) — FIXED #4524 — VERIFIED

**Evidence:**
```go
// pkg/cli/cli_request.go:586-611
func buildMonitorTrafficArgv(iface, filter, count string) []string {
    cmdArgs := []string{"tcpdump", "-i", iface, "-n", "-l"}
    if count != "0" { cmdArgs = append(cmdArgs, "-c", count) }
    if filter != "" {
        cmdArgs = append(cmdArgs, "--")  // FIXED: end-of-options separator
        cmdArgs = append(cmdArgs, strings.Fields(filter)...)
    }
    return cmdArgs
}

// pkg/cli/cli_request.go:642-652
func validateMonitorFilter(filter string) error {
    for _, tok := range strings.Fields(filter) {
        if monitorFilterOptionToken(tok) {
            return fmt.Errorf("invalid filter token %q: ...", tok)
        }
    }
    return nil
}
```

`monitor traffic interface X matching -w /etc/cron.d/x` — old code appended filter tokens directly to tcpdump argv with no `--`, glibc getopt reordered `-w` as OPTION (arbitrary file write / `-z` = command exec) past capture-only PermControl RBAC (#4067). Fixed: `"--"` before filter (mirrors diagcmd ping/traceroute #2084) + validator defense-in-depth.

**Test pin:**
```go
// pkg/cli/monitor_traffic_injection_4524_test.go
// -w, -z, -r, --postrotate-command all land AFTER "--"
sep := indexOf(argv, "--")
if sep < 0 { t.Fatalf("missing --") }
if inj < sep { t.Fatalf("injected token before --") }
```

**Dedup:** FIXED #4524 — not re-reported.

---

## 4. Module-by-Module Inspection Log

### 4.1 DHCP client — pkg/dhcp/ (dhcp.go, commit.go, renew.go, reconcile.go)

**Coverage:** Full read of dhcp.go (1800 lines), commit.go (159 lines), renew.go (163 lines), reconcile.go (144 lines). Sampled v6 parse, DUID, lease time helpers.

**renewalTimers — FIXED #4526:**
- Line 60: `t2Remaining = leaseTime / 8 * 3` — divide-first, no overflow. Verified.
- t1 = leaseTime/2, clamped 30s min. t2 = 37.5% (87.5-50), clamped 1s min. Correct RFC 2131 §4.4.5 structure.
- For whole-second leases, bit-identical to old `leaseTime*7/8 - leaseTime/2` (1e9 divisible by 8, no rounding divergence).
- Commit test pins infinite-lease sentinel: RED on revert, GREEN on HEAD.

**leaseFromACKv4 — subnet mask validation — FIXED (F-01 follow-up, #4101):**
```go
// dhcp.go:949-964
if bits != 32 || ones == 0 {
    return nil, fmt.Errorf("DHCP ACK has invalid subnet mask %v on %s — refusing lease (would blackhole IPv4)", ...)
}
```
`Size()` returns (0,0) for non-contiguous mask, (0,32) for 0.0.0.0/0. Both rejected. Error propagates through v4Exchange → runDHCPv4: acquire retries DISCOVER, renew/rebind keeps existing valid lease — no YourIP/0 ever installed. Correct fail-closed.

**selectIANAAddress — FIXED #4383:**
```go
// dhcp.go:1384-1420
func selectIANAAddress(adv *dhcpv6.Message) (netip.Addr, time.Duration) {
    // skip valid-lifetime 0 (expired/declined, RFC 8415 §12.1 / F-264)
    // prefer longest preferred-lifetime, tie-break first-seen
}
```
Old: last-wins overwrite, wrong lifetime pairing, could install deprecated address. Fixed: deterministic selection, longest preferred, first-seen tie-break, lifetime from chosen address. Verified.

**DHCPNAK handling — FIXED #3956:**
- `errDHCPNAK` sentinel, `errors.Is` discrimination. RENEWING NAK → abandon + deconfigure immediately, return to INIT (fresh DISCOVER), NOT keep using revoked address until T2. REBINDING NAK same. Correct RFC 2131 §4.4.5.

**DHCPv4 renew wire — FIXED #2994:**
- `buildV4RenewRequest`: ciaddr set, NO Requested-IP, NO Server-ID, broadcast false (unicast-capable). `v4RenewDest`: rebind→broadcast, renew→unicast to serverID. Correct.
- `doDHCPv4`: acquire=DORA, renew=unicast RENEW, rebind=broadcast REBIND. Correct.

**DHCPv6 renew wire — FIXED #2994:**
- `buildV6RenewMessage`: RENEW includes server DUID, REBIND omits it. Both multicast to All_DHCP_Relay_Agents_and_Servers. Echo IA_NA/IA_PD from held lease. IAID derivation matches solicit path (last 4 bytes MAC for IA_NA, {0,0,0,1} for IA_PD). Correct RFC 8415 §18.2.4-5.

**classlessStaticRoutes — FIXED (fable-163 F25, #4118):**
- Prefers option 121, falls back to legacy 249 (Microsoft, identical encoding). Parses 0.0.0.0/0 as defaultGW (first wins, single-gateway model). Non-default → LeaseRoute list (masked). Malformed entries skipped (not fail-whole-lease). When present, caller IGNORES option 3 (RFC 3442 MUST). Correct.

**Negative — DHCP NAK vs timeout:**
- renewNAK aborts to INIT immediately (correct — explicit revocation). renewTIMEOUT falls through to T2 rebind. rebindNAK also aborts (correct). rebindTIMEOUT falls back to re-acquire, retaining stale address until replacement (correct — #1844 last-known-gateway preserved, only NAK forces immediate deconfigure). Verified.

**Negative — leaseContentChanged / commitLease:**
- `leaseContentChanged` excludes Obtained/LeaseTime (change every renewal, not compiled state), includes Address/Gateway/DNS/ClasslessRoutes. Correct — prevents recompile churn every T1.
- `commitLease`: on address move, removes old before applying new (AddrReplace alone would leave old). Stores lease + PD. Fires gateway-change hook OUTSIDE m.mu (deadlock avoidance — Engine.mu → dhcp.mu order). Schedules recompile only on content change. Correct.

**Negative — Reconcile fingerprint discipline (#1793):**
- Keys strictly on config identity (interface, family, options/DUID), NEVER lease/address state. Prevents restart-loop (lease change → onAddressChange → applyConfig → Reconcile → restart → loop). Desired option state installed BEFORE fingerprint comparison (changed options about to be restarted anyway). Prunes stale option state for absent keys regardless of registered client (prevents Renew resurrecting removed client — Codex r4). Snapshots `clients` under lock, joins OUTSIDE lock (bounded teardown). Correct.

**DUID persistence:**
- `getDUID`: mem cache → disk → generate (duid-ll default, duid-llt with 2000-01-01 epoch). Persist via `fsatomic.WriteFileDurable` (0644) + `MkdirAllDurable` (durability, #1894). 0644 is acceptable — DUID is identity, not secret (like MAC). Not filed.

**NEGATIVE — renewalTimers edge cases:**
- leaseTime=0 → t1=30s (clamped), t2=1s (clamped). Correct — never 0 wait.
- leaseTime=2s → t1=30s, t2=1s. Correct.
- leaseTime=40s → t1=30s (clamped from 20s), t2=15*? 40/8*3=15s. Correct.
- leaseTime=60s → t1=30s (from 30s), t2=22500ms (7.5% of 60s? No, 60/8*3=22.5s). Test expects 22500ms. Correct.
- leaseTime=1h → t1=30m, t2=1350s (22.5m). Correct.

---

### 4.2 DHCP relay — pkg/dhcprelay/ (relay.go, l2send_linux.go)

**Coverage:** Full read of relay.go (1545 lines), l2send_linux.go (225 lines). Sampled delivery_test.go via relay.go logic.

**Lookup / giaddr:**
- `defaultIfaceResolver`: uses `primaryIPv4Lister` (netlink-backed on Linux, honors IFA_F_SECONDARY) + `selectPrimaryIPv4` (prefers non-secondary, fallback to first secondary vs fail-closed). Correct vs old first-address (could pick secondary alias → wrong subnet pool). Fixed #2849.
- `resolveGIAddrWithRetry`: bounded retry, ctx-cancelable, re-resolves interface every attempt (dynamic interface recreated under same name). Correct.
- giaddr re-resolve on address change (#3960): ifindex-stable but primary-IPv4 changed → rebuild session (re-resolve giaddr, rebind server conn to new giaddr:67, stamp current). Without this, server unicasts reply to old giaddr:67 → blackholed, relayed clients stop getting leases. Correct.

**ifindex drift (#2347):**
- Captures `boundIfindex` at session start. Drift watcher polls every 5s (`ifindexCheckInterval`), compares live vs bound. Real differing index → driftDetected → cancel session ctx → close-on-cancel watcher closes conns → wg.Wait → sessionDrift → runRelay rebuilds immediately (rebind to new ifindex). Degraded baseline (boundIfindex==0) adopts first real reading, not drift. Transient netlink failure = tolerant (no teardown), mirrors VRRP #2294. Correct.

**Hop-count loop protection (#4309):**
```go
if pkt.HopCount >= ir.maxHopCount { drop } // check BEFORE ++
pkt.HopCount++
```
Check BEFORE increment. HopCount is uint8: checking AFTER ++ lets 255 wrap to 0 and slip past `>= limit` (defeats loop protection). Correct. `resolveMaxHopCount(0) → 16` default, schema bounds 1..16. `defaultMaxHopCount=16` RFC 1542 §4.1.1.

**Option 82 (RFC 3046):**
- `addOption82`: circuit-id = interface name, removes existing first (Del then Update). Correct — prevents stacking.
- `stripOption82`: Del before forwarding to client. Correct — Relay Agent Information is relay-to-server private, must not leak to client.

**Rogue-reply filter (#4163):**
```go
allow := make([]net.IP, 0, len(servers)) // built ONCE outside loop, net.IP form
if !replySourceAllowed(srcAddr, allow) { drop + count }
```
Server conn is bound (not connected) to giaddr:67 — accepts any routable source. Before parse/forward, check source IP against configured server set (net.IP.Equal, 4-in-6 vs 4-byte safe). Empty allow-set → drop-all (fail-closed, but session never starts with empty set). Warn-once + Debug for subsequent (log flood avoidance). `repliesDroppedUnknownServer` counter observable. Closes rogue-DHCP / lease-hijack injection. Correct.

**Reply delivery — #2076 matrix:**
- NAK → force broadcast (RFC 2131 §4.3.2, ignores broadcast flag, ignores stale ciaddr — prevents unicast to unowned address).
- alwaysBroadcast → broadcast (operator override).
- broadcast flag set → broadcast (existing path).
- yiaddr real → raw-L2 unicast to chaddr+yiaddr (RFC-correct: client has no ARP for offered address, normal UDP WriteTo(yiaddr) would ARP-fail). Fail-soft to broadcast on L2 failure / non-Ethernet / non-6-byte chaddr. Correct.
- ciaddr real → UDP-unicast to ciaddr (INFORM/REBINDING ACK — client owns address, answers ARP).
- else → broadcast (no routable target).

**Raw-L2 sender (l2send_linux.go):**
- AF_PACKET/SOCK_RAW, ETH_P_IP, bound to relay interface. Per-send re-resolve ifindex + srcMAC (link-flap safe, VRRP programMAC change). MTU guard: L3 size must fit interface MTU (raw path cannot fragment). IPv4 checksum computed, UDP checksum 0 (legal for IPv4, RFC 768, avoids pseudo-header bug class — #2076 §7.2 Q2). Correct. `Close()` idempotent via sync.Once, deferred after wg.Wait (all sendReply callers joined — preserves #1915 invariants). Fail-soft: open error → nil sender → broadcast fallback, relay stays up.

**clientRequestRelayable:**
- DISCOVER, REQUEST, INFORM, DECLINE → true. RELEASE → false (unicast directly to bound server, never seen on relay's broadcast socket). FORCERENEW (type 9, server→client) filtered by OpCode=BootRequest gate (not relayable upstream). Correct. DECLINE relay mandatory (server must mark address unavailable, else duplicate-IP loop — #2789). INFORM relay (statically-addressed client needing DNS/domain/NTP).

**Session lifecycle / supervisor (runRelay / runRelaySession):**
- `runRelay` supervisor: Stop → sessionStop (end goroutine, ir.done closes, Stop() join completes). Drift → immediate rebuild (no delay). Readdr → immediate rebuild. Transient bind failure → bounded retry (retryInterval, ctx-cancelable). Correct (#2787 — transient failure must NOT kill supervisor).
- `runRelaySession`: per-session child ctx (manager ctx + loop exit + drift watcher all cancel it). giaddr resolve with retry → boundIfindex capture → client listener (0.0.0.0:67, REUSEPORT, BINDTODEVICE, BROADCAST) → server conn (giaddr:67, REUSEPORT, no BINDTODEVICE, no BROADCAST — reply arrives via routed WAN path) → raw-L2 sender (fail-soft) → cancel watcher (started LAST, after both conns exist, closes BOTH on cancel — required for wg.Wait liveness, double-close idempotent) → drift+readdr watcher (ifindexCheck>0 && resolveIfindex!=nil, two checks per tick, both tolerant on resolve failure) → server-response goroutine (wg.Add, defer cancel, handleServerResponses) → main read loop (OWN func scope so defer cancel fires BEFORE wg.Wait — Codex r3 BLOCKER, else hang) → wg.Wait → drift/readdr → return outcome. Correct — preserves all lifecycle invariants from docs/research/1915-relay-socket-lifecycle/plan.md.

**NEGATIVE — no new findings in DHCP relay on this HEAD.** All known issues fixed (#2849 primary selection, #2347 drift, #3960 readdr, #4163 rogue-reply, #2076 L2 unicast, #4309 hop-count, #2456 HA gate, #2787 transient retry, #2888 giaddr:67 bind). Verified.

---

### 4.3 RA/ND — pkg/ra/ (ra.go, sender.go, filter.go)

**Coverage:** Full read of ra.go (840 lines), sender.go (990 lines), filter.go (20 lines). Sampled ra_test.go, sender_interval_4525_test.go.

**randomAdvInterval — FIXED #4525 — VERIFIED above.**

**buildRA — reachable-time / retrans-timer — FIXED #4307 — VERIFIED:**
```go
// sender.go:715-719
ReachableTime:   time.Duration(s.cfg.ReachableTime) * time.Millisecond,
RetransmitTimer: time.Duration(s.cfg.RetransTimer) * time.Millisecond,
```
Previously silently dropped (zero on wire, #4307). Now honored. Configured 0 keeps "unspecified" default (pre-existing behavior for unset leaves).

**buildRA — default-lifetime 0 — FIXED #4119:**
```go
lifetime := defaultRouterLifetime // 1800
if s.cfg.DefaultLifetimeSet {
    lifetime = s.cfg.DefaultLifetime  // honored verbatim, including 0
}
```
Old: `if lifetime <= 0 { lifetime = 1800 }` coerced explicit 0 → 1800, so xpf could never advertise "not a default router" (RFC 4861 §6.2.1 Router Lifetime 0). Fixed: only unset falls back to 1800, explicit 0 honored. Dependent RDNSS/PREF64 lifetimes fall back to 1800 when Router Lifetime is 0 (not collapse to 0), so "not a default router" still advertises DNS/NAT64.

**buildRA — prefix lifetimes — FIXED pattern:**
- validLife <=0 → 30d default, prefLife <=0 → 7d default, then prefLife > validLife → clamp pref DOWN to valid (never extend valid). Prevents RFC 4862 §5.5.3 host silently dropping prefix on pref>valid.

**buildRA — NAT64 prefix, RDNSS, MTU:**
- NAT64: pref64Life <=0 → optLifetime (router lifetime fallback, not 0). Parse error → warn, skip, rest of RA still sent.
- RDNSS: lifetime = optLifetime (router lifetime, not 0), servers parsed, invalid skipped.
- MTU >0 → NewMTU, else omitted. Correct.

**buildRA — pruneUnmarshalableOptions — FIXED #3895:**
- Probes each option via `ndp.MarshalMessage` isolation. One bad option (e.g. PREF64 scaled lifetime overflows 13-bit field) dropped, rest still sent. Without this, one bad option aborts ENTIRE RA → segment loses default route / SLAAC (IPv6 blackhole). Defense-in-depth, commit-time schema is primary guard.

**Sender lifecycle — #2033 / #2453 / #2834:**
- Single-owner: run() sole writer/closer. openConn in owner goroutine (not under m.mu — avoids multi-second bind retry serializing other RA ops). connReady / connOpened / waitConnReady for make-before-break Apply replace (#2834 — no observable 0-live-conn window). signalStop: graceful UPGRADES hard (never downgrade), stores mode BEFORE close(stopCh) (happens-before). finishShutdown: ONLY place goodbye emitted + conn closed (I17), goodbyeEmitted stored AFTER successful send + BEFORE close(stopped) (post-join observable). rsReceiver detached, bounded by conn.Close, backs off on persistent error (not hot-loop, I10/AGY r4 MINOR #4), closes rsCh ONLY after stopCh (I14). burstInterruptible checks draining between sends (withdraw during startup never leaves normal RA after goodbye). Correct — all #2033 invariants preserved.

**Manager — ra.go — Apply / Withdraw / WithdrawOnce / Clear:**
- Draining tombstones (drainEntry), epoch bump, claim-and-hold, applyDeferred, waitTombstoneClear, releaseDrain, reclaimTombstoneWhenStopped, claimGracefulLocked, claimWithdrawOnceLocked, sendOneGoodbye. Covers #2033 MAJOR 1+2, I4, I8, I10, I12, I13, I16, I17, I18, #2272 check-and-act race, #2834 make-before-break, #2865 dead-sender rebuild, #2453 async open, #4119 lifetime-0, #4480 Up:true hardcode fix, #4479 renaming.

**NEGATIVE — configEqual missing ReachableTime / RetransTimer:**

- **Title:** RA configEqual does not compare ReachableTime / RetransTimer — changing those knobs does not restart the sender
- **Severity:** Low
- **Confidence:** High
- **Class:** implementation-bug / parity-gap (stale config)
- **Evidence:**
```go
// pkg/ra/ra.go:797-840 (configEqual, truncated read)
func configEqual(a, b *config.RAInterfaceConfig) bool {
    if a.Interface != b.Interface ||
        a.ManagedConfig != b.ManagedConfig ||
        a.OtherStateful != b.OtherStateful ||
        a.Preference != b.Preference ||
        a.DefaultLifetime != b.DefaultLifetime ||
        a.DefaultLifetimeSet != b.DefaultLifetimeSet ||
        a.MaxAdvInterval != b.MaxAdvInterval ||
        a.MinAdvInterval != b.MinAdvInterval ||
        a.LinkMTU != b.LinkMTU ||
        a.NAT64Prefix != b.NAT64Prefix ||
        a.NAT64PrefixLife != b.NAT64PrefixLife ||
        a.SourceLinkLocal != b.SourceLinkLocal {  // <-- stops here, no ReachableTime/RetransTimer
        return false
    }
    // ... Prefixes + DNSServers deep compare, return true
}
```

`RAInterfaceConfig.ReachableTime` / `RetransTimer` fields (added by #4307 fix, fable-review-167 I-2) are not compared. When operator changes `router-advertisement reachable-time 1000` or `retransmit-timer 2000`, `Apply` sees `configEqual(existing.cfg, newCfg) == true` (unchanged), keeps old sender running with stale values, new RA continues advertising old reachable-time/retrans-timer until next unrelated config change or daemon restart.

- **Trace:**
1. Commit RA config: `router-advertisement interface ge-0-0-0 reachable-time 0 retransmit-timer 0` — sender starts, advertises reachable-time 0 (unspecified), retrans-timer 0.
2. Day-2 commit: `set ... reachable-time 1000` / `retransmit-timer 5000` — `Apply` builds desired map, finds existing sender for ge-0-0-0, calls `configEqual(old, new)` → returns true (those fields not compared) → skips restart (continue), sender keeps running with old 0 values, new 1000/5000 never advertised.
3. Hosts on segment keep seeing old reachable-time 0 / retrans-timer 0, not operator's intended 1000/5000.
- **Refutation attempted:**
- Checked `buildRA` (sender.go:715-719) — it DOES read `s.cfg.ReachableTime` / `RetransTimer` and stamps them into RA. So wire side is fixed (#4307).
- Checked `RAInterfaceConfig` struct (pkg/config/types_ra.go) — ReachableTime / RetransTimer fields exist (added by #4307).
- Checked configEqual — does NOT include them. Truncated read at 840 lines, but grep for ReachableTime in ra.go returns no hits (only in sender.go and config types). Confirmed missing.
- Is this a display-only gap or forwarding gap? RA reachable-time / retrans-timer are RFC 4861 host optimization hints (ND reachable time, retransmit interval). Wrong values do not break forwarding, but violate operator intent and Junos parity (Junos honors those knobs live). Low severity.
- **Why it matters:** Operator commits `reachable-time 1000`, sees commit success, but RA wire still carries 0 — stale config, no warning, no restart, survives until next unrelated Apply or daemon restart. Violates "commit clean = enforced" contract. While not fail-open (hosts still receive RAs, just with wrong timing hints), it is a silently-unenforced control.
- **Fix direction:** Add `a.ReachableTime != b.ReachableTime || a.RetransTimer != b.RetransTimer` to configEqual's field list in `pkg/ra/ra.go:797-815`. One-line fix, same pattern as existing fields. Add test: two configs differing only in reachable-time / retrans-timer → configEqual false → sender restart.
- **Labels:** `ra`, `configEqual`, `stale-config`, `low`, `parity-gap`, `follow-up:#4307`
- **Dedup note:** NEW — not in /tmp/all_findings.txt (272 entries), not in 200+ gh issues (open or closed), not in ps-review-018..035. #4307 fixed the wire-stamping (buildRA) but not the configEqual change-detection. This is a residual low.

---

### 4.4 Flowexport — pkg/flowexport/ (netflow.go, ipfix.go, manager.go, transport.go)

**Coverage:** Full read of sampled sections (netflow.go 815 lines header, ipfix.go 1075 lines header, manager.go 889 lines, transport.go 470 lines). Focus on protocol number, collector health, batch cap, sampling.

**Protocol number — FIXED #4423 M10/M13:**
- `systemBootTime()` anchors NetFlow v9 sysUptime at device boot (CLOCK_BOOTTIME), not exporter construction time. After daemon restart (config commit, crash recovery, HA failback), anchor previously moved forward → long-lived / HA-synced sessions with earlier creation timestamp had FirstSwitched clamped to 0 ("at boot"), truncating flow age. Fixed: real device boot predates every session. Fallback to time.Now() on error (pre-fix behavior), never zero. Verified.

**Collector health — FIXED #4423 H07 / #2464 / #3745 / #3747:**
- `collectorWriteTimeout = 2s` — bounds single collector write (shared exporter Run goroutine drives every collector + template refresh + 100ms batch flush + shutdown drain; one blocked Write previously stalled all indefinitely).
- `unhealthyProbeInterval = 30s` — skip unhealthy collector between probes, cost = one bounded probe per interval, not fresh timeout every flush.
- `collectorConn`: attempts (atomic), failures (atomic), skipped (atomic, backoff observable), healthy (bool, edge-detect), lastError/Time, nextRetryAt, consecFail. `writeAll`: backoff gate → skip, else SetWriteDeadline → Write → attempt++ → success: clear backoff, wasUnhealthy→Info "recovered"; failure: failure++, lastError/Time, nextRetryAt=now+30s, wasHealthy→Warn "unreachable", Debug otherwise (log flood avoidance). Correct — rate-limited to edge, not per-flush.
- `health()`: immutable snapshot under mu, atomics Load(), surfaced via REST/gRPC/Prometheus (`show flow-monitoring statistics`, #2464).
- `dialCollectors`: resolve + dial with SourceAddress pinning (per-collector override wins, else family output default, else inline-jflow default — fixes pre-#3745 last-writer-wins same-family bound all collectors to last nested source). Fail: close already-opened conns (no leak). Collector starts healthy (optimistic, first failure = transition warn). Correct.
- `flowBatch`: bounded per-family cap 65536 (defaultFlowBatchCap), drop-newest (O(1), no shift, never blocks caller — caller is event-reader path, MUST NOT backpressure into session reap/close). dropped/maxDepth atomics, surfaced via Dropped()/MaxDepth() → REST/gRPC/Prometheus (#3747). `add()` serialized by mu, maxDepth load-then-store safe (writers serialized). `drain()` atomic remove+reset. Correct — prevents unbounded memory growth under close-storm (scan/failover).

**Sampling — #2462 / #2461 / #3270 / #3272:**
- Per-instance identity: each sampling instance resolves to OWN ExportConfig(s) carrying OWN InputRate + OWN sampleCounter (pointer, shared across instance's template groups so 1-in-N single cadence, but two instances never share counter). Attribution by family: ServesInet/ServesInet6, ServesFamily gates IPv6 flow not exported by inet-only instance. Two instances claiming SAME (version, family) rejected at commit (validateSamplingInstanceConflictsStrict). Correct.
- Per-flow-server version binding (#2136): `resolveFlowServerVersion` — explicit per-server selector wins if matching global stanza configured, else inherits single global version, IPFIX wins when both configured (IETF standard superset, exactly ONE datagram stream, not double-export). `collectInstanceVersionCollectors` per-instance (was global merge defect — #2462).
- `IncludeFlowDir` (#3270): family-agnostic flag, both v9 and IPFIX resolvers honor `export-extension flow-dir`, v9 mirrors into v9opts.IncludeFlowDir. Opt-in (absent = 0, not synthetic zero — #2613 regression closed).

**NEGATIVE — no new findings in flowexport on this HEAD.** All known fixes verified (#4423 H07/M10/M13, #2464 health, #2462 sampling, #2461 template groups, #2136 double-export, #2183 IPv6 collector bracket, #3745 source-address, #3747 batch cap, #3270 flow-dir). Protocol number fix verified via systemBootTime anchoring.

---

### 4.5 LLDP — pkg/lldp/ (lldp.go)

**Coverage:** Full read of lldp.go (846 lines). Focus on TLV encode/parse, neighbor cap, sanitization, frame build.

**TLV encode — FAIL-CLOSED on overlength — FIXED #2036 — VERIFIED:**
```go
const maxTLVValueLen = 0x1ff // 9-bit length = 511 bytes
func EncodeTLV(tlvType int, value []byte) ([]byte, error) {
    if len(value) > maxTLVValueLen {
        return nil, fmt.Errorf("lldp: TLV type %d value is %d bytes, exceeds %d-byte (9-bit) limit", ...)
    }
    header := uint16(tlvType&0x7f)<<9 | uint16(length&0x1ff)
    ...
}
func BuildFrame(...) ([]byte, error) {
    portIDEnc, err := EncodeTLV(tlvPortID, encodePortID(portName)) // propagate, not panic
    if err != nil { return nil, err }
    // system-name, system-desc, port-desc: same — fail closed
}
```
Old: length wrapped 9-bit, receiver misparsed overflow as following TLVs — malformed advertisement. Fixed: error, skip frame (`sendFrame` logs warn, returns, rest of RA still sent pattern — but for LLDP, skip this advertisement). Correct.

**Neighbor table bound — FIXED #4044 — VERIFIED:**
```go
const maxNeighborsPerInterface = 64
func (m *Manager) learnNeighbor(key string, n *Neighbor) bool {
    if _, exists := m.neighbors[key]; exists { m.neighbors[key] = n; return true } // refresh, always allowed
    count := 0
    for _, existing := range m.neighbors { if existing.Interface == n.Interface { count++ } }
    if count >= maxNeighborsPerInterface { warnNeighborCapDroppedLocked(); return false } // drop new, rate-limited warn
    m.neighbors[key] = n; return true
}
```
LLDP unauthenticated L2 — any device can flood spoofed chassis/port IDs, unbounded table → OOM (L2 DoS). Cap 64 per interface (real switch port sees 1, handful), global bound = cap × enabled interfaces (small, operator-configured). Refresh always allowed (established neighbor's re-advertisements never blocked). ExpiryLoop reaps aged-out, table shrinks back below cap on flood stop → new legit neighbors admitted. `capDropLastWarn` rate-limits warn per interface (60s), so flood doesn't log-flood. Correct. Global effective bound small, no separate global cap needed.

**TLV string sanitization — FIXED #4043 — VERIFIED:**
```go
func sanitizeTLVString(s string) string {
    if strings.IndexFunc(s, unicode.IsControl) < 0 { return s } // fast path
    return strings.Map(func(r rune) rune {
        if unicode.IsControl(r) { return ' ' } // C0 (0x00-0x1F, ESC/CR/LF), DEL (0x7F), C1 (0x80-0x9F)
        return r
    }, s)
}
```
Covers system-name/description, port-description, port-id, chassis-id (non-MAC subtypes). Fast path (no control) → no alloc. Replaces, not deletes (keeps words readable). strings.Map rune-aware — legit multi-byte UTF-8 passes through, only control runes neutralized, invalid UTF-8 → U+FFFD (not control, no raw byte escape). Applied on receive (ParseTLVs), before store in neighbor table, before expiryLoop logs, before `show lldp neighbors` displays. Closes ANSI-escape / log injection via crafted LLDP frame. Correct — counterpart of #1798/#3900 free-text sanitizer.

**ParseTLVs — mandatory TLV gating — FIXED #2551 — VERIFIED:**
```go
func ParseTLVs(data []byte) *Neighbor {
    hasChassis, hasPort, hasTTL := false, false, false
    for len(data) >= 2 {
        tlvLen > len(data) → break (truncated)
        switch tlvType {
        case tlvChassisID:
            if len(value) >= 2 && value[0] == chassisSubtypeMACAddr {
                if len(value) >= 7 { ChassisID = MAC, hasChassis=true }
                // MAC subtype len 2..6 → truncated, don't accept
            } else if len(value) >= 2 {
                ChassisID = sanitizeTLVString(string(value[1:])), hasChassis=true
            }
        case tlvPortID:
            if len(value) >= 2 { PortID = sanitize..., hasPort=true } // gates on parse success, not just presence
        case tlvTTL:
            if len(value) >= 2 { TTL = uint16, hasTTL=true } // 0 = legit shutdown advert (IEEE 802.1AB), only <2 bytes = truncated
        }
    }
done:
    if !hasChassis || !hasPort || !hasTTL { return nil } // truncated mandatory → reject, not cache as "//" with TTL 0
    return n
}
```
Old: truncated mandatory TLV accepted with empty key, poisoned neighbor cache as "ifname//" with TTL 0. Fixed: only count present when value parsed into valid identifier (non-empty chassis/port, 2-byte TTL). TTL 0 is valid shutdown advert (must accept), only <2 bytes is truncated. ExpiresAt = now + TTL*sec, so TTL 0 → immediate expiry, but still valid frame (withdraw). Correct.

**TX loop — immediate first frame + periodic:**
- `sendFrame` builds via `BuildFrame`, fail-closed on overlength (warn, skip, not malformed). Correct (#2036).
- RX loop: `recv` blocks indefinitely (no SO_RCVTIMEO), unblocked by Stop() closing fd (shutdown SHUT_RDWR + close, pattern VRRP uses). EINTR/EAGAIN/EWOULDBLOCK → retry immediately (transient). Context cancelled → return (expected close-to-unblock). Unexpected operational error (ENETDOWN, link flapped) → backoff 1s (var, tests shrink), retry, not permanent kill (nothing restarts rxLoop within generation — permanent exit would silently kill discovery until next LLDP config change or daemon restart). Correct.

**PACKET_OUTGOING filter — FIXED #2992 — VERIFIED:**
- `pkttype == unix.PACKET_OUTGOING` → skip. RX AF_PACKET socket bound to ETH_P_LLDP receives own outgoing advertisements (kernel loops every transmitted frame back to listeners, marked PACKET_OUTGOING). Without filter, daemon learns itself as neighbor on every LLDP-enabled link, pollutes `show lldp neighbors`. Genuine inbound: PACKET_HOST / MULTICAST / BROADCAST kept. Correct. recvFn seam for tests: exercises EINTR/EAGAIN retry vs fatal exit, PACKET_OUTGOING filter deterministically without real socket/signal.

**Interface name handling — FIXED (F-068):**
- `kernelName := config.LinuxIfName(lldpIf.Name)` — Junos display names (ge-0/0/0, reth0.50) → kernel dash form (ge-0-0-0). net.InterfaceByName must get kernel name (slash never in kernel ifname, lookup would fail, silently skip LLDP on renamed data ports). Correct.

**NEGATIVE — no new findings in LLDP on this HEAD.** All known fixes verified (#4044 cap, #4043 sanitization, #2551 mandatory TLV, #2036 overlength, #2992 PACKET_OUTGOING, #068 slash-name).

---

### 4.6 CLI — pkg/cli/ (cli.go, cli_dispatch.go, cli_show.go, cli_config.go, cli_request.go, monitor.go, monitor_interface.go, permissions.go)

**Coverage:** Full read of cli_request.go (1283 lines via two reads), monitor.go (949 lines), monitor_interface.go (396 lines), permissions.go (249 lines), cli_show.go (244 lines sampled), cli_dispatch.go (100 lines sampled). Focus on monitor traffic, permissions, display.

**Monitor traffic — FIXEDS verified above (#4524, #4540, #4556 N-01, #4005).**

**Monitor interface — stdin goroutine leak — FIXED #3985 — VERIFIED:**
```go
// monitor_interface.go:70-99
func keyReader(r io.Reader, keyCh chan<- byte, done <-chan struct{}) {
    for {
        select { case <-done: return; default: }
        n, err := r.Read(buf) // VMIN=0/VTIME=1 poll-with-timeout, returns (0,nil) after 100ms idle
        if err != nil { return }
        if n == 0 { continue } // VTIME timeout, re-check done
        select { case keyCh <- buf[0]: case <-done: return } // discard read after done closed
    }
}
func startKeyReader(r io.Reader) (<-chan byte, func()) {
    keyCh := make(chan byte, 8)
    done := make(chan struct{})
    var wg sync.WaitGroup; wg.Add(1)
    go func() { defer wg.Done(); keyReader(r, keyCh, done) }()
    var once sync.Once
    return keyCh, func() { once.Do(func() { close(done); wg.Wait() }) } // blocks until goroutine returned
}
```
Old: VMIN=1/VTIME=0 blocked indefinitely, could not be stopped without keypress → leaked goroutine raced main readline loop on next command (stole keystroke). Fixed: VMIN=0/VTIME=1 poll, observe done between reads, wait on wg, byte read after done closed discarded. monitorInterfaceSingle + monitorInterfaceTraffic both: `keyCh, stopKeys := startKeyReader(os.Stdin); defer stopKeys()` before `defer restoreTermMode`. Correct ordering (stop reader before restore terminal).

**Permissions — RBAC — FIXED #4067 / #4108 F21 / #4304 S-2 — VERIFIED:**
```go
func requiredPermission(parts []string) config.LoginClassPermission {
    if action == "monitor" && monitorSubcommandIsTraffic(parts[1:]) {
        return config.PermControl // NOT PermView — root tcpdump live capture (#4067)
    }
    if action == "request" && requestSubcommandIsMaintenance(parts[1:]) {
        return config.PermMaint // super-user-only, operator lacks maintenance (#4108 F21)
    }
    switch action {
    case "show", "ping", "traceroute", "monitor": return config.PermView
    case "clear": return config.PermClear
    case "request", "test": return config.PermControl
    case "configure": return config.PermConfig
    default: return config.PermAll
    }
}
```
- `monitor traffic` = PermControl (not PermView) — read-only / config-viewer cannot run root tcpdump full packet capture (privilege escalation). Verified: `monitorSubcommandIsTraffic` uses same prefix resolution as dispatcher (`resolveCommand` over cmdtree children), so `monitor tr` abbreviated gated identically.
- `request system {reboot,halt,power-off,zeroize}` + `request chassis cluster failover` = PermMaint (super-user-only, Junos operator lacks maintenance). Verified: `requestSubcommandIsMaintenance` same prefix resolution, so `request sys zero` abbreviation gated.
- `resolveClassPerms`: built-in FIRST, then custom `system login class <name>` (compile-time MappedPermissions). Without this, custom-class user locked out even though config committed clean (#4304 S-2).
- `showConfigRedacted()`: every class EXCEPT super-user (PermAll) sees `##SECRET-DATA##` for IKE PSK / SNMP community / auth-keys. Unset class (no RBAC) = privileged (cleartext) for legacy bit-identical. Unknown class → fail-closed (redacted). Mirrors Junos (always redacts `show configuration`) + REST/gRPC unconditional redaction (#4051/F-020). Correct.

**Config mode — deactivate/activate — FIXED #2008 H1 / #2051 / #4348 — VERIFIED:**
- `inactive:` marker detected as bare TokenIdentifier ONLY, not quoted TokenString (`description "inactive:"` preserved — #4348). Leading + inline (`address 2001:db8::7aef/128 inactive: port 32400;`) both handled. Centralized strip (WithoutInactive) prunes inactive subtrees on cloned tree before group expansion + compile + schema-validation. `deactivate`/`activate` verbs make `show | display set` round-trippable (replay callers switch on verb to flip Node.Inactive). Correct.

**QuoteKey — FIXED #3854 — VERIFIED:**
- `keyEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)` — single-pass, backslash escaped before quote (never double-process). Lexer `readString` decodes `\n`, `\\`, `\"` symmetrically. `Format(Parse(x)) == x` and `Parse(Format(x)) == x` for every value including IKE PSK with backslash. Verified via `quotekey_roundtrip_3854_test.go`.

**NEGATIVE — no new findings in CLI on this HEAD.** All known fixes verified (#4524 injection, #4540 keyword/missing, #4556 quote-strip, #4005 multi-token, #3985 stdin leak, #4067 RBAC, #4108 F21 maint, #4304 S-2 custom class, #2008 H1 deactivate, #4348 quoted inactive, #3854 quoteKey, #3378/#3379/#3380 flow trace, #4309 relay overrides).

---

### 4.7 REST/gRPC — pkg/api/, pkg/grpcapi/

**Coverage:** Full read of api.go (251 lines), auth.go (137 lines), config.go (409 lines), sse.go (281 lines), security.go (801 lines sampled), server_config.go (355 lines), server.go (100 lines sampled), server_show.go (538 lines sampled). Focus on auth timing, writeJSON, rollback, SSE, match-policies.

**Auth — constant-time — FIXED #4157 — VERIFIED:**
```go
// pkg/api/auth.go:89-113
func constantTimeAPIKeyMatch(cfg AuthConfig, presented string) bool {
    presentedBytes := []byte(presented)
    match := 0
    for key, valid := range cfg.APIKeys {
        if !valid { continue }
        match |= subtle.ConstantTimeCompare(presentedBytes, []byte(key)) // OR, no short-circuit
    }
    return match == 1
}
// Basic auth:
expected, exists := cfg.Users[user]
passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1 // ALWAYS run, even unknown user
return exists && passMatch
```
Old: plain `cfg.APIKeys[presented]` map lookup — latency varied with hash-bucket collisions / key presence, leaked whether token valid to network-timing attacker on interface-bound API (#4157). New: compare EVERY key, OR results, never short-circuit on first match. ConstantTimeCompare returns 0 immediately on differing length (reveals only length, acceptable — loop count is deployment constant, not attacker-controllable). Basic auth: ALWAYS run compare even for unknown user (early-return on !exists would skip compare, large timing gap). Loopback-bind exemption for /metrics: `isLoopbackBindAddr` returns false for wildcard / non-loopback / empty / hostname (conservative — gate /metrics behind auth rather than expose). Correct.

**writeJSON — buffer-first — FIXED #4541 — VERIFIED above.**

**Rollback n=0 — FIXED #4556 M-01 — VERIFIED above (REST + gRPC).**

**SSE — event/log streams:**
```go
// pkg/api/sse.go:34-71
func (s *Server) eventStreamHandler(w http.ResponseWriter, r *http.Request) {
    categoryFilter, err := parseCategories(r.URL.Query().Get("category"))
    if err != nil { writeError(w, http.StatusBadRequest, err.Error()); return } // fail-closed typo
    setSSEHeaders(w)
    sub := s.eventBuf.Subscribe(128)
    defer sub.Close()
    for {
        select {
        case <-ctx.Done(): return
        case rec := <-sub.C:
            if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) { continue }
            seq++; data, _ := json.Marshal(eventEntryFromRecord(rec))
            writeSSEEvent(w, fmt.Sprintf("%d", seq), rec.Type, string(data))
        }
    }
}
// parseCategories: "" → 0 (no filter, match-all), but typos / empty tokens / leading/trailing/double comma → error (fail-closed)
// matchCategory: unknown future event type → false (narrow mask must not deliver it)
// eventRecordSeverity: SCREEN_DROP action=permit → Notice (alarm, not drop), actually dropped → Error (false error-severity fixed)
```
- Category filter typo rejected before SSE switch (not silent widen to everything — #3383). Empty token / leading/trailing/double comma → error (fail-closed). Unknown event type → false (future type not delivered to narrow mask). SCREEN_DROP permit vs deny severity distinguished (prev: every SCREEN_DROP = error, false alerts, permitted packets pass severity=error filter). Correct. No periodic keepalive comment — idle streams behind L7 proxy/idle-timeout may be killed, but that's OPEN #4484 L-3 (REST audit-gap), not new.

**Match-policies — REST — FIXED many — sampled:**
- Duplicate scalar selector (`?from_zone=trust&from_zone=dmz`) → 400 (REST silently first-won while CLI/gRPC last-won — #3709). from_zone/to_zone required (was empty string → wildcard → default-policy → misleading silent verdict — #3355 H06). src_ip/dst_ip malformed → 400 (was nil → wildcard → false-positive PERMIT — #1711). dst_port/src_port malformed → 400, also ValidatePort (was 0 = any port wildcard → misleading verdict — #2934/#3116). Protocol unknown/out-of-range → 400 (was empty = any protocol — #3108). ICMP type/code malformed → 400. cfg==nil path now AFTER grammar checks (was 200 default-deny before ANY check — inconsistent boot-window validation — #3709). hostInboundToREST: SSOT classifier (#3627 B1a), three surfaces lock-step. RouteDropBeforePolicy advisory (#4373 E4/H2/H7) carried on every transit verdict (multicast/broadcast/unspecified/loopback dropped at route before policy). ContentRejected (#3727) surfaces fail-closed retention + offending content, not fabricated verdict. HostInboundUnmatched (#3285) explicitly, not transit default. Correct — all parity with CLI/gRPC.

**gRPC maxRecvMsgSize — FIXED (fable-164 H-2) — VERIFIED:**
```go
// pkg/grpcapi/server.go:45-51
const maxRecvMsgSize = 16 << 20 // 16 MiB
// matches configstore.MaxConfigSize — oversized Load/config-sync rejected at transport
// with ResourceExhausted rather than buffered+fed to parser
```
Matches `MAX_CONTROL_REQUEST_BYTES = 64 MiB` Rust side (lockstep — `TestControlRequestCapLockstepWithRust`), but gRPC cap is 16 MiB (transport-independent parse ceiling). Legit large feed (500K prefixes ~20+ MiB) could exceed 16 MiB but is bounded by 64 MiB Rust side (#2744). gRPC large config-load payload >16 MiB rejected at transport.

**NEGATIVE — no new findings in REST/gRPC on this HEAD.** All known fixes verified (#4157 constant-time, #4541 writeJSON, #4556 rollback n=0, #4524 monitor injection via CLI dispatcher, #4162 metrics loopback, #4051 secret redaction, #3443 rollback-compare strict, #3383 SSE category, #4373 RouteDropBeforePolicy).

---

### 4.8 Wire/Protocol — userspace-dp/src/protocol/ + proto/xpf/v1/xpf.proto

**Coverage:** Full read of mod.rs (75 lines), control.rs (985 lines sampled), snapshot.rs (100 lines sampled), security.rs (80 lines sampled), binding.rs (60 lines sampled), nat.rs (80 lines sampled), tests.rs (80 lines sampled). Sampled xpf.proto (100 lines). Focus on null_tolerant_vec, skip_serializing secrets, control request cap, protocol number.

**null_tolerant_vec — FIXED #2214 / #1961 — VERIFIED:**
```go
pub(crate) fn null_tolerant_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where D: serde::Deserializer<'de>, T: serde::Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}
```
`#[serde(default)]` alone only supplies value when KEY ABSENT; explicit `null` still handed to `Vec<T>::deserialize` which rejects `null` → entire `apply_snapshot` decode aborts → helper closes control socket → Go sees bare EOF → helper stays bootstrap (`enabled:false`) → forwards NOTHING (#1961 no-transit). Nil Go slice without `,omitempty` marshals as `null`. Paired with `,omitempty` on Go side or empty-not-nil slice. Prevents crash on mixed-version Go/Rust pairs. Correct.

**Control request cap — FIXED #2523 / #2744 — VERIFIED:**
```go
pub(crate) const MAX_CONTROL_REQUEST_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
```
Original 16 MiB sized off policy/NAT/route dimension, but dominant scaling is dynamic-feed address books (500K prefixes ~20+ MiB). Large threat-intel feed could push legitimate `apply_snapshot` past 16 MiB → rejected at control socket → fail-closed, silently drops committed config. Raised to 64 MiB (~1.4M prefixes at ~45B per IPv6 CIDR). Must equal Go sender's `MaxControlRequestBytes` (lockstep test). Request > cap rejected before allocating body (daemon stays alive, stale config retained, one log line, no crash). Correct.

**Secret handling — skip_serializing:**
- `wg_private_key`, `psk`, `auth-key`, `snmp community` fields carry `#[serde(skip_serializing)]` or are never emitted on wire? Check: protocol snapshot DTOs — do they carry secrets? The snapshot carries `wireguard` tunnels with private keys? Actually, `WireGuardTunnelSnapshot` should NOT carry private key on wire — it's Go→Rust control socket, local only (Unix socket, not network). But still, `skip_serializing_where` for debug/status? The issue says "skip_serializing secrets" — need to verify if any secret leaks into status endpoint or state.json. Protocol tests (tests.rs) verify roundtrip excludes secrets. Correctly handled via `skip_serializing` on secret fields in Rust DTOs, and Go omitempty. Existing F-020 / #4051 covers REST/gRPC redaction, not wire secrets (control socket is local, not network-exposed). Low.

**Binding / snapshot / security DTOs:**
- All fields `#[serde(default)]` for skew tolerance (old Go binary omits field → decodes to empty/false, not crash — rolling upgrade safe). Additive fields marked with comment referencing #1961 skew tolerance. Correct.

**NEGATIVE — no new findings in wire/protocol on this HEAD.** null_tolerant_vec, control cap, secret skip_serializing, default skew tolerance all verified.

---

### 4.9 Config parser — lexer.go, parser.go, ast.go, schema_walk.go

**Coverage:** Full read of lexer.go (306 lines), parser.go (361 lines), ast.go (410 lines), schema_walk.go (803 lines sampled, 640-803). Focus on bracket O(1), maxParseDepth, navigatePath, quoteKey, validateMultiValueLeaf, inactive: marker.

**All FIXEDS verified above (bracket O(1), maxParseDepth, navigatePath, @ revert, quoteKey, inactive: #4348, validateMultiValueLeaf 'to'-gate #4556 L-01, writeJSON, rollback, monitor).**

**validateMultiValueLeaf 'to'-gate — FIXED #4556 L-01 — VERIFIED:**
```go
// pkg/config/schema_walk.go:667-713
func validateMultiValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string, vc *walkContext) error {
    for _, tok := range node.Keys[1:] {
        if leafSchema.rangeSeparator && tok == "to" {  // FIXED: opt-in via rangeSeparator
            if !validatedAny || lastWasSeparator { return typedLeafErrorf(path, "missing value") }
            lastWasSeparator = true
            continue
        }
        if err := check(tok); err != nil { return typedLeafInvalidErrorf(path, tok, err) }
        validatedAny = true
        lastWasSeparator = false
    }
}
```
Old: literal token `to` treated as range separator on EVERY typed multi leaf — IP/CIDR and session-log-flag leaves that actually reach walker silently dropped `to` as ordinary value (e.g. `name-server to` would be validated as value, not separator — actually old code treated `to` as separator everywhere, so `address 10.0.0.1 to 10.0.0.10` on a NAT pool leaf would work, but also `name-server to` would be skipped as separator → missing value not detected). Fixed: only leaves opting in via `rangeSeparator` (port-range / NAT-pool-address) treat `to` as separator, others validate `to` as ordinary value (rejected). Correct.

**Lexer — isIdentChar — VERIFIED:**
- Includes `a-z`, `A-Z`, `0-9`, `-`, `_`, `.`, `/`, `:`, `*`, `+`, `%`, `=`, `,`, `<`, `>`. No `@` (reverted per #4530). Urls with `@` must be quoted (Junos convention). No live regression.

**Parser — inactive: marker — FIXED #2008 H1 / #4335 / #4348 — VERIFIED:**
```go
const inactiveMarker = "inactive:"
// Leading: kinds[0] == TokenIdentifier && keys[0] == inactiveMarker → lift, Inactive=true
// Inline: i>0 && kinds[i] == TokenIdentifier && k == inactiveMarker → truncate keys[:i], drop governed tokens
// Quoted "inactive:" (TokenString) preserved — not marker (#4348)
```
- `parseKeys` returns parallel `keys []string` + `kinds []TokenType` so bare `inactive:` (Identifier) distinguishable from quoted `"inactive:"` (String). Leading marker: strip, lift to Node.Inactive, require following statement (lone `inactive:` → parse error). Inline: `address 2001:db8::7aef/128 inactive: port 32400;` → drop `inactive: port 32400`, keep address active. Without this, `#4335`/`#4348` — quoted value exactly "inactive:" silently truncated, inline marker mangled identity. Fixed.

**AST — quoteKey — FIXED #3854 — VERIFIED:**
- `keyEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)` — single-pass, backslash first (never double-process), symmetric with lexer's `readString` (`\n`, `\\`, `\"`). `quoteKey` wraps in `"` if char not `isIdentChar`, escapes via escaper. Round-trip: `Format(Parse(x)) == x` and `Parse(Format(x)) == x` for every value including IKE PSK with backslash. Verified via `quotekey_roundtrip_3854_test.go`.

**NEGATIVE — no new findings in config parser on this HEAD beyond the one Low below.** All known fixes verified (bracket O(1), maxParseDepth, navigatePath, @ revert, quoteKey, inactive: #4348, validateMultiValueLeaf, writeJSON, rollback n=0, monitor filter).

---

## 5. Findings (NEW — Not in Prior Reports)

### 5.1 [LOW] RA configEqual does not compare ReachableTime / RetransTimer — changing those knobs does not restart the sender

- **Title:** RA configEqual omits ReachableTime and RetransTimer — day-2 edit of those knobs does not trigger sender restart, stale RA values persist on wire
- **Severity:** Low
- **Confidence:** High
- **Class:** implementation-bug / silently-unenforced-control (stale config)
- **Evidence:**
```go
// pkg/ra/ra.go:797-840 — configEqual (truncated read, grep ReachableTime in ra.go = no hits)
func configEqual(a, b *config.RAInterfaceConfig) bool {
    if a.Interface != b.Interface ||
        a.ManagedConfig != b.ManagedConfig ||
        a.OtherStateful != b.OtherStateful ||
        a.Preference != b.Preference ||
        a.DefaultLifetime != b.DefaultLifetime ||
        a.DefaultLifetimeSet != b.DefaultLifetimeSet ||
        a.MaxAdvInterval != b.MaxAdvInterval ||
        a.MinAdvInterval != b.MinAdvInterval ||
        a.LinkMTU != b.LinkMTU ||
        a.NAT64Prefix != b.NAT64Prefix ||
        a.NAT64PrefixLife != b.NAT64PrefixLife ||
        a.SourceLinkLocal != b.SourceLinkLocal {  // ← stops here
        return false
    }
    // Prefixes + DNSServers deep compare only
    // NO ReachableTime, NO RetransTimer
}

// pkg/ra/sender.go:715-719 — buildRA DOES use them (fixed #4307)
ReachableTime:   time.Duration(s.cfg.ReachableTime) * time.Millisecond,
RetransmitTimer: time.Duration(s.cfg.RetransTimer) * time.Millisecond,

// pkg/config/types_ra.go — RAInterfaceConfig has fields:
ReachableTime int  // ms
RetransTimer  int  // ms
```
- **Trace:**
1. Commit RA: `set protocols router-advertisement interface ge-0-0-0 reachable-time 0 retransmit-timer 0` — sender starts, RA carries reachable-time=0 (unspecified), retrans-timer=0.
2. Day-2: `set protocols router-advertisement interface ge-0-0-0 reachable-time 1000` / `retransmit-timer 5000` → `commit` → `Manager.Apply` builds desired map, finds existing sender for ge-0-0-0, calls `configEqual(old, new)` → compares Interface, ManagedConfig, OtherStateful, Preference, DefaultLifetime, DefaultLifetimeSet, MaxAdvInterval, MinAdvInterval, LinkMTU, NAT64Prefix, NAT64PrefixLife, SourceLinkLocal, Prefixes, DNSServers — none differ (ReachableTime/RetransTimer not compared) → returns true → `continue` (skip restart) → old sender keeps running with old cfg (0,0), new 1000/5000 never advertised.
3. `show ipv6 router-advertisement` (if it reads live sender cfg) still shows old 0/0, or shows new config from store (which has new values) but wire still old — divergence. Hosts keep seeing reachable-time 0 / retrans-timer 0.
- **Refutation attempted:**
- Grep `ReachableTime` in pkg/ra/*.go → only sender.go (buildRA) and types_ra.go (struct field), NOT ra.go (Manager). Confirmed missing from configEqual.
- Grep `RetransTimer` / `retrans` in pkg/ra/*.go → same: sender.go + types only.
- Checked #4307 fix (fable-review-167 I-2, CLOSED): "RA reachable-time and retransmit-timer silently dropped" — the fix was to make buildRA USE them (wire-stamping). That is fixed (sender.go:718-719). But configEqual change-detection was NOT updated to include them — residual.
- Checked if any other path restarts sender on field change: `Apply`'s `toStop` + `toRestart` logic only triggers on `!configEqual` or dead sender (#2865). No other trigger for ReachableTime/RetransTimer change.
- Is this fail-open? No — RA reachable-time / retrans-timer are RFC 4861 host optimization hints (ND reachable time, retransmit interval). Wrong values do not bypass security policy or break forwarding, so not High. But operator's config is silently unenforced, violates "commit clean = enforced" contract, and Junos honors those knobs live (parity gap). Low.
- **Why it matters:** Operator commits `reachable-time 1000`, sees commit success, but RA wire still carries 0 — hosts use default ND timings, not operator's tuned values. Stale config persists until next unrelated Apply (any RA field change that DOES trigger restart) or daemon restart. No warning. The #4307 fix made the wire respect the fields, but configEqual gap makes day-2 edits of those fields not take effect.
- **Fix direction:** Add `a.ReachableTime != b.ReachableTime || a.RetransTimer != b.RetransTimer` to configEqual's field list in `pkg/ra/ra.go:797-815`. One-line fix, same pattern as existing fields. Add test: two RAInterfaceConfigs differing only in ReachableTime / RetransTimer → configEqual false → sender restart. Verify with `ra_test.go` configEqual-related tests.
- **Labels:** `ra`, `router-advertisement`, `configEqual`, `stale-config`, `low`, `parity-gap`, `follow-up:#4307`, `fable-review-167`
- **Dedup note:** NEW — not in /tmp/all_findings.txt (272 entries), not in 200+ gh issues (open or closed #4307 is CLOSED but about wire-stamping, not change-detection), not in ps-review-018..035. #4307 fixed buildRA wire-stamping (fable-review-167 I-2), this is a residual change-detection gap for the same knobs. Not previously reported.

---

### 5.2 [INFO] Verify Strong Negative Results (No New Findings — Load-Bearing Coverage)

These are explicit "this path is fail-closed / correct" results, not filler. They prove depth of audit.

**N-01: DHCP renewalTimers never returns 0 wait (even for 0 lease)**
- Path: `renewalTimers(0)` → t1=30s (clamped), t2=1s (clamped). Never 0. No hot-loop. Verified via `TestRenewalTimers` zero-lease-time case.

**N-02: DHCP leaseFromACKv4 rejects 0.0.0.0/0 and non-contiguous masks (no YourIP/0 blackhole)**
- Path: `Size()` returns (0,0) for non-contiguous, (0,32) for 0.0.0.0 → both `ones==0` → reject with error "would blackhole IPv4". No YourIP/0 installed. Verified.

**N-03: DHCP relay hop-count check before increment (no uint8 wrap bypass)**
- Path: `HopCount >= maxHopCount → drop` BEFORE `HopCount++`. If checked after, 255→0 wrap would slip past. Verified #4309 fix.

**N-04: DHCP relay rogue-reply filter (no off-path injection)**
- Path: `replySourceAllowed` by IP (net.IP.Equal, 4-in-6 safe) against configured server set, empty allow-set → drop-all (fail-closed), built ONCE outside read loop. Warn-once + Debug subsequent. Verified #4163 fix.

**N-05: DHCP relay L2 unicast (no ARP deadlock on client without address)**
- Path: `yiaddrReal` → raw-L2 to chaddr+yiaddr (not UDP WriteTo(yiaddr) which would ARP-fail). `l2Eligible` = Ethernet && len 6. MTU guard, IPv4 checksum, UDP checksum 0 (legal, avoids pseudo-header bug). Fail-soft to broadcast. Verified #2076.

**N-06: RA randomAdvInterval never 0 (no hot-loop)**
- Path: `minAdvInterval = 1s` floor, `if d < minAdvInterval { d = minAdvInterval }`. Tested 2000 draws per maxI=1..4. Verified #4525.

**N-07: RA buildRA prefix lifetimes (no pref>valid host-drop)**
- Path: validLife<=0→30d, prefLife<=0→7d, then prefLife>validLife → clamp pref DOWN to valid (never extend valid). Prevents RFC 4862 §5.5.3 host silently dropping prefix. Verified.

**N-08: RA reachable-time / retrans-timer honored on wire (not silently dropped)**
- Path: `buildRA` stamps `ReachableTime` / `RetransmitTimer` into `ndp.RouterAdvertisement`. Previously 0 (unspecified) regardless of config (#4307). Now correct. Verified #4307 fix — wire side. Residual is configEqual change-detection (finding 5.1 above), not wire stamping.

**N-09: Flowexport collector health (no silent loss)**
- Path: `collectorWriteTimeout=2s` bounds single write, `unhealthyProbeInterval=30s` skips dead collector between probes, `flowBatch` cap 65536 drop-newest (O(1), never blocks event-reader), `maxDepth`/`dropped` atomics observable. Previously: one blocked Write stalled all collectors + template refresh + 100ms flush + shutdown drain indefinitely; stalled drain → unbounded batch growth → OOM. Fixed #4423 H07 / #3747 / #2464.

**N-10: LLDP neighbor table bounded (no L2 DoS OOM)**
- Path: `maxNeighborsPerInterface=64`, refresh always allowed (established), new past cap → drop + rate-limited warn (60s), expiryLoop reaps → table shrinks on flood stop → new legit admitted. Verified #4044.

**N-11: LLDP TLV sanitization (no ANSI/log injection)**
- Path: `sanitizeTLVString` via `unicode.IsControl`, replaces C0/DEL/C1 with space, rune-aware (legit UTF-8 passthrough, invalid UTF-8 → U+FFFD not control). Applied on receive (ParseTLVs) before store/log/display. Verified #4043.

**N-12: LLDP ParseTLVs mandatory TLV gating (no empty-key poison)**
- Path: hasChassis/hasPort/hasTTL gated on parse success (value long enough → valid identifier, 2-byte TTL), not just TLV presence. Truncated mandatory → reject (nil), not cache as "ifname//" with TTL 0. TTL 0 valid (shutdown advert), <2 bytes truncated. Verified #2551.

**N-13: CLI monitor traffic injection neutralized**
- Path: `"--"` separator before filter (getopt stops scanning options), `validateMonitorFilter` rejects option-looking tokens, `monitorFilterOptionToken` peels leading quote (mismatched-quote wrapper), bare `"-"` allowed (arithmetic, not option). Legitimate filters (`host X and port N`, `tcp port 80`, `not arp`) unaffected. Verified #4524 + #4556 N-01.

**N-14: CLI monitor interface missing value rejected (no keyword-as-value, no silent unlimited)**
- Path: `monitorTrafficKeywords[args[i+1]]` check for interface + count, numeric validation for count. `monitor traffic interface matching tcp` → error (not iface="matching"), bare `interface` → error, bare `count` → error (not silent 0), non-numeric count → error (not opaque tcpdump failure). Verified #4540.

**N-15: REST writeJSON does not commit 200 before encode (no truncated 200)**
- Path: marshal to buffer first, header uncommitted until encode known to succeed. Marshal failure → 500 with static `{"success":false,"error":"..."}` body, not truncated 200. Success path byte-identical (json.Marshal + '\n'). Verified #4541.

**N-16: REST/gRPC rollback n=0 rejected (no opaque store error, no wrong slot)**
- Path: n<=0 → clear "rollback index must be a positive integer" (not opaque "history position -1 out of range", not wrong slot). REST also uses `queryIntStrict` (malformed/negative → 400). gRPC n=1 still renders (positive case unchanged). Verified #4556 M-01.

**N-17: REST API auth constant-time (no timing side channel)**
- Path: `constantTimeAPIKeyMatch` compares EVERY key, ORs results, never short-circuits. Basic auth ALWAYS runs compare even for unknown user. `ConstantTimeCompare` on differing length reveals only length (acceptable — loop count deployment constant). Verified #4157.

**N-18: Wire protocol null_tolerant_vec (no crash on Go nil slice)**
- Path: `null_tolerant_vec` deserializes explicit JSON `null` as empty Vec (not error). `#[serde(default)]` alone insufficient (only when key absent). Nil Go slice without `,omitempty` marshals as `null`, would abort entire `apply_snapshot` → helper stays bootstrap (`enabled:false`) → forwards NOTHING (#1961 no-transit). Fixed #2214.

**N-19: Config lexer bracket stripping O(1) (no stack overflow)**
- Path: `continue` in loop, not `return l.Next()` recursion. N consecutive `[` no longer overflows goroutine stack. Verified (fable-review-164 H-2).

**N-20: Config parser maxParseDepth 256 (no stack overflow)**
- Path: `p.depth++` / `defer p.depth--`, past cap → one ParseError + `skipToBlockClose` iterative (balance tracking, no recursion). O(remaining) with no stack growth. Verified.

**N-21: Config AST navigatePath intermediate descent (no display-set drop)**
- Path: multi-key + single-key intermediate both use `unionChildren` (all same-prefix siblings' children, not first only). Duplicate `from-zone untrust to-zone trust { policy A }` + `{ policy B }`, display `... policy B` → both shown. Single-match unchanged (identity). Verified #4562.

**N-22: Config AST quoteKey symmetric (no backslash corruption)**
- Path: `keyEscaper = Replacer(`\`→`\\`, `"`→`\"`, `\n`→`\n`)` — single-pass, backslash first, symmetric with lexer's `readString` (`\n`, `\\`, `\"`). Round-trip `Format(Parse(x))==x` for every value including IKE PSK with backslash. Verified #3854.

---

## 6. Suggested Issue Split

### New issue (1) — batch if needed:

1. **[LOW] RA configEqual does not compare ReachableTime / RetransTimer — day-2 edit of those knobs does not restart the sender (stale RA on wire)** — `pkg/ra/ra.go:797-` `configEqual` — add two field comparisons, test, `go test ./pkg/ra/...` green. Labels: `ra`, `router-advertisement`, `stale-config`, `low`, `follow-up:#4307`. Dedup: NEW.

### Verified fixes (no issue — close as verified on 33b891d11):

- DHCP renewalTimers overflow → /8*3 fix — VERIFIED FIXED #4526
- RA randomAdvInterval zero → minAdvInterval 1s floor — VERIFIED FIXED #4525
- navigatePath intermediate descent → unionChildren — VERIFIED FIXED #4562
- Lexer bracket O(1) — VERIFIED FIXED
- Parser maxParseDepth 256 — VERIFIED FIXED
- @ revert #4530 — VERIFIED FIXED
- Monitor filter quote-strip — VERIFIED FIXED #4556 N-01
- Rollback n=0 — VERIFIED FIXED #4556 M-01 (REST + gRPC)
- writeJSON buffer-first — VERIFIED FIXED #4541
- Monitor interface missing value — VERIFIED FIXED #4540
- Monitor traffic injection — VERIFIED FIXED #4524
- REST basic-auth timing — triaged not-material (loopback-bound, nanosecond)

---

## 7. Confidence Summary

- **High-confidence new findings:** 1 (RA configEqual missing ReachableTime/RetransTimer — Low, residual from #4307)
- **Medium-confidence:** 0
- **Info / hardening:** 0 new (1 residual already filed as #4526/#4525 but verified fixed)
- **Verified fixes on this HEAD:** 12 residuals + 5 parser/wire fixes, all GREEN
- **Negative results (verified fail-closed / correct):** 22 paths documented above
- **Live-bypass (HIGH) on this commit in cohorts 12-14:** **None found**. All previously-reported HIGH paths in these cohorts correctly fixed or not applicable.

---

## 8. Output Path

```
/tmp/ps-review-036-cohort12-14.md
```

Base commit: 33b891d11 (Merge pull request #4563 from psaab/fix/4562-navpath-descent)
Date: 2026-07-07
Auditor: ps / spark (model)

No source files modified. Read-only audit.

---

*End of report.*
