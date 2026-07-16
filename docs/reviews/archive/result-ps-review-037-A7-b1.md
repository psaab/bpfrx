# Triage result — ps-review-037-A7-b1

- **Batch**: ps-review-037-A7-b1
- **Subsystem**: A7 — Daemon lifecycle & host integration (core firewall / VRRP-HA failover & cold-boot / integer-truncation / DDNS-observability resource safety / FRR / IPsec / routing route-leak)
- **Review base**: d4506d4450e2 (`#4571` merge). **Current origin/master**: 57d24d9aed4b64680831a1765a128921e79c00f7. Cited code is byte-identical between the two — findings re-verified against CURRENT master, not the review's stale base.
- **Real bpfrx or avacado**: REAL bpfrx. Every cited symbol resolves on `origin/master`; real issue numbers; real file:lines. No avacado tells.
- **Outcome counts**: 11 findings total (3 LOW "NEW" + 8 self-declared INFO/NEGATIVE). Dispositions: **1 GENUINE-RESIDUAL (LOW, defense-in-depth)**, 2 NOT-MATERIAL, 8 NEGATIVE (agreed), 0 DUP, 0 ALREADY-FIXED, 0 CONFABULATED.

---

## Per-finding disposition

### F-A7-001 — `startupGoodbyeRA` stale on RG-ID reuse — **NOT-MATERIAL**

Symbol confirmed: `daemon.go:519` (`startupGoodbyeRA map[int]bool`), written at `daemon_ha.go:769-773` inside `reconcileRGState`. The observation (map entry never evicted; one-shot suppresses the reconcile-safety goodbye RA on delete+re-add of the same RG ID without a daemon restart) is factually accurate about the map.

**Why NOT-MATERIAL — concrete harm is effectively null:**
- The `startupGoodbyeRA`/`WithdrawOnce` path (`daemon_ha.go:789 go d.ra.WithdrawOnce(rgRA)`) is a *reconcile safety-net* for the cold-boot-secondary case only: a node that came up secondary WITHOUT ever going through a MASTER→BACKUP event still emits one goodbye RA to clear routes from a *previous primary run before reboot*.
- Genuine runtime demotions do NOT rely on it. `clearRethServicesForRG` (`daemon_ha.go:1045`, called on VRRP BACKUP at `:481` and `:745`) sends the withdraw independently: `d.ra.WithdrawInterfaces(...)` when another RG still masters, else `d.ra.Withdraw()` (`daemon_ha.go:1069-1075`, log line "RA withdrawn (BACKUP, goodbye RA sent)"). This fires on EVERY demotion, ungated by `startupGoodbyeRA`.
- On a genuine cold boot (daemon restart) the map is fresh → goodbye RA is sent normally. The map only persists across a live RG delete+re-add WITHOUT restart.
- In that residual window the new same-ID RG comes up secondary having NEVER been primary on this node, so this node advertised no RAs for the new prefixes → there are no stale routes *from this node* to withdraw. Suppressing the goodbye RA is therefore harmless.
- Map is bounded by `MaxRedundancyGroups` (~few) → no memory leak. No security impact, no traffic loss.

Severity as filed (LOW/Medium-confidence) over-states it; disproving path = the demotion withdraw at `daemon_ha.go:1069-1075`. Not worth a filed issue on its own.

### F-A7-002 — `warmNeighborCache` UDP fan-out to public session IPs — **NOT-MATERIAL**

Symbol confirmed: `daemon_ha.go:1221` `warmNeighborCache`, called from `daemon_neighbor.go:563` inside `maintainClusterNeighborReadiness`. Code matches the review's quote.

**Why NOT-MATERIAL — the review self-refutes and the bounds hold:**
- HA-only: `maintainClusterNeighborReadiness` is gated on `d.cluster != nil`; standalone firewalls never run it (`daemon_neighbor.go:390` comment).
- Guarded single-flight: `neighborWarmupInFlight` atomic CAS (skip-if-in-flight); dispatched in its own goroutine so it never blocks the periodic loop or session installs.
- No amplification: it is strictly 1-probe-per-unique-session-IP (1:1, not N:1). An attacker must first establish real forwarded sessions (passing policy) to seed each IP.
- Rate is negligible: the review computes ~666 pps for 10K IPs, ~6666 pps burst for 100K, per 15s — trivial for a firewall data path. `net.DialTimeout(udp)` + 1-byte `Write` does a route lookup + socket create, not a blocking round-trip.
- No lock contention: `ForEachV4/V6` iterate BPF maps (RCU-protected) — do not block `SetSessionV4/V6` (this is exactly the review's own F-A7-003 negative).
- Filter `IsGlobalUnicast() && !(IsPrivate() && IsLoopback())` plus shared-gateway routing means most probes collapse to one ARP for the WAN gateway.

No unbounded growth, no freeze, no meaningful amplification/reflection primitive. LOW as filed is generous; NOT-MATERIAL.

### F-A7-003 — `warmNeighborCache` lock contention — **NEGATIVE (agreed)**

Self-classified NEGATIVE by the review and correct: BPF map iteration via `NextKey` is RCU-protected in the kernel and does not hold a Go lock that `SetSessionV4` needs; `userspaceSessionStore` delegates `ForEach*` to the BPF-backed store. No blocking of session installs. Agreed.

### F-A7-004 — `vtysh -c "show bgp neighbor <ip> …"` unsanitized IP concatenation — **GENUINE-RESIDUAL (LOW, defense-in-depth)**

Symbols confirmed: `vtysh.go:192/200/209` (`GetBGPNeighborReceivedRoutes/AdvertisedRoutes/Detail`) each do `m.executor().Vtysh("show bgp neighbor " + ip + " …")`; `realExecutor.Vtysh` at `vtysh.go:85` runs `exec.CommandContext(ctx, "vtysh", "-c", command)`.

**The review's OWN refutation is factually WRONG and must be corrected.** The review claims: *"`<ip>` is validated as IP by CLI dispatcher before reaching this function … `net.ParseIP` rejects control chars."* Verified against master — **no such guard exists in either caller**:
- gRPC `pkg/grpcapi/server_routing.go:144/153/164`: `ip := strings.TrimPrefix(req.Type, "received-routes:")` — a raw substring of the client-supplied `Type` string, passed straight through. No `net.ParseIP`, no sanitization (`grep ParseIP` over the file = 0 hits).
- CLI `pkg/cli/cli_show_routing.go:388/395/403`: `ip = args[1]` — raw token, no validation (`grep ParseIP` = 0 hits).

So the path is genuinely UNGUARDED, not a misread of a hardened path. Crafted input: a local gRPC `GetBGPStatus{Type:"received-routes:1.2.3.4\nconfigure terminal\n…"}` reaches `vtysh -c` with an embedded newline; depending on FRR vtysh `-c` multi-line handling the extra lines can be executed as the daemon's uid (root).

**Why LOW and not higher (honest bounds):**
- **No shell.** `exec.CommandContext(ctx, "vtysh", "-c", command)` passes `command` as a single argv element — classic shell metacharacter injection (`;`, `|`, `$()`, backticks) is inert. The only vector is vtysh's own `-c` line handling.
- **No trust-boundary crossing.** gRPC binds `127.0.0.1:50051` (`cmd/xpfd/main.go:245`) and has NO per-RPC RBAC/login-class interceptor (`grep PermView/Authorize/UnaryInterceptor` over `pkg/grpcapi/` finds only the fabric-proxy auth, not command authz). Any principal that can reach the localhost gRPC socket is already admin-equivalent and could run `configure` directly — no view→config escalation.
- The interactive CLI path cannot inject a newline (whitespace tokenizer splits args), so the only injector is the raw gRPC `Type` field, which requires localhost-admin access.

**Why it is still a genuine residual worth reporting (not INFO):** it is an unsanitized operator-influenced string flowing into an external command interpreter's argument, and the codebase's settled discipline is belt-and-suspenders sanitization at exactly these boundaries (`sanitizeFRRValue`, `validRouterID`). The fix is a 3-line `net.ParseIP(ip) == nil → error` at each function boundary. Novel: prior FRR-vtysh issues (#2889 unquoted password; #2223 redistribute; #2980 router-id) are frr.conf-RENDER surfaces, not the read-side `vtysh -c` show path. No existing issue covers this (`gh issue list --search vtysh`/`GetBGPNeighbor` = none matching).

**Lane: go** — add `net.ParseIP` validation in `pkg/frr/vtysh.go` (and optionally reject at the gRPC/CLI boundary). No cargo, no shim.

### F-A7-005 — IPsec apply/teardown ordering — **NEGATIVE (agreed)**
`ipsec/manager.go` `Apply` = swap conn names → write atomic → reload (`swanctl --load-all`) → `terminateRemovedConns`. Ordering correct (reload before terminate); idempotent teardown. Verified correct. Agreed.

### F-A7-006 — FRR sanitize belt / no injection — **NEGATIVE (agreed)**
`sanitizeFRRValue` strips C0+DEL from every free-text render value; next-hop/origin/source-protocol are typed/validated tokens, not free-text. Matches the standing #4498 disposition. Agreed.

### F-A7-007 — DDNS / Surface A resource safety — **NEGATIVE (agreed)**
Depth-1 nudge channels, `CompareAndSwap` skip-if-in-flight guards, per-pass 60s/10s timeouts, `sync.Map` dedup bounded by provider count, HTTP client cache reap-on-supersede, fail-closed transient handling. Bounded, no leak. Agreed.

### F-A7-008 — VRRP/HA failover ordering — **NEGATIVE (agreed)**
Activation (rg_active → blackhole removal → VRRP MASTER) and demotion (preflight → resign → blackhole inject → clear rg_active) ordering matches #485; posture reconciliation respects non-preempt (#86). Agreed.

### F-A7-009 — Cold-boot split-brain prevention — **NEGATIVE (agreed)**
`BulkEverCompleted()` cold-start gate + sync-ready hold + VRRP sync-hold; #4386 fix (500ms heartbeat "peer never seen" no longer bypasses the grace) verified present. Agreed.

### F-A7-010 — Integer truncation in A7 scope — **NEGATIVE (agreed)**
`rgID/ifindex/priority int`, `Workers>=1`, `RingEntries [1..16384]+pow2`, ports 1..65535 pre-cast, `ZoneID` widened u16 (#3075), `OwnerRGID int32` (#2467), VLAN 1..4094. No unguarded narrowing in A7 scope. Agreed.

### F-A7-011 — Route-leak correctness (next-table / rib-group #3876 / PBR #4534) — **NEGATIVE (agreed)**
next-table pref 100-199 hard-cap 100; rib-group per-prefix pref 30000-30999 (post-#3876) wins over default; PBR pref 31000-31999 discard/reject skipped (#4534), unrepresentable L4 fail-closed, `maxPBRRules` cap. Verified correct. Agreed.

---

## Genuine residual (1)

**F-A7-004** — LOW / defense-in-depth. `pkg/frr/vtysh.go:192/200/209` concatenate an unvalidated `ip` (raw gRPC `Type` substring at `pkg/grpcapi/server_routing.go:144/153/164`, or raw CLI `args[1]` at `pkg/cli/cli_show_routing.go:388/395/403`) into a `vtysh -c` command. No `net.ParseIP` guard exists anywhere on the path (the review's "validated by CLI dispatcher" claim is false). Bounded by: argv exec (no shell) + localhost-only gRPC with no per-RPC RBAC (caller is admin-equivalent) → no privilege escalation, hence LOW. Fix: `net.ParseIP(ip)==nil → error` at each `GetBGPNeighbor*` boundary. Lane: go.
