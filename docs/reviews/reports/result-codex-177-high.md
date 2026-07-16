# codex-review-177 — Suggested-Issue-Split HIGH triage (A7–A10)

- **File:** /tmp/codex-review-177.md, base commit `d22789fa6` (STALE)
- **Scope:** the `##### A<area> H<n>` "Coordinator result: CONFIRMED High"
  entries in the ledger window ~L18785–18991 → **A7-b2 H1 through A10-b4 H4**
- **Re-verified against:** origin/master `812bf30c1` (fetched fresh), via
  `git show origin/master:<path>` (never the stale working tree)
- **H-findings processed:** 15
- **Outcome:** 13 FILED, 1 ALREADY-FIXED, 1 DUP

| # | ID | Title | Verdict |
|---|----|-------|---------|
| 1 | A7-b2 H1 | IPsec deletion drops unload/termination debt | **ALREADY-FIXED** by #4898/#4433 |
| 2 | A8-b1 H1 | CLI/REST API bind bypasses no-auth loopback clamp | **FILED #5127** |
| 3 | A7-b1 H1 | SNMP client ACL absent from reconcile hash | **FILED #5129** |
| 4 | A7-b1 H2 | Removed login users retain credentials | **FILED #5128** |
| 5 | A7-b1 H3 | Deferred-worker recovery failure swallowed | **FILED #5134** |
| 6 | A8-b2 H1 | Primary gRPC bind unauthenticated | **FILED #5126** |
| 7 | A9-b1 H1 | Feed producers never reconcile after boot | **FILED #5133** |
| 8 | A9-b1 H2 | VRF DNS setup errors mutate RPM path-health | **FILED #5135** |
| 9 | A10-b2 H1 | View-only `last N` unbounded preallocation | **FILED #5132** |
| 10 | A10-b2 H2 | Flow trace owns arbitrary `/var/log` names | **FILED #5130** |
| 11 | A10-b2 H3 | ISSU reports drain before async demotion | **FILED #5136** |
| 12 | A10-b4 H1 | Unsigned image sidecar controls mixed-base safety | **FILED #5131** |
| 13 | A10-b4 H2 | Image fetch overwrites live qcow2 backing storage | **FILED #5137** |
| 14 | A10-b4 H3 | Mouse-latency FAIL exits successfully | **DUP of #4907** |
| 15 | A10-b4 H4 | Rejoin fallback leaves higher RGs drained | **FILED #5138** |

---

## Per-finding reasoning

### A7-b2 H1 — ALREADY-FIXED by #4898/#4433
Fixed exactly as the team lead noted. `pkg/ipsec/manager.go` (origin/master):
`clearConfig()` now ends `return m.reload()` (propagates the reload error
instead of `_ = m.reload()`; the empty-clear branch no longer reports false
success). `Apply` gates state promotion + SA teardown on reload SUCCESS
(`if applyErr != nil { return applyErr }`), and on failure preserves
`prevConnNames` so the next Apply/Clear recomputes the diff and **retries**
the dropped termination debt. `terminateRemovedConns` handles the unload +
live-SA teardown. All three gaps the finding described are closed. **Not filed.**

### A8-b1 H1 — FILED #5127 (bug, security)
Still genuine. `apiCfg.Addr = d.opts.APIAddr` (daemon_run.go:1107); auth
derivation + `clampBindToLoopback` live **only** inside the
`WebManagement != nil` block (1334–1363). `--api-addr 0.0.0.0:8080` + no
web-management stanza → REST config-mutation/DHCP/system-action mux binds
non-loopback with `Auth==nil` and no clamp. The #4903/#4928 clamp exists but
sits in the wrong scope. Default is loopback, but the flag is a supported knob.

### A7-b1 H1 — FILED #5129 (bug, security)
`snmpConfigHash` community loop writes only `name` + `Authorization`
(daemon_snmp_reconcile.go:62–70); `Clients`/`Restrict` never hashed. Gate
`if d.snmpHashSet && h == d.snmpHash { return false }` (234–236) skips
`UpdateConfig`. An ACL-only tightening (remove/deny a source host) commits
clean but the live agent keeps the old allowlist. Not covered by the other SNMP
issues (#4917/#4918/#4924/#5032 — EngineID / trimToFit / TimeTicks / v3 salts).

### A7-b1 H2 — FILED #5128 (bug, security)
Read carefully per the lead's warning about the D2 UID-keyed lock. The
`xpfProvisioned` marker is consumed **only** by `reconcileUserPassword`, which
runs inside the **present-user** loop (daemon_system.go:922). `applySystemLogin`
early-returns on empty users (857) and never iterates a removed user. No sweep
enumerates `provisionedUsersDir` for absent users; `reconcileSudoers` revokes
only the sudo grant. So a wholly-removed user keeps account+password+keys. The
D2 mechanism covers only "password directive removed on a still-present user",
NOT "user removed" — the finding's gap persists. Distinct from #5026 (test-pin).

### A7-b1 H3 — FILED #5134 (bug, dataplane)
`daemon_apply.go:990–997` (deferred-MAC reapply) logs+discards `ApplyConfig`
err; outer apply returns nil. `manager_compile.go:323–340` advances
`lastSnapshot`/`publishedSnapshot`/hash only after `apply_snapshot` succeeds, so
the workerless `DeferWorkers=true` snapshot stays published; the status-refresh
replay (420–486) rebases off it. Distinct layer from #4952 (Rust
`bringup.rs` spawn) and #4959 (address-only map mutation).

### A8-b2 H1 — FILED #5126 (bug, security)
`NewServer` stores addr unchanged (grpcapi/server.go:188–226; doc-comment
asserts loopback-only but nothing enforces it). `Run` binds it with only
`configLockInterceptor`; fabric auth + destructive-method allowlist are
exclusive to `RunFabricListener`. `--grpc-addr` (main.go:245) accepts any
address → full 48-RPC surface (config mutation + `SystemAction`) unauthenticated
off-loopback.

### A9-b1 H1 — FILED #5133 (bug, security)
`feeds.New` + `d.feeds.Apply` appear exactly once, in the boot-only block gated
on `len(FeedServers)>0` (daemon_run.go:462–470). No day-2 apply path
re-constructs/re-Applies; `feedSnapshotsForConfig` returns nil when
`d.feeds==nil` (daemon_feeds.go:12–29). A post-boot feed add never fetches → a
feed-backed deny policy enforces zero prefixes. Not #4922 (invalid-line byte
cap).

### A9-b1 H2 — FILED #5135 (bug)
`vrfBoundResolver` Control returns raw `applyVRFBind`/`RawConn.Control` errors
(icmp.go:335–355) — no `ErrProbeSetup`. The data-socket Control wraps the same
failures with the sentinel (rpm.go:68–83). `runSingleTest` holds state only on
`errors.Is(err, ErrProbeSetup)` (521–529). Hostname targets resolve first, so a
VRF-bind capability failure leaks as a path failure → spurious ip-monitoring
failover. The exact class #1843 was meant to prevent; resolver path missed.

### A10-b2 H1 — FILED #5132 (bug, security)
`filterStream` `last` case: `ring := make([]string, n)` with `n` any positive
operand, before reading (cli_dispatch.go:132–146). `show` is PermView
(permissions.go:151–157). `show x | last 2000000000` → immediate ~32 GB alloc.
Related to #4886 B but distinct: #4886 B is output-size-driven and its
streaming-pager fix does not bound this operand-driven prealloc.

### A10-b2 H2 — FILED #5130 (bug, security)
`monitor security flow-trace` stays PermView (only `monitor traffic` elevated,
permissions.go:130–157). `sanitizeTraceFilename` accepts any bare basename
(monitor.go:30–45); `openTraceFile` O_NOFOLLOW admits an existing regular
`/var/log` file; `rotateTraceFile` renames/removes siblings + the active name
(76–113). A view-priv user can make root append to / rotate away / delete
`/var/log/auth.log` etc. (audit-log tamper). Distinct from #4883 B
(writer-error leaves monitor Active).

### A10-b2 H3 — FILED #5136 (bug)
CLI prints "Traffic has been drained to peer" + `systemctl stop xpfd`
immediately after `ForceSecondary()` returns (cli_request_system.go:151–186).
`ForceSecondary` only mutates state + fires best-effort `sendEvent` (droppable,
manager.go:371–380) and returns nil (failover.go:118–146); real demotion is
async in daemon_ha.go:180–301 and can fail. Operator stop can blackhole while
still master.

### A10-b4 H1 — FILED #5131 (bug, security)
`sign.write_manifest(sums, [qcow_out, meta_out])` signs only qcow2+metadata
(bake.py:667); the `xpf-<ver>.manifest` sidecar with `ha-protocol-*` /
`session-sync-*` compat fields is written separately, unsigned (705–713).
publish.py allowlist admits `*.manifest` (89–111); `_gate_mixed_base` trusts
those unsigned fields to authorize a session-preserving mixed-base roll
(xpf-deploy.py:1390–1450). Tamper the sidecar (signed image intact) → forge the
gate. Distinct from #4904 (--skip-validate / base-checksum / publish TOCTOU).

### A10-b4 H2 — FILED #5137 (bug)
`_install_libvirt_golden` `shutil.copyfile(srcq, golden)` in place over the
read-only COW backing used by every per-VM overlay (`qemu-img -b <golden>`),
documented immutable (xpf-deploy.py:567–614). No ref scan / versioned base /
rebase / in-use refusal → re-fetch corrupts live overlays (both HA members) on
next backing read. Distinct from #4905 (path-escape / ISO perms / alias delete /
status-misread).

### A10-b4 H3 — DUP of #4907
#4907 explicitly lists "Mouse-latency matrix exits 0 on FAIL (C175-HC-029):
`test/incus/mouse_latency_aggregate.py:388`
`return 0 if verdict in ("PASS","FAIL") else 2`" — identical finding. **Not
filed.**

### A10-b4 H4 — FILED #5138 (bug)
`configuredRGs` falls back to `{0,1,2}` on status error / parse miss
(cluster_cli.go:523–531); config supports RG ≥ 3. `ResetFailover` then resets
only 0–2, leaving RG 3+ drained. `RejoinAndConfirm` checks only
`PeerAlive`/`SyncEstablished`, no per-RG applied-ownership
(kernel_drain.go:115–160). A transient status failure during a rolling upgrade
→ RG 3+ blackhole after the peer is drained next. Not #4867 (dual-active
reaffirm).

---

## Dedup basis
`gh issue list --state open --limit 400` (78 open). Checked each finding
against SNMP (#4917/#4918/#4924/#5032), memory cohorts (#4886), CLI fail-open
(#4883), supply-chain (#4904/#4905), perf-tooling (#4907), reconcile
(#4952/#4959), cluster (#4867), and fleet filings (#5026/#5031/#5032). Only
A10-b4 H3 matched an existing issue.
