# Triage result — ps-review-042 (Paladin full-tree, 20 batches)

- Review base: `7f6f6b8b4` (stale). Gated against CURRENT origin/master
  `d1449fe77` (~40 commits ahead; drive-to-zero campaign merged ~21 PRs).
- Ground truth read via `git show origin/master:<path>` only. Local main checkout
  treated as stale — never used.
- The aggregated `/tmp/ps-review-042.md` truncates each subagent block before its
  Findings section; full findings extracted from the underlying
  `/tmp/review-work-ps-042/ps-*.md` reports (20 files, 78 finding headers).

## Filed issues (6)
- **#5244** — config: sampling `input rate` accepts negative → uint32 wrap disables flow export. (A3-b1 F-01)
- **#5245** — cluster: RG removal in UpdateConfig leaks the takeover holdTimer. (A5-01)
- **#5246** — cluster: ManualFailover pre-hook window races ResetFailover. (A5)
- **#5247** — dataplane/userspace: sessionMirrorFailed sticky, blocks HA takeover-readiness. (A6-b1)
- **#5248** — config: zone `interfaces` bracketed list not handled by #2419 SSOT. (A3-b1 F-02)
- **#5250** — [cohort] low-materiality hardening backlog (21 items across observability/dataplane/daemon/api/config).

## Totals
- Distinct actual findings evaluated: ~48 (excluding pure negatives / INFO / "No finding").
- Filed as own issue: **5** (#5244-5248). Cohort tracker: **1** (#5250, 21 low items).
- Already-fixed / mitigated by recent campaign: 3 (see below).
- Self-declared DUP of open issue (suppression / dedup-index): ~14.
- Retired-eBPF path / not-material: 1 (NAT poolID).
- Negatives / INFO / test-only / documented-by-design: ~24.

---

## Per-finding gate results (material candidates)

### FILED
- **A3-b1 F-01 sampling negative input rate** — SYMBOL-EXISTS ✓ (compiler_services.go:1394,
  `inst.InputRate = n`, no guard). ALREADY-FIXED ✗ (port-mirroring sibling 1340-1347
  rejects, sampling missed). NOVEL ✓ (not in dedup/open/closed). MATERIAL ✓ (silent
  observability disable). → **#5244**.
- **A5-01 RG removal holdTimer leak** — SYMBOL-EXISTS ✓ (group_state.go:43-51 removal loop,
  no `holdTimer.Stop()`; holdTimer armed readiness.go:38, stopped only readiness.go +
  manager.go:434). NOVEL ✓ (distinct from #5080 monitor-debt, #5138). MATERIAL ✓ (timer
  leak + spurious election on RG churn). → **#5245**.
- **A5 ManualFailover/ResetFailover race** — SYMBOL-EXISTS ✓ (failover.go: ManualFailover
  unlocks 55 for preHook, re-sets ManualFailover 107; ResetFailover 149 clears without
  checking failoverInProgress). NOVEL ✓ (distinct from #5138 which is the RG-fallback bug).
  MATERIAL ✓ (operator reset overridden → node parks SecondaryHold). → **#5246**.
- **A6-b1 sessionMirrorFailed sticky** — SYMBOL-EXISTS ✓ (manager_ha.go set 337 / gate 306).
  ALREADY-FIXED ✗ (`= false` only in process.go:205/254 = process restart; not on mirror
  success). NOVEL ✓ (residual of closed #346 which only added recording). MATERIAL ✓
  (transient control-socket failure blocks HA takeover-readiness until helper restart). → **#5247**.
- **A3-b1 F-02 zone interfaces bracket** — SYMBOL-EXISTS ✓ (compiler_security_zones.go:113-115
  children-only; schema_security.go:167 interfaces = wildcard, NOT multi). NOVEL ✓ (not the
  #2419 fixes, not #5181). MATERIAL ~ (either silent member drop or hard commit reject;
  security-boundary parity gap). Filed with the drop-vs-reject caveat. → **#5248**.

### ALREADY-FIXED / MITIGATED by recent campaign (NOT filed)
- **A8-b1 F1 uncapped offset O(N) session-table DoS** — mitigated by **#5233** (39cfeedc5):
  sessions.go now aborts the offset walk on client disconnect via
  `newRequestCancelSampler(r.Context())` (lines 145-165). Core hidden-loop DoS closed;
  remaining offset-cap nicety not material enough to refile.
- **A3-b3 F-02 application-set bracket members truncated** — self-declared dup of #5181;
  FIXED on master (9d4a05b4d, "config: keep all bracketed application-set members #5181").
- **A9 F5-adjacent unknown-feed / malformed feed URL** — #5183 malformed feed URL fixed
  (c3d0e5026). Unknown-binding-name typo variant kept in cohort (#5250) as distinct.

### RETIRED-eBPF / NOT MATERIAL (NOT filed)
- **A6-b1 NAT poolID uint8 overflow (MAX_NAT_POOLS=32)** — lives in `pkg/dataplane/compiler_nat.go`
  (retired-eBPF compiler per project memory). Live map write is a no-op:
  `loader.go:394 userspaceShimCompileDataplane.SetNATPoolIPV4` is a stub; the real BPF write
  `maps_nat.go:156 (*Manager).SetNATPoolIPV4` is the retired eBPF Manager. The userspace NAT
  snapshot builder (`userspace/nat.go`) does NOT consume `result.PoolIDs`/`NextPoolID` and has
  no 32-pool index. No live OOB. → moot.

### NOT MATERIAL (evaluated, not filed)
- **A7-b2 F1 sanitizeFRRValue only strips C0/DEL** — SYMBOL-EXISTS ✓ (policy_render.go:49-63).
  But newline/all control chars ARE stripped → config-line injection already closed. `!` fires
  only at start-of-line (values are embedded mid-line); `;`/`$` are literal in FRR config (not a
  shell); FRR `description` takes rest-of-line so spaces are legal. Residual (password with
  spaces) is narrow and validator-gated. Injection premise doesn't hold → not material.
- **A9 F1 flowBatch maxDepth non-monotonic** — real but observability-metric-only → cohort #5250.

### DUP of open issue / suppression list (NOT filed)
- A10-b1-01 publish-generation GC (#4876), A10-b2-01 DDNS plaintext http (#4861), A10-b2-02
  Cloudflare pagination (#4909), A10-b2-03 DDNS durability (#4873), A10-b2-04 DHCP expiry (#4874),
  A10-b3-01 zone-detail wildcard order (#4885), A10-b3-02 scheduler republish (#3849/#3780),
  A10-b3-03 deploy/bake supply-chain (#4904/#4905), A10-b3-04 perf-analysis exit0 (#4907),
  A10-b3-05 xsk-repro (#4906), A10-b3-06 iperf metrics (#4907), A1-b2 FINDING-1 tcp_seg MTU floor
  (#5159), A3-b1 F-03 feed interval (#4879), F-04 DPD interval (#4878), F-05 chassis priority
  packed (#4880/#5184), F-08 appid proto0 (#4887), A7-b1 F2 DDNS http (#4861), F3 IPsec rebind
  (#4899), A7-b2 F4 routing rule del (#5118), F6 lldp linger (#5123), A8-b2 F4 log symlink (#5130).

### NEGATIVE / INFO / test-only / by-design (NOT filed) — representative
- A1-b1 F1 (FABRIC flag literal, maintainability), A1-b1 F2 / A1-b3 F5,F6 / A2 F2 / A3-b1
  F06-F11 / A3-b3 F-01 / A3-b4 / A4-b1 (all negatives or positives), A1-b2 FINDING-2/4/5 &
  A1-b3 F1 (test-only unwrap/trunc), A1-b2 FINDING-3 (WG unwrap, related #5154), A1-b3 F2
  (year-2106 saturation by design), A1-b3 F4 (unreachable livelock), A2 F3 (NAT64 frag TTL obs),
  A5 HeartbeatGroupID/lease uint8 (defense-in-depth, commit-gated, #5184-adjacent — low),
  A6-b2 F2 (dead code), A8-b1 F3 (fail-closed today), A8-b2 F1 (dead helper), A9 F6-F10 (verified
  safe). A10-b1-03/A8-b2-F1 dead-code trunc: not live.
