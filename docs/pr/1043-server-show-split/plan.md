# #1043 — `pkg/grpcapi/server_show.go` modularity split

## Status

REV-3 — phase 1 of 4 (single-domain narrow scope per turn-cost).

Getting server_show.go under 2,000 LOC requires extracting ~2,200
LOC across 8 domains. That is 8 commits' worth of mechanical churn
— too large for a focused review gate AND too time-costly in a
multi-batch grind. Splitting into single-domain PRs:

- **Phase 1 (this PR)**: extract the `firewall` case body alone
  (~130 LOC — the largest single-case body, NOT the whole
  firewall-family group). server_show.go: 4,072 → ~3,945.
  Single-case-body extraction. Establishes the pattern for
  Phase 2-N. The original "firewall-family" grouping (firewall +
  policy-options + policies-hit-count + policies-detail + screen,
  ~465 LOC) re-splits into per-case phases later if reviewers
  prefer narrower diffs per PR; this Phase 1 demonstration is
  intentionally minimal.
- **Phase 2**: chassis (~371 LOC).
- **Phase 3**: nat (~295 LOC).
- **Phase 4**: dhcp_lldp_snmp (~242 LOC).
- **Phase 5**: flow (~245 LOC).
- **Phase 6**: interfaces_extras (~221 LOC).
- **Phase 7**: system (~217 LOC).
- **Phase 8**: zones_detail (~159 LOC).

Phase 3 (server_show.go ≈ 2,944) lands the file under 3,000.
Phase 7 (≈ 1,977) lands it under 2,000 (modularity threshold met).

REV-2 → REV-3 deltas (preserved from earlier review):

Round-1 verdicts:
- Codex: PROCEED-WITH-CHANGES — flagged inflated LOC estimates (cluster
  was 800 in plan, actually 355) and the "pure relocation" claim being
  partially false because of top-level `break` sites in cases.
- Gemini Pro: REJECT — same LOC-estimate FAIL.

Both reviewers found the methodology PASS, naming PASS/CONCERN
(consistent with existing pattern), and test approach PASS. The
plan was rejected only because the LOC math was wrong.

Rev-2 changes:
- Replaced estimated LOC with measured per-case LOC from awk over
  the actual file. Total case-body LOC is **3,163** across 80 cases
  (file = 4,072 LOC; non-case overhead = 909 LOC).
- Expanded extraction set from 5 domains (~1,400 LOC, would not
  reach threshold) to 8 domains (~2,200 LOC, gets server_show.go
  to ~1,850 LOC ≤ 2,000 threshold).
- Documented the `break` → `return nil` translation explicitly:
  every top-level `break` inside an extracted case body becomes a
  bare `return nil` (the extracted method writes to a `*strings.Builder`
  passed by reference; an early break maps to early return without
  changing semantics).
- Added per-domain CLI smoke gate (one representative `cli show ...`
  command per extracted file, executed against the loss userspace
  cluster post-deploy).

## Bug / scope

`pkg/grpcapi/server_show.go` is currently 4,072 LOC (issue cited 5,288 — earlier splits removed ~1,200). Still 2× over the project's 2,000-LOC modularity-discipline threshold. The structure is one giant `ShowText` RPC handler with 80+ `case "X":` blocks dispatching by show-command name.

Existing pattern in `pkg/grpcapi/`: sibling files `server_<domain>.go` (e.g., `server_cluster.go`, `server_routing.go`, `server_sessions.go`). Some `server_show_<domain>.go` files already exist (`server_show_events.go`, `server_show_chassis_forwarding_test.go`). Continue the same pattern.

## Approach

**Phase 1 (this PR): extract just the `firewall` case body** (~130 LOC) into `pkg/grpcapi/server_show_firewall.go` to demonstrate the methodology before the broader phased extraction. Each extraction is a semantic relocation: case body → private method `(s *Server) showX(...)` in the new file → original case becomes `case "X": s.showX(...)`.

Target across the full phase plan: get `server_show.go` from 4,072 LOC under the 2,000 threshold, ideally to ~1,800 LOC. Phase 1 gets 4,072 → 3,945 (the table below shows the full plan; this PR ships only Phase 1's first case body).

### Domain groups to extract (rev-2 — measured LOC)

Per-case LOC measured by awk over `pkg/grpcapi/server_show.go`. Top-of-list
domains chosen by combined LOC + cohesion. Naming convention:
`server_show_<domain>.go` per existing siblings (`server_show_events.go`,
`server_show_forwarding.go`, `server_show_interfaces.go`,
`server_show_status.go`, `server_show_zones.go`).

**Note**: The Phase 1 PR ships only the `firewall` case body (130 LOC),
not the full ~465 LOC firewall-family group. The remaining
firewall-family cases (`policy-options`, `policies-hit-count`,
`policies-detail`, `screen`) extract in subsequent Phase 1a/1b/...
PRs if reviewers prefer narrow per-case diffs.

| File | Cases | Measured LOC |
|------|-------|-------------:|
| `server_show_chassis.go` | `chassis` (75), `chassis-hardware` (6), `chassis-forwarding` (36), `chassis-cluster` + 8 variants (~108), `chassis-environment` (33), `storage` (26), `commit-history` (17), `alarms` (17), `security-alarms*` (53) | **~371** |
| `server_show_firewall.go` | **Phase 1 (this PR)**: `firewall` (130). Future: `policy-options` (56), `policies-hit-count` (57), `policies-detail` (126), `screen` (96) — extract in follow-up PRs. | **~130 (this PR)**, ~465 (full domain) |
| `server_show_nat.go` | `nat-static` (20), `nat-nptv6` (24), `persistent-nat` (23), `nat-source-rule-detail` (85), `nat-dest-rule-detail` (74), `persistent-nat-detail` (53), `nat64` (16) | **~295** |
| `server_show_interfaces_extras.go` | `interfaces-extensive` (100), `interfaces-detail` (96), `interfaces-statistics` (25) — note existing `server_show_interfaces.go` already exists for the basic interface RPC; this file is named `_extras` to avoid collision | **~221** |
| `server_show_dhcp_lldp_snmp.go` | `dhcp-server` (27), `dhcp-server-detail` (79), `dhcp-relay` (21), `lldp` (37), `lldp-neighbors` (18), `snmp` (41), `snmp-v3` (19) | **~242** |
| `server_show_system.go` | `system-services` (73), `system-syslog` (36), `ntp` (27), `version` (17), `login` (19), `internet-options` (9), `root-authentication` (24), `backup-router` (12) | **~217** |
| `server_show_flow.go` | `flow-monitoring` (20), `flow-timeouts` (36), `flow-statistics` (40), `flow-traceoptions` (34), `sessions-top:bytes`/`packets` (115) | **~245** |
| `server_show_zones_detail.go` | `zones-detail` (159) — existing `server_show_zones.go` covers the basic zone RPC | **~159** |

Total extraction: **~2,215 LOC**. Post-extraction estimate:
- Original `server_show.go`: 4,072 LOC
- Removed (case bodies): ~2,215
- Added back (dispatcher one-liners ≈ 80 cases × 2 LOC = ~160)
- Net: 4,072 − 2,215 + 160 = **~2,017** ← right at the threshold

To safely undercut 2,000, add one more small extraction OR remove
some helpers along with their call sites. Marginal: extracting
`schedulers` (25), `tunnels` (25), `rpm` (33), `event-options` (34),
`ipv6-router-advertisement` (39), `forwarding-options` (52) into a
catch-all `server_show_misc.go` adds ~210 LOC, getting us to **~1,807**.

### Methodology

For each domain extraction (one commit per file):

1. Identify the case bodies in the source switch.
2. Move each body verbatim into a private method:
   `func (s *Server) show<CaseName>(ctx context.Context, req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) error`.
3. **`break` → `return nil`**: every top-level `break` inside an
   extracted case body becomes a bare `return nil`. The switch's
   implicit fall-through to end-of-switch is preserved by the
   method returning to the dispatcher, which then continues the
   switch's natural break. Verified by code inspection of the
   ~10 top-level `break` sites Codex flagged at lines 2170, 2625,
   2683, 2826, 2859, 465-613 (those are nested-loop breaks, NOT
   top-level — distinct from the switch breaks; left untouched).
4. The dispatcher case becomes:
   ```go
   case "X":
       if err := s.showX(ctx, req, cfg, &buf); err != nil {
           return nil, err
       }
   ```
5. Helpers private to a single domain (e.g., closures defined
   inline in a case body) move to private functions in the new file.
6. Cross-domain helpers (`writeRPMConfig`, `firewallFilterTermExpansionCount`)
   stay in `server_show.go` until they have multi-file callers.

## Methodology

For each domain extraction:

1. Identify the case bodies in the source switch.
2. Move each body verbatim into a private method `(s *Server) show<CaseName>(ctx, req, ...) (*pb.ShowTextResponse, error)`.
3. Replace the original case body with a one-line dispatch: `case "X": return s.showX(ctx, req, ...)`.
4. Methods carry their own helpers (private to the new file). Shared helpers (`writeRPMConfig`, etc.) stay in `server_show.go` until a future PR.

**Method signatures**: most cases consume `req *pb.ShowTextRequest` (for filter args), `cfg *config.Config` (resolved from Server state), and a shared `&strings.Builder` buf. Prefer threading these through as parameters rather than touching `*Server` state directly.

## What this PR does NOT do

- **No behavior change.** Every extracted case body is byte-for-byte identical to the original (modulo formal-parameter names + the dispatch wrapper). Smoke MUST be byte-for-byte identical pre/post.
- **No domain consolidation across files.** Sibling extracted files are independent; helpers stay in `server_show.go` until they have multi-file callers.
- **No `pkg/grpcapi/show/` subdirectory.** The issue proposed this naming; existing pattern is `server_show_X.go` siblings. Stick with the existing pattern; subdirectory creation is its own scope question.
- **No companion-file split** of `server.go` (254 LOC, well under threshold). Issue mentions it as adjacent; defer.

## Tests

- **No new tests.** This is a pure relocation; existing tests cover the behavior.
- Existing tests live in `server_*_test.go` files. The relocated methods retain the same call paths, so `cluster.test`, integration, and unit tests should all pass without modification.

## Acceptance gate

- `go build ./...` — clean.
- `go test ./pkg/grpcapi/...` — all existing tests pass.
- `go vet ./...` — clean.
- `wc -l pkg/grpcapi/server_show.go` ≤ 2,000.
- Cluster smoke (loss userspace cluster, all 6 CoS classes, **v4 and v6**):
  - iperf3 against 172.16.80.200 + 2001:559:8585:80::200
  - All classes pass at expected rates with 0 retransmits.
  - This is a Go-side gRPC handler refactor; runtime behavior is via the dataplane which doesn't touch this code. Smoke is a regression sanity check, not a functional verifier.
- **Per-domain CLI smoke** (Codex round-1 ask): one representative `cli show ...` command per extracted file, executed against the loss userspace cluster post-deploy. Verifies byte-for-byte output equivalence:
  - `cli show chassis cluster status` → `server_show_chassis.go`
  - `cli show security policies` → `server_show_firewall.go`
  - `cli show security nat source detail` → `server_show_nat.go`
  - `cli show interfaces detail` → `server_show_interfaces_extras.go`
  - `cli show system services dhcp local-server lease` (or similar) → `server_show_dhcp_lldp_snmp.go`
  - `cli show system version` → `server_show_system.go`
  - `cli show security flow session summary` → `server_show_flow.go`
  - `cli show security zones-detail` (or actual flag) → `server_show_zones_detail.go`

## Risks

1. **Compile-time imports may need re-arranging.** Some helpers in `server_show.go` reference package-private types from `pkg/grpcapi`; the extracted files need the same imports. Should compile cleanly.

2. **Method receiver vs free function.** Most case bodies access `s.cfg`, `s.cluster`, etc. The natural translation is a method on `*Server`. Free functions would require threading state through, which is more churn.

3. **Test discoverability.** After splitting, tests that target specific show commands stay where they are (in `server_show_*_test.go`). The relocated methods are still reachable via the public `ShowText` API surface, so test paths don't change.

4. **Future merge conflicts.** Open PRs that touch `server_show.go` will need to rebase. Check open PRs first (`gh pr list --search "server_show"`).
