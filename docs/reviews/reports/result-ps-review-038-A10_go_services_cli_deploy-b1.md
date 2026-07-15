# Triage result — ps-review-038-A10_go_services_cli_deploy-b1

- **Subsystem**: A10 go services / CLI / deploy — batch 1/3 (bpf/headers, cmd/cli, cmd/shimverify, cmd/xpfd, pkg/cli)
- **Review base**: d4506d4450e23f9a3fc572206b3c82f6b6c99029 (per header)
- **Triaged against**: origin/master `57d24d9aed4b64680831a1765a128921e79c00f7` (base == master line; drift is forward, all cited symbols still present)
- **Real bpfrx or avacado?**: **Real bpfrx.** Evidence paths are written as `/home/ps/git/avacado-xpf/...` (reviewer ran from an avacado clone), BUT every cited symbol exists at the identical relative path on origin/master with matching code. Not confabulated — a real-code review with an avacado-rooted path prefix.
- **Outcome counts**: 3 findings → 0 GENUINE-RESIDUAL, 0 DUP, 0 ALREADY-FIXED, 3 NOT-MATERIAL (F2 additionally REFUTED by upstream commit guard), 0 CONFABULATED. Negative/dedup sections: clean, nothing new.

All three findings are self-rated Low / informational and every one lands on a client-side surface whose out-of-range value is already rejected authoritatively server-side. F2's crafted scenario is additionally impossible because the config compiler rejects the input at commit.

---

## F1 — remote monitor packet-drop: missing client-side port range validation (Low, UX)

**Symbol check**: EXISTS. `cmd/cli/monitor.go` `handleMonitorSecurityPacketDrop` — `source-port`/`destination-port` cases do `req.SourcePort = uint32(v)` from `strconv.Atoi(args[i])` with no range check (confirmed on origin/master, same code as the review quote).

**Disposition: NOT-MATERIAL (server-hardened, cosmetic UX).**

Reasoning: the remote CLI just forwards the value; the authoritative validation is server-side and present:
- `pkg/grpcapi/server_diag.go:227-233` — `MonitorPacketDrop` validate: `if req.SourcePort > 65535 { return InvalidArgument "source-port must be 0..65535" }` and the identical guard for `DestinationPort`.
- Negative input is also caught: `Atoi(-5)` → `uint32(-5)` wraps to `4294967291` → `> 65535` → rejected.
- Test coverage on master: `pkg/grpcapi/server_packet_drop_validation_3382_test.go:84-85` (`SourcePort:70000`, `DestinationPort:99999` both expected-reject).

The only observable difference is an opaque gRPC `InvalidArgument` from the server versus an immediate local error message. No truncation reaches the dataplane, no filter is silently mis-applied, no security or correctness impact. The finding self-acknowledges this ("relying on server rejection", Severity Low). A pure surface-consistency nicety, not a defect. Why not a genuine residual: the request is *correctly* rejected end-to-end; there is no wrong behavior to fix, only a cosmetic error-locality preference.

**Dedup**: novel surface (not in #4517-#4581 or the open set), but immaterial — nothing to file.

---

## F2 — app_resolve.go: uint16 truncation without range guard (Low, display)

**Symbol check**: EXISTS. `pkg/cli/app_resolve.go` — `else { if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort { return name } }` (confirmed, `resolveAppName`).

**Disposition: NOT-MATERIAL — and the crafted scenario is REFUTED by an upstream commit-time guard (the A2 pattern).**

Reasoning — two independent kills:

1. **Scenario unreachable (commit guard).** F2's premise is `application foo destination-port 70000` reaching display, hedged as "compiler may not reject if app not validated elsewhere." It IS rejected. `validatePortSpec` (`pkg/config/compiler_applications.go:625`, numeric branch lines 645-661) returns `"invalid port %d: must be 1-65535"` for any numeric outside 1..65535, and `ValidateConfig` runs application ports through it. Ground truth: `parser_ast_test.go:4967 TestValidatePortSpec` asserts `{"99999", false}` (and `{"0", false}`), so `70000` and `65536` are both rejected at commit. The out-of-range `DestinationPort` string can never be persisted, so `resolveAppName` is never called with `portStr="70000"`/`"65536"`. The truncation line is real but unreachable with a value that would mis-compare.

2. **Display-only, no enforcement.** Even setting (1) aside, `resolveAppName` produces a human-readable app label in `show` output only; it is not on any policy/session-match path (enforcement uses `appid.SessionMatches`, a different path — the finding itself concedes "no policy bypass, only display confusion"). Blast radius would be a cosmetic mislabel, not a bypass.

Why not even a Low residual: the mislabel requires a config state the compiler forbids. There is no reachable input that produces the wrong label.

**Dedup**: distinct from #4569/#4555/#4572 (all dataplane), but refuted — nothing to file.

---

## F3 — remote ping/traceroute count/size negative accepted client-side (Low, informational)

**Symbol check**: EXISTS. `cmd/cli/main.go` `handlePing` — `if v, err := strconv.Atoi(args[i]); err == nil { req.Count = int32(v) }` (and same for `Size`), no local bound (confirmed).

**Disposition: NOT-MATERIAL (server-hardened, cosmetic UX).**

Reasoning: server-side is fully guarded:
- `pkg/grpcapi/server_diag.go:220-224` — `if req.Count < 0 { return InvalidArgument "count must be >= 0 (0 = unlimited)" }` and `if req.Count > 8192 { ... }`.
- `server_diag.go:74` — `if count <= 0` handles the non-positive path before building argv; `buildPingArgv` receives an already-clamped count; `size` only used when `req.Size > 0` (line 94).

Negative `count`/`size` cannot drive a runaway probe loop or argv injection — rejected/ignored server-side with a clear message. The finding is explicitly "informational, not security." Cosmetic error-locality only. Why not a residual: correct end-to-end rejection, no defect.

**Dedup**: novel surface, immaterial.

---

## Negative results / dedup cross-check (review's own section)

Spot-verified the load-bearing claims; all hold on master:
- `cmd/cli/clear.go` / `show.go` / `pkg/cli/session_filter.go`: port validation 1..65535 before uint16 — the correct pattern the F1/F2 sites diverge from (server still the backstop). No bug.
- `pkg/cli/monitor.go` trace file handling (O_NOFOLLOW, sanitize, 0600, rotate-fail-closed) — matches #3378/#3379/#4540/#4556 as described. No bug.
- `cmd/xpfd/main.go` check-config size cap + IsRegular + post-read re-check — TOCTOU advisory only, consistent with note; not in-batch-actionable.
- bpf/headers MAX_EXT_HDRS=6 vs userspace 8 — correctly deferred to open #4555, not re-reported.

No finding in this batch reaches GENUINE-RESIDUAL. The subsystem is well-hardened: every client-side leniency the review surfaces has an authoritative server-side or commit-time guard, and F2's exploit input is impossible to commit.
