# Triage Result — ps-review-038-A8_go_api_grpc_rest-b1

- **Subsystem**: A8_go_api_grpc_rest (batch 1/2) — REST HTTP API (`pkg/api`) + gRPC (`pkg/grpcapi`); zone policy, integer truncation, DoS, resource leaks.
- **Base == current master?** Review base `d4506d445`; triaged against current `origin/master` `57d24d9aed4b64680831a1765a128921e79c00f7` (fetched this session). Symbols re-verified on current master.
- **Real bpfrx or avacado?** Review cites `/home/ps/git/avacado-xpf/...` paths throughout (avacado-fork authored), BUT every cited symbol is present in real bpfrx on origin/master (`server_sessions.go`, `pkg/api/nat.go`, `pkg/api/sessions.go`). So findings are triaged against real bpfrx code — none confabulated.
- **Outcome counts**: 8 findings. 0 GENUINE-RESIDUAL, 0 CONFABULATED. NOT-MATERIAL: 3 (F-01, F-02, F-03). NEGATIVE (self-refuted by reviewer): 3 (F-04, F-06, F-07). DUP (self-marked, #4484): 2 (F-05, F-08).
- **Net**: **0 genuine residuals.** Every finding is either a hardened path the reviewer misreads as latent, a display-only no-op, or a self-marked negative/duplicate.

---

## F-01 — gRPC `buildSessionFilter` port truncation before validation — NOT-MATERIAL (already-fixed + tested)

**Claim (Medium/High):** `f.srcPort = uint16(req.SourcePort)` at `server_sessions.go:342` truncates *before* the `req.SourcePort > 65535` check at :369; `SourcePort=65536` → `srcPort=0` (wildcard). "Latent filter-bypass one refactor away."

**Disposition: NOT-MATERIAL / ALREADY-FIXED.** The reviewer's own trace concedes "the current code IS safe." Verified on current master:
- `buildSessionFilter` sets `inputErr` for `req.SourcePort/DestinationPort/Zone > 65535` (`server_sessions.go:367-373`).
- `validate()` returns `inputErr` first (`server_sessions.go:328-336`).
- **All three** `buildSessionFilter` callers gate on `validate()` and return the error *before* any iteration or clear: GetSessions (`:78-81`), pagination (`:602-604`), and the shared clear path (`:968-971`). So `SourcePort=65536` fails the RPC with `InvalidArgument` before `matchV4/matchV6` or session-clear ever runs — the truncated `srcPort=0` predicate is never consumed.
- This is the *exact* concern already reviewed: the code carries an explicit `NOTE` block (`server_sessions.go:344-352`, "a filtered clear degrading to clear-all (Codex r2 Critical)") and a pinned regression test (`session_filter_test.go:117-131`, "65536 -> no zone filter, 65537 -> zone 1 — Codex r3 Medium"; plus `session_filter_3439_test.go`).

The "one refactor away" residual is hypothetical future-refactor risk, not a reachable bug on master. Severity is not Medium — it is a no-op on the guarded path. Not filed.

## F-02 — REST `natDestHandler` `DstPort`/`TranslatePort` uint16 truncation — NOT-MATERIAL (display-only, commit-gated, fail-closed)

**Claim (Low/High):** `natDestHandler` (`pkg/api/nat.go:96,101`) casts `rule.Match.DestinationPort int` and `pool.Port int` to `uint16`; a value >65535 (via tolerant/HA-sync load) wraps → wrong port shown.

**Disposition: NOT-MATERIAL.** Verified symbols exist (`nat.go:81,96,101`). But the value the handler reads is bounded on every production path:
- Commit / commit-check hard-reject out-of-range destination ports: `validateNATMatchDestinationPortStrict` (`compiler_validate_strict_nat.go:358`, rejects `p<1||p>65535` on `Destination.RuleSets`) and `validateDNATPoolStrict` (`:441`, rejects pool `port<1||>65535` via `parseCanonicalPort`).
- The *only* escape the reviewer names is the #1960 tolerant-load / peer-sync path — which **downgrades these to a warning** but the compiler docs (`compiler_validate_strict_nat.go:427-440`) explicitly note the **snapshot builder independently fails CLOSED** (skips the rule rather than wrapping the port). So in the one scenario where an out-of-range port could sit in `ActiveConfig`, the corresponding DNAT rule is **not installed** — the REST truncation is a cosmetic wrong-number on a rule the dataplane already dropped, on an already-invalid config that bypassed commit.
- Impact is display-only (no forwarding/security effect), and reachability requires a config that was invalid at author time and survived only the defense-in-depth lenient loader. Below the genuine-residual bar (crafted-input reaching an *unguarded* sink). Not filed.

## F-03 — REST `sessionEntryFromPB` uint16 port truncation — NOT-MATERIAL (mathematical no-op)

**Claim (Low/High):** `sessionEntryFromPB` (`pkg/api/sessions.go:395,414`) truncates `uint32` proto ports to `uint16`; a port 65536 would wrap.

**Disposition: NOT-MATERIAL.** Verified symbols exist. The reviewer self-hedges ("session ports always 0..65535 at the dataplane level, so truncation is safe"). Confirmed: the peer-projection `SessionEntry.src_port/dst_port/nat_*_port` are populated by the peer's own `GetSessions`, whose ports come from `ntohs(key.SrcPort)` where `key.SrcPort` is a **uint16** dataplane conntrack field (`server_sessions.go:159,205,465,635`; `ntohs` returns uint16). A uint16 source can never exceed 65535, so `uint16(e.GetSrcPort())` is a lossless no-op — no reachable value wraps. Not filed.

## F-04 — `peerSessionsRequest` lenient `ParseUint` — NEGATIVE (self-refuted)

Reviewer concluded "NEGATIVE — no finding here after analysis": `ParseUint(...,10,16)` rejects >65535, and `peerSessionsRequest` is only reached after `buildSessionQuery` already validated ports fail-closed. Confirmed consistent with master. No disposition change.

## F-05 — SSE no concurrent-stream cap / no per-write deadline — DUP (#4484, self-marked)

Reviewer self-marks "NEGATIVE / DUPLICATE of #4484 L-04 (SSE cap)" (opus-172 LOW batch). The `WriteTimeout`-unset is deliberate (SSE + large scrapes must not be severed; documented in `server.go`). SSE streams are auth-gated when `metricsRequireAuth`. Already-filed LOW; per triage rules a re-report of a filed/closed LOW is not a new residual. Not re-filed.

## F-06 — `MonitorInterface` no VRF isolation on interface name — NEGATIVE (self-refuted)

Reviewer concluded "NEGATIVE — display-only concern, no security impact": `monitor interface` is a diagnostic counter view (like `monitor traffic`), not a security boundary; the interface name is already validated against the active config. Confirmed. No change.

## F-07 — `configSearchHandler` raw `strings.Contains` — NEGATIVE (self-refuted, informational)

Reviewer concluded "NEGATIVE — no vulnerability": literal substring match over the **redacted** render (`ShowActiveRedacted`, #4051), URL-decoded query used only as a `strings.Contains` literal — no regex/SQL/command/HTML sink. Confirmed. No change.

## F-08 — REST session-list no cross-request rate limit — DUP/NEGATIVE (self-marked #4484)

Reviewer self-marks "NEGATIVE / already covered by #4484 (session/metrics DoS hardening)": authenticated-only, bounded by `limit≤10000` + HTTP `ReadTimeout=30s` + 16MiB body cap; the metrics amplification path already has the 3s TTL cache + singleflight. REST session-list lacking the cache is a known lower-priority observation folded into the opus-172 LOW batch. Not a new residual.

---

## Security-Focus Notes cross-check (reviewer prose, no F-number)

- **Ping `-I`/`Source` option-confusion**: reviewer declines to file. Confirmed non-material on master: `PingArgv` (`diagcmd/diagcmd.go:65-77`) appends `-I opts.Source` then `"--", opts.Target`. Target is `--`-protected (#2084); exec is via argv (no shell). A `Source="-n"` at worst yields `ping -I -n -- target` which ping rejects as an invalid interface — no RCE, authenticated-only. Correctly non-filed.
- All other security notes (constant-time auth #4157, 16MiB body/recv caps, secret redaction, fabric HMAC ±1 window / allowlist fail-closed, filtered-clear guard) reviewed as sound and match master.

---

## Conclusion

**0 genuine residuals.** F-01 is a hardened path (validate() gate at all 3 callers + Codex r2/r3 comment + regression test) the reviewer itself calls "safe." F-02/F-03 are display-only truncations of values the commit gate (F-02) or the uint16 source (F-03) bound to ≤65535, with fail-closed dataplane behavior on the one lenient-load escape. F-04/F-06/F-07 are reviewer-self-marked NEGATIVE. F-05/F-08 are reviewer-self-marked duplicates of #4484. Nothing to file or drive.
