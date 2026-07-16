# Triage result — ps-review-023.md

**Review:** Cohorts 12-14 — DHCP/RA/Flowexport + CLI/REST/gRPC + Wire/Protocol/Config-Parser
**Base:** `c2ee227c4` (current master — FRESH base, findings against current code)
**Triaged vs:** origin/master `22910f775` (all cited symbols confirmed to EXIST in bpfrx — no avacado-fork confabulation in this cohort)
**Outcome:** 3 GENUINE residuals (all filed + driven) · 3 not-material · 2 negative · 0 confabulated · 0 dup

---

## GENUINE residuals — filed + driven

| Finding | Sev | Issue | Evidence (current master) | Status |
|---|---|---|---|---|
| **13-02** `monitor traffic ... matching <filter>` tcpdump option injection | **HIGH** | **#4524** | `pkg/cli/cli_request.go:568` `buildMonitorTrafficArgv` appends `strings.Fields(filter)...` with NO `--` separator → `matching -w /etc/cron.d/x` / `-z <cmd>` reach tcpdump as options (getopt permutation) → root file-write/command-exec. RBAC gates at PermControl → a control-but-not-super-user login-class escalates to root. (Review's cited path `monitor.go:565` was WRONG; real code `cli_request.go:568`.) | **MERGED #4527** — inserted `--` before filter tokens (mirrors diagcmd #2084) + `validateMonitorFilter`; hostile-review MERGE-READY (empirically proven no file written for `-w` after `--`). |
| **12-02** RA `randomAdvInterval` returns 0 → RA hot-loop | Low | **#4525** | `pkg/ra/sender.go:863` — for `max-advertisement-interval` 1-2, interval draws 0 → `advTimer.Reset(0)` (sender.go:468) fires immediately → RA/ND flood + CPU spin. Schema `schema_routing.go:455` permits it (`ValidateIntegerMin(1)`). | **MERGED #4528** — runtime floor ≥1s + RFC-4861 schema `ValidateInteger(4,1800)`/`(3,1350)` + `crossCheckRAIntervals` cross-field gate. |
| **12-01** DHCP `renewalTimers` int64 overflow (>41.8yr leases) | Low (impact ~nil) | **#4526** | `pkg/dhcp/commit.go:52` `leaseTime*7/8` overflows for a max-uint32 lease → T2 clamps to 1s. But `t1 = leaseTime/2` dominates → no rebind storm; effectively nil impact. Cleanliness only. | **MERGED #4531** — reordered to `leaseTime/8*3` (divide-before-multiply); bit-identical for normal leases. |

## NOT-MATERIAL (disproving evidence recorded)

- **13-01** REST Basic-auth username-enumeration timing — the material early-return gap is already fixed (#4157, compare always runs); the residual (subtle.ConstantTimeCompare length short-circuit + Go map-lookup) is a nanosecond side channel swamped by network jitter, loopback-bound by default. Not exploitable.
- **14-01** Config lexer `,`/`%` in `isIdentChar` → prefix-list collapse — speculative; comma-separated prefix lists are not valid Junos syntax, no real/feed config produces them, `%` must stay (link-local zone-id). No demonstrated bug.
- **14-02** Control-socket cap lockstep — both constants present + equal (64 MiB); already guarded by `TestControlRequestCapLockstepWithRust` (`control_request_cap_2744_test.go`) under `make test`.

## NEGATIVE (verified-correct)

- **14-03** `navigatePath` terminal single-key — `pkg/config/ast.go:221-239` returns every sibling sharing the leading keyword (#3980, F-037 fixed).
- Review's own negatives section (Option-82 length, classless-route blackhole, RA PREF64 pruning, NetFlow protocol-num, ping/traceroute `--`, REST redaction, gRPC dual-accept, lexer bracket-loop, parser depth cap) — spot-verified consistent with master.

---

*Method: read-only triage agent, fresh base but weight-verified HARD (a sibling cohort ps-021 partly confabulated code against a different fork; local checkout is stale so all checks used `git show origin/master:`). The 13-02 HIGH is the standout — a real privilege-escalation the fresh-base audit surfaced.*
