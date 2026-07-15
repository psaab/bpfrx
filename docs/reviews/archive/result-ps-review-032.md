# Triage result — ps-review-032.md

**Review:** Cohorts 12-14 — CLI/REST/gRPC + Wire/Protocol + Config Parser (fresh base, NOT avacado)
**Base:** `b1bd96fb6` · **Triaged vs:** origin/master `198d5a593`
**Outcome:** 2 GENUINE (both LOW) · 2 not-material (over-rated Mediums) · 7 prior-fix re-verified · 13 negatives · 0 confabulated

## GENUINE (LOW) — filed
- **L-01 → #4540** (usability): monitor-traffic missing-iface-value swallows a keyword as the iface name; value-less count → silent unlimited. cli_request.go parseMonitorTrafficArgs. Fix: reject iface==keyword + error on value-less count.
- **M-02 → #4541** (hardening): writeJSON WriteHeader-before-Encode + ignored error → truncated 200 on marshal failure. api.go:47-51. Zero current trigger. Fix: marshal-to-buffer, 500 on error.

## NOT-MATERIAL (over-rated)
- **H-01** stripSurroundingQuotes hides '-' from validateMonitorFilter — the review's OWN "impact: NONE"; `--` unconditionally neutralizes (buildMonitorTrafficArgv) + the validator checks the identical string getopt sees. Redundant defense-in-depth, cosmetic. Residual-of-#4524, rendered harmless by #4524's -- fix.
- **M-01** REST rollback n=0 non-negative-vs-positive — already FAILS CLOSED: ShowRollbackRedacted(0)→history.Get(-1)→HTTP 400 (history.go:54). Only a cosmetic error-message wording nit.

## Prior-fix re-verification (7, all correct — no re-report): #4526 DHCP, #4525 RA, #4524 monitor-injection, #4157 REST-auth-timing, #4530 isIdentChar-@-revert, #2744 control-req-cap-lockstep, #3980 navigatePath.

*Confabulation: NONE (all symbols exist in bpfrx). The #4524-class injection surface all-fixed on master. Cohort in good shape.*
