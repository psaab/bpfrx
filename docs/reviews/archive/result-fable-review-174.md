# Triage result — fable-review-174 (Paladin Defensive-Coverage Campaign, ~8953 lines)

**Review base:** `f9954237c` · **Verified against origin/master:** `fc479ca65`.
**Method:** parent inline (FleetView roster walled — no delegated triage this pass). Two finding batches: batch 1 (DHCP/scheduler, H1/H2/M1-M6/L1-L12) + batch 2 (config/host-zone, M1-M3/L1-L5). Every FILE candidate re-verified via `git show origin/master:<path>` (symbol grep + whole-function-body read + dedup vs open issues #5658-5671).

## Headline
The review's own pre-verification gate-count declared `{MATERIAL: 0, DUP: 3, NEG: 1}` and its "verified-against-origin/master highlights" section was left empty ("to be filled after manual re-check") — i.e. it landed as a RAW review needing coordinator verification. On manual re-verification against current master, **3 findings survived all 3 gates as genuinely-material-and-new**; the rest are defense-in-depth on already-fail-closed designs, not-currently-reachable (sanitized upstream), review-self-downgraded ("No bug"), or explicit negatives.

## Summary line
**3 filed (#5669, #5670, #5671) / 1 cohort (#5672, ~20 low-materiality survivors) / 3 negatives dropped (L8/L9/L10) / 0 dup-refiled.**

---

## FILED (material, verified on origin/master)

### #5669 — scheduler: republish-failure fail-open has no bounded-age fail-closed/alert (H1)
- **Root:** `pkg/scheduler/scheduler.go` — the #3780 republish self-heal latches `republishPending` + retries next tick (60s), but there is NO bounded-age handling. Under control-socket contention the retry can keep failing, extending the documented fail-open window (scheduled permit forwards past window close) indefinitely; `republishFailures`/`republishFirstFail` are metric-only, never acted on, no `slog.Warn` at the decision point.
- **Gate outcome:** FILE. symbol-exists ✓ (comment+latch live at 24-37/162-182), not-already-fixed ✓ (#3780 mitigates via retry only — no age bound), real+material ✓ (packet-path fail-open on a firewall contract). Severity Medium (bounded+self-healing common case; tail is the contention stall). Defense-in-depth hardening on a known residual the code comment already calls out.

### #5670 — dhcprelay: no per-interface rate-limiting → CPU-exhaust / amplification DoS (H2)
- **Root:** `pkg/dhcprelay/relay.go` — client+server listener loops forward each request to all N servers with an Option-82 insert; `RelayStats` covers backup/max-hops/giaddr/unknown-server semantic drops but there is NO rate-limit/token-bucket/pps cap (verified: grep for rate-limit/token/pps/throttle returns nothing). Unauthenticated client-segment flood → per-packet `dhcpv4.FromBytes` + Option-82 alloc + sequential fan-out to every server (amplification factor N) + collateral server rate-limiting of real clients.
- **Gate outcome:** FILE. symbol-exists ✓, not-already-fixed ✓ (no rate-limit path exists), real+material ✓ (unauthenticated, amplifying, no backpressure). Severity Medium-High.

### #5671 — config: memberIsNestedSet lacks the '&& as != nil' guard lookupApplicationSet has (batch-2 M2)
- **Root:** `pkg/config/predefined.go` — `memberIsNestedSet` (L294) `if _, ok := apps.ApplicationSets[memberName]; ok { return true }` treats a present-but-nil (tolerant-load #1960) entry as a nested set; `lookupApplicationSet` (L226) correctly guards `&& as != nil`. Asymmetry → a nil-valued app-set key routes to lookup, which skips nil and errors "application-set not found" instead of falling through to leaf-application resolution.
- **Gate outcome:** FILE. asymmetry CONFIRMED on master (both functions read), not-already-fixed ✓, real ✓ (rare tolerant-load path, concrete one-line fix + fail-on-revert test). Severity Low-Medium. Adjacent to the just-merged #5664 appid predefined-bundle resolver but a distinct nil-guard site.

---

## COHORT → #5672 (low-materiality / defense-in-depth survivors)

Verified-not-material-enough-to-file-individually, per "don't file 20 trivial ones":
- **DHCP batch-1 M1-M6:** DUID path-traversal (already `validInterfaceName`-guarded, defense-depth); Option-82 re-stamp missing log (observability); DDNS reconciler TOCTOU (required-column guard ALREADY fails closed on empty/header-only; residual = indistinguishable-legit-empty only); T1/T2 clamp (review confirms #4526 overflow fix correct — latency note); lease-sync memfile durability window; systemctl CombinedOutput output-leak (no arg injection, confirmed).
- **Batch-2 M1/M3 + L1-L5:** junosHostZoneByInterface trailing-dot (NOT reachable — sanitized upstream, harden-only); routinginstanceid int cast (review self-downgraded "No bug", 64-bit-only); junosHostAddrScoped any-ipv4 leg; samplingFlowServerNode SetPath; junosHostParsePorts whitespace-split; natpool.parsePoolAddr silent-nil; syslogFacilitySeverity wildcard-key unvalidated.
- **Batch-1 L1-L7/L11/L12:** L2-sender MAC boundary; policy-sim scheduler-map staleness (sim-only); natshow silent partial parse; deploy 0700 dir; dist-signing XPF_SIGN_SECKEY /proc leak; image-bake SHA pin; test/incus parser OOM; DDNS iapd PD seam; scheduler tz 5s drift flapping.

## DROPPED (negatives — review self-labeled, no action)
- **L8** — no TOCTOU in control-socket handling (contention rule correctly observed).
- **L9** — no per-packet hot-path allocation (bounded/accounted).
- **L10** — DHCP relay giaddr primary/secondary selection correct post-#2849.

---

*Marker: `/tmp/.researched-fable-review-174.md`. All ground truth verified via `git show origin/master:<path>`, never the stale main checkout. Triaged inline (parent) — FleetView roster walled, no delegated triage available this pass.*
