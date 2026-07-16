# Triage result — ps-review-024.md

**Review title:** "Cohorts 9-11 — IPsec/IKE/WireGuard + HA/Cluster/VRRP + DHCP/relay" — **MISLABELED**; actual content is **Cohort 8 — Firewall filters + PBR + Routing** (no IPsec/HA/DHCP findings present). (Same title/content mismatch as ps-019 and ps-021.)
**Base:** `b1bd96fb6` (~2 commits behind master — FRESH base)
**Triaged vs:** origin/master `3d8875fdc` (all cited symbols confirmed to EXIST in bpfrx — no confabulation)
**Outcome:** 2 GENUINE residuals (filed) · 2 not-material (disproven with evidence) · negatives verified · 0 confabulated · 0 dup

---

## GENUINE residuals — filed

| Finding | Sev | Issue | Evidence (current master) | Fix |
|---|---|---|---|---|
| **M-01** PBR kernel-mirror steers a `routing-instance` term even with `discard`/`reject` | Low-Med | **#4534** | `pkg/routing/rules.go:770` `buildPBRFromFilter` never reads `term.Action` → a `routing-instance+discard` term (surviving lenient load, #1960) builds a global steering `ip rule` while userspace correctly `RouteOverride::Drop`s (#4392). Kernel slow-path-mirror fail-open VRF-steer. | `continue` when `term.Action` ∈ {discard,reject}; mirror the userspace is_drop gate. Go. |
| **L-01** three-color policer with unspecified color mode disarms forwarding instead of color-blind default | Low | **#4535** | `compiler_firewall.go:85-121` leaves `ColorBlind=false` when neither color-blind nor color-aware set → `userspaceSupportsThreeColorPolicers=false` → `ForwardingSupported=false` (visible "Forwarding blocked by" reason). Junos defaults to color-blind + enforces → parity gap (xpf refuses a config Junos accepts). | default `ColorBlind=true` when neither `ColorBlindConfigured` nor `ColorAwareConfigured`. Go. |

## NOT-MATERIAL (disproven with evidence)

- **M-02 / F-129** `filter_term_semantics_match` omits the six `flex_*` fields (`cache_sensitive.rs:287`) — **moot**: `FilterTerm::has_per_packet_l4_match()` returns `|| flex_enabled`, so any flex-bearing filter makes the flow-cache DECLINE (`mod.rs:224/290`) → every packet re-evaluated live; there's no cached verdict to go stale. Optional defense-in-depth, not a bug.
- **M-03** next-table global `ip rule` no source-VRF scoping (claimed High VRF-leak) — **overstated**: the sole caller (`daemon_apply.go:1249-1258`) passes only `cfg.RoutingOptions.StaticRoutes` (main table), so a per-RI `next-table` route is never programmed (that's the separate known F-174 gap — the trace is internally inconsistent). The main-table residual is the already-documented "no iif selector" limitation (H03) — Low at most.

## NEGATIVE (verified)

N-01..N-20 spot-verified against master (port-except fail-closed, flex_matches bounds, RI-conflict userspace drop #4392, DSCP-0 PBR drop, family-any gates, firewallPrefixListRefs #3843) — consistent, no confabulation.

---

*Method: read-only triage, fresh base, weight-verified HARD. The triage correctly downgraded M-01 (Medium→Low-Med), disproved M-02/M-03 with disproving file:lines, and corrected L-01's "silent drop" mischaracterization to "visible whole-dataplane disarm" while keeping the genuine parity gap.*
