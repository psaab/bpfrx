# Authoritative Backlog

Date: 2026-03-06
Status: Active

This document is the canonical backlog snapshot for parity and HA-followup work.
It reconciles contradictions across `docs/feature-gaps.md`, `docs/phases.md`,
`docs/next-features/*.md`, `docs/bugs.md`, and `docs/sync-protocol.md`.

## Scope and precedence

Use these sources in this order when there is disagreement:

1. Runtime behavior and merged implementation evidence (code + tests + PR notes in `docs/phases.md`)
2. Row-level status entries in `docs/feature-gaps.md` (not the top summary table)
3. Proposed work in `docs/next-features/*.md` and HA proposal docs
4. `docs/bugs.md` for current/fixed bug state

## Open Backlog

### 1) vSRX parity gaps (from `docs/feature-gaps.md` row data)

Row-level gap totals:
- Missing: 120
- Partial: 12
- Parse-Only: 3
- Total Open Gaps: 135

Category totals:

| Category | Missing | Partial | Parse-Only | Open |
|---|---:|---:|---:|---:|
| 1. Security Policies (Unified/Advanced) | 7 | 0 | 1 | 8 |
| 2. Application Security (AppSecure) | 7 | 0 | 1 | 8 |
| 3. Intrusion Detection & Prevention (IDP/IPS) | 8 | 0 | 0 | 8 |
| 4. Content Security (UTM) | 6 | 0 | 0 | 6 |
| 5. SSL/TLS Inspection | 4 | 0 | 0 | 4 |
| 6. Advanced Threat Prevention (ATP) | 5 | 1 | 0 | 6 |
| 7. User/Identity Firewall | 5 | 0 | 0 | 5 |
| 8. NAT Enhancements | 5 | 1 | 0 | 6 |
| 9. Screen/IDS Enhancements | 4 | 2 | 0 | 6 |
| 10. Security Flow Enhancements | 5 | 0 | 0 | 5 |
| 11. ALG Enhancements | 9 | 0 | 0 | 9 |
| 12. Security Logging Enhancements | 0 | 0 | 0 | 0 |
| 13. PKI / Certificates | 3 | 1 | 0 | 4 |
| 14. Routing Enhancements | 10 | 3 | 0 | 13 |
| 15. VPN Enhancements | 8 | 0 | 0 | 8 |
| 17. Firewall Filter Enhancements | 2 | 0 | 0 | 2 |
| 18. QoS / Class of Service | 7 | 1 | 0 | 8 |
| 19. Multi-Tenancy | 4 | 0 | 0 | 4 |
| 20. Management & Automation | 9 | 2 | 0 | 11 |
| 21. Interface Enhancements | 1 | 1 | 0 | 2 |
| 22. System Enhancements | 5 | 0 | 1 | 6 |
| 23. Miscellaneous Features | 6 | 0 | 0 | 6 |

High-priority open items:
- Unified Policies (requires AppID)
- Dynamic Application Match (requires AppID)
- Application Services in Policy
- Application Identification (AppID) runtime wiring (currently parse-only)
- IDP Policy
- IDP Signature Database
- IDP Protocol Anomaly Detection
- NETCONF/YANG

### 2) Requested/proposed work still open

From `docs/next-features` and HA proposal docs:
- Strict single-owner VIP mode for same-L2 HA (tracking issue #104)
- Deterministic VRRP failover reconciliation
- Runtime wiring for `services application-identification`
- Runtime wiring for `security pre-id-default-policy`
- Runtime behavior for `system master-password`
- Runtime behavior for `system license autoupdate url`

### 3) Additional open items from bug/test planning docs

- `docs/bugs.md`: `RETH .link file overwritten with virtual MAC on DHCP recompile` is still marked `FIXING`
- `docs/active-active-new-connections.md`: DPDK zone-encoded path still documented with TODO placeholder
- `docs/test_env.md`:
  - Verify PBR overrides VRF routing (TODO)
  - Multi-ISP VRF test (TODO)

### 4) Candidate gaps not tracked in `feature-gaps.md`

From Juniper vSRX deployment guide (2026-01-20) feature tables:
- Junos Telemetry Interface (JTI)
- AppQoE (called out in CSB license feature list)
- Cloud-init parity (if this is a product-scope requirement)

These are not currently tracked as explicit rows in `docs/feature-gaps.md`.

## Implemented and should be treated as closed

These are documented as implemented in `docs/phases.md` and should not remain in open status tables:

- Sprint IF-1: LAG/ae, flexible VLAN tagging, interface bandwidth, point-to-point runtime wiring, primary/preferred wiring, interface description display
- Remaining parity caveat in section 21: transparent mode is still missing, and primary/preferred is still partial for some device-originated traffic paths.
- Sprint PR #67: `monitor security flow` and `monitor security packet-drop`
- Sprint #68: HA fail-closed default + `set chassis cluster hitless-restart` opt-in
- HA sync hardening sprint #69-#80 items called out as fixed in `docs/bugs.md`
- System NTP threshold action runtime wiring (`accept`/`reject`) via chrony
- Sprint CC-18: Junos IKE/IPsec compatibility items now merged on `master`:
  - gateway `local-certificate` / pubkey auth generation
  - `traffic-selector` support
  - structured DPD parsing and runtime generation
  - `external-interface` to runtime `local-address` resolution
  - Junos `$9$` PSK decoding
- Sync known-issues pair below are marked fixed in `docs/bugs.md`:
  - NO_NEIGH failover issue
  - Monotonic clock skew session expiry issue

## Stale or historical docs

### `docs/vsrx-gaps.md`

- Marked as a historical snapshot and superseded for active planning by `docs/feature-gaps.md` and this backlog file.

## Maintenance actions

1. Keep `docs/feature-gaps.md` summary totals in lockstep with row-level status changes.
2. For `docs/next-features/*`, always include explicit `Date` and `Status` metadata and flip to `Implemented` when shipped.
3. Decide whether JTI/AppQoE/Cloud-init are in product scope; if yes, add explicit rows to `docs/feature-gaps.md`.

## Reproducibility note

Gap counts above were computed from row-level status parsing in `docs/feature-gaps.md`
(Missing/Partial/Parse-Only only), excluding `Done` rows.
