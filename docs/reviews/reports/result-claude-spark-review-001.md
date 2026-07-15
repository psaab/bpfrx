# Triage result — claude-spark-review-001

- Review base: `4e0c7f74c` (self-reported == origin/master at review time).
- Independently verified against **CURRENT origin/master `816ac53c598946831b7b520101653975bab3d208`** (fetched fresh; a few commits ahead of the review base — includes #5141 TCP-seg clamp).
- Self-triage claim: 0 material individually-filed, 1 cohort (13 survivors), 2 fixed on origin/master, 0 stale/dup/NEG.
- **My verdict: self-triage is SOUND. 0 promotions.** Both "fixed" are genuinely fixed on CURRENT origin/master; every sampled cohort survivor legitimately stays low-materiality.

## Actions
- **Filed 1 cohort issue: #5609** — "[cohort] claude-spark-review-001 low-materiality + defense-in-depth + lenient/HA-sync survivors" (15 items NEW to this review; overlapping items deduped to open cohort #5557).
- **0 material issues filed** — no cohort survivor passed all three gates as a clean-config-reachable material bug.
- **2 FIXED confirmed genuinely fixed** on origin/master (firsthand grep of the fix code).
- **~7 survivors deduped to OPEN #5557** (same claude campaign re-run; not re-filed).

## Firsthand sample verification (>10 findings checked against origin/master tip)

| # | Finding | Symbol-exists? | Fixed? | Material? | Verdict |
|---|---------|----------------|--------|-----------|---------|
| FIXED-1 | Quarantine scoped-global drop-whole-rule fail-open (zones_quarantine.go) | yes | **YES — pruneQuarantined+ScopeSingular at :137,161,171** | n/a | genuinely-fixed-confirmed |
| FIXED-2 | Backup-node host-inbound VIP scoping (zones_host_inbound.go) | yes | **YES — VirtualAddresses fold at :270-271** | n/a | genuinely-fixed-confirmed |
| C-1 | Lifeline fab* prefix over-exempt (lifeline.go:74) | yes | no | LOW — host-bound only; #3682 CLOSED as visibility-only design decision | COHORT → deduped to #5557 |
| C-2 | IsWildcardZoneSet mixed any+concrete collapse (types_security.go:482) | yes | no | LOW — strict commit REJECTS mixing (compiler_validate_strict_policy.go:600-614 confirmed); only lenient/old-binary path | COHORT (filed #5609) |
| C-3 | Multicast host-inbound not per-zone scoped (host_inbound_multicast.go) | yes | no (enforcement DEFERRED, advisory-only) | LOW — fail-open-but-bounded (kernel joins only); #4455 CLOSED = catalog+advisory landed, enforcement deferred | COHORT (filed #5609) |
| C-4 | IKE per-netdev union across VLAN siblings (junos_host_deny.go:884-928) | yes | no | LOW — IKE authenticated, same-zone over-shield | COHORT (filed #5609) |
| C-5 | Bracket host-inbound override first-member-only (compiler_security_zones.go:134-163) | yes (confirmed InterfaceHostInbound[iface.Name()]) | no | LOW — raw load-override only; falls back to zone-level host-inbound | COHORT (filed #5609) |
| C-6 | VLAN trunk untagged first-wins zone (forwarding_build/interfaces.rs:82-91) | yes | no | LOW — policy still applied to a real zone; truly-unzoned fail-closed id-0 | COHORT (filed #5609) |
| C-7 | NAT64 frag-assoc port-free key sibling-SNAT (nat64.rs:250,282) | yes (path corrected: src/nat64.rs not afxdp/) | no | LOW — fail-safe drop not wrong-dst; RFC 8200 §4.5; bounded | COHORT (filed #5609) |
| C-8 | NPTv6 whole-snapshot abort vs NAT skip (nptv6.rs:223) | yes (path corrected: src/nptv6.rs) | no | LOW — fail-CLOSED availability divergence; #2241 justified | COHORT (filed #5609) |
| C-9 | compiler_nat_source no-translation still defaults PortLow/High (:486-489) | yes | no | LOW — no wire effect; Rust ignores range when no_translation | COHORT (filed #5609) |
| C-10 | Synthetic ifindex panic (interfaces.go:45) | yes | no | LOW — unreachable; panic→error hygiene | COHORT → deduped to #5557 |
| C-11 | RST-suppression warn-only (maps_sync.go:1141) | yes (RST WARN string present) | no | LOW — observability + TOCTOU | COHORT → deduped to #5557 |
| C-12 | networkd rp_filter all-knob warn-only (networkd.go:373-395) | yes (restoreSlowPathRPFilter present) | no | LOW — slow-path only, fast path unaffected | COHORT (filed #5609) |
| C-13 | probe_pin rethMap-incomplete fallback (probe_pin.go) | yes (ResolveProbeInterface present) | no | LOW — fail-CLOSED (probe HELD after #1895), not false PASS | COHORT (filed #5609) |
| C-14 | Zeroize custom-archive-dir retains tenant PSKs (cited factory_reset.go:60) | **NO — factory_reset.go does not exist**; logic in compiler_system.go/cli_request_system.go | unknown | LOW — path mis-cited, behavior UNVERIFIED | COHORT (filed #5609, flagged unverified) |

## Per-finding-table verdicts (every row)

The review's machine-extracted per-finding table (~lines 51-102) is dominated by
extraction-artifact rows ("s — MATERIAL (live enforcement)", "s (MATERIAL/COHORT only)",
"| Area | Gate verdict |", etc.) that carry no real finding — these are header/regex
noise, not findings (NEG). The substantive rows resolve as:

- FIXED rows (ps-A6): 2 real findings (quarantine, backup-VIP) → **both genuinely-fixed-confirmed** on origin/master 816ac53c5 (firsthand).
- COHORT rows with concrete descriptions → all verified LOW-materiality; filed in #5609 or deduped to #5557 (see table above).
- Artifact "s ..." / duplicated-header rows → NEG (no finding), correctly not carried.

## Honesty note
The self-triage was **substantively correct**. The only inaccuracies were minor
citation drift in the review (wrong file paths/line offsets for `zone_counters.rs`
[actually src/afxdp/zone_counters.rs], `nat64.rs`/`nptv6.rs` [src/ not afxdp/], and a
non-existent `factory_reset.go`) — none changes any materiality verdict; corrected in
#5609. No "fixed" was wishful (both fixes present firsthand), and no cohort survivor was
a mis-rated material bug. Dedup against open cohort #5557 avoided ~7 double-files.
