# Triage result — ps-review-027.md

**Review:** Cohorts 3+4 — Host-inbound + Zone + Screen/IDS
**Base:** `b1bd96fb6` (FRESH — ≈ current master; only screen/PBR/CoS commits since, none touch these findings)
**Triaged vs:** origin/master `198d5a593`
**Cites real bpfrx code?** YES — host_inbound.rs, extract.rs, compiler_security_zones.go, lifeline.go, zones.go all verified present (NOT avacado; unlike ps-021 which cited nonexistent nftables host-inbound symbols).
**Outcome:** 2 GENUINE (both LOW — review's MED over-scoped, corrected) · 1 deliberate · 5 not-material · 1 negative · 0 confabulated

## GENUINE — filed
### S-03 -> #4543 · LOW (review MEDIUM)
- WHERE: screen/extract.rs IPv4-options TLV walk `if opt_len < 2 || pos + opt_len > opt_end { break; }`.
- SCENARIO: the walk tests kind==LSRR(131)/SSRR(137) BEFORE validating length, so a malformed option before an LSRR aborts the scan via `break` → saw_ipv4_source_route=false → check_source_route Pass. Input `[type=0x44,len=0x01][LSRR...]`: len<2 hits break, the LSRR is never seen, the source-route screen passes it.
- WHY REAL (not negative): no MalformedIpv4Options variant exists (packet.rs has only Truncated*), so malformed-option does NOT fail closed — inconsistent with the file's OWN #4167 (truncation fail-closed).
- WHY LOW not MEDIUM (bounds the review missed): (1) the exploit packet is itself malformed IP, dropped upstream; (2) xpf's AF_XDP forwarder does NOT honor source-routing, so a leaked option transits INERT — screen-contract violation, not a live routing bypass.
- FIX: Err(TruncatedIpv4Header) ("ip-malformed") on malformed TLV, matching #4167 + vSRX.
### H-01 -> #4544 · LOW (review MEDIUM; its exploit trace REFUTED)
- WHERE: compiler_security_zones.go zone-level `zone.HostInboundTraffic = parseHostInboundNode(prop)` (OVERWRITE); interface-level FindChild (first-wins).
- REVIEW'S FLAT-SET TRACE REFUTED: ConfigTree.SetPath reuses an existing same-key container (`!n.IsLeaf && keysEqual → current=&n.Children`) so two set-lines MERGE; LoadMerge also merges (via FormatSet). The two common authoring paths do NOT lose — the review's headline reachability is wrong.
- THE ONE REACHABLE PATH: `load override` (store_command.go:196) splices the RAW hierarchical parse; parseStatements does NOT merge same-key blocks; commit compiles it directly (no FormatSet round-trip), no dup-block schema reject. So a hand-authored file with two literal host-inbound-traffic blocks loses the second.
- WHY LOW not MEDIUM: needs (a) hand-authored config (Junos-exported always shows one merged block) AND (b) load override specifically. Fail-OPEN only if the dropped block was the restrictive one. Narrow + config-time.
- FIX: accumulate FindChildren at both levels, OR commit-check reject dup blocks.

## DELIBERATE
- H-02 lifeline HasPrefix(base,"fab")/em0 over-broad — the file-header comment documents it as a tracked design question; #3682 changes VISIBILITY only. Recorded tradeoff.

## NOT-MATERIAL (disproving mechanism each)
- Z-01 buildInterfaceZoneMap out[base]=zone before unit-continue — the polluted base entry is never read (VRRP uses exact zoneByIface[unitName]; static uses snap.Zone). No consumer -> no bypass.
- Z-02 VRRP VIP unit-not-in-zone — depends on Z-01 and fails CLOSED (unzoned catch-all DROP). Not fail-open by definition.
- S-01 flowless UNSPEC==UNSPEC LAND — mod.rs gates check_land under `if addrs_known`; flowless returns addrs_known=false so the UNSPEC pair never reaches check_land. Defense-in-depth only.
- S-04 SynCookieValidatedCache::take_valid doesn't reap other sets — expired entries lazily reclaimed on next insert (bounded 4096); len is over-count only, NOT a security gate.
- S-05 alarm-without-drop->drop SYN-cookie window — one SYN under active flood; next over-attack SYN arms cookie-active in drop mode; in that instant a session-less ACK forwards to normal flow/policy (deliberate audit contract, = normal non-cookie behavior).

## NEGATIVE
- S-02 fabric-skip flowless — stage_classify_fabric_ingress sets FABRIC_INGRESS_FLAG BEFORE stage_screen_check (passes skip_rate_flood). Correctly wired; reviewer self-downgraded.

*Verify-first REFUTED the review's 2 over-scoped high-severity claims (H-01 flat-set fail-open; S-03 MEDIUM) -> both LOW with disproving/bounding traces. 0 confabulation.*
