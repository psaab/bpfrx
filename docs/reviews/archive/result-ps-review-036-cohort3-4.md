# Triage Result — ps-review-036 (Cohorts 3+4: Host-inbound + Zone + Screen/IDS)

- **Review file**: `/tmp/ps-review-036-cohort3-4.md`
- **Cohort**: RE-AUDIT of host-inbound / zone / lifeline / screen-IDS (ps-027 previously covered this cohort → S-03/#4550, H-01/#4554)
- **Review's declared base**: `33b891d11` (Merge PR #4563). Triaged against **current** `origin/master = 0b4109522e` (fetched this session). NOT avacado.
- **Master SHA at triage**: `0b4109522e7f4a93cb3b8ec7b7655483bb5a6b3f`
- **Method**: dedup HARD against ps-027 dispositions + filed/merged list, then confirm each cited symbol EXISTS on `origin/master` (`git show origin/master:<path>` + grep) before classifying. Weight-verify HARD.

## Outcome counts

| Disposition | Count | IDs |
|-------------|-------|-----|
| GENUINE-RESIDUAL (novel) | 1 | L-01 (Low, weak exploitability — file-worthy but near NOT-MATERIAL) |
| DUP (already filed, OPEN) | 2 | L-02 → #4455, L-03 → #4146 |
| ALREADY-FIXED (verified real symbols) | 8 | #4544, #4543, #4167, #3902, #3405, #3362, #3172, #4545 |
| NEGATIVE (verified fail-closed, coverage proof) | 17 | §5.1 (7 HI/zone) + §5.2 (10 screen) |
| NOT-MATERIAL (re-confirmed from ps-027) | 5 | Z-01, Z-02, S-01, S-04, S-05 |
| CONFABULATED | 0 | — every cited symbol verified present on master |

**No CONFABULATION.** Every symbol the review cites was confirmed on `origin/master`
(`mergeHostInbound`/`dedupHostInboundTokens` compiler_security_zones.go:50/65;
`BuildZoneHostInboundViews`/`BuildUnzonedHostInboundAddrs` zones_host_inbound.go:80/353;
`TruncatedIpv4Header` fail-closed + LSRR(131)/SSRR(137) extract.rs:106/130/136;
`host_inbound_admits` + `None => true` host_inbound.rs:474/498;
`udp_flood_drop`/`increment_ip_port`/`increment`/`cell_index_ip_port` mod.rs:681/693, syn_rate.rs:229/197/212).
The review's self-dedup and its "FIXED"/negative tables are accurate.

---

## NOVEL finding

### L-01 — GENUINE-RESIDUAL, Low (weak exploitability; review's "2× threshold" framing overstated)

**Claim**: On the flowless path a non-first UDP fragment is counted in the primary
per-destination CMS under key `(dst_ip, 0)` (because `dst_port=0` for a fragment),
which is a DIFFERENT sketch cell than the flow-present path's `(dst_ip, real_port)`.
So fragment traffic and reassembled-flow traffic to the same `(dst_ip, port)` do not
share the UDP-flood counter.

**Verification (traces to real code on master — CONFIRMED)**:
- `poll_stages.rs:491-503` — flowless branch calls `extract_screen_info(..., 0 /*src_port*/, 0 /*dst_port*/, ...)`. dst_port is hardcoded 0 for a fragment.
- `poll_stages.rs:523` → `check_flowless_screens_opts` → `mod.rs:1220` calls `self.udp_flood_drop(zone, &pkt.dst_ip, pkt.dst_port /*=0*/, ...)`.
- `mod.rs:681-693` `udp_flood_drop` → `sketch.increment_ip_port(dst_ip, dst_port, ...)`.
- `syn_rate.rs:212` `cell_index_ip_port` hashes `(ip, port)` jointly → `(dst_ip,0)` and `(dst_ip,53)` map to different cells. Confirmed.
- **Coherence of the scenario** (the load-bearing check): `inspect.rs:1277` — `parse_session_flow_from_bytes` returns `None` ONLY when `frame_is_non_first_fragment`; `inspect.rs:265-267` confirms first/atomic fragments (offset 0, MF 0 or 1) carry the real L4 header and return `Some(flow)`. Therefore a FIRST fragment takes the flow-present path with `dst_port=53` → `(ip,53)`; a NON-FIRST fragment takes flowless → `(ip,0)`. The two-bucket split the review describes is real, not a mis-read. (Had first fragments also gone flowless, all fragments would share `(ip,0)` and this would be fail-closed, not a split — I checked; they do not.)

**Dedup (NOT filed — NOVEL)**:
- `gh issue list --search "udp flood fragment"` → only #3902 (CLOSED) and #4155 (CLOSED). #3902 is a DIFFERENT bug: the flowless path did not run the source-independent screens AT ALL (fail-open) — now fixed so udp-flood DOES run on flowless. L-01 is about the bucket KEY once it runs, which #3902 did not address. #4155 is fabric-redirect double-count, unrelated.
- No open issue, no prior ps-review (018-035), no `all_findings.txt` entry, no `feature-gaps.md` entry mentions the fragment bucket split. Confirmed NOVEL.

**Severity reasoning (Low, and I DOWNGRADE the review's "2× effective threshold" framing)**:
- Exploitability: to deliver reassembled UDP datagrams to `victim:53`, the attacker MUST send first fragments, which ARE counted at `(ip,53)` against the correct threshold. So the effective **datagram-delivery rate to a specific port is still capped correctly** — the attacker cannot push more than `threshold` reassembled datagrams/sec to the port. The review's "attacker doubles the effective per-destination-port threshold" is measured in raw IP-fragment PACKET count, not in effective attack delivery. The extra allowance is only un-reassemblable-alone trailing-fragment NOISE.
- Blast radius: bounded twice — (a) the shared `(ip,0)` bucket still caps ALL non-first UDP fragments to an IP at `threshold`, and (b) the per-zone SECONDARY `TokenBucket` aggregate at `8× threshold` (mod.rs `SECONDARY_FLOOD_CEILING_MULT`) catches large floods. So the un-accounted headroom is bounded to roughly `threshold`-worth of non-first-fragment pps, not unbounded.
- Deliberateness bound: the degradation is DOCUMENTED at `mod.rs:675-679` ("a non-first fragment carries no L4 port, so `dst_port` is 0 there and the cap degrades to per-destination-IP (the best available for a fragment)"). The residual is the subtle point the comment did not spell out — `(dst_ip,0)` is a distinct namespace from `(dst_ip,port)`, so it does not COMBINE with same-IP flow counting. That is a genuine accounting imperfection but within the authors' stated "best available for a fragment" intent.
- vSRX-parity bound: it is not firmly established that vSRX counts non-first fragments toward the udp-flood threshold at all (Junos flow reassembles / handles fragments in a separate module). So "an admit a real vSRX would deny" is plausible but not proven — this is why it is Low, not Medium.
- **Why not higher**: effective per-port delivery still capped + double-bounded + documented + parity uncertain. **Why not dismissed / NOT-MATERIAL**: it traces to real code, is genuinely novel, and has a clean, real one-line fix.

**Fix direction (real, minimal — validated)**: for a non-first UDP fragment, call the
per-IP-only sketch `increment(dst_ip, ...)` (exists at `syn_rate.rs:197`, this is exactly
what ICMP flood uses) instead of `increment_ip_port(dst_ip, 0, ...)`. That folds trailing
fragments into a consistent per-destination-IP abstraction rather than an orphaned `(ip,0)`
namespace. `screen/mod.rs` (`udp_flood_drop` non-first-fragment branch) + `poll_stages.rs`
(flowless plumbing). Alternatively document as a known limitation. Either is Low priority.

**File as**: 1 Low issue, labels `screen`, `udp-flood`, `fragment`, `accounting`, `vsrx-parity`, `low`.

---

## DUP findings (already filed, OPEN — do NOT re-file)

### L-02 → #4455 (DUP, OPEN)
Per-zone multicast/broadcast host-inbound admission (OSPF 224.0.0.5/6, VRRP 224.0.0.18,
PIM, IGMP, etc. bypass per-zone `host-inbound-traffic protocols` because they match no
per-zone unicast `daddr` set → fall through). `gh issue view 4455` = OPEN, title
"HI-1: per-zone multicast/broadcast host-inbound admission (iifname gate + Rust lockstep)".
Needs iifname dimension + Rust lockstep + #1960 behavior-change treatment. Confirmed still
present on master (`daemon_nft.go` per-zone rules key on unicast `daddr` only), correctly
NOT re-reported by the review. Matches the task's filed/merged dedup list (#4455 NEEDS-RESEARCH).

### L-03 → #4146 (DUP, OPEN)
`to-zone junos-host then deny` not enforced for direct host-bound traffic — the XDP shim
shunts local-destined packets to the kernel, which has no junos-host policy gate (only the
nft `host-inbound-traffic` chain). `gh issue view 4146` = OPEN. Confirmed still present,
correctly NOT re-reported. Matches the task's dedup list (#4146).

---

## ALREADY-FIXED verifications (confirmations, not findings — all symbols real on master)

The review's §1 "CLOSED / previously-fixed" table was spot-verified. These are the cohort's
prior High/Medium bugs, all fixed and closed; not re-filing:
- **#4544** (CLOSED) dup host-inbound block token loss — `mergeHostInbound` compiler_security_zones.go:50, `FindChildren("host-inbound-traffic")` :104. This is ps-027 H-01 → #4554 in the task list; #4544 is the config-layer sibling. Fixed.
- **#4543** (CLOSED) IPv4 malformed-option source-route bypass — `extract.rs` fail-closed `Err(TruncatedIpv4Header)` at :106/:130, LSRR/SSRR kind test precedes length check (:136). This is ps-027 S-03 → #4550. Fixed.
- **#4167** IPv4 truncated header fail-open — extract.rs:105-106/:129-131. Fixed.
- **#3902** flowless bypasses source-independent screens — `check_flowless_screens_opts` mod.rs:1149. Fixed (and is the parent of L-01's code path, but a distinct closed bug).
- **#3405** host-inbound default-deny for no-stanza zones — `configured = zone != nil` zones_host_inbound.go + `None => true` host_inbound.rs:498 only for unknown zone id 0. Fixed.
- **#3362** per-interface override — `buildInterfaceHostInboundMap` zones_host_inbound.go:95, `ifindex_host_inbound`. Fixed.
- **#3172** VRRP VIP scoping — zones_host_inbound.go. Fixed.
- **#4545** writeJSON/monitor — out-of-cohort, verified via git log. Fixed.

---

## NOT-MATERIAL (re-confirmed from ps-027 — do NOT re-file)

The review re-confirms these as harmless, matching ps-027 (task's do-not-re-file list):
- **Z-01** `buildInterfaceZoneMap` base-cut `out["reth0"]` parent pollution — written but no consumer reads it (VRRP reads exact unit name; static path independent). §3.3. Still present, harmless.
- **Z-02** fail-closed zone default — confirmed.
- **S-01** LAND `addrs_known` guard — confirmed (prevents UNSPEC==UNSPEC false LAND).
- **S-04** SynCookie length over-count — confirmed.
- **S-05** alarm→drop 1-SYN window — confirmed.

---

## NEGATIVES (17 — verified fail-closed, coverage proof; §5.1 + §5.2)

Reviewed as coverage proof; symbols verified real. No action. Highlights:
- HI/zone (7): empty configured zone default-denies (test `empty_configured_zone_default_denies`); per-iface override keyed by ifindex; dup blocks merged not dropped; lifelines excluded (DHCP/SLAAC still captured); unzoned catch-all DROP under `junos-host` sentinel; addressless transient window observable (WARN+gauge); family gating in `ZoneHostInbound::admits`.
- Screen (10): IPv4/IPv6 truncated + malformed-option fail-closed; LAND addrs_known guard; flowless runs all source-independent screens; IPv6 EH MAX=8 unified (0|43|51|60|44|135|139|140|253|254, ESP not walked); both-family fragment screens; source-route = actual LSRR/SSRR/RH0/RH1 only; SYN-flood ordering (#3315/#4112); scan/sweep bounded+window-aware; SYN-cookie zone-bound/epoch-tolerant/gen-gated.

---

## Bottom line

RE-AUDIT is clean. The cohort's prior High/Medium bugs are all fixed on master. One NOVEL
Low residual (L-01, UDP-flood non-first-fragment bucket namespace split) — file-worthy but
weak: effective per-port datagram delivery is still capped by first-fragment counting, it is
double-bounded (shared `(ip,0)` cap + 8× aggregate), it is documented-deliberate degradation,
and vSRX parity is unproven; I downgrade the review's "2× effective threshold" wording as
raw-fragment-count, not effective-delivery. L-02/#4455 and L-03/#4146 are correctly identified
open dups. No confabulation; no new High/Medium.
