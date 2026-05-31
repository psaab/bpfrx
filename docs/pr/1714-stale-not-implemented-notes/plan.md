# #1714 — Doc accuracy: 3 stale "not implemented" notes

Status: DRAFT v1 — doc-only, lightweight plan (no code change)

## Issue framing

Three in-tree docs claim features are unimplemented that are in fact
shipped. Stale "not implemented" notes mislead operators, planning, and
risk duplicate work. Fix each to match current code, verified against
`origin/master` (a35132bca at edit time; issue cited ac6991c3 — anchors
unchanged between the two).

If a reviewer concludes any "it's implemented" claim is itself wrong,
PLAN-KILL / revise is the right call — accuracy is the whole point.

## Per-claim verification (read against master before editing)

1. **SNMP traps** — `docs/feature-gaps.md:377` says "trap sending not
   implemented". VERIFIED FALSE: `pkg/snmp/traps.go` `buildLinkTrap`
   builds SNMPv2c linkUp/linkDown PDUs (OIDs `1.3.6.1.6.3.1.1.5.4` /
   `.5.3`), `NotifyLinkUp`/`NotifyLinkDown` + `sendTrap` (UDP/162) send
   to configured targets, wired from `pkg/daemon/daemon_flow.go:454-456`,
   `traps_test.go` covers it. Still missing: any trap class beyond
   linkUp/linkDown (auth-failure, cold/warm-start, HA role change,
   policy/security alarms). Fix: state linkUp/linkDown done; enumerate
   missing classes; keep status Partial.

2. **SYN-cookie** — `docs/userspace-performance-plan.md:81` H4 says
   "SYN cookies not implemented | screen.rs". VERIFIED FALSE:
   `userspace-dp/src/screen/syncookie.rs` (557 LOC) implements the
   codec/SipHash24 MAC/validated cache; wired via `screen/mod.rs`
   (`SynCookieCodec`, `syn_cookie_standby_ack_counters`) with hot-path
   `syn_cookie_syn_ack_sent` batch counter. `feature-gaps.md:201`
   already documents it as wired. `syn-proxy` mode is genuinely not
   implemented (no `syn_proxy` symbol in tree). Fix H4: userspace
   `syn-cookie` is implemented; the open item is benchmark/validation +
   `syn-proxy`, not "not implemented". Point at current files/counters.

3. **IPv6 VRRP** — `docs/bugs.md:517-521` says IPv6 VRRP adverts not
   implemented, cites stubbed `instance.go:617-628` (`_ = pkt`).
   VERIFIED FALSE on both send AND receive: `pkg/vrrp/instance.go`
   `sendAdvert` (832) sends IPv6 adverts when IPv6 VIPs present (branch
   867-880) via `sendPacketIPv6` (954, dst ff02::12, hop limit 255,
   pseudo-header checksum in `Marshal(true,...)`); `receiverIPv6` (503,
   ip6:112) + `parseAfPacketIPv6` (670) handle receive; the AF_PACKET
   BPF filter in `manager.go:565+` matches 0x86DD tagged and untagged.
   Cited line range now points at `parseAfPacketIPv6`, not a stub. No
   remaining IPv6 receive/failover gap found. Fix: remove the stale
   bugs.md entry (it is a resolved/never-true feature gap).

## Edits (minimal)

- `docs/feature-gaps.md:377` — reword description + status.
- `docs/userspace-performance-plan.md:81` — reword H4 row.
- `docs/bugs.md:517-521` — remove the stale entry.

## Out of scope

No code changes. No tests/smoke (doc-only). `go build ./...` sanity only.

## Risk

Behavioral: none (docs). Architectural: none. Only risk is propagating a
wrong "it's implemented" claim — mitigated by reading each cited symbol
end-to-end (done above).
