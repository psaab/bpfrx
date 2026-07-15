# fable-review-167 — vSRX Parity Coverage Campaign

**Focus:** complete configuration/behavioral parity with Juniper vSRX —
which Junos idioms an operator copies from a real vSRX config that xpf
silently drops, mis-handles, wrongly rejects, or accepts-but-never-wires,
and which `show`/`clear`/`request` surfaces diverge. Deliverable is a
remediation work-list plus a precise correction of the parity
documentation's own staleness.

## 1. Base commit reviewed

`cb993896e` — "Merge pull request #4216 from psaab/fix/hb165-h5h13"
(tip of `origin/master` at review time). Reviewed via a detached
read-only worktree of freshly-fetched `origin/master`; the primary
checkout's in-progress `_Log.md` conflict blocks `git pull --rebase`,
so no repo mutation was performed (consistent with campaigns 165/166).

## 2. Output path

`/tmp/fable-review-167.md` (highest existing campaign number 166; fable
owns it, so this campaign takes 167).

## 3. Duplicate suppression summary

Two dedup passes anchor this campaign:

- **Prior-review inventory** — every parity finding across
  fable-review-{161,163,164,165,166}, codex-review-{001,002,121-163},
  agy-review-{001-005,121-152} was catalogued by domain. The
  most-duplicated defects (each already reported 3+ times) are
  suppressed: junos-host deny not enforced (F-193/H-1/codex-001/121),
  intrazone default-permit (codex-121), static-NAT shadowing
  (agy-134-01), host-inbound bracket-list drops, `then log
  [session-init session-close]` drop-close, IKE `proposals[]` truncate,
  match-policies silent wildcarding, reject global-bucket, VRRPv3
  checksum/owner/accept-data.
- **Authoritative known-gap baseline** — `docs/feature-gaps.md` (ACTIVE
  tracker, 2026-05-24), `docs/authoritative-backlog.md`,
  `docs/feature-coverage.md`, and umbrella issue **#2008** (204 features
  audited, ~87% verified parity, ~137 open row-level gaps). Every tracked
  Missing/Partial gap and every explicitly-rejected item (§ below) is
  cited-not-reported.

**Rejected / intentional-divergence items NOT re-proposed:** tcp-mss
`ipsec-vpn` context (#2486); route-filter `through` (#2525); interface
ARP policer (#2008 H9) and static MAC override (H10); TCP session knobs
enforcement (#2078 PLAN-KILL — config-only-with-advisory is settled);
firewall-filter no-match implicit ACCEPT (#3295, deliberate); per-policy
hit-count preserved across commit; NAT translation-hits per-flow; NAT46
fail-closed (#2358); proxy-ARP per-address narrowing (#2197 defer);
mixed positive+except in one term (#3359); `system license autoupdate
url` (the sole acknowledged parse-only, no plan); the non-Junos
extensions `surplus-sharing`/`equal-flow-enforcement`/per-worker screen
caps.

**Open parity issues cited-not-reported:** #3611 (junos-host self-zone),
#4146 (junos-host direct-path deny), #3616 (IPsec passthrough
host-inbound), #3226 (system-services all), #4114 (port-scan threshold
semantics), #3607 (RateCounter over-throttle), #2354 (QinQ transit),
#2387 (5-tuple session identity), #4080 (VRRP accept-data), #4070
(apply-groups leaf-list), #4082/#4090 (dual-fabric), #3651 (zone
counters), #3618 (reject bucket), #3995 + #4217-#4223/#4226 (CoS
schema/fail-open batch — freshly filed from campaign 166), #4047/#4056/
#4107 (security hardening).

Every novel finding below carries its own dedup note.

## 4. Domain checklist

| # | Domain | Status |
|---|--------|--------|
| 1 | Security policy / zones / host-inbound | reviewed — P-1..P-6 |
| 2 | Screen / flow / ALG | reviewed — P-3, P-4 |
| 3 | NAT | reviewed — N-* (agent) |
| 4 | IPsec / IKE / VPN | reviewed — V-* (agent) |
| 5 | Routing (static/BGP/OSPF/FRR/PBR) | reviewed — R-* (agent) |
| 6 | Interfaces / VLAN / tunnels / DHCP / RA / VRRP | reviewed — I-* (agent) |
| 7 | System / management / SNMP / logging | reviewed — S-* (agent) |
| 8 | CLI (show/clear/request) | reviewed — C-* (agent) |
| 9 | Firewall filters / CoS config | reviewed — F-* (agent) |
| 10 | Parity-documentation accuracy | reviewed — D-1 |

## 5. Module-by-module inspection log

The policy/flow domain was audited by empirically compiling 20+ probe
configs through the real `ParseSetCommand → SetPath → SchemaValidate →
CompileConfig` pipeline (probe modules in scratchpad, checkout
untouched). The remaining domains were audited against real vSRX config
idioms with source verification. Negative results (Junos idioms verified
handled correctly) are recorded at the end of each findings block —
these matter for a parity campaign because they document what NOT to
re-open.

Confidence tiers: **High** = verified in source this run (top items
re-verified line-by-line by the coordinating reviewer); **Medium** =
likely gap needing runtime confirmation; **Low** = doc/parity nuance
worth a triage row.

---

## 6. Findings — POLICY / FLOW / ZONES

### P-1. Zone-pair `from-zone junos-host` policies commit clean but are never enforced — and both the code comment and CLI reference falsely claim they are rejected at commit

- **Severity:** High (silent security-control inertness + false documentation)
- **Confidence:** High (source-verified)
- **Junos expected:** `from-zone junos-host to-zone <z>` zone-pair policies
  are valid and enforced against firewall-self-originated traffic
  (e.g. blocking the device from initiating connections to a zone).
- **xpf actual:** the stanza commits with zero warnings and is inert. The
  commit-reject for host-originated rules exists ONLY for the *global*
  `match from-zone junos-host` form
  (`pkg/config/compiler_validate_strict.go:2788` — inside the
  global-policy iteration), while `policyZoneSpecialTokens`
  (`:2653`) exempts `junos-host` from the zone-pair undefined-zone check,
  so the zone-pair form escapes every gate. The dataplane never consults
  host-originated rules (`userspace-dp/src/policy.rs:3603-3607`: "locally
  generated traffic egresses via the kernel TX path").
- **Evidence:** the `policy.rs` comment states *"`from-zone junos-host` …
  whether zone-pair or a GLOBAL … That direction is rejected at commit"* —
  but the code only rejects the global form; `docs/junos-cli-reference.md`
  repeats the false claim.
- **Reproduction:**
  `set security policies from-zone junos-host to-zone trust policy hb1 match source-address any destination-address any application any` +
  `set security policies from-zone junos-host to-zone trust policy hb1 then deny`
  → commits clean, blocks nothing.
- **Fix direction:** either reject the zone-pair form at commit too (add
  `junos-host` from-zone detection in the zone-pair strict path,
  matching the global gate), or — better for parity — wire host-originated
  policy against the kernel TX path. At minimum correct the two false
  "rejected at commit" statements. Pairs with the open #3611 (Piece A was
  scoped to the global form only).
- **Labels:** vsrx-parity, bug, policy, docs
- **Dedup note:** the suppressed junos-host cluster (F-193/H-1/codex-001/
  121) is all about the *to-zone junos-host* (host-INBOUND) deny not
  enforced. This is the opposite direction (host-ORIGINATED) AND the
  novel element is that the commit-gate + docs claim rejection that
  doesn't happen for the zone-pair spelling. #3611 Piece A closed only
  the global form.

### P-2. `security policies policy-rematch` commits clean and is silently dropped; xpf never re-evaluates existing sessions on ANY policy change (not even the Junos default)

- **Severity:** High (stale-session security exposure)
- **Confidence:** High
- **Junos expected:** `policy-rematch` re-evaluates in-progress sessions
  against the changed policy set; even WITHOUT it, Junos drops the
  sessions of a *deleted* policy immediately at commit.
- **xpf actual:** `policy-rematch [extensive]` is absent from `setSchema`
  and from `compilePolicies`' child switch (unknown names ignored), with
  no strict gate and no advisory. Deeper: xpf performs no session
  invalidation on commit at all — a session permitted by a since-deleted
  policy keeps forwarding until idle timeout. #3395 re-resolves the
  policy id only for *logging attribution*
  (`userspace-dp/src/event_stream/mod.rs:755`), never the verdict, and
  `pkg/daemon/daemon_apply.go` invalidates no sessions.
- **Reproduction:** `set security policies policy-rematch` → clean commit,
  no effect. Permit a flow, delete the permitting policy, commit → flow
  keeps forwarding.
- **Fix direction:** implement session re-evaluation on commit for
  deleted/modified policies (Junos default), gate `policy-rematch` behind
  it; until then, reject-or-advise on the knob per the repo's #3113/#2078
  doctrine.
- **Labels:** vsrx-parity, bug, policy, flow
- **Dedup note:** feature-gaps §1 tracks policy-rematch the *feature* as
  Missing but not the silent-accept or the broader no-session-
  invalidation-on-commit behavior; neither is in any prior review.

### P-3. Five `security flow` knobs commit clean with zero parsing and zero advisory — inconsistent with the repo's own accepted-with-advisory doctrine for adjacent flow knobs

- **Severity:** Medium
- **Confidence:** High (grep: no handling in `pkg/config`)
- **Junos expected:** `route-change-timeout`, `sync-icmp-session`,
  `force-ip-reassembly`, `multicast-session-lifetime`,
  `preserve-incoming-fragment-size` all alter flow behavior.
- **xpf actual:** all five commit clean and do nothing, with no warning.
  This is inconsistent with the sibling `security flow tcp-session`
  knobs (#2078, accepted WITH a commit advisory) and screens (#3318,
  rejected). `sync-icmp-session` is the most dangerous in an HA
  deployment — an operator reasonably believes ICMP sessions sync.
- **Fix direction:** add a commit advisory (the #2078 pattern) for each,
  stating the knob is accepted but unenforced.
- **Labels:** vsrx-parity, bug, flow
- **Dedup note:** tracked as Missing *features* but the silent-accept
  (vs the repo's own advisory doctrine) is unreported; force-ip-reassembly
  has partial mitigation in #3291 but the knob itself is silently accepted.

### P-4. Unimplemented ALG stanzas and unknown `policy <name>` children are silently dropped

- **Severity:** Medium (P-4a ALG) / Medium (P-4b typo-swallow)
- **Confidence:** High
- **Junos expected:** unknown config is rejected at parse/commit; ALG
  sub-stanzas (H.323 gatekeeper, MSRPC settings) configure behavior.
- **xpf actual:** (a) `set security alg h323 disable`, `alg msrpc
  disable`, etc. commit clean — benign for bare `disable`, but any
  richer child silently drops. (b) unknown *direct* children of
  `policy <name>` are silently dropped — `policy p1 foobar baz` commits
  clean; the exhaustive #3113/#3114/#3115 gates cover `match`/`then`
  but not the policy level itself, so a typo'd `scheduler-nam`/
  `descripton` vanishes. Same for `security policies traceoptions` and
  zone/top-level `application-tracking`.
- **Fix direction:** an allowlist gate at the `policy <name>` child level
  and the `security alg <proto>` child level, mirroring the match/then
  gates.
- **Labels:** vsrx-parity, bug, policy, alg
- **Dedup note:** the match/then gates are known-good; the container-level
  gaps (policy children, alg children) are unreported.

### P-5. Policy-based IPsec VPN has no explicit gap row (documentation)

- **Severity:** Low (doc completeness)
- **Confidence:** High
- `then permit tunnel ipsec-vpn` rejects at commit (#3114), so only
  route-based (st0/XFRM) VPN exists — but feature-gaps §15 never states
  "policy-based VPN: unsupported (rejected at commit)", a top-5 vSRX
  idiom operators hit immediately.
- **Fix direction:** add the explicit gap row.
- **Labels:** vsrx-parity, docs, vpn
- **Dedup note:** unreported; §15 lists many VPN gaps but omits this one.

### P-NEG. Policy/flow negative results (verified handled correctly — do not re-open)

Unified policies / `match dynamic-application`/`url-category`/
`source-identity` reject at commit (#3113/#3142/#3673); `then permit
application-services`/`firewall-authentication`/`tunnel ipsec-vpn` reject
(#3114); `then reject profile`/`tcp-reset` reject (#3115); `then log
session-init/session-close` + `then count` fully wired (#2508/#2785/
#3363); `scheduler-name` binding with undefined-scheduler reject
(#1378/#3117); `from-zone any`/`to-zone any` wildcard tiers enforced
(#3090/#3148/#3639); default-policy `permit-all|deny-all|reject-all`
typed enum + `default-policy-log` (#3065/#3534); address negation both-
families fail-closed (#3023); `to-zone junos-host` (host-INBOUND)
enforced with the #4146 stricter-than-kernel warn; unknown screen options
reject (#3318); ALG type-tagging (DNS/FTP/SIP/TFTP disable) reaches the
dataplane; duplicate inner match/then and duplicate zone sub-blocks are
systematically closed.

---

### X-1. CROSS-CUTTING ROOT CAUSE — the config schema is opt-in, so unmodeled Junos leaves commit clean and are silently inert (the worst parity failure mode)

- **Severity:** High (systemic)
- **Confidence:** High
- `walkSchemaNode`/`SchemaValidate` resolve an unmodeled keyword to a nil
  schema child and return WITHOUT error
  (`pkg/config/schema_walk.go:250-254`: "Unknown keywords are not our
  concern — the gate is opt-in"). The per-node compiler `switch` then has
  no `case`, so the leaf is dropped. Net effect: a valid Junos leaf xpf
  does not model **commits with zero warning, gets no `?`-help, and has
  zero runtime effect** — the operator believes it is active.
- This single mechanism produces the majority of the individual findings
  in sections 7-13 (every "silently dropped" item). The repo already has
  the correct counter-pattern for some subtrees — screens (#3318),
  policy match/then (#3113/#3114/#3115), firewall `from` leaves (#3307),
  route-filter `through` (#2525) all **reject** unknown/unimplemented
  leaves at commit. The gap is that this fail-loud discipline was applied
  per-subtree and never made the schema-wide default.
- **Fix direction (strategic):** flip high-risk subtrees to closed-world
  (reject unknown leaves) the way screens/policy already do — prioritizing
  the security- and reachability-affecting trees (`security ipsec`,
  `security nat then`, `protocols ospf/bgp interface`, `interfaces …
  family`, `snmp community`). A blanket flip is infeasible (it would break
  the deliberate accepted-with-advisory knobs), so the practical form is a
  per-subtree allowlist + reject, tracked as one umbrella issue with
  per-domain children.
- **Labels:** vsrx-parity, architecture, config
- **Dedup note:** the opt-in behavior is documented in-code as
  intentional; what is unreported is its *aggregate* parity cost — the
  dozens of silently-inert real-vSRX leaves catalogued below.

---

## 7. Findings — NAT

### N-1. `then static-nat prefix-name <addr>` compiles to an EMPTY translation target

- **Severity:** Medium · **Confidence:** High (probe-verified)
- **Junos:** `then static-nat prefix-name <address-book-name>` — the named
  form of static NAT — installs a 1:1 like `then static-nat prefix <ip>`.
- **xpf:** the static-nat `then` parser recognizes only `nptv6-prefix`,
  `prefix`, `inet`; any other target (including `prefix-name`) falls
  through leaving `rule.Then = ""`. The rule commits with no error and an
  **empty translation target** (probe: `STATIC rule "R1" then=""`).
- **Evidence:** `pkg/config/compiler_nat.go:2184-2228` (target switch,
  `rule.Then` reset to "" each block, no `prefix-name` case).
- **Repro:** `set security address-book global address INSIDEHOST
  10.0.0.5/32` + `set security nat static rule-set S rule R1 then
  static-nat prefix-name INSIDEHOST`.
- **Fix:** add a `prefix-name` case resolving the address-book name (or
  hard-reject if unresolved), mirroring DNAT `destination-address-name`
  (#3229). Note the asymmetry: `match destination-address <name>` IS
  rejected (`compiler_nat.go:348`) but the `then` target is not.
- **Labels:** vsrx-parity, bug, nat
- **Dedup note:** #3031/#3164/#3229 cover other NAT named/prefix forms;
  the `then static-nat` target keyword `prefix-name` is unlisted.

### N-2. NAT `port-overloading` knobs silently dropped

- **Severity:** Medium (security/compliance) · **Confidence:** High
- `security nat source interface port-overloading off` (disable src-port
  reuse across destinations) and `pool <p> port-overloading-factor <n>`
  appear nowhere in `pkg/config` (grep empty); both commit with no effect,
  so `off` hardens nothing.
- **Fix:** wire `port-overloading off` to the SNAT allocator (unique
  src-port per mapping), analogous to the existing `port-randomization
  disable`; or reject.
- **Labels:** vsrx-parity, bug, nat
- **Dedup note:** distinct from port-randomization-disable / deterministic
  / address-persistent (all tracked-done).

### N-3. NAT-to-routing-instance translation targets silently dropped

- **Severity:** Low-Medium · **Confidence:** High (probe-verified)
- `then static-nat inet routing-instance <ri>` and destination `pool <p>
  { routing-instance <ri>; }` lose the RI (StaticNATRule has only `Then`;
  NATPool has no RI field) — commits clean, RI dropped.
- **Fix:** thread the RI into the DNAT/static snapshot or reject.
- **Labels:** vsrx-parity, bug, nat
- **Dedup note:** NAT `from/to routing-instance` *scope* (#3096) works
  (verified negative); the translation-*target* RI is a different
  construct and unlisted.

### N-NEG. NAT negative results (verified handled)

NAT `from/to routing-instance` scope (#3096); DNAT pool `address port
<n>`; static-nat `mapped-port` + `/32` host mapping (#2491); df-bit
copy/set/clear render (#4015). Do not re-open.

---

## 8. Findings — IPsec / IKE / VPN

### V-1. `proposal-set standard|basic|compatible|suiteb-*` is unusable — the most common vSRX crypto shorthand cannot commit a working tunnel

- **Severity:** Medium · **Confidence:** High (probe-verified)
- **Junos:** `security ike policy P proposal-set standard` (and the ipsec
  equivalent) expand to Juniper-curated proposal sets — the standard way
  operators avoid hand-defining proposals.
- **xpf:** `proposal-set` appears nowhere in `pkg/` (grep empty); silently
  dropped, so the policy has no resolvable proposal. The IPsec side then
  hard-rejects with a misleading "no resolvable ipsec proposal" message;
  the IKE side leaves the chain unresolved (`errIKEChainUnresolved`) and
  the VPN is skipped at render. Either way the tunnel cannot be built.
- **Evidence:** `schema_security.go:744-761` (ike policy) + `:820-825`
  (ipsec policy) declare only `proposals`/`mode`/`pre-shared-key`.
- **Fix:** expand `proposal-set` to the corresponding fixed swanctl
  proposal strings, or reject naming the unsupported keyword.
- **Labels:** vsrx-parity, bug, ipsec
- **Dedup note:** F-040/F-161 cover the explicit `proposals[]` list
  truncation; the predefined `proposal-set` keyword is distinct.

### V-2. IPsec `proposal … protocol ah` is silently rendered as ESP with a fabricated cipher

- **Severity:** Medium (crypto correctness — operator gets a different
  protocol AND a cipher they never specified) · **Confidence:** High
- **Junos:** `protocol ah` selects AH (integrity only, no encryption);
  swanctl expresses this via `ah_proposals`, not `esp_proposals`.
- **xpf:** `IPsecProposal.Protocol` is captured
  (`compiler_ipsec.go:280-281`) but never consulted; `buildESPProposal`
  ignores it and **defaults empty encryption to `aes256`**
  (`pkg/ipsec/ike.go:457-460`), and `renderConfig` always emits
  `esp_proposals` (`pkg/ipsec/policy.go:193`). No `ah_proposals` code
  exists. So `protocol ah` + `hmac-sha-256-128` renders as
  `esp_proposals = aes256-sha256`.
- **Repro:** `set security ipsec proposal AHPROP protocol ah` +
  `authentication-algorithm hmac-sha-256-128`.
- **Fix:** emit `ah_proposals` (integrity+DH, no cipher) when
  `Protocol == "ah"`, or reject AH at commit.
- **Labels:** vsrx-parity, bug, ipsec, security
- **Dedup note:** F-024 (ESP dangling-proposal fallback) is unrelated.

### V-3. `security ipsec vpn … vpn-monitor` silently dropped

- **Severity:** Medium · **Confidence:** High
- `vpn-monitor { source-interface; destination-ip; optimized; }` drives
  tunnel liveness (ICMP probes) + st0 interface-state coupling — heavily
  used in site-to-site. Appears nowhere in `.go`/`.rs`; commits clean, no
  effect. DPD (#3994) is IKE-layer and does not substitute for
  vpn-monitor's interface-state coupling.
- **Fix:** implement probe-driven monitoring, or reject/warn.
- **Labels:** vsrx-parity, bug, vpn
- **Dedup note:** not in the VPN known-missing list (SSL/remote-access/
  Dynamic/Auto/AD/Group/PowerMode/lifetime-kb/dual-stack).

### V-4. `security ipsec vpn … manual` (manual-key SA) silently produces a dead tunnel; V-5. `establish-tunnels` value unvalidated

- **Severity:** Low each · **Confidence:** High (probe-verified)
- V-4: `manual { protocol esp; spi …; encryption/authentication … }` has
  no case in `compileIPsec`; the whole block drops and the VPN compiles
  to an empty shell that commits OK — a silent dead tunnel. Fix: reject
  `manual` with a clear "not supported".
- V-5: `establish-tunnels` has `args:1` but no validator
  (`schema_security.go:857`); only `immediately` is acted on, so a typo
  (`on-tarffic`) or newer `responder-only` stores verbatim and silently
  degrades to on-traffic. Fix: `ValidateEnum([immediately, on-traffic,
  responder-only])`.
- **Labels:** vsrx-parity, bug, vpn
- **Dedup note:** neither listed; establish-tunnels is "done" in §15 but
  the missing enum validation is the novel slice. (Adjunct, cite-only:
  IKE gateway `general-ikeid`/`aaa`/`xauth` commit silently inert — these
  belong to the tracked AutoVPN/remote-access gaps; flagging only that
  they fail silently rather than rejecting.)

### V-NEG. IPsec/VPN negative results (verified handled)

`perfect-forward-secrecy keys group<N>`; `proposals [ p1 p2 ]` bracket
lists on IKE/IPsec policies (#3904); `dh-group group14` prefixed spelling
(#2639). Do not re-open.

---

## 9. Findings — ROUTING

### R-1. OSPF/OSPFv3 interface timers and DR priority silently dropped — adjacency will not form with a fast-timer neighbor

- **Severity:** High · **Confidence:** High (source-verified)
- **Junos:** `interface <if> { hello-interval 1; dead-interval 3;
  retransmit-interval 5; priority 200; }` tune adjacency timers and DR
  election.
- **xpf:** the OSPF interface schema declares only
  `passive/no-passive/interface-type/cost/authentication/bfd`
  (`schema_routing.go:259-274`; OSPFv3 thinner at `:292-299`); the
  compiler switch has no case for the timers or priority
  (`compiler_protocols.go:84-117`); `OSPFInterface` has no such fields
  (`types_routing.go:373-386`); the renderer emits only `ip ospf cost` +
  auth. All four leaves drop silently → FRR keeps default 10/40/1/1.
- **Repro:** `set protocols ospf area 0 interface ge-0-0-1 hello-interval
  1` + `dead-interval 3` → commits; adjacency to a fast-timer neighbor
  never comes up.
- **Fix:** add the leaves to schema + struct + compiler + render as `ip
  ospf hello-interval/dead-interval/retransmit-interval/priority` (and
  `ipv6 ospf6 …`).
- **Labels:** vsrx-parity, bug, routing
- **Dedup note:** distinct from tracked OSPF area-types (NSSA/stub/
  virtual-link) and BFD (done); interface timer/priority knobs unlisted.

### R-2. BGP `local-address` (update-source) and `passive`/`hold-time`/per-group `local-as` silently dropped — iBGP loopback peering will not establish

- **Severity:** High (local-address); Medium (others) · **Confidence:** High
- **Junos:** `group <g> { local-address <lo0-ip>; hold-time 30; passive;
  local-as <asn>; neighbor <x> {…} }`.
- **xpf:** neither the BGP schema (`schema_routing.go:302-382`) nor the
  group/neighbor compiler switches model `local-address`, `passive`,
  `hold-time`, or per-group `local-as`; the structs lack the fields
  (`types_routing.go:388-429`); the renderer never emits `neighbor X
  update-source/passive/timers`. So iBGP designs that peer loopback-to-
  loopback silently omit `update-source` → the SYN sources from the
  egress IP the peer has no `neighbor` for → the session never comes up.
- **Repro:** `set protocols bgp group ibgp local-address 10.255.0.1` +
  `neighbor 10.255.0.2 peer-as 65000` → commits; no `update-source` in
  FRR → session flaps.
- **Fix:** map `local-address`→`update-source`, `passive`→`passive`,
  `hold-time`→`timers`, per-group `local-as`→`neighbor local-as`.
- **Labels:** vsrx-parity, bug, routing
- **Dedup note:** dedup covers `multihop` (handled), import (#2490),
  as-path-prepend, community, peer-as; these four are unlisted.

### R-NEG. Routing negative results (verified handled)

BGP `graceful-restart`/`log-updown`/`remove-private`/`route-reflector-
client`/`allowas-in`/`default-originate`/`maximum-prefix`/TCP-MD5
`authentication-key`/`multihop` all render correctly
(`policy_render.go:641-702,842-907`); OSPF `reference-bandwidth`; VRRP
`preempt hold-time` + `track-interface priority-cost`; RA `link-mtu`/
`dns-server-address`/`preference`/PREF64 lifetime (#2497/#3895). Note the
feature-gaps "Graceful Restart Missing" row refers to the *global*
`routing-options graceful-restart`, a different path — the BGP-level one
IS rendered.

---

## 10. Findings — INTERFACES / RA / VRRP / DHCP

### I-1. VRRP `authentication-type`/`authentication-key` parsed but never enforced — a rogue host can hijack mastership

- **Severity:** Medium (security) · **Confidence:** High
- The values are parsed (`compiler_interfaces.go:721-730,811-814`), stored
  (`types_interfaces.go:111-112`), and copied into the VRRP instance
  (`vrrp.go:47-48`) — but the packet build/receive path never references
  them (the dataplane is RFC 5798 VRRPv3, which removed authentication).
  Inert; operator believes adverts are authenticated.
- **Fix:** enforce VRRPv2 auth when configured (mode-select v2), or —
  matching the `accept-data`/#4080 doctrine — reject/advise at commit that
  VRRPv3 cannot authenticate.
- **Labels:** vsrx-parity, bug, vrrp, security
- **Dedup note:** #4080 (accept-data), owner/preempt, checksum, GARP are
  the tracked VRRP items; auth-type/key are unlisted.

### I-2. RA `reachable-time` and `retransmit-timer` silently dropped

- **Severity:** Medium · **Confidence:** High
- Neither leaf exists in the RA interface schema
  (`schema_routing.go:420-533`) or `RAInterfaceConfig`; the sender never
  sets `ReachableTime`/`RetransmitTimer` (`pkg/ra/sender.go:698-702`), so
  both go on the wire as 0 ("unspecified"). Hosts cannot be tuned via RA.
- **Fix:** add both (typed ms), compile, set on the `ndp.RouterAdvertisement`.
- **Labels:** vsrx-parity, bug, ra
- **Dedup note:** F-075 (nat64prefix lifetime), #4119 (default-lifetime 0),
  link-mtu/dns-server (done) are the tracked RA items; these two unlisted.

### I-3. Interface ARP/addressing knobs silently dropped (unnumbered-address, gratuitous-arp-reply, no-gratuitous-arp-request, targeted-broadcast, native-vlan-id)

- **Severity:** Medium (`unnumbered-address` — an unnumbered P2P/tunnel
  interface gets NO address, link unusable) to Low (others)
- **Confidence:** High (grep: none appear in `pkg/config`/`pkg/networkd`)
- **Fix:** model `unnumbered-address` (borrow the referenced unit's address
  in networkd); map gratuitous-arp knobs to `arp_accept`/`arp_ignore`/
  `drop_gratuitous_arp` sysctls; fold `native-vlan-id` into the tracked
  QinQ work (#2354); at minimum reject the unmodeled ones.
- **Labels:** vsrx-parity, bug, interfaces
- **Dedup note:** tracked interface items are interface-range/LLDP/
  deriveKernelName/QinQ/GRE/df-bit — none of these five.

### I-4. DHCP relay overrides limited to `always-broadcast`; `forward-only`, `relay-agent-option` (option-82), `maximum-hop-count` silently dropped

- **Severity:** Medium · **Confidence:** Medium-High
- The dhcp-relay schema models only `server-group`/`group`/`overrides {
  always-broadcast }` (`schema_routing.go:608-620`); `forward-only`
  (forward without relay state) and option-82 injection appear nowhere in
  `pkg/config`/`pkg/dhcp`. Standard relay knobs, silently dropped.
- **Fix:** add the common relay overrides, or reject the unmodeled ones.
- **Labels:** vsrx-parity, bug, dhcp
- **Dedup note:** the tracked DHCP items are all DHCPv4 *client*; relay
  overrides are unlisted.

### I-NEG. Interface/VRRP negative results (verified handled)

VRRP `advertise-interval` unit handling (Junos seconds → ms →
centiseconds on the wire, `vrrp.go:55-60,1695-1710`) — no unit bug.

---

## 11. Findings — SYSTEM / SNMP / LOGGING

### S-1. `system syslog` host/file sub-statements are MISPARSED into bogus facility/severity pairs

- **Severity:** Medium · **Confidence:** High (source-verified)
- The syslog compiler treats every non-`allow-duplicates` child of a
  `host`/`file`/`user` node as a `<facility> <severity>` pair
  (`compiler_system.go:271-287`, `len(prop.Keys) >= 2`). So
  `source-address 10.0.1.1`, `match "regex"`, `structured-data`,
  `explicit-priority`, `port 5514`, `archive size 1m files 5` are not
  merely inert — `source-address 10.0.1.1` is appended as
  `SyslogFacility{Facility:"source-address", Severity:"10.0.1.1"}`,
  polluting the facility filter. `source-address` (mgmt-syslog source IP)
  and `structured-data` are routinely present in real configs.
- **Repro:** `set system syslog host 10.0.0.5 source-address 10.0.1.1` →
  compiled `SyslogHostConfig.Facilities` carries a garbage
  `source-address` facility.
- **Fix:** switch on known host/file sub-keywords (source-address, match,
  structured-data, explicit-priority, archive, port) before the fallback
  facility/severity append.
- **Labels:** vsrx-parity, bug, system, logging
- **Dedup note:** the `security log` stream path is well-typed (verified);
  this is the `system syslog` (management logging) tree, unreported.

### S-2. Custom `system login class <name>` unsupported — a real vSRX RBAC config is REJECTED at commit

- **Severity:** Medium · **Confidence:** High
- Login classes are a hard-coded set (`ValidLoginClasses()`,
  `types_system.go:580`); the schema has only `login user`, no `login
  class`. Two-sided: (a) a `class <name> {…}` definition is silently
  accepted-inert; (b) the user's `class` leaf is enum-validated against
  the built-ins only (`schema_system.go:143-146`), so `set system login
  user bob class noc-admin` is **hard-rejected at commit**. A real vSRX
  config with custom RBAC classes cannot be committed as written.
- **Fix:** parse `login class` (permissions/allow-commands/deny-commands/
  idle-timeout); feed defined names into `ValidLoginClasses()` +
  `pkg/cli/permissions.go`.
- **Labels:** vsrx-parity, bug, system
- **Dedup note:** not the F21 zeroize-RBAC item; this is custom-class
  definition + granular permissions.

### S-3. SNMP `community <c> clients` source-IP restriction silently ignored (allow-all)

- **Severity:** Medium (security) · **Confidence:** High
- `compileSNMP` parses only `authorization` under `community`
  (`compiler_system.go:874-897`); there is no `clients` field, and the
  agent answers `remoteAddr` unconditionally (`pkg/snmp/agent.go:548-577`).
  An operator who scoped a community to a mgmt subnet gets an agent that
  answers EVERY source.
- **Fix:** parse `clients` prefixes (with `restrict`), enforce against
  `remoteAddr` before serving.
- **Labels:** vsrx-parity, bug, snmp, security
- **Dedup note:** distinct from the tracked SNMPv3-USM-partial / trap-class
  gaps.

### S-4. SSH hardening knobs (`ciphers`/`macs`/`connection-limit`/`client-alive-*`/`protocol-version`) silently inert

- **Severity:** Medium · **Confidence:** High
- The SSH compiler reads only `root-login` + `key-exchange`
  (`compiler_system.go:321-333`); the standard sshd-hardening knobs commit
  clean and never reach the drop-in, so the box keeps base-image cipher/
  MAC defaults.
- **Fix:** render `Ciphers`/`MACs`/`MaxStartups`/`ClientAlive*` into the
  existing `sshd_config.d/xpf.conf` drop-in.
- **Labels:** vsrx-parity, bug, system
- **Dedup note:** `key-exchange`/H5 is done; ciphers/macs are separate.

### S-5. Grouped system/SNMP silently-inert knobs

- **Severity:** Low-Medium · **Confidence:** High
- (a) SNMP `trap-options source-address` ignored (traps from default
  egress IP); (b) SNMP `view` / community `view` (MIB view scoping),
  `health-monitor`, `rmon` — all no-ops (a view-scoped community is
  silently promoted to full ifTable exposure); (c) `system login
  retry-options`/`login message`/`announcement` (banner) inert;
  (d) `system internet-options` beyond one leaf, and `system ntp
  boot-server`/`authentication-key`/`source-address` inert.
- **Fix:** parse + wire, or reject the security-relevant ones (view,
  trap-options source-address).
- **Labels:** vsrx-parity, bug, system, snmp
- **Dedup note:** all unreported; separate from the tracked trap-group
  version/categories (F-069) and SNMPv3-USM-partial.

### S-NEG. System/logging negative results

The `security log` stream tree (mode/format/source-interface/transport/
severity/facility/category) is well-typed (`schema_security.go:521-593`);
TLS `tls-profile` is deliberately reject-at-commit (#3350). **Doc
correction:** `request system configuration rescue save/delete` IS
implemented (`pkg/cli/cli_request.go`, `pkg/configstore/store_persist.go`)
— `feature-gaps.md:676` marking Rescue Configuration "Missing" is STALE
(fold into D-1).

---

## 12. Findings — CLI

### C-1. Grouped `show`/`request` drill-down gaps

- **Severity:** Low each · **Confidence:** High (Medium for C-1c)
- (a) `show security ike/ipsec security-associations` has no `detail` or
  index/peer filter (`tree.go:453-459`) — Junos routinely uses `… detail`,
  `… index <n>`, `… <peer-ip>`. (b) `show security nat static` has no
  `rule [detail]` drill-down (`tree.go:430`) while source/destination do.
  (c) `request security policies check` (validate the compiled policy DB
  for shadowed/redundant rules) missing — `request security` exposes only
  `ipsec sa clear` + `wireguard generate-private-key`.
- **Fix:** add the sub-commands + completers; `policies check` maps to a
  shadow/redundancy pass over the compiled policy set.
- **Labels:** vsrx-parity, cli
- **Dedup note:** distinct from the tracked match-policies wildcarding
  (codex-128) and CoS `show` gaps (G-8); these are IKE/NAT/policy-check
  surfaces.

### C-NEG. CLI negative results

`clear security flow session` filters are complete (`tree.go:712-751`).

---

## 13. Findings — FIREWALL FILTERS / CoS CONFIG

### F-1. `firewall family any` (and mpls/ccc/vpls/bridge) folds into the IPv4 pool, LOSING the IPv6 arm — a `family any` discard filter fails open for v6

- **Severity:** Medium (security fail-open) · **Confidence:** High (source-verified)
- `compileFirewall` sets `dest := fw.FiltersInet` and switches to
  `FiltersInet6` only for the literal `"inet6"`
  (`compiler_firewall.go:183-185`). A uniquely-named `family any filter
  drop6` therefore compiles as IPv4-only and is enforced on IPv4 traffic
  only — Junos `family any` is protocol-independent and matches both. So a
  `family any` discard filter silently lets IPv6 through. #3884 only
  rejects same-NAME cross-family collisions, not a uniquely-named `family
  any` losing its v6 arm.
- **Repro:** `set firewall family any filter drop6 term t then discard`
  bound as an input filter → v4 dropped, v6 passes.
- **Fix:** expand `family any` to both `FiltersInet` and `FiltersInet6`,
  or reject `family any`/mpls/… at commit (the #3307 pattern).
- **Labels:** vsrx-parity, bug, filter, security
- **Dedup note:** F-030 (same-name cross-family overwrite) is the related
  prior finding; the `family any` v6-arm loss is a distinct mechanism.

### F-2. CoS `traffic-control-profiles` + `output-traffic-control-profile` entirely absent — hierarchical shaping binding silently applies zero shaping

- **Severity:** Medium · **Confidence:** High (grep: 0 non-test hits)
- The standard Junos hierarchical binding —
  `traffic-control-profiles <n> { scheduler-map; shaping-rate;
  guaranteed-rate; }` referenced by `interfaces <if> unit N {
  output-traffic-control-profile <n>; }` — is unmodeled; xpf supports only
  the flat `class-of-service interfaces <if> { scheduler-map;
  shaping-rate; }` (`schema_cos.go:102-131`). An operator whose config
  binds shaping via a TCP gets a clean commit and ZERO shaping.
- **Fix:** parse `traffic-control-profiles`, resolve
  `output-traffic-control-profile` to the existing shaping/scheduler-map
  plumbing.
- **Labels:** vsrx-parity, bug, cos
- **Dedup note:** not in the tracked CoS-missing list (WRED, transmit-rate
  percent, ieee-802.1 rewrite, show interfaces queue, strict-high, default
  classifiers) nor the #4217-#4226/#3995 batch.

### F-3. Grouped filter/CoS lower-severity gaps

- **Severity:** Low each · **Confidence:** High
- (a) `firewall filter <n> interface-specific;` silently inert (one shared
  counter instead of per-interface instances — diverges on `show
  firewall` semantics). (b) CoS `classifiers inet-precedence` and
  `rewrite-rules inet-precedence`/`exp` absent (only dscp + ieee-802.1
  exist). (c) cite-only: `from packet-length`/`ttl`/`ip-options`/
  `precedence` are reject-at-commit (#3307) — the tracked fail-closed
  doctrine, not a silent no-op.
- **Labels:** vsrx-parity, bug, filter, cos
- **Dedup note:** interface-specific and inet-precedence/exp are unlisted;
  ieee-802.1 *rewrite* is already tracked-missing.

---

## 14. Finding — PARITY DOCUMENTATION ACCURACY

### D-1. `docs/vsrx-gaps.md` is entirely stale, and `docs/feature-gaps.md` has internal contradictions — the parity docs themselves misrepresent xpf's parity posture

- **Severity:** Medium (a parity campaign that trusts these docs will
  chase phantom gaps and miss real ones)
- **Confidence:** High
- **`docs/vsrx-gaps.md` (2026-02-13 snapshot) — every one of these is now
  WRONG and must not be re-reported as a gap:**
  - **§5 High Availability — the entire section (all 8 rows) shipped:**
    Chassis Cluster, Session Sync, Redundancy Groups, Redundant Ethernet
    (bondless-RETH runtime), Fabric Links (dual fab0/fab1 + cross-chassis
    forwarding), ISSU, Graceful Switchover (priority-0 burst, ~1ms
    takeover), IP Monitoring for Failover (#1827).
  - **§3 Routing:** BFD (OSPF/OSPFv3/IS-IS/BGP), OSPFv3, BGP import all
    shipped; routing-policy row's claims stale.
  - **§2 NAT:** Twice NAT, NAT Proxy ARP, deterministic/address-shifting
    NAT all Done.
  - **§4 VPN:** IPsec DPD (#3994), traffic selectors Done.
  - **§6 Management:** apply-groups, System Login Classes (RBAC), SNMP
    v2c traps (linkUp/Down), SNMPv3 USM (partial), event policies — all
    shipped or partial (row says "No").
  - **§7 QoS:** policing, shaping, scheduling, BA classification, rewrite
    rules — all shipped or partial (rows say "No").
  - **§9 Logging:** structured RT_FLOW syslog, binary streaming, top-K
    aggregation (#3099), event-mode, `monitor security flow`/packet
    capture — all Done (rows say "No").
  - **§8 IPv6:** DHCPv6 Prefix Delegation (IA_PD) is wired
    (`pkg/dhcp/dhcp.go`/`commit.go`/`renew.go`).
  - **§11 + the 16-item "Parse-Only" summary:** primary/preferred address,
    point-to-point, master-password, NTP threshold action, LAG/ae,
    `log.mode`, reth/fabric — all now Done. **Only survivor:** `system
    license autoupdate url`.
- **`docs/feature-gaps.md` internal staleness (report precisely):**
  - §8 NAT callout still says multi-host-prefix DNAT `match
    destination-address` is hard-rejected (#3029), but #3164 implemented
    LPM prefix DNAT and removed that reject —
    `docs/feature-coverage.md` §"Destination NAT" is the current truth.
  - Screen check count disagrees: feature-gaps §9 says "12 checks",
    feature-coverage/CLAUDE.md say "11".
  - Summary-table total (138) vs backlog row-parse (137) differ by one
    (known maintenance drift).
  - §"Management" marks **Rescue Configuration "Missing"**
    (feature-gaps.md:676), but `request system configuration rescue
    save/delete` IS implemented (`pkg/cli/cli_request.go`,
    `pkg/configstore/store_persist.go`) — stale (found by the system-domain
    sweep).
- **Fix direction:** either delete `docs/vsrx-gaps.md` (it self-declares
  "superseded") or stamp every stale row; reconcile the feature-gaps.md
  NAT callout, screen count, and total against feature-coverage.md.
- **Labels:** vsrx-parity, docs
- **Dedup note:** the staleness is acknowledged in the abstract
  (vsrx-gaps.md header + authoritative-backlog.md), but the precise
  row-by-row correction — and the feature-gaps.md *internal*
  contradictions — are unreported.

---

## 15. Suggested issue split

Ordered by triage priority. The recurring shape is "unmodeled Junos leaf
commits clean and is silently inert" (X-1) — so the highest-leverage
single action is #1.

1. **[architecture][vsrx-parity] Umbrella: flip security/reachability
   config subtrees to closed-world (reject unknown leaves)** — X-1, with
   per-domain children below. This is the systemic fix; the individual
   findings are its instances.
2. **[bug][routing][vsrx-parity] OSPF interface timers/priority + BGP
   local-address/passive/hold-time/local-as silently dropped** — R-1, R-2
   (the two findings with real "session/adjacency won't form" breakage).
3. **[bug][ipsec][security] `protocol ah` renders as ESP with a fabricated
   cipher; `proposal-set` unusable; `vpn-monitor`/`manual` silently
   dropped** — V-1, V-2, V-3, V-4, V-5.
4. **[bug][policy][security] zone-pair `from-zone junos-host` inert +
   false "rejected at commit" docs; `policy-rematch` + no
   session-invalidation-on-commit** — P-1, P-2.
5. **[bug][security] silent security-control inertness: SNMP community
   `clients` allow-all, VRRP auth parsed-not-enforced, `family any`
   filter fails open for IPv6** — S-3, I-1, F-1.
6. **[bug][system] `system syslog` host/file substatements misparsed into
   bogus facilities; custom `login class` rejected; SSH hardening knobs
   inert** — S-1, S-2, S-4, S-5.
7. **[bug][nat] `then static-nat prefix-name` empty target;
   port-overloading + NAT-to-routing-instance dropped** — N-1, N-2, N-3.
8. **[bug][interfaces] RA reachable-time/retransmit-timer, unnumbered-
   address + ARP knobs, DHCP relay forward-only/option-82 dropped** — I-2,
   I-3, I-4.
9. **[bug][cos] `traffic-control-profiles`/`output-traffic-control-profile`
   absent (hierarchical shaping silently no-ops); inet-precedence
   classifiers/rewrites; interface-specific counters** — F-2, F-3.
10. **[bug][policy][flow] `security flow` knobs + ALG substanzas + unknown
    `policy` children silently accepted (advisory doctrine)** — P-3, P-4.
11. **[cli][vsrx-parity] IKE/IPsec SA `detail`/filter, NAT static rule
    detail, `request security policies check`** — C-1.
12. **[docs][vsrx-parity] Correct the parity documentation: delete/stamp
    stale `vsrx-gaps.md`; reconcile feature-gaps.md NAT callout, screen
    count, total, rescue-config row; add policy-based-VPN gap row** — D-1,
    P-5.

## 16. Campaign summary

- **~30 novel findings** across every parity domain (2 High: R-1, R-2;
  1 systemic High: X-1; the rest Medium/Low), plus one architecture-level
  root cause and a precise documentation-accuracy correction. Every
  finding carries a dedup note against ~137 tracked gaps in
  feature-gaps.md, umbrella issue #2008, the rejected/intentional-
  divergence list, and the full prior-review parity inventory.
- **The headline is systemic, not a single bug:** xpf's config schema is
  opt-in (`schema_walk.go:250-254`), so any Junos leaf xpf does not model
  commits clean and is silently inert — the worst parity failure mode
  because the operator believes the setting is active. This campaign
  catalogues ~25 concrete instances an operator hits copying a real vSRX
  config: OSPF/BGP session-breaking timers, `protocol ah` mis-rendered as
  ESP, SNMP source-IP restrictions that don't restrict, VRRP auth that
  doesn't authenticate, a `family any` filter that fails open for IPv6,
  syslog substatements corrupted into bogus facilities, and hierarchical
  CoS shaping that applies nothing. The repo already has the correct
  counter-pattern (screens #3318, policy match/then #3113-#3115, firewall
  `from` #3307 all reject unknown leaves) — it was applied per-subtree and
  never made the schema-wide default.
- **The parity docs themselves are the second story:** `docs/vsrx-gaps.md`
  is entirely stale (its HA/routing/NAT/QoS/logging sections describe
  shipped features as gaps), and `feature-gaps.md` carries internal
  contradictions (NAT DNAT callout vs #3164, 11-vs-12 screen count,
  137-vs-138 total, a stale "Rescue Configuration Missing" row). A parity
  campaign that trusts them chases phantoms and misses real gaps — D-1
  gives the row-by-row correction.
- **Strong negative results throughout** (recorded per the honesty rule):
  the policy match/then surface, `security log` stream tree, BGP
  neighbor render path, RA link-mtu/RDNSS, NAT scope/mapped-port, and PFS/
  proposal-list handling are all verified vSRX-correct — the gaps cluster
  at the *container levels the per-subtree gates don't cover* and in the
  unmodeled-leaf silent-drop class, not in the wired features.

