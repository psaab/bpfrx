# fable-review-170 — vSRX drop-in readiness: can xpf run `/home/ps/vsrx.conf` as-is?

**Focus (operator-directed):** take an existing production vSRX config and
run it on xpf unchanged. Test subject: `/home/ps/vsrx.conf` (5,423 lines,
a real chassis-cluster firewall — reth0–reth4, GRE/IP-IP tunnels, 5 VRFs,
NPTv6, NetFlow v9, ~200 address objects, dozens of policies). Reviewed at
`origin/master` `04fa690cd`; compiled on the loss cluster's own `xpfd
check-config`.

## 0. Verdict

**No — it is not a drop-in today.** The config **hard-fails commit** on
**10 distinct construct classes** before it will compile at all, and once
those are removed it still mis-programs reth on the secondary node
(finding 169) and silently drops several accepted-but-unwired features.

Getting it to *pass commit-check* required removing/rewriting:

| # | Blocker | Class | Scope in this config |
|---|---------|-------|----------------------|
| 1 | `security flow tcp-mss ipsec-vpn` | intentional reject (#2486) | 1 stanza |
| 2 | **address-book object names containing `/`** | **novel — high impact** | **194 objects** |
| 3 | `system services web-management` off-loopback w/o api-auth | security reject (#4047) | J-Web on fxp0 |
| 4 | `from-zone junos-host` security policy | reject (#3611/#4230) | 1 policy |
| 5 | inline (mid-line) `inactive:` not pruned | parser bug | 1 line |
| 6 | application term `source-port 0-N` (range from 0) | novel reject | multi-term apps |
| 7 | per-term `alg ssh` (ALG ∉ dns/ftp/sip/tftp) | reject (unenforced anyway) | 3 terms |
| 8 | filter term: positive `source-address 0/0` + `except` prefix-list | over-strict (#3359) | 2 filters |
| 9 | FBF → undefined routing-instance | stricter than Junos | 1 term |
| 10 | NPTv6 rule flagged overlapping **itself** | bug | NPTv6-INBOUND |

Only after all 10 are stripped does `check-config` return PASS.

## 1. Method

Iterative compile-and-strip against the real config on
`loss:xpf-userspace-fw0` (`xpfd check-config -node-id 0`): run → capture
the first hard error → remove/rewrite the offending construct → repeat
until PASS. Each blocker below is a real rejection reproduced on the
deployed binary. Three apparent errors during the run were **transform
artifacts** (my bulk address-rename briefly corrupted a `$5$` crypt hash
and an IPv6 literal and a CIDR value) and are explicitly **not** counted —
real vSRX `$5$` hashes and IPv6 addresses are accepted.

## 2. Hard-reject catalog (the drop-in blockers)

### B-1 · `security flow tcp-mss ipsec-vpn` — intentional reject (#2486)
```
security flow tcp-mss ipsec-vpn is not supported … use 'all-tcp'
```
Known/tracked intentional divergence (kernel XFRM handles IPsec). Still a
drop-in blocker: the operator must rewrite to `all-tcp`. **Config fix.**

### B-2 · Address-book object names containing `/` — NOVEL, the biggest blocker
```
address-book entry name "net4_sfmix_72.52.96.201/32" must not contain '/'
```
vSRX permits arbitrary address-object names, and the near-universal
operator convention is to name an object after its prefix
(`net4_sfmix_72.52.96.201/32`, `net_10.0.0.0/8`, `net_2001:559:8585:200::/64`).
**This config has 194 such objects** (v4 and v6). xpf reserves `/` and
hard-rejects every one — and every policy/NAT/filter **reference** must be
renamed in lockstep. This single class makes a mechanical drop-in
impossible: it is a config-wide find-and-replace, not a localized edit.
Impact is not specific to this config — it will hit essentially every
real vSRX config that names objects by prefix. **Highest-value fix
target:** either allow `/` in object names (map it to a safe internal
encoding) or ship a migration transform. **xpf should change.**

### B-3 · `web-management` bound off-loopback without api-auth (#4047)
```
system services web-management binds the REST/config API off-loopback
(http interface "fxp0.0" …) without api-auth … the REST API is UNAUTHENTICATED
```
Real vSRX configs run J-Web on `fxp0`. xpf's REST API is unauthenticated,
so it rejects any off-loopback bind. Security-motivated and tracked
(#4047), but a drop-in blocker for any config with `web-management`.
**Config fix (add api-auth or drop the binding), or xpf could accept +
warn.**

### B-4 · `from-zone junos-host` security policy — reject (#3611/#4230)
```
from-zone junos-host (host-originated / locally-generated traffic) is not
supported … the rule would commit but silently never match
```
Host-originated policy control. Note: in fable-review-167 the zone-pair
form was silently *accepted*; #4230 has since turned it into a hard
reject — which is more honest but now *blocks* the config. **Config fix.**

### B-5 · Inline `inactive:` not pruned — parser bug
```
destination-nat pool "plex6-on-traefik": address "inactive:" is not a single host address
```
Source line: `address 2001:559:8585:80::7aef/128 inactive: port 32400;`.
xpf prunes **leading** `inactive:` (31 such lines here work fine) but not
an **inline** one — it reads the literal token `inactive:` as the pool
address. Rare (1 line here) but a genuine parser fidelity gap: Junos
deactivates the governed statement regardless of position. **xpf should
fix.**

### B-6 · Application term `source-port 0-N` — novel reject
```
application "FaceTime-3478-3497-0_41640": source-port: invalid port 0: must be 1-65535
```
Source: `term 0_41640 … source-port 0-41640 …`. Multi-term application
definitions routinely use `0-N` as the low half of a port split; Junos
accepts 0 as the range floor. xpf requires 1-65535 and rejects the range.
**xpf should accept `0-N` (clamp/normalize).**

### B-7 · Per-term `alg ssh` — reject (and not even enforced)
```
application "ssh-long-22": unknown alg "ssh"; supported … dns/ftp/sip/tftp
… a per-application alg is validated at commit but is not yet enforced
```
`application ssh-long { term 22 alg ssh …; }`. Operators tag apps with
ALGs outside xpf's four (ssh, http, etc.). xpf rejects at commit for an
ALG it then admits it doesn't even enforce — a pure drop-in blocker with
no functional cost to accepting it. **xpf should accept-and-ignore (or
warn) unknown ALG names rather than reject.**

### B-8 · Filter term: `source-address 0/0` + `except` prefix-list — over-strict (#3359)
```
a positive source address match … and an `except` source-prefix-list are
mutually exclusive in the same term (Junos rejects this; split into separate terms)
```
The term is the canonical **"match any EXCEPT the management hosts, then
reject"** idiom (`source-address { 0.0.0.0/0; } source-prefix-list {
management-hosts except; }`). **Junos accepts this** — the error's claim
that "Junos rejects this" is wrong for the `0/0 + except` shape. Present
on both the inet and inet6 management filters. xpf's #3359 mutual-exclusion
is stricter than Junos here and blocks a common lockdown pattern. **xpf
should allow `any + except-list` (or at least stop asserting Junos rejects
it).**

### B-9 · FBF → undefined routing-instance — stricter than Junos
```
references undefined routing-instance "MonkeyBrains" … filter-based-forwarding
would … silently blackhole
```
The **original config itself carries** `## 'MonkeyBrains' is not defined` —
i.e. Junos flagged it as a *warning* and **committed anyway**; this config
ran in production. xpf hard-rejects. Defensible safety posture, but it
means a config that vSRX ran will not load. **Divergence to decide:
warn-and-commit (Junos parity) vs hard-reject.**

### B-10 · NPTv6 rule flagged as overlapping itself — bug
```
static nat rule-set "NPTv6-INBOUND" rule "map-v6-neutral" … overlaps
rule-set "NPTv6-INBOUND" rule "map-v6-neutral"
```
The rule-set has a **single** rule (`destination 2602:fd41:70::/48 →
nptv6-prefix 2001:559:8585::/48`). NPTv6 is inherently bidirectional; the
overlap detector compares the rule's mapping against its own reverse and
reports a self-overlap. This blocks *any* NPTv6 inbound mapping. **xpf
should exclude a rule from its own overlap check / model NPTv6's
bidirectionality.**

## 3. It's a cluster config — findings 168 & 169 compound after commit

`vsrx.conf` is a chassis cluster with the **flat** `redundant-parent`
form (8 flat `ge-{0,7}/0/N` member stanzas). So even once the 10 blockers
above are cleared and it commits:

- **fable-review-169:** the flat form has no `chassis cluster node <id>`
  leaf, so `Cluster.NodeID` defaults to 0 on both nodes and
  `RethToPhysical` binds every reth to the **node-0** member on **node 1**
  — the secondary's reth interfaces are dead. Loading this config as-is
  breaks HA. (Fix: stamp `Cluster.NodeID` from the compile nodeID.)
- **fable-review-168:** `show interfaces reth0[.unit]` reports "Not
  present" (only `terse` resolves reth), so the operator can't even
  inspect the reths the config defines.

A cluster config is therefore doubly non-droppable: it won't commit, and
if patched to commit it mis-programs the secondary.

## 4. Silently accepted-but-unwired (the second half of "not a drop-in")

After PASS, the compile is clean but xpf's schema is opt-in (campaign-167
X-1: unmodeled leaves commit with no effect). Features present in
`vsrx.conf` that commit but do **not** behave as on vSRX include, at
minimum: `services flow-monitoring version9` NetFlow **template** config
(refresh-rate / export-extensions — xpf exports its own fixed template),
the GRE/IP-IP `tunnel { routing-instance { destination … } }` VRF binding,
`event-options`, and `rpm` probe wiring — each needs per-feature
verification before the config's *observable behavior* matches vSRX.
(Several sibling features **are** wired — interface `sampling`,
`gre-performance-acceleration`, base `flow-monitoring` — so this is
per-leaf, not wholesale.) A full silent-drop audit of the committed
config is the natural follow-up; the hard-reject catalog above is the
blocker that must be cleared first.

## 5. What it would take to make vsrx.conf a drop-in

Ranked by leverage:

1. **Allow `/` in address-object names (B-2).** Single highest-impact
   change — 194 objects here, and it recurs in every prefix-named config.
   Map `/` to an internal-safe encoding at parse, or provide a migration
   pass that renames objects + references together.
2. **Relax the over-strict / buggy rejects (B-6, B-8, B-10, B-5).** These
   are cases where xpf is stricter than Junos or simply wrong (NPTv6
   self-overlap, `0/0 + except`, `source-port 0-N`, inline `inactive:`) —
   accepting them costs nothing and is pure parity.
3. **Decide the accept-vs-reject posture for the "safety" rejects
   (B-1, B-3, B-4, B-7, B-9).** Each is intentional, but each blocks a
   config vSRX ran. A `warn-and-accept` mode (or a documented migration
   checklist) would let real configs load while preserving the guardrail.
4. **Fix the cluster reth model (169) and reth show (168)** so the
   committed cluster config actually works on both nodes.
5. **Then** audit the silent-drop set (§4) so committed behavior matches.

Until at least items 1–2 land, "take an existing vSRX config and run with
it" is not achievable for a config of this shape — it stops at commit on
the very first address object.

## 6. Dedup / relationship

- B-2, B-5, B-6, B-8(over-strictness), B-9, B-10 are **novel** (not in the
  campaign-167/169 catalogs). B-1/B-3/B-4/B-7 are tracked intentional
  rejects, surfaced here as concrete drop-in blockers.
- §3 references fable-review-168 (reth show) and 169 (reth node-1
  mis-bind), which this cluster config triggers directly.

## 7. Verification performed

- Iterative `xpfd check-config` on `loss:xpf-userspace-fw0` against the
  real `vsrx.conf`, strip-by-strip, to PASS — every blocker reproduced on
  the deployed binary; strip catalog retained.
- Transform artifacts (crypt-hash / IPv6 / CIDR corruption from the bulk
  address rename) identified and excluded from the blocker count.
- Code spot-checks at `origin/master` `04fa690cd` for the silent-drop
  claims (compiler_services / compiler_interfaces / compiler_security_flow).
- Confirmed the flat `redundant-parent` form (169 applies). No repo files
  modified; loss candidate not touched (locked by another agent — #1875
  respected; check-config is read-only and needs no lock).
