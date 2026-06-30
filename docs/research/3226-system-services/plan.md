# #3226 — `system-services all` / `any-service` host-inbound admission posture

**Status:** PLAN-DEFER-operator — CONVERGED v3. Claude-SMR + AGY + Codex all
PLAN-DEFER-operator. (Note: reviewer-cited line numbers vary ±5 from this doc
— e.g. Codex reads the Rust short-circuit at forwarding.rs:279 and the alias at
host_inbound.rs:86; both are the same unambiguous code, within range.)
**Issue:** #3226 (labels: audit, enhancement). Provenance: codex-review-071 finding 071-04.
**Branch:** `research/3226-system-services`
**Verified against:** `origin/master` @ `b3b8b6029` (newer than the e7496acd0 / e8d4cbd9f the prior triage comments referenced — see §4, the #3277 lifeline fix has landed since).

---

## 1. Issue framing (in my words)

xpf compiles the Junos host-inbound tokens `system-services all` and
`any-service` into a single boolean (`all_services`) on both enforcement
surfaces. That boolean is a **packet-wide admit**: every IP protocol, every
TCP/UDP port, every ICMP type destined to a firewall-local interface IP in that
zone is accepted, with **no catch-all drop**.

The issue argues this is broader than Junos. In Junos:
- `system-services all` = the union of the **named** system-service tokens
  (ssh/https/snmp/dns/...), NOT every host-bound IP protocol.
- `any-service` is a distinct token (entire port range), which xpf currently
  aliases to the same boolean.

So the current behavior admits OSPF (proto 89), PIM (103), arbitrary/future IP
protocol numbers, and any unlisted TCP/UDP port to any zone address carrying
`system-services all` — which can mask a missing explicit `protocols` entry.

The issue's "Direction" proposes: scope `all` to the union of known
system-service tokens (the #3200 SSOT) + a catch-all drop; keep `any-service` as
either the Junos entire-port-range token or a documented full-admit escape hatch.
It explicitly flags this as a **/research candidate** because it reverses a
deliberate #3199 decision and needs a parity/posture call.

---

## 2. Honest scope / value framing

**What the win actually is.** The change tightens the host-bound attack surface
on a *data* zone (e.g. an untrust uplink) that carries `system-services all`: it
would stop admitting non-named IP protocols (OSPF/PIM/raw/future proto numbers)
and unlisted TCP/UDP ports to the firewall's own interface IPs in that zone. It
brings xpf's `all` token to Junos-strict semantics.

**At absolute scale, the value is bounded by how `all` is actually used:**
- The canonical cluster configs (`ha-cluster.conf`,
  `ha-cluster-userspace.conf`, `ha-cluster-loss.conf`, `xpf-cluster-fw0.conf`)
  use `system-services { all }` **only on the `control` zone**, whose interfaces
  are **all lifeline interfaces** (em0/fab0/fab1, or fxp1/fab0/fab1) → those
  zones resolve to an **empty address set** → **no deny rule is ever emitted**
  for them regardless of scoping (§4). So scoping `all` is a **no-op on every
  shipped config** (independently confirmed by the AGY review across all four).
- **Corroboration (Codex r1):** `test/incus/xpf-cluster-fw1.conf:89-91`
  (the node-1 counterpart) already uses `system-services { ping }` — NOT `all`
  — on its control zone, and HA works. That is direct proof that the **lifeline
  exclusion, not the `all` token, is the control-plane protection**: a control
  zone with a *scoped* host-inbound set still functions because its lifeline
  interfaces contribute no address to the deny path. Scoping `all` everywhere
  would land in exactly that already-proven-safe state.
- The real exposure exists only for an operator who put `system-services all` on
  a **data** zone with live firewall-local addresses. That is a config we do not
  ship and (per Junos hygiene) should not be common, but it is the case the
  issue is about.

**Option B only PARTIALLY satisfies the issue's literal example (Claude-SMR
H1).** The issue's motivating test is "`system-services all` admits
SSH/HTTPS/SNMP but denies OSPF/**GRE**/VRRP." But `gre` is a *named* xpf
system-service (proto 47 — §3/§5), so a union-of-named `all` **still admits
GRE/47**. Option B closes OSPF(89)/PIM(103)/raw-and-future-protos/unlisted
TCP-UDP ports, but NOT GRE, unless `gre` is also reclassified out of
system-services (a separate compatibility change, §10 out-of-scope). So even the
recommended split does not fully match the issue's stated expectation.

**This is fundamentally a posture/parity decision, not a perf change.** If the
maintainer concludes the current documented broad-alias is the preferred
posture (zero-surprise-on-upgrade beats Junos-strict-correctness), **PLAN-KILL
is an acceptable verdict** — the behavior is correct-by-design and documented,
and the only residual is documentation accuracy (split the two tokens in prose).
Given that scoping `all` is a **no-op on every shipped config** (Claude-SMR H2)
AND Option B does not fully close the issue's example (H1), Option A and Option B
are genuinely **co-equal**; the marginal value is precisely why the posture call
belongs to the maintainer, not the engineer.

---

## 3. PROVEN current behavior (file:line, master b3b8b6029)

### Rust AF_XDP layer (secondary / edge-case local-delivery path)
- `userspace-dp/src/afxdp/forwarding/host_inbound.rs:88`
  `"all" | "any-service" => hi.all_services = true,` — both tokens alias to one
  boolean.
- `userspace-dp/src/afxdp/types/forwarding.rs:284-286`
  ```rust
  if self.all_services {
      return true;
  }
  ```
  `ZoneHostInbound::admits` short-circuits to accept for any
  protocol/port/ICMP-type before any per-token check.
- Struct doc `forwarding.rs:221-225` records the decision verbatim: *"treating
  it as a full admit (slightly broader than Junos, which scopes `all` to service
  traffic) keeps a `host-inbound { all }` control/heartbeat zone fully open and
  is the safe direction."*

### Go kernel nft layer (primary path — host-bound traffic is shunted to kernel by the XDP shim)
- `pkg/daemon/daemon_nft.go:486-493` `hostInboundAllowsAll` returns true if the
  zone's system-services contains `all` or `any-service`.
- `pkg/daemon/daemon_nft.go:438-441` `emitHostInboundZone`: when
  `hostInboundAllowsAll`, emits a bare `"<fam> daddr <addrs> accept"` and
  `return`s — **no catch-all drop**.
- `pkg/daemon/daemon_nft.go:423-425` `hostInboundEmitsDrop` returns false for an
  all-services zone, so no per-zone deny **counter** is even declared.

**Net:** every host-bound IP protocol/port/ICMP type to a non-lifeline firewall
address in an `all`/`any-service` zone is accepted. (ESP/AH proto 50/51, IPv6
ND, and v4/v6 PMTUD/error are accepted globally on BOTH layers regardless —
`daemon_nft.go:392/405-406`, Rust `is_icmp_host_inbound_global_accept` /
`stage_ipsec_passthrough_check` — so those are out of the scoping question.)

### This is a DELIBERATE, documented decision
- #3199 commit `abe1030c0` ("host-inbound: scope `protocols all` to routing
  protocols") explicitly states in its message: *"`system-services all` /
  `any-service` keep their (intentionally broad, documented) full-admit."* It
  scoped the **sibling** `protocols all` to the routing set while consciously
  leaving the system-services full-admit in place.
- `userspace-dp/src/afxdp/forwarding/README.md:138/212-213` documents `all` /
  `any-service` as a full-admit short-circuit.

So #3226 is **not** an accidental over-admit; it is a reversal request against a
recorded design choice.

---

## 4. What's already shipped / changed since the prior triage (CRITICAL UPDATE)

The two prior /research-disposition comments on #3226 (against e8d4cbd9f and
e7496acd0) identified a **hard blocker**: the lifeline matcher
(`hostInboundLifelineInterface`) hardcoded `fxp0`/`em0`/`fab*`, so a control
zone rooted on `control-interface fxp1` (as `test/incus/xpf-cluster-fw0.conf`
uses) would NOT be lifeline-excluded once `all` was scoped → catch-all drop on
the heartbeat plane → HA split-brain. They made the split **hard-gated on a
lifeline-matcher hardening prerequisite**.

**That prerequisite has since SHIPPED as #3277.** On master b3b8b6029:
- `pkg/dataplane/userspace/zones.go:73-84` `hostInboundLifelineSet(cfg)` now
  derives the lifeline base-name set from
  `cfg.Chassis.Cluster.ControlInterface`, `FabricInterface`, `Fabric1Interface`
  **UNION** the always-on defaults `fxp0` (hardcoded) and `em0`/`fab*`
  (`hostInboundLifelineInterface` lines 94-102).
- `test/incus/xpf-cluster-fw0.conf:17/19/20` sets `control-interface fxp1;
  fabric-interface fab0; fabric1-interface fab1;`. All three are now in the
  lifeline set → the control zone (`fxp1; fab0; fab1;`, line 100) resolves to an
  empty address set.
- `docs/ha-cluster-userspace.conf` and `docs/ha-cluster.conf` use
  `control-interface em0` + control zone `{ em0; fab0; fab1; }` — all lifeline
  by default.

**Consequence:** the control-zone-safety blocker the prior research raised is
**resolved**. For all three canonical configs, the control zone contributes no
firewall address to the deny path, so scoping `all` cannot strand the heartbeat
plane. The split is **safe-by-construction** for shipped configs.

Other relevant already-shipped context the plan must compose with:
- **#3405** (commit `8a69c54ff`): every configured zone now gets a
  `ZoneHostInbound` entry; a no-stanza zone is default-deny. `all` is the only
  full-admit short-circuit left.
- **#3200 SSOT** (`pkg/config/host_inbound_tokens.go`):
  `KnownHostInboundSystemServices` is the canonical named-service allowlist;
  `KnownHostInboundProtocols` + `HostInboundAllExpansionProtocols()` is the
  `protocols all` expansion pattern #3199 used.
- **#3225** family maps (`HostInboundServiceFamily` /
  `HostInboundProtocolFamily`): a scoped expansion must be family-aware.
- **#3486 parity test** (`config.TestHostInboundRustClassifierMatchesGoSSOT`):
  the Rust `classify_system_service` arms must equal the Go SSOT — any new
  classification must update both sides.
- **VRRP rides AF_PACKET SOCK_RAW** (`pkg/vrrp`, link-layer before XDP/nft) — it
  bypasses host-inbound entirely. Scoping `all` does NOT touch VRRP. Proof: the
  `wan`/`lan` zones are already scoped on master and do not list `vrrp`, yet
  VRRP works.

---

## 5. Concrete design (only if the maintainer chooses to ship — Option B below)

The mechanism mirrors exactly how #3199 (`abe1030c0`) handled `protocols all`:
expand at classify time, no short-circuit, let the existing per-zone catch-all
drop apply.

### `system-services all` → union of named system-services
- **Rust** (`host_inbound.rs`): replace the `"all" => all_services = true` half
  of the arm with a recursion over the **named** system-service set (every
  `classify_system_service` arm except `all`/`any-service`), exactly like
  `classify_protocol("all")` recurses over `KNOWN_ROUTING_PROTOCOL_TOKENS`. This
  populates `tcp_ports`/`udp_ports*`/`icmp_types*`/`ip_protocols*` from the named
  set; the existing `admits` per-token match + the per-zone catch-all drop then
  apply.
- **Go SSOT**: add `HostInboundAllServiceExpansion()` to
  `pkg/config/host_inbound_tokens.go` = `KnownHostInboundSystemServices` minus
  `{all, any-service}`, mirroring `HostInboundAllExpansionProtocols()`.
- **Go nft** (`daemon_nft.go`): drop `all` from `hostInboundAllowsAll`; add a
  `case "all"` to `hostInboundServiceMatches` that expands over the named set
  (family-aware via `HostInboundServiceFamily`). `all` then flows through the
  per-match accept path and gets the per-zone catch-all drop.

### `any-service` → two sub-options (Claude-SMR H3)
There is no evidence `any-service` is used in any xpf config; distinguishing it
from `all` adds struct fields + admits branches + an nft rule for a token of
unproven usage. Two co-equal sub-choices:
- **B1 (cheaper, recommended):** `any-service` stays the documented full-admit
  escape hatch (the only token that keeps the `all_services` short-circuit),
  with an explicit commit warning that it is a non-Junos blanket admit. Only
  `all` is scoped. Smaller blast radius, fewer new fields.
- **B2 (strict Junos):** `any-service` → entire TCP+UDP port range. Add
  `any_tcp` / `any_udp` bool flags to `ZoneHostInbound`; `admits` returns true
  for proto 6/17 regardless of port but still drops non-TCP/UDP IP protocols not
  otherwise permitted. nft mirror: `<fam> daddr <addrs> meta l4proto { tcp, udp
  } accept` + catch-all drop. Adopt only if a real `any-service` use case exists.

### `gre` classification — a design fork the issue's example test exposes
`gre` is currently a **system-service** token (`host_inbound.rs:208-209` →
`ip_protocols.insert(47)`; `KnownHostInboundSystemServices` line 87). Therefore
a union-of-named `all` **would still admit GRE proto 47** — which contradicts the
issue's proposed test "`system-services all` ... denies OSPF/GRE/VRRP". OSPF
(89) and VRRP (112) are `protocols` tokens, so `system-services all` correctly
would NOT admit them; but GRE is the exception. **This is a sub-decision for the
maintainer:** (a) accept that `system-services all` admits gre/47 (it is a named
xpf service) and correct the issue's test expectation, or (b) reclassify `gre`
out of `system-services` (a separate, larger compatibility change). Recommended:
(a) — keep gre a named service, fix the test wording.

### Multiple Path Options
- **Option A — keep the documented broad alias (status quo).** Update
  `forwarding/README.md` + the struct/`hostInboundAllowsAll` comments to make
  the alias and its superset-of-Junos nature explicit, and note `all`/
  `any-service` are aliased. Zero behavior change. → **PLAN-KILL** disposition
  (correct-by-design + doc-accuracy).
- **Option B — Junos-correct split (recommended if the maintainer wants
  strict parity).** `all`→union-of-named + drop; `any-service`→entire
  TCP/UDP port range + drop non-TCP/UDP. Now SAFE-by-construction given #3277;
  still HA-adjacent → `make test-failover` required.
- **Option C — split the two tokens but keep `all` as a control-zone-only
  full-admit heuristic.** Rejected: heuristics on zone name are fragile, and
  #3277 already makes lifeline exclusion the real protection, so there is no need
  for a special-case.

---

## 6. Public API / behavior preserved (Option B)

- `KnownHostInboundSystemServices` / `KnownHostInboundProtocols` SSOT maps
  unchanged (both tokens stay recognized at commit).
- `HostInboundAllExpansionProtocols()` (the `protocols all` path) untouched.
- The global ESP/AH + ND + PMTUD/error exemptions untouched.
- The #3277 lifeline exclusion untouched (it remains the real control-plane
  protection).
- `ZoneHostInbound::admits` signature unchanged; only the `all_services`
  short-circuit is replaced by `any_tcp`/`any_udp` + populated named sets.
- The #3486 Go↔Rust parity test contract preserved (both sides updated in
  lockstep).

---

## 7. Hidden invariants the change must preserve (Option B)

1. **Go↔Rust parity (#3486 / #1961 wire) (Claude-SMR H4).** The nft `all`
   expansion and the Rust classifier expansion MUST yield the same admit set, or
   a host-bound packet is accepted on one path and dropped on the other
   (split-brain). NOTE the existing `TestHostInboundRustClassifierMatchesGoSSOT`
   compares the *token-arm sets* (classify arms == SSOT maps) — it would NOT
   catch a divergence in how Go vs Rust *expand* `all` into ports/protos. The
   plan must add a SEPARATE assertion that compiles a `system-services all` zone
   through BOTH layers and compares the resulting concrete admit sets
   (tcp_ports / udp_ports{,_v4,_v6} / icmp_types{_v4,_v6} / ip_protocols{,_v4,_v6}
   vs the nft match set), not merely extend the arm-equality test.
2. **Family-awareness (#3225).** The named-set expansion must route each token
   through `HostInboundServiceFamily`, or `all` re-opens dhcp/67-68 on IPv6
   (the #3225 regression).
3. **Lifeline exclusion is the control-plane safety net, not `all`.** The plan
   must NOT weaken `hostInboundLifelineSet`/`hostInboundLifelineInterface`. Test
   that each canonical control zone still yields an empty address set after the
   change (no deny emitted).
4. **Counter declaration symmetry (`daemon_nft.go`).** Once `all` stops being a
   full-admit, an `all` data-zone now emits a catch-all drop → a named drop
   counter. `hostInboundEmitsDrop` and the counter pre-pass must agree (nft
   rejects an undeclared counter reference). The two sites already share
   `hostInboundEmitsDrop`, so dropping `all` from `hostInboundAllowsAll` keeps
   them aligned automatically — verify.
5. **No fail-open on the empty-expansion edge.** If the named set were ever
   empty, the zone must default-deny (catch-all drop), never silently admit.
6. **ident-reset interaction.** Under the union, `all` no longer "wins" over the
   `ident-reset` no-op/reset. Confirm the union does NOT include an `ident`-admit
   (it must not — `ident-reset` contributes nothing/reset, and there is no
   plain-ident token), so TCP/113 stays reset (kernel) / dropped (XSK).

---

## 8. Risk assessment (Option B)

| Risk | Level | Notes |
|------|-------|-------|
| Behavioral regression on shipped configs | **LOW** | All canonical `all` usage is on lifeline-only control zones → empty address set → no deny emitted → no-op. Verified §4. |
| HA / control-plane regression (split-brain) | **LOW** (post-#3277) | Was the blocker; #3277 made the lifeline set config-derived. `make test-failover` is the gate. |
| Silent upgrade behavior change on a DATA zone with `system-services all` | **MED** | An operator who used `all` on a data zone to open a non-named port/protocol loses that admit silently on upgrade. This is the core posture tradeoff — Junos-strict vs zero-surprise. |
| Go↔Rust split-brain (parity drift) | **MED** | Mitigated by extending the #3486 parity test to the `all` expansion + the #3200 SSOT being the single source. |
| Architectural mismatch | **LOW** | Mechanism is byte-for-byte the #3199 `protocols all` pattern, already proven on this exact surface. |
| `gre`-as-service ambiguity | **LOW** | Documented sub-decision (§5); recommend keeping gre a named service and fixing the test expectation. |

---

## 9. Test plan (Option B only — skip entirely under Option A/PLAN-KILL)

- `cargo build --release` clean; `cargo test --release` (forwarding/host_inbound
  suite — ~97+ tests) green, incl. 5/5 named-test flake check on any new test.
- `go test ./pkg/config/... ./pkg/daemon/... ./pkg/dataplane/...` — must include:
  - extend `TestHostInboundRustClassifierMatchesGoSSOT` (#3486) to assert the
    `all` expansion matches across Go/Rust.
  - new test: a data zone with `system-services all` admits ssh(22)/https(443)/
    snmp(161)/dns(53) but DROPS an unlisted proto (e.g. OSPF 89, PIM 103) and an
    unlisted TCP/UDP port — on BOTH the nft payload and the Rust `admits`.
  - new test: `any-service` admits an arbitrary TCP and UDP port but drops a raw
    non-TCP/UDP proto not otherwise permitted.
  - regression: each canonical control zone (em0/fab*/fxp1) still yields an empty
    address set → no deny rule (lifeline exclusion intact).
  - family-awareness: `all` does not open dhcp udp/67-68 on the IPv6 path.
- `make build` (xpfd) + `make build-userspace-dp` clean.
- **`make test-failover` REQUIRED** (touches control-zone admission + the
  cluster heartbeat path; HA-adjacent — CLAUDE.md mandate).
- Smoke on the loss userspace cluster: confirm heartbeat/session-sync/fabric
  survive a deploy with the scoped `all`, and a normal trust→untrust forwarding
  pass is unaffected (host-inbound is local-delivery only, not transit).
- Doc updates: `userspace-dp/src/afxdp/forwarding/README.md` host-inbound
  section + the struct/`hostInboundAllowsAll` comments to reflect the split.

---

## 10. Out of scope (explicitly)

- Reclassifying `gre` out of `system-services` (a separate compatibility
  change; §5 recommends keeping it a named service).
- Any change to `protocols all` (already correctly scoped by #3199).
- Any change to the global ESP/AH/ND/PMTUD exemptions.
- Any change to the #3277 lifeline derivation (it is the safety net and stays).
- Per-interface override semantics (#3362) beyond inheriting the new
  classification (the override path classifies via the same
  `zone_host_inbound_from_tokens`, so it follows automatically).
- A config `commit` warning on `any-service` as a non-Junos escape hatch — only
  relevant if the maintainer chooses to keep `any-service` as full-admit rather
  than entire-port-range; fold into the chosen option's docs.

---

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Posture: is the documented broad-alias the desired posture?** #3199
   deliberately kept it. Given the only shipped `all` usage is on lifeline-only
   control zones (no-op there), is the data-zone surface worth a reversal of a
   recorded decision? (If "no" → PLAN-KILL with doc-accuracy follow-up.)
2. **Is the #3277 lifeline fix actually sufficient** to make the split
   safe-by-construction, or is there a control-plane path I'm missing
   (peer→local heartbeat/session-sync/config-sync to a non-lifeline address)?
   Prove the heartbeat/fabric host-bound traffic never lands on a scoped address.
3. **Upgrade silent-change blast radius:** is there any realistic deployed
   config (outside the canonical three) that leans on `system-services all`
   admitting a non-named protocol/port on a data zone? If yes, MED→HIGH.
4. **`gre`-as-service:** is keeping gre a named service (so `all` admits 47) the
   right call, or does Junos parity demand gre move under `protocols`? The
   issue's own example test assumes `all` denies GRE — which contradicts the
   current SSOT. Which way?
5. **`any-service` semantics:** entire-TCP/UDP-port-range vs documented
   full-admit escape hatch — does the project want the strict Junos meaning, or
   is the escape hatch operationally valuable (e.g. a quick "open everything on
   this box" for a lab/bring-up)?
6. **Parity-test sufficiency:** does extending #3486 to the `all` expansion fully
   prevent Go/Rust split-brain, or is there an expansion path (family maps,
   icmp-types) the parity test would not catch?
7. **Is this even a bug, or purely a posture decision?** The convergent verdict
   should pick exactly one of: PLAN-DEFER-operator (posture), PLAN-KILL
   (correct-by-design + doc), or PLAN-READY-as-fix (parity bug). Argue it.

---

## Recommendation (pre-review)

**PLAN-DEFER-operator (posture decision).** The current behavior is deliberate
and documented (#3199), and the control-zone-safety blocker the prior research
raised is now resolved by #3277 — so the engineering for the Junos-correct split
(Option B) is well-understood, low-risk on shipped configs, and ready. What is
NOT mine to decide is the **posture**: Junos-strict-correctness + tighter
data-zone box (Option B) vs zero-surprise-on-upgrade + keep the documented alias
(Option A / PLAN-KILL).

After folding Claude-SMR H1+H2, the two options are **genuinely co-equal**, not
B-leaning: scoping `all` is a no-op on all four shipped configs, AND Option B
does not even fully close the issue's literal example (gre/47 stays admitted
because gre is a named service). So the honest framing is — the engineering is
ready, but the *value* is marginal and the *cost* (new classifier path,
parity-set test, mandatory `make test-failover`) is real. If the maintainer
weights Junos-strict-parity highest, ship **Option B** (with `any-service`
sub-choice B1 = keep documented escape hatch, the cheaper default), hard-gated on
`make test-failover`. If the maintainer weights zero-surprise-on-upgrade + churn
avoidance highest — which, given the no-op-on-shipped-configs reality, is the
slightly stronger default — take **Option A / PLAN-KILL** with a documentation
pass making the `all`/`any-service` alias + superset-of-Junos nature explicit in
`forwarding/README.md` and the struct/`hostInboundAllowsAll` comments. Either way
the #3277 lifeline derivation stays as the real control-plane safety net.
