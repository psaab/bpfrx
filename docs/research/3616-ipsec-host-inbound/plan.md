# Plan of Action — #3616: IPsec/IKE/ESP/AH passthrough (Stage 11) vs host-inbound enforcement

- Issue: #3616 (`userspace-dp: IPsec/IKE/ESP/AH passthrough (Stage 11) bypasses
  per-zone host-inbound service enforcement — decide + pin vSRX parity`)
- Base: origin/master `0be2bd792`
- Branch: `research/3616-ipsec-host-inbound`
- Mode: `/research` — STOP at PLAN-READY / PLAN-DEFER / PLAN-KILL. No code, no PR.
- Revision: **r3 (post review-r1 — Claude SMR + AGY + Codex folded; exposure model
  corrected to add the native-GRE-inner local-delivery path (Codex M1/M2 — direct-
  ish IKE/ESP-to-self CAN reach Stage 11 when native GRE is configured); F1 refined
  (outer ESP → kernel, inner ESP over native GRE → Stage 11); L15 confirmed NOT
  telemetry-free (slow_path routes on local_ifindex) — fix stays local_ifindex=0;
  Option B zone resolution refined to logical-ifindex + GRE-inner ingress zone;
  line refs corrected; Junos SA claim attributed)**

---

## 1. Problem statement

The AF_XDP local-delivery pipeline recognizes IPsec traffic (ESP proto 50, AH
proto 51, IKE/NAT-T UDP 500/4500) in a dedicated passthrough stage ("Stage 11")
that runs BEFORE the per-zone host-inbound admission gate. On a match it builds a
synthetic `LocalDelivery` `SessionDecision` and reinjects the packet toward the
kernel XFRM stack. The concern: a zone that omits `host-inbound-traffic
system-services ike`/`ipsec` still lets IKE/ESP/AH reach the box's XFRM/strongSwan
stack — a claimed host-inbound bypass. Junos `host-inbound-traffic
system-services ike` is a real operator knob, so "no ike in host-inbound" ought to
mean "block IKE to the box".

The central question the issue poses: is the passthrough-before-host-inbound
ordering an INTENTIONAL control-plane exception (IPsec must reach strongSwan) or a
genuine SECURITY BYPASS that should be gated by the ike/ipsec tokens?

**Answer (derived below): a NUANCED split.** The ESP/AH exemption is correct-by-
design and already ratified + tested on the KERNEL path. Raw OUTER ESP is shunted
to the kernel unconditionally by the shim and never reaches Stage 11 (F1). The one
genuine divergence is IKE (UDP 500/4500 — plus inner ESP over native GRE), and it
is confined to the SECONDARY AF_XDP path. That path is reached by MORE than just
DNAT-to-self: Codex M1/M2 correctly identified that IPsec carried INSIDE a native
GRE tunnel whose inner destination is a firewall-local address is REDIRECTED to
the XSK (not shunted to the kernel), decapped in userspace, and hits Stage 11 —
so direct-ish IKE/ESP-to-self CAN bypass host-inbound when native GRE is
configured. The exposure is therefore broader than r2 stated (native-GRE-inner +
DNAT-to-self), though still config-gated. It remains a real, if narrow, host-
inbound parity gap for IKE/inner-ESP — not a broad management-plane hole. A
Stage-11 IKE gate must reproduce the kernel chain's `ct established,related
accept`-first ordering (AGY M2) AND resolve the correct (logical / GRE-inner)
ingress zone (Codex M6) or it will drop return/established/tunnelled IKE. Given
those subtleties plus the config-gated exposure, the recommendation is Option A
(ratify + document + telemetry-only L15 + per-class pinning tests) with the
IKE/inner-ESP gate deferred as specced hardening.

---

## 2. Current behavior (proven with file:line)

### 2.1 Stage 11 runs BEFORE the host-inbound gate (bypass confirmed)

- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:566-575` — Stage 11
  (`stage_ipsec_passthrough_check`) is invoked immediately after screen (stage 10)
  and BEFORE the flow-cache fast path (`:584`) and the slow-path local-delivery
  resolution. On `RecycleAndContinue` it drops the UMEM frame and `continue`s the
  poll loop, so nothing downstream runs.
- `userspace-dp/src/afxdp/poll_stages.rs:674-715` — the stage: if
  `is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port)` it builds a
  synthetic `SessionDecision{ disposition: LocalDelivery, local_ifindex:0,
  egress_ifindex:0, tx_ifindex:0, ... }` and calls
  `maybe_reinject_slow_path_from_frame(...)`, then returns `RecycleAndContinue`.
- The host-inbound admission gate is
  `poll_descriptor/filter.rs:435-473 host_inbound_gated_lo0_action` →
  `:452 host_inbound_admits_iface`, reached only on the LocalDelivery slow-path
  AFTER resolution (session-HIT call `mod.rs:827-849`; session-MISS call
  `mod.rs:1713-1734` — Codex minor line-ref fix). Because Stage 11 short-circuits
  and `continue`s the loop, `host_inbound_admits_iface` NEVER runs for a packet
  Stage 11 claims. **Bypass confirmed by ordering.**
- Stage 11 itself has NO local-destination / DNAT predicate (Codex M1): it fires
  on ANY `is_ipsec_traffic` packet that reaches it, BEFORE userspace DNAT and
  before host-inbound. What reaches it is decided upstream by the shim + the
  native-GRE decap (§2.5), not by Stage 11.

### 2.2 `is_ipsec_traffic` recognizes ESP/AH/IKE

- `userspace-dp/src/afxdp/forwarding/mod.rs:1059-1063`:
  `protocol == PROTO_ESP (50) || protocol == PROTO_AH (51) || (PROTO_UDP && (dst_port == 500 || 4500))`.

### 2.3 The ike/ipsec tokens DO feed the host-inbound gate — but are dead for the passthrough path

- `userspace-dp/src/afxdp/forwarding/host_inbound.rs:143-146` — the `"ike" |
  "ipsec"` arm inserts UDP 500/4500 into the admit set, and its comment states raw
  ESP/AH is handled "by the kernel XFRM stack / stage_ipsec_passthrough_check
  before host-inbound enforcement". So the token IS classified into the gate, but
  because Stage 11 intercepts IKE UDP 500/4500 first, the token's UDP-500/4500
  admit is never consulted for an IKE packet that reaches Stage 11.

### 2.4 The synthetic decision zeroes the interface context (L15 telemetry gap)

- `poll_stages.rs:691-693` — `local_ifindex/egress_ifindex/tx_ifindex = 0`. The
  slow-path exception telemetry (`recent_exceptions`, `local_tunnel_deliveries`)
  therefore loses the real local/ingress interface for IPsec passthrough packets.

### 2.5 The architecture is TWO host-inbound enforcement paths, not one

This is the decisive context the issue's severity turns on.

- **PRIMARY path — kernel nftables chain** (`pkg/daemon/daemon_nft.go`). The XDP
  shim shunts local-destination traffic to the kernel BEFORE userspace-dp ever
  sees it:
  - `userspace-xdp/src/lib.rs:531-533` — **ALL ESP (proto 50) is shunted to the
    kernel unconditionally** (`cpumap_or_pass`) in the normal datapath, right
    after parsing and BEFORE the session-action logic (`:574+`). This is
    load-bearing (F1): **raw ESP never reaches userspace-dp Stage 11 in the normal
    path.** The interface-NAT-ESP check (`:1040`,
    `PROTO_ESP && is_interface_nat_destination`) lives inside
    `is_degraded_local_or_control` (`:1024-1047`), consulted ONLY on the
    heartbeat-stale degraded path (`:519`), and it routes to the kernel
    (`pass_local_control`) or drops — never to the XSK. So Stage 11's ESP arm of
    `is_ipsec_traffic` is defensive/near-dead for ESP.
  - `userspace-xdp/src/lib.rs:611-623` — a session-miss packet with
    `is_local_destination()` true (e.g. IKE UDP 500/4500 to an interface IP / VIP,
    IPv4 AH-to-self) is `PASS_TO_KERNEL`.
  - So genuine, direct host-bound IPsec-to-self is handled by the KERNEL chain,
    not by userspace-dp Stage 11.
  - The kernel chain (`daemon_nft.go:378-411 buildHostInboundFilterPayload`):
    `ct state established,related accept` FIRST (`:380`), THEN
    `meta l4proto { 50, 51 } accept` — raw ESP/AH are GLOBALLY exempt (accepted
    before any per-zone drop). IKE UDP 500/4500 is NOT globally exempt: it is
    gated on the per-zone `ike` token via `emitHostInboundZone` (per-match accept +
    catch-all `drop`). **The kernel path correctly gates NEW inbound IKE on
    `system-services ike`, while `ct established,related accept` unconditionally
    lets return/established IKE through (e.g. the reply for a firewall-initiated
    tunnel on a zone that omits `ike`). Junos parity holds on the primary path.**
  - This exemption is deliberate and regression-guarded:
    `pkg/daemon/host_inbound_nft_test.go:187 TestHostInboundFilterExemptsIPsecAndV6Errors`
    asserts `meta l4proto { 50, 51 } accept` is present AND precedes every per-zone
    drop (fail-on-revert).

- **SECONDARY path — AF_XDP Stage 11** (userspace-dp). Reached when IPsec traffic
  is NOT shunted to the kernel by the shim. Three sub-cases reach it:
  - **DNAT / static-NAT-to-self IKE**: outer dst is a non-local address that a
    prerouting NAT rule rewrites to a local IP. The shim's `is_local_destination`
    keys on the arriving (pre-NAT) dst, so it does NOT shunt; the packet reaches
    the XSK and Stage 11 fires.
  - **Native-GRE-inner local IPsec (Codex M1/M2 — the important widening)**: when
    native GRE is configured, an inner packet whose destination is a firewall-
    local address is classified `USERSPACE_SESSION_ACTION_REDIRECT` — steered to
    the XSK, NOT `PASS_TO_KERNEL` — by `classify_native_gre_inner_ipv4`
    (`userspace-xdp/src/lib.rs:844`, `USERSPACE_LOCAL_V4`) and `_ipv6` (`:976`,
    `USERSPACE_LOCAL_V6`). It is then GRE-decapped in userspace
    (`poll_descriptor/mod.rs:495-502`), and Stage 11's `is_ipsec_traffic` sees the
    INNER protocol. So inner IKE (UDP 500/4500) AND inner ESP (proto 50) destined
    to a firewall-local address, carried in a native GRE tunnel, reach Stage 11
    and bypass host-inbound. This is direct-ish IPsec-to-self — NOT a NAT edge —
    so the "primary path always shunts direct IKE/ESP to the kernel" claim is
    FALSE for the native-GRE tunnel-entry path.
  - **Transit-shaped / NAT AH (IPv4, proto 51)**: AH is NOT shunted at `:531`
    (only outer ESP is), so transit/NAT-shaped IPv4 AH can reach the XSK.
  - OUTER ESP does NOT reach Stage 11 (F1, `:531` shunts it to the kernel), but
    INNER ESP over native GRE DOES (above), so the ESP arm of `is_ipsec_traffic`
    is NOT wholly dead — it is dead for outer ESP, live for GRE-inner ESP.
  - On this secondary path, Stage 11 exempts whatever it sees from host-inbound
    entirely — the behavior the issue flags.

**Net:** the "bypass" the issue describes exists on the SECONDARY AF_XDP path for
IKE + inner ESP (native-GRE-inner local, and DNAT-to-self) + transit/NAT IPv4 AH;
outer ESP never reaches it. Direct IKE/ESP/AH to an interface IP or VIP OUTSIDE a
GRE tunnel — the classic case an operator means when they write `system-services
ike` — is enforced by the kernel chain, where new IKE IS gated and
established/return IKE rides `ct established,related accept`. The native-GRE
tunnel-entry case is the one where direct-to-self IPsec escapes that kernel
enforcement onto the exempt AF_XDP path.

---

## 3. Root-cause / parity analysis

### 3.1 Is the ESP/AH exemption correct Junos parity?

Yes (with one attribution caveat, Codex minor). The operative claim — in Junos/
vSRX the IPsec data plane (ESP/AH) is authorized by the negotiated IKE/IPsec SA,
not by a separate host-inbound service, and the standard external-zone config is
`host-inbound-traffic { system-services { ike; } }` (`ike` alone; ESP implicitly
permitted once the tunnel negotiates) — is asserted here from the repo's own
kernel-chain comments (`daemon_nft.go:381-392`) and its fail-on-revert test
(`host_inbound_nft_test.go:187`), NOT from an independent Junos citation. The
/engineer pass should confirm it against Junos host-inbound-traffic docs before
relying on it as parity. Either way, xpf is internally self-consistent: the kernel
chain accepts raw ESP/AH globally and gates IKE on `ike`, and gating raw ESP/AH on
a token would break the tunnel data plane AFTER IKE succeeded (a silent
black-hole). The ESP/AH exemption is therefore correct-by-design (kernel-
consistent) and should be RATIFIED, not gated.

### 3.2 Is the IKE exemption on Stage 11 a genuine bypass?

Yes, but narrow. `host-inbound-traffic system-services ike` is a real Junos knob;
a zone that omits it should drop IKE to the box. The kernel path enforces this.
Stage 11 does not — so a DNAT/static-NAT-to-self IKE flow reaches strongSwan even
on a zone that never opened `ike`. It IS a real host-inbound divergence for IKE,
and it IS an inconsistency between xpf's own two paths (kernel enforces, AF_XDP
does not), which is exactly why audits keep re-flagging it.

### 3.3 How narrow is the realistic exposure?

Narrow but broader than r2 claimed (Codex M1/M2). Two config-gated ways reach it:

- DNAT/static-NAT-to-self IKE: needs a NAT rule translating an external tuple to a
  local IP on UDP 500/4500, a zone omitting `ike`/`ipsec`, and the expectation that
  the omission blocks it. Contrived; no repo config exercises it.
- Native-GRE-inner local IPsec: needs native GRE configured and inner IKE/ESP
  destined to a firewall-local address, on an (inner-facing) zone that omits
  `ike`/`ipsec`. More plausible than the NAT case (a GRE tunnel carrying IPsec that
  terminates on the firewall), though still a specific design.

Neither is a broad management-plane hole, but the native-GRE case IS a genuine
direct-to-self host-inbound bypass for IKE/inner-ESP — the kernel enforcement the
box otherwise applies does not cover it. This is why the issue is Severity:Medium
(design decision) and why the security case for the gate is real even though it is
deferred.

Caveat (F2): outside native GRE, the "direct IKE-to-self goes to the kernel" claim
is load-bearing on the shim's `is_local_destination` local-address set being
complete. A transiently stale/incomplete set (e.g. a freshly added VIP not yet
propagated to the shim) would also let direct IKE-to-self reach Stage 11 — another
defence-in-depth argument for the gate.

### 3.4 Feasibility of gating IKE at Stage 11 — and the established/return-IKE trap

Zone resolution is feasible but MORE than a raw ifindex lookup (Codex M6). At
Stage 11 `meta.ingress_ifindex` is set, but: (1) `ingress_zone_override` is
computed at stage 9 (mod.rs :526-529) and is NOT currently passed into Stage 11
(`:566-572`) — the gate would need it plumbed in; (2) existing host-inbound
callers resolve the LOGICAL (unit) ifindex first (`poll_stages.rs:337-350`,
`mod.rs:1471-1481`) before `ifindex_to_zone_id`, so a raw
`ifindex_to_zone_id[meta.ingress_ifindex]` is NOT equivalent for VLAN
sub-interfaces; (3) for the native-GRE-inner case the "ingress" is the GRE tunnel,
so the correct host-inbound zone is the tunnel's zone, not the physical netdev's.
The gate must reuse the exact resolution the resolver uses. It runs only when
`is_ipsec_traffic` is true (rare), so there is no common-datapath hot-path cost.
`host_inbound_admits_iface(state, logical_ifindex, zone_id, PROTO_UDP, dst_port,
is_v6, 0)` already exists and honours per-interface overrides.

BUT (AGY M2 — decisive): the kernel chain gates NEW inbound IKE while letting
established/return IKE through via `ct state established,related accept` at
`daemon_nft.go:380`, evaluated BEFORE the per-zone service match. A naive Stage-11
gate that calls only `host_inbound_admits_iface` (which has NO conntrack-state
awareness) would DROP a return/established IKE packet on a zone that omits `ike` —
e.g. the reply for a firewall-initiated tunnel, if such a flow ever reaches Stage
11. To be correct, a Stage-11 IKE gate MUST reproduce the established-first
ordering: admit if the flow is established/related, else apply the zone service
check to NEW inbound IKE only. That extra care — plus the near-nil exposure — is
why the gate is DEFERRED (Option A shipped) rather than shipped now. The gate
admits whenever `ike`/`ipsec` is configured, so a correctly-configured tunnel does
not break; the risk is entirely in the established/return-flow edge if the gate is
implemented carelessly.

---

## 4. Design — Multiple Path Options

### Option A — Ratify everything (pure option (b) from the issue)

Declare the passthrough-before-host-inbound ordering a deliberate userspace-
dataplane semantic for ALL of ESP/AH/IKE. Document it in the host-inbound
reference + `docs/userspace-dataplane-architecture.md`. Carry the real
ingress/local ifindex into the synthetic decision (fix L15). Add the per-class
pinning tests (M12) asserting the ratified (exempt) behavior.

- Pro: zero datapath behavior change; zero tunnel-breakage risk; ESP/AH already
  ratified on the kernel path so this only formalizes reality; simplest.
- Con: leaves the AF_XDP IKE path inconsistent with the kernel IKE gate and with
  Junos; the audit finding is closed by fiat + doc, not by parity. A future audit
  could re-flag the kernel-vs-AF_XDP IKE inconsistency.

### Option B — Ratify ESP/AH, GATE new inbound IKE at Stage 11 (hybrid; DEFERRED hardening)

- Ratify + document the ESP/AH exemption (as Option A) — it is correct-by-design
  and kernel-consistent.
- For the IKE sub-case ONLY (UDP 500/4500), run a host-inbound admit BEFORE the
  passthrough reinject, reproducing the kernel's established-first ordering:
  - **Established/related first**: if the flow is established/related, ADMIT
    (passthrough) unconditionally — mirrors `ct established,related accept`
    (`daemon_nft.go:380`) so return/reply IKE for a firewall-initiated tunnel is
    never dropped (AGY M2). This requires a reliable established/related signal at
    Stage 11 — see OQ5.
  - Else (NEW inbound IKE): resolve the LOGICAL ingress ifindex + zone the same way
    the resolver does (`poll_stages.rs:337-350` / `mod.rs:1471-1481`), plumbing
    `ingress_zone_override` into Stage 11 and handling the GRE-inner tunnel-zone
    case (Codex M6) — NOT a raw `ifindex_to_zone_id[meta.ingress_ifindex]`. Then
    `host_inbound_admits_iface(fw, logical_ifindex, zone_id, PROTO_UDP, dst_port,
    is_v6, 0)` → passthrough reinject; else drop the frame (silent, Junos posture),
    count a host-inbound deny, `RecycleAndContinue`. Applies to inner ESP over
    native GRE as well (an ESP sub-case gate), not only IKE.
- ESP/AH keep the unconditional passthrough (no gate) — SA is the authorization
  (and raw ESP does not even reach Stage 11, F1).
- Fix L15 telemetry-only (see Option A / §6) — NOT part of the gate.
- Add per-class pinning tests (M12): ESP/AH stay exempt/passthrough; NEW IKE 500 +
  NAT-T 4500 DENIED when the zone omits ike/ipsec and ADMITTED when it lists them;
  established/related IKE ADMITTED regardless of the token; v4 and v6.

- Pro: exact Junos + kernel-path parity for IKE; closes the genuine (if narrow)
  divergence; admits-when-configured + established-first so tunnels do not break;
  cold-path change; kills the recurring audit flag with actual parity.
- Con: a new drop behavior for NEW DNAT-to-self IKE on a zone that omits `ike`
  (intended parity change, but IS a behavior change); needs ingress-zone
  resolution AND a correct established/related signal at Stage 11 (OQ5) — get the
  established-first ordering wrong and you drop return IKE (AGY M2). Given the
  near-nil exposure, this care is why the gate is DEFERRED, not shipped now.

### Option C — Gate ESP/AH too (full option (a))

Gate every IPsec class (ESP/AH/IKE) on the ike/ipsec tokens before passthrough.

- REJECTED. Gating raw ESP/AH breaks the tunnel data plane after IKE succeeds,
  diverges from Junos (SA is the authorization) AND from xpf's own tested kernel
  exemption (`TestHostInboundFilterExemptsIPsecAndV6Errors`). This is the
  black-hole the kernel comment at `daemon_nft.go:388-391` explicitly warns
  against. Not viable.

---

## 5. Recommendation

**Option A shipped now; Option B (the IKE gate) DEFERRED as documented hardening.**

Review round r1 shifted the balance. F1 shows raw OUTER ESP never reaches Stage 11;
Codex M1/M2 shows the exposure is broader than DNAT-to-self (native-GRE-inner
local IPsec reaches Stage 11); AGY M2 + Codex M6 show a correct gate must reproduce
the kernel's `ct established,related accept`-first ordering AND resolve the correct
logical/GRE-inner ingress zone, or it drops return/established/tunnelled IPsec.
With the exposure real-but-config-gated and the gate non-trivial to get right, the
proportionate, low-risk answer is:

- **Ship (Option A):** ratify the ESP/AH + IKE passthrough-before-host-inbound
  ordering as a deliberate userspace-dataplane semantic; document it in the
  host-inbound reference + `docs/userspace-dataplane-architecture.md` (including
  the two-path kernel-primary / AF_XDP-secondary model and the F1 ESP-shunt fact);
  fix L15 telemetry-only (local_ifindex stays 0 — see §6); add the per-class
  pinning tests (M12) asserting the ratified exempt behavior.
- **Defer (Option B):** the NEW-inbound-IKE gate at Stage 11 with established-first
  ordering — record it as a scoped, low-priority hardening with the OQ5
  established/related-signal requirement, to be picked up if/when a real
  DNAT-to-self-IKE deployment or a stricter parity mandate makes it worth the new
  drop path.

The issue explicitly allows PLAN-DEFER "if gating risks breaking tunnels" — AGY M2
shows a careless gate does exactly that, so deferring the gate (while shipping the
ratify + telemetry + tests) is the contract-correct outcome.

**Not PLAN-KILL:** the ratify decision, the L15 telemetry fix, the documentation,
and the pinning tests are real, shippable work that terminates the recurring audit
flag on an explicit ratified answer rather than leaving it re-flaggable.

---

## 6. Implementation plan (for the eventual /engineer pass — NOT executed here)

### Ship now (Option A)

1. `userspace-dp/src/afxdp/poll_stages.rs` — `stage_ipsec_passthrough_check`: L15
   telemetry-only fix. Do NOT populate `local_ifindex`/`egress_ifindex`/
   `tx_ifindex` in the synthetic `ForwardingResolution` — they MUST stay 0. AGY
   confirmed `slow_path.rs:213-222` routes a LocalDelivery reinject on
   `local_ifindex`: a non-zero value triggers the `local_tunnel_deliveries` map
   lookup and diverts from the generic TUN injector (`slow_path.enqueue`). Carry
   the real ingress/local ifindex ONLY in the exception / telemetry record
   (`recent_exceptions` / `local_tunnel_deliveries` accounting), never in the
   routing decision.
2. `userspace-dp/src/afxdp/forwarding/README.md` "Host-terminated IPsec
   passthrough" — document the ratified ESP/AH+IKE exemption, the two-path model
   (kernel primary gates new IKE + established-first; AF_XDP secondary exempts),
   and the F1 fact (raw ESP shunted at shim `:531`, never reaches Stage 11).
3. `docs/userspace-dataplane-architecture.md` — add the IPsec host-inbound
   semantics + the two-path model + the ratified exemption + deferred-gate note.
4. `userspace-dp/src/afxdp/forwarding/host_inbound.rs` — clarify the `ike`/`ipsec`
   arm comment: the token gates IKE on the KERNEL path; the AF_XDP Stage-11 path
   exempts it (ratified), with the gate deferred (#3616 Option B).
5. Tests (M12): `poll_stages.rs` (or `forwarding/tests.rs`) per-class pinning
   tests asserting the ratified behavior — ESP/AH and IKE 500/4500 are passed
   through (exempt) on a zone that omits ike/ipsec, v4 and v6. Fail-on-revert
   guards the ratified semantic.

### Deferred (Option B — the IKE gate)

6. `stage_ipsec_passthrough_check`: split the gated sub-case (IKE UDP 500/4500 +
   inner ESP over native GRE) from the always-exempt one; established/related →
   admit; else zone service check via `host_inbound_admits_iface` on the LOGICAL
   ingress ifindex/zone the resolver computes (`poll_stages.rs:337-350` /
   `mod.rs:1471-1481`), with `ingress_zone_override` plumbed into Stage 11 and the
   GRE-inner tunnel-zone case handled (Codex M6) — NOT a raw
   `ifindex_to_zone_id[meta.ingress_ifindex]`; on deny count + `RecycleAndContinue`.
   Requires the OQ5 established/related signal (may force the gate AFTER session
   resolution rather than at Stage 11). If a new deny counter is added, verify no
   Go/Rust contract test governs host-inbound deny counters before adding one
   (MEMORY: screen-flag cross-package contract) and mirror both sides if so.

No Go control-plane change is required for either scope: `ifindex_to_zone_id` and
the per-zone/per-interface host-inbound sets are already published to the
dataplane.

---

## 7. Risk table

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|-----------|
| R1 | (deferred gate) IKE gate drops a legitimate DNAT-to-self tunnel whose zone omits `ike` | Low | Tunnel fails to establish | Gate ADMITS whenever `ike`/`ipsec` configured; standard IPsec zones list it. Document the parity change. DEFERRED, so not shipped now. |
| R2 | Gating ESP/AH by mistake black-holes the data plane after IKE | Low (Option A/B keep ESP/AH ungated) | Tunnel data-plane blackhole | ESP/AH never gated; Option C rejected; pinning test asserts ESP/AH stay exempt. Raw ESP does not even reach Stage 11 (F1). |
| R3 | (deferred gate) Ingress-zone resolution wrong at Stage 11: raw physical ifindex != logical/unit zone; `ingress_zone_override` not plumbed; GRE-inner zone is the tunnel's (Codex M6) | Medium if gate shipped naively | Mis-gate (wrong deny/admit) | Reuse the resolver's LOGICAL ifindex path (`poll_stages.rs:337-350`, `mod.rs:1471-1481`) + plumb `ingress_zone_override` + handle GRE-inner tunnel zone; unit-test VLAN + GRE-inner. DEFERRED. |
| R4 | L15 non-zero ifindex changes reinject ROUTING, not just telemetry | Confirmed real | Mis-delivery of IPsec-to-self | AGY M2/minor: `slow_path.rs:213-222` routes a LocalDelivery reinject on `local_ifindex` (>0 → `local_tunnel_deliveries` lookup, diverts from TUN). Fix keeps `local_ifindex`=0; carry the real ifindex ONLY in the telemetry/exception record. |
| R5 | (deferred gate) New IKE-deny counter breaks a Go/Rust contract test | Low | Build RED | Check for a host-inbound-deny-counter contract test before adding; mirror both sides if present. DEFERRED. |
| R6 | IPv6 AH never sets protocol==51 (shim walks NEXTHDR_AUTH) so v6 AH is invisible to Stage 11 | Certain (documented) | None | v6 AH-to-self rides the local-dest shunt to the kernel; document, do not gate. Pinning tests scope AH to IPv4. |
| R7 | Hot-path regression from the L15/telemetry change or (deferred) gate | Very low | Throughput | Both touch only `is_ipsec_traffic` packets (rare); no change to the common datapath instruction path. Smoke iperf3 to confirm at /engineer. |
| R8 | (deferred gate) Naive IKE gate drops established/return IKE (e.g. reply for a firewall-initiated tunnel) | Medium if gate shipped carelessly | Tunnel breakage | AGY M2: kernel does `ct established,related accept` FIRST (`daemon_nft.go:380`). The Stage-11 gate MUST admit established/related before the zone check (OQ5). This risk is why the gate is DEFERRED, not shipped. |

---

## 8. Test plan

### Unit (Rust, `cargo test` in userspace-dp)

- `is_ipsec_traffic` coverage already exists (`forwarding/tests.rs:2438-2490`).
- Option A (shipped) pinning tests: assert the RATIFIED exempt behavior — ESP/AH
  and IKE 500/4500 pass through (exempt) on a zone that omits ike/ipsec, v4 and v6.
  Fail-on-revert. (M12)
- L15: assert the synthetic `ForwardingResolution` keeps `local_ifindex`/
  `egress_ifindex`/`tx_ifindex` = 0 (so reinject routing is unchanged) and that
  the real ingress/local ifindex appears only in the telemetry/exception record.
- Option B (deferred) tests, when built: per class via `stage_ipsec_passthrough_check`
  (or an extracted testable predicate):
  - ESP/AH — always passthrough/exempt (outer), zone with and without ike.
  - IKE UDP 500 + NAT-T UDP 4500 — DENY when zone omits ike/ipsec; ADMIT when zone
    lists ike/ipsec; v4 and v6.
  - Native-GRE-inner IKE + inner ESP to a local address — gated identically on the
    tunnel's zone (Codex M1/M2).
  - Established/related IKE — ADMIT regardless of the token (R8/AGY M2).
  - Per-interface host-inbound override present → override governs.

### Cross-path parity (Go)

- Confirm the kernel chain's IKE gating + ESP/AH exemption remain asserted
  (`TestHostInboundFilterExemptsIPsecAndV6Errors`) and that the AF_XDP IKE gate
  now matches the kernel's per-zone IKE behavior (a documented-intent parity note;
  a full cross-layer contract test is optional).

### Smoke (loss userspace cluster) — for /engineer, not /research

- iperf3 baseline unchanged (gate is cold-path). `make cluster-deploy` + a
  functional IPsec establish on a zone that lists `ike` still works (tunnel up).
- Negative: a zone omitting `ike` with a DNAT-to-self-IKE rule drops IKE
  (host-inbound deny counter increments), tunnel does NOT establish — the ratified
  parity behavior.

---

## 9. Rollback plan

- Docs-only research branch — nothing to roll back for /research.
- For the eventual PR: the change is isolated to `stage_ipsec_passthrough_check`
  + docs + tests. Revert is a single-commit `git revert`. The gate is
  additive-behind-`is_ipsec_traffic`; reverting restores the always-passthrough.
  No control-plane / wire-format change, so no cross-version coupling.

---

## 10. Blast radius / affected surfaces

- Datapath: only IPsec packets that reach userspace-dp Stage 11 (secondary
  NAT-to-self / interface-NAT path). Common transit + direct-to-self IPsec (kernel
  path) unaffected.
- No Go control-plane, gRPC, wire-format, or config-schema change (Option B).
- HA: none — Stage 11 runs per-worker on ingress; no session-sync / VRRP / fabric
  interaction. No `test-failover` gate triggered (no cluster/VRRP/session-sync
  code touched), though a cluster smoke is prudent at /engineer.
- Docs: forwarding README + userspace-dataplane-architecture + host_inbound.rs
  comment.

---

## 11. Open questions / decision points

1. **Gate IKE (Option B) or ratify-all (Option A)?** — RESOLVED for now: ship
   Option A, DEFER the IKE gate (Option B). Reopen the gate if a real
   DNAT-to-self-IKE deployment or a stricter parity mandate arrives.
2. **L15 ifindex — RESOLVED telemetry-only.** `slow_path.rs:213-222` routes on
   `local_ifindex`; the fix keeps it 0 and carries the real ifindex only in the
   telemetry/exception record (R4).
3. **IKE-deny counter** — (deferred gate) reuse `xpf_host_inbound_denies_total` or
   add a scoped IPsec-deny counter? Prefer reuse to avoid a new Go/Rust contract
   surface (R5).
4. **v6 AH** — confirmed out of scope: the shim walks NEXTHDR_AUTH so protocol
   never surfaces as 51 on v6; v6 AH-to-self rides the local-dest shunt. Document,
   do not gate (R6).
5. **(deferred gate) Established/related signal at Stage 11.** To gate NEW IKE
   without dropping return/established IKE (R8/AGY M2), the gate needs a reliable
   established/related flag at Stage 11. Determine whether the `flow: Option<&Session
   Flow>` at `poll_stages.rs:682` already carries conntrack state, or whether the
   gate must run after session resolution (which would move it out of Stage 11).
   This is a primary reason the gate is deferred rather than shipped.
6. **(deferred gate) Native-GRE-inner ingress zone.** For inner IPsec that arrived
   in a native GRE tunnel (Codex M1/M2), which zone governs host-inbound — the GRE
   tunnel's zone or the physical netdev's? The gate must key on the tunnel's
   logical zone. Confirm how the resolver derives the zone for GRE-decapped inner
   packets (`stage_native_gre_decap` at `mod.rs:495-502` + the logical-ifindex
   resolution) before wiring the gate.

---

## Appendix — evidence index

- Stage 11 call site + ordering: `poll_descriptor/mod.rs:566-575`, `:584`.
- Stage 11 body + synthetic decision (L15 zeros): `poll_stages.rs:674-715`
  (`:691-693`).
- Stage 11 has no local-dest/DNAT predicate: `poll_stages.rs:682-686`.
- `is_ipsec_traffic`: `forwarding/mod.rs:1059-1063`.
- Host-inbound gate on local-delivery: `poll_descriptor/filter.rs:435-473`
  (`:452`); session-HIT call `mod.rs:827-849`, session-MISS call `mod.rs:1713-1734`.
- Native-GRE-inner local delivery → XSK (NOT kernel): `userspace-xdp/src/lib.rs:844`
  (`USERSPACE_LOCAL_V4`), `:976` (`USERSPACE_LOCAL_V6`); dispatch arm `:636-658`;
  userspace GRE decap before Stage 11: `poll_descriptor/mod.rs:495-502`.
- Logical-ifindex zone resolution the gate must reuse: `poll_stages.rs:337-350`,
  `mod.rs:1471-1481`.
- ike/ipsec token classification: `forwarding/host_inbound.rs:143-146`.
- Kernel chain ESP/AH exempt + IKE per-zone gate: `pkg/daemon/daemon_nft.go:381-411`,
  `:429-478`.
- Kernel exemption test: `pkg/daemon/host_inbound_nft_test.go:187-223`.
- Shim ESP unconditional kernel shunt (normal path, F1): `userspace-xdp/src/lib.rs:531-533`.
- Shim local-dest shunt: `userspace-xdp/src/lib.rs:611-623`. Interface-NAT-ESP
  check is degraded-path only (`is_degraded_local_or_control`): `:1024-1047`
  (`:1040`) — routes to kernel/drop, NOT the XSK.
- Kernel established-first ordering (return/reply IKE bypass): `pkg/daemon/daemon_nft.go:380`.
- L15 reinject routes on `local_ifindex`: `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:213-222`.
- Ingress-zone resolution primitives: `forwarding/mod.rs:285,1268`
  (`ifindex_to_zone_id`), `host_inbound.rs:496-512` (`host_inbound_admits_iface`).
- Forwarding README IPsec section: `forwarding/README.md:334-367`.
