# Plan of Action — #3616: IPsec/IKE/ESP/AH passthrough (Stage 11) vs host-inbound enforcement

- Issue: #3616 (`userspace-dp: IPsec/IKE/ESP/AH passthrough (Stage 11) bypasses
  per-zone host-inbound service enforcement — decide + pin vSRX parity`)
- Base: origin/master `0be2bd792`
- Branch: `research/3616-ipsec-host-inbound`
- Mode: `/research` — STOP at PLAN-READY / PLAN-DEFER / PLAN-KILL. No code, no PR.
- Revision: **r3 (converged)**

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
design and already ratified + tested on the kernel path. The one genuine
divergence is IKE (UDP 500/4500), and even that is confined to a SECONDARY path
(DNAT/static-NAT-to-self) that ordinary IKE-to-self never traverses. This is a
narrow, real parity gap for IKE — not a broad bypass.

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
  AFTER resolution (mod.rs ~756-847 / ~941). Because Stage 11 short-circuits and
  `continue`s the loop, `host_inbound_admits_iface` NEVER runs for a packet Stage
  11 claims. **Bypass confirmed by ordering.**

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
    kernel unconditionally** (`cpumap_or_pass`), before any XSK redirect.
  - `userspace-xdp/src/lib.rs:611-623` — a session-miss packet with
    `is_local_destination()` true (e.g. IKE UDP 500/4500 to an interface IP / VIP,
    IPv4 AH-to-self) is `PASS_TO_KERNEL`.
  - So genuine, direct host-bound IPsec-to-self is handled by the KERNEL chain,
    not by userspace-dp Stage 11.
  - The kernel chain (`daemon_nft.go:381-392 buildHostInboundFilterPayload`):
    `meta l4proto { 50, 51 } accept` — raw ESP/AH are GLOBALLY exempt (accepted
    before any per-zone drop). IKE UDP 500/4500 is NOT globally exempt: it is
    gated on the per-zone `ike` token via `emitHostInboundZone` (per-match accept +
    catch-all `drop`). **The kernel path correctly gates IKE on `system-services
    ike` — Junos parity holds on the primary path.**
  - This exemption is deliberate and regression-guarded:
    `pkg/daemon/host_inbound_nft_test.go:187 TestHostInboundFilterExemptsIPsecAndV6Errors`
    asserts `meta l4proto { 50, 51 } accept` is present AND precedes every per-zone
    drop (fail-on-revert).

- **SECONDARY path — AF_XDP Stage 11** (userspace-dp). Reached ONLY when IPsec
  traffic is NOT shunted by the shim, i.e. it is NOT a plain local destination:
  - DNAT / static-NAT-to-self: outer dst is a non-local address that a
    prerouting NAT rule rewrites to a local IP. The shim's `is_local_destination`
    keys on the arriving (pre-NAT) dst, so it does NOT shunt; the packet reaches
    the XSK and Stage 11 fires.
  - Interface-NAT ESP: `userspace-xdp/src/lib.rs:627-630` and `:1040`
    (`PROTO_ESP && is_interface_nat_destination`) route interface-NAT ESP to the
    XSK rather than the kernel.
  - Transit-shaped AH that is actually host-terminated after NAT.
  - On this secondary path, Stage 11 exempts IKE/ESP/AH from host-inbound
    entirely — the behavior the issue flags.

**Net:** the "bypass" the issue describes exists only on the SECONDARY
(NAT-to-self / interface-NAT) path. Direct IKE/ESP/AH to an interface IP or VIP —
the case an operator means when they write `system-services ike` — is enforced by
the kernel chain, where IKE IS gated. For ESP/AH the exemption is intentional and
consistent across BOTH paths.

---

## 3. Root-cause / parity analysis

### 3.1 Is the ESP/AH exemption correct Junos parity?

Yes. In Junos/vSRX the IPsec data plane (ESP/AH) is authorized by the negotiated
IKE/IPsec SA, not by a separate host-inbound service. The standard external-zone
config is `host-inbound-traffic { system-services { ike; } }` — `ike` alone; ESP
is implicitly permitted once the tunnel negotiates. xpf mirrors exactly this: the
kernel chain accepts raw ESP/AH globally and gates IKE on `ike`. Gating raw ESP/AH
on a token would break the tunnel data plane AFTER IKE succeeded (a silent
black-hole) and diverges from Junos. The ESP/AH exemption is therefore
correct-by-design and should be RATIFIED, not gated.

### 3.2 Is the IKE exemption on Stage 11 a genuine bypass?

Yes, but narrow. `host-inbound-traffic system-services ike` is a real Junos knob;
a zone that omits it should drop IKE to the box. The kernel path enforces this.
Stage 11 does not — so a DNAT/static-NAT-to-self IKE flow reaches strongSwan even
on a zone that never opened `ike`. It IS a real host-inbound divergence for IKE,
and it IS an inconsistency between xpf's own two paths (kernel enforces, AF_XDP
does not), which is exactly why audits keep re-flagging it.

### 3.3 How narrow is the realistic exposure?

Very. To reach Stage 11 with IKE an operator must (a) configure DNAT / static-NAT
translating some external tuple to a local IP on UDP 500/4500, AND (b) omit
`system-services ike`/`ipsec` on the ingress zone, AND (c) expect (b) to block it.
Genuine direct IKE-to-self never reaches Stage 11 (shim shunt → kernel → gated).
No repo config exercises DNAT-to-self-IKE. So the exposure is an edge-of-edge
case, not a broad management-plane hole. This is why the issue is Severity:Medium
(design decision), and why PLAN-DEFER of the IKE gate is defensible.

### 3.4 Feasibility of gating IKE at Stage 11

Feasible and cheap. At Stage 11 `meta.ingress_ifindex` is set and the fabric
ingress override (`ingress_zone_override`) is already computed (stage 9, mod.rs
:526-529). `ForwardingState.ifindex_to_zone_id` (types/forwarding.rs; used at
forwarding/mod.rs:285,1268) resolves the ingress zone from the ifindex, and
`host_inbound_admits_iface(state, ingress_ifindex, zone_id, PROTO_UDP, dst_port,
is_v6, 0)` already exists and honours per-interface overrides. The gate runs only
when `is_ipsec_traffic` is true (rare), so there is no per-packet hot-path cost on
the common datapath. Gating admits whenever `ike`/`ipsec` is configured (the
standard case), so it does not break configured tunnels.

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

### Option B — Ratify ESP/AH, GATE IKE at Stage 11 (hybrid; recommended)

- Ratify + document the ESP/AH exemption (as Option A) — it is correct-by-design
  and kernel-consistent.
- For the IKE sub-case ONLY (UDP 500/4500), run a host-inbound admit BEFORE the
  passthrough reinject:
  - Resolve `zone_id` from `ingress_zone_override.or(ifindex_to_zone_id[ingress_ifindex])`.
  - `if host_inbound_admits_iface(fw, ingress_ifindex, zone_id, PROTO_UDP,
    dst_port, is_v6, 0)` → passthrough reinject (as today).
  - else → drop the IKE frame (silent, Junos posture), count a host-inbound deny
    (reuse the existing `xpf_host_inbound_denies_total` path / a scoped counter),
    and `RecycleAndContinue`.
- ESP/AH keep the unconditional passthrough (no gate) — SA is the authorization.
- Fix L15 (carry real ifindex into the synthetic decision) for both arms.
- Add per-class pinning tests (M12): ESP admitted/exempt, AH admitted/exempt, IKE
  500 + NAT-T 4500 DENIED when the zone omits ike/ipsec and ADMITTED when it lists
  ike/ipsec, on both v4 and v6.

- Pro: exact Junos + kernel-path parity for IKE; closes the genuine (if narrow)
  divergence; admits-when-configured so tunnels do not break; small, cold-path
  change; kills the recurring audit flag with actual parity.
- Con: a new (narrow) drop behavior — a DNAT-to-self IKE flow on a zone that omits
  `ike` now drops (this is the INTENDED parity change, but it IS a behavior
  change); needs the ingress-zone resolution wired at Stage 11; a contrived
  DNAT-to-self-IPsec deployment that relied on the prior always-pass would need to
  add `system-services ike` (correct Junos behavior anyway).

### Option C — Gate ESP/AH too (full option (a))

Gate every IPsec class (ESP/AH/IKE) on the ike/ipsec tokens before passthrough.

- REJECTED. Gating raw ESP/AH breaks the tunnel data plane after IKE succeeds,
  diverges from Junos (SA is the authorization) AND from xpf's own tested kernel
  exemption (`TestHostInboundFilterExemptsIPsecAndV6Errors`). This is the
  black-hole the kernel comment at `daemon_nft.go:388-391` explicitly warns
  against. Not viable.

---

## 5. Recommendation

**Option B (hybrid).** SECURITY-weighted, the IKE divergence is a real
host-inbound parity gap and an internal kernel-vs-AF_XDP inconsistency; the fix is
a small, cold-path, admit-when-configured gate that cannot break a correctly
configured tunnel. Ratifying ESP/AH is correct-by-design and already true on the
kernel path. Option B closes the genuine gap AND documents the intentional part,
so the audit finding terminates on parity rather than on a doc-only waiver.

**PLAN-DEFER of the IKE gate to Option A is acceptable** if the reviewers judge the
DNAT-to-self-IKE exposure too narrow to warrant a new drop path — in that case
ship the ratify + doc + L15 + exempt-pinning-tests half now and leave the IKE gate
as a documented, deferred hardening. Either way, L15 + the per-class pinning tests
(M12) ship.

**Not PLAN-KILL:** the issue is a legitimate parity decision that needs an
explicit ratified answer + a pinning test; killing it would leave the recurring
audit flag and the L15 telemetry gap unresolved.

---

## 6. Implementation plan (for the eventual /engineer pass — NOT executed here)

Files (Option B):

1. `userspace-dp/src/afxdp/poll_stages.rs`
   - `stage_ipsec_passthrough_check`: split the IKE sub-case from ESP/AH. For
     UDP 500/4500, resolve the ingress zone and call `host_inbound_admits_iface`;
     on deny, count + `RecycleAndContinue` without reinject. ESP/AH keep the
     unconditional reinject.
   - Populate `local_ifindex`/`egress_ifindex`/`tx_ifindex` in the synthetic
     `ForwardingResolution` from the resolved local/ingress interface (L15) for
     both arms. (Confirm the reinject path's expectations for a LocalDelivery
     synthetic decision so a non-zero ifindex does not change reinject routing —
     it should only enrich telemetry.)
   - The stage needs access to `worker_ctx.forwarding` (already passed) for
     `ifindex_to_zone_id` + `host_inbound_admits_iface`, and `meta` (present).
2. `userspace-dp/src/afxdp/forwarding/host_inbound.rs` — comment update at the
   `ike`/`ipsec` arm (the token now genuinely gates IKE on the AF_XDP path too).
3. `userspace-dp/src/afxdp/forwarding/README.md` "Host-terminated IPsec
   passthrough" — document the ratified ESP/AH exemption + the IKE gate + the
   two-path (kernel primary / AF_XDP secondary) model.
4. `docs/userspace-dataplane-architecture.md` — add the IPsec host-inbound
   semantics + the two-path model.
5. Tests: `poll_stages.rs` (or `forwarding/tests.rs`) per-class pinning tests
   (M12). If a counter is added for the IKE deny, keep the Go/Rust screen-flag /
   metric contract in lockstep (see MEMORY: screen-flag cross-package contract) —
   verify no analogous contract test governs host-inbound deny counters before
   adding one.

Option A subset: items 3-5 (exempt-pinning tests) + L15 only; skip the gate in 1
and the comment flip in 2.

No Go control-plane change is required for Option B: `ifindex_to_zone_id` and the
per-zone/per-interface host-inbound sets are already published to the dataplane.

---

## 7. Risk table

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|-----------|
| R1 | IKE gate drops a legitimate DNAT-to-self tunnel whose zone omits `ike` | Low | Tunnel fails to establish | Gate ADMITS whenever `ike`/`ipsec` configured; standard IPsec zones list it. Document the parity change; a contrived deployment adds `ike` (correct Junos). |
| R2 | Gating ESP/AH by mistake black-holes the data plane after IKE | Low (Option B keeps ESP/AH ungated) | Tunnel data-plane blackhole | Option B never gates ESP/AH; Option C explicitly rejected; pinning test asserts ESP/AH stay exempt. |
| R3 | Ingress-zone resolution wrong at Stage 11 (override vs ifindex map) → wrong admit/deny | Low | Mis-gate | Reuse the exact resolution the resolver uses (`ingress_zone_override.or(ifindex_to_zone_id)`); unit-test both branches. |
| R4 | L15 non-zero ifindex changes reinject routing (not just telemetry) | Low | Mis-delivery of IPsec-to-self | Verify `maybe_reinject_slow_path_from_frame` uses the TUN/slow-path, not the resolution's tx_ifindex, for LocalDelivery; keep change telemetry-only if it does. |
| R5 | New IKE-deny counter breaks a Go/Rust contract test | Low | Build RED | Check for a host-inbound-deny-counter contract test before adding; if present, mirror both sides (MEMORY: screen-flag / raw-event contract). |
| R6 | Over-scoping: IPv6 AH never sets protocol==51 (shim walks NEXTHDR_AUTH) so an "AH gate" would be dead on v6 | Certain (documented) | None (Option B does not gate AH) | Document that AH gating is not attempted; v6 AH-to-self rides the local-dest shunt to the kernel. |
| R7 | Hot-path regression from the new gate | Very low | Throughput | Gate runs only when `is_ipsec_traffic` (rare); no change to the common datapath instruction path. Smoke iperf3 to confirm. |

---

## 8. Test plan

### Unit (Rust, `cargo test` in userspace-dp)

- `is_ipsec_traffic` coverage already exists (`forwarding/tests.rs:2438-2490`).
- Option B new: drive `stage_ipsec_passthrough_check` (or a extracted testable
  predicate) per class:
  - ESP (proto 50) — always passthrough/exempt, zone with and without ike. (M12)
  - AH (proto 51, v4) — always passthrough/exempt. (M12)
  - IKE UDP 500 — DENY when zone omits ike/ipsec; ADMIT (passthrough) when zone
    lists ike or ipsec; v4 and v6. (M12)
  - NAT-T UDP 4500 — same as IKE 500. (M12)
  - Per-interface host-inbound override present → override governs (parity with
    `host_inbound_admits_iface`).
- L15: assert the synthetic decision carries the resolved ingress/local ifindex
  (non-zero) for a passthrough packet.

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

1. **Gate IKE (Option B) or ratify-all (Option A)?** — the core reviewer decision.
   Recommendation: Option B, with Option A as an acceptable PLAN-DEFER of the gate
   half. SECURITY-weighted toward B; exposure-narrowness admits A.
2. **L15 ifindex — telemetry-only?** Confirm a non-zero `tx_ifindex`/`egress_ifindex`
   in the synthetic LocalDelivery decision does not alter reinject routing (R4). If
   it could, carry the real ifindex ONLY in the telemetry/exception record, not in
   the `ForwardingResolution`.
3. **IKE-deny counter** — reuse `xpf_host_inbound_denies_total` or add a scoped
   IPsec-deny counter? Prefer reuse to avoid a new Go/Rust contract surface (R5).
4. **v6 AH** — confirmed out of scope: the shim walks NEXTHDR_AUTH so protocol
   never surfaces as 51 on v6; v6 AH-to-self rides the local-dest shunt. Document,
   do not gate (R6).

---

## Appendix — evidence index

- Stage 11 call site + ordering: `poll_descriptor/mod.rs:566-575`, `:584`.
- Stage 11 body + synthetic decision (L15 zeros): `poll_stages.rs:674-715`
  (`:691-693`).
- `is_ipsec_traffic`: `forwarding/mod.rs:1059-1063`.
- Host-inbound gate on local-delivery: `poll_descriptor/filter.rs:435-473`
  (`:452`).
- ike/ipsec token classification: `forwarding/host_inbound.rs:143-146`.
- Kernel chain ESP/AH exempt + IKE per-zone gate: `pkg/daemon/daemon_nft.go:381-411`,
  `:429-478`.
- Kernel exemption test: `pkg/daemon/host_inbound_nft_test.go:187-223`.
- Shim ESP unconditional kernel shunt: `userspace-xdp/src/lib.rs:531-533`.
- Shim local-dest / interface-NAT ESP routing: `userspace-xdp/src/lib.rs:611-630`,
  `:1037-1046`.
- Ingress-zone resolution primitives: `forwarding/mod.rs:285,1268`
  (`ifindex_to_zone_id`), `host_inbound.rs:496-512` (`host_inbound_admits_iface`).
- Forwarding README IPsec section: `forwarding/README.md:334-367`.
