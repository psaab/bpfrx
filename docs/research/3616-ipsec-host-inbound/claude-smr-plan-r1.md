# Claude SMR — HOSTILE plan review r1 — #3616

Reviewing `docs/research/3616-ipsec-host-inbound/plan.md` (r3) against
origin/master `0be2bd792`. Posture: adversarial. Goal: break the plan.

## Verdict

**PLAN-READY (Option B) with ONE required accuracy correction (F1).** Pure
Option A (ratify + doc + L15 + tests, defer the IKE gate) is a defensible
PLAN-DEFER given the near-nil exposure; NOT PLAN-KILL. The recommendation and
architecture survive hostile review; one provenance claim is wrong and must be
fixed before this is engineered.

## What I tried to break, and what held

1. **"Direct IKE-to-self is shunted to the kernel, gated there."** Held.
   `userspace-xdp/src/lib.rs:611-623` passes a session-miss local-destination
   packet to the kernel (`cpumap_or_pass`); the kernel chain
   (`daemon_nft.go:408-411,468-477`) gates IKE on the per-zone `ike` token +
   catch-all drop. `host_inbound_nft_test.go:187-223` pins the ESP/AH exemption.
   The primary path genuinely has Junos parity for IKE.

2. **"Gating IKE at Stage 11 is feasible."** Held. `meta.ingress_ifindex` is set
   at Stage 11; `ingress_zone_override` is computed at stage 9
   (`poll_descriptor/mod.rs:526-529`); `ForwardingState.ifindex_to_zone_id`
   (used at `forwarding/mod.rs:285,1268`) resolves the zone;
   `host_inbound_admits_iface` (`host_inbound.rs:496-512`) already honours the
   per-interface override. The `flow` is `Some` before the check
   (`poll_stages.rs:682-684`) so `dst_port` is available.

3. **"Gating IKE won't break configured tunnels."** Held with the R1 caveat.
   The gate admits whenever `ike`/`ipsec` is configured — the standard external-
   zone config. The only behavior change is dropping DNAT-to-self IKE on a zone
   that never opened `ike`, which is the intended Junos-parity outcome.

4. **PLAN-KILL?** Rejected. The ESP/AH exemption being correct-by-design does
   NOT make the whole issue moot: the IKE divergence is real, the L15 telemetry
   gap is real, and the recurring audit flag needs a ratified answer + pinning
   test. Killing leaves all three unresolved.

## Findings

### F1 (MAJOR — accuracy). The plan overstates that interface-NAT ESP reaches Stage 11.

`userspace-xdp/src/lib.rs:531-533` shunts **ALL ESP (proto 50) unconditionally**
to the kernel in the normal datapath, BEFORE the session-action logic
(`:574+`). The interface-NAT-ESP check the plan cites (`:1040`,
`PROTO_ESP && is_interface_nat_destination`) lives inside
`is_degraded_local_or_control` (`:1024-1047`), which is only consulted on the
HEARTBEAT-STALE degraded path (`:519`). So in the normal path **raw ESP
essentially never reaches userspace-dp Stage 11** — the ESP arm of
`is_ipsec_traffic` is defensive/near-dead for ESP.

Impact on the plan: this STRENGTHENS "ratify ESP/AH" (Stage 11's ESP handling is
moot), but §2.5 and §7/R2 and the Appendix imply interface-NAT ESP routinely
reaches the XSK. Correct the exposure model: **ESP → kernel (shim :531), so ESP
does not reach Stage 11 in the normal path; AH (proto 51, IPv4) reaches Stage 11
only for transit/NAT-shaped AH (it is NOT shunted at :531); IKE reaches Stage 11
only via DNAT/static-NAT-to-self.** This makes the genuine-divergence surface
even narrower (IKE + transit-shaped AH), reinforcing that the IKE gate is a
parity/consistency fix rather than a hot bypass. Also revisit whether the AH
class even needs a Stage-11 pinning test for host-inbound (AH has no port; the
gate never applies to it; the test should assert AH stays exempt/passthrough).

### F2 (MINOR). The "direct IKE-to-self never reaches Stage 11" claim depends on the shim's local-IP map being complete.

The shunt at `:611-623` fires on `is_local_destination`, which keys on a
local-address set the control plane publishes to the shim. A transiently stale /
incomplete set (e.g. a freshly added VIP not yet propagated) would let direct
IKE-to-self reach Stage 11. This widens the window slightly and is another
argument FOR the IKE gate (defence in depth) rather than against it. Add one
sentence in §3.3 acknowledging the shunt is the load-bearing assumption.

### F3 (MINOR — must-verify, already an open question). L15 ifindex must not change reinject routing.

The plan flags R4/OQ2 correctly. Reinforce: the /engineer pass MUST confirm
`maybe_reinject_slow_path_from_frame` ignores `resolution.tx_ifindex` for a
LocalDelivery synthetic decision (it should route to the slow-path TUN). SAFEST
implementation: carry the real ingress/local ifindex ONLY in the exception /
telemetry record, NOT in `ForwardingResolution`, so the fix is provably
telemetry-only regardless of the reinject internals.

### F4 (MINOR — scope). Which zone governs DNAT-to-self host-inbound is a genuine semantic choice.

Option B gates on the INGRESS zone (consistent with the existing
`host_inbound_admits_iface` model). For DNAT-to-self this is the WAN/untrust zone
the packet arrived on, not the post-NAT local address's zone. This matches how
every other service is already gated on this path, so it is the right choice —
but the plan should state it explicitly (it is only implied) so the /engineer
pass does not "fix" it into keying on the translated address.

## Bottom line

Architecture and recommendation are sound. Fix F1 (correct the ESP/Stage-11
provenance), fold F2/F4 as one-line clarifications, and keep F3 as a hard
must-verify gate on the /engineer pass. Verdict PLAN-READY (Option B); pure-A
PLAN-DEFER acceptable.
