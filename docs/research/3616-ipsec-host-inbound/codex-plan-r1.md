# Codex — HOSTILE plan review r1 — #3616

VERDICT: NEEDS-REVISION

Verbatim findings (against plan.md r3-pre / the r2 draft):

## MAJOR

- Stage 11 has no local-destination or DNAT-to-self predicate. It fires on all
  `is_ipsec_traffic` packets before DNAT and before the host-inbound gate, making
  the exposure substantially broader than "DNAT/static-NAT-to-self only". Sources:
  `poll_stages.rs:682-686`, `poll_descriptor/mod.rs:566-584` and `1111-1118`,
  `userspace-xdp/src/lib.rs:631-634`.

- Direct IKE-to-self CAN reach Stage 11 via native-GRE inner local delivery. XDP
  redirects v4/v6 local-map hits to XSK rather than kernel for GRE
  (`userspace-xdp/src/lib.rs:841-845`, `973-977`); userspace GRE-decaps before
  Stage 11 (`poll_descriptor/mod.rs:495-502`); Stage 11 then catches UDP/500/4500.
  The "primary path shunts direct IKE to kernel" claim is false for the GRE tunnel
  entry path.

- The interface-NAT ESP-to-XSK claim is wrong for ordinary outer ESP. XDP shunts
  parsed ESP unconditionally to kernel at `userspace-xdp/src/lib.rs:531-533` before
  the interface-NAT branch at `627-630`. The degraded-path check at `1037-1041` is
  a control/local path, not a normal XSK routing path.

- Inner ESP over native GRE can reach Stage 11 (GRE decap at `mod.rs:495-502` then
  `is_ipsec_traffic` at `forwarding/mod.rs:1059-1061`), contradicting the plan's
  ESP reachability model.

- The L15 `local_ifindex` fix is not telemetry-only.
  `maybe_reinject_slow_path_from_frame` routes through `local_tunnel_deliveries`
  and returns early when `local_ifindex > 0`
  (`tx/dispatch/slow_path.rs:213-224`), bypassing the generic slow-path enqueue at
  `253` and `283-299`. Setting the ifindex changes reinject routing, not logging.

- Option B zone resolution is underspecified. Stage 11 runs without
  `ingress_zone_override` (computed at `mod.rs:526-529` but not passed at
  `566-572`); existing host-inbound callers resolve logical ifindex first
  (`poll_stages.rs:337-350`, `mod.rs:1471-1481`). Raw
  `ifindex_to_zone_id[meta.ingress_ifindex]` is not equivalent.

## MINOR

- Host-inbound line reference near `~941` in the plan is wrong. Actual session-hit
  host-inbound call is `mod.rs:827-849`; session-miss call is `mod.rs:1713-1734`.

- Kernel ESP/AH exemption and IKE gating are source-confirmed
  (`daemon_nft.go:381-392`, `626-634`; `host_inbound_nft_test.go:181-223`), but the
  Junos SA-authorization claim rests only on repo comments and the test, not an
  independent proof.

## Disposition (all folded into plan.md r3)

- Exposure model corrected: native-GRE-inner local IPsec (IKE + inner ESP) reaches
  Stage 11 (verified: `lib.rs:844`/`:976` return REDIRECT for `USERSPACE_LOCAL_*`
  hits → XSK → decap `mod.rs:501` → Stage 11). §1, §2.1, §2.5, §3.3.
- ESP model refined: outer ESP → kernel (`:531`), inner ESP over GRE → Stage 11.
- L15: confirmed NOT telemetry-free; fix keeps `local_ifindex`=0, real ifindex in
  telemetry record only. §6, R4.
- Option B zone resolution: logical-ifindex + `ingress_zone_override` plumb +
  GRE-inner tunnel zone. §3.4, §4, §6, R3, OQ6.
- Line refs fixed (827-849 / 1713-1734). Junos SA claim attributed (§3.1).
