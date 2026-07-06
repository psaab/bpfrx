# AGY — HOSTILE plan review r1 — #3616

VERDICT: NEEDS-REVISION

## MAJOR

- lib.rs:531-533 / 627-630 / 1040: ESP shunting in the shim is unconditional in
  healthy mode (`:531`, cpumap_or_pass to kernel) and routes to the kernel in
  degraded mode (is_degraded_local_or_control). Raw ESP never reaches userspace-dp
  Stage 11 — the ESP arm at poll_stages.rs:675-715 is dead code for outer ESP.
  (Matches Claude SMR F1.)

- poll_stages.rs:675-715: Gating IKE at Stage 11 without checking established/related
  drops valid IKE responses for firewall-initiated tunnels when the zone omits
  `ike`. The kernel chain handles this via `ct state established,related accept`
  first (daemon_nft.go:380); Stage 11 has no such check. (The decisive
  established-first finding — R8/OQ5.)

## MINOR

- slow_path.rs:213-222: Populating local_ifindex with a non-zero value changes
  reinjection routing (triggers local_tunnel_deliveries lookup), not just telemetry.

- host_inbound.rs:496-512: imprecise plan file:line index for
  host_inbound_admits_iface (plan Appendix used 455-512; correct is 496-512).

## Disposition (all folded into plan.md r3)

- F1 corrected (outer ESP → kernel; note inner ESP over native GRE DOES reach
  Stage 11 per Codex). §2.5.
- Established-first ordering requirement added as the decisive reason to DEFER the
  gate (Option A shipped). §3.4, §4, §5, R8, OQ5.
- L15 constrained telemetry-only (local_ifindex stays 0). §6, R4.
- host_inbound_admits_iface line ref set to 496-512 in Appendix.
