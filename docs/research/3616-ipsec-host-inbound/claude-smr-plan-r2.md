# Claude SMR — plan review r2 (convergence) — #3616

Reviewing `plan.md` r3 (Codex + AGY + my r1 SMR folded). Posture: confirm the
revision actually closed the r1 findings and re-attack the new exposure model.

## Verdict

**PLAN-READY (Option A: ratify + document + telemetry-only L15 + per-class pinning
tests) with the IKE/inner-ESP host-inbound gate (Option B) DEFERRED as specced
hardening.** Not PLAN-KILL. The plan now correctly models the exposure and the
risks; the shipped scope is low-risk, well-defined, and terminates the audit flag.

## r1 findings — closure check

- SMR F1 / AGY M1 (outer ESP never reaches Stage 11): folded — §2.5 now states
  outer ESP → kernel (`lib.rs:531`), inner ESP over native GRE → Stage 11.
- Codex M1/M2 (native-GRE-inner local IPsec reaches Stage 11): folded — verified
  independently: `classify_native_gre_inner_ipv4/_ipv6` return REDIRECT (to XSK)
  for `USERSPACE_LOCAL_V4/_V6` hits (`lib.rs:844`/`:976`), decap at `mod.rs:501`,
  then Stage 11. The "direct IKE-to-self always shunted to kernel" claim is fixed.
- AGY M2 (established/return IKE dropped by naive gate): folded — R8 + OQ5; the
  decisive reason the gate is deferred, and Option B now requires established-first.
- SMR F3 / AGY minor / Codex M5 (L15 not telemetry-free): folded — §6 + R4 keep
  `local_ifindex`=0 (slow_path.rs:213-224 routes on it); real ifindex only in the
  telemetry record.
- Codex M6 (zone resolution underspecified): folded — §3.4/§4/§6/R3/OQ6 now require
  the logical-ifindex resolution + `ingress_zone_override` plumb + GRE-inner zone.
- Codex minors (line refs, Junos-SA attribution): folded — 827-849/1713-1734;
  §3.1 attributes the SA claim to repo comments + kernel test, flagged for Junos
  doc confirmation at /engineer.

## Re-attack on the r3 model

1. **Does the broader exposure (native-GRE-inner) flip the recommendation to ship
   the gate now?** No. It strengthens the eventual security case, but Codex M6 +
   AGY M2 show the gate is non-trivial (established-first ordering, logical/GRE-
   inner zone, `ingress_zone_override` plumbing) and mis-implementation drops live
   tunnels (R8/R3). Shipping the low-risk ratify+doc+L15+tests now and deferring
   the gate with a concrete spec is the proportionate call the issue explicitly
   sanctions ("PLAN-DEFER acceptable if gating risks breaking tunnels").

2. **Is Option A actually shippable without touching the gate?** Yes. Items 1-5 of
   §6 (L15 telemetry-only, docs ×2, comment clarify, exempt-pinning tests) are
   independent of the gate and need no Go control-plane change.

3. **Is this genuinely a security bypass?** Yes, narrow and config-gated: native
   GRE + inner IPsec-to-self on a zone omitting `ike`/`ipsec` bypasses the host-
   inbound enforcement the kernel path otherwise applies. It is NOT a broad
   management-plane hole (outer direct IPsec-to-self is kernel-gated), and no
   shipped config exercises it. Severity Medium is right.

## Residual nits (non-blocking, for /engineer)

- Confirm OQ5 empirically: whether `flow` at `poll_stages.rs:682` carries a
  usable established/related signal, else the gate moves after session resolution.
- Confirm OQ6: the zone the resolver assigns to GRE-decapped inner packets.

Both are explicitly captured as open questions gating the deferred Option B, not
the shipped Option A. Converged.
