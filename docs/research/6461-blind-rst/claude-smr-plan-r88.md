# Claude SMR hostile plan-review — round 88 (v10.4.1 fold verification)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I authored the
v10.4.1 re-entry fold; this pass attacks it. Verdict: **PLAN NO for
v10.4.1-as-first-written** — three precision nits (all folded
in-revision); no LOW or above. Codex r87's findings are individually
verified against the code; both retreats now hold accepted status from
Codex itself.

## Codex r87 finding verification (against this branch's code)

- **r87-1 (split transaction) — CONFIRMED and closed by the fold.**
  `poll_descriptor/mod.rs:4662` clones the stored decision into
  `pending_decision`, but the epilogue at `:5126` passes the separate
  outer decision to reinjection, which applies the supplied NAT before
  enqueueing (`slow_path.rs:199`). Under v10.4.0's "discard the NAT"
  the two decision objects could diverge (P1 vs P2) across paths. The
  v10.4.1 re-entry makes the miss-derived decision the ONLY object —
  install, publication, buffering, replay, and reinjection all consume
  it by construction.
- **r87-2 (DNAT erasure) — CONFIRMED and closed by the fold.**
  `is_translated_forward_session_key` (`promote.rs:32`) accepts
  `rewrite_src == key.src_ip || rewrite_dst == key.dst_ip` —
  address-only, port-blind; DNAT same-address port remapping exists
  (`destination.rs:699`). "Clear the stored NAT" could strand
  `rewrite_dst_port`. Full post-resolve miss-decision re-entry
  recomputes the complete current pre-routing NAT
  (`poll_descriptor/mod.rs:1014`) from the packet — the stored decision
  is used for nothing but provenance.
- **r86-5 reciprocity (RESOLVED by Codex) and both retreats (ACCEPTED
  by Codex) re-verified** — `NatDecision::reverse` (`nat/mod.rs:105`)
  and `reverse_session_key` (`session/key.rs:173`) round-trip the
  SNAT/hairpin/NPTv6/NAT64 families; the second retreat leaves the seed
  lifecycle byte-identical to master with the carve-out HA-safe by
  construction (no peer copy).

## Finding 1 (nit — "re-enters the pipeline" needed scoping)

The first v10.4.1 text said the packet "goes through the cold/miss
pipeline" unscoped — readable as re-running the FULL packet pipeline
(screens, flow parse, session lookup), which would double-fire screen
counters and re-run the lookup for the purged class. Folded: re-entry
is at the POST-RESOLVE miss-decision stage (zones, pre-routing DNAT,
policy, SNAT, guard, install); the upstream pipeline does not re-run.

## Finding 2 (nit — §9's bullet (c) still described the v10.4.0 semantics)

The §9 site-9 test bullet still said "runs the FULL seed transaction";
folded to assert the re-entry semantics: DNAT port-remap preservation,
`P2 != P1` owned install, no-longer-matches → no translation,
deterministic reacquire through the allocator, sole-decision
consumption across install/publication/buffering/replay/reinjection,
and no upstream re-run.

## Finding 3 (nit — two stale "clean baseline" references)

§5.2(iii)'s pointer and the §9 test heading still said "clean pre-SNAT
baseline" (the v10.4.0 name); folded to "cold/miss re-entry" for
terminological consistency (the §11 question already used it).

## Bottom line

The purged-class corner is now expressed as ONE uniform semantic
(miss-decision re-entry from the packet, sole decision object) instead
of a patch on the stored decision — the same class of simplification as
the two retreats, and it eliminates the two r87 BLOCKERs by
construction rather than by added guards. The plan's shipped scope has
been stable in shape for three rounds; the findings have descended from
BLOCKERs in the gate's constructor paths (r83) to BLOCKERs in a
documented corner's decision plumbing (r87) to editorials. Three nits
folded. If Codex r88 verifies and finds nothing new at LOW+, this plan
is at convergence.
