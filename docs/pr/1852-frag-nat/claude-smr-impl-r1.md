# Claude SMR implementation review — #1852 PR #1857 r1 (hostile)

Reviewing the implementation diff (engineer/1852-frag-nat, head 27bfda1e5).
Posture: hostile, hunting for missed mutation sites and regressions.

## Verdict: MERGE-READY (after the two review-driven fixes)

The implementation matches the converged plan. Two real gaps were found
by the external reviewers and fixed; I verified both plus the rest.

### Verified correct

- **v6 fragment predicate** (`inspect.rs`): bounded `0..6` walk, reads the
  fragment header (44) offset bits with mask `0xFFF8` — matches
  `parse_embedded_v6_l4` and `screen/extract.rs` semantics. `_ => false`
  for any non-ext next-header (so an L4 protocol = not a fragment).
- **apply_nat_ipv6**: `skip_l4_csum = nat.nptv6 || non_first_fragment`
  keeps the address byte-writes (outside the skip guard) and skips every
  v6 L4 checksum adjust; the port rewrite is separately gated. v4 mirror
  gates each adjust branch + the port rewrite, keeping the IP writes.
- **Descriptor fall-back**: `apply_rewrite_descriptor` returns `None` on a
  non-first fragment; `flow_cache_hit.rs:271` `.or_else(rewrite_forwarded_frame_in_place)`
  re-runs the generic (gated) path — not a drop. Parity preserved.
- **SNAT pre-allocation gate**: static SNAT returns first
  (`nat_exception.rs`), interface-mode returns before the gate
  (`source.rs`), the gate fires before `try_next_port` / `allocate_translation`.
  Address-only NAT keeps working on fragments; only port-translating pool
  allocation is refused (drop + counted).
- **clamp_tcp_mss**: self-gates fragments (both families) and derives the
  v6 offset via the ext-aware helper; the shared
  `packet_rel_l4_offset_and_protocol` is unchanged (GRE/tunnel forward
  fragments unaffected).
- **embedded ICMPv4**: parse + builder both gate the quoted-fragment case.

### Review-driven fixes (both confirmed)

1. **SNAT gate frame (Codex H1 / AGY)** — initial commit used `raw_frame`;
   for a GRE-decapped inner fragment that is the OUTER packet. Fixed to
   `packet_frame` (the decap-aware effective frame) at both call sites
   (commit 71dc6827f). The rewrite-leaf gate was already correct (computes
   from the rewritten packet); this aligns the leak gate with it.
2. **Forced tunnel L4 recompute (Codex H2)** — the copy builder's
   `force_tunnel_l4_recompute` block ran a full L4 recompute at
   rel_l4+16/+6 regardless of the fragment gate, re-corrupting payload on
   tunnel egress. Fixed: gated with `!non_first_fragment` in both build
   arms + a build-path regression test (commit 27bfda1e5).

### Residual scan (no further blockers)

- I re-checked every `recompute_l4_checksum_*` / `enforce_expected_ports*`
  / `apply_nat_*` / port-write site in the diff. The segmentation builders
  pass `non_first_fragment=false` but are protected by the admission gate
  (`forwarded_tcp_may_need_segmentation` refuses non-first fragments) — a
  non-first fragment never reaches them. The build/in-place/descriptor/
  slow paths all gate. No unguarded L4 write remains.
- Non-fragmented + offset-0/atomic traffic is byte-identical (the predicate
  returns false; all gates are no-ops).

## Bottom line

MERGE-READY from the SMR seat after the two fixes. Pending Codex r2 +
AGY r2 confirmation of the tunnel-recompute fix and Copilot.
