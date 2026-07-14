# Triage result: ps-review-038-A1_rust_dataplane_packet-b1

- **Subsystem**: A1 Rust AF_XDP dataplane packet path, batch 1/3 (bind/UMEM setup,
  bpf_map HA sync, poll_descriptor loop, ethernet/VLAN, frame/checksum, parser/EH).
- **Base vs master**: review Base `d4506d4450e2...`; triaged against current
  `origin/master` = **cc451b6b58112328143c8afa654bdb8e48074a99** (fetched this run).
- **Provenance**: **real bpfrx** — cited symbols exist on master (verified below);
  not an avacado/confabulated tree.
- **Outcome counts**: 1 stated item → **1 NEGATIVE (coverage/informational)**;
  0 genuine residuals, 0 dup, 0 already-fixed-as-new, 0 confabulated.

## The review's own framing
This is one of three A1 sub-batches. The header (lines 7-14) is a module-by-module
walk-through and the single Findings entry (lines 18-30) is titled
**"A1_b1 batch reviewed - no new findings beyond dedup"**, Severity **Low
(informational)**, `Labels: coverage`, `Fix direction: No fix needed for this batch`.
The author explicitly states the batch is covered by other findings and dedups its
observations against #4533 (EH overflow) and #4556 (screen pending-port). There is
no crafted input, no cited unguarded file:line, no exploit claim — by construction
this is a NEGATIVE result, not a deferred finding.

## Verification of the load-bearing coverage claims

**Claim: "Parser uses MAX_IPV6_EXT_HEADERS=8 with fail-closed on overflow
(matches #4533 fix)."** CONFIRMED on master.
- `userspace-dp/src/afxdp/frame/inspect.rs:24` — `pub(in crate::afxdp) const
  MAX_IPV6_EXT_HEADERS: usize = 8;`
- The IPv6 EH walkers at inspect.rs:61, :120, :183, :257, :339 all loop
  `for _ in 0..MAX_IPV6_EXT_HEADERS` and are genuinely fail-closed: each hop uses
  `frame.get(offset..offset+N)?` (Option short-circuit), `offset.checked_add(...)?`
  (no wrap), `if frame.len() < offset { return None }` bounds re-check, `59 →
  return None` (no-next-header drop), and the post-loop bound returns `None`
  (inspect.rs:96) rather than surrendering the ext-header offset as a fake L4
  offset. This is exactly the #2292/#4533 hardened shape the review describes.
  No overflow, no fall-through, no fail-open path.

**Claim: EH overflow fixed in #4533; screen pending-port closed in #4556.** These
are this session's already-merged backlog items; the review correctly points at
closed work rather than raising anything novel. No re-file warranted.

**Structural note (not a defect):** the header lists `userspace-dp/src/parser/*`
and `userspace-dp/src/frame/*` as if top-level dirs; on master these live under
`userspace-dp/src/afxdp/` (`parser.rs`, `parser_tests.rs`, `frame/`). This is loose
path shorthand in the batch header, not a confabulation — the actual symbols
(`MAX_IPV6_EXT_HEADERS`, the frame inspect walkers, `bind.rs`, `bpf_map/`,
`poll_descriptor/`, `ethernet.rs`) all exist. The A2-style "claimed HIGH refuted by
upstream guard" and #4572 "headline already neutralized upstream" patterns do not
apply here because the batch makes no HIGH/exploit claim to refute.

## Disposition
- **F1 (only item) — "A1_b1 batch reviewed - no new findings beyond dedup"**:
  **NEGATIVE**. Self-declared informational coverage note; no actionable residual.
  The two symbols it leans on (EH walker fail-closed bound; screen pending-port) are
  verified present/closed on master. Nothing to drive.

**Genuine residuals: 0.**
