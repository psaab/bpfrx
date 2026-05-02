# #989 — L4 protocol specialization (frame/tcp.rs, frame/udp.rs)

## Status

REV-3 — addresses Codex + Gemini round-2 feedback.

Round-2 deltas (rev-2 → rev-3):
- §2.2: drop the bogus "five extracted functions" / `packet_tcp_flags`
  visibility-widening sentence. Rev-2 already moved to 6 functions;
  this fixes the doc drift Codex flagged.
- §2.2.1 (NEW): inventory exclusions for two TCP-flag-touching
  forwarding-policy branches (`cluster_peer_return_fast_path` and
  `should_cache_local_delivery_session_on_miss`). They are
  forwarding policy with embedded protocol checks, not TCP
  helpers. Out of scope here.
- §2.3: `clamp_tcp_mss` test coverage expanded from 3 cases to 8,
  covering MSS-not-at-start, malformed option lengths, IPv6
  pseudo-header recompute, multiple MSS options, EOL before MSS,
  and the non-SYN no-op path.
- Acceptance gate: add `#[inline]` to all 6 relocated functions
  to close Gemini's codegen-units > 1 inlining concern.

Earlier round-1 asks remain addressed:
- Inventory was extended 4 → 6 functions (rev-2).
- `frame/tcp_segmentation.rs` documented as already-isolated.
- `inspect.rs` claim walked back to "IP-header inspection plus
  L4-tuple parsing".

Round-1 asks (both reviewers, consistent):
- Inventory was incomplete: `frame_has_tcp_rst`, `extract_tcp_window`,
  and the existing `frame/tcp_segmentation.rs` were not listed.
- The "inspect.rs becomes purely IP-header-level" claim was overreach —
  L4 parsing (`parse_flow_ports`) and ICMP-id handling stay there.
- Need targeted unit tests for the relocated functions, especially
  `clamp_tcp_mss` checksum behavior, in this PR.

Rev-2 changes: extend the move scope to include `frame_has_tcp_rst`
and `extract_tcp_window`; document `frame/tcp_segmentation.rs` as
already-isolated; walk back the inspect.rs scope claim; add a
colocated `frame/tcp_tests.rs` covering all 6 relocated functions.

## Background

The issue #989 proposes four new modules: `frame/tcp.rs`,
`frame/udp.rs`, `frame/icmp.rs`, `frame/arp.rs`. After surveying
the current tree, two of the four are already substantially in
place under different names:

| Issue's proposed module | Existing equivalent              | Action |
|------------------------|---------------------------------|--------|
| `frame/icmp.rs`        | `afxdp/icmp.rs` + `afxdp/icmp_embed.rs` | Skip — already isolated |
| `frame/arp.rs`         | `afxdp/parser.rs::classify_arp` + `afxdp/neighbor.rs` | Skip — already isolated |
| `frame/tcp.rs`         | scattered (see §1.1)            | EXTRACT |
| `frame/udp.rs`         | scattered (see §1.2)            | EXTRACT (smaller — minor cohesion gain) |

Scope reduction is intentional. The issue's "Implementation Plan"
predates the icmp.rs / icmp_embed.rs / parser.rs splits. Re-doing
work already shipped just churns blame. This PR ships the two
genuine extractions; ICMP/ARP cohesion is documented as
already-satisfied.

### 1.1 Current TCP-specific call sites (the scattered surface)

| File                                  | Function                              | LOC   | What it owns |
|---------------------------------------|---------------------------------------|-------|--------------|
| `afxdp/forwarding/mod.rs:660`         | `effective_tcp_mss`                   | ~20   | MSS policy lookup |
| `afxdp/forwarding/mod.rs:713`         | `native_gre_tcp_mss`                  | ~30   | GRE-specific MSS adjustment |
| `afxdp/forwarding/mod.rs:743`         | `clamp_tcp_mss`                       | ~80   | MSS clamp on packet (post-IP-header path) |
| `afxdp/forwarding/mod.rs:824`         | `clamp_tcp_mss_frame`                 | ~50   | MSS clamp on raw frame (whole-Ethernet path) |
| `afxdp/frame/inspect.rs:12`           | `frame_has_tcp_rst`                   | ~30   | RST-flag fast detect |
| `afxdp/frame/inspect.rs:42`           | `extract_tcp_flags_and_window`        | ~30   | Read SYN/ACK/FIN/RST + advertised window |
| `afxdp/frame/inspect.rs:76`           | `extract_tcp_window`                  | ~45   | Read advertised window only |
| `afxdp/frame/inspect.rs:123`          | `tcp_flags_str`                       | ~25   | Render TCP flags for log |
| `afxdp/gre.rs:173`                    | `packet_tcp_flags`                    | ~25   | TCP flag read for GRE-tunneled inner |

Total: ~335 LOC of TCP-only logic spread across 3 files.

**Already-cohesive TCP module: `frame/tcp_segmentation.rs`** (338 LOC,
extracted in #1046). Owns TCP segmentation builders for the
forwarding hot path. This PR keeps it as a sibling of the
new `frame/tcp.rs` rather than merging — segmentation is a distinct
concern from flag/window extraction and MSS clamping, and the file
is already past the "module is too big to absorb more" threshold.
Future cohesion: `frame/tcp.rs` owns inspection + mutation kernels;
`frame/tcp_segmentation.rs` owns the segmentation builder.

### 1.2 Current UDP-specific call sites

UDP is mostly inline in `frame/mod.rs` checksum/port helpers and is
not a clean cohesion boundary on its own — `apply_l4_checksum_port`,
`adjust_l4_checksum_port`, etc. are protocol-agnostic by design
(they take `protocol: u8` and branch). Extracting a `frame/udp.rs`
purely to host UDP-specific bits would gain ~30 LOC of cohesion at
the cost of fragmenting the L4 checksum codepath.

**Decision: defer `frame/udp.rs` to a future PR.** The
protocol-agnostic L4 helpers in `byte_writes.rs` (#963 PR-B) and
`mod.rs` already handle UDP correctly. Splitting on a non-cohesion
boundary creates churn without payoff.

This PR ships **only** `frame/tcp.rs`.

## Proposal

### 2.1 New module: `userspace-dp/src/afxdp/frame/tcp.rs`

Owns (rev-2: 6 functions, was 4 in rev-1):
1. `pub(in crate::afxdp) fn frame_has_tcp_rst(frame: &[u8]) -> bool`
   — moved verbatim from `frame/inspect.rs:12`.
2. `pub(in crate::afxdp) fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)>`
   — moved verbatim from `frame/inspect.rs:42`.
3. `pub(in crate::afxdp) fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16>`
   — moved verbatim from `frame/inspect.rs:76`.
4. `pub(in crate::afxdp) fn tcp_flags_str(flags: u8) -> String`
   — moved verbatim from `frame/inspect.rs:123`.
5. `pub(super) fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool`
   — moved verbatim from `forwarding/mod.rs:743`.
6. `pub(super) fn clamp_tcp_mss_frame(frame: &mut [u8], l3_offset: usize, max_mss: u16) -> bool`
   — moved verbatim from `forwarding/mod.rs:824`.

`packet_tcp_flags` (gre.rs:173) stays in `gre.rs` — it is
GRE-specific and only called from `match_tunnel_endpoint`. Per Q2.

Does NOT own (kept where they live):
- `effective_tcp_mss(forwarding)` — pure `ForwardingState` lookup
  with no TCP logic. Stays in `forwarding/mod.rs`.
- `native_gre_tcp_mss(...)` — GRE-specific MSS computation. Stays
  in `forwarding/mod.rs` (GRE policy belongs with the GRE
  forwarding decision; TCP module would have to re-import GRE
  state).

### 2.2 Visibility and call-site impact

All six extracted functions have callers in `forwarding/mod.rs`,
`frame/mod.rs`, and the test surface. Move requires:
- Updating import paths at each call site.
- No visibility widening — every relocated fn is already
  `pub(in crate::afxdp)` or `pub(super)`. (`packet_tcp_flags` is
  NOT in scope; per Q2 it stays in `gre.rs` private.)
- Add `#[inline]` to all 6 relocated functions. Codex/Gemini
  round-2 raised the codegen-units > 1 concern: cross-module
  inlining is not guaranteed by default. `#[inline]` marks the
  function body as eligible for inlining across compilation
  units (it gets emitted into every CGU that calls it). This
  is the standard Rust idiom for "hot small fn that crosses a
  module boundary"; LTO is not required.

### 2.2.1 Inventory exclusions (Codex round-2 finding 1)

Two TCP-flag-touching forwarding-policy branches are NOT moved:
- `cluster_peer_return_fast_path` (`forwarding/mod.rs:402-406`)
  — rejects pure TCP SYN. This is forwarding policy that
  happens to read a TCP flag, not a TCP helper. It belongs
  with the cluster fast-path logic in `forwarding/`.
- `should_cache_local_delivery_session_on_miss`
  (`forwarding/mod.rs:1059-1079`) — special-cases TCP
  ACK-without-SYN. Same rationale: session-caching policy with
  an embedded protocol check, not a pure TCP helper.

These are explicitly out of scope; this PR's cohesion axis is
"reusable TCP byte kernels", not "every code site that touches
a TCP flag". A future refactor can extract them into helpers
that delegate into `frame/tcp.rs` (e.g.
`is_pure_tcp_syn(frame: &[u8]) -> bool`); that is out of scope
here.

### 2.3 Tests (rev-2: COLOCATE in this PR per dual-review feedback)

Existing integration tests stay where they are — they test
end-to-end paths and would just churn if moved.

New: `frame/tcp_tests.rs` (colocated per the modularity-discipline
rule, loaded via `#[cfg(test)] #[path = "tcp_tests.rs"] mod tests;`
inside `frame/tcp.rs`). Targeted unit tests:

| Function                          | Coverage |
|----------------------------------|----------|
| `frame_has_tcp_rst`              | 4 cases: TCP+RST set, TCP+RST clear, non-TCP, truncated |
| `extract_tcp_flags_and_window`   | 3 cases: typical SYN+ACK, FIN+ACK, truncated frame returns None |
| `extract_tcp_window`             | 2 cases: v4 + v6 windows, truncated returns None |
| `tcp_flags_str`                  | 4 cases: all-zero, single flag, all-flags, common SYN/ACK combos |
| `clamp_tcp_mss` (parser-edge)    | 8 cases (see expanded list below) |
| `clamp_tcp_mss_frame`            | 2 cases: smoke parity with the post-IP-header path on v4 + v6 |

**`clamp_tcp_mss` parser-edge coverage** (Codex round-2 finding 4
+ Gemini round-2 CONCERN 2):

1. MSS at start of options, clamp shortens — assert checksum
   independently recomputed.
2. MSS NOT at start of options (preceded by NOP NOP TIMESTAMP) —
   verify the parser walks past these and still rewrites MSS.
3. EOL option encountered before MSS — verify clamp returns
   without rewriting (no-op, checksum still valid).
4. Multiple MSS options — document that the parser stops at the
   first; assert subsequent ones are NOT rewritten.
5. Malformed option length (length byte = 0 or 1, would loop
   infinitely) — verify the parser bails out cleanly without
   panicking or stalling.
6. Non-SYN packet (ACK-only) — verify no-op (clamp_tcp_mss only
   touches SYN / SYN+ACK), checksum still valid.
7. IPv6 frame — verify checksum is recomputed correctly with
   the IPv6 pseudo-header.
8. No-op when current MSS already <= max_mss — verify checksum
   is unchanged AND the original MSS bytes are unchanged.

Cases 5 and 7 close the gaps both reviewers flagged: malformed
options and IPv6 pseudo-header coverage.

Total new tests: ~25 (was ~18 in rev-2). Lift no test bodies
from existing files — new tests are additions, integration
tests stay in place.

### 2.4 What this PR is NOT

- Not adding new functionality.
- Not changing any TCP logic.
- Not changing test bodies (the relocated functions retain their
  existing test coverage where it lives today).
- Not extracting UDP (deferred — see §1.2).
- Not extracting ICMP/ARP (already done — see table above).

## Risks

1. **Visibility widening**: `packet_tcp_flags` widens from
   fn-private to `pub(super)`. This is the minimum needed to host
   it in `tcp.rs`; alternative is keeping it in `gre.rs` since
   it is GRE-specific (currently called only from
   `match_tunnel_endpoint`). **Mitigation**: leave it in `gre.rs`.
   Updated proposal: drop item (5) from §2.1.

2. **Re-export churn**: `frame/mod.rs` currently re-exports
   `extract_tcp_flags_and_window` to its callers. After the move
   to `frame/tcp.rs`, the re-export needs to follow.

3. **Compile-time cycles**: `forwarding/mod.rs` and
   `frame/tcp.rs` would both reference shared types (`MssPolicy`,
   etc.). Existing types are already shared via crate-level
   modules; no new cycle introduced.

## Open questions for review

Q1. Is the §2.1 boundary the right one? Specifically, do
`clamp_tcp_mss` and `clamp_tcp_mss_frame` belong in `frame/tcp.rs`
(they mutate L4 bytes) or in `forwarding/tcp.rs` (they implement
forwarding policy)? Argument for `frame/tcp.rs`: they only touch
TCP option bytes — pure protocol mutation, no forwarding policy.
Argument against: their callers compute the policy via
`effective_tcp_mss()` which lives in `forwarding/`. Proposed
answer: `frame/tcp.rs`. The mutation is the cohesion axis.

Q2. Should `packet_tcp_flags` be moved at all? It is a 25-LOC
GRE-specific helper. Per the risk analysis above, **keep it in
`gre.rs`**. Final §2.1 list is items 1-6 (the four inspection
helpers plus the two clamp helpers; `packet_tcp_flags` was the
only candidate dropped from rev-1's seven-item list).

Q3. Should this PR also colocate TCP tests (move TCP-specific
cases from `frame/tests.rs` into `frame/tcp_tests.rs`)? Proposed
answer: no — keep this PR a pure relocation, follow-up for tests.
Risks of bundling: larger diff, harder to verify "no behavior
change", mixes mechanical move with judgment-call splits.

Q4. After this PR, what does `frame/inspect.rs` actually own?
Codex round-1 caught the rev-1 overreach: even after the four TCP
helpers move out, `inspect.rs` retains `parse_flow_ports`
(frame/inspect.rs:333, ~80 LOC of TCP+UDP+ICMP L4 port/identifier
parsing) and other L4-aware logic. Honest description after this
PR: `inspect.rs` becomes "IP-header inspection plus L4-tuple
parsing" — TCP-specific *flag/window/RST* helpers move out, but
the TCP+UDP+ICMP tuple-parsing helper stays. Future PRs can
revisit `parse_flow_ports` placement if the cohesion is wrong;
that is out of scope here.

## Acceptance gate

- `cargo test --release` — all existing tests pass + ~26 new
  unit tests under `frame/tcp_tests.rs` pass.
- `cargo build --release` — clean, no new warnings.
- `clamp_tcp_mss` checksum sanity test — independent recomputation
  inside the new test verifies the relocated function still
  produces a valid TCP checksum after MSS rewrite. (Direct response
  to Codex R1.)
- Cluster smoke (loss userspace cluster, all 6 CoS classes) —
  TCP MSS clamp path is exercised by every iperf3 stream, so any
  breakage in the relocation surfaces as a retransmit count >0 on
  at least one class.

Performance gate (Gemini round-2 FAIL on perf, addressed in rev-3):
Gemini round-2 was correct: with `codegen-units > 1` (the
release default) and no LTO override in `Cargo.toml`, cross-CGU
inlining is NOT guaranteed. Moving these hot-path TCP functions
across a module boundary risks losing inlining at the call sites
in `frame/mod.rs:315`, `:354` and the conntrack fast-path.

Rev-3 fix: add `#[inline]` to all 6 relocated functions. This
is the standard Rust idiom for "small fn that crosses a module
boundary into a hot caller" — the compiler emits the body into
every CGU that calls it, and inlining works without LTO. The
existing functions don't carry `#[inline]` today, but they live
in the same crate as their callers and most are
`pub(in crate::afxdp)` / `pub(super)` so the inlining decision
was implicit. After the move, the explicit annotation makes the
inlining contract durable.

A formal `perf stat` validation is still out of scope here
(same posture as #963 PR-B); the `#[inline]` attribute is the
compile-time guarantee that closes the codegen-units risk.
