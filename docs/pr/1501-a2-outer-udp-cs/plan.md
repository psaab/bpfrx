# #1501 A2 — Outer IPv4 UDP cs=0 by default

## Status

DRAFT v2 — Antigravity PLAN-NEEDS-MINOR addressed (sentinel buffer
pre-fill so the regression gate proves the function *wrote* cs=0
rather than relying on zero-initialized memory). Codex plan review
still pending.

## Round-1 plan-review verdicts

- **Antigravity (job adversarial-review-mpkq2awd-e66pif):**
  **PLAN-NEEDS-MINOR.** Confirmed RFC 768 / RFC 8200 accuracy, code
  reality (outer.rs:103 writes 0; lines 57-69 hold the stale TODO),
  caller analysis (test-only), receive-side analysis (try_decap
  takes post-strip wg_record), and perf framing. Sole minor: the
  proposed `udp_checksum_is_zero_on_ipv4_outer` test would silently
  pass under regression because `let mut out = [0u8; 40]` is
  already zero. Required correction: pre-fill the buffer with
  non-zero sentinel bytes (e.g. `0xff`) so the assertion proves
  the function actively wrote zero. v2 applies this discipline to
  both the new test and the strengthened `ipv4_checksum_is_correct`
  test.
- **Codex:** pending.

## Issue framing

#1501 is the follow-up minors tracker for the clean-room WireGuard
engine merged in #1499. Item A2 is the mechanical engine-side
follow-up:

> "Outer UDP IPv4 checksum can be left as 0 (RFC 768 §"UDP CHECKSUM
> IS NULL"). Source: r8 commit message deferred list —
> `userspace-dp/src/afxdp/wg/outer.rs:57`. The current code always
> computes the outer UDP IPv4 checksum… Recommended change: emit
> `cs=0` on the outer IPv4 UDP header by default; leave IPv6 outer
> untouched. Add a config knob (`outer-udp-checksum compute|zero`,
> default `zero` for v4) if behavior needs to be tunable for
> receivers that drop `cs=0`. Mechanical 1-line change in
> `write_outer_ipv4_udp` plus 2 tests."

The issue body is **wrong on a load-bearing fact**: the current
code already emits `cs=0`. `userspace-dp/src/afxdp/wg/outer.rs:103`
reads:

```rust
hdr[26..28].copy_from_slice(&0u16.to_be_bytes()); // checksum = 0
```

What the file is internally inconsistent about:

- Lines 52-55: doc comment correctly explains we set UDP cs to 0
  (RFC 768) and why — "UDP checksum offload semantics differ across
  NICs and we want a known-baseline behavior".
- Lines 57-69: a `TODO(#1499 r4 / udp-checksum)` block claims the
  opposite — that the integration PR should compute the UDP
  checksum or delegate to offload, citing "kernel WG and
  wireguard-go emit a non-zero UDP checksum on IPv4".

The TODO's premise is contradicted by RFC 768 (cs=0 is legal IPv4
UDP) AND by the issue body's own assertion that "kernel WG does
[cs=0] for outer-IPv4 traffic" (#1501 A2 body, paragraph 2). The
TODO is stale guidance left over from the #1499 r4 review
discussion that subsequently resolved in favor of emitting cs=0.

**Therefore the real A2 work is:**

1. Resolve the contradiction in `outer.rs` doc/TODO: remove the
   stale "compute it" TODO, tighten the kept comment to cite the
   RFC and explain the v4-vs-v6 asymmetry.
2. Add an explicit wire-byte test that the UDP checksum field is
   zero on the IPv4 outer (currently nothing asserts byte 26-27).
3. Add a code-level guard so the `cs=0` invariant cannot silently
   regress (e.g., assertion inside an existing test, since the
   only callers are tests today).

## Honest scope/value framing

A2 as described in the issue body would be a true per-packet perf
win (~20-30 cycles, material at line rate) if the code currently
computed the UDP checksum. **It does not** — the code already
emits `cs=0`. So the *runtime* perf delta of this PR is **zero**.

The actual value is:

- **Doc correctness.** Future contributors reading `outer.rs:57`
  would see a TODO directing them to add UDP-checksum compute or
  offload and might act on it, regressing the wire behavior we
  intentionally have. The TODO is a landmine.
- **Test coverage.** Today nothing asserts `cs==0` on the wire.
  Anyone "fixing" the cs=0 to compute (the TODO's instruction)
  would not trip any existing test. That's the silent-regression
  surface this PR closes.
- **#1501 close-out.** A2 is in the tracker; closing it via
  doc/test cleanup is the honest disposition since the code half
  already shipped.

If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict. The honest framing
here is that the "perf gain" line in the issue body does not
apply to this PR because the perf win already shipped silently
with #1499 — this PR is documentation + a regression gate.

## What's already shipped / partially batched

- #1499 merged with `write_outer_ipv4_udp` writing `cs=0` at
  line 103. Both the inline comment at 52-55 (correct) and the
  TODO at 57-69 (now stale) landed together.
- IPv6 outer is not implemented at all — only IPv4 outer is
  supported in #1499 scope. RFC 8200 §8.1 (non-zero UDP cs
  required for IPv6) only matters when the v6 outer ships, and
  the v6 builder is a separate follow-up out of scope here.
- The engine's `try_decap` operates on the WG transport record
  AFTER the outer UDP/IP has been stripped by the AF_XDP shim
  caller. There is no receive-side outer UDP checksum
  verification in the engine. (Verified by reading engine.rs:633
  signature — `wg_record: &[u8]`.)

## Concrete design

### Source change in `userspace-dp/src/afxdp/wg/outer.rs`

Replace the 23-line comment block at lines 47-69 with a tighter,
non-contradictory doc comment. The function body is unchanged
(it already sets cs=0). The new comment explains:

1. RFC 768 §"UDP CHECKSUM IS NULL" allows IPv4 UDP cs=0.
2. Kernel WireGuard emits cs=0 on outer IPv4 — we match that.
3. RFC 8200 §8.1 forbids cs=0 on IPv6 UDP; the v6 outer
   builder (when it ships, separate follow-up) must NOT take
   the same shortcut.
4. The IPv4 header checksum (mandatory) is computed; the UDP
   checksum (optional on IPv4) is zero.

Proposed replacement comment:

```rust
/// Write the outer IPv4 + UDP header for a WG-encapsulated payload.
///
/// `payload_len` is the length of the WG transport record
/// (header + ciphertext + tag) that follows the UDP header.
///
/// IPv4 header checksum: mandatory — computed here over the
/// IPv4 header only.
///
/// UDP checksum: emitted as 0 ("not computed") per RFC 768
/// §"UDP CHECKSUM IS NULL". This matches kernel WireGuard's
/// behavior for outer-IPv4 traffic and saves the per-packet
/// pseudo-header + payload sum. RFC 8200 §8.1 requires a
/// non-zero UDP checksum on IPv6 — when the v6 outer builder
/// ships it MUST compute the UDP checksum (cannot take this
/// shortcut). Some commercial midboxes drop UDPv4 with cs=0;
/// if a deployment encounters one, the integration layer can
/// surface an `outer-udp-checksum compute|zero` config knob
/// — out of scope for this engine-side PR.
```

### Test additions in the existing `outer_tests` mod

Add two unit tests to the existing `#[cfg(test)] mod outer_tests`
block at the bottom of `outer.rs`:

1. `udp_checksum_is_zero_on_ipv4_outer` — calls
   `write_outer_ipv4_udp` and asserts `out[26..28] == [0, 0]`.
   This is the byte-level regression gate that fails if anyone
   "fixes" the TODO by adding a UDP checksum compute step.

   **CRITICAL: pre-fill the output buffer with non-zero
   sentinel bytes (`0xff`) before the call.** Per Antigravity
   plan-review v1: a zero-initialized buffer would silently
   pass even if a future commit deleted the cs=0 write — the
   sentinel forces the assertion to prove the function
   *actively wrote* zero rather than left the bytes
   pre-zeroed. Same discipline applies to the strengthened
   `ipv4_checksum_is_correct` assertion below.

   Test skeleton (note `[0xffu8; 40]`, NOT `[0u8; 40]`):

   ```rust
   #[test]
   fn udp_checksum_is_zero_on_ipv4_outer() {
       let mut out = [0xffu8; 40]; // sentinel — prove the
                                   // function wrote zero,
                                   // not that init left zero.
       write_outer_ipv4_udp(
           &mut out,
           Ipv4Addr::new(10, 0, 0, 1),
           Ipv4Addr::new(10, 0, 0, 2),
           51820, 51820, 0, 64, 100,
       ).unwrap();
       assert_eq!(&out[26..28], &[0, 0]);
   }
   ```

2. Strengthen the existing `ipv4_checksum_is_correct` test by
   adding `out[26..28] == [0, 0]` as a second assertion, AND
   change its buffer init from `[0u8; 28]` to `[0xffu8; 28]`
   so the same sentinel discipline applies to the existing
   self-check. The IPv4 header self-check still works under
   sentinel init because the function overwrites every
   IPv4-header byte; the UDP cs assertion is what needs the
   sentinel.

   Alternatively, the assertion can live in its own new
   `#[test]` fn — what matters is that the wire-byte UDP cs
   assertion exists with a non-zero pre-fill.

If the reviewer wants the second assertion as a separate
`#[test]` fn rather than as an extension of the existing
self-check fn, that's a minor I'll accept; the byte-level
assertion with sentinel pre-fill is what matters.

### What the PR does NOT change

- No config knob in this PR. The issue body proposed
  `outer-udp-checksum compute|zero` as optional; since the
  default is already cs=0 and we have no reported midbox-drop
  case in the test lab, deferring the knob to the integration
  PR (where the Junos config compiler lives anyway) is the
  smaller-scope path.
- No IPv6 outer change — the v6 builder doesn't exist yet.
- No engine.rs changes — `try_encap` doesn't call
  `write_outer_ipv4_udp`; only test code does today.
- No receive-side UDP cs verify path — none exists, and adding
  one would be a behavior change (kernel WG accepts cs=0; we
  do too because the shim hands us the record post-UDP-strip).

## Public API preservation

- `pub(crate) fn write_outer_ipv4_udp(...) -> Option<usize>` —
  signature unchanged.
- `pub(crate) fn write_outer_eth(...)` — untouched.
- `pub(crate) fn outer_l2_len(...)` — untouched.
- No new public exports. No new config fields. No new enums.

The crate-internal `outer.rs` module is consumed only by
`afxdp/wg/tests.rs` and by `outer.rs`'s own test module.
There are no daemon callers and no Go callers. Verified by
`grep -rn "write_outer_ipv4_udp"` returning 6 hits, all
within `userspace-dp/src/afxdp/wg/`.

## Hidden invariants the change must preserve

1. **Wire-byte position of the UDP checksum field.** Bytes
   26..28 of the emitted `out` slice carry the UDP cs field
   (IP_HDR_LEN=20 + UDP cs offset 6 = 26). The new assertion
   is anchored on this offset and must remain accurate.
2. **IPv4 header checksum still computed and self-checks to
   zero.** The existing `ipv4_checksum_is_correct` test must
   still pass; we are NOT skipping the IPv4 header cs (which
   is mandatory per RFC 791).
3. **Total length and UDP length fields unchanged.** This PR
   does not touch `total_len`, `udp_len`, TTL, TOS, or any
   IPv4 header field other than the doc comment.
4. **No allocation introduced.** The function is already
   no-alloc; the doc edit cannot introduce allocations.
5. **IPv6 path unchanged.** There is no IPv6 outer builder
   today; the doc explicitly forbids carrying this shortcut
   over when the v6 builder ships.

## Risk assessment

| Risk class | Level | Rationale |
|------------|-------|-----------|
| Behavioral regression | NONE | Code body unchanged; only comment + tests added. Wire bytes are identical to master. |
| Lifetime / borrow-checker | NONE | No new code. |
| Performance regression | NONE | Code body unchanged; cs=0 already shipping. |
| Architectural mismatch (#961 / #946 Phase 2) | NONE | Engine-internal doc + test addition. No cross-cutting state. No batched-pipeline implications. |
| Wire-interop regression with midboxes | NONE — pre-existing | We are not changing the wire. If a midbox drops cs=0, it dropped today's master too. The integration PR can add an opt-in knob if a real deployment hits one. |

## Test plan

- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release` clean.
- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release` — all userspace-dp tests pass, including the two new assertions.
- 5/5 flake check on the named `outer_tests::udp_checksum_is_zero_on_ipv4_outer`.
- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — 30 packages, no regressions (Go side does not touch this code, so the gate is purely "we didn't break the build").
- Smoke on `loss:xpf-userspace-fw0/fw1`:
  - **Pass A — CoS disabled:** v4+v6 × push+reverse single-stream + 12-stream `-R` reproducer.
  - **Pass B — CoS enabled:** 5201-5206 × v4+v6 × push+reverse (24 cells).
  - Pass criterion: 0 retrans on saturated cells. WG dataplane is not actually wired up in this cluster (engine is library-only at master; integration PR ships separately), so smoke is really catching "we didn't break the AF_XDP boundary or the build pipeline". Reviewers should call this honestly — the smoke matrix here is gating *build + non-WG* dataplane correctness.

## Out of scope (explicitly)

- A1 (deterministic race-test gate) — separate follow-up.
- A3 (tighten blanket `#[allow(dead_code)]`) — separate follow-up;
  also depends on integration PR.
- A4 (hot-path no-alloc instrumentation harness) — separate
  follow-up.
- B1-B4 (integration-PR items) — out of scope by tracker design.
- IPv6 outer builder + UDP cs compute for v6 — no v6 outer exists.
- `outer-udp-checksum compute|zero` config knob — integration PR.
- Receive-side outer UDP cs verify — no such path exists.

## Open questions for adversarial review

1. **Is the perf framing honest?** The issue body claims ~20-30
   cycles saved per packet, but the code already does cs=0 today.
   PR-as-described is doc+test only with zero runtime delta. Does
   the reviewer agree this is the right disposition (close A2 via
   doc/test cleanup) vs. closing the tracker item as "already
   shipped" with no PR? If the latter is preferred, PLAN-KILL is
   the right call and I'll comment on the issue.
2. **Stale TODO removal.** Is the TODO at lines 57-69 truly
   stale, or is there a real wire-interop case in the test lab
   today (e.g., a known midbox path) where cs=0 has been
   observed to be dropped? If so, the TODO should stay (perhaps
   restated) and the integration PR should still be expected to
   add the knob. Quote the line of evidence either way.
3. **Test placement.** Should the new byte-level cs=0 assertion
   go in `outer.rs`'s own `outer_tests` module (smaller blast
   radius, no integration dependency) or in
   `afxdp/wg/tests.rs::outer_ipv4_*` (next to the existing
   integration-level outer-header tests)? Both are valid; the
   plan picks `outer.rs` because it doesn't drag in
   `WgEngine`. Push back if you disagree.
4. **Config knob: defer to integration vs. land now.** Plan
   defers the `outer-udp-checksum compute|zero` knob. Reviewer
   should confirm there is no real-world receiver in our test
   lab (or known production target) that drops cs=0, otherwise
   the knob may need to land in this PR. The default (`zero`)
   matches today's behavior either way.
5. **Documentation update reach.** Are there other docs (README,
   protocol doc under `docs/`, engineering-style.md) that
   reference outer UDP cs behavior and would now be stale?
   Quick `grep` shows the only mention is the TODO inside
   `outer.rs` itself, so no other docs need updating — confirm
   this finding.
6. **IPv6 forward-compat.** When the v6 outer builder ships,
   it MUST compute UDP cs. The plan adds a forward-looking
   comment but no compile-time guard. Should a `const _: () =
   assert!(...)` or `#[deprecated]` marker be added now to
   force the v6 author to confront the asymmetry? Plan says
   no (comment is sufficient; the v6 author will write a v6
   function and the v6 test suite will catch a missing cs);
   reviewer may push back.
7. **#1373 retirement coupling.** The eBPF dataplane is being
   retired; does any retirement-phase doc reference outer UDP
   cs behavior that this PR would now contradict? Plan says
   no (eBPF dataplane has no WG outer; WG is userspace-only).
