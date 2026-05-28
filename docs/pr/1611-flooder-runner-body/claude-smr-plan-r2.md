# Claude SMR plan review r2 — #1611 cold-path flooder runner body

**Plan commit**: v4 (pending commit).
**Verdict**: **PLAN-READY**.

## Round-2 context

Round-1 verdicts:
- Codex r1 (task-mpovfie0-6vc58v): PLAN-KILL with 1 blocking
  finding (sendmmsg partial-retry off by one) + 2 majors
  (3 Mpps premise unverified, no integration syscall coverage).
- AGY r1 (adversarial-review-mpovrmah-4b35sc, retry after
  infra timeout): PLAN-NEEDS-MINOR with 5 concrete findings
  (PACKET_QDISC_BYPASS recommended over PACKET_TX_RING,
  blocking smoke gate, ENOBUFS silent treatment, yield_now
  vs 5ms sleep, IFF_UP check, frame buffer alignment).
- Claude SMR r1: PLAN-NEEDS-MINOR (sendmmsg wording, RFC 6864
  ID note, ifindex-0 failure, AF_XDP RX visibility topology).

All findings from all three reviewers are inlined into v4.

## v4 changes vs v3

1. Sendmmsg loop: PRNG-advance wording corrected (AGY r1 ¶1
   noticed v3 said "advanced N times" instead of "advanced
   batch times"). Loop refills from scratch every iteration.
2. PACKET_QDISC_BYPASS adopted as default (not opt-in), via
   one-line `setsockopt`. PACKET_TX_RING rejected for v4 per
   AGY r1 finding 2 (overkill for test harness). PACKET_TX_RING
   becomes follow-up if blocking 2.5 Mpps gate fails.
3. Hot-path error handling: ENOBUFS silent (treated as
   EAGAIN), EAGAIN replaced with `yield_now()` instead of
   5ms sleep (AGY r1 finding A + B).
4. IFF_UP check via `ioctl(SIOCGIFFLAGS)` before bind (AGY r1
   finding C).
5. Frame buffer struct `#[repr(align(64))]` (AGY r1 finding D).
6. Blocking smoke gate at ≥2.5 Mpps (AGY r1 finding 3, with
   AGY's recommended threshold; Codex r1 wanted 3 Mpps but
   AGY r1's virtio-VM measurement is the closer match for the
   target environment).
7. `#[ignore]`-gated CAP_NET_RAW integration test in plan
   (Codex r1 MAJOR-3).
8. RFC 6864 IPv4 ID rationale (Claude SMR r1 MINOR-2).
9. `if_nametoindex == 0` explicit failure (Claude SMR r1 MINOR-3).
10. AF_PACKET TX → AF_XDP RX topology note (Claude SMR r1 axis 9).

## Verdict justification

All three reviewers' findings are inlined. Architecture is now:
- AF_PACKET SOCK_RAW + PACKET_QDISC_BYPASS + sendmmsg(32)
- Per-packet xorshift 5-tuple, src_port_base=1024 default
- IPv4-only 64-byte frame (IPv6 deferred to follow-up)
- TSC stays in dataplane (#1612), not flooder
- Blocking 2.5 Mpps gate on the loss cluster host
- CAP_NET_RAW integration test gated by env var
- 14 unit tests (was 9 in step-1)

This is the same architecture #1607 plan v2-r4 §4.2 specified,
plus AGY's hot-path-hardening fixes. The blocking gate is the
honest empirical truth-source: if PACKET_QDISC_BYPASS + sendmmsg
can't hit 2.5 Mpps on the loss cluster, the PR doesn't merge,
and the methodology debt (PACKET_TX_RING) is paid in a follow-up.

## Domain checks PASSED

- **Hot-path allocation**: One pre-allocated mmsghdr+iovec+frame
  array. No per-packet allocations.
- **Per-packet stalls**: `yield_now()` for EAGAIN/ENOBUFS (no
  5ms sleep at 3 Mpps).
- **Logging**: ENOBUFS silent (no per-packet log spam at 3 Mpps).
  Other errno: first occurrence logged, then counter-only.
- **Wire correctness**: IPv4 14+20+8+22=64, total_len=50, UDP
  len=30, csum scheme RFC 1071, UDP-over-IPv4 csum=0 (RFC 768).
- **Reserved port 0**: src_port_base=1024 default skips port 0;
  `--src-port-base 0` opt-in for explicit port-0 measurement.
- **PRNG distribution**: xorshift64 is stateless modulo the
  64-bit register; discarded unsent slots' PRNG output don't
  bias the distribution.
- **AF_XDP visibility**: AF_PACKET TX on host → host NIC → loss
  cluster wire → firewall AF_XDP RX on ge-0-0-1. Independent
  kernel paths on the two ends.

## Self-correction note

I missed in r1:
- The "advanced N times" PRNG-state typo (AGY r1 ¶1 caught it).
- The ENOBUFS-as-storm risk (AGY r1 finding A caught it).
- The 5ms sleep wasting 15k packets of TX (AGY r1 finding B
  caught it).
- The IFF_UP / down-interface silent failure (AGY r1 finding C).
- Frame buffer alignment for DMA throughput (AGY r1 finding D).

These are all real and good catches. Future Claude SMR rounds
on this kind of test-harness work should systematically
checklist:
- PRNG state-advance accounting on partial-submit paths
- Per-error-code logging hygiene at 3+ Mpps rates
- yield vs sleep granularity in hot loops
- ioctl-pair pre-bind sanity checks (UP, MTU, MAC valid)
- Cache-line alignment of buffers feeding kernel copy paths

## Final verdict

PLAN-READY. All reviewer findings addressed. Proceeding to
implementation against v4.
