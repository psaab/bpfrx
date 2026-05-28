# Claude SMR plan review r1 — #1611 cold-path flooder runner body

**Plan commit**: 0c491ad9831d07ce2da6b46ff4aba737161ce525
**Verdict**: **PLAN-NEEDS-MINOR** — architecture is sound; three
items need tightening before code lands.

## Domain hats covered

- Network protocols (UDP/IPv4 frame layout, port semantics, IPv4
  ID handling, kernel-side AF_PACKET path)
- Linux AF_PACKET / sendmmsg kernel ABI
- AF_XDP RX visibility (loss userspace cluster wiring)
- CPU architecture (per-packet TSC cost, sendmmsg cache footprint)
- Software-design (xpfd state isolation, test-binary discipline)

## Verdict summary

PLAN-NEEDS-MINOR. The architecture is right: AF_PACKET SOCK_RAW
+ sendmmsg from `loss:cluster-userspace-host` toward the firewall
LAN side is the standard #1607 wiring (confirmed against plan
v2-r4 line 601 + line 868). Frame layout 14+20+8+22 = 64 B is
arithmetically correct. The src_port_base=1024 default is the
codebase-correct choice (verified at
`userspace-dp/src/afxdp/frame/inspect.rs:207`). TSC stays out of
the flooder per plan v2-r4 §4.3.

Three minor items to address before code lands:

## Findings

### MINOR-1 — sendmmsg partial-submit description is confused

**Evidence**: plan.md line "Track partial submissions: if N <
batch, advance the PRNG counter by N (not batch) and resubmit
from offset N+1 next iteration."

**Risk**: This wording describes a re-queue-from-N scheme that
is unnecessary and slightly wrong. Per `man 2 sendmmsg`:
> On success, sendmmsg() returns the number of messages sent
> from msgvec; if this is less than n, the caller can retry with
> a further sendmmsg() call to send the remaining messages.

The first N messages WERE sent successfully — the caller does
NOT re-prepare them. But "resubmit from offset N+1 next
iteration" implies the next iteration starts indexing at N+1
into the SAME msgvec, which is not what the code wants to do.

**Recommendation**: simplify the plan text to:
> Per-iteration: PRNG-refill all `batch` slots, call
> `sendmmsg(fd, msgs.as_mut_ptr(), batch as u32, 0)`. On
> return value N: count `tx_packets += N`,
> `tx_batches += if N == batch { 1 } else { 0 }`,
> `err_partial += if 0 < N < batch { 1 } else { 0 }`. Refill
> from scratch next iteration — the per-packet PRNG state
> already advanced N times during prepare.

This is also simpler to test in
`partial_sendmmsg_advances_correctly`.

### MINOR-2 — IPv4 ID field randomization risk (axis 6)

**Evidence**: plan.md "ID field randomized from the same
xorshift stream — keeps the IPv4 fragment-reassembly mid-layer
from treating identical-ID packets as fragment dupes."

**Risk**: Two angles:
1. The DF (Don't Fragment) bit is set in the plan; that
   eliminates the fragment-reassembly concern (kernels with DF
   set never reassemble; the ID field becomes a debug tag, not
   a reassembly key).
2. Per RFC 6864 §4.2: for atomic datagrams (DF=1, no
   fragmentation), the IPv4 ID is unconstrained — random is
   fine. NO kernel rate-limit path keys off it.

So this isn't actually a hazard, but the plan should note the
DF=1 → ID-doesn't-matter logic explicitly so a reviewer doesn't
re-flag it. Add one line to §4 frame-assembly section:
"IPv4 flags=DF (per RFC 6864 §4.2 atomic datagram, ID field is
unconstrained random)."

### MINOR-3 — Missing explicit ifindex resolution failure path

**Evidence**: plan.md says "Resolve `--iface` to ifindex via
`if_nametoindex(3)`" — but doesn't specify what happens when
`if_nametoindex` returns 0 (the documented "not found" sentinel).

**Risk**: A typo in `--iface ge-0-0-1` (e.g., extra space)
would silently bind to ifindex 0 (which is "any interface" in
some socket families and not-bound-properly in others). Either
the AF_PACKET bind fails downstream or, worse, the bind
succeeds against an unintended interface.

**Recommendation**: add to plan §4 (point 1):
> If `if_nametoindex(name)` returns 0, fail with
> `"interface '<name>' not found — check `ip link show`"`. No
> implicit fallback.

## Domain-specific checks the plan passed

### Hot-path allocation rule

The plan correctly says "One `mmsghdr` array of size `batch`
allocated once, before the hot loop." No per-packet allocations.
Verified — this matches the codebase discipline.

### AF_XDP RX visibility (axis 9 — CRITICAL)

The flooder runs on `loss:cluster-userspace-host` (per plan
v2-r4 line 601), NOT on the firewall. The host TX-emits AF_PACKET
frames OUT its NIC; these arrive at the firewall's `reth1.0`
(LAN side, mapped from ge-0-0-1 per CLAUDE.md cluster topology)
via normal Ethernet. The firewall's AF_XDP socket is bound on
the RX side of the LAN-facing interface (`ge-0-0-1` on each
firewall node), so the kernel delivers ALL frames at the RX
side via the XDP program — including AF_PACKET-originated
frames from the host. **The AF_XDP RX path SEES the AF_PACKET
TX traffic.**

This is a critical correctness check. The plan does not call
this out explicitly; it should add a note to §4 (or §3 design
intro):
> The flooder runs on `loss:cluster-userspace-host` and the
> AF_PACKET TX traffic arrives at the firewall via normal
> Ethernet. The firewall-side AF_XDP RX path sees every frame —
> AF_PACKET TX and AF_XDP RX live on independent kernel paths
> on the two ends of the wire.

Without this note, an axis-9-style PLAN-KILL is possible from
a reviewer who hasn't internalized the cluster topology.

### Reserved src_port=0 (axis 3)

Plan defaults `--src-port-base 1024`. Verified the rationale
at `userspace-dp/src/afxdp/frame/inspect.rs:207`:
```rust
PROTO_TCP | PROTO_UDP => flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0,
```
A flow with src_port==0 fails `metadata_tuple_complete`, which
short-circuits flow installation to a NON-cold-path code path
(metadata-incomplete handling). Measuring port-0 traffic
through this code would record latencies from a different code
path than what the Scale Target table wants to characterize.

The plan's contradiction with the parent task prompt is
**correct on the codebase side**. The parent task prompt's
"NOT skipping port 0" guidance appears to be a misreading.

### TSC scope (axis 4)

Plan defers per-packet TSC to the dataplane-side
`ColdPathSampler` per plan v2-r4 §4.3. This is correct: per-
packet `rdtscp` at 5+ Mpps from a userland process would itself
cost ~50 ns/packet of overhead and the data it produces (host
TX timestamp) is useless to a cold-path latency histogram
measured at the firewall ingress.

The plan correctly does NOT add `--use-tsc` / `--use-clock-gettime`
flags to the flooder. The parent task prompt's framing of TSC
in the flooder context appears to be a misreading.

### Numerical correctness — IPv4 csum

Plan §4 says "folded 16-bit one's-complement sum over the 20-byte
header. Cheap (~5 ns)." This is the standard RFC 1071 algorithm.
The unit test `frame_assembly_ipv4_csum_matches_rfc1071` —
golden-value check against a known-csum test vector — is the
right gate.

The implementation must remember:
- Zero the csum field BEFORE computing the sum.
- Carry-fold the upper 16 bits into the lower (loop until upper=0).
- One's complement (XOR 0xFFFF).
- Sum-to-zero ⇒ store 0xFFFF (RFC 768 only; for IPv4 header
  RFC 791 says any complement of all-zeros is fine; 0xFFFF and
  0x0000 are equivalent in practice but 0xFFFF is canonical for
  UDP-over-IPv4).

This belongs in implementation review, not plan review. Plan
text doesn't need this depth.

## Self-correction notes

Nothing missed yet vs Codex/AGY (both still running). I will
update this doc with self-correction notes on round-2 if
either reviewer catches something this verdict missed.

## What Claude SMR would PLAN-KILL on

If the plan had:
- Per-packet TSC in the flooder (would re-introduce the
  measurement-overhead bias #1607 was trying to escape)
- src_port_base default 0 (would short-circuit
  metadata_tuple_complete and skew the histogram)
- Wire-protocol additions in scope (would balloon review
  surface contra AGY r4 axis 4)
- Workspace inclusion (would couple flooder build to dataplane
  build)

None of these apply. PLAN-NEEDS-MINOR for the three textual
issues above; a 5-line revision to plan.md addresses all three.

## Action items before PLAN-READY

1. Fix MINOR-1 wording on sendmmsg partial-submit.
2. Fix MINOR-2 — add the DF=1 rationale.
3. Fix MINOR-3 — add ifindex-0 failure path.
4. Add the axis 9 topology note to §4.

Once these land, Claude SMR will re-verdict as PLAN-READY in r2.
