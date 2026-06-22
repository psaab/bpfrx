# Next Feature: Explicit Twice NAT Parity

Date: 2026-04-13  
Status: Proposed (tracking issue #645)

## Why this doc exists
The current Twice NAT gap is no longer "xpf has separate SNAT and DNAT, but no combined path at all." The userspace dataplane already carries important combined-NAT building blocks. The remaining work is to define the supported contract, validate it end-to-end, and close the parity gap with evidence.

## Current state
xpf already has concrete userspace support pieces for combined SNAT + DNAT flows:

- `userspace-dp/src/nat.rs` has merged `NatDecision` state for source and destination address/port rewrites.
- `userspace-dp/src/afxdp.rs` merges pre-routing DNAT with post-policy SNAT instead of letting later NAT overwrite earlier NAT.
- `userspace-dp/src/session.rs` carries reverse-key logic for translated ports so return traffic can match the same session.
- Session sync messages preserve both NAT legs and translated ports.
- `show security flow session` already understands sessions carrying both SNAT and DNAT flags.
- Unit tests exist for merged NAT decisions and reverse-key behavior.

This means the main gap is no longer raw plumbing. The missing part is product-level confidence and a precise statement of what is supported.

## Remaining gap
The open Twice NAT parity work is:

- no explicit end-to-end validation that one flow can hit DNAT and SNAT together on supported dataplanes
- no HA/failover validation proving both NAT legs survive session sync and failover
- no support matrix spelling out whether eBPF and userspace AF_XDP have the same combined-NAT behavior (DPDK retired #1525)
- feature-gap docs still describe Twice NAT as if the combined path were mostly hypothetical

## Proposed implementation scope

### 1. Define the evaluation contract
Document and validate one supported order for combined NAT:

1. pre-routing DNAT
2. FIB lookup and security policy evaluation against the translated destination
3. post-policy SNAT
4. session creation preserving both NAT legs and translated ports

This should be the documented behavior for all dataplanes that claim Twice NAT support.

#### Implemented (#2345): inbound destination-translation policy tuple

As of #2345 the userspace AF_XDP dataplane evaluates the inbound
security policy against the POST-translation destination tuple for the
SAME-FAMILY inbound destination translations that happen before the
route/zone lookup:

- **DNAT / static-DNAT** — policy matches on the translated internal
  destination address, and on the translated destination **port** for
  port-based DNAT (e.g. public `VIP:443` DNAT'd to internal `B:8443` is
  matched as `B:8443`, not `VIP:443`).
- **inbound NPTv6** — policy matches on the translated internal IPv6
  prefix destination, not the external/public prefix.

The destination **zone** was already correct before #2345: it is derived
from the translated destination (the resolution's `egress_ifindex`), so
only the address/port half of the tuple needed correcting. This matches
Junos/SRX semantics, where inbound destination translation precedes the
security-policy lookup and the policy is matched on the real internal
destination in the destination zone. Implementation: `policy_dst_ip` /
`policy_dst_port` in `userspace-dp/src/afxdp/poll_descriptor/mod.rs`,
used in both the `ForwardCandidate` and `MissingNeighbor` policy-eval
sites. Session reversal is unaffected — the policy-tuple change touches
only the policy lookup, not the installed session keys, so the reverse
session is still keyed off the public-facing wire tuple (DNAT reverse
source = the internal host with the translated port; reverse dst = the
original external client).

**NAT64 is excluded from this post-translation matching, by design.**
NAT64 is a cross-family translation: the translated destination is IPv4
while the flow source remains IPv6. xpf's policy matcher
(`policy.rs::evaluate_policy`) requires the source and destination of the
match to be the SAME address family — a mixed `(V6 src, V4 dst)` tuple
matches no rule and falls to default-deny. Feeding the extracted IPv4
destination into the policy match would therefore break ALL NAT64
connectivity rather than fix it. NAT64 keeps its historical behavior:
the policy is matched on the synthetic IPv6 destination (the only
same-family tuple available at the policy-eval site), so NAT64 security
policy must be written against the synthetic IPv6 destination prefix.
Making NAT64 policy match the real IPv4 server is a larger, separate
design change (cross-family policy matching) and is intentionally NOT
part of #2345.

### 2. Add end-to-end coverage
Add explicit tests for:

- DNAT + interface SNAT on the same flow
- DNAT + pool SNAT on the same flow
- port-forwarding DNAT combined with SNAT port allocation
- reverse traffic matching the existing session instead of creating a parallel partial-NAT session
- `show security flow session` reporting both SNAT and DNAT state for the same session

### 3. Add HA/session-sync coverage
Add failover coverage proving that:

- the forward session carries both translated address/port legs into sync messages
- the peer reconstructs the same combined NAT state
- post-failover return traffic still matches the restored session and reverses both NAT legs correctly

### 4. Audit dataplane parity
Make the support statement explicit:

- if eBPF and userspace AF_XDP support Twice NAT, document that and test each path (DPDK retired #1525)
- if support is intentionally narrower, say so directly and scope the feature-gap row to the supported dataplanes

### 5. Update public gap tracking
Once validated, rewrite the Twice NAT row in `docs/feature-gaps.md` from a vague partial to a precise supported/partial statement backed by tests.

## Non-goals
This proposal does not assume:

- a separate monolithic "twice-nat" configuration family
- ALG payload rewriting for embedded IP/port literals
- new NAT feature families such as overflow pools or deterministic rule ordering changes unrelated to combined SNAT + DNAT

## Acceptance criteria
- Combined SNAT + DNAT flows work end-to-end on every dataplane we claim supports Twice NAT.
- Return traffic matches the same session and reverses both NAT legs correctly.
- HA/session sync preserves translated addresses and ports across failover.
- `show security flow session` and related operational views show both SNAT and DNAT state for combined flows.
- `docs/feature-gaps.md` no longer describes Twice NAT as an unproven combination when the supporting tests are merged.
