# Next Feature: Explicit Twice NAT Parity

Date: 2026-04-13  
Status: Proposed (tracking issue #645)

## Why this doc exists
The current Twice NAT gap is no longer "bpfrx has separate SNAT and DNAT, but no combined path at all." The userspace dataplane already carries important combined-NAT building blocks. The remaining work is to define the supported contract, validate it end-to-end, and close the parity gap with evidence.

## Current state
bpfrx already has concrete userspace support pieces for combined SNAT + DNAT flows:

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
- no support matrix spelling out whether eBPF, userspace AF_XDP, and DPDK all have the same combined-NAT behavior
- feature-gap docs still describe Twice NAT as if the combined path were mostly hypothetical

## Proposed implementation scope

### 1. Define the evaluation contract
Document and validate one supported order for combined NAT:

1. pre-routing DNAT
2. FIB lookup and security policy evaluation against the translated destination
3. post-policy SNAT
4. session creation preserving both NAT legs and translated ports

This should be the documented behavior for all dataplanes that claim Twice NAT support.

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

- if eBPF, userspace AF_XDP, and DPDK all support Twice NAT, document that and test each path
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
