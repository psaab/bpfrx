# Next Feature: Real DNS Proxy Runtime

Date: 2026-04-13  
Status: Proposed (tracking issue #660)

## Why this doc exists
`system services dns dns-proxy ...` now imports cleanly for vSRX compatibility, but bpfrx still does not provide an actual firewall-side DNS proxy. The current implementation only toggles `systemd-resolved` as a host resolver service. That is not vSRX parity.

This document describes how to move from:

- syntax-compatible no-op import

to:

- a real DNS forwarder/cache answering client queries on the firewall

without conflating host OS resolver behavior with client-facing DNS proxy behavior.

## Current state

Today:

- `system services dns;` enables/disables `systemd-resolved`
- `system services dns dns-proxy ...` is accepted for import compatibility and emits warnings
- there is no listener model for client queries on firewall interfaces
- there is no VRF-aware upstream forwarding model for DNS proxy
- there is no caching, ACL model, or forwarder selection based on imported vSRX config

This means the config compiles, but DNS proxy behavior does not exist.

## What vSRX parity requires

At minimum, parity needs:

- the firewall to listen for DNS queries from clients
- binding to the intended interfaces / service contexts
- forwarding to configured upstream resolvers
- cache behavior, even if small and initially basic
- support for imported `dns-proxy`, `forwarders`, and `default-domain`

Phase 1 does not need to be a full recursive resolver. A forwarding cache is enough.

## Recommended runtime direction

Use a dedicated bpfrx-managed DNS forwarder/cache process and stop using `systemd-resolved` as the mechanism behind `system services dns`.

Recommended direction:

- use `unbound` as the first implementation target

Why `unbound` is the best initial fit:

- mature forwarding + caching behavior
- good interface binding and access-control support
- straightforward upstream forward-zone configuration
- predictable daemon model managed by bpfrxd
- easier to reason about as a firewall-side listener than `systemd-resolved`

Alternatives:

- `CoreDNS`: flexible plugin model, but more work to express vSRX-like forwarder/cache behavior cleanly
- `dnsmasq`: light and simple, but less attractive as the long-term base if we want stronger policy, caching, and per-view behavior
- custom bpfrxd helper: highest control, worst time-to-value

Recommendation:

- Phase 1: manage `unbound`
- keep the abstraction in bpfrxd generic enough that a future daemon swap is possible

## Required systemd-resolved change

The core design constraint is that `systemd-resolved` cannot remain the client-facing DNS service pretending to be vSRX DNS proxy.

We should split the problem into two planes:

1. firewall client-facing DNS proxy plane
2. host OS resolver plane

The firewall client-facing plane should move to the new managed DNS proxy.

For the host OS plane, there are two viable approaches:

### Option A: disable systemd-resolved entirely

- stop and disable `systemd-resolved`
- render `/etc/resolv.conf` directly from configured host resolver inputs
- let the bpfrx-managed DNS proxy be the only DNS daemon on the node

Pros:

- simplest ownership model
- no ambiguity over who owns port 53
- avoids dual-daemon DNS confusion

Cons:

- we must take over host resolver file management cleanly
- larger change in host networking assumptions

### Option B: keep systemd-resolved for host resolution only

- disable stub listener / avoid binding conflicts
- stop treating it as the implementation of `system services dns`
- run the bpfrx-managed DNS proxy on the service IPs/interfaces
- leave host OS resolution on `systemd-resolved` or explicit upstreams

Pros:

- smaller host OS disruption
- cleaner migration path

Cons:

- more moving parts
- easier to create confusing failure modes if ownership boundaries are sloppy

Recommendation:

- start with Option B if we can guarantee clean listener separation
- fall back to Option A if `systemd-resolved` creates too much ownership ambiguity

Either way, the current `applyDNSService()` model needs to stop meaning “toggle `systemd-resolved` and call it done.”

## Proposed config/runtime contract

### Supported in phase 1

- `system services dns;`
- `system services dns dns-proxy { ... }`
- `default-domain`
- `forwarders`

### Explicitly out of scope in phase 1

- advanced recursive resolver behavior
- DNSSEC validation policy knobs
- split-horizon views beyond basic bind/ACL separation
- DNS rewrite / RPZ / sinkhole behavior
- HA state replication of cache contents

## Detailed implementation plan

### Phase 0: Finish import-compatibility baseline

This is effectively the state from `#659`:

- vSRX syntax compiles
- unsupported parts warn instead of failing

This phase is done and should remain intact while runtime work proceeds.

### Phase 1: Add explicit config model for DNS proxy intent

Compiler/types work:

- extend `SystemServicesConfig` to carry a real DNS proxy sub-config
- capture:
  - enabled state
  - `default-domain`
  - `forwarders`
  - optional bind/listen metadata if we later add explicit listener controls
- stop reducing everything to a single `DNSEnabled bool`

Compiler behavior:

- no compile warnings for the knobs we actually support
- warnings only for remaining imported-but-unimplemented dns-proxy subtrees

Tests:

- parser/compiler coverage for:
  - flat and hierarchical syntax
  - multiple forwarders
  - inactive subtrees
  - vSRX import snippets from `vsrx.conf`

### Phase 2: Add bpfrxd-managed DNS proxy renderer/manager

Daemon work:

- introduce a DNS proxy manager alongside the current system service managers
- render a deterministic config file for the chosen daemon
- manage lifecycle:
  - enable/start
  - reload on config changes
  - stop/disable on removal

Generated config needs:

- interface / address binds
- access-control for the client subnets we intend to serve
- upstream forwarder list
- cache sizing defaults
- default domain handling where it maps cleanly

Tests:

- unit tests for rendered daemon config
- daemon tests for create/update/delete behavior

### Phase 3: Replace systemd-resolved ownership model

Refactor `applyDNSService()`:

- stop calling `systemd-resolved` the DNS implementation for `system services dns`
- introduce separate host-resolver management and firewall-dns-proxy management

If using Option B:

- disable `systemd-resolved` stub listener or otherwise prevent listener overlap
- keep host OS resolution explicit and separate

If using Option A:

- disable `systemd-resolved`
- manage `/etc/resolv.conf` directly

Tests:

- integration test that port 53 is owned by the new proxy runtime, not `systemd-resolved`
- smoke check that the host OS can still resolve names after the transition

### Phase 4: Bind/query path validation

Validation in a lab environment:

- query the firewall IP from a client on the intended interface
- confirm query is answered by the new proxy
- confirm upstream forwarding uses configured forwarders
- confirm reply path works in the intended VRF/routing-instance

Must validate:

- IPv4 client to IPv4 upstream
- IPv6 client to IPv6 upstream
- mixed client/upstream cases only if we intend to support them

### Phase 5: HA behavior

Decide the supported HA contract:

- active node only owns DNS proxy listener on RETH/service IPs
- standby must not answer client DNS queries for active-owned service addresses
- failover should restart or rebind the proxy cleanly when ownership changes

Phase 1 HA requirement:

- listener ownership follows RG/service IP ownership
- no cache sync requirement

Tests:

- query during steady state on primary
- fail over RG
- query again on new primary
- verify old standby no longer answers

### Phase 6: Observability and CLI

Add operational visibility:

- `show services dns-proxy`
- daemon status
- bound listeners
- configured forwarders
- cache counters if available
- last reload / last error

Warnings/alarms:

- daemon failed to bind
- no reachable forwarders
- conflicting local DNS listener

## Acceptance criteria

- `vsrx.conf` style `dns-proxy` config compiles without fatal error
- supported dns-proxy knobs no longer emit “unsupported” warnings
- firewall listens on the intended address/interface for DNS queries
- client queries are forwarded to configured upstreams and replied successfully
- `systemd-resolved` is no longer the mechanism standing in for vSRX DNS proxy
- HA failover preserves service ownership semantics for DNS proxy listeners
- operator can inspect runtime state with dedicated CLI/status output

## Non-goals

- full recursive resolver feature parity on day one
- DNS security product features beyond forwarding/cache parity
- cache synchronization between HA peers
- using DNS proxy as a control-plane replacement for every host OS DNS need

## Suggested rollout order

1. config model + warning cleanup
2. daemon renderer/manager
3. listener ownership transition away from `systemd-resolved`
4. single-node functional tests
5. HA listener ownership tests
6. operator visibility / CLI

## Related

- tracking issue: #660
- import-compatibility follow-up: #659
- current gap row: `docs/feature-gaps.md` DNS Proxy = Missing
