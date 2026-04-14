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

Use a dedicated bpfrx-managed DNS forwarder/cache process and stop using `systemd-resolved` as the mechanism behind any bpfrx-managed DNS behavior.

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
- have the new runtime replace both:
  - client-facing firewall DNS proxy behavior
  - host OS DNS behavior that is currently being delegated to `systemd-resolved`

## Required systemd-resolved change

The core design constraint is that `systemd-resolved` should not remain anywhere in the bpfrx DNS path.

Recommended ownership model:

- stop and disable `systemd-resolved`
- stop treating `system services dns` as a thin wrapper around a host OS service toggle
- let the bpfrx-managed DNS runtime own:
  - client-facing firewall DNS listeners
  - upstream forwarding behavior
  - cache behavior
  - host OS DNS configuration previously delegated to `systemd-resolved`

This is intentionally not a hybrid split design. The DNS runtime should replace all DNS things that `systemd-resolved` currently provides for bpfrx-managed nodes.

What this implies:

- `applyDNSService()` needs to be rewritten around the new DNS runtime
- `/etc/resolv.conf` management becomes bpfrx-owned
- the host OS should either:
  - point at the new local DNS runtime, or
  - receive explicit upstream resolver config rendered directly by bpfrx

Why this is preferable:

- one owner for DNS behavior
- no ambiguity over listener ownership
- no split-brain between “host DNS” and “firewall DNS”
- simpler operator story and fewer hidden interactions

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

### Phase 3: Replace systemd-resolved entirely

Refactor `applyDNSService()`:

- stop calling `systemd-resolved` for any bpfrx-managed DNS behavior
- disable `systemd-resolved`
- manage `/etc/resolv.conf` directly or point it at the new local DNS runtime
- let the bpfrx-managed DNS runtime be the only DNS owner on the node

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
- stale or unexpected local DNS listener

## Acceptance criteria

- `vsrx.conf` style `dns-proxy` config compiles without fatal error
- supported dns-proxy knobs no longer emit “unsupported” warnings
- firewall listens on the intended address/interface for DNS queries
- client queries are forwarded to configured upstreams and replied successfully
- `systemd-resolved` is disabled and no longer provides any bpfrx-managed DNS behavior
- the new runtime owns both firewall DNS behavior and host DNS behavior for the node
- HA failover preserves service ownership semantics for DNS proxy listeners
- operator can inspect runtime state with dedicated CLI/status output

## Non-goals

- full recursive resolver feature parity on day one
- DNS security product features beyond forwarding/cache parity
- cache synchronization between HA peers
- preserving `systemd-resolved` as a parallel DNS owner

## Suggested rollout order

1. config model + warning cleanup
2. daemon renderer/manager
3. full DNS ownership transition away from `systemd-resolved`
4. single-node functional tests
5. HA listener ownership tests
6. operator visibility / CLI

## Related

- tracking issue: #660
- import-compatibility follow-up: #659
- current gap row: `docs/feature-gaps.md` DNS Proxy = Missing
