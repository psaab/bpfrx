# #5630 — IPsec typed endpoints bypass IP/FQDN validation

**Status:** IMPLEMENTED. codex-review-181 root M20 (`A3-b01-F002`,
Medium, CONFIRMED MATERIAL). Companion to #2074, which validates the
VPN→gateway *reference* but never the typed endpoint *values*.

## Problem

`compileIKE` / `compileIPsec` (`pkg/config/compiler_ipsec.go`) copy the
IKE-gateway endpoint leaves verbatim from a one-argument schema slot:

- gateway `address`          → `gw.Address`      → swanctl `remote_addrs`
- gateway `dynamic hostname` → `gw.DynamicHostname` → swanctl `remote_addrs`
- gateway `local-address`    → `gw.LocalAddress` → swanctl `local_addrs`
- vpn `local-address`        → `vpn.LocalAddr`   → swanctl `local_addrs`

`renderConfig` (`pkg/ipsec/policy.go`, `resolveRemoteAddr`) interpolates
those values straight into the generated swanctl.conf. The only
commit-time gate, `validateIPsecGatewayReferencesStrict` (#2074), checked
that a referenced gateway is *nonempty* — never that its endpoint value
is a usable IP or hostname. A printable-but-invalid endpoint therefore
passed strict commit and reached strongSwan, where `swanctl --load-all`
rejects or mishandles the connection: **a config that commits but never
loads is a silently broken tunnel.**

The `IsUsableIPsecEndpoint` predicate already existed but was applied
*only* to an inline `vpn.Gateway` literal, not to the typed object
fields or the local endpoints.

> Scope: this is the endpoint *outage / invalid-value* class only (per
> the coordinator's narrowed M20 wording). It is **not** a newline /
> config-injection claim — control characters are already handled by the
> global control-char gate + `sanitizeSwanctlValue` render belt.

## Fix

Two changes, both in `pkg/config`:

1. **`validateIPsecEndpointsStrict(cfg)`** (`compiler_validate_strict_ipsec.go`):
   a strict-accumulator validator on the fully-compiled `*Config` that
   runs the four effective endpoint fields through `IsUsableIPsecEndpoint`
   (the same predicate #2074 uses for the inline literal). Wired into the
   strict-validator chain in `compiler_uniformgates.go` right after the
   gateway-reference gate, with a `lenientIPsecEndpoints` downgrade — hard
   reject on commit / commit-check, warn on the tolerant load / peer-sync
   paths (#1960 fail-closed-on-load doctrine). Exactly the
   `validateIPsecGatewayReferencesStrict` template.

2. **`isPlausibleHostname` hardening** (`compiler_ipsec.go`): reject a
   hostname whose rightmost (top-level) label is entirely numeric (RFC
   3696 §2 / RFC 1123 §2.1). Without this, a botched IPv4 literal such as
   `10.0.0.999` (fails `net.ParseIP` because 999 > 255) was otherwise a
   run of digit-only labels and masqueraded as a "plausible hostname",
   slipping past `IsUsableIPsecEndpoint`. This is the exact issue repro.
   A valid IPv4/IPv6 literal is accepted by the `net.ParseIP` branch
   *before* the hostname scan, so real address literals are unaffected;
   this also closes the same `10.0.0.999`-as-inline-gateway hole in
   `validateIPsecGatewayReferencesStrict`.

## What is accepted / rejected (matches strongSwan)

- **Accepted:** literal IPv4 (`203.0.113.1`), literal IPv6 (`2001:db8::1`),
  dotted FQDN (`peer.example.com`), absolute FQDN with a trailing root dot
  (`peer.example.com.`). These are exactly the forms strongSwan's
  `remote_addrs`/`local_addrs` resolve, so a legitimate hostname or v6
  gateway still commits and renders unchanged.
- **Rejected:** a value that is neither a parseable IP nor a
  syntactically valid hostname — a malformed IP octet (`10.0.0.999`),
  too many octets (`1.2.3.4.5`), or a malformed FQDN (`bad..host`,
  `-bad.example.com`, an underscore, an all-numeric TLD). strongSwan
  itself would reject or fail to resolve these, so this does not invent a
  stricter rule than the downstream parser enforces.

Single-label bare hostnames (`vpnpeer`) remain rejected — unchanged,
intentional, and documented #2074 behavior (define a proper gateway
`address`/`dynamic hostname` instead).

## Tests

- `pkg/config/compiler_ipsec_endpoint_5630_test.go` —
  `TestValidateIPsecEndpoints_{Reject,Accept,Lenient}`: malformed
  endpoints (bad IP octet, five octets, bad FQDN, bad dynamic hostname,
  bad gateway/vpn local-address) are rejected at strict commit; valid
  IPv4/IPv6/FQDN remote + local endpoints still commit; the tolerant
  paths warn instead of failing. Flat-set `ParseSetCommand` + `SetPath`
  per CLAUDE.md.
- `pkg/ipsec/endpoint_render_5630_test.go` —
  `TestRenderValidEndpoints_5630`: valid IPv4/IPv6/FQDN endpoints render
  into `remote_addrs`/`local_addrs` unchanged.

RED-on-revert verified two ways: neutralizing
`validateIPsecEndpointsStrict` turns every reject case RED; reverting the
`isPlausibleHostname` all-numeric-TLD hardening (validator kept) turns the
`10.0.0.999` / `1.2.3.4.5` cases RED while the structurally-malformed FQDN
cases stay caught — proving the hostname hardening is load-bearing for the
exact repro.
