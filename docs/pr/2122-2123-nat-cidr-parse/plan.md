# #2122 + #2123: NAT static + NAT64 address parse rejects the /32 (/128) CIDR mask

Status: READY — small two-site bug fix matching an established idiom.

## Issue framing

Two HIGH-severity NAT-correctness bugs with the **same root cause** in two
modules:

- **#2122** — static 1:1 NAT silently drops every rule written in canonical
  Junos prefix form. `StaticNatTable::from_snapshots`
  (`userspace-dp/src/nat/static_nat.rs:29-36`) parses
  `snap.external_ip` / `snap.internal_ip` with `IpAddr::from_str`, which
  REJECTS CIDR notation. The Go compiler emits the canonical mask intact
  (`compileNATStatic` → `rule.Match = "203.0.113.5/32"`,
  `rule.Then = "10.0.0.5/32"`), and `buildStaticNATSnapshots`
  (`pkg/dataplane/userspace/nat.go:131-137`) copies it verbatim. Each rule
  then hits the `Err(_) => continue` arm and is dropped, so (1) no 1:1
  translation occurs and (2) the external IP is never registered as a local
  address (`forwarding_build/mod.rs` iterates `static_nat.external_ips()`),
  so inbound traffic to the external IP is not even recognized.

- **#2123** — NAT64 range-form source pool drops every pool address.
  `Nat64State::from_snapshots` (`userspace-dp/src/nat64.rs:74-78`) collects
  the pool with `snap.pool_addresses.iter().filter_map(|s| s.parse().ok())`
  into `Vec<Ipv4Addr>`. `Ipv4Addr::from_str` also rejects CIDR. When the
  pool is configured as a range (`address 100.64.0.1 to 100.64.0.4`),
  `expandAddressRange` (`compiler_nat.go:188`) appends `/32` to every
  produced IP, so `PoolAddresses = [100.64.0.1/32, ...]`. `filter_map`
  silently discards all of them, leaving `pool_v4` empty;
  `allocate_v4_source` then returns `None` and NAT64 forward translation
  cannot proceed for any flow using that rule.

A bare-IP static NAT / discrete bare-IP pool happens to parse, which is why
quick smoke tests never caught it. The /32 form is the *canonical* Junos
syntax (it is literally the form used in the project's own #2008 H15 test,
which only asserts the Go-side `.Match` field and never verifies the Rust
install).

## Decision: fix the Rust parse side (be tolerant of the canonical /32-/128 form)

The codebase already has an established idiom for exactly this: the SNAT
pool path at `userspace-dp/src/nat/source.rs:240-251` strips the mask before
parse:

```rust
// Pool addresses may be bare IPs or /32 CIDRs — strip the mask.
let ip_str = addr_str.split('/').next().unwrap_or(addr_str);
if let Ok(ip) = ip_str.parse::<IpAddr>() { ... }
```

The fix mirrors that idiom in both buggy sites. Rationale for the Rust side
over the Go side:

1. It matches the existing, reviewed SNAT-pool idiom — one consistent way to
   handle the canonical form across all NAT pool/address parse sites.
2. Static NAT's `external_ip` feeds two consumers (the DNAT/SNAT maps AND
   `external_ips()` local-address recognition). A tolerant parse fixes both
   with a single change at the parse boundary.
3. It is robust against any Go caller that supplies a masked form; the Go
   side already strips for DNAT, but the parse-side tolerance is the
   lower-blast-radius, canonical fix and needs no Go change.
4. The masks emitted here are always host masks (/32 from `expandAddressRange`,
   /32 or /128 from canonical prefix form). NAT static and the NAT64 pool
   operate on exact host IPs, so discarding the mask is semantically correct
   — there is no prefix-length information to lose.

Note the NAT64 *prefix* (`64:ff9b::/96`) is intentionally NOT touched: it
already splits on `/` and validates the /96 (`nat64.rs:60-67`). Only the
`pool_addresses` collection is the bug.

## Concrete design

### static_nat.rs (#2122)

Add a small private helper and route both parses through it:

```rust
/// Parse a NAT address that may carry a canonical host mask (`x.x.x.x/32`,
/// `addr/128`). Junos emits static-NAT match/then in canonical prefix form;
/// IpAddr::from_str rejects the mask, so strip it before parse. Mirrors the
/// SNAT-pool idiom in nat/source.rs.
fn parse_nat_addr(s: &str) -> Option<IpAddr> {
    s.split('/').next().unwrap_or(s).parse().ok()
}
```

`from_snapshots` then becomes:

```rust
let external_ip = match parse_nat_addr(&snap.external_ip) {
    Some(ip) => ip,
    None => continue,
};
let internal_ip = match parse_nat_addr(&snap.internal_ip) {
    Some(ip) => ip,
    None => continue,
};
```

The existing skip-on-invalid behavior (`continue` on a genuinely malformed
address) is preserved — `parse_nat_addr` still returns `None` for
`"not-an-ip"`.

### nat64.rs (#2123)

```rust
let pool_v4: Vec<Ipv4Addr> = snap
    .pool_addresses
    .iter()
    .filter_map(|s| s.split('/').next().unwrap_or(s).parse().ok())
    .collect();
```

## Public API preservation

No signatures change. `StaticNatTable::from_snapshots`,
`Nat64State::from_snapshots`, and all downstream methods keep their exact
shapes. Only the internal parse becomes mask-tolerant.

## Hidden invariants preserved

- **Skip genuinely-invalid addresses.** `parse_nat_addr("not-an-ip")` →
  `None` → `continue`, matching the existing `static_nat_invalid_ip_skipped`
  test. The NAT64 `filter_map` likewise still discards genuinely-bad entries.
- **Bare addresses still parse.** `split('/').next()` on a string with no
  `/` returns the whole string, so existing bare-IP configs are unaffected.
- **No allocation on the hot path.** This is config-apply (snapshot install)
  time, not per-packet. `split('/').next()` returns a borrowed `&str`, no
  allocation.
- **external_ips() local-address recognition** is fixed as a side effect:
  the DNAT map is now populated for /32 rules, so `external_ips()` yields the
  external IP and inbound traffic is recognized.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Strictly widens accepted input; bare-IP and invalid-IP behavior unchanged. |
| Lifetime / borrow | LOW | `split('/').next()` borrows from the snapshot string; no new owned data. |
| Performance | NONE | Config-apply path, not per-packet. |
| Architectural mismatch | NONE | Mirrors the existing reviewed source.rs idiom. |

## Test plan (non-tautological — must FAIL pre-fix)

cargo unit tests added in `nat/tests.rs` and `nat64_tests.rs`:

- **#2122**:
  - `static_nat_dnat_matches_external_ip_v4_with_cidr_mask` — external_ip
    `203.0.113.5/32`, internal_ip `10.0.0.5/32`; assert `match_dnat` and
    `match_snat` both succeed AND `external_ips()` contains the bare external
    IP. (Fails pre-fix: both parses error → rule dropped → table empty.)
  - `static_nat_dnat_matches_external_ip_v6_with_cidr_mask` — `.../128`.
  - Keep the existing bare-IP and `static_nat_invalid_ip_skipped` tests
    green (proves no regression of the skip path).
- **#2123**:
  - `nat64_pool_with_cidr_mask_yields_nonempty_pool` — pool addresses
    `["100.64.0.1/32", "100.64.0.2/32"]`; assert `pool_v4.len() == 2` and
    `allocate_v4_source` returns the expected round-robin addresses. (Fails
    pre-fix: filter_map discards both → pool empty → allocate returns None.)
  - `nat64_pool_mixed_bare_and_masked` — `["198.51.100.1", "198.51.100.5/32"]`
    → both present (proves range-expanded + discrete-bare coexist).

Gates: cargo build clean, full `cargo test` suite, 5x flake on the new named
tests, full Go suite (no Go change, but run to confirm nothing breaks).

## Smoke

Loss-cluster NAT smoke is **pending parent-run** (the parent drives the NAT
smoke via /security-matrix: trust→untrust SNAT). This PR does not run the
loss-cluster smoke per the engineering directive.

## Out of scope

- Go-side mask stripping for static-NAT / NAT64 snapshots — deliberately not
  done; the parse-side fix is canonical and sufficient. The DNAT Go-side
  strip stays as-is (it strips before the snapshot; harmless either way).
- NPTv6 prefix handling (`nptv6.rs` already splits on `/`).
