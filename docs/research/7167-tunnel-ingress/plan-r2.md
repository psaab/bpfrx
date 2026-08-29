# #7167 — bounded logical-tunnel-ingress: research plan r2

Continues `plan-r1.md`. Written at `1ca966a8d`, still before any
implementation.

**Status: r1's blocking §3 measurement is ANSWERED, and answering it also
CORRECTS a conclusion recorded in the issue's own comment thread. The correction
matters more than the answer, because it inverts the safety reading of one of
the two config shapes.**

---

## 1. What r1 left blocking, and what the issue thread had already done

r1 §3 said the hinge was "is the outbound (LAN → tunnel) direction already
adjudicated?" The issue thread then measured two things and left a third open:

1. The FIB resolves a route via a tunnel ifindex normally (`ForwardCandidate`),
   and `tunnel_interfaces` membership cannot change that — the FIB's tunnel
   branch is gated on `tunnel_endpoint_id != 0`, a property of the ROUTE, and an
   xfrmi route carries no endpoint id. So the fixture was structurally the
   production shape.
2. `egress_zone_id(xfrmi)` is the tunnel's zone for Shape A (interface row
   exists and is zoned) and **0** for Shape B (`bind-interface` only, no row).
   Against the policy evaluator in isolation, to-zone 0 **denies** under every
   policy tested, including a `from-zone any to-zone any permit` wildcard.
3. **Left open:** that implies a Shape B tunnel is non-functional outbound, yet
   #4515 blesses Shape B. So either (a) those packets never reach the evaluator,
   or (b) Shape B is outbound-broken and unreported.

## 2. THE ANSWER: (a). Shape B never reaches the evaluator.

Measured by executing the real Go→Rust forwarding build and the real FIB lookup,
not by reading. Same route in both arms — a static route whose next-hop is the
tunnel INTERFACE only (`@st0.0`), which is the shape a route-based IPsec config
produces. The ONLY difference is whether an interface row for `st0.0` exists:

```
Shape A (interface row)  built[ifindex=44 nh=None] -> disposition=MissingNeighbor  egress_ifindex=44
Shape B (no row)         built[ifindex=0  nh=None] -> disposition=NoRoute          egress_ifindex=0
```

### The mechanism, end to end

1. Go encodes an interface-only next-hop as `"@" + iface` — `routes.go`
   (`case nh.Interface != "": target = "@" + nh.Interface`).
2. Rust `parse_route_next_hop("@st0.0")` → `(None, Some("st0.0"))`
   (`forwarding_build/fib.rs:408`).
3. `resolve_ifindex` looks the name up in `names` then `linux_names`
   (`forwarding_build/fib.rs:446`). **Shape B has no interface row, so it is in
   neither map** → `None`.
4. `.unwrap_or((0, 0))` (`forwarding_build/fib.rs:381`, v6 at `:405`) turns that
   miss into **ifindex 0** — a legal-looking value, not an error.
5. At lookup, `if ifindex <= 0 { return no_route_resolution(...) }`
   (`forwarding/fib.rs:546`) → **NoRoute**.
6. `NoRoute.is_slow_path_eligible()` is **true**, pinned at
   `tests_slow_path_disposition.rs:100`, beside `PolicyDenied` /
   `HAInactive` / `DiscardRoute` which are explicitly *"NOT eligible: must drop,
   never reinject"* (`:102-105`).

So the packet is **reinjected to the kernel**, which forwards it under no zone
policy, no session, no NAT, no screen, and no nftables `hook forward` chain.

### Step 4 is the defect's shape, and it is a known class

`resolve_ifindex` returning `None` and `.unwrap_or((0, 0))` collapsing it into a
**legal zero** is a resolver whose failure is indistinguishable from a valid
result at its own boundary. Nothing between step 4 and step 5 can tell "no such
interface" from "interface 0". Any fix that makes Shape B visible must decide
what an unresolvable tunnel next-hop MEANS, not merely populate the map.

## 3. THE CORRECTION: Shape B is fail-OPEN in production, not fail-closed

The issue thread concluded, from the isolated evaluator probe, that *"Shape B is
fail-closed, not silently permitted — every policy set denies, including the
wildcard."*

**That is true of the evaluator and false of production.** The Shape B packet
resolves NoRoute at step 5 and is reinjected at step 6; it never reaches the
evaluator whose verdict was measured. The isolated probe measured a site the
production path does not arrive at, so its `Deny` describes a branch that is
never taken.

The production reading is the opposite one: **Shape B outbound is unadjudicated
kernel forwarding** — the #7167 defect itself, in the direction requirement 9
covers.

This also resolves why Shape B tunnels work in the field: they work *because*
they are unadjudicated, not because they are permitted.

### Consequence for requirement 9

Requirement 9 ("route-based IPsec egress must retain xpf policy evaluation
before kernel XFRM encryption") is:

| shape | outbound disposition | requirement 9 |
|---|---|---|
| Shape A (row, zoned) | `MissingNeighbor` → runs its own zone-policy evaluation; a deny exits before the reinject gate | **satisfied** |
| Shape B (no row) | `NoRoute` → unconditional reinject | **NOT satisfied** |

r1 §2.2's egress objection is therefore answered *for Shape A only*. An
ingress-only capture mechanism covers both directions for Shape A. For Shape B
it does not, because Shape B has no adjudicated outbound path to preserve.

### Consequence for #7949

#7949 asks whether making a `bind-interface`-only tunnel visible in
`snapshot.Interfaces` is a neutral change. The issue thread suggested the risk
was turning a working tunnel into a dead one (*not evaluated* → *evaluated and
denied*). The measurement changes the baseline, and both halves move:

- Today's Shape B baseline is **not** "not evaluated, benign". It is
  "unadjudicated kernel forwarding" — a security gap, not a neutral state.
- Adding a row moves Shape B from `NoRoute` to `MissingNeighbor`, i.e. into
  adjudication. If the row names a zone, that is the fix. If it names none,
  to-zone is 0 and the tunnel goes dark.

So the row change is not neutral in either direction, and the zone must be
authored in the same change. That is a sharper statement than either issue
currently carries.

## 4. What is NOT established here

- **Nothing about the inbound direction.** This measures LAN → tunnel only. The
  decapped-plaintext ingress problem that is #7167's core is untouched by it.
- **Nothing about whether the reinjected packet is actually forwarded.** Step 6
  establishes reinject-eligibility; that the kernel then routes it rests on
  `ip_forward=1`, which `daemon_transit_gate.go` keeps at 1 whenever the
  dataplane is armed and names this very path as the reason.
- **Nothing about Shape A's inbound.** Shape A's outbound being adjudicated says
  nothing about decapped inbound plaintext, which arrives on the xfrmi and is
  excluded from binding by `netdevExclusionClasses`.

## 5. Corrections to r1 itself

r1 §3 wrote that `NoRoute` is *"a **drop** disposition (`disposition.rs:865` —
bumps `route_miss`, records an exception), yet route-based IPsec demonstrably
works, so LAN→tunnel traffic is not resolving NoRoute. Something else is
happening and the plan must say what."*

Both halves need correcting. `disposition.rs:865` bumps a counter and records an
exception; it is **not** the drop/reinject decision. That decision is
`is_slow_path_eligible()`, and NoRoute IS eligible
(`tests_slow_path_disposition.rs:100`). So NoRoute is a **reinject**, and
LAN→tunnel traffic on Shape B *is* resolving NoRoute — the "something else"
r1 went looking for is the slow-path gate, and the answer is that there is no
contradiction to resolve.

## 6. The next measurement

Inbound, and it is r1 §4's item 2 rather than a new one: **what does the
evaluation contract need, expressed without reference to xfrmi or to a TUN
write?** §2's finding sharpens one input to it — a capture mechanism must supply
a resolvable logical ifindex, because an unresolvable one does not fail closed,
it becomes ifindex 0 and reinjects.

## 7. Method, for reproduction

The probe was temporary and is not committed. ~80 lines appended to
`userspace-dp/src/afxdp/forwarding/tests.rs`: build a `ConfigSnapshot` with one
LAN interface and one route `next_hops: ["@st0.0"]`, run it through
`build_forwarding_state`, then `lookup_forwarding_resolution_v4` for a
destination inside the routed prefix; the two arms differ only by whether an
`InterfaceSnapshot` for `st0.0` is pushed. Run with
`cargo test --manifest-path userspace-dp/Cargo.toml --bins <name> -- --test-threads=1 --nocapture`.
