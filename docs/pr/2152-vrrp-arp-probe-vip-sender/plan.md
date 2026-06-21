# #2152 — VRRP gateway ARP probe must use the VIP as sender, not the primary IP

Status: PLAN-READY — Codex PLAN-NEEDS-MINOR + AGY PLAN-NEEDS-MINOR, all
minors resolved (see "Adversarial plan review" below).

## Adversarial plan review

- Codex (task-mqncaton-c1y329): PLAN-NEEDS-MINOR. Confirmed architecture
  correct; confirmed caller-3 must stay primary-IP; confirmed exactly 3
  callers; confirmed VIP sites gated by `ip.To4()!=nil`. Minors:
  (1) the vrrp test must be a CALL-SITE seam executing sendGARP and
  capturing the sender, not a pure frame-build helper (tautological) —
  ADDRESSED: implemented `arpProbeFn` seam +
  `TestSendGARPProbeUsesVIPAsSender`. (2) `PrimaryIPv4` returns
  first-non-LL IPv4 (kernel order), not "the configured primary" —
  ADDRESSED: comment/name describe it honestly ("first non-link-local
  IPv4", "interface-derived sender"); kept exported as it is a
  cross-package (cluster -> daemon) helper with a unit test. (3) the
  skip-if-VIP-is-.1 guard exists in sendGARP but NOT directSendGARPs —
  ADDRESSED: added the guard to directSendGARPs for parity.
- AGY (adversarial-review-mqncbb5u-u4se03): PLAN-NEEDS-MINOR. Confirmed
  caller-3 primary-IP is "100% correct". Minors: (3) directSendGARPs
  missing the skip-.1 guard — ADDRESSED (same as Codex 3). (4) test must
  be a real seam, not a frame-build — ADDRESSED. (2) flagged a
  MASTER->BACKUP goroutine state-race (sendGARP runs async; a node that
  just lost MASTER could still emit a probe for a VIP it no longer
  owns). DEFERRED as out of scope: this race pre-dates #2152 and already
  affects the gratuitous-ARP burst (`SendGratuitousARPBurst`) and IPv6
  NA in the same goroutine — the sender-IP fix does not make it worse.
  Adding a `getState()!=StateMaster` guard would gate the GARP/NA burst
  too and interacts with the #2081/#2082 forced-send / ReconcileVIPs
  semantics; it deserves its own issue, not a rider on this surgical
  fix. NOTE: AGY wrote its own implementation into the MAIN checkout
  (`/home/ps/git/bpfrx`), not this worktree — those edits are NOT part
  of this PR and must be discarded by the operator.

Original status: DRAFT v1 — pending adversarial plan review

## Issue framing

On a VRRP master transition, `sendGARP` emits a gratuitous-ARP burst per
VIP and then, to defeat routers that ignore gratuitous ARP, sends a
unicast ARP *Request* (a "probe") to the subnet gateway (`.1`). The ARP
protocol guarantees the target updates its ARP cache from the request's
**sender** hardware/protocol address fields, so the probe's sender IP is
load-bearing: it MUST be the VIP so the gateway re-binds VIP → our (new)
MAC.

`SendARPProbe(iface string, targetIP net.IP)` does NOT receive the
sender IP. It self-resolves the sender from `ifi.Addrs()`, picking the
first non-`169.254.x.x` IPv4. A RETH interface carries both the node's
primary IP (e.g. `10.0.0.2`) and the VRRP VIP (e.g. `10.0.0.100`); the
primary is usually added first, so the probe goes out with sender =
primary. The gateway refreshes its cache for the primary and learns
nothing new about the VIP. After failover the gateway's VIP → MAC entry
stays stale (old node's MAC) until it ages out (minutes), blackholing
VIP traffic and defeating the sub-100ms failover target against
GARP-ignoring gateways.

Both `sendGARP` (`pkg/vrrp/instance.go`) and the `SendARPProbe` loop
comment already SAY "use the VIP" — this is an intent/impl mismatch, not
a design question.

## Honest scope/value framing

Pure HA failover-correctness fix. No perf dimension — the win is that
VIP traffic is not blackholed for minutes on failover against gateways
that ignore gratuitous ARP. Surgical: one signature change, three
callers updated, one dead loop replaced by an explicit-parameter helper.
If reviewers conclude the approach is wrong, PLAN-KILL is an acceptable
verdict — but the fix matches the issue's recommended fix verbatim.

## What's already shipped / relevant prior work

The dual GARP (Request+Reply) + gateway ARP-probe mechanism landed
earlier (docs/bugs.md "Failover loss reduced from ~30s to ~3.5s"). The
gateway probe was wired into `sendGARP` and `directSendGARPs`. The
sender-IP self-resolution bug has been latent since then.

## Blast radius — ALL callers of SendARPProbe (3, not 1)

The issue text names only the `sendGARP` call site. Repo grep finds
THREE callers, and they do NOT all want the VIP:

1. `pkg/vrrp/instance.go` `sendGARP` (~L1286) — VRRP failover GARP.
   VIP is in scope (`ip.To4()`). **Must pass VIP.** (The bug.)
2. `pkg/daemon/daemon_ha_vip.go` `directSendGARPs` (~L519) —
   direct-mode (non-VRRP) failover GARP for an RG's VIPs. VIP is in
   scope (`ip.To4()`). **Same bug, same fix — must pass VIP.**
3. `pkg/daemon/daemon_neighbor.go` (~L347) — NUD_FAILED neighbor-table
   reprobe. This is NOT a VIP refresh; it wants the kernel to
   repopulate ARP for a forwarded next-hop. The correct sender here is
   the interface's own primary IPv4 (the CURRENT self-resolve
   behavior). **Must preserve the self-resolve semantics** — passing a
   VIP here would be wrong.

So "drop the now-dead loop" (issue text) is only correct for callers 1
and 2. Caller 3 still needs primary-IP self-resolution. The clean
design keeps that logic available as an explicit helper.

## Concrete design

### `pkg/cluster/garp.go`

Change the signature to take the sender explicitly and build the frame
from it directly (no self-resolution inside):

```go
// SendARPProbe sends a standard ARP Request for targetIP with senderIP
// as the ARP sender protocol address. The target (typically a router)
// updates its ARP cache with senderIP -> our MAC as a side effect, so
// senderIP MUST be the address whose MAC binding we want refreshed
// (e.g. a VRRP VIP on failover).
func SendARPProbe(iface string, senderIP, targetIP net.IP) error {
    sender4 := senderIP.To4()
    if sender4 == nil {
        return fmt.Errorf("sender not an IPv4 address: %s", senderIP)
    }
    target4 := targetIP.To4()
    if target4 == nil {
        return fmt.Errorf("target not an IPv4 address: %s", targetIP)
    }
    ifi, err := net.InterfaceByName(iface)
    if err != nil {
        return fmt.Errorf("interface %s: %w", iface, err)
    }
    pkt := buildARPRequest(ifi.HardwareAddr, sender4, target4)
    // ... unchanged raw AF_PACKET socket send ...
}
```

Extract the dropped self-resolution into a reusable helper so caller 3
keeps its behavior with an explicit sender:

```go
// PrimaryIPv4 returns the interface's first non-link-local IPv4 address,
// to use as an ARP sender IP when no specific source (e.g. a VIP) is
// required.
func PrimaryIPv4(iface string) (net.IP, error) {
    ifi, err := net.InterfaceByName(iface)
    ...
    // same loop as before; skip 169.254.x.x; first match wins
}
```

### `pkg/vrrp/instance.go` `sendGARP`

```go
if err := cluster.SendARPProbe(vi.cfg.Interface, ip.To4(), gwIP); err != nil {
```

(`ip` is the parsed VIP already in scope.)

### `pkg/daemon/daemon_ha_vip.go` `directSendGARPs`

```go
if err := cluster.SendARPProbe(ifName, ip.To4(), gw); err != nil {
```

(`ip` is the parsed VIP already in scope at the call site.)

### `pkg/daemon/daemon_neighbor.go`

Preserve primary-IP semantics explicitly:

```go
if sender, perr := cluster.PrimaryIPv4(p.iface); perr == nil {
    cluster.SendARPProbe(p.iface, sender, p.ip)
} else {
    slog.Debug("failed-neighbor reprobe: no IPv4 sender", "iface", p.iface, "err", perr)
}
```

(Behavior preserved: same first-non-LL-IPv4 the old in-function loop
selected; we just no longer hard-fail silently inside SendARPProbe.)

## Public API preservation

`SendARPProbe` is an exported cross-package symbol; its signature
CHANGES (adds `senderIP`). All three in-repo callers are updated in the
same PR. `grep -rn SendARPProbe` across the repo confirms no other
callers (docs references only). `PrimaryIPv4` is newly exported.

## Hidden invariants the change must preserve

- **Frame layout unchanged** — `buildARPRequest` is untouched; sender
  protocol address still at `pkt[28:32]`, target at `pkt[38:42]`.
- **Caller-3 sender semantics** — NUD_FAILED reprobe must still use the
  interface primary IPv4 (first non-link-local), not a VIP.
- **Error handling at call sites** — sendGARP / directSendGARPs already
  log-and-continue on probe error; unchanged.
- **No new per-packet / per-poll logging** — caller 3 stays on Debug.
- **`.1` gateway derivation, skip-if-VIP-is-.1 guard** — unchanged.

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | Signature change with all callers updated in-tree; caller 3 semantics preserved via PrimaryIPv4 helper. |
| Lifetime / borrow | N/A | Go. |
| Performance regression | NONE | Failover-only path; no hot path. |
| Architectural mismatch | NONE | Matches issue's recommended fix exactly; resolves a documented intent/impl mismatch. |

## Test plan (unit only — parent runs make test-failover)

Non-tautological assertion: the crafted ARP frame's **sender protocol
address field (`pkt[28:32]`) equals the VIP, not the primary**, and this
must FAIL against pre-fix behavior (which self-resolved to primary).

- **`pkg/cluster` `garp_test.go`**:
  - `TestBuildARPRequest_SenderIsExplicit` — call `buildARPRequest(mac,
    vip, gw)` and assert `pkt[28:32] == vip` and `pkt[38:42] == gw`.
    This locks the frame seam SendARPProbe feeds.
  - `TestSendARPProbe_RejectsBadSenderTarget` — IPv6 sender / IPv6
    target rejected with error (signature contract).
- **`pkg/vrrp` `instance_garp_test.go`** (or new file): a seam test that
  exercises the sendGARP wiring. Because `sendGARP` does live AF_PACKET
  I/O, introduce a package-level function var seam in cluster
  (`var arpProbeFn = sendARPProbeRaw`) OR — preferred, network-free —
  add a tiny exported pure helper that crafts the probe frame for a
  given (mac, vip, gw) and assert in the vrrp test that the frame built
  from the VIP-in-scope has sender == VIP. Final seam choice decided in
  implementation; the assertion MUST be: frame.sender == VIP, and the
  test MUST fail if the wiring reverts to passing the primary.
- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test -race ./pkg/cluster/ ./pkg/vrrp/`
- Full `go test ./...` build-sanity for the daemon callers.
- `make test-failover`: **PENDING — parent runs it** (VRRP/HA smoke
  class; this sub-task does NOT run loss-cluster smoke per instruction).

## Out of scope (explicitly)

- IPv6 NA / ND parity for the gateway probe (tracked in
  `docs/next-features/ipv6-ha-failover-parity.md`).
- Any change to gateway `.1` derivation heuristics.

## Open questions for adversarial review

1. Is keeping caller-3 (NUD_FAILED reprobe) on primary-IP self-resolve
   correct, or should it too pass a specific sender? (I claim primary is
   correct — it is a forwarding-path neighbor refresh, not a VIP move.)
2. Is `PrimaryIPv4` the right place/name, or should caller 3 inline its
   own resolution to avoid a new exported symbol?
3. Frame-seam vs function-var seam for the non-tautological vrrp test —
   which is least invasive and genuinely fails pre-fix?
4. Does `ip.To4()` at the directSendGARPs call site always re-parse to a
   4-byte form safe for buildARPRequest? (It is gated by `ip.To4() !=
   nil` already.)
5. Any caller of SendARPProbe outside the repo (vendored/embedded) that
   this breaks? (grep says no.)
6. Should the probe sender be validated to actually be one of the VIPs
   on the interface, or is trusting the caller acceptable? (I claim
   trust-caller; the VIP is already config-derived.)
