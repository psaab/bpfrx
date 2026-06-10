# Claude SMR plan-review — #1844 round 1

Reviewer stance: hostile domain SMR (control-plane routing, DHCP client
lifecycle, Go concurrency). Reviewed plan v1 (`plan.md` @ 1388f2499)
against the post-#1843 tree (`origin/engineer/1827-ipmon-pr1` @
d18071d5c). I attempted to break the trigger plumbing, the
winner-resolution change, and the withdrawal story; findings below are
quote-anchored.

## Verdict: PLAN-NEEDS-REVISION

Architecture is sound (single decision point preserved; no second
actuation path; dependency direction daemon → {ipmon, dhcp} kept;
v4-only cut is correctly justified by `RouteSnapshot` having no device
field — `pkg/dataplane/userspace/protocol.go:499-506` confirms, and
adding one is a both-sides wire change). But the plan misdescribes the
lease-delete fire sites, and three smaller holes need folding before
PLAN-READY.

## Findings

### 1. HIGH — §4.3 fire-site enumeration is wrong; the terminal site is `finishClient`, not the run-loop deletes

Plan §4.3 item 2 says the delete fires live in "the `ctx.Done()`
branches of `runDHCPv4` / `runDHCPv6`" and proposes
`removeLeaseAndNotify(key)` replacing "the four inline delete sites".
The code says otherwise: lease cleanup is **centralized in
`finishClient`** (`pkg/dhcp/dhcp.go:274-305`), which runs in the client
goroutine's defer "on every exit path" — including cancellation
interleavings that exit the run loop **without** hitting its own
`ctx.Done` cleanup branches (the function comment says exactly this,
and it covers DHCPv4 max-retransmission exit and the DHCPv6 link-local
abort, which the run-loop branches do NOT cover). The plan's scheme
either double-fires (run-loop branch deletes, then finishClient fires
again) or — worse, if the helper gates on lease presence — misses the
max-retransmission and mid-exchange-cancel exits entirely, leaving a
stale gateway in the overlay after a client dies.

**Required revision:** exactly two fire sites: (a) `commitLease` on
gateway delta (as planned); (b) `finishClient`, fired unconditionally
after `m.mu.Unlock()` (cheap; the engine gate absorbs no-ops). Drop the
run-loop `removeLeaseAndNotify` idea; the run-loop inline deletes stay
untouched (their redundancy with finishClient is pre-existing and not
this PR's business).

### 2. MEDIUM — hook wiring must be a nil-guarded closure, not a method value

Plan §4.3 wires `d.dhcp.SetGatewayChangeHook(d.ipmon.NotifyNextHopChange)`.
Verified safe TODAY: `d.ipmon = ipmon.New(...)` precedes the first
`applyConfig` (daemon_run.go:244, comment says "before the first
applyConfig"), and the DHCP manager is created lazily inside an apply
(`daemon_dhcp.go:119`). But that's an ordering accident two refactors
away from a nil-pointer panic on a DHCP-client goroutine. Wire a
closure: `func() { if e := d.ipmon; e != nil { e.NotifyNextHopChange() } }`.
Same for the resolver (`resolveDHCPNextHop` already nil-checks `d.dhcp`
per the plan — keep symmetric).

### 3. MEDIUM — interface-name spelling/normalization is underspecified

Plan §4.1 check 2 says the value "must parse as `<ifd>.<unit>` where
the unit exists in `cfg.Interfaces`". Three unstated decisions:
(a) bare ifd (`next-hop ge-0/0/3`) must be rejected with a
distinct error (unit required), not fall through to "not a valid IP";
(b) the accepted spelling must be defined as **the interface name as
configured under `interfaces`** (Junos form, `ge-0/0/3.0`) — decide
explicitly whether the dashed Linux form (`ge-0-0-3.0`) is also
accepted (recommend: no; error message names the configured form);
(c) the `<unit>` token is the UNIT NUMBER, but the lease key uses the
**VLAN ID** when `unit.VlanID > 0` (`daemon_dhcp.go:30-33`) — unit
number ≠ vlan-id in general. The plan's example (`ge-0/0/3.50` "when
the unit has vlan-id 50") quietly assumes unit==vlan. The compile rule
must be: operator writes `<ifd>.<unit-number>`; the compiler looks up
that unit and derives the lease key from its VlanID via the shared
helper. State this.

### 4. MEDIUM — commit-reject management interfaces

`collectDHCPRoutes` excludes mgmt-VRF leases from FRR
(`daemon_flow.go:31-33`) because mgmt routing must not leak into the
default table. An interface-typed next-hop naming `fxp0.0` (DHCP,
`unit.DHCP` true — passes plan §4.1 check 4) would inject a default
route via the management gateway into the master table the moment a
policy fails. Compile-time reject interface-typed next-hops on
management interfaces (fxp*/em*/fab* — same name classes the daemon
treats as mgmt). Cheap check, closes a real operator footgun.

### 5. LOW — document the Renew transient

`Renew` (`pkg/dhcp/dhcp.go:309-352`) cancels the client →
`finishClient` removes lease AND address → fresh DORA. With finding 1's
fire site, a manual `request dhcp client renew` during FAIL produces a
withdraw-then-reinject pair if re-acquisition outlasts the debounce.
This is CORRECT (the uplink address itself is gone during the window)
but will surprise operators; add to §4.5.

### 6. LOW — `PolicyStatus` needs an explicit field for the unresolved annotation

§4.2 says display.go annotates "by diffing cfg-declared routes against
resolved ones" — display.go only sees `PolicyStatus`. Add
`UnresolvedRoutes []string` (destination prefixes whose candidate was
skipped) populated in `Status()`; keeps display dumb.

### 7. LOW — gauge definition

`xpf_ipmon_unresolved_next_hops` "at last overlay computation":
`activeOverlayLocked` is called from `Status()`/`RoutesApplied()` too,
so the value refreshes on metric scrape without an actuation — fine,
but say so, and make the skip-count a return value rather than engine
side-state to keep `activeOverlayLocked` pure.

## Answers to plan §12 questions (SMR position)

1. No parse ambiguity found: no valid interface name parses as an IP
   (`net.ParseIP` accepts no `/` or alpha); tunnel/loopback units fail
   the `unit.DHCP` check structurally — no extra rejection needed
   beyond finding 3's normalization rules.
2. Keep last-known gateway (parity). The expiry timer is machinery
   without an operator scenario: in the expiry window the kernel
   address is still plumbed and the FRR AD-200 default still points at
   the same gateway — withdrawing only the overlay route changes
   nothing real.
3. Gate is sufficient. Same-content re-actuations are bounded by the
   3 s throttle and made cheap by the snapshot content-hash skip; a
   per-key resolved-gateway cache is premature state.
4. v4-only stands — verified the wire-change claim (finding preamble).
5. Aggregate `func()` is right; per-key payload has no consumer (the
   resolver re-reads everything) and would just grow the API.
