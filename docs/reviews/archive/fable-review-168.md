# fable-review-168 — reth (Redundant Ethernet) Config & Operational Parity

**Focus (operator-directed):** "The reth configs are completely wrong and
missing." Reference: `/home/ps/vsrx.conf` (a real vSRX chassis-cluster
config, `reth-count 5`, reth0–reth4). Compared against the running loss
cluster (`loss:xpf-userspace-fw0/fw1`) and current `origin/master`
(`ba4553bfa`).

## 0. Bottom line up front

The reth **configuration** and **forwarding** are NOT wrong or missing —
they compile faithfully and the addresses are programmed and forwarding.
What IS broken is reth **operational visibility**: the everyday command
an operator uses to inspect an interface —

```
show interfaces reth0
show interfaces reth0.50
show interfaces reth0 detail
show interfaces reth0 extensive
```

— reports **"Physical interface: reth0, Not present"** (or empty), on
both the local CLI and the remote/gRPC CLI. Only `show interfaces terse`
works. To an operator that reads exactly as "reth is missing" — which is
what was observed — even though the reth is configured, up, and passing
traffic.

This is a **localized CLI/gRPC show-path bug**, not a dataplane or
config-compiler defect, so the fix is small and low-risk. Root cause and
fix are in §3.

## 1. What is actually correct (evidence the config/forwarding are fine)

A probe compiling the vsrx.conf reth model
(`chassis cluster reth-count 5` + RG0/1/2/3/5 + reth0/1/2/4 with the full
unit sets) through xpf's real parser+compiler
(`config.NewParser` → `CompileConfigForNode`, node 0) preserves it
faithfully:

```
CLUSTER reth-count=5  node-id=0  RGs=5
  RG1 monitors=[ge-0/0/0 ge-7/0/0]   RG2 monitors=[ge-0/0/3 ge-7/0/3]
  RG3 monitors=[ge-0/0/1 ge-7/0/1]   RG5 monitors=[ge-0/0/2 ge-7/0/2]
IFACE reth0  vlanTag=false redGroup=1 units=1
    unit 0    addrs=2 [50.220.171.30/30 2001:559:800c:1900::881a/126]
IFACE reth1  vlanTag=true  redGroup=2 units=5
    unit 1    vlan-id=1  addrs=7 [192.168.0.254/24 192.168.0.1/24 10.255.0.1/24 172.16.0.1/20 fe80::351/64 …]
    unit 50   vlan-id=50 addrs=1 …  unit 80  vlan-id=80 addrs=2 …
IFACE reth2  vlanTag=false redGroup=3 units=1     (inactive: vlan-tagging correctly deactivated)
IFACE reth4  vlanTag=false redGroup=5 units=1 addrs=4 …
```

Verified correct at the config layer:
- `reth-count 5`, non-contiguous redundancy-groups (0,1,2,3,5) preserved;
- `redundant-parent` bindings (ge-X/0/N → rethM) correct on both nodes;
- `redundant-ether-options { redundancy-group N; }` → `RedundancyGroup`;
- `vlan-tagging` on reth1 = true; per-unit `vlan-id` preserved;
- **multi-address per family preserved** (reth1 unit 1 = 7 addresses;
  reth4 unit 0 = 4) — not truncated to the first;
- **`inactive: vlan-tagging`** on reth2 correctly leaves `VlanTagging =
  false` (Junos-correct — an inactive statement is not applied);
- `xpfd check-config` PASSES the reth model (reth-count 5, reth4/RG5,
  `inactive: vlan-tagging`, multi-address, `primary`/`preferred`).

And on the live loss cluster, the reth addresses ARE programmed and
forwarding — but on the **physical member**, because xpf uses **bondless
RETH** (no `reth0` bond netdev; VRRP + addresses live on the active
member, per CLAUDE.md "bondless RETH … RethToPhysical resolution"):

```
ge-0-0-1   UP   10.0.61.1/24  2001:559:8585:ef00::1/64      ← reth1.0
ge-0-0-2.50  UP 172.16.50.8/24 2001:559:8585:50::8/64       ← reth0.50
ge-0-0-2.80  UP 172.16.80.8/24 2001:559:8585:80::8/64       ← reth0.80
# there is NO kernel netdev named reth0 or reth1
```

`show chassis cluster status` / `show chassis cluster interfaces` render
reth0/reth1 Up under their RGs, with interface-monitor and fabric state —
all correct. So the HA/reth machinery genuinely works.

## 2. The break (reproduced live on loss)

Every operational `show interfaces` variant EXCEPT `terse` fails to find
the reth:

| Command | Result | vSRX behavior |
|---|---|---|
| `show interfaces terse [reth0]` | ✅ works (synthesizes reth0.50/.80, `aenet --> reth0.50` on members) | shows reth |
| `show interfaces reth0` | ❌ `Physical interface: reth0, Not present` | full reth detail |
| `show interfaces reth0.50` | ❌ `Physical interface: reth0, Not present` | logical unit detail |
| `show interfaces reth1.0` | ❌ `interface reth1.0 not found in configuration` | logical unit detail |
| `show interfaces reth0 detail` | ❌ empty output | detail |
| `show interfaces reth0 extensive` | ❌ `interface extensive not found in configuration` | extensive |

Secondary: the physical-member detail view omits the reth association.
`show interfaces ge-0-0-2 detail` shows the **reth virtual MAC**
(`02:bf:72:16:01:00`) and a bare `ge-0-0-2.0`, but does NOT list the
reth0.50 / reth0.80 logical units that actually live on it, and never
says the member belongs to reth0. vSRX shows the member's units as
`aenet` pointing at the reth. (Terse DOES show `aenet --> reth0.50`;
detail does not.)

(The loss box runs an April build, but the break is confirmed present at
current `origin/master` — see §3.)

## 3. Root cause (code, at HEAD `ba4553bfa`)

The reth→physical-member resolution helper `cfg.RethToPhysical()` (and
the `physToReth` reverse map) is called in **exactly one place**: the
terse handler. Every other show path does a raw kernel-netdev lookup that
cannot succeed for a bondless reth.

`pkg/cli/cli_show_interfaces.go`:
- `showInterfacesTerse()` (line 544) — builds `physToReth` /
  `rethToPhys := cfg.RethToPhysical()` (lines 552-553) and synthesizes
  the reth view. **This is the only reth-aware path.**
- `showInterfaces()` summary loop (line ~180) — resolves the name to a
  netdev via `netlink.LinkByName(physName)` / `net.InterfaceByName`, and
  on failure prints `"Physical interface: %s, Not present"`
  (line 189). For `reth0` there is no netdev → "Not present". No
  `RethToPhysical` call.
- `showInterfacesDetail(filterName)` (line 421) — iterates
  `netlink.LinkList()` and keeps only `attrs.Name == filterName`. No
  kernel link is named `reth0`, so nothing matches → empty output. No
  `RethToPhysical` call.
- `showInterfacesExtensiveFiltered()` (859) — same netlink-based shape.

`pkg/grpcapi/server_show_interfaces.go` mirrors this exactly: the same
`RethToPhysical()`/`physToReth` logic exists only in its terse handler
(lines 382-383), while the detail path prints the identical
`"Physical interface: %s, Not present"` (line 150). So the remote `cli`
client and any gRPC consumer of the text `show interfaces` hit the same
wall. (Issue **#3460**, closed June, fixed the *structured* `GetInterfaces`
RPC to resolve kernel ifnames — a different surface; it did not touch the
text detail/extensive/summary paths audited here, which still lack reth
resolution at HEAD.)

The `filterName != "" && !strings.HasPrefix(...)` filter also explains
the "not found in configuration" variants: a reth only enters the summary
loop via a security-zone membership, and the member/modifier arg parsing
(`extensive`, `reth1.0`) diverges further.

## 4. Fix direction

Teach the non-terse show paths the same reth resolution the terse path
already has — this is a copy of existing, working logic, not new
machinery:

1. In `showInterfaces` (summary) and `showInterfacesDetail` /
   `…Extensive` (both CLI and the gRPC twins): before the raw netdev
   lookup, build `physToReth`/`rethToPhys := cfg.RethToPhysical()`. When
   the requested name is a reth (present in `rethToPhys`), render the
   reth as a logical aggregate over its resolved physical member —
   pulling counters/MAC/link-state from the member netdev and the
   addresses/units from `cfg.Interfaces[reth].Units`. When the requested
   name is a reth **member**, add the `aenet --> reth<N>.<unit>` lines
   (as terse already does at line 702 / gRPC 572) and list the reth
   logical units.
2. Fold the four surfaces (CLI summary/detail/extensive + gRPC) through a
   single reth-resolution helper so terse and detail cannot drift again.
3. Add a regression test: a 2-reth cluster config, assert
   `show interfaces reth0`, `reth0.0`, and `reth0 detail` are non-empty
   and name the physical member — none exists today (the gap survived
   precisely because only terse is covered).

## 5. Related / context (not part of this bug)

- **reth `mac <addr>` override is reject-at-commit** (`#2008 H10`,
  intentional per the deterministic per-node RETH-MAC design). vsrx.conf
  carries it on reth2 as `inactive: mac …`, so it does not trip the
  reject — but an operator migrating a vSRX config with an **active**
  reth `mac` gets a hard commit failure. This is a known/tracked
  intentional divergence, cited for migration awareness, not re-reported.
- reth `redundant-ether-options { lacp … / minimum-links … }` is not
  exercised by vsrx.conf; `MinimumLinks` exists in the type but LACP on a
  bondless reth is a separate question — out of scope here.

## 6. Dedup note

Not previously reported. codex-review-153 touched host-inbound duplicate
local addresses (adjacent area, different bug). #3460 (closed) fixed the
structured `GetInterfaces` RPC's kernel-ifname resolution; #1565 (closed)
fixed `net.InterfaceByName` with `/`-names in `pkg/api`. Neither covers
the text `show interfaces <reth> [detail|extensive]` reth-resolution gap,
which is present at HEAD on both the CLI and gRPC text paths.

## 7. Verification performed

- Compiled the vsrx.conf reth model through the real parser+compiler
  (probe test, `pkg/config`) — dump in §1.
- `xpfd check-config` on the reth model + hard variants (reth4/RG5,
  `inactive: vlan-tagging`, multi-address, `primary`/`preferred`) — all
  PASS.
- Live `loss:xpf-userspace-fw0`: `show interfaces` variants (§2),
  `show chassis cluster status/interfaces`, `ip -br addr`, `/etc/xpf/
  xpf.conf` reth source vs running-config (round-trips faithfully).
- Read the current-master (`ba4553bfa`) CLI + gRPC show-interfaces code
  to confirm the root cause is present at HEAD, not only the April build
  (§3). No repo files modified; loss candidate NOT touched (it was locked
  by another agent — respected the #1875 lock).
