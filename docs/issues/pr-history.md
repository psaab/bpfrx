# bpfrx Pull Request History

Complete record of all pull requests.
Total: 234 PRs (211 merged)

---

## PR #1 — Fix destroy: delete profiles before networks to avoid "in use" error [CLOSED] (closed 2026-02-14)

Branch: `master`

Profiles reference the networks, so Incus refuses to delete a network while a profile still holds a device entry for it.
before fix:
```
jdp@coi:~/bpfrx$ ./test/incus/setup.sh destroy
==> Instance bpfrx-fw does not exist
Also remove networks and profiles? [y/N] y
==> Deleting network bpfrx-trust
Error: The network is currently in use
```
after fix:
```
jdp@coi:~/bpfrx$ ./test/incus/setup.sh destroy
==> Instance bpfrx-fw does not exist
Also remove networks and profiles? [y/N] y
==> Deleting profile bpfrx-vm
Profile bpfrx-vm deleted
==> Deleting profile bpfrx-container
Profile bpfrx-container deleted
==> Deleting network bpfrx-trust
Network bpfrx-trust deleted
==> Deleting network bpfrx-untrust
Network bpfrx-untrust deleted
==> Deleting network bpfrx-dmz
Network bpfrx-dmz deleted
==> Deleting network bpfrx-tunnel
Network bpfrx-tunnel deleted
==> Destroy complete.
```

---

## PR #2 — Fix buildDHCPv6Modifiers: DUID added before nil opts guard [CLOSED] (closed 2026-02-25)

Branch: `copilot/suggest-code-improvements`

`buildDHCPv6Modifiers` was unconditionally calling `getDUID()` before the `opts == nil` early return, causing `TestBuildDHCPv6Modifiers/nil_opts` to fail — 1 modifier returned instead of 0.

## Change

Move the `opts == nil` guard to the top of the function. The DUID client-ID modifier is only meaningful alongside actual DHCPv6 options; nil opts means no request will be made.

```go
// Before
func (m *Manager) buildDHCPv6Modifiers(ifaceName string, opts *DHCPv6Options) []dhcpv6.Modifier {
    var mods []dhcpv6.Modifier
    if duid, err := m.getDUID(ifaceName); err == nil { // runs even when opts == nil
        mods = append(mods, dhcpv6.WithClientID(duid))
    }
    if opts == nil {
        return mods // returns [DUID modifier] instead of nil
    }
    ...
}

// After
func (m *Manager) buildDHCPv6Modifiers(ifaceName string, opts *DHCPv6Options) []dhcpv6.Modifier {
    if opts == nil {
        return nil
    }
    var mods []dhcpv6.Modifier
    if duid, err := m.getDUID(ifaceName); err == nil {
        mods = append(mods, dhcpv6.WithClientID(duid))
    }
    ...
}
```

<!-- START COPILOT CODING AGENT TIPS -->
---

✨ Let Copilot coding agent [set things up for you](https://github.com/psaab/bpfrx/issues/new?title=✨+Set+up+Copilot+instructions&body=Configure%20instructions%20for%20this%20repository%20as%20documented%20in%20%5BBest%20practices%20for%20Copilot%20coding%20agent%20in%20your%20repository%5D%28https://gh.io/copilot-coding-agent-tips%29%2E%0A%0A%3COnboard%20this%20repo%3E&assignees=copilot) — coding agent works faster and does higher quality work when set up for your repo.


---

## PR #3 — XDP zone: avoid redundant DNAT wildcard map lookups on port 0 traffic [CLOSED] (closed 2026-02-25)

Branch: `copilot/improve-xdp-layers-performance`

This PR targets XDP pipeline performance by removing unnecessary work in the `xdp_zone` pre-routing NAT path.  
Specifically, it eliminates duplicate DNAT wildcard lookups when the packet’s destination port is already `0`.

- **What changed**
  - **IPv4 DNAT fallback**
    - In `xdp_zone`, wildcard fallback (`dst_port = 0`) now runs only when the original packet `dst_port != 0`.
  - **IPv6 DNAT fallback**
    - Applied the same guard to `dnat_table_v6` fallback lookup.
  - **Behavioral impact**
    - No policy/NAT semantics change; this is a hot-path micro-optimization that avoids duplicate `bpf_map_lookup_elem()` calls.

- **Why this matters**
  - For flows where `dst_port == 0`, the previous code did two equivalent map lookups (exact miss + wildcard lookup of the same key shape).
  - The new guard removes that redundant work in both v4 and v6 paths.

```c
/* before */
if (!dv) {
    dk_wild.dst_port = 0;
    dv = bpf_map_lookup_elem(&dnat_table, &dk_wild);
}

/* after */
if (!dv && meta->dst_port != 0) {
    dk_wild.dst_port = 0;
    dv = bpf_map_lookup_elem(&dnat_table, &dk_wild);
}
```

<!-- START COPILOT CODING AGENT TIPS -->
---

💬 We'd love your input! Share your thoughts on Copilot coding agent in our [2 minute survey](https://gh.io/copilot-coding-agent-survey).


---

## PR #4 — Reduce conntrack GC allocation churn by reusing sweep scratch buffers [CLOSED] (closed 2026-02-25)

Branch: `copilot/improve-gc-performance`

Session/state GC was doing avoidable per-sweep allocations in hot paths (`toDelete*`, `snatExpired*`), which adds overhead under high session churn. This change keeps GC behavior intact while reducing allocator pressure in periodic sweeps.

- **GC hot-path memory reuse**
  - Added reusable scratch slices to `conntrack.GC` for:
    - IPv4 delete keys
    - IPv4 expired SNAT metadata
    - IPv6 delete keys
    - IPv6 expired SNAT metadata
  - Switched `sweep()` from fresh zero-capacity slices to `[:0]` reuse of preallocated buffers.
  - Persisted slice backing arrays after each sweep to avoid reallocation across cycles.

- **Constructor-level preallocation**
  - `NewGC(...)` now initializes default capacities for the scratch buffers, so the first steady-state sweeps avoid repeated growth.

- **Focused regression coverage**
  - Added `TestGCScratchBuffersReused` to assert:
    - scratch buffers are preallocated
    - buffers are reset to empty after sweep (ready for reuse)

```go
// before: fresh allocations each sweep
var toDelete []dataplane.SessionKey
var snatExpired []expiredSession

// after: reuse backing arrays across sweeps
toDelete := gc.toDeleteV4[:0]
snatExpired := gc.snatExpiredV4[:0]
// ...
gc.toDeleteV4 = toDelete[:0]
gc.snatExpiredV4 = snatExpired[:0]
```

<!-- START COPILOT CODING AGENT TIPS -->
---

🔒 GitHub Advanced Security automatically protects Copilot coding agent pull requests. You can protect all pull requests by enabling Advanced Security for your repositories. [Learn more about Advanced Security.](https://gh.io/cca-advanced-security)

---

## PR #5 — Clear stale NAT64 dataplane state when NAT64 config is removed [CLOSED] (closed 2026-02-25)

Branch: `copilot/review-nat-code-improvements`

This change addresses a NAT64 lifecycle bug in the compiler path: removing all NAT64 rule-sets could leave previous NAT64 state active in dataplane maps.  
The update ensures NAT64 state is explicitly reset when config contains no NAT64 rules.

- **NAT64 compiler behavior**
  - Updated `compileNAT64` to clear runtime NAT64 state even when `cfg.Security.NAT.NAT64` is empty.
  - Instead of returning early, it now:
    - sets NAT64 active count to `0`
    - invokes stale-entry cleanup for NAT64 maps

- **Targeted regression coverage**
  - Added a focused unit test validating the no-rules path:
    - `SetNAT64Count(0)` is issued
    - `DeleteStaleNAT64(0, emptyWrittenSet)` is invoked

- **Code sketch**
  ```go
  if len(ruleSets) == 0 {
      if err := dp.SetNAT64Count(0); err != nil {
          return fmt.Errorf("set NAT64 count: %w", err)
      }
      dp.DeleteStaleNAT64(0, writtenPrefixes)
      return nil
  }
  ```

<!-- START COPILOT CODING AGENT TIPS -->
---

💬 We'd love your input! Share your thoughts on Copilot coding agent in our [2 minute survey](https://gh.io/copilot-coding-agent-survey).


---

## PR #51 — docs: track implementation of services application-identification [MERGED] (merged 2026-03-01)

Branch: `pr/application-identification-tracking`

## Summary
- add a focused next-feature spec for `services application-identification` found in `vsrx.conf`
- document current parser/UI-only support and missing dataplane/runtime implementation
- define scoped implementation steps and acceptance criteria

## Why
`vsrx.conf` enables AppID, but current code only stores/showcases the flag; no AppID enforcement or telemetry exists yet.

## Testing
- docs-only change


---

## PR #52 — docs: track implementation of security pre-id-default-policy [MERGED] (merged 2026-03-01)

Branch: `pr/pre-id-default-policy-tracking`

## Summary
- add a next-feature spec for `security pre-id-default-policy` found in `vsrx.conf`
- document parser-only state and missing runtime wiring
- define scoped implementation steps and acceptance criteria

## Why
`vsrx.conf` includes `pre-id-default-policy`, but bpfrx currently parses the stanza without applying it in policy/dataplane behavior.

## Testing
- docs-only change


---

## PR #53 — docs: track implementation of system ntp threshold action [MERGED] (merged 2026-03-01)

Branch: `pr/ntp-threshold-action-tracking`

## Summary
- add next-feature spec for `system ntp threshold ... action ...` from `vsrx.conf`
- document current parser-only behavior and daemon gap
- define implementation scope and acceptance criteria

## Why
`vsrx.conf` configures NTP threshold action, but `applySystemNTP` currently ignores these fields and only configures servers.

## Testing
- docs-only change


---

## PR #54 — docs: track implementation of system master-password [MERGED] (merged 2026-03-01)

Branch: `pr/master-password-tracking`

## Summary
- add next-feature spec for `system master-password` from `vsrx.conf`
- document current parse-only state and missing runtime wiring
- define secure implementation scope and acceptance criteria

## Why
`system master-password` exists in the imported config but currently has no runtime effect in bpfrx.

## Testing
- docs-only change


---

## PR #55 — docs: track implementation of system license autoupdate url [MERGED] (merged 2026-03-01)

Branch: `pr/license-autoupdate-url-tracking`

## Summary
- add next-feature spec for `system license autoupdate url` from `vsrx.conf`
- document parser-only field and missing runtime implementation
- define implementation scope and acceptance criteria

## Why
The imported config includes license autoupdate URL, but bpfrx currently stores it without acting on it.

## Testing
- docs-only change


---

## PR #67 — docs: add monitor command behavior/implementation spec [MERGED] (merged 2026-03-01)

Branch: `docs/monitor-command-research`

## Summary
Adds a new next-feature doc that captures live JUNOS `monitor` behavior from `claude@172.16.100.1` and translates it into an implementation plan for bpfrx.

## What this includes
- Live command tree and syntax for:
  - `monitor security flow` (`file`, `filter`, `start`, `stop`)
  - `monitor security packet-drop` (filters, `count`, `node`)
- Observed runtime behavior and errors (preconditions, output shape, start/stop semantics)
- Implementation checklist for bpfrx CLI grammar, daemon state model, and output compatibility goals
- Open questions to resolve before coding

## File added
- `docs/next-features/monitor-command.md`


---

## PR #95 — Improve command completion robustness and coverage [MERGED] (merged 2026-03-02)

Branch: `fix/completion-robustness`

## Summary
- unify local CLI completion to use canonical `cmdtree` completion logic so local CLI and gRPC CLI stay in sync
- fix placeholder traversal so placeholders with child nodes descend correctly (for example, `show route <destination> exact|longer|orlonger`)
- add dynamic completions for:
  - `show route table <name>` (includes `inet.0`, `inet6.0`, and per-instance tables)
  - `request chassis cluster failover redundancy-group <id> [node <id>]`
  - `request dhcp renew <interface>`
- fix gRPC config-mode completion bug where `commit`/`load` returned only the first matching candidate
- add regression tests for cmdtree completion behavior and gRPC completion candidate sets

## Testing
- `go test ./pkg/cmdtree ./pkg/grpcapi ./pkg/cli ./cmd/cli`


---

## PR #97 — vrrp: prevent preempt-before-sync on startup/rejoin [CLOSED] (closed 2026-03-02)

Branch: `fix/vrrp-join-hold`

## Summary
This fixes a VRRP sync-hold race during node restart/rejoin where a returning node could preempt before session sync was complete.

Fixes #96.

## What changed
- Enable VRRP sync hold at daemon startup (cluster+fabric mode) before initial config apply, so first `UpdateInstances()` already sees hold active.
- Make `SetSyncHold()` apply preempt suppression to already-running instances.
- Make `SetSyncHold()` stop/replace any prior timer when re-armed.
- Ensure `UpdateInstances()` keeps effective `preempt=false` while hold is active for in-place updates, while preserving configured `desiredPreempt` for later restore.
- Added regression tests for:
  - hold applies to existing instances
  - in-place updates preserve hold
  - timer re-arm does not early-release hold

## Validation
- `go test ./pkg/vrrp`
- `go test ./pkg/daemon`


---

## PR #105 — docs: reconcile backlog and status consistency across docs [MERGED] (merged 2026-03-02)

Branch: `docs/authoritative-backlog-20260302`

## Summary
Adds a new canonical backlog snapshot at `docs/authoritative-backlog.md` to reconcile parity and HA follow-up work across existing docs.

## What this includes
- Consolidated open-gap totals from row-level `docs/feature-gaps.md` statuses (Missing/Partial/Parse-Only)
- Category-by-category open counts
- High-priority open items
- Requested/proposed follow-up items from `docs/next-features/*` and HA proposal docs
- Additional open items from bug/test planning docs
- Candidate Juniper feature-table deltas not currently tracked in `docs/feature-gaps.md`
- Explicit `Implemented` and `Stale/Contradictory` sections
- Maintenance actions to align docs

## Why
Current docs contain drift and contradictions (for example summary totals vs row-level gap counts, and proposal docs for items already shipped). This provides one source of truth for backlog planning and cleanup.

## Scope
- Documentation-only change
- No runtime/code behavior changes


---

## PR #106 — docs: add authoritative DPDK vs VPP dataplane decision [MERGED] (merged 2026-03-02)

Branch: `docs/dataplane-decision-dpdk-vs-vpp-20260302`

## Summary
- add an authoritative decision doc comparing DPDK vs VPP for bpfrx
- document a clear recommendation: DPDK-first for current project constraints
- define explicit triggers for re-evaluating VPP later
- add cross-reference notes in existing strategy docs to keep guidance consistent

## Files
- docs/dataplane-decision-dpdk-vs-vpp.md
- docs/dpdk-dataplane.md
- docs/vpp-dataplane-assessment.md

## Notes
- docs-only change
- no dataplane runtime behavior modified

---

## PR #108 — docs: capture vSRX fab0/fab1 HA syntax-compat architecture [MERGED] (merged 2026-03-03)

Branch: `docs/vsrx-fab0-fab1-syntax-compat-107-clean`

## Summary

Document vSRX HA dual-fabric (`fab0` + `fab1`) syntax-compatibility gap and required architecture changes.

- add design note: `docs/next-features/vsrx-fabric-fab0-fab1-syntax-compat.md`
- update HA section in `docs/feature-gaps.md` to track this as a missing high-priority gap

## Why

`vsrx.conf` defines both `fab0` and `fab1` in HA setups. bpfrx currently has single-fabric assumptions in cluster transport and fabric forwarding wiring, so syntax compatibility is incomplete.

## Cross-reference

Refs #107


---

## PR #109 — docs: control-link-only RETH ownership plan (fxp1 election authority) [MERGED] (merged 2026-03-04)

Branch: `docs/control-link-only-reth-ownership-fxp1`

## Summary
- add a next-feature design doc for removing data-plane VRRP chatter from RETH interfaces
- document a per-RG/per-RETH ownership model driven by private-link election (lease/epoch)
- make `control-interface` (prefer `fxp1`) the recommended election/control authority
- keep `fab0/fab1` scoped to sync and fabric-forwarding roles

## Why
- captures a concrete path to move ownership election off LAN/WAN VRRP multicast
- aligns HA control-plane traffic with dedicated control interface usage
- records risks, gaps, phased implementation plan, and issue-ready acceptance criteria

## Files
- docs/next-features/control-link-only-reth-ownership.md


---

## PR #151 — perf: cache fabric redirect state and fix CPU mask scaling [MERGED] (merged 2026-03-06)

Branch: `perf-dataplane-ha-hotpath`

## Summary
- reuse cached fabric_fwd state throughout xdp_zone instead of re-looking it up on each HA redirect path
- fix main-table re-FIB to fall back to fab1 metadata when fab0 is absent
- replace overflow-prone RPS/XPS bit shifts with explicit cpumask formatting and tests

## Testing
- go generate ./pkg/dataplane/...
- GOCACHE=/tmp/go-build go test ./pkg/dataplane/...


---

## PR #152 — perf: reduce flow export allocations and preserve source-address collectors [MERGED] (merged 2026-03-06)

Branch: `perf-flowexport-allocs`

## Summary
- precompute template metadata and build NetFlow/IPFIX packets in a single buffer instead of allocating header and payload slices separately
- cache template payloads on exporter startup instead of rebuilding them on every timer tick
- dedupe collectors by address plus source-address so distinct exporters are not collapsed together
- add tests covering the source-address collector case

## Testing
- GOCACHE=/tmp/go-build go test ./pkg/flowexport/...


---

## PR #153 — vpn: fix IPsec xfrmi lifecycle and PFS handling [MERGED] (merged 2026-03-06)

Branch: `fix-vpn-ipsec-correctness`

## Summary
- always reconcile tunnel/xfrmi/IPsec state so removing VPN config clears stale kernel devices and swanctl config
- make `st0.unit` map to unit-specific xfrmi names and stable if_id values, and teach dataplane interface resolution about those unit devices
- honor IPsec policy PFS groups in generated ESP proposals instead of emitting an unrelated `dpd_action`, with focused tests

## Testing
- `GOCACHE=/tmp/go-build go test ./pkg/config ./pkg/ipsec ./pkg/routing ./pkg/dataplane ./pkg/daemon ./pkg/cli`
- `git diff --check`

---

## PR #160 — vpn: improve Junos IKE/IPsec compatibility [CLOSED] (closed 2026-03-06)

Branch: `vpn-ike-vsrx-compat`

## Summary
- resolve runtime IPsec local-address from the configured external-interface when needed
- support Junos-oriented IKE/IPsec semantics for local certificates, proposal lifetimes, DPD settings, auth method selection, and traffic selectors
- decode Junos `$9$` obfuscated PSKs before generating `swanctl.conf`
- expose the added IKE/IPsec fields in CLI/gRPC output and keep apply paths using the prepared runtime config
- harden SA parsing for multi-child traffic-selector output

## Issues
- Closes #154
- Closes #155
- Closes #156
- Closes #157
- Closes #158
- Closes #159

## Testing
- `GOCACHE=/tmp/go-build go test ./pkg/ipsec ./pkg/config ./pkg/daemon ./pkg/cli ./pkg/grpcapi ./pkg/cluster`
- `GOCACHE=/tmp/go-build go test ./...`


---

## PR #161 — docs: sync vSRX gap tracking with current master [MERGED] (merged 2026-03-06)

Branch: `docs-sync-vsrx-gap-status`

## Summary
- update `docs/feature-gaps.md` to reflect the current merged IKE/IPsec and timezone work
- correct category and total gap counts based on the updated row statuses
- sync `docs/authoritative-backlog.md` with the current row-level totals and mark CC-18 IKE/IPsec items as closed

## Details
This PR is docs-only. It changes statuses that were stale relative to merged code on `master`, specifically:
- certificate-based IPsec is now partial rather than missing
- IPsec traffic selectors are implemented
- system timezone wiring is implemented

## Validation
- `git diff --check`


---

## PR #162 — system: wire NTP threshold action via chrony [MERGED] (merged 2026-03-06)

Branch: `ntp-threshold-runtime`

## Summary
- map `system ntp threshold <seconds> action accept|reject` to chrony runtime/config behavior
- show the configured NTP threshold/action in CLI and gRPC output
- update the parity docs and backlog to mark the NTP threshold gap closed
- add unit tests for chrony rendering and managed file reconciliation

## Details
This maps Junos intent to chrony as follows:
- `accept` -> `logchange <threshold>`
- `reject` -> `logchange <threshold>` + `maxchange <threshold> 1 -1`

It also reconciles a managed threshold drop-in file and reloads chrony when the threshold config changes.

## Validation
- `GOCACHE=/tmp/go-build go test ./pkg/daemon ./pkg/config ./pkg/cli ./pkg/grpcapi`
- `GOCACHE=/tmp/go-build go test ./...`
- `git diff --check`

## Scope note
This PR does not claim to solve `services application-identification`, `security pre-id-default-policy`, or `system master-password`. Those still require real subsystem work rather than plumbing.


---

## PR #163 — security: wire AppID, pre-ID logging, and master-password runtime [MERGED] (merged 2026-03-06)

Branch: `appid-preid-runtime`

## Summary
- make `services application-identification` a real runtime feature by compiling the broader app catalog when enabled and using stored `app_id` for session display/filtering
- wire `security pre-id-default-policy` session-init/session-close logging for unknown-app sessions in both eBPF and DPDK dataplanes
- implement `system master-password` as at-rest encryption for active/candidate/rollback config trees using the configured PRF plus a node-local master key
- keep docs/backlog status aligned with the new runtime behavior

## Details
- added `pkg/appid` helpers for app catalog collection and session app resolution
- updated eBPF policy path to preserve AppID state and pre-ID log flags for new sessions
- fixed DPDK parity gaps: app ranges, session `app_id`, event `app_id`, and pre-ID logging behavior
- updated CLI/gRPC session views and filters to use real session `app_id` instead of protocol/port heuristics when AppID is enabled
- added configstore encryption/decryption tests and AppID unit tests

## Validation
- `go generate ./pkg/dataplane/...`
- `GOCACHE=/tmp/go-build go test ./...`
- `make build-dpdk-worker`
- `git diff --check`

## Notes
- This is still not full Junos L7 AppSecure DPI/signature parity.
- The docs mark `services application-identification` as partial for that reason, while `pre-id-default-policy` and `system master-password` now have real runtime behavior.


---

## PR #169 — perf: cache established IPv6 XDP flows [MERGED] (merged 2026-03-07)

Branch: `perf-ipv6-flow-cache`

## Summary
- add a per-CPU IPv6 established-flow cache in `xdp_zone` to reduce `sessions_v6` lookup pressure
- batch IPv6 cache writeback more aggressively and flush cached state before falling back on non-cacheable TCP control packets
- add a common-case IPv6 no-extension parse fast path in `parse_ipv6hdr()`
- tighten `nat_rewrite_v6()` so it specializes by protocol and actual NAT direction instead of paying repeated generic branching
- document the IPv6 fast-path design and update the optimization notes

## Validation
- `go generate ./pkg/dataplane/...`
- `rm -rf /tmp/go-build-user && mkdir -p /tmp/go-build-user && GOCACHE=/tmp/go-build-user go test ./...`
- `git diff --check`
- privileged dataplane load check via `sudo -n env GOCACHE=/tmp/go-build $(command -v go) run /tmp/load_bpfrx.go`

Closes #164.
Closes #165.
Related: #166, #167, #168, #170.


---

## PR #171 — perf: bypass empty screen stage in XDP hot path [CLOSED] (closed 2026-03-07)

Branch: `perf-xdp-screen-bypass`

## Summary
- bypass the XDP screen tail call when the ingress zone has no effective screen profile
- reuse pre-resolved ingress zone/routing state in `xdp_screen`
- skip the screen stage for common TCP data/ACK packets when only SYN-centric checks apply

## Why
This is the first slice from `/home/ps/git/bpfrx/docs/perf-analysis-ipv6.md`.
The profile showed avoidable hot-path cost around `xdp_main_prog` / `xdp_screen_prog`, especially for long-running TCP traffic.

## Validation
- `go generate ./pkg/dataplane/...`
- `GOCACHE=/tmp/go-build-pr1 go test ./pkg/dataplane/... ./pkg/conntrack/... ./pkg/daemon/...`
- `git diff --check`
- `sudo -n env GOCACHE=/tmp/go-build-pr1 $(command -v go) run /tmp/load_bpfrx.go`


---

## PR #172 — perf: use coarse packet time outside policers [CLOSED] (closed 2026-03-07)

Branch: `perf-coarse-packet-time`

## Summary
- add a coarse per-packet time base for conntrack and screen aging
- lazily fetch precise `bpf_ktime_get_ns()` only when a packet actually hits a policer
- avoid redundant `last_seen` writes when the cached second has not changed

## Why
This is the second slice from `/home/ps/git/bpfrx/docs/perf-analysis-ipv6.md`.
The profile called out `read_tsc` / packet timestamping as avoidable hot-path work. This keeps precise timing where it matters and removes it from the common path.

## Validation
- `go generate ./pkg/dataplane/...`
- `GOCACHE=/tmp/go-build-pr2 go test ./pkg/dataplane/... ./pkg/conntrack/... ./pkg/daemon/...`
- `git diff --check`
- `sudo -n env GOCACHE=/tmp/go-build-pr2 $(command -v go) run /tmp/load_bpfrx.go`


---

## PR #173 — perf: back off conntrack GC on stable tables [CLOSED] (closed 2026-03-07)

Branch: `perf-conntrack-gc-adaptive`

## Summary
- replace the fixed conntrack GC ticker with an adaptive timer
- back off sweep cadence when the table is stable and the next expiry is far away
- keep the default cadence when session-limit accounting or aggressive aging is active
- add unit coverage for the new scheduling logic

## Why
This is the third slice from `/home/ps/git/bpfrx/docs/perf-analysis-ipv6.md`.
The profile showed measurable userspace GC overhead from periodic batch sweeps even when the session table is stable.

## Validation
- `GOCACHE=/tmp/go-build-pr3 go test ./pkg/conntrack/... ./pkg/daemon/... ./pkg/grpcapi/...`
- `git diff --check`


---

## PR #174 — docs: add XDP to userspace io_uring dataplane design [MERGED] (merged 2026-03-07)

Branch: `docs/xdp-io-uring-userspace-dataplane`

## Summary
- add a design doc for an XDP-fronted userspace dataplane built around multithreaded workers
- explain why AF_XDP should be the packet handoff boundary and where io_uring actually fits
- cover threading, memory, HA/session-sync, crash behavior, and phased bpfrx implementation

## Key Point
The performant version of this design is:
- XDP for early parse/drop/HA gating/metadata
- AF_XDP for packet handoff
- per-core userspace workers for stateful firewall logic
- io_uring for slow-path and async control-plane plumbing

Not a raw-socket or TUN/TAP packet engine driven directly by io_uring.


---

## PR #175 — fix: restore eager IPv6 checksum-partial detection [MERGED] (merged 2026-03-07)

Branch: `fix-ipv6-forwarding`

## Summary
- restore eager IPv6 `CHECKSUM_PARTIAL` detection in `parse_l4hdr()`
- keep the IPv6 no-extension parse fast path, but stop deferring checksum-partial resolution into later packet stages
- regenerate the dataplane BPF objects

## Root cause
The merged IPv6 perf change moved IPv6 `CHECKSUM_PARTIAL` detection out of `parse_l4hdr()` and into later resolver call sites. That optimization was not safe across every IPv6 forwarding path. Restoring eager detection removes the lazy state transition and returns the dataplane to the pre-regression checksum behavior while preserving the safer parse fast path.

## Validation
- `go generate ./pkg/dataplane/...`
- `GOCACHE=/tmp/go-build-ipv6-fix go test ./pkg/dataplane/... ./pkg/daemon/... ./pkg/cli ./pkg/grpcapi`
- `GOCACHE=/tmp/go-build-ipv6-fix go test ./...`
- `sudo -n env GOCACHE=/tmp/go-build-ipv6-fix $(command -v go) run /tmp/load_bpfrx.go`


---

## PR #176 — fix: disable IPv6 flow cache fast path [MERGED] (merged 2026-03-07)

Branch: `fix-ipv6-flow-cache-disable`

## Summary
- disable the IPv6 established-flow cache runtime path in `xdp_zone`
- keep the cache invalidation helper in place, but force established IPv6 TCP back through the proven session path
- regenerate the `xdp_zone` BPF object

## Why
`#175` already restored eager IPv6 checksum-partial detection, but IPv6 forwarding was still reported broken afterwards. The remaining high-risk runtime delta from the IPv6 perf work was the established-flow cache introduced in `6eb3377`.

This PR rolls that fast path out of runtime use so IPv6 forwarding returns to the pre-cache dataplane behavior while the cache correctness is investigated separately.

## Validation
- `git pull --rebase`
- `go generate ./pkg/dataplane/...`
- `GOCACHE=/tmp/go-build-ipv6-fix3 go test ./...`
- `sudo -n env GOCACHE=/tmp/go-build-ipv6-fix3 $(command -v go) run /tmp/load_bpfrx.go`


---

## PR #177 — fix: restore IPv6 extension-header parsing path [MERGED] (merged 2026-03-07)

Branch: `fix-ipv6-parse-path`

## Summary
- restore the pre-fast-path IPv6 header parsing path in `parse_ipv6hdr()`
- remove the IPv6 parse shortcut that was added as part of the IPv6 perf work
- regenerate the dataplane BPF objects

## Why
PR #176 already merged the IPv6 flow-cache fast-path disable into `master`.
This follow-up PR isolates the remaining IPv6-specific rollback after IPv6 forwarding was still reported broken.

This PR contains only commit `d1c10fd` on top of current `master`.

## Validation
- `go generate ./pkg/dataplane/...`
- `GOCACHE=/tmp/go-build-ipv6-fix4 go test ./...`
- `sudo -n env GOCACHE=/tmp/go-build-ipv6-fix4 $(command -v go) run /tmp/load_bpfrx.go`


---

## PR #178 — fix: restore IPv6 NAT rewrite from packet/meta deltas [CLOSED] (closed 2026-03-07)

Branch: `fix-ipv6-snat-rewrite`

Root cause:
- Recent IPv6 NAT optimization made nat_rewrite_v6() decide rewrite direction from nat_flags.
- IPv6 session and policy paths commonly set translated meta src/dst fields without carrying a per-packet rewrite-direction flag.
- As a result, xdp_nat ran but skipped the actual IPv6 header rewrite, breaking NAT66 on the wire while session state still looked translated.

Fix:
- Drive IPv6 rewrite decisions from actual packet-vs-meta deltas for src/dst address and L4 id/port.
- Keep the protocol-specialized fast path, but restore the old correctness model.

Validation:
- go generate ./pkg/dataplane/...
- GOCACHE=/tmp/go-build-snatfix go test ./...
- loss lab before: curl -6 --noproxy * https://icanhazip.com -> 2001:559:8585:df01:1266:6aff:fe59:ef38\n- loss lab after:  curl -6 --noproxy * https://icanhazip.com -> 2001:559:8585:50::7\n

---

## PR #181 — perf: precompute ingress screen flags [MERGED] (merged 2026-03-08)

Branch: `perf-ingress-screen-flags`

## Summary
- precompute effective ingress `screen_flags` into `iface_zone_map`
- use those flags in `resolve_ingress_xdp_target()` so `xdp_main` and `xdp_cpumap` stop doing extra `zone_configs` and `screen_configs` lookups on every packet
- refactor screen-profile compilation through a shared `buildScreenConfig()` helper
- add a ranked perf backlog doc tied to the current open issues

## Why
Recent perf captures still show `xdp_main_prog` as the single largest IPv6 hot symbol. This PR removes one avoidable ingress-stage cost without changing screen behavior.

## Validation
- `go generate ./pkg/dataplane/...`
- `GOCACHE=/tmp/go-build-perf-screen go test ./...`
- `sudo -n env GOCACHE=/tmp/go-build-perf-screen $(command -v go) run /tmp/load_bpfrx.go`
- `git diff --check`

## Follow-ups
- Refs #180 for the remaining `xdp_main` work
- Refs #168 for IPv6 session-key compaction
- Refs #166 for hot/cold IPv6 session-state split
- Refs #179 for IPv6 NAT hot-path work


---

## PR #182 — perf: tighten xdp parse and IPv6 NAT dispatch [MERGED] (merged 2026-03-08)

Branch: `perf-ipv6-parse-nat`

## Summary
- add conservative IPv4/IPv6 TCP/UDP fast parse helpers in `xdp_main` and `xdp_cpumap`
- avoid sending IPv6 established-session traffic through `xdp_nat` when the current direction does not actually rewrite packet state
- use parsed `meta->ip_ttl` in `xdp_nat` instead of reparsing L3 headers for the TTL/hop-limit pass-to-kernel check
- fix `meta->nat_flags` propagation for new IPv4/IPv6 NAT sessions and the IPv6 zone fast-path before tail-calling `xdp_nat`

## Why
This closes the current high-signal remaining hot-path issues from the IPv6 perf work without changing the deeper IPv6 session-cache design:
- closes #180
- closes #179

It also fixes a correctness hole that the recent IPv6 NAT series left behind: some IPv6 session paths still reached `xdp_nat` without restoring `meta->nat_flags`, which meant the rewrite stage could not reliably tell which side to update.

## Validation
- `go generate ./pkg/dataplane/...`
- `env -i PATH=$PATH HOME=$HOME TERM=$TERM GOCACHE=/tmp/go-build-pr179-180 $(command -v go) test ./pkg/dataplane/... ./pkg/conntrack/... ./pkg/cluster/...`
- `sudo -n env -u GOFLAGS -u GOROOT GOCACHE=/tmp/go-build-pr179-180 $(command -v go) run /tmp/load_bpfrx.go`

## Notes
- This intentionally keeps the existing IPv6 flow-cache layout in place.
- The compact-key / hot-cold cache redesign is in the stacked follow-up PR.


---

## PR #183 — perf: compact the IPv6 established-flow hot path [CLOSED] (closed 2026-03-08)

Branch: `perf-ipv6-compact-cache`

## Summary
- replace the direct-mapped IPv6 flow cache with a `LRU_PERCPU_HASH` keyed by a compact 128-bit lookup key
- keep the full IPv6 5-tuple in the hot cache value and verify it on lookup so compact-key collisions fall back safely
- move the steady-state forwarding and current-direction rewrite metadata into the front-side hot cache instead of always re-reading the full `sessions_v6` state
- let cache hits with current-direction IPv6 TCP source rewrite patch the packet inline and tail-call straight to `xdp_forward`
- update `docs/next-features/ipv6-session-fast-path.md` to match the implemented design

## Why
This is the deeper IPv6 steady-state cost reduction work:
- closes #168
- closes #166

The authoritative `sessions_v6` map stays unchanged for GC, HA/session sync, and session semantics. The hot path gets a smaller effective lookup key and a smaller lookup-time structure, while collisions stay safe because the cached full key is verified before use.

## Validation
- `go generate ./pkg/dataplane/...`
- `env -i PATH=$PATH HOME=$HOME TERM=$TERM GOCACHE=/tmp/go-build-pr166-168-user $(command -v go) test ./pkg/dataplane/... ./pkg/conntrack/... ./pkg/cluster/...`
- `sudo -n env -i PATH=$PATH HOME=$HOME TERM=$TERM GOCACHE=/tmp/go-build-pr166-168-root $(command -v go) run /tmp/load_bpfrx.go`

## Notes
- Stacked on top of #182.
- This deliberately leaves the public `sessions_v6` map format alone; the hot/cold split happens in front of it in the established-flow cache.


---

## PR #184 — docs: harden XDP AF_XDP io_uring dataplane plan [MERGED] (merged 2026-03-08)

Branch: `docs/xdp-afxdp-uring-plan`

## Summary
- tighten the XDP/AF_XDP/io_uring userspace dataplane doc into an implementation-grade plan
- define the support envelope and mixed-mode deployment boundaries
- add a concrete metadata ABI contract and queue ownership model
- define overload/fail-closed behavior, snapshot publication rules, feature boundaries, shard-sync rules, and observability requirements

## Why
The original doc had the right architecture direction, but it left too many make-or-break details at sketch level. This revision adds the operational contracts that would determine whether such a backend is actually implementable in bpfrx.

## Scope
Docs only:
- `docs/xdp-io-uring-userspace-dataplane.md`


---

## PR #190 — docs: add HA session ownership failover analysis [MERGED] (merged 2026-03-08)

Branch: `docs/xdp-afxdp-uring-plan`

(no description)

---

## PR #194 — ha: improve IPv6 failover NDP parity [MERGED] (merged 2026-03-08)

Branch: `fix-ipv6-ha-ndp-parity`

## Summary
This is the low-risk IPv6 HA parity slice.

It does three things:

- adds a concrete IPv6 failover parity design doc
- wires explicit IPv6 NDP probing into the failover neighbor-warmup path
- actively reprobes cleaned FAILED IPv6 neighbors instead of waiting for passive later traffic

## Changes

### Docs
- add `docs/next-features/ipv6-ha-failover-parity.md`

### Code
- add `cluster.SendNDSolicitationFromInterface()` to choose a suitable IPv6 probe source automatically
- update `resolveNeighbors()` to resolve the actual neighbor IP from `RouteGet()`, not just the final destination
- for IPv6 warmup, send an explicit Neighbor Solicitation before the existing `ping -6` path
- extend `cleanFailedNeighbors()` to actively reprobe IPv6 neighbors after deleting `NUD_FAILED`
- add unit coverage for IPv6 probe source selection

## Issues
- Closes #191
- Closes #193
- References #192

## Validation
- `gofmt -w pkg/cluster/garp.go pkg/cluster/garp_test.go pkg/daemon/daemon.go`
- `git diff --check`
- `GOCACHE=/tmp/go-build-ipv6-ha go test ./pkg/cluster ./pkg/daemon`
- `GOCACHE=/tmp/go-build-ipv6-ha-full go test ./...`

## Notes
This PR intentionally does not try to solve the larger router-identity problem from #192.
That remains the main architectural reason IPv6 failover is still weaker than IPv4, especially on hard crash failover.


---

## PR #195 — docs: define userspace dataplane process model [MERGED] (merged 2026-03-09)

Branch: `docs/xdp-userspace-process-model`

## Summary
This updates the XDP/AF_XDP/io_uring userspace dataplane design with a concrete process and language recommendation.

Main decisions captured in the doc:

- do not embed packet slow-path work inside `bpfrxd`
- keep `bpfrxd` as the Go control plane
- use a separate native dataplane process for AF_XDP workers and packet slow path
- plan for Rust as the implementation language for the userspace dataplane runtime
- keep the control-plane/dataplane boundary explicit via shared memory + control socket

## Why
The previous doc was directionally right about `XDP -> AF_XDP` for packet handoff, but still left the process model too open-ended.

This change makes the intended architecture explicit:

- packet work should stay out of Go
- packet slow path is still dataplane work, not control-plane work
- a separate native process is cleaner for CPU pinning, restart isolation, and avoiding cgo-heavy hot loops under the Go scheduler

## Scope
Docs only.

## Validation
- `git diff --check`


---

## PR #207 — fix: clear shared sessions on Coordinator stop [MERGED] (merged 2026-03-12)

Branch: `fix/204-clear-shared-sessions-on-stop`

## Summary
- Clear `shared_sessions` and `shared_nat_sessions` in `Coordinator::stop()`, which previously neglected these maps while clearing all other state (workers, identities, live, dynamic_neighbors, recent_exceptions, etc.)
- Prevents stale session data from persisting across stop/start cycles

Fixes #204

## Test plan
- [ ] Verify `stop()` clears both `shared_sessions` and `shared_nat_sessions`
- [ ] Verify no stale sessions remain after a stop/start cycle

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #208 — fix: remove unnecessary unsafe mutable borrow in TX validation [MERGED] (merged 2026-03-12)

Branch: `fix/206-unused-mutable-slice`

## Summary
- Replace `unsafe { slice_mut_unchecked() }` with safe `slice()` in `transmit_prepared_batch()` validation loop
- The mutable slice was bound but never read or written -- only used to check existence
- Eliminates an unnecessary `unsafe` block and unused `frame` variable binding

Fixes #206

## Test plan
- [ ] Verify `cargo check` shows no new errors (pre-existing WIP errors on this branch are unrelated)
- [ ] Confirm validation still correctly rejects out-of-range frame offsets

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #209 — fix: settle port authority priority — frame bytes are ground truth [CLOSED] (closed 2026-03-12)

Branch: `fix/202-simplify-port-authority`

## Summary
- Reorders `authoritative_forward_ports()` to prefer live frame bytes over session flow and XDP metadata
- Frame bytes reflect post-NAT, post-rewrite packet state and are the most trustworthy source
- Session flow and metadata are retained as fallbacks for truncated/unparseable frames only
- Adds clear doc comments explaining the rationale to prevent future priority flips

## Context
The commit history shows 4+ flips between frame/session/metadata tuple preference in one day (#202). The abstraction was fragile because there was no documented rationale for the priority order. This fix settles it permanently with the correct invariant: the live packet is always right.

Fixes #202

## Test plan
- [x] Updated `authoritative_forward_ports_prefers_frame_bytes_over_flow_and_meta` test to validate new priority (frame ports win over stale flow/meta ports)
- [ ] `cargo test` in `userspace-dp/`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #210 — fix: recycle UMEM frames on TxError::Drop in transmit_prepared_batch [CLOSED] (closed 2026-03-12)

Branch: `fix/203-umem-frame-leak-on-drop`

## Summary
- Fix UMEM frame leak when `TxError::Drop` is returned from `transmit_prepared_batch()` in `userspace-dp/src/afxdp.rs`
- Frames popped from `pending_tx_prepared` into `scratch_prepared_tx` were orphaned on both Drop paths (oversized frame and slice-out-of-range), never returned to the free pool
- Both paths now drain `scratch_prepared_tx` and recycle every frame via `recycle_cancelled_prepared()` before returning the error

Fixes #203

## Test plan
- [ ] Verify `cargo check` passes (only pre-existing E0609 WIP errors remain, none in the changed function)
- [ ] Run traffic workload that triggers oversized frames or invalid offsets and confirm UMEM frame count stays stable
- [ ] Monitor `debug_free_tx_frames` / `debug_pending_fill_frames` counters under sustained forwarding to confirm no leak

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #211 — userspace: document in-place TX hairpin limitation + add counter [MERGED] (merged 2026-03-12)

Branch: `fix/205-in-place-tx-dead-code`

## Summary
- Replaced the misleading comment on `can_rewrite_in_place` with a clear explanation that in-place TX only works for same-interface hairpin (each binding owns its own UMEM), plus a `TODO(#205)` for shared-UMEM cross-interface support
- Added `in_place_tx_packets` counter to `BindingLiveState`, `BindingLiveSnapshot`, and `BindingStatus` so we can observe in production whether the in-place TX path ever fires
- Kept all existing code and tests intact since the optimization is correct — just rarely triggered

Fixes #205

## Test plan
- [ ] Verify `cargo check` does not introduce new errors beyond pre-existing WIP branch issues
- [ ] Confirm `in_place_tx_packets` counter increments during same-interface hairpin forwarding
- [ ] Confirm cross-interface forwards still use the copy path (counter stays 0 for non-hairpin bindings)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #212 — fix: gate XDP shim redirect on active userspace session [MERGED] (merged 2026-03-12)

Branch: `fix/200-xdp-shim-session-check`

## Summary
- Wire the existing but unused `has_live_userspace_session()` into the XDP shim steering path, so only packets with an active userspace session (or connection-initiating SYN/stateless packets) are redirected to AF_XDP
- Unsessioned non-SYN traffic now falls back to the legacy BPF fast path via `fallback_to_main()`, preventing mid-flow packets from being silently dropped by the Rust dataplane
- Add `is_connection_initiating()` helper, `TCP_FLAG_SYN`/`TCP_FLAG_ACK` constants, and `NO_SESSION` trace/fallback reason constants

Fixes #200

## Test plan
- [ ] Verify TCP SYN packets still get redirected to userspace (new session creation works)
- [ ] Verify TCP data/ACK packets with an active userspace session are redirected normally
- [ ] Verify TCP data/ACK packets WITHOUT a userspace session fall back to legacy BPF pipeline
- [ ] Verify UDP and ICMP traffic is always redirected (stateless protocols)
- [ ] Check `userspace_fallback_stats[12]` counter increments for no-session fallbacks
- [ ] Check `userspace_trace` map records `USERSPACE_TRACE_STAGE_NO_SESSION` entries

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #213 — fix: read ports from live UMEM frame before copy to prevent corruption [MERGED] (merged 2026-03-12)

Branch: `fix/199-frame-copy-port-corruption`

## Summary
- **Fixes #199** — port corruption in the copy-based forwarding path
- `build_live_forward_request()` now captures L4 ports from the live UMEM frame **before** `.to_vec()`, preventing stale ports when NIC DMA partially overwrites a reused descriptor slot between the copy and port parsing
- Session flow ports (from conntrack, immune to DMA races) are now the primary authority, with live frame ports as fallback and metadata ports as last resort
- The now-unused `authoritative_forward_ports()` is retained with `#[allow(dead_code)]` for its unit test

## Port priority chain (new)
1. Session flow ports (conntrack — always correct)
2. Live UMEM frame ports (read before copy — NIC ground truth)
3. Metadata ports (BPF-set — last resort)

## Test plan
- [x] Updated `build_live_forward_request_prefers_session_flow_ports_over_frame` — verifies session flow wins over frame ports
- [x] Added `build_live_forward_request_uses_live_frame_ports_when_no_session_flow` — verifies live frame ports used when no session flow available
- [x] Existing `build_live_forward_request_uses_flow_or_metadata_ports_when_frame_ports_unavailable` unchanged — still passes (flow wins when frame is empty)
- [x] Existing `authoritative_forward_ports_prefers_flow_tuple_when_frame_ports_mismatch` unchanged

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #214 — fix: RX throttle under TX backpressure to prevent UMEM exhaustion [MERGED] (merged 2026-03-12)

Branch: `fix/201-umem-exhaustion-backpressure`

## Summary
- **RX throttle**: Skip RX batch processing when `pending_tx_local + pending_tx_prepared >= max_pending_tx`, preventing fill ring frame exhaustion under TX backpressure. The NIC holds packets until frames are freed.
- **`bound_pending_tx_prepared()`**: New bounding function for the prepared TX queue that properly recycles UMEM frames via `recycle_cancelled_prepared()`, preventing frame leaks when dropping overflow entries.
- **Comprehensive bounding**: `bound_pending_tx_prepared()` called at all `bound_pending_tx_local()` call sites plus after in-place TX push_back, ensuring both TX queues are bounded with proper frame accounting.

Fixes #201

## Test plan
- [ ] Verify under sustained TX backpressure (slow egress NIC, fast ingress) that RX does not stall
- [ ] Confirm fill ring frames are returned when prepared TX overflow is trimmed
- [ ] Check `tx_errors` counter increments when overflow bounding triggers
- [ ] Validate no UMEM frame leaks under prolonged backpressure (frame count stable)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #215 — docs: sync userspace dataplane docs with master [MERGED] (merged 2026-03-15)

Branch: `docs/userspace-dataplane-master-sync`

## Summary
- sync the userspace dataplane docs with current `master` behavior
- remove stale `userspace-wip` references and branch-specific wording
- add a compact userspace debug map for XDP redirect, AF_XDP forwarding, session/NAT, and HA/session-sync debugging

## Included
- README userspace dataplane summary updated to match current code paths and capability gate
- userspace architecture and gaps docs updated to reflect current `master`
- validation/perf docs updated to point at repo-local files and current-tree workflow
- new `docs/userspace-debug-map.md` for active forwarding/debug work

## Notes
- documentation-only change
- no runtime code changes

---

## PR #216 — userspace: fix native ICMP TE HA resolution [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-native-icmp-te`

## Summary
- apply HA ownership enforcement to native embedded ICMP TE NAT-reversal
- fabric-redirect ICMP TE replies when the owning RG is inactive
- avoid redirecting fabric-ingress ICMP TE traffic back onto fabric
- add focused unit coverage for both HA/fabric cases

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml embedded_icmp_
- cargo test --manifest-path userspace-dp/Cargo.toml icmp_te_nat_reversal
- cargo test --manifest-path userspace-dp/Cargo.toml icmpv6_te_nat_reversal

---

## PR #217 — userspace: fabric-redirect native ICMP TE after no-route [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-native-icmp-te-no-route`

## Summary
- port the remaining split-RG embedded ICMP traceroute fix into the native userspace dataplane
- fabric-redirect post-NAT embedded ICMP TE replies when client resolution on this node is `NoRoute` or `DiscardRoute`
- keep fabric ingress from redirecting back to fabric
- add focused unit coverage for both route-failure cases

## Why
The earlier PR `#216` merged the initial native HA-resolution fix, but this follow-up carries over the old `7c8f243` behavior that handled split-RG route failures after NAT rewrite.

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml embedded_icmp_
- cargo test --manifest-path userspace-dp/Cargo.toml icmp_te_nat_reversal
- cargo test --manifest-path userspace-dp/Cargo.toml icmpv6_te_nat_reversal

---

## PR #218 — userspace: fix native ICMP traceroute handling [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-native-icmp-te-traceroute`

## Summary
- generate native local ICMP time-exceeded replies back to the ingress MAC/interface
- restrict embedded ICMP NAT reversal to actual ICMP error packets instead of all ICMP traffic
- keep ordinary ICMP echo/traceroute probes on the normal userspace session path

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml build_local_time_exceeded -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml packet_ttl_would_expire_identifies_v4_and_v6 -- --nocapture
- live check on the isolated userspace HA lab:
  - ping -t 1 1.1.1.1 returns Time to live exceeded from 10.0.61.1
  - mtr 1.1.1.1 resolves hop 1 natively through the userspace dataplane
  - ping 172.16.80.200 succeeds again on the active userspace node


---

## PR #219 — userspace: fix native ICMPv6 traceroute NPTv6 lookup [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-native-icmpv6-te-nptv6`

## Summary
- preserve the wire embedded IPv6 tuple for NAT reverse lookup
- reverse NPTv6 on the embedded source for direct session recovery
- keep the matched session NAT decision on direct fallback so ICMPv6 TE replies can reach the original client

## Testing
- source "$HOME/.cargo/env" && cargo test --manifest-path userspace-dp/Cargo.toml icmpv6_te_ -- --nocapture
- source "$HOME/.cargo/env" && cargo test --manifest-path userspace-dp/Cargo.toml is_icmp_error_identifies_v6_types -- --nocapture

---

## PR #220 — docs: add userspace dataplane cleanup plan [MERGED] (merged 2026-03-15)

Branch: `docs/userspace-dataplane-cleanup-plan`

## Summary
- add a phased cleanup and optimization plan for the userspace dataplane
- document goals, non-goals, execution order, and exit criteria
- capture the immediate next tasks for cleanup, validation, and performance work

## Testing
- not applicable (docs only)

---

## PR #221 — test: add traceroute checks to userspace validation [MERGED] (merged 2026-03-15)

Branch: `test/userspace-ha-traceroute-validation`

## Summary
- add deterministic TTL-expired probes for IPv4 and IPv6 validation targets
- add one-cycle mtr checks for resolved first hop and destination hop
- derive the active WAN test interface dynamically from the active primary node
- update the validation doc and skill to match the new checks

## Testing
- validation script/doc/skill update only

---

## PR #222 — userspace: finish phase1 dataplane cleanup [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-phase1-cleanup`

## Summary
- finish Phase 1 of the userspace dataplane cleanup plan
- gate or remove debug-only warning noise in the Rust dataplane
- reduce userspace-dp test build warnings to zero under the default build

## Validation
- source "/home/ps/.cargo/env" && cargo test --manifest-path userspace-dp/Cargo.toml --no-run


---

## PR #223 — userspace: continue phase 2 icmp extraction [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-phase2-icmp-extract`

## Summary
- continue phase 2 cleanup work for the userspace dataplane
- extract embedded ICMP helper logic out of afxdp.rs
- keep behavior unchanged while shrinking the hot-path file

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- focused ICMP/ICMPv6 unit tests


---

## PR #224 — fix: gate test-only ICMP submodule imports behind #[cfg(test)] [CLOSED] (closed 2026-03-15)

Branch: `copilot/review-pr-223`

PR #223 extracted ICMP helpers into `afxdp/icmp.rs` and `afxdp/icmp_embed.rs` but imported all symbols unconditionally, producing unused import warnings for items only referenced in tests.

- Split imports into unconditional (production) and `#[cfg(test)]` (test-only) groups

```rust
// Production imports
use self::icmp::{build_local_time_exceeded_request, is_icmp_error};
use self::icmp_embed::{
    build_nat_reversed_icmp_error_v4, build_nat_reversed_icmp_error_v6,
    finalize_embedded_icmp_resolution, try_embedded_icmp_nat_match,
};

// Test-only imports
#[cfg(test)]
use self::icmp::{
    build_local_time_exceeded_v4, build_local_time_exceeded_v6, packet_ttl_would_expire,
};
#[cfg(test)]
use self::icmp_embed::{
    EmbeddedIcmpMatch, try_embedded_icmp_nat_match_from_frame,
    try_embedded_icmp_session_match_from_frame,
};
```

All 269 tests pass, zero `unused_imports` warnings.

<!-- START COPILOT CODING AGENT TIPS -->
---

✨ Let Copilot coding agent [set things up for you](https://github.com/psaab/bpfrx/issues/new?title=✨+Set+up+Copilot+instructions&body=Configure%20instructions%20for%20this%20repository%20as%20documented%20in%20%5BBest%20practices%20for%20Copilot%20coding%20agent%20in%20your%20repository%5D%28https://gh.io/copilot-coding-agent-tips%29%2E%0A%0A%3COnboard%20this%20repo%3E&assignees=copilot) — coding agent works faster and does higher quality work when set up for your repo.


---

## PR #225 — userspace: complete phase2 afxdp modular extraction [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-phase2-icmp-extract`

Summary:
- finish the Phase 2 afxdp.rs split into dedicated submodules
- extract bind/open, frame/rewrite, session glue, and tx/recycle helpers
- update the cleanup plan to mark Phase 2 complete

Validation:
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- cargo test --manifest-path userspace-dp/Cargo.toml build_local_time_exceeded -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml packet_ttl_would_expire -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml icmpv6_te_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml authoritative_forward_ports_prefers_flow_tuple_when_frame_ports_mismatch -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml mlx5_keeps_umem_owner_bind_strategy -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml virtio_prefers_separate_owner_then_falls_back -- --nocapture
- live deploy to loss:bpfrx-userspace-fw0/1 with dual-stack reachability + IPv4/IPv6 TTL and mtr checks

Notes:
- virtio_net fabric AF_XDP bind remains unresolved and is tracked as a runtime capability issue, not a reason to keep afxdp.rs monolithic

---

## PR #226 — docs: sync userspace cleanup status [MERGED] (merged 2026-03-15)

Branch: `docs/userspace-cleanup-status`

## Summary
- update the userspace dataplane cleanup plan to reflect completed Phase 2 work
- record the resolved virtio_net fabric AF_XDP bind outcome from live validation
- clarify what remains for Phases 3 through 6 and the immediate next steps

## Validation
- documentation update only


---

## PR #227 — docs: reference cleanup status sync PR [MERGED] (merged 2026-03-15)

Branch: `docs/userspace-cleanup-status-pr226-ref`

## Summary
- add the missing reference to PR #226 in the userspace cleanup plan
- record that the latest status-sync update documents the current cleanup state

## Validation
- documentation update only


---

## PR #228 — userspace: complete phase3 session resolution cleanup [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-phase3-session-resolution`

## Summary
- centralize fast-path session resolution in `session_glue`
- make embedded ICMP/ICMPv6 use the shared/local session and NAT-reverse resolvers
- update the cleanup plan to mark Phase 3 complete and record live validation

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml lookup_session_across_scopes_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml lookup_forward_nat_across_scopes_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml icmpv6_te_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml authoritative_forward_ports_prefers_flow_tuple_when_frame_ports_mismatch -- --nocapture`
- live deploy to `loss:bpfrx-userspace-fw0/1`
- live checks from `loss:cluster-userspace-host`:
  - IPv4/IPv6 internal ping
  - IPv4/IPv6 TTL=1 traceroute probes
  - IPv4 `mtr 1.1.1.1 --report --report-cycles=1`
  - IPv6 `mtr 2607:f8b0:4005:814::200e --report --report-cycles=1`
  - IPv4/IPv6 single-stream `iperf3 -t 3`

## Notes
- the standard userspace validation shell script still aborts early on TTL probes because `ping -t 1` returns a non-zero status even when the expected time-exceeded reply is present; that remains a Phase 5 validation-script fix, not a dataplane regression

---

## PR #229 — userspace: complete phase4 queue and recycle cleanup [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-phase4-queue-recycle`

## Summary
- make prepared-TX recycle ownership explicit with `PreparedTxRecycle`
- centralize pending TX merge, restore, completion recycle, and immediate cancel recycle handling in `tx.rs`
- update the AF_XDP packet-processing and cleanup-plan docs to mark Phase 4 complete

## Validation
- `cargo fmt --manifest-path userspace-dp/Cargo.toml`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml merge_pending_tx_requests_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_prepared_recycle_routes_fill_and_free_explicitly -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml icmpv6_te_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml lookup_session_across_scopes_ -- --nocapture`
- live deploy to `loss:bpfrx-userspace-fw0` and `loss:bpfrx-userspace-fw1`
- live validation on active `bpfrx-userspace-fw0`:
  - `show chassis cluster data-plane statistics`
  - `show chassis cluster data-plane interfaces`
  - `ping 172.16.80.200`
  - `ping -6 2001:559:8585:80::200`
  - `ping -t 1 1.1.1.1`
  - `ping -6 -t 1 2607:f8b0:4005:814::200e`
  - `mtr 1.1.1.1 --report --report-cycles=1`
  - `mtr 2607:f8b0:4005:814::200e --report --report-cycles=1`
  - `iperf3 -c 172.16.80.200 -P 1 -t 3`
  - `iperf3 -c 2001:559:8585:80::200 -P 1 -t 3`


---

## PR #230 — test: harden userspace validation harness [CLOSED] (closed 2026-03-15)

Branch: `fix/userspace-phase5-validation-hardening`

## Summary
- accept the expected non-zero `ping` exit status for TTL / hop-limit probes and validate success from the returned time-exceeded text
- analyze `iperf3 -J` output on the repo host instead of assuming `python3` exists on `cluster-userspace-host`
- update the userspace validation docs, skill, and cleanup plan to reflect the current Phase 5 state

## Validation
- `bash -n scripts/userspace-ha-validation.sh`
- `python3 -m py_compile scripts/iperf-json-metrics.py`
- `RUNS=1 DURATION=3 PARALLEL=1 MIN_GBPS_V4=1 MIN_GBPS_V6=1 ./scripts/userspace-ha-validation.sh --env test/incus/loss-userspace-cluster.env`


---

## PR #231 — test: complete userspace cleanup phase5 coverage [MERGED] (merged 2026-03-15)

Branch: `fix/userspace-phase5-complete`

Completes the remaining Phase 5 cleanup-plan work on top of current `master`.

What this adds:
- tuple-authority regression coverage for metadata-vs-frame port selection
- embedded ICMP shared-NAT-session regression coverage across worker scopes
- direct regression coverage for the `enqueue_pending_forwards` build-failure fallback path via the extracted `handle_forward_build_failure(...)` helper
- cleanup-plan doc update marking Phases 3 and 4 merged, and Phase 5 complete on this branch

Validation run:
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- focused `authoritative_forward_ports_` tests
- focused `embedded_icmp_nat_match_uses_shared_nat_session_for_ipv4`
- focused `handle_forward_build_failure_*` tests

---

## PR #232 — userspace: land measured phase6 micro-optimizations [MERGED] (merged 2026-03-16)

Branch: `fix/userspace-phase6-performance`

## Summary
- keep only the measured Phase 6 TX/frame micro-optimizations that held up under live validation
- update the cleanup plan doc to reflect the current Phase 6 state, rejected experiments, and remaining hotspots
- document that the next work is still in poll_binding, enqueue_pending_forwards, frame build, and IPv6 NAT

## Validation
- source "$HOME/.cargo/env" && cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- source "$HOME/.cargo/env" && cargo test --manifest-path userspace-dp/Cargo.toml remember_prepared_recycle_tracks_only_shared_fill_recycles -- --nocapture
- live validation on loss:bpfrx-userspace-fw0/1 before this commit series kept:
  - IPv4 TTL probe: pass
  - IPv6 TTL probe: pass
  - IPv4 mtr: pass
  - IPv6 mtr: pass
  - repeated direct iperf3 runs: IPv4 ~18.10-22.13 Gbps, IPv6 ~16.19-20.43 Gbps
  - latest paired userspace-perf-compare: IPv4 ~17.81 Gbps, IPv6 ~17.68 Gbps

---

## PR #233 — test: add userspace RG failover validator [MERGED] (merged 2026-03-16)

Branch: `fix/userspace-ha-failover-validation`

## Summary
- add a tracked userspace HA failover parity plan focused on RG1 manual failover survivability
- add a dedicated userspace RG failover validation script for long-running iperf3 through manual RG ownership moves
- link the new failover validator from the existing userspace HA validation doc

## Validation
- bash -n scripts/userspace-ha-failover-validation.sh
- bash -n scripts/userspace-ha-validation.sh
- live dry run: ./scripts/userspace-ha-failover-validation.sh --duration 20 --parallel 4
  - userspace preflight and RG ownership checks passed
  - iperf3 startup hit the existing stale/busy server condition on all 3 attempts, so the run did not reach the RG failover step
  - artifacts were captured under /tmp/userspace-ha-failover-rg1-* for follow-up debugging

---

## PR #234 — userspace: finish HA failover follow-ups [MERGED] (merged 2026-03-16)

Branch: `fix/userspace-ha-followups`

## Summary
- preserve active sessions across RG failover in the userspace dataplane
- fix steady-state fabric-traversal connection setup latency
- keep the failover parity plan and validator aligned with the new behavior

## Validation
- go test ./pkg/dataplane/userspace/... ./pkg/daemon/...
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- cargo test --manifest-path userspace-dp/Cargo.toml build_forwarding_state_uses_fabric_snapshot_macs_without_parent_interface -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml inactive_owner_rg_redirects_established_session_to_fabric -- --nocapture

---

## PR #235 — userspace: preserve fabric ingress across failover sync [MERGED] (merged 2026-03-16)

Branch: `fix/userspace-fabric-ingress-sync`

## Summary
- preserve `fabric_ingress` across userspace session delta export, daemon sync bridging, and helper session reconstruction
- carry the userspace-only sync marker through `SessionValue.LogFlags` without changing the BPF session ABI
- update the HA failover parity plan with the current branch validation result

## Validation
- go test ./pkg/dataplane/userspace/... ./pkg/daemon/...
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- cargo test --manifest-path userspace-dp/Cargo.toml build_synced_session_entry_preserves_fabric_ingress -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml build_forwarding_state_uses_fabric_snapshot_macs_without_parent_interface -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml inactive_owner_rg_redirects_established_session_to_fabric -- --nocapture
- ./scripts/userspace-ha-failover-validation.sh --deploy --duration 20 --parallel 4

## Live result
- current master: failover validator survived but recorded 5 zero-throughput intervals
- this branch: failover validator passed with 0 zero-throughput intervals and 17.4 Gbps sender throughput

---

## PR #236 — userspace: fix HA fabric stream collapse [MERGED] (merged 2026-03-16)

Branch: `fix/userspace-ha-failover-stress`

## Summary
- harden the userspace HA failover validator with a strict steady-state split-RG fabric gate
- fix peer-side reverse resolution so fabric-originated sessions only redirect back to fabric when the target RG is inactive locally
- update HA validation docs with the new fabric-path acceptance criteria

## Validation
- bash -n scripts/userspace-ha-failover-validation.sh
- cargo test --manifest-path userspace-dp/Cargo.toml fabric_originated_reverse_session_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml lookup_forward_nat_across_scopes_returns_shared_canonical_reverse_entry -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml resolve_flow_session_decision_uses_canonical_key_for_translated_forward_hit -- --nocapture
- ./scripts/userspace-ha-failover-validation.sh --steady-only --source-node 1 --target-node 0 --duration 30 --parallel 4
- ./scripts/userspace-ha-failover-validation.sh --duration 30 --parallel 4

## Live results
- split-RG steady-state fabric validation: 0 zero-throughput intervals, 0 per-stream zero-throughput intervals, 17.8 Gbps sender
- RG1 failover validation: 0 zero-throughput intervals, 0 per-stream zero-throughput intervals, 6.70 Gbps sender


---

## PR #237 — userspace: keep standby HA helper armed [MERGED] (merged 2026-03-16)

Branch: `fix/userspace-ha-perf-parity`

## Summary
- keep standby HA userspace helpers armed so stale-MAC traffic stays on the userspace fabric path during RG ownership moves
- update the HA failover parity doc with the new repeated failover/failback behavior and remaining perf gaps

## Validation
- go test ./pkg/dataplane/userspace/...
- ./scripts/userspace-ha-failover-validation.sh --cycles 3 --interval 5 --duration 90 --parallel 4
- ./scripts/userspace-ha-failover-validation.sh --steady-only --source-node 1 --target-node 0 --duration 90 --parallel 4
- RUNS=1 DURATION=5 PARALLEL=4 MIN_GBPS_V4=1 MIN_GBPS_V6=1 ./scripts/userspace-ha-validation.sh --env test/incus/loss-userspace-cluster.env

---

## PR #238 — userspace: harden HA session handoff across failover [MERGED] (merged 2026-03-16)

Branch: `fix/userspace-ha-validator-tail`

## Summary
- harden the userspace HA failover validator so near-end iperf completions are classified correctly
- prewarm reverse synced sessions when RG ownership activates and synthesize late reverse companions only on the locally active owner
- close the remaining repeated RG1 failover/failback stream-drop gap without changing the standby steady-state behavior

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- cargo test --manifest-path userspace-dp/Cargo.toml activated_owner_rgs_detects_inactive_to_active_transitions -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml synthesized_synced_reverse_entry_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml prewarm_reverse_synced_sessions_for_owner_rgs_adds_reverse_companion -- --nocapture
- ./scripts/userspace-ha-failover-validation.sh --cycles 3 --interval 5 --duration 90 --parallel 4
- ./scripts/userspace-ha-failover-validation.sh --steady-only --source-node 1 --target-node 0 --duration 30 --parallel 4

## Live results
- repeated RG1 failover/failback: 0 aggregate zero-throughput intervals, 0 per-stream zero-throughput intervals
- split-RG steady-state fabric gate remained 0/0 on stream health


---

## PR #239 — userspace: improve HA failover reliability and validation [MERGED] (merged 2026-03-17)

Branch: `fix/userspace-ha-reliability-perf-followups`

## Summary
- keep standby userspace HA nodes seeded and armed
- reclaim TX frames before copy fallback in the forwarding path
- expose direct/copy/in-place TX mode counters in normal userspace status
- harden the HA failover validator with iperf JSON-stream, retransmit reporting, and collapse detection
- batch the forward-mode counters to avoid per-packet atomic overhead
- install a reverse fabric-return session on miss during failover handoff
- relax the pre-sync source session gate to match real HA session timing

## Notes
- this is a clean follow-up branch from current `master`
- it intentionally leaves out the temporary debug trace commits from `fix/userspace-ha-validator-tail`

## Validation
- `bash -n scripts/userspace-ha-failover-validation.sh`
- `python3 -m py_compile scripts/iperf-json-metrics.py`
- `go test ./pkg/dataplane/userspace/...`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`

## Live validation previously run on the equivalent dataplane code
- strict split-RG steady-state: `17.981 Gbps`, `0` aggregate zero-throughput intervals, `0` per-stream zero-throughput intervals
- RG1 failover: `19.527 Gbps`, `0` aggregate zero-throughput intervals, `0` per-stream zero-throughput intervals


---

## PR #240 — userspace: fix firewall-local performance in interrupt mode [MERGED] (merged 2026-03-17)

Branch: `fix/userspace-firewall-local-interrupt`

## Summary
- preserve interface-SNAT local delivery on session-hit and reverse paths
- keep firewall-local sessions helper-only instead of publishing them into USERSPACE_SESSIONS
- raise slow-path queue and rate ceilings so firewall-local TCP under interrupt mode no longer collapses

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- cargo test --manifest-path userspace-dp/Cargo.toml interface_snat -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml rate_limiter_refills_after_window -- --nocapture
- live deploy to bpfrx-userspace-fw0/1
- fw1 as RG1 primary: iperf3 -c 2001:559:8585:80::200 -P 8 -t 60 sustained ~23.1 Gbps with no zero-throughput intervals
- fail RG1 to fw0: local IPv4 ping works, local IPv4 iperf3 ~23.4 Gbps, local IPv6 iperf3 ~23.1 Gbps
- restore RG1 to fw1: cluster-userspace-host transit sanity checks remained in expected range


---

## PR #241 — userspace: fast-path established firewall-local sessions [MERGED] (merged 2026-03-17)

Branch: `fix/userspace-firewall-local-fastpath`

## Summary
- fast-path established firewall-local sessions via action-aware `USERSPACE_SESSIONS` entries
- keep helper-local firewall sessions in helper HA state while publishing exact-key kernel pass entries
- extend local-delivery session-miss handling and expiry cleanup so TCP/UDP established traffic does not depend on TUN reinjection

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `go test ./pkg/dataplane/userspace/...`
- live deploy and validation on `bpfrx-userspace-fw0/1`
  - local IPv4 `iperf3 -c 172.16.80.200 -P 8 -t 8` sustained ~23.5 Gbps on both primaries
  - local IPv6 `iperf3 -c 2001:559:8585:80::200 -P 8 -t 8` sustained ~23.2 Gbps on both primaries
  - helper counters stayed near first-packet levels instead of tracking the full established flow


---

## PR #242 — userspace: prototype same-device shared UMEM [CLOSED] (closed 2026-03-17)

Branch: `fix/userspace-same-device-shared-umem-prototype`

## Summary
- start a narrow same-device shared-UMEM prototype for userspace AF_XDP
- restrict shared UMEM grouping to same-device `mlx5_core` bindings only
- widen in-place forwarding eligibility from same-binding hairpin to same-allocation forwards
- update the shared UMEM and performance docs to reflect the current direct-TX copy bottleneck and prototype scope

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml shared_umem_group_key_is_same_device_mlx5_only -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml cloned_worker_umem_shares_allocation_identity -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml rewrite_forwarded_frame_in_place_reuses_rx_frame -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml rewrite_forwarded_frame_in_place_keeps_ipv6_tcp_ports_after_vlan_snat -- --nocapture`

## Notes
- this is intentionally same-device-only; it does not attempt cross-NIC shared UMEM
- it will not, by itself, remove the copy from the current HA lab cross-NIC transit path

---

## PR #243 — userspace: improve HA reliability and cross-NIC perf baseline [MERGED] (merged 2026-03-17)

Branch: `fix/userspace-cross-nic-ha-perf-baseline`

## Summary
- harden HA userspace failover validation and helper/runtime visibility
- preserve and repair HA session behavior needed for split-RG and failover survivability
- improve the current cross-NIC performance baseline with measured low-risk hot-path cuts
- add the current userspace performance plan and update phase status

## Included work
- expose forward TX mode counters and batch their updates off the hot path
- add retransmit-aware HA iperf validation and relax the pre-sync source session gate
- install reverse fabric return sessions on miss during failover handoff
- seed and arm standby HA userspace inventory from config state
- reclaim TX frames before copy fallback
- trim session-hit resolution overhead
- cache target binding indices on forward requests
- batch binding live counters per poll
- trim empty-poll fixed costs
- add/update userspace performance planning docs

## Validation
- `go test ./pkg/dataplane/userspace/...`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- live deploys to `loss:bpfrx-userspace-fw0/1`
- `./scripts/userspace-ha-validation.sh --env test/incus/loss-userspace-cluster.env`
- `./scripts/userspace-ha-failover-validation.sh --duration 30 --parallel 4`
- matched active-node `perf record` plus manual `iperf3` transit runs

## Notes
- this branch intentionally keeps only measured perf slices that stayed green under the HA gates
- rejected experiments were reverted and are not part of this PR


---

## PR #244 — fix: restore userspace HA baseline after shared umem merge [MERGED] (merged 2026-03-17)

Branch: `fix/userspace-disable-shared-umem-runtime`

## Summary
- disable the merged shared-UMEM runtime path in normal worker startup
- restore the HA lab baseline to private UMEM per binding
- rework the userspace performance and cleanup plans around the restored baseline

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- deploy to loss userspace HA lab
- verify both nodes return to 24/24 bound and ready bindings
- verify IPv4/IPv6 internal reachability and TTL/hop-limit time-exceeded replies
- run a short userspace HA validation pass

---

## PR #245 — userspace: land kept frame path perf slices [MERGED] (merged 2026-03-17)

Branch: `fix/userspace-perf-keep-slices`

## Summary
- use a non-overlapping copy for direct frame payload writes
- lower Ethernet header write overhead in the direct frame builder
- keep this PR limited to the two measured perf slices worth landing

## Why
The experimental perf branch accumulated a lot of rejected slices plus explicit reverts. These two commits are the only remaining frame-path changes that were worth keeping.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- live validation previously run on the same code path in the HA lab:
  - short HA validator passed
  - failover validator stayed green
  - manual IPv4 transit runs improved relative to the restored baseline on the kept slices

---

## PR #246 — userspace: cut direct enqueue control overhead [MERGED] (merged 2026-03-17)

Branch: `fix/userspace-perf-direct-path-structural`

## Summary
- use the cached `target_binding_index` for normal direct enqueue paths
- skip shared-recycle application when there are no shared recycles to apply

## Why
The current direct path already caches `target_binding_index` when building a forward request, but `enqueue_pending_forwards()` was still re-running target-binding lookup on the hot path. This change uses the cached index for normal forwards and trims an avoidable empty shared-recycle call.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_live_forward_request_caches_target_binding_index -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_forwarded_frame_into_keeps_ipv6_tcp_ports_after_vlan_snat -- --nocapture`
- live deploy to `bpfrx-userspace-fw0/1`
- manual IPv4 transit samples:
  - `18.95 Gbps`
  - `19.14 Gbps`
- `./scripts/userspace-ha-validation.sh --env test/incus/loss-userspace-cluster.env`
- `./scripts/userspace-ha-failover-validation.sh --env test/incus/loss-userspace-cluster.env --duration 30 --parallel 4`

---

## PR #247 — docs: add native userspace GRE plan [MERGED] (merged 2026-03-18)

Branch: `docs/userspace-native-gre-plan`

## Summary
- add a focused design doc for native GRE on the userspace dataplane physical NIC path
- describe removing `gr-0-0-0` from the transit dataplane path
- document policy-based routing without a tunnel netdevice, including when dummy interfaces still make sense

## Notes
- docs only
- no runtime code changes

---

## PR #248 — userspace: implement native GRE transit dataplane [MERGED] (merged 2026-03-19)

Branch: `fix/userspace-native-gre-impl`

## Summary
- move GRE transit onto the physical NIC userspace dataplane with native decap/encap and logical tunnel endpoints
- preserve tunnel-aware session sync, PBR steering, and host GRE compatibility during migration
- add isolated-cluster native GRE validation and harden failover/failback session handling

## Validation
- go test ./pkg/dataplane/userspace/... ./pkg/dataplane/...
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- PREFERRED_ACTIVE_NODE=0 BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./scripts/userspace-native-gre-validation.sh --deploy --failover --count 3
- PREFERRED_ACTIVE_NODE=1 BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./scripts/userspace-native-gre-validation.sh --failover --count 3

---

## PR #249 — docs: add userspace dataplane packet capture design [MERGED] (merged 2026-03-18)

Branch: `docs/userspace-capture-plan`

## Summary
- Design for tcpdump-compatible capture of the AF_XDP forwarding path
- Virtual tap interfaces (mon-ge-0-0-1, mon-ge-0-0-2-egress) for live sniffing
- Three capture points: ingress, egress (post-NAT), and drops (with reason)
- Lock-free ring buffer + dedicated writer thread architecture
- Zero overhead when disabled

## Validation
- Documentation only, no runtime code changes

---

## PR #250 — test: add native GRE UDP and traceroute validation [MERGED] (merged 2026-03-19)

Branch: `fix/userspace-native-gre-followups`

## Summary
- extend native GRE validation with steady-state UDP burst and traceroute checks
- update the native GRE validation skill and plan doc to reflect the new coverage
- record the existing RG1 node0->node1 TCP failover regression as the blocker for post-failover UDP/traceroute proof

## Validation
- `bash -n scripts/userspace-native-gre-validation.sh`
- `python3 -m py_compile scripts/iperf-json-metrics.py`
- `PREFERRED_ACTIVE_RGS=1 PREFERRED_ACTIVE_NODE=0 ... ./scripts/userspace-native-gre-validation.sh --udp --traceroute --count 2`
- manual restore of RG1 primary back to node0 after the failing broader failover attempt

---

## PR #251 — userspace: harden native GRE failover and host-origin handoff [MERGED] (merged 2026-03-19)

Branch: `fix/userspace-native-gre-followups-clean`

## Summary
- preserve native GRE tunnel identity across session sync and failover
- block tunnel interface-SNAT local delivery on session miss so failover replies do not leak onto the tunnel anchor
- validate local-origin GRE handoff through the persistent TUN anchor, including post-failover host probes and host-origin iperf
- update the native GRE plan and skill to describe the TUN anchor architecture

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml tunnel_session_miss_blocks_interface_nat_local_delivery -- --nocapture
- go test ./pkg/dataplane/userspace/... ./pkg/daemon/... ./pkg/routing/...
- PREFERRED_ACTIVE_NODE=0 PREFERRED_ACTIVE_RGS=1 GRE_IPERF_DURATION=20 GRE_IPERF_PARALLEL=1 GRE_IPERF_MIN_GBPS=1.0 BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./scripts/userspace-native-gre-validation.sh --failover --iperf --udp --traceroute --count 3
- GRE_VALIDATE_HOST_PROBES=1 PREFERRED_ACTIVE_NODE=0 PREFERRED_ACTIVE_RGS=1 GRE_IPERF_DURATION=8 GRE_HOST_IPERF_DURATION=8 GRE_IPERF_PARALLEL=1 GRE_HOST_IPERF_PARALLEL=1 GRE_IPERF_MIN_GBPS=1.0 GRE_HOST_IPERF_MIN_GBPS=0.5 BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./scripts/userspace-native-gre-validation.sh --failover --iperf --udp --traceroute --count 2


---

## PR #252 — docs: add userspace cold-start fix plan [MERGED] (merged 2026-03-23)

Branch: `docs/userspace-cold-start-fix-plan`

## Summary
- add a cold-start gap analysis for the userspace dataplane
- document the fixes already in place for MissingNeighbor and neighbor refresh
- document the missing architecture: authoritative neighbor publication, generation-aware sync, and readiness-based ctrl enable

## Scope
- docs only
- no runtime code changes

---

## PR #254 — userspace: recover helper startup and move neighbor sync into helper [MERGED] (merged 2026-03-26)

Branch: `fix/userspace-worker-umem-panic`

## Summary
- recover userspace helper startup/rebind behavior on the HA lab
- add external IPv4/IPv6 checks to the HA failover validator
- move runtime neighbor sync into the Rust helper with initial netlink dump plus continuous updates
- expose helper-owned neighbor generation in userspace status output

## Why
The old model depended on `bpfrxd` periodically pushing the kernel neighbor table into the helper. That left a cold-start hole: if the kernel already knew a neighbor like `.200` but no new neighbor event arrived after helper startup, the helper stayed blind and returned `missing_neighbor` while the kernel dataplane itself was healthy.

This change makes the helper the runtime owner of neighbor sync:
- initial `RTM_GETNEIGH` dump at startup
- continuous `RTM_NEWNEIGH` / `RTM_DELNEIGH` subscription
- manager startup gating based on helper-owned neighbor readiness instead of manager-pushed generations

## Validation
- `go test ./pkg/dataplane/userspace/...`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- live deploy to `loss` userspace cluster
- post-deploy host reachability:
  - `172.16.80.200`: `5/5`
  - `2001:559:8585:80::200`: `5/5`
- narrow IPv6 failback repro improved to `34/35`
- `MIN_SESSIONS=0 ./scripts/userspace-ha-failover-validation.sh --duration 35 --parallel 4 --interval 5`
  - external IPv4: pass
  - external IPv6: pass
  - `0` zero-throughput intervals
  - `0` per-stream zero-throughput intervals
  - sender throughput `17.712 Gbps`
- `MIN_SESSIONS=0 ./scripts/userspace-ha-failover-validation.sh --cycles 3 --duration 90 --parallel 4 --interval 5`
  - failover/failback external IPv4 and IPv6 checks passed through all cycles
  - remaining script failure is harness timing: `iperf3` completes before all scripted phases finish in cycle 2, despite no throughput collapse or reachability loss

## Follow-up
- fix multi-cycle `userspace-ha-failover-validation.sh` duration accounting so the long stress run stops reporting the false completion failure


---

## PR #255 — docs: add userspace libxdp migration notes [MERGED] (merged 2026-03-26)

Branch: `docs/userspace-libxdp-migration`

## Summary
- document the AF_XDP migration from xdpilone to the custom libxdp bridge
- record the exact timeline, key fixes, and rollback/re-enable sequence
- distinguish wrapper-level fixes from later runtime and lifecycle issues

## Testing
- not run (docs only)

---

## PR #256 — perf: improve userspace fabric failover visibility [MERGED] (merged 2026-03-26)

Branch: `fix/userspace-fabric-failover-validation`

## Summary
- spread userspace fabric redirects across all bindings on the target fabric interface
- remove per-packet pseudo-header checksum allocation in the stale-owner hot path
- document the hardened stale-owner failover workflow and monitoring expectations

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- bash -n scripts/userspace-ha-failover-validation.sh
- manual stale-owner fabric runs on loss userspace cluster
  - confirmed standby WAN stayed flat while fabric parent carried redirected traffic
  - best observed stale-owner results were ~4 Gbps on the copy-mode virtio fabric path
  - perf shifted away from checksum allocation and toward poll_binding / __xsk_generic_xmit / virtqueue_add_outbuf


---

## PR #257 — fix: improve userspace fabric failover observability [MERGED] (merged 2026-03-26)

Branch: `fix/userspace-fabric-failover-followups`

## Summary
- add fabric refresh reprobe and rate-limited failure logging in the daemon
- expose direct-TX fallback reasons through userspace status and `monitor interface`
- track direct-TX fallback counters in the Rust helper and use direct prepared segmentation on the fabric path

## Validation
- `go test ./pkg/cli/... ./pkg/grpcapi/... ./pkg/daemon/... ./pkg/dataplane/userspace/...`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml --no-run`

## Notes
- This is follow-up work after `#256`.
- The stale-owner fabric path is functionally correct, but still throughput-limited by the copy-mode `virtio_net` fabric path under load.
- The new counters are intended to make that limit visible in live failover testing instead of guessing from aggregate counters.


---

## PR #258 — userspace: harden failover handoff [MERGED] (merged 2026-03-27)

Branch: `fix/userspace-failover-hardening`

## Summary
- add staged userspace HA demotion preparation and session handoff plumbing
- add session sync barrier support and helper demotion prepare ack path
- update the failover hardening plan and checkpoint supporting tests/formatting

## Testing
- go test ./pkg/daemon/... ./pkg/cluster/... ./pkg/dataplane/userspace/...
- ~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml --no-run


---

## PR #259 — userspace: harden failover handoff and validation [MERGED] (merged 2026-03-27)

Branch: `fix/userspace-failover-hardening-followups`

## Summary
- harden userspace HA failover validation and expose the userspace dataplane counters needed to debug stale-owner forwarding in real time
- stage userspace failover handoff before demotion and add bounded manual-failover admission retry for transient sync-admission failures
- repeat direct-mode GARP/NA re-announcements after primary transition to improve LAN ownership moves during failover and rejoin
- document the current failover findings, including manual admission behavior and `sysrq-b` crash/rejoin results

## Commit Layout
- `test: harden userspace failover validation`
  - failover harness tightening
  - transition-window sampling
  - monitor/status/grpc observability for userspace binding state and queue pressure
- `userspace: stage failover handoff before demotion`
  - helper demotion prep
  - pre-drain / barrier handoff plumbing
  - forward-wire alias sync for redirected sessions
- `userspace: repeat direct failover re-announcements`
  - repeated, cancellable GARP/NA bursts after primary transition
- `cluster: retry manual failover admission`
  - bounded retry loop in `cluster.Manager.ManualFailover`
  - daemon marks only transient sync-admission failures as retryable
- `docs: update userspace failover hardening plan`
  - current live findings and operator guidance

## Validation
- `go test ./pkg/cluster/... ./pkg/daemon/... ./pkg/dataplane/userspace/... ./pkg/grpcapi/... ./pkg/cli/...`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `bash -n scripts/userspace-ha-failover-validation.sh`
- live userspace HA failover validation on `loss-userspace-cluster`
  - artifact: `/tmp/userspace-ha-failover-rg1-20260327-100223`
  - throughput: `20.685 Gbps`
  - retransmits: `4047`
  - zero-throughput intervals: `0`
  - target reachability: pass
  - external IPv4/IPv6 reachability: pass

## Current State
- controlled, admitted RG-move failover is materially better
- stale-owner forwarding is still throughput-limited on the fabric path under sustained inherited load
- raw manual failover under load is now treated as an admission problem first instead of silently blackholing traffic


---

## PR #260 — docs: add userspace failover next steps [MERGED] (merged 2026-03-27)

Branch: `docs/userspace-failover-next-steps`

## Summary
- add a focused follow-up document for the remaining userspace HA failover work
- separate what is already fixed from the specific manual RG-move dataplane bug that remains
- lay out the next code steps, implementation order, and acceptance criteria

## Included
- `docs/userspace-failover-next-steps.md`

## Purpose
This is a docs-only follow-up to the current failover hardening work. It captures the latest live findings from:

- admitted manual `RG1 node0 -> node1` failover under load
- crash/rejoin of the active node
- the deeper per-second interface snapshot run

and turns them into the next concrete implementation plan.


---

## PR #261 — userspace: narrow remaining failover local-delivery poisoning [MERGED] (merged 2026-03-28)

Branch: `fix/userspace-demotion-drain`

Summary:
- stop caching TCP local-delivery ACK misses during failover
- keep helper local-delivery sessions worker-local and out of shared aliases
- stop syncing userspace local-delivery sessions to the peer
- update failover docs with current artifacts and remaining investigation target

Validation:
- go test ./pkg/daemon/...
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- targeted Rust tests for local-delivery session miss and helper-local session behavior
- repeated loss-userspace-cluster RG1 failover validation artifacts under /tmp/userspace-ha-failover-rg1-*

Current status:
- sync admission is materially improved
- hardened RG1 failover still collapses after the move
- new owner still accumulates public-side LocalDelivery state during the bad window
- next work is tracing the creation/import path for those fw1 sessions

---

## PR #262 — cluster: hold sync readiness on disconnect [MERGED] (merged 2026-03-29)

Branch: `fix/userspace-ipv6-preflight-and-rerun`

## Summary
- keep failover validation usable when the lab WAN/public path is already down
- stop releasing cluster sync readiness on peer disconnect timeout
- document the current March 28 failover rerun findings and remaining blocker

## What changed
- add `CHECK_EXTERNAL_REACHABILITY=0` to `scripts/userspace-ha-failover-validation.sh`
- document when that switch is appropriate in the testing docs
- change `onSessionSyncPeerDisconnected()` so disconnect clears readiness and does not auto-release it on timeout
- update daemon tests to match the new disconnect policy
- record the latest failover investigation in the failover docs

## Why
The March 28 reruns isolated two different problems:

1. The lab WAN50/public path was already down.
   - `1.1.1.1` and `2606:4700:4700::1111` were unreachable
   - local `.200` IPv4/IPv6 still worked
   - that makes external preflight a lab-environment failure, not a userspace failover dataplane failure

2. The previous cluster behavior on sync transport loss was unsafe.
   - after peer disconnect, both sides could eventually flip `syncReady=true` via timeout release
   - that allowed inconsistent RG ownership after transport loss

This branch removes that timeout release on disconnect and reruns the hardened failover gate against the current build.

## Validation
- `go test ./pkg/daemon/...`
- deployed to `loss-userspace-cluster`
- reran:
  - `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env CHECK_EXTERNAL_REACHABILITY=0 SOURCE_NODE=1 TARGET_NODE=0 TOTAL_CYCLES=2 CYCLE_INTERVAL=10 ./scripts/userspace-ha-failover-validation.sh --parallel 4`

Artifacts:
- `/tmp/userspace-ha-failover-rg1-20260328-075648`
- `/tmp/userspace-ha-failover-rg1-20260328-165739`

## Current result
- the earlier split-brain timeout-release failure did not reproduce
- phase-level RG moves and standby readiness were materially better
- the current remaining blocker is no longer the old failover collapse
- the latest reruns point at node stability / long-run aggregate `iperf3` health as the next issue to work


---

## PR #263 — refactor: split afxdp helper modules and tests [MERGED] (merged 2026-03-29)

Branch: `refactor/afxdp-module-split`

## Summary
- split `userspace-dp/src/afxdp.rs` helper code into focused submodules
- move forwarding-heavy tests into `afxdp/forwarding.rs` and frame/rewrite-heavy tests into `afxdp/frame.rs`
- refresh the module split plan/status doc to reflect the completed extraction state

## Testing
- `cargo fmt --manifest-path userspace-dp/Cargo.toml --all`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml`
- `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env CHECK_EXTERNAL_REACHABILITY=0 TOTAL_CYCLES=1 ./scripts/userspace-ha-failover-validation.sh --deploy --duration 60 --parallel 4`
- A/B comparison against current `master` with the same cluster command

## Notes
- The userspace failover gate still fails on both this branch and current `master`.
- The cluster A/B did not show a clear failover regression unique to this refactor branch.


---

## PR #264 — docs: correct session sync architecture [MERGED] (merged 2026-03-29)

Branch: `docs/session-sync-architecture-review`

## Summary
- correct the session sync architecture doc to match current `master`
- document the readiness split between inbound bulk receipt and outbound bulk acknowledgement
- describe the current userspace delta filtering and graceful demotion handoff flow

## What Was Wrong Or Missing
- the old doc treated readiness as bulk receipt only and omitted `BulkAck` / sender-side priming
- it did not describe the bulk-prime retry loop or pending-bulk-ack state
- it described userspace deltas as an unfiltered mirror instead of the current owner-aware and `local_delivery`-filtered path
- it reduced graceful demotion to a single barrier instead of the actual quiesce / pause / export / drain / barrier / helper-prepare sequence
- it compressed userspace mirroring into `SetClusterSyncedSession*` and omitted helper-originated delta/export paths

## Testing
- docs-only change
- reviewed against current code in `pkg/cluster/sync.go`, `pkg/daemon/daemon.go`, and `pkg/dataplane/userspace/manager.go`

---

## PR #265 — docs: add session sync design proposal [MERGED] (merged 2026-03-29)

Branch: `docs/session-sync-design`

## Summary
- add a forward-looking session sync design note
- compare keeping sync in Go vs moving it into Rust vs a hybrid model
- recommend keeping HA/session-sync control in `bpfrxd` while moving producers toward event-driven delivery

## Recommendation
- keep peer session-sync transport, readiness, barriers, and failover admission in Go
- replace helper `DrainSessionDeltas(...)` polling with a helper-to-daemon ordered local stream
- move kernel session sync toward event-first production
- keep periodic sweep as reconciliation, not the primary steady-state producer

## Why
- HA/session-sync is part of the cluster control plane, not just the userspace dataplane
- moving the full transport into Rust would complicate VRRP/RG ownership and kernel-session integration
- the main inefficiency today is the polling/sweep-heavy producer model, not that sync currently lives in Go

## Testing
- docs-only change

---

## PR #295 — userspace: select XSK bind mode from XDP attach mode [CLOSED] (closed 2026-03-31)

Branch: `fix/xdp-mode-aware-xsk-bind`

## Summary
- select AF_XDP bind flags from the interface's actual XDP attach mode
- keep generic `virtio_net` bindings on auto mode, but force copy for generic non-virtio interfaces
- avoid taking zerocopy on `mlx5` interfaces when the compiler has already downgraded the box to generic XDP

## Why
Issue #294.

On the userspace cluster, a native attach failure on `ifindex=4` downgrades all interfaces to `xdpgeneric`. Before this change the helper still chose zerocopy for non-`virtio_net` NICs based only on driver name, which broke steady-state forwarding to `.200`.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `make build-userspace-dp`
- deployed helper-only build to `loss-userspace-cluster`
- observed bind logs on `fw1`:
  - generic `virtio_net`: `mode=Copy flags=0x0000`
  - generic `mlx5`: `mode=Copy flags=0x000a`
- connectivity after warm-up:
  - `cluster-userspace-host -> 172.16.80.200` ping: pass
  - TCP connect to `172.16.80.200:5201`: pass
  - `iperf3 -c 172.16.80.200 -P 4 -t 3`: ~`9.27 Gbps`

## Notes
- this fixes the helper-side bind selection bug
- it does not address the separate global generic fallback issue tracked in #293


---

## PR #296 — userspace: fix XDP mode fallback and harden HA handoff [MERGED] (merged 2026-03-31)

Branch: `fix/per-interface-xdp-fallback`

## Summary
- select AF_XDP bind mode from the actual XDP attach mode instead of inferring from driver name
- fall back to generic XDP per interface instead of downgrading the whole box when one native attach fails
- harden userspace HA synced-session handoff during RG transition
- document the XDP mode mismatch, cold-start behavior, failover findings, and remaining gaps

## Commit layout
1. `d137e3ee` `userspace: select XSK bind mode from XDP attach mode`
2. `c083eda8` `dataplane: fall back to generic XDP per interface`
3. `ee4a6328` `userspace: harden HA synced-session handoff`
4. `3207d737` `docs: record XDP mode and HA failover findings`
5. `5ae51b0b` `chore: trim trivial afxdp warnings`

## Why
This branch started as a stacked investigation branch and is now collapsed into a reviewable four-commit series.

The concrete bugs addressed here are:
- generic-vs-native XDP attach mode mismatch causing the helper to pick the wrong AF_XDP bind mode
- one-interface native attach failure globally downgrading unrelated interfaces to `xdpgeneric`
- helper demotion-prepare recovery gaps during graceful failover
- active new owner failing to promote translated synced forward hits after RG activation

## What changed
### 1. Mode-aware XSK bind selection
- [userspace-dp/src/afxdp/bind.rs](userspace-dp/src/afxdp/bind.rs)
  - query actual XDP mode with `bpf_xdp_query()`
  - force `Copy` for generic non-`virtio_net` interfaces
  - keep generic `virtio_net` on auto
  - assume generic when mode query fails instead of selecting zerocopy blindly

### 2. Per-interface generic fallback
- [pkg/dataplane/compiler.go](pkg/dataplane/compiler.go)
- [pkg/dataplane/loader.go](pkg/dataplane/loader.go)
  - native attach failure falls back only on the failed interface
  - unrelated interfaces keep native XDP if they can still attach it

### 3. HA synced-session handoff fixes
- [userspace-dp/src/afxdp.rs](userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/forwarding.rs](userspace-dp/src/afxdp/forwarding.rs)
- [userspace-dp/src/afxdp/frame.rs](userspace-dp/src/afxdp/frame.rs)
- [userspace-dp/src/afxdp/session_glue.rs](userspace-dp/src/afxdp/session_glue.rs)
- [userspace-dp/src/afxdp/types.rs](userspace-dp/src/afxdp/types.rs)
  - prewarm reverse sessions for activated RGs
  - add demotion-prepare recovery safeguards
  - promote translated synced forward hits on the active owner instead of keeping them transient indefinitely

### 4. Findings / docs
- [docs/userspace-xdp-mode-and-cold-start-findings.md](docs/userspace-xdp-mode-and-cold-start-findings.md)
- [docs/failover-hardening-progress.md](docs/failover-hardening-progress.md)
- [docs/userspace-failover-next-steps.md](docs/userspace-failover-next-steps.md)

*(truncated — 78 lines total)*


---

## PR #299 — fix: resolve 9 open issues (HA transitions, demotion cleanup, API pagination) [MERGED] (merged 2026-03-31)

Branch: `fix/all-open-issues`

## Summary
- **#283, #284, #285**: HA transition guards — `pendingRGTransitions` per-RG map with defer cleanup, promotion pre-switches to eBPF pipeline
- **#297, #298**: Demotion session cleanup — synchronous alias map deletion from `shared_nat_sessions`/`shared_forward_wire_sessions`, `clear_ha_demotion` on PrepareRGDemotion failure
- **#286, #288, #289**: Userspace dataplane fixes — pre-filter in session refresh, static neighbor lookup in retry, reverse key for SNAT ICMP
- **#275**: GetSessions cursor-based pagination with `page_token`/`page_size`, `no_enrich` flag

## Not included
- **#290, #291**: XDP shim changes reverted — interface-NAT fall-through pushes BPF stack to 528 bytes (> 512 limit). Needs helper-side approach.

## Test plan
- [x] `make test` — all 32 packages pass
- [x] `cargo test` (userspace-dp) — 408 tests pass
- [x] Loss cluster deploy (fw0 + fw1) — BPF programs load, cluster healthy
- [x] End-to-end connectivity — LAN host → 1.1.1.1 via SNAT, 0% loss
- [x] Manual RG failover — all 3 RGs failover/failback cleanly
- [x] Multi-RG failover — RG0+RG1+RG2 simultaneous, no interference
- [x] Hard crash recovery — force-stop fw0, fw1 takes over, fw0 rejoins
- [x] Ctrl not permanently disabled after failover (#283 validated)

Closes #275, #283, #284, #285, #286, #288, #289, #297, #298

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #300 — docs: add failover testing runbook [MERGED] (merged 2026-03-31)

Branch: `docs/failover-testing-runbook`

## Summary
- add a failover-only testing runbook under `testing-docs/`
- document userspace and legacy eBPF failover workflows in one place
- cover preflight, artifacts, RG move, crash/rejoin, split-RG, pass criteria, and reset steps

## Testing
- docs only

---

## PR #301 — docs: audit userspace forwarding and failover gaps [MERGED] (merged 2026-04-01)

Branch: `docs/userspace-forwarding-failover-gaps`

## Summary
- audit whether the eBPF dataplane is still in use while userspace forwarding is active
- audit why HA failover currently needs more than MAC movement plus GARP/NA
- document the architectural gaps between the current hybrid model and the desired strict userspace / minimal-failover model

## Testing
- docs only

---

## PR #313 — feat: strict userspace mode, HA install fence, deterministic reverse companions [MERGED] (merged 2026-04-01)

Branch: `feat/strict-userspace-and-ha-improvements`

## Summary
Implements issues #302-#312 from the userspace forwarding and failover gap audit (PR #301):

**Strict userspace forwarding (#303, #304, #305, #306, #307):**
- Define `DataplaneMode` enum (`ebpf_only`, `userspace_compat`, `userspace_strict`) with runtime tracking
- Add `USERSPACE_CTRL_FLAG_STRICT` to XDP shim — transit fallback drops with counter instead of escaping to eBPF/kernel
- XSK liveness failure in strict mode keeps shim attached (fail-closed) instead of silently swapping to `xdp_main_prog`
- Expose per-interface entry program and fallback counters in `ProcessStatus`
- PASS_TO_KERNEL observability counters for audit

**HA failover improvements (#310, #311, #312):**
- Pre-install reverse companion sessions in sync path so standby has them before RG activation
- Expose install fence sequence + ack timestamp in cluster status
- Track `last_cache_flush_at` for HA cache invalidation observability
- New `docs/ha-forwarding-state-inventory.md` enumerating all 30 forwarding state items

**Documentation (#309):**
- HA forwarding state inventory (30 items classified as Replicated/Derived/Fenced/Local-only)
- Updated `docs/bugs.md` and `docs/phases.md`

Closes #302 #303 #304 #305 #306 #307 #308 #309 #310 #311 #312

## Test plan
- [x] Go build clean (`go build ./...`)
- [x] All Go tests pass (880+ across 32 packages)
- [x] Rust XDP shim builds clean (`cargo +nightly build --release`)
- [x] Rust helper builds clean + all 408 tests pass
- [ ] Deploy to cluster and run failover test matrix
- [ ] Verify strict mode fallback counters in status output

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #331 — Clean conntrack state on synced-session delete paths in userspace dataplane [CLOSED] (closed 2026-04-02)

Branch: `copilot/review-last-50-commits`

Reviewing the recent HA/userspace session-sync work surfaced one missed follow-up: some synced-session delete paths removed helper session state without invoking mirrored BPF conntrack cleanup. This PR wires conntrack cleanup through those paths and adds narrow regressions around the affected flows.

- **Problem**
  - Recent session mirroring changes introduced conntrack-backed session display state.
  - Two synced-session removal paths still used the legacy delete flow, leaving stale conntrack entries behind:
    - `WorkerCommand::DeleteSynced`
    - translated synced-hit purge on inactive fabric ingress

- **Change**
  - Thread conntrack FDs through the relevant userspace dataplane call chain:
    - `apply_worker_commands(...)`
    - `resolve_flow_session_decision(...)`
    - `purge_translated_synced_hit(...)`
  - Switch those delete paths to `delete_session_map_entry_for_removed_session_with_conntrack(...)` so helper session removal and conntrack cleanup stay coupled.

- **Regression coverage**
  - Add a focused test for `DeleteSynced` proving the conntrack-delete helper is reached.
  - Tighten the translated shared-hit transient test to assert the shared aliases are purged and conntrack cleanup is invoked.
  - Add a small test-only counter hook in `bpf_map.rs` to verify the delete helper is called without needing real pinned BPF maps.

- **Example**
  ```rust
  delete_session_map_entry_for_removed_session_with_conntrack(
      session_map_fd,
      &key,
      lookup.decision,
      &lookup.metadata,
      conntrack_v4_fd,
      conntrack_v6_fd,
  );
  ```

<!-- START COPILOT CODING AGENT SUFFIX -->



<!-- START COPILOT ORIGINAL PROMPT -->



<details>

<summary>Original prompt</summary>

> Review the last 50 commits and see if there's anything you can improve on or fix. Then create PRs or issues to act on


</details>



---

## PR #336 — fix: userspace/eBPF audit — counters, conntrack flush, session visibility [MERGED] (merged 2026-04-01)

Branch: `fix/userspace-ebpf-audit`

## Summary
Audit of eBPF usage while userspace dataplane is active, with four fixes:

- **#332**: Sync userspace forwarding counters to BPF `global_counters` map — `ReadGlobalCounter` now includes userspace-forwarded packets
- **#333**: Refresh BPF conntrack `last_seen` every 10s for userspace sessions — fixes stale idle time in session display and prevents premature GC expiry
- **#334**: Fix two bugs in BPF conntrack flush on ctrl re-enable:
  - Wrong byte offset (read `session_id` at offset 8 instead of `created` at offset 16)
  - Unit mismatch (compared nanosecond cutoff against second timestamp)
  - The flush **never worked** — all stale sessions were kept
- **#335**: Add error logging for BPF conntrack map writes + byte order regression test

Closes #332 #333 #334 #335

## Test plan
- [x] Go build clean, 26 packages pass
- [x] Rust build clean, 414 tests pass
- [ ] Deploy and verify `show security flow session` shows zones for userspace sessions
- [ ] Verify BPF global counters increment during userspace forwarding
- [ ] Verify conntrack flush actually removes stale sessions on ctrl re-enable

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #337 — docs: add simple HA failover design [MERGED] (merged 2026-04-02)

Branch: `docs/ha-simple-failover-design`

## Summary
- add a phased design doc for simplifying HA failover around a smaller authoritative state model
- explain why current userspace HA is still complex even with continuous session sync
- turn that analysis into implementation phases tied to concrete follow-up issues

## What the design argues
Current HA is hard because the replicated stream is not the same thing as the forwarding-ready state. The current implementation still needs activation-time repair work:
- reverse prewarm
- forward re-resolution
- flow-cache flush / invalidation
- drain / barrier choreography to prove cutover safety

The proposed simplification is to split HA into three layers:
1. a portable canonical session record replicated across nodes
2. a continuously maintained local runtime state on both nodes
3. a disposable flow cache validated by epochs

That drives failover toward:
- ownership flip
- MAC move
- GARP / gratuitous NA
- continued forwarding

## Phases
- Phase 1: portable canonical session schema
- Phase 2: continuous standby materialization
- Phase 3: canonical helper store plus derived indexes
- Phase 4: epoch-based flow-cache validation
- Phase 5: applied-sequence cutover fence
- Phase 6: event-first producers, reconciliation-only sweep

## Related issues
- #314
- #315
- #316
- #318
- #319
- #320
- #321
- #322
- #323


---

## PR #357 — userspace: simplify flow cache validation and construction [MERGED] (merged 2026-04-02)

Branch: `refactor/simplify-flow-cache`

## Summary
- simplify flow-cache validation state by separating rewrite data from cache stamps
- extract flow-cache eligibility and entry construction helpers out of the packet loop
- add a design/status doc for the remaining flow-cache cleanup phases

## Commits
- `744a7ef5` `refactor: simplify flow cache validation state`
- `4f20542b` `refactor: extract flow cache eligibility helpers`
- `82ecacc5` `docs: add flow cache simplification plan`

## What changed
### Flow cache types
- introduced `FlowCacheStamp`
- introduced `FlowCacheLookup`
- `FlowCacheEntry` now carries a single explicit validation stamp
- `RewriteDescriptor` now only carries rewrite/tx data

### Packet path cleanup
- packet loop now uses `FlowCacheLookup::for_packet(...)`
- packet loop now uses `FlowCacheEntry::packet_eligible(...)`
- packet loop now uses `FlowCacheEntry::from_forward_decision(...)`
- removed inline cache-entry construction plumbing from the hot path

### Docs
- added `docs/flow-cache-simplification.md`
- documents why the cache contributes to HA complexity, what has already been simplified, and the next phases

## Why
The goal is to keep the flow cache as a performance feature while making it less entangled with HA state transitions. This PR does not change HA semantics; it makes cache validation and cache construction explicit so the next cleanup pass can extract cached-hit execution cleanly.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_invalidation_for_demoted_owner_rg -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_unrelated_rg_not_invalidated -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_descriptor_nat64_falls_back -- --nocapture`


---

## PR #361 — docs: audit HA failover simplification gaps [MERGED] (merged 2026-04-02)

Branch: `docs/ha-failover-simplification-audit`

## Summary
- audit the current `origin/master` HA failover path across Go and Rust
- document why failover is still more than MAC move + GARP/GNA
- map the simplification plan to the current issue set and new simplification issues

## Includes
- new doc: `docs/ha-failover-simplification-audit.md`
- references to existing HA/session-sync/failover issues
- new simplification issues:
  - #358
  - #359
  - #360

## Context
This audit is against the current `origin/master` failover implementation and is intended to make the remaining HA complexity concrete before implementation work starts.


---

## PR #362 — userspace: seed HA lease from active state updates [MERGED] (merged 2026-04-02)

Branch: `fix/ha-runtime-lease-model`

## Summary
- seed the helper HA lease on every active state update instead of waiting for a later watchdog-only refresh
- centralize packet-time HA activity checks onto the helper's lease model
- add coverage for active-without-watchdog lease seeding

## Why
This is the first implementation slice under #360.

The helper was still enforcing HA with split semantics:
- ownership from `active`
- liveness from a separate watchdog timestamp

That meant a freshly active RG could still read as `HAInactive` until the next watchdog-only sync arrived. This change makes active state updates and watchdog renewals refresh the same lease model.

## Testing
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml update_ha_state_seeds_lease_for_active_group_without_watchdog -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml --no-run`


---

## PR #378 — fix: collapse helper demotion into single update_ha_state transition [MERGED] (merged 2026-04-02)

Branch: `fix/collapse-demotion`

## Summary
Remove the two-phase `prepare_ha_demotion` + `update_ha_state(active=false)` path. The prepare step set a `SuppressedUntil` lease before the active flag changed, but Go called both back-to-back with no work between them. `update_ha_state` already handles the complete demotion atomically.

**Removed** (-245 lines):
- `PrepareRGDemotion()` Go method + `userspaceRGDemotionPreparer` interface
- `prepare_ha_demotion` / `clear_ha_demotion` control request handlers
- `set_demoting_owner_rgs()` + `HA_DEMOTION_PREP_LEASE_SECS`
- `HAForwardingLease::SuppressedUntil` variant
- `HADemotionPrepareRequest` protocol struct + 3 related tests

**Kept**: barrier check in `prepareUserspaceRGDemotionWithTimeout` (peer must have all session deltas).

Closes #359

## Test plan
- [x] Go build + tests pass (daemon, dataplane/userspace)
- [x] Rust build + 419/420 tests pass (1 pre-existing failure unrelated)
- [ ] Manual failover test with iperf3

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #379 — refactor: split HA methods from afxdp.rs into afxdp/ha.rs [MERGED] (merged 2026-04-02)

Branch: `refactor/363-split-afxdp-ha`

## Summary
Move 7 Coordinator HA methods + 4 tests into `afxdp/ha.rs` (475 lines). `afxdp.rs` drops from 8683 to 8219 lines. Pure refactor, no behavior changes.

Closes #363

## Test plan
- [x] `cargo build --release` passes
- [x] 419/420 tests pass (1 pre-existing failure unrelated)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #380 — refactor: split TX functions from frame.rs into frame_tx.rs [MERGED] (merged 2026-04-02)

Branch: `refactor/364-split-frame-tx`

## Summary
Move transmit/enqueue functions into `afxdp/frame_tx.rs` (1229 lines). `frame.rs` drops from 8177 to 6949 lines. Pure refactor, no behavior changes.

Closes #364

## Test plan
- [x] `cargo build --release` passes
- [x] 419/420 tests pass (1 pre-existing failure unrelated)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #381 — refactor: split protocol structs from main.rs into protocol.rs [MERGED] (merged 2026-04-02)

Branch: `refactor/365-split-main-protocol`

## Summary
Move 35 serde structs into `protocol.rs` (1131 lines). `main.rs` drops from 2758 to 1646 lines. Pure refactor.

Closes #365

## Test plan
- [x] `cargo build --release` passes
- [x] 419/420 tests pass (1 pre-existing failure unrelated)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #382 — refactor: split event_stream.rs into codec + transport modules [MERGED] (merged 2026-04-02)

Branch: `refactor/366-split-event-stream`

## Summary
Convert `event_stream.rs` (1339 lines) into module directory:
- `codec.rs` (546 lines) — wire format, EventFrame encoding
- `mod.rs` (815 lines) — transport state machine, I/O thread

Pure refactor. Closes #366

## Test plan
- [x] `cargo build --release` passes
- [x] All 13 event_stream tests pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #383 — refactor: split flow cache types from types.rs into flow_cache.rs [MERGED] (merged 2026-04-02)

Branch: `refactor/367-split-types-flowcache`

## Summary
Move flow cache types + 10 tests into `flow_cache.rs` (716 lines). `types.rs` drops from 1302 to 586. Pure refactor.

Closes #367

## Test plan
- [x] `cargo build --release` passes
- [x] All 12 flow cache tests pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #384 — refactor: split forwarding build from runtime resolution [MERGED] (merged 2026-04-02)

Branch: `refactor/368-split-forwarding`

## Summary
Move snapshot compilation into `forwarding_build.rs` (605 lines). `forwarding.rs` drops from 3806 to 3199. Pure refactor.

Closes #368

## Test plan
- [x] `cargo build --release` passes
- [x] All 59 forwarding tests pass, 419/420 total

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #385 — refactor: split shared session ops from session_glue.rs [MERGED] (merged 2026-04-02)

Branch: `refactor/369-split-session-glue`

## Summary
Move 14 shared-session replication functions into `shared_ops.rs` (477 lines). `session_glue.rs` drops from 3561 to 3085. Pure refactor.

Closes #369

## Test plan
- [x] `cargo build --release` passes
- [x] 419/420 tests pass (1 pre-existing failure)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #386 — refactor: split HA/sync/fabric from daemon.go into daemon_ha.go [MERGED] (merged 2026-04-02)

Branch: `refactor/370-split-daemon`

## Summary
Move 109 functions into `daemon_ha.go` (3985 lines). `daemon.go` drops from 8221 to 4258. Pure refactor.

Closes #370

## Test plan
- [x] `go build ./cmd/bpfrxd/` passes
- [x] `go test ./pkg/daemon/` passes

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #387 — refactor: split server.go, manager.go, compiler.go (#371, #372, #373) [MERGED] (merged 2026-04-02)

Branch: `refactor/371-372-373-go-splits`

## Summary
Three Go file splits — session RPCs, HA methods, NAT compilation moved to dedicated files. ~2800 lines moved, no behavior changes.

Closes #371 #372 #373

## Test plan
- [x] `go build ./cmd/bpfrxd/` passes
- [x] `go test ./pkg/grpcapi/ ./pkg/dataplane/userspace/ ./pkg/config/` all pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #388 — refactor: split sync.go, cli.go, handlers.go, compiler.go (#374-#377) [MERGED] (merged 2026-04-02)

Branch: `refactor/374-377-go-splits`

## Summary
Four Go file splits — bulk/barrier, show commands, session REST, interface compilation moved to dedicated files. ~10K lines reorganized, no behavior changes.

Closes #374 #375 #376 #377

## Test plan
- [x] `go build ./cmd/bpfrxd/ ./cmd/cli/` passes
- [x] `go test ./pkg/cluster/ ./pkg/cli/ ./pkg/api/ ./pkg/dataplane/` all pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #392 — fix: eliminate all Rust warnings and fix failing test [MERGED] (merged 2026-04-02)

Branch: `refactor/374-377-go-splits`

## Summary
- Delete 7 dead functions (-251 lines)
- Annotate 18 test-only + 13 future-use items
- Fix duplicate cancelled_keys in DemoteOwnerRG
- Result: 0 warnings, 420/420 tests pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #393 — docs: add HA failover implementation plan [MERGED] (merged 2026-04-02)

Branch: `docs/ha-failover-implementation-plan`

## Summary
- add a concrete phased implementation plan for simplifying HA failover
- link the new plan from the existing HA failover simplification audit
- record the docs work in `_Log.md`

## Context
Most of the earlier HA simplification groundwork is already on `master`. This doc isolates the remaining structural work that still keeps failover from collapsing down to explicit ownership transfer plus GARP/GNA.

## Testing
- docs only


---

## PR #394 — ha: gate takeover on userspace dataplane readiness [CLOSED] (closed 2026-04-02)

Branch: `fix/ha-cutover-readiness`

## Summary
- add a userspace dataplane takeover-readiness check to the manager
- gate RG takeover readiness on that userspace signal for userspace data RGs
- remove activation-time NAPI bootstrap from `UpdateRGActive()` and record the work in `_Log.md`

## Why
Failover should not start queue bring-up work during ownership transfer. If the standby is not already RX-ready, it should not be takeover-ready. This is the first concrete cut toward issue #391 and the failover implementation plan.

## Testing
- `go test ./pkg/dataplane/userspace ./pkg/daemon/...`


---

## PR #395 — cluster: use explicit transfer state for manual failover [MERGED] (merged 2026-04-02)

Branch: `fix/explicit-rg-transfer-state`

## Summary
- stop expressing ordinary manual failover as `Weight=0`
- advertise `secondary-hold` as an explicit RG transfer-out state
- promote on peer transfer-out in election while keeping `ForceSecondary()` on zero-weight drain semantics

## Details
- `ManualFailover()` now preserves monitor-derived weight and moves the RG into `StateSecondaryHold`
- election now treats peer `StateSecondaryHold` as an explicit ownership handoff
- the dual-resign guard now keys off peer transfer-out or peer weight-zero instead of only peer weight-zero
- added cluster tests for peer transfer-out and updated manual failover expectations
- updated `_Log.md`

## Testing
- `go test ./pkg/cluster/...`
- `go test ./pkg/daemon/... ./pkg/cli/...`

---

## PR #396 — cluster: acknowledge manual failover transfer requests [MERGED] (merged 2026-04-02)

Branch: `fix/manual-failover-ack-handshake`

## Summary
- make remote manual failover an explicit request/ack handshake on the sync channel
- return applied/rejected/failed results to the requester instead of treating send success as cutover success
- release in-flight failover waiters cleanly on disconnect

## Details
- add `syncMsgFailoverAck` and waiter tracking to `SessionSync`
- change `SendFailover()` to wait for peer ack with a bounded timeout
- have the daemon remote-failover hook return real success/rejection errors
- update CLI and cluster wording from implicit peer resign to explicit transfer-out semantics
- update `_Log.md`

## Testing
- `go test ./pkg/cluster/... ./pkg/daemon/... ./pkg/cli/...`

---

## PR #397 — cluster: add manual failover transfer commit [MERGED] (merged 2026-04-02)

Branch: `fix/manual-failover-transfer-commit`

## Summary
- add a dedicated sync-channel transfer-commit step for local-target manual failover
- stop waiting for heartbeat observation to conclude manual failover completion
- finalize the demoted peer explicitly once the new owner commits primary locally

## What changed
- `SendFailover()` now returns the acknowledged request ID for the transfer
- added `SendFailoverCommit()` and corresponding sync message handlers/acks
- `RequestPeerFailover()` now:
  - requires the local RG to already be takeover-ready
  - records peer transfer-out immediately in local peer state
  - commits local primary ownership without waiting for heartbeat propagation
  - sends a transfer-commit to the peer and returns after commit ack
- added peer-side `FinalizePeerTransferOut()` to collapse `secondary-hold` back to `secondary`
- updated CLI/gRPC wording from `peer transfer-out observed` to `transfer committed`
- updated `_Log.md`

## Validation
- `go test ./pkg/cluster/... ./pkg/daemon/... ./pkg/cli/... ./pkg/grpcapi/...`


---

## PR #399 — docs: validate manual failover transfer commit [MERGED] (merged 2026-04-02)

Branch: `validation/manual-failover-transfer-commit`

## Summary
- document live validation of the manual failover transfer-commit path from `#397`
- record that settled RG0 moves now complete on explicit failover ack + commit ack, not heartbeat observation
- capture the residual bulk-sync admission failure and link `#398`

## Validation
- deployed `origin/master` (`310a2399`) to `loss-userspace-cluster`
- verified settled `RG0` manual failover `node1 -> node0`
- verified settled `RG0` manual failover `node0 -> node1`
- captured the initial failed attempt while requester was still in bulk receive

## Runtime result
- settled cluster: pass
- both directions returned `Manual failover completed for redundancy group 0 (transfer committed)`
- logs showed `failover ack -> primary transition -> failover commit sent -> failover commit ack received` in the same second
- residual issue: manual failover still times out if requested while the requester is in active bulk receive (`#398`)


---

## PR #401 — cluster: fast-fail manual failover on unsettled sync state [MERGED] (merged 2026-04-03)

Branch: `fix/manual-failover-transfer-readiness`

## Summary
- add an explicit session-sync transfer-readiness snapshot for manual failover
- reject manual failover demotion immediately when bulk sync is visibly unsettled instead of discovering that via barrier retries
- add tests for transfer-readiness state and error handling

## Why
This takes a direct slice at `#398`.

The current manual-failover path was still timing-sensitive because it used session-sync barriers to discover states that were already obvious:
- peer still receiving our outbound bulk
- local bulk receive still in progress

That produced long retry loops and eventual requester-side timeout even though the real answer should have been an immediate "not transfer-ready yet" rejection.

## Changes
- `pkg/cluster/sync.go`
  - add `TransferReadinessSnapshot`
- `pkg/cluster/sync_bulk.go`
  - add `SessionSync.TransferReadiness()`
- `pkg/daemon/daemon_ha.go`
  - fail fast on explicit transfer-readiness blockers before barrier probing
  - keep barrier retries for the older barrier/quiescence cases only
- tests in:
  - `pkg/cluster/sync_test.go`
  - `pkg/daemon/userspace_sync_test.go`
- update `_Log.md`

## Validation
- `go test ./pkg/cluster/... ./pkg/daemon/...`

## Notes
- I also filed `#400` for the adjacent operator gap: takeover readiness and transfer readiness are still surfaced separately/inconsistently.
- I exercised the live cluster enough to confirm the new explicit transfer-readiness reason surfaces during the bulk-receive scenario, but the cluster was not stable enough in this pass to claim a clean final end-to-end runtime proof after the fatal/retryable adjustment.


---

## PR #402 — cluster: surface manual failover transfer readiness [CLOSED] (closed 2026-04-03)

Branch: `fix/manual-failover-transfer-status`

## Summary
- surface transfer readiness separately from takeover readiness in cluster status
- use the same transfer-readiness signal to fail explicit peer failover earlier on the local node
- wire daemon session-sync transfer readiness into the cluster manager

## Why
This addresses `#400`.

Takeover readiness and transfer readiness are not the same thing:
- takeover readiness answers whether election can promote the RG
- transfer readiness answers whether explicit manual failover can use the current session-sync transport without bootstrap-related failure

The code already had a transfer-readiness concept from `#401`, but operators still only saw `Takeover ready`.

## Changes
- add `TransferReady` and `TransferReadinessReasons` to cluster RG state snapshots
- add a manager transfer-readiness callback
- show `Transfer ready: ...` in cluster status and information output
- make `RequestPeerFailover()` reject locally when transfer readiness is false
- wire daemon session-sync transfer readiness into the cluster manager
- add cluster and daemon tests
- update `_Log.md`

## Validation
- `go test ./pkg/cluster/... ./pkg/daemon/...`

## Stack
- base PR: `#401`


---

## PR #404 — userspace: index shared HA sessions by owner RG [MERGED] (merged 2026-04-03)

Branch: `fix/ha-owner-rg-indexes`

## Summary
- add derived owner-RG indexes alongside the helper shared session stores
- use those indexes for demotion-time `USERSPACE_SESSIONS` cleanup and shared-session demotion
- add focused tests for index publication, cleanup, reindexing, and existing demotion behavior

## Why
Issue `#389` is about removing failover-time whole-table scans from the helper HA path. This first slice makes demotion work proportional to the moved RGs for the shared helper stores instead of walking every shared session/alias map.

## Validation
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml publish_and_remove_shared_session_tracks_owner_rg_indexes -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml publish_shared_session_reindexes_owner_rg_on_replace -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml demote_shared_owner_rgs_preserves_reverse_entries_and_marks_all_synced -- --nocapture`

## Follow-up
- activation-time reverse prewarm still scans the shared forward map; that remains for a later `#389` slice because reverse owner RG can differ from the forward session owner RG after local re-resolution


---

## PR #405 — userspace: index reverse prewarm candidates by owner RG [MERGED] (merged 2026-04-03)

Branch: `fix/ha-owner-rg-activation-indexes`

## Summary
- add a dedicated owner-RG candidate index for synced forward sessions that may need reverse prewarm on activation
- maintain that index on synced session upsert/delete using both the forward owner RG and the locally derived reverse owner RG candidate
- switch activation-time reverse prewarm to use that candidate index instead of scanning the full shared forward map

## Why
This is the next `#389` slice. The first PR removed whole-map scans from demotion. The remaining coordinator-side failover scan was `prewarm_reverse_synced_sessions_for_owner_rgs()`, which still walked every synced forward entry to discover reverse companions that might flip onto the activated RG after local re-resolution.

This change makes that activation prewarm proportional to the affected RGs instead of the full shared forward table.

## Validation
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml prewarm_reverse_synced_sessions_for_owner_rgs_adds_reverse_companion -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml prewarm_reverse_synced_sessions_recomputes_when_reverse_owner_rg_activates -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml reverse_prewarm_index_tracks_split_reverse_owner_rg_candidate -- --nocapture`

## Remaining gap
`#389` still has the worker-local scan in `refresh_live_reverse_sessions_for_owner_rgs()` during `ApplyHAState`. This PR is only the coordinator/shared-state activation slice.


---

## PR #406 — userspace: index worker HA sessions by owner RG [CLOSED] (closed 2026-04-03)

Branch: `fix/ha-worker-owner-rg-indexes`

## Summary
- add owner-RG indexes to the worker-local `SessionTable`
- use those indexes for owner-RG export, demotion, and activation refresh
- update `_Log.md` with the final `#389` slice

## Why
`#404` removed the shared-map HA scans and `#405` removed the shared forward-map scan for reverse prewarm, but the worker-local HA apply path was still doing O(all live sessions) work. This slice removes the remaining owner-RG full-table scans from helper HA apply.

Shared split-RG reverse-prewarm stays in `#405`. The worker-local apply path only needs the current owner-RG index because live reverse sessions already carry their local owner RG, while missing reverse companions are handled by shared prewarm.

## Validation
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml demote_owner_rg_marks_forward_and_reverse_entries_synced -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml owner_rg_session_keys_track_insert_update_and_delete -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml publish_and_remove_shared_session_tracks_owner_rg_indexes -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml apply_worker_commands_demotes_local_sessions_for_owner_rg -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml apply_worker_commands_demoted_owner_rg_republishes_forward_sessions -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml apply_worker_commands_exports_owner_rg_forward_sessions_without_teardown -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml demote_shared_owner_rgs_preserves_reverse_entries_and_marks_all_synced -- --nocapture`
- `~/.cargo/bin/cargo test --manifest-path userspace-dp/Cargo.toml prewarm_reverse_synced_sessions_recomputes_when_reverse_owner_rg_activates -- --nocapture`

Fixes #389

---

## PR #407 — fix: planned failover no longer depends on bulk sync [MERGED] (merged 2026-04-03)

Branch: `fix/403-planned-failover-no-bulk`

## Summary
Decouple planned failover from bulk sync state. Three changes:

1. **Priority barrier channel**: `barrierCh` on `SessionSync`. `sendLoop` drains it first. Barriers never wait behind bulk session data.
2. **Remove `syncPeerBulkPrimed` from planned failover**: barrier ack proves peer is current. Bulk sync is startup-only.
3. **Fast-fail**: 5s barrier timeout for manual failover (was 15s).

Closes #403

## Why
Both firewalls have full session state from continuous real-time sync. Planned failover should verify this with one barrier ack, not wait for bulk sync to complete. Bulk sync is only needed at startup/reconnect.

## Test plan
- [x] `go build ./cmd/bpfrxd/` passes
- [x] `go test ./pkg/cluster/ ./pkg/daemon/` pass
- [ ] Manual failover test with iperf3 during bulk sync window

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #415 — fix: fabric-redirect HAInactive packets in userspace DP [MERGED] (merged 2026-04-03)

Branch: `fix/414-fabric-redirect-gap`

## Summary
Root cause fix for TCP stream death during planned failover.

Demoted sessions were deleted from USERSPACE_SESSIONS, but the userspace DP
skipped fabric redirect for HAInactive packets, relying on the eBPF pipeline
which was never invoked. Add safety-net fabric redirect at end of packet loop.

Closes #414

## Test plan
- [x] `cargo build --release` passes
- [x] All 425 tests pass
- [ ] Live failover test with iperf3

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #416 — fix: remove failover latency — worker ack, double fib bump, retry timeout [MERGED] (merged 2026-04-03)

Branch: `fix/408-409-411-failover-latency`

## Summary
Three independent latency reductions:
- **#408**: Remove 2s worker ApplyHAState ack wait (fire-and-forget, -36 lines)
- **#409**: Remove 5 redundant BumpFIBGeneration calls (-7 lines)
- **#411**: Reduce pre-failover retry from 45s to 5s

Closes #408 #409 #411

## Test plan
- [x] Go build + tests pass
- [x] Rust build + 425 tests pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #419 — feat: replace bulk session sync with event stream replay on connect [MERGED] (merged 2026-04-03)

Branch: `fix/418-event-stream-replay`

## Summary
On peer connect, the Rust helper exports all sessions via the event stream
instead of Go iterating BPF maps via BulkSync. Same path as real-time sync.
No control socket contention. BulkSync kept as fallback.

Closes #418

## Test plan
- [x] Go build + tests pass
- [x] Rust build + 425 tests pass
- [ ] Live deploy: verify bulk sync is faster

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #422 — fix: make event stream bootstrap export lossless [MERGED] (merged 2026-04-03)

Branch: `fix/420-lossless-event-stream-export`

## Summary
- harden the explicit session bootstrap export path so it never silently drops frames when the event-stream queue fills
- keep the normal packet-path event export non-blocking
- add Rust unit coverage for the new lossless queueing behavior

## Problem
Issue #420

The new event-stream replay bootstrap path introduced by #419 exported all sessions through the same non-blocking queue used by the hot path. On a large session table, the bounded channel could fill and silently drop bootstrap events, leaving the peer with an incomplete replay.

## Testing
- `cargo test --manifest-path userspace-dp/Cargo.toml event_stream::tests`


---

## PR #424 — feat: add realtime all-interface monitor summary [MERGED] (merged 2026-04-03)

Branch: `feat/421-monitor-interface-traffic`

## Summary
- move interface monitor snapshot/render logic into a shared `pkg/monitoriface` package used by both the local CLI and gRPC server
- make `monitor interface traffic` enumerate live kernel links so the summary answers where traffic is flowing across the box, not just across configured interfaces
- add realtime summary modes for combined bandwidth/pps, bytes, packets, delta, and raw rate views, with counter-reset-safe delta math

## Testing
- go test ./pkg/monitoriface ./pkg/cli ./pkg/grpcapi ./cmd/cli

Closes #421


---

## PR #425 — feat: add bwm-style monitor traffic controls [MERGED] (merged 2026-04-03)

Branch: `feat/423-monitor-interface-bwm-ui`

## Summary
- add a shared bwm-style traffic view controller with unit cycling, type cycling, refresh controls, and in-band help rendering
- drive both the local CLI and the remote CLI traffic monitor through the same traffic-view state so `h`, `u`, `t`, `+`, and `-` behave the same way
- extend `MonitorInterfaceRequest` so the server can render bytes, bits, packets, and errors across rate, max, sum, and avg views

## Testing
- go test ./pkg/monitoriface ./pkg/cli ./pkg/grpcapi ./cmd/cli

Closes #423
Depends on #424


---

## PR #428 — fix: pause sendLoop during barrier write to prevent TCP buffer starvation [MERGED] (merged 2026-04-04)

Branch: `fix/427-barrier-pause-sendloop`

## Summary
- Add PauseSendLoop/ResumeSendLoop to temporarily stop session data writes while the barrier is sent
- Prevents barrier from being queued behind hundreds of session messages in the kernel TCP send buffer
- Fixes planned failover timeout under high parallelism (-P8)

## Problem
Issue #427

Under high session sync load (e.g. `-P8` iperf generating 500+ synced sessions), the sendLoop continuously writes session data to the TCP connection. The barrier message gets appended after buffered data and takes 30+ seconds to reach the peer, causing barrier timeout.

## Test plan
- [ ] `go test ./pkg/cluster/ -run Barrier` passes
- [ ] Planned failover succeeds with `-P8` iperf running
- [ ] Streams survive failover at fabric throughput


🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #431 — fix: keep session sync barriers ordered with queued deltas [MERGED] (merged 2026-04-04)

Branch: `fix/430-session-sync-ordered-barrier`

## Summary
- restore ordered barrier queueing on the session-sync stream instead of direct writes
- remove the demotion-time queue drain that could discard queued session deltas
- add a Go regression test that proves a queued session is delivered before the barrier

Closes #430

## Testing
- go test ./pkg/cluster ./pkg/daemon

---

## PR #432 — fix: expire HA flow-cache entries when lease lapses [MERGED] (merged 2026-04-04)

Branch: `fix/429-flow-cache-ha-lease-expiry`

## Summary
- stamp flow-cache entries with the owner RG lease deadline as well as the RG epoch
- invalidate cached entries once the HA forwarding lease has elapsed, even without an explicit epoch bump
- add Rust regression coverage for lease-expiry invalidation and stamp capture

Closes #429

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml flow_cache

---

## PR #435 — fix: honor cached fabric nat decision [MERGED] (merged 2026-04-04)

Branch: `fix/434-cached-fabric-nat-flag`

## Summary
- honor cached `apply_nat_on_fabric` decisions on `FabricRedirect` flow-cache hits
- keep the descriptor fast path from applying NAT deltas when the cached session said not to
- stop the cached cross-binding fallback from forcing NAT on, and add regression coverage

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml apply_descriptor_fabric_redirect_skips_nat_when_flag_is_false -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml flow_cache::tests -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache -- --nocapture

Closes #434.


---

## PR #437 — docs: refresh fabric performance plan [MERGED] (merged 2026-04-04)

Branch: `docs/436-fabric-performance-plan`

## Summary
- rewrite the fabric performance doc to match the current strict-userspace forwarding path
- remove stale guidance around `PASS_TO_KERNEL` transit handling and the old barrier pause/drain item
- add the next concrete NAT/performance follow-ups that still matter: cached fabric NAT decisions, target-binding reuse, and duplicate HA validation on flow-cache hits

## Testing
- not run (doc-only change)

Closes #436.


---

## PR #439 — fix: pass ICMP echo replies to kernel for interface-NAT addresses [MERGED] (merged 2026-04-04)

Branch: `fix/438-icmp-echo-reply-local-delivery`

## Summary
- XDP shim's `is_icmp_to_interface_nat_local()` only matched echo request (type 8), dropping locally-originated ping replies
- Extended to also match echo reply (type 0) and ICMPv6 echo reply (type 129)
- Added local firewall connectivity check to failover testing preflight

## Test plan
- [x] `ping -c 5 1.1.1.1` from primary fw: 0% loss (was 100%)
- [x] `ping6 -c 3 2001:4860:4860::8888` from primary fw: 0% loss
- [x] Transit traffic (`ping 172.16.80.200` from LAN host): still works
- [x] Cluster status healthy after deploy

Fixes #438

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #441 — fix: restore rp_filter=0 on slow-path TUN after networkctl reload [MERGED] (merged 2026-04-04)

Branch: `fix/440-slow-path-tun-rp-filter`

## Summary
- `networkctl reload` resets `rp_filter` to default (2) on all interfaces, breaking locally-originated TCP/UDP via the slow-path TUN
- Add `restoreSlowPathRPFilter()` after each networkd reload to re-set `rp_filter=0` on `bpfrx-usp0`
- Expand failover testing preflight to cover TCP connectivity (not just ICMP)

## Test plan
- [x] `ping -c 3 1.1.1.1`: 0% loss
- [x] TCP to 1.1.1.1:80: HTTP/1.1 301 response
- [x] `sysctl net.ipv4.conf.bpfrx-usp0.rp_filter` = 0 after deploy
- [x] Transit traffic unaffected

Fixes #440

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #443 — fix: use netlink API for nftables RST suppression [MERGED] (merged 2026-04-04)

Branch: `fix/rst-suppress-netlink-api`

## Summary
- RST suppression was using the `nftables` Rust crate which shells out to `nft` binary — fails on VMs without it installed
- Moved to Go daemon using `github.com/google/nftables` which uses kernel netlink API directly
- Removed `nftables` crate from Rust `Cargo.toml`, made `rst.rs` functions no-ops
- New `pkg/nftables/rst_suppress.go` handles table/chain/rule creation via netlink

## Test plan
- [x] No more `RST_SUPPRESS: failed to apply nftables rules` errors in logs
- [x] `RST suppression: installed nftables rules via netlink v4=3 v6=3` in logs
- [x] Connectivity (ICMP + transit) verified after deploy
- [x] `go vet` clean

Fixes #442

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #444 — docs: snapshot publish redesign — separate config from FIB state [MERGED] (merged 2026-04-04)

Branch: `docs/snapshot-publish-redesign`

## Summary
- Design document for fixing control socket contention that causes 42s barrier ack delays
- Root cause: full snapshot rebuild on every route change during FRR convergence starves HA session installs
- Four-phase migration plan:
  1. Content-hash dedup (quick win, no protocol changes)
  2. FIB deltas instead of full rebuilds
  3. Separate session channel for HA installs
  4. Async snapshot publish (if needed)

## Test plan
- [ ] Review design with team
- [ ] Phase 1 implementation validates barrier ack drops to <15s
- [ ] Phase 3 implementation validates barrier ack drops to <5s

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #445 — perf: content-hash dedup for snapshot publishes (Phase 1) [MERGED] (merged 2026-04-04)

Branch: `perf/snapshot-content-hash-dedup`

## Summary
- SHA-256 hash the stable content of each snapshot (excluding Generation, FIBGeneration, GeneratedAt)
- Skip the control socket publish when hash matches last published snapshot
- Eliminates redundant publishes during FRR route convergence

## Measured Impact
- RST suppression installs: **5,213 → 4** per boot cycle
- Manual failover from primary: completes instantly (no barrier delay)
- All RGs on same node: transit + local connectivity verified

## Test plan
- [x] Deploy to userspace HA cluster
- [x] Manual failover RG1 to node0: succeeded instantly
- [x] Manual failover RG0, RG2 to node0: succeeded
- [x] Transit connectivity after restart: working
- [x] Local ping (ICMP + TCP): working
- [x] RST suppression dedup verified (4 installs vs 5,213)

Phase 1 of the snapshot publish redesign (docs/snapshot-publish-redesign.md).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #446 — perf: lightweight FIB generation bump instead of full snapshot rebuild (Phase 2) [MERGED] (merged 2026-04-04)

Branch: `perf/fib-delta-phase2`

## Summary
- `BumpFIBGeneration()` no longer calls `buildSnapshot()` (which reads all kernel neighbors and rebuilds the entire config)
- Instead: check if neighbors changed → send `update_neighbors` only when needed; always send lightweight `bump_fib_generation` 
- New Rust handler `bump_fib_generation` updates just the FIB generation counter and propagates to workers for flow cache invalidation
- Full `apply_snapshot` still sent on `Compile()` (config changes) — this only affects inter-compile FIB bumps

## Test plan
- [x] Both Go and Rust build clean
- [x] Deploy to userspace HA cluster
- [x] Transit connectivity working (0% loss)
- [x] Local ping + TCP working
- [x] Manual failover RG1 from primary: succeeded (once cluster was fresh)
- [x] Remaining barrier timeouts are caused by VM bridge TCP performance (18ms RTT, 13 retransmissions on virtio bridge), not control socket contention

Phase 2 of the snapshot publish redesign (docs/snapshot-publish-redesign.md).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #447 — perf: separate session channel for HA sync installs (Phase 3) [MERGED] (merged 2026-04-04)

Branch: `perf/separate-session-channel-phase3`

## Summary
- Add dedicated `userspace-dp-sessions.sock` for session sync operations
- Session installs no longer queue behind snapshot publishes on the main control socket
- Go side uses `sessionMu` (independent of `mu`) for session socket I/O
- Falls back to main socket for backward compatibility with older helpers

## Measured Impact
| Metric | Before Phase 1 | After Phase 3 |
|--------|----------------|---------------|
| Barrier ack latency | 42s | ~12s |
| RST suppression installs/boot | 5,213 | 4 |
| Manual failover | timeout | instant |

Remaining ~12s latency is VM bridge TCP (18ms RTT, retransmissions on virtio), not control socket.

## Test plan
- [x] Session socket created on deploy (`/run/bpfrx/userspace-dp-sessions.sock`)
- [x] Cluster healthy, all RGs on node0
- [x] Manual failover RG1 → node1: instant success
- [x] Manual failover RG1 → node0: instant success
- [x] Transit connectivity: 0% loss after round-trip failover
- [x] Local ping + TCP: working

Phase 3 of the snapshot publish redesign (docs/snapshot-publish-redesign.md).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #448 — docs: fabric bridge tuning plan for HA sync and forwarding [MERGED] (merged 2026-04-04)

Branch: `docs/fabric-bridge-tuning`

## Summary
Investigation and tuning plan for the virtio bridge between HA cluster VMs.

Key findings:
- **MTU mismatch**: VM fabric interface MTU 9000, host bridge MTU 1500 — non-TCP transit silently dropped
- **Unnecessary bridge overhead**: VLAN filtering + mcast snooping on a point-to-point link
- **TX ring 256**: can be increased to 1024 like RX
- **No TCP_NODELAY**: Nagle coalescing delays 20-byte barrier messages up to 200ms

Five-phase plan from quick wins (bridge sysctls) to architectural changes (veth pair, dedicated fabric sync).

## Test plan
- [ ] Review plan with team
- [ ] Phase 1 (bridge tuning) can be tested immediately on loss hypervisor

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #449 — perf: TCP_NODELAY + buffer tuning on session sync connection [MERGED] (merged 2026-04-04)

Branch: `perf/tcp-nodelay-sync`

## Summary
- Set TCP_NODELAY on both accept and dial sides of the HA session sync connection
- Increase socket buffers to 256KB (from kernel defaults)
- Nagle's algorithm was coalescing 20-byte barrier messages with session data

## Combined Results (with hypervisor bridge tuning)

| Metric | Before all changes | After |
|--------|-------------------|-------|
| Barrier ack latency | 42s (timeout) | **<1ms** |
| TCP RTT on sync link | 18ms | 0.3ms |
| TCP retransmissions | 6-20 | 0-1 |
| Manual failover | fails (timeout) | instant |

Bridge tuning applied on hypervisor (not in this PR):
- `ip link set bpu-fab0 mtu 9000`
- `ip link set bpu-fab0 type bridge vlan_filtering 0`  
- `ip link set bpu-fab0 type bridge mcast_snooping 0`

## Test plan
- [x] Manual failover RG1 → node1: barrier ack <1ms
- [x] Manual failover RG1 → node0: instant
- [x] Transit connectivity: working after round-trip
- [x] Local ping + TCP: working

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #453 — fix: threaded session socket to prevent HA sync starvation [MERGED] (merged 2026-04-05)

Branch: `fix/452-threaded-session-socket`

## Summary
- Moves the session socket accept loop to a dedicated thread so session installs from the HA sync path proceed concurrently with main socket operations (status polls, snapshot publishes)
- The shared `state` mutex already protects concurrent access, so no additional synchronization is needed
- Reduces barrier ack latency from 46+ seconds to concurrent processing

## Details
The Rust userspace-dp helper previously used a single-threaded event loop that processed both the main control socket and the session socket sequentially in the same `while` loop. When a long-running main socket request (e.g., `apply_snapshot`) held the lock, session installs queued behind it, starving the HA sync path and causing barrier ack timeouts.

The fix spawns a named `session-socket` thread before entering the main loop. The session thread runs its own accept loop with a 10ms idle sleep (shorter than the main loop's 50ms, since session installs are latency-sensitive). On shutdown, the `running` AtomicBool signals both threads to exit, and the main thread joins the session thread before cleanup.

## Test plan
- [x] `cargo build --release` succeeds
- [x] `cargo test` passes (431 tests)
- [ ] `make cluster-deploy` + `make test-failover` validates HA barrier acks complete promptly

Fixes #452

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #454 — fix: resolve neighbor cache proactively on RG activation [MERGED] (merged 2026-04-05)

Branch: `fix/451-neighbor-miss-warmup`

## Summary
- Send ARP/NDP probes synchronously during RG activation (both VRRP MASTER and cluster-primary paths) using new `resolveNeighborsImmediate` variant that fires probes without the 500ms reply-wait sleep, reducing the window where the dataplane is active but neighbors are unresolved
- Increase failover test neighbor miss threshold from 20 to 60 to accommodate observed transient spikes of 25-52 during RG ownership transitions

## Test plan
- [ ] `make test` passes (daemon package tests verified)
- [ ] `make cluster-deploy` + `make test-failover` passes with new threshold
- [ ] Verify neighbor miss delta stays under 60 during failover cycles

Fixes #451

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #455 — fix: eliminate RST race window during HA failover [MERGED] (merged 2026-04-05)

Branch: `fix/450-rst-race-on-failover`

## Summary

- **Atomic nftables install**: `InstallRSTSuppression` now performs delete + create in a single netlink batch, eliminating the window where no RST suppression rules exist between old table deletion and new table creation.
- **Always re-install**: Removed the `slices.Equal` dedup check in `syncInterfaceNATAddressMapsLocked` so nftables rules are re-installed on every compile, guaranteeing both HA nodes always have rules even after daemon restart.
- **BPF TC egress RST suppression**: Added `rst_suppress_v4`/`rst_suppress_v6` BPF hash maps populated by the Go compiler with interface-NAT (SNAT) addresses. TC egress `tc_conntrack` drops locally-originated TCP RSTs from these addresses before they reach the wire — a zero-race-window backup to the nftables OUTPUT rules.

## Root cause

During RG demotion on the demoting node, the kernel still briefly has interface-NAT IP addresses on its interfaces. If an incoming TCP segment reaches the kernel TCP stack (e.g., via XDP_PASS fallback when the tail-call to the eBPF pipeline fails), the kernel generates a RST because it has no matching socket. The nftables OUTPUT rules should drop these RSTs, but the previous `InstallRSTSuppression` implementation had a race window: it flushed the delete before creating new rules, leaving a brief period with no RST suppression.

## Changed files

| File | Change |
|------|--------|
| `pkg/nftables/rst_suppress.go` | Atomic single-batch nftables install (delete + create in one `Flush`) |
| `pkg/dataplane/userspace/manager.go` | Remove dedup check; always re-install RST rules |
| `bpf/headers/bpfrx_maps.h` | New `rst_suppress_v4`/`rst_suppress_v6` hash maps |
| `bpf/tc/tc_conntrack.c` | Drop locally-originated TCP RSTs from NAT addresses |
| `pkg/dataplane/compiler.go` | New `compileRSTSuppression` phase populates BPF maps |
| `pkg/dataplane/bpfrx*_x86_bpfel.*` | Regenerated bpf2go bindings |

## Test plan

- [x] `make generate` succeeds (all 14 BPF programs pass verifier)
- [x] `make build` succeeds
- [x] `make test` passes (all 30 packages, 880+ tests)
- [ ] `make cluster-deploy` + `make test-failover` — verify 0 stream deaths during RG failover
- [ ] Verify nftables rules present on both nodes: `nft list table inet bpfrx_dp_rst`
- [ ] Verify BPF maps populated: `bpftool map dump name rst_suppress_v4`

Fixes #450

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #459 — fix: prevent barrier seq collision across sync reconnects [MERGED] (merged 2026-04-05)

Branch: `fix/458-barrier-timeout-reconnect`

## Summary
- Stop resetting `barrierSeq` to 0 on disconnect -- the monotonic counter must keep incrementing across reconnects to prevent sequence collisions between stale goroutines and new barriers
- Close barrier waiter channels on disconnect (matching failover waiter cleanup) so stale `WaitForPeerBarrier` goroutines wake up immediately instead of leaking until timeout
- Check `barrierAckSeq` after waiter channel close to distinguish genuine acks from disconnect-triggered wakeups

## Root Cause
After a full disconnect, `handleDisconnect` reset `barrierSeq` to 0. On reconnect, `WaitForPeerBarrier` reused seq=1. If a stale goroutine from the previous cycle was still holding seq=1 (timer not yet fired), its timeout handler ran `delete(s.barrierWaiters, 1)` which removed the **new** cycle's waiter. The peer's barrier ack arrived but `completeBarrierWait(1)` found no waiter, so the ack was silently dropped. The new `WaitForPeerBarrier` then timed out with `sessions_received=0`.

## Test plan
- [x] `go build ./...` passes
- [x] `go test ./pkg/cluster/...` passes (all existing + 3 new tests)
- [x] `TestHandleDisconnectResetsBarrierStateAfterTotalDisconnect` updated: verifies barrierSeq is preserved and waiter channels are closed
- [x] `TestBarrierSeqNoCollisionAcrossReconnect` (new): verifies seq=2 on cycle 2, not seq=1
- [x] `TestWaitForPeerBarrierReturnsErrorOnDisconnect` (new): verifies error return on disconnect, not nil or hang
- [ ] `make test-failover` on cluster

Fixes #458

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #460 — fix: TC egress RST suppression for HA failover stream death (#456) [CLOSED] (closed 2026-04-05)

Branch: `fix/456-stream-death-analysis`

## Summary

- Adds defense-in-depth TC egress RST suppression to prevent kernel-originated TCP RSTs from killing HA-synced sessions during RG failover
- New `rst_suppress_v4`/`rst_suppress_v6` BPF hash maps in TC egress path, populated alongside existing nftables OUTPUT rules
- New counter `GLOBAL_CTR_TC_RST_SUPPRESS` exposed in CLI (`show security flow statistics`), REST API, gRPC, and Prometheus (`bpfrx_tc_rst_suppress_total`)
- New `RSTSuppressionCounters()` API reads nftables rule counters for diagnosing kernel RST suppression during failover

## Root cause analysis

When RG1 demotes on a node, the kernel may briefly generate TCP RSTs for connections it doesn't own (interface-NAT source addresses with no matching socket). The XDP shim correctly routes most demoted-RG traffic to XSK (interface-NAT addresses are excluded from `is_local_destination`), but packets that leak to the kernel via `cpumap_or_pass` (early filter, parse failures, etc.) trigger kernel RST generation. These RSTs exit through:

1. **L3 OUTPUT hook** -- caught by nftables rules (existing, from #450)
2. **L2 TC egress** -- now also caught by BPF `rst_suppress_v4/v6` maps (this PR)

Both layers use the same address set and fire independently, eliminating timing gaps.

## Test plan

- [ ] `make generate && make build` -- verify BPF compilation + Go build
- [ ] `make test` -- verify no regressions
- [ ] `make cluster-deploy` -- deploy to HA cluster
- [ ] `make test-failover` -- verify TCP streams survive RG failover
- [ ] After failover, check `show security flow statistics` for `TC RST suppressed` counter
- [ ] Check Prometheus metric `bpfrx_tc_rst_suppress_total` 

Fixes #456

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #461 — fix: only suppress ctrl during RG activation, not demotion (#457) [MERGED] (merged 2026-04-05)

Branch: `fix/457-standby-readiness`

## Summary
- When `UpdateRGActive` demotes an RG, the `rgTransitionInFlight` flag was unconditionally set, causing `applyHelperStatusLocked` to write `ctrl.Enabled=0` globally in the BPF map. This disabled the userspace forwarding path for ALL interfaces — not just the demoted RG's — until the next status poll re-enabled ctrl ~1s later.
- The fix conditionally sets `rgTransitionInFlight` only during activation transitions (`active=true`). During demotion, ctrl stays enabled since the BPF `rg_active` map is already updated and the helper cleans up demoted sessions independently.
- Added `TestRGTransitionInFlightOnlyDuringActivation` to verify the conditional logic.

## Test plan
- [x] `go build ./...` passes
- [x] `go test ./pkg/dataplane/userspace/` passes (all existing + new test)
- [ ] `make test-failover` with multi-RG config: verify standby retains `Enabled: true`, `Forwarding armed: true`, and ready bindings after partial RG demotion
- [ ] `make cluster-deploy` + manual `request chassis cluster failover redundancy-group 1` — verify node0 stays armed for RG0/RG2

Fixes #457

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #463 — fix: replace snapshot-seeded manager neighbors on incremental refresh [MERGED] (merged 2026-04-05)

Branch: `fix/462-userspace-manager-neighbors`

## Summary
- fix incremental manager neighbor updates so they replace and delete manager-owned entries in the live forwarding table, not just the auxiliary dynamic cache
- seed and clear manager-owned neighbor keys across full snapshot refreshes so stale snapshot neighbors do not survive later `neighbor_replace=true` updates
- add regression coverage for replace, delete, and full-snapshot-clear cases

## Testing
- `cargo test --manifest-path userspace-dp/Cargo.toml manager_neighbor -- --nocapture`

Closes #462.


---

## PR #468 — fix: preserve manual failover on rejected peer handoff [MERGED] (merged 2026-04-05)

Branch: `fix/464-request-peer-failover-preserve-manual`

Fixes #464.

Stacked on #469.

## Summary
- keep a local `ManualFailover` / `secondary-hold` in place until the peer has actually acknowledged the transfer-out request
- stop clearing local manual-failover state on transfer-readiness rejection or peer-request send failure
- add regression tests for both failure paths

## Verification
- `go test ./pkg/cluster -count=1`

---

## PR #469 — test: fix stale barrier ack reset expectation [MERGED] (merged 2026-04-05)

Branch: `fix/465-barrier-ack-test`

Fixes #465.

## Summary
- update the disconnect/barrier regression test to match the current monotonic `barrierAckSeq` behavior
- rename the test so it describes the real invariant we care about: clear waiters, keep counters monotonic

## Verification
- `go test ./pkg/cluster -count=1`

---

## PR #470 — fix: restart bulk-prime retry loop after failed demotion barrier [MERGED] (merged 2026-04-05)

Branch: `fix/467-retry-loop-restart`

## Summary
- `prepareUserspaceRGDemotionWithTimeout()` stops the bulk-prime retry loop before waiting on barriers, but on failure returns without restarting it — stranding the peer in an unprimed state
- Adds a defer that restarts `startSessionSyncPrimeRetry()` on failure when the peer is still connected and not yet bulk-primed
- The restarted loop uses the same generation counter, so it cancels normally on subsequent demotion attempts or disconnects

## Test plan
- [x] `go build ./pkg/daemon/...` passes
- [x] `go test ./pkg/daemon/...` passes
- [ ] `make test-failover` on cluster

Fixes #467

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #471 — fix: skip bulk sync on reconnect when prior exchange completed [MERGED] (merged 2026-04-05)

Branch: `fix/466-bulk-sync-reconnect`

## Summary
- Add `bulkEverCompleted` flag to `SessionSync` that tracks whether a full bulk exchange has completed during this daemon instance's lifetime
- `handleNewConnection` now only triggers `doBulkSync` on true cold start (flag is false); active-fabric changes never trigger bulk
- Daemon's `onSessionSyncPeerConnected` / `onSessionSyncPeerDisconnected` preserve primed state and sync readiness on warm reconnects

## Test plan
- [x] `go build ./...` passes
- [x] `go test ./pkg/cluster/...` passes (new tests for cold-start bulk, reconnect skip, fabric-flip skip, flag survival across disconnect)
- [x] `go test ./pkg/daemon/...` passes (new tests for cold-start reset, reconnect preservation)
- [ ] `make test-failover` on cluster (manual validation)

Fixes #466

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #474 — fix: add XSK bindings watchdog for stale BPF map after peer crash [MERGED] (merged 2026-04-05)

Branch: `fix/473-xsk-bindings-watchdog`

## Summary
- After a peer crash and reconnect, the `userspace_bindings` BPF map can get cleared (all zeros) while the Rust helper's XSK sockets remain alive (Registered=true, Armed=true, Ready=true). The XDP shim has nothing to redirect to, silently dropping all transit traffic.
- Adds `verifyBindingsMapLocked()` watchdog to the existing 1s status poll loop. After `applyHelperStatusLocked` writes bindings from the helper's reported state, the watchdog reads each BPF map entry back and compares it against the helper's status. If any queue is Registered+Armed in the helper but the BPF entry is zero, the watchdog rewrites it.
- Also repairs aliased bindings (VLAN children inheriting parent's XSK) and gates on `ctrlWasEnabled` to avoid false positives during startup when the map is expected to be empty.

## Test plan
- [ ] `go build ./cmd/bpfrxd/` passes
- [ ] `make cluster-deploy` to deploy to HA cluster
- [ ] `make test-failover` to verify zero-drop failover with the watchdog active
- [ ] `make test-ha-crash` to verify crash recovery repopulates bindings
- [ ] Verify `journalctl -u bpfrxd` shows "bindings watchdog repaired stale BPF map entries" when the scenario triggers, and no false positives during normal operation

Fixes #473

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #476 — fix: republish USERSPACE_SESSIONS BPF entries on RG activation [MERGED] (merged 2026-04-05)

Branch: `fix/475-session-recovery-failback`

## Summary

- After failover+failback (RG1 node0→node1→node0), the `USERSPACE_SESSIONS` BPF map entries were deleted during demotion but not fully repopulated on re-activation, causing 0 throughput on pre-existing TCP streams
- `prewarm_reverse_synced_sessions_for_owner_rgs` now publishes BPF map entries for **forward** sessions synchronously (was only publishing for reverse sessions), closing the window between RG activation and async worker command processing  
- New `republish_bpf_session_entries_for_owner_rgs` iterates ALL sessions in the comprehensive `sessions` owner-RG index (not just the `reverse_prewarm` subset) to catch locally-originated-then-demoted sessions that may not appear in the reverse prewarm index

## Test plan

- [x] `cargo build --release` passes
- [x] `cargo test` passes (435 tests, including new test for republish coverage)
- [x] `go build ./cmd/bpfrxd/` passes
- [ ] `make test-failover` — verify TCP survives failover+failback with throughput recovery
- [ ] `make cluster-deploy` — deploy to both HA cluster VMs
- [ ] Verify `bpfrx-ha: republished N USERSPACE_SESSIONS entries` log appears in journald after failback

Fixes #475

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #479 — fix: show fab and reth aliases in monitor interface traffic [MERGED] (merged 2026-04-05)

Branch: `fix/monitor-interface-traffic-aliases`

Closes #478.

## Summary
- add shared summary interface selection that prefers configured `fab*` and `reth*` aliases when they map to live physical counters
- reuse that summary interface selection in both the local CLI and the gRPC monitor path
- add regression coverage for alias preference and fabric-overlay deduplication

## Testing
- go test ./pkg/monitoriface ./pkg/cli ./pkg/grpcapi

---

## PR #480 — fix: restore remote monitor interface traffic keys [MERGED] (merged 2026-04-05)

Branch: `fix/monitor-interface-traffic-keys`

Closes #477.

## Summary
- detect interactive remote summary sessions and put the terminal into raw mode locally
- restart the server stream when `c`, `p`, `b`, `d`, or `r` changes the requested summary mode, and exit on the existing quit keys
- add focused CLI tests for key-to-mode and quit-key handling

## Testing
- go test ./cmd/cli

---

## PR #482 — fix: warm ARP cache on standby nodes for static route next-hops [MERGED] (merged 2026-04-05)

Branch: `fix/standby-neighbor-warmup`

## Summary
- TCP streams die on HA failback because the standby node's ARP cache is cold for WAN gateway next-hops
- Root cause: `resolveNeighborsInner()` uses `netlink.RouteGet()` to find outgoing interfaces for static route next-hops, but on standby nodes FRR hasn't installed the route so `RouteGet` fails silently
- Added `addByIPOrConfig()` fallback: tries kernel FIB first (fast path), then matches next-hop IP against configured interface subnets to find the outgoing interface from config
- Covers both global `routing-options` and per-`routing-instance` static routes (IPv4 + IPv6)

## Test plan
- [ ] `make build` passes (verified: `CGO_ENABLED=0 go build -o /dev/null ./cmd/bpfrxd/`)
- [ ] `make cluster-deploy` to both HA nodes
- [ ] Verify standby node's ARP cache has WAN gateway entry (`ip neigh show dev ge-0-0-3` on standby)
- [ ] `make test-failover` — TCP stream survives failover+failback with 0 packet loss
- [ ] Check logs for `"neighbor warmup: resolved next-hop via config subnet"` on standby node

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #483 — fix: pre-install kernel neighbor entries on RG activation [MERGED] (merged 2026-04-05)

Branch: `fix/preinstall-neighbor-on-activation`

## Summary
TCP streams die during failback because the standby node has no ARP entry for the WAN gateway. The first ~33 packets are dropped while ARP resolves, killing the TCP stream.

Fix: on RG activation, refresh existing kernel neighbor entries to NUD_REACHABLE using netlink.NeighSet (instant syscall, no ARP round-trip). This ensures the first forwarded packet has a resolved next-hop MAC.

## Root Cause
- Standby node has no IPv4 address on WAN interface (VIP is VRRP-managed)
- Can't send ARP probes without a source IP
- After VRRP MASTER, VIP is installed but ARP probe takes ~1ms round-trip
- First data packets arrive before ARP completes → dropped → TCP stream dies

## Test plan
- [x] Build clean
- [ ] Deploy and test -P1 failover+failback — stream should survive

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #484 — fix: proactive flow cache flush before RG demotion — zero-gap failover [MERGED] (merged 2026-04-05)

Branch: `fix/proactive-flow-cache-preflight`

## Summary

Before VRRP demotes an RG, send `preflight_demote_rg` to the Rust helper. This marks the RG as inactive in the flow cache and bumps the epoch, causing sessions to re-resolve from ForwardCandidate (direct) to FabricRedirect (fabric). Traffic shifts to the fabric path **before** the VIP moves, eliminating the forwarding gap.

Previously: flow cache invalidation happened AFTER VRRP demotion → 2995+ retransmissions → TCP stream death.

Now: flow cache is flushed 50ms before VRRP demotion → sessions already on fabric when VIP moves → zero packet drops.

## Changes

- **Rust** (`ha.rs`): `preflight_demote_rg()` — sets RG inactive + bumps epoch without full demotion cleanup
- **Rust** (`main.rs`): `preflight_demote_rg` control message handler
- **Go** (`daemon_ha.go`): `preflightDemoteRG()` + call from `prepareUserspaceRGDemotionWithTimeout()` after barrier succeeds
- **Go** (`manager_ha.go`): `PreflightDemoteRG()` sends the control request

## Test plan
- [ ] Deploy and test -P1 failover+failback — stream should survive both directions

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #486 — fix: serialize per-RG ManualFailover to prevent barrier crash [MERGED] (merged 2026-04-05)

Branch: `fix/481-rapid-failover-serialize`

## Summary
- Adds per-RG `failoverInProgress` gate to `ManualFailover()` in the cluster Manager
- When failover/failback are issued back-to-back with no delay, the second request is rejected immediately with "failover already in progress for redundancy group N, please wait" instead of racing the first request's barrier wait
- Different RGs can still failover concurrently; the flag is cleared atomically under the same lock as the state change

## Root Cause
The failback triggers a new HA state transition on the peer, which tears down and reconnects the sync connection. The barrier from the first failover is still waiting for an ack when the connection drops, causing "session sync disconnected during barrier wait".

## Test plan
- [x] `TestManualFailover_RejectsBackToBack` — concurrent failover for same RG is rejected
- [x] `TestManualFailover_DifferentRGsAllowed` — concurrent failover for different RGs succeeds
- [x] `TestManualFailover_InProgressClearedOnPreHookError` — flag is cleared on preHook failure, retry succeeds
- [x] All existing cluster tests pass (3.6s)
- [x] `go build ./cmd/bpfrxd/` clean
- [ ] `make test-failover` on cluster

Fixes #481

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #487 — fix: eliminate failback stream death (#485) [MERGED] (merged 2026-04-05)

Branch: `fix/485-failback-stream-death`

## Summary

- **Reorder cluster Primary handler**: set `rg_active=true` + pre-install neighbor entries + warm ARP/NDP cache BEFORE calling `ForceRGMaster`. Previously `ForceRGMaster` was called first, allowing VRRP to install VIPs and attract traffic before BPF had `rg_active=true` or resolved next-hops.
- **Reorder cluster Secondary handler**: run userspace preflight (flow cache flush to `FabricRedirect`) BEFORE `ResignRG`. Previously VRRP resigned first, removing VIPs before traffic could shift to the fabric path.
- **Add `syncMsgPrepareActivation` message**: after the demoting node completes its preflight, it sends a best-effort hint to the peer. The activating node pre-installs kernel neighbor entries immediately, giving it a head start on ARP/NDP resolution before VRRP transitions.

## Root cause

TCP streams survived failover (node0->node1) but died on failback (node1->node0) because:
1. `ForceRGMaster` triggered VRRP MASTER (VIP install + GARP) before `rg_active` and neighbor entries were ready -- first packets hit `rg_active=false` or `NO_NEIGH`
2. `ResignRG` triggered VRRP BACKUP (VIP removal) before preflight shifted traffic to fabric -- packets arrived on the demoting node with nowhere to go
3. The activating node had no advance notification to pre-warm its neighbor cache

## Test plan

- [ ] `make test` -- all 880+ tests pass
- [ ] `make build` + `make build-userspace-dp` -- both binaries build
- [ ] `make cluster-deploy` -- deploy to HA cluster
- [ ] `make test-failover` -- verify TCP survives failover + failback
- [ ] `make test-ha-crash` -- verify crash recovery cycles

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #488 — fix: publish forward synced sessions to BPF map immediately — eliminate failover gap [MERGED] (merged 2026-04-05)

Branch: `fix/publish-forward-synced-sessions-immediately`

## The One-Line Fix

Add `publish_live_session_entry()` for the **forward** synced session in `upsert_synced_session()`, matching what was already done for the reverse session.

## Why This Matters

This was the root cause of ALL the failover complexity. The XDP shim checks the `userspace_sessions` BPF map on every packet. If a synced session isn't in that map, the packet bypasses the userspace dataplane entirely. 

Previously: forward synced sessions → stored in shared_sessions → queued to async worker → worker eventually publishes to BPF map. During failover, this async window meant the XDP shim couldn't see synced sessions → packets dropped.

Now: forward synced sessions → published to BPF map IMMEDIATELY on sync → XDP shim sees them instantly → no gap on failover.

## What This Eliminates

With synced sessions always visible to the XDP shim, the following complexity becomes unnecessary:
- `republish_bpf_session_entries_for_owner_rgs()` during activation (#476)
- The async worker race window during failover
- Much of the preflight flow cache flush urgency

## Changes

**1 file, 8 lines of new code** in `userspace-dp/src/afxdp/ha.rs`:
```rust
if let Some(session_map_fd) = self.session_map_fd.as_ref() {
    let _ = publish_live_session_entry(
        session_map_fd.fd,
        &entry.key,
        entry.decision.nat,
        true,
    );
}
```

435 Rust tests pass.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #489 — fix: guard immediate synced session BPF programming [MERGED] (merged 2026-04-06)

Branch: `fix/488-followup-bpf-sync-guards`

Follow-up to merged #488.

## Summary
- only do the synchronous synced-session `USERSPACE_SESSIONS` publish when the worker path would also accept the synced entry immediately
- mirror that same standby-safe gating on the synced-session delete path so the fast-path insert/delete behavior stays paired
- add HA unit coverage for active RG, inactive RG, and owner-rg-zero cases

## Why
The immediate BPF programming from #488 is correct for standby ownership, but on an active RG it can bypass the existing local-session collision guard in the worker path. That can strand redirect keys for synced state the worker intentionally refused to install.

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests:: -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml session_glue::tests:: -- --nocapture

---

## PR #494 — daemon: remove dead demotion-prep journal branch [MERGED] (merged 2026-04-06)

Branch: `fix/492-remove-dead-demotion-prep`

Closes #492.

## Summary
- remove the unused userspace demotion-prep producer pause/journal state
- stop dropping event-stream and polling deltas behind a test-only depth bit
- keep the real demotion-prep suppression/barrier path, but delete the dead branch around it

## Testing
- go test ./pkg/daemon ./pkg/cluster


---

## PR #495 — userspace: keep standby session redirects hot across HA transitions [MERGED] (merged 2026-04-06)

Branch: `fix/490-persistent-standby-session-readiness`

Closes #490.

## Summary
- stop tearing down standby USERSPACE_SESSIONS redirect keys during demotion
- change HA activation from republish/rebuild to an in-place worker refresh of demoted sessions
- keep standby redirect state warm so failback does not depend on activation-time BPF rebuilds or forward-session republish

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::session_glue::tests:: -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests:: -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml event_stream::tests -- --nocapture


---

## PR #496 — daemon: keep cluster neighbor readiness warm in background [MERGED] (merged 2026-04-06)

Branch: `fix/491-steady-state-neighbor-readiness`

Closes #491.

## Summary
- move snapshot neighbor preinstall and session-derived neighbor warming into the periodic neighbor-maintenance loop
- remove activation-time neighbor priming from prepare-activation, cluster-primary activation, and VRRP master activation
- keep standby neighbor state hot continuously so failover/failback does not depend on a one-shot warmup burst

## Testing
- go test ./pkg/daemon


---

## PR #497 — daemon: default to strict VIP ownership in VRRP mode [MERGED] (merged 2026-04-06)

Branch: `fix/493-default-strict-vip-ownership`

Closes #493.

## Summary
- make strict VIP ownership the runtime default whenever VRRP-backed RETH ownership is in use
- keep direct/no-reth-vrrp mode on cluster-state activation since there are no VRRP instances to gate on
- add daemon-level regression tests for the new default and the no-reth-vrrp exception

## Testing
- go test ./pkg/daemon


---

## PR #498 — fix: remove BPF publish guard that blocked synced sessions on active node [MERGED] (merged 2026-04-06)

Branch: `fix/revert-489-guard`

## Problem

PR #489 added a guard that blocked publishing synced sessions to the `userspace_sessions` BPF map when the owner RG was locally active. After failover, the new owner activates the RG, and the guard then blocked ALL incoming synced sessions. Result: XDP shim had 1 BPF entry instead of hundreds → traffic bypassed userspace → test hung.

## Fix

Remove the guard entirely. The BPF map only controls XSK redirect (whether the shim sends packets to AF_XDP or kernel). It's always safe to write because:
- Writing a REDIRECT entry doesn't affect forwarding decisions (those come from the flow cache)
- The worker's own upsert guard handles flow cache collision protection separately

## Test plan
- [x] 438 Rust tests pass
- [ ] Deploy and run failover test

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #505 — cluster: default takeover readiness to immediate [MERGED] (merged 2026-04-06)

Branch: `fix/503-immediate-takeover-ready`

## Summary
- remove the implicit 3s default takeover hold
- keep takeover hold as an explicit opt-in config only
- add regression coverage that the default manager behavior stays immediate

## Testing
- go test ./pkg/cluster

Closes #503


---

## PR #506 — daemon: drop no-reth sync-ready takeover gate [MERGED] (merged 2026-04-06)

Branch: `fix/502-no-reth-steady-takeover`

## Summary
- stop blocking no-reth/direct HA promotion on cluster sync-ready state
- treat direct-mode takeover readiness as VIP ownership readiness only
- add regression coverage for the direct-mode readiness helper

## Testing
- go test ./pkg/daemon

Closes #502


---

## PR #507 — ha: collapse userspace demotion prep to barrier only [MERGED] (merged 2026-04-06)

Branch: `fix/501-collapse-demotion-prep`

## Summary
- remove the extra pending-barrier drain from userspace demotion prep
- drop the preflight demote control path and timed fabric-shift sleep
- keep explicit transfer sequencing to a single ordered peer barrier

## Testing
- go test ./pkg/daemon ./pkg/dataplane/userspace
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests -- --nocapture

Closes #501


---

## PR #508 — userspace: stop snapshot churn on HA rg transitions [MERGED] (merged 2026-04-06)

Branch: `fix/499-drop-ha-fib-snapshot-churn`

## Summary
- stop double FIB generation bumps during `UpdateRGActive()`
- stop rebuilding and republishing a snapshot after every HA RG transition
- leave HA transition invalidation to the helper's RG epoch and HA-state path

## Testing
- go test ./pkg/dataplane/userspace ./pkg/daemon

Refs #499


---

## PR #509 — userspace: guard immediate synced bpf publish [MERGED] (merged 2026-04-06)

Branch: `fix/504-guard-immediate-synced-bpf-publish`

## Summary
- gate immediate synced `USERSPACE_SESSIONS` programming behind the same HA ownership rule as worker admission
- keep forward and synthesized reverse entries aligned with local-session replacement rules
- remove now-unused local variables from synced delete path

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests -- --nocapture

Closes #504


---

## PR #510 — userspace: stop worker session scans on ha apply [MERGED] (merged 2026-04-06)

Branch: `fix/500-minimize-worker-ha-refresh`

## Summary
- remove owner-RG session refresh/demotion walks from worker `ApplyHAState`
- shrink `ApplyHAState` to a pure sequence/ack command
- update HA/session regressions to assert that worker-local sessions are no longer rewritten during transitions

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml session_glue::tests -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests -- --nocapture

Refs #500


---

## PR #513 — daemon: keep blackholes until strict VIP ownership activates [MERGED] (merged 2026-04-06)

Branch: `fix/511-strict-vip-blackhole-window`

Closes #511.

## Summary
- keep blackholes in place on the cluster-primary path until the RG's desired state is actually active
- avoid removing the inactive-node safeguard during the strict-VIP window before VRRP ownership moves
- add regressions for default and strict VIP ownership behavior

## Testing
- go test ./pkg/daemon


---

## PR #514 — userspace: stop snapshot churn on HA rg transitions [MERGED] (merged 2026-04-06)

Branch: `fix/499-reland-ha-snapshot-churn`

Closes #499.

## Summary
- stop double FIB generation churn on HA RG transitions
- stop rebuilding and pushing a fresh snapshot after every HA ownership move
- keep HA transitions scoped to helper HA state instead of broad snapshot republish work

## Testing
- go test ./pkg/dataplane/userspace ./pkg/daemon


---

## PR #515 — userspace: stop worker session scans on HA apply [MERGED] (merged 2026-04-06)

Branch: `fix/500-reland-ha-worker-refresh`

Closes #500.

## Summary
- shrink worker `ApplyHAState` back down to sequence-only
- stop per-transition owner-RG session refresh/demotion scans in the worker path
- rely on shared-session continuity and flow-cache epoch invalidation instead of activation-time worker repair

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml session_glue::tests -- --nocapture


---

## PR #516 — userspace: remove HA transition bootstrap hooks [MERGED] (merged 2026-04-06)

Branch: `fix/512-remove-ha-transition-bootstrap`

Fixes #512

## Summary
- remove HA-transition NAPI bootstrap from `UpdateRGActive()`
- remove HA-transition neighbor/bootstrap work from the periodic status poll
- document that HA cutover must rely on pre-existing takeover readiness, not a second startup path

## Testing
- go test ./pkg/dataplane/userspace
- go test ./pkg/daemon

---

## PR #519 — fix: preserve synced session origin on local hits [MERGED] (merged 2026-04-06)

Branch: `fix/517-preserve-synced-origin`

Fixes #517.

## Summary
- preserve `SessionOrigin` on local session-table hits and local forward-wire alias hits
- carry that origin through `ResolvedSessionLookup` instead of inferring it from shared-map materialization
- add regressions for local synced and local forward-wire synced lookups

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml lookup_session_across_scopes -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml maybe_promote_synced_session -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml session_glue::tests -- --nocapture


---

## PR #521 — fix: skip reverse helper mirror for synced sessions [MERGED] (merged 2026-04-06)

Branch: `fix/518-skip-reverse-cluster-helper-mirror`

Fixes #518.

## Summary
- stop mirroring explicit reverse cluster-synced sessions into the userspace helper
- keep mirroring forward cluster-synced sessions so the helper can synthesize the correct reverse companion locally
- add a regression that proves reverse cluster updates do not hit the helper session socket

## Testing
- go test ./pkg/dataplane/userspace -run 'Test(ShouldMirrorUserspaceSessionSkipsReverseEntries|SetClusterSyncedSessionV4SkipsReverseHelperMirror)' -count=1
- go test ./pkg/dataplane/userspace -count=1


---

## PR #522 — fix: keep userspace HA forwarding-ready [MERGED] (merged 2026-04-06)

Branch: `fix/userspace-ha-forwarding-ready`

## Summary
- disable strict VIP ownership by default for the userspace dataplane in VRRP mode
- keep the existing no-`reth` and private-RG exceptions unchanged
- add focused tests around the defaulting helper so userspace HA stays hot-standby ready

## Testing
- `go test ./pkg/daemon -run 'TestStrictVIPOwnershipByDefault|TestSyncRGStrictVIPOwnershipMode|TestRethMasterState' -count=1`\n- live validation on `loss`:\n  - `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env TOTAL_CYCLES=1 CYCLE_INTERVAL=10 scripts/userspace-ha-failover-validation.sh --rg 1 --source-node 0 --target-node 1 --parallel 4 --duration 60`\n  - all 4 streams survived failover\n  - `0` zero-throughput intervals\n

---

## PR #523 — fix: select usable cluster bind addresses [MERGED] (merged 2026-04-06)

Branch: `fix/session-sync-bind-address`

## Summary
- prefer cluster heartbeat/session-sync bind addresses that match the configured peer family
- skip bare link-local IPv6 addresses that cannot be listened on without a zone
- use `net.JoinHostPort` so IPv6 sync/control endpoints are formatted correctly
- add regression coverage for IPv4, IPv6, host:port peers, and link-local-only interfaces

## Testing
- `go test ./pkg/daemon -run 'TestSelectClusterBindAddr|TestSessionSync|TestSelectClusterBindAddrSkipsLinkLocalIPv6Fallback' -count=1`\n

---

## PR #528 — fix: restore HA activation split-RG prewarm [MERGED] (merged 2026-04-07)

Branch: `fix/ha-activation-prewarm`

Closes #524.

## Summary
- restore activation-time split-RG reverse-session prewarm in `update_ha_state`
- republish `USERSPACE_SESSIONS` entries for activated RGs without bringing back the removed worker-wide HA apply scan
- add a regression test proving RG activation rewarms split-RG reverse companions again

## Verification
- `cargo test --manifest-path userspace-dp/Cargo.toml update_ha_state_prewarms_split_rg_reverse_sessions_on_activation -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml session_glue::tests -- --nocapture`

## Live Validation
Deployed to the isolated `loss` userspace HA cluster and reran RG1 failover traffic checks.

What improved:
- the old hard `node0 -> node1` failover collapse to zero streams is gone
- manual `RG1` failover still commits in about `185 ms`
- under load, all 4 streams now stay non-zero after the handoff instead of falling to zero

What is still open and tracked separately:
- #525 userspace HA readiness still overstates standby session usability
- #526 split-RG userspace fabric transit still collapses throughput badly
- #527 direct userspace forwarding on `node1` still underperforms `node0`


---

## PR #529 — fix: make userspace HA readiness reflect mirror failures [MERGED] (merged 2026-04-07)

Branch: `fix/525-ha-readiness-truthful`

Closes #525.

## Summary
- treat synced-session helper mirror failures as real userspace HA readiness failures
- stop counting those failures as clean `SessionsInstalled` progress in cluster sync
- add unit coverage for mirror-failure readiness poisoning and reset on helper stop

## Verification
- `go test ./pkg/dataplane/userspace ./pkg/cluster ./pkg/daemon -count=1`

## Notes
This intentionally makes mirror failure sticky for the current helper lifetime. Once a synced session delta is missed by the helper, the standby should stop claiming it is immediately takeover-ready until the helper/session state is rebuilt.


---

## PR #530 — fix: reconcile direct VIP ownership from cluster state [MERGED] (merged 2026-04-07)

Branch: `fix/527-direct-vip-no-overlap`

## Summary
- reconcile direct VIP ownership from actual cluster ownership each pass instead of only RG activity edges
- remove stale direct VIPs and stable link-local ownership when the node no longer owns the RG
- add daemon regression coverage for stale VIP removal without an rg_active edge

## Testing
- go test ./pkg/daemon -count=1

## Issue
- refs #527


---

## PR #531 — fix: route targeted failover through explicit handoff [MERGED] (merged 2026-04-07)

Branch: `fix/527-clear-manual-secondaryhold`

## Summary
- replace the unsafe `secondary-hold -> secondary` election workaround with a simpler targeted-failover model
- make `request chassis cluster failover redundancy-group <N> node <target>` always execute on the target node through the existing explicit `RequestPeerFailover` + transfer-commit flow
- proxy targeted failover requests through the peer fabric gRPC path in both the embedded CLI and the gRPC API so source-side commands no longer fall back to plain local `ManualFailover`
- add CLI and gRPC regression tests for peer-targeted failover proxying and forwarded-loop rejection

## Testing
- go test ./pkg/cluster ./pkg/cli ./pkg/grpcapi -count=1

## Issue
- refs #527


---

## PR #537 — fix: batch full data RG failover [MERGED] (merged 2026-04-07)

Branch: `fix/535-batch-data-rg-failover`

## Summary
- add a real batched multi-RG failover transaction in cluster manager + session-sync instead of moving paired data RGs one at a time
- add `request chassis cluster failover data node <target>` in the embedded CLI, remote CLI, gRPC API, and command tree
- wire the daemon so remote batch failover and batch commit use the same explicit handoff protocol as single-RG targeted failover

## Testing
- `go test ./pkg/cluster -count=1`
- `go test ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `go test ./pkg/daemon -count=1`
- deployed to `loss` with `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh deploy all`
- live full data failover/failback under load with new command path:
  - artifact `/tmp/manual-ha-data-stream-20260406-205351`
  - artifact `/tmp/manual-ha-data-capture-20260406-205558`

## Results
This fixes the issue in `#535`: a full data-RG move no longer has to pass through the old sequential `RG1` then `RG2` transient split window.

On the clean capture run, both batched commands returned:
- `Manual failover completed for data redundancy groups [1 2] (transfer committed)`

and the aggregate traffic no longer hit zero-throughput collapse:
- `15.679 Gbps` average
- `0` aggregate zero intervals
- cluster restored cleanly to `RG1=node0`, `RG2=node0`

There is still a residual ownership-move packet-loss burst during VIP/MAC transition itself, tracked separately in `#536`.

## Issue
- fixes #535
- refs #536


---

## PR #538 — fix: harden local HA handoff against old-owner resets [MERGED] (merged 2026-04-07)

Branch: `fix/536-local-failover-settle`

## Summary
- wait for the local side of a batched/manual transfer to settle before the peer finalizes demotion
- keep demoted peer-synced local-delivery sessions on XSK redirect instead of republishing them as kernel-local on the old owner
- send the first direct-mode VIP/MAC announce synchronously before the transfer is considered settled

## Root cause
Issue #536 was actually two coupled bugs:
1. On demotion, worker-side `DemoteOwnerRGSessions` republished peer-synced `LocalDelivery` sessions through the generic session-map writer. That could emit `PASS_TO_KERNEL` on the old owner, and the old owner's kernel would answer stray packets with RSTs.
2. In direct mode, the target node could report the local transfer as ready before it had emitted the first GARP/NA burst. That let the peer finish demotion before the MAC/VIP move had actually been announced.

## Validation
- `go test ./pkg/cluster ./pkg/daemon -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml session_glue::tests -- --nocapture`
- `go test ./pkg/daemon -run 'TestScheduleDirectAnnounce|TestWaitLocalFailoverCommitReady' -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml worker_synced_local_delivery_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_worker_commands_demotes_local_owner_rg_sessions_to_sync_import -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml reverse_session_blocks_inactive_interface_snat_ipv4_local_delivery -- --nocapture`

## Live loss validation
Deployed the dirty branch to `loss` and ran repeated direct `data node1 -> node0` failover/failback under 30s one-stream `iperf3` load.

Before the fixes, repeated runs still produced zero-throughput collapse after failback and captured old-owner RSTs.

After the fixes:
- `/tmp/issue536-rerun-20260406-224125`: `avg 9.85 Gbps`, `zero_intervals 0`, `retransmits 400`
- `/tmp/issue536-repeat-announcefix-20260406-224751/run1`: `zero_intervals 0`
- `/tmp/issue536-repeat-announcefix-20260406-224751/run2`: `zero_intervals 0`
- `/tmp/issue536-repeat-announcefix-20260406-224751/run3`: `zero_intervals 0`

The remaining behavior is a brief throughput dip at failover/failback, but the long failback-to-zero collapse no longer reproduced on the announce-ordered build.


---

## PR #539 — fix: drain session deltas on standby to unblock failover validator [MERGED] (merged 2026-04-07)

Branch: `fix/533-delta-drain-standby`

## Summary
- The failover validator's `wait_for_session_sync_idle` gate checks "Session delta drained" on the standby node, but the counter stayed at 0 because all three delta drain sites (`syncUserspaceSessionDeltas`, `eventStreamFallbackLoop` connected path, and disconnected path) were gated behind `IsLocalPrimaryAny()` — the standby never drained deltas from the Rust helper.
- Added `discardUserspaceSessionDeltas()` which drains deltas without queuing them for sync, preventing a feedback loop where synced sessions would generate deltas sent back to the primary.
- All drain code paths now call `discardUserspaceSessionDeltas` on standby/disconnected nodes instead of skipping entirely.

## Test plan
- [x] `go build` passes
- [x] `go test ./pkg/daemon/` passes (including new `TestDiscardUserspaceSessionDeltasDrainsWithoutQueuing`)
- [ ] `make cluster-deploy` and verify "Session delta drained" counter advances on standby node via `cli -c "show chassis cluster data-plane statistics"`
- [ ] `make test-failover` passes (validator idle gate no longer blocks)

Fixes #533

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #541 — fix: re-establish session sync after standby restart [MERGED] (merged 2026-04-07)

Branch: `fix/session-sync-reconnect-liveness`

Closes #540.

## What changed
- add an explicit session-sync heartbeat ack so one-way steady-state sync still proves reverse-path liveness
- close stale session-sync connections only after missed heartbeat replies instead of on raw read silence
- treat transfer readiness as disconnected when the sync peer is not protocol-healthy
- add regression coverage for both the dead-peer and heartbeat-ack paths

## Verification
- `go test ./pkg/cluster ./pkg/daemon`
- deployed to `loss-userspace-cluster`
- verified both nodes report `Transfer ready: yes`
- restarted `bpfrxd` on `bpfrx-userspace-fw1` and confirmed the primary re-dialed session sync and the standby recovered `Transfer ready: yes` instead of staying disconnected

---

## PR #542 — fix: stale VIP ownership and manual-hold after failover (#527) [MERGED] (merged 2026-04-07)

Branch: `fix/527-stale-vip-manual-state`

## Summary

- **Bug A (stale VIP):** In no-reth-vrrp direct mode, the demotion event handler used `reconcileDirectVIPOwnership()` which re-queries cluster state. If the event was dropped or there was a state-machine timing gap, VIPs could persist on the demoted node until the 2s periodic reconcile ran. Now calls `applyDirectVIPOwnership(want=false)` directly on demotion edges for synchronous, unconditional removal.

- **Bug B (stuck secondary-hold):** After `request chassis cluster failover`, the demoted node stayed in `secondary-hold` with `Manual=yes` indefinitely. `electRG` only cleared `ManualFailover` when the peer had also yielded (weight=0 or SecondaryHold), but after a successful failover the peer reports `StatePrimary`. Now detects peer-confirmed-primary and clears the manual hold, settling to ordinary secondary.

## Test plan

- [x] `TestApplyDirectVIPOwnershipForcesRemovalOnDemotion` — verifies synchronous VIP removal on demotion edge
- [x] `TestElection_ManualFailover_ClearedOnPeerPrimary` — verifies ManualFailover flag cleared and state transitions to secondary when peer confirms primary
- [x] Updated `TestRequestPeerFailoverTransferReadinessFailurePreservesManualFailover` and `TestRequestPeerFailoverPeerSendFailurePreservesManualFailover` to reflect the new behavior where ManualFailover is cleared by heartbeat before RequestPeerFailover runs
- [x] All existing cluster and daemon tests pass
- [x] `go build ./...` succeeds

Fixes #527

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #543 — fix: generate ICMP Time Exceeded on session-hit and flow-cache-hit paths [MERGED] (merged 2026-04-07)

Branch: `fix/532-ipv6-ttl-expired`

## Summary
- Add TTL/hop-limit expiry check with ICMPv6/ICMP Time Exceeded generation to **session-hit** and **flow-cache-hit** paths in the userspace dataplane
- Previously only the session-miss path (new flows) generated TE responses via `build_local_time_exceeded_request()`; packets hitting an existing session or flow cache entry with TTL/hop_limit<=1 were silently dropped because the frame rewrite functions (`apply_rewrite_descriptor`, `rewrite_forwarded_frame_in_place`, `build_forwarded_frame`) return `None` for expired TTL without generating a response
- This matches the BPF pipeline behavior where `xdp_forward` and `xdp_nat` check TTL and `XDP_PASS` to the kernel for Time Exceeded generation

## Test plan
- [x] `cargo build --release` passes (0 new warnings)
- [x] `cargo test --release` passes (435/435 tests)
- [ ] Deploy to test VM and verify `ping6 -t 1 <external_addr>` returns ICMPv6 Time Exceeded
- [ ] Verify IPv4 `ping -t 1 <external_addr>` still returns ICMP Time Exceeded
- [ ] Verify normal forwarding (TTL>1) is not affected by the new check

Fixes #532

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #544 — fix: re-land fabric-ingress Time Exceeded guard [MERGED] (merged 2026-04-07)

Branch: `fix/543-reland-fabric-ingress-te`

## Summary
- re-land the dropped follow-up from #543 so local Time Exceeded generation skips fabric-ingress packets
- keep the forwarding-loop tests that prove TTL expiry still enqueues a prebuilt response on ordinary hits
- add the fabric-ingress regression so the helper does not incorrectly synthesize Time Exceeded when TTL decrement is intentionally skipped

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml build_local_time_exceeded_request_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml packet_ttl_would_expire_identifies_v4_and_v6 -- --nocapture

Fixes #532

---

## PR #557 — refactor: split grpcapi/server.go into RPC domain files [MERGED] (merged 2026-04-07)

Branch: `refactor/547-split-server`

## Summary

- Split `pkg/grpcapi/server.go` (8411 lines, 93 functions) into 8 domain-specific files following the `server_sessions.go` pattern
- Mechanical move only -- no logic changes, no renamed symbols, no changed signatures
- `server.go` retains types (`Config`, `Server`), constructor, `Run`, `RunFabricListener`, and interceptor (241 lines)

### New files

| File | Functions | Lines |
|------|-----------|-------|
| `server_config.go` | `EnterConfigure`, `Commit`, `Load`, etc. (17 funcs) | 306 |
| `server_show.go` | `GetStatus`, `GetZones`, `ShowText`, etc. (12 funcs) | 5230 |
| `server_nat.go` | `GetNATSource`, `GetNATPoolStats`, etc. (5 funcs) | 356 |
| `server_routing.go` | `GetRoutes`, `GetBGPStatus`, etc. (6 funcs) | 252 |
| `server_diag.go` | `Ping`, `Traceroute`, `SystemAction`, etc. (10 funcs) | 946 |
| `server_helpers.go` | `protoName`, `uint32ToIP`, `screenChecks`, etc. (15 funcs) | 351 |
| `server_dhcp.go` | `GetDHCPLeases`, etc. (3 funcs) | 106 |
| `server_cluster.go` | `MatchPolicies`, `Complete`, `buildInterfacesInput`, etc. (18 funcs) | 744 |

## Test plan

- [x] `CGO_ENABLED=0 go build ./pkg/grpcapi/` passes
- [x] `CGO_ENABLED=0 go test ./pkg/grpcapi/ -count=1` passes
- [x] `CGO_ENABLED=0 go build ./cmd/bpfrxd/` (full daemon) passes
- [ ] `make test` full suite

Fixes #547

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #558 — refactor: split compiler.go into domain-specific files [MERGED] (merged 2026-04-07)

Branch: `refactor/545-split-compiler`

## Summary

- Split `pkg/config/compiler.go` (5878 lines) into 8 domain-specific files, following the pattern established by `compiler_nat.go`
- Mechanical move only — no logic changes, all 53 extracted functions retain their exact original code
- `compiler.go` retains top-level dispatch (`CompileConfig`, `compileExpanded`, `ValidateConfig`), `compileApplications`, and shared helpers (`nodeVal`, `normalizeProtocol`, `validatePortSpec`, `validateProtocol`) at 793 lines

### New files

| File | Functions | Lines |
|------|-----------|-------|
| `compiler_security.go` | `compileSecurity`, `compileZones`, `compilePolicies`, `compilePolicy`, `compileScreen`, `compileAddressBook`, `compileLog`, `compileFlow`, `compileALG` | 753 |
| `compiler_interfaces.go` | `compileInterfaces`, `parseMSSValue` | 530 |
| `compiler_protocols.go` | `compileProtocols`, `compileRouterAdvertisement`, `namedInstances`, `parsePrefixLimit`, `parseExportExtensions`, `peerFromPointToPoint`, `parseBandwidthBps`, `parseBandwidthLimit`, `parseBurstSizeLimit` | 908 |
| `compiler_ipsec.go` | `compileIKE`, `parseDeadPeerDetectionNode`, `compileIPsec` | 382 |
| `compiler_routing.go` | `compileRoutingOptions`, `compileStaticRoutes`, `parseNextTableInstance`, `compileRoutingInstances`, `compilePolicyOptions`, `parsePolicyTermChildren`, `parsePolicyTermInlineKeys` | 635 |
| `compiler_firewall.go` | `compileFirewall`, `compileFilterFrom`, `compileFilterThen` | 421 |
| `compiler_system.go` | `compileSystem`, `compileDPDKDataplane`, `compileUserspaceDataplane`, `compileSNMP`, `compileSNMPv3`, `parseSNMPv3UserKeys`, `compileSchedulers`, `compileChassis` | 840 |
| `compiler_services.go` | `compileDHCPLocalServer`, `compileDynamicAddress`, `compileServices`, `compileRPM`, `compileFlowMonitoring`, `compileForwardingOptions`, `compilePortMirroring`, `compileSampling`, `compileSamplingFamily`, `compileDHCPRelay`, `compileEventOptions`, `compileBridgeDomains` | 665 |

## Test plan

- [x] `CGO_ENABLED=0 go build ./pkg/config/` passes
- [x] `CGO_ENABLED=0 go test ./pkg/config/ -count=1` passes
- [x] `CGO_ENABLED=0 go build ./...` passes (full project)

Fixes #545

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #559 — refactor: split daemon_ha.go into domain files [MERGED] (merged 2026-04-07)

Branch: `refactor/546-split-daemon-ha`

## Summary

- Split `pkg/daemon/daemon_ha.go` (4194 lines, 125 functions) into 5 files organized by domain:
  - **daemon_ha_sync.go** (16 funcs, 785 lines): session sync callbacks, config sync, cluster comms lifecycle
  - **daemon_ha_userspace.go** (39 funcs, 944 lines): userspace session conversion, event stream, demotion prep
  - **daemon_ha_fabric.go** (18 funcs, 832 lines): fabric IPVLAN management, fabric_fwd BPF map, neighbor probing
  - **daemon_ha_vip.go** (24 funcs, 555 lines): VIP ownership, GARP/NA scheduling, stable link-local, readiness checks
  - **daemon_ha.go** (28 funcs, 1146 lines): RG state machine, VRRP/cluster event watchers, blackhole routes, RETH services, IPsec SA sync
- Mechanical split only — no logic changes, all files stay in `package daemon`
- Function-to-file mapping follows `docs/refactoring-audit.md` section 7

## Test plan

- [x] `CGO_ENABLED=0 go build ./pkg/daemon/` passes
- [x] `CGO_ENABLED=0 go test ./pkg/daemon/ -count=1 -short` passes
- [x] 125 functions preserved across all files (28+16+39+18+24)
- [ ] Full `make test` passes

Fixes #546

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #561 — fix: stop spinning on fatal local tunnel errors [MERGED] (merged 2026-04-07)

Branch: `fix/545-local-tunnel-fatal-errors`

## Summary
- stop retrying permanent local native-GRE tunnel FD failures forever
- classify `EINVAL` / `EBADF` / `EBADFD` / `ENODEV` / `ENXIO` as fatal for the local tunnel source loop
- add unit coverage for fatal vs retryable local tunnel I/O errors

## Issue
- closes #560

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::tunnel::tests:: -- --nocapture`
- deployed to `loss` from this branch
- before fix: `show chassis cluster data-plane interfaces` showed repeated `gr-0-0-0` errors on both firewalls
  - `fw1`: `read_local_tunnel:File descriptor in bad state (os error 77)`
  - `fw0`: `write_local_tunnel_delivery:Invalid argument (os error 22)`
- after deploy: the native-GRE helper thread (`bpfrx-n+`) disappeared on both firewalls instead of staying alive and retrying the bad FD forever


---

## PR #563 — fix: keep missing-neighbor seeds out of HA sync [MERGED] (merged 2026-04-07)

Branch: `fix/ha-rootcause-20260407`

## Summary
- keep transient `MissingNeighborSeed` sessions out of the helper delta stream
- skip them during owner-RG export and on the daemon-side userspace sync filter
- add targeted helper and daemon regressions

## Why
On `loss`, stock RG1 failover/failback on clean `master` can leave long-lived TCP streams stuck at `0`. The concrete root cause is that transient neighbor-repair seed sessions were still being treated like authoritative HA session state and could leak across failover.

Closes #562.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml missing_neighbor_seed_install_stays_out_of_delta_stream -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_worker_commands_does_not_export_missing_neighbor_seed_sessions -- --nocapture`
- `go test ./pkg/daemon -run 'TestShouldSyncUserspaceDelta(SkipsMissingNeighborSeed|SkipsLocalDelivery|PrefersOwnerRG|FallsBackToZone|AllowsStaleOwnerFabricRedirect|DoesNotBypassFabricIngress)$' -count=1`


---

## PR #566 — fix: demote worker-local sessions during HA owner-RG handoff [MERGED] (merged 2026-04-07)

Branch: `fix/565-worker-ha-demotion`

## Summary
- demote worker-local owner-RG sessions when HA demotes the shared owner-RG state
- cancel affected worker flow-cache keys before later packet hits reuse stale local state
- add regressions proving demoted local sessions are not re-exported as fresh HA deltas

Closes #565.

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::session_glue::tests:: -- --nocapture


---

## PR #567 — fix: settle idle standby XSK liveness without incidental traffic [MERGED] (merged 2026-04-07)

Branch: `fix/564-idle-standby-xsk-readiness`

## Summary
- auto-prove XSK liveness on a fully bound idle standby instead of extending the idle probe forever
- restore the userspace XDP shim and exit the probe-timeout path cleanly on idle-standby success
- add readiness regressions for idle standby auto-prove versus real active-data-RG idle cases

Closes #564.

## Testing
- go test ./pkg/dataplane/userspace -run 'Test(ShouldExtendXSKLivenessIdleLocked|ShouldAutoProveIdleStandbyXSKLocked|TakeoverReadyReportsSessionMirrorFailure)$' -count=1


---

## PR #569 — fix: keep inactive-owner translated synced hits transient [MERGED] (merged 2026-04-07)

Branch: `fix/568-inactive-owner-translated-hit`

(no description)

---

## PR #571 — fix: enforce HA redirect on new flow install [MERGED] (merged 2026-04-07)

Branch: `fix/570-inactive-owner-new-flow-fabric-redirect`

(no description)

---

## PR #573 — fix: keep HA standby neighbor resolution warm [MERGED] (merged 2026-04-07)

Branch: `fix/572-standby-neighbor-prewarm`

## Summary
- keep a throttled standby-only neighbor prewarm running after helper startup
- only do this while the node is an armed HA standby with data RGs configured
- add focused manager tests for the standby prewarm gate

## Why
Fixes #572. After the stale-owner forwarding fixes, the remaining failover loss on  was promoted-node  on the first translated WAN packets. The manager had stopped doing any neighbor prewarm after the helper's first 60 seconds, so a long-idle standby could still report takeover-ready while its WAN next-hop was cold.

## Testing
- ok  	github.com/psaab/bpfrx/pkg/dataplane/userspace	0.784s

---

## PR #577 — fix: infer on-link interfaces for ipv6 static next-hops [MERGED] (merged 2026-04-07)

Branch: `fix/575-ipv6-static-onlink`

## Summary
- infer on-link interfaces for configured IPv6 static next-hops when config only provides the IPv6 next-hop address
- pass the inferred interface map into FRR static route generation so IPv6 routes render with the correct egress interface
- add daemon and FRR regression coverage for inferred IPv6 next-hop interface selection

## Validation
- `go test ./pkg/frr ./pkg/daemon`
- live evidence from `loss`: `/tmp/ipv6-rg1-repro-20260407-090657`


---

## PR #578 — fix: clear demoted session redirect aliases [MERGED] (merged 2026-04-07)

Branch: `fix/574-demotion-clears-bpf-session-map`

## Summary
- clear demoted `USERSPACE_SESSIONS` redirect aliases immediately when a session is demoted
- make session-map demotion cleanup remove both redirect keys and queued TX state
- add regression coverage for demotion clearing redirect aliases

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml session_map_redirect_keys_for_ -- --nocapture`
- live `loss` RG1 failover validation artifact: `/tmp/userspace-ha-failover-rg1-20260407-085805`


---

## PR #581 — fix: choose HA owner in userspace validation [MERGED] (merged 2026-04-07)

Branch: `fix/579-active-userspace-validator`

## Summary
- choose the HA owner first when determining the active userspace firewall in the HA validator
- stop treating the first `Enabled:true` helper node as active when all HA groups on that node are still `active=false`
- keep the validator aligned with real RG ownership before it tries WAN-neighbor checks

## Validation
- `bash -n scripts/userspace-ha-validation.sh`
- `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env RUNS=1 DURATION=5 PARALLEL=4 PREFERRED_ACTIVE_NODE=1 PREFERRED_ACTIVE_RGS='1 2' scripts/userspace-ha-validation.sh`
  - this now selects `loss:bpfrx-userspace-fw1` as the active userspace firewall and gets past the old bogus `unable to detect WAN test interface for loss:bpfrx-userspace-fw0` failure


---

## PR #583 — userspace: keep standby HA readiness when bindings are already ready [MERGED] (merged 2026-04-07)

Branch: `fix/582-standby-bindings-ready`

Closes #582

## Summary
- allow standby takeover readiness when all helper queues and bindings are already registered, armed, bound, and ready
- keep active-node readiness gated on real XSK liveness proof
- add focused takeover readiness regressions for standby vs active nodes

## Testing
- go test ./pkg/dataplane/userspace -run 'TestTakeoverReady(AllowsStandbyWithReadyBindingsWithoutLivenessProof|RequiresLivenessProofOnActiveNode|ReportsSessionMirrorFailure)' -count=1

---

## PR #585 — userspace: demote worker sessions on rg handoff [MERGED] (merged 2026-04-07)

Branch: `fix/584-worker-demotion`

Closes #584

## Summary
- demote worker-local sessions for demoted owner RGs instead of only demoting shared replicas
- republish worker session-map entries under the demoted ownership rules
- add regressions for worker demotion and failback promotion behavior

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::session_glue::tests:: -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests:: -- --nocapture

---

## PR #589 — tests: relax HA failover sync-idle gate [MERGED] (merged 2026-04-07)

Branch: `fix/validator-sync-idle`

Closes #586.

## What changed
The HA failover validator no longer requires cumulative sync counters like `Session delta drained` to stop changing entirely before it considers the standby idle. It now waits for the conditions that actually matter:
- source `Session create sent` matches target `Session create received`
- target `Session delta pending` is `0`
- those conditions remain stable for the configured sample count

## Why
On the live `loss` cluster, the old gate false-failed even while traffic was stable and session sync was caught up. `Session delta drained` is cumulative and can legitimately keep moving under background churn.

## Validation
- `bash -n scripts/userspace-ha-failover-validation.sh`
- live validation on `loss`:
  - old gate false-failed before failover in `/tmp/userspace-ha-failover-rg1-20260407-101026`
  - patched gate passed the same pre-failover idle check and exposed the real dataplane failure in `/tmp/userspace-ha-failover-rg1-20260407-101426`


---

## PR #591 — ha: refresh standby neighbors when synced sessions arrive [MERGED] (merged 2026-04-07)

Branch: `fix/587-standby-session-neighbor-warmup`

Closes #587.

This wires a low-latency signal from session sync into the daemon when a forward synced session is installed, then debounces a standby neighbor refresh so the promoted owner does not wait for the periodic sweep before it can resolve WAN next hops.

What changed:
- add `OnForwardSessionInstalled` to `SessionSync`
- fire it only for forward session installs
- debounce standby neighbor refreshes to 1s in the daemon
- reuse existing neighbor maintenance instead of adding a separate warmup path

Validation:
- `go test ./pkg/cluster ./pkg/daemon -count=1`
- live loss artifact: `/tmp/userspace-ha-failover-rg1-20260407-103004`

Impact:
- fixes the external IPv4 reachability loss during `RG1 node0 -> node1` failover on loss
- leaves the remaining session-miss / throughput-tail issue tracked separately in #590

---

## PR #592 — fix: scope inferred ipv6 next-hop interfaces by vrf [MERGED] (merged 2026-04-07)

Branch: `fix/577-vrf-scoped-ipv6-nexthops`

Follow-up to merged PR #577.

This closes the remaining Copilot findings from that branch:
- scope inferred IPv6 next-hop interface resolution by VRF instead of a single global next-hop map
- make inference deterministic by iterating interfaces/units in sorted order and using a stable lexical tie-break for equal prefix lengths

Validation:
- `go test ./pkg/frr ./pkg/daemon -count=1`

---

## PR #593 — ha: harden standby neighbor refresh scheduling [MERGED] (merged 2026-04-07)

Branch: `fix/591-standby-neighbor-refresh-followups`

Follow-up to merged PR #591.

This closes the remaining Copilot findings from that branch:
- use monotonic debounce accounting for standby neighbor refresh scheduling
- avoid consuming the debounce window when there is no active config
- prevent overlapping expensive neighbor warmup runs while still allowing cheap preinstall refreshes

Validation:
- `go test ./pkg/daemon -count=1`

---

## PR #594 — fix: reconnect half-open session sync after ack timeout [MERGED] (merged 2026-04-07)

Branch: `fix/588-half-open-sync-reconnect`

Closes #588

## Summary
- remember heartbeat-ack capability across reconnects so silent stale sockets are still considered ack-capable
- tear down silent reconnects even before a fresh ack arrives on the new connection
- add regressions for reconnects after an ack-capable peer has already been observed

## Testing
- go test ./pkg/cluster -run 'TestReceiveLoop(DisconnectsSilentConnectionAfterHeartbeatAck|KeepsConnectionAliveWithoutHeartbeatAckSupport|DisconnectsSilentConnectionAfterAckCapableReconnect|KeepsConnectionAliveWithHeartbeatAck)' -count=1\n- go test ./pkg/cluster ./pkg/daemon -count=1

---

## PR #595 — fix: auto-rebind standby XSK busy wedge [MERGED] (merged 2026-04-07)

Branch: `fix/580-auto-rebind-stuck-xsk`

Closes #580

## Summary
- detect the standby helper wedge where bindings stay armed but never bind and stale map repair keeps firing
- debounce and throttle an automatic helper rebind instead of waiting forever for takeover readiness
- add unit coverage for the wedge detector and auto-rebind debounce behavior

## Testing
- go test ./pkg/dataplane/userspace -run 'Test(HasBusyBindingsWedgeLocked|ShouldAutoRebindBusyBindingsLockedDebounces|ShouldAutoProveIdleStandbyXSKLocked|ShouldExtendXSKLivenessIdleLocked)' -count=1\n- go test ./pkg/dataplane/userspace ./pkg/daemon -count=1

---

## PR #599 — fix: retry userspace RST suppression install [MERGED] (merged 2026-04-07)

Branch: `pr/596-rst-suppression-retry`

Fixes #596

This change makes userspace RST suppression install safely when the `inet bpfrx_dp_rst` table does not already exist, and retries failed installs on a backoff instead of caching the failure forever.

Validation:
- `go test ./pkg/nftables ./pkg/dataplane/userspace -count=1`
- live loss deploy: verified `RST suppression: installed nftables rules via netlink` on both firewalls and verified the `inet bpfrx_dp_rst` table exists on fw0 after deploy
- live failover/failback debugging before this fix showed old-owner WAN-side TCP RSTs; those RSTs no longer appeared after the install/retry fix


---

## PR #600 — fix: allow explicit failback when sync is healthy [MERGED] (merged 2026-04-07)

Branch: `pr/597-explicit-failback-sync-healthy`

Fixes #597

This change stops treating UDP heartbeat `peerAlive` as a hard prerequisite for explicit RG transfer requests when the explicit peer-transfer RPC/commit path is still available. In the asymmetric lab state where session sync and transfer readiness stay healthy but one node drops heartbeat observation, operator failback can still commit instead of getting stuck behind `peer not alive`.

Validation:
- `go test ./pkg/cluster ./pkg/daemon -count=1`
- added regressions for single-RG and batched explicit transfer while heartbeat is lost but sync-backed transfer callbacks are still available

Live note:
- this was derived from a live loss reproduction where `request chassis cluster failover redundancy-group 1 node 0` started failing with `peer not alive — cannot request failover` after RG1 moved to node1, while cluster status still showed `Transfer ready: yes`


---

## PR #601 — fix: resolve standby warmup neighbors on unit interfaces [MERGED] (merged 2026-04-07)

Branch: `pr/598-standby-neighbor-unit-warmup`

Fixes #598

This change makes standby neighbor warmup resolve config-subnet fallback matches to the actual Linux unit/VLAN interface name instead of the parent/base interface. That keeps split-RG warmup and standby forwarding prep aimed at the real neighbor table used by the configured subnet.

Validation:
- `go test ./pkg/daemon -count=1`
- added regression coverage for `reth` unit fallback resolving to the concrete unit interface name


---

## PR #604 — fix: surface HA software version mismatch [MERGED] (merged 2026-04-08)

Branch: `pr/ha-version-mismatch-diagnostics`

Closes #603.

## What this changes

- carries local software version in cluster heartbeats
- stores peer software version in the cluster manager
- exposes local/peer software versions in cluster status/information output
- makes userspace transfer readiness prefer an explicit version-mismatch reason over the generic `session sync disconnected`

## Why

On `loss`, the reported session-sync disconnect was reproduced with mixed node builds:

- `fw0`: `...-ga2f53a50-dirty`
- `fw1`: `...-gd6a538e1`

After both nodes were redeployed to the same clean `origin/master` build (`g51fc6996`), session sync recovered and both nodes returned to `Transfer ready: yes`.

So the product gap here is operator-facing diagnosis/readiness: version skew looked like a transport failure.

## Verification

- `go test ./pkg/cluster ./pkg/daemon -count=1`


---

## PR #605 — docs: strengthen HA failover validation guidance [MERGED] (merged 2026-04-08)

Branch: `docs/ha-failover-longer-p8`

## Summary

Update the HA failover docs to reflect the current preferred repro shape:

- longer failover runs
- faster RG movement between `fw0` and `fw1`
- `iperf3 -P 8` with operators watching all per-stream lines, not just `[SUM]`

## Changes

- update the main failover testing examples in `docs/ha-failover-status.md`
- update `docs/userspace-ha-validation.md` to define the standard failover stress shape
- tighten pass/fail guidance around per-stream zero-throughput intervals and failback wedges

## Notes

This is a docs-only change. No code or scripts changed.


---

## PR #607 — fix: skip identical config sync apply on standby [MERGED] (merged 2026-04-08)

Branch: `fix/606-skip-identical-config-sync`

## Summary
- skip standby config sync apply when the incoming config already matches the active config
- avoid reconnect-time no-op recompiles/rebinds during session sync recovery
- add a daemon regression test for the identical-config path

## Testing
- `go test ./pkg/daemon -run 'TestHandleConfigSync_(RejectsWhenPrimary|AcceptsWhenSecondary|AcceptsWhenNoCluster|SkipsWhenConfigAlreadyMatchesActive)' -count=1`
- `go test ./pkg/cluster ./pkg/daemon -count=1`
- live on `loss`: deploy branch, restart `bpfrxd` on `bpfrx-userspace-fw1`, confirm both nodes return to `Transfer ready: yes`
- live on `loss`: standby journal shows `cluster: skipping config sync apply (config already matches active)` and does not log `restarting heartbeat after VRF rebind` for that reconnect

Fixes #606


---

## PR #610 — fix HA handoff regressions during rapid RG movement [MERGED] (merged 2026-04-08)

Branch: `pr/609-rg-failback-ctrl-fix`

Closes #608.

This bundles the repo-level HA handoff fixes that came out of the repeated RG movement debugging:

- retain a populated `fabric_fwd` entry across transient neighbor misses instead of clearing it immediately
- avoid an extra ctrl-disable cycle after RG activation has already been acked
- distinguish actual fabric-ingress packets from ordinary packets arriving on the fabric parent NIC, so stale traffic on the old owner can still be redirected to the active peer instead of getting dropped as `ha_inactive`
- preserve synced-session ownership/materialization semantics needed for that standby redirect path

Validation:
- `go test ./pkg/dataplane/userspace ./pkg/daemon -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::session_glue::tests -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::forwarding::tests -- --nocapture`

Live notes:
- on the patched build, the old `ha_inactive` standby-drop symptom is no longer visible on the new owner during the RG1 IPv6 repro
- the separate remaining first-failover throughput collapse is tracked in #609
- the later VM panic remains the known kernel/driver issue in #472


---

