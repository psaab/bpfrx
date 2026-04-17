# bpfrx Pull Request History

Complete record of all pull requests.
Total: 317 PRs (293 merged)

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

## PR #614 — cluster: preserve committed reverse failovers through heartbeat gaps [MERGED] (merged 2026-04-08)

Branch: `pr/611-reverse-failover-commit-grace`

## Summary
- preserve committed manual failovers through transient post-commit heartbeat gaps
- keep the new primary from self-demoting while the matching session-sync barrier ack is still in flight
- clear stale inbound transfer grace when RG ownership direction flips repeatedly
- update the HA failover docs to require reverse-path `iperf3 -R` validation, not only host-sending tests

## What changed
- add a transfer-commit grace window that keeps the peer in `secondary-hold` briefly after commit and suppresses old-primary heartbeat reclaim during that window
- apply the same grace handling to batch failovers
- clear stale `peerTransferOutOverride` / `peerTransferCommitGraceUntil` markers when finalizing a peer transfer-out, so the old owner cannot re-elect itself on the next heartbeat during rapid alternating moves
- add regression tests for:
  - post-commit heartbeat-gap handling
  - single-RG direction flips
  - batch direction flips
- document forward and reverse failover test requirements in:
  - `docs/ha-failover-status.md`
  - `docs/userspace-ha-validation.md`
  - `testing-docs/failover-testing.md`

## Verification
- `go test ./pkg/cluster ./pkg/daemon -count=1`
- `go test ./pkg/cluster -run 'TestFinalizePeerTransferOut(ClearsStaleInboundTransferGrace|BatchClearsStaleInboundTransferGrace)' -count=1`

## Live validation
- before this follow-up fix, alternating RG1 transfers could snap ownership back to the old owner a few seconds after a committed direction change
- after this fix, the old-owner snapback is gone, but the first reverse `-P 12` failover now cleanly exposes the remaining mlx5 kernel panic on the old owner

Closes #611
Closes #612
Closes #615

Related to #613
Related to #472


---

## PR #616 — userspace-dp: keep reverse sessions live across RG moves [MERGED] (merged 2026-04-08)

Branch: `pr/613-reverse-fabric-cache-owner-rg`

Fixes #613.

## Summary
- stamp cached forwarding decisions with the logical owner RG so stale fabric redirects are invalidated when that RG becomes locally active again
- refresh demoted local sessions through current HA/fabric resolution so repeated RG moves republish reverse-path sessions with a concrete fabric redirect instead of leaving a stale local decision behind
- keep reverse-prewarm/shared-owner indexes aligned with owner-RG demotion so failback reactivation can recover the correct session path quickly

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::session_glue::tests -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::forwarding::tests -- --nocapture`
- live HA validation artifact: `/tmp/reverse-rg2-6move-cuh-fw1ctl-20260408-111638`
  - source host: `loss:cluster-userspace-host` (`10.0.61.102` path)
  - command: `iperf3 -c 172.16.80.200 -P 12 -t 34 -R`
  - six committed RG2 moves: `node0,node1,node0,node1,node0,node1`
  - no `[SUM] 0.00 bits/sec` intervals
  - split-RG intervals held around `3.96-4.54 Gbits/sec`
  - failback recovered to `19.2-20.8 Gbits/sec` within about 1-2 seconds


---

## PR #617 — userspace-dp: refresh synced reverse sessions on RG demotion [MERGED] (merged 2026-04-09)

Branch: `pr/617-split-rg-reverse-demotion-refresh`

## Summary
- revisit all sessions owned by a demoting RG so synced reverse companions also get HA transition refresh
- preserve the existing origin conversion behavior for locally-owned sessions while still returning synced keys for worker-side re-resolution
- add regressions for synced owner-RG demotion and split-RG reverse rewrite to fabric redirect

## Testing
- cargo test --manifest-path userspace-dp/Cargo.toml demote_owner_rg -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml apply_worker_commands_demote_split_reverse_owner_rg_rewrites_to_fabric_redirect -- --nocapture

Related: #613

---

## PR #618 — docs: add CoS design history summary [MERGED] (merged 2026-04-09)

Branch: `pr/cos-design-steps-summary`

## Summary
Add `docs/cos-design-steps.md`, a design-history summary for how `docs/cos-traffic-shaping.md` was developed.

## What it includes
- the prompt chronology that drove each review/rewrite step
- what each `/tmp` review artifact represented
- the major design pivots, including the reset back to a true hierarchy
- how those iterations led to the current CoS shaping doc

## Testing
- not run; documentation-only change


---

## PR #619 — HA: wait for local failover settle before peer demotion [MERGED] (merged 2026-04-09)

Branch: `pr/536-local-failover-settle-rebased`

## Summary
- restore the previous peer RG snapshot when a requested failover aborts after local promotion, instead of leaving the peer parked in synthetic `secondary-hold`
- wait for the target daemon to observe local promotion side effects before sending the peer-demotion commit
- tighten userspace transfer readiness and direct announce behavior during HA handoff
- treat interface-NAT local-delivery session decisions as HA-owned so standby cached/session-hit decisions invalidate or redirect correctly

## Validation
- `go test ./pkg/daemon ./pkg/cluster -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::forwarding::tests -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::session_glue::tests -- --nocapture`

## Live Smoke
Deployed the equivalent tree from `~/git/codex-bpfrx` to the isolated `loss` userspace HA cluster and ran:
- `iperf3 -c 172.16.80.200 -P 12 -t 32 -R -J`
- RG1 moves: `node1 -> node0 -> node1 -> node0`

The cluster recovered healthy after all four moves, but reverse traffic still showed multi-second blackout windows with several `0.0 Gbps` intervals. Artifact:
- `/tmp/reverse-rg1-smoke-local-20260409-145558.json`

This PR is draft because that repeated reverse-failover dataplane gap is still open.


---

## PR #620 — docs: simplify CoS shaping hierarchy [MERGED] (merged 2026-04-10)

Branch: `pr/cos-traffic-shaping-reservation-container`

## Summary
- rewrite the service tree as `root(interface) -> reservation -> container`
- make the first pass explicitly FIFO per container with weighted scheduling among reservations
- replace the abstract sharding language with a concrete many-core ownership model
- document the phase-1 limitation that same-container micro-flow fairness is not solved yet

## Testing
- not run (documentation-only change)

---

## PR #621 — HA: stabilize repeated RG2 failover recovery [MERGED] (merged 2026-04-12)

Branch: `pr/ha-rg2-100x10-no-exact-zero-streams`

## Summary
- keep repeated RG activation bookkeeping from getting stuck behind stale rgStateMachine epochs
- republish and prewarm split-RG reverse sessions on owner-RG transitions in the userspace dataplane
- validate the clean origin/master-based deploy with repeated RG2 failovers on the isolated loss userspace HA cluster

## Validation
- `GOTOOLCHAIN=local go test ./pkg/daemon -run 'TestWaitLocalFailoverCommitReadyWaitsForPromotionSettle|TestWaitLocalFailoverCommitReadyTimesOutWithoutPromotionSettle|TestRecordRGActiveAppliedIfCurrentOrStableClearsSameDesiredStaleEpoch|TestRecordRGActiveAppliedIfCurrentOrStableRejectsChangedDesiredState' -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::ha::tests -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml prewarm_reverse_synced_sessions_after_demotion_recomputes_split_owner_reverse -- --nocapture`

## Live HA Validation
- clean rebooted/stabilized userspace HA boot before validation to avoid mlx/XSK guest-crash contamination
- 4-move 10s cadence artifact: `/tmp/narrow-short-4move-10s-fg-20260410-065125`
- 100-move 10s cadence artifact: `/tmp/narrow-long-100move-10s-fg-20260410-065357`
- `100/100` RG2 failover requests committed successfully
- `exact_zero_intervals=0`
- `exact_zero_streams=0`
- no mlx/XSK crash signatures captured on either userspace firewall console

## Note
The existing `scripts/iperf-json-metrics.py` zero counters are thresholded at `<= 50 Mbps`, not literal `0.0 bps`, so the soak still reports nonzero thresholded zero counters even though no stream hit an exact zero interval.

---

## PR #622 — docs: sync CoS design notes with current hierarchy [MERGED] (merged 2026-04-10)

Branch: `pr/cos-doc-sync-after-cleanup`

## Summary
- sync `docs/cos-design-steps.md` with the later simplification that produced the current `root(interface) -> reservation -> container` CoS model
- make the design-steps summary explicit about Phase 1 being FIFO-per-container and reservation-level weighted scheduling
- clean up `docs/cos-traffic-shaping.md` so it matches the intended current wording after the earlier local merge cleanup

## Notes
- documentation-only change
- no tests run

---

## PR #623 — userspace: clarify standby forwarding status [MERGED] (merged 2026-04-12)

Branch: `pr/userspace-standby-role-status`

## Summary
- add an explicit local HA forwarding role line to userspace dataplane status
- distinguish active ownership from standby armed-for-failover state
- cover both active and standby-armed output in status formatter tests

## Validation
- go test ./pkg/dataplane/userspace -run 'TestFormatStatusSummary|TestFormatStatusSummaryReportsStandbyArmedRole|TestFormatBindings' -count=1
- live cluster check on 2026-04-10:
  - fw0 primary, fw1 secondary
  - fw1 had blackhole default routes and no service IPs on data interfaces
  - during iperf3 -c 172.16.80.200 -P 8 -t 10, fw0 dataplane counters advanced by ~19.9M RX packets while fw1 advanced by 1 RX / 1 TX packet
  - issue was misleading status wording, not real dual transit forwarding

---

## PR #624 — docs: add CoS timer wheel plan [MERGED] (merged 2026-04-11)

Branch: `wip/cos-timer-wheel-plan`

## Summary
- add a concrete timer-wheel design to the CoS shaping doc
- make the timer wheel a reservation wakeup mechanism, not per-packet pacing
- update the implementation and validation plans accordingly
- record the timer-wheel design pivot in cos-design-steps

## Details
- parking applies to backlogged-but-ineligible reservations, not packets
- wakeups are driven by expected root/reservation budget refill or lease-age deadlines
- the initial sketch uses a per-shard multi-level wheel so sleeping reservations do not require busy rescans across shards
- the many-core section stays hierarchical: the wheel serves the root/reservation/container scheduler rather than bypassing it

## Validation
- documentation-only change
- git diff --check

---

## PR #626 — userspace-dp: keep UMEM bounds at registered length [MERGED] (merged 2026-04-12)

Branch: `pr/umem-hugepage-registered-bounds`

Fixes #625.

## Summary
- keep hugepage-backed UMEM allocation and rounded `munmap` length
- restore `MmapArea` slice bounds to the registered UMEM length
- add a regression test that rejects accesses into the rounded hugepage tail
- restore the small invalid-descriptor slow-path regression to the original past-the-end semantics

## Problem
Commit `136b9dbb64754723350a7f338f62fc4af22f965a` changed `MmapArea` access bounds from the registered UMEM length to the rounded mapping length. That made descriptors in the padded hugepage tail look valid to userspace parsing helpers even though those bytes are outside the UMEM region registered with XSK.

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml mmap_area_rejects_access_beyond_registered_len_even_if_mapping_is_rounded -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml maybe_reinject_slow_path_records_extract_failure_for_invalid_desc -- --nocapture

---

## PR #627 — refactor: split userspace manager snapshot builders [MERGED] (merged 2026-04-12)

Branch: `pr/550-userspace-manager-split`

Move-only first pass for #550.

This extracts the pure snapshot assembly helpers from pkg/dataplane/userspace/manager.go into pkg/dataplane/userspace/snapshot.go while keeping lifecycle/control-plane entrypoints in manager.go.

Scope:
- move buildSnapshot and the snapshot helper functions into snapshot.go
- keep behavior unchanged
- keep the rest of manager.go focused on control flow and process lifecycle

Validation:
- go test ./pkg/dataplane/userspace -count=1

---

## PR #628 — refactor: split pkg/config/ast.go [MERGED] (merged 2026-04-12)

Branch: `pr/553-config-ast-split`

Move-only first pass for #553.

This splits pkg/config/ast.go into:
- ast_groups.go for apply-groups expansion
- ast_edit.go for set/delete/copy/rename/insert path mutation
- ast_format.go for hierarchical/set/JSON/XML/inheritance formatting

Core types, navigation helpers, and schema completion stay in ast.go.

Tests:
- go test ./pkg/config

---

## PR #629 — refactor: split config parser tests by subsystem [MERGED] (merged 2026-04-12)

Branch: `pr/555-parser-test-subsystem-split`

Move-only first-pass split of pkg/config/parser_test.go into subsystem files per #555.

Files:
- parser_ast_test.go
- parser_system_test.go
- parser_security_test.go
- parser_routing_test.go
- parser_services_test.go
- parser_cluster_test.go

Validation:
- go test ./pkg/config -count=1

---

## PR #630 — refactor: split daemon helpers by subsystem [MERGED] (merged 2026-04-12)

Branch: `pr/549-daemon-system-config-split`

Move-only first pass for #549.

This splits pkg/daemon/daemon.go into subsystem files:
- daemon_system.go
- daemon_reth.go
- daemon_neighbor.go
- daemon_flow.go
- daemon_nft.go
- daemon_cluster_bind.go

Behavior is unchanged. Validation:
- go test ./pkg/daemon -count=1

---

## PR #631 — refactor: split pkg/cli dispatch paths [MERGED] (merged 2026-04-12)

Branch: `pr/552-cli-dispatch-split`

Issue #552 move-only first pass for pkg/cli/cli.go.

What changed:
- split dispatch and command-family handlers into pkg/cli/cli_dispatch.go, cli_clear.go, cli_config.go, cli_request.go, and cli_helpers.go
- left cli_show.go and cmd/cli/main.go untouched
- kept this as a mechanical move-only refactor with no behavior changes

Validation:
- go test ./pkg/cli -count=1
- go test ./pkg/cli -run ^$


---

## PR #632 — refactor: split cluster sync helpers [MERGED] (merged 2026-04-12)

Branch: `pr/551-cluster-sync-split`

Implements the move-only first pass for #551.

Changes:
- split protocol encoding/decoding helpers into pkg/cluster/sync_protocol.go
- split connection lifecycle and message handling into pkg/cluster/sync_conn.go
- split manual failover request/ack/commit paths into pkg/cluster/sync_failover.go
- left sync bulk logic and stale reconciliation in pkg/cluster/sync.go

Validation:
- go test ./pkg/cluster -count=1

---

## PR #633 — userspace-dp: split afxdp root module [MERGED] (merged 2026-04-12)

Branch: `pr/556-afxdp-root-split`

Move-only refactor for issue #556.\n\nSummary:\n- move Coordinator into userspace-dp/src/afxdp/coordinator.rs\n- move BindingWorker and worker_loop into userspace-dp/src/afxdp/worker.rs\n- move afxdp tests into userspace-dp/src/afxdp/tests.rs\n- keep userspace-dp/src/afxdp.rs as module wiring and shared top-level helpers\n\nValidation:\n- cargo test --manifest-path userspace-dp/Cargo.toml afxdp::tests -- --nocapture

---

## PR #634 — cli: split show commands by domain [MERGED] (merged 2026-04-12)

Branch: `pr/548-cli-show-domain-split`

Fixes #548.

First-pass move-only split of pkg/cli/cli_show.go into domain files, keeping shared help helpers separate and leaving cmd/cli/main.go untouched. This also accounts for the open #552 shared CLI split by isolating the show-command domains without changing behavior.

Tests:
- go test ./pkg/cli -run "^$"
- go test ./pkg/cli -count=1


---

## PR #635 — refactor: split cmd/cli/main.go by command family [MERGED] (merged 2026-04-12)

Branch: `pr/554-cmd-cli-main-split`

Move-only first pass for #554.

Scope:
- split cmd/cli/main.go into shared runtime plus show/request/clear/monitor files
- keep main() and top-level wiring in main.go
- leave ping/traceroute/load/test families in main.go for this pass

Validation:
- go test ./cmd/cli -count=1
- go test ./pkg/cli -count=1

---

## PR #636 — daemon: bind RETH RA to stable link-local [MERGED] (merged 2026-04-13)

Branch: `pr/ha-ra-stable-link-local-source`

## Summary
- bind RA senders on HA RETH interfaces to the stable router link-local when no explicit RA source link-local is configured
- keep explicit configured link-local addresses taking precedence
- stop skipping RA source-link-local selection for static RA configs when DHCP-PD is not in use
- add daemon tests for both the stable-link-local and explicit-link-local cases

## Problem
On the `loss` userspace HA cluster, IPv6 could degrade after deploy even though policy/config looked unchanged. The active node logged repeated RA send failures like:

```
ra: failed to send RA ... fe80::bf:72ff:fe16:200%ge-0-0-1->ff02::1%ge-0-0-1: sendmsg: invalid argument
```

The root cause was that the RA sender auto-selected a transient EUI-64 link-local, while HA reconcile had already removed that address and installed the stable router link-local on the active RETH member. The sender then kept trying to transmit from an address the interface no longer owned.

## Validation
- `go test ./pkg/daemon -run 'TestBuildRAConfigsUsesStableRethLinkLocal|TestBuildRAConfigsPrefersExplicitLinkLocal|TestSelectClusterBindAddr|TestSelectClusterBindAddrSkipsLinkLocalIPv6Fallback' -count=1`
- `go test ./pkg/daemon -count=1`
- live deploy to `loss:bpfrx-userspace-fw0/1`
- post-deploy `show ipv6 router-advertisement` on `fw0` now reports source `fe80::bf72:16:2%ge-0-0-1`
- no new `ra: failed to send RA` warnings after deploy
- `cluster-userspace-host` recovered IPv6 default route via `fe80::bf72:16:2` and successful IPv6 ping to `2607:f8b0:4005:814::200e`


---

## PR #637 — test/incus: keep isolated LAN IPv6 off the host parent [MERGED] (merged 2026-04-13)

Branch: `pr/loss-host-ignore-lan-ra`

## Summary
- disable IPv6 RA/autoconf on the host-side SR-IOV LAN parent before create/deploy
- flush any dynamic global IPv6 addresses learned on that parent
- prevent the host from installing an on-link route to the isolated LAN and bypassing the firewall

## Validation
- `bash -n test/incus/cluster-setup.sh`
- on `loss`, before the fix: `ip -6 route get 2001:559:8585:ef00:1266:6aff:fe0b:d017` resolved to `dev mlx1` and `ping -6` returned `Destination unreachable: Address unreachable`
- applied the runtime equivalent on `loss`: disabled `accept_ra`/`autoconf` on `mlx1` and flushed dynamic global IPv6 state
- after the fix on `loss`, the same route resolves via `fe80::100 dev ix0` and `ping -6 -c 5 2001:559:8585:ef00:1266:6aff:fe0b:d017` succeeds


---

## PR #638 — refactor: complete userspace manager split [MERGED] (merged 2026-04-13)

Branch: `pr/finish-602-userspace-manager-split`

Fixes #550
Fixes #602

## Summary
- move userspace manager map/bootstrap/watchdog helpers into `maps_sync.go`
- move helper lifecycle, control socket, status loop, and link-cycle handling into `process.go`
- leave `manager.go` focused on the core manager type and public entrypoints

## Testing
- `go test ./pkg/dataplane/userspace -count=1`
- `go test ./pkg/dataplane/userspace ./pkg/daemon -count=1`

---

## PR #639 — cli: follow up flow brief formatting review [MERGED] (merged 2026-04-13)

Branch: `pr/cli-flow-brief-followups`

Follow-up to `5aa6a110` based on review feedback.

## Summary
- guard the local brief-writer flush explicitly
- handle empty endpoint strings defensively in brief output
- collapse duplicated local/peer brief-row construction into one helper

## Testing
- `go test ./pkg/cli -count=1`

---

## PR #640 — monitor: merge userspace XSK traffic into interface view [MERGED] (merged 2026-04-13)

Branch: `pr/monitor-interface-merge-userspace-xsk`

## Summary
- merge userspace/XSK RX/TX counters into monitor interface traffic totals and rates
- keep kernel/interface error stats separate
- add monitor regression coverage for merged summary and rate calculations

## Why
`monitor interface traffic` was rendering from interface counters only. On the userspace dataplane that misses the XSK/helper path, so 10Gbps of forwarded traffic could look mostly idle.

## Validation
- `go test ./pkg/monitoriface ./pkg/cli -count=1`


---

## PR #642 — cli: fix command help and completion prefix handling [MERGED] (merged 2026-04-13)

Branch: `pr/cli-completion-prefix-audit`

## Summary
- make command-tree completion and help resolve unique prefixes in already-typed words instead of requiring exact parent tokens
- normalize consumed config-path prefixes before schema completion so `show configuration` and config-mode completions work after abbreviated parents
- remove the stale hardcoded gRPC config completion lists so `commit comment` and `load set` show up again

## Validation
- go test ./pkg/cmdtree ./pkg/config ./pkg/grpcapi ./pkg/cli ./cmd/cli -count=1

---

## PR #643 — monitor: include userspace ingress in interface traffic [MERGED] (merged 2026-04-13)

Branch: `pr/monitor-interface-userspace-rx-fix`

## Summary
- merge userspace RX as well as TX into monitor interface traffic counters
- keep per-interface delta/rate calculations aligned with the merged userspace view
- add regressions for ingress-only and egress-only userspace rows

## Validation
- go test ./pkg/monitoriface ./pkg/cli -count=1

## Root cause
Live userspace binding stats on `loss:bpfrx-userspace-fw0` showed `ge-0-0-1` carrying the ingress side and `ge-0-0-2` carrying the egress side, while the monitor summary only folded in helper TX counters. The interface/BPF counters for those rows remained tiny, so `reth1` stayed near zero even though XSK RX was busy.


---

## PR #644 — docs: refresh vSRX parity gaps from PDFs [MERGED] (merged 2026-04-13)

Branch: `pr/vsrx-gap-refresh-from-pdfs`

## Summary
- refresh the vSRX parity docs from the consolidated deployment, user, and datasheet PDFs
- add the untracked PDF-backed gaps for JTI, AppQoE, cloud-init/bootstrap ISO, and remote-access IPsec VPN
- broaden the Geneve row to cover the documented Geneve flow infrastructure and AWS GWLB behavior
- tighten completeness notes for partially implemented areas, including CoS wording and existing partial-parity rows
- sync `docs/authoritative-backlog.md` so these are no longer listed as untracked candidate gaps

## Validation
- `git diff --check`


---

## PR #646 — docs: propose explicit Twice NAT parity work [MERGED] (merged 2026-04-13)

Branch: `pr/twice-nat-parity-proposal`

## Summary
- add a dedicated Twice NAT proposal doc tied to #645
- update the stale Twice NAT gap row to reflect existing userspace merge plumbing
- track the remaining parity/validation work in the authoritative backlog

## Why
The repo already has userspace building blocks for combined SNAT+DNAT, so the real gap is explicit support definition and end-to-end / HA validation rather than a blank implementation area.

## Validation
- `git diff --check`

Closes #645 only after the actual implementation/validation work lands; this PR just captures the proposal and tracking updates.

---

## PR #647 — twice-nat: enforce zone-aware dnat parity [MERGED] (merged 2026-04-14)

Branch: `pr/twice-nat-completeness`

Fixes #645

This finishes the main Twice NAT parity gaps across the supported dataplanes:
- make static DNAT lookup zone-aware in eBPF, DPDK, and userspace
- keep dynamic SNAT return-path DNAT entries wildcarded by zone
- match post-DNAT SNAT against the translated destination in userspace
- preserve both NAT legs in gRPC/session visibility and session-sync tests

Validation:
- go test ./pkg/dataplane ./pkg/conntrack ./pkg/cluster ./pkg/grpcapi ./pkg/dataplane/userspace -count=1
- cargo test --manifest-path userspace-dp/Cargo.toml dnat_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml post_dnat_source_nat_matches_translated_destination -- --nocapture

---

## PR #649 — services: tighten rpm probe config support [MERGED] (merged 2026-04-13)

Branch: `pr/rpm-tightening`

## Summary
- expand the RPM schema/help tree to match the probe/test syntax the compiler already supports
- tighten RPM compile-time validation so missing targets, unsupported probe types, and bad numeric values fail early
- improve local and remote `show services rpm` config fallback so it shows the effective probe settings instead of a partial stub

## Details
- centralize RPM default handling on `RPMTest` helper methods and use those defaults in the runtime and operational output
- add explicit completion coverage for the RPM subtree
- add config tests for default behavior and validation failures
- keep the deeper vSRX parity gaps tracked separately in #648

## Validation
- `git diff --check`
- `go test ./pkg/config ./pkg/rpm ./pkg/cli ./pkg/grpcapi -count=1`


---

## PR #655 — services: inherit root rpm probe-limit [MERGED] (merged 2026-04-14)

Branch: `pr/rpm-root-probe-limit`

Fixes #142\n\nThis wires top-level services rpm { probe-limit N; } into the existing per-test RPM behavior instead of silently dropping it. Tests without an explicit probe-limit now inherit the root value, while per-test overrides still win.\n\nValidation:\n- go test ./pkg/config ./pkg/grpcapi -count=1

---

## PR #656 — config: reject persist-groups-inheritance [MERGED] (merged 2026-04-14)

Branch: `pr/commit-persist-groups-reject`

Fixes #650\n\nThis stops silently dropping system commit persist-groups-inheritance. The compiler now fails explicitly when that Junos-only knob is present, which keeps imported configs honest instead of pretending the behavior exists.\n\nValidation:\n- go test ./pkg/config -count=1

---

## PR #657 — config: reject unsupported flow export app-id [MERGED] (merged 2026-04-14)

Branch: `pr/flow-export-appid-reject`

Fixes #144

This narrows flow-monitoring export-extension handling to what runtime actually supports. `flow-dir` remains supported; `app-id` is now rejected at compile time for both NetFlow v9 and IPFIX templates instead of compiling with a misleading warning.

Validation:
- go test ./pkg/config ./pkg/flowexport -count=1

---

## PR #658 — config: reject unsupported dns-proxy subtree [CLOSED] (closed 2026-04-14)

Branch: `pr/dns-proxy-reject`

Fixes #652

This keeps `system services dns;` as the existing service toggle, but rejects `system services dns { dns-proxy { ... } }` explicitly so imported vSRX config cannot look supported when it is not.

Validation:
- go test ./pkg/config -count=1

---

## PR #659 — config: accept unsupported vSRX syntax with warnings [MERGED] (merged 2026-04-14)

Branch: `pr/vsrx-syntax-noop-warnings`

Fixes #650
Fixes #652

This follow-up changes the import-compatibility policy for vSRX config:
- accept unsupported vSRX syntax as compile-time no-op state instead of rejecting it
- emit explicit warnings so operators still see that behavior is not implemented

Included in this change:
- `system commit persist-groups-inheritance` compiles and warns instead of failing
- `system services dns dns-proxy` compiles and warns instead of failing
- `services flow-monitoring ... export-extension app-id` compiles and warns instead of failing
- generic `CompileConfig()` now falls back to `node0` for `apply-groups "${node}"` and warns
- lexer accepts the SSH/base64/comma tokens present in `vsrx.conf`

Validation:
- go test ./pkg/config -count=1
- go test ./pkg/config -run TestCompileLocalVsrxConf -count=1 -v

This supersedes the reject-based direction from #656 and #658 and aligns import behavior with the requirement that vSRX config should load even when some features are runtime no-ops.

---

## PR #661 — docs: add dns-proxy runtime plan [MERGED] (merged 2026-04-14)

Branch: `pr/dns-proxy-runtime-plan`

Refs #660

Adds a detailed feature design for real firewall-side DNS proxy support, including:
- why `systemd-resolved` is not sufficient
- recommended runtime direction (`unbound`)
- host resolver vs client-facing DNS proxy split
- phased implementation plan
- acceptance criteria and HA/runtime concerns

Also links the work from `docs/authoritative-backlog.md`.

Validation:
- git diff --check

---

## PR #662 — cluster: gate HA transfer on protocol compatibility [MERGED] (merged 2026-04-14)

Branch: `pr/ha-protocol-compat`

Fixes #641

## Summary
- advertise an explicit HA protocol compatibility version in cluster heartbeat
- gate userspace transfer readiness on HA protocol compatibility instead of software build string equality
- keep software version strings as status/information metadata only
- treat heartbeats from older daemons that do not advertise the field as the legacy compatibility version

## Why
Rolling upgrades were blocked by `Transfer ready: no (software version mismatch ...)` even when heartbeat/session-sync/failover wire behavior had not changed. The readiness contract should follow protocol compatibility, not build-label drift.

## Implementation
- add `HAProtocolVersion` to the optional heartbeat trailer without changing the existing heartbeat wire version byte
- reserve space for the field during marshal so monitor truncation does not drop compatibility metadata
- default missing peer values to `LegacyHAProtocolVersion` for backward compatibility with older heartbeats
- surface local/peer HA protocol versions in cluster status/information output
- switch userspace transfer readiness mismatch reporting to `ha protocol mismatch local=X peer=Y`

## Validation
- `go test ./pkg/cluster ./pkg/daemon -count=1`


---

## PR #663 — userspace-dp: add phase 1 class-of-service shaping [MERGED] (merged 2026-04-14)

Branch: `pr/cos-phase1-shaper`

## Summary
- add Phase 1 `class-of-service` parsing/compiler/types for forwarding classes, schedulers, scheduler-maps, and interface shaping
- propagate CoS config into the userspace snapshot and implement userspace egress queue selection plus shaped per-interface TX scheduling
- update the parity docs to reflect that bpfrx now has a userspace-only Phase 1 CoS implementation rather than a fully missing feature set

## Scope
This is the documented Phase 1 cut from `docs/cos-traffic-shaping.md`:
- userspace-only
- egress-only
- one shaped root per interface
- one FIFO container per forwarding class / reservation
- forwarding-class classification via existing firewall filter actions
- scheduler-map driven queue selection and interface shaping

This does **not** try to claim full Junos CoS parity yet:
- no BA classifiers
- no WRED
- no richer Junos scheduler/drop-profile model
- no multi-shard ownership/timer-wheel work yet

## Validation
- `go test ./pkg/config ./pkg/dataplane/userspace -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml resolve_cos_queue_id -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `git diff --check`


---

## PR #664 — rename: bpfrx -> xpf across entire codebase [MERGED] (merged 2026-04-14)

Branch: `pr/rename-bpfrx-to-xpf`

## Summary
- Rename the project from bpfrx to xpf throughout the entire codebase
- Add deploy-time migration for existing VMs with old bpfrxd service
- Add standalone migration script for manual use on deployed systems

## Scope

**Content replacement** (352 files, 4516 lines):
- Go module: `github.com/psaab/bpfrx` -> `github.com/psaab/xpf`
- Daemon binary: `bpfrxd` -> `xpfd`
- Rust crate: `bpfrx-userspace-dp` -> `xpf-userspace-dp`
- Config directory: `/etc/bpfrx/` -> `/etc/xpf/`
- All code, configs, docs, tests, scripts, proto, CLAUDE.md

**File renames** (44 files):
- BPF headers: `bpfrx_*.h` -> `xpf_*.h`
- bpf2go bindings: `bpfrx{tc,xdp}*_x86_bpfel.{go,o}` -> `xpf{tc,xdp}*`
- Proto: `proto/bpfrx/v1/bpfrx.proto` -> `proto/xpf/v1/xpf.proto`
- gRPC: `pkg/grpcapi/bpfrxv1/` -> `pkg/grpcapi/xpfv1/`
- Test configs: `test/incus/bpfrx-*.conf` -> `test/incus/xpf-*.conf`
- Systemd unit: `bpfrxd.service` -> `xpfd.service`
- Daemon cmd: `cmd/bpfrxd/` -> `cmd/xpfd/`

**Deploy migration** (automatic on next deploy):
- `setup.sh` and `cluster-setup.sh` deploy functions now stop/disable/remove old `bpfrxd.service`, remove `/usr/local/sbin/bpfrxd`, and rename `/etc/bpfrx` -> `/etc/xpf` before installing `xpfd`

**Standalone migration script** (`scripts/migrate-bpfrx-to-xpf.sh`):
- Stops old service, cleans BPF state, removes old binaries
- Renames config dir, networkd files, CLI history
- Cleans up old nftables table
- Enables new xpfd service

## Validation
- `go build ./cmd/xpfd/` compiles clean
- `cargo check` (Rust userspace-dp) compiles clean

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #665 — build: repair native xpf generated artifacts [MERGED] (merged 2026-04-14)

Branch: `pr/xpf-native-build-repair`

## Summary
- regenerate the renamed xpf protobuf bindings so native `xpfd` and `cli` no longer panic during proto init
- regenerate the renamed eBPF objects/bpf2go bindings and fix stale `loadBpfrx...` loader references that still pointed at pre-rename symbols
- restore a clean native xpf build/deploy path for `xpfd` and `xpf-userspace-dp`

## Why
The xpf rename left the repo in a state where freshly built binaries were not deployable:
- generated protobuf bindings under `pkg/grpcapi/xpfv1/` were corrupted and caused immediate startup panics
- generated eBPF objects/bindings under `pkg/dataplane/` were corrupted
- `pkg/dataplane/loader_ebpf.go` still referenced stale `loadBpfrx...` symbols after regeneration

This is the exact repair set required to make the live binary migration on `xpf-userspace-fw0/1` work with real native xpf binaries instead of wrappers.

## Validation
- `make build build-ctl`
- `go test ./pkg/dataplane/... ./pkg/grpcapi/... -count=1`
- `./xpfd -h`
- `./cli -h`
- live rollout to `xpf-userspace-fw0/1` using real native binaries:
  - `/usr/local/sbin/xpfd`
  - `/usr/local/sbin/xpf-userspace-dp`
  - `/run/xpf/userspace-dp.sock`
  - `/run/xpf/userspace-dp-sessions.sock`
  - `/run/xpf/userspace-dp.json`
- post-rollout cluster state healthy on both nodes with `Takeover ready: yes` and `Transfer ready: yes`


---

## PR #666 — userspace-dp: add CoS timer-wheel wakeups [MERGED] (merged 2026-04-14)

Branch: `pr/cos-timer-wheel-userspace`

## Summary
- add queue-level timer-wheel deferred eligibility to the userspace CoS shaper
- park backlogged but ineligible CoS queues instead of rescanning them every scheduler poll
- update the CoS gap note to reflect timer-wheel wakeups in the userspace shaping path

## Scope
This is the next userspace CoS step after the Phase 1 FIFO-per-class shaper.

It intentionally stays within the current queue-based runtime model:
- userspace only
- egress only
- queue-level park/wake semantics
- not the later full reservation/container hierarchy yet

## What changed
- extend `CoSInterfaceRuntime` / `CoSQueueRuntime` with runnable/parked wake state and a two-level per-interface timer wheel
- estimate earliest eligible wake ticks from root and queue token deficits
- advance the timer wheel on each shaped TX scheduler pass
- park ineligible queues and wake them back into the runnable set when due
- add focused Rust regressions for short wakes, long cascaded wakes, and wake-tick calculation

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml timer_wheel_wakes_short_parked_queue -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml timer_wheel_cascades_long_parked_queue -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml estimate_cos_queue_wakeup_tick_uses_token_deficits -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml resolve_cos_queue_id -- --nocapture`


---

## PR #667 — userspace-dp: classify CoS queues from egress filters [MERGED] (merged 2026-04-14)

Branch: `pr/cos-egress-filter-classification`

## Summary
- teach the userspace snapshot/protocol to carry per-interface output filters
- make CoS queue selection prefer the shaped egress output filter with ingress-input fallback
- update the CoS test recipe docs and add Go/Rust regressions

## Validation
- go test ./pkg/dataplane/userspace -count=1
- cargo test --manifest-path userspace-dp/Cargo.toml interface_filter_assignment -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml resolve_cos_queue_id_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture
- git diff --check

---

## PR #668 — userspace-dp: add CoS guarantee and surplus scheduling [MERGED] (merged 2026-04-14)

Branch: `pr/cos-guarantee-surplus-exact`

## Summary
- carry `transmit-rate exact` from config into the userspace CoS snapshot
- treat ordinary `transmit-rate` as a guarantee and add a surplus-borrow phase for non-`exact` queues
- update CoS docs and feature-gap notes to match the new userspace behavior

## Validation
- `go test ./pkg/config ./pkg/dataplane/userspace -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml resolve_cos_queue_id_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml surplus_phase_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml estimate_cos_queue_wakeup_tick_ -- --nocapture`
- `git diff --check`

---

## PR #669 — userspace: add CoS interface runtime observability [MERGED] (merged 2026-04-14)

Branch: `pr/cos-interface-observability`

## Summary
- export worker-local CoS queue runtime into helper status snapshots
- replace the old class-of-service filter dump with a shared local/remote formatter
- support `show class-of-service interface [IFACE[.UNIT]]` with config plus live userspace queue state

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml build_worker_cos_statuses_aggregates_runtime_by_interface_and_queue -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml resolve_cos_queue_id_ -- --nocapture`
- `go test ./pkg/dataplane/userspace ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `git diff --check`

---

## PR #670 — userspace: add CoS owner-worker handoff [MERGED] (merged 2026-04-14)

Branch: `pr/cos-owner-worker-handoff`

## Summary
- add a first Phase 4 CoS slice: one static owner worker per shaped egress interface
- hand shaped traffic from non-owner workers to the owner before CoS queue admission
- update CoS docs/gap notes to reflect the implemented owner-worker model

## Details
This does not attempt full many-core leasing yet. It implements the first concrete step from the CoS plan:
- the coordinator derives an owner worker for each shaped egress interface from the TX binding map
- non-owner workers redirect shaped `TxRequest`s to that owner worker
- prepared shaped frames on a non-owner worker are copied back into a local `TxRequest`, redirected, and the original prepared frame is recycled locally
- owner workers enqueue the handed-off traffic into the existing CoS queueing/scheduling path

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_owner_worker_by_ifindex_prefers_lowest_worker_with_tx_binding -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml redirect_local_cos_request_to_owner_pushes_worker_command -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_worker_cos_statuses_aggregates_runtime_by_interface_and_queue -- --nocapture`
- `go test ./pkg/dataplane/userspace ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `git diff --check`


---

## PR #671 — userspace: spread static CoS owners across workers [MERGED] (merged 2026-04-14)

Branch: `pr/cos-owner-spread-status`

## Summary
- spread static CoS interface ownership across eligible workers on the same TX path
- expose the chosen owner worker in `show class-of-service interface`
- update the CoS docs/gap note to reflect the stronger static ownership model

## Details
This is still the static-ownership part of Phase 4, not shared-budget leasing.

The coordinator now assigns shaped egress interfaces deterministically across the workers that can transmit on the resolved TX binding, instead of always pinning every such interface to the lowest worker. That keeps one owner per shaped interface, but avoids piling every shaped interface on the same worker when several share the same TX path.

The merged CoS runtime status now includes `owner_worker_id`, and the CLI summary shows it so the static ownership decision is visible during testing.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_owner_worker_by_ifindex_ -- --nocapture`
- `go test ./pkg/dataplane/userspace ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `git diff --check`


---

## PR #672 — cos: add userspace dscp classifier attachment [MERGED] (merged 2026-04-14)

Branch: `pr/cos-dscp-classifiers`

## Summary
- add `class-of-service classifiers dscp ...` parsing plus interface `classifiers dscp <name>` attachment
- carry DSCP classifier definitions through the userspace snapshot/runtime and use them as a fallback CoS queue selector when filters do not set a forwarding class
- accept decimal CoS bandwidth syntax used by live configs such as `10.0g` and `12.5g`, and keep interface-only CoS configs from being dropped from the snapshot
- tighten CoS exact-budget handling on shared TX paths and fix userspace firewall-filter observability for `show firewall filter ... family inet6`

## Validation
- `go test ./pkg/config ./pkg/dataplane/userspace ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml resolve_cos_queue_id_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml interface_output_filter_counted_records_term_hits -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml redirect_local_cos_request_to_owner_binding_pushes_owner_live_queue -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state_binds_dscp_classifier_to_usable_interface_queue_ids -- --nocapture`
- `git diff --check`

## Live Validation
- binary-only rollout to `xpf-userspace-fw0/1` on build `userspace-forwarding-ok-20260402-bfb00432-472-g097d57c5` to preserve the live CoS test config
- `show firewall filter bandwidth-output family inet6` now resolves the real `inet6` filter instead of the `inet` filter with the same name
- after a 5s IPv6 `iperf3 -c 2001:559:8585:80::200 -p 5201 -P 4 -t 5`, term `0` reported `179327 packets, 271465458 bytes`
- HA remained healthy during the skewed rollout and after both nodes converged on the same build

## Scope Notes
- userspace-only
- DSCP classifiers act as a fallback after explicit firewall filter `then forwarding-class ...` decisions
- `loss-priority` on CoS DSCP classifiers is accepted for syntax compatibility but is not enforced yet
- 802.1p BA classifiers are still not implemented
- this PR now includes validation-driven follow-up fixes discovered while exercising the DSCP classifier path: decimal CoS bandwidth parsing, exact-budget centralization on shared TX paths, and userspace firewall-filter counter/family fixes


---

## PR #673 — cos: add userspace 802.1p classifiers [MERGED] (merged 2026-04-14)

Branch: `pr/cos-8021p-classifiers`

## Summary
- add `class-of-service classifiers ieee-802.1 ...` parsing, compiler support, and unit attachment
- preserve ingress VLAN PCP and explicit VLAN-header presence through XDP metadata and use the attached 802.1p classifier as a CoS queue-selection fallback in the userspace dataplane
- surface the classifier in userspace CoS observability and update the CoS docs / feature-gap notes

## Scope
- userspace dataplane only
- DSCP / firewall filter forwarding-class still take precedence over 802.1p fallback classification
- 802.1p fallback applies only to tagged ingress traffic; untagged packets do not implicitly match PCP 0
- priority-tagged frames (VID 0) retain VLAN-header presence and remain eligible for 802.1p fallback classification
- `loss-priority` is still syntax-only and not enforced yet
- 802.1p rewrite / remarking is not implemented in this change

## Validation
- `go generate ./pkg/dataplane/...`
- `go test ./pkg/config ./pkg/dataplane/userspace ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml ieee8021_classifier -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state_binds_dscp_classifier_to_usable_interface_queue_ids -- --nocapture`
- `git diff --check`


---

## PR #674 — cos: add userspace dscp rewrite-rules [MERGED] (merged 2026-04-15)

Branch: `pr/cos-dscp-rewrite-rules`

## Summary
- add `class-of-service rewrite-rules dscp ...` parsing and userspace snapshot support
- attach DSCP rewrite-rules on shaped userspace egress interfaces and map them onto CoS queues by forwarding-class
- apply queue-level DSCP rewrite as a fallback behind explicit firewall-filter DSCP rewrite actions
- update CoS docs and feature-gap status for userspace DSCP rewrite-rule support

## Validation
- `go test ./pkg/config ./pkg/dataplane/userspace ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml resolve_cos_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_dscp_rewrite_to_ -- --nocapture`
- `git diff --check`


---

## PR #676 — cos: finish userspace phase 3 scheduling [MERGED] (merged 2026-04-15)

Branch: `pr/cos-phase3-fairness`

## Summary
- bound guarantee-phase service to a per-visit CIR quantum instead of draining an entire queue turn
- add explicit regressions for guarantee rotation, strict surplus priority, and same-priority weighted sharing
- refresh the CoS implementation docs/status to mark Phase 3 complete in the userspace path

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml guarantee_phase_limits_service_to_visit_quantum -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml guarantee_phase_rotates_between_backlogged_queues -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml surplus_phase_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `git diff --check`

---

## PR #677 — cos: complete phase 4 userspace leasing [MERGED] (merged 2026-04-15)

Branch: `pr/cos-phase4-leasing`

## Summary
- complete the current userspace Phase 4 CoS slice with deterministic queue ownership across eligible workers
- add shared root-budget leasing so shaped interfaces can safely share bandwidth across queue owners
- fix the userspace XDP metadata layout drift that broke forwarding after the queue-owner/lease work landed
- surface queue-level owner worker information in CoS status and update the CoS docs/gap text to mark Phase 4 complete for userspace

## Details
- replace interface-level CoS owner maps with `(egress_ifindex, queue_id)` ownership maps
- build shared root lease state per shaped interface and hand it to workers through the coordinator
- redirect shaped packets to the owning worker before local owner-binding enqueue so same-worker binding redirects do not bypass CoS ownership
- release unused root lease credit on reload, drain, and empty-queue transitions
- expose queue owner worker IDs in the userspace status schema and CLI formatter
- restore `UserspaceDpMeta` layout compatibility between `userspace-xdp` and `xpf-userspace-dp` by reintroducing VLAN-presence/PCP fields and adding compile-time size/offset assertions on both sides of the wire format

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml shared_cos_root_lease_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_shared_cos_root_leases_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml guarantee_phase_limits_service_to_visit_quantum -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml guarantee_phase_rotates_between_backlogged_queues -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_owner_worker_by_queue_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml redirect_local_cos_request_to_owner_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo +nightly build --release` in `userspace-xdp`
- `bash pkg/dataplane/build-userspace-xdp.sh`
- `make build build-userspace-dp`
- `go test ./pkg/dataplane/userspace ./pkg/cli ./pkg/grpcapi ./cmd/cli -count=1`
- `git diff --check`
- clean binary-only rollout of exact PR head `47cd9891` to `xpf-userspace-fw0/1`
- live forwarding validation from `cluster-userspace-host`:
  - IPv4 ping to `172.16.80.200`: `3/3`
  - IPv6 ping to `2001:559:8585:80::200`: `3/3`
  - IPv4 `iperf3 -t 5 -P 2`: about `449 Mbit/s` sender / `440 Mbit/s` receiver
  - IPv6 `iperf3 -t 5 -P 2`: about `568 Mbit/s` sender / `558 Mbit/s` receiver


---

## PR #679 — userspace-dp: cut hot-path CPU overhead [MERGED] (merged 2026-04-16)

Branch: `pr/userspace-perf-hotpath-cuts`

## Summary

This PR cuts the hot-path CPU overhead that showed up after the recent userspace dataplane CoS work and restores the no-CoS fast path to the expected throughput band.

It includes:

- hot-path filter lookup and match reductions
- precomputed ingress logical-interface lookup
- reduced TX-selection work when CoS / filter state cannot affect the packet
- lower-overhead pending-forward request handling
- smaller flow-cache fallback overhead by reusing precomputed `expected_ports` and `target_binding_index`
- exact CoS queue correctness hardening: when an exact queue first falls back to a local item, already-queued prepared items are demoted to local and their TX frames are recycled immediately
- an engineering note in `docs/userspace-dataplane-perf-hotspots.md`

Remaining perf tail work is tracked separately in `#678`.

## Validation

Local:

- `cargo test --manifest-path userspace-dp/Cargo.toml build_live_forward_request_from_frame_uses_precomputed_hints -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml demote_prepared_cos_queue_to_local_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml cos_queue_accepts_prepared_ -- --nocapture`
- `make build-userspace-dp`
- `git diff --check`

Live on the `loss` userspace HA cluster with helper-only rollouts preserving `/etc/xpf/xpf.conf` and `/etc/xpf/.configdb`:

- `./scripts/userspace-perf-compare.sh --duration 8 --parallel 12`
- IPv4: `23.02 Gbps`
- IPv6: `22.77 Gbps`
- helper hash on `xpf-userspace-fw0/1`: `8ec95142d5093be59558a035947f71b2dbb2301fff8f724d6234c7361582f88c`
- `iperf3 -c 2001:559:8585:80::200 -t 20 -P 12 -p 5202`
- exact `5202` queue completed cleanly at `9.45 Gbits/sec`; the earlier zero-throughput hang is fixed, but throughput is still capped well below the desired `10g exact` target

Representative remaining hot symbols after the perf slice:

- IPv4: `poll_binding` ~13.4%, `enqueue_pending_forwards` ~4.3%
- IPv6: `poll_binding` ~13.3%, `enqueue_pending_forwards` ~3.7%, `apply_nat_ipv6` ~3.2%

Remaining exact-queue work is architectural rather than another small fast-path tweak: the current exact queue service still behaves like a single-owner / single-frame-pool design.


---

## PR #682 — userspace-dp: share exact CoS queues across workers [MERGED] (merged 2026-04-16)

Branch: `pr/cos-shared-exact-queue-service`

## Summary

This implements the core architecture from #680.

The exact CoS queue path no longer collapses into single-owner execution when multiple eligible workers already have a valid local TX path for the shaped egress interface.

The implementation does three things together:

- introduces authoritative shared exact-queue lease state per egress interface and queue id
- keeps exact queue execution on the local worker when that worker already has a valid TX path
- derives default exact queue burst from the scheduler rate instead of inheriting the root shaper burst directly

The result is that exact queue service is now sharded across eligible workers instead of being funneled through one logical owner / frame pool.

## What Changed

- added `SharedCoSQueueLease` and coordinator plumbing for exact queues
- compute active shard counts per shaped egress interface and build shared queue/root leases from that view
- allow exact queues to execute locally on workers with a valid TX path instead of cross-worker redirecting by default
- keep non-exact queue behavior on the existing local-token model
- start exact queue runtimes with zero local tokens and top them up from the shared queue lease
- return unused exact queue credit when queues drain or bindings refresh
- derive default exact queue burst from the queue scheduler rate, capped by the root burst

## Correctness Notes

- root shaping remains shared
- exact queue shaping is now also shared and authoritative across eligible workers
- the existing mixed exact queue demotion safety belt from `a736d010` remains in place
- this does **not** try to solve the separate best-effort / exact enforcement semantics tracked in #681

## Validation

### Local

```bash
cargo fmt --manifest-path userspace-dp/Cargo.toml
cargo test --manifest-path userspace-dp/Cargo.toml shared_cos_queue_lease_bounds_total_outstanding_credit -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml build_shared_cos_queue_leases_only_tracks_exact_queues -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml build_shared_cos_queue_leases_reuses_existing_matching_lease_arc -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml refresh_cos_owner_worker_map_from_binding_statuses_keeps_shared_arcs_when_unchanged -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state_derives_default_exact_queue_burst_from_scheduler_rate -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml redirect_local_cos_request_to_owner_keeps_exact_queue_on_eligible_worker -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml maybe_top_up_cos_queue_lease_unblocks_large_frame_exceeding_lease_bytes -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml build_cos_owner_worker_by_queue_ -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml guarantee_phase_ -- --nocapture
cargo test --manifest-path userspace-dp/Cargo.toml --no-run
git diff --check
```


*(truncated — 82 lines total)*


---

## PR #684 — userspace-dp: flatten exact CoS hot path [MERGED] (merged 2026-04-16)

Branch: `pr/cos-exact-hotpath-flatten`

## Summary
- replace mutex-backed shared exact CoS lease state with packed atomic lease state
- publish worker-local flattened CoS fast-path metadata for queue owner/live/root lease lookups
- rewire exact CoS redirect, scheduler, and shaped-worker enqueue paths to use the flattened metadata instead of tree lookups
- preserve explicit queue-id semantics by treating an explicit queue miss as a miss, not a default-queue fallback

## Validation
- cargo test --manifest-path userspace-dp/Cargo.toml --no-run
- cargo test --manifest-path userspace-dp/Cargo.toml shared_cos_root_lease_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml redirect_local_cos_request_to_owner_ -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml build_worker_cos_fast_interfaces_flattens_owner_and_lease_state -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml maybe_top_up_cos_queue_lease_unblocks_local_exact_queue_without_tokens -- --nocapture
- cargo test --manifest-path userspace-dp/Cargo.toml shared_exact_queue_lease_uses_ -- --nocapture
- cargo fmt --manifest-path userspace-dp/Cargo.toml
- git diff --check

Closes #683

---

## PR #686 — userspace-dp: make exact CoS queue enforcement authoritative [MERGED] (merged 2026-04-16)

Branch: `pr/cos-exact-enforcement`

## Summary
- derive default exact queue burst from the scheduler queue rate instead of inheriting the parent interface shaper burst
- stop exact queues from silently falling back to local per-runtime token refill when the shared queue lease is unavailable
- add focused regressions for scheduler-rate-derived exact burst sizing and for exact queues refusing local refill without a shared lease

Closes #681.

## Why
The old behavior had two semantic problems:
- an exact queue with no explicit buffer inherited the interface shaper burst, which let a low-rate exact queue start with a budget sized for the much larger parent shaper
- exact queue service could still degrade into local refill if the shared lease was absent, which breaks the idea that exact queue rate is authoritative and shared

This slice makes the queue contract tighter:
- exact queue default burst now tracks queue rate
- exact queue refill is authoritative through the shared queue lease path only

## Files
- `userspace-dp/src/afxdp/forwarding_build.rs`
- `userspace-dp/src/afxdp/tx.rs`

## Focused tests
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state_derives_exact_queue_default_burst_from_queue_rate -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml exact_queue_without_shared_lease_does_not_locally_refill -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml maybe_top_up_cos_queue_lease_unblocks_local_exact_queue_without_tokens -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml shared_cos_queue_lease_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml redirect_local_cos_request_to_owner_keeps_exact_queue_on_eligible_worker -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo fmt --manifest-path userspace-dp/Cargo.toml`
- `git diff --check`

## Live rollout
Helper-only rollout to the isolated loss userspace HA cluster:
- deployed `/usr/local/sbin/xpf-userspace-dp` only
- preserved `/etc/xpf/xpf.conf`
- preserved `/etc/xpf/.configdb`
- restarted secondary first, then primary
- deployed helper SHA: `d4c9306c14688dc1f62379c0d2709a3713475635eda632cd47fa332b4704a676`

## Live validation
Configured CoS contract on `reth0.80`:
- `5201` -> `iperf-a` -> `1g exact`
- `5202` -> `iperf-b` -> `10g exact`
- `5203` -> `best-effort` -> `100m exact`

Runtime CoS state after rollout:
- queue 0 buffer: `122.07 KiB` at `100 Mb/s`
- queue 4 buffer: `1.19 MiB` at `1 Gb/s`
- queue 5 buffer: `11.92 MiB` at `10 Gb/s`


*(truncated — 84 lines total)*


---

## PR #687 — userspace-dp: drain exact CoS queues directly [MERGED] (merged 2026-04-16)

Branch: `pr/cos-direct-exact-drain`

## Summary
- fix #685 by bypassing transient `CoSBatch` materialization for exact guarantee queues
- drain exact local/prepared queue heads directly into the existing TX scratch vectors and submit from scratch
- restore only the unsent tail back to the CoS queue head after partial ring insertion instead of rebuilding a batch container
- fix the direct prepared-path drop case so invalid/oversized prepared frames are recycled immediately instead of being lost

## Code
- `userspace-dp/src/afxdp/tx.rs`
  - split exact guarantee selection from the non-exact batch path
  - added direct exact local/prepared queue service helpers
  - kept non-exact/surplus service on the existing `CoSBatch` path
  - added regressions for exact scratch drain ordering and prepared-drop recycle behavior

## Validation
### Rust
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml drain_exact_ -- --nocapture`
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml settle_exact_ -- --nocapture`
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml maybe_top_up_cos_queue_lease_ -- --nocapture`
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml exact_queue_without_shared_lease_ -- --nocapture`
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml prepared_cos_request_stays_on_current_tx_binding_ -- --nocapture`
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml build_cos_state -- --nocapture`
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml guarantee_phase_ -- --nocapture`
- `cargo test --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml --no-run`
- `cargo fmt --manifest-path /tmp/xpf-685/userspace-dp/Cargo.toml`
- `git -C /tmp/xpf-685 diff --check`
- `make -C /tmp/xpf-685 build-userspace-dp`

### Helper-only rollout
- rolled `/tmp/xpf-685/xpf-userspace-dp` to `loss:xpf-userspace-fw1` then `loss:xpf-userspace-fw0`
- preserved `/etc/xpf/xpf.conf`
- preserved `/etc/xpf/.configdb`
- deployed helper sha256: `aa9df922439e93405824530ba5b45469bd62cc7e7815a4793de6f0ffd8ebacde`
- HA recovered cleanly with `Takeover ready: yes` / `Transfer ready: yes`

### Live CoS validation
Two separate agents ran the IPv4 and IPv6 `iperf3` matrices and only reported findings back to the coordinator.

IPv4 agent:
- `5201` exact 1G: `962 / 955 Mbit/s`, `86` retransmits
- `5202` exact 10G: `9.57 / 9.54 Gbit/s`, `550` retransmits
- `5203` best-effort 100M short: `96.3 / 95.3 Mbit/s`, `28` retransmits

IPv6 agent:
- `5201` exact 1G: `949 / 942 Mbit/s`, `86` retransmits
- `5202` exact 10G: `9.41 / 9.39 Gbit/s`, `25842` retransmits

Note on the low 30s `5203` runs from the parallel matrix: they overlapped cross-family best-effort traffic. A coordinator follow-up running IPv4 `5203` and IPv6 `5203` together held about `48.0 + 47.3 = 95.3 Mbit/s` aggregate, which is consistent with a shared `100m exact` best-effort queue budget rather than a rate-enforcement miss.

### Coordinator-side perf on exact path
Serial perf captures on the active firewall during `5202` runs:

*(truncated — 68 lines total)*


---

## PR #692 — userspace-dp: add fair service for low-rate exact CoS queues [MERGED] (merged 2026-04-16)

Branch: `pr/cos-5201-flow-fairness`

## Summary
- add hashed per-flow round-robin service for low-rate owner-local exact CoS queues
- keep the earlier per-flow backlog admission guard, but stop treating the queue as a single FIFO once packets are admitted
- leave the high-rate shared exact path unchanged so `5202` stays on the existing fast path

## Root Cause
`5201` was still using a single FIFO inside the low-rate exact queue. Even after fixing rate enforcement and owner-local placement, one flow could occupy the head of the queue for too long and the rest of the TCP fanout would only see tail-drop fairness, not service fairness.

That showed up live as:
- IPv4 `5201`: `1.019 / 1.015 Gbit/s`, retrans `88549`, per-stream `min/max/avg 0.032/0.235/0.085`, ratio `7.283`

The correct fix was not another token tweak. The queue discipline itself needed to become flow-aware on the low-rate owner-local exact path.

## Implementation
- extend `CoSQueueRuntime` with hashed flow buckets and a round-robin bucket ring
- use the existing flow key to map packets into per-flow buckets
- preserve FIFO inside each flow bucket
- dequeue low-rate exact work in bucket round-robin order
- keep the flow-share admission guard so one bucket cannot consume the whole queue backlog
- keep high-rate shared exact queues on the existing queue structure and fast path
- update reset/status/demotion paths so they operate correctly on both FIFO and fair-bucket queues

## Validation
Unit / build:
- `cargo test --manifest-path userspace-dp/Cargo.toml flow_fair_queue_round_robins_distinct_local_flows -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml flow_fair_queue_round_robins_distinct_prepared_flows -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml flow_fair_exact_queue_limits_dominant_flow_share -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml cos_queue_push_and_pop_track_flow_bucket_bytes -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml drain_exact_local_items_to_scratch_stops_before_prepared_tail -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo fmt --manifest-path userspace-dp/Cargo.toml`
- `git diff --check`
- `make build-userspace-dp`

Live rollout:
- helper-only rollout to `xpf-userspace-fw1` then `xpf-userspace-fw0`
- config preserved on both nodes
- helper SHA `b1e2d993ec10c4c44c8f0536f4adaff392816ce1d1e07d2044a71a7597c44431`

Live port matrix:
- IPv4 `5201`: `1.036 / 1.034 Gbit/s`, retrans `148560`, per-stream `min/max/avg 0.050/0.103/0.086`, ratio `2.057`
- IPv4 `5202`: `9.533 / 9.518 Gbit/s`, retrans `43012`
- IPv4 `5203`: `0.103 / 0.103 Gbit/s`, retrans `14416`
- IPv6 `5201` repeat: `1.042 / 1.041 Gbit/s`, retrans `213359`, per-stream `min/max/avg 0.073/0.098/0.087`, ratio `1.34`
- IPv6 `5202`: `9.388 / 9.372 Gbit/s`, retrans `68831`
- IPv6 `5203`: `0.098 / 0.098 Gbit/s`, retrans `7356`

Perf samples after the slice:
- IPv4 `5201`: `worker_loop 24.37%`, `poll_binding 13.31%`, `drain_pending_tx 2.23%`
- IPv4 `5202`: `memmove 14.54%`, `drain_pending_tx 11.41%`, `poll_binding 9.36%`, `drain_shaped_tx 4.06%`

*(truncated — 56 lines total)*


---

## PR #695 — userspace-dp: cut exact drain request movement [MERGED] (merged 2026-04-16)

Branch: `pr/cos-exact-zero-move-drain`

## Summary
- remove transient request reshaping from exact CoS direct service by draining exact local/prepared queues straight into dedicated TX scratch descriptors
- commit exact FIFO queue progress only after TX ring submission and restore only the unsent tail, instead of materializing and rebuilding queue batches
- keep the low-rate flow-fair exact path unchanged and leave the rejected empty-ingest micro-cut out of this PR because it regressed live behavior

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml exact_ -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo fmt --manifest-path userspace-dp/Cargo.toml`
- `git diff --check`
- `make build-userspace-dp`
- helper-only rollout with `scripts/userspace-helper-rollout.sh`, preserving `/etc/xpf/xpf.conf` and `/etc/xpf/.configdb`

## Live CoS checks on helper `45c3f170b41d43209f13dd10ef753ec0b831489ed92688147724929b52542ff4`
- IPv4 `5201`: `1.112 / 1.105 Gbit/s`
- IPv4 `5202`: `9.565 / 9.543 Gbit/s`
- IPv4 `5203`: `0.097 / 0.095 Gbit/s`
- IPv6 `5201`: `1.024 / 1.019 Gbit/s`
- IPv6 `5202`: `9.385 / 9.363 Gbit/s`
- IPv6 `5203`: `0.095 / 0.094 Gbit/s`
- IPv6 `5201` repeat 30s: `1.016 / 1.014 Gbit/s`

## Perf on active firewall (`5202`, `-P 12`, `20s`)
Before this slice (`#688` baseline):
- IPv4: `drain_pending_tx 27.33%`, `memmove 13.47%`, `poll_binding 8.20%`
- IPv6: `memmove 16.33%`, `drain_pending_tx 11.54%`, `poll_binding 9.32%`

With this PR helper:
- IPv4: `drain_pending_tx 22.70%`, `memmove 14.54%`, `poll_binding 8.40%`
- IPv6: `drain_pending_tx 27.35%`, `memmove 11.44%`, `poll_binding 8.52%`

Interpretation:
- this slice removes exact-drain request movement and reduces the combined exact-path request-management tail on IPv4
- IPv6 remains dominated by `drain_pending_tx`, but the remaining `memmove` now looks more like packet-byte copy than queue-structure churn
- the follow-on empty-ingest fast-path experiment was tested live and rejected because it worsened the exact path and made low-rate fairness noisier

Closes #688


---

## PR #696 — userspace-dp: pin shared-exact threshold policy with unit tests [MERGED] (merged 2026-04-16)

Branch: `pr/cos-shared-exact-threshold-tests`

## Summary
- document what the low-rate-exact single-owner threshold is and why the constants have the values they have
- add six boundary unit tests for `queue_uses_shared_exact_service` covering the exact 10g-iface config from the live loss HA CoS lab
- pin the current 100g-iface behavior as a known rough edge (shaping_rate/4 dominates MIN and mis-classifies genuinely high-rate queues) so a future policy fix is explicit rather than silent

## Motivation
Issue #690's required change (route low-rate exact queues to a single owner worker) is implemented by `queue_uses_shared_exact_service` at `userspace-dp/src/afxdp/worker.rs:1461`. The predicate is correct for the current 10g lab:
- `100m exact` / `1g exact` → single owner (below the 2.5g MIN floor)
- `10g exact` → shared

Live 5201 fairness on the deployed helper (SHA `45c3f170…`, matches master):
- IPv4 12-flow 30s: `1.123 / 1.119 Gbit/s`, ratio `1.41`
- IPv6 12-flow 30s: `1.012 / 1.009 Gbit/s`, ratio `1.40`

Both meet #690's stated acceptance criteria. The residual imperfection is SFQ hash-bucket collisions (tracked separately in #693), not a single-owner routing problem.

What was missing was explicit regression coverage for the predicate itself. The only existing asserts are inside `build_worker_cos_fast_interfaces_flattens_owner_and_lease_state`, which tests the whole flat-path assembly. A future perf or refactor slice that tweaks the threshold could flip classification for `5201` or `5202` without a single focused test firing.

## What this PR does
- **Expanded rustdoc** on `queue_uses_shared_exact_service`:
  - describes the two threshold components (absolute per-worker capacity floor, and the iface-rate-relative term)
  - explains the 2.5 Gbps MIN as an empirical single-worker exact throughput ceiling tied to PR #680's throughput-collapse investigation
  - calls out the high-iface rough edge
- **Six unit tests**:
  - `queue_uses_shared_exact_service_rejects_non_exact_queue`
  - `queue_uses_shared_exact_service_10g_iface_pins_5201_config_policy` — asserts the exact loss HA lab shape (best-effort / iperf-a single-owner, iperf-b shared)
  - `queue_uses_shared_exact_service_10g_iface_threshold_is_exactly_inclusive` — byte-precise boundary; guards against off-by-one drift
  - `queue_uses_shared_exact_service_slow_iface_absolute_floor_applies` — documents the 1g-iface case where MIN dominates
  - `queue_uses_shared_exact_service_high_iface_rate_keeps_large_queues_single_owner` — pins the 100g-iface rough edge on purpose; see the inline comment
  - `queue_uses_shared_exact_service_zero_iface_rate_falls_back_to_absolute_floor` — bootstrap / unconfigured iface case; no underflow

No behavior change. No code path other than the predicate is touched.

## Not in this PR
- Any change to the threshold policy itself. The 100g-iface rough edge is a real bug (a 10g exact queue on a 100g iface gets single-owner service, which regresses to PR #680's collapse shape), but fixing it is a separate change that needs live validation on a >10g iface. Filing that as a follow-on is better than sneaking a policy flip in under "add tests".
- The residual SFQ hash collisions (#693). Orthogonal.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml queue_uses_shared_exact_service` — 6 tests, all pass.
- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo fmt --manifest-path userspace-dp/Cargo.toml`
- `git diff --check`
- Three pre-existing failures on master (`build_shared_cos_root_leases_uses_active_workers_per_interface`, `maybe_top_up_cos_root_lease_unblocks_large_frame_exceeding_lease_bytes`, `resolve_cos_queue_id_defaults_when_output_filter_has_no_forwarding_class`) fail before and after this change. Not this PR's concern; worth a separate look.
- Live 5201 fairness checks noted above show the policy is in place on the deployed helper.

Refs #690.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #699 — userspace-dp: per-queue randomized SFQ hash seed [MERGED] (merged 2026-04-16)

Branch: `pr/cos-flow-fair-hash-seed`

## Summary
- add a per-queue `flow_hash_seed: u64` drawn from `getrandom(2)` at runtime construction and mixed into `exact_cos_flow_bucket()` before the 5-tuple terms
- preserves determinism inside one runtime instance (required for correct enqueue/dequeue bucket accounting) while making the bucket mapping unpredictable across restarts and nodes
- hot-path shape is one cached `u64` XOR — no per-packet RNG, no allocations, no locks
- closes #693

## Why
PR #692's SFQ gives 5201 flow fairness inside one queue but the bucket mapping is still a pure function of the 5-tuple. That is externally probeable: a hostile or just unlucky source that can vary ports can steer flows into a small number of buckets and degrade fairness on purpose, and collision hot spots repeat across restarts and across HA nodes.

Live IPv6 5201 12-flow 30s run currently shows five identical streams at `92.3 Mbit/s` (rates `[66.0, 71.3, 73.8, 76.0, 77.8, 92.3, 92.3, 92.3, 92.3, 92.4, 92.4, 92.6]`). That is the textbook signature of 12 flows mapping into <12 distinct SFQ buckets under a stable hash — multiple flows sharing a bucket split that bucket's fair share.

## Implementation

**Field:**
```rust
pub(super) struct CoSQueueRuntime {
    ...
    pub(super) flow_fair: bool,
    pub(super) flow_hash_seed: u64,  // new
    ...
}
```

**Seed source:** `cos_flow_hash_seed_from_os()` — `libc::getrandom()` with `flags=0`. The daemon starts well after `systemd-random-seed`, so urandom is initialized. A CLOCK_MONOTONIC-mixed fallback exists for degenerate syscall failure; it is strictly better than the zero-seed it replaces, and is exercised by a regression test.

**Hash mix:**
```rust
let mut seed = queue_seed
    ^ (flow_key.protocol as u64)
    ^ ((flow_key.addr_family as u64) << 8);
```

At `queue_seed == 0`, XOR is identity → mathematically byte-identical to the pre-seed behavior. Legacy flow-fair tests stay green with explicit `flow_hash_seed = 0` pinning after enabling `flow_fair`.

**Callers updated (all four):**
- `account_cos_queue_flow_enqueue` / `_dequeue` — accounting
- `cos_queue_push_back` / `cos_queue_push_front` — item placement
- The admission check in the CoS enqueue path (`flow_share_exceeded`)

## Performance shape
- Adds one `u64` field to `CoSQueueRuntime` (8 bytes, colocated with the flow-fair hot fields).
- Adds one XOR in the hash function (one register op, same instruction count order as a single `mix_cos_flow_bucket` call).
- Zero added syscalls on the hot path; `getrandom` only runs once per queue at runtime construction.
- No allocations, no locks, no RNG state to manage across threads.

## Validation

**Unit coverage (4 new tests covering every required property from #693):**
- `exact_cos_flow_bucket_is_stable_for_same_seed_and_flow` — 4096 iterations of one (seed, flow) pair must all return the same bucket. Pins the determinism property.
- `exact_cos_flow_bucket_diverges_across_seeds_for_same_flow` — scans 1..8192 seeds, requires at least one to map the same flow to a different bucket. Pins the "seed is actually mixed in" property.

*(truncated — 72 lines total)*


---

## PR #700 — userspace-dp: drop iface_rate/4 term from shared-exact threshold (#697) [MERGED] (merged 2026-04-16)

Branch: `pr/cos-shared-exact-absolute-threshold`

## Summary
- replace `max(iface_rate / 4, MIN)` with just `COS_SHARED_EXACT_MIN_RATE_BYTES`
- fixes the shared-exact policy inversion at >10g iface rates where the old threshold scaled UP with iface rate and mis-classified high-rate queues as single-owner, routing them into the PR #680 throughput-collapse shape
- byte-identical behavior on the 10g loss HA lab (where `iface_rate / 4 == MIN == 2.5g`)
- closes #697

## Why
The old policy treated the shared-exact cutoff as a fraction of the interface shaper. That was backwards. A single worker's sustained exact drain throughput is an absolute property of the drain loop and the TX ring — it does not scale with iface rate. The `/ 4` term meant:

| iface | old threshold | 10g exact queue gets |
|-------|---------------|---------------------|
| 10g   | max(2.5g, 2.5g) = 2.5g | **shared** (correct) |
| 25g   | max(6.25g, 2.5g) = 6.25g | **single-owner** (collapse) |
| 100g  | max(25g, 2.5g) = 25g | **single-owner** (collapse) |

At 25g+ a 10g exact queue would have been routed to one owner worker that cannot sustain 10g exact — exactly PR #680's failure mode.

## Implementation

One line in `userspace-dp/src/afxdp/worker.rs`:

```rust
fn queue_uses_shared_exact_service(_iface: &CoSInterfaceConfig, queue: &CoSQueueConfig) -> bool {
    if !queue.exact { return false; }
    queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES
}
```

The `iface` parameter is retained so call sites do not churn; it is no longer consulted. Rustdoc updated to document the policy and name #697 / PR #680 as the rationale.

## Test diff

**Removed:**
- `queue_uses_shared_exact_service_high_iface_rate_keeps_large_queues_single_owner` — this test explicitly pinned the BUG (a 10g exact queue on a 100g iface asserted as single-owner). Its job was done the moment the policy change landed.
- `queue_uses_shared_exact_service_iface_rate_gate_boundary_is_byte_precise` — the iface-rate gate no longer exists, so this test asserts a code path that does not run.

**Added:**
- `queue_uses_shared_exact_service_threshold_does_not_scale_with_iface_rate` — iterates iface rates {10, 25, 40, 50, 100, 200, 400 Gbps} and asserts a 10g exact queue shards on every one. This is the correctness property #697 asked for.
- `queue_uses_shared_exact_service_high_iface_rate_shards_mid_rate_queues` — byte-precise boundary at a 100g iface. Under the old policy a 2.5g exact queue on a 100g iface would have been single-owner (threshold was 25g); under the fix it shards.

**Tightened:**
- `queue_uses_shared_exact_service_threshold_is_exactly_inclusive` — now iterates iface rates {1g, 10g, 100g} and asserts the byte-precise boundary holds on all three. Pins that the threshold cannot re-gain an iface-dependent term without the test failing loudly.
- `queue_uses_shared_exact_service_slow_iface_below_threshold_is_single_owner` — renamed and re-documented; no longer talks about MIN "dominating" `/ 4` since `/ 4` is gone.
- `queue_uses_shared_exact_service_zero_iface_rate_uses_absolute_threshold` — retained as a bootstrap sanity check (no divide-by-zero etc).

## Live validation

Helper SHA `b4c8bfa9e56e399b63c3261b2455eabd73cb8a9c1b44eb2b616781f6b8c8043a` rolled out to `xpf-userspace-fw0` and `xpf-userspace-fw1`; xpfd restarted on both nodes.

12-stream iperf3, 20–30s:

*(truncated — 74 lines total)*


---

## PR #701 — userspace-dp: split guarantee RR cursors by class (#689) [MERGED] (merged 2026-04-16)

Branch: `pr/cos-split-guarantee-rr-cursors`

## Summary
- split `root.guarantee_rr` into `exact_guarantee_rr` + `nonexact_guarantee_rr` (plus `legacy_guarantee_rr` for the test-only unified selector) so the two guarantee passes in `drain_shaped_tx` rotate independently
- documents the scheduler semantics as strict-priority exact-over-nonexact with class-independent round-robin within each class, matching what `drain_shaped_tx` actually does
- closes #689

## Why
The guarantee service phase runs two passes:

1. `service_exact_guarantee_queue_direct` (exact pass, runs first in `drain_shaped_tx`)
2. `build_nonexact_cos_batch` (non-exact fallback when exact returned None)

Before this PR both read from and wrote to the same `root.guarantee_rr` cursor. That is the shape #689 calls out as "accidentally coupled by an implementation detail" — neither true unified RR (because the exact pass always wins at a shared rr position) nor true class-independent RR (because serving an exact queue advances the cursor the non-exact pass will read next).

Worked example. Queues `[Q0 exact, Q1 nonexact, Q2 exact, Q3 nonexact]`, all backlogged with tokens to send:
- shared cursor: exact pass picks Q0, advances rr to 1; next call picks Q2 (skipping Q1), advances rr to 3; next call picks Q0 (skipping Q3), advances rr back to 1. If Q0 and Q2 always have tokens, Q1 and Q3 are starved indefinitely while the cursor oscillates 1 ↔ 3. Even if exact queues go token-starved occasionally and let non-exact run, the non-exact rotation is a function of *where the exact pass happened to leave the cursor*, not of non-exact service history.

Split cursor:
- `exact_guarantee_rr` rotates 0 → 2 → 0 → 2 regardless of non-exact activity.
- `nonexact_guarantee_rr` rotates 1 → 3 → 1 → 3 regardless of exact activity.
- Strict priority between classes is preserved (exact pass runs first in `drain_shaped_tx`; non-exact fires when exact yields).

## Implementation

`types.rs`:
```rust
pub(super) exact_guarantee_rr: usize,
pub(super) nonexact_guarantee_rr: usize,
pub(super) legacy_guarantee_rr: usize,
```

`tx.rs`:
- `select_exact_cos_guarantee_queue_with_fast_path` reads/writes `exact_guarantee_rr`
- `select_nonexact_cos_guarantee_batch` reads/writes `nonexact_guarantee_rr`
- `select_cos_guarantee_batch_with_fast_path` (test-only unified selector) reads/writes `legacy_guarantee_rr`. Kept separate so test harnesses that exercise the legacy walk do not corrupt the production cursors and vice versa.

Rustdoc on each selector names its cursor explicitly.

## Test diff

**Added**:
- `exact_and_nonexact_guarantee_rr_cursors_advance_independently` — serving an exact queue must leave the non-exact cursor untouched and vice versa.
- `exact_guarantee_rr_walks_exact_queues_in_order_independent_of_nonexact` — 4 rounds, non-exact service interleaved between exact calls; exact sequence must be `[0, 2, 0, 2]`.
- `nonexact_guarantee_rr_walks_nonexact_queues_in_order_independent_of_exact` — symmetric: non-exact sequence `[1, 3, 1, 3]` regardless of exact activity.
- `guarantee_rr_cursors_start_at_zero_after_runtime_build` — pin that all three cursors initialize to 0 (catches a refactor that drops a field or leaves it uninitialized).

**Test helper** `test_mixed_class_root_with_primed_queues` uses a 1 Mbps per-queue rate so `cos_guarantee_quantum_bytes` clamps to its 1500-byte minimum and each selector call consumes exactly one packet from the chosen queue. That lets the rotation tests run multiple rounds of selection without any queue draining to empty.

## Validation

- `cargo test --manifest-path userspace-dp/Cargo.toml guarantee_rr` — 4 new tests green (plus 3 existing flow-fair tests untouched)

*(truncated — 71 lines total)*


---

## PR #702 — userspace-dp: fix three pre-existing CoS test failures [MERGED] (merged 2026-04-16)

Branch: `pr/fix-pre-existing-test-failures`

Three CoS tests were asserting stale invariants and failing on master. Fix each:

**build_shared_cos_root_leases_uses_active_workers_per_interface** (coordinator.rs)
Root cause: assertion `first+second+third+fourth == tx_frame_capacity()*2` (8192) was copy-pasted from the sibling queue-lease test. For this test's config (100 Mbps / 256 KB / 2 shards) `lease_bytes=20 000` and `max_total_leased = lease_bytes * active_shards = 40 000`, not 8192.
Fix: rewrite to drain the full budget and pin the real invariant — root budget scales with `active_shards`.

**maybe_top_up_cos_root_lease_unblocks_large_frame_exceeding_lease_bytes** (tx.rs)
Root cause: precondition `lease_bytes() < tx_frame_capacity()` was valid when `COS_ROOT_LEASE_TARGET_US=25`. Commit e4ae9eeb bumped it to 200, so at 400 Mbps lease_bytes is now 10 000 (> 4096) and the precondition trips.
Fix: drop rate to 50 Mbps so the raw target (1250) floors up to `COS_ROOT_LEASE_MIN_BYTES=1500` < 4096, exercising the same regression path.

**resolve_cos_queue_id_defaults_when_output_filter_has_no_forwarding_class** (tx.rs)
Root cause: test expected an assigned but no-op output filter to shadow ingress classification and fall back to default queue. Commit a15a6120 intentionally changed the gating (`interface_output_filter_needs_tx_eval`) to skip the output filter entirely when it has no `forwarding_class`, `dscp_rewrite`, or counter term — matching Junos semantics.
Fix: update assertion to the new invariant (ingress classification is preserved) and leave a comment above the test explaining the contract change.

## Validation
- `cargo test --manifest-path userspace-dp/Cargo.toml` — 620 pass, 0 fail
- `cargo fmt --manifest-path userspace-dp/Cargo.toml`
- `git diff --check`

---

## PR #703 — userspace-dp: validate COS_SHARED_EXACT_MIN_RATE_BYTES + end-to-end dispatch coverage (#698) [MERGED] (merged 2026-04-17)

Branch: `pr/cos-min-constant-validation`

## Summary
- drain-path micro-bench (`cargo test -- --ignored --nocapture`) with documented scope and baseline
- end-to-end fast-interface assembly test for the live loss HA 3-queue shape (100m / 1g / 10g exact on 10g iface)
- queue-rate > iface-rate misconfig pin
- rustdoc on `COS_SHARED_EXACT_MIN_RATE_BYTES` now cites the bench and names the actual gating mechanism
- closes #698

## Why
The 2.5 Gbps `COS_SHARED_EXACT_MIN_RATE_BYTES` constant has been load-bearing across four merged PRs (#692, #696, #700, #701) without any checked-in measurement backing it. The rustdoc called it "empirical" but pointed at no data a reader could verify. Similarly, every CoS PR in this series validated live against the 100m/1g/10g three-queue loss HA config, but that shape had never been exercised end-to-end through `build_worker_cos_fast_interfaces` in unit tests — the predicate was tested in isolation, and the assembly was tested with two-queue shapes.

## Micro-bench

**Scope (what it covers):**
- `drain_exact_local_fifo_items_to_scratch` — VecDeque indexed read, pattern match, free-frame pop, UMEM `slice_mut_unchecked` + `copy_from_slice` (the 1500-byte memcpy that dominates `memmove` in the live profile), scratch Vec push, root/secondary budget decrement.
- `settle_exact_local_fifo_submission` — queue.items.pop_front per sent packet, scratch Vec pop.
- Re-prime between iterations to simulate steady inflow.
- 10 000 batches × 256 packets × 1500 B, with 1000 warmup iterations for cache + branch predictor settle.

**Scope (what it does NOT cover):**
- TX ring insert + commit — no XDP socket in unit tests; ~20 ns combined on x86-64 amortized at TX_BATCH_SIZE.
- Kernel wakeup syscall (`sendto`) — amortized over batches of 256 at ~2-4 ns/packet.
- Completion ring reap — ~20-50 ns per completion.
- Non-drain per-worker cost: RX, forwarding, NAT, session lookup, conntrack. These are measured in the live cluster profile, not here. **They dominate in production and are the real gate on per-worker aggregate throughput.**

**Baseline** (development host, release build):
```
packet len            : 1500 B
batches               : 10000
packets per batch     : 256
total packets         : 2 560 000
elapsed               : 768.6 ms
ns/packet (drain+settle): 300.24
throughput (pps)      : 3.331 Mpps
throughput (line rate): 39.968 Gbps
min-constant gate     : 2.500 Gbps
verdict               : drain alone exceeds MIN — constant gated by non-drain per-worker work (expected)
```

## What this tells us about the MIN constant

Drain alone sustains ~16× the 2.5 Gbps MIN on reasonable hardware. That's the key signal: **the constant is not gated by drain speed.** It's gated by the per-worker aggregate budget after RX / forward / NAT / session / conntrack work consume their share of the per-packet cycle budget. That's consistent with the PR #680 collapse shape — the drain couldn't absorb 10g line-rate not because it was too slow in isolation, but because non-drain work left insufficient CPU for drain+completion to keep up.

If the drain micro-bench ever drops below 2.5 Gbps, the MIN constant would need to drop too. The bench catches that regression the first time a human re-runs it.

## End-to-end dispatch test

`build_worker_cos_fast_interfaces_matches_live_loss_ha_3_queue_shape` covers the exact production CoS config every PR in this series has validated live:

```
reth0.80 shaper 10g

*(truncated — 85 lines total)*


---

## PR #713 — userspace-dp: add per-reason CoS drop telemetry (#710) [MERGED] (merged 2026-04-17)

Branch: `pr/cos-drop-telemetry`

## Summary
- Nine new drop-reason counters spanning the CoS enqueue / shaper / submit / redirect pipeline, per (ifindex, queue_id) where meaningful and per-binding where inherently cross-queue.
- Both worker-level and coordinator-level aggregators updated so the counters survive the two-layer status aggregation.
- Live data on the #704 repro ranks the root causes with real numbers instead of hypotheses.
- Closes #710.

## Why

Before this PR the only live drop signal was `tx_errors` (a monotonic counter) plus a "last_error" string. That is useless for triage. #704's 16-flow bimodal-fairness-collapse investigation had four credible root-cause hypotheses (#705 SFQ admission cap, #706 redirect-inbox mutex, #707 buffer undersizing, #709 owner-worker hotspot) and no way to rank them by actual in-production cost. This PR closes that gap.

## Counter design

**Per-queue (`CoSQueueRuntime.drop_counters`)** — single-writer per worker, plain `u64` with `wrapping_add`. No atomics needed on the hot path; snapshot reads happen through the already-existing `build_worker_cos_statuses` → `ArcSwap` publication path.

| Counter | Where | Indicates |
|---------|-------|-----------|
| `admission_flow_share_drops` | `enqueue_cos_item` admission | SFQ per-flow cap exceeded (#705, #711) |
| `admission_buffer_drops` | same | Queue buffer cap exceeded (#707) |
| `root_token_starvation_parks` | `select_cos_*_guarantee_*` | Root shaper tokens empty (scheduling, not a drop) |
| `queue_token_starvation_parks` | exact selector | Per-queue tokens empty (scheduling, not a drop) |
| `tx_ring_full_drops` | `service_exact_*_queue_direct` | `writer.insert` returned 0; frames recycled |

**Per-binding (`BindingLiveState`)** — multi-writer, `AtomicU64` with `Relaxed`. These are inherently cross-queue or cross-worker.

| Counter | Where | Indicates |
|---------|-------|-----------|
| `redirect_inbox_overflow_drops` | `enqueue_tx` / `enqueue_tx_owned` | Owner not draining redirects fast enough (#706, #709) |
| `pending_tx_local_overflow_drops` | `bound_pending_tx_*` | Per-worker FIFO cap hit |
| `tx_submit_error_drops` | `TxError::Drop` / `ExactCoSScratchBuild::Drop` | Frame-level submit errors (capacity/slice) |
| `no_owner_binding_drops` | `apply_worker_shaped_tx_requests` | Cross-worker redirect arrived for an unknown egress |

## Aggregation fix caught during validation

First attempt showed every per-queue counter at zero during live traffic while `tx_errors` was advancing monotonically. Triaged by iterating: telemetry-first, not hypothesis-first. The bug was that `Coordinator::cos_statuses` does its *own* second-layer aggregation across per-worker snapshots, and that aggregator did not sum the new drop-counter fields — they were being discarded on the way out of the coordinator. Caught only because the live numbers did not add up. Fix landed in the same commit; the second-layer aggregation now mirrors the first.

Lesson for reviewers: when adding a counter, grep for every aggregation layer it must survive. This repo has two for CoS status.

## Live validation on #704 repro

Helper SHA `5a6914152c18c0d604f4a0f5e99e7b9d4554680f44a344847d99b14245e3db83` deployed to both loss-HA nodes. 16-flow iperf3 on port 5201 (1g exact iperf-a queue) for 30s:

```
aggregate: 1.079 Gbps  retrans: 149701
tx_errors on owner slot 4: 2671
```

Drop-reason breakdown on `reth0.80 q4 (iperf-a)`:

| Counter | Value | Notes |
|---------|-------|-------|

*(truncated — 100 lines total)*


---

## PR #714 — userspace-dp: grow SFQ buckets 64→1024 + fixed-capacity RR ring (#711, #694) [MERGED] (merged 2026-04-17)

Branch: `pr/cos-sfq-1024-buckets`

## Summary
- `COS_FLOW_FAIR_BUCKETS: 64 → 1024`. Collision probability at 16 flows: 88% → 11%.
- `flow_rr_buckets: VecDeque<u8>` → `FlowRrRing` (heap-free, `[u16; 1024] + head + len`). Closes #694.
- `exact_cos_flow_bucket` returns `u16` (was `u8`) so the widened mask isn't silently truncated.
- 8 new regression tests. Drain-path cost slightly faster (169 vs 177 ns/pkt). Live ratio on the #704 repro: **13.26× → 1.35×**.

## Evidence driving the change

#710 telemetry shipped in #713 produced hard numbers on the #704 16-flow collapse:
- `admission_flow_share_drops` = 2671, matching `tx_errors` exactly. Primary drop reason.
- Zero activity on the mutex, owner-hotspot, pending-FIFO, buffer-cap, or submit-error paths.

Hypothesis: the primary driver isn't the admission cap itself (that's #705's scope) — it's that 16 flows into 64 buckets collide ~88% of the time, and colliding flows share one admission slot. Three or four unlucky flows get half the admission budget of the rest, compounding the cwnd-collapse cycle.

#711 tests that hypothesis directly by 16×-ing the bucket count.

## Bucket-count selection

Birthday-paradox collision probability by flow count:

| N flows | 64 buckets | 1024 buckets |
|--------:|-----------:|-------------:|
| 8       | 40%        | <1%          |
| 16      | 88%        | 11%          |
| 32      | 99%        | 38%          |
| 64      | 99.99%     | 87%          |

1024 covers the production regime (N ≤ 64 flows/queue) with headroom. Not 4096 or higher — the per-queue memory overhead of `[VecDeque; N]` inline headers grows linearly and the gains beyond 1024 stop mattering for realistic flow counts.

## HFT-lens design decisions

**Bucket ID width: u16.** 1024 buckets need 10 bits. `u8` (the prior return type of `exact_cos_flow_bucket`) would have silently truncated the hash to 8 bits — giving the widened mask no actual work to do. u16 is the minimum that exposes the full 10-bit bucket space; u32 would waste cache.

**Fixed ring (#694).** Heap-free `[u16; 1024] + head + len` (2 KB total) fits in L1d. Replaces `VecDeque<u8>` which paid allocator cost per queue. Same O(1) push/pop complexity. Head/tail indexing via `% COS_FLOW_FAIR_BUCKETS`.

**Invariant unchanged.** The callers in `cos_queue_push_*` / `cos_queue_pop_front` already gate on "bucket transitioned empty → non-empty" before pushing, and on "bucket still non-empty" before re-enqueueing the RR cursor after dequeue. The ring itself does not re-validate on the hot path. New ring-invariant unit tests pin this contract (no-duplicates, wrap-around, capacity edges).

**Memory budget.** Per flow-fair queue: ~34 KB (1024 × 24-byte VecDeque headers + 1024 × 8-byte u64 + 2 KB fixed ring). Non-flow-fair queues have the same inline footprint but their headers stay cold (never touched on the non-flow-fair path). At 4 workers × 8 queues × 1 iface ≈ 1 MB per cluster. Tolerable.

## Hot-path cost

Drain micro-bench (release, development host):
```
before: 177 ns/packet, 5.65 Mpps, ~68 Gbps
after:  169 ns/packet, 5.91 Mpps, ~71 Gbps
```

Within noise, slightly faster if anything. The fixed ring avoids the `VecDeque<u8>` heap indirection on push/pop; the bucket-count grow itself doesn't affect per-packet cost (same O(1) ops, same cache behavior for the small active-bucket set actually in use).

## Live validation on the #704 repro

*(truncated — 111 lines total)*


---

## PR #715 — userspace-dp: lock-free redirect inbox eliminates cross-producer mutex (#706) [MERGED] (merged 2026-04-17)

Branch: `pr/706-mpsc-redirect-inbox`

## Summary

- Replace `Mutex<VecDeque<TxRequest>>` in `BindingLiveState::pending_tx` with a hand-rolled bounded MPMC queue (Vyukov's bounded algorithm, used MPSC-style — N worker producers, owner-worker consumer).
- Eliminates the cross-producer and producer↔consumer serialisation on every redirected `TxRequest`.
- Overflow semantics flip to drop-newest (old queued packets are closer to being serviced by the owner; evicting them only extends tail latency). Counter contract — `tx_errors` + `redirect_inbox_overflow_drops` — is preserved.
- `cancel_queued_flow_on_binding` loses the in-place filter on the redirect inbox (cannot mutate a lock-free ring from a non-consumer thread). Worker-owned queues still filter; post-RST stragglers are absorbed by the peer's RST handling.

## Test plan

- [x] `cargo test` — 649 userspace-dp tests green, 0 fail. New `mpsc_inbox` suite covers: FIFO on single producer, `Err` on full ring, capacity power-of-two rounding, concurrent producers below-cap lose no items, concurrent producers above-cap drop exactly the overflow (`pushed_ok + err == total`, `popped == pushed_ok`), `Drop` runs for orphaned values.
- [x] Updated `enqueue_tx_owned_increments_redirect_inbox_overflow_counter_when_soft_cap_drops_newcomer` — drop-newest flip, counter contract preserved.
- [x] `make test` — full Go suite green.
- [x] Live deploy on `loss:xpf-userspace-{fw0,fw1}` with CoS re-applied (iperf-a 1g exact queue at 5201, iperf-b 10g shared, best-effort 100m). Both nodes active, no panics.

## Live data (16-flow iperf3, 30s, port 5201, 1 Gbps exact queue)

| Run | Total | Rate ratio | Retrans/30s | Flows with max_cwnd < 50 KB |
|---|---|---|---|---|
| 1 | 1.07 Gbps | 1.49× | 139 k | 9/16 |
| 2 | 1.16 Gbps | 1.64× | 217 k | 13/16 |
| 3 | 1.11 Gbps | 1.91× | 190 k | 12/16 |

## What this PR did and did not do

**Did**: the rate distribution across the 16 flows is now flat (50–94 Mbps, ~1.5× max/min). Before this change, the split was bimodal (5 owner-local flows healthy multi-Gbps, 11 redirected flows collapsed sub-500 Mbps). Removing the cross-worker mutex let every redirected flow move at the same rate as owner-local ones.

**Did not**: cwnd collapse and the retransmit storm persist. #706's hypothesis was that mutex jitter was driving single-packet drops which forced RTOs (cwnd reset to 1 MSS) and drove the bimodal pattern. The data shows that theory was only half right — the mutex was causing the *bimodal split*, not the retransmit storm itself. With the mutex gone, every flow shares the *same* pathology: admission-cap drops push per-flow cwnd below the 3-dupack fast-retransmit threshold, so single drops take an RTO, and cwnd oscillates between "just below the cap" and 1 MSS.

That failure mode is now unambiguously pinned to **#705 (admission cap off distinct flow count) and/or #707 (1.19 MB exact-queue buffer too small for 16 flows × RTT × BDP)** — with the mutex out of the way, there is no other structural throttle between the ring-level fairness and the TCP-layer behaviour. This PR is a prerequisite for either fix being measurable.

Refs: #706, #704, #705, #707, #709.

---

## PR #716 — userspace-dp: flow-aware CoS admission buffer + 16 MSS fast-retransmit floor (#707) [MERGED] (merged 2026-04-17)

Branch: `pr/707-flow-aware-buffer-limit`

## Summary

Flow-fair admission on low-rate exact queues has two undersized gates. Both need to be fixed together because each is hidden by the other tripping first.

1. **`COS_FLOW_FAIR_MIN_SHARE_BYTES` raised 4 → 16 MTU-sized packets** (6 KB → 24 KB). 4 is exactly the 3-dupack fast-retransmit threshold with no headroom — a single drop in the last MTU produces < 3 dupacks before cwnd is drained → RTO → cwnd reset to 1 MSS. 16 gives 3 dupacks + ~13 MTU of reorder/retransmit window. A top-level `const _: () = assert!` pins the floor at build time, not just test time.

2. **Flow-aware aggregate cap** matching the per-flow clamp's denominator. Per-flow clamp already reasoned about *prospective* active flows (current + 1 when the target bucket is empty). Aggregate cap was keyed off current active count, so at the new-flow boundary the per-flow gate admitted the first packet while the aggregate gate rejected it. Helper `cos_flow_aware_buffer_limit(queue, flow_bucket)` now uses the same prospective-active formula, driven from a single `flow_bucket` computed once per admission.

Non-flow-fair queues (best-effort, pure rate-limited) bypass the scaling and keep the operator-configured buffer.

## HFT hot-path shape

- One `flow_bucket` computation per admission (already present, reordered earlier).
- Branchless `prospective_active` compute via `saturating_add` on the `is_empty?1:0` boolean.
- One `saturating_mul` + one `max` extra per admission (~2–3 ns on modern x86).
- No allocations, no atomics, no heap state.
- Backing `VecDeque` is dynamic — logical cap only, zero memory cost until traffic fills it.

## Deferred to follow-up

Reviewer flagged a latency-envelope concern: `COS_FLOW_FAIR_BUCKETS = 1024` active flows would allow the cap to reach ~24 MB = ~190 ms of queue residence time on a 1 Gbps queue. A `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS`-derived clamp is the right shape but it is an operator-visible behaviour choice, not a bug fix — kept out of this PR pending queueing-budget policy discussion. Rustdoc on the helper calls it out so the concern is visible at the source.

## Test plan

- [x] `cargo test` — 651 green.
  - `cos_flow_aware_buffer_limit_scales_with_prospective_active_flow_count`: base wins low, floor wins high, prospective count (+1 for empty target) is the denominator.
  - `cos_flow_aware_buffer_limit_matches_share_limit_at_new_flow_boundary`: **new regression guard for the review's correctness finding** — at 15 active + 1 new-flow boundary, both gates admit the new flow's first packet.
  - `cos_flow_aware_buffer_limit_respects_non_flow_fair_queues`: `flow_fair=false` bypass.
  - `cos_queue_flow_share_limit_never_drops_below_fast_retransmit_floor`: per-flow share stays ≥ 16 MTU at 16 flows.
  - Top-level `const _: () = assert!` enforces floor at `cargo build`.
- [x] `make test` — full Go suite green.
- [x] Live deploy + CoS re-apply via new `test/incus/apply-cos-config.sh` + 3× 16-flow iperf3 on 5201.

## Live data and honest framing

With CoS active and the 1 Gbps exact queue, the **scheduler auto-sizes `buffer` to 1.19 MiB** (~9.5 ms × rate), not the 125 KB the issue's math assumed. That means:

- Before this PR, `buffer / 16 = 75 KB` per flow — already 3× above the 16-MTU floor.
- This PR's flow-aware expansion is a **no-op for scheduler-auto-sized buffers** (`base (1.19 MB)` > `prospective × 24 KB`) at this workload.

16-flow iperf3 results (3 runs, 30 s, port 5201):

| Run | Total | Rate ratio | Retrans / 30 s | cwnd < 50 KB |
|---|---|---|---|---|
| 1 | 1.10 Gbps | 1.48× | 175 k | 11 / 16 |
| 2 | 1.06 Gbps | 1.53× | 125 k | 8 / 16 |
| 3 | 1.10 Gbps | 1.44× | 204 k | 12 / 16 |

Rate ratio (1.5×) is healthy. Retransmit and cwnd-collapse numbers are statistically identical to the post-#706 baseline — the dominant driver on this workload is **bursty tail-drop on a ~10 ms bufferbloat queue**, not undersized per-flow share. That requires AQM (ECN marking or CoDel) rather than larger caps, and is properly scoped as a separate change.


*(truncated — 58 lines total)*


---

## PR #719 — docs: engineering-style.md — coding and review discipline [MERGED] (merged 2026-04-17)

Branch: `pr/engineering-style-doc`

## Summary

Distill the coding / review personality that has emerged across the recent CoS work (#714, #715, #716) into a checked-in file that future sessions always load.

- **New**: `docs/engineering-style.md` — terse, opinionated, meant to be read once in full before touching hot-path code or reviewing a PR.
- **Updated**: `CLAUDE.md` now points at the style doc in the *Working Style* section, so agent sessions load it automatically alongside the project facts.

## What it covers

- First principles (latency > memory, correctness > perf > convenience, one source of truth per formula, honest framing, narrow scope).
- Hot-path coding rules: allocation, atomic orderings, cache-padding cross-core atomics, branchless arithmetic, `const _: () = assert!` vs `#[test]` pins.
- API shape discipline: drain-into-buffer signatures, `unsafe` fn for SC invariants, operator-visible units match live config.
- Overflow / failure policy matrix (drop-newest vs drop-oldest, return Err vs panic vs counter-bump).
- Review discipline: adversarial by design, severity tags, concrete code shape in comments, test-strength standards with counter-factual assertions.
- PR discipline: title/body/commit/merge conventions.
- Project-specific gotchas that repeatedly bite (CoS wipe on deploy, iperf3 endpoint, `cli` not `xpfctl`, `source ~/.sshrc`).
- Tone signals from reviews that worked (`"I would either ... or ..."`, `"behaviour choice, not a bug fix"`, `"does not recreate the old failure mode"`).

## Test plan

- [x] Docs-only change.
- [x] Links verified, no dangling file refs.

Since the file prescribes the *taste* of the codebase, please review the prescriptions themselves — not just the prose. Anything I got wrong, overclaimed, or missed from what you actually want the personality to be is worth calling out before merge.

---

## PR #720 — userspace-dp: latency-envelope clamp on cos_flow_aware_buffer_limit (#717) [MERGED] (merged 2026-04-17)

Branch: `pr/717-latency-clamp`

## Summary

- Adds `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS = 5 ms` and clamps the flow-aware admission cap in `cos_flow_aware_buffer_limit` against `delay_cap = transmit_rate_bytes × 5 ms`.
- Applied as `.min(delay_cap.max(base))` — operator-configured `buffer-size` always wins over the clamp. Explicit operator intent is preserved.
- Compile-time pin `const _: () = assert!(MAX_QUEUE_DELAY_NS >= 1 ms)` so the constant cannot drift below a value where TCP has no room to grow cwnd past a handful of packets.
- Deletes the "currently uncapped on the high side" rustdoc paragraph and rewrites it to describe the clamp and cite #717.
- Deferred: operator-visible `set class-of-service max-queue-delay` knob — tracked as a follow-up under #717 design question 2.

## Why

`cos_flow_aware_buffer_limit()` after #716 scales the aggregate admission cap with `prospective_active × COS_FLOW_FAIR_MIN_SHARE_BYTES`. With the #711 bucket grow this reaches `1024 × 24 KB ≈ 24 MB` at max. On a 1 Gbps queue that is `~190 ms` of queue residence — far outside the scheduler's predictable regime. Flagged in #716 review; explicitly deferred because clamping queueing delay is a behaviour choice, not a bug fix.

## Hot-path shape

One extra `u128` multiply + divide per admission decision. Branchless arithmetic (`.max()`, `.min()`, `.saturating_mul()`) all the way down. No new branches that depend on runtime-varying data other than `queue.flow_fair`, which is already a config-time boolean lifted to the top of the hot function. The enqueue path calls this once per admission, not per packet.

## Test plan

- [x] `cargo test --manifest-path userspace-dp/Cargo.toml cos_flow_aware` — 7/7 pass (3 pre-existing + 4 new)
- [x] `cargo test --manifest-path userspace-dp/Cargo.toml` — 655/655 pass (651 pre-existing + 4 new), 0 fail, 1 ignored

New tests (all pin the clamp mechanically, not via trivial arithmetic):

- `cos_flow_aware_buffer_limit_clamps_high_flow_count_to_max_delay` — at 1024 active flows on a 1 Gbps queue the cap equals `delay_cap` (625 KB), not the flow-aware expansion (~24 MB). Carries a counter-factual that reconstructs the pre-clamp 24 MB value so a future refactor that deletes the clamp fails loudly.
- `cos_flow_aware_buffer_limit_honours_operator_base_above_delay_cap` — with `buffer_bytes = 100 MiB` (above delay_cap on a 1 Gbps queue), the returned cap equals the operator base; counter-factual asserts a naive `.min(delay_cap)` would have shrunk operator intent.
- `cos_flow_aware_buffer_limit_preserves_non_flow_fair_path_after_clamp` — `flow_fair = false` bypasses both the floor and the clamp; returns raw `buffer_bytes.max(COS_MIN_BURST_BYTES)`. Exercises a 10 MB operator base at 1 Gbps so a future refactor that moves the clamp above the `flow_fair` early return fails here.
- `cos_flow_aware_buffer_limit_delay_cap_scales_linearly_with_rate` — same flow count, same max-delay const, 1 Gbps (625 KB) vs 10 Gbps (6.25 MB) — pins the formula's linearity.

All operator-visible units are decimal bytes/rate matching operator config semantics per `docs/engineering-style.md` (e.g. `buffer_bytes: 125_000`, `transmit_rate_bytes: 125_000_000`, not `* 1024`).

## Live data

No runtime data claimed. This is a bounded worst-case latency fix; the observable effect is a tail-latency envelope under 1024-flow saturation. Orchestrator will run failover + CoS iperf3 validation after this and #718 both land.

## Deferred

- Operator-visible `set class-of-service max-queue-delay <ms>` config knob. Const for now; follow-up tracked under #717 (design question 2).
- `show class-of-service interface` surfacing the effective cap — separate issue.

## Refs

- #716 (flow-aware buffer + fast-retransmit floor — PR this clamps)
- #717 (this PR)
- #707 (original buffer undersizing bug)

---

## PR #721 — userspace-dp: ECN CE marking at CoS admission (#718) [MERGED] (merged 2026-04-17)

Branch: `pr/718-ecn-marking`

## Summary

- Mark ECN-negotiated packets CE at 50% of `buffer_limit` before the admission drop decision fires. Non-ECT packets are untouched per RFC 3168 6.1.1.1 — they fall through to the existing buffer / flow-share drop path, so the fix degrades gracefully.
- IPv4 updates the header checksum incrementally per RFC 1624 on the one-byte TOS mutation. IPv6 has no header checksum.
- New `admission_ecn_marked` counter plumbed through `CoSQueueDropCounters` -> worker status -> coordinator aggregation -> `CoSQueueStatus` protocol, so operators see the marking rate alongside existing admission drop reasons.
- Compile-time pins: `COS_ECN_MARK_THRESHOLD_NUM < COS_ECN_MARK_THRESHOLD_DEN` and `DEN > 0` via `const _: () = assert!`, so a refactor flipping the fraction or zeroing the denominator fails `cargo build`.

## Scope constraints

- **Only `CoSPendingTxItem::Local` is marked in this PR.** `Prepared` points into the umem and needs separate slice-mut plumbing; marked with `TODO(#718-followup):` at the call site and covered by a regression test (`admission_does_not_mark_prepared_variant`) so the follow-up implementer sees an explicit pin.
- Does not touch `cos_flow_aware_buffer_limit` internals (Agent A's territory on #717).
- No operator-visible config knobs yet — the 1/2 threshold is a constant. A knob is a follow-up once the signal from the live data supports sizing it.

## Hot-path cost

Per admission, when NOT above threshold:
- 1 `saturating_mul` + 1 divide to compute `ecn_threshold`
- 1 compare against `queue.queued_bytes`
- Total: ~2-3 ns

When above threshold with an ECT packet:
- Above + 1 match on `expected_addr_family`
- ~20 ns of bit-twiddle for ECN extract / mask / set
- IPv4 only: ~5 ns for the incremental checksum update (one `u32` add, two folds, one XOR)
- No allocations, no atomics, no mutex acquisition.

## Test plan

- [x] `cargo test --manifest-path userspace-dp/Cargo.toml mark_ecn_ce` — 11 marker tests pass
- [x] `cargo test --manifest-path userspace-dp/Cargo.toml admission` — 5 admission tests pass
- [x] `cargo test --manifest-path userspace-dp/Cargo.toml` — 667 pass / 0 fail / 1 ignored (baseline 651, delta +16)
- [ ] Live validation deferred until #717 lands too (orchestrator will run `test-failover` + iperf3 burst on loss cluster)

### New tests

Marker-level (byte-precise, catch endian / offset / mask regressions):
- `mark_ecn_ce_ipv4_converts_ect0_to_ce_and_updates_checksum`
- `mark_ecn_ce_ipv4_converts_ect1_to_ce_and_updates_checksum`
- `mark_ecn_ce_ipv4_leaves_not_ect_untouched` (RFC 3168 guard)
- `mark_ecn_ce_ipv4_leaves_ce_untouched` (idempotent)
- `mark_ecn_ce_ipv4_rejects_short_buffer`
- `mark_ecn_ce_ipv6_converts_ect0_to_ce`
- `mark_ecn_ce_ipv6_converts_ect1_to_ce`
- `mark_ecn_ce_ipv6_leaves_not_ect_untouched`
- `mark_ecn_ce_ipv6_leaves_ce_untouched`
- `mark_ecn_ce_ipv6_rejects_short_buffer`
- `maybe_mark_ecn_ce_dispatches_by_addr_family`

Admission-level (drive `apply_cos_admission_ecn_policy` at exact byte boundaries):
- `admission_ecn_marked_counter_increments_when_marking_above_threshold`

*(truncated — 70 lines total)*


---

## PR #723 — userspace-dp: ECN mark on per-flow threshold alongside aggregate (#722) [MERGED] (merged 2026-04-17)

Branch: `pr/722-per-flow-ecn`

## Summary

- Extend `apply_cos_admission_ecn_policy` so CE-marking fires on either the aggregate **or** the per-flow threshold, whichever trips first.
- Per-flow threshold is derived from `cos_queue_flow_share_limit(queue, buffer_limit, flow_bucket) * NUM/DEN` — same fraction the aggregate arm uses.
- Non-flow-fair queues are unaffected (`cos_queue_flow_share_limit` returns `buffer_limit`, so the two arms collapse into one).

## Why

#718 landed ECN CE marking keyed off aggregate queue depth. Live validation on the 16-flow iperf3 / 1 Gbps exact queue workload showed the aggregate threshold never fires — the queue sits at ~31% utilisation (~378 KB of a 1.19 MiB buffer) while the 50% threshold is ~594 KB. Drops on that workload come from the **per-flow** fair-share cap (24 KB per flow under `flow_fair`), not the aggregate cap, so `admission_ecn_marked` stayed at 0 and ECN-negotiated TCP flows still fell into RTO.

With the per-flow arm in place, flows get a CE mark when their bucket crosses half of the share cap — before the share cap itself trips the drop. ECN-negotiated TCP halves cwnd via ECE instead of collapsing through fast-retransmit/RTO.

## Hot-path shape

Added per admission:

- 1× `cos_queue_flow_share_limit` call (pure, inlined: `saturating_add + max + div_ceil + clamp`): ~5 ns
- 1× `saturating_mul` + 1× divide for `flow_ecn_threshold`: ~2 ns
- 1× array index + compare for `flow_above`: ~1 ns

Total: ~10 ns per admission on top of #718's cost. No allocations, no atomics.

## Test plan

- [x] `cargo test --manifest-path userspace-dp/Cargo.toml admission_ecn` — 6 tests pass (1 pre-existing + 5 new).
- [x] `cargo test --manifest-path userspace-dp/Cargo.toml` — **676 passed, 0 failed** (was 671; +5 new as expected).
- [ ] Live: `admission_ecn_marked` counter should advance on the 16-flow / 1 Gbps exact-queue workload once deployed (deferred to follow-up validation, see #722 acceptance criteria).

### New tests

- `admission_ecn_marks_when_per_flow_above_threshold_aggregate_below` — recreates the #722 live state (aggregate ~31%, per-flow bucket > 50% of share_cap). Includes a **counter-factual assertion** that reconstructs the pre-#722 aggregate-only formula and proves it would have missed this state — guards against a future refactor silently dropping the per-flow arm.
- `admission_ecn_marks_when_aggregate_above_threshold_per_flow_below` — keeps the #718 aggregate arm alive.
- `admission_ecn_does_not_mark_when_both_thresholds_below` — below-threshold guard.
- `admission_ecn_does_not_mark_when_flow_share_already_exceeded` — keeps the #718 invariant that doomed packets do not burn ECN marks.
- `admission_ecn_per_flow_threshold_matches_share_cap_denominator` — pins both arms to the same `NUM/DEN` fraction so they cannot drift if the constants change.

## Deferred

- Live `admission_ecn_marked` validation on the 16-flow workload (#722 acceptance criteria).
- Prepared (`umem` slice) variant of the ECN mark path — still the TODO(#718-followup) left by #718.
- Whether to lower the aggregate threshold (or drop it entirely in favour of the per-flow arm) is a behaviour choice and intentionally not in this PR.

## Refs

- #722 — this issue
- #718 — initial ECN implementation (aggregate-only arm)
- #704 — umbrella cwnd-collapse symptom

---

## PR #724 — cos: surface admission drop counters in show class-of-service interface [MERGED] (merged 2026-04-17)

Branch: `pr/observability-cos-drops`

## Summary

- Three per-queue admission counters — `admission_flow_share_drops`, `admission_buffer_drops`, `admission_ecn_marked` — already exist in the Rust dataplane (`CoSQueueDropCounters` in `userspace-dp/src/afxdp/types.rs`), are already aggregated across workers in `coordinator.rs`, and are already serialised on the wire in `userspace-dp/src/protocol.rs`.
- The Go `CoSQueueStatus` never had matching fields, and `FormatCoSInterfaceSummary` never rendered them. Operators had **no** way to see which admission decision was firing on the live system.
- This PR surfaces the existing counters. No new counters, no behaviour changes, no new `show` subcommand.

## Before / After

**Before** (`show class-of-service interface`):

```
    Queue  Owner  Class        Priority  Exact  Transmit rate  Buffer       Queued pkts  Queued bytes  Runnable  Parked  Next wake   Surplus deficit
    4      1      iperf-a      5         yes    1.00 Gb/s      1.19 MiB     255          378.02 KiB    0         1       6053592261  -
```

**After**:

```
    Queue  Owner  Class        Priority  Exact  Transmit rate  Buffer       Queued pkts  Queued bytes  Runnable  Parked  Next wake   Surplus deficit
    4      1      iperf-a      5         yes    1.00 Gb/s      1.19 MiB     255          378.02 KiB    0         1       6053592261  -
           Drops: flow_share=12345  buffer=0  ecn_marked=4567
```

Column alignment across queue rows is preserved (a naive tabwriter interleave breaks it; see the implementation note in `cosfmt.go`). Zero-valued counters are still rendered — operators need to SEE the zero to confirm the counter is wired end-to-end.

## Why this matters

We have been iterating on CoS admission-path fixes across #706 / #707 / #708 / #709 / #711 / #718 / #722. Without live operator visibility into which admission counter is incrementing, there is no way to confirm on the running system whether e.g. #722's per-flow ECN threshold is firing or whether flow-share drops dominate instead. Log scraping is not a substitute; a per-queue counter summary is what operators need at the CLI.

## Hot-path impact

None. `FormatCoSInterfaceSummary` is display-path code on the status poll; it runs once per CLI invocation, not per packet.

## Scope discipline

- The JSON tags on the new Go struct fields match the Rust `serde(rename = ...)` names exactly. They are the wire contract.
- No change to admission decision logic (`tx.rs`), no new counters, no renames.
- Extends the existing rendering; no new `show class-of-service interface extensive` subcommand.

## Test plan

- [x] `go test ./pkg/dataplane/userspace/...` — 6 of 6 format tests pass, including two new ones covering the non-zero and all-zero render paths.
- [x] `go test ./pkg/cli/... ./pkg/grpcapi/...` — green.
- [x] `cargo test --manifest-path userspace-dp/Cargo.toml` — 671 passed, 1 ignored, 0 failed. Test count unchanged because no Rust code was modified.

## Refs

- #718 — ECN CE marking at CoS admission (the counter this PR exposes)
- #722 — per-flow ECN threshold (pending; this PR unblocks live validation of #722 by making the counter visible)

---

## PR #726 — docs+cos: validation methodology + #725 findings + interface-level drops gate [MERGED] (merged 2026-04-17)

Branch: `pr/cos-validation-docs`

## Summary

Originally a docs-only follow-up to #725. Review surfaced a real correctness issue in the render path from #724 (per-queue gate suppresses the Drops line in exactly the \`wired-but-silent\` case operators care about), so this PR now carries both:

**Docs** (\`docs/cos-validation-notes.md\`): how to read the CoS admission drop counters surfaced in #724, a decision tree mapping \`(flow_share, buffer, ecn_marked)\` patterns to fixes, and the current (dated, verifiable) test-env limitation that blocks ECN end-to-end validation.

**Code** (\`pkg/dataplane/userspace/cosfmt.go\`, \`cosfmt_test.go\`): Drops-line suppression keyed on **interface** runtime, not per-queue runtime. New multi-queue regression test pinning the queue-row → drops-row interleave invariant.

Updated: \`docs/engineering-style.md\` cross-links the validation methodology so future sessions hit it before writing admission-path code.

## Review findings applied

- **psaab / cosfmt.go:150** — interface-level gate, not per-queue. Removed \`cosQueueView.hasRuntime\`; gate is \`view.interfaceState != nil\`. Zero-valued counters now render on every configured queue of a runtime-visible interface, preserving the \`zero means wired-and-quiet\` contract.
- **psaab / cosfmt_test.go** — new \`TestFormatCoSInterfaceSummaryInterleavesPerQueueDropsInOrder\` with distinct counter tuples per queue. Uses class-name anchors so tabwriter column-width changes don't make it fragile.
- **psaab / cos-validation-notes.md:61** — ECN-never-negotiated section now stamped \`Observed state 2026-04-17\` with a tcpdump verification command operators can re-run.
- **Copilot / cos-validation-notes.md:92** — clarified #717 (tracking issue) vs #720 (the PR that landed the latency clamp).
- **Copilot / cos-validation-notes.md:103** — corrected per-flow drop-rate math: 190/sec / 16 flows ≈ 12 drops/sec per flow (one every ~80 ms), not one every 1–2 s.
- **Copilot / cos-validation-notes.md:123** — replaced dead \`feedback_cos_deploy_config.md\` reference with real paths (\`test/incus/apply-cos-config.sh\` + cross-link to engineering-style.md).
- **Copilot / PR description** — PR body/title updated to reflect both docs and code changes.

## Test plan

- [x] \`go test ./pkg/dataplane/userspace/... ./pkg/cli/... ./pkg/grpcapi/...\` green (+1 new test).
- [x] \`cargo test --manifest-path userspace-dp/Cargo.toml\` unchanged (no Rust source changes in this PR).
- [x] Links verified, no dangling refs in docs.

Refs: #725, #724, #722, #721, #720, #716, #704.

---

## PR #727 — userspace-dp: ECN CE marking on Prepared CoS variant (#718 follow-up) [MERGED] (merged 2026-04-17)

Branch: `pr/727-ecn-prepared-marking`

## Summary

- #718 / #722 landed ECN CE marking at CoS admission, but the policy only handled `CoSPendingTxItem::Local` — the Prepared variant (the XSK-RX→XSK-TX zero-copy hot path carrying iperf3 and NAT'd flows) fell through to a `TODO(#718-followup)` and left `ecn_marked` dormant on the exact workload the marker was meant to attack.
- This PR wires the Prepared variant into `apply_cos_admission_ecn_policy` via a new `maybe_mark_ecn_ce_prepared(req, umem)` helper that mutates the frame bytes in place via `MmapArea::slice_mut_unchecked`. The existing `mark_ecn_ce_ipv4` / `mark_ecn_ce_ipv6` primitives stay unchanged.
- `apply_cos_admission_ecn_policy` now dispatches on `CoSPendingTxItem` and bumps a single `admission_ecn_marked` counter on either branch. Per-variant subcounters can be added later if operators ask for Local-vs-Prepared attribution.

## Why the marker was dormant

See [`docs/cos-validation-notes.md`](https://github.com/psaab/xpf/blob/master/docs/cos-validation-notes.md) for the counter-reading methodology. Live-workload findings from the gRPC-captured iperf3 runs showed `ecn_marked=0` across all admission events because every packet on the 16-flow / 1 Gbps exact-queue path went through the `CoSPendingTxItem::Prepared` branch of `enqueue_cos_item`, and that branch hit the TODO and returned false without marking. Local-variant packets only appear on the slow path (first packet of a new flow, CoS-demoted queues), so the marker's dormancy on Prepared was invisible in the unit tests that only covered Local.

## Safety

The new helper is documented at the call site. Admission runs strictly before the frame is enqueued into the CoS queue, let alone submitted to the XSK TX ring, so the worker that built the frame is still the sole owner of `[req.offset, req.offset + req.len)` within the UMEM. Out-of-range slices return None and the marker returns false — no panic, counter unchanged, packet falls through to the existing admission path.

## Hot-path cost (Prepared branch)

- 1 `slice_mut_unchecked` call: in-range check + pointer arithmetic. ~5 ns.
- 1 dispatch match on `expected_addr_family`. ~1 ns (predictable).
- 1 call to `mark_ecn_ce_ipv4` or `_ipv6`. Already budgeted in #718.

Total ~10 ns added per Prepared admission, same order as the Local branch. No allocations, no atomics, no new branches on unpredictable state.

## Test plan

- [x] `admission_ecn_marks_prepared_ipv4_ect0_packet_above_threshold` — pre-state ECT(0), post-state CE, counter bumped by exactly 1, IP checksum recomputed-from-scratch matches what's in the UMEM.
- [x] `admission_ecn_marks_prepared_ipv6_ect0_packet_above_threshold` — at a non-zero UMEM offset (128); verifies `req.offset` is honoured; tclass goes ECT(0)→CE; version + flow-label nibbles unchanged.
- [x] `admission_ecn_leaves_prepared_not_ect_packet_untouched` — NOT-ECT packet above threshold: counter unchanged, UMEM bytes byte-identical (RFC 3168 §6.1.1.1).
- [x] `admission_ecn_skips_prepared_when_umem_slice_out_of_range` — `offset: u64::MAX / 2, len: 1` → `slice_mut_unchecked` returns None → marker returns false → counter unchanged, no panic.
- [x] `admission_ecn_counter_increments_for_both_local_and_prepared_in_same_queue` — ECT(0) Local + ECT(0) Prepared on one queue: single counter advances by exactly 2. Counter-factual for an accidental counter split.
- [x] Existing admission-ECN tests (6) updated to pass the new `&MmapArea` argument; all still green.
- [x] `mark_ecn_ce_*` primitives unchanged, group 11/11 pass.
- [x] `admission_ecn` group 11/11 pass.
- [x] `cargo test --manifest-path userspace-dp/Cargo.toml` — full suite 680/680 pass.

## Acceptance target (post-merge, orchestrator-driven)

Per [`docs/cos-validation-notes.md`](https://github.com/psaab/xpf/blob/master/docs/cos-validation-notes.md), `ecn_marked` on queue 4 should become non-zero during a live 16-flow iperf3 run through the loss userspace cluster, once the test-env ECN negotiation gap is closed. This PR does not change the marker's RFC 3168 behaviour (still mark-only-on-ECT); it just lets the marker reach the packets it was already supposed to see.

## Refs

- #718 — ECN CE marking at CoS admission (Local-variant landing)
- #722 — per-flow ECN mark threshold
- #704 — umbrella cwnd-collapse symptom
- #725 — validation-pipeline gap findings that surfaced the dormancy

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

---

## PR #728 — userspace-dp: VLAN-aware L3 offset for ECN marking + threshold tune (fixes dormant #727) [MERGED] (merged 2026-04-17)

Branch: `pr/728-vlan-l3-offset`

## Summary

The ECN marker added in #718 / #722 / #727 was structurally correct but **dormant on the live workload** despite verified end-to-end ECT(0) packets. Root cause: the hard-coded `TX_L3_OFFSET = 14` in both Local and Prepared markers missed the 802.1Q tag on VLAN subinterfaces (`reth0 unit 80` → frames are tagged, L3 at offset 18). The marker was reading into the VLAN TCI byte, which rarely matches ECT(0)/ECT(1), so RFC 3168 NOT-ECT early-return fired on every packet.

## Fix

- New `ethernet_l3_offset(bytes)` helper decodes the ethertype and hops a single 802.1Q / 802.1ad VLAN tag. Returns 14 for bare IPv4/IPv6, 18 for single-tagged, `None` for unknown ethertypes (refuses to guess).
- `maybe_mark_ecn_ce` and `maybe_mark_ecn_ce_prepared` derive the L3 offset from each frame instead of the old constant. `TX_L3_OFFSET` deleted.
- Constants `ETH_HDR_LEN = 14`, `VLAN_TAG_LEN = 4` replace magic numbers.

Also tuned `COS_ECN_MARK_THRESHOLD` from 1/2 → 1/5. 50% was too high to catch microburst spikes; 20% fires an order of magnitude earlier and bumps the counter reliably on live load. Rustdoc on the constants documents this as a telemetry-driven tuning knob, not a from-first-principles value.

## Regression pins

- `maybe_mark_ecn_ce_handles_single_vlan_tagged_frame` — VLAN-tagged ECT(0) frame, asserts mark landed at byte 19 (l3_offset 18 + 1) and VLAN TCI at 14–15 is untouched. A revert to hardcoded offset 14 would stamp the TCI instead and this test fails loudly.
- `maybe_mark_ecn_ce_rejects_unknown_ethertype` — unknown ethertype → `None` → no marking. Guards against a future refactor defaulting to 14 on unrecognised frames.

## Live data (`loss:xpf-userspace-fw0`, 16-flow iperf3, 30s, port 5201)

|  | Pre-fix (ecn_marked=0) | Post-fix | Δ |
|---|---|---|---|
| Rate ratio | 1.74× | **1.28×** | best recorded |
| Retransmits | ~200 k | **114 k** | −43% |
| flow_share drops | 2809 | **75** | **−97%** |
| ecn_marked | 0 | **97 349** | ∞ |
| Rate distribution | 42–91 Mbps | 55–71 Mbps | tight |

Queue depth steady at ~150 KB (1.2 ms queueing latency at 1 Gbps, down from microburst-spike pattern). `collapsed=16/16` by the old metric definition is an artefact — all flows now hold `cwnd ≈ 12 KB` steady-state under ECN, which is correct behaviour for a rate-limited link with AQM, not the RTO-driven collapse that metric was designed to catch.

## Test plan

- [x] `cargo test --manifest-path userspace-dp/Cargo.toml` — 682 green, +2 new pins, 0 fail.
- [x] Build + deploy + re-apply CoS via `./test/incus/apply-cos-config.sh`.
- [x] 16-flow iperf3 at port 5201 with `tcp_ecn=1` end-to-end — counters bump as expected (97k marks / 30s / 16 flows).
- [x] Server-side gRPC capture at `172.16.80.200:50051` confirmed ECT(0) preserved through the firewall pre-fix.

Refs: #718, #722, #727, #725.

---

## PR #729 — docs: refresh cos-validation-notes with post-#728 baseline [MERGED] (merged 2026-04-17)

Branch: `pr/cos-notes-post-728-refresh`

## Summary

- Fold the post-#728 live baseline (1.28x rate ratio, 114k retransmits, 75 flow_share drops, 97k ecn_marked per 30 s, ~150 KB queue / 1.5 ms latency, cwnd 8-17 KB) into the CoS validation methodology doc so future sessions don't start from the stale pre-ECN numbers.
- Reframe the "ECN never negotiated" section as **resolved 2026-04-17 via #728**. The old framing was wrong: the server negotiates ECN, but the marker was reading into the 802.1Q TCI byte because `TX_L3_OFFSET=14` missed the VLAN tag on `reth0 unit 80`. Keeps the tcpdump verification command but narrows the conclusion you can draw from it.
- Update the decision tree: new first row describes the current healthy ECN-paced baseline with microburst residual, pointing at #709 (owner-worker hotspot) / #718 Option B (CoDel) as the remaining levers. The old `flow_share high / ecn_marked 0` row now carries the #728 lesson: run the gRPC server-side capture before concluding the endpoint isn't negotiating ECN.
- Add a new **gRPC server-side capture** section pointing at `.codex/skills/iperf-grpc-tcpdump/SKILL.md` and the helper script, with a one-liner `grpcurl` example. Explains why firewall-side netdev tcpdump is useless on AF_XDP and how this capture path unblocked #728.
- All live numbers are tagged "Observed 2026-04-17, post-#728" so future rot is visible.
- Docs-only. No Rust, no tests, no scripts.

## Test plan

- [x] `go test ./pkg/dataplane/userspace/...` — passes (docs-only change, unaffected).
- [x] Re-read top-to-bottom for coherence; reordered so methodology (counters + gRPC capture + decision tree) sits before the dated baseline and the resolved-history section.
- [x] Verified the `engineering-style.md#project-specific-reminders` cross-link anchor still exists (section heading unchanged at line 198).

## Refs

- #727, #728 — the PRs whose live data this doc now reflects
- #725 — validation-pipeline gap that motivated the original doc
- #709, #718 — remaining levers for the microburst residual called out in the new baseline section

---

## PR #730 — docs: #709 owner-worker hotspot design plan [MERGED] (merged 2026-04-17)

Branch: `pr/709-architect-plan`

## Summary

Architect plan for #709 (low-rate exact queue owner-worker hotspot). Docs only. Implementation lands in a follow-up PR against the narrow write scope in section 4 of the plan.

**Recommended slice: Option E — close the telemetry gap before committing to a structural fix.**

Post-#715 / #716 / #720 / #727 / #728, the visible-to-operator symptoms of the owner hotspot (cwnd bimodality tied to RSS landing) are largely masked by ECN working. Residual per-flow variance is not distinguishable on current telemetry from CPU scheduler jitter (#712), ECN-residual microbursts, or sender-side noise. Landing Option B (work-stealing off-worker drain) against noise-level symptoms would violate [engineering-style.md](../blob/master/docs/engineering-style.md)'s discipline for performance PRs (before/after data required).

Plan: [docs/709-owner-hotspot-plan.md](../blob/pr/709-architect-plan/docs/709-owner-hotspot-plan.md).

Contents:
- Options A–E summary table
- Recommendation + why (and what it does not fix)
- Narrow write scope: 7 files, mostly in `userspace-dp/src/afxdp/`
- Invariants: MPSC inbox unchanged, no hot-path allocations, sampled redirect-acquire timing only
- Acceptance criteria tied to `show class-of-service interface` + `cos-validation-notes.md` methodology
- Out-of-scope items filed as follow-up issues on merge (B/C/D as separate issues; A subsumed by #712)

## Test plan

This PR is docs only — no code changes, no tests to run. The implementation PR is responsible for:

- [ ] New `OwnerProfile:` line in `show class-of-service interface` on queue 4 shows non-zero drain_p50/p99 and owner_pps/peer_pps mid-iperf3
- [ ] `flow_share_drops` / `buffer_drops` / `ecn_marked` on queue 4 unchanged from post-#728 baseline (±20%)
- [ ] 5202 / 5203 throughput unchanged
- [ ] Prometheus scrape adds the new series; `promtool check metrics` clean

## Refs

- #709 — issue this plan addresses
- #712 — CPU pinning; Option A is subsumed there
- #715 / #716 / #720 / #727 / #728 — merged fixes that mask the visible symptoms
- `docs/engineering-style.md` — narrow-scope, honest-framing principles
- `docs/cos-validation-notes.md` — validation methodology

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #731 — userspace-dp: owner-profile telemetry for low-rate exact queues (#709 Option E) [MERGED] (merged 2026-04-17)

Branch: `pr/709-owner-profile-telemetry`

## Summary

Implements the measure-before-fix slice from `docs/709-owner-hotspot-plan.md`
§4/§5/§6. Closes the telemetry gap that currently prevents us from
attributing residual #704 cwnd variance on low-rate exact queues to
the owner-worker hotspot versus CPU jitter versus ECN-residual
microbursts.

- Add `drain_latency_hist` (16 power-of-two ns buckets, 1 µs to ~16 ms),
  `drain_invocations`, `drain_noop_invocations`, `redirect_acquire_hist`
  (sampled 1-in-256 on peer-redirect push), and owner-vs-peer pps
  counters on `BindingLiveState`. Bucket selection is branchless
  (one `leading_zeros` + one saturating subtract + one min).
- Time every `drain_shaped_tx` invocation with one pair of
  `monotonic_nanos()` calls (VDSO, no syscall); sample
  `enqueue_tx_owned` producer-side with a worker-seeded counter so
  samples don't lockstep.
- Surface via `show class-of-service interface` (new `OwnerProfile:`
  line under the `Drops:` line, only for exact queues with a named
  owner worker) and Prometheus (`xpf_cos_drain_latency_ns_bucket`,
  `xpf_cos_redirect_acquire_ns_bucket`, `xpf_cos_drain_invocations_total`,
  `xpf_cos_owner_pps`, `xpf_cos_peer_pps`).
- New "Reading the owner-profile counters" section in
  `docs/cos-validation-notes.md` with the decision tree §3 of the
  plan depends on (fat drain_p99 tail → Option B; redirect_p99 > 1 ms
  → smaller producer-side fix; owner_pps >> peer_pps → Option C/D).

## Hot-path shape

- Common `enqueue_tx_owned` push: +1 `fetch_add(Relaxed)` + `&` + `==` (~2-3 ns).
- Sampled push (1-in-256): +2 `monotonic_nanos()` (~30 ns VDSO) + 1 bucket write — amortises to ~0.13 ns per push.
- Every `drain_shaped_tx` invocation: +2 `monotonic_nanos()` + 1 bucket write (~30 ns per tick — an order of magnitude below drain itself).
- Zero allocations. Histograms are `[AtomicU64; 16]` inline on `BindingLiveState`. No `Vec`, no `HashMap`.
- MPSC invariants from #715 preserved: the sample timer wraps `push` externally, no new atomic on the MPSC ring itself.
- Bucket select branchless per plan §5 invariant.

## Deliberately does NOT fix

- The owner hotspot itself. That's Option B (work-stealing off-owner drain) / C (RSS retargeting) / D (owner rotation), each gated on what the new telemetry shows. Deferred per plan §7.
- Live perf numbers today. This PR is telemetry-only; it does not claim to move retransmits, cwnd, or throughput on the 16-flow iperf3 workload. The whole point is to gather data before committing to a structural change.

## Prometheus cardinality

Per plan §5: `num_queues (≤ 64) × num_interfaces (≤ 8) × DRAIN_HIST_BUCKETS (16) = ≤ 8192 series` for each of the two histograms, plus `512` for each of the two gauges. Total ≤ **16896 series**. Within the plan's envelope; flagging here for reviewer visibility per plan §5.

## Design decisions not spelled out in the plan

1. **Bucket lower-bound layout.** The plan comment sketched `ns=0..1024 → 0, 1024..2048 → 1, ... 2^(B+10)..2^(B+11) → B`. The formula `b = 54 - (ns | 1).leading_zeros()` yields `ns=1024 → 1`, not `ns=1024 → 0`. I aligned both the Rust const doc and the CLI µs-formatter on the formula's actual behavior (bucket 0 = sub-1024 ns catch-all; bucket N for N ≥ 1 = [2^(N+9), 2^(N+10))). Flagged explicitly in `bucket_index_for_ns` rustdoc.

2. **Owner-profile aggregation = max, not sum.** The admission counters use `saturating_add` across workers because only the owner writes non-zero. For owner-profile histograms, sum would double-count if any peer worker surfaced the queue with identical values; max is idempotent and preserves the owner's data. Documented in `merge_owner_profile_max` rustdoc.

*(truncated — 73 lines total)*


---

## PR #733 — docs: #708 enqueue pacing design plan [MERGED] (merged 2026-04-17)

Branch: `pr/708-architect-plan`

## Summary

Architect plan for #708 enqueue-side pacing. Docs-only; the
implementor writes code against `docs/708-enqueue-pacing-plan.md §4`
in a follow-up PR.

**Pick:** Option B — per-SFQ-bucket token bucket, reusing #711's
`flow_bucket_bytes` array layout. Narrowest surface that plausibly
moves the residual microburst signal.

**Load-bearing ordering decision:** pacing gate sits **strictly
after** `apply_cos_admission_ecn_policy` in `enqueue_cos_item`. ECN
keeps priority as the lower-latency signal (#718 "mark only if
admitted" invariant); pacing catches microbursts ECN can't react to
in one tick. Reversing the order would make either the marker or
the pacer dead code depending on which threshold fires first.

**Honest framing (per `engineering-style.md`):** the ~114–136k
iperf3 retransmit count on the post-#728 baseline is dominated by
ECN-induced fast-recovery entries (100k CE marks/30s → recovery
entries bump `RetransSegs`), not by wire loss. §3 predicts ≤10%
movement on retrans and names a zero-valued
`admission_pacing_drops` counter as a valid
"close-as-implemented-dormant" outcome.

## Plan structure (matches `docs/709-owner-hotspot-plan.md`)

1. Problem restatement with post-#728 baseline
2. Options A-E at-a-glance with specific verdicts (Option D
   flagged as already landed via #727/#728 — not a new scope)
3. Recommendation (Option B) with honest predictions
4. Narrow write scope — exact files, exact fields, exact integration points
5. Invariants the implementor must preserve (ECN ordering first)
6. Acceptance criteria — quantitative, citing `cos-validation-notes.md`
7. Out-of-scope with named follow-up issue titles

## Test plan

- [ ] Reviewers read the plan, flag any ordering concern (§5 "ECN
      ordering is load-bearing" is the top risk)
- [ ] Reviewers confirm §4 slice is small enough to land as one PR
- [ ] Implementor spawns against §4; the plan is specific enough to
      execute without re-reading issue threads

## Refs

- #708 (closes via implementation follow-up)
- #704 umbrella, #709 companion plan, #727/#728 landed ECN marker,
  #711 SFQ array this plan reuses, #724 counter render pattern
- `docs/engineering-style.md` — narrow-scope, honest-framing

*(truncated — 53 lines total)*


---

## PR #734 — userspace-dp: per-bucket pacing at CoS admission (#708 Option B) [MERGED] (merged 2026-04-17)

Branch: `pr/708-per-bucket-pacing`

## Summary

Implements #708 Option B per [architect plan](docs/708-enqueue-pacing-plan.md) §4/§5: an enqueue-side per-SFQ-bucket token-bucket pacing gate that sits strictly after the ECN marker in `enqueue_cos_item`, with a new `admission_pacing_drops` counter surfaced through the CLI `Drops:` line and Prometheus.

- Adds `flow_bucket_tokens: [u64; 1024]` + `flow_bucket_last_refill_ns: [u64; 1024]` on `CoSQueueRuntime`, and `admission_pacing_drops` on `CoSQueueDropCounters`.
- Pacing gate is integrated inline in `enqueue_cos_item`. Drop-reason attribution priority: `flow_share > pacing > buffer` (plan §5 invariant).
- Refill primitive mirrors the `elapsed_ns × rate / 1e9` math from `refill_cos_tokens`. Per-bucket rate = `queue.transmit_rate_bytes / cos_queue_prospective_active_flows()` — same denominator the per-flow share cap uses (#704 duplication guard).
- Burst cap clamps at `COS_FLOW_FAIR_MIN_SHARE_BYTES` (fast-retransmit floor, 24 KB) so a freshly-arriving flow gets a full recovery window without pacing firing.
- Prometheus exports `xpf_cos_admission_pacing_drops_total{ifindex, queue_id}`.

## Hot-path shape

Per admission, on flow-fair queues: one `refill_cos_flow_bucket_tokens` call (O(1) after the lazy per-bucket refill choice), one `cos_flow_bucket_pacing_exceeded` check, one `saturating_sub` on admit. All branchless `saturating_*` / `.min()` arithmetic. `flow_bucket_tokens` and `flow_bucket_last_refill_ns` are inline `[u64; 1024]` — no allocations.

**Refill strategy: lazy per-bucket (strategy b in the brief), diverges from plan §4.** Plan §4 specified a single shared `pacing_last_refill_ns: u64` + O(1024) refill loop on every admission. At 1 Gbps × 83 kpps that's 83M u64 adds/second — pit-of-expensive. This PR lands per-bucket timestamps up front (8 KB extra per queue) to keep the hot path O(1). Plan §7 had deferred this to a follow-up; I'm landing it now because the perf cost otherwise is baked into every admission. Called out here honestly per engineering-style.md "trust but verify". If the reviewer disagrees, reverting to shared-timestamp is one array removal.

## Top-of-mind risk: ECN ordering

The marker MUST run before pacing. Counter-factual Rust test `pacing_gate_after_ecn_marker_ordering` reconstructs the reversed order and proves `admission_ecn_marked` does NOT bump in that formulation — meaning pacing-before-marker makes ECN dead code. This is the load-bearing invariant for the whole slice.

## Honest framing on live outcome (per plan §3)

`admission_pacing_drops` may land at zero on the current workload. If the ~75 residual `flow_share_drops`/30s are not microburst-driven (i.e. come from slow-timescale buildup that ECN is already marking), pacing will sit dormant. **That is a valid close-as-implemented-not-needed outcome** per plan §3, and this PR does not claim iperf3 retrans will move. The decision tree in `docs/cos-validation-notes.md` now has a row for exactly this shape.

## Test plan

- [x] `cargo test --manifest-path userspace-dp/Cargo.toml` — 699 passed (up from 692, +7 new tests)
- [x] `go test ./pkg/dataplane/userspace/... ./pkg/api/...` — all green
- [x] `go test ./...` — all green
- [x] New Rust tests cover: refill math at queue fair rate, drop on token starvation, admit on sufficient tokens, ECN ordering counter-factual, non-flow-fair bypass, burst-cap at fast-retransmit floor, snapshot propagation
- [x] Extended Go `TestFormatCoSInterfaceSummaryRendersAdmissionDropCounters` and the multi-queue interleave test to cover the new `pacing=N` column
- [x] New Go `TestFormatCoSInterfaceSummaryRendersZeroPacingDropsExplicitly` pins the zero-visibility invariant from #724

## Deferred

- Live validation on the 16-flow / 1 Gbps exact-queue workload — orchestrator will run this after merge per the agent brief "Do NOT deploy to cluster VMs. Orchestrator validates live after merge."
- Per-flow token-bucket pacing (plan §7 Option A) — only if this slice's counter shows ≥100k pacing drops/30s, which would mean per-bucket resolution is insufficient.
- Option C BQL-style adaptive admission cap — deferred per plan §7.
- `admission_flow_share_drops` and `admission_buffer_drops` Prometheus counters — only `admission_pacing_drops` is exported here per the narrow scope contract; adding the others is one more three-line block that can land in a follow-up if operators ask for it.

## Refs

- Closes #708 (on live-data validation)
- Plan: `docs/708-enqueue-pacing-plan.md`
- Methodology: `docs/cos-validation-notes.md` (decision tree updated with `pacing` column)
- Related: #704, #705, #710, #711, #716, #717, #718, #722, #724, #727, #728

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## PR #736 — Revert #734 pacing — burst cap too aggressive, doubles retrans; retry in #735 [MERGED] (merged 2026-04-17)

Branch: `pr/revert-708-pacing`

## Why revert

Live validation of #734 on the 16-flow / 1 Gbps exact queue workload showed net regression on the primary jitter metrics:

| Metric | pre-#708 | post-#708 | Δ |
|---|---|---|---|
| `flow_share_drops` / 30s | 75–156 | **0** | −100% |
| `ecn_marked` / 30s | 97–101 k | 27 k | −73% |
| `admission_pacing_drops` / 30s | — | **23 k** (firing heavily) | new |
| iperf3 retransmits / 30s | 114–136 k | **260 k** | **+100%** |
| Rate ratio | 1.24–1.28× | **1.55×** | degraded |

Pacing absorbed all flow-share drops (good), but converted ECN marks into tail-drops (bad), doubling sender-side retrans.

## Root cause

Architect plan §5 chose burst cap = `COS_FLOW_FAIR_MIN_SHARE_BYTES = 24 KB` (the fast-retransmit floor). TCP cubic at steady state runs cwnd > 24 KB routinely during burst transmission — normal behaviour, not a microburst. Pacing drops those legitimate bursts.

The ordering invariant ("ECN first, pacing second") prevents ECN becoming dead code but doesn't protect against a marked packet ALSO being dropped by pacing on a later admission: sender sees CE + drop, weights the drop heavier, ECN's smooth-backoff benefit is lost.

## Next step

Retry tracked in #735 with burst cap = `share_cap` (~76 KB at 16 flows on 1 Gbps) instead of `MIN_SHARE_BYTES` (24 KB). Expected to keep the flow_share-drops improvement while not converting ECN signals into drops. Re-measure before re-merging.

## Test plan

- [x] `cargo test` — 692 green (same as pre-#734).
- [x] `go test ./pkg/dataplane/userspace/...` — green.
- [ ] Re-deploy + re-validate post-revert restores 1.24× ratio / 114k retrans.

Refs: #708, #734, #735, #733 (plan that needs a §5 update before retry).

---

