# bpfrx Project Memory

## Project Overview
- **Goal:** eBPF-based firewall cloning Juniper vSRX capabilities with native Junos configuration syntax
- **Stack:** Go userspace (cilium/ebpf) + C eBPF programs (XDP ingress + TC egress)
- **Architecture plan:** `/home/ps/.claude/plans/glistening-hugging-music.md`
- **Detailed phase notes:** `phases.md`
- **Bug tracker:** `bugs.md`
- **Future optimizations:** `optimizations.md`
- **Sync protocol reference:** `sync-protocol.md`

## Build & Deployment
- `make generate` then `make build` for full build (bpf2go + Go binary)
- `make build-ctl` builds remote CLI client (`cli` binary)
- `make proto` regenerates protobuf Go code (needs `PATH=$PATH:$HOME/go/bin`)
- All 14 BPF programs pass verifier on kernel 6.18.9 (9 XDP + 5 TC)
- **Known:** xdp_zone fails verifier on kernel 6.12 (NAT64 loop complexity)
- 630+ tests pass (`make test`) across 20 packages
- **systemd deployment:** `make test-deploy` builds, pushes, installs unit, starts service

## Architecture

### BPF Pipeline (Tail Calls)
```
XDP Ingress: main -> screen -> zone(+pre-routing) -> conntrack -> policy -> nat -> nat64 -> forward
TC Egress:   main -> screen_egress -> conntrack -> nat -> forward
```
- Per-CPU array scratch map passes metadata between stages
- Dual session entries (forward + reverse) in HASH map
- NAT uses "meta as desired state" pattern

### Config System
- Three-phase compilation: Junos AST -> typed Go structs -> eBPF map entries
- Candidate/active config with commit model (up to 50 rollback slots)
- Config validation: cross-reference checks for zones, addresses, apps, screens
- `load override`/`load merge` for bulk config import
- `show | display set` for flat set export (FormatSet())
- **${node} variable expansion:** `ExpandGroupsWithVars()` resolves `${node}` in apply-groups references
  - `CompileConfigForNode(tree, nodeID)` — single config for both HA nodes
  - Cluster node ID from `/etc/bpfrx/node-id` file (file absent = standalone)
  - Configstore `compileTree()` dispatches to correct compiler based on nodeID

### Interface Management (networkd)
- **bpfrxd manages ALL interfaces** — renames, addresses, DHCP, and brings down unconfigured ones
- `.link` files: boot-time rename via `bpfrx-link-setup.service` (PCI bus order → fxp0, em0, ge-X-0-Y), prefix `10-bpfrx-`; RETH members use `OriginalName=` (PCI name) instead of `MACAddress=` for stable boot matching
- `.network` files: addresses, RA disable, VLAN parent, ActivationPolicy=always-down for unmanaged
- Unmanaged interfaces: brought down immediately + ActivationPolicy=always-down for persistence
- DHCP interfaces: daemon's DHCP client manages addresses; address reconciliation skipped
- VRF devices and tunnel interfaces excluded from unmanaged detection (`daemonOwned` map)
- `setup.sh` writes bootstrap `.link` files for first boot (before daemon has ever run)

### APIs & CLIs
- **gRPC:** 127.0.0.1:50051 (config, sessions, stats, routes, IPsec, DHCP)
- **HTTP REST:** 127.0.0.1:8080 (health, Prometheus, config, full gRPC parity)
- **Local CLI:** `bpfrxd` in TTY mode (tab completion, `?` help, pipe filters)
- **Remote CLI:** `cli` binary connects via gRPC
- **Single source of truth:** `pkg/cmdtree/tree.go` defines `OperationalTree` and `ConfigTopLevel`
  - `pkg/cli` imports via type alias `completionNode = cmdtree.Node`
  - `pkg/grpcapi` imports `cmdtree.CompleteFromTree()` directly
  - `cmd/cli` imports `cmdtree.LookupDesc()` and `cmdtree.PrintTreeHelp()`
  - Adding a command to `pkg/cmdtree/tree.go` auto-propagates to ALL CLIs
- **Dynamic completion:** `Node.DynamicFn` provides config-aware tab/? for interfaces, zones, routing instances
- **Junos-style prefix matching:** `resolveCommand()` + `cmdtree.KeysFromTree()` — no hardcoded lists
- **`?` instant help:** readline `Listener` intercepts `?` key, shows help without Enter
- **Tab descriptions:** Multi-match tab shows descriptions above prompt via `cmdtree.WriteHelp()`

### Chassis Cluster (HA)
- **pkg/cluster/cluster.go:** Core state machine — Manager, NodeState, RedundancyGroupState
- **State enum:** StateSecondary (0), StatePrimary (1), StateSecondaryHold (2), StateLost (3), StateDisabled (4)
- **Weight scoring:** Initial 255, subtract per monitor; weight=0 → secondary; "ip:" prefix for IP monitors
- **Event channel:** ClusterEvent → GARP on primary; manual failover/reset supported
- **Manual failover (`6d63020`):** `ManualFailover()` MUST set `rg.Weight=0` so peer election sees "Peer weight 0" → becomes primary. `ResetFailover()` calls `recalcWeight()` to restore weight from monitor state
- **Config:** ClusterConfig.{ClusterID, NodeID, HeartbeatInterval, HeartbeatThreshold, ControlInterface, PeerAddress, FabricInterface, FabricPeerAddress, ConfigSync, NATStateSync, IPsecSASync}
- **Daemon:** Manager.Start(ctx)/Stop() lifecycle, RETH IP registration in applyConfig, auto-StartHeartbeat when PeerAddress configured
- **Two-VM test env:** `test/incus/cluster-setup.sh` (bpfrx-fw0 + bpfrx-fw1 + cluster-lan-host)
- **Commands:** show chassis cluster {status,interfaces,information,statistics}; request failover; request system software in-service-upgrade
- **monitor.go:** 1s netlink link state + ICMP probes; testable via interfaces
- **garp.go:** AF_PACKET ARP reply + IPv6 NA (unsolicited, RFC 4861), auto on primary; **heartbeat.go:** UDP:4784, "BPFX" magic
- **election.go:** Preempt/non-preempt/split-brain, effective priority = base*weight/255; active/active per-RG primary
- **sync.go:** TCP RTO — "BPSY" magic, 9 msg types (7 session + 1 config + 1 IPsec SA), full session install via SetSessionV4/V6; **reth.go:** physical member management
- **VRRP-backed RETH (bondless):** native Go VRRPv3 daemon (`pkg/vrrp/`) manages RETH VIPs directly on physical member interfaces; VRID=100+rgID; priority 200(primary)/100(secondary); no bond devices — VRRP runs on physical; `RethToPhysical()` resolves reth→physical member; networkd omits static addresses for RETH (VRRP owns VIPs); SNAT uses config-based address lookup for RETH interfaces
  - **pkg/vrrp/**: packet.go (codec), instance.go (state machine, VIP mgmt), manager.go (lifecycle, AF_PACKET sockets)
  - AF_PACKET receiver for all instances; `reconcileInterfaceAddresses()` skips RETH; IPv6 NODAD; RETH→physical FRR routes
- **RETH virtual MAC:** Per-node `02:bf:72:CC:RR:NN`; `programRethMAC()` step 2.6 (link-down→set MAC→link-up); `accept_dad=0`; compiler skips `.link` when virtual MAC; `bpf_fib_lookup` smac auto-uses kernel MAC
  - **Gotcha:** `netlink.LinkSetHardwareAddr` returns EAGAIN on UP interfaces — must bring down first
  - **Gotcha:** kernel link-local not regenerated without down/up cycle after MAC change
  - **Gotcha:** import cycle `cluster↔dataplane` — `isVirtualRethMAC()` duplicated locally in compiler.go
  - **Gotcha:** RETH `.link` must use `OriginalName=` not `MACAddress=` (MAC alternates physical↔virtual across reboots)
- **ISSU:** `ForceSecondary()` drains all RGs to peer, then operator replaces binary + restarts
- **VRRP sync hold:** preempt=false until bulk sync (10s timeout). `ReleaseSyncHold()` → `preemptNowCh` for instant preemption
- **VRRP timing:** RETH 30ms interval (masterDown ~97ms, measured ~60ms failover); configurable `reth-advertise-interval`; async GARP burst; 3× priority-0 on shutdown; user VRRP seconds*1000; wire centiseconds
- **VIP reconciliation:** `ReconcileVIPs()` re-adds VIPs + GARP after `programRethMAC` link DOWN/UP
- **Reboot resilience:** RETH `.link` `OriginalName=`; `ensureRethLinkOriginalName()` auto-fix; `deriveKernelName()` virtio-over-PCI
- **Fabric forwarding:** `try_fabric_redirect()` in xdp_zone redirects to fabric peer when FIB fails for synced sessions
- **IPsec SA sync:** Primary sends active connection names every 30s; new primary re-initiates via swanctl --initiate
- **Config sync:** `syncMsgConfig=8`, `QueueConfig()` sends full config text, `OnConfigReceived` callback, 16MB payload limit
- **Config read-only:** `clusterReadOnly` field in configstore — secondary nodes reject config mutations
- **MASTER-only radvd/kea:** `watchVRRPEvents()` → `applyRethServices()` on MASTER, `clearRethServices()` + goodbye RA on BACKUP

### NPTv6 (RFC 6296)
- **Stateless IPv6 prefix translation:** 1:1 /48 prefix rewriting, checksum-neutral
- **Algorithm:** precompute adj, rewrite prefix words 0-2, apply adj to word[3] with carry fold
- **BPF:** `nptv6_rules` HASH (128), key: prefix[6]+direction(u8), value: xlat_prefix[6]+adjustment(u16)
- **Helper:** `nptv6_translate()` in `bpfrx_nat.h` — inbound adds ~adj, outbound adds adj; 0xFFFF→0x0000
- **Session flag:** `SESS_FLAG_NPTV6 (1<<8)`; config: `StaticNATRule.IsNPTv6 bool`
- **Pipeline:** inbound in xdp_zone (dst rewrite), outbound in xdp_policy (src rewrite)
- **Config:** `then static-nat nptv6-prefix <internal-prefix>` (both hierarchical + flat set)

### Routing
- **FRR is sole route manager** — bpfrx NEVER directly modifies kernel routes
- Static, DHCP-learned, per-VRF routes all managed via FRR frr.conf
- `systemctl reload frr` triggers diff-based update
- BGP/OSPF/IS-IS export → FRR redistribute mapping
- BGP neighbor inheritance from group (description, multihop, peer-as)
- **next-table route leaking:** Uses `ip rule` (not FRR) — adds `ip rule add to <prefix> lookup <table>` for inter-VRF static route leaking
- **rib-groups route leaking:** Uses `ip rule add from all lookup <table> pref 33000+` for interface-routes rib-group leaking between VRFs
- **PBR:** `ip rule` at priority 34000-34999 for firewall filter `routing-instance` action (DSCP→TOS, src/dst addr)
- **ip rule priority ranges:** rib-groups 33000-33099, PBR 34000-34999 (both after main table at 32766)

## Key Patterns & Gotchas
- `binary.NativeEndian` for BPF `__be32` IP fields — **NEVER BigEndian**
- C struct padding: always match Go struct size to C sizeof (trailing Pad bytes)
- Parser handles both `{ }` hierarchical and flat `set` syntax
- **Flat set tests:** Use `ParseSetCommand()` + `tree.SetPath()`, NOT `NewParser()` (newlines are whitespace in parser)
- IPv6 sessions use `session_v6_scratch` per-CPU map (stack too small)
- **TTL check must exist in BOTH xdp_nat AND xdp_forward:**
  - `xdp_nat`: catches NAT'd traffic before NAT rewrite (preserves original IPs for ICMP TE)
  - `xdp_forward`: catches non-NAT established sessions that skip xdp_nat via conntrack fast-path
  - Conntrack fast-path: `next_prog = XDP_PROG_FORWARD` when no SNAT/DNAT flags (`xdp_conntrack.c:64-66`)
- BPF verifier: branch merges lose packet range — re-read ctx->data after
- BPF verifier: combined stack limit is 512 bytes across call frames
  - All 4 REJECT functions (RST v4/v6, ICMP unreach v4/v6) must be `__noinline`
  - ICMP functions use `session_v4_scratch` map as byte buffer (free at REJECT time)
  - xdp_policy had 528 bytes; fixed by using scratch map fields instead of stack arrays
  - Use meta->nat_src_ip.v6 as scratch buffer for SNAT allocation
- BPF verifier: variable-offset pkt pointer range tracking
  - Verifier only updates `r` (validated range) when `var_off` is narrow (~0xFF)
  - With `var_off=(0x0; 0xffff)` (e.g. from loop-computed offset), verifier refuses to track range after bounds check → `r=0` → all packet accesses fail
  - Fix: use constant-offset from validated pointer, e.g. `(void *)(emb_ip6 + 1)` instead of `data + variable_offset`
  - `__u16` type causes `<<48; s>>48` sign-extension → `smin=-32768` → also fails for pkt pointer math
  - **Narrowing meta offsets:** `meta->l3_offset` (u16) has wide var_off; mask with `& 0x3F` before pkt pointer math (`66833c5`)
- BPF verifier: **pointer bitwise OR prohibited** (`0080cbc`)
  - `if (sv4 || sv6)` where both are pointers → compiler emits `|=` on pointer regs → verifier rejects
  - Fix: use separate `if (ptr != NULL)` checks — NEVER logical OR two BPF pointers
- **CHECKSUM_PARTIAL in generic XDP (NAT64):** (`78baec0`)
  - Generic XDP (virtio-net) preserves `skb->ip_summed=CHECKSUM_PARTIAL` through `bpf_redirect_map`
  - From-scratch checksums get CORRUPTED: kernel/NIC adds L4 byte sum to already-complete value
  - Fix: when `meta->csum_partial`, write only pseudo-header seed (`csum_fold(ph)` WITHOUT complement)
  - ICMPv4 (no pseudo-header): set `checksum=0` for CHECKSUM_PARTIAL, kernel sums all bytes
  - NAT44 unaffected: incremental updates (`csum_update`) are compatible with CHECKSUM_PARTIAL
  - `bpf_xdp_adjust_head(ctx, 20)` doesn't move `skb->csum_start` — L4 header stays at same memory addr
- `iter.Next(&key, nil)` crashes in cilium/ebpf v0.20 — use `var val []byte`
- TTY detection: `unix.IoctlGetTermios(fd, TCGETS)` not `os.ModeCharDevice`
- Interfaces must be brought UP after XDP/TC attachment (netlink.LinkSetUp)
- `bpf_fib_lookup` NO_NEIGH (rc=7): route exists but no ARP entry
  - STALE entries work fine — only truly absent entries cause NO_NEIGH
  - `arping` doesn't populate kernel ARP with XDP attached — use `ping` instead
  - `skb->ingress_ifindex != 0` in TC identifies kernel-forwarded packets
  - **Existing sessions (`d95a84e`):** META_FLAG_KERNEL_ROUTE + conntrack tail-call — NAT reversal then kernel forwards. In cluster mode, `try_fabric_redirect()` sends to peer via fabric link instead (faster, avoids kernel path)
  - **New connections:** XDP_PASS → kernel resolves ARP/NDP → retransmit goes through full pipeline
  - **RST protection:** conntrack skips state→CLOSED transition when META_FLAG_KERNEL_ROUTE set (kernel may drop the RST, poisoning session)

## Hitless Restart Patterns
- Non-destructive SIGTERM (no FRR/DHCP/VRF cleanup); full teardown via `bpfrxd cleanup`
- DHCP uses `context.Background()` — prevents address removal on restart
- Deferred `link.Update()` AFTER all compilation; stale pins need `bpfrxd cleanup` + fresh start
- **PROG_ARRAY pinning (CRITICAL):** `xdp_progs`/`tc_progs` MUST be pinned to survive daemon exit
- Deterministic IDs (sorted keys); populate-before-clear; dnat_table before sessions (`a030446`)

## Performance
- **bpf_printk:** NEVER leave in production (55%+ CPU)
- **Throughput:** 25+ Gbps native XDP, 15.6 Gbps virtio-net
- **Cluster failover:** ~60ms (VRRP 30ms, masterDown ~97ms); planned shutdown near-instant (priority-0 burst); failback ~130ms; reboot→MASTER ~6s
- Per-interface XDP: `redirect_capable` map; iavf lacks native XDP, use PF passthrough

## Incus Test Environment
- See `test_env.md` for topology details; CLAUDE.md for make targets
- VM: Debian 13, kernel 6.18.9; `sg incus-admin -c "make ..."` if permission errors
- **Cluster:** `make cluster-init/create/deploy/destroy` — bpfrx-fw0 (pri 200) + bpfrx-fw1 (pri 100) + cluster-lan-host
  - Heartbeat: 10.99.0.0/30, Fabric: 10.99.1.0/30, WAN RETH: 172.16.50.10, LAN RETH: 10.0.60.1

## SSH / Git Push — `source ~/.sshrc` before `git push`

## Team Pattern (User Preference) — MANDATORY
- **Always spawn:** Feature teammates + Test teammate (REQUIRED) + Docs teammate (REQUIRED)
- Test teammate: `make test` + `make test-deploy` + connectivity tests; never stops until validated
- Docs teammate: updates bugs.md, phases.md, optimizations.md, MEMORY.md continuously
- **Testing focus:** eBPF only (not DPDK) until further notice
- **Code for both:** Always implement for both eBPF and DPDK structs/code

## Workflow
- **Always commit and push** when finishing a task
- **Full validation before commit:** `make test` + `make test-deploy` + connectivity tests
- Guard context window — keep messages concise

## Recent Features (see `phases.md` for full details)
- **Fabric cross-chassis fwd:** `try_fabric_redirect()` redirects to peer via fabric when FIB fails for synced sessions
- **Session sync failover:** Hitless TCP — NO_NEIGH kernel-route, monotonic rebase, ARP/ND warmup
- **Sub-100ms failover (`ff7821c`, `ae1a717`):** VRRP 30ms (was 250ms), async GARP burst, 3× priority-0 shutdown, immediate peer takeover; sync 1s, debounce 500ms, heartbeat 200ms/5
- **Reboot resilience (`f8353de`):** `.link` OriginalName= for RETH + auto-fix
- **VIP reconciliation (`a4eb2b2`):** `ReconcileVIPs()` after programRethMAC
- Sprints: VRRP-NATIVE, HA-CONFIG, NPTv6, SEC-LOG, FF-1, IF-1, HA-8, HA-TIMING, HA-REBOOT (see `phases.md`)

### Firewall Filter Policer Architecture
- Token bucket + three-color policer (per-CPU lock-free); lo0 filter in `xdp_forward.c`; flex match byte-offset from L3
