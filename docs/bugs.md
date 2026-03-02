# Bugs Found During VM Testing

## Critical Bugs

### Manual failover leaves both nodes secondary (`6d63020`)
- **Symptom:** `request chassis cluster failover redundancy-group 1 node 1` causes both nodes to show RG1 as "secondary" — peer never becomes primary
- **Root cause:** `ManualFailover()` set `ManualFailover=true` and `State=Secondary` but left `Weight=255`. Heartbeat still advertised full weight. Peer's election saw `peerEff=200 > localEff=100` and stayed secondary. The `ManualFailover` flag is local-only (not sent in heartbeat) — peer relies entirely on weight to detect failover
- **Fix:** Set `rg.Weight = 0` in `ManualFailover()` so peer sees "Peer weight 0" → `electLocalPrimary`. `ResetFailover()` calls `recalcWeight()` to restore weight from monitor state + re-run election
- **Note:** `ForceSecondary()` (ISSU) already did `rg.Weight = 0` correctly — `ManualFailover()` was the only path missing it

### BulkSync nil pointer panic after SO_REUSEPORT fix (`e3ceebe`)
- **Symptom:** `panic: runtime error: invalid memory address or nil pointer dereference` in `BulkSync()` at `sync.go:402` — 3 crash-loops on fw0 after cluster deploy
- **Root cause:** `NewSessionSync()` created with `dp=nil`; `SetDataPlane()` called later during daemon startup. Previously masked by 60s socket bind retry delay (old sockets blocked rebind). After adding `SO_REUSEPORT`, sockets bind immediately → peer connects before dp is wired → `BulkSync()` calls `s.dp.IterateSessions()` on nil dp
- **Fix:** Added `if s.dp == nil { return fmt.Errorf("dataplane not ready") }` guard at top of `BulkSync()`. Callers already handle error gracefully (log warning, continue). `handleMessage()` already had per-case `if s.dp != nil` guards — no change needed there
- **Lesson:** When removing timing-dependent workarounds (bind retries), audit all code paths that assumed the old timing provided implicit ordering guarantees

### NAT64 TCP broken on generic XDP (CHECKSUM_PARTIAL corruption) (`78baec0`)
- **Symptom:** NAT64 TCP (iperf3 via `64:ff9b::`) fails with bad checksum; ICMP ping works
- **Root cause:** Three interacting bugs:
  1. **xdp_policy.c session key corruption:** `meta->src_ip` was overwritten with SNAT IPv4 addr BEFORE `create_session_v6()` used it as session key source. Fix: use `nat_src_ip` as scratch, overwrite `src_ip` after session creation.
  2. **xdp_conntrack.c + xdp_zone.c NAT64 flag propagation:** On established session hits, `SESS_FLAG_NAT64` was not propagated from session flags to `meta->nat_flags`, so `xdp_nat` never dispatched to `xdp_nat64` for existing sessions.
  3. **xdp_nat64.c CHECKSUM_PARTIAL corruption:** Generic XDP (virtio-net) preserves `skb->ip_summed=CHECKSUM_PARTIAL` through `bpf_redirect_map`. From-scratch TCP/UDP checksum was complete, but kernel/NIC finalizes by adding L4 byte sums to the existing check field — corrupting it.
- **Fix for #3:** Split into two paths based on `meta->csum_partial`:
  - `csum_partial=1`: write only IPv4 pseudo-header seed (`csum_fold(ph)` without complement). Kernel's `skb_checksum_help` finalizes by summing L4 bytes + seed.
  - `csum_partial=0`: compute full from-scratch checksum (existing loop + `~csum_fold(sum)`)
  - ICMPv4 (no pseudo-header): set `checksum=0` for CHECKSUM_PARTIAL (kernel sums all ICMP bytes)
- **Why NAT44 wasn't affected:** NAT44 uses incremental checksum updates compatible with CHECKSUM_PARTIAL
- **Why ICMP ping worked:** ICMPv6→ICMPv4 checksum happened to be correct because the from-scratch sum for short ICMP echo packets was finalized correctly
- **Key insight:** `bpf_xdp_adjust_head(ctx, 20)` for IPv6→IPv4 doesn't move `skb->csum_start` — TCP header stays at same memory address, only `skb->data` shifts
- **Files:** `bpf/xdp/xdp_nat64.c`, `bpf/xdp/xdp_conntrack.c`, `bpf/xdp/xdp_policy.c`, `bpf/xdp/xdp_zone.c`

### VRRP manager deadlock on cluster secondary node (`58ad85b`)
- **Symptom:** `show security vrrp` hangs indefinitely on fw1 (cluster secondary)
- **Root cause:** Three interacting bugs:
  1. `File()` puts socket in blocking mode → `recvmsg` syscall blocks indefinitely
  2. `stop()` calls `conn.Close()` AFTER `<-vi.stopped` → waits for receiver that's stuck in `recvmsg`
  3. `UpdateInstances()` holds Manager write lock during `stop()` → all `RLock` callers (gRPC handlers) blocked
- **Race trigger:** DHCP recompile + cluster debounced timer both call `UpdateInstances()` within milliseconds — timer holds write lock, blocks on `stop()`, then DHCP blocks waiting for write lock, then all gRPC handlers block on read lock
- **Fix:** (a) Use `SyscallConn().Control()` instead of `File()` for SO_BINDTODEVICE, (b) `SetReadDeadline(1s)` in receiver, (c) Close socket BEFORE waiting for goroutine exit in `stop()`
- **Bonus fix:** Manager nil panic — `applyConfig()` ran before manager creation; moved eager creation to before first `applyConfig`
- **Files:** `pkg/vrrp/instance.go`, `pkg/vrrp/manager.go`, `pkg/daemon/daemon.go`

### NAT64 ICMP error payload length for truncated embedded packets (`5fa143b`)
- ICMP errors from some routers (directly connected gateways) truncate the embedded original packet
- `nat64_icmp_error_4to6()` computed IPv6 `payload_len` from embedded IPv4 `tot_len` (full original size)
- But the ICMP error only included a portion of the L4 data → IPv6 payload_length exceeded actual data
- tcpdump showed: `[header+payload length 112 > length 96] (invalid)` → packet dropped by receiver
- **Fix:** Cap `emb_l4_len` by `outer_tot_len - 48` (actual data present in ICMP error)
- **Root cause:** `outer_tot_len - outer_hdr(20) - icmp_err(8) - emb_hdr(20)` = actual embedded L4 bytes
- **File:** `bpf/xdp/xdp_nat64.c` lines 782-793

### NAT64 ICMP traceroute echo ID bug (`91bdd38`)
- In `nat64_xlate_6to4()`, `old_sport = meta->src_port` for ICMP stored the SNAT-allocated port, not the original echo ID
- TCP/UDP correctly read `old_sport` from packet header; ICMP had no such override
- `nat64_state.orig_src_port` got the wrong value → ICMP error translation restored wrong echo ID → mtr couldn't match responses
- **Fix:** Added `else if (orig_proto == PROTO_ICMPV6) { old_sport = meta->dst_port; }` — `meta->dst_port` retains original echo ID since policy only changes `src_port`
- **File:** `bpf/xdp/xdp_nat64.c` line 282

### ipToUint32BE byte order
- `binary.BigEndian.Uint32(ip4)` produced wrong bytes when cilium/ebpf serializes as native-endian
- **Fix:** Use `binary.NativeEndian.Uint32(ip4)` so bytes match raw network order BPF writes to `__be32`
- **Affected:** DNAT, static NAT, NAT pool IPs, NAT64 prefix
- **File:** maps.go

### Family inet/inet6 AST shape
- Hierarchical syntax `family inet { dhcp; }` creates `Node{Keys:["family","inet"]}` — AF name is Keys[1]
- Set-command `set interfaces eth0 unit 0 family inet dhcp` creates `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`
- **Fix:** Compiler must handle BOTH shapes
- **File:** compiler.go

### SessionValueV6 trailing padding
- C struct is 152 bytes (8-byte aligned due to __u64), Go struct was 148 bytes
- **Fix:** Added `Pad2 [4]byte` to match. Compare `sizeof` in C vs Go `unsafe.Sizeof`
- **Pattern:** When mirroring C structs in Go for cilium/ebpf, always add trailing padding

### Host-inbound bypass in XDP policy
- `bpf_fib_lookup` with broadcast/unicast-to-unknown-IP matches default route
- Sends host-bound packets through policy pipeline where deny-all drops them
- **Fix:** xdp_policy checks `host_inbound_flag()` before denying, tail-calls to xdp_forward with fwd_ifindex=0

## Important Bugs

### tx_ports devmap value size
- Go wrote 4-byte struct (ifindex only) but BPF DEVMAP_HASH expects 8-byte `bpf_devmap_val` (ifindex + prog_fd)
- **File:** loader.go

### SNAT hierarchical syntax
- Config compiler only handled flat `source-nat interface` keys, not hierarchical `source-nat { interface; }` with child nodes
- **Fix:** FindChild() fallback in compiler.go

### iter.Next(&key, nil) crash
- cilium/ebpf v0.20 panics when iterating non-empty maps with nil value pointer
- **Fix:** Always use `var val []byte; iter.Next(&key, &val)`

### TTY detection for daemon mode
- `os.Stdin.Stat()` with `os.ModeCharDevice` returns true for `/dev/null` (it IS a character device)
- Caused CLI to start under systemd, read EOF from /dev/null, exit immediately
- **Fix:** Use `unix.IoctlGetTermios(fd, unix.TCGETS)` — only succeeds on real terminals

## SR-IOV Bugs

### SR-IOV in Incus VMs
- `nictype: sriov` and `nictype: physical` both fail with `DeviceNotFound` (agent race)
- **Fix:** Use `type: pci` with `address=<BDF>` instead — hot-add after boot
- VFs on enp101s0f0np0 (X710) have individual IOMMU groups so VFIO works

### SR-IOV PCI passthrough pattern
```bash
vf_pci=$(readlink -f /sys/class/net/enp101s0f0v0/device | xargs basename)
incus config device add VM internet pci address=$vf_pci
```
VF appears as enp10s0f0 inside VM (NOT enp10s0 as initially expected).

## Phase 39+ Bugs

### xdp_policy BPF stack overflow (528 > 512 bytes)
- Combined stack of `xdp_policy_prog` + `nat_pool_alloc_v6` was 528 bytes (512 limit)
- Two 16-byte stack arrays in IPv6 SNAT path: `orig_src_ip_save[16]` and `alloc_ip_v6[16]`
- **Fix:** Replace stack arrays with per-CPU scratch map fields:
  - `alloc_ip_v6[16]` → `meta->nat_src_ip.v6` (scratch buffer)
  - `orig_src_ip_save[16]` → direct `meta->src_ip.v6` reads (not yet modified)
- **Commit:** 8162f9f

### uint32ToIP() NAT display bug
- `uint32ToIP()` in server.go used `binary.BigEndian.PutUint32` for rendering
- NAT IPs displayed with swapped octets: `10.2.0.10` instead of `10.0.2.10`
- **Fix:** Changed to `binary.NativeEndian.PutUint32`

### Interfaces not UP after XDP/TC attachment
- XDP/TC attachment doesn't bring interfaces UP
- **Fix:** Added `netlink.LinkSetUp()` after attachment
- Note: use `netlink.LinkByIndex()`, not `*net.Interface` (different types)

### Management DHCP route shadowing FRR
- systemd-networkd installs DHCP default route (distance 0) on enp5s0
- Shadows FRR DHCP-learned routes (distance 200)
- **Fix:** Set `UseRoutes=false` in `/etc/systemd/network/enp5s0.network`

### BPF_FIB_LKUP_RET_NO_NEIGH (rc=7) cold ARP forwarding failure
- `bpf_fib_lookup` returns NO_NEIGH when route exists but no ARP/NDP entry
- Does NOT fill dmac/smac fields — cannot `bpf_redirect_map` with zero MACs
- **Forward path fix:** XDP_PASS original (un-NAT'd) packet at xdp_zone → kernel forwards → triggers ARP → TC drops (no CT match, `ingress_ifindex != 0`)
- **Return path issue:** SNAT'd return packet has local dst IP → kernel delivers locally instead of forwarding → no ARP trigger for original sender
- **Fix:** Periodic ping-based neighbor resolution (every 15s) for DNAT pools, static NAT, gateways, address-book hosts
- STALE ARP entries work fine with `bpf_fib_lookup` (returns SUCCESS)
- **Files:** `xdp_zone.c`, `tc_main.c`, `tc_conntrack.c`, `daemon.go`

### arping doesn't populate kernel ARP table with XDP attached
- `arping` uses PF_PACKET raw sockets for ARP — ARP replies received by arping but NOT by kernel ARP handler when XDP is attached
- **Fix:** Use `ping` instead of `arping` for proactive neighbor resolution — `ping` triggers the kernel's own ARP/NDP resolution before sending ICMP
- Note: only affects arping tool, not ARP protocol itself. Kernel-initiated ARP (from routing decisions) works fine with XDP.

### TC egress: kernel-forwarded packets leak without session
- When XDP_PASS sends a packet to kernel (e.g., NO_NEIGH case), kernel may forward it through TC egress
- Without conntrack match, un-NAT'd packets would leak to destination
- **Fix:** Check `skb->ingress_ifindex != 0` (indicates kernel forwarded, not locally originated) in tc_conntrack → `TC_ACT_SHOT`
- **Files:** `tc_main.c` (propagate ingress_ifindex), `tc_conntrack.c` (drop on CT miss)

## Performance Bugs

### bpf_printk consuming 55%+ CPU (`e104112`)
- Debug tracing left in production BPF → always remove for production

### CHECKSUM_PARTIAL NAT checksum corruption (`0950a1f`)
- Non-complemented update needed for PH seed in CHECKSUM_PARTIAL

### Generic XDP 16% CPU overhead (`f9edb92`)
- All interfaces forced generic because iavf lacks native XDP
- Fix: Per-interface mode selection with `redirect_capable` map

### Cross-CPU NAT port collisions (`7aa77f0`)
- Fix: Per-CPU port counter partitioning

## Hitless Restart Bugs

### Destructive daemon shutdown kills sessions and routes
- `daemon.Close()` called `frr.Clear()`, `dhcp.StopAll()`, `routing.ClearVRFs()`
- Fix: Non-destructive SIGTERM; full teardown only via `bpfrxd cleanup`

### DHCP context cancellation removes addresses on restart
- DHCP context derived from daemon ctx → cancelled on SIGTERM
- Fix: Use `context.Background()` for DHCP clients

### Premature link.Update() with empty config maps
- Programs replaced before policies/NAT/screen compiled → brief deny-all
- Fix: Defer all `link.Update()` to end of `Compile()`

### Stale generic XDP pinned links after mode change
- `link.Update()` replaces program but NOT attachment mode
- Fix: One-time `bpfrxd cleanup` + fresh start after structural changes

### PROG_ARRAY entries cleared on daemon exit (CRITICAL)
- Kernel calls `bpf_fd_array_map_clear()` on PROG_ARRAY maps when `usercnt` drops to 0
- `usercnt` tracks userspace references: FDs + pin files
- `xdp_progs` and `tc_progs` were NOT pinned → daemon exit closes all FDs → `usercnt=0` → entries cleared
- Map itself survived (embedded ref from xdp_main_prog via pinned link), but ALL entries gone
- xdp_main tail calls fail → `XDP_PASS` → all traffic bypasses XDP pipeline → kernel forwards raw
- SNAT return traffic (dst=firewall IP) reaches kernel TCP → RST → kills connections
- Forward traffic goes through kernel un-SNAT'd → server RSTs unknown source
- **Fix:** Add `xdp_progs` and `tc_progs` to `pinnedMaps` in `loader_ebpf.go`
- Pin file maintains `usercnt > 0` → entries survive → tail calls work → hitless restart
- On restart, new daemon reuses pinned map and atomically updates entries with new program FDs
- **File:** `pkg/dataplane/loader_ebpf.go`

### Random zone/screen/address/app ID assignment across restarts
- Go `for name := range map` iterates in random order → zone IDs change every restart
- Session entries store zone IDs → stale after restart → policy lookups fail
- **Fix:** Sort map keys before iterating (`slices.Sort(maps.Keys(...))`)
- **File:** `pkg/dataplane/compiler.go`

### Map clearing before repopulation during compile
- `ClearIfaceZoneMap()`, `ClearZonePairPolicies()`, etc. called BEFORE new entries written
- Brief window: running BPF programs see empty maps → packets dropped/misclassified
- **Fix:** Write new entries first (overwrite), then delete stale entries not in new config
- **File:** `pkg/dataplane/compiler.go`, `pkg/dataplane/maps.go`

### TTL expiry check after NAT breaks mtr/traceroute (`df28c91`)
- TTL<=1 check was in `xdp_forward`, AFTER `xdp_nat` had rewritten src IP (SNAT) and MACs
- XDP_PASS delivered modified packet to kernel: wrong dst MAC → silent drop, or ICMP Time Exceeded sent to SNAT'd source (firewall's own WAN IP)
- Hop 1 showed `???` in mtr for both zone-to-zone and zone-to-WAN paths
- **Fix:** Moved TTL check to top of `xdp_nat_prog`, before any NAT rewrite
  - Kernel receives original unmodified packet (correct IPs + MACs)
  - Correctly generates ICMP Time Exceeded from ingress interface IP to original sender
  - Includes ingress VLAN tag push-back for sub-interface delivery
- **Key insight:** TTL must be checked BEFORE NAT, just like real routers (Junos checks TTL before NAT translation)
- **Files:** `bpf/xdp/xdp_nat.c` (added check), `bpf/xdp/xdp_forward.c` (removed redundant checks)

### Non-NAT established sessions skip xdp_nat TTL check
- Conntrack fast-path for established sessions without NAT flags tail-calls directly to `XDP_PROG_FORWARD`, skipping `xdp_nat` entirely
- `xdp_conntrack.c:64-66`: `next_prog = XDP_PROG_FORWARD` when no SNAT/DNAT flags
- xdp_forward had NO TTL check (removed in `df28c91`), so TTL=1 packets got decremented to 0 and forwarded to destination (Linux accepts TTL=0 at final hop)
- Zone-to-WAN mtr worked (SNAT → goes through xdp_nat), zone-to-zone mtr showed destination at hop 1 (no NAT → skips xdp_nat)
- **Fix:** Added TTL/hop_limit check in `xdp_forward` BEFORE MAC rewrite, as safety net for non-NAT path
  - For NAT'd traffic, `xdp_nat` catches TTL<=1 first (before NAT rewrite, correct IPs)
  - For non-NAT traffic, `xdp_forward` catches TTL<=1 (IPs unchanged, correct for ICMP TE)
- **Key insight:** TTL check must exist in BOTH `xdp_nat` (for NAT'd traffic) AND `xdp_forward` (for non-NAT established sessions)
- **Files:** `bpf/xdp/xdp_forward.c` (added TTL check before MAC rewrite)

## Phase 47+ Bugs

### Teardrop screen check field name (`a2e6113`)
- Screen compilation used `TCP.TearDrop` but the field is `IP.TearDrop`
- Teardrop is an IP fragmentation attack, not TCP
- **Fix:** Changed to `screenCfg.IP.TearDrop` in compiler.go
- **File:** `pkg/config/compiler.go`

### SNAT TCP sessions dying on daemon restart (`a030446`)
- SNAT sessions have forward (original→NAT'd) and reverse (NAT'd→original) entries
- On restart, dnat_table was cleared before new entries written
- Return traffic arrived during gap → no dnat_table entry → dropped → TCP RST
- **Fix:** Write dnat_table entries BEFORE clearing session-related maps
- Populate-before-clear pattern extended to dnat_table
- **File:** `pkg/dataplane/compiler.go`

### Flat set syntax test using wrong parser (`ac9354b`)
- `TestMultiTermApplicationSetSyntax` used `NewParser(input)` with flat set commands
- Parser treats newlines as whitespace → all set lines merged into one giant node
- **Fix:** Use `ParseSetCommand()` + `tree.SetPath()` (standard pattern for all flat set tests)
- **Gotcha:** NEVER use `NewParser()` for flat `set` syntax — always use SetPath loop
- **File:** `pkg/config/parser_test.go`

### Show system processes in remote CLI (`be7a24b`)
- Remote CLI's `show system processes` was not dispatched to ShowText RPC
- **Fix:** Added routing to use ShowText("processes") in cmd/cli/main.go

### Show chassis/storage routing in remote CLI (`5d853ca`)
- `show chassis` and `show system storage` not handled in remote CLI
- **Fix:** Added ShowText RPC dispatch for these commands

### uint32ToIP() NAT display byte order (FIXED previously)
- `uint32ToIP()` in server.go used `binary.BigEndian.PutUint32` for rendering
- NAT IPs displayed with swapped octets: `10.2.0.10` instead of `10.0.2.10`
- **Fix:** Changed to `binary.NativeEndian.PutUint32`

## Sprint GAP-1 Bugs

### SNAT multiple source-address list parsing (FIXED, Sprint GAP-1)
- `source-address [ 10.0.1.0/24 10.0.2.0/24 ]` only captured first address
- Compiler used `rule.Match.SourceAddress` (singular) — only first element from bracket list
- **Fix:** Added `SourceAddresses []string` field; compilation now iterates all addresses, creating one BPF rule per source address with shared counter ID
- **File:** `pkg/dataplane/compiler.go`, `pkg/config/types.go`

### BPF source-port range byte-order (FIXED, Sprint GAP-1, task #17)
- `xdp_policy.c` compared `__be16` source port against `app_value.src_port_low/high` stored via `htons()`
- Both `meta->src_port` and map values are in network byte order → comparison is correct (both sides NBO)
- Initially reported as bug but confirmed not an issue since BPF map values written with `htons()` match `meta->src_port` which is also `__be16`

### TC forward mirror counter race (FIXED, Sprint GAP-1)
- `__sync_fetch_and_add(cnt, 1)` return value was used for rate sampling before increment completed
- **Fix:** Read `*cnt` first, then `__sync_fetch_and_add(cnt, 1)` separately
- **File:** `bpf/tc/tc_forward.c`

### SetPath leaf duplication bug (FIXED, `13daf45`)
- `SetPath()` always appended leaf nodes without checking for existing leaves with same keyword
- `set system host-name X` repeatedly → accumulated duplicate entries instead of replacing
- **Root cause:** No distinction between single-value (host-name) and multi-value (source-address) leaves
- **Fix:** Added `multi` flag to `schemaNode` + `children == nil` check:
  - Single-value leaves (`args > 0`, `!multi`, `children == nil`): replace existing leaf by keyword
  - Multi-value leaves (`multi: true`): accumulate (skip exact duplicates)
  - Named containers with children (interface, neighbor): never replace (different values = different entries)
- **File:** `pkg/config/ast.go`

## Sprint VRRP-NATIVE Bugs

### VRRP shared socket misses multicast on VLAN sub-interfaces (FIXED, `70b107c`)
- Shared `ip4:112` raw socket on `0.0.0.0` didn't receive VRRP multicast on VLAN sub-interfaces (e.g. `ge-7-0-1.50`)
- Both cluster nodes became MASTER for VRID 101 (WAN VLAN) — each thought the other was dead
- tcpdump confirmed packets were on the wire; host socket just didn't deliver them
- **Root cause:** Linux raw socket multicast on VLAN sub-interfaces requires `SO_BINDTODEVICE` to the specific sub-interface
- **Fix:** Changed from shared socket in Manager to per-instance sockets with `SO_BINDTODEVICE` + per-interface `JoinGroup(224.0.0.18)`
- **Files:** `pkg/vrrp/manager.go` (removed shared socket), `pkg/vrrp/instance.go` (added per-instance socket+receiver)

### VRRP self-sent packets not filtered (FIXED, `70b107c`)
- Original receiver didn't filter self-sent VRRP advertisements
- Could cause state machine confusion if own multicast packets were received
- RFC 5798 §6.4.2/6.4.3 requires filtering advertisements from own source IP
- **Fix:** Added `localIP` field to vrrpInstance, resolved from interface addresses on socket open; receiver skips packets where `hdr.Src.Equal(vi.localIP)`
- **File:** `pkg/vrrp/instance.go`

### RETH VRRP instances missing from CLI status (FIXED, `70b107c`)
- `show security vrrp` on cluster nodes showed "No VRRP groups configured"
- gRPC `GetVRRPStatus` only called `CollectInstances(cfg)` (user VRRP groups) but NOT `CollectRethInstances(cfg, localPri)` (cluster RETH VRRP instances)
- **Fix:** Added `CollectRethInstances()` call in gRPC handler when cluster manager is available, using `s.cluster.LocalPriorities()` for priority mapping
- **File:** `pkg/grpcapi/server.go`

## Session Sync Bugs

### Forward-only session sync — missing reverse entries (FIXED)
- **Symptom:** After VRRP failover, return traffic on takeover node had no conntrack match → policy evaluation as new connection → dropped
- **Root cause:** Periodic sweep sent only forward entries (`IsReverse==0`). `handleMessage()` installed forward entry only, without creating the reverse entry. Bulk sync sent both, but sweep didn't.
- **Fix:** `handleMessage()` now creates reverse entry from each forward entry: copies value, sets `IsReverse=1`, sets `ReverseKey = original key`, installs via `SetSessionV4/V6(val.ReverseKey, revVal)`
- **File:** `pkg/cluster/sync.go` (`handleMessage()` — syncMsgSessionV4/V6 cases)

### Missing dnat_table entries for SNAT sessions (FIXED)
- **Symptom:** After failover, SNAT return traffic not de-NAT'd. `xdp_zone` couldn't find dnat_table entry for dst rewrite → conntrack lookup used SNAT'd dst IP → miss → new connection → kernel RST
- **Root cause:** SNAT sessions need dnat_table entries for pre-routing dst rewrite on takeover node. dnat_table entries are derived from sessions (not config), so they were never synced.
- **Fix:** `handleMessage()` creates dnat_table entry for each forward SNAT session: `{Protocol, NATSrcIP, NATSrcPort} → {SrcIP, SrcPort}`
- **Also fixed:** Delete messages now clean up reverse entries AND dnat_table entries (lookup before delete)
- **File:** `pkg/cluster/sync.go`

### NO_NEIGH drops synced SNAT sessions after failover (FIXED, `0080cbc`)
- **Symptom:** After VRRP failover, takeover node lacks ARP entries for next hops → `bpf_fib_lookup` returns `NO_NEIGH` (rc=7) → `XDP_PASS` with un-NAT'd packet → kernel sends RST (local dst) or forwards with wrong source
- **Root cause:** ARP/NDP caches are per-node. Secondary never sent traffic to SNAT destinations → cold ARP cache
- **Fix (two parts):**
  1. **BPF:** In `xdp_zone.c`, for existing sessions (sv4/sv6 not NULL) with NO_NEIGH, XDP_DROP instead of XDP_PASS. Dropping is safe because ARP warmup resolves neighbors within ~50ms; TCP retransmits at ~200ms recover the connection.
  2. **Userspace:** `warmNeighborCache()` in `daemon.go` — on VRRP MASTER transition, iterates synced sessions and triggers kernel ARP/NDP resolution via UDP connect to each unique destination IP.
- **Also added:** `SendNDSolicitation()` in `garp.go` for IPv6 neighbor resolution during failover
- **Files:** `bpf/xdp/xdp_zone.c`, `pkg/daemon/daemon.go`, `pkg/cluster/garp.go`

### Monotonic clock skew in GC — premature session expiry (FIXED, `0080cbc`)
- **Symptom:** Synced sessions carry remote node's monotonic timestamps (`Created`, `LastSeen`). If local node uptime > remote uptime: `LastSeen + Timeout < local_now` → premature expiry within seconds
- **Root cause:** `CLOCK_MONOTONIC` is relative to boot time. Node reboots (low timestamp), syncs to long-running peer (high local time) → GC kills synced sessions
- **Fix:** Set `LastSeen = local monotonic time` when installing synced sessions in `handleMessage()`. `Created` kept original for display.
- **File:** `pkg/cluster/sync.go`

### BPF verifier: pointer bitwise OR prohibited (FIXED, `0080cbc`)
- **Symptom:** xdp_zone_prog failed to load with `"R1 bitwise operator |= on pointer prohibited"`
- **Root cause:** `if (sv4 || sv6)` where both are `struct session_*_value *` pointers compiles to a BPF `|=` instruction on pointer registers, which the verifier rejects
- **Cascade failure:** BPF load fail → `d.dp = nil` → `applyConfig` never called → VRF never created → `mgmtVRFInterfaces` empty → `vrfDevice=""` → TCP bind to VRF-only fabric address fails with EADDRNOTAVAIL → session sync never starts
- **Fix:** Changed to separate `if (sv4 != NULL)` and `if (sv6 != NULL)` checks
- **Key insight:** Never use C logical OR (`||`) on two BPF pointer values — the compiler may emit `|=` which the verifier rejects. Use separate NULL checks instead.
- **File:** `bpf/xdp/xdp_zone.c`

### Sync start retry count insufficient (FIXED, `0080cbc`)
- **Symptom:** Original 10 retries (20s) exhausted before VRF was ready on slow starts
- **Fix:** Increased from 10 to 30 retries (60s total) in `startClusterComms()` goroutine
- **File:** `pkg/daemon/daemon.go`

### FIB cache not synced (BY DESIGN — not a bug)
- Session FIB cache fields (`fib_ifindex`, `fib_dmac`, `fib_smac`, `fib_gen`) are zeroed in synced sessions
- Interface indices and MAC addresses differ between cluster nodes
- Zero `fib_ifindex` forces fresh `bpf_fib_lookup` on first packet → correct local FIB cache populated
- No fix needed — this is correct behavior

## Known Open Issues

### Configure mode double echo (FIXED)
- Extra echo characters when typing in configure mode via `incus exec -- cli`
- Was PTY multiplexing issue between incus exec and chzyer/readline

### flow_config_map not found warning (FIXED)
- Was caused by `flow_config_map` not being extracted from zone objects during Load()
- Fixed: `loader_ebpf.go:197` extracts `zoneObjs.FlowConfigMap` into `m.maps`
- Confirmed working: "flow config compiled" with tcp_mss_ipsec=1350 on all recent deploys

### rib-group ip rule priority too high (FIXED)
- `ip rule add from all lookup <table> pref 200` was consulted BEFORE main table (pref 32766)
- If VRF table had a default route, ALL traffic used that default instead of main table routes
- Symptom: firewall couldn't ping anything on trust0/untrust0 — all traffic routed via dmz-vr's default
- **Fix:** Changed ribGroupRulePriority from 200 to 33000 (after main table at 32766)
- Also added legacy cleanup (200-299 range) for migration from old priority

### VLAN interface name stripping in FRR (FIXED, `89a1a5e`)
- Phase 50b qualified next-hop stripped ALL dot-suffixes from interface names
- `wan0.50` (VLAN sub-interface) → `wan0` (wrong device)
- IPv6 default route pointed to `wan0` instead of `wan0.50`, gateway unreachable
- **Fix:** Only strip `.0` suffix (Junos default unit), not VLAN suffixes like `.50`
- **File:** `pkg/frr/frr.go`

### configstore refactor broke initial config loading (FIXED)
- `Store.Load()` reads only from DB (active.json), not from text config file
- On first start (no DB), daemon started with empty config — no FRR routes, no interface management
- **Fix:** `daemon.bootstrapFromFile()` — reads text config, parses, LoadOverride + Commit to seed DB
- Subsequent restarts load from DB normally

### NAT64 three-bug saga (FIXED `1cde2af`)
1. **Zone FIB miss for 64:ff9b::/96**: No kernel IPv6 route for NAT64 prefix → bpf_fib_lookup failed → packet treated as local. Fix: detect nat64_prefix_map in zone's FIB-failed branch, do IPv4 FIB for embedded v4 dst.
2. **Reverse path NO_NEIGH (rc=7)**: After 4→6 xlate, NDP cache empty for client → redirect failed. Fix: accept NO_NEIGH, save ingress MAC before bpf_xdp_adjust_head(-20), XDP_PASS for kernel NDP resolution.
3. **ICMPv6 checksum wrong**: Incremental ICMPv4→ICMPv6 conversion failed (ICMPv4 has no pseudo-header, ICMPv6 does). Fix: from-scratch checksum — zero field, sum IPv6 pseudo-header + all ICMPv6 words.
- **Key lesson:** `bpf_xdp_adjust_head(-20)` invalidates ALL pointers and overwrites old Ethernet header with IPv6 data. Must save MAC before adjust_head.
- **Key lesson:** For ICMP checksum conversion between v4/v6, always use from-scratch recomputation — incremental is too error-prone due to pseudo-header asymmetry.

### NAT64 ICMP traceroute (FIXED `91bdd38`)
Three fixes for mtr/traceroute6 over NAT64 (64:ff9b::/96):
1. **Wrong echo ID in nat64_state**: For ICMPv6 echo, policy sets `meta->src_port = alloc_v4_port` (SNAT'd) but NAT64 used this as `old_sport` for `nat64_state.orig_src_port`. When ICMP errors came back, the translated ICMPv6 embedded packet had the SNAT'd echo ID instead of the original — mtr couldn't match. Fix: use `meta->dst_port` (original echo ID, unchanged by policy) for ICMPv6 protocol.
2. **No ICMP error 4→6 translation**: Added `nat64_icmp_error_4to6()` for full IPv4 ICMP error → ICMPv6 error translation (RFC 7915). Handles Time Exceeded, Dest Unreachable, Param Problem with bpf_xdp_adjust_head(-40) to grow packet.
3. **NPTv6 reverse in error path**: nat64_state stores post-NPTv6 (external prefix) addresses. Added INBOUND NPTv6 lookup in the error translation to reverse back to internal prefix before checksum/routing.
- **Key lesson:** For ICMP echo in NAT64, `meta->src_port` is unreliable after policy stage — always use `meta->dst_port` for the original echo ID.
- **Key lesson:** UDP traceroute worked but ICMP didn't — protocol-specific embedded L4 handling is where bugs hide.

### VRRP split-brain on VLAN sub-interfaces (FIXED, `e018918`)
- **Symptom:** Both cluster nodes became MASTER for VRID 101 (WAN VLAN sub-interface ge-*-0-1.50)
- **Root cause (two parts):**
  1. XDP strips VLAN tags in xdp_main for pipeline processing. VRRP bypass XDP_PASS'd without restoring the tag → kernel delivered to parent interface (no IPv4 config) → silently dropped
  2. Even with tag restored, raw IP sockets (AF_INET SOCK_RAW proto 112) don't receive multicast on VLAN sub-interfaces — kernel counts IpInDelivers but recvmsg never returns the packet (kernel limitation)
- **Fix (two parts):**
  1. Moved VRRP bypass in xdp_zone.c to before zone lookup; push VLAN tag back via `xdp_vlan_tag_push()` before XDP_PASS
  2. VLAN sub-interfaces use AF_PACKET (SOCK_RAW + ETH_P_ALL + PACKET_MR_PROMISC + BPF filter) for receiving. Raw IP socket kept for sending. Non-VLAN interfaces unchanged.
- **Key insight:** AF_PACKET on VLAN sub-interfaces requires PACKET_MR_PROMISC to receive multicast from remote peers. Without it, only locally-generated multicast (IP-layer loopback) is delivered. This matches tcpdump's behavior (always sets PACKET_MR_PROMISC).
- **Key insight:** VIP-aware local IP selection needed — during split-brain both nodes have the VIP, so using VIP as source address causes peer to filter our adverts as "self-sent"
- **Files:** `bpf/xdp/xdp_zone.c`, `pkg/vrrp/instance.go`, `pkg/vrrp/manager.go`

### VRRP failover failure on non-VLAN interfaces + RETH VIP reconciliation (FIXED, `d951626`)
- **Symptom:** When fw0 rebooted, fw1 didn't serve WAN traffic for ~28 seconds. Also, fw1's LAN RETH interface (ge-7-0-0) was stuck as MASTER in split-brain with fw0 after restarts.
- **Root cause (two parts):**
  1. Raw IP sockets (proto 112) with SO_BINDTODEVICE don't reliably receive VRRP multicast in generic XDP mode. AF_PACKET taps fire BEFORE generic XDP in the kernel's receive path (`__netif_receive_skb_core` → ptype_all → do_xdp_generic`). The raw IP socket relies on the packet making it through the full kernel stack after XDP, which is unreliable for multicast.
  2. `reconcileInterfaceAddresses()` in the dataplane compiler was adding RETH VIP addresses (10.0.60.1/24, 172.16.50.6/24) to BACKUP node's physical member interfaces on every config compile, bypassing VRRP's VIP management. BACKUP nodes always had VIPs they shouldn't.
- **Fix (three parts):**
  1. Use AF_PACKET receiver for ALL VRRP instances (not just VLAN sub-interfaces). Removed the `isVLAN` conditional — all interfaces now use AF_PACKET for receiving, raw IP socket for sending only.
  2. Skip `reconcileInterfaceAddresses()` for RETH interfaces (`RedundancyGroup > 0`). The link-local base addresses (169.254.RG.NODE/32) are managed by systemd-networkd via .network files; VIPs are managed by VRRP.
  3. Added `removeVIPs()` in INIT→BACKUP transition to clean up stale VIPs from previous daemon runs.
- **Key insight:** Generic XDP (`xdpgeneric`) processes packets AFTER AF_PACKET taps but BEFORE the IP stack delivers to raw sockets. AF_PACKET is the only reliable way to receive multicast when generic XDP is attached.
- **Key insight:** Group 101 (VLAN, AF_PACKET) stayed BACKUP correctly while group 102 (non-VLAN, raw socket) went to MASTER — proving the raw socket was the problem.
- **Files:** `pkg/vrrp/instance.go`, `pkg/dataplane/compiler.go`

### VRRP failover: upstream router ignores gratuitous ARP (FIXED, `7bcaee9`)
- **Symptom:** After fw1 becomes MASTER, VIPs are added and GARP is sent, but external pings to 172.16.50.6 fail for ~30 seconds. Manual `ping 172.16.50.1` from fw1 fixes it immediately.
- **Root cause:** Upstream router ignores gratuitous ARP Reply packets (opcode 2). Only updates ARP cache from standard ARP traffic (requests/responses to normal queries).
- **Verified:** tcpdump confirmed GARP exits on VLAN 50 with correct MAC/IP; fw1 can ping router after VIP add; after that ping, external pings work.
- **Fix (three parts):**
  1. Send GARP as both ARP Request (opcode 1) AND Reply (opcode 2) — some devices only honor one format. `buildGratuitousARP()` now takes opcode parameter.
  2. After GARP, synchronously send a standard ARP probe to the .1 address of each VIP subnet. The probe's source IP/MAC forces the gateway to update its ARP cache. Uses `net.ParseCIDR()` to compute subnet .1 address; skips if .1 equals our VIP (e.g., 10.0.60.1 LAN gateway).
  3. Promoted GARP/NA error logging from Debug to Warn for visibility.
- **Result:** Failover loss reduced from ~30s to ~3.5s (master-down timer only). External pings resume immediately after fw1 becomes MASTER.
- **Key insight:** Gratuitous ARP is unreliable across vendors. Always follow GARP with a standard ARP Request to the gateway — the ARP protocol guarantees the gateway updates its cache from the request's source fields.
- **Files:** `pkg/cluster/garp.go` (dual GARP + SendARPProbe + buildARPRequest), `pkg/vrrp/instance.go` (integrated gateway probe into sendGARP)

### IPv6 VIP unreachable: DAD failure + missing interface + RETH name (FIXED, `d03b29e`)
- **Symptom:** `ping 2001:559:8585:50::6` from host returns "Destination unreachable: Address unreachable"
- **Root cause (three bugs):**
  1. **DAD failure:** Kernel performed Duplicate Address Detection on VRRP IPv6 VIP; failed because secondary still briefly held the address. `ip -6 addr` showed `dadfailed tentative`.
  2. **Missing interface in FRR route:** `compileStaticRoutes()` only checked `prop.Children` for "interface" keyword. Config `next-hop fe80::50 interface reth0.50` has "interface" in `prop.Keys[2]` (leaf node with all keys inline), not in Children. FRR got `ipv6 route ::/0 fe80::50 5` without interface → route installed on parent device instead of VLAN sub-interface.
  3. **RETH→physical name translation:** Even with interface extracted, FRR got `reth0.50` instead of `ge-0-0-1.50`. FRR needs kernel interface names, not Junos RETH names.
- **Fix (three parts):**
  1. Added `unix.IFA_F_NODAD` flag for IPv6 VIPs in VRRP `addVIPs()` — prevents DAD failure
  2. Added inline keys scan in `compileStaticRoutes()`: `for j := 2; j < len(prop.Keys)-1; j++ { if prop.Keys[j] == "interface" { ... } }`
  3. Added `RethMap` to FRR `FullConfig`; `generateStaticRoute()` resolves RETH names to physical names via map lookup + `LinuxIfName()` for slash→dash conversion
- **Verification:** FRR config now shows `ipv6 route ::/0 fe80::50 ge-0-0-1.50 5`; kernel route shows `via fe80::50 dev ge-0-0-1.50`; ping to `2001:559:8585:50::6` works
- **Files:** `pkg/vrrp/instance.go`, `pkg/config/compiler.go`, `pkg/frr/frr.go`, `pkg/frr/frr_test.go`, `pkg/daemon/daemon.go`

### Cluster config sync broken: ${node} parse error + no reverse-sync (FIXED, `64bc9d5`)
- **Symptom:** Config changes committed on primary (fw0) never appeared on secondary (fw1). fw1 log showed: `"cluster: config sync apply failed" err="sync config parse error: line 93, column 14: unexpected character: $"`
- **Root cause (parse error):** `Format()` used `KeyPath()` which joins keys with spaces but doesn't re-quote keys containing special characters. When the original config has `apply-groups "${node}"`, the parser stores the key as `${node}` (without quotes). `Format()` then outputs it unquoted, and the receiving parser fails on `$`.
- **Fix (quoting):** Added `QuotedKeyPath()` and `quoteKey()` to `pkg/config/ast.go`. Keys containing non-identifier characters are wrapped in double quotes. All format output paths (Format, FormatPath, FormatSet, FormatCompare, FormatInheritance) updated.
- **Symptom (reverse-sync):** When fw0 returned after being down, it preempted to primary and pushed its STALE disk config to fw1, overwriting fw1's newer config. No mechanism existed for the returning node to receive config from the node that was running.
- **Root cause:** VRRP preemption via heartbeat is faster (~1s) than TCP sync connection (~3s). By the time `OnPeerConnected` fired on fw1, it was already secondary and `syncConfigToPeer()` returned early (checks `IsLocalPrimary(0)`).
- **Fix (reverse-sync):** Added `OnPeerConnected` callback to `SessionSync`. On reconnect: (a) stable node (running >30s) calls `pushConfigToPeer()` which bypasses the primary check, (b) fresh node (running <30s) skips push to avoid overwriting newer config. Added `startTime` field to Daemon.
- **Files:** `pkg/config/ast.go`, `pkg/config/parser_test.go`, `pkg/cluster/sync.go`, `pkg/daemon/daemon.go`

### RETH .link file overwritten with virtual MAC on DHCP recompile (FIXING)
- **Symptom:** After a DHCP recompile (or any config recompile), the `.link` file for RETH member interfaces was rewritten with `MACAddress=02:bf:72:...` (the virtual MAC). On reboot, the interface starts with its physical MAC, so the `.link` file no longer matches and the interface is not renamed. The daemon then cannot find the interface by its config name.
- **Root cause:** In `pkg/dataplane/compiler.go`, the `isVirtualRethMAC` block had an `if/else if` structure that made `getPermAddr()` and `originalName` recovery mutually exclusive:
  ```go
  if permMAC := getPermAddr(...); permMAC != "" {
      mac = permMAC
  } else if originalName == "" {
      // recover originalName
  }
  ```
  If `getPermAddr()` returned any value (which it does when the virtual MAC is set), the `originalName` recovery path was completely skipped, leaving `originalName=""`. The `.link` file then used `MACAddress=` with the permanent MAC (better than virtual MAC, but still fragile since MACs can change). On a fresh boot where `getPermAddr` returned the physical MAC (virtual not yet set), the `.link` was correct but fragile.
- **Deeper issue:** Even with the permanent MAC, `MACAddress=` matching is unreliable for RETH members because the MAC alternates between physical (at boot, before daemon) and virtual (after daemon programs it). `OriginalName=` matching by kernel PCI name (e.g. `enp6s0`) is stable across reboots.
- **Fix (three parts):**
  1. **compiler.go:** Restructured `isVirtualRethMAC` block to make `originalName` recovery independent of `getPermAddr`. `originalName` recovery always runs first when needed. Added `readOriginalNameFromLink()` (reads existing `.link` file) as first fallback before `getOriginalKernelName()` (reads netlink altnames). Added `findInterfaceByMAC()` to locate RETH members that exist under their kernel name when the config name lookup fails.
  2. **networkd.go:** Added `OriginalName` field to `InterfaceConfig`. `generateLink()` uses `OriginalName=` for matching when set, falling back to `MACAddress=` for non-RETH interfaces.
  3. **daemon.go:** Added `renameRethMember()` (finds interface by RETH virtual MAC, renames it) and `fixRethLinkFile()` (rewrites `.link` with `OriginalName=`). Step 2.6 in `applyConfig` now checks if the RETH member exists under its config name; if not, finds it by MAC and renames it, then fixes the `.link` file.
- **Key insight:** PCI-based kernel names (e.g. `enp6s0`) are stable across reboots and are the correct match criteria for `.link` files on RETH members. `MACAddress=` is unreliable because the MAC is physical at boot time and virtual after the daemon programs it. `OriginalName=` in systemd `.link` files matches the kernel's predictable network interface name before any udev renames.
- **Recovery chain:** `readOriginalNameFromLink()` (existing `.link` file, most reliable) -> `getOriginalKernelName()` (netlink altnames) -> `findInterfaceByMAC()` (scan by RETH virtual MAC when interface not found by name)
- **Files:** `pkg/dataplane/compiler.go`, `pkg/networkd/networkd.go`, `pkg/daemon/daemon.go`

## Reboot/Failover Bugs (Sprint: Hitless Reboot)

These bugs were discovered testing iperf3 (~4.7 Gbps reverse mode) through the cluster while rebooting the primary node (fw0). Each bug manifested as iperf3 dying after ~7 seconds post-reboot.

### VRRP VIPs flushed by networkctl reload (FIXED, `b8bb2d0`)
- **Symptom:** ~7 seconds after boot, VRRP VIPs (172.16.50.6/24, 2001:559:8585:50::6/64) disappeared from ge-0-0-1.50. iperf3 died. `ip addr show ge-0-0-1.50` showed only 169.254.1.1/32 — all VRRP VIPs gone.
- **Root cause:** DHCP lease obtained ~3s after boot triggers `"DHCP address changed, recompiling dataplane"`. Recompile writes .network files and calls `networkctl reload`. networkd asynchronously reconfigures all managed interfaces, removing addresses not in the .network file. VRRP VIPs are "foreign" addresses (added by VRRP, not in .network file) — networkd flushed them.
- **Timeline:** Boot T=0 → initial compile T+2s → DHCP lease T+3s → recompile T+5s → networkctl reload T+5s → VIPs flushed T+7s → iperf3 dies.
- **Fix:** Added `KeepAddresses bool` field to `networkd.InterfaceConfig`. When set, `generateNetwork()` emits `KeepConfiguration=static` in the .network file. systemd-networkd then preserves externally-added static addresses across reloads. Set for all RETH interfaces (both VLAN sub-interfaces and regular) since VRRP manages their VIPs.
- **Files:** `pkg/networkd/networkd.go` (KeepAddresses field, generateNetwork), `pkg/dataplane/compiler.go` (KeepAddresses: isVRRPReth)

### Cluster heartbeat bind failure not retried — permanent dual-MASTER (FIXED, `b8bb2d0`)
- **Symptom:** After simultaneous restart of both nodes (`cluster-deploy` restarts both), both became Primary for all RGs with VRRP priority 200. fw1 log showed: `"failed to start cluster heartbeat" err="listen heartbeat: listen udp4 10.99.0.2:4784: bind: cannot assign requested address"`. Both nodes stayed MASTER permanently.
- **Root cause:** On boot, the control interface (fxp1) is in VRF vrf-mgmt. Its address (10.99.0.1/30 or 10.99.0.2/30) may not be assigned yet when the daemon tries to bind the heartbeat UDP socket. Without heartbeat, the election state machine never runs — both nodes default to Primary (highest priority wins nothing because no one is checking). VRRP gets priority 200 from `LocalPriorities()` which returns 200 for Primary.
- **Fix:** Changed heartbeat startup from single-try to a retry goroutine: 30 attempts, 2s intervals (60s total). Same pattern as existing session sync retry. On bind success, heartbeat starts and election resolves — higher priority node stays Primary, lower becomes Secondary.
- **Key insight:** `cluster-deploy` restarts both nodes simultaneously. Staggered deploys (fw1 first, then fw0) avoid the issue, but the retry makes it robust for any deployment pattern.
- **File:** `pkg/daemon/daemon.go` (heartbeat start section in cluster setup)

### DHCP-triggered recompile rxvlan toggle kills iavf data path (FIXED)
- **Symptom:** iperf3 at ~4.7 Gbps dies exactly at ~7 seconds after fw0 reboot. Consistent across multiple reboots. fw1 (secondary serving traffic via VRRP failover) was fine — only the rebooted node's traffic disrupted.
- **Root cause:** DHCP lease triggers full dataplane recompile. `compileZones()` runs `ethtool -K <iface> rxvlan off` on ALL physical interfaces each recompile (the `attached` map is local, rebuilt every call). On the iavf VF (ge-0-0-1, WAN interface), toggling rxvlan causes a driver reset/reconfiguration that drops in-flight packets. Even though rxvlan was already off, the `ethtool -K rxvlan off` command still triggers the driver path that disrupts the NIC.
- **Timeline:** Matches exactly — DHCP recompile at T+5s, ethtool runs on ge-0-0-1 at T+5s, iperf3 dies at T+7s (2s TCP timeout after packets stop flowing).
- **Fix:** Added `isRxVlanOff()` helper that queries `ethtool -k <iface>` for current rx-vlan-offload state. Only calls `ethtool -K rxvlan off` if it's currently on. On recompile, rxvlan is already off → ethtool set is skipped → no driver disruption.
- **Key insight:** iavf VF driver is sensitive to ethtool feature changes — even a no-op toggle (off→off) causes internal reconfiguration. Always check-before-set for NIC offload features.
- **File:** `pkg/dataplane/compiler.go` (isRxVlanOff helper, conditional in compileZones)

### VRF binding lost after networkctl reconfigure — heartbeat/sync EADDRNOTAVAIL (FIXED, `1360a25`)
- **Symptom:** After rebooting fw0, heartbeat and session sync failed all 30 retries with `EADDRNOTAVAIL`. Both nodes became dual-MASTER. Even after adding `VRF=vrf-mgmt` to .network files (commit `73400d4`), the binding was still lost on reboot.
- **Root cause:** The daemon creates vrf-mgmt via netlink (`routing.CreateVRF()`), not via a `.netdev` file. systemd-networkd considers netlink-created VRF devices "unmanaged" (`networkctl status vrf-mgmt` shows "Network File: n/a", "State: carrier (unmanaged)"). The `VRF=` directive in `.network` files is ignored for unmanaged VRF targets. When `networkctl reconfigure` runs (triggered by DHCP recompile), it strips the VRF master binding from fxp1/fab0.
- **Timeline:** Boot T=0 → initial applyConfig T+2s → VRF created + interfaces bound → DHCP lease T+3s → recompile T+5s → `networkctl reconfigure` strips VRF bindings → heartbeat bind to 10.99.0.1:4784 in VRF fails → EADDRNOTAVAIL for 60s → cluster never forms.
- **Evidence:** `ip -d link show fxp1` showed no `master vrf-mgmt`; `ip route show table 999` was empty; addresses visible in global table but unreachable via `SO_BINDTODEVICE=vrf-mgmt`.
- **Fix:** Added step 2.7 in `applyConfig()` to re-bind management VRF interfaces after every `networkd.Apply()`. This runs after the networkctl reconfigure and restores the VRF membership regardless of what networkd does. The VRF= directive in .network files (from `73400d4`) is kept as a best-effort hint for networkd but the real fix is the explicit re-bind.
- **Key insight:** networkd's `VRF=` directive only works when networkd manages both the interface AND the VRF device. For daemon-created VRFs (via netlink), you must re-bind after any networkctl operation.
- **Files:** `pkg/daemon/daemon.go` (step 2.7 VRF re-bind), `pkg/networkd/networkd.go` (VRFName field), `pkg/dataplane/compiler.go` (VRFName for fxp/fab)

### Per-node RETH virtual MAC — FDB conflicts on shared L2 domain (FIXED, `bc66bba`)
- **Symptom:** After rebooting fw0, WAN connectivity lost entirely. Both nodes had identical RETH virtual MAC `02:bf:72:01:01:00`, causing FDB flapping on the upstream switch/bridge. Packets randomly delivered to wrong node.
- **Root cause:** `RethMAC(clusterID, rgID)` was node-agnostic — both node 0 and node 1 got the same MAC per RETH. When both nodes' physical member interfaces (ge-0-0-1 on fw0, ge-7-0-1 on fw1) are on the same L2 domain (via Incus bridge), the switch sees the same source MAC from two ports and flaps between them.
- **Fix:** Changed `RethMAC(clusterID, rgID)` to `RethMAC(clusterID, rgID, nodeID)`. MAC format changed from `02:bf:72:CC:RR:00` to `02:bf:72:CC:RR:NN`. Each node gets a unique MAC per RETH. VRRP + gratuitous ARP/NA handle failover (the MASTER advertises the VIP, clients use the VIP — the underlying MAC differences are transparent since clients use L3 addresses, not L2 MACs).
- **Key insight:** On real hardware with dedicated L2 segments per node, identical RETH MACs would work. But in virtualized environments (Incus bridges, SR-IOV VFs from same PF), both nodes share L2 → unique MACs required. Per-node MAC is universally safe.
- **Files:** `pkg/cluster/reth.go` (RethMAC signature), `pkg/cluster/reth_test.go`, `pkg/daemon/daemon.go` (programRethMAC calls), `pkg/dataplane/compiler.go` (isVirtualRethMAC)

### Bootstrap .link files use MACAddress= for RETH members — boot failure (FIXED, `f8353de`)
- **Symptom:** After reboot, RETH member interfaces not renamed. Daemon can't find `ge-0-0-0` / `ge-7-0-0` etc. All RETH connectivity lost.
- **Root cause:** `cluster-setup.sh` wrote `.link` files with `MACAddress=` for RETH members. The daemon programs a virtual MAC (`02:bf:72:CC:RR:NN`) at runtime. On reboot, the interface starts with its original physical MAC, so the `.link` file (which had the physical MAC from first boot) might not match if the daemon had rewritten it with the virtual MAC. Even if the physical MAC matched, `MACAddress=` is fundamentally fragile for RETH members because the MAC alternates between physical (boot) and virtual (daemon).
- **Fix (two parts):**
  1. `cluster-setup.sh`: Changed RETH members from `MACAddress=` to `OriginalName=` (PCI kernel name). LAN is always `enp8s0`, WAN discovered dynamically by exclusion. Non-RETH interfaces (fxp0/fxp1/fab0) keep `MACAddress=`.
  2. `daemon.go`: Added `ensureRethLinkOriginalName()` — runs unconditionally for every RETH member, detects and rewrites stale `MACAddress=` to `OriginalName=`. Uses `deriveKernelName()` which handles virtio-over-PCI (sysfs path is `virtioN`, must traverse to parent PCI device).
- **Gotcha:** Virtio interfaces have sysfs device path like `/sys/devices/.../virtio14/net/ge-0-0-0` — the device directory is `virtioN`, not a PCI address. `deriveKernelName()` traverses to parent directory to find the actual PCI address.
- **Files:** `test/incus/cluster-setup.sh`, `pkg/daemon/daemon.go`

### VRRP VIPs lost after programRethMAC on simultaneous boot (FIXED, `a4eb2b2`)
- **Symptom:** After simultaneous reboot of both nodes, fw0 becomes MASTER but missing IPv6 LAN VIP `2001:559:8585:cf01::1/64`. IPv4 VIPs sometimes also missing.
- **Root cause:** Race condition during simultaneous boot:
  1. DHCP recompile triggers early `applyConfig` → VRRP starts, adds VIPs on MASTER instances
  2. Config sync recompile triggers second `applyConfig` → `programRethMAC()` does link DOWN/UP to set virtual MAC → kernel removes ALL addresses including VRRP VIPs
  3. `UpdateInstances()` in second `applyConfig` sees no config change (same priority/preempt/VIPs) → `continue` → VIPs never re-added
- **Timeline:** Boot → DHCP recompile (T+3s) → VRRP MASTER + VIPs → config sync recompile (T+5s) → `programRethMAC` link DOWN/UP → VIPs gone → `UpdateInstances` no-ops
- **Fix:** Added `ReconcileVIPs()` method to `pkg/vrrp/manager.go` — iterates all instances, re-adds VIPs and sends GARP on any that are in MASTER state. Called from `daemon.go` after RETH MAC programming loop (step 2.6b).
- **Key insight:** `programRethMAC` link DOWN/UP is inherently destructive to addresses. Any external address manager (VRRP) must reconcile after MAC programming. `UpdateInstances()` correctly skips unchanged configs — the VIP reconciliation is a separate concern.
- **Files:** `pkg/vrrp/manager.go` (ReconcileVIPs), `pkg/daemon/daemon.go` (call site after step 2.6)
- **Symptom:** After rebooting fw0, WAN connectivity lost entirely. Both nodes had identical RETH virtual MAC `02:bf:72:01:01:00`, causing FDB flapping on the upstream switch/bridge. Packets randomly delivered to wrong node.
- **Root cause:** `RethMAC(clusterID, rgID)` was node-agnostic — both node 0 and node 1 got the same MAC per RETH. When both nodes' physical member interfaces (ge-0-0-1 on fw0, ge-7-0-1 on fw1) are on the same L2 domain (via Incus bridge), the switch sees the same source MAC from two ports and flaps between them.
- **Fix:** Changed `RethMAC(clusterID, rgID)` to `RethMAC(clusterID, rgID, nodeID)`. MAC format changed from `02:bf:72:CC:RR:00` to `02:bf:72:CC:RR:NN`. Each node gets a unique MAC per RETH. VRRP + gratuitous ARP/NA handle failover (the MASTER advertises the VIP, clients use the VIP — the underlying MAC differences are transparent since clients use L3 addresses, not L2 MACs).
- **Key insight:** On real hardware with dedicated L2 segments per node, identical RETH MACs would work. But in virtualized environments (Incus bridges, SR-IOV VFs from same PF), both nodes share L2 → unique MACs required. Per-node MAC is universally safe.
- **Files:** `pkg/cluster/reth.go` (RethMAC signature), `pkg/cluster/reth_test.go`, `pkg/daemon/daemon.go` (programRethMAC calls), `pkg/dataplane/compiler.go` (isVirtualRethMAC)

## Fabric Hardening Sprint

### #61: NO_NEIGH FABRIC_FWD sessionless leak to XDP_PASS (FIXED)
- **Symptom:** In xdp_zone NO_NEIGH branch, when `META_FLAG_FABRIC_FWD` is set and no session exists (`sv4==NULL && sv6==NULL`), code falls through to the host-inbound `XDP_PASS` path. Transit packets from the fabric peer leak into the kernel stack instead of being dropped.
- **Root cause:** The NO_NEIGH handler had separate guards for existing sessions (`sv4 || sv6` → XDP_DROP) and `META_FLAG_KERNEL_ROUTE` (→ tail call conntrack), but no guard for `META_FLAG_FABRIC_FWD` on sessionless packets. FABRIC_FWD traffic without a local session should never reach the host.
- **Fix:** Added `META_FLAG_FABRIC_FWD` check before the host-inbound fallthrough — drops with `GLOBAL_CTR_FABRIC_FWD_DROP` counter instead of `XDP_PASS`.
- **File:** `bpf/xdp/xdp_zone.c`

### #62: UNREACHABLE/BLACKHOLE FABRIC_FWD re-FIB miss leak (FIXED)
- **Symptom:** In xdp_zone UNREACHABLE/BLACKHOLE branch, when `META_FLAG_FABRIC_FWD` is set and re-FIB in main table (254) also fails, no explicit drop occurs. Transit fabric packets with unreachable routes leak through.
- **Root cause:** The UNREACHABLE/BLACKHOLE handler attempted re-FIB in main table for FABRIC_FWD traffic but had no explicit drop when that re-FIB also returned UNREACHABLE/BLACKHOLE. Missing counter increment on this path.
- **Fix:** Added `XDP_DROP` with `GLOBAL_CTR_FABRIC_FWD_DROP` counter increment when re-FIB fails for FABRIC_FWD packets in the UNREACHABLE/BLACKHOLE branch.
- **File:** `bpf/xdp/xdp_zone.c`

### #63: Non-deterministic fib_ifindex fallback in refreshFabricFwd (FIXED)
- **Symptom:** When the fabric interface is a VRF member, `refreshFabricFwd()` needs a non-VRF ifindex for `bpf_fib_lookup` main-table queries. The fallback iterated `netlink.LinkList()` and picked the first UP, non-VRF link — which is non-deterministic (link order varies between boots/reloads).
- **Root cause:** `netlink.LinkList()` returns links in arbitrary kernel order. The "first UP non-VRF" heuristic could pick different interfaces each time, leading to inconsistent FIB lookup results.
- **Fix:** Use loopback interface (ifindex 1) as the non-VRF fallback. Loopback is always present, always UP, and never a VRF member. Eliminates the `LinkList()` iteration entirely.
- **File:** `pkg/daemon/daemon.go`

### #64: DPDK zone decode returns early + no fabric ingress validation (FIXED)
- **Symptom:** In `dpdk_worker/zone.c`, zone-encoded MAC decode (from `bpf_redirect_map` fabric forwarding) returned immediately after decoding, skipping FIB resolution. Additionally, no validation that the packet actually arrived on the fabric interface — any interface could spoof a zone-encoded MAC.
- **Root cause:** The zone-encoded MAC decode block had an early `return` that bypassed the rest of the zone processing pipeline (FIB lookup, forwarding decision). No check compared `port_id` against the expected fabric interface.
- **Fix:** (1) Added `fabric_ifindex` field to DPDK `shared_memory` struct, populated by Go manager. (2) Added ingress validation — only accept zone-encoded MACs from the fabric interface. (3) Removed early return so decoded packets continue through FIB resolution.
- **Files:** `dpdk_worker/zone.c`, `dpdk_worker/tables.h`, `pkg/dataplane/dpdk/manager.go`

## DPDK + HA Hardening Sprint

### #65: DPDK zone-encoded fabric validation compares port_id against kernel ifindex (FIXED)
- **Symptom:** DPDK `zone.c` fabric ingress validation (added in #64) always fails — zone-encoded MAC packets from the fabric peer are rejected even on the correct interface.
- **Root cause:** `meta->ingress_ifindex` in DPDK is the DPDK `port_id` (from `pkt->port`), but `shm->fabric_ifindex` is the kernel `ifindex` (populated from netlink). These are different numbering namespaces — DPDK port_id 0 is not kernel ifindex 5. The comparison `meta->ingress_ifindex != shm->fabric_ifindex` always evaluates true for non-matching IDs.
- **Fix:** (1) Added `ifindex_to_port` mapping array in DPDK `shared_memory`, populated by the DPDK worker at `port_init` time. (2) Renamed `fabric_ifindex` to `fabric_port_id` in the DPDK shared memory struct. (3) Go `UpdateFabricFwd()` translates the kernel ifindex to DPDK port_id via the mapping before writing to shared memory.
- **Files:** `dpdk_worker/zone.c`, `dpdk_worker/tables.h`, `pkg/dataplane/dpdk/manager.go`

### #66: HA failover race — stale rg_active from interleaved transitions (FIXED)
- **Symptom:** During rapid HA failover/failback sequences, the `rg_active` BPF map and blackhole side effects can be set to stale values. Traffic is dropped or forwarded incorrectly for a brief window after a valid transition has already occurred.
- **Root cause:** `watchClusterEvents` and `watchVRRPEvents` goroutines both call into `rgStateMachine` and apply `rg_active`/blackhole side effects. When they interleave — e.g., a cluster state change triggers a transition, then a VRRP event triggers another transition before the first goroutine finishes applying side effects — the first goroutine's side effects overwrite the second (newer) transition's state. The side effects are non-atomic relative to the state machine transitions.
- **Fix:** Added epoch guard to the state machine. Each transition increments a monotonic epoch counter. After applying side effects, the goroutine re-reads the current epoch from the state machine. If a newer transition has occurred (epoch mismatch), the stale side effects are skipped — the newer transition's goroutine will apply the correct state.
- **Files:** `pkg/daemon/daemon.go`

## HA Sync Hardening Sprint

### #69: Stale receiveLoop tears down active sync connection (FIXED)
- **Symptom:** After a sync reconnect race (accept/connect overlap), the live sync connection is torn down. Session sync stops working until the next reconnect cycle (~1s). During that window, incremental session updates are lost.
- **Root cause:** `handleDisconnect()` unconditionally closed `s.conn` and set it to nil. When conn A is replaced by conn B (via `acceptLoop` or `connectLoop`), conn A's lingering `receiveLoop` goroutine eventually gets a read error and calls `handleDisconnect()` — which closes conn B (the active connection) because `s.conn` now points to conn B.
- **Fix:** Pass the specific `net.Conn` to `handleDisconnect(conn)`. Only close if `s.conn == conn` (pointer identity check). If the connection has been replaced, log "ignoring stale disconnect" and return without side effects.
- **Files:** `pkg/cluster/sync.go`, `pkg/cluster/sync_test.go`

### #70: BulkSync sends all sessions regardless of RG ownership (FIXED)
- **Symptom:** In active/active per-RG configurations, `BulkSync()` sent every session in the table to the peer, including sessions owned by RGs the local node is not primary for. The incremental 1s sweep correctly filtered via `ShouldSyncZone()`, but bulk sync did not — causing unnecessary bandwidth and potentially installing sessions on the wrong node.
- **Root cause:** `BulkSync()` iterated all sessions without checking `ShouldSyncZone()` or filtering reverse entries.
- **Fix:** Skip reverse entries and apply `ShouldSyncZone()` ownership check in both v4 and v6 `BulkSync` iterators, matching the incremental sweep behavior.
- **Files:** `pkg/cluster/sync.go`, `pkg/cluster/sync_test.go`

### #71: Stale sessions persist after bulk sync from recovering peer (FIXED)
- **Symptom:** After a node crashes and recovers, it receives the peer's current session table via BulkSync. But sessions that existed locally before the crash (and no longer exist on the peer) are never cleaned up. These phantom sessions persist until GC timeout and can black-hole traffic that matches them.
- **Root cause:** BulkSync only installed received sessions — it never compared against local state to identify stale entries.
- **Fix:** Track received forward session keys during BulkStart→BulkEnd. On BulkEnd, `reconcileStaleSessions()` iterates local sessions in peer-owned zones, deletes any not in the received set (forward + reverse + dnat_table cleanup).
- **Files:** `pkg/cluster/sync.go`, `pkg/cluster/sync_test.go`

### #72: No mechanism to fence a hung peer on heartbeat timeout (FIXED)
- **Symptom:** When heartbeat detects peer loss, the surviving node takes over via VRRP. But if the peer's daemon is hung (not crashed), it may continue partially forwarding traffic — causing split-brain forwarding until the hung daemon times out or is killed.
- **Root cause:** No fence/STONITH mechanism existed to tell the peer to stand down.
- **Fix:** Added `syncMsgFence` message type. On heartbeat timeout with `peer-fencing disable-rg` configured, the surviving node sends a fence message via the fabric sync connection. The receiver disables all RGs (`rg_active=false`). Best-effort — if the sync connection is also down, falls back to normal heartbeat-driven failover. Fence events tracked in cluster history.
- **Files:** `pkg/cluster/cluster.go`, `pkg/cluster/cluster_test.go`, `pkg/cluster/events.go`, `pkg/cluster/sync.go`, `pkg/cmdtree/tree.go`, `pkg/config/ast.go`, `pkg/config/compiler.go`, `pkg/config/types.go`, `pkg/config/parser_test.go`

### #76: Concurrent sync writers / short-write framing corruption (FIXED)
- **Symptom:** Under heavy load with simultaneous session sync (sendLoop), config push, failover, keepalive, and BulkSync all writing to the same TCP connection, the receiver intermittently failed to parse messages — invalid magic bytes or payload lengths exceeding sanity limits. This caused sync disconnects and session loss during the most critical moments (failover transitions).
- **Root cause:** Two interacting bugs:
  1. **No write serialization:** `sendLoop()` (incremental sessions), `QueueConfig()`, `SendFailover()`, `SendFence()`, `BulkSync()`, `receiveLoop()` (keepalives), and `QueueIPsecSA()` all called `conn.Write()` or `writeMsg()` concurrently without any mutex. TCP `Write()` on Go's `net.Conn` is not atomic for large payloads — concurrent writes can interleave bytes, producing corrupted framing.
  2. **Split header+payload writes in `writeMsg()`:** `writeMsg()` used two separate `conn.Write()` calls — one for the 12-byte header and one for the payload. Even with a mutex, another writer could theoretically slip between the two writes in a race. More practically, the kernel could split the TCP segments at the header/payload boundary, making the corruption window wider.
- **Fix:**
  1. Added `writeMu sync.Mutex` to `SessionSync`. All write paths (`sendLoop`, `QueueConfig`, `SendFailover`, `SendFence`, `BulkSync`, `receiveLoop` keepalives, `QueueIPsecSA`) acquire `writeMu` before writing and release after.
  2. Rewrote `writeMsg()` to allocate a single buffer (`syncHeaderSize + len(payload)`), copy header and payload into it, then issue one `conn.Write(buf)` call — eliminating the split-write hazard entirely.
- **Files:** `pkg/cluster/sync.go`, `pkg/cluster/sync_test.go`

### #77: Fixed 10s sync-hold timeout releasing before bulk sync (FIXED)
- **Symptom:** On a returning high-priority node, VRRP preemption was released by the 10s safety timeout before the peer's BulkSync had arrived. The node became MASTER without session state, breaking all existing TCP connections that had been synced to the peer during the outage.
- **Root cause:** `SetSyncHold(10s)` was a fixed timeout as a safety net. But in practice, BulkSync can take longer than 10s for large session tables or slow fabric links. Once the timeout fires, `ReleaseSyncHold()` restores preempt on all VRRP instances — the returning node preempts to MASTER immediately, without waiting for session state. The timeout and bulk-sync-complete paths were indistinguishable, making debugging difficult.
- **Fix:**
  1. Increased sync-hold timeout from 10s to 30s to provide adequate buffer for large bulk syncs.
  2. Added `syncHoldReason` field to Manager: `"bulk-sync-complete"` (normal path via `ReleaseSyncHold()`) vs `"timeout-degraded"` (safety timeout fired). Internal `releaseSyncHoldWithReason()` records the reason.
  3. Added `SyncHoldReason()` accessor for diagnostics — allows operators and logs to distinguish normal vs degraded preemption.
  4. Timeout log message now warns about degraded mode: `"vrrp: sync-hold timeout: bulk sync did not complete within timeout, releasing in degraded mode"`.
- **Files:** `pkg/vrrp/manager.go`, `pkg/vrrp/vrrp_test.go`

### #78: Reconnect config sync accepting stale secondary config (FIXED)
- **Symptom:** After a sync reconnection race (e.g., both nodes reconnect after fabric flap), the secondary could push its outdated config to the primary. The primary's `handleConfigSync()` had no authority check — it accepted any incoming config text. This overwrote the authoritative primary config with stale data, potentially reverting security policies.
- **Root cause:** Two missing authority checks:
  1. `handleConfigSync()` accepted config from any peer without checking whether this node is the RG0 primary (config authority). A reconnecting secondary that still had an old config in its push queue could overwrite the primary's current config.
  2. `OnPeerConnected` callback pushed config on every reconnect regardless of RG0 ownership. A secondary that reconnected first could push its stale config before the primary had a chance to push the authoritative version.
- **Fix:**
  1. `handleConfigSync()` now checks `d.cluster.IsLocalPrimary(0)` — if this node is RG0 primary, incoming config sync is rejected with a warning log: `"cluster: rejecting config sync (this node is RG0 primary)"`.
  2. `OnPeerConnected` now checks `d.cluster.IsLocalPrimary(0)` before pushing — only the RG0 primary pushes config to a reconnecting peer. Non-primary nodes log `"cluster: skipping config push (not RG0 primary)"` and return.
- **Files:** `pkg/daemon/daemon.go`

### #79: Fabric_fwd passive/delayed population at startup (FIXED)
- **Symptom:** After a node restart, the `fabric_fwd` BPF map (cross-chassis forwarding MACs) took up to 60s to populate — the initial retry loop waited 2s between attempts with no active ARP probing, and the fabric peer's ARP entry was often absent after reboot. During this window, synced sessions hitting `try_fabric_redirect()` were silently dropped (no MAC to write into packet).
- **Root cause:** `populateFabricFwd()` used a passive retry strategy: poll `netlink.NeighList()` every 2s for up to 30 attempts (60s total). It never actively triggered ARP resolution. After a reboot, the kernel ARP table is empty — waiting for an organic ARP reply could take the full 60s. Additionally, `arping` doesn't populate kernel ARP when XDP is attached (raw PF_PACKET sockets bypass XDP).
- **Fix:**
  1. Fast retry: reduced from 30×2s (60s) to 10×500ms (5s) with immediate first attempt (no initial delay).
  2. Active ARP probe: added `probeFabricNeighbor()` — checks if a valid neighbor entry exists, and if not, runs `ping -c1 -W1 -I <fabIface> <peerIP>` to trigger kernel ARP resolution. Uses `ping` (not `arping`) because `ping` generates normal IP packets that go through the kernel stack and populate ARP, while `arping` uses PF_PACKET which bypasses XDP.
  3. Fallback: if fast retries don't succeed within 5s, falls back to the existing 30s periodic refresh loop.
- **Files:** `pkg/daemon/daemon.go`

### #80: Periodic neighbor warmup using stale startup config snapshot (FIXED)
- **Symptom:** After a config change that added new static routes or interfaces, the periodic neighbor resolver (15s interval) continued resolving neighbors based on the old config snapshot captured at daemon startup. New next-hops were never probed, causing `bpf_fib_lookup` NO_NEIGH (rc=7) failures for traffic using the new routes — packets fell back to kernel forwarding or were dropped.
- **Root cause:** `runPeriodicNeighborResolution()` captured `cfg *config.Config` as a parameter at launch time. The config pointer was never updated — it used the startup config snapshot for the lifetime of the goroutine, even after `commit` applied new configs.
- **Fix:** Changed `runPeriodicNeighborResolution()` to fetch fresh config from `d.store.ActiveConfig()` on each tick instead of using a captured parameter. Added nil guard (active config may be nil during early startup). The function signature changed from `(ctx, cfg)` to just `(ctx)`.
- **Files:** `pkg/daemon/daemon.go`

## Open Investigation

### Transient connectivity loss to 172.16.100.247 from cluster-lan-host after deploy restart (FIXED)
- **Status:** FIXED — root cause identified and resolved (#75)
- **Symptom:** After `make cluster-deploy` restarts both fw0 and fw1, `ping 172.16.100.247` from `cluster-lan-host` fails (100% packet loss) for ~10-30s, then self-resolves
- **Root cause:** `resolveNeighbors()` ran during `applyConfig()` BEFORE VRRP MASTER transition installed RETH VIPs. Without VIPs, `RouteGet()` for WAN next-hops failed — no ARP entries were primed. The periodic neighbor resolver had a 15s blind spot (no initial run at goroutine start), so recovery waited for the first tick at ~15s
- **Fix:**
  1. Skip `resolveNeighbors()` in cluster mode during `applyConfig()` (useless without VIPs)
  2. Trigger `resolveNeighbors()` on VRRP MASTER event in `watchVRRPEvents()` (after VIPs installed)
  3. Run periodic resolver immediately at goroutine start (no 15s blind spot)
- **Verification:** Two consecutive `systemctl restart bpfrxd` tests with continuous ping (0.5s interval) — 0% packet loss in both runs (30/30 and 40/40 pings received)
