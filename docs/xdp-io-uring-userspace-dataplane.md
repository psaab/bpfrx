# XDP to Userspace Dataplane via io_uring

Date: 2026-03-06

Note: This is an architecture exploration document. It is intentionally grounded in
bpfrx's current XDP/TC, HA, and `pkg/dataplane.DataPlane` model.

## Executive Summary

If the goal is "use XDP to hand packets to a multithreaded userspace dataplane and
still be extremely performant", the design should **not** be "XDP hands packets to
raw sockets/TUN and io_uring does all packet I/O".

That would give up too much of what makes XDP fast:
- SKB allocation returns
- extra copies return
- socket-layer parsing returns
- kernel queueing/scheduling returns

The performant design is a **hybrid**:
- **XDP stays on the NIC ingress path** for early parse, early drop, metadata stamping,
  HA ownership gating, and fast bypass decisions.
- **AF_XDP (XSK)** is the real packet handoff into userspace.
- **io_uring** is used around that fast path for the things it is actually good at:
  slow-path reinjection, control sockets, session-sync transport, logging/export,
  async netlink helpers, disk I/O, and wakeup orchestration.

If the requirement is "io_uring must be the primary packet RX/TX engine", then the
answer is blunt: that will not be the most performant version of this design.
For maximum performance, the fast path should be **XDP + AF_XDP + per-core workers**,
with io_uring supporting the rest of the system.

## What Problem This Would Solve

This architecture is attractive if you want:
- richer userspace logic than eBPF verifier limits comfortably allow
- easier debugging than deep BPF pipelines
- a path that is lighter-weight than full DPDK/VFIO in some environments
- to preserve XDP's early-drop and fail-closed properties
- to keep bpfrx's current Go control plane and `DataPlane` abstraction

This architecture is **not** the best fit if the only goal is raw 100G packet I/O.
For that, the existing DPDK plan is still the cleaner end state.

## Hard Constraint: XDP Does Not Hand Off Directly to io_uring

Today, XDP's high-performance handoff primitives are:
- `bpf_redirect_map()` to a `DEVMAP`
- `bpf_redirect_map()` to a `CPUMAP`
- `bpf_redirect_map()` to an `XSKMAP` (AF_XDP)
- `XDP_PASS`
- `XDP_TX`

There is no direct "redirect to io_uring" primitive.

So there are only two realistic ways to combine XDP and io_uring:

1. **Bad for max performance:**
   `XDP_PASS` into the normal kernel socket path, then userspace consumes with
   `io_uring` on raw sockets/TUN/TAP/UDP/TCP.

2. **Good for max performance:**
   `XDP -> AF_XDP` for the fast path, then use `io_uring` for everything around it.

The second option is the design that makes sense for bpfrx.

## Recommended Architecture

### High-Level Model

```text
NIC RX queue
  -> XDP classifier / early-drop / metadata stamp
  -> XSKMAP redirect to per-queue AF_XDP socket
  -> per-core userspace worker
  -> session / NAT / policy / FIB / HA ownership
  -> AF_XDP TX on egress interface queue

Exceptions / slow path:
  -> io_uring-driven reinjection to TUN/TAP or control sockets
```

### Key Principle

Treat the system as:
- **XDP = front-end classifier and guardrail**
- **AF_XDP = zero-copy packet conveyor into userspace**
- **userspace workers = stateful firewall dataplane**
- **io_uring = asynchronous systems plumbing around the dataplane**

That gives you the best chance of staying close to native-XDP efficiency while moving
stateful complexity into userspace.

### Support Envelope

This design only makes sense if the implementation is explicit about what it supports.

#### Primary supported mode

- native XDP capable NIC
- AF_XDP bound to hardware RX/TX queues
- zero-copy AF_XDP where the driver supports it
- pinned worker cores with stable RSS / queue affinity

This is the target mode for the fast path.

#### Acceptable but not target mode

- native XDP with AF_XDP copy mode

This can still be useful for bring-up, labs, and lower-end systems, but it should not
be treated as the performance target when comparing against the current eBPF or DPDK
dataplanes.

#### Explicitly not the primary fast path

- generic XDP plus AF_XDP
- raw sockets consumed with io_uring
- TUN/TAP as the primary packet handoff

If an interface only supports those paths, bpfrx should keep using the current eBPF/TC
dataplane on that interface instead of pretending the userspace dataplane is equivalent.

#### Mixed-mode operation

The implementation should allow mixed dataplanes on the same node:

- AF_XDP userspace dataplane on native-XDP-capable data interfaces
- existing eBPF/TC dataplane on unsupported interfaces
- the same Go control plane publishing config to both backends

That reduces bring-up risk and avoids turning driver capability mismatches into an
all-or-nothing deployment problem.

## Why This Fits bpfrx Better Than a Pure io_uring Packet Engine

bpfrx already has:
- a strong `pkg/dataplane.DataPlane` interface
- a clean Go control plane
- HA/session-sync logic outside the dataplane hot path
- existing XDP stage boundaries that map naturally to "what stays in XDP" vs
  "what moves to userspace"

The right architectural move is not "replace XDP with io_uring sockets".
It is:
- keep cheap stateless work in XDP
- move stateful heavy work to userspace
- keep the slow-path/control-path asynchronous with io_uring

## Proposed Packet Path

### 1. XDP ingress stays very small

The XDP program should do only the work that is worth doing before userspace:
- parse Ethernet/VLAN/IP/L4 headers
- reject garbage early
- apply the cheapest screen checks
- enforce HA/RG ownership and watchdog state
- decide whether traffic is:
  - host-local and should stay in the kernel
  - simple enough to forward/drop in XDP
  - or requires userspace stateful processing
- stamp metadata for userspace
- redirect to AF_XDP

This is a smaller XDP program than today's full chain.

### 2. XDP writes a fixed metadata header

Before redirecting to AF_XDP, XDP should reserve metadata headroom and write a
compact fixed struct, for example:

```c
struct usr_dp_meta {
    __u32 ingress_ifindex;
    __u32 ingress_ifindex_phys;
    __u16 ingress_vlan;
    __u16 rg_id;
    __u16 ingress_zone;
    __u16 route_table_hint;
    __u16 pkt_len;
    __u8  addr_family;
    __u8  protocol;
    __u8  tcp_flags;
    __u8  flags;
    __u32 flow_hash;
    __u32 now_sec;
    __u32 fib_gen;
    __u32 mark;
    __u16 src_port;
    __u16 dst_port;
    __u8  src_ip[16];
    __u8  dst_ip[16];
};
```

This matters because it avoids reparsing and redoing the same zone/HA classification
in userspace.

#### Metadata ABI contract

This must be treated as a real ABI, not an informal struct.

Rules:

- XDP writes metadata via `bpf_xdp_adjust_meta()`, not by overloading packet payload.
- The metadata struct must be fixed-size, naturally aligned, and versioned.
- All multi-byte fields should be little-endian host order unless there is a strong
  reason to preserve network order. The choice must be documented and consistent.
- The metadata version must be the first field so workers can reject incompatible
  packets instead of silently misparsing them.
- `pkt_len` must represent the post-VLAN-pop packet length seen by workers.
- `ingress_vlan` must preserve the original logical ingress VLAN so userspace can
  reason about sub-interface ownership and restore tags on transmit when needed.
- `flow_hash` must be the same shard key used for worker assignment and for session
  sync shard ownership on both cluster nodes.
- `fib_gen` and config generation fields must be checked by workers so packets
  stamped under an old control-plane snapshot cannot be processed against a newer
  snapshot silently.

Recommended first fields:

```c
struct usr_dp_meta_v1 {
    __u16 version;
    __u16 meta_len;
    __u32 config_gen;
    __u32 ingress_ifindex;
    ...
};
```

Workers should hard-drop packets with unknown metadata versions or impossible
`meta_len` values.

### 3. AF_XDP is the handoff boundary

Each worker owns one AF_XDP socket per queue, ideally per interface queue index.

Example on a 4-core box:
- worker 0 owns queue 0 on trust/untrust/fabric interfaces
- worker 1 owns queue 1 on trust/untrust/fabric interfaces
- worker 2 owns queue 2 on trust/untrust/fabric interfaces
- worker 3 owns queue 3 on trust/untrust/fabric interfaces

This preserves queue affinity and avoids cross-thread packet movement.

### 3a. Queue Ownership Model

The design needs a precise queue ownership contract.

Rules:

- each worker owns one queue index per participating interface
- a worker never touches another worker's AF_XDP rings in the fast path
- each flow must map to the same worker on ingress and on the standby node
- queue ownership must be configured from the smallest queue count across the active
  dataplane interfaces in a forwarding group

Example:

- if LAN has 8 queues and WAN has 4 queues, the userspace fast path should use 4
  worker shards unless there is an explicit remapping layer
- the remaining LAN queues should either be disabled for AF_XDP or remain on the
  existing dataplane

This is stricter than "one worker per core", but it avoids hidden cross-queue
forwarding costs.

#### RSS and repair strategy

- symmetric NIC RSS is the first choice
- if NIC RSS cannot guarantee symmetry, XDP may compute the same flow hash itself
  and redirect into the appropriate `XSKMAP` entry
- `CPUMAP` should not be the normal repair mechanism for this backend; it adds
  another handoff and defeats the point of queue ownership

If stable flow-to-worker mapping cannot be guaranteed, this backend should not be
enabled on that interface set.

### 4. Userspace worker does the stateful firewall work

The worker performs what today is spread across:
- `xdp_zone`
- `xdp_conntrack`
- `xdp_policy`
- `xdp_nat`
- `xdp_nat64`
- part of `xdp_forward`

This includes:
- session lookup / creation
- TCP state updates
- NAT / NAT64 / NPTv6
- zone-pair policy evaluation
- application lookup
- FIB and adjacency lookup
- fabric redirect decisions
- event generation

### 5. AF_XDP TX handles the common forwarding path

For packets with a resolved L2 adjacency and a supported egress interface:
- rewrite headers in userspace
- enqueue directly to the worker's AF_XDP TX ring for the egress interface/queue

That keeps the common path fully out of the SKB stack.

### 5a. Backpressure and Overload Policy

This needs an explicit policy. Without one, "slow path" just becomes hidden packet loss.

Recommended rules:

- if the worker RX ring is starved for fill entries, XDP drops forwarded traffic
  and increments an explicit backpressure counter
- if the worker is alive but its rings are saturated, forwarded traffic is dropped
  fail-closed by default
- host-local traffic may still `XDP_PASS` to the kernel if that is already the
  current behavior for the interface/zone
- unresolved-neighbor and unsupported-route exceptions may use a bounded slow path,
  but only behind an explicit rate limiter
- there must be no automatic "everything falls back to kernel sockets" mode for
  forwarded traffic under overload

The point is to preserve deterministic behavior:

- local control-plane reachability may degrade gracefully
- transit forwarding must either stay on the fast path or fail closed

Anything else will create opaque overload behavior during HA or traffic tests.

### 6. io_uring handles exceptions and slow-path work

Use io_uring for:
- TUN/TAP reinjection of local/exception traffic
- session sync TCP sockets
- gRPC/REST/event export sockets
- async logging / IPFIX / NetFlow output
- netlink helper threads and route-neighbor refresh work
- disk/config operations
- watchdog/eventfd wakeups between helper threads and workers

This is where io_uring is a real win.

## Threading Model

### One worker per RX queue/core

The design should be **strictly sharded**.

Each worker gets:
- one CPU core, pinned
- one RX queue per dataplane interface
- one local session table shard
- one local NAT allocator shard
- one local counters block
- one local timer wheel / expiry heap

### No locks in the fast path

Fast path rules:
- no shared global session table
- no shared global NAT allocator
- no shared counter cachelines
- no cross-thread lookups on steady-state flows
- no syscalls in the common packet path

### Flow steering is mandatory

To stay performant, every packet of a flow must land on the same worker.

Use:
- NIC RSS with symmetric hash where possible
- queue index alignment across interfaces
- XDP-computed fallback hash only when NIC RSS cannot guarantee symmetry

If a flow can bounce between workers, the design degrades badly.

## Memory Model

### Packet buffers

Use AF_XDP UMEM for packet buffers.

Recommendations:
- large pre-registered UMEM region
- per-worker UMEM or per-NUMA UMEM partitioning
- fixed-size frames sized for MTU + metadata headroom
- separate slow-path buffer pool for reinjection paths

### Session tables

Use per-worker lock-free or single-owner hash tables in userspace.

Recommended split:
- hot session state in a cacheline-friendly struct
- cold/logging fields out of line
- per-worker expiry structure, not a global GC sweep

That is more important for performance than whether the helper threads use io_uring.

### Shared state with Go control plane

Use shared memory or copy-on-publish snapshots for config tables:
- zone maps
- policy arrays
- application tables
- NAT rules
- route/neighbor mirrors
- RG ownership state

Do not make workers call back into Go on packet path decisions.

#### Snapshot publication contract

This part needs hard rules:

- workers only read immutable snapshots
- the Go control plane publishes a new snapshot, then flips a generation pointer
- old snapshots remain valid until all workers have quiesced past the old generation
- XDP stamps `config_gen` and `fib_gen` into packet metadata
- workers must reject or slow-path packets whose stamped generation no longer matches
  an installed snapshot

That avoids processing a packet classified under config generation `N` with policy or
adjacency state from generation `N+1`.

## What Should Stay in XDP vs Move to Userspace

### Keep in XDP

Keep only the work that benefits from being before userspace:
- malformed packet drop
- obvious stateless drops
- HA watchdog and ownership gating
- very cheap screen checks
- local-kernel bypass decisions
- metadata stamping
- queue/worker steering

### Move to userspace

Move the heavier, stateful, branchy work:
- session table
- policy engine
- NAT/NAT64/NPTv6
- application matching
- FIB/adjacency cache
- fabric forwarding decisions
- event/log export production

### Why

This is the right split because the expensive part of bpfrx is not Ethernet parsing.
It is state, hashing, timers, NAT, and policy.

### Feature Coverage Boundaries

The implementation should be explicit about what is in scope for the first usable backend.

#### Fast path in userspace

- IPv4/IPv6 routed forwarding
- zone policy
- session state / TCP tracking
- source NAT / destination NAT / NAT64 / NPTv6
- basic FIB + adjacency forwarding
- HA ownership checks and fabric redirect decisions

#### Slow path through kernel or helper thread

- local services / host-inbound traffic
- unresolved neighbors
- ICMP error generation
- route types not supported by the worker fast path
- exceptional packets that fail metadata or adjacency validation

#### Keep on current backend initially

- IPsec dataplane handling through `xfrmi`
- GRE/IPIP encapsulation and decapsulation
- TC egress mirroring / clone semantics
- any feature that depends on skb-only helpers or existing TC hooks

This is important because bpfrx is not just a basic routed firewall. Pretending the
first userspace backend covers every current feature would guarantee a bad rollout.

## Where io_uring Actually Helps

io_uring helps a lot, but not in the way people often mean.

### Good io_uring uses here

1. **Slow-path reinjection**
- write host-bound/exception packets to TUN/TAP with batched SQEs

2. **Session sync transport**
- replace blocking write/read goroutines with batched async I/O
- coalesce sync messages
- reduce wakeup overhead

3. **Flow export / logging**
- async UDP/TCP export with batching
- durable log/file writes without dedicated writer threads

4. **Netlink and route helper plumbing**
- async helper sockets
- background neighbor refresh and route invalidation

5. **Worker wakeup orchestration**
- eventfd + io_uring poll instead of ad hoc blocking helpers

### Bad io_uring uses here

1. primary packet RX from raw sockets
2. primary packet RX from TUN/TAP as the fast path
3. primary forwarding via kernel sockets on every packet

Those paths reintroduce the kernel networking overhead you were trying to avoid.

## Routing and Neighbor Model

The userspace dataplane needs a route/adjacency mirror, similar to the DPDK plan.

Recommended model:
- Go daemon subscribes to netlink route/neigh/link updates
- publishes immutable route and adjacency snapshots to workers
- workers use a fast local FIB cache and adjacency cache
- unresolved neighbor or unsupported route types go to slow path

This mirrors how bpfrx already thinks about FIB generation and route invalidation.

## HA and Session Sync

This design can fit bpfrx HA, but only if ownership is explicit and cheap.

### Required HA rules

1. XDP must know whether this node/worker is allowed to accept fast-path traffic.
2. XDP must fail closed if the userspace dataplane heartbeat goes stale.
3. RG ownership state must be visible to both XDP and userspace workers.
4. Session sync must remain outside the worker hot path.

### Recommended split

- XDP enforces watchdog and coarse RG ownership.
- Userspace workers own session state and counters.
- Go control plane owns cluster protocol, replay, fencing, and configuration authority.

### Session sync implementation

Do not stream every packet-path mutation directly from workers to the peer.
Use batched delta publication from workers to a sync thread:
- per-worker append-only delta ring
- sync thread batches and transmits
- periodic sweep/backfill remains available for repair

That preserves the current bpfrx sync design principles.

### Shard ownership and replay rules

This part should not stay implicit.

- the same `flow_hash` used for worker selection must determine the owning worker shard
- both HA nodes must use the same hash algorithm and shard count for replicated flows
- session sync messages must carry shard ID so replay and backfill can be targeted
- bulk replay should be partitioned by shard, not emitted as one global stream
- standby workers should install sessions into the shard that would own the flow if
  the node became active

That keeps failover from turning into a cross-thread session migration problem.

#### Fabric forwarding interaction

- XDP still decides whether the packet belongs on the local node or should be sent
  to the peer under HA ownership rules
- once a packet is handed to a local worker, that worker is authoritative for the
  local session shard
- fabric redirects must preserve enough metadata for the receiving node to derive
  the same worker shard deterministically

## Crash and Recovery Model

This is the biggest architectural tradeoff versus today's eBPF dataplane.

### eBPF today
- dataplane survives daemon restart
- pinned links/maps keep forwarding alive

### userspace fast path
- if workers crash, forwarding stops

### Mitigation

Use XDP as a hard guard:
- workers update a watchdog map per shard/core
- XDP checks freshness before redirecting to AF_XDP
- if stale:
  - host-local traffic can still `XDP_PASS`
  - forwarded traffic should fail closed or fail to a deliberately-limited slow path

This gives deterministic failure instead of undefined stale forwarding.

#### Watchdog contract

- each worker updates a per-shard heartbeat map entry
- XDP checks both process-wide liveness and shard-local liveness before redirect
- a stale shard heartbeat must fail closed for forwarded traffic even if the process
  is still partially alive
- workers should not be considered healthy until their AF_XDP rings, config snapshot,
  and route snapshot are all installed

## What an Implementation Would Look Like in bpfrx

## Phase 1: Add a new dataplane backend type

Add a new backend type, likely:
- `TypeAFXDPUring` or `TypeUser`

Keep the existing `DataPlane` interface and implement a new backend alongside eBPF and DPDK.

## Phase 2: Shrink XDP to a front-end classifier

Replace the full XDP tail-call chain on selected interfaces with:
- parse
- cheap filter/screen
- HA guard
- metadata stamp
- XSK redirect

## Phase 3: Build a per-core userspace worker runtime

Likely process layout:
- same process as `bpfrxd`, with pinned worker goroutines plus C/Rust hot loops, or
- separate worker process with shared memory control plane

For performance, a separate native worker binary is cleaner than trying to run the
hot loop in normal Go goroutines.

## Phase 4: Move session/NAT/policy into worker-local tables

Do not preserve the current "global map + GC sweep" design as-is.
For userspace, the right model is:
- sharded tables
- worker-local expiry wheels
- batched aggregation to control plane

## Phase 5: Use io_uring for the non-AF_XDP parts

Once the packet fast path is correct, add io_uring to:
- session sync sockets
- flow export
- logging
- slow-path TUN reinjection
- helper socket polling

That is the order that makes architectural sense.

## Performance Rules If This Must Be Extremely Fast

1. **AF_XDP, not raw sockets, is the fast-path handoff.**
2. **One flow, one worker, one queue.**
3. **No locks on steady-state packet path.**
4. **No Go allocations on steady-state packet path.**
5. **No syscalls on steady-state packet path.**
6. **XDP writes metadata so userspace does not redo cheap classification.**
7. **Keep local traffic and unsupported exceptions out of the fast path.**
8. **Use per-worker expiry structures, not a global GC sweep.**
9. **Keep XDP watchdog ownership checks so userspace failures fail closed.**
10. **Use io_uring for the edges of the dataplane, not as a substitute for AF_XDP.**

## Observability Requirements

This backend will be too hard to debug unless observability is part of the design.

Required counters and state:

- per-worker RX/TX packets and bytes
- per-worker drop reasons
- AF_XDP fill/rx/tx/completion ring occupancy and starvation counters
- worker heartbeat age
- packets dropped by XDP because the worker shard was stale or overloaded
- slow-path packet counts by reason
- per-shard session counts
- per-shard session-sync delta backlog
- route/adjacency snapshot generation currently installed per worker
- queue imbalance indicators across workers

Required CLI / API surface:

- `show dataplane workers`
- `show dataplane xsk`
- `show dataplane backpressure`
- `show cluster shard-sync`

Without that, bring-up and HA debugging will be mostly guesswork.

## Advantages of This Design

- preserves XDP's best property: cheap drop before the kernel stack
- removes eBPF verifier pressure from the stateful firewall path
- keeps bpfrx's current Go control-plane architecture intact
- can reuse much of the DPDK route/session/config backend thinking
- gives a reasonable path to multithreaded userspace processing without immediately
  committing to full DPDK/VFIO deployment requirements

## Disadvantages and Risks

- more complex than current eBPF
- still weaker crash resilience than pinned BPF dataplane
- AF_XDP queue/interface management is operationally sharp-edged
- if implemented poorly, it becomes "worse than DPDK and less simple than XDP"
- if io_uring is forced into the primary packet I/O role, performance will likely
  disappoint relative to AF_XDP or DPDK

## Recommendation

If bpfrx wants to explore this space seriously, the right target is:

**XDP front-end + AF_XDP userspace workers + io_uring for slow-path and async systems work**

Not:

**XDP front-end + io_uring raw-socket/TUN packet engine**

That second design is architecturally possible, but it is not the version I would
expect to be "extremely performant".

## Open Questions

1. Should this be a separate worker process, or an in-process backend under `bpfrxd`?
2. Do we want AF_XDP only for native-XDP-capable NICs, with eBPF/TC retained elsewhere?
3. Do we want a kernel slow path via TUN/TAP, or strict fail-closed on unresolved neighbors/local exceptions?
4. Should session sync read worker-local delta rings directly, or aggregate through a single userspace dataplane manager?
5. If this path is pursued, is it still worth carrying both this and the DPDK backend long-term?

## Bottom Line

A performant design exists, but it is really:
- **XDP + AF_XDP** for packet handoff
- **multithreaded userspace workers** for stateful processing
- **io_uring** for the surrounding async plumbing

If the goal is maximum performance, I would design it that way from day one.
