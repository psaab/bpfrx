# Triage result: gemini-review-047

Base reviewed by Gemini: `275989b76` — verified against **current origin/master `9bfd48226`**
(paths mapped by stripping the `gemini-xpf/` prefix). 3-gate triage:
symbol-exists → already-fixed → real+material.

~16 real findings (2 "Low" entries are misparsed section headers — ignored).

## Tally
- **GENUINE filed (4):** #5379, #5380, #5381, #5382
- **DUP (2):** High#2 → #5373 (closed); High#3 → #5079 (open)
- **NOT-MATERIAL / NA (10)**

---

## High Severity

### High#1 — reject_reply build-before-rate-limit CPU/heap churn → NOT-MATERIAL
`userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs`. Symbol exists. The
build-then-consume ordering is **deliberate and heavily documented** (#3656
H11/H12): the reject reply is built first (a side-effect-free reflection) so an
**unreplyable** frame consumes NEITHER the per-zone reject token (H11) NOR a
budget-drop counter (H12). Gemini's proposed fix (hoist the budget + rate checks
above the build) **reintroduces exactly the H11/H12 mis-attribution bugs** the
comment describes. The build is on the cold reject **exception** path, not the
transit fast path. Not filed.

### High#2 — member-range int64 loop overflow infinite loop → DUP-of-#5373
`pkg/config/compiler_interface_range.go`. Per instructions, already filed as
**#5373** ("config: interface member-range expansion infinite-loop/OOM via int64
loop-variable overflow…"). #5373 is currently CLOSED. Recorded as DUP, not re-filed.

### High#3 — peer stuck StateSecondaryHold on local-commit-failure abort → DUP-of-#5079
`pkg/cluster/failover.go`. Genuine gap and **already tracked open** as **#5079**
("cluster: remote failover demotes owner before requester commit with no abort
frame, lease, or reqID-bound rollback (both nodes can strand secondary)").
Confirmed the mechanism: `abortRequestedPeerFailover` reverts only the
initiator's local override; there is **no abort message type** (grep of
`pkg/cluster` finds only Failover/Ack/Commit/CommitAck/Batch/Fence — no
FailoverAbort), and the peer runs `ManualFailover` on the *request* (before the
commit) via `OnRemoteFailover`. The existing unit test
`TestRequestPeerFailoverAbortsToPriorPeerStateWhenLocalCommitReadyHookFails`
only asserts the initiator's local reversion (its mock `SendFailover` never
models the peer's transition), so it does not disprove the two-node desync.
DUP-of-#5079, not re-filed.

### High#4 — sequential per-request socket dial hang → GENUINE → **#5380**
`pkg/dataplane/userspace/manager_ha.go:1406` (`syncSessionRequestsLocked`) +
`process_control.go` (`requestSessionSync`). Confirmed: loops per request, each
opens a fresh Unix socket via `net.DialTimeout(...,2s)` + 3s deadline, logs and
**continues** on error (no fast-fail). `deleteHelperSessionsV4` chunks by
`sessionHelperDeleteChunk` and guards `m.proc == nil`, but a hung-but-unreaped
helper window is real. Bulk clear against a hung helper serializes into a
multi-minute stall holding `m.sessionMu`. Filed **#5380** (bug/dataplane/perf).
Code fix driveable now; multi-minute-hang verification is lab-bound.

## Medium Severity

### Medium#1 — GRE encap redundant `.to_vec()` → GENUINE → **#5381**
`userspace-dp/src/afxdp/gre.rs:837`. Confirmed `let inner_packet =
inner_frame.get(inner_l3..)?.to_vec();` — inner packet is only read afterward
(`packet_trimmed_len`, reslice, `inner_tos_byte`, `.len()`, `copy_from_slice`)
and `inner_frame: &[u8]` outlives the body, so the owned copy is unnecessary. A
removable per-packet heap alloc+copy on the native GRE egress path. Low-severity
perf. Filed **#5381** (bug/dataplane/perf).

### Medium#2 — xsk-repro `/tmp` predictable temp file → NOT-MATERIAL
`test/xsk-repro/main.rs:250`. Symbol exists. But this is a **manual
diagnostic/repro harness** run by an admin under `sudo`, not shipped in the
appliance dataplane. No privilege boundary is crossed (the "attacker" needs a
symlink race in `/tmp` with `fs.protected_symlinks` off, or must trick an admin
into running their own tool). Not filed.

### Medium#3 — Annotate bypasses config-lock ownership → GENUINE → **#5379**
`pkg/configstore/store_command.go:241`. Confirmed: all 7 sibling mutators call
`ensureHolderLocked(sessionID)` (lines 25/64/115/145/169/193/220); `Annotate`
does not, has no `*As` variant, and `pkg/configstore/README.md`'s enforcement
list **omits Annotate** while its threat model explicitly forbids a non-holder
extending the lease via `touchConfigLockLocked` — which `Annotate` does.
Reachable via REST (`pkg/api/config.go:399`) + local CLI
(`pkg/cli/cli_dispatch.go:504`); **not** gRPC/fabric-exposed (no gRPC handler),
so localhost multi-session consistency/authorization gap. Filed **#5379**
(bug/security). Driveable now.

### Medium#4 — VRRP false promotion on AdvertiseInterval increase → NOT-MATERIAL (false positive)
`pkg/vrrp/instance.go`. Two independent disproofs on master: (1) `updateConfig`
does **not** apply `AdvertiseInterval` at all (only Priority/Preempt/hold/track),
and the manager reconcile treats an interval-only delta as no-change or forces a
full restart — there is no in-place path that leaves a stale timer from a new
interval. (2) `masterDownInterval()` derives the timeout from the **learned**
master advert interval (`masterAdverInterval`, RFC 5798 §6.4.2), not local
config, specifically to handle rolling/mismatched intervals — so Gemini's
proposed fix (reset the timer from local config) would recompute the same value
and is a no-op. Not filed.

### Medium#5 — BumpFIBGeneration RMW race → NOT-MATERIAL
`pkg/dataplane/maps_fabric.go:78`. The cited RMW is reachable via the live
`userspace.Manager.BumpFIBGeneration` → `m.bpfShim.BumpFIBGeneration()` (shim
owns `fib_gen_map`), which runs **before** `m.mu`. But the **only** live caller
is `pkg/daemon/daemon_ipmon.go:323`, which the code documents runs under
`d.applySem` ("pendingFIBBump is mutated only here, under d.applySem"). The other
call site (`pkg/dataplane/compiler.go:291`) is retired-eBPF dead code. No
concurrent caller exists → the lost-update race is not reachable. Not filed.

### Medium#6 — DHCP PD-only leases omitted → GENUINE → **#5382**
`pkg/grpcapi/server_dhcp.go`. Confirmed the `if !attached && len(resp.Leases) >
0` guard on master drops a standalone PD entry when there are no IA_NA leases
(PD-only client) → empty lease table. Gemini self-noted this as a restatement of
a prior campaign dedup entry, but no matching **open GitHub issue** was found.
Display/observability vSRX-parity gap. Filed **#5382** (bug/vsrx-parity).

## Low Severity

### Low#1 — libbpf_xsk_test.c `system()` command injection → NOT-MATERIAL
`test/xsk-repro/libbpf_xsk_test.c:254`. Confirmed `snprintf(cmd,...,"ip link set
%s ...",iface); system(cmd);` with `iface` from argv. But it's a manual
diagnostic C tool the admin runs with their own argument — no privilege boundary
crossed, not shipped. Not filed.

### Low#2 — WaitForPeerBarriersDrained blocks full timeout on disconnect → NOT-MATERIAL
`pkg/cluster/sync_bulk.go:419`. Symbol exists, but tree-wide grep finds **no
live production caller** — only tests, and the docs
(`docs/session-sync-architecture.md`, `_Log.md`, pr-history) explicitly call it
a "retained primitive with no current live" caller. Not reachable in production.
Not filed.

### Low#3 — data race / nil-panic on `d.sessionSync` during teardown → NOT-APPLICABLE
File: `unknown`, no evidence snippet in the review. No concrete symbol/line to
verify; unverifiable as written. Not filed.

### Low#4 — data race / nil-panic on `d.dp` interface reads → NOT-APPLICABLE
File: `unknown`, no evidence. Unverifiable as written. Not filed.

### Low#5 — RETH link-local not programmed for VlanID 0 sub-interfaces → NOT-APPLICABLE
File: `unknown`, no evidence. Unverifiable as written. Not filed.

### Low#6 — web-mgmt fails to bind on link-local-only IPv6 → NOT-APPLICABLE
File: `unknown`, no evidence. Unverifiable as written. Not filed.

### Low#7 / Low#8 — MISPARSED section headers ("26. Other Associated Test
Suites", "Files Covered (42 files)"). Not findings; ignored per instructions.

---

## Filed issues
| # | Sev | Title | Driveable |
|---|-----|-------|-----------|
| #5379 | Med | configstore: Annotate bypasses config-lock ownership | now (Go) |
| #5380 | High | userspace-dp/HA: syncSessionRequestsLocked per-request socket dial, no fast-fail | code now; hang-verify lab-bound |
| #5381 | Med(low) | userspace-dp: GRE encap redundant `.to_vec()` | now (Rust dp) |
| #5382 | Med | grpcapi: GetDHCPLeases drops PD-only delegated prefixes | now (Go) |

Dups: #5373 (High#2, closed), #5079 (High#3, open).
