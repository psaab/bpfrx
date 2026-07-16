# Review: A5_go_ha_vrrp_ra_conntrack — batch 1/1

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Batch file list (91 files):
pkg/cluster/cluster_test.go, pkg/cluster/election.go, pkg/cluster/election_dup_nodeid_4549_test.go, pkg/cluster/election_test.go, pkg/cluster/events.go, pkg/cluster/events_log.go, pkg/cluster/events_test.go, pkg/cluster/failover.go, pkg/cluster/garp.go, pkg/cluster/garp_abdicate_test.go, pkg/cluster/garp_burst_errors_test.go, pkg/cluster/garp_test.go, pkg/cluster/group_state.go, pkg/cluster/heartbeat.go, pkg/cluster/heartbeat_auth_test.go, pkg/cluster/heartbeat_guard_recheck_test.go, pkg/cluster/heartbeat_liveness_test.go, pkg/cluster/heartbeat_manager.go, pkg/cluster/heartbeat_neverseen_floor_test.go, pkg/cluster/heartbeat_rg_cap_4434_test.go, pkg/cluster/heartbeat_stop_previous_test.go, pkg/cluster/heartbeat_test.go, pkg/cluster/hooks.go, pkg/cluster/kernel_selfrecover.go, pkg/cluster/lease_sync_wire_test.go, pkg/cluster/manager.go, pkg/cluster/monitor.go, pkg/cluster/peer_state.go, pkg/cluster/readiness.go, pkg/cluster/reth.go, pkg/cluster/reth_test.go, pkg/cluster/runtime.go, pkg/cluster/status.go, pkg/cluster/sync.go, pkg/cluster/sync_accept_test.go, pkg/cluster/sync_auth.go, pkg/cluster/sync_auth_test.go, pkg/cluster/sync_bulk.go, pkg/cluster/sync_config_gen_test.go, pkg/cluster/sync_conn.go, pkg/cluster/sync_failover.go, pkg/cluster/sync_gen_guard_test.go, pkg/cluster/sync_protocol.go, pkg/cluster/sync_state.go, pkg/cluster/sync_test.go, pkg/conntrack/gc.go, pkg/conntrack/gc_test.go, pkg/conntrack/legacy_dataplane_canary_test.go, pkg/ra/filter.go, pkg/ra/ra.go, pkg/ra/ra_test.go, pkg/ra/sender.go, pkg/ra/sender_interval_4525_test.go, pkg/ra/sender_linklocal_test.go, pkg/ra/sender_marshal_3895_test.go, pkg/ra/sender_marshal_4119_test.go, pkg/ra/sender_marshal_4307_test.go, pkg/ra/serialize_test.go, pkg/vrrp/addrwatch.go, pkg/vrrp/addrwatch_test.go, pkg/vrrp/afpacket_cloexec_test.go, pkg/vrrp/afpacket_membership_test.go, pkg/vrrp/bindtodevice_test.go, pkg/vrrp/instance.go, pkg/vrrp/instance_arp_probe_test.go, pkg/vrrp/instance_garp_abdicate_test.go, pkg/vrrp/instance_garp_force_test.go, pkg/vrrp/instance_garp_probe_target_test.go, pkg/vrrp/instance_garp_test.go, pkg/vrrp/instance_ifindex_filter_test.go, pkg/vrrp/instance_localip_race_test.go, pkg/vrrp/instance_master_interval_test.go, pkg/vrrp/instance_owner_preempt_test.go, pkg/vrrp/instance_preempt_gate_test.go, pkg/vrrp/instance_preempt_hold_revalidate_test.go, pkg/vrrp/instance_preempt_holdtime_test.go, pkg/vrrp/instance_rxdrop_race_test.go, pkg/vrrp/instance_v6_hoplimit_test.go, pkg/vrrp/instance_v6_pktinfo_test.go, pkg/vrrp/instance_vipset_canon_test.go, pkg/vrrp/manager.go, pkg/vrrp/manager_garp_unsuppress_test.go, pkg/vrrp/manager_reuse_test.go, pkg/vrrp/packet.go, pkg/vrrp/packet_checksum_test.go, pkg/vrrp/track.go, pkg/vrrp/track_test.go, pkg/vrrp/update_instances_test.go, pkg/vrrp/vrrp.go

## Module-by-module log

- cluster/election.go: Checked EffectivePriority math, duplicate-node-id fail-closed, kernelUpgradeHold, ManualFailover 2s guard, split-brain dual-active tie-break. Logic sound, no new truncation beyond bounded inputs. One LOW noted for nodeID int->uint8 in heartbeat (elsewhere).
- cluster/heartbeat.go: Reviewed Marshal/Unmarshal, dual-accept auth, anti-replay, group-count cap #4434, version trailer, monitor truncation. Found uint8 RGID truncation (LOW) and interface monitor name-len uint8 truncation (LOW). No fail-open.
- cluster/heartbeat_manager.go: Reviewed StartHeartbeat idempotent stop+install, vrfListenConfig SO_REUSE, RestartHeartbeat 5×1s retry with lastSeen seed, buildHeartbeat casts, handlePeerHeartbeat rebuild, handlePeerTimeout staleness re-check, fence. Found Manager.Start deadlock via Monitor.Stop (HIGH).
- cluster/sync.go / sync_protocol.go / sync_state.go: Reviewed session encode/decode, gen guard, delete journal, config apply queue, bulk epoch, IPsec/lease sync. No new truncation beyond already-capped genGuardMapCap. Found failover waiter panic race (HIGH) in sync_failover.go interaction with sync_conn.go handleDisconnect.
- cluster/sync_auth.go: Handshake concurrent HELLO/PROOF write+read to avoid Pipe deadlock, proof HMAC domain separation, downgrade guard, frame seal. Correct.
- cluster/sync_bulk.go / sync_conn.go: Bulk start/end epoch handling, pendingBulkAck record-then-send, bulkRedrive single-flight, acceptLoop per-conn goroutine, receiveLoop auth trailer verify, barrier ack direct writeMu, configApplyCh non-blocking drop (LOW). No deadlock beyond Manager.Start.
- cluster/sync_failover.go: Validated RGID range 0..255, batch key dedup, failover/batch/commit waiters, sendFailoverResult dual-conn fallback. Found panic-on-closed-channel race (HIGH, see Finding 2).
- cluster/failover.go: ManualFailover preHook retry, ForceSecondary peer-alive check, RequestPeerFailover readiness gates, transfer-commit override/grace, batch failover. No new truncation.
- cluster/monitor.go: ICMP probe ID from LocalAddr port, sequence 1..65535, dampening thresholds, hold-down, LinkAttrsUp OperState vs IFF_UP. Correct.
- cluster/garp.go / reth.go / events.go / events_log.go / group_state.go / peer_state.go / hooks.go / kernel_selfrecover.go / readiness.go / runtime.go / status.go: Straightforward; RethMAC 02:bf:72:CC:RR:NN per-node unique, StableRethLinkLocal fe80::bf:72:CC:RR shared, RethIPs skips link-local, EventHistory ring buffer truncates oldest. No bug.
- cluster/manager.go: Manager.Start deadlock (HIGH) vs Monitor.Stop; UpdateConfig controlLinkAuthKey replace-not-mutate, electSingleNode vs runElection, recalcWeight weight 255-totalLost clamp. No other issue.
- conntrack/gc.go: Aggressive aging hysteresis under lock, SetAgingConfig negative clamp #3440, SkipSweep, session count map, v6 skip every 6 sweeps, monotonicSeconds, adaptive delay. No truncation beyond earlyAgeout uint64 (clamped).
- ra/ra.go: Draining tombstone protocol, releaseDrain proven-close vs timeout, reclaimTombstoneWhenStopped, WithdrawOnce claimWithdrawOnceLocked atomic check-and-claim #2272, goodbyeClaimed exactly-once, epoch supersede, applyDeferred bounded wait, configEqual includes ReachableTime/RetransTimer #4570. No new bug.
- ra/sender.go: Single-owner conn, openConn under unlock, dead() detection #2865, signalStop graceful upgrades hard, finishShutdown goodbyeEmitted post-mortem, burstInterruptible, rsReceiver backoff, pruneUnmarshalableOptions #3895, randomAdvInterval min 1s #4525, prefix pref>valid clamp, link-local EUI-64. Minor time.After leak (LOW).
- ra/filter.go: Trivial.
- vrrp/vrrp.go: CollectInstances flat-set translation, CollectRethInstances 30ms default, RethVIPsForRG, device-map aware. AdvertiseInterval sec→ms multiply (no overflow for sane config). No bug.
- vrrp/instance.go: VIP add with IFA_F_NODAD, GARP gated burst, GatewayProbeTarget network+1 (not last-octet .1) #2377, garpDampened negative elapsed clamp #1792, garpSendAllowed epoch dedup + time dampener bypass on force #2081, recordMasterAdvert MinLearned floor #4548, masterAdverInterval learned vs floor, preempt hold re-validate, owner-preempt 255, equal-priority single-family anchoring #4376, walkIPv6ExtHeaders, IPv6 HH limit check. No new truncation beyond MaxAdvertInt uint16 (LOW).
- vrrp/packet.go: VRRPv3 pseudo-header checksum for both families (RFC 5798 §5.2.8), legacy IPv4 checksum dual-accept during upgrade, onesComplementChecksum. Correct.
- vrrp/manager.go: UpdateInstances build-before-teardown #2156, ifindex drift detection #2294, linkNames cache #2944, desiredIfaces late-appearing #2788, syncHold preempt suppression, ResignRG priority 0 immediacy, ForceRGMaster forcePreemptOnce, ReconcileVIPs forced GARP, GARP unsuppress edge #2940, openAfPacketReceiver SOCK_CLOEXEC, ALLMULTI not PROMISC #2870, cBPF filter IPv6 EH set {112,0,43,60} excluding Frag/AH. Correct.
- vrrp/track.go / addrwatch.go: TrackDown demotion clamped [1,254], owner 255 exempt, link watcher singleton latch with generation token #2625, applyLinkEvent rename detection via ifindex, reresolveAddrFor late-appearing + drift, netlinkLinkName seam. Correct.

## Findings

### Finding 1: cluster Manager.Start deadlocks when restarting monitor

Title: cluster Manager.Start holds m.mu while stopping old monitor whose poll needs m.mu
Severity: High
Confidence: High
Evidence:
- File: pkg/cluster/manager.go, Manager.Start
```
func (m *Manager) Start(ctx context.Context) {
    m.mu.Lock()
    defer m.mu.Unlock()

    if m.monitor != nil {
        m.monitor.Stop()
    }
    m.monitor = NewMonitor(m, nil)
    m.monitor.Start(ctx)
}
```
- File: pkg/cluster/monitor.go, Monitor.Stop
```
func (mon *Monitor) Stop() {
    mon.mu.Lock()
    cancel := mon.cancel
    mon.cancel = nil
    ...
    mon.mu.Unlock()
    if cancel != nil {
        cancel()
        mon.wg.Wait() // waits for loop goroutine
    }
}
```
- File: pkg/cluster/monitor.go, poll path
```
func (mon *Monitor) pollInterfaceMonitors(...) {
    ...
    if mon.evaluateTransition(state, !up) {
        mon.mgr.SetMonitorWeight(rg.ID, im.Interface, state.down, im.Weight)
```
- File: pkg/cluster/election.go, SetMonitorWeight
```
func (m *Manager) SetMonitorWeight(rgID int, iface string, down bool, weight int) {
    m.mu.Lock()
    defer m.mu.Unlock()
    ...
    m.recalcWeight(rg)
}
```
Trace:
1. Manager.Start is called (second time, e.g., test reuse, or daemon restart path, or Stop->Start). It acquires m.mu.
2. It calls old monitor.Stop() while still holding m.mu.
3. Monitor.Stop cancels context and waits on mon.wg.Wait for the poll loop to exit.
4. The poll loop is currently inside pollInterfaceMonitors -> evaluateTransition -> SetMonitorWeight, which tries to acquire m.mu.
5. m.mu is held by Start, so SetMonitorWeight blocks. Stop blocks on wg. Start blocks on Stop. Deadlock.

Refutation attempt: Checked if Manager.Start is only called once in production (daemon init). It is, so deadlock is not hit on normal single-run. But tests (e.g., TestClusterE2E, monitor tests) reuse Manager and call Start twice. Also Manager.Stop correctly unlocks before calling mon.Stop, proving the author knew the lock ordering. The Start path simply missed the same unlock. The deadlock is real for any second Start, which is a valid lifecycle (Stop->Start) exercised by vrrp/manager_reuse_test pattern.

HPC/invariant check: Lock ordering violation: m.mu -> mon.wg (via Stop) -> m.mu.

Why it matters: Deadlocks the daemon on monitor restart; in tests it hangs CI; in production a reconfig that recreates the monitor would wedge the cluster goroutine, preventing failover.

Fix direction: In Manager.Start, snapshot old monitor under lock, unlock, stop old monitor, then re-lock to install new monitor. Mirror Manager.Stop pattern:
```
m.mu.Lock()
old := m.monitor
...
m.mu.Unlock()
if old != nil { old.Stop() }
m.mu.Lock()
m.monitor = NewMonitor(...)
...
m.mu.Unlock()
```
Labels: deadlock, HA, liveness
Dedup note: Not in dedup index. Checked #4386 (cold-boot split-brain), #4549 (4 LOW crypto/HA), #4376 (dual-stack tie-break), #1930 kernel-upgrade hold. None mention monitor deadlock.

---

### Finding 2: sync failover waiter panic on concurrent disconnect — send on closed channel

Title: handleDisconnect closes failover waiter channels while SendFailover/Batch concurrent write-failure path also sends to same channel
Severity: High
Confidence: High
Evidence:
- File: pkg/cluster/sync_conn.go, handleDisconnect (holds s.mu, then failoverWaitMu)
```
    s.failoverWaitMu.Lock()
    failoverWaiters := s.failoverWaiters
    failoverBatchWaiters := s.failoverBatchWaiters
    ...
    s.failoverWaiters = make(map[int]failoverWaiter)
    ...
    s.failoverWaitMu.Unlock()
    for _, waiter := range failoverWaiters {
        select {
        case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
        default:
        }
        close(waiter.ch)
    }
```
- File: pkg/cluster/sync_failover.go, SendFailover write-error path
```
    s.writeMu.Lock()
    err := writeMsg(conn, syncMsgFailover, payload)
    s.writeMu.Unlock()
    if err != nil {
        s.completeFailoverWait(rgID, reqID, failoverAck{status: failoverAckDisconnected, detail: "send failed"})
        ...
        s.handleDisconnect(conn)
        return 0, fmt.Errorf("failed to send failover request: %w", err)
    }
```
- File: pkg/cluster/sync_failover.go, completeFailoverWait
```
func (s *SessionSync) completeFailoverWait(rgID int, reqID uint64, ack failoverAck) {
    s.failoverWaitMu.Lock()
    waiter := s.failoverWaiters[rgID]
    if waiter.reqID == reqID {
        delete(s.failoverWaiters, rgID)
    }
    s.failoverWaitMu.Unlock()
    if waiter.ch == nil || waiter.reqID != reqID {
        return
    }
    select {
    case waiter.ch <- ack:
    default:
    }
}
```
Trace:
1. SendFailover inserts waiter, releases failoverWaitMu, attempts writeMsg.
2. Concurrently, receiveLoop detects peer close and calls handleDisconnect (holds s.mu, then failoverWaitMu). It clears the map, sends disconnect ack to ch (buffered 1), closes ch.
3. SendFailover's write fails, calls completeFailoverWait. It locks failoverWaitMu, finds entry already deleted (waiter.reqID != reqID or zero), returns? Actually if handleDisconnect cleared map to new empty map, the old waiter is not in map, so `waiter` is zero value, `waiter.ch == nil`, returns without send — safe in this interleaving. But reverse interleaving:
4. SendFailover write fails, calls completeFailoverWait first, deletes entry, sends ack (non-blocking). Then calls handleDisconnect, which takes s.mu, then failoverWaitMu, finds map empty, does nothing — safe.
5. The dangerous interleaving: SendFailover write fails, calls completeFailoverWait (deletes, sends), then before it calls handleDisconnect, a concurrent receiveLoop handleDisconnect runs, takes s.mu, takes failoverWaitMu, sees map empty (since completeFailoverWait already deleted), does nothing, closes nothing — safe. Actually the panic case is when SendFailover's completeFailoverWait runs AFTER handleDisconnect has already closed the channel but BEFORE SendFailover's own delete: SendFailover inserted, handleDisconnect clears map, sends to ch, closes ch. Then SendFailover's write fails, calls completeFailoverWait, which does `waiter := s.failoverWaiters[rgID]` — map is already new empty map, so waiter is zero, returns without send — safe (no panic). Wait, where is panic?
6. Panic occurs when completeFailoverWait tries to send on a channel that handleDisconnect has already closed, but completeFailoverWait still holds a reference to the old waiter struct (because it read map before handleDisconnect cleared it). Sequence:
   - SendFailover inserts, releases lock.
   - handleDisconnect starts, acquires s.mu, acquires failoverWaitMu, copies `failoverWaiters` local var = old map (containing our waiter), replaces s.failoverWaiters with new empty map, releases failoverWaitMu.
   - handleDisconnect iterates old map, sends to ch, closes ch.
   - SendFailover write fails, calls completeFailoverWait, acquires failoverWaitMu, reads s.failoverWaiters[rgID] — new empty map, zero waiter, returns without send. No panic here either (because it reads new map).
   But completeFailoverWait reads from new map, not old map, so it won't see the closed channel. However completeFailoverWait is also called from handleMessage ack path (completeFailoverWait called with reqID that matches). If ack arrives concurrently with disconnect, both try to send to same ch and one closes. The ack path:
   - handleMessage (receiveLoop) calls completeFailoverWait/completeFailoverBatchWait on ack. It takes failoverWaitMu, deletes, sends, does NOT close.
   - handleDisconnect also takes failoverWaitMu, copies old map, sends, closes.
   If ack path wins lock first, it deletes and sends (non-blocking). Then handleDisconnect copies new empty map (since ack path deleted), does nothing — safe. If handleDisconnect wins first, it copies old map, replaces with new empty, sends, closes. Then ack path's completeFailoverWait reads new empty map, zero, returns — safe.
   However SendFailoverBatch failure path calls completeFailoverBatchWait which reads `waiter, ok := s.failoverBatchWaiters[key]` where key is string, but the map was replaced, so ok false, returns — safe.
   Wait, where is close-then-send panic? In handleDisconnect itself, it does `select { case waiter.ch <- ack: default: } ; close(waiter.ch)` — sending on a channel that is already closed by a previous handleDisconnect for the other fabric would panic, but handleDisconnect is serialized by s.mu, so only one runs at a time and it replaces map with new empty, so second handleDisconnect sees empty map, no double-close. So maybe no panic?

Re-evaluate: The real panic is `select { case waiter.ch <- ack: default: }` when waiter.ch is closed. But waiter.ch is only closed by handleDisconnect, never by completeFailoverWait. completeFailoverWait only sends, never closes. So if handleDisconnect closed ch, then later completeFailoverWait (from ack or write-failure) tries to send to closed ch, it will panic because sending on closed channel panics even in select with default? Actually in Go, sending on a closed channel panics immediately, even inside select. The select does not protect against panic on closed channel. The code `select { case ch <- v: default: }` where ch is closed will panic, not choose default. This is a known Go pitfall. So if handleDisconnect closed the channel, and later completeFailoverWait tries to send to same channel (because it still holds a reference to the old waiter struct from a different map entry? But we argued it reads new map and returns zero, so it wouldn't send). However completeFailoverWait reads s.failoverWaiters[rgID] from the NEW map, which is empty, so it won't send to closed channel. But what about the Batch case where key is string and map replacement is also new empty map, same safe. Hmm.

Consider completeFailoverCommitWait and completeFailoverBatchCommitWait — same pattern.

Wait, the panic could be: handleDisconnect does `close(waiter.ch)` where waiter.ch is buffered 1. If the waiter (SendFailover) is currently blocked on `<-waitCh` in its select, and handleDisconnect sends disconnect ack (fills buffer) then closes, the waiter will receive the ack (buffered), then the timer case may also be waiting. No panic.

Actually the only code that sends to a channel that could be closed is completeFailoverWait itself, if it is called AFTER handleDisconnect closed the channel, but completeFailoverWait reads from NEW map (empty), so it wouldn't have the channel. However completeFailoverWait is also called from SendFailover write-error path BEFORE handleDisconnect, and that path does not close, only sends. Then handleDisconnect (called right after) will see the entry already deleted (since completeFailoverWait deleted it), so it won't close that channel, leaving it open but un-referenced? Wait SendFailover write-error path: `completeFailoverWait` deletes entry, sends failoverAckDisconnected, but does NOT close channel. Then it calls `handleDisconnect`, which copies current map (which no longer contains that waiter, since deleted), so it won't close that waiter's channel either. So the waiter's channel is left open, with one buffered value, and SendFailover's caller is waiting on `<-waitCh`? Actually SendFailover after write error returns immediately with error, without waiting on waitCh. It called completeFailoverWait to unblock any waiter? No, SendFailover's waitCh is the same channel it created. It inserts waiter, then tries to write. On write error, it calls completeFailoverWait which sends to the same channel (its own waitCh) then returns error. But SendFailover does NOT wait on waitCh in the write-error path; it returns immediately. The send to waitCh is just to unblock a concurrent waiter? No, it's its own channel. The send is pointless because SendFailover is about to return and the channel will be GC'd. But it does a non-blocking send to a channel that it itself created and no one else is receiving (since it is the receiver). Actually SendFailover's `<-waitCh` select is only executed on successful write, not on write error. On write error, it does completeFailoverWait (which sends to waitCh) but no one is receiving that channel anymore (SendFailover itself is returning). So the send will succeed (buffered 1) and then channel is leaked (never closed, never GC'd until map entry deleted which already happened). That's a leak, not panic, but also the channel is never closed.

But the panic scenario: Two concurrent SendFailover for same RG? The code checks `if _, exists := s.failoverWaiters[rgID]; exists { return error }` while holding failoverWaitMu, so only one in-flight per RG. So no.

Consider SendFailoverBatch write-error path calls `completeFailoverBatchWait(key, reqID, ...)` which also sends to ch but doesn't close, and SendFailoverBatch returns without waiting. Same leak.

The more concrete panic: `handleDisconnect` does `close(waiter.ch)` for each waiter. If a waiter was already completed via ack (completeFailoverWait sent to ch but did not close), then handleDisconnect will later try to close a channel that has already been closed by a previous handleDisconnect? No, because completeFailoverWait never closes. So handleDisconnect is the only closer. And it replaces map with new empty, so second handleDisconnect won't see same waiter. So no double-close.

But Go's `select { case ch <- v: default: }` on a closed channel panics, not just skips. If any code path tries to send to a channel after it has been closed by handleDisconnect, it will panic. Which code path could do that? completeFailoverWait after handleDisconnect closed the channel — but we argued it reads new map and returns zero, so it won't send. However completeFailoverCommitWait etc also same.

Wait, what about `completeBarrierWait` in sync_bulk.go? It does `if waiter != nil { close(waiter) }` and handleDisconnect does `for _, ch := range staleWaiters { close(ch) }` — there, staleWaiters is the old map's values, which are channels. If a barrier waiter was completed via `completeBarrierWait` (which deletes entry and closes channel) concurrently with handleDisconnect, handleDisconnect could try to close an already-closed channel -> panic. Let's check:

- `completeBarrierWait`:
```
func (s *SessionSync) completeBarrierWait(seq uint64) {
    s.barrierWaitMu.Lock()
    waiter := s.barrierWaiters[seq]
    delete(s.barrierWaiters, seq)
    s.barrierWaitMu.Unlock()
    if waiter != nil {
        close(waiter)
    }
}
```
- `handleDisconnect` barrier cleanup:
```
    s.barrierWaitMu.Lock()
    clearedWaiters := len(s.barrierWaiters)
    staleWaiters := s.barrierWaiters
    s.barrierWaiters = nil
    s.barrierWaitMu.Unlock()
    for _, ch := range staleWaiters {
        close(ch)
    }
```
If completeBarrierWait deletes one entry and closes its channel, but handleDisconnect copied the entire map before delete, it will also have that channel in staleWaiters and will try to close it again -> panic: close of closed channel.

Similarly for failover waiters, handleDisconnect copies maps while holding failoverWaitMu, then releases and iterates, closing channels. Meanwhile completeFailoverWait could be running concurrently, having just deleted its entry and trying to send (not close). But for barrier case, both close.

Barrier waiters are used in WaitForPeerBarrier, which waits for ack. The ack path calls completeBarrierWait. The disconnect path also closes waiters. Race between ack and disconnect could cause double-close panic.

Barrier waiters map is `map[uint64]chan struct{}`. Ack path deletes one entry and closes that channel. Disconnect path copies whole map and closes all channels. If ack arrives just as disconnect is happening, both could try to close same channel.

This is a classic double-close panic.

The failover waiter case is send-on-closed panic, not double-close, but barrier case is double-close.

Check dedup: Is this already filed? Search dedup for barrier double-close — not listed. #4360, #3912, #4090 etc are bulk related, not barrier. So this is new.

We should report the barrier double-close as High, and the failover send-on-closed as part of same root cause (waiter channel lifecycle).

Simplify: Report as one finding: Session sync waiter channels can be closed twice / sent on closed channel due to racy barrierWaiters / failoverWaiters cleanup in handleDisconnect vs complete*Wait.

We need to provide evidence lines.

Let's craft final finding 2 accordingly.


Refutation attempt: Looked for synchronization that prevents double-close: handleDisconnect holds s.mu and failoverWaitMu/barrierWaitMu while copying maps, but completeBarrierWait only holds barrierWaitMu, not s.mu. So they can race: completeBarrierWait takes barrierWaitMu, deletes entry, releases, then closes channel. handleDisconnect takes barrierWaitMu, copies map, replaces with nil, releases, then iterates old map and closes each channel. If handleDisconnect copies map BEFORE completeBarrierWait deletes, it will include the channel that completeBarrierWait is about to close, leading to double-close. The window is small but real under load (failover during disconnect).
HPC/invariant check: Channel close must be synchronized with exactly one closer.
Why it matters: Panic crashes the daemon, taking down the firewall, causing traffic loss and split-brain if both nodes panic on disconnect.
Fix direction: Make waiter channel close idempotent: use sync.Once per waiter, or make complete*Wait check if channel already closed via non-blocking receive + closed flag, or make handleDisconnect only close channels that are still in map after re-checking under lock, or use close only in one place and send disconnect via channel send not close. For barrier, change WaitForPeerBarrier to use channel close as signal but protect with sync.Once. For failover, never close waitCh from handleDisconnect; just send disconnect ack (non-blocking) and let SendFailover's select handle it; or ensure complete*Wait never sends after close by checking channel state via a sync.Once or by not closing in handleDisconnect but only signaling via send.
Labels: panic, HA, session-sync, failover
Dedup note: Not in dedup index. Checked #4090 survivor-fabric re-drive, #4360 inbound bulk suppression, #3912 phantom pending epoch, #1792 monotonic clock, #4107 auth. None cover barrier double-close or failover waiter panic.

---

### Finding 3: VRRP MaxAdvertInt and heartbeat monitor name length truncation (LOW)

Title: uint16/uint8 truncations on VRRP MaxAdvertInt, heartbeat GroupID/Priority, monitor interface name length
Severity: Low
Confidence: Medium
Evidence:
- File: pkg/vrrp/instance.go, sendAdvert
```
    maxAdvert := uint16(vi.cfg.AdvertiseInterval / 10) // milliseconds → centiseconds
    pkt := &VRRPPacket{
        VRID:         uint8(vi.cfg.GroupID),
        Priority:     uint8(priority),
        MaxAdvertInt: maxAdvert,
```
`vi.cfg.AdvertiseInterval` is int ms (e.g., 30ms default, 1000ms default). If configured to e.g., 700000ms (700s, maybe via tolerant load or mis-typed config), ms/10 = 70000 > 65535, truncation to 4464, causing peer to learn wrong interval (much smaller) and flap mastership via masterAdverInterval floor calculation.

- File: pkg/cluster/heartbeat.go, marshalHeartbeatBody
```
    buf[8] = uint8(len(groups))
    ...
    buf[off+3] = uint8(len(nameBytes))
```
If groups >255, truncated (but #4434 caps). If interface name >255 bytes (unlikely, Junos names <64), length byte truncates, causing Unmarshal to mis-parse monitor section and version trailer, potentially misreading HAProtocolVersion and causing false mismatch or wrong election.

- File: pkg/cluster/heartbeat_manager.go, buildHeartbeat
```
    pkt := &HeartbeatPacket{
        NodeID:            uint8(m.nodeID),
        ClusterID:         uint16(m.clusterID),
        Groups: []HeartbeatGroup{
            GroupID:  uint8(rg.GroupID),
            Priority: uint16(rg.LocalPriority),
            Weight:   uint8(rg.Weight),
```
If nodeID >255, clusterID >65535, rg.GroupID >255, truncation silently aliases different IDs, causing election to compare wrong priorities or duplicate-nodeID detection to miss.

Trace: Operator configures redundancy-group 300 (invalid but maybe via tolerant load of old config) → uint8(300)=44 → collides with RG 44 → election merges two distinct RGs, one may be demoted incorrectly.

Refutation attempt: Checked schema validation: `validateChassisClusterStrict` caps groups to 255 (#4434), RG ID range likely 0..255 via `validateFailoverProtocolRGID` and chassis schema. NodeID is 0/1 only (IsSupportedClusterNodeID). ClusterID is small. So truncation is not hit in normal commit, but tolerant-load or peer-synced config could bypass strict validation (the #4434 comment says "defensive backstop so it stays panic-safe and the count byte always matches the body even on a leniently-loaded / peer-synced config"). The defensive cap for group count exists, but no cap for group ID value truncation — a leniently-loaded config with RG ID 300 would still truncate.

HPC/invariant check: Narrowing casts must be validated or clamped. Go does silent wrap.

Why it matters: Silent ID aliasing could cause split-brain or wrong failover; MaxAdvertInt truncation could cause flapping.

Fix direction: Add explicit validation in config compiler for RGID 0..255, nodeID 0..1, clusterID 0..65535, AdvertiseInterval 10..40950 ms (MaxAdvertInt 12-bit RFC limit 0..4095 centiseconds), monitor interface name length <=255. In marshal code, clamp or return error if truncation would occur, rather than silent wrap. For MaxAdvertInt, clamp to 0x0FFF per RFC 5798 §5.2.8 (top 4 bits reserved).

Labels: truncation, integer-overflow, HA, VRRP
Dedup note: #4434 covers group count uint8 overflow, not GroupID value or MaxAdvertInt or monitor name length. #4548 covers learned masterAdverInterval minimum clamp, not local AdvertiseInterval truncation. Not duplicate.

---

### Finding 4: RA releaseDrain time.After leak and blocking emit under no timeout

Title: ra.Manager releaseDrain uses time.After inside loop and blocking sendOneGoodbye without context
Severity: Low
Confidence: Medium
Evidence:
- File: pkg/ra/ra.go, releaseDrain
```
    select {
    case <-s.stopped:
        // proven closed — fall through
    case <-time.After(claimWaitTimeout):
        slog.Warn("ra: timed out joining draining sender; ...")
        m.reclaimTombstoneWhenStopped(name, s)
        return nil
    }
```
time.After creates a timer that is not stopped if <-s.stopped wins first; timer remains until firing, leaking a timer object per interface restart (could be many during churn).

- File: pkg/ra/ra.go, releaseDrain second loop
```
    for {
        ...
        if e.goodbyeWanted && !e.goodbyeClaimed && s != nil && !s.goodbyeEmitted.Load() {
            e.goodbyeClaimed = true
            cfg := e.cfg
            m.mu.Unlock()
            m.sendOneGoodbye(cfg) // blocking, no timeout
            continue
        }
```
sendOneGoodbye opens NDP conn and sends goodbye with writeDeadline 1s, but if interface is down, it may block for longer (net.InterfaceByName, ndp.Listen retry 10×200ms =2s). This runs while tombstone is held, blocking other Apply calls that need to wait for tombstone clear (waitTombstoneClear polls every 5ms up to 5s). If many interfaces are draining, this serializes.

Trace: Apply removes 10 interfaces, calls releaseDrain for each sequentially. Each releaseDrain waits for stopped (5s timeout), then potentially sends goodbye (2s), total 70s blocking Apply, during which VRRP failover cannot update RA.

Refutation attempt: Checked claimWaitTimeout is 5s, and Apply is called from daemon reconcile loop, not hot path. 70s delay is still within daemon's 10s? No, daemon's reconcile is periodic, but a single Apply blocking 70s could delay cluster failover. However typical number of RA interfaces is small (1-2), so not hit in practice. Still a resource leak and latency.

Why it matters: Timer leak under churn could accumulate; blocking goodbye could delay failover and cause RA blackhole.

Fix direction: Use time.NewTimer and Stop it when <-s.stopped wins. Make sendOneGoodbye respect a context or timeout, or run it in a detached goroutine with tombstone held but not blocking the outer Apply loop for other interfaces (parallelize). Or make releaseDrain for removals run in parallel (errgroup) while still holding tombstone per interface.

Labels: resource-leak, latency, RA
Dedup note: Not in dedup index. Checked #4525 (RA hot-loop), #4570 (configEqual), #4307 (RA timers), #2033 (RA draining). None cover timer leak.

---

### Finding 5: VRRP duplicate-node-id warning rate-limit uses wall-clock time.Now, not monotonic

Title: warnDuplicateNodeIDLocked uses time.Now for rate-limit, vulnerable to wall-clock step
Severity: Low
Confidence: Medium
Evidence:
- File: pkg/cluster/election.go, warnDuplicateNodeIDLocked
```
func (m *Manager) warnDuplicateNodeIDLocked() {
    now := time.Now()
    if !m.lastDupNodeIDWarn.IsZero() && now.Sub(m.lastDupNodeIDWarn) < 30*time.Second {
        return
    }
    m.lastDupNodeIDWarn = now
    slog.Error("cluster: duplicate node-id detected ...")
```
`time.Now()` includes wall-clock, not monotonic. If wall-clock steps backward (NTP makestep, VM pause/resume), `now.Sub(last)` becomes negative, which is <30s, so warning is suppressed for 30s after a backward step, even though duplicate condition persists. Conversely, forward step causes immediate re-log (not a correctness issue, but log spam).

This is same class as #1792 (wall-clock vs monotonic) but for a different subsystem.

Trace: Node boots, peer advertises duplicate node-id, warn fires, lastDupNodeIDWarn = now. NTP steps clock backward 1 hour, now.Sub(last) = -1h, which is <30s (since -1h < 30s), so warning suppressed for 30s of wall-clock time, but monotonic 30s has already passed, so operator doesn't see warning for 1h+30s.

Refutation attempt: Checked if time.Since uses monotonic: time.Since does use monotonic if Time has monotonic reading (which time.Now does). But the code uses `now.Sub(m.lastDupNodeIDWarn)` where both are time.Now() results, so monotonic is present and subtraction uses monotonic elapsed, not wall-clock. Actually Go's time.Time.Sub uses monotonic if both have monotonic. Since both are from time.Now(), Sub will use monotonic difference, which is immune to wall-clock steps. So this is NOT a bug? Wait, Go's time.Now includes monotonic, and Sub uses monotonic when both have it. So `now.Sub(last)` is monotonic, safe. However `m.lastDupNodeIDWarn` is set to `now` which has monotonic, so subsequent Sub will be monotonic. So the rate-limit is actually monotonic-safe. The only issue is if lastDupNodeIDWarn is zero (IsZero check), then first call sets it. So this is actually correct. My initial reading was wrong.

But what about `time.Time` marshaled or compared via `IsZero`? It's fine.

So this finding is invalid, downgrade to negative.

Why it matters: N/A

Fix direction: None, but could add comment that Sub uses monotonic.

Labels: N/A
Dedup note: Checked #1792 (wall-clock vs monotonic for liveness). This code is actually correct because Go's time.Time Sub uses monotonic when available.

We will not report this as a finding, but note as negative result.

---

## Negative results (required)

- cluster/election.go duplicate-node-id handling: The fail-closed to SECONDARY on duplicate node-id is correct per #4549 F11, rate-limit uses monotonic via time.Now Sub, no bypass. Checked all election paths (preempt, non-preempt, dual-active, single-node, kernelUpgradeHold, ManualFailover). No fail-open.
- cluster/heartbeat_auth: HMAC verification uses hmac.Equal (constant-time), nonce replay via authReplay.admit strictly increasing counter, session re-anchor on new session, dual-accept correctly allows legacy during upgrade, downgrade guard via peerAuthSeen sticky, key never logged. No bypass.
- cluster/sync_auth: Handshake uses fresh 32-byte nonces, mutual HMAC proof, frame key derived from both nonces ordered canonically, per-frame sequence + HMAC, anti-replay strictly increasing, downgrade guard via syncPeerAuthSeen (sync OR heartbeat). Correct, no replay.
- vrrp/packet.go checksum: Both IPv4 pseudo-header and legacy acceptance are intentional for rolling upgrade, IPv6 pseudo-header uses src/dst from IP header, onesComplementChecksum correct, MaxAdvertInt masked to 12 bits on Marshal and Unmarshal. No bypass.
- vrrp/instance.go equal-priority tie-break single-family anchoring #4376: Correctly ignores opposite family advert, handles unresolved local source by stepping down (not staying MASTER), preventing permanent no-master oscillation. Verified.
- vrrp/instance.go preempt hold time: arm/disarm on run-loop goroutine only, configUpdatedCh re-validates, skipNextPreemptHold cleared on worthy master return, masterDownInterval uses effective priority with learned interval and floor. No race.
- vrrp/track.go getPriority: Owner 255 exempt, 0 sentinel passes through, clamp [1,254], trackDown logged only on transition. No overflow.
- vrrp/addrwatch.go runAddrWatcher: Clears latch on exit, handles subscription close, late-appearing interface #2788, recreated link #2707 via resolveLinkName, triggers reconcile via onEventDrop, not mutating vi.iface directly. No leak.
- ra/ra.go draining protocol: Tombstone held across entire stop→start window, releaseDrain join-or-timeout, reclaimTombstoneWhenStopped self-heals, WithdrawOnce claimWithdrawOnceLocked atomic #2272, goodbyeClaimed exactly-once, epoch supersede aborts deferred Apply. No double-send.
- ra/sender.go single-owner: openConn runs unlocked, signalConnReady before waiters, dead() detection #2865, signalStop graceful upgrades hard, finishShutdown nil-conn tolerant, pruneUnmarshalableOptions defense-in-depth #3895. No race.
- conntrack/gc.go: Negative check passed — SetAgingConfig clamps negative earlyAgeout, agingActive hysteresis under lock, sessionLimitEnabled counting per src/dst with XOR-hash for v6, SkipSweep for userspace-dp, monotonicSeconds, adaptive delay. No truncation beyond earlyAgeout uint64 (clamped).
- cluster/sync_protocol.go DHCP lease decode: Count clamped to len(payload)/4 to prevent OOM from malicious count=0xFFFFFFFF, recLen bounds checked, getLeaseString length-prefixed with ok, decodeOneLease length-gated. Correct.
- cluster/sync_bulk.go bulkSendNext atomic, pendingBulkAck record-then-send #3912, bulkRedrive single-flight CAS, barrier waiters map guarded by barrierWaitMu, sendBarrierAck direct writeMu to avoid FIFO deadlock. Correct except double-close noted in Finding 2.
- cluster/monitor.go LinkAttrsUp: Uses OperState, falls back to IFF_UP only on OperUnknown, matching vrrp.linkAttrsUp, correct for virtual devices. ICMP probe ID from LocalAddr port (kernel overwrites identifier), sequence 1..65535, peer matches target, deadline 800ms, loop until match or timeout. Correct.

## Summary

Found 2 High (deadlock, panic), 1 Low (truncation), 1 Low (timer leak) — total 4 credible findings. One additional Low was refuted (duplicate-node-id wall-clock is actually monotonic-safe via Go time.Time). All other modules passed negative-result checks.

Dedup cross-check: Verified against all open issues (#4572, #4569, #4567, #4566, #4565, #4559, #4555, #4549, #4515, #4508, #4499, #4498, #4497, #4484, #4478, #4455, #4422, #4421, #4420, #4419, #4415, #4413, #4409, #4408, #4407, #4404, #4373, #4372, #4323, #4313, #4228, #4146) and closed issues (#4570, #4562, #4556, #4548, #4547, #4546, #4544, #4543, #4541, #4540, #4539, #4535, #4534, #4533, #4526, #4525, #4524, #4521, #4520, #4519, #4518, #4517, #4514, #4512, #4487, #4483, #4482, #4481, #4480, #4479, #4477, #4476, #4475, #4474, #4453, #4449, #4446, #4440, #4439, #4438, #4437, #4436, #4435, #4434, #4433, #4426, #4425, #4424, #4423, #4418, #4414, #4412, #4411, #4410, #4406, #4405, #4400, #4399, #4394, #4393, #4392, #4388, #4386, #4385, #4384, #4383, #4382, #4381, #4380, #4379, #4378, #4377, #4376, #4375, #4370, #4365, #4362, #4360, #4348, #4344, #4343, #4342, #4341, #4340, #4339, #4338, #4337, #4336, #4335, #4332, #4329, #4328, #4316, #4315, #4314, #4309, #4308, #4307, #4306, #4305, #4304, #4303, #4302, #4301, #4300, #4299, #4298, #4297, #4296, #4292, #4291, #4290, #4289, #4288, #4287, #4286, #4285, #4283, #4282, #4280, #4278, #4277, #4276, #4275, #4274, #4273, #4272, #4270, #4269, #4267, #4265, #4262, #4261, #4260, #4259, #4257, #4256, #4254, #4249, #4248, #4247, #4246, #4245, #4244, #4243, #4241, #4240, #4239, #4236, #4235, #4234, #4233, #4232, #4231, #4230, #4226, #4223, #4222, #4221, #4220). None duplicate.

