package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// applyCloseoutDrainTimeout bounds how long runShutdownSequence waits for an
// in-flight, just-cancelled apply to finish its bounded nft/login host-
// authorization closeout (#5643 / M35) before proceeding to teardown. It must be
// comfortably under the systemd unit's TimeoutStopSec (20s) so a wedged apply
// can never stall the whole stop past the drain budget.
const applyCloseoutDrainTimeout = 5 * time.Second

// runShutdownSequence performs the ordered post-run teardown: abort in-flight
// apply, stop the signal context, wait background goroutines, then tear down
// SNMP/flowexport/feeds/RPM/archive/event-engine/ipmon/natpool-alarm/FRR/LLDP,
// clear HA rg_active (non-hitless), withdraw RA, stop VRRP/cluster/session-sync,
// close/teardown the dataplane, and restore step0 tunables. The ordering is
// load-bearing (see the per-step comments). Extracted verbatim from Run() so
// the 1690-LOC lifecycle stays reviewable (#4662 Increment 1). Returns runErr
// unchanged.
func (d *Daemon) runShutdownSequence(wg *sync.WaitGroup, stop func(), runErr error) error {
	// #2926: explicitly abort any in-flight commit/remediation apply NOW, at the
	// very start of the shutdown sequence and BEFORE the explicit subsystem
	// teardown below (FRR Stop, HA rg_active clear, dp.Teardown). applyCancelCtx
	// callers (commit/sync/confirmed-commit) then bail at their next coarse
	// boundary instead of completing netlink + an FRR reload + a Rust sync while
	// we tear down. applyCancelContext is a child of the signal context, so a
	// signal-driven stop has already cancelled it; this call also covers the
	// interactive CLI-exit path and is idempotent. The teardown itself performs
	// no applyConfigLocked, so nothing legitimate is aborted here.
	if d.applyCancel != nil {
		d.applyCancel()

		// #5643 (M35): the cancel above makes an in-flight promoted apply bail at
		// its next #2926 boundary, where applyConfigLocked now runs the bounded
		// nft/login host-authorization closeout so the committed (restrictive)
		// config is still enforced even though the apply is abandoned. Drain
		// applySem so that closeout COMPLETES before we tear down / exit —
		// otherwise the process could stop with the OLD, more-permissive host
		// authorization still live in the kernel nft tables / on-disk credentials.
		// applySem is a weight-1 mutex: acquiring it waits for the in-flight apply
		// (now including its closeout) to release. The closeout is bounded (two
		// atomic nft loads + local credential reconciles, no FRR/netlink reload),
		// so this cannot hang on unbounded work; bound it defensively anyway so a
		// wedged apply cannot block the whole shutdown past the drain budget.
		if d.applySem != nil {
			drainCtx, cancelDrain := context.WithTimeout(context.Background(), applyCloseoutDrainTimeout)
			if err := d.applySem.Acquire(drainCtx, 1); err == nil {
				d.applySem.Release(1)
			} else {
				slog.Warn("shutdown: timed out draining in-flight apply before teardown; "+
					"host-authorization closeout may be incomplete", "err", err)
			}
			cancelDrain()
		}
	}

	// Cancel context to stop background goroutines, then wait for them.
	stop()
	wg.Wait()

	// #5308: cancel + join the two long-lived loops that bind to d.daemonCtx
	// (never cancelled in production) rather than the run WaitGroup above, so
	// wg.Wait does NOT cover them. Both call into subsystems torn down further
	// below and therefore MUST be stopped first: the policy scheduler
	// republishes schedule state through the dataplane runtime
	// (UpdatePolicyScheduleState — closed by dp.Close/dp.Teardown), and the RPM
	// probe-pin retry loop runs routing-pin syscalls through the routing/FRR
	// manager (stopped by frr.Stop / routing teardown). Cancelling + joining
	// here guarantees no late scheduler tick runs against a closed runtime and
	// no late pin-retry tick runs a syscall after routing is gone. Both helpers
	// are idempotent / nil-safe (a never-started loop joins cleanly), so this is
	// also the safety-net for the Run()-returns path via the defers in Run.
	d.stopPolicySchedulerLoop()
	d.stopPinRetryLoop()

	// #5523 C179-093: cancel + join the two remaining background loops that do
	// NOT bind to the run WaitGroup and were previously leaked at shutdown:
	//   - the session-aggregation flush goroutine (binds to context.Background,
	//     cancelled only via aggCancel) — cancelling here triggers its #5313
	//     ctx.Done final flush so the pending window is emitted rather than
	//     dropped, and joins it. Done BEFORE the flow/feeds/event teardown below
	//     so the flush still has a live SetLogFunc -> er.ForwardLogMsg path.
	//   - the IPsec DHCP-rebind retry loop (bound to d.daemonCtx, never
	//     cancelled in production) — stopping it before FRR/IPsec teardown keeps
	//     a late 30s rebind tick from racing a swanctl reapply against a
	//     torn-down subsystem. Both helpers are idempotent / nil-safe.
	d.stopAggregator()
	d.stopIPsecRebindLoop()

	// Stop the SNMP agent + link-state trap monitor (#3967). Their goroutines
	// bind to d.daemonCtx (never cancelled in production) rather than the run
	// WaitGroup, so wg.Wait above does not cover them — teardownSNMP cancels
	// the agent's lifetime context, joins the goroutines, and releases UDP/161.
	d.teardownSNMP()

	// Clean up flow exporters.
	d.stopFlowExporter()
	d.stopIPFIXExporter()

	// Clean up dynamic address feeds.
	if d.feeds != nil {
		d.feeds.StopAll()
	}

	// Clean up RPM probes.
	if d.rpm != nil {
		d.rpm.StopAll()
	}

	// Stop the periodic configuration-archival timer (#4078). Its goroutine
	// binds to a per-generation stop channel (not the run WaitGroup), so this
	// explicit stop is the authoritative shutdown for the boot-armed timer,
	// whose captured daemon-stop context may predate applyCancelContext.
	d.stopArchiveTimer()

	// Stop the event-options action worker (after RPM so no events arrive
	// during teardown). Close drains in-flight lock-retry backoffs (#2157).
	if d.eventEngine != nil {
		d.eventEngine.Close()
	}

	// Stop the ip-monitoring engine (after RPM so no transitions
	// arrive during teardown).
	if d.ipmon != nil {
		d.ipmon.Stop()
	}

	// #2079/#2114: stop the NAT pool-utilization-alarm monitor. Routed
	// through the helper so the atomic pointer is read/cleared the same way
	// as the runtime start/discard paths.
	d.stopAndDiscardNATPoolAlarm()

	// Stop the FRR manager (after ipmon, whose actuator is an FRR
	// writer): cancels the degraded-retry goroutine and kills any
	// in-flight frr-reload.py process group (#1880).
	if d.frr != nil {
		d.frr.Stop()
	}

	// Clean up LLDP.
	if d.lldpMgr != nil {
		d.lldpMgr.Stop()
	}

	// Determine shutdown mode early so we can clear rg_active BEFORE
	// stopping subsystems (VRRP, sync) that may hang.
	cfg := d.store.ActiveConfig()
	haMode := cfg != nil && cfg.Chassis.Cluster != nil
	hitless := !haMode // standalone = hitless by default
	if haMode && cfg.Chassis.Cluster.HitlessRestart {
		hitless = true // operator explicitly opted in
	}

	// In HA fail-closed mode, clear rg_active and watchdog immediately so
	// BPF stops forwarding traffic even if subsequent cleanup steps hang.
	// #2114: one snapshot for the whole HA-clear block (plan §5.3 rule 5).
	if rt := d.dataplane(); !hitless && rt != nil && cfg.Chassis.Cluster != nil {
		slog.Info("HA shutdown: clearing rg_active for all RGs")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			err := runHAShutdownUpdate(shutdownCtx, func(ctx context.Context) error {
				return rt.HA().SetRGActive(ctx, rg.ID, false)
			})
			if err != nil {
				slog.Warn("failed to clear rg_active on shutdown", "rg", rg.ID, "err", err)
			}
			err = runHAShutdownUpdate(shutdownCtx, func(ctx context.Context) error {
				return rt.HA().SetHAWatchdog(ctx, rg.ID, 0)
			})
			if err != nil {
				slog.Warn("failed to clear ha_watchdog on shutdown", "rg", rg.ID, "err", err)
			}
		}
	}

	// Withdraw RA senders (sends goodbye RAs with lifetime=0) before VRRP
	// stop so hosts immediately stop using this node as a default router.
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			slog.Warn("shutdown: failed to withdraw RA senders", "err", err)
		}
	}

	// Direct-mode: remove VIPs before VRRP stop (VRRP won't manage them).
	if d.isNoRethVRRP() && cfg.Chassis.Cluster != nil {
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			d.directRemoveVIPs(rg.ID)
		}
	}

	// Stop VRRP manager (removes VIPs, sends priority-0).
	if d.vrrpMgr != nil {
		d.vrrpMgr.Stop()
	}

	// Stop cluster monitor (heartbeats) immediately after VRRP priority-0.
	// This ensures the peer's heartbeat timeout starts promptly instead of
	// being delayed by the 5s sync Stop timeout below.
	if d.cluster != nil {
		d.cluster.Stop()
	}

	// Stop session sync (5s timeout to avoid blocking teardown).
	if ss := d.getSessionSync(); ss != nil {
		d.stopSyncReadyTimer()
		ss.Stop()
	}

	// #2114: a SECOND snapshot for final-stats + Close/Teardown (plan §5.3
	// rule 5), matching the pre-cell two separate reads.
	if rt := d.dataplane(); rt != nil {
		// logFinalStats now reads through the runtime Telemetry
		// domain (#1519); the dataplaneReadyProbe gate keeps the
		// "no-op when dp not loaded" contract intact for both
		// backends.
		if ready, ok := rt.(dataplaneReadyProbe); ok {
			logFinalStats(ready, rt.Telemetry())
		}
		if hitless {
			// Hitless: close Go handles only — BPF programs keep running.
			slog.Info("hitless shutdown: preserving BPF state")
			rt.Close()
		} else {
			// Fail-closed: tear down all pinned BPF state.
			slog.Info("HA shutdown: tearing down BPF state")
			rt.Teardown()
		}
	}

	// #801 B2: restore any host-scope tunables xpfd claimed to their
	// pre-xpfd values. No-op if `claim-host-tunables` was never set.
	// Runs on every shutdown (hitless + fail-closed) so stopping xpfd
	// leaves the host as xpfd found it.
	d.restoreStep0TunablesOnShutdown()

	slog.Info("shutdown complete")
	return runErr
}

func runHAShutdownUpdate(ctx context.Context, update func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- update(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
