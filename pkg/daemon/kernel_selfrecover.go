package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/upgrade"
)

// kernelSRCluster adapts *cluster.Manager to upgrade.SelfRecoveryCluster for the
// #1930 INC-2 kernel-channel bounded local self-recovery.
type kernelSRCluster struct{ m *cluster.Manager }

func (a kernelSRCluster) LocalDrained() (bool, error)       { return a.m.LocalDrained(), nil }
func (a kernelSRCluster) PeerHealthyPrimary() (bool, error) { return a.m.PeerHealthyPrimary(), nil }
func (a kernelSRCluster) ResetFailover() error              { return a.m.ResetAllFailover() }

// holdSecondaryIfKernelCandidateArmed keeps a CANDIDATE-TRIAL boot SECONDARY
// until the promotion gate verifies the dataplane (r2 AGY Critical). The drain
// the orchestrator set is in-memory ManualFailover, lost across the reboot, so a
// candidate node boots election-eligible and — under preempt, OR via the
// isolated-node auto-promote path if it can't see the peer — could claim primary
// BEFORE xpf-kernel-promote.service runs verify-dataplane + the forward beacon.
// A verifier-rejected candidate claiming primary would blackhole cluster traffic.
//
// FIX (r2 AGY: the prior ForceSecondary-at-startup was a no-op because peerAlive
// is still false before heartbeats start): set the UNCONDITIONAL
// kernelUpgradeHold flag — which election honors regardless of peer state and
// does NOT auto-clear for an isolated node — and do it BEFORE cluster.Start so
// there is no election window. The hold is cleared by promote (verified) /
// rejoin / revert. No-op on an ordinary boot.
func (d *Daemon) holdSecondaryIfKernelCandidateArmed() {
	if d.cluster == nil {
		return
	}
	r, err := upgrade.NewKernelRunner(upgrade.KernelConfig{Sys: upgrade.NewKernelSystem()})
	if err != nil {
		return
	}
	armed, j, err := r.IsArmed()
	if err != nil || !armed {
		return
	}
	d.cluster.SetKernelUpgradeHold()
	slog.Info("kernel-candidate boot: holding SECONDARY (election hold) until promotion "+
		"verifies the dataplane", "candidate", j.CandidateVersion)
}

// reconcileKernelUpgradeHold releases the election hold once the candidate trial
// has RESOLVED. The promotion gate runs in a SEPARATE process
// (xpf-kernel-promote.service, After=xpfd) and clears only the on-disk journal,
// so the running daemon — which set the in-memory hold at boot — must notice
// "held but no longer armed" and release it; otherwise a SUCCESSFULLY promoted
// candidate would stay SECONDARY forever (a leaked hold). It is a no-op unless
// the hold is set, and clears it only once the journal is no longer ARMED
// (promote -> PROMOTED, or revert -> REVERTED/reboot). While still armed the
// hold persists (the trial is in flight and the hold is doing its job).
func (d *Daemon) reconcileKernelUpgradeHold() {
	if d.cluster == nil || !d.cluster.KernelUpgradeHeld() {
		return
	}
	r, err := upgrade.NewKernelRunner(upgrade.KernelConfig{Sys: upgrade.NewKernelSystem()})
	if err != nil {
		return
	}
	armed, _, err := r.IsArmed()
	if err != nil || armed {
		return // still a trial in flight (or can't tell) — keep holding
	}
	d.cluster.ClearKernelUpgradeHold()
	slog.Info("kernel-candidate trial resolved (no longer armed); releasing the " +
		"SECONDARY election hold so the node can take its normal role")
}

// startKernelSelfRecovery runs the bounded local self-recovery loop for the
// LANE-1 HA kernel channel (#1930 INC-2). If the external orchestrator crashes
// while this node is drained+rebooting for a kernel roll, the node would come
// back up drained with nothing to ResetFailover it. This loop notices that
// orphaned-drained state (no active roll lease naming us + a healthy primary
// peer) and auto-rejoins after a grace period. It is a no-op on a node that is
// not drained — i.e. virtually always.
//
// The loop is HA-only (started only when a cluster manager exists) and ticks
// slowly (it is a safety net, not a hot path).
func (d *Daemon) startKernelSelfRecovery(ctx context.Context) {
	if d.cluster == nil {
		return
	}
	sr := upgrade.NewKernelSelfRecovery(upgrade.SelfRecoveryConfig{
		NodeID: d.cluster.NodeID(),
		Logf:   func(f string, a ...any) { slog.Info("kernel-self-recovery", "msg", fmt.Sprintf(f, a...)) },
		// Refuse self-recovery while a candidate trial is still ARMED — even if
		// the orchestrator lease expired (r2 AGY long-hanging-roll TTL split-brain).
		Armed: func() (bool, error) {
			r, err := upgrade.NewKernelRunner(upgrade.KernelConfig{Sys: upgrade.NewKernelSystem()})
			if err != nil {
				return false, err
			}
			armed, _, err := r.IsArmed()
			return armed, err
		},
	}, kernelSRCluster{m: d.cluster})

	go func() {
		// Reconcile the in-memory election hold against the journal on a SHORT
		// cadence from the start: the promotion gate (a separate process) can
		// resolve within ~120s of boot, and we want the verified candidate to
		// drop its hold and resume its role promptly (fast failback), not wait
		// out the self-recovery settle. Cheap (a journal read; an election only
		// on the resolving tick).
		holdTick := time.NewTicker(5 * time.Second)
		defer holdTick.Stop()

		// Initial settle so a normal boot→election→rejoin completes before the
		// first self-recovery evaluation (the grace inside Tick adds further
		// hysteresis). The hold reconcile runs throughout this window.
		settle := time.NewTimer(30 * time.Second)
		defer settle.Stop()
		settled := false

		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-holdTick.C:
				d.reconcileKernelUpgradeHold()
			case <-settle.C:
				settled = true
			case <-tick.C:
				if !settled {
					continue // not past the initial settle yet
				}
				if did, err := sr.Tick(); err != nil {
					slog.Debug("kernel-self-recovery tick error", "err", err)
				} else if did {
					slog.Warn("kernel-self-recovery: auto-rejoined an orphaned-drained node " +
						"(external kernel-roll orchestrator appears to have crashed mid-roll)")
				}
			}
		}
	}()
}
