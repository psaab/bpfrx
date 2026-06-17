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

// drainIfKernelCandidateArmed keeps a CANDIDATE-TRIAL boot DRAINED until the
// promotion gate verifies the dataplane (r2 AGY Critical). ManualFailover is
// in-memory in the cluster Manager and is lost across the reboot, so a candidate
// node boots election-eligible and — under preempt — could claim primary BEFORE
// xpf-kernel-promote.service has run verify-dataplane + the forward beacon. If
// the candidate's shim is verifier-rejected, that would blackhole cluster
// traffic. So: at startup, if the kernel journal shows an ARMED candidate (this
// IS the trial boot), ForceSecondary so the node stays secondary until promote
// (on PASS the orchestrator's `rejoin` / the promote path restores it; on a
// REVERT the node reboots to known-good anyway). No-op on an ordinary boot.
func (d *Daemon) drainIfKernelCandidateArmed(ctx context.Context) {
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
	// Only hold-secondary if the peer can actually take over; otherwise forcing
	// secondary would strand traffic (no primary). If the peer is not ready we
	// leave election to run — the promote gate still reverts a bad candidate.
	if !d.cluster.PeerHealthyPrimary() {
		slog.Warn("kernel-candidate boot: peer not a healthy primary; "+
			"NOT holding secondary (promote gate still guards)", "candidate", j.CandidateVersion)
		return
	}
	if err := d.cluster.ForceSecondary(); err != nil {
		slog.Warn("kernel-candidate boot: could not hold secondary", "err", err)
		return
	}
	slog.Info("kernel-candidate boot: holding SECONDARY until promotion verifies the dataplane",
		"candidate", j.CandidateVersion)
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
	}, kernelSRCluster{m: d.cluster})

	go func() {
		// Initial settle so a normal boot→election→rejoin completes before the
		// first evaluation (the grace inside Tick adds further hysteresis).
		t := time.NewTimer(30 * time.Second)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
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
