package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Kernel-channel HA bounded local self-recovery (#1930 INC-2).
//
// The LANE-1 HA kernel roll is driven by an EXTERNAL orchestrator
// (scripts/deploy/xpf-deploy.py): it drains a node (ForceSecondary), reboots it
// into the candidate, and on success ResetFailover()s it back. The hazard
// (r2 AGY): if the orchestrator CRASHES while a node is drained+rebooting, the
// node comes back up still drained (all RGs ManualFailover=true, weight 0) with
// nothing to ResetFailover it — it sits passive forever, halving cluster
// capacity and leaving no automatic recovery.
//
// This is the bounded LOCAL self-recovery: at daemon startup (and periodically),
// a node that finds itself DRAINED, with NO active kernel-roll lease naming it,
// and a HEALTHY PRIMARY peer, auto-ResetFailover()s after a grace period. The
// lease is the coordination point: while a roll is legitimately in progress the
// orchestrator holds a lease naming the node, which SUPPRESSES self-recovery
// (so we never fight a real in-flight roll); once the orchestrator finishes (or
// crashes, letting the lease EXPIRE), self-recovery is free to act.
//
// Conservative by construction: it only ResetFailovers (rejoins as ELIGIBLE —
// VRRP preempt rules then decide who is primary); it never forces primary. If
// the peer is not a healthy primary, it does nothing (a real dual-down needs
// operator/orchestrator attention, not an automatic rejoin race).

// KernelRollLease is the coordination record the external orchestrator writes
// to each node it is actively rolling. Its presence + unexpired TTL SUPPRESSES
// that node's self-recovery. A crashed orchestrator's lease expires, re-enabling
// self-recovery.
type KernelRollLease struct {
	// NodeID is the cluster node-id the orchestrator is actively rolling.
	NodeID int `json:"node_id"`
	// Holder identifies the orchestrator (host/pid/run-id) for diagnostics.
	Holder string `json:"holder,omitempty"`
	// ExpiresAt is the lease TTL deadline; past it the lease is dead.
	ExpiresAt time.Time `json:"expires_at"`
}

// DefaultKernelRollLeasePath is where the orchestrator drops the per-node lease
// and where self-recovery reads it.
const DefaultKernelRollLeasePath = "/var/lib/xpf/kernel-roll.lease"

// SelfRecoveryCluster is the minimal cluster surface the self-recovery needs.
// The daemon supplies an adapter over its cluster.Manager.
type SelfRecoveryCluster interface {
	// LocalDrained reports whether THIS node is drained (all enabled RGs in
	// ManualFailover / weight 0 — the ForceSecondary state).
	LocalDrained() (bool, error)
	// PeerHealthyPrimary reports whether the peer is alive AND owns the RGs
	// (a real primary that can keep forwarding while we rejoin).
	PeerHealthyPrimary() (bool, error)
	// ResetFailover clears the local manual-failover on all RGs (rejoin as
	// eligible; VRRP preempt rules then govern primary).
	ResetFailover() error
}

// SelfRecoveryConfig configures a KernelSelfRecovery.
type SelfRecoveryConfig struct {
	// NodeID is THIS node's cluster node-id (matched against a lease's NodeID).
	NodeID int
	// LeasePath is the kernel-roll lease file (default DefaultKernelRollLeasePath).
	LeasePath string
	// Grace is how long the node must continuously observe the
	// drained-no-lease-healthy-peer condition before auto-ResetFailover. It
	// absorbs the normal boot→rejoin settle so a legitimately-mid-roll node
	// (whose lease is briefly missing during a write) is not prematurely reset.
	Grace time.Duration
	// Now is the clock (injectable for tests).
	Now func() time.Time
	// Logf is an optional progress sink.
	Logf func(format string, args ...any)
	// Armed reports whether a kernel candidate is STILL armed on this node
	// (journal state >= ARMED and not yet PROMOTED/REVERTED). When it returns
	// true a candidate trial is genuinely in flight — the promotion oneshot will
	// resolve it to PROMOTED or REVERTED — so self-recovery MUST NOT rejoin the
	// node even if the orchestrator's lease has expired (r2 AGY: a legitimately
	// long-hanging roll whose lease TTL elapsed would otherwise be torn back into
	// the election as an unverified candidate -> split-brain). Optional; if nil,
	// self-recovery does not gate on armed state (tests / non-kernel callers).
	Armed func() (bool, error)
}

func (c *SelfRecoveryConfig) withDefaults() {
	if c.LeasePath == "" {
		c.LeasePath = DefaultKernelRollLeasePath
	}
	if c.Grace == 0 {
		c.Grace = 90 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// KernelSelfRecovery is the bounded local self-recovery state machine.
type KernelSelfRecovery struct {
	cfg SelfRecoveryConfig
	cl  SelfRecoveryCluster
	// drainedSince is when this node first observed the recoverable condition
	// (drained + no active lease for us + healthy peer); zero when not observed.
	drainedSince time.Time
}

// NewKernelSelfRecovery builds the self-recovery helper.
func NewKernelSelfRecovery(cfg SelfRecoveryConfig, cl SelfRecoveryCluster) *KernelSelfRecovery {
	cfg.withDefaults()
	return &KernelSelfRecovery{cfg: cfg, cl: cl}
}

// leaseState classifies the kernel-roll lease w.r.t. THIS node.
type leaseState int

const (
	leaseNone        leaseState = iota // no (readable) lease present
	leaseActiveOurs                    // unexpired lease naming this node
	leaseExpiredOurs                   // expired lease naming this node
	leaseOther                         // lease names the OTHER node
)

// readLeaseState classifies the on-disk lease. The DISTINCTION drives the fix
// for AGY's "self-recovery fires during manual maintenance / #1917" (r2):
// self-recovery acts ONLY on leaseExpiredOurs — the unambiguous fingerprint of
// a CRASHED kernel-roll orchestrator (it wrote a lease naming us, then died
// without clearing it). leaseNone is NOT a self-recovery trigger: a manually
// drained node or a #1917 binary-rolling drain never wrote a kernel-roll lease,
// so we leave it alone.
func (s *KernelSelfRecovery) readLeaseState() leaseState {
	data, err := os.ReadFile(s.cfg.LeasePath)
	if err != nil {
		// A genuinely absent lease is the common case (no roll in progress) — not
		// worth logging. A non-NotExist error (permission/I/O) IS actionable: log
		// it. Either way return leaseNone, which is a NO-OP in Tick (it acts only
		// on leaseExpiredOurs), so a transient read error can only DELAY recovery
		// (the safe direction), never trigger an unintended ResetFailover.
		if !os.IsNotExist(err) {
			s.cfg.Logf("kernel self-recovery: lease %s unreadable (%v); treating as no-lease "+
				"this tick (will retry)", s.cfg.LeasePath, err)
		}
		return leaseNone
	}
	var l KernelRollLease
	if err := json.Unmarshal(data, &l); err != nil {
		// A transient partial read during the orchestrator's atomic write — treat
		// as "no decision this tick" (none); the grace timer + next tick re-read
		// absorb it (r2 AGY non-atomic-write transient).
		s.cfg.Logf("kernel self-recovery: ignoring unparsable lease %s: %v", s.cfg.LeasePath, err)
		return leaseNone
	}
	if l.NodeID != s.cfg.NodeID {
		return leaseOther
	}
	if s.cfg.Now().Before(l.ExpiresAt) {
		return leaseActiveOurs
	}
	s.cfg.Logf("kernel self-recovery: EXPIRED lease for node %d (orchestrator crashed mid-roll?)", l.NodeID)
	return leaseExpiredOurs
}

// Tick evaluates the recovery condition once. Call it at startup and on a timer.
// It auto-ResetFailovers only after the condition holds continuously for Grace.
// Returns true iff it performed a ResetFailover this tick.
func (s *KernelSelfRecovery) Tick() (bool, error) {
	// Self-recovery fires ONLY on an EXPIRED lease naming this node — the
	// unambiguous fingerprint of a CRASHED kernel-roll orchestrator (r2 AGY):
	//   - leaseActiveOurs: a roll is legitimately in progress — never recover.
	//   - leaseOther / leaseNone: NOT our kernel roll — a manually drained node
	//     or a #1917 binary-rolling drain never wrote a lease naming us, so we
	//     must NOT auto-rejoin (that would break the operator's / #1917's
	//     maintenance window — the cross-feature interaction AGY flagged).
	//   - leaseExpiredOurs: the orchestrator wrote our lease then died without
	//     clearing it — THIS is the case self-recovery exists for.
	st := s.readLeaseState()
	if st != leaseExpiredOurs {
		s.drainedSince = time.Time{}
		return false, nil
	}

	// A still-ARMED journal means a candidate trial is genuinely in flight (the
	// promotion oneshot will drive it to PROMOTED or REVERTED), regardless of how
	// long it has taken — an expired orchestrator lease does NOT make it safe to
	// rejoin (r2 AGY long-hanging-roll TTL split-brain). Refuse self-recovery
	// while armed; the bounded promote/revert path owns the resolution. The
	// election hold (kernelUpgradeHold) keeps the node SECONDARY meanwhile.
	if s.cfg.Armed != nil {
		armed, err := s.cfg.Armed()
		if err != nil {
			return false, fmt.Errorf("kernel self-recovery: armed check: %w", err)
		}
		if armed {
			s.drainedSince = time.Time{}
			s.cfg.Logf("kernel self-recovery: lease expired but a candidate is STILL ARMED; " +
				"a trial is in flight (promote/revert owns it) -> NOT recovering")
			return false, nil
		}
	}

	drained, err := s.cl.LocalDrained()
	if err != nil {
		return false, fmt.Errorf("kernel self-recovery: local drained check: %w", err)
	}
	if !drained {
		s.drainedSince = time.Time{} // not drained -> reset the timer
		return false, nil
	}

	peerOK, err := s.cl.PeerHealthyPrimary()
	if err != nil {
		return false, fmt.Errorf("kernel self-recovery: peer health check: %w", err)
	}
	if !peerOK {
		// Drained but the peer is NOT a healthy primary — a real dual-down /
		// split scenario. Do NOT auto-rejoin (that could race a recovering
		// peer); leave it for the orchestrator/operator.
		s.drainedSince = time.Time{}
		s.cfg.Logf("kernel self-recovery: drained but peer is not a healthy primary; " +
			"NOT auto-recovering (needs orchestrator/operator)")
		return false, nil
	}

	now := s.cfg.Now()
	if s.drainedSince.IsZero() {
		s.drainedSince = now
		s.cfg.Logf("kernel self-recovery: observed drained+no-lease+healthy-peer; "+
			"will auto-ResetFailover in %s if it persists", s.cfg.Grace)
		return false, nil
	}
	if now.Sub(s.drainedSince) < s.cfg.Grace {
		return false, nil // still within grace
	}

	// Condition held for Grace -> the orchestrator is gone and left us drained.
	s.cfg.Logf("kernel self-recovery: drained+orphaned for %s with a healthy peer; " +
		"auto-ResetFailover (rejoin as eligible)")
	if err := s.cl.ResetFailover(); err != nil {
		return false, fmt.Errorf("kernel self-recovery: ResetFailover: %w", err)
	}
	s.drainedSince = time.Time{}
	return true, nil
}
