package daemon

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Managed service-file reload debt (#6800).
//
// Two of the daemon's managed-file appliers converge an on-disk service
// configuration and then gate a RUNTIME reload on "did the file set actually
// change":
//
//   - applySyslogFiles     -> reconcileSyslogDropins  -> systemctl restart rsyslog
//   - applySystemNTP       -> reconcileManagedFile    -> chronyc reload sources /
//                                                        systemctl reload chrony
//
// The gate is correct for the steady state — it is what stops every commit from
// bouncing rsyslog — but before this change it also ERASED the debt created by a
// FAILED reload. The write half had already succeeded, so the files were
// converged; the reload half failed, was logged, and dropped. On the next apply
// the reconcile compared desired against the (already converged) on-disk set,
// reported `changed == false`, and skipped the reload. The running daemon kept
// serving the PREVIOUS ruleset — records still flowing to a removed syslog
// destination, or chrony still stepping to the old server set — for as long as
// the operator did not happen to make a FURTHER syslog/NTP edit. A reboot was
// the only reliable recovery, on a node that had reported a successful commit.
//
// The failure is not exotic: `systemctl restart rsyslog` fails whenever the unit
// is in a failed/masked state, whenever the transaction is refused because
// another job is queued on the unit, and whenever the 15s exec timeout expires
// on a loaded box. Each of those is transient — which is exactly why a retry
// owner recovers and a dropped error does not.
//
// The fix is the pattern this repo has settled on for "a failure has no retry
// owner" (proxyARPReassertLoop #4001, raDeadSenderReassertLoop #6793,
// fabricIPVLANReassertLoop #6791): a PERSISTENT debt recording the exact reload
// still owed, consulted by the next apply, plus an always-on re-assert loop
// started unconditionally in Run so recovery does not depend on an operator
// committing again.
//
// The debt retains the OWED REQUEST, not a re-derived one. That distinction is
// load-bearing for chrony, whose runtime reload has two INDEPENDENT legs: a
// sources reload (`chronyc reload sources`) and a threshold reload (`systemctl
// reload chrony`). If apply #1 fails the sources leg and apply #2 changes only
// the threshold file, re-deriving the request from apply #2's own change flags
// would run the threshold leg alone and silently drop the sources debt. Both
// call sites therefore fold the retained debt INTO the request they issue.

// serviceReloadDebt is the retained "a runtime reload is still owed" record for
// the xpf-managed service configuration files. The zero value is "nothing
// owed", so a Daemon built as a struct literal (which is how most of this
// package's tests build one) needs no initialisation.
type serviceReloadDebt struct {
	mu sync.Mutex
	// rsyslogRestart: the managed /etc/rsyslog.d/10-xpf-* drop-ins are on disk
	// but `systemctl restart rsyslog` has not succeeded since they were written.
	rsyslogRestart bool
	// chronySources: /etc/chrony/sources.d/xpf.sources is on disk but
	// `chronyc reload sources` has not succeeded since it was written.
	chronySources bool
	// chronyThreshold: /etc/chrony/conf.d/xpf-threshold.conf is on disk but no
	// chrony reload/restart has succeeded since it was written.
	chronyThreshold bool
}

// noteRsyslogRestartResult records the outcome of one `systemctl restart
// rsyslog`. A failure LATCHES the debt; a success DISCHARGES it. Both
// directions matter: without the latch the failure is forgotten (the #6800
// defect), and without the discharge the re-assert loop would bounce rsyslog
// every tick forever after a single failure.
func (d *Daemon) noteRsyslogRestartResult(err error) {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	d.svcReloadDebt.rsyslogRestart = err != nil
}

// rsyslogRestartOwed reports whether a rsyslog restart is still owed.
func (d *Daemon) rsyslogRestartOwed() bool {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return d.svcReloadDebt.rsyslogRestart
}

// chronyReloadOwed reports which chrony reload legs are still owed. The two
// legs are returned separately rather than as one boolean because they drive
// DIFFERENT runtime commands, and collapsing them would make the re-drive
// re-derive a request instead of replaying the owed one.
func (d *Daemon) chronyReloadOwed() (sources, threshold bool) {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return d.svcReloadDebt.chronySources, d.svcReloadDebt.chronyThreshold
}

// noteChronyReloadResult records the outcome of one chrony runtime reload.
//
// Plain assignment is correct — not an OR — because every caller folds the
// outstanding debt into the request it issues (see applySystemNTP and
// reassertServiceReloadDebtOnce), so a leg that was NOT attempted here had no
// debt to preserve, and a leg that WAS attempted is fully described by its
// outcome.
func (d *Daemon) noteChronyReloadResult(out chronyReloadOutcome) {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	d.svcReloadDebt.chronySources = out.sourcesFailed
	d.svcReloadDebt.chronyThreshold = out.thresholdFailed
}

// serviceReloadDebtOutstanding reports whether ANY managed-service reload is
// still owed. It is the re-assert loop's cheap gate: three bools under one
// mutex, so a healthy node pays nothing per tick.
func (d *Daemon) serviceReloadDebtOutstanding() bool {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return d.svcReloadDebt.rsyslogRestart ||
		d.svcReloadDebt.chronySources ||
		d.svcReloadDebt.chronyThreshold
}

// rsyslogRestartFn is the rsyslog runtime-restart entry point. Both owners —
// the apply path (applySyslogFiles) and the re-assert loop — go through this
// one seam, which is what makes the re-drive assertable without a real systemd.
// It still routes through runCommandTimeout, so a test that stubs the generic
// exec seam observes it too.
var rsyslogRestartFn = func() ([]byte, error) {
	return runCommandTimeout("systemctl", "restart", "rsyslog")
}

// chronyReloadFn is the chrony runtime-reload entry point, shared by the apply
// path and the re-assert loop for the same reason as rsyslogRestartFn.
var chronyReloadFn = reloadChronyRuntime

// serviceReloadDebtReassertInterval paces the managed-service reload retry
// owner. 30s matches proxyARPReassertLoop, raDeadSenderReassertLoop and
// fabricIPVLANReassertLoop — the other always-on self-heal loops. A tighter
// cadence would buy little: the gap this closes is measured in "until the
// operator next edits syslog or NTP", i.e. potentially forever, so turning that
// into tens of seconds is the whole win.
var serviceReloadDebtReassertInterval = 30 * time.Second

// serviceReloadDebtReassertLoop is the retry owner a failed managed-service
// reload did not have (#6800).
//
// Always-on and mode-agnostic, mirroring its sibling loops: it consults only
// the retained debt, so it is free on the overwhelmingly common path (a node
// whose reloads all succeeded owes nothing and the tick returns immediately),
// and it needs no config of its own — the owed request was captured when the
// apply issued it.
func (d *Daemon) serviceReloadDebtReassertLoop(ctx context.Context) {
	t := time.NewTicker(serviceReloadDebtReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertServiceReloadDebtOnce(ctx)
		}
	}
}

// reassertServiceReloadDebtOnce re-drives one round of owed managed-service
// reloads.
//
// It takes applySem BEFORE reading any state the apply path also writes, for
// the reason #4001 gave the proxy-ARP loop: a tick that runs concurrently with
// a commit reads a torn view. Here that is literal — reconcileSyslogDropins is
// mid-way through removing and rewriting /etc/rsyslog.d/10-xpf-*, so a restart
// issued from outside the semaphore can load a HALF-CONVERGED drop-in set and
// then latch a success for it. Blocking behind the in-flight commit means the
// restart always loads a fully converged file set.
//
// The per-service gates below are deliberately read INSIDE the semaphore, and
// they are the only gates that decide anything. The serviceReloadDebtOutstanding
// pre-check is an optimisation OUTSIDE the semaphore — it avoids queueing behind
// a commit for nothing — and its answer is stale by the time the tick is let
// through: a commit that landed in between may already have re-run the reload
// and discharged the debt, and restarting rsyslog again then would be a
// gratuitous bounce of a healthy logging pipeline. Each service therefore
// re-reads its OWN debt under the semaphore, which also keeps one service's
// outstanding reload from dragging the other's healthy one along.
func (d *Daemon) reassertServiceReloadDebtOnce(ctx context.Context) {
	if !d.serviceReloadDebtOutstanding() {
		return // cheap path: nothing owed
	}
	if d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown) — do not reload.
	}
	defer d.applySem.Release(1)

	if d.rsyslogRestartOwed() {
		slog.Warn("rsyslog restart still owed from an earlier apply — retrying " +
			"(the managed drop-ins are on disk but rsyslog has not re-read them)")
		out, err := rsyslogRestartFn()
		d.noteRsyslogRestartResult(err)
		if err != nil {
			slog.Error("rsyslog restart re-assert failed; will retry",
				"err", err, "output", strings.TrimSpace(string(out)))
		} else {
			slog.Info("rsyslog restart re-asserted")
		}
	}

	// Replay the exact owed legs. Re-deriving them from the current config
	// would be wrong twice over: it cannot tell which leg failed, and the file
	// it would diff against is already converged.
	if sources, threshold := d.chronyReloadOwed(); sources || threshold {
		slog.Warn("chrony reload still owed from an earlier apply — retrying",
			"sources", sources, "threshold", threshold)
		d.noteChronyReloadResult(chronyReloadFn(sources, threshold))
	}
}
