package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// ipsecRebindRetryInterval is the cadence of the autonomous retry of a
// failed DHCP-lease-change IPsec rebind (#4899). Control-plane cost only (a
// swanctl re-render + --load-all), and the loop runs ONLY while a rebind is
// pending, so a healthy box never pays for it. It mirrors the slow periodic
// probe-pin retry (#1895, probePinRetryInterval).
const ipsecRebindRetryInterval = 30 * time.Second

// ipsecApplyForLeaseChange performs the swanctl re-render + reload for the
// DHCP-lease-change rebind path. Production re-renders local_addrs from the
// interface's CURRENT kernel address (resolved inside PrepareConfig at apply
// time), so re-applying the same config picks up the new lease. Tests inject a
// seam so the retry lifecycle can be driven without shelling out to swanctl.
func (d *Daemon) ipsecApplyForLeaseChange(cfg *config.Config) error {
	if d.ipsecApply != nil {
		return d.ipsecApply(cfg)
	}
	return d.ipsec.Apply(ipsec.PrepareConfig(cfg))
}

// activeConfigForRebind returns the config the retry loop re-renders against —
// the LIVE active config in production, not the config captured when the
// failure occurred. Reading the live config means a commit that removes the
// VPN (or the DHCP binding) converges the loop instead of resurrecting deleted
// config. Tests override the source so the loop has a config without seeding
// the configstore.
func (d *Daemon) activeConfigForRebind() *config.Config {
	if d.ipsecRebindActiveCfg != nil {
		return d.ipsecRebindActiveCfg()
	}
	if d.store == nil {
		return nil
	}
	return d.store.ActiveConfig()
}

// IPsecRebindPending reports whether the last DHCP-lease-change IPsec rebind
// failed and has not yet reconverged — swanctl local_addrs are bound to a
// stale lease address while set. Backs the xpf_ipsec_rebind_pending gauge
// (0/1, no labels). Read lock-free by the metrics collector (#4899).
func (d *Daemon) IPsecRebindPending() bool {
	return d.ipsecRebindPending.Load()
}

// armIPsecRebind marks a lease-change rebind as pending (raising the health
// signal) and ensures the single-flight retry loop is running. Safe to call
// from the lease callback and from the retry loop itself; a live loop is not
// duplicated. Callers hold applySem, so the pending flag always reflects the
// last completed apply attempt.
func (d *Daemon) armIPsecRebind() {
	d.ipsecRebindMu.Lock()
	defer d.ipsecRebindMu.Unlock()
	d.ipsecRebindPending.Store(true)
	if d.daemonCtx == nil || d.ipsecRebindRetryActive {
		return
	}
	d.ipsecRebindRetryActive = true
	go d.ipsecRebindRetryLoop(d.daemonCtx)
}

// clearIPsecRebindPending drops the health signal after a successful reapply,
// logging the recovery exactly once (only when a rebind was actually pending —
// the common healthy path is silent).
func (d *Daemon) clearIPsecRebindPending() {
	d.ipsecRebindMu.Lock()
	recovered := d.ipsecRebindPending.Load()
	d.ipsecRebindPending.Store(false)
	d.ipsecRebindMu.Unlock()
	if recovered {
		slog.Info("IPsec rebind after DHCP address change recovered; swanctl local_addrs reconverged")
	}
}

// disarmIPsecRebindIfConverged clears the retry-active flag (stopping the
// loop) ONLY if no rebind is pending, re-checking pending under ipsecRebindMu
// so a failure that re-armed pending between the loop's apply and this check
// keeps the loop alive. Returns true when the loop was disarmed and should
// exit.
func (d *Daemon) disarmIPsecRebindIfConverged() bool {
	d.ipsecRebindMu.Lock()
	defer d.ipsecRebindMu.Unlock()
	if d.ipsecRebindPending.Load() {
		return false
	}
	d.ipsecRebindRetryActive = false
	return true
}

// disarmIPsecRebindOnShutdown unconditionally clears the retry-active flag when
// the daemon context is cancelled. The pending flag is left as-is; the boot
// apply re-renders IPsec on the next start.
func (d *Daemon) disarmIPsecRebindOnShutdown() {
	d.ipsecRebindMu.Lock()
	d.ipsecRebindRetryActive = false
	d.ipsecRebindMu.Unlock()
}

// ipsecRebindRetryLoop is the slow autonomous retry of a failed
// DHCP-lease-change IPsec rebind (#4899). It re-attempts the swanctl
// re-render+reload against the live active config until it converges, the
// rebind target disappears (VPN/DHCP binding removed by a commit), or the
// daemon shuts down. armIPsecRebind restarts it if a later lease change fails
// again. Mirrors probePinRetryLoop (#1895).
func (d *Daemon) ipsecRebindRetryLoop(ctx context.Context) {
	interval := d.ipsecRebindRetryEvery
	if interval <= 0 {
		interval = ipsecRebindRetryInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.disarmIPsecRebindOnShutdown()
			return
		case <-ticker.C:
			if d.tryIPsecRebindRetry(ctx) {
				return
			}
		}
	}
}

// tryIPsecRebindRetry runs one retry attempt under applySem and returns
// stop=true when the loop has been disarmed and should exit. Holding applySem
// across the apply AND the pending/active state update keeps every attempt
// atomic with the lease callback's own apply+record, so the final pending
// state always reflects the last completed apply (no lost-failure race).
func (d *Daemon) tryIPsecRebindRetry(ctx context.Context) (stop bool) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		// Context cancelled (shutdown). Disarm and stop; the loop's ctx.Done
		// branch would otherwise never run because we return here.
		d.disarmIPsecRebindOnShutdown()
		return true
	}
	defer d.applySem.Release(1)

	// Re-check convergence under applySem: a concurrent lease-change apply may
	// have already reconverged while this tick waited for the lock.
	if d.disarmIPsecRebindIfConverged() {
		return true
	}

	cfg := d.activeConfigForRebind()
	if cfg == nil || d.ipsec == nil || !ipsec.HasDHCPBoundGateway(cfg) {
		// The rebind target is gone (VPN deleted / interface no longer
		// DHCP-bound). Clear pending and stop; a future lease change re-arms.
		d.clearIPsecRebindPending()
		return d.disarmIPsecRebindIfConverged()
	}

	if err := d.ipsecApplyForLeaseChange(cfg); err != nil {
		slog.Warn("IPsec rebind retry after DHCP address change failed; "+
			"local_addrs still stale, will retry", "err", err)
		d.armIPsecRebind() // pending stays set; the loop is already active
		return false
	}
	d.clearIPsecRebindPending()
	return d.disarmIPsecRebindIfConverged()
}
