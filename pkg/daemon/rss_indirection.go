// Package daemon implements the xpf daemon lifecycle.
//
// This file implements D3 RSS indirection persistence (issue #785).
//
// For mlx5_core-driven interfaces that will be bound to userspace-dp with
// N workers, we reshape the hardware RSS indirection table so that hash
// outputs land only on queues 0..N-1. Queues N..RX_count-1 are weighted 0
// and never receive traffic. This avoids the wasted kernel-fallback path
// on queues that no userspace worker consumes.
//
// Why a sibling file to linksetup.go (not inline): the weight-vector
// computation is a pure function with several edge cases that deserve
// their own unit tests; keeping it here lets the tests live beside the
// logic without bloating linksetup.go, which already owns PCI enumeration
// and .link-file management.
//
// Applied strictly before any AF_XDP socket binding opens an RX ring on
// first boot — driven from enumerateAndRenameInterfaces() at daemon
// startup. The reviewer's #M4 concern (no mid-traffic re-hash) is
// addressed by call ordering: this runs from Run() before the dataplane
// is loaded, so RX rings do not yet exist.
//
// Re-applied from the daemon reconcile path (applyConfig) on every
// commit, so changes to `system dataplane workers` or the
// `rss-indirection enable|disable` knob take effect without a restart.
// Re-application is idempotent (matching tables skip the write) and
// strictly per-mlx5 (driver-guarded at both the top-level scan and the
// per-interface call site).
package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// mlx5Driver is the sysfs driver name we detect D3-eligible NICs by.
	// Non-mlx5 drivers are skipped silently — xpf must still bring up
	// virtio, i40e, etc. unchanged. D3 is an optimization, not a
	// correctness requirement.
	mlx5Driver = "mlx5_core"
)

// rssExecutor abstracts ethtool invocation and sysfs enumeration so unit
// tests can inject a fake without touching the real binary or real sysfs.
// Real callers use realRSSExecutor.
type rssExecutor interface {
	// runEthtool runs `ethtool <args...>` and returns combined output + err.
	// On ErrNotFound (binary missing), callers treat it as non-fatal.
	runEthtool(args ...string) ([]byte, error)
	// readDriver returns the sysfs driver name for iface (basename of
	// /sys/class/net/<iface>/device/driver), or "" if not a PCI NIC.
	readDriver(iface string) string
	// readQueueCount returns the number of RX queues for iface, as
	// enumerated from /sys/class/net/<iface>/queues/rx-*.
	readQueueCount(iface string) int
	// listInterfaces returns the set of netdev names to consider (real
	// sysfs: basenames of /sys/class/net). Injection point for tests so
	// the top-level scan path is exercised without touching real netdevs.
	listInterfaces() []string
}

// realRSSExecutor is the production implementation of rssExecutor.
type realRSSExecutor struct{}

func (realRSSExecutor) runEthtool(args ...string) ([]byte, error) {
	return exec.Command("ethtool", args...).CombinedOutput()
}

func (realRSSExecutor) readDriver(iface string) string {
	link, err := os.Readlink(filepath.Join("/sys/class/net", iface, "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

func (realRSSExecutor) readQueueCount(iface string) int {
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", iface, "queues"))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			n++
		}
	}
	return n
}

func (realRSSExecutor) listInterfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// applyRSSIndirection reshapes the RSS indirection table on mlx5_core
// interfaces that are actually bound to the userspace dataplane so that
// only queues 0..workers-1 receive traffic.
//
// Invariants:
//   - Runs at daemon startup (and on reconcile for worker-count changes),
//     before the dataplane binds any AF_XDP socket on startup.
//   - `allowed` is the userspace-dp binding allowlist — the authoritative
//     set of Linux interface names that AF_XDP will bind. Only members
//     of that set are ever considered, and every member is still passed
//     through the mlx5 driver guard. An empty allowlist is treated as
//     "no interfaces to touch" (no-op) — never a fall-back to scanning
//     every netdev. Review finding Codex H1.
//   - Non-mlx5 interfaces in the allowlist are skipped — `ethtool` is
//     never invoked on virtio, iavf, i40e, etc. The driver-guard is
//     also repeated inside applyRSSIndirectionOne as defense in depth.
//   - enabled == false is a hard kill switch: restore the default
//     indirection table on every allowlisted mlx5 interface.
//   - workers == 1 is skipped (single worker benefits from default RSS
//     spreading across all HW queues / IRQ lines; weight-pinning to a
//     single queue would serialize the worker on one IRQ — reviewer #L1).
//   - workers >= queue_count: weight reshaping is skipped (default
//     table already delivers to every queue), BUT the live table is
//     probed and reset to default if it carries a stale concentrated
//     layout left over from a prior workers < queue_count apply (#805).
//   - Idempotent: if the live indirection table already matches the
//     computed layout, no write is issued.
//   - Never returns a non-nil error — D3 regressions must not break
//     interface bring-up.
func applyRSSIndirection(enabled bool, workers int, allowed []string, execer rssExecutor) {
	if !enabled {
		// Kill switch. Actively restore default (equal-weight) RSS on
		// every allowlisted mlx5 interface so toggling disable at
		// runtime reverts the table without a daemon restart.
		// Idempotent: restoring an already-default table is a no-op
		// ethtool call. The restore is scoped per-interface with the
		// same driver filter as the apply path, so non-mlx5 netdevs
		// and non-userspace-dp interfaces are never touched.
		restoreDefaultRSSIndirection(allowed, execer)
		slog.Info("linksetup: rss indirection disabled by config",
			"allowed_count", len(allowed))
		return
	}
	if workers <= 0 {
		// Non-userspace deploys (ebpf/dpdk) hit this path every boot —
		// keep at Debug to avoid info-level noise on the default path.
		slog.Debug("linksetup: rss indirection skipped (no workers configured)")
		return
	}
	if workers == 1 {
		slog.Info("linksetup: rss indirection skipped (single worker — keep default RSS)")
		return
	}
	if len(allowed) == 0 {
		// No userspace-dp bindings derived from config — nothing to
		// reshape. This is distinct from "listInterfaces returned
		// nothing": an empty allowlist means the compiled config has
		// no userspace-dp-bound mlx5 interfaces (e.g. management-only
		// deploy), not a sysfs error.
		slog.Debug("linksetup: rss indirection skipped (no userspace-dp bound interfaces)",
			"workers", workers)
		return
	}

	for _, iface := range allowed {
		if iface == "lo" {
			continue
		}
		drv := execer.readDriver(iface)
		if drv != mlx5Driver {
			// Allowlist can legitimately include non-mlx5 interfaces
			// (virtio/iavf/i40e that userspace-dp binds on); skip
			// silently at the driver guard. Codex H1: never invoke
			// ethtool on a non-mlx5 netdev.
			slog.Debug("linksetup: rss indirection skipped (non-mlx5 driver)",
				"iface", iface, "driver", drv)
			continue
		}
		applyRSSIndirectionOne(iface, workers, execer)
	}
}

// restoreDefaultRSSIndirection is called when the kill switch is engaged.
// Runs `ethtool -X <iface> default` on every allowlisted mlx5 interface so
// the kernel reverts to equal-weight RSS across all HW queues. Idempotent
// (already-default is a no-op). Non-mlx5 interfaces are filtered out at
// the call site, mirroring applyRSSIndirection's guard. An empty allowlist
// is a no-op: the restore path must not escape the userspace-dp binding
// scope (Codex H1).
func restoreDefaultRSSIndirection(allowed []string, execer rssExecutor) {
	if len(allowed) == 0 {
		return
	}
	for _, iface := range allowed {
		if iface == "lo" {
			continue
		}
		if execer.readDriver(iface) != mlx5Driver {
			continue
		}
		out, err := execer.runEthtool("-X", iface, "default")
		if err != nil {
			if isExecNotFound(err) {
				slog.Warn("linksetup: ethtool binary not found, cannot restore default rss indirection",
					"iface", iface)
				return
			}
			slog.Warn("linksetup: ethtool -X default failed",
				"iface", iface, "err", err,
				"output", strings.TrimSpace(string(out)))
			continue
		}
		slog.Info("linksetup: restored default rss indirection", "iface", iface)
	}
}

// applyRSSIndirectionOne applies the weight-vector to a single mlx5 iface.
// Errors are logged and swallowed: D3 is best-effort.
//
// The caller (applyRSSIndirection) is responsible for driver filtering;
// this function additionally re-checks the driver as defense in depth so a
// future caller cannot accidentally invoke ethtool on a non-mlx5 netdev.
func applyRSSIndirectionOne(iface string, workers int, execer rssExecutor) {
	if drv := execer.readDriver(iface); drv != mlx5Driver {
		slog.Debug("linksetup: rss indirection skipped (non-mlx5 driver at per-iface check)",
			"iface", iface, "driver", drv)
		return
	}
	queues := execer.readQueueCount(iface)
	weights, reason := computeWeightVector(workers, queues)
	if weights == nil {
		slog.Info("linksetup: rss indirection skipped", "iface", iface,
			"workers", workers, "queues", queues, "reason", reason)
		// #805: When workers >= queues > 1 we previously left the
		// indirection table alone. That's correct on a fresh install
		// (kernel default is round-robin = what we want) but wrong on
		// the workers<queues → workers>=queues transition, where a
		// concentrated `[1,...,1,0,...,0]` table written by an earlier
		// applyRSSIndirectionOne for the prior worker count stays live
		// and starves queues that now host worker-bound AF_XDP sockets.
		// Inspect the live table; if it isn't the round-robin default,
		// restore it.
		//
		// Guard requires queues > 1: with a single-queue NIC there is
		// no possible concentration to undo (the default and any
		// "configured" layout both have entry[i] == 0 for every i).
		if workers > 1 && workers >= queues && queues > 1 {
			maybeRestoreDefault(iface, queues, execer)
		}
		return
	}

	// Idempotency: read the live table; skip the write if it already
	// matches the target layout. Avoids kernel log noise on repeated
	// daemon restarts and avoids spurious NIC churn during reconcile.
	out, err := execer.runEthtool("-x", iface)
	if err != nil {
		// ethtool missing / unsupported → best-effort skip.
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, skipping rss indirection",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -x failed, skipping rss indirection",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	if indirectionTableMatches(out, weights) {
		slog.Debug("linksetup: rss indirection unchanged", "iface", iface)
		return
	}

	args := []string{"-X", iface, "weight"}
	for _, w := range weights {
		args = append(args, strconv.Itoa(w))
	}
	if out, err := execer.runEthtool(args...); err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, rss indirection not applied",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -X failed",
			"iface", iface, "weights", weights, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	slog.Info("linksetup: applied rss indirection",
		"iface", iface, "workers", workers, "queues", len(weights),
		"weights", weights)
}

// maybeRestoreDefault reads the live RSS indirection table and, if it
// is not the kernel's default round-robin shape, runs
// `ethtool -X <iface> default` to restore it. Used on the
// workers >= queues skip path (#805) to undo a concentrated table
// left behind by a prior workers < queues apply when the operator
// has since increased the worker count to match queue count.
//
// Best-effort: ethtool probe failures are logged and skipped without
// attempting a write, mirroring the apply path's error handling.
func maybeRestoreDefault(iface string, queues int, execer rssExecutor) {
	out, err := execer.runEthtool("-x", iface)
	if err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, cannot probe for default rss indirection",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -x failed, cannot probe for default rss indirection",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	if indirectionTableIsDefault(out, queues) {
		slog.Debug("linksetup: rss indirection already default, no restore needed",
			"iface", iface)
		return
	}
	if out, err := execer.runEthtool("-X", iface, "default"); err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, cannot restore default rss indirection",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -X default failed",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	slog.Info("linksetup: restored default round-robin rss indirection",
		"iface", iface,
		"reason", "workers>=queues with stale constrained table")
}

// indirectionTableIsDefault reports true iff the live `ethtool -x`
// output describes a round-robin indirection table where
// entry[i] == i mod queueCount. This is the exact shape mlx5
// produces on `ethtool -X iface default` (verified live on the
// loss:xpf-userspace-fw0 cluster, 6-queue ge-0-0-2).
//
// Stricter than indirectionTableMatches: rejects any custom table
// that uses every queue at least once but doesn't match the
// round-robin pattern.
//
// Returns false on empty/unparseable input, or on any row whose
// entries don't all match the expected (rowIdx + j) % queueCount
// position. Returns true only when at least one entry has been
// successfully parsed AND verified.
func indirectionTableIsDefault(output []byte, queueCount int) bool {
	if queueCount <= 0 {
		return false
	}
	sawAnyEntry := false
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		colon := bytes.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		rowIdx, err := strconv.Atoi(string(trimmed[:colon]))
		if err != nil {
			continue
		}
		for j, tok := range bytes.Fields(trimmed[colon+1:]) {
			q, err := strconv.Atoi(string(tok))
			if err != nil {
				return false
			}
			expected := (rowIdx + j) % queueCount
			if q != expected {
				return false
			}
			sawAnyEntry = true
		}
	}
	return sawAnyEntry
}

// computeWeightVector returns the weight vector for the given worker and
// queue counts, or nil if D3 should skip this interface. The second return
// value is a human-readable skip reason (empty if a vector was produced).
//
// Cases:
//   - workers <= 0 or queues <= 0: skip (misconfigured).
//   - workers == 1: skip (single worker — keep default RSS spreading load
//     across all HW queues / IRQ lines; pinning to queue 0 would serialize
//     the worker on one IRQ).
//   - workers >= queues: skip (default table already delivers to every
//     queue; no reshaping possible or useful).
//   - workers < queues: produce `[1]*workers + [0]*(queues - workers)`.
func computeWeightVector(workers, queues int) ([]int, string) {
	if workers <= 0 {
		return nil, "workers <= 0"
	}
	if queues <= 0 {
		return nil, "queue count unknown"
	}
	if workers == 1 {
		return nil, "workers == 1 (keep default RSS)"
	}
	if workers >= queues {
		return nil, fmt.Sprintf("workers (%d) >= queues (%d)", workers, queues)
	}
	v := make([]int, queues)
	for i := 0; i < workers; i++ {
		v[i] = 1
	}
	return v, ""
}

// indirectionTableMatches returns true if the live `ethtool -x` output
// already describes a table that only uses queues 0..(activeCount-1),
// where activeCount is the number of non-zero weights. The table layout
// for an mlx5 NIC with weight [1 1 1 1 0 0] looks like:
//
//	RX flow hash indirection table for eth0 with 6 RX ring(s):
//	    0:      0     1     2     3     0     1
//	    8:      2     3     0     1     2     3
//	...
//
// i.e. no queue index >= activeCount appears. We conservatively treat any
// appearance of a queue >= activeCount as a mismatch so the reapply goes
// through.
func indirectionTableMatches(output []byte, weights []int) bool {
	if len(weights) == 0 {
		return false
	}
	active := 0
	for _, w := range weights {
		if w > 0 {
			active++
		}
	}
	if active == 0 {
		return false
	}

	// Lines of interest start with whitespace + digits + ':', e.g.
	// "    0:      0     1     2     3     0     1".
	sawAnyRow := false
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		// Only parse lines of the form "<index>: <qn> <qn> ..."
		colon := bytes.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		if _, err := strconv.Atoi(string(trimmed[:colon])); err != nil {
			continue
		}
		sawAnyRow = true
		for _, tok := range bytes.Fields(trimmed[colon+1:]) {
			q, err := strconv.Atoi(string(tok))
			if err != nil {
				return false
			}
			if q < 0 || q >= active {
				return false
			}
		}
	}
	return sawAnyRow
}

// isExecNotFound returns true if err indicates the ethtool binary is
// missing. `exec.Command("ethtool").CombinedOutput()` wraps the stable
// `exec.ErrNotFound` sentinel in an *exec.Error, so errors.Is is the
// correct mechanism — no substring matching required.
func isExecNotFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}
