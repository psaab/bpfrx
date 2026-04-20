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

// applyRSSIndirection reshapes the RSS indirection table on every mlx5_core
// interface so that only queues 0..workers-1 receive traffic.
//
// Invariants:
//   - Runs at daemon startup (and on reconcile for worker-count changes),
//     before the dataplane binds any AF_XDP socket on startup.
//   - Non-mlx5 interfaces are skipped at the per-interface call site —
//     `ethtool` is never invoked on virtio, iavf, i40e, etc. The
//     driver-guard is also repeated inside applyRSSIndirectionOne as
//     defense in depth, so a mis-fed allowlist cannot touch non-mlx5.
//   - enabled == false is a hard kill switch: skip everything.
//   - workers == 1 is skipped (single worker benefits from default RSS
//     spreading across all HW queues / IRQ lines; weight-pinning to a
//     single queue would serialize the worker on one IRQ — reviewer #L1).
//   - workers >= queue_count is skipped (default table already delivers
//     traffic to every queue; reshaping does nothing useful).
//   - Idempotent: if the live indirection table already matches the
//     computed layout, no write is issued.
//   - Never returns a non-nil error — D3 regressions must not break
//     interface bring-up.
func applyRSSIndirection(enabled bool, workers int, execer rssExecutor) {
	if !enabled {
		slog.Info("linksetup: rss indirection disabled by config")
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

	ifaces := execer.listInterfaces()
	if len(ifaces) == 0 {
		slog.Warn("linksetup: rss indirection could not enumerate interfaces")
		return
	}

	for _, iface := range ifaces {
		if iface == "lo" {
			continue
		}
		drv := execer.readDriver(iface)
		if drv != mlx5Driver {
			// Explicit per-interface mlx5 guard at the call site —
			// prevents any `ethtool` invocation on virtio/iavf/i40e/etc.
			// Review finding HIGH #1.
			slog.Debug("linksetup: rss indirection skipped (non-mlx5 driver)",
				"iface", iface, "driver", drv)
			continue
		}
		applyRSSIndirectionOne(iface, workers, execer)
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
