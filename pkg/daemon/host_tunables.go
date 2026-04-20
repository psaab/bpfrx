// Host-scope tunables (#801): CPU governor + net.core.netdev_budget.
//
// Both knobs are Phase-B Step-0 audit fixes. The governor pushes every
// writable /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor node to
// the operator's requested mode (default "performance"). The budget
// writes /proc/sys/net/core/netdev_budget. Neither touches a network
// interface directly — they are system-wide, so there is no per-iface
// driver guard: either the sysfs node is writable or it is not.
//
// Why a separate file from rss_indirection.go: these knobs cross
// sysctl + cpufreq abstraction lines and have different failure modes
// (VM no-op for governor, read-only mounts for sysctl) that deserve
// their own logging and their own unit tests. Keeping them here means
// test fakes don't have to stub ethtool.
//
// All three functions are best-effort: a failure never blocks daemon
// startup or config commit. Matches D3's invariant that tunables must
// not regress interface bring-up.
package daemon

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Defaults used when the operator omits the knob entirely. Exposed so
// applyConfig can resolve defaults at the call site (avoids sprinkling
// literal constants across daemon.go).
const (
	defaultCPUGovernor  = "performance"
	defaultNetdevBudget = 600
	defaultCoalesceRX   = 8
	defaultCoalesceTX   = 8
)

// hostTunableFS abstracts the filesystem writes performed by the
// governor + netdev_budget logic so unit tests can assert exact writes
// without touching real sysfs. The interface is intentionally narrow:
// list-cpufreq-governor-nodes, read one, write one, write a sysctl
// file. Production callers use realHostTunableFS; tests use a fake.
type hostTunableFS interface {
	// listCPUGovernorPaths returns the absolute paths of every
	// /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor node. An
	// empty slice indicates cpufreq is not exposed (typical VM).
	listCPUGovernorPaths() []string
	// readFile reads the file at path. Distinct from writeFile so
	// idempotency (skip-if-already-set) can be asserted in tests.
	readFile(path string) ([]byte, error)
	// writeFile writes data to path. Failures are returned for the
	// caller to log (we never want a fake that silently drops writes).
	writeFile(path string, data []byte) error
}

type realHostTunableFS struct{}

func (realHostTunableFS) listCPUGovernorPaths() []string {
	// glob is the simplest expression of "one node per CPU". cpufreq
	// filesystems are small — no reason to walk.
	matches, err := filepath.Glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
	if err != nil || len(matches) == 0 {
		return nil
	}
	return matches
}

func (realHostTunableFS) readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (realHostTunableFS) writeFile(path string, data []byte) error {
	// 0644 is the sysfs/proc convention; real writes go through the
	// kernel's sysfs handler and ignore the mode, but setting it keeps
	// this identical to `echo > ...`.
	return os.WriteFile(path, data, 0644)
}

// applyCPUGovernor writes the requested governor to every writable
// cpufreq node. `requested` values:
//   - ""          : no-op (operator left default unspecified — treat as "leave alone")
//   - "default"   : alias of "" — no-op
//   - anything else: try to write verbatim. We do NOT validate the
//     governor name because bare-metal operators may legitimately
//     request `powersave` / `ondemand` on a lab box. The kernel
//     enforces the valid set.
//
// VM semantics: `listCPUGovernorPaths` returns an empty slice when
// cpufreq is not exposed through QEMU/KVM to the guest (every current
// xpf VM). We log once at info and return. When xpfd runs on a bare
// metal chassis the writes land and the governor changes.
//
// Idempotency: each node is read first and skipped if it already
// matches. Avoids sysfs write-amplification across reconciles.
//
// Read-only mounts (chroot, unprivileged containers) surface as
// EACCES/EROFS on writeFile. We log one warning per node and move on.
func applyCPUGovernor(requested string, fs hostTunableFS) {
	requested = strings.TrimSpace(requested)
	if requested == "" || requested == "default" {
		// Operator opted out. Nothing to do.
		slog.Debug("linksetup: cpu governor skip (no config)")
		return
	}
	paths := fs.listCPUGovernorPaths()
	if len(paths) == 0 {
		// VM case. Informational, not warning — this is expected.
		slog.Info("linksetup: cpu governor skip (no cpufreq sysfs — VM?)",
			"requested", requested)
		return
	}

	wrote := 0
	skipped := 0
	failed := 0
	target := []byte(requested)
	for _, p := range paths {
		existing, err := fs.readFile(p)
		if err == nil && strings.TrimSpace(string(existing)) == requested {
			skipped++
			continue
		}
		if err := fs.writeFile(p, target); err != nil {
			// Read-only host, EACCES, or governor name not on the
			// kernel's allowed list. Log once per failing node with
			// the specific path so the operator can pinpoint it.
			failed++
			// Log only the first few failures (cpu0 is
			// representative of every other CPU's failure mode).
			if failed <= 2 {
				slog.Warn("linksetup: cpu governor write failed",
					"path", p, "requested", requested, "err", err)
			}
			continue
		}
		wrote++
	}
	slog.Info("linksetup: cpu governor applied",
		"requested", requested, "wrote", wrote,
		"skipped_already_set", skipped, "failed", failed,
		"total", len(paths))
}

// sysctlPathNetdevBudget is the procfs path written by applyNetdevBudget.
// Exposed as a constant so the test fake can assert on exact paths.
const sysctlPathNetdevBudget = "/proc/sys/net/core/netdev_budget"

// applyNetdevBudget writes the requested value to /proc/sys/net/core/
// netdev_budget. 0 is the sentinel for "leave kernel default" — the
// daemon resolves a non-zero default at the call site.
//
// Why we accept 0 as "skip" instead of always writing defaultNetdevBudget:
// some deploy paths may prefer to leave the value at the kernel default
// (300) for profiling comparisons without editing sysctl.conf. The
// compiler emits 0 when the knob is omitted, and the call site decides
// whether to substitute defaultNetdevBudget (yes, for userspace-dp
// deploys) or pass 0 through (non-userspace deploys).
//
// Idempotent: reads current value first and skips the write if it
// already matches. Read-only /proc (unprivileged container) surfaces
// as a log warning, not a fatal error.
func applyNetdevBudget(value int, fs hostTunableFS) {
	if value == 0 {
		slog.Debug("linksetup: netdev_budget skip (no config)")
		return
	}
	if value < 0 {
		// Defensive — net.core.netdev_budget must be > 0. Don't
		// propagate a nonsense value to the kernel.
		slog.Warn("linksetup: netdev_budget skip (non-positive)", "value", value)
		return
	}
	want := strconv.Itoa(value)
	existing, err := fs.readFile(sysctlPathNetdevBudget)
	if err == nil && strings.TrimSpace(string(existing)) == want {
		slog.Debug("linksetup: netdev_budget already set", "value", value)
		return
	}
	if err := fs.writeFile(sysctlPathNetdevBudget, []byte(want)); err != nil {
		if errors.Is(err, os.ErrPermission) {
			slog.Warn("linksetup: netdev_budget write denied (read-only /proc?)",
				"value", value, "err", err)
			return
		}
		slog.Warn("linksetup: netdev_budget write failed",
			"value", value, "err", err)
		return
	}
	slog.Info("linksetup: netdev_budget applied", "value", value)
}

// resolvedHostTunables returns the effective governor + budget given
// the config values and default substitution rules. Extracted as a
// pure function so the daemon-wire code can unit-test the
// "omitted-becomes-default when userspace-dp in use" logic.
//
//   - governorIn=""          → defaultCPUGovernor if userspaceDP else ""
//   - governorIn="default"   → "" (pass-through sentinel for skip)
//   - governorIn="performance"/"schedutil"/anything else → verbatim
//
//   - budgetIn=0             → defaultNetdevBudget if userspaceDP else 0
//   - budgetIn>0             → verbatim
//
// The rationale: the #801 Step-0 audit is scoped to userspace-dp
// deploys (the only configuration where the line-rate PRs apply).
// eBPF/DPDK/no-dataplane deploys never receive the default — their
// baseline remains "whatever the host has". Operator can still opt
// in on those deploys by setting the knob explicitly.
func resolvedHostTunables(governorIn string, budgetIn int, userspaceDP bool) (string, int) {
	gov := governorIn
	if gov == "" && userspaceDP {
		gov = defaultCPUGovernor
	}
	if gov == "default" {
		// "default" is an explicit skip sentinel. Normalize to "" so
		// applyCPUGovernor's skip path is taken.
		gov = ""
	}
	budget := budgetIn
	if budget == 0 && userspaceDP {
		budget = defaultNetdevBudget
	}
	return gov, budget
}

// applyHostTunables is the single entry point called from daemon
// startup + reconcile. Composes the governor + budget paths with
// consistent logging, and swallows all errors. Mirrors D3's
// applyRSSIndirection contract.
func applyHostTunables(governor string, budget int, fs hostTunableFS) {
	applyCPUGovernor(governor, fs)
	applyNetdevBudget(budget, fs)
}

