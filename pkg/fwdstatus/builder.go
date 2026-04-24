package fwdstatus

import (
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// userHZ is the kernel's scheduler tick frequency.  Every mainline
// kernel config we ship sets CONFIG_HZ_100=y, so this is 100 on
// every supported deployment.  golang.org/x/sys/unix does not expose
// `Sysconf`/`_SC_CLK_TCK` on Linux and we avoid cgo in this package,
// so the value is hardcoded.  There is no init-time validation; a
// pathological custom kernel with a different HZ would cause CPU
// percentages derived from /proc ticks to be inaccurate, but will
// not crash the daemon.
const userHZ = 100

// Well-known follow-up issue numbers printed in the rendered output.
const (
	followupUMEMBuffer  = 878 // UMEM utilization telemetry for userspace-dp.
	followupClusterPeer = 879 // Cluster peer rendering for show chassis forwarding.
)

// UMEMBufferFollowup returns the issue number printed when Buffer%
// cannot be read on userspace-dp.  Callers may override to 0 if they
// want to suppress the reference.
func UMEMBufferFollowup() int { return followupUMEMBuffer }

// ClusterPeerFollowup returns the issue number printed when cluster
// mode is detected but peer data is not yet plumbed.
func ClusterPeerFollowup() int { return followupClusterPeer }

// DataPlaneAccessor is the small surface Build needs from the
// dataplane.  Both `dataplane.DataPlane` and mocks in tests satisfy
// it.  Package keeps the interface narrow so tests don't have to
// stub dozens of unrelated methods.
type DataPlaneAccessor interface {
	IsLoaded() bool
	GetMapStats() []dataplane.MapStats
}

// Build gathers all fields of a ForwardingStatus.  Nil `dp` is
// tolerated (treated as "dataplane not loaded" → State=Unknown).
// `proc` must be non-nil; callers that want to bypass /proc should
// pass a stub implementation that returns os.ErrNotExist — Build
// maps that into State=Unknown with uptime falling back to
// `startTime`.
func Build(
	dp DataPlaneAccessor,
	proc ProcReader,
	startTime time.Time,
	clusterMode bool,
) (*ForwardingStatus, error) {
	fs := &ForwardingStatus{
		State:              StateUnknown,
		WorkerCPUMode:      CPUModeEBPFNoWorkers,
		BufferKnown:        false,
		BufferFollowupRef:  followupUMEMBuffer,
		ClusterMode:        clusterMode,
		ClusterFollowupRef: followupClusterPeer,
	}

	// --- Uptime + Daemon CPU %: shared PID-start anchor ------------
	selfStat, statErr := proc.ReadSelfStat()
	stat, btimeErr := proc.ReadStat()
	hasProcStat := statErr == nil && btimeErr == nil

	if hasProcStat {
		pidStart := time.Unix(int64(stat.BootTime)+int64(selfStat.StartTimeTicks)/userHZ, 0)
		fs.Uptime = time.Since(pidStart)

		wallNs := fs.Uptime.Nanoseconds()
		if wallNs > 0 {
			// Per-core percent: 100% = one core fully saturated;
			// a daemon using 2 cores sustained reports 200%.  This
			// matches `top` and is honest on CPU-pinned deployments
			// where normalizing by NumCPU() would under-report load.
			cpuNs := ticksToNanos(selfStat.UtimeTicks + selfStat.StimeTicks)
			fs.DaemonCPUPercent = float64(cpuNs) * 100.0 / float64(wallNs)
		}
	} else {
		// Fallback: in-memory daemon start time.  Differs from true
		// PID-start by ms at most.  State stays Unknown below because
		// /proc/self/stat was unreadable.
		fs.Uptime = time.Since(startTime)
	}

	// --- Heap % --------------------------------------------------
	selfStatm, statmErr := proc.ReadSelfStatm()
	hasStatm := statmErr == nil
	if hasStatm {
		rssBytes := uint64(selfStatm.ResidentPages) * uint64(pageSize())
		limitBytes := uint64(0)
		if cgroupMax, err := proc.ReadCgroupMemoryMax(); err == nil && cgroupMax > 0 {
			limitBytes = cgroupMax
		}
		if limitBytes == 0 {
			if mi, err := proc.ReadMemInfo(); err == nil && mi.MemTotalBytes > 0 {
				limitBytes = mi.MemTotalBytes
			}
		}
		if limitBytes > 0 {
			fs.HeapPercent = float64(rssBytes) * 100.0 / float64(limitBytes)
		}
	}

	// --- Buffer % ------------------------------------------------
	// eBPF path: max BPF map utilization.
	// Userspace-dp path: unknown (BPF maps don't represent ring fill).
	//
	// Note: GetMapStats() iterates every entry of every BPF map and
	// userspace.Manager.Status() takes Manager.mu.  That's acceptable
	// because `show chassis forwarding` is a rare CLI diagnostic, but
	// don't wire this into a high-frequency poller.
	isUserspace := false
	if dp != nil {
		if _, ok := dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			isUserspace = true
		}
	}
	if dp != nil && !isUserspace {
		// Skip Array / PerCPUArray types — their "UsedCount" is the
		// iterator's slot count (always == MaxEntries, giving a
		// nonsense 100%).  `showSystemBuffers` skips them for the
		// same reason.  Only Hash / LPMTrie-style maps track
		// meaningful occupancy.
		maxPct := 0.0
		for _, ms := range dp.GetMapStats() {
			if ms.MaxEntries == 0 {
				continue
			}
			if ms.Type == "Array" || ms.Type == "PerCPUArray" {
				continue
			}
			pct := float64(ms.UsedCount) * 100.0 / float64(ms.MaxEntries)
			if pct > maxPct {
				maxPct = pct
			}
		}
		fs.BufferPercent = maxPct
		fs.BufferKnown = true
	}

	// --- Worker CPU % (userspace-dp only) ------------------------
	var usStatus userspace.ProcessStatus
	var usErr error
	if dp != nil && isUserspace {
		if acc, ok := dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			usStatus, usErr = acc.Status()
		}
	}
	if isUserspace && usErr == nil {
		fs.WorkerCPUMode = CPUModeWorkers
		fs.WorkerCPUPercent = sumWorkerCPUPercent(usStatus)
	}

	// --- State ---------------------------------------------------
	switch {
	case dp == nil || !dp.IsLoaded():
		fs.State = StateUnknown
	case !hasProcStat || !hasStatm:
		fs.State = StateUnknown
	case isUserspace && usErr != nil:
		fs.State = StateUnknown
	case isUserspace && !allHeartbeatsFresh(usStatus.WorkerHeartbeats, time.Now(), 2*time.Second):
		fs.State = StateDegraded
	default:
		fs.State = StateOnline
	}

	return fs, nil
}

func ticksToNanos(ticks uint64) uint64 {
	return ticks * 1_000_000_000 / userHZ
}

// sumWorkerCPUPercent returns the cumulative summed CPU% across all
// workers in the given status.  Each worker contributes
// thread_cpu_ns / wall_ns * 100; summing yields aggregate daemon
// worker load (can exceed 100 on multi-core).
func sumWorkerCPUPercent(st userspace.ProcessStatus) float64 {
	total := 0.0
	for _, w := range st.WorkerRuntime {
		if w.WallNS == 0 {
			continue
		}
		total += float64(w.ThreadCPUNS) * 100.0 / float64(w.WallNS)
	}
	return total
}

// allHeartbeatsFresh returns true iff every heartbeat is within
// maxAge of now.  Empty slice returns true (no workers → trivially
// fresh; caller distinguishes the empty vs populated case when
// interpreting Degraded).
func allHeartbeatsFresh(hbs []time.Time, now time.Time, maxAge time.Duration) bool {
	for _, hb := range hbs {
		if now.Sub(hb) > maxAge {
			return false
		}
	}
	return true
}

// pageSize is runtime.Getpagesize wrapped so tests can't accidentally
// call it with a mock that doesn't match the real parser (the parser
// returns raw page counts).
func pageSize() int {
	return syscallPageSize
}

// syscallPageSize is the page size in bytes used to convert the
// `resident` field of /proc/self/statm (which is in pages) to
// bytes.  Hardcoded to 4096 — Linux x86_64/arm64 page size on every
// mainline kernel config we ship.  We intentionally do NOT call
// `unix.Getpagesize()` here to keep this package dependency-light;
// if we ever deploy on a kernel with a non-4K page size (HugeTLBFS
// main allocation, transparent-hugepage config), Heap% will be
// inaccurate by a constant factor until this is fetched at runtime.
var syscallPageSize = 4096

// (A library package must not panic on sensor unreliability.  A
// malformed /proc/self/stat is caught by Build returning State=Unknown
// — no init-time sanity check here.  If a user deploys on a kernel
// with a non-standard HZ, the operator will see wrong CPU percentages
// and investigate; that is strictly better than crashing xpfd.)
