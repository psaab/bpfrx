package fwdstatus

import (
	"context"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ringSize is the sampler ring capacity.  At 1s cadence it holds 6m
// of history — comfortably past the 5m window lookup, with headroom
// for occasional missed samples.
const ringSize = 360

// SampleInterval is the sampler cadence.
const SampleInterval = 1 * time.Second

// CPU window indices.
const (
	CPUWindow5s = iota
	CPUWindow1m
	CPUWindow5m
	numCPUWindows
)

// cpuSample is one tick of the cumulative-counter ring.  All
// counters are monotonic nanoseconds.
type cpuSample struct {
	wall            time.Time
	daemonCPUNs     uint64 // /proc/self/stat utime+stime, converted to ns
	workerThreadNs  uint64 // Σ WorkerRuntimeStatus.thread_cpu_ns across workers
	workerWallNs    uint64 // Σ WorkerRuntimeStatus.wall_ns across workers
}

// Sampler maintains a ring of cumulative CPU counters.  One
// instance per daemon, started at boot.  Snapshot() returns a
// read-only copy safe to hand to Build() off-lock.
type Sampler struct {
	mu    sync.Mutex
	ring  [ringSize]cpuSample
	head  int    // next write index, wraps 0..ringSize-1
	count uint64 // monotonic count of samples ever taken (no wrap)

	dp   DataPlaneAccessor
	proc ProcReader

	// Snapshot of the last successfully-read worker telemetry.
	// On a failed Status() call the sampler reuses these values so
	// the counter series stays monotonic (see plan §Error handling).
	lastWorkerThread uint64
	lastWorkerWall   uint64
}

// NewSampler constructs a Sampler.  The sampler is not running
// until Start() is called.
func NewSampler(dp DataPlaneAccessor, proc ProcReader) *Sampler {
	return &Sampler{dp: dp, proc: proc}
}

// Start primes one sample synchronously, then launches a goroutine
// that samples every SampleInterval until ctx is canceled.
// Returns immediately after priming.
func (s *Sampler) Start(ctx context.Context) {
	s.sample(time.Now())
	go s.loop(ctx)
}

func (s *Sampler) loop(ctx context.Context) {
	t := time.NewTicker(SampleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.sample(now)
		}
	}
}

// sample captures one row and appends it to the ring.  On
// /proc/self/stat read failure the sample is dropped entirely —
// skipping preserves monotonicity of daemonCPUNs.  On worker
// telemetry failure the worker counters are held at their
// previous values (honest zero-rate for that interval).
//
// Worker CPU comes from Σthread_cpu_ns (OS thread CPU via
// CLOCK_THREAD_CPUTIME_ID) divided by Σwall_ns.  NOT Σactive_ns —
// that was tried and reverted: see #883 (workers bypassed under
// load) and #884 (active_ns idle-poll undercounting).
func (s *Sampler) sample(now time.Time) {
	selfStat, statErr := s.proc.ReadSelfStat()
	if statErr != nil {
		return
	}
	daemonNs := ticksToNanos(selfStat.UtimeTicks + selfStat.StimeTicks)

	// Worker counters — userspace-dp only.
	workerThread, workerWall := s.lastWorkerThread, s.lastWorkerWall
	if s.dp != nil {
		if us, ok := s.dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			if st, err := us.Status(); err == nil {
				var tc, w uint64
				for _, wr := range st.WorkerRuntime {
					tc += wr.ThreadCPUNS
					w += wr.WallNS
				}
				workerThread, workerWall = tc, w
			}
		}
	}

	s.mu.Lock()
	s.ring[s.head] = cpuSample{
		wall:           now,
		daemonCPUNs:    daemonNs,
		workerThreadNs: workerThread,
		workerWallNs:   workerWall,
	}
	s.head = (s.head + 1) % ringSize
	s.count++
	s.lastWorkerThread = workerThread
	s.lastWorkerWall = workerWall
	s.mu.Unlock()
}

// SamplerSnapshot is a value-type view of the ring passed to
// Build().  Samples is ordered oldest-first, newest-last.  Empty
// snapshot renders as all-windows-invalid in Build().
type SamplerSnapshot struct {
	Samples []cpuSample
	Now     time.Time
}

// Snapshot copies the ring under lock and returns it.  Always
// ordered oldest-first.
func (s *Sampler) Snapshot() SamplerSnapshot {
	s.mu.Lock()
	n := int(s.count)
	if n > ringSize {
		n = ringSize
	}
	out := make([]cpuSample, n)
	if s.count <= ringSize {
		// Ring has not yet rolled over; entries 0..count-1 are in
		// chronological order.
		copy(out, s.ring[:n])
	} else {
		// Ring has rolled over; oldest entry is at head.
		tail := ringSize - s.head
		copy(out[:tail], s.ring[s.head:])
		copy(out[tail:], s.ring[:s.head])
	}
	s.mu.Unlock()
	return SamplerSnapshot{Samples: out, Now: time.Now()}
}

// computeCPUWindows returns per-core Daemon CPU% and per-worker-average
// Worker thread CPU% for the three windows, plus parallel validity
// flags.  A window is valid iff the snapshot contains a sample with
// wall ≤ newest.wall − W.
//
// Daemon %: (Δdaemon_cpu_ns / Δwall_ns) × 100 — per-core percent;
//          can exceed 100% on multi-core.
// Worker %: (Δworker_thread_cpu_ns / Δworker_wall_ns) × 100 —
//          per-worker-average OS thread CPU via CLOCK_THREAD_CPUTIME_ID,
//          summed across workers.  Busy-poll mode shows ~100% regardless
//          of traffic (known false-positive); eBPF path has no workers
//          so Δworker_wall_ns stays 0 and the window flags as invalid.
//          See #883 / #884 for why we don't use active_ns here.
func computeCPUWindows(snap SamplerSnapshot) (
	daemonPct, workerPct [numCPUWindows]float64,
	daemonValid, workerValid [numCPUWindows]bool,
) {
	if len(snap.Samples) < 2 {
		return
	}
	newest := snap.Samples[len(snap.Samples)-1]
	windows := [numCPUWindows]time.Duration{
		5 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
	}
	for i, w := range windows {
		target := newest.wall.Add(-w)
		idx := findSampleAtOrBefore(snap.Samples, target)
		if idx < 0 {
			continue
		}
		then := snap.Samples[idx]
		wallDelta := newest.wall.Sub(then.wall)
		if wallDelta <= 0 {
			continue
		}
		// Guard against non-monotonic counters.  A userspace-dp
		// restart or a brief Status() miscarriage can reset the
		// cumulative series; an unchecked subtract on uint64 would
		// underflow to a huge value and pass the clamp-on-display
		// path, reporting a bogus 9e20%.  Mark the window invalid
		// in that case so the operator sees `-` until fresh samples
		// accumulate.
		wallNs := uint64(wallDelta.Nanoseconds())
		if newest.daemonCPUNs >= then.daemonCPUNs {
			daemonDelta := newest.daemonCPUNs - then.daemonCPUNs
			daemonPct[i] = float64(daemonDelta) * 100.0 / float64(wallNs)
			daemonValid[i] = true
		}

		if newest.workerWallNs > then.workerWallNs &&
			newest.workerThreadNs >= then.workerThreadNs {
			workerWallDelta := newest.workerWallNs - then.workerWallNs
			workerThreadDelta := newest.workerThreadNs - then.workerThreadNs
			workerPct[i] = float64(workerThreadDelta) * 100.0 /
				float64(workerWallDelta)
			workerValid[i] = true
		}
	}
	return
}

// findSampleAtOrBefore returns the index of the sample with the
// largest wall ≤ target, or -1 if none.  Samples is ordered
// oldest-first so we scan forward and return the last element
// that satisfies the predicate.
func findSampleAtOrBefore(samples []cpuSample, target time.Time) int {
	idx := -1
	for i := range samples {
		if samples[i].wall.After(target) {
			break
		}
		idx = i
	}
	return idx
}
