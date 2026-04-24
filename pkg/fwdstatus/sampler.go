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
	wall           time.Time
	daemonCPUNs    uint64 // /proc/self/stat utime+stime, converted to ns
	workerActiveNs uint64 // Σ WorkerRuntimeStatus.active_ns across workers
	workerWallNs   uint64 // Σ WorkerRuntimeStatus.wall_ns across workers
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
	lastWorkerActive uint64
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
func (s *Sampler) sample(now time.Time) {
	selfStat, statErr := s.proc.ReadSelfStat()
	if statErr != nil {
		return
	}
	daemonNs := ticksToNanos(selfStat.UtimeTicks + selfStat.StimeTicks)

	// Worker counters — userspace-dp only.
	workerActive, workerWall := s.lastWorkerActive, s.lastWorkerWall
	if s.dp != nil {
		if us, ok := s.dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			if st, err := us.Status(); err == nil {
				var a, w uint64
				for _, wr := range st.WorkerRuntime {
					a += wr.ActiveNS
					w += wr.WallNS
				}
				workerActive, workerWall = a, w
			}
		}
	}

	s.mu.Lock()
	s.ring[s.head] = cpuSample{
		wall:           now,
		daemonCPUNs:    daemonNs,
		workerActiveNs: workerActive,
		workerWallNs:   workerWall,
	}
	s.head = (s.head + 1) % ringSize
	s.count++
	s.lastWorkerActive = workerActive
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
// Worker activity% for the three windows, plus parallel validity
// flags.  A window is valid iff the snapshot contains a sample with
// wall ≤ newest.wall − W.
//
// Daemon %: (Δdaemon_cpu_ns / Δwall_ns) × 100 — per-core percent;
//          can exceed 100% on multi-core.
// Worker %: (Δworker_active_ns / Δworker_wall_ns) × 100 — fraction
//          of per-worker wall time spent in did_work=true iterations,
//          in [0, 100].  Zero when worker_wall didn't advance (eBPF
//          path or no workers).
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
		wallNs := uint64(wallDelta.Nanoseconds())
		daemonDelta := newest.daemonCPUNs - then.daemonCPUNs
		daemonPct[i] = float64(daemonDelta) * 100.0 / float64(wallNs)
		daemonValid[i] = true

		workerWallDelta := newest.workerWallNs - then.workerWallNs
		if workerWallDelta > 0 {
			workerActiveDelta := newest.workerActiveNs - then.workerActiveNs
			workerPct[i] = float64(workerActiveDelta) * 100.0 /
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
