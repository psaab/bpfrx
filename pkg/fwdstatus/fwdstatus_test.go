package fwdstatus

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// --- Format: label + value + order ---------------------------------

func TestFormat_LabelsAndOrderEBPF(t *testing.T) {
	fs := &ForwardingStatus{
		State: StateOnline,
		DaemonCPUWindows: [numCPUWindows]float64{4, 3, 2},
		DaemonCPUWindowValid: [numCPUWindows]bool{true, true, true},
		WorkerCPUMode:  CPUModeEBPFNoWorkers,
		HeapPercent:    72.0,
		BufferPercent:  83.0,
		BufferKnown:    true,
		Uptime:         474635 * time.Second,
	}
	out := Format(fs)
	wantLabelsInOrder := []string{
		"State",
		"Daemon CPU utilization",
		"Worker threads CPU utilization",
		"Heap utilization",
		"Buffer utilization",
		"Uptime:",
	}
	last := -1
	for _, l := range wantLabelsInOrder {
		idx := strings.Index(out, l)
		if idx < 0 {
			t.Errorf("missing label %q in output:\n%s", l, out)
			continue
		}
		if idx <= last {
			t.Errorf("label %q appeared out of order (idx=%d last=%d):\n%s", l, idx, last, out)
		}
		last = idx
	}
	if !strings.Contains(out, "Online") {
		t.Errorf("State missing: %s", out)
	}
	if !strings.Contains(out, "N/A") {
		t.Errorf("eBPF worker row should mention N/A: %s", out)
	}
	if !regexp.MustCompile(`\d+%`).MatchString(out) {
		t.Errorf("expected percentage: %s", out)
	}
}

func TestFormat_BufferUnknownUserspace(t *testing.T) {
	fs := &ForwardingStatus{
		State:              StateOnline,
		WorkerCPUMode:      CPUModeWorkers,
		WorkerCPUWindows:   [numCPUWindows]float64{45, 40, 35},
		WorkerCPUWindowValid: [numCPUWindows]bool{true, true, true},
		BufferKnown:        false,
		BufferFollowupRef:  878,
	}
	out := Format(fs)
	if !strings.Contains(out, "unknown (see #878)") {
		t.Errorf("expected unknown buffer with follow-up: %s", out)
	}
}

// BufferFollowupRef == 0 suppresses the "(see #N)" suffix — callers
// that don't have a follow-up issue shouldn't see `#0` rendered.
func TestFormat_BufferUnknownNoRef(t *testing.T) {
	fs := &ForwardingStatus{
		State:             StateOnline,
		BufferKnown:       false,
		BufferFollowupRef: 0,
	}
	out := Format(fs)
	if !regexp.MustCompile(`Buffer utilization\s+unknown$`).MatchString(strings.TrimRight(out, "\n")) &&
		!strings.Contains(out, "Buffer utilization                 unknown\n") {
		t.Errorf("expected plain 'unknown' with no #N, got: %s", out)
	}
	if strings.Contains(out, "#0") {
		t.Errorf("should not render #0: %s", out)
	}
}

func TestFormat_BufferKnownPercent(t *testing.T) {
	fs := &ForwardingStatus{
		State:         StateOnline,
		BufferKnown:   true,
		BufferPercent: 50.3,
	}
	out := Format(fs)
	if !regexp.MustCompile(`Buffer utilization\s+50 percent`).MatchString(out) {
		t.Errorf("expected buffer percent: %s", out)
	}
}

// TestFormat_NoClusterNote — fwdstatus is a pure single-block
// formatter post-#879. The cluster framing (node0:/node1: headers,
// peer block) is now composed in the gRPC handler, not here.
func TestFormat_NoClusterNote(t *testing.T) {
	fs := &ForwardingStatus{State: StateOnline}
	out := Format(fs)
	if strings.Contains(out, "peer-node rendering deferred") {
		t.Errorf("fwdstatus should no longer emit cluster note: %s", out)
	}
	if strings.Contains(out, "node0:") || strings.Contains(out, "node1:") {
		t.Errorf("fwdstatus should not render node headers: %s", out)
	}
}

func TestFormat_UptimeShape(t *testing.T) {
	fs := &ForwardingStatus{Uptime: (5*24+12)*time.Hour + 50*time.Minute + 35*time.Second}
	out := Format(fs)
	// "5 days, 12 hours, 50 minutes, 35 seconds"
	if !strings.Contains(out, "5 days, 12 hours, 50 minutes, 35 seconds") {
		t.Errorf("uptime shape wrong: %s", out)
	}
}

func TestFormat_HeapAndBufferClampButCPUDoesNot(t *testing.T) {
	fs := &ForwardingStatus{
		DaemonCPUWindows:     [numCPUWindows]float64{230.4, 230.4, 230.4}, // multi-core >100
		DaemonCPUWindowValid: [numCPUWindows]bool{true, true, true},
		WorkerCPUMode:        CPUModeWorkers,
		WorkerCPUWindows:     [numCPUWindows]float64{-3.0, -3.0, -3.0}, // negatives floor to 0
		WorkerCPUWindowValid: [numCPUWindows]bool{true, true, true},
		HeapPercent:          150.0,
		BufferKnown:          true,
		BufferPercent:        -5.0,
	}
	out := Format(fs)
	// 230% is honest per-core utilization — must not clamp
	if !regexp.MustCompile(`Daemon CPU utilization\s+230%\s*/\s*230%\s*/\s*230%`).MatchString(out) {
		t.Errorf("daemon CPU must not clamp to 100 (per-core): %s", out)
	}
	// negative worker CPU floors to 0
	if !regexp.MustCompile(`Worker threads CPU utilization\s+0%\s*/\s*0%\s*/\s*0%`).MatchString(out) {
		t.Errorf("expected worker CPU floored to 0: %s", out)
	}
	// 150% heap clamps to 100
	if !regexp.MustCompile(`Heap utilization\s+100 percent`).MatchString(out) {
		t.Errorf("expected heap clamped to 100: %s", out)
	}
	// -5% buffer clamps to 0
	if !regexp.MustCompile(`Buffer utilization\s+0 percent`).MatchString(out) {
		t.Errorf("expected buffer clamped to 0: %s", out)
	}
}

// --- State transitions: Build ---------------------------------------

// fakeDP is a DataPlaneAccessor for tests.  Set isUserspace=true to
// make Build treat it as userspace-dp (adds the Status method).
type fakeDP struct {
	loaded   bool
	mapStats []dataplane.MapStats
}

func (f *fakeDP) IsLoaded() bool                   { return f.loaded }
func (f *fakeDP) GetMapStats() []dataplane.MapStats { return f.mapStats }

type fakeUserspaceDP struct {
	fakeDP
	status userspace.ProcessStatus
	err    error
}

func (f *fakeUserspaceDP) Status() (userspace.ProcessStatus, error) {
	return f.status, f.err
}

// fakeProcReader injects canned /proc contents.
type fakeProcReader struct {
	selfStat    ProcSelfStat
	selfStatErr error
	selfStatm   ProcSelfStatm
	selfStatmErr error
	stat        ProcStat
	statErr     error
	memInfo     ProcMemInfo
	memInfoErr  error
	cgroupMax   uint64
	cgroupErr   error
}

func (f *fakeProcReader) ReadSelfStat() (ProcSelfStat, error) {
	return f.selfStat, f.selfStatErr
}
func (f *fakeProcReader) ReadSelfStatm() (ProcSelfStatm, error) {
	return f.selfStatm, f.selfStatmErr
}
func (f *fakeProcReader) ReadStat() (ProcStat, error) { return f.stat, f.statErr }
func (f *fakeProcReader) ReadMemInfo() (ProcMemInfo, error) {
	return f.memInfo, f.memInfoErr
}
func (f *fakeProcReader) ReadCgroupMemoryMax() (uint64, error) {
	return f.cgroupMax, f.cgroupErr
}

// freshProcReader returns a reader that parses clean with plausible
// values: ~100s uptime, moderate CPU accumulation, 16 GiB MemTotal.
func freshProcReader() *fakeProcReader {
	now := time.Now().Unix()
	// Daemon started 100 ticks (=1s when userHZ=100) after boot, and
	// boot was now-1000s ago, so daemon has been up ~999s.
	return &fakeProcReader{
		selfStat: ProcSelfStat{
			UtimeTicks:     50,
			StimeTicks:     50,
			StartTimeTicks: 100,
		},
		stat:      ProcStat{BootTime: uint64(now - 1000)},
		selfStatm: ProcSelfStatm{ResidentPages: 10000},
		memInfo:   ProcMemInfo{MemTotalBytes: 16 * 1024 * 1024 * 1024},
	}
}

func TestBuild_Online_eBPF(t *testing.T) {
	dp := &fakeDP{loaded: true, mapStats: []dataplane.MapStats{
		{Name: "sessions", MaxEntries: 100, UsedCount: 30},
	}}
	fs, err := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.State != StateOnline {
		t.Errorf("state: got %q, want Online", fs.State)
	}
	if fs.WorkerCPUMode != CPUModeEBPFNoWorkers {
		t.Error("eBPF path should set CPUModeEBPFNoWorkers")
	}
	if !fs.BufferKnown {
		t.Error("eBPF path: BufferKnown should be true")
	}
	if fs.BufferPercent != 30 {
		t.Errorf("Buffer%%: got %v, want 30", fs.BufferPercent)
	}
}

func TestBuild_Unknown_DpNil(t *testing.T) {
	fs, _ := Build(nil, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("dp==nil: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_NotLoaded(t *testing.T) {
	dp := &fakeDP{loaded: false}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("!IsLoaded: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_SelfStatErr(t *testing.T) {
	dp := &fakeDP{loaded: true}
	proc := freshProcReader()
	proc.selfStatErr = os.ErrNotExist
	fs, _ := Build(dp, proc, time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("selfStat err: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_StatmErr(t *testing.T) {
	dp := &fakeDP{loaded: true}
	proc := freshProcReader()
	proc.selfStatmErr = os.ErrNotExist
	fs, _ := Build(dp, proc, time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("statm err: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Unknown_UserspaceStatusErr(t *testing.T) {
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		err:    errors.New("status unavailable"),
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateUnknown {
		t.Errorf("userspace Status err: state %q, want Unknown", fs.State)
	}
}

func TestBuild_Degraded_StaleHeartbeat(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{
				now.Add(-500 * time.Millisecond),
				now.Add(-5 * time.Second), // stale
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateDegraded {
		t.Errorf("stale hb: state %q, want Degraded", fs.State)
	}
}

func TestBuild_Online_UserspaceFreshHeartbeats(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{
				now.Add(-100 * time.Millisecond),
				now.Add(-200 * time.Millisecond),
			},
			WorkerRuntime: []userspace.WorkerRuntimeStatus{
				{WallNS: 10_000_000_000, ThreadCPUNS: 3_000_000_000},
				{WallNS: 10_000_000_000, ThreadCPUNS: 2_000_000_000},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.State != StateOnline {
		t.Errorf("fresh hb: state %q, want Online", fs.State)
	}
	if fs.WorkerCPUMode != CPUModeWorkers {
		t.Error("userspace should set CPUModeWorkers")
	}
	// Worker CPU values now come from the sampler, not sum of
	// cumulative thread_cpu_ns at Build time. With an empty
	// SamplerSnapshot, all windows should be invalid.
	for i, v := range fs.WorkerCPUWindowValid {
		if v {
			t.Errorf("empty snapshot: WorkerCPUWindowValid[%d] should be false", i)
		}
	}
	if fs.BufferKnown {
		t.Error("userspace-dp Buffer should be unknown")
	}
	if fs.BufferFollowupRef != followupUMEMBuffer {
		t.Errorf("buffer follow-up: got %d, want %d", fs.BufferFollowupRef, followupUMEMBuffer)
	}
}

// #878 Buffer% derivation tests for the userspace-dp path. Pin the
// contract that:
//   - No bindings → BufferKnown=false (legacy "unknown" rendering).
//   - Pre-#878 helper (UmemTotalFrames=0) → still BufferKnown=false.
//   - Mixed bindings → only those with capacities count; max wins.
//   - max(umem%, tx%) per binding; max across bindings overall.

func TestBuild_UserspaceBuffer_NoBindings_StaysUnknown(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.BufferKnown {
		t.Error("no bindings: BufferKnown must stay false")
	}
	if fs.BufferFollowupRef != followupUMEMBuffer {
		t.Errorf("no bindings: BufferFollowupRef=%d, want %d", fs.BufferFollowupRef, followupUMEMBuffer)
	}
}

func TestBuild_UserspaceBuffer_PreHelper_StaysUnknown(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// Pre-#878 helper: capacities zero. Even with
				// nonzero OutstandingTX, must stay unknown.
				{UmemTotalFrames: 0, TxRingCapacity: 0, OutstandingTX: 100},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if fs.BufferKnown {
		t.Error("pre-#878 helper: BufferKnown must stay false")
	}
}

func TestBuild_UserspaceBuffer_UMEMHeavy(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// UMEM 80%, TX 5% → max = 80.
				{UmemTotalFrames: 1000, UmemInflightFrames: 800, TxRingCapacity: 200, OutstandingTX: 10},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferFollowupRef != 0 {
		t.Errorf("BufferFollowupRef=%d, want 0 once known", fs.BufferFollowupRef)
	}
	if fs.BufferPercent != 80.0 {
		t.Errorf("BufferPercent=%v, want 80", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_TXHeavy(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// UMEM 10%, TX 90% → max = 90.
				{UmemTotalFrames: 1000, UmemInflightFrames: 100, TxRingCapacity: 100, OutstandingTX: 90},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferPercent != 90.0 {
		t.Errorf("BufferPercent=%v, want 90", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_MaxAcrossBindings(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				{UmemTotalFrames: 1000, UmemInflightFrames: 100, TxRingCapacity: 100, OutstandingTX: 10}, // 10%
				{UmemTotalFrames: 1000, UmemInflightFrames: 750, TxRingCapacity: 100, OutstandingTX: 20}, // 75%
				{UmemTotalFrames: 1000, UmemInflightFrames: 50, TxRingCapacity: 100, OutstandingTX: 5},   // 5%
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferPercent != 75.0 {
		t.Errorf("BufferPercent=%v, want 75 (max across bindings)", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_MixedKnownAndUnknown(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// Skipped (UmemTotalFrames=0).
				{UmemTotalFrames: 0, OutstandingTX: 999},
				// Counted: 50%.
				{UmemTotalFrames: 200, UmemInflightFrames: 100, TxRingCapacity: 100, OutstandingTX: 30},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("at least one binding has capacities; BufferKnown must be true")
	}
	if fs.BufferPercent != 50.0 {
		t.Errorf("BufferPercent=%v, want 50 (only the binding with capacities counts)", fs.BufferPercent)
	}
}

func TestBuild_UserspaceBuffer_ClampedTo100(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{
				// Pathological: OutstandingTX > capacity (cross-field tearing or bug).
				{UmemTotalFrames: 100, UmemInflightFrames: 50, TxRingCapacity: 100, OutstandingTX: 200},
			},
		},
	}
	fs, _ := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true")
	}
	if fs.BufferPercent != 100.0 {
		t.Errorf("BufferPercent=%v, want 100 (clamped)", fs.BufferPercent)
	}
}

// (Cluster-mode rendering moved to the gRPC handler in #879;
// fwdstatus.Build no longer takes a clusterMode flag. Cluster
// composition tests live in pkg/grpcapi/.)
