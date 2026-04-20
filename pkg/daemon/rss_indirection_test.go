// D3 RSS indirection tests (#785). Covers:
//   - weight-vector computation across edge cases (workers==1,
//     workers==queues, workers<queues, workers>queues).
//   - mlx5 vs non-mlx5 gating via fake sysfs.
//   - idempotent skip when the live table already matches.
//   - graceful skip when ethtool is missing.
//   - top-level kill-switch via the enabled argument (#797).
//   - twice-call idempotency on matching state (#797 Go LOW #3).
//
// No real NIC is required — ethtool, sysfs driver lookup, queue count,
// and netdev enumeration are all injected via the rssExecutor interface.
package daemon

import (
	"errors"
	"io/fs"
	"os/exec"
	"reflect"
	"testing"
)

// fakeRSSExecutor records ethtool invocations and replays scripted output.
type fakeRSSExecutor struct {
	// Interfaces visible to the sysfs scan. Order preserved as returned.
	ifaces []string
	// Per-iface driver name. Missing key → non-PCI / unknown; treated
	// as empty string (skip).
	drivers map[string]string
	// Per-iface RX queue count.
	queues map[string]int
	// Scripted ethtool -x <iface> output for idempotency probe.
	ethtoolX map[string][]byte
	// Recorded argvs, in call order. `{"-X", "eth0", "weight", "1", "1", "0", "0"}`, etc.
	calls [][]string
}

func (f *fakeRSSExecutor) runEthtool(args ...string) ([]byte, error) {
	cp := make([]string, len(args))
	copy(cp, args)
	f.calls = append(f.calls, cp)
	if len(args) >= 2 && args[0] == "-x" {
		if out, ok := f.ethtoolX[args[1]]; ok {
			return out, nil
		}
		// Wrap exec.ErrNotFound so errors.Is detects it — mirrors the
		// real *exec.Error shape returned by os/exec.
		return nil, &exec.Error{Name: "ethtool", Err: exec.ErrNotFound}
	}
	return nil, nil
}

func (f *fakeRSSExecutor) readDriver(iface string) string {
	return f.drivers[iface]
}

func (f *fakeRSSExecutor) readQueueCount(iface string) int {
	return f.queues[iface]
}

func (f *fakeRSSExecutor) listInterfaces() []string {
	return f.ifaces
}

func TestComputeWeightVector_WorkersOne_Skips(t *testing.T) {
	// Single-worker deploys get default RSS: pinning to queue 0 would
	// serialize the worker on one IRQ line. Reviewer #L1.
	v, reason := computeWeightVector(1, 6)
	if v != nil {
		t.Fatalf("workers=1 must skip, got %v", v)
	}
	if reason == "" {
		t.Fatal("expected a non-empty skip reason")
	}
}

func TestComputeWeightVector_FourOfSix(t *testing.T) {
	v, reason := computeWeightVector(4, 6)
	want := []int{1, 1, 1, 1, 0, 0}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("want %v, got %v (reason=%q)", want, v, reason)
	}
}

func TestComputeWeightVector_WorkersEqualsQueues_Skips(t *testing.T) {
	// workers==queues: default table already delivers to every queue.
	// No reshaping is useful; plan §2.3 says skip.
	v, _ := computeWeightVector(4, 4)
	if v != nil {
		t.Fatalf("workers==queues must skip, got %v", v)
	}
}

func TestComputeWeightVector_WorkersExceedsQueues_Skips(t *testing.T) {
	// The edge case from the brief: workers=5, queues=4.
	//
	// Defence: we cannot honor "hash onto queues 0..4" when only 4 queues
	// exist. Writing weight [1 1 1 1] is indistinguishable from the
	// default table (which is what the kernel has already); writing
	// anything else (e.g. [1 1 1 1 1] of length queues=4 would be
	// malformed) is not valid ethtool input.
	//
	// We skip *and log a warning* via the reason string. The caller
	// that logs "rss indirection skipped" surfaces this; operationally
	// this means "your userspace-dp worker count exceeds the HW queue
	// count — workers 5..N will still bind because AF_XDP queue binding
	// is handled separately, but RSS can't steer traffic to them."
	v, reason := computeWeightVector(5, 4)
	if v != nil {
		t.Fatalf("workers>queues must skip, got %v", v)
	}
	if reason == "" {
		t.Fatal("expected skip reason for workers>queues")
	}
}

func TestComputeWeightVector_GeneralizesTo4of8(t *testing.T) {
	// Reviewer flagged hardcoding "1 1 1 1 0 0". Confirm it generalizes.
	v, _ := computeWeightVector(4, 8)
	want := []int{1, 1, 1, 1, 0, 0, 0, 0}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("want %v, got %v", want, v)
	}
}

func TestComputeWeightVector_ZeroInputs(t *testing.T) {
	if v, _ := computeWeightVector(0, 6); v != nil {
		t.Fatalf("workers=0 must skip, got %v", v)
	}
	if v, _ := computeWeightVector(4, 0); v != nil {
		t.Fatalf("queues=0 must skip, got %v", v)
	}
}

// mlx5 detected → ethtool -X weight is issued with the expected argv.
func TestApplyRSSIndirectionOne_MlxWritesWeightVector(t *testing.T) {
	// Default-looking ethtool -x output: all 6 queues active.
	defaultTable := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     4     5
    8:      0     1     2     3     4     5
   16:      0     1     2     3     4     5
RSS hash key:
Operation not supported
`)
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": defaultTable},
	}
	applyRSSIndirectionOne("eth0", 4, f)

	// Expect two ethtool calls: probe then write.
	if len(f.calls) != 2 {
		t.Fatalf("want 2 ethtool calls, got %d: %v", len(f.calls), f.calls)
	}
	wantProbe := []string{"-x", "eth0"}
	if !reflect.DeepEqual(f.calls[0], wantProbe) {
		t.Fatalf("probe mismatch: want %v got %v", wantProbe, f.calls[0])
	}
	wantWrite := []string{"-X", "eth0", "weight", "1", "1", "1", "1", "0", "0"}
	if !reflect.DeepEqual(f.calls[1], wantWrite) {
		t.Fatalf("write mismatch: want %v got %v", wantWrite, f.calls[1])
	}
}

// Already-constrained table → no write.
func TestApplyRSSIndirectionOne_MatchingTable_SkipsWrite(t *testing.T) {
	// Live table only uses queues 0..3 (weight 1 1 1 1 0 0 applied
	// previously). ethtool distributes rows across the active queues.
	matchingTable := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     0     1
    8:      2     3     0     1     2     3
   16:      0     1     2     3     0     1
`)
	f := &fakeRSSExecutor{
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": matchingTable},
	}
	applyRSSIndirectionOne("eth0", 4, f)

	if len(f.calls) != 1 {
		t.Fatalf("want 1 ethtool call (probe only), got %d: %v", len(f.calls), f.calls)
	}
	if f.calls[0][0] != "-x" {
		t.Fatalf("want probe-only, got %v", f.calls[0])
	}
}

// Go MEDIUM #2 + #3: Non-mlx5 driver must short-circuit at the top-level
// scan, with no ethtool invocation at all. The test now actually calls
// applyRSSIndirection with a fake that owns both the interface list and
// the driver map — the driver guard is exercised for real.
func TestApplyRSSIndirection_NonMlx_Skips(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:  []string{"eth0", "eth1"},
		drivers: map[string]string{"eth0": "virtio_net", "eth1": "iavf"},
		queues:  map[string]int{"eth0": 4, "eth1": 4},
	}
	applyRSSIndirection(true, 4, f)
	if len(f.calls) != 0 {
		t.Fatalf("non-mlx5 interfaces must not trigger any ethtool call, got %v", f.calls)
	}
}

// Go HIGH #1 flavour: mixed interface set. Only the mlx5 interface
// receives ethtool writes; virtio/iavf siblings are untouched.
func TestApplyRSSIndirection_MixedDrivers_OnlyMlxTouched(t *testing.T) {
	defaultTable := []byte(`RX flow hash indirection table for mlx0 with 6 RX ring(s):
    0:      0     1     2     3     4     5
    8:      0     1     2     3     4     5
`)
	f := &fakeRSSExecutor{
		ifaces: []string{"lo", "virt0", "mlx0", "iavf0"},
		drivers: map[string]string{
			"virt0": "virtio_net",
			"mlx0":  "mlx5_core",
			"iavf0": "iavf",
		},
		queues:   map[string]int{"mlx0": 6, "virt0": 4, "iavf0": 4},
		ethtoolX: map[string][]byte{"mlx0": defaultTable},
	}
	applyRSSIndirection(true, 4, f)

	// All ethtool invocations must target mlx0 only.
	for _, c := range f.calls {
		if len(c) < 2 {
			t.Fatalf("malformed call: %v", c)
		}
		if c[1] != "mlx0" {
			t.Fatalf("ethtool invoked on non-mlx5 iface: %v", c)
		}
	}
	// And the write must have happened.
	sawWrite := false
	for _, c := range f.calls {
		if c[0] == "-X" {
			sawWrite = true
		}
	}
	if !sawWrite {
		t.Fatalf("expected a -X write on mlx0, got %v", f.calls)
	}
}

// ethtool binary missing on probe → function skips cleanly, no write.
func TestApplyRSSIndirectionOne_EthtoolMissing_SkipsGracefully(t *testing.T) {
	f := &fakeRSSExecutor{
		drivers: map[string]string{"eth0": "mlx5_core"},
		queues:  map[string]int{"eth0": 6},
		// No entry in ethtoolX → probe returns ErrNotFound.
	}
	applyRSSIndirectionOne("eth0", 4, f)
	// Exactly one call — the probe. No write because probe failed.
	if len(f.calls) != 1 || f.calls[0][0] != "-x" {
		t.Fatalf("want 1 probe-only call, got %v", f.calls)
	}
}

// Workers == 1 skips at the top level (no sysfs scan, no ethtool).
func TestApplyRSSIndirection_SingleWorker_Skips(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:  []string{"eth0"},
		drivers: map[string]string{"eth0": "mlx5_core"},
		queues:  map[string]int{"eth0": 4},
	}
	applyRSSIndirection(true, 1, f)
	if len(f.calls) != 0 {
		t.Fatalf("workers=1 must issue no ethtool calls, got %v", f.calls)
	}
}

// Workers == 0 skips at the top level.
func TestApplyRSSIndirection_ZeroWorkers_Skips(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces:  []string{"eth0"},
		drivers: map[string]string{"eth0": "mlx5_core"},
		queues:  map[string]int{"eth0": 4},
	}
	applyRSSIndirection(true, 0, f)
	if len(f.calls) != 0 {
		t.Fatalf("workers=0 must issue no ethtool calls, got %v", f.calls)
	}
}

// MEDIUM (Codex) rollback: when enabled=false the apply path short-
// circuits, and on mlx5 interfaces the kernel's default RSS table is
// restored via `ethtool -X <iface> default`. Non-mlx5 interfaces are
// untouched.
func TestApplyRSSIndirection_DisabledRestoresDefault(t *testing.T) {
	f := &fakeRSSExecutor{
		ifaces: []string{"lo", "virt0", "mlx0", "mlx1"},
		drivers: map[string]string{
			"virt0": "virtio_net",
			"mlx0":  "mlx5_core",
			"mlx1":  "mlx5_core",
		},
		queues: map[string]int{"mlx0": 6, "mlx1": 6, "virt0": 4},
	}
	applyRSSIndirection(false, 4, f)

	// Exactly one restore call per mlx5 interface; virt0/lo untouched.
	if len(f.calls) != 2 {
		t.Fatalf("want 2 restore calls (mlx0, mlx1), got %d: %v", len(f.calls), f.calls)
	}
	seen := map[string]bool{}
	for _, c := range f.calls {
		if len(c) != 3 || c[0] != "-X" || c[2] != "default" {
			t.Fatalf("expected `ethtool -X <iface> default`, got %v", c)
		}
		if d := f.drivers[c[1]]; d != "mlx5_core" {
			t.Fatalf("restore invoked on non-mlx5 iface %q (driver=%q)", c[1], d)
		}
		seen[c[1]] = true
	}
	if !seen["mlx0"] || !seen["mlx1"] {
		t.Fatalf("both mlx5 interfaces must be restored, saw %v", seen)
	}
}

// Go LOW #3: the idempotency claim must be demonstrated on repeated
// invocation. After the first call writes the weight vector, the second
// call sees a matching table and must not write again.
func TestApplyRSSIndirection_TwiceIsIdempotent(t *testing.T) {
	// We can't replay the kernel's actual post-write table from a pure
	// fake, but the semantics we need to pin are: "if the probe already
	// returns a matching layout, the second call issues exactly one more
	// ethtool call (the probe) and no write." Simulate that by pre-
	// populating ethtoolX with a matching table.
	matchingTable := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     0     1
    8:      2     3     0     1     2     3
`)
	f := &fakeRSSExecutor{
		ifaces:   []string{"eth0"},
		drivers:  map[string]string{"eth0": "mlx5_core"},
		queues:   map[string]int{"eth0": 6},
		ethtoolX: map[string][]byte{"eth0": matchingTable},
	}

	applyRSSIndirection(true, 4, f)
	if len(f.calls) != 1 || f.calls[0][0] != "-x" {
		t.Fatalf("first call: want probe-only, got %v", f.calls)
	}
	applyRSSIndirection(true, 4, f)
	if len(f.calls) != 2 {
		t.Fatalf("second call must be exactly +1 probe, got total %d: %v",
			len(f.calls), f.calls)
	}
	if f.calls[1][0] != "-x" {
		t.Fatalf("second call must be probe-only, got %v", f.calls[1])
	}
}

func TestIndirectionTableMatches_TrueWhenConstrained(t *testing.T) {
	// Table only uses queues 0..3; weights allow 4 active queues.
	out := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     0     1
    8:      2     3     0     1     2     3
RSS hash key:
...
`)
	if !indirectionTableMatches(out, []int{1, 1, 1, 1, 0, 0}) {
		t.Fatal("expected match")
	}
}

func TestIndirectionTableMatches_FalseWhenQueueOutOfRange(t *testing.T) {
	out := []byte(`RX flow hash indirection table for eth0 with 6 RX ring(s):
    0:      0     1     2     3     4     5
`)
	if indirectionTableMatches(out, []int{1, 1, 1, 1, 0, 0}) {
		t.Fatal("queue 4 and 5 appear: must not match")
	}
}

// Sanity: the production isExecNotFound detects the stable sentinel that
// `exec.Command("missing").CombinedOutput()` wraps, without substring
// matching (Go MEDIUM #1).
func TestIsExecNotFound_DetectsSentinel(t *testing.T) {
	wrapped := &exec.Error{Name: "ethtool", Err: exec.ErrNotFound}
	if !isExecNotFound(wrapped) {
		t.Fatal("expected true for wrapped exec.ErrNotFound")
	}
	fsPathErr := &fs.PathError{Op: "exec", Path: "ethtool", Err: exec.ErrNotFound}
	if !isExecNotFound(fsPathErr) {
		t.Fatal("expected true for PathError wrapping exec.ErrNotFound")
	}
	other := errors.New("some other error")
	if isExecNotFound(other) {
		t.Fatal("must not match unrelated errors")
	}
	if isExecNotFound(nil) {
		t.Fatal("nil must not match")
	}
}
