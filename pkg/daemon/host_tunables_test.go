// Unit tests for host-scope tunables (#801):
//   - CPU governor: resolves default + skip via empty/"default"; VM no-op
//     when cpufreq sysfs is absent; idempotent skip when already set;
//     graceful warning on read-only sysfs.
//   - netdev_budget: resolves default + 0-sentinel; idempotent when the
//     live /proc file already matches; graceful warning on EACCES.
//   - resolvedHostTunables: covers the userspace-dp default-substitution
//     matrix so daemon.go never accidentally applies the "performance"
//     default on a non-userspace-dp deploy.
//
// Every path is driven through the injectable hostTunableFS fake so
// tests never touch real /sys or /proc.
package daemon

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
)

// fakeHostFS records writes and optionally returns a scripted error.
type fakeHostFS struct {
	cpufreqPaths []string           // what listCPUGovernorPaths returns
	files        map[string][]byte  // pre-populated read values
	writeErrs    map[string]error   // per-path error on writeFile (nil = success)
	writes       map[string]string  // recorded writeFile data
	writeOrder   []string           // ordered log of writeFile paths
}

func newFakeHostFS() *fakeHostFS {
	return &fakeHostFS{
		files:     map[string][]byte{},
		writeErrs: map[string]error{},
		writes:    map[string]string{},
	}
}

func (f *fakeHostFS) listCPUGovernorPaths() []string { return f.cpufreqPaths }

func (f *fakeHostFS) readFile(path string) ([]byte, error) {
	if data, ok := f.files[path]; ok {
		return data, nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

func (f *fakeHostFS) writeFile(path string, data []byte) error {
	if err, ok := f.writeErrs[path]; ok && err != nil {
		return err
	}
	f.writes[path] = string(data)
	f.writeOrder = append(f.writeOrder, path)
	// Update the file so subsequent reads see what we just wrote
	// (mirrors real sysfs round-tripping).
	f.files[path] = append([]byte(nil), data...)
	return nil
}

// --- resolvedHostTunables -------------------------------------------------

func TestResolvedHostTunables_UserspaceDP_DefaultsSubstituted(t *testing.T) {
	gov, budget := resolvedHostTunables("", 0, true)
	if gov != defaultCPUGovernor {
		t.Errorf("want default governor %q, got %q", defaultCPUGovernor, gov)
	}
	if budget != defaultNetdevBudget {
		t.Errorf("want default budget %d, got %d", defaultNetdevBudget, budget)
	}
}

func TestResolvedHostTunables_NonUserspaceDP_NoSubstitution(t *testing.T) {
	// eBPF/DPDK deploys MUST keep the host's native values unless the
	// operator explicitly opted in. Prevents the #801 defaults from
	// leaking onto deploys the issue did not cover.
	gov, budget := resolvedHostTunables("", 0, false)
	if gov != "" {
		t.Errorf("non-userspace deploy must not get default governor, got %q", gov)
	}
	if budget != 0 {
		t.Errorf("non-userspace deploy must not get default budget, got %d", budget)
	}
}

func TestResolvedHostTunables_DefaultSentinel_NormalizedToSkip(t *testing.T) {
	// "default" is the operator's explicit opt-out — distinct from
	// omission. We normalize to "" so applyCPUGovernor's skip branch
	// is taken regardless of deploy type.
	gov, _ := resolvedHostTunables("default", 0, true)
	if gov != "" {
		t.Errorf("'default' must normalize to empty skip sentinel, got %q", gov)
	}
}

func TestResolvedHostTunables_ExplicitGovernorOverrideUserspaceDefault(t *testing.T) {
	gov, _ := resolvedHostTunables("schedutil", 0, true)
	if gov != "schedutil" {
		t.Errorf("explicit governor must override default, got %q", gov)
	}
}

func TestResolvedHostTunables_ExplicitBudgetOverrideUserspaceDefault(t *testing.T) {
	_, budget := resolvedHostTunables("", 1024, true)
	if budget != 1024 {
		t.Errorf("explicit budget must override default, got %d", budget)
	}
}

// --- applyCPUGovernor -----------------------------------------------------

func TestApplyCPUGovernor_EmptyString_Skip(t *testing.T) {
	// Mirrors "no config" — every writeable cpufreq node must be
	// untouched. This is the non-userspace-dp default path.
	f := newFakeHostFS()
	f.cpufreqPaths = []string{"/sys/cpu0/scaling_governor"}
	applyCPUGovernor("", f)
	if len(f.writes) != 0 {
		t.Fatalf("empty governor must not write, got %v", f.writes)
	}
}

func TestApplyCPUGovernor_NoCpufreqSysfs_VMNoOp(t *testing.T) {
	// Every xpf VM hits this path: `performance` is requested but
	// cpufreq is not exposed by QEMU/KVM. Must not panic, must not
	// error, must not write.
	f := newFakeHostFS() // cpufreqPaths = nil
	applyCPUGovernor("performance", f)
	if len(f.writes) != 0 {
		t.Fatalf("VM no-op must not write, got %v", f.writes)
	}
}

func TestApplyCPUGovernor_WritesOnceAcrossAllCPUs(t *testing.T) {
	f := newFakeHostFS()
	f.cpufreqPaths = []string{
		"/sys/cpu0/scaling_governor",
		"/sys/cpu1/scaling_governor",
		"/sys/cpu2/scaling_governor",
		"/sys/cpu3/scaling_governor",
	}
	// Pre-seed all four at schedutil so every one gets rewritten.
	for _, p := range f.cpufreqPaths {
		f.files[p] = []byte("schedutil\n")
	}
	applyCPUGovernor("performance", f)
	if len(f.writes) != 4 {
		t.Fatalf("want 4 writes (one per cpu), got %d: %v", len(f.writes), f.writes)
	}
	for _, p := range f.cpufreqPaths {
		if f.writes[p] != "performance" {
			t.Errorf("%s: want performance, got %q", p, f.writes[p])
		}
	}
}

func TestApplyCPUGovernor_IdempotentWhenAlreadySet(t *testing.T) {
	f := newFakeHostFS()
	f.cpufreqPaths = []string{
		"/sys/cpu0/scaling_governor",
		"/sys/cpu1/scaling_governor",
	}
	f.files["/sys/cpu0/scaling_governor"] = []byte("performance\n")
	f.files["/sys/cpu1/scaling_governor"] = []byte("performance")
	applyCPUGovernor("performance", f)
	if len(f.writes) != 0 {
		t.Fatalf("already-set must skip every write, got %v", f.writes)
	}
}

func TestApplyCPUGovernor_PartialFailure_ContinuesOtherCPUs(t *testing.T) {
	// Read-only sysfs on one CPU (rare but possible in chroots) must
	// not abort the walk — other CPUs still get the write.
	f := newFakeHostFS()
	f.cpufreqPaths = []string{
		"/sys/cpu0/scaling_governor",
		"/sys/cpu1/scaling_governor",
	}
	f.writeErrs["/sys/cpu0/scaling_governor"] = &fs.PathError{
		Op: "write", Path: "/sys/cpu0/scaling_governor", Err: fs.ErrPermission,
	}
	applyCPUGovernor("performance", f)
	if _, ok := f.writes["/sys/cpu1/scaling_governor"]; !ok {
		t.Fatal("cpu1 must be written even after cpu0 failed")
	}
	if _, ok := f.writes["/sys/cpu0/scaling_governor"]; ok {
		t.Fatal("cpu0 write recorded despite scripted error")
	}
}

// --- applyNetdevBudget ---------------------------------------------------

func TestApplyNetdevBudget_ZeroSentinel_Skip(t *testing.T) {
	f := newFakeHostFS()
	applyNetdevBudget(0, f)
	if len(f.writes) != 0 {
		t.Fatalf("value=0 must skip, got %v", f.writes)
	}
}

func TestApplyNetdevBudget_Negative_Skip(t *testing.T) {
	// Defensive — a nonsensical value must not be propagated to the
	// kernel. (The kernel would reject it, but we log and skip instead
	// of spamming warnings on every reconcile.)
	f := newFakeHostFS()
	applyNetdevBudget(-1, f)
	if len(f.writes) != 0 {
		t.Fatalf("negative value must skip, got %v", f.writes)
	}
}

func TestApplyNetdevBudget_Writes600(t *testing.T) {
	f := newFakeHostFS()
	f.files[sysctlPathNetdevBudget] = []byte("300\n")
	applyNetdevBudget(600, f)
	if f.writes[sysctlPathNetdevBudget] != "600" {
		t.Fatalf("want 600 written, got %q", f.writes[sysctlPathNetdevBudget])
	}
}

func TestApplyNetdevBudget_IdempotentWhenAlreadySet(t *testing.T) {
	f := newFakeHostFS()
	f.files[sysctlPathNetdevBudget] = []byte("600\n")
	applyNetdevBudget(600, f)
	if len(f.writes) != 0 {
		t.Fatalf("already-set must skip write, got %v", f.writes)
	}
}

func TestApplyNetdevBudget_ReadOnlyProc_LogsAndContinues(t *testing.T) {
	// Unprivileged container surfaces as EACCES on write. Must log
	// (not panic) and return cleanly so daemon startup is not blocked.
	f := newFakeHostFS()
	f.files[sysctlPathNetdevBudget] = []byte("300\n")
	f.writeErrs[sysctlPathNetdevBudget] = &fs.PathError{
		Op: "write", Path: sysctlPathNetdevBudget, Err: fs.ErrPermission,
	}
	applyNetdevBudget(600, f)
	if _, ok := f.writes[sysctlPathNetdevBudget]; ok {
		t.Fatal("write recorded despite scripted EACCES")
	}
}

// Sanity: errors.Is compatibility is the glue that lets the real
// applyNetdevBudget distinguish EACCES from other errors. Catches any
// future regression in the fake or the production isPermissionErr
// pattern.
func TestFakeHostFS_ErrorSurface(t *testing.T) {
	f := newFakeHostFS()
	f.writeErrs["/x"] = &fs.PathError{Op: "write", Path: "/x", Err: fs.ErrPermission}
	err := f.writeFile("/x", []byte("v"))
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("fake must preserve fs.ErrPermission, got %T", err)
	}
}

// End-to-end sanity: applyHostTunables composes both without the
// caller having to know about either. Uses the same fake; checks both
// writes happen.
func TestApplyHostTunables_AppliesBoth(t *testing.T) {
	f := newFakeHostFS()
	f.cpufreqPaths = []string{"/sys/cpu0/scaling_governor"}
	f.files["/sys/cpu0/scaling_governor"] = []byte("schedutil")
	f.files[sysctlPathNetdevBudget] = []byte("300")
	applyHostTunables("performance", 600, f)

	wantOrder := []string{"/sys/cpu0/scaling_governor", sysctlPathNetdevBudget}
	if !reflect.DeepEqual(f.writeOrder, wantOrder) {
		t.Fatalf("write order: want %v, got %v", wantOrder, f.writeOrder)
	}
}
