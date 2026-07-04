package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type fakePinnedTCLink struct {
	path     string
	unpinned bool
	closed   bool
	unpinErr error
	closeErr error
}

func (f *fakePinnedTCLink) Unpin() error {
	if f.unpinErr != nil {
		return f.unpinErr
	}
	f.unpinned = true
	return os.Remove(f.path)
}

func (f *fakePinnedTCLink) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	f.closed = true
	return nil
}

func TestUserspaceShimDNATMapCapacityMatchesLegacyPinnedMap(t *testing.T) {
	t.Parallel()

	specs := userspaceShimSharedMapSpecs()
	byName := make(map[string]uint32, len(specs))
	flagsByName := make(map[string]uint32, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec.MaxEntries
		flagsByName[spec.Name] = spec.Flags
	}
	for _, name := range []string{"dnat_table", "dnat_table_v6"} {
		if got := byName[name]; got != userspaceShimMaxSessions {
			t.Fatalf("%s max_entries = %d, want legacy-compatible %d",
				name, got, userspaceShimMaxSessions)
		}
		if flagsByName[name]&unix.BPF_F_NO_PREALLOC == 0 {
			t.Fatalf("%s flags = %#x, want BPF_F_NO_PREALLOC",
				name, flagsByName[name])
		}
	}
}

func TestEmbeddedUserspaceShimDNATMapMatchesSharedPinnedMap(t *testing.T) {
	t.Parallel()

	spec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load Rust userspace XDP spec: %v", err)
	}
	dnat := spec.Maps["dnat_table"]
	if dnat == nil {
		t.Fatal("Rust userspace XDP spec missing dnat_table")
	}
	if dnat.MaxEntries != userspaceShimMaxSessions {
		t.Fatalf("embedded dnat_table max_entries = %d, want %d",
			dnat.MaxEntries, userspaceShimMaxSessions)
	}
	if dnat.Flags&unix.BPF_F_NO_PREALLOC == 0 {
		t.Fatalf("embedded dnat_table flags = %#x, want BPF_F_NO_PREALLOC",
			dnat.Flags)
	}
}

func TestValidateUserspaceShimSpecDriftMentionsUserspaceXDPGenerate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec *ebpf.CollectionSpec
	}{
		{
			name: "bindings",
			spec: &ebpf.CollectionSpec{
				Maps: map[string]*ebpf.MapSpec{
					"userspace_bindings": {MaxEntries: BindingArrayMaxEntries - 1},
				},
			},
		},
		{
			name: "ingress-ifaces",
			spec: &ebpf.CollectionSpec{
				Maps: map[string]*ebpf.MapSpec{
					"userspace_bindings":       {MaxEntries: BindingArrayMaxEntries},
					"userspace_ingress_ifaces": {MaxEntries: MaxInterfaces - 1},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateUserspaceShimSpec(tt.spec)
			if err == nil {
				t.Fatal("validateUserspaceShimSpec succeeded, want drift error")
			}
			if !strings.Contains(err.Error(), "Re-run `make generate-userspace-xdp`.") {
				t.Fatalf("err = %v, want userspace XDP regeneration target", err)
			}
			if strings.Contains(err.Error(), "Re-run `make generate`.") {
				t.Fatalf("err = %v, should not point at legacy bpf2go generation", err)
			}
		})
	}
}

func TestLoadOrCreatePinnedShimMapRefusesIncompatiblePinnedMap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pin := filepath.Join(dir, "sessions")
	if err := os.WriteFile(pin, []byte("existing state"), 0600); err != nil {
		t.Fatalf("write pinned map marker: %v", err)
	}
	loadCalls := 0
	_, err := loadOrCreatePinnedShimMapWith(
		&ebpf.MapSpec{Name: "sessions"},
		dir,
		func(spec *ebpf.MapSpec, opts ebpf.MapOptions) (*ebpf.Map, error) {
			loadCalls++
			if spec.Name != "sessions" {
				t.Fatalf("spec.Name = %q, want sessions", spec.Name)
			}
			if opts.PinPath != dir {
				t.Fatalf("PinPath = %q, want %q", opts.PinPath, dir)
			}
			return nil, ebpf.ErrMapIncompatible
		},
	)
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Fatalf("err = %v, want ErrMapIncompatible", err)
	}
	if !strings.Contains(err.Error(), "refusing to reset incompatible userspace shim map") {
		t.Fatalf("err = %v, want fail-closed reset refusal", err)
	}
	if loadCalls != 1 {
		t.Fatalf("load calls = %d, want no destructive retry", loadCalls)
	}
	if got, err := os.ReadFile(pin); err != nil || string(got) != "existing state" {
		t.Fatalf("pinned map marker = %q, %v; want preserved state", got, err)
	}
}

func TestDisposablePinShapeMatches(t *testing.T) {
	t.Parallel()

	// The #4113 target spec: userspace_fallback_stats is a PerCpuArray<u64>
	// with 16 reason slots keyed by u32.
	want := &ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 16}
	tests := []struct {
		name       string
		pinType    ebpf.MapType
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		match      bool
	}{
		{"stale-array-from-old-daemon", ebpf.Array, 4, 8, 16, false},
		{"already-migrated-percpu", ebpf.PerCPUArray, 4, 8, 16, true},
		{"value-size-drift", ebpf.PerCPUArray, 4, 16, 16, false},
		{"max-entries-drift", ebpf.PerCPUArray, 4, 8, 32, false},
		{"key-size-drift", ebpf.PerCPUArray, 8, 8, 16, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := disposablePinShapeMatches(tt.pinType, tt.keySize, tt.valueSize, tt.maxEntries, want)
			if got != tt.match {
				t.Fatalf("disposablePinShapeMatches(%v, k=%d v=%d n=%d) = %v, want %v",
					tt.pinType, tt.keySize, tt.valueSize, tt.maxEntries, got, tt.match)
			}
		})
	}
}

// TestReconcileDisposableCollectionPinMigratesArrayToPerCPUArray reproduces the
// #4113 upgrade-brick: an old daemon left an Array pin for
// userspace_fallback_stats; the new daemon's PerCpuArray spec is incompatible,
// so the PinByName load fails with ErrMapIncompatible. The reconcile must drop
// the stale pin so the load recreates it fresh. Requires root + bpffs.
func TestReconcileDisposableCollectionPinMigratesArrayToPerCPUArray(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock (needs root): %v", err)
	}

	// Pins must live on a bpffs mount; t.TempDir() is tmpfs and cannot hold BPF
	// pins. Use a unique subdir under the real bpffs.
	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("xpf-test-4113-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Skipf("create bpffs test dir %s (needs root+bpffs): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	pinPath := filepath.Join(dir, userspaceFallbackStatsMapName)

	// Old daemon: a shared Array<u64> pinned counter map.
	oldArray, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       userspaceFallbackStatsMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		t.Skipf("create Array map (needs root): %v", err)
	}
	if err := oldArray.Pin(pinPath); err != nil {
		oldArray.Close()
		t.Skipf("pin Array map at %s: %v", pinPath, err)
	}
	oldArray.Close() // fd closed; pin persists, as across a daemon restart

	// New daemon spec: PerCpuArray, pinned by name (mirrors the collection load).
	newSpec := &ebpf.MapSpec{
		Name:       userspaceFallbackStatsMapName,
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
		Pinning:    ebpf.PinByName,
	}

	// Without the reconcile, PinByName load against the stale Array pin bricks.
	bricked, err := ebpf.NewMapWithOptions(newSpec, ebpf.MapOptions{PinPath: dir})
	if err == nil {
		bricked.Close()
		t.Fatal("PinByName load succeeded against stale Array pin; expected ErrMapIncompatible (brick)")
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Fatalf("PinByName load err = %v, want ErrMapIncompatible", err)
	}

	// The reconcile drops the incompatible disposable pin.
	if err := reconcileDisposableCollectionPin(pinPath, newSpec); err != nil {
		t.Fatalf("reconcileDisposableCollectionPin: %v", err)
	}
	if _, statErr := os.Stat(pinPath); !os.IsNotExist(statErr) {
		t.Fatalf("stale pin still present after reconcile: statErr=%v", statErr)
	}

	// Now the PinByName load succeeds and produces a PerCpuArray.
	migrated, err := ebpf.NewMapWithOptions(newSpec, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		t.Fatalf("PinByName load after reconcile: %v", err)
	}
	defer func() {
		_ = migrated.Unpin()
		_ = migrated.Close()
	}()
	if migrated.Type() != ebpf.PerCPUArray {
		t.Fatalf("migrated map type = %v, want PerCPUArray", migrated.Type())
	}

	// Idempotent: a second reconcile against the now-compatible pin is a no-op
	// (accumulated counters survive an ordinary restart).
	if err := reconcileDisposableCollectionPin(pinPath, newSpec); err != nil {
		t.Fatalf("reconcile on compatible pin: %v", err)
	}
	if _, statErr := os.Stat(pinPath); statErr != nil {
		t.Fatalf("compatible pin was removed by reconcile: %v", statErr)
	}
}

// TestReconcileDisposableCollectionPinNoOpOnRealEmbeddedSpec guards against a
// silent regression where the reconcile resets the counter on EVERY restart
// (losing accumulated counts) because the embedded PerCpuArray spec's reported
// shape does not match what a freshly created+pinned map of that spec reads
// back. It uses the REAL embedded userspace_fallback_stats spec, not a
// hand-built one. Requires root + bpffs.
func TestReconcileDisposableCollectionPinNoOpOnRealEmbeddedSpec(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock (needs root): %v", err)
	}
	collSpec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load Rust userspace XDP spec: %v", err)
	}
	spec := collSpec.Maps[userspaceFallbackStatsMapName]
	if spec == nil {
		t.Fatalf("embedded spec missing %s", userspaceFallbackStatsMapName)
	}
	if spec.Type != ebpf.PerCPUArray {
		t.Fatalf("embedded %s type = %v, want PerCPUArray (F13)", userspaceFallbackStatsMapName, spec.Type)
	}

	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("xpf-test-4113r-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Skipf("create bpffs test dir %s (needs root+bpffs): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pinPath := filepath.Join(dir, userspaceFallbackStatsMapName)

	pinSpec := spec.Copy()
	pinSpec.Pinning = ebpf.PinByName
	m, err := ebpf.NewMapWithOptions(pinSpec, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		t.Skipf("create+pin embedded spec (needs root): %v", err)
	}
	defer func() {
		_ = m.Unpin()
		_ = m.Close()
	}()

	// The reconcile must treat a pin created from the real embedded spec as
	// compatible (no reset), so counters survive an ordinary restart.
	if err := reconcileDisposableCollectionPin(pinPath, spec); err != nil {
		t.Fatalf("reconcile on real-spec pin: %v", err)
	}
	if _, statErr := os.Stat(pinPath); statErr != nil {
		t.Fatalf("reconcile removed a compatible real-spec pin: %v", statErr)
	}
}

func TestCleanupUserspaceShimLegacyOnlyMapPinsRemovesOnlyLegacyPins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{
		"xdp_progs",
		"tc_progs",
		"policer_states",
		"dnat_table",
		"sessions",
		"xdp_progs.bak",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pin"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := cleanupUserspaceShimLegacyOnlyMapPinsIn(dir, userspaceShimLegacyOnlyMapPins); err != nil {
		t.Fatalf("cleanup legacy-only map pins: %v", err)
	}

	for _, name := range userspaceShimLegacyOnlyMapPins {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after cleanup, err=%v", name, err)
		}
	}
	for _, name := range []string{"dnat_table", "sessions", "xdp_progs.bak"} {
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(got) != "pin" {
			t.Fatalf("%s = %q, %v; want preserved pin marker", name, got, err)
		}
	}
}

func TestCleanupUserspaceShimLegacyTCLinksDetachesTCPinsOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"tc_1", "tc_22", "tc_bad", "tc_", "xdp_1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pin"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	links := make(map[string]*fakePinnedTCLink)
	var loaded []string
	err := cleanupUserspaceShimLegacyTCLinksIn(dir, func(path string) (pinnedTCLink, error) {
		loaded = append(loaded, filepath.Base(path))
		link := &fakePinnedTCLink{path: path}
		links[filepath.Base(path)] = link
		return link, nil
	})
	if err != nil {
		t.Fatalf("cleanup legacy TC links: %v", err)
	}

	sort.Strings(loaded)
	if want := []string{"tc_1", "tc_22"}; !reflect.DeepEqual(loaded, want) {
		t.Fatalf("loaded pins = %v, want %v", loaded, want)
	}
	for _, name := range loaded {
		link := links[name]
		if link == nil || !link.unpinned || !link.closed {
			t.Fatalf("%s link state = %#v, want unpinned and closed", name, link)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after cleanup, err=%v", name, err)
		}
	}
	for _, name := range []string{"tc_bad", "tc_", "xdp_1"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s should be left alone, stat err=%v", name, err)
		}
	}
}

func TestCleanupUserspaceShimLegacyTCLinksContinuesAfterPinError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"tc_1", "tc_2"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pin"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	links := make(map[string]*fakePinnedTCLink)
	err := cleanupUserspaceShimLegacyTCLinksIn(dir, func(path string) (pinnedTCLink, error) {
		name := filepath.Base(path)
		link := &fakePinnedTCLink{path: path}
		if name == "tc_1" {
			link.unpinErr = errors.New("unpin failed")
		}
		links[name] = link
		return link, nil
	})
	if err == nil || !strings.Contains(err.Error(), "unpin failed") {
		t.Fatalf("err = %v, want aggregated first-pin failure", err)
	}
	if !links["tc_1"].closed {
		t.Fatalf("tc_1 close was not attempted after unpin failure")
	}
	if !links["tc_2"].unpinned || !links["tc_2"].closed {
		t.Fatalf("tc_2 state = %#v, want cleanup despite tc_1 failure", links["tc_2"])
	}
	if _, err := os.Stat(filepath.Join(dir, "tc_2")); !os.IsNotExist(err) {
		t.Fatalf("tc_2 still exists after cleanup, err=%v", err)
	}
}

func TestCleanupUserspaceShimLegacyTCLinksRemovesUnreadablePins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pin := filepath.Join(dir, "tc_9")
	if err := os.WriteFile(pin, []byte("pin"), 0600); err != nil {
		t.Fatalf("write pin: %v", err)
	}

	err := cleanupUserspaceShimLegacyTCLinksIn(dir, func(string) (pinnedTCLink, error) {
		return nil, errors.New("cannot load pinned link")
	})
	if err != nil {
		t.Fatalf("cleanup unreadable legacy TC link: %v", err)
	}
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Fatalf("unreadable TC pin still exists, err=%v", err)
	}
}
