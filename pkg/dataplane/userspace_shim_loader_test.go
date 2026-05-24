package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
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
