package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"golang.org/x/sys/unix"
)

type fakePinnedTCLink struct {
	path     string
	unpinned bool
	closed   bool
}

func (f *fakePinnedTCLink) Unpin() error {
	f.unpinned = true
	return os.Remove(f.path)
}

func (f *fakePinnedTCLink) Close() error {
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
