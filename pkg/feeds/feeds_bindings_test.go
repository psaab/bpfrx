package feeds

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// installPrefixes seeds a feed's active snapshot directly so SnapshotForBindings
// has live prefixes to resolve, mirroring what a successful fetch would do.
func (m *Manager) installPrefixes(name string, prefixes []string) {
	fs := m.newFeed(name, "http://example.test/"+name, retainForever)
	m.mu.Lock()
	cp := make([]string, len(prefixes))
	copy(cp, prefixes)
	fs.prefixes = cp
	fs.hasSnapshot = true
	m.mu.Unlock()
}

func bindingCfg(bindings map[string][]string) *config.DynamicAddressConfig {
	ab := make(map[string]*config.AddressBinding, len(bindings))
	for name, feedNames := range bindings {
		ab[name] = &config.AddressBinding{Name: name, FeedNames: feedNames}
	}
	return &config.DynamicAddressConfig{AddressBindings: ab}
}

func TestSnapshotForBindingsResolvesSingleFeed(t *testing.T) {
	m := New(nil)
	m.installPrefixes("threat-feed", []string{"198.51.100.0/24", "203.0.113.0/24"})

	got := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"bad-actors": {"threat-feed"},
	}))
	want := map[string][]string{
		"bad-actors": {"198.51.100.0/24", "203.0.113.0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SnapshotForBindings = %v, want %v", got, want)
	}
}

func TestSnapshotForBindingsUnionsAndDedupsMultipleFeeds(t *testing.T) {
	m := New(nil)
	m.installPrefixes("feed-a", []string{"198.51.100.0/24", "10.0.0.0/8"})
	m.installPrefixes("feed-b", []string{"203.0.113.0/24", "10.0.0.0/8"}) // 10/8 overlaps feed-a

	got := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"aggregate": {"feed-a", "feed-b"},
	}))
	want := []string{"10.0.0.0/8", "198.51.100.0/24", "203.0.113.0/24"}
	sort.Strings(want)
	if !reflect.DeepEqual(got["aggregate"], want) {
		t.Fatalf("aggregate = %v, want deduped union %v", got["aggregate"], want)
	}
}

func TestSnapshotForBindingsEmptyForUnloadedFeed(t *testing.T) {
	m := New(nil)
	// "missing-feed" was never started/fetched; the binding still produces an
	// entry, but a non-nil empty slice (fail-closed: matches nothing). This is
	// the documented startup-before-first-fetch / unknown-feed case (#2049).
	got := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"pending": {"missing-feed"},
	}))
	prefixes, ok := got["pending"]
	if !ok {
		t.Fatalf("a feed-backed binding must be present in the overlay even when empty")
	}
	if prefixes == nil {
		t.Fatalf("empty binding must be a non-nil slice, got nil")
	}
	if len(prefixes) != 0 {
		t.Fatalf("unloaded feed must contribute no prefixes, got %v", prefixes)
	}
}

func TestSnapshotForBindingsNilWithoutBindings(t *testing.T) {
	m := New(nil)
	if got := m.SnapshotForBindings(nil); got != nil {
		t.Fatalf("nil config must yield nil overlay, got %v", got)
	}
	if got := m.SnapshotForBindings(&config.DynamicAddressConfig{}); got != nil {
		t.Fatalf("no bindings must yield nil overlay, got %v", got)
	}
}

// TestSnapshotForBindingsDeepCopy proves the returned slices are independent of
// the manager's internal state — a caller mutation must not corrupt the feed.
func TestSnapshotForBindingsDeepCopy(t *testing.T) {
	m := New(nil)
	m.installPrefixes("feed", []string{"198.51.100.0/24"})
	got := m.SnapshotForBindings(bindingCfg(map[string][]string{"name": {"feed"}}))
	got["name"][0] = "0.0.0.0/0" // mutate the caller's copy

	again := m.SnapshotForBindings(bindingCfg(map[string][]string{"name": {"feed"}}))
	if again["name"][0] != "198.51.100.0/24" {
		t.Fatalf("manager state corrupted by caller mutation: %v", again["name"])
	}
}
