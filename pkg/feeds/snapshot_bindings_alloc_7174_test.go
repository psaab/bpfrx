package feeds

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7174 C12b: SnapshotForBindings must pre-size its union from the constituent
// feeds' known lengths instead of regrowing an unsized slice and map.
//
// This is an ALLOCATION fix with byte-identical output, so no assertion over
// the returned data can fail for the reason the fix exists. The observable
// property is the allocation count, and it discriminates cleanly. Measured on
// this fixture (4 feeds x 2000 prefixes):
//
//	pre-sized (this change):  36 allocations
//	unsized   (before):       98 allocations
//
// The bound is set between them with margin either way, so a Go-version drift
// in the constant overhead does not red it while a revert to unsized regrowth
// does. If this ever fails at a number near 36 rather than near 98, the
// regression is elsewhere and the bound should be re-measured rather than
// raised.
//
// The row this closes says the defect is "no aggregate union budget". The
// ruling was to bound the ALLOCATION, not the data: capping the prefix set
// would truncate security policy, and truncating a deny-list fails OPEN while
// truncating an allow-list fails CLOSED — the same code with opposite failure
// directions depending on use. That decision belongs in its own issue, not in
// an allocation row.
const snapshotBindingsAllocBound = 60

func TestSnapshotForBindingsPreSizesItsUnion_7174(t *testing.T) {
	const nFeeds, nPrefix = 4, 2000
	m := &Manager{feeds: map[string]*feedState{}}
	names := make([]string, 0, nFeeds)
	for f := 0; f < nFeeds; f++ {
		name := fmt.Sprintf("feed%d", f)
		ps := make([]string, 0, nPrefix)
		for i := 0; i < nPrefix; i++ {
			// Distinct across feeds, so dedup removes nothing and the union is
			// the full sum — the worst case for an unsized append.
			ps = append(ps, fmt.Sprintf("10.%d.%d.%d/32", f, i/256, i%256))
		}
		m.feeds[name] = &feedState{prefixes: ps}
		names = append(names, name)
	}
	cfg := &config.DynamicAddressConfig{AddressBindings: map[string]*config.AddressBinding{
		"binding": {FeedNames: names},
	}}

	// PREMISE: the binding must actually resolve. If it were omitted (an
	// unready constituent) the function would allocate almost nothing and this
	// would pass having measured the empty path.
	got := m.SnapshotForBindings(cfg)
	if len(got["binding"]) != nFeeds*nPrefix {
		t.Fatalf("premise: binding resolved to %d prefixes, want %d — the "+
			"allocation assertion below would be measuring the omitted path",
			len(got["binding"]), nFeeds*nPrefix)
	}

	allocs := testing.AllocsPerRun(20, func() { m.SnapshotForBindings(cfg) })
	if allocs > snapshotBindingsAllocBound {
		t.Errorf("SnapshotForBindings made %v allocations, want <= %d — the "+
			"union is regrowing instead of being pre-sized from the "+
			"constituent feeds' lengths (#7174 C12b). Unsized measured 98 on "+
			"this fixture; pre-sized measured 36",
			allocs, snapshotBindingsAllocBound)
	}
}

// The readiness pre-pass must still OMIT a binding with any unready
// constituent — the #5645 fail-closed contract. Moving readiness out of the
// merge loop is where that could regress silently, because the omitted and
// merged paths both return a map and only the key's presence differs.
func TestSnapshotForBindingsStillOmitsUnreadyBinding_7174(t *testing.T) {
	m := &Manager{feeds: map[string]*feedState{
		"ready":   {prefixes: []string{"10.0.0.0/8"}},
		"unready": {prefixes: nil},
	}}
	cfg := &config.DynamicAddressConfig{AddressBindings: map[string]*config.AddressBinding{
		"mixed": {FeedNames: []string{"ready", "unready"}},
	}}
	got := m.SnapshotForBindings(cfg)
	if _, present := got["mixed"]; present {
		t.Errorf("a binding with an unready constituent must be OMITTED so the "+
			"referencing policy stays unresolved and fails CLOSED (#5645); got %v", got)
	}
}
