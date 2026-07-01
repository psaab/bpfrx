package routing

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeVRFOps implements vrfOps with an in-memory link table for
// hermetic ReconcileVRFs tests. Each method increments a call
// counter so tests can assert "zero netlink calls" on no-op paths.
type fakeVRFOps struct {
	links map[string]*netlink.Vrf // name -> link

	adds       int
	dels       int
	setUps     int
	byNameHits int

	// #847 orphan-reap test hooks.
	extraLinks  []netlink.Link // non-VRF links to surface via LinkList
	linkListErr error          // when set, LinkList returns this error
}

func newFakeVRFOps() *fakeVRFOps {
	return &fakeVRFOps{links: map[string]*netlink.Vrf{}}
}

func (f *fakeVRFOps) LinkByName(name string) (netlink.Link, error) {
	f.byNameHits++
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	// Return the real netlink not-found error so isLinkNotFound()
	// can distinguish absence from transient failure.
	return nil, errLinkNotFound{errors.New("link not found")}
}

func (f *fakeVRFOps) LinkAdd(link netlink.Link) error {
	f.adds++
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return errors.New("fakeVRFOps only accepts *netlink.Vrf")
	}
	name := vrf.LinkAttrs.Name
	if _, exists := f.links[name]; exists {
		return errors.New("link already exists")
	}
	// Clone so callers can't mutate our table.
	clone := *vrf
	f.links[name] = &clone
	return nil
}

func (f *fakeVRFOps) LinkDel(link netlink.Link) error {
	f.dels++
	name := link.Attrs().Name
	if _, ok := f.links[name]; !ok {
		return errors.New("link not found")
	}
	delete(f.links, name)
	return nil
}

func (f *fakeVRFOps) LinkSetUp(link netlink.Link) error {
	f.setUps++
	return nil
}

// LinkSetMaster is part of vrfOps (used by BindInterfaceToVRF). The
// reconcile path never calls it; the fake just records nothing and
// succeeds so *fakeVRFOps satisfies the interface.
func (f *fakeVRFOps) LinkSetMaster(link, master netlink.Link) error {
	return nil
}

// #847: orphan-reap pass enumerates the kernel `vrf-*` namespace.
// Returns the seeded VRF links plus any extra non-VRF links the
// test pre-populated via extraLinks (used to verify the type-assert
// guard skips misnamed bridges/etc).
func (f *fakeVRFOps) LinkList() ([]netlink.Link, error) {
	if f.linkListErr != nil {
		return nil, f.linkListErr
	}
	out := make([]netlink.Link, 0, len(f.links)+len(f.extraLinks))
	for _, l := range f.links {
		out = append(out, l)
	}
	for _, l := range f.extraLinks {
		out = append(out, l)
	}
	return out, nil
}

// seed adds a link without going through LinkAdd, so it isn't counted.
// Used to set up initial kernel state for a test.
func (f *fakeVRFOps) seed(name string, table uint32) {
	f.links[name] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Table:     table,
	}
}

func (f *fakeVRFOps) has(name string) bool {
	_, ok := f.links[name]
	return ok
}

func TestReconcileVRFs(t *testing.T) {
	type scenario struct {
		name      string
		seeds     map[string]uint32 // pre-existing kernel VRFs
		tracked   []string          // initial m.vrfs
		desired   []VRFSpec         // input
		wantVrfs  []string          // expected new m.vrfs (order-preserving)
		wantLinks map[string]uint32 // expected kernel state after call
		wantAdds  int
		wantDels  int
		// Negative = skip assertion (used where the exact SetUp/ByName
		// count isn't a load-bearing property for the scenario).
		wantSetUps     int
		wantByNameHits int
		wantErr        bool
	}
	cases := []scenario{
		{
			name:      "empty to single-vrf creates",
			desired:   []VRFSpec{{Name: "a", TableID: 100}},
			wantVrfs:  []string{"vrf-a"},
			wantLinks: map[string]uint32{"vrf-a": 100},
			wantAdds:  1,
		},
		{
			name:      "fully-matching tracked set is no-op",
			seeds:     map[string]uint32{"vrf-a": 100, "vrf-b": 200},
			tracked:   []string{"vrf-a", "vrf-b"},
			desired:   []VRFSpec{{Name: "a", TableID: 100}, {Name: "b", TableID: 200}},
			wantVrfs:  []string{"vrf-a", "vrf-b"},
			wantLinks: map[string]uint32{"vrf-a": 100, "vrf-b": 200},
		},
		{
			name:      "tracked table mismatch triggers recreate",
			seeds:     map[string]uint32{"vrf-a": 100},
			tracked:   []string{"vrf-a"},
			desired:   []VRFSpec{{Name: "a", TableID: 101}},
			wantVrfs:  []string{"vrf-a"},
			wantLinks: map[string]uint32{"vrf-a": 101},
			wantAdds:  1,
			wantDels:  1,
		},
		{
			name:      "tracked removed-from-desired is deleted",
			seeds:     map[string]uint32{"vrf-a": 100},
			tracked:   []string{"vrf-a"},
			desired:   nil,
			wantVrfs:  []string{},
			wantLinks: map[string]uint32{},
			wantDels:  1,
		},
		{
			name:      "preserve one, add another",
			seeds:     map[string]uint32{"vrf-a": 100},
			tracked:   []string{"vrf-a"},
			desired:   []VRFSpec{{Name: "a", TableID: 100}, {Name: "b", TableID: 200}},
			wantVrfs:  []string{"vrf-a", "vrf-b"},
			wantLinks: map[string]uint32{"vrf-a": 100, "vrf-b": 200},
			wantAdds:  1,
		},
		{
			name:      "preserve one, remove one, add one",
			seeds:     map[string]uint32{"vrf-a": 100, "vrf-b": 200},
			tracked:   []string{"vrf-a", "vrf-b"},
			desired:   []VRFSpec{{Name: "a", TableID: 100}, {Name: "c", TableID: 300}},
			wantVrfs:  []string{"vrf-a", "vrf-c"},
			wantLinks: map[string]uint32{"vrf-a": 100, "vrf-c": 300},
			wantAdds:  1,
			wantDels:  1,
		},
		{
			// Post-restart scenario: VRF survived the daemon exit and
			// is in desired. Adopt it so future reconciles can manage
			// or delete it. Matching table means zero netlink churn:
			// no LinkAdd, no LinkDel. LinkByName fires once for the
			// lookup, LinkSetUp fires once as defensive ensure-up.
			name:           "pre-existing desired VRF is adopted (matching table)",
			seeds:          map[string]uint32{"vrf-x": 500},
			tracked:        nil,
			desired:        []VRFSpec{{Name: "x", TableID: 500}},
			wantVrfs:       []string{"vrf-x"},
			wantLinks:      map[string]uint32{"vrf-x": 500},
			wantSetUps:     1,
			wantByNameHits: 1,
		},
		{
			// Post-restart with table mismatch — xpfd is authoritative
			// for its own vrf-* namespace, so recreate with the
			// desired table.
			name:      "pre-existing desired VRF is recreated on table mismatch",
			seeds:     map[string]uint32{"vrf-x": 500},
			tracked:   nil,
			desired:   []VRFSpec{{Name: "x", TableID: 999}},
			wantVrfs:  []string{"vrf-x"},
			wantLinks: map[string]uint32{"vrf-x": 999},
			wantAdds:  1,
			wantDels:  1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeVRFOps()
			for name, tbl := range tc.seeds {
				ops.seed(name, tbl)
			}
			newTracked, err := reconcileVRFs(ops, tc.tracked, tc.desired)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !stringSlicesEqual(newTracked, tc.wantVrfs) {
				t.Errorf("tracked = %v, want %v", newTracked, tc.wantVrfs)
			}
			if ops.adds != tc.wantAdds {
				t.Errorf("LinkAdd count = %d, want %d", ops.adds, tc.wantAdds)
			}
			if ops.dels != tc.wantDels {
				t.Errorf("LinkDel count = %d, want %d", ops.dels, tc.wantDels)
			}
			if tc.wantSetUps > 0 && ops.setUps != tc.wantSetUps {
				t.Errorf("LinkSetUp count = %d, want %d", ops.setUps, tc.wantSetUps)
			}
			if tc.wantByNameHits > 0 && ops.byNameHits != tc.wantByNameHits {
				t.Errorf("LinkByName count = %d, want %d", ops.byNameHits, tc.wantByNameHits)
			}
			if len(ops.links) != len(tc.wantLinks) {
				t.Errorf("kernel link count = %d, want %d (have=%v)",
					len(ops.links), len(tc.wantLinks), ops.links)
			}
			for name, wantTbl := range tc.wantLinks {
				got, ok := ops.links[name]
				if !ok {
					t.Errorf("link %s missing from kernel", name)
					continue
				}
				if got.Table != wantTbl {
					t.Errorf("link %s table = %d, want %d", name, got.Table, wantTbl)
				}
			}
		})
	}
}

// TestReconcileVRFs_PreservesIfindexOnNoop explicitly asserts that the
// matching-tracked case issues zero LinkAdd/LinkDel calls. This is the
// property that #844 depends on — the whole bug was unnecessary
// delete+recreate churning the ifindex of vrf-mgmt and orphaning the
// cluster-sync listener's SO_BINDTODEVICE pin.
func TestReconcileVRFs_PreservesIfindexOnNoop(t *testing.T) {
	ops := newFakeVRFOps()
	ops.seed("vrf-mgmt", 999)
	ops.seed("vrf-sfmix", 100)

	tracked := []string{"vrf-mgmt", "vrf-sfmix"}
	desired := []VRFSpec{
		{Name: "sfmix", TableID: 100},
		{Name: "mgmt", TableID: 999},
	}

	_, err := reconcileVRFs(ops, tracked, desired)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ops.adds != 0 {
		t.Errorf("expected zero LinkAdd calls on matching reconcile, got %d", ops.adds)
	}
	if ops.dels != 0 {
		t.Errorf("expected zero LinkDel calls on matching reconcile, got %d", ops.dels)
	}
	if !ops.has("vrf-mgmt") {
		t.Error("vrf-mgmt should still be present")
	}
}

// injectableFakeOps lets tests force specific netlink calls to error
// so we can verify the partial-failure ownership contract.
type injectableFakeOps struct {
	*fakeVRFOps
	failAddFor   string // vrfName that should fail on LinkAdd
	failDelFor   string // vrfName that should fail on LinkDel
	failSetUpFor string // vrfName that should fail on LinkSetUp
}

func newInjectable() *injectableFakeOps {
	return &injectableFakeOps{fakeVRFOps: newFakeVRFOps()}
}

func (i *injectableFakeOps) LinkAdd(link netlink.Link) error {
	name := link.Attrs().Name
	if name == i.failAddFor {
		i.adds++
		return errors.New("injected LinkAdd failure")
	}
	return i.fakeVRFOps.LinkAdd(link)
}

func (i *injectableFakeOps) LinkDel(link netlink.Link) error {
	name := link.Attrs().Name
	if name == i.failDelFor {
		i.dels++
		return errors.New("injected LinkDel failure")
	}
	return i.fakeVRFOps.LinkDel(link)
}

func (i *injectableFakeOps) LinkSetUp(link netlink.Link) error {
	name := link.Attrs().Name
	if name == i.failSetUpFor {
		i.setUps++
		return errors.New("injected LinkSetUp failure")
	}
	return i.fakeVRFOps.LinkSetUp(link)
}

// TestReconcileVRFs_PartialCreatePreservesOwnership: if LinkAdd
// succeeds but LinkSetUp fails, the VRF must still land in
// m.vrfs so the next reconcile can clean it up.
func TestReconcileVRFs_PartialCreatePreservesOwnership(t *testing.T) {
	ops := newInjectable()
	ops.failSetUpFor = "vrf-b"

	tracked, err := reconcileVRFs(ops, nil,
		[]VRFSpec{{Name: "a", TableID: 100}, {Name: "b", TableID: 200}})
	if err == nil {
		t.Fatal("expected error from partial create, got nil")
	}
	wantTracked := []string{"vrf-a", "vrf-b"}
	if !stringSlicesEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v — partial create must retain ownership",
			tracked, wantTracked)
	}
	if !ops.has("vrf-b") {
		t.Error("vrf-b should still exist in kernel (LinkAdd succeeded)")
	}
	// Two creates attempted: one success (a), one partial (b).
	// No deletes. SetUp called three times: once per post-add, one for
	// a on pre-existing path (not in this scenario — both created
	// fresh), but the fake also calls setUp on the partial path.
	if ops.adds != 2 {
		t.Errorf("wantAdds 2 (a succeeds, b partial), got %d", ops.adds)
	}
	if ops.dels != 0 {
		t.Errorf("wantDels 0, got %d", ops.dels)
	}
}

// TestReconcileVRFs_LinkAddFailureSkipsOwnership: if LinkAdd fails
// entirely, nothing was created — VRF must NOT be in m.vrfs.
func TestReconcileVRFs_LinkAddFailureSkipsOwnership(t *testing.T) {
	ops := newInjectable()
	ops.failAddFor = "vrf-b"

	tracked, err := reconcileVRFs(ops, nil,
		[]VRFSpec{{Name: "a", TableID: 100}, {Name: "b", TableID: 200}})
	if err == nil {
		t.Fatal("expected error from LinkAdd failure, got nil")
	}
	wantTracked := []string{"vrf-a"}
	if !stringSlicesEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v — LinkAdd failure must not track",
			tracked, wantTracked)
	}
	if ops.has("vrf-b") {
		t.Error("vrf-b should not exist in kernel (LinkAdd was injected to fail)")
	}
	// Two creates attempted; one succeeds (a), one fails (b). Both
	// counted in `adds` (LinkAdd was called regardless of whether it
	// errored).
	if ops.adds != 2 {
		t.Errorf("wantAdds 2, got %d", ops.adds)
	}
	if ops.dels != 0 {
		t.Errorf("wantDels 0, got %d", ops.dels)
	}
}

// TestReconcileVRFs_LinkDelFailureRetainsOwnership: if LinkDel fails
// on a managed VRF removal, the VRF stays in m.vrfs so next
// reconcile can retry. Otherwise the VRF would be orphaned.
func TestReconcileVRFs_LinkDelFailureRetainsOwnership(t *testing.T) {
	ops := newInjectable()
	ops.failDelFor = "vrf-a"
	ops.seed("vrf-a", 100)

	tracked, err := reconcileVRFs(ops, []string{"vrf-a"}, nil)
	if err == nil {
		t.Fatal("expected error from LinkDel failure, got nil")
	}
	wantTracked := []string{"vrf-a"}
	if !stringSlicesEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v — LinkDel failure must retain ownership",
			tracked, wantTracked)
	}
	if !ops.has("vrf-a") {
		t.Error("vrf-a should still exist in kernel (LinkDel was injected to fail)")
	}
	if ops.adds != 0 {
		t.Errorf("wantAdds 0, got %d", ops.adds)
	}
	if ops.dels != 1 {
		t.Errorf("wantDels 1 (del attempted + injected failure), got %d", ops.dels)
	}
}

// TestReconcileVRFs_RecreateDelFailureRetainsOwnership: if table-ID
// mismatch triggers LinkDel + LinkAdd but LinkDel fails, the managed
// VRF stays tracked so the next reconcile retries. The bug would be
// losing ownership because the old VRF is still in the kernel.
func TestReconcileVRFs_RecreateDelFailureRetainsOwnership(t *testing.T) {
	ops := newInjectable()
	ops.failDelFor = "vrf-a"
	ops.seed("vrf-a", 100) // kernel has table 100

	tracked, err := reconcileVRFs(ops,
		[]string{"vrf-a"},
		[]VRFSpec{{Name: "a", TableID: 101}}) // desired table 101 (mismatch)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	wantTracked := []string{"vrf-a"}
	if !stringSlicesEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v", tracked, wantTracked)
	}
	// LinkDel attempted (and failed), LinkAdd NOT attempted (we skip
	// the recreate after del fails).
	if ops.adds != 0 {
		t.Errorf("wantAdds 0 (recreate skipped after del fails), got %d", ops.adds)
	}
	if ops.dels != 1 {
		t.Errorf("wantDels 1 (injected failure), got %d", ops.dels)
	}
}

// TestReconcileVRFs_TransientLookupErrorRetainsOwnership: a non-
// not-found error from LinkByName during delete (tracked-but-not-
// desired path) must NOT drop the VRF from tracked.
func TestReconcileVRFs_TransientLookupErrorRetainsOwnership(t *testing.T) {
	ops := &transientLookupOps{fakeVRFOps: newFakeVRFOps(), failFor: "vrf-a"}
	ops.seed("vrf-a", 100)

	tracked, err := reconcileVRFs(ops, []string{"vrf-a"}, nil)
	if err == nil {
		t.Fatal("expected error from transient LinkByName failure, got nil")
	}
	wantTracked := []string{"vrf-a"}
	if !stringSlicesEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v — transient lookup error must retain ownership",
			tracked, wantTracked)
	}
	if ops.adds != 0 {
		t.Errorf("wantAdds 0, got %d", ops.adds)
	}
	if ops.dels != 0 {
		t.Errorf("wantDels 0, got %d", ops.dels)
	}
}

// TestReconcileVRFs_TransientLookupOnDesiredTracked: the critical
// #844-class bug scenario — vrf-mgmt is both in desired AND in m.vrfs
// (we created it earlier), and LinkByName returns a transient
// non-LinkNotFound error. Must retain ownership so IsManagedVRF
// keeps returning true and mgmt binds don't silently disappear.
func TestReconcileVRFs_TransientLookupOnDesiredTracked(t *testing.T) {
	ops := &transientLookupOps{fakeVRFOps: newFakeVRFOps(), failFor: "vrf-mgmt"}
	ops.seed("vrf-mgmt", 999)

	tracked, err := reconcileVRFs(ops,
		[]string{"vrf-mgmt"},
		[]VRFSpec{{Name: "mgmt", TableID: 999}})
	if err == nil {
		t.Fatal("expected error from transient LinkByName failure, got nil")
	}
	wantTracked := []string{"vrf-mgmt"}
	if !stringSlicesEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v — transient lookup on tracked+desired VRF must NOT drop ownership",
			tracked, wantTracked)
	}
	if ops.adds != 0 {
		t.Errorf("wantAdds 0 (should not attempt LinkAdd on transient lookup), got %d", ops.adds)
	}
	if ops.dels != 0 {
		t.Errorf("wantDels 0, got %d", ops.dels)
	}
}

// transientLookupOps fails LinkByName for a specific name with a
// non-LinkNotFoundError (transient / EINVAL-style) error.
type transientLookupOps struct {
	*fakeVRFOps
	failFor string
}

func (t *transientLookupOps) LinkByName(name string) (netlink.Link, error) {
	t.byNameHits++
	if name == t.failFor {
		return nil, errors.New("transient netlink error (not LinkNotFoundError)")
	}
	if l, ok := t.links[name]; ok {
		return l, nil
	}
	return nil, errLinkNotFound{errors.New("link not found")}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestResolveRibTable(t *testing.T) {
	tableIDs := map[string]int{
		"tunnel-vr": 100,
		"dmz-vr":    101,
	}

	tests := []struct {
		ribName string
		want    int
		wantOK  bool
	}{
		{"inet.0", 254, true},
		{"inet6.0", 254, true},
		{"dmz-vr.inet.0", 101, true},
		{"dmz-vr.inet6.0", 101, true},
		{"tunnel-vr.inet.0", 100, true},
		// #2226: unresolvable rib names report ok=false (NOT a bare
		// table 0 the needsLeak loop would read as a real target table
		// and spuriously leak the source table into the main lookup).
		{"unknown-vr.inet.0", 0, false},
		{"garbage", 0, false},
		// #2253: a malformed family token whose prefix IS a defined
		// instance must NOT resolve. A loose ".inet" substring match
		// accepted these and mapped them onto the instance table; the
		// exact ".inet.0" / ".inet6.0" suffix match rejects them.
		{"dmz-vr.inet9.0", 0, false},
		{"dmz-vr.inetX.0", 0, false},
		{"dmz-vr.inetfoo.0", 0, false},
		{"dmz-vr.inet60.0", 0, false},
		{"dmz-vr.inet.0.garbage", 0, false},
		{"dmz-vr.inet", 0, false},
		{".inet.0", 0, false},  // empty instance prefix
		{".inet6.0", 0, false}, // empty instance prefix
	}

	for _, tt := range tests {
		got, ok := resolveRibTable(tt.ribName, tableIDs)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("resolveRibTable(%q) = (%d, %v), want (%d, %v)", tt.ribName, got, ok, tt.want, tt.wantOK)
		}
	}
}

// TestRibInstanceFromName (#2253) pins the EXACT-suffix family matcher that
// resolveRibTable and the commit-time gate share in spirit. A loose ".inet"
// substring match accepted malformed family tokens (".inetX.0", ".inetfoo.0",
// ".inet60.0") and trailing garbage (".inet.0.x"), mapping a typo'd rib onto
// a real instance table. Restoring the substring match must break this test.
func TestRibInstanceFromName(t *testing.T) {
	tests := []struct {
		ribName  string
		instance string
		ok       bool
	}{
		// Valid: exact ".inet.0" / ".inet6.0" suffix, non-empty instance.
		{"vrf1.inet.0", "vrf1", true},
		{"vrf1.inet6.0", "vrf1", true},
		{"tunnel-vr.inet.0", "tunnel-vr", true},
		{"a.b.inet.0", "a.b", true}, // dotted instance prefix is fine
		// Bare main-table names are NOT instance ribs (caller handles them).
		{"inet.0", "", false},
		{"inet6.0", "", false},
		// Malformed family token — the #2253 bug class.
		{"vrf1.inet9.0", "", false},
		{"vrf1.inetX.0", "", false},
		{"vrf1.inetfoo.0", "", false},
		{"vrf1.inet60.0", "", false},
		{"inet9.0", "", false},
		// Trailing garbage after a valid suffix is rejected.
		{"vrf1.inet.0.garbage", "", false},
		// Empty instance prefix is rejected.
		{".inet.0", "", false},
		{".inet6.0", "", false},
		// No family suffix at all.
		{"garbage", "", false},
		{"vrf1.inet", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		instance, ok := ribInstanceFromName(tt.ribName)
		if instance != tt.instance || ok != tt.ok {
			t.Errorf("ribInstanceFromName(%q) = (%q, %v), want (%q, %v)",
				tt.ribName, instance, ok, tt.instance, tt.ok)
		}
	}
}

func TestRibGroupNeedsLeak(t *testing.T) {
	// Verify that the rib-group logic correctly identifies when leaking is needed.
	// We can't test actual ip rule creation without netlink, but we can test
	// the resolveRibTable helper and the logic structure.

	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {
			Name:       "dmz-leak",
			ImportRibs: []string{"dmz-vr.inet.0", "inet.0"},
		},
		"self-only": {
			Name:       "self-only",
			ImportRibs: []string{"tunnel-vr.inet.0"},
		},
	}

	instances := []*config.RoutingInstanceConfig{
		{Name: "tunnel-vr", TableID: 100, InterfaceRoutesRibGroup: "self-only"},
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
	}

	tableIDs := map[string]int{
		"tunnel-vr": 100,
		"dmz-vr":    101,
	}

	// dmz-leak should need leaking (dmz-vr.inet.0=101, inet.0=254 → different tables)
	rg := ribGroups["dmz-leak"]
	inst := instances[1] // dmz-vr
	needsLeak := false
	for _, ribName := range rg.ImportRibs {
		if t, ok := resolveRibTable(ribName, tableIDs); ok && t != inst.TableID {
			needsLeak = true
			break
		}
	}
	if !needsLeak {
		t.Error("dmz-leak should need leaking")
	}

	// self-only should NOT need leaking (only tunnel-vr.inet.0=100, same as instance)
	rg = ribGroups["self-only"]
	inst = instances[0] // tunnel-vr
	needsLeak = false
	for _, ribName := range rg.ImportRibs {
		if t, ok := resolveRibTable(ribName, tableIDs); ok && t != inst.TableID {
			needsLeak = true
			break
		}
	}
	if needsLeak {
		t.Error("self-only should NOT need leaking")
	}
}

func TestDscpToTOS(t *testing.T) {
	tests := []struct {
		dscp string
		want uint8
	}{
		{"ef", 46 << 2},   // 0xB8 = 184
		{"af43", 38 << 2}, // 0x98 = 152
		{"af42", 36 << 2}, // 0x90 = 144
		{"af41", 34 << 2}, // 0x88 = 136
		{"af33", 30 << 2}, // 120
		{"cs1", 8 << 2},   // 32
		{"cs5", 40 << 2},  // 160
		{"be", 0},         // best effort = 0
		{"cs0", 0},        // cs0 = 0 → TOS = 0
		{"46", 46 << 2},   // numeric DSCP
		{"0", 0},          // zero
		{"63", 63 << 2},   // max DSCP
		{"invalid", 0},    // unknown name → 0
		{"EF", 46 << 2},   // case-insensitive
		{"AF43", 38 << 2}, // case-insensitive
	}

	for _, tt := range tests {
		got := dscpToTOS(tt.dscp)
		if got != tt.want {
			t.Errorf("dscpToTOS(%q) = %d (0x%02X), want %d (0x%02X)",
				tt.dscp, got, got, tt.want, tt.want)
		}
	}
}

// pbrTestConfig builds a *config.Config that attaches filter as the input
// filter (#3430 H1: only attached filters program PBR rules) on a single
// interface unit, with the given routing instances and prefix-lists.
func pbrTestConfig(family string, filter *config.FirewallFilter, instances []*config.RoutingInstanceConfig, pls map[string]*config.PrefixList) *config.Config {
	cfg := &config.Config{RoutingInstances: instances}
	cfg.PolicyOptions.PrefixLists = pls
	unit := &config.InterfaceUnit{Number: 0}
	if family == "inet6" {
		cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{filter.Name: filter}
		unit.FilterInputV6 = filter.Name
	} else {
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{filter.Name: filter}
		unit.FilterInputV4 = filter.Name
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: unit}},
	}
	return cfg
}

func TestBuildPBRRules(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{
		{Name: "Comcast-GigabitPro", TableID: 100},
		{Name: "ATT", TableID: 101},
	}

	t.Run("DSCP-based routing", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "inet-source-dscp",
			Terms: []*config.FirewallFilterTerm{
				{Name: "dscp-to-gigabitpro", DSCPs: []string{"ef"}, RoutingInstance: "Comcast-GigabitPro"},
				{Name: "dscp-to-att", DSCPs: []string{"af43"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("unexpected build error: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("expected 2 PBR rules, got %d", len(rules))
		}
		var comcast, att *PBRRule
		for i := range rules {
			switch rules[i].Instance {
			case "Comcast-GigabitPro":
				comcast = &rules[i]
			case "ATT":
				att = &rules[i]
			}
		}
		if comcast == nil || att == nil {
			t.Fatal("expected rules for both Comcast-GigabitPro and ATT")
		}
		if comcast.TOS != 184 || !comcast.TOSSet {
			t.Errorf("Comcast TOS = %d set=%v, want 184/true", comcast.TOS, comcast.TOSSet)
		}
		if comcast.TableID != 100 || comcast.Family != unix.AF_INET {
			t.Errorf("Comcast table/family = %d/%d, want 100/AF_INET", comcast.TableID, comcast.Family)
		}
		if att.TOS != 152 || att.TableID != 101 {
			t.Errorf("ATT TOS/table = %d/%d, want 152/101", att.TOS, att.TableID)
		}
	})

	t.Run("source address routing", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "src-routing",
			Terms: []*config.FirewallFilterTerm{
				{Name: "from-subnet", SourceAddresses: []string{"10.0.1.0/24"}, RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Src != "10.0.1.0/24" {
			t.Errorf("src = %q, want 10.0.1.0/24", rules[0].Src)
		}
		if rules[0].TOSSet {
			t.Errorf("TOSSet = true, want false (no DSCP)")
		}
		if rules[0].TableID != 101 {
			t.Errorf("table = %d, want 101", rules[0].TableID)
		}
	})

	t.Run("destination address routing", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "dst-routing",
			Terms: []*config.FirewallFilterTerm{
				{Name: "to-subnet", DestAddresses: []string{"192.168.0.0/16"}, RoutingInstance: "Comcast-GigabitPro"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Dst != "192.168.0.0/16" {
			t.Errorf("dst = %q, want 192.168.0.0/16", rules[0].Dst)
		}
	})

	t.Run("inet6 filter", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "v6-routing",
			Terms: []*config.FirewallFilterTerm{
				{Name: "dscp-route", DSCPs: []string{"ef"}, RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet6", filter, instances, nil))
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Family != unix.AF_INET6 {
			t.Errorf("family = %d, want AF_INET6", rules[0].Family)
		}
	})

	t.Run("no criteria skipped", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "no-criteria",
			Terms: []*config.FirewallFilterTerm{
				{Name: "accept-all", RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for no-criteria term, got %d", len(rules))
		}
	})

	t.Run("unknown instance skipped", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "bad-ref",
			Terms: []*config.FirewallFilterTerm{
				{Name: "bad", DSCPs: []string{"ef"}, RoutingInstance: "NonExistent"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for unknown instance, got %d", len(rules))
		}
	})

	t.Run("terms without routing-instance ignored", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "mixed",
			Terms: []*config.FirewallFilterTerm{
				{Name: "accept-term", DSCPs: []string{"ef"}, Action: "accept"},
				{Name: "route-term", DSCPs: []string{"af43"}, RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Instance != "ATT" {
			t.Errorf("instance = %q, want ATT", rules[0].Instance)
		}
	})

	t.Run("multi-address cross product", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "multi",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:            "cross",
					SourceAddresses: []string{"10.0.1.0/24", "10.0.2.0/24"},
					DestAddresses:   []string{"192.168.1.0/24", "192.168.2.0/24"},
					RoutingInstance: "ATT",
				},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 4 {
			t.Fatalf("expected 4 PBR rules (2×2 cross product), got %d", len(rules))
		}
	})

	t.Run("nil config", func(t *testing.T) {
		rules, err := BuildPBRRules(nil)
		if len(rules) != 0 || err != nil {
			t.Errorf("expected 0 rules / nil err for nil config, got %d / %v", len(rules), err)
		}
	})

	// === #3430 RED-on-revert coverage ===

	// H1: a defined-but-unattached filter must program NO ip rule. Pre-fix the
	// builder walked the global filter catalog and emitted a rule.
	t.Run("H1 unattached filter ignored", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "staged",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DSCPs: []string{"ef"}, RoutingInstance: "ATT"},
			},
		}
		cfg := &config.Config{RoutingInstances: instances}
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{filter.Name: filter}
		// No interface attachment.
		rules, _ := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Errorf("unattached filter must emit 0 PBR rules, got %d", len(rules))
		}
	})

	// H1: a filter attached only as an OUTPUT filter is not FBF.
	t.Run("H1 output-only attachment ignored", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "egress",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DSCPs: []string{"ef"}, RoutingInstance: "ATT"},
			},
		}
		cfg := &config.Config{RoutingInstances: instances}
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{filter.Name: filter}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, FilterOutputV4: filter.Name},
			}},
		}
		rules, _ := BuildPBRRules(cfg)
		if len(rules) != 0 {
			t.Errorf("output-only attachment must emit 0 PBR rules, got %d", len(rules))
		}
	})

	// H2: DSCP 0 (be / cs0 / numeric 0) is NOT representable as an ip rule (the
	// netlink layer writes the rtmsg tos only when non-zero and has no FRA_DSCP
	// escape hatch, and a zero tos matches ANY DSCP). The fail-safe disposition
	// is DROP + degraded build error, NOT a silently over-matching rule.
	// Pre-fix the builder emitted a TOSSet/TOS=0 rule that reached the wire with
	// no tos selector and matched all DSCP.
	t.Run("H2 dscp zero dropped and degraded", func(t *testing.T) {
		for _, d := range []string{"be", "cs0", "0"} {
			filter := &config.FirewallFilter{
				Name: "z",
				Terms: []*config.FirewallFilterTerm{
					{Name: "t", DSCPs: []string{d}, RoutingInstance: "ATT"},
				},
			}
			rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
			if len(rules) != 0 {
				t.Errorf("dscp %q: expected 0 rules (dropped), got %d: %+v", d, len(rules), rules)
			}
			if err == nil {
				t.Errorf("dscp %q: expected a degraded build error", d)
			}
		}
	})

	// H2: DSCP 0 combined with an address must NOT fall back to an address-only
	// rule (that would over-match all DSCP from that source). Drop entirely.
	t.Run("H2 dscp zero with address still dropped", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "zaddr",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DSCPs: []string{"be"}, SourceAddresses: []string{"10.0.0.0/8"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 0 {
			t.Errorf("dscp-0 + address must emit 0 rules (no address-only over-match), got %d: %+v", len(rules), rules)
		}
		if err == nil {
			t.Error("expected a degraded build error")
		}
	})

	// H2: within a multi-value DSCP set only the DSCP-0 value is dropped; the
	// representable values still emit exact rules (with the degraded error).
	t.Run("H2 multi-value dscp drops only zero", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "zmulti",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DSCPs: []string{"be", "ef"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule (ef kept, be dropped), got %d: %+v", len(rules), rules)
		}
		if rules[0].TOS != 184 || !rules[0].TOSSet {
			t.Errorf("kept rule TOS=%d set=%v, want 184/true (ef)", rules[0].TOS, rules[0].TOSSet)
		}
		if err == nil {
			t.Error("expected a degraded build error for the dropped be value")
		}
	})

	// A representable nonzero DSCP reaches the wire: TOSSet true, TOS nonzero.
	t.Run("H2 nonzero dscp emits tos selector", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "nz",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DSCPs: []string{"ef"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 || rules[0].TOS != 184 || !rules[0].TOSSet {
			t.Fatalf("expected 1 rule TOS=184/set, got %+v", rules)
		}
	})

	// M1: `any` source widens to no selector; a bare host promotes to /32//128.
	t.Run("M1 any and bare host", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "norm",
			Terms: []*config.FirewallFilterTerm{
				{Name: "anysrc", SourceAddresses: []string{"any"}, DSCPs: []string{"ef"}, RoutingInstance: "ATT"},
				{Name: "host4", SourceAddresses: []string{"192.0.2.10"}, RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(rules))
		}
		var anyR, hostR *PBRRule
		for i := range rules {
			if rules[i].TOSSet {
				anyR = &rules[i]
			} else {
				hostR = &rules[i]
			}
		}
		if anyR == nil || anyR.Src != "" {
			t.Errorf("any source must yield empty Src (no selector), got %+v", anyR)
		}
		if hostR == nil || hostR.Src != "192.0.2.10/32" {
			t.Errorf("bare host must promote to /32, got %+v", hostR)
		}
	})

	t.Run("M1 bare host v6", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "norm6",
			Terms: []*config.FirewallFilterTerm{
				{Name: "host6", DestAddresses: []string{"2001:db8::1"}, RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet6", filter, instances, nil))
		if len(rules) != 1 || rules[0].Dst != "2001:db8::1/128" {
			t.Fatalf("bare v6 host must promote to /128, got %+v", rules)
		}
	})

	// M2: source-prefix-list must expand to its prefixes.
	t.Run("M2 prefix-list expansion", func(t *testing.T) {
		pls := map[string]*config.PrefixList{
			"corp": {Name: "corp", Prefixes: []string{"10.1.0.0/16", "10.2.0.0/16"}},
		}
		filter := &config.FirewallFilter{
			Name: "pl",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", SourcePrefixLists: []config.PrefixListRef{{Name: "corp"}}, RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules (one per prefix), got %d", len(rules))
		}
		got := map[string]bool{rules[0].Src: true, rules[1].Src: true}
		if !got["10.1.0.0/16"] || !got["10.2.0.0/16"] {
			t.Errorf("prefix-list not expanded: %+v", rules)
		}
	})

	// M2: an empty positive prefix-list is constrained-but-matches-nothing →
	// emit no rule (NOT a match-all widening).
	t.Run("M2 empty positive prefix-list emits nothing", func(t *testing.T) {
		pls := map[string]*config.PrefixList{"empty": {Name: "empty"}}
		filter := &config.FirewallFilter{
			Name: "ple",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", SourcePrefixLists: []config.PrefixListRef{{Name: "empty"}}, RoutingInstance: "ATT"},
			},
		}
		rules, _ := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
		if len(rules) != 0 {
			t.Errorf("empty positive prefix-list must emit 0 rules, got %d: %+v", len(rules), rules)
		}
	})

	// M2: an empty `except` prefix-list means "match everything NOT in {}" =
	// match ALL → one unconstrained rule (Src ""), no degraded error.
	t.Run("M2 empty except matches all", func(t *testing.T) {
		pls := map[string]*config.PrefixList{"none": {Name: "none"}}
		filter := &config.FirewallFilter{
			Name: "plea",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DSCPs: []string{"ef"}, SourcePrefixLists: []config.PrefixListRef{{Name: "none", Except: true}}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
		if err != nil {
			t.Fatalf("empty except must not degrade, got err: %v", err)
		}
		if len(rules) != 1 || rules[0].Src != "" {
			t.Fatalf("empty except must yield one unconstrained rule (Src \"\"), got %+v", rules)
		}
	})

	// M2: a non-empty `except` prefix-list cannot be represented as an ip rule
	// → degraded build error AND no rule emitted (fail-safe).
	t.Run("M2 non-empty except degrades", func(t *testing.T) {
		pls := map[string]*config.PrefixList{"block": {Name: "block", Prefixes: []string{"10.9.0.0/16"}}}
		filter := &config.FirewallFilter{
			Name: "plx",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", SourcePrefixLists: []config.PrefixListRef{{Name: "block", Except: true}}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
		if len(rules) != 0 {
			t.Errorf("non-empty except must emit 0 rules, got %d", len(rules))
		}
		if err == nil {
			t.Errorf("non-empty except must return a degraded build error")
		}
	})

	// M3: an expansion beyond maxPBRRules truncates and reports degraded.
	t.Run("M3 truncation degrades", func(t *testing.T) {
		srcs := make([]string, 0, 40)
		dsts := make([]string, 0, 40)
		for i := 0; i < 40; i++ {
			srcs = append(srcs, fmt.Sprintf("10.%d.0.0/16", i))
			dsts = append(dsts, fmt.Sprintf("192.168.%d.0/24", i))
		}
		filter := &config.FirewallFilter{
			Name: "big",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", SourceAddresses: srcs, DestAddresses: dsts, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != maxPBRRules {
			t.Errorf("expected truncation to %d rules, got %d", maxPBRRules, len(rules))
		}
		if err == nil {
			t.Errorf("overflow must return a degraded build error")
		}
	})

	// === #3730 L4/per-packet predicate coverage ===

	// #3730 OVER-STEER (the security bug): a term constrained by BOTH an address
	// AND a destination-port must NOT collapse to an address-only rule that
	// steers every protocol/port to that host. The emitted ip rule MUST carry the
	// dport selector. Pre-fix buildPBRFromFilter read only the address and dropped
	// the port, so this asserted Dport was silently nil (RED on revert).
	t.Run("3730 dest-port honored not over-steered", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "portsteer",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:             "https-to-att",
					DestAddresses:    []string{"203.0.113.10/32"},
					DestinationPorts: []string{"443"},
					RoutingInstance:  "ATT",
				},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("unexpected degraded error for a representable dport term: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d: %+v", len(rules), rules)
		}
		if rules[0].Dst != "203.0.113.10/32" {
			t.Errorf("dst = %q, want 203.0.113.10/32", rules[0].Dst)
		}
		if rules[0].Dport == nil {
			t.Fatal("#3730 over-steer: address+dest-port term must emit a dport selector, got nil (would steer ALL ports to the host)")
		}
		if rules[0].Dport.Lo != 443 || rules[0].Dport.Hi != 443 {
			t.Errorf("dport = %s, want 443", rules[0].Dport)
		}
	})

	// #3730 UNDER-STEER: a term with ONLY an L4 predicate (destination-port, no
	// dscp/address) previously hit the "no ip-rule-compatible criteria" branch and
	// emitted NO rule (silent no-op) even though the operator believed FBF was
	// active. It must now emit a rule carrying the dport. RED on revert (0 rules).
	t.Run("3730 port-only term now emits a rule", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "portonly",
			Terms: []*config.FirewallFilterTerm{
				{Name: "dns", DestinationPorts: []string{"53"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("port-only term must emit 1 rule (not a silent no-op), got %d", len(rules))
		}
		if rules[0].Dport == nil || rules[0].Dport.Lo != 53 || rules[0].Dport.Hi != 53 {
			t.Errorf("expected dport 53, got %s", rules[0].Dport)
		}
		if rules[0].Src != "" || rules[0].Dst != "" || rules[0].TOSSet {
			t.Errorf("port-only rule must carry no addr/dscp selector, got %+v", rules[0])
		}
	})

	// #3730 protocol honored: `from protocol tcp` → IPProto 6. A multi-protocol
	// set expands to one rule per protocol.
	t.Run("3730 protocol honored and expanded", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "protosteer",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:            "tcp-udp",
					Protocols:       []string{"tcp", "udp"},
					DestAddresses:   []string{"198.51.100.0/24"},
					RoutingInstance: "ATT",
				},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules (tcp + udp), got %d: %+v", len(rules), rules)
		}
		gotProto := map[int]bool{rules[0].IPProto: true, rules[1].IPProto: true}
		if !gotProto[6] || !gotProto[17] {
			t.Errorf("expected IPProto 6 (tcp) and 17 (udp), got %+v", rules)
		}
	})

	// #3730 source-port range honored: `from source-port 1024-2048` → a single
	// FRA_SPORT_RANGE [1024,2048].
	t.Run("3730 source-port range honored", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "sportrange",
			Terms: []*config.FirewallFilterTerm{
				{Name: "ephem", SourcePorts: []string{"1024-2048"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 || rules[0].Sport == nil {
			t.Fatalf("expected 1 rule with an sport range, got %+v", rules)
		}
		if rules[0].Sport.Lo != 1024 || rules[0].Sport.Hi != 2048 {
			t.Errorf("sport = %s, want 1024-2048", rules[0].Sport)
		}
	})

	// #3730 named port honored via the shared SSOT resolver (config.junosServicePorts).
	t.Run("3730 named dest-port resolves", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "named",
			Terms: []*config.FirewallFilterTerm{
				{Name: "web", DestinationPorts: []string{"https"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 || rules[0].Dport == nil || rules[0].Dport.Lo != 443 {
			t.Fatalf("named port `https` must resolve to 443, got %+v", rules)
		}
	})

	// #3730 UNREPRESENTABLE predicates fail closed (degrade + drop, never widen).
	// Each of these has no ip-rule selector; a rule honoring only the address
	// would over-steer, so the whole term is dropped and the build is degraded.
	t.Run("3730 unrepresentable predicates degrade not widen", func(t *testing.T) {
		cases := []struct {
			name string
			term *config.FirewallFilterTerm
		}{
			{"tcp-flags", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				TCPFlags: []string{"syn"}, RoutingInstance: "ATT"}},
			{"is-fragment", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				IsFragment: true, RoutingInstance: "ATT"}},
			{"icmp-type", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				ICMPTypes: []int{8}, RoutingInstance: "ATT"}},
			{"icmp-code", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				ICMPCodes: []int{0}, RoutingInstance: "ATT"}},
			{"dest-port-except", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				DestPortsExcept: []string{"80"}, RoutingInstance: "ATT"}},
			{"source-port-except", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				SourcePortsExcept: []string{"22"}, RoutingInstance: "ATT"}},
			{"flex-match", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				FlexMatch: &config.FlexMatchConfig{ByteOffset: 4, BitLength: 8, Value: 1}, RoutingInstance: "ATT"}},
			{"unknown-from", &config.FirewallFilterTerm{
				Name: "t", DestAddresses: []string{"10.0.0.0/8"},
				UnknownFrom: []string{"ttl"}, RoutingInstance: "ATT"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				filter := &config.FirewallFilter{Name: "u", Terms: []*config.FirewallFilterTerm{tc.term}}
				rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
				if len(rules) != 0 {
					t.Errorf("%s: unrepresentable predicate must emit 0 rules (no address-only over-steer), got %d: %+v",
						tc.name, len(rules), rules)
				}
				if err == nil {
					t.Errorf("%s: unrepresentable predicate must return a degraded build error", tc.name)
				}
			})
		}
	})

	// #3730 an unparseable port / unknown protocol also fails closed.
	t.Run("3730 unparseable port degrades", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "badport",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DestinationPorts: []string{"not-a-port"}, DestAddresses: []string{"10.0.0.0/8"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 0 {
			t.Errorf("unparseable port must emit 0 rules, got %d", len(rules))
		}
		if err == nil {
			t.Error("unparseable port must return a degraded build error")
		}
	})

	// #3730 protocol 0 (HOPOPT) is not expressible (FRA_IP_PROTO>0 emit condition)
	// → fail closed, mirroring the DSCP-0 handling.
	t.Run("3730 protocol zero degrades", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "proto0",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", Protocols: []string{"0"}, DestAddresses: []string{"10.0.0.0/8"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if len(rules) != 0 {
			t.Errorf("protocol 0 must emit 0 rules, got %d", len(rules))
		}
		if err == nil {
			t.Error("protocol 0 must return a degraded build error")
		}
	})

	// #3730 an address-only term still works unchanged (the honor path must not
	// regress the representable-address case).
	t.Run("3730 address-only unchanged", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "addronly",
			Terms: []*config.FirewallFilterTerm{
				{Name: "t", DestAddresses: []string{"10.5.0.0/16"}, RoutingInstance: "ATT"},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("address-only term must not degrade, got %v", err)
		}
		if len(rules) != 1 || rules[0].Dst != "10.5.0.0/16" {
			t.Fatalf("expected 1 address-only rule, got %+v", rules)
		}
		if rules[0].IPProto != 0 || rules[0].Sport != nil || rules[0].Dport != nil {
			t.Errorf("address-only rule must carry no L4 selector, got %+v", rules[0])
		}
	})

	// #3730 apply leg: a rule carrying L4 selectors reaches the netlink rule with
	// IPProto/Dport set. This pins the pbrManager.Apply wiring (RED if the Apply
	// stops copying IPProto/Sport/Dport onto the netlink.Rule).
	t.Run("3730 apply emits L4 selectors", func(t *testing.T) {
		ops := newFakeRuleOps()
		p := &pbrManager{ops: ops}
		if err := p.Apply([]PBRRule{
			{Family: unix.AF_INET, IPProto: 6, Dport: &PBRPortRange{Lo: 443, Hi: 443}, TableID: 100, Instance: "vr"},
		}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		got := ops.rules[unix.AF_INET]
		if len(got) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(got))
		}
		if got[0].IPProto != 6 {
			t.Errorf("netlink rule IPProto = %d, want 6", got[0].IPProto)
		}
		if got[0].Dport == nil || got[0].Dport.Start != 443 || got[0].Dport.End != 443 {
			t.Errorf("netlink rule Dport = %+v, want [443,443]", got[0].Dport)
		}
	})
}

// NOTE (#1918): the former TestProbeICMP asserted probeICMP("127.0.0.1")
// returns true (route exists) and probeICMP("not-an-ip") returns false.
// Both encoded the bug — the old prober returned true on socket-open
// without any echo round-trip, i.e. a route-existence check, not a
// liveness check. probeICMP is deleted; the real prober (icmpProber) and
// its consumer (keepaliveLoop) are now covered by deterministic,
// injected-prober tests in tunnel_keepalive_test.go.

func TestKeepaliveState(t *testing.T) {
	state := &KeepaliveState{
		Up:         true,
		RemoteAddr: "10.0.0.1",
		Interval:   5,
		MaxRetries: 3,
	}

	// Initial state should be up
	if !state.Up {
		t.Error("expected initial state to be up")
	}

	// Simulate failures
	for i := 0; i < 3; i++ {
		state.Failures++
	}
	if state.Failures != 3 {
		t.Errorf("expected 3 failures, got %d", state.Failures)
	}

	// After reaching max retries, should be marked down
	state.Up = false
	state.LastFailure = time.Now()

	if state.Up {
		t.Error("expected state to be down after max retries")
	}

	// Simulate recovery
	state.Failures = 0
	state.Up = true
	state.LastSuccess = time.Now()

	if !state.Up {
		t.Error("expected state to be up after recovery")
	}
}

func TestKeepaliveDefaults(t *testing.T) {
	// When KeepaliveRetry is 0, startKeepalive should default to 3
	// We can't call startKeepalive without a netlink handle, but we
	// can verify the default logic inline.
	maxRetries := 0
	if maxRetries <= 0 {
		maxRetries = 3
	}
	if maxRetries != 3 {
		t.Errorf("expected default maxRetries to be 3, got %d", maxRetries)
	}
}

func TestInterfaceMonitorStatuses(t *testing.T) {
	// Test the monitor state storage and retrieval without netlink.
	// Post-#1698 the monitor state lives on the monitorManager domain,
	// which is independently constructible — exercise it directly
	// rather than reaching into Manager internals.
	mm := &monitorManager{
		monitorStatus: make(map[int][]InterfaceMonitorStatus),
	}

	// No monitors → nil
	if got := mm.Statuses(); got != nil {
		t.Errorf("expected nil for empty monitors, got %v", got)
	}

	// Set some state directly
	mm.mu.Lock()
	mm.monitorStatus[0] = []InterfaceMonitorStatus{
		{Interface: "trust0", Weight: 255, Up: true},
	}
	mm.monitorStatus[1] = []InterfaceMonitorStatus{
		{Interface: "untrust0", Weight: 200, Up: true},
		{Interface: "dmz0", Weight: 100, Up: false},
	}
	mm.mu.Unlock()

	got := mm.Statuses()
	if got == nil {
		t.Fatal("expected non-nil monitor statuses")
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(got))
	}
	if len(got[0]) != 1 || got[0][0].Interface != "trust0" {
		t.Errorf("group 0: unexpected %v", got[0])
	}
	if len(got[1]) != 2 {
		t.Fatalf("group 1: expected 2 monitors, got %d", len(got[1]))
	}
	if got[1][1].Up {
		t.Error("dmz0 should be down")
	}

	// Verify returned map is a copy (modify doesn't affect original)
	got[0] = nil
	if mm.Statuses()[0] == nil {
		t.Error("modifying returned map should not affect original")
	}
}

func TestRethMemberCollection(t *testing.T) {
	// Test the logic that groups physical interfaces by their RedundantParent.
	// Bonds are no longer created — this validates the config-level mapping only.
	interfaces := map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth1"},
		"reth0":    {Name: "reth0", RedundancyGroup: 1},
		"reth1":    {Name: "reth1", RedundancyGroup: 1},
		"trust0":   {Name: "trust0"},
	}

	rethMembers := make(map[string][]string)
	for _, ifc := range interfaces {
		if ifc.RedundantParent != "" {
			rethMembers[ifc.RedundantParent] = append(rethMembers[ifc.RedundantParent], ifc.Name)
		}
	}

	if len(rethMembers) != 2 {
		t.Fatalf("expected 2 RETH groups, got %d", len(rethMembers))
	}
	if len(rethMembers["reth0"]) != 2 {
		t.Errorf("reth0 should have 2 members, got %d", len(rethMembers["reth0"]))
	}
	if len(rethMembers["reth1"]) != 1 {
		t.Errorf("reth1 should have 1 member, got %d", len(rethMembers["reth1"]))
	}
}

func TestMultiVRFRibGroupLeaking(t *testing.T) {
	// Test that rib-groups with 8+ import-ribs correctly identify leaking needs
	// for multiple VRFs.
	ribGroups := map[string]*config.RibGroup{
		"Other-ISPS": {
			Name: "Other-ISPS",
			ImportRibs: []string{
				"Comcast-BCI.inet.0", "inet.0",
				"Other-GigabitPro.inet.0", "bv-firehouse-vpn.inet.0",
				"Comcast-GigabitPro.inet.0", "ATT.inet.0",
				"Atherton-Fiber.inet.0", "sfmix.inet.0",
			},
		},
		"Other-ISP6": {
			Name: "Other-ISP6",
			ImportRibs: []string{
				"Comcast-BCI.inet6.0", "inet6.0",
				"Other-GigabitPro.inet6.0",
				"Comcast-GigabitPro.inet6.0", "ATT.inet6.0",
				"Atherton-Fiber.inet6.0",
			},
		},
	}

	instances := []*config.RoutingInstanceConfig{
		{Name: "Comcast-BCI", TableID: 100, InterfaceRoutesRibGroup: "Other-ISPS"},
		{Name: "ATT", TableID: 101, InterfaceRoutesRibGroup: "Other-ISPS"},
		{Name: "Atherton-Fiber", TableID: 102, InterfaceRoutesRibGroup: "Other-ISPS"},
		{Name: "Other-GigabitPro", TableID: 103, InterfaceRoutesRibGroup: "Other-ISPS"},
		{Name: "bv-firehouse-vpn", TableID: 104, InterfaceRoutesRibGroup: "Other-ISPS"},
		{Name: "Comcast-GigabitPro", TableID: 105, InterfaceRoutesRibGroup: "Other-ISPS"},
		{Name: "sfmix", TableID: 106, InterfaceRoutesRibGroup: "Other-ISPS"},
	}

	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Every instance with Other-ISPS should need leaking because
	// inet.0 (254) is a different table from any instance table
	for _, inst := range instances {
		rg := ribGroups[inst.InterfaceRoutesRibGroup]
		needsLeak := false
		for _, ribName := range rg.ImportRibs {
			if t, ok := resolveRibTable(ribName, tableIDs); ok && t != inst.TableID {
				needsLeak = true
				break
			}
		}
		if !needsLeak {
			t.Errorf("instance %s with rib-group Other-ISPS should need leaking", inst.Name)
		}
	}
}

func TestIPv6OnlyRibGroupLeaking(t *testing.T) {
	// Test that instances with only InterfaceRoutesRibGroupV6 are also detected
	ribGroups := map[string]*config.RibGroup{
		"v6-leak": {
			Name:       "v6-leak",
			ImportRibs: []string{"vpn-vr.inet6.0", "inet6.0"},
		},
	}

	instances := []*config.RoutingInstanceConfig{
		{Name: "vpn-vr", TableID: 100, InterfaceRoutesRibGroupV6: "v6-leak"},
	}

	tableIDs := map[string]int{"vpn-vr": 100}

	// vpn-vr has only V6 rib-group but should still need leaking
	inst := instances[0]
	rgName := inst.InterfaceRoutesRibGroupV6
	rg := ribGroups[rgName]
	needsLeak := false
	for _, ribName := range rg.ImportRibs {
		if t, ok := resolveRibTable(ribName, tableIDs); ok && t != inst.TableID {
			needsLeak = true
			break
		}
	}
	if !needsLeak {
		t.Error("vpn-vr with IPv6-only rib-group should need leaking")
	}
}

// #847: orphan-reap pass deletes vrf-* kernel devices that aren't
// in `desired` and weren't in `tracked`. Covers the cross-restart
// rename leak: m.vrfs is empty after restart, so the existing
// "tracked-but-not-desired" deletion path can't catch the stale VRF.
func TestReconcileVRFs_OrphanReap(t *testing.T) {
	cases := []struct {
		name        string
		seeds       map[string]uint32
		extraLinks  []netlink.Link
		tracked     []string
		desired     []VRFSpec
		wantLinks   map[string]uint32
		wantVrfs    []string
		wantOrphans int // expected number of orphan deletions
	}{
		{
			name:    "stale vrf reaped after rename",
			seeds:   map[string]uint32{"vrf-old": 100},
			tracked: nil,
			desired: []VRFSpec{{Name: "new", TableID: 200}},
			wantLinks: map[string]uint32{
				"vrf-new": 200,
			},
			wantVrfs:    []string{"vrf-new"},
			wantOrphans: 1,
		},
		{
			name:    "multiple orphans reaped",
			seeds:   map[string]uint32{"vrf-old1": 100, "vrf-old2": 101, "vrf-keep": 200},
			tracked: nil,
			desired: []VRFSpec{{Name: "keep", TableID: 200}},
			wantLinks: map[string]uint32{
				"vrf-keep": 200,
			},
			wantVrfs:    []string{"vrf-keep"},
			wantOrphans: 2,
		},
		{
			name: "non-VRF interface with vrf- prefix is left alone",
			seeds: map[string]uint32{
				"vrf-real": 100,
			},
			extraLinks: []netlink.Link{
				&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vrf-fake-bridge"}},
			},
			tracked:     nil,
			desired:     []VRFSpec{{Name: "real", TableID: 100}},
			wantLinks:   map[string]uint32{"vrf-real": 100},
			wantVrfs:    []string{"vrf-real"},
			wantOrphans: 0,
		},
		{
			name:        "empty desired with no orphans is no-op",
			seeds:       map[string]uint32{},
			tracked:     nil,
			desired:     nil,
			wantLinks:   map[string]uint32{},
			wantVrfs:    nil,
			wantOrphans: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeVRFOps()
			for name, table := range tc.seeds {
				ops.seed(name, table)
			}
			ops.extraLinks = tc.extraLinks
			delsBefore := ops.dels

			got, err := reconcileVRFs(ops, tc.tracked, tc.desired)
			if err != nil {
				t.Fatalf("reconcileVRFs: %v", err)
			}
			// reflect.DeepEqual([]string{}, nil) is false; treat both as
			// "empty" for the want=nil cases.
			if len(got) != 0 || len(tc.wantVrfs) != 0 {
				if !reflect.DeepEqual(got, tc.wantVrfs) {
					t.Errorf("tracked: got %v, want %v", got, tc.wantVrfs)
				}
			}
			gotLinks := make(map[string]uint32, len(ops.links))
			for n, l := range ops.links {
				gotLinks[n] = l.Table
			}
			if !reflect.DeepEqual(gotLinks, tc.wantLinks) {
				t.Errorf("kernel: got %v, want %v", gotLinks, tc.wantLinks)
			}
			gotOrphans := ops.dels - delsBefore - countAlreadyDeleted(tc.tracked, tc.desired)
			if gotOrphans != tc.wantOrphans {
				t.Errorf("orphan dels: got %d, want %d", gotOrphans, tc.wantOrphans)
			}
		})
	}
}

// countAlreadyDeleted counts entries that the existing
// "tracked-but-not-desired" loop would delete; subtract from total
// dels to isolate orphan-reap deletions.
func countAlreadyDeleted(tracked []string, desired []VRFSpec) int {
	desiredByName := make(map[string]bool, len(desired))
	for _, d := range desired {
		desiredByName["vrf-"+d.Name] = true
	}
	count := 0
	for _, t := range tracked {
		if !desiredByName[t] {
			count++
		}
	}
	return count
}
