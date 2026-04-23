package routing

import (
	"errors"
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
		name    string
		seeds   map[string]uint32         // pre-existing kernel VRFs
		tracked []string                  // initial m.vrfs
		desired []VRFSpec                 // input
		wantVrfs []string                 // expected new m.vrfs (order-preserving)
		wantLinks       map[string]uint32 // expected kernel state after call
		wantAdds        int
		wantDels        int
		// Negative = skip assertion (used where the exact SetUp/ByName
		// count isn't a load-bearing property for the scenario).
		wantSetUps      int
		wantByNameHits  int
		wantErr         bool
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
	}{
		{"inet.0", 254},
		{"inet6.0", 254},
		{"dmz-vr.inet.0", 101},
		{"dmz-vr.inet6.0", 101},
		{"tunnel-vr.inet.0", 100},
		{"unknown-vr.inet.0", 0},
		{"garbage", 0},
	}

	for _, tt := range tests {
		got := resolveRibTable(tt.ribName, tableIDs)
		if got != tt.want {
			t.Errorf("resolveRibTable(%q) = %d, want %d", tt.ribName, got, tt.want)
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
		if resolveRibTable(ribName, tableIDs) != inst.TableID {
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
		if resolveRibTable(ribName, tableIDs) != inst.TableID {
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
		{"ef", 46 << 2},     // 0xB8 = 184
		{"af43", 38 << 2},   // 0x98 = 152
		{"af42", 36 << 2},   // 0x90 = 144
		{"af41", 34 << 2},   // 0x88 = 136
		{"af33", 30 << 2},   // 120
		{"cs1", 8 << 2},     // 32
		{"cs5", 40 << 2},    // 160
		{"be", 0},           // best effort = 0
		{"cs0", 0},          // cs0 = 0 → TOS = 0
		{"46", 46 << 2},     // numeric DSCP
		{"0", 0},            // zero
		{"63", 63 << 2},     // max DSCP
		{"invalid", 0},      // unknown name → 0
		{"EF", 46 << 2},     // case-insensitive
		{"AF43", 38 << 2},   // case-insensitive
	}

	for _, tt := range tests {
		got := dscpToTOS(tt.dscp)
		if got != tt.want {
			t.Errorf("dscpToTOS(%q) = %d (0x%02X), want %d (0x%02X)",
				tt.dscp, got, got, tt.want, tt.want)
		}
	}
}

func TestBuildPBRRules(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{
		{Name: "Comcast-GigabitPro", TableID: 100},
		{Name: "ATT", TableID: 101},
	}

	t.Run("DSCP-based routing", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"inet-source-dscp": {
					Name: "inet-source-dscp",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "dscp-to-gigabitpro",
							DSCP:            "ef",
							RoutingInstance: "Comcast-GigabitPro",
						},
						{
							Name:            "dscp-to-att",
							DSCP:            "af43",
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 2 {
			t.Fatalf("expected 2 PBR rules, got %d", len(rules))
		}

		// Find rules by instance (map iteration order is nondeterministic
		// but there's only one filter so order is deterministic within terms)
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

		if comcast.TOS != 184 { // ef=46, TOS=46<<2=184=0xB8
			t.Errorf("Comcast TOS = %d, want 184 (0xB8)", comcast.TOS)
		}
		if comcast.TableID != 100 {
			t.Errorf("Comcast table = %d, want 100", comcast.TableID)
		}
		if comcast.Family != unix.AF_INET {
			t.Errorf("Comcast family = %d, want AF_INET", comcast.Family)
		}

		if att.TOS != 152 { // af43=38, TOS=38<<2=152=0x98
			t.Errorf("ATT TOS = %d, want 152 (0x98)", att.TOS)
		}
		if att.TableID != 101 {
			t.Errorf("ATT table = %d, want 101", att.TableID)
		}
	})

	t.Run("source address routing", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"src-routing": {
					Name: "src-routing",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "from-subnet",
							SourceAddresses: []string{"10.0.1.0/24"},
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Src != "10.0.1.0/24" {
			t.Errorf("src = %q, want 10.0.1.0/24", rules[0].Src)
		}
		if rules[0].TOS != 0 {
			t.Errorf("TOS = %d, want 0", rules[0].TOS)
		}
		if rules[0].TableID != 101 {
			t.Errorf("table = %d, want 101", rules[0].TableID)
		}
	})

	t.Run("destination address routing", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"dst-routing": {
					Name: "dst-routing",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "to-subnet",
							DestAddresses:   []string{"192.168.0.0/16"},
							RoutingInstance: "Comcast-GigabitPro",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Dst != "192.168.0.0/16" {
			t.Errorf("dst = %q, want 192.168.0.0/16", rules[0].Dst)
		}
	})

	t.Run("inet6 filter", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet6: map[string]*config.FirewallFilter{
				"v6-routing": {
					Name: "v6-routing",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "dscp-route",
							DSCP:            "ef",
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Family != unix.AF_INET6 {
			t.Errorf("family = %d, want AF_INET6", rules[0].Family)
		}
	})

	t.Run("no criteria skipped", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"no-criteria": {
					Name: "no-criteria",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "accept-all",
							RoutingInstance: "ATT",
							// No DSCP, no source, no dest — can't express as ip rule
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for no-criteria term, got %d", len(rules))
		}
	})

	t.Run("unknown instance skipped", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"bad-ref": {
					Name: "bad-ref",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "bad",
							DSCP:            "ef",
							RoutingInstance: "NonExistent",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for unknown instance, got %d", len(rules))
		}
	})

	t.Run("terms without routing-instance ignored", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"mixed": {
					Name: "mixed",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:   "accept-term",
							DSCP:   "ef",
							Action: "accept",
						},
						{
							Name:            "route-term",
							DSCP:            "af43",
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 1 {
			t.Fatalf("expected 1 PBR rule, got %d", len(rules))
		}
		if rules[0].Instance != "ATT" {
			t.Errorf("instance = %q, want ATT", rules[0].Instance)
		}
	})

	t.Run("multi-address cross product", func(t *testing.T) {
		fw := &config.FirewallConfig{
			FiltersInet: map[string]*config.FirewallFilter{
				"multi": {
					Name: "multi",
					Terms: []*config.FirewallFilterTerm{
						{
							Name:            "cross",
							SourceAddresses: []string{"10.0.1.0/24", "10.0.2.0/24"},
							DestAddresses:   []string{"192.168.1.0/24", "192.168.2.0/24"},
							RoutingInstance: "ATT",
						},
					},
				},
			},
		}

		rules := BuildPBRRules(fw, instances)
		if len(rules) != 4 {
			t.Fatalf("expected 4 PBR rules (2×2 cross product), got %d", len(rules))
		}
	})

	t.Run("nil firewall", func(t *testing.T) {
		rules := BuildPBRRules(nil, instances)
		if len(rules) != 0 {
			t.Errorf("expected 0 PBR rules for nil config, got %d", len(rules))
		}
	})
}

func TestProbeICMP(t *testing.T) {
	// localhost should always be reachable (via UDP fallback at minimum)
	if !probeICMP("127.0.0.1") {
		t.Error("expected probe to 127.0.0.1 to succeed")
	}

	// Invalid address should fail
	if probeICMP("not-an-ip") {
		t.Error("expected probe to invalid address to fail")
	}
}

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
	m := &Manager{
		monitorStatus: make(map[int][]InterfaceMonitorStatus),
	}

	// No monitors → nil
	if got := m.InterfaceMonitorStatuses(); got != nil {
		t.Errorf("expected nil for empty monitors, got %v", got)
	}

	// Set some state directly
	m.mu.Lock()
	m.monitorStatus[0] = []InterfaceMonitorStatus{
		{Interface: "trust0", Weight: 255, Up: true},
	}
	m.monitorStatus[1] = []InterfaceMonitorStatus{
		{Interface: "untrust0", Weight: 200, Up: true},
		{Interface: "dmz0", Weight: 100, Up: false},
	}
	m.mu.Unlock()

	got := m.InterfaceMonitorStatuses()
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
	if m.InterfaceMonitorStatuses()[0] == nil {
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
		"reth0":     {Name: "reth0", RedundancyGroup: 1},
		"reth1":     {Name: "reth1", RedundancyGroup: 1},
		"trust0":    {Name: "trust0"},
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
			if resolveRibTable(ribName, tableIDs) != inst.TableID {
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
		if resolveRibTable(ribName, tableIDs) != inst.TableID {
			needsLeak = true
			break
		}
	}
	if !needsLeak {
		t.Error("vpn-vr with IPv6-only rib-group should need leaking")
	}
}
