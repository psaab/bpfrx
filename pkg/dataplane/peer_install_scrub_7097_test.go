package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// #7097: the peer-install node-local scrub must not fall behind the struct.
//
// A peer-owned session must not inherit fields that only mean something on the
// node that produced them. Before this change FOUR install sites each carried
// their own hand-written list of those fields, and every one of them listed the
// five FIB fields and not the #4983 ingress pair that #6928 added to the ABI.
// Nothing reached any of them with a non-zero value — pkg/cluster's session wire
// never encodes the pair — so the incompleteness was latent, which is exactly
// why nothing noticed it.
//
// The fix is one list (`ScrubNodeLocal`, session_node_local.go). These tests are
// the two halves that keep it one list:
//
//   - the CENSUS below asserts the helper zeroes the declared node-local set and
//     NOTHING else, by filling every field with a non-zero sentinel through
//     reflection and comparing both directions. It reads no marker comment and
//     no hand-maintained name list against the struct, so a field added to the
//     helper without being declared fails as loudly as one declared without
//     being zeroed. The field COUNT is pinned separately, so a new field on the
//     struct forces a human to classify it.
//   - the DELEGATION pin asserts every peer-install site calls the helper and
//     none has re-grown a private list.

// nodeLocalSessionFields are the fields a peer-owned row must NOT inherit.
// FIB* are the resolved EGRESS of a lookup the ORIGINATING node performed;
// IngressIfindex / IngressVlanID are the #4983 ingress-binding identity,
// node-local for the same reason (node 0's `ge-0-0-1` and node 1's `ge-7-0-1`
// are different numbers for one logical RETH member).
//
// IngressIfaceFold (#7095) is deliberately NOT here, and the distinction is the
// whole reason that field exists. It is a fold of the RETH-RELATIVE name
// (`reth0.50`), which both chassis agree on by construction — it is the one
// ingress-identity field that is MEANT to survive the wire, and the receiving
// node resolves it back to its own {ifindex, vlan}. Scrubbing it would delete
// the peer's answer and put every synced session back on the #4792 zone
// approximation, which is exactly what #7095 removed.
//
// TunnelDiscriminator (#7188) is NOT here either, and for a stronger reason
// than #7095's. It is not merely cluster-agreeable, it is SYMMETRIC BY
// CONSTRUCTION: an RFC 2890 GRE Key is carried identically in both directions
// of a tunnel and is identical on both chassis — being symmetric is precisely
// why that field was chosen as the discriminator over the PPTP call ID and the
// ESP SPI, which are allocated per-direction. Scrubbing it would put both of a
// peer's same-endpoint keyed tunnels back on one key, which is the aliasing
// #7188 exists to remove.
var nodeLocalSessionFields = map[string]bool{
	"FibIfindex":     true,
	"FibVlanID":      true,
	"FibDmac":        true,
	"FibSmac":        true,
	"FibGen":         true,
	"IngressIfindex": true,
	"IngressVlanID":  true,
}

// fillNonZero sets every settable field of a struct to a non-zero sentinel, so
// "this field came back zero" means the scrub zeroed it rather than the fixture
// never having set it. A fixture that left a field at its zero value would make
// the scrub look complete for a field it never touches.
func fillNonZero(t *testing.T, v reflect.Value) {
	t.Helper()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			f.SetUint(0x5A)
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			f.SetInt(0x5A)
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Array:
			for j := 0; j < f.Len(); j++ {
				if f.Index(j).Kind() == reflect.Uint8 {
					f.Index(j).SetUint(0x5A)
				}
			}
		case reflect.Struct:
			fillNonZero(t, f)
		default:
			// A field kind this helper cannot seed would read as "scrubbed" for
			// free. Fail rather than quietly under-cover it.
			t.Fatalf("field %s has kind %s, which fillNonZero does not seed — "+
				"the zero/non-zero comparison below would be vacuous for it (#7097)",
				v.Type().Field(i).Name, f.Kind())
		}
	}
}

// zeroedFields reports which top-level fields of `after` are zero while the
// same field of `before` was not.
func zeroedFields(before, after reflect.Value) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < before.NumField(); i++ {
		name := before.Type().Field(i).Name
		b, a := before.Field(i), after.Field(i)
		if !b.IsZero() && a.IsZero() {
			out[name] = true
		}
	}
	return out
}

func assertScrubCensus(t *testing.T, before, after reflect.Value) {
	t.Helper()
	scrubbed := zeroedFields(before, after)
	if len(scrubbed) == 0 {
		t.Fatal("the scrub zeroed NOTHING — the fixture or the call did not run, " +
			"and the two directional checks below would both pass vacuously (#7097)")
	}
	for name := range nodeLocalSessionFields {
		if !scrubbed[name] {
			t.Errorf("%s is NODE-LOCAL but survived the peer-install scrub. A "+
				"peer-owned row can then inherit this node's number and render a "+
				"confidently wrong answer — worse than the zero the consumer falls "+
				"back on (#7097)", name)
		}
	}
	for name := range scrubbed {
		if !nodeLocalSessionFields[name] {
			t.Errorf("the scrub zeroes %s, which is NOT declared node-local. Either "+
				"it is node-local and this list is stale, or the scrub is destroying "+
				"a field the peer legitimately owns (#7097)", name)
		}
	}
}

// The census on the single-sourced helper itself.
func TestScrubNodeLocalCoversExactlyTheNodeLocalFields7097(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ScrubNodeLocal()
		assertScrubCensus(t, before, reflect.ValueOf(val))
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ScrubNodeLocal()
		assertScrubCensus(t, before, reflect.ValueOf(val))
	})
}

// The wiring bind for the two session-store install sites: the census above
// proves the HELPER is right, this proves the store actually CALLS it. A
// sessionStoreTestDP does not implement clusterSyncedSessionInstaller, so the
// early return is not taken and the scrub branch runs.
func TestPeerInstallStoreScrubsNodeLocalFields7097(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)

		dp := &sessionStoreTestDP{}
		key := SessionKey{Protocol: 6}
		if err := (dataPlaneSessionStore{dp: dp}).putClusterSyncedV4Raw(key, val); err != nil {
			t.Fatalf("putClusterSyncedV4Raw: %v", err)
		}
		got, ok := dp.v4[key]
		if !ok {
			t.Fatal("the store did not install the row — the scrub branch was not " +
				"reached and this cell measures nothing")
		}
		assertScrubCensus(t, before, reflect.ValueOf(got))
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)

		dp := &sessionStoreTestDP{}
		key := SessionKeyV6{Protocol: 6}
		if err := (dataPlaneSessionStore{dp: dp}).putClusterSyncedV6Raw(key, val); err != nil {
			t.Fatalf("putClusterSyncedV6Raw: %v", err)
		}
		got, ok := dp.v6[key]
		if !ok {
			t.Fatal("the store did not install the row — the scrub branch was not " +
				"reached and this cell measures nothing")
		}
		assertScrubCensus(t, before, reflect.ValueOf(got))
	})
}

// The population pin. The census compares the helper against a DECLARED set;
// this is what stops that set going stale silently. A field added to
// SessionValue is either node-local (add it to ScrubNodeLocal AND to
// nodeLocalSessionFields) or it is not (update this number) — either way a human
// classifies it, which is the step #6928 skipped.
func TestSessionValueFieldCountIsPinned7097(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		want int
	}{
		// 38/39 since #7239 added RoutingDomain (37/38 after #7188's
		// TunnelDiscriminator, 36/37 after #7095's IngressIfaceFold). All three
		// are classified NOT node-local and are therefore absent from
		// ScrubNodeLocal / nodeLocalSessionFields — see the note on
		// nodeLocalSessionFields.
		//
		// The #7239 classification, stated rather than assumed, because this is
		// the step #6928 skipped: RoutingDomain is
		// `StableRoutingInstanceTableID(name)`, a pure function of the
		// routing-instance NAME. Both nodes compute the SAME number for the same
		// instance from identical config, with no synced or persisted state.
		// That is exactly the property that makes it legal on the wire, and it
		// is what distinguishes it from IngressIfindex — an ifindex is
		// node-local and names a different NIC on the peer, which is why #6928
		// declined to sync one and why #7095 had to invent a name fold instead.
		// A cluster-stable number needs no scrub.
		{"SessionValue", reflect.TypeOf(SessionValue{}), 38},
		{"SessionValueV6", reflect.TypeOf(SessionValueV6{}), 39},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.typ.NumField(); got != tc.want {
				t.Fatalf("%s has %d fields, pinned at %d. A new field must be "+
					"classified: node-local fields go in BOTH ScrubNodeLocal and "+
					"nodeLocalSessionFields; everything else just updates this number "+
					"(#7097)", tc.name, got, tc.want)
			}
		})
	}
}

// clusterSyncedInstallSites are every function that installs a session the
// CLUSTER PEER owns. Each must delegate the node-local strip to ScrubNodeLocal
// rather than keep its own list.
//
// The manager pair is the branch PRODUCTION takes: putClusterSyncedV4Raw's
// scrub runs only when the dataplane does not implement
// clusterSyncedSessionInstaller, and the userspace manager does implement it. A
// behavioural test for the manager pair would need a real BPF map (its whole
// package's manager tests t.Skipf without CAP_SYS_ADMIN/memlock), so it would
// SKIP on developer machines — which is why this pin is structural. It is not a
// substitute for the census: the census proves the helper is complete, this
// proves nobody bypasses it.
var clusterSyncedInstallSites = map[string][]string{
	"session_store.go": {
		"putClusterSyncedV4Raw",
		"putClusterSyncedV6Raw",
	},
	"userspace/manager_sessions.go": {
		"SetClusterSyncedSessionV4",
		"SetClusterSyncedSessionV6",
	},
}

func TestClusterSyncedInstallSitesDelegateTheScrub7097(t *testing.T) {

	for file, fns := range clusterSyncedInstallSites {
		t.Run(file, func(t *testing.T) {
			path := filepath.Join(".", filepath.FromSlash(file))
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			fset := token.NewFileSet()
			// Parsing with the Go parser, not a text scan, is what makes this
			// immune to being satisfied by its own doc comment: comments are not
			// expressions and never appear in the AST walked below.
			f, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			found := map[string]bool{}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				var want bool
				for _, name := range fns {
					if fd.Name.Name == name {
						want = true
					}
				}
				if !want {
					continue
				}
				found[fd.Name.Name] = true

				var callsScrub bool
				var ownList []string
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CallExpr:
						if sel, ok := x.Fun.(*ast.SelectorExpr); ok &&
							sel.Sel.Name == "ScrubNodeLocal" {
							callsScrub = true
						}
					case *ast.AssignStmt:
						for _, lhs := range x.Lhs {
							sel, ok := lhs.(*ast.SelectorExpr)
							if !ok {
								continue
							}
							if nodeLocalSessionFields[sel.Sel.Name] {
								ownList = append(ownList, sel.Sel.Name)
							}
						}
					}
					return true
				})

				if !callsScrub {
					t.Errorf("%s does not call ScrubNodeLocal. A peer-install site "+
						"that strips node-local fields by hand is how #7097 happened: "+
						"#6928 added IngressIfindex/IngressVlanID to the ABI and every "+
						"private list silently stopped covering the field class it "+
						"existed to cover", fd.Name.Name)
				}
				if len(ownList) > 0 {
					t.Errorf("%s assigns node-local fields directly (%s). Delete the "+
						"private list and let ScrubNodeLocal own it, or this site will "+
						"drift from the others again (#7097)",
						fd.Name.Name, strings.Join(ownList, ", "))
				}
			}

			// Anti-vacuity: a renamed or moved function must fail here, not
			// silently reduce this cell to zero checks.
			for _, name := range fns {
				if !found[name] {
					t.Errorf("%s not found in %s — this pin checked nothing for it. "+
						"If the function moved, move this entry with it (#7097)",
						name, file)
				}
			}
		})
	}
}
