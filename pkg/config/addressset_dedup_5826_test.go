package config

// #5826: address-set member dedup used appendUniqueString, which linearly
// scanned the FULL existing member slice on every append, so a size-valid config
// with N unique members across repeated same-name stanzas cost O(N²) string
// comparisons during commit / boot / HA config-sync / validation. The fix keeps
// a per-address-set membership index (a map for direct-address members and a
// SEPARATE map for nested-set members) alongside the ordered slice, appending
// only on a first-seen map miss — O(N) with byte-identical output (first-seen
// order + exact union-by-name dedup).
//
// These tests pin (1) the preserved behavior — deterministic first-seen order,
// exact union, independent direct/nested namespaces — and (2) the O(N) scaling.
// The #4706 tests (addressbook_dup_addrset_merge_4706_test.go) also stay GREEN,
// since the observable output is unchanged.

import (
	"reflect"
	"strconv"
	"testing"
	"time"
)

// TestAddressSetDedupFirstSeenOrderAndUnion_5826 pins the exact first-seen order
// and union-by-name dedup across THREE same-name address-set blocks with
// interleaved overlapping + distinct members, in BOTH the direct-address and
// nested-address-set namespaces.
func TestAddressSetDedupFirstSeenOrderAndUnion_5826(t *testing.T) {
	cfg := compileHierarchical(t, `
security {
    address-book {
        global {
            address A1 { 10.0.1.0/24; }
            address A2 { 10.0.2.0/24; }
            address A3 { 10.0.3.0/24; }
            address-set INNER1 { address A1; }
            address-set INNER2 { address A2; }
            address-set S {
                address A1;
                address A2;
                address-set INNER1;
            }
            address-set S {
                address A2;
                address A3;
                address-set INNER1;
            }
            address-set S {
                address A1;
                address-set INNER2;
            }
        }
    }
}
`)
	s := cfg.Security.AddressBook.AddressSets["S"]
	if s == nil {
		t.Fatal("address-set S missing")
	}
	// Direct addresses: first-seen A1,A2 (block1), A3 (block2); dups A2/A1 skipped.
	if want := []string{"A1", "A2", "A3"}; !reflect.DeepEqual(s.Addresses, want) {
		t.Fatalf("S.Addresses = %v, want first-seen union %v", s.Addresses, want)
	}
	// Nested sets: INNER1 (block1), INNER2 (block3); dup INNER1 (block2) skipped.
	if want := []string{"INNER1", "INNER2"}; !reflect.DeepEqual(s.AddressSets, want) {
		t.Fatalf("S.AddressSets = %v, want first-seen union %v", s.AddressSets, want)
	}
}

// TestAddressSetDedupNamespacesIndependent_5826 proves the direct-address dedup
// map and the nested-set dedup map are SEPARATE: the SAME name used as a direct
// `address` member AND as a nested `address-set` member lands in BOTH slices
// (deduped within each namespace, not across). Driven directly against
// parseAddressBookEntries so the dedup is isolated from full-pipeline reference
// validation (Junos would not let one name be both an address and an
// address-set entity, but the compiler's two dedup namespaces are independent).
func TestAddressSetDedupNamespacesIndependent_5826(t *testing.T) {
	set := &Node{Keys: []string{"address-set", "S"}}
	set.Children = []*Node{
		{Keys: []string{"address", "X"}},
		{Keys: []string{"address", "X"}}, // dup direct -> skip
		{Keys: []string{"address", "Y"}},
		{Keys: []string{"address-set", "X"}}, // same name, DIFFERENT namespace -> kept
		{Keys: []string{"address-set", "X"}}, // dup nested -> skip
		{Keys: []string{"address-set", "Z"}},
	}
	node := &Node{Children: []*Node{set}}
	ab := &AddressBook{Addresses: map[string]*Address{}, AddressSets: map[string]*AddressSet{}}
	parseAddressBookEntries(node, ab)

	s := ab.AddressSets["S"]
	if s == nil {
		t.Fatal("address-set S missing")
	}
	if want := []string{"X", "Y"}; !reflect.DeepEqual(s.Addresses, want) {
		t.Fatalf("S.Addresses = %v, want %v (direct namespace deduped)", s.Addresses, want)
	}
	if want := []string{"X", "Z"}; !reflect.DeepEqual(s.AddressSets, want) {
		t.Fatalf("S.AddressSets = %v, want %v (nested namespace deduped INDEPENDENTLY — X kept in both)",
			s.AddressSets, want)
	}
}

// bigAddressSetNode builds a `global` node carrying ONE `address-set BIG` block
// with n distinct direct-address members a0..a{n-1}, for the scaling guard.
func bigAddressSetNode(n int) *Node {
	set := &Node{Keys: []string{"address-set", "BIG"}}
	set.Children = make([]*Node, 0, n)
	for i := 0; i < n; i++ {
		set.Children = append(set.Children, &Node{Keys: []string{"address", "a" + strconv.Itoa(i)}})
	}
	return &Node{Children: []*Node{set}}
}

func runParseBig(n int) (time.Duration, *AddressSet) {
	ab := &AddressBook{Addresses: map[string]*Address{}, AddressSets: map[string]*AddressSet{}}
	node := bigAddressSetNode(n)
	start := time.Now()
	parseAddressBookEntries(node, ab)
	return time.Since(start), ab.AddressSets["BIG"]
}

// TestAddressSetDedupScalesLinearly_5826 is the perf guard. At N=80000 the fixed
// O(N) path finishes in a few ms; the pre-#5826 O(N²) linear scan performs
// N²/2 ≈ 3.2e9 string comparisons and takes SECONDS. A generous 3s budget clears
// the O(N) path by ~100x while the linear scan blows it — the fail-on-revert
// lever (reverting to appendUniqueString makes this test RED). It also pins
// correctness at large N (exactly N members, first-seen order).
func TestAddressSetDedupScalesLinearly_5826(t *testing.T) {
	const N = 80000

	dN, as := runParseBig(N)
	if as == nil || len(as.Addresses) != N {
		got := -1
		if as != nil {
			got = len(as.Addresses)
		}
		t.Fatalf("BIG has %d members, want %d", got, N)
	}
	// Spot-check first-seen order at the ends + a middle index.
	for _, i := range []int{0, 1, N / 2, N - 1} {
		if as.Addresses[i] != "a"+strconv.Itoa(i) {
			t.Fatalf("member[%d] = %q, first-seen order not preserved", i, as.Addresses[i])
		}
	}

	const budget = 3 * time.Second
	if dN > budget {
		t.Fatalf("parseAddressBookEntries of %d unique members took %v > %v — the dedup is not O(N) "+
			"(the O(N²) linear scan regressed?) — #5826", N, dN, budget)
	}

	// Informational ~linear-growth signal: T(2N) should be a small multiple of
	// T(N), not ~4x. Logged (not hard-asserted) so wall-clock noise never flakes
	// the gate; the budget above is the hard fail-on-revert.
	d2N, _ := runParseBig(2 * N)
	ratio := 0.0
	if dN > 0 {
		ratio = float64(d2N) / float64(dN)
	}
	t.Logf("#5826 scaling: T(%d)=%v T(%d)=%v ratio=%.2fx (O(N) ~2x, O(N²) ~4x)", N, dN, 2*N, d2N, ratio)
}

// BenchmarkParseAddressSetMembers benchmarks the dedup at several N; cited in the
// PR body. Growth at N vs 2N is ~linear under the fix (was quadratic).
func BenchmarkParseAddressSetMembers(b *testing.B) {
	for _, n := range []int{1000, 10000, 40000, 80000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			node := bigAddressSetNode(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ab := &AddressBook{Addresses: map[string]*Address{}, AddressSets: map[string]*AddressSet{}}
				parseAddressBookEntries(node, ab)
			}
		})
	}
}
