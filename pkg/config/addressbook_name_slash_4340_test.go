package config

import "testing"

// TestAddressBookSlashNameCommits is the #4340 acceptance proof. Real vSRX
// configs name an address object after its prefix — the near-universal operator
// convention: net_10.0.0.0/8, net4_sfmix_72.52.96.201/32,
// net_2001:559:8585:200::/64. The `/` in such a NAME is a display identifier,
// not a structural token, so it must commit and its policy reference must
// resolve.
//
// RED-on-revert: before #4340 validateAddressBookEntryNamesStrict rejected any
// `/` in an address-book entry name ("must not contain '/'"), so both the
// definition AND the policy reference failed at commit.
func TestAddressBookSlashNameCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces ge-0-0-0",
		"set security zones security-zone untrust interfaces ge-0-0-1",
		// v4 and v6 objects named after their prefix (a CIDR value + a `/`
		// in the NAME).
		"set security address-book global address net_10.0.0.0/8 10.0.0.0/8",
		"set security address-book global address net4_sfmix_72.52.96.201/32 72.52.96.201/32",
		"set security address-book global address net_2001:559:8585:200::/64 2001:559:8585:200::/64",
		// An address-set that references the slash-named members.
		"set security address-book global address-set feeds address net_10.0.0.0/8",
		"set security address-book global address-set feeds address net_2001:559:8585:200::/64",
		// A policy that references the slash-named objects by name.
		"set security policies from-zone trust to-zone untrust policy p1 match source-address net_10.0.0.0/8",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address net4_sfmix_72.52.96.201/32",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address feeds",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a prefix-named address object (the #4340 blocker): %v", err)
	}

	// The address objects are keyed by the FULL slash-bearing name and carry
	// the CIDR VALUE (name and value are distinct — the value legitimately
	// contains a `/` too).
	ab := cfg.Security.AddressBook
	if ab == nil {
		t.Fatal("compiled config has no global address book")
	}
	for name, wantValue := range map[string]string{
		"net_10.0.0.0/8":             "10.0.0.0/8",
		"net4_sfmix_72.52.96.201/32": "72.52.96.201/32",
		"net_2001:559:8585:200::/64": "2001:559:8585:200::/64",
	} {
		addr := ab.Addresses[name]
		if addr == nil {
			t.Fatalf("address %q not found in the compiled book (keys: %v)", name, addressNames(ab))
		}
		if addr.Value != wantValue {
			t.Fatalf("address %q: value = %q, want %q (name must not be confused with the CIDR value)", name, addr.Value, wantValue)
		}
	}

	// The address-set resolved its slash-named members (strict commit runs
	// validatePolicyMatchAddressSetMembersStrict, so a dangling member would
	// have failed above — assert the members are the slash names verbatim).
	set := ab.AddressSets["feeds"]
	if set == nil {
		t.Fatal("address-set feeds not found")
	}
	if len(set.Addresses) != 2 {
		t.Fatalf("address-set feeds members = %v, want the two slash-named entries", set.Addresses)
	}

	// The policy's source-address tokens are the slash names verbatim (global
	// book — not rewritten by the zone-local fold), so they resolve directly
	// against the book. A successful STRICT compile already proves
	// validatePolicyMatchAddressesStrict recognized them; assert the tokens
	// survived unmangled for good measure.
	pol := findPolicy(t, cfg, "trust", "untrust", "p1")
	assertContains(t, "source-address", pol.Match.SourceAddresses, "net_10.0.0.0/8")
	assertContains(t, "source-address", pol.Match.SourceAddresses, "net4_sfmix_72.52.96.201/32")
	assertContains(t, "destination-address", pol.Match.DestinationAddresses, "feeds")
}

// TestAddressBookSlashNameZoneLocalFoldRoundTrips proves the zone-local fold
// (resolveZoneLocalAddressBooks) mints a collision-proof synthetic name for a
// `/`-bearing zone-local object and rewrites the policy reference to it — and
// that ZoneLocalUnqualify reverses it back to the authored `/`-bearing name.
// This is the case that made #3061 reserve `/` in the first place; #4340 keeps
// it correct while permitting the `/`.
func TestAddressBookSlashNameZoneLocalFoldRoundTrips(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces ge-0-0-0",
		"set security zones security-zone untrust interfaces ge-0-0-1",
		"set security zones security-zone trust address-book address net_172.16.0.0/12 172.16.0.0/12",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address net_172.16.0.0/12",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a `/`-named zone-local object: %v", err)
	}

	// The fold injected the qualified synthetic name into the global book.
	const qualified = "zone-local/trust/net_172.16.0.0/12"
	addr := cfg.Security.AddressBook.Addresses[qualified]
	if addr == nil {
		t.Fatalf("zone-local fold did not mint %q (keys: %v)", qualified, addressNames(cfg.Security.AddressBook))
	}
	if addr.Value != "172.16.0.0/12" {
		t.Fatalf("qualified entry value = %q, want 172.16.0.0/12", addr.Value)
	}

	// The policy source token was rewritten to the qualified name so it
	// resolves zone-locally.
	pol := findPolicy(t, cfg, "trust", "untrust", "p1")
	assertContains(t, "source-address", pol.Match.SourceAddresses, qualified)

	// ZoneLocalUnqualify reverses it: the `/`-free zone is the first segment,
	// the `/`-bearing object name follows, split on the FIRST `/` only.
	zone, name, ok := ZoneLocalUnqualify(qualified)
	if !ok || zone != "trust" || name != "net_172.16.0.0/12" {
		t.Fatalf("ZoneLocalUnqualify(%q) = (%q, %q, %v), want (trust, net_172.16.0.0/12, true)", qualified, zone, name, ok)
	}
	// DisplayAddressName shows the authored `/`-bearing name to the operator.
	if got := DisplayAddressName(qualified); got != "net_172.16.0.0/12" {
		t.Fatalf("DisplayAddressName(%q) = %q, want net_172.16.0.0/12", qualified, got)
	}
	// A non-synthetic `/`-bearing operator name is returned unchanged.
	if got := DisplayAddressName("net_10.0.0.0/8"); got != "net_10.0.0.0/8" {
		t.Fatalf("DisplayAddressName should not touch a non-synthetic slash name; got %q", got)
	}
}

func addressNames(ab *AddressBook) []string {
	if ab == nil {
		return nil
	}
	out := make([]string, 0, len(ab.Addresses))
	for n := range ab.Addresses {
		out = append(out, n)
	}
	return out
}

func assertContains(t *testing.T, field string, tokens []string, want string) {
	t.Helper()
	for _, tok := range tokens {
		if tok == want {
			return
		}
	}
	t.Fatalf("%s %v does not contain %q", field, tokens, want)
}
