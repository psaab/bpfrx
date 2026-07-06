package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestPolicySlashNameResolvesToPrefix is the #4340 end-to-end dataplane proof:
// a security policy that references a prefix-named address object
// (net_10.0.0.0/8) must resolve to that object's PREFIX through the userspace
// snapshot builder, exactly as a non-slash name does. The resolution path keys
// the object by its FULL name via direct map lookups
// (resolveUserspaceAddressBookEntry / classifyPolicyAddresses), so the `/` in
// the name is inert.
func TestPolicySlashNameResolvesToPrefix(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"net_10.0.0.0/8":             {Name: "net_10.0.0.0/8", Value: "10.0.0.0/8"},
					"net_2001:559:8585:200::/64": {Name: "net_2001:559:8585:200::/64", Value: "2001:559:8585:200::/64"},
				},
				AddressSets: map[string]*config.AddressSet{
					"feeds": {Name: "feeds", Addresses: []string{"net_10.0.0.0/8", "net_2001:559:8585:200::/64"}},
				},
			},
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name: "p1",
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"net_10.0.0.0/8"},
								DestinationAddresses: []string{"feeds"},
							},
							Action: config.PolicyPermit,
						},
					},
				},
			},
		},
	}

	snaps, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(snaps))
	}
	s := snaps[0]

	// The single slash-named source object resolved to a book ID (not dropped
	// to a free-form literal), and its full-expansion prefix is 10.0.0.0/8.
	if len(s.SourceBookIDs) != 1 {
		t.Fatalf("source slash-named object did not resolve to a book id: bookIDs=%v literals=%v", s.SourceBookIDs, s.SourceLiterals)
	}
	if !slices.Contains(s.SourceAddresses, "10.0.0.0/8") {
		t.Fatalf("source did not expand to the object prefix 10.0.0.0/8: %v", s.SourceAddresses)
	}

	// The destination address-set expands both slash-named members to their
	// prefixes.
	if len(s.DestinationBookIDs) != 1 {
		t.Fatalf("destination address-set did not resolve to a book id: %v", s.DestinationBookIDs)
	}
	for _, want := range []string{"10.0.0.0/8", "2001:559:8585:200::/64"} {
		if !slices.Contains(s.DestinationAddresses, want) {
			t.Fatalf("destination did not expand to %q: %v", want, s.DestinationAddresses)
		}
	}
}
