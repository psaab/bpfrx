package configstore

import (
	"strings"
	"testing"
)

// #9424, the OPERATOR channel. All four channels accepted the bracketed
// spelling and kept only the first address; `configstore.CheckText` is the gate
// every commit and every `xpfd check-config` actually goes through.
const addrBase9424 = "system { host-name p; }\n"

func addrUnitCheck9424(t *testing.T, body string) ([]string, error) {
	t.Helper()
	cfg, err := CheckText(addrBase9424+
		"interfaces { ge-0/0/0 { unit 0 { "+body+" } } }", -1)
	if err != nil {
		return nil, err
	}
	iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if iface == nil || iface.Units[0] == nil {
		t.Fatalf("fixture broken: no ge-0/0/0 unit 0")
	}
	return iface.Units[0].Addresses, nil
}

func TestBracketedAddressListAtCommit9424(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"inet bracketed pair", `family inet { address [ 10.0.0.1/24 10.0.0.2/24 ]; }`,
			[]string{"10.0.0.1/24", "10.0.0.2/24"}},
		{"inet two stanzas (POSITIVE CONTROL)", `family inet { address 10.0.0.1/24; address 10.0.0.2/24; }`,
			[]string{"10.0.0.1/24", "10.0.0.2/24"}},
		{"inet bracketed triple", `family inet { address [ 10.0.0.1/24 10.0.0.2/24 10.0.0.3/24 ]; }`,
			[]string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24"}},
		{"inet6 bracketed pair", `family inet6 { address [ 2001:db8::1/64 2001:db8::2/64 ]; }`,
			[]string{"2001:db8::1/64", "2001:db8::2/64"}},
	}
	for _, tc := range cases {
		got, err := addrUnitCheck9424(t, tc.body)
		if err != nil {
			t.Fatalf("%s: rejected by the operator commit path: %v", tc.name, err)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("%s: Addresses=%v, want %v — the commit path kept only the first "+
				"address of the bracketed list (#9424)", tc.name, got, tc.want)
		}
	}
}

// A token inside the bracket that is not an address for its family is REFUSED
// at commit rather than discarded. The typed-leaf gate validates only the FIRST
// key slot of an `address` leaf, so accumulating the valid extras while ignoring
// the invalid ones would leave this issue's own defect in place.
func TestBracketedAddressListGarbageRefusedAtCommit9424(t *testing.T) {
	for body, bad := range map[string]string{
		`family inet { address [ 10.0.0.1/24 not-an-address ]; }`:  "not-an-address",
		`family inet { address [ 10.0.0.1/24 2001:db8::1/64 ]; }`:  "2001:db8::1/64",
		`family inet6 { address [ 2001:db8::1/64 10.0.0.1/24 ]; }`: "10.0.0.1/24",
	} {
		_, err := addrUnitCheck9424(t, body)
		if err == nil {
			t.Fatalf("%s: accepted at commit with %q silently discarded (#9424)", body, bad)
		}
		if !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "interface address list") {
			t.Fatalf("%s: rejected, but not by the #9424 gate naming %q: %v", body, bad, err)
		}
	}
}

// The brace-elided vrrp-group spelling shares the packed shape and must stay
// committable — its tokens are a sub-statement body, not a bracketed list.
func TestElidedVRRPStanzaStillCommits9424(t *testing.T) {
	got, err := addrUnitCheck9424(t,
		`family inet { address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.100/24; }`)
	if err != nil {
		t.Fatalf("a brace-elided vrrp-group stanza is now refused at commit: %v", err)
	}
	if len(got) != 1 || got[0] != "10.0.0.1/24" {
		t.Fatalf("Addresses=%v — a sub-statement value was read as an address", got)
	}
}
