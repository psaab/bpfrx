package config

import (
	"net/netip"
	"reflect"
	"testing"
)

// #8631: `expandProxyARPPrefix` classified a `::ffff:` block as v6 while the
// installer (`pkg/dataplane/proxyarp.go`, `addr.Is6() && !addr.Is4In6()`)
// classified the identical literal as v4. The block therefore expanded under v6
// rules — no network-address skip, `/128` suffix — into entries the installer
// then programmed as AF_INET.
//
// THE COUNTS ARE THE ASSERTION, not the suffixes. A cell that checked only
// `/32` vs `/128` passes on a half-fix that unmaps the address and leaves the
// v6 host count, which is the more likely wrong repair: the mask is in v6
// bit-space, so `::ffff:10.0.0.0/126` is four addresses and the v4-equivalent
// mask is 126-96 = 30. v4 excludes the network AND broadcast addresses, so a
// /30 is 2 hosts where a /126 is 4.
//
// (The issue body says a v4 /30 yields 3. Measured, it yields 2 —
// `proxyARPPrefixHostCount` subtracts both the network and the broadcast
// address. Asserting 3 would have failed against correct code.)
func TestProxyARPMappedV4BlockExpandsUnderV4Rules8631(t *testing.T) {
	const mapped = "::ffff:10.0.0.0/126"
	const plain = "10.0.0.0/30"

	got := expandProxyARPPrefix(mapped)
	want := expandProxyARPPrefix(plain)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("a v4-mapped block must expand exactly as the v4 block it "+
			"denotes — the installer treats both as AF_INET.\n mapped %s -> %v\n plain  %s -> %v",
			mapped, got, plain, want)
	}
	if len(got) != 2 {
		t.Errorf("a /30 has 2 ARP-addressable hosts (network and broadcast "+
			"excluded); got %d: %v", len(got), got)
	}
	for _, e := range got {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			t.Fatalf("expanded entry %q does not parse: %v", e, err)
		}
		if !p.Addr().Is4() {
			t.Errorf("expanded entry %q is not a v4 address; a v4 address still "+
				"wearing a v6 mask is the invalid-prefix trap this fix exists to "+
				"avoid, not a cosmetic difference", e)
		}
	}
}

// ANTI-OVER-REACH, and it is the half that decides the fix is placed rather
// than merely present: `Unmap` must be a NO-OP on a genuine v6 block. Convert
// too eagerly and every real v6 proxy-ND block silently loses its network
// address and its /128 spelling.
func TestProxyARPGenuineV6BlockIsUntouched8631(t *testing.T) {
	got := expandProxyARPPrefix("2001:db8::/126")
	want := []string{
		"2001:db8::/128", "2001:db8::1/128", "2001:db8::2/128", "2001:db8::3/128",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("a genuine v6 /126 must still expand to all 4 addresses with "+
			"/128 suffixes — v6 has no network or broadcast address to skip.\n got  %v\n want %v",
			got, want)
	}

	// And plain v4 is unchanged, so the normalization cannot have altered the
	// path it was modelled on.
	if got := expandProxyARPPrefix("10.0.0.0/31"); !reflect.DeepEqual(
		got, []string{"10.0.0.0/32", "10.0.0.1/32"}) {
		t.Errorf("plain v4 /31 must be unchanged (no network skip below /31); got %v", got)
	}
}

// #8631: a mapped prefix whose length is BELOW the v4 floor does not denote a
// v4 block at all — `::ffff:10.0.0.0/64` would convert to a nonsensical -32.
// It must be left alone and keep failing closed at the commit gate, rather than
// being turned into a malformed prefix.
//
// This is the near-miss the issue records: the naive repair unmaps the address
// while keeping the v6 mask, which builds an invalid prefix instead of a
// narrower one.
func TestProxyARPMappedPrefixBelowTheV4FloorStillFailsClosed8631(t *testing.T) {
	const tooWide = "::ffff:10.0.0.0/64"

	if got := expandProxyARPPrefix(tooWide); !reflect.DeepEqual(got, []string{tooWide}) {
		t.Errorf("a mapped prefix below the v4 floor must be left exactly as "+
			"authored so the commit gate can refuse it; got %v", got)
	}
	if err := proxyARPNonHostPrefixError("ge-0/0/0", tooWide); err == nil {
		t.Error("a mapped prefix below the v4 floor must still be REFUSED at " +
			"commit — converting it would replace a clear refusal with a " +
			"malformed prefix")
	}
	// /96 IS above the floor, converts to a v4 /0, and is still far over the
	// expansion cap — so the conversion must not smuggle it past the gate.
	if err := proxyARPNonHostPrefixError("ge-0/0/0", "::ffff:10.0.0.0/96"); err == nil {
		t.Error("::ffff:10.0.0.0/96 is the whole v4 space and must stay refused")
	}
}

// A mapped SINGLE host is a v4 /32 and must be recognised as single-host by the
// commit gate, not misread as a multi-host v6 block.
func TestProxyARPMappedSingleHostIsAV4Host8631(t *testing.T) {
	if err := proxyARPNonHostPrefixError("ge-0/0/0", "::ffff:10.0.0.1/128"); err != nil {
		t.Errorf("a mapped /128 is a single v4 host and must not be refused: %v", err)
	}
	if got := expandProxyARPPrefix("::ffff:10.0.0.1/128"); !reflect.DeepEqual(
		got, []string{"10.0.0.1/32"}) {
		t.Errorf("a mapped single host must normalize to its v4 spelling; got %v", got)
	}
}
