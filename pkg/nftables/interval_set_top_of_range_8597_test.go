package nftables

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/google/nftables"
)

// #8597 (muse-004 K06) — a prefix reaching the TOP of the key space encoded its
// interval end at the BOTTOM.
//
// `prefixNext` returned `lastAddr(pfx).Next()`, and for a prefix whose last
// address is 255.255.255.255 (or the v6 equivalent) that is invalid. The
// fallback was the UNSPECIFIED address — 0.0.0.0 — so the end marker for an
// interval running to the top of the range landed at the very bottom of it.
//
// Measured by installing the set in a private netns and reading it BACK from
// the kernel, which stores exactly what it was sent:
//
//	{0.0.0.0/0, 10.0.0.0/8}
//	  00000000 start, 00000000 END, 0a000000 start, 0b000000 END
//	  -> the /0 member is a ZERO-WIDTH interval. A term that must match
//	     everything matches nothing. Fail-CLOSED.
//
//	{128.0.0.0/1, 10.0.0.0/8}
//	  00000000 END, 0a000000 start, 0b000000 END, 80000000 start
//	  -> the wrapped end sorts to the bottom as an end marker with no start
//	     before it, and 128.0.0.0 is left open to the top anyway.
//	     Fail-OPEN at the bottom.
//
// Two wrong encodings, in opposite directions, from one fallback. The kernel
// ACCEPTS both — this is not a load failure, which is why it needed a readback
// rather than an install check.

// intervalSetKeys builds the anonymous set for a saddr match and returns its
// elements as "hexkey" / "hexkey!end" strings, in emission order.
func intervalSetKeys(t *testing.T, f nlFamily, addrs []string) []string {
	t.Helper()
	p := newBuildPlan(t, "xpf_iv_8597", hostInboundPriority)
	p.rule().saddr(f, addrs, false).emit(verdictAccept()...)
	if p.err != nil {
		t.Fatalf("build: %v", p.err)
	}
	var out []string
	for _, els := range p.sets {
		for _, e := range els {
			k := hex.EncodeToString(e.Key)
			if e.IntervalEnd {
				k += "!end"
			}
			out = append(out, k)
		}
	}
	return out
}

// TestTopOfRangePrefixHasNoEndElement_8597 is the RED-on-revert core.
//
// Restoring the Unspecified() fallback puts a `00000000!end` back into each of
// these, which is what the kernel then stores.
func TestTopOfRangePrefixHasNoEndElement_8597(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fam   nlFamily
		addrs []string
		want  []string
	}{
		{
			name: "v4 default route in a multi-prefix list",
			fam:  famV4, addrs: []string{"0.0.0.0/0", "10.0.0.0/8"},
			// 0.0.0.0/0 opens at the bottom and never closes; 10/8 is an
			// ordinary closed interval.
			want: []string{"00000000", "0a000000", "0b000000!end"},
		},
		{
			name: "v4 prefix whose last address is the top",
			fam:  famV4, addrs: []string{"128.0.0.0/1", "10.0.0.0/8"},
			want: []string{"80000000", "0a000000", "0b000000!end"},
		},
		{
			name: "v6 default route",
			fam:  famV6, addrs: []string{"::/0", "2001:db8::/32"},
			want: []string{
				"00000000000000000000000000000000",
				"20010db8000000000000000000000000",
				"20010db9000000000000000000000000!end",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := intervalSetKeys(t, tc.fam, tc.addrs)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d elements %v, want %d %v — a top-of-range prefix must "+
					"emit a START and NO end, not a start plus a wrapped end at the "+
					"bottom of the key space (#8597/K06)", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("element %d = %q, want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// TestOrdinaryPrefixesStillGetTheirEnd_8597 is the OVER-BROAD control. Dropping
// the end element for prefixes that HAVE a valid next address would turn every
// interval into an open-ended one — every set would match from its lowest
// member upward, a total fail-open. This is the case the fix must not touch.
func TestOrdinaryPrefixesStillGetTheirEnd_8597(t *testing.T) {
	got := intervalSetKeys(t, famV4, []string{"10.0.0.0/8", "192.168.0.0/16"})
	want := []string{"0a000000", "0b000000!end", "c0a80000", "c0a90000!end"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("element %d = %q, want %q (full: %v) — an ordinary prefix must keep "+
				"its closed interval", i, got[i], want[i], got)
		}
	}
}

// TestPrefixNextReportsWhetherAnEndExists_8597 pins the helper's contract
// directly. The boolean is the whole change: a value with no way to say "there
// is none" is what forced the wrapped fallback.
func TestPrefixNextReportsWhetherAnEndExists_8597(t *testing.T) {
	for _, tc := range []struct {
		pfx  string
		want string // "" = no end exists
	}{
		{"10.0.0.0/8", "11.0.0.0"},
		{"192.168.0.0/16", "192.169.0.0"},
		{"0.0.0.0/1", "128.0.0.0"},
		{"0.0.0.0/0", ""},
		{"128.0.0.0/1", ""},
		{"255.255.255.255/32", ""},
		{"2001:db8::/32", "2001:db9::"},
		{"::/0", ""},
		{"8000::/1", ""},
	} {
		p := netip.MustParsePrefix(tc.pfx)
		end, ok := prefixNext(p)
		if tc.want == "" {
			if ok {
				t.Errorf("prefixNext(%s) = (%v, true); this prefix reaches the top of the "+
					"key space and has NO first-address-not-covered", tc.pfx, end)
			}
			continue
		}
		if !ok {
			t.Errorf("prefixNext(%s) reported no end; want %s", tc.pfx, tc.want)
			continue
		}
		if end.String() != tc.want {
			t.Errorf("prefixNext(%s) = %v, want %s", tc.pfx, end, tc.want)
		}
	}
}

// TestKernelStoresTheIntervalSetAsEmitted_8597 is the non-vacuity control for
// the whole file, and the reason the cells above assert an ENCODING rather than
// a behaviour.
//
// The kernel ACCEPTS the broken encoding — `Flush` succeeds either way — so an
// install check proves nothing here. What it does do is store exactly what it
// was sent, which is what makes the emitted elements the thing worth pinning.
// This asserts that round-trip, so if a future kernel or library started
// normalising the elements, the unit cells above would be shown to be measuring
// something the kernel no longer preserves.
//
// Skips without CAP_NET_ADMIN, like every other kernel-gated cell in this
// package. Run it with:
//
//	unshare -rn env GOFLAGS=-mod=mod go test ./pkg/nftables/ -run _8597
func TestKernelStoresTheIntervalSetAsEmitted_8597(t *testing.T) {
	enterPrivateNetns(t)
	p := newBuildPlan(t, "xpf_iv_k_8597", hostInboundPriority)
	p.rule().saddr(famV4, []string{"128.0.0.0/1", "10.0.0.0/8"}, false).emit(verdictAccept()...)
	if p.err != nil {
		t.Fatalf("build: %v", p.err)
	}
	if err := p.c.Flush(); err != nil {
		t.Fatalf("kernel rejected the interval set: %v", err)
	}
	c, err := nftables.New()
	if err != nil {
		t.Skipf("nftables.New: %v", err)
	}
	sets, err := c.GetSets(p.table)
	if err != nil {
		t.Fatalf("GetSets: %v", err)
	}
	seen := map[string]bool{}
	for _, s := range sets {
		els, err := c.GetSetElements(s)
		if err != nil {
			t.Fatalf("GetSetElements: %v", err)
		}
		for _, e := range els {
			k := hex.EncodeToString(e.Key)
			if e.IntervalEnd {
				k += "!end"
			}
			seen[k] = true
		}
	}
	if seen["00000000!end"] {
		t.Error("the kernel holds an interval END at 0.0.0.0 for a set whose only " +
			"top-of-range member starts at 128.0.0.0 — the wrapped end is back, at the " +
			"opposite end of the key space from the interval it belongs to (#8597/K06)")
	}
	for _, want := range []string{"80000000", "0a000000", "0b000000!end"} {
		if !seen[want] {
			t.Errorf("the kernel does not hold %q; the emitted encoding is not what is "+
				"stored, so the unit cells above are pinning something the kernel does "+
				"not preserve", want)
		}
	}
}
