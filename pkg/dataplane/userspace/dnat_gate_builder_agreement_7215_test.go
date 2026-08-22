package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7215 — the AGREEMENT gate between the DNAT commit check and the DNAT
// snapshot builder.
//
// validateDestinationNATAddressesStrict (pkg/config, #2396(c)/#3228) exists to
// refuse exactly the `match destination-address` values that
// dnatDestinationParts (below, #3164) would SKIP, so an operator never gets a
// clean commit for an entry the wire never carries. Its doc comment said the
// two "MUST match exactly" — and they did not: the gate stripped the mask text
// before parsing, so it accepted `10.0.0.0/33` while dnatDestinationParts
// returned ok == false and dropped it.
//
// A comment cannot fail. This differential can. It is the reason the gate now
// calls config.NATMatchPrefixParses rather than re-deriving the predicate:
// there is ONE predicate, and this test is what says so.
//
// WHY THIS IS ONE TEST AND NOT TWO. The property being bound is AGREEMENT
// between two functions in two packages, not the behaviour of either. A
// per-function test would pin each to a value table and go green while the
// tables drifted apart — which is precisely how #7215 happened. So the
// assertion is `gate(v) == builder(v)` for every v, and the corpus is chosen to
// straddle the boundary rather than to describe either side.
func TestDNATGateAndBuilderAgree7215(t *testing.T) {
	corpus := []string{
		// Values the builder INSTALLS — the over-rejection side. If the gate
		// ever refuses one of these it bricks the next commit on a working box
		// (#1960). `0.0.0.0/0` and `::/0` ship in docs/ha-cluster-userspace.conf
		// and test/incus/xpf-cluster-fw0.conf today; `1.2.3.4/024` is the
		// zero-padded length Rust's u8::from_str reads as 24 and netip.ParsePrefix
		// refuses.
		"0.0.0.0/0", "::/0", "192.0.2.5", "192.0.2.5/32", "10.0.0.0/8",
		"1.2.3.4/024", "1.2.3.4/0024", "2001:db8::/32", "2001:db8::1",
		"2001:db8::1/128", "::ffff:1.2.3.4", "::ffff:1.2.3.4/120",
		"10.1.2.3/8", "255.255.255.255/32",

		// The #7215 class: the ADDRESS half parses, the whole token does not.
		// Every one of these passed the old gate and was dropped by the builder.
		"10.0.0.0/33", "10.0.0.0/129", "2001:db8::/129", "10.0.0.0/abc",
		"10.0.0.0/", "1.2.3.4/-1", "1.2.3.4/+24", "1.2.3.4/ 24",
		"1.2.3.4/24/25", "10.0.0.1/255.255.255.0", "1.2.3.4/32 ",

		// Values BOTH sides already refused — the #7145 class and friends.
		// They are here so the differential is not a table of only the cells
		// that moved.
		"999.1.1.1/24", "zznotanaddr", "web-server", "", `""`, "/32", "/",
		"fe80::1%eth0", "fe80::1%eth0/64", " 1.2.3.4/24",
	}
	for _, v := range corpus {
		gate := config.NATMatchPrefixParses(v)
		_, _, builder := dnatDestinationParts(v)
		if gate != builder {
			t.Errorf("DIVERGENCE on %q: commit gate accepts=%v, snapshot builder installs=%v.\n"+
				"  gate=true/builder=false is the #7215 defect: a clean commit for an entry "+
				"the wire never carries, leaving traffic to it untranslated with no operator "+
				"feedback.\n"+
				"  gate=false/builder=true is the #1960 brick: a value the dataplane "+
				"forwards on today refused at the operator's next commit.\n"+
				"  Both are regressions; neither is a wording change. Fix the predicate, not "+
				"this corpus.", v, gate, builder)
		}
	}
}
