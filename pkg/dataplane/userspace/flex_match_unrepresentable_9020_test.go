package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9020: an UNREPRESENTABLE flexible-match-range shipped to the userspace
// filter as a DEFAULTED LIVE match on the tolerant load / peer-sync path.
//
// The compiler records the unrepresentable tokens in UnknownFlexMatch and then
// assigns term.FlexMatch anyway, so the term reached the dataplane enforcing
// something the operator never wrote: `byte-offset 999` became offset 0, an
// unparseable `match-value` became 0, and a `match-start` outside
// {layer-3, layer-4} was evaluated at the L3 base. A discard term then dropped
// traffic it should not and admitted the traffic it was written to drop.
//
// The strict commit gate already rejects all of these, so this is reachable
// ONLY on the tolerant path (#1960) — which is exactly the path that cannot
// reject, so it must fail CLOSED instead.
//
// The nftables sibling has always checked both conditions
// (daemon_nft.go:2248); only this path checked one.
//
// FIXTURE NOTE, because it cost four attempts: the compiler expects a nested
// `range <name>` level — `flexible-match-range { range r1 { ... } }`. Without
// it nothing compiles at all and EVERY row reads flexMatch=nil, which looks
// exactly like "no defect". The GOOD row below is the liveness control that
// makes the others meaningful.

func flexTermSnapshot9020(t *testing.T, fromBody string) (unknown []string, snapJSON string) {
	t.Helper()
	src := `firewall { family inet { filter F { term T { from { ` + fromBody + ` } then { discard; } } } } }`
	tree, perrs := config.NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs[0])
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("lenient compile: %v", err)
	}
	for _, f := range cfg.Firewall.FiltersInet {
		for _, term := range f.Terms {
			unknown = term.UnknownFlexMatch
		}
	}
	b, err := json.Marshal(BuildFirewallFilterSnapshots(cfg))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return unknown, string(b)
}

func TestUnrepresentableFlexMatchFailsClosed9020(t *testing.T) {
	// LIVENESS: a representable range must ship a REAL match. Without this the
	// assertions below pass against a fixture that compiles to nothing — which
	// is what the first four attempts at this fixture did.
	unk, good := flexTermSnapshot9020(t,
		`flexible-match-range { range r1 { match-start layer-3; byte-offset 4; bit-length 16; match-value 0x1234; } }`)
	if len(unk) != 0 {
		t.Fatalf("the representable fixture recorded unknown tokens %v — it is not a control", unk)
	}
	if !strings.Contains(good, `"offset":4`) || !strings.Contains(good, `"value":4660`) {
		t.Fatalf("the representable fixture did not ship a live match: %s", good)
	}
	if strings.Contains(good, flexMatchStartUnrepresentable) {
		t.Fatalf("the representable fixture was poisoned; the fix is over-broad: %s", good)
	}

	for _, c := range []struct{ name, body, wantToken string }{
		{"byte-offset out of range",
			`flexible-match-range { range r1 { match-start layer-3; byte-offset 999; bit-length 16; match-value 0x1234; } }`,
			"byte-offset 999"},
		{"unparseable match-value",
			`flexible-match-range { range r1 { match-start layer-3; byte-offset 4; bit-length 16; match-value 0xZZZZ; } }`,
			"match-value 0xZZZZ"},
		{"match-start outside layer-3/layer-4",
			`flexible-match-range { range r1 { match-start payload; byte-offset 4; bit-length 16; match-value 0x1234; } }`,
			"match-start payload"},
	} {
		t.Run(c.name, func(t *testing.T) {
			unknown, snap := flexTermSnapshot9020(t, c.body)
			// The compiler must have SEEN it as unrepresentable, or this row is
			// measuring a representable value and proves nothing.
			found := false
			for _, u := range unknown {
				if u == c.wantToken {
					found = true
				}
			}
			if !found {
				t.Fatalf("UnknownFlexMatch = %v, want it to contain %q — the compiler did not "+
					"record this as unrepresentable, so the fixture is not exercising the defect",
					unknown, c.wantToken)
			}
			if !strings.Contains(snap, flexMatchStartUnrepresentable) {
				t.Errorf("an unrepresentable flexible-match-range shipped a LIVE match to the "+
					"dataplane instead of failing closed. The term enforces something the "+
					"operator never wrote — a discard drops traffic it should not and admits "+
					"the traffic it was written to drop.\nsnapshot: %s", snap)
			}
		})
	}
}

// The sentinel must not name a cause the operator may not have. It reaches
// `show firewall ... effective`, and it now covers two causes.
func TestSentinelDoesNotClaimMultiRange9020(t *testing.T) {
	if strings.Contains(flexMatchStartUnrepresentable, "multi") {
		t.Errorf("the fail-closed sentinel is %q — it reaches operator-facing output and would "+
			"tell someone with ONE range that their term names several",
			flexMatchStartUnrepresentable)
	}
	// And it must still not be a real match-start, or the Rust side would
	// evaluate it as a base instead of lowering to Unsupported.
	if flexMatchStartUnrepresentable == "layer-3" || flexMatchStartUnrepresentable == "layer-4" {
		t.Fatalf("the sentinel %q is a REAL match-start; the Rust compiler would evaluate the "+
			"term at that base rather than failing it closed", flexMatchStartUnrepresentable)
	}
}
