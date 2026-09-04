package natshow

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8580 — the shared source-NAT rule rendering, and a census that stops a
// private copy coming back.
//
// THE DRIFT THIS REPLACES. Five surfaces rendered a rule's action from their
// own copy of the same switch. Counting reads of `Then.Off` per file before
// this change: pkg/natshow 1, pkg/cli 0, pkg/api 0, pkg/grpcapi 0. So #7640
// ("render the action the rule ACTUALLY carries") and #7363 (the full address
// match) landed in one copy and left four wrong — `then source-nat off`
// reported as `interface`, its exact opposite, and an address-book-scoped rule
// reported as matching everything.
//
// WHY SINGLE-SOURCED RATHER THAN CROSS-CHECKED, per #8258's predicate: an
// agreement test between five copies must pick a spelling to compare against,
// which encodes which copy is trusted, and it does not stop a sixth copy being
// written. Routing every surface through one function removes the class. What
// remains to guard is (a) that the one function is right, and (b) that nobody
// writes copy six — which is what the census below is for.

func TestSourceRuleActionCases_8580(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule *config.NATRule
		want string
	}{
		{"pool", &config.NATRule{Then: config.NATThen{PoolName: "p1"}}, "pool p1"},
		// The two the four private copies got wrong.
		{"off", &config.NATRule{Then: config.NATThen{Off: true}}, "off"},
		{"actionless", &config.NATRule{}, "none"},
		// The ordinary case the private copies got right, kept so a fix that
		// broke it would be visible rather than traded away.
		{"interface", &config.NATRule{Then: config.NATThen{Interface: true}}, "interface"},
		// Precedence: a pool wins over a stray `off`, matching the renderer's
		// switch order rather than an alphabetical accident.
		{"pool-beats-off", &config.NATRule{Then: config.NATThen{PoolName: "p1", Off: true}}, "pool p1"},
		{"nil", nil, "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SourceRuleAction(tc.rule); got != tc.want {
				t.Fatalf("SourceRuleAction = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSourceRuleMatchShapes_8580(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule *config.NATRule
		want string
	}{
		{"none", &config.NATRule{}, "0.0.0.0/0"},
		{"singular-cidr", &config.NATRule{Match: config.NATMatch{SourceAddress: "10.0.0.0/8"}}, "10.0.0.0/8"},
		// The bracket-list shape: the singular field holds only the FIRST
		// element, so a copy reading it alone under-reports the scope.
		{
			"plural-cidrs",
			&config.NATRule{Match: config.NATMatch{
				SourceAddress:   "10.0.0.0/8",
				SourceAddresses: []string{"10.0.0.0/8", "192.168.0.0/16"},
			}},
			"10.0.0.0/8 192.168.0.0/16",
		},
		// The address-book shape: the singular CIDR field is EMPTY, so a copy
		// reading it alone falls back to 0.0.0.0/0 and reports the rule as
		// matching every source.
		{
			"address-book-name",
			&config.NATRule{Match: config.NATMatch{SourceAddressName: "trusted"}},
			"trusted",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RuleMatchSource(tc.rule); got != tc.want {
				t.Fatalf("RuleMatchSource = %q, want %q", got, tc.want)
			}
		})
	}
	// The destination side is a separate field set and was fixed separately in
	// #7363 for exactly that reason.
	d := &config.NATRule{Match: config.NATMatch{DestinationAddressName: "servers"}}
	if got := RuleMatchDestination(d); got != "servers" {
		t.Fatalf("RuleMatchDestination = %q, want %q", got, "servers")
	}
}

// natRenderSurfaces are the files that render a source-NAT rule's action. If a
// sixth surface is added it belongs here, and the census below is what makes
// that a build failure rather than a silent fifth divergence.
var natRenderSurfaces = []string{
	filepath.Join("..", "cli", "cli_show_nat.go"),
	filepath.Join("..", "api", "nat.go"),
	filepath.Join("..", "grpcapi", "server_nat.go"),
}

var (
	privateActionCopyRe = regexp.MustCompile(`(?m)^\s*action := "interface"`)
	privateMatchCopyRe  = regexp.MustCompile(`(?m)^\s*(src|dst)Match := "0\.0\.0\.0/0"`)
	sharedCallRe        = regexp.MustCompile(`natshow\.SourceRule(Action|MatchSource|MatchDestination)\(`)
)

// TestNATRenderSurfacesUseTheSharedComputation_8580 is the census, and it is
// the part that survives this change rather than describing it.
func TestNATRenderSurfacesUseTheSharedComputation_8580(t *testing.T) {
	for _, rel := range natRenderSurfaces {
		src, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("read %s: %v — the census cannot run, and a census that "+
				"cannot read its population passes vacuously", rel, err)
		}
		text := string(src)

		// POSITIVE CONTROL FIRST. A scan whose pattern has rotted finds
		// nothing, matches nothing against nothing, and passes forever — the
		// failure a census is least able to notice about itself, because the
		// census is what you would consult to find it. Every file in this list
		// must be seen to CALL the shared computation; if one does not, either
		// it stopped rendering rules (remove it here) or the pattern is wrong.
		if !sharedCallRe.MatchString(text) {
			t.Fatalf("%s does not call natshow.SourceRule* at all. Either this file no "+
				"longer renders source-NAT rules — in which case drop it from "+
				"natRenderSurfaces — or the scan below is matching a name that no longer "+
				"exists and is asserting nothing", rel)
		}

		if m := privateActionCopyRe.FindString(text); m != "" {
			t.Errorf("%s reintroduces a private copy of the rule-action switch (%q).\n"+
				"That copy is how `then source-nat off` came to be reported as \"interface\" "+
				"— its exact opposite — on four surfaces at once, and how an ACTIONLESS rule "+
				"came to claim it translates. Call natshow.SourceRuleAction.",
				rel, strings.TrimSpace(m))
		}
		if m := privateMatchCopyRe.FindString(text); m != "" {
			t.Errorf("%s reintroduces a private copy of the address-match default (%q).\n"+
				"Reading the singular field alone renders an address-book-scoped rule as "+
				"0.0.0.0/0 — matching EVERY source — and a bracket list as only its first "+
				"element. Call natshow.RuleMatchSource / ...Destination.",
				rel, strings.TrimSpace(m))
		}
	}
}
