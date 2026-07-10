package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// childSectionNames returns the trimmed swanctl child-section header names
// (the `<name> {` line inside the children{} block) that begin with the given
// connection-name prefix. It returns every occurrence, so a duplicate name
// shows up twice — the exact symptom of the #5122 collision.
func childSectionNames(rendered, connPrefix string) []string {
	var names []string
	for _, line := range strings.Split(rendered, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, connPrefix+"-") {
			continue
		}
		if !strings.HasSuffix(trimmed, " {") {
			continue
		}
		names = append(names, strings.TrimSuffix(trimmed, " {"))
	}
	return names
}

// TestChildNameCollisionDisambiguated is the #5122 RED-on-revert guard. Two
// distinct traffic-selector names that differ ONLY in a sanitized character
// (`site/a` vs `site:a` — both legal Junos identifier chars) both sanitize to
// the base `site-a`. Before the fix effectiveTrafficSelectors emitted TWO
// `tun1-site-a {` child sections with identical names, so strongSwan rejected
// the config or silently merged/lost one selector. The fix appends a stable
// hash of the original selector name to each colliding entry, so both sections
// render with DISTINCT names and neither selector is dropped.
//
// Reverting the disambiguation in policy.go makes both sections share the name
// `tun1-site-a` and this test goes RED.
func TestChildNameCollisionDisambiguated(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"site/a": {Name: "site/a", LocalIP: "10.0.1.0/24", RemoteIP: "10.0.9.0/24"},
					"site:a": {Name: "site:a", LocalIP: "10.0.2.0/24", RemoteIP: "10.0.9.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
	}

	got := m.generateConfig(cfg)

	names := childSectionNames(got, "tun1")
	if len(names) != 2 {
		t.Fatalf("expected 2 child sections for the two selectors, got %d: %v\n%s",
			len(names), names, got)
	}
	if names[0] == names[1] {
		t.Fatalf("distinct selectors site/a and site:a rendered DUPLICATE child "+
			"section name %q (strongSwan would reject/merge one selector, #5122):\n%s",
			names[0], got)
	}
	// Both selectors must survive to the render — assert each distinct local_ts
	// prefix is present, proving neither child was overwritten/dropped.
	if !strings.Contains(got, "local_ts = 10.0.1.0/24") {
		t.Fatalf("selector site/a (local_ts 10.0.1.0/24) missing from render:\n%s", got)
	}
	if !strings.Contains(got, "local_ts = 10.0.2.0/24") {
		t.Fatalf("selector site:a (local_ts 10.0.2.0/24) missing from render:\n%s", got)
	}
	// Both disambiguated names must keep the sanitized base as a prefix so the
	// naming stays recognizable / stable-shaped.
	for _, n := range names {
		if !strings.HasPrefix(n, "tun1-site-a") {
			t.Fatalf("disambiguated child section %q lost the sanitized base prefix "+
				"tun1-site-a:\n%s", n, got)
		}
	}
}

// TestChildNameNonCollidingUnchanged is the no-churn negative control: two
// selectors whose sanitized bases already differ (and a lone selector) keep
// their plain `connName-<sanitized>` names with NO hash suffix. Only an actual
// collision may trigger disambiguation.
func TestChildNameNonCollidingUnchanged(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"alpha": {Name: "alpha", LocalIP: "10.0.1.0/24", RemoteIP: "10.0.9.0/24"},
					"beta":  {Name: "beta", LocalIP: "10.0.2.0/24", RemoteIP: "10.0.9.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
	}

	got := m.generateConfig(cfg)
	names := childSectionNames(got, "tun1")
	want := map[string]bool{"tun1-alpha": true, "tun1-beta": true}
	if len(names) != 2 {
		t.Fatalf("expected 2 child sections, got %d: %v\n%s", len(names), names, got)
	}
	for _, n := range names {
		if !want[n] {
			t.Fatalf("non-colliding selector rendered unexpected/disambiguated name "+
				"%q (want one of %v):\n%s", n, want, got)
		}
	}
}

// TestChildNameSingleSelectorUnchanged asserts a normal single selector renders
// its `connName-<sanitized>` name unchanged (no disambiguator applied).
func TestChildNameSingleSelectorUnchanged(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.0.1.0/24", RemoteIP: "10.0.9.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
	}

	got := m.generateConfig(cfg)
	if !strings.Contains(got, "tun1-ts1 {\n") {
		t.Fatalf("single selector did not render its plain child section tun1-ts1:\n%s", got)
	}
}
