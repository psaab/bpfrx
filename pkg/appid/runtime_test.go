package appid

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCatalogNamesReferencedOnly(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-web": {Name: "custom-web", Protocol: "tcp", DestinationPort: "8443"},
			},
			ApplicationSets: map[string]*config.ApplicationSet{
				"web-set": {Name: "web-set", Applications: []string{"junos-http", "custom-web"}},
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					Policies: []*config.Policy{
						{Match: config.PolicyMatch{Applications: []string{"web-set"}}},
					},
				},
			},
		},
	}

	got, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	want := []string{"custom-web", "junos-http"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CatalogNames() = %v, want %v", got, want)
	}
}

func TestResolveSessionNameUsesAppIDWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	got := ResolveSessionName(map[uint16]string{7: "junos-http"}, cfg, 6, 80, 7)
	if got != "junos-http" {
		t.Fatalf("ResolveSessionName() = %q, want junos-http", got)
	}
}

func TestResolveSessionNameUnknownWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	got := ResolveSessionName(nil, cfg, 6, 80, 0)
	if got != Unknown {
		t.Fatalf("ResolveSessionName() = %q, want %q", got, Unknown)
	}
}

func TestResolveSessionNameFallbackWhenDisabled(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-web": {Name: "custom-web", Protocol: "tcp", DestinationPort: "8443-8445"},
			},
		},
	}

	got := ResolveSessionName(nil, cfg, 6, 8444, 0)
	if got != "custom-web" {
		t.Fatalf("ResolveSessionName() = %q, want custom-web", got)
	}
}

func TestSessionMatchesUnknown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	if !SessionMatches("unknown", nil, cfg, 6, 80, 0) {
		t.Fatal("SessionMatches() should match UNKNOWN when AppID is enabled")
	}
}
