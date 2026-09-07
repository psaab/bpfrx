package config

import (
	"strings"
	"testing"
)

// #9407 advisory. The kernel-name resolver cannot resolve a unit the config
// never declares — it returns the reference verbatim, and `ge-0-0-1.0` is not a
// device. Guessing (a blanket ".0" strip) would rewrite a legitimately dotted
// DECLARED interface name too (#8994), so the residual is SAID rather than
// guessed at.

const keaIfaces9407 = `
interfaces {
    ge-0/0/1 {
        gigether-options { redundant-parent reth1; }
    }
    reth1 {
        redundant-ether-options { redundancy-group 1; }
        unit 0 { family inet { address 10.0.61.1/24; } }
        unit 80 { vlan-id 180; family inet { address 10.0.80.1/24; } }
    }
}
`

func keaWarn9407(t *testing.T, body string) []string {
	t.Helper()
	text := keaIfaces9407 + `
system {
    services {
        dhcp-local-server {
            group g1 { ` + body + ` }
        }
    }
}
`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#9407") {
			out = append(out, w)
		}
	}
	return out
}

func TestDHCPServerInterfaceRefWarnings9407(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{
			name: "declared untagged unit is silent",
			body: "interface reth1.0;",
		},
		{
			name: "declared tagged unit is silent",
			body: "interface reth1.80;",
		},
		{
			name: "undeclared unit is the case the resolver cannot resolve",
			body: "interface reth1.7;",
			want: "interface reth1.7 names no configured unit on reth1",
		},
		{
			name: "undeclared interface",
			body: "interface reth9.0;",
			want: "interface reth9.0 names no configured interface",
		},
		{
			name: "the consequence names Kea and the symptom",
			body: "interface reth9.0;",
			want: "Kea will be given a device name the kernel does not have",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := keaWarn9407(t, tc.body)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected silence, got %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("no #9407 advisory; want one carrying %q", tc.want)
			}
			if joined := strings.Join(got, "\n"); !strings.Contains(joined, tc.want) {
				t.Fatalf("advisory %q does not carry %q", joined, tc.want)
			}
		})
	}
}

// The DHCPv6 family shares the derivation, so it must share the advisory.
func TestDHCPServerInterfaceRefWarningsCoversV6_9407(t *testing.T) {
	text := keaIfaces9407 + `
system {
    services {
        dhcpv6-local-server {
            group g6 { interface reth9.0; }
        }
    }
}
`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	var got []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#9407") {
			got = append(got, w)
		}
	}
	if len(got) == 0 {
		t.Fatal("no #9407 advisory for a DHCPv6 group; the v6 family shares the " +
			"derivation, so a v4-only advisory covers half the surface")
	}
	if !strings.Contains(strings.Join(got, "\n"), "dhcpv6-local-server group g6") {
		t.Fatalf("advisory %v does not name the v6 family and group", got)
	}
}
