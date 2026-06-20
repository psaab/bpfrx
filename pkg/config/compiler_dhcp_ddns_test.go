package config

import (
	"strings"
	"testing"
)

// #1387 DHCP dynamic-dns config-model tests. All use the production
// ParseSetCommand + SetPath path (buildTree), never NewParser (the
// flat-set merge gotcha in CLAUDE.md). They prove the dual-AST compile,
// the empty-block-is-absent guard, TSIG redaction, and the schema typed
// leaves (enum + ttl validators) at commit check.

func ddnsOf(t *testing.T, cfg *Config) *DHCPDynamicDNSConfig {
	t.Helper()
	return cfg.System.DHCPServer.DynamicDNS
}

func TestDHCPDDNSHierarchicalAndFlatSetCompileEqually(t *testing.T) {
	// Dual-AST equality: the hierarchical block and the flat-set spelling
	// must compile to the same typed DHCPDynamicDNSConfig (plan §5 inv 5).
	flat := buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns domain corp.example.com",
		"set system services dhcp-local-server dynamic-dns ttl 600",
		"set system services dhcp-local-server dynamic-dns hostname-source fqdn",
		"set system services dhcp-local-server dynamic-dns conflict-policy strict-fail",
		"set system services dhcp-local-server dynamic-dns backend rfc2136",
		"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
		"set system services dhcp-local-server dynamic-dns tsig-key xpf-key",
		"set system services dhcp-local-server dynamic-dns tsig-algorithm hmac-sha256",
		"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
	})
	cflat, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("CompileConfig(flat): %v", err)
	}
	df := ddnsOf(t, cflat)
	if df == nil {
		t.Fatal("flat-set DDNS compiled to nil")
	}

	want := &DHCPDynamicDNSConfig{
		Enabled:        true,
		Domain:         "corp.example.com",
		TTLSeconds:     600,
		HostnameSource: "fqdn",
		ConflictPolicy: "strict-fail",
		Backend:        "rfc2136",
		UpdateServer:   "192.0.2.53",
		TSIGKeyName:    "xpf-key",
		TSIGAlgorithm:  "hmac-sha256",
		TSIGSecret:     "c2VjcmV0",
	}
	if *df != *want {
		t.Fatalf("flat-set DDNS mismatch:\n got %+v\nwant %+v", *df, *want)
	}

	// Hierarchical NewParser path: build the same content through the
	// real parser to prove the hierarchical AST compiles identically.
	hierSrc := `system {
  services {
    dhcp-local-server {
      dynamic-dns {
        enable;
        domain corp.example.com;
        ttl 600;
        hostname-source fqdn;
        conflict-policy strict-fail;
        backend rfc2136;
        update-server 192.0.2.53;
        tsig-key xpf-key;
        tsig-algorithm hmac-sha256;
        tsig-secret c2VjcmV0;
      }
    }
  }
}`
	hp := NewParser(hierSrc)
	htree, perrs := hp.Parse()
	if len(perrs) > 0 {
		t.Fatalf("hierarchical Parse: %v", perrs)
	}
	chier, err := CompileConfig(htree)
	if err != nil {
		t.Fatalf("CompileConfig(hier): %v", err)
	}
	dh := ddnsOf(t, chier)
	if dh == nil {
		t.Fatal("hierarchical DDNS compiled to nil")
	}
	if *dh != *df {
		t.Fatalf("hierarchical vs flat-set DDNS differ:\n hier %+v\n flat %+v", *dh, *df)
	}
}

func TestDHCPDDNSAbsentByDefault(t *testing.T) {
	// No dynamic-dns stanza => nil block => zero behaviour change.
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server group g0 interface ge-0/0/0",
		"set system services dhcp-local-server group g0 pool p0 subnet 10.0.1.0/24",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if ddnsOf(t, cfg) != nil {
		t.Fatal("absent dynamic-dns must compile to nil DynamicDNS")
	}
}

func TestDHCPDDNSV6BlockCompiles(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcpv6-local-server dynamic-dns enable",
		"set system services dhcpv6-local-server dynamic-dns domain v6.example.com",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	d := ddnsOf(t, cfg)
	if d == nil || !d.Enabled || d.Domain != "v6.example.com" {
		t.Fatalf("v6 dynamic-dns not compiled: %+v", d)
	}
}

func TestDHCPDDNSStringRedactsTSIGSecret(t *testing.T) {
	d := &DHCPDynamicDNSConfig{
		Enabled:       true,
		TSIGKeyName:   "k",
		TSIGAlgorithm: "hmac-sha256",
		TSIGSecret:    "TOPSECRET-base64==",
	}
	s := d.String()
	if strings.Contains(s, "TOPSECRET") {
		t.Fatalf("String() leaked TSIG secret: %q", s)
	}
	if !strings.Contains(s, "<redacted>") {
		t.Fatalf("String() did not redact a set secret: %q", s)
	}
	// An unset secret renders empty, not <redacted>.
	d.TSIGSecret = ""
	if strings.Contains(d.String(), "<redacted>") {
		t.Fatalf("String() redacted an empty secret: %q", d.String())
	}
}

func TestDHCPDDNSSchemaAcceptsValidLeaves(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns ttl 300",
		"set system services dhcp-local-server dynamic-dns hostname-source client-hostname",
		"set system services dhcp-local-server dynamic-dns conflict-policy replace-owned",
		"set system services dhcp-local-server dynamic-dns backend rfc2136",
	})
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected valid DDNS leaves: %v", err)
	}
}

func TestDHCPDDNSSchemaRejectsBadEnumAndTTL(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"bad hostname-source", "set system services dhcp-local-server dynamic-dns hostname-source bogus"},
		{"bad conflict-policy", "set system services dhcp-local-server dynamic-dns conflict-policy maybe"},
		{"bad backend", "set system services dhcp-local-server dynamic-dns backend windows-dns"},
		{"zero ttl", "set system services dhcp-local-server dynamic-dns ttl 0"},
		{"garbage ttl", "set system services dhcp-local-server dynamic-dns ttl notanumber"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("SchemaValidate accepted invalid leaf %q", tc.line)
			}
		})
	}
}
