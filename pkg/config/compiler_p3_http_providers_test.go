package config

import (
	"strings"
	"testing"
)

// compiler_p3_http_providers_test.go: #2691 P3 — the dyndns2 / cloudflare /
// route53 / generic provider backends compile their per-backend leaves
// (credentials config.Secret-redacted) from the flat-set spelling, and the
// commit-time warn-validation flags an incomplete HTTP provider. Fail-on-revert.

func TestP3HTTPProvidersCompile(t *testing.T) {
	tree := buildTree(t, []string{
		// dyndns2 (token-in-password style; duckdns name resolves an endpoint).
		"set system services dynamic-dns provider duckdns backend dyndns2",
		"set system services dynamic-dns provider duckdns username myuser",
		"set system services dynamic-dns provider duckdns password tok-secret-a",
		// cloudflare.
		"set system services dynamic-dns provider cf backend cloudflare",
		"set system services dynamic-dns provider cf api-token cf-secret-b",
		"set system services dynamic-dns provider cf zone example.net",
		// route53.
		"set system services dynamic-dns provider aws backend route53",
		"set system services dynamic-dns provider aws aws-access-key AKID",
		"set system services dynamic-dns provider aws aws-secret-key aws-secret-c",
		"set system services dynamic-dns provider aws aws-region us-west-2",
		"set system services dynamic-dns provider aws hosted-zone-id Z123ABC",
		// generic templated + checkip.
		"set system services dynamic-dns provider tmpl backend generic",
		`set system services dynamic-dns provider tmpl url-template "https://dns.example/upd?h=%h&i=%i"`,
		"set system services dynamic-dns provider tmpl ok-response good",
		"set system services dynamic-dns provider tmpl checkip-url https://checkip.example/",
		"set system services dynamic-dns provider tmpl checkip-allowlist 1.1.1.1,8.8.8.8",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cat := cfg.System.Services.DynamicDNS
	if cat == nil {
		t.Fatal("provider catalog did not compile")
	}

	dd := cat.Providers["duckdns"]
	if dd == nil || dd.Backend != "dyndns2" || dd.Username != "myuser" || dd.Password != "tok-secret-a" {
		t.Fatalf("duckdns provider mismatch: %+v", dd)
	}
	cf := cat.Providers["cf"]
	if cf == nil || cf.Backend != "cloudflare" || cf.APIToken != "cf-secret-b" || cf.Zone != "example.net" {
		t.Fatalf("cf provider mismatch: %+v", cf)
	}
	aws := cat.Providers["aws"]
	if aws == nil || aws.Backend != "route53" || aws.AWSAccessKeyID != "AKID" ||
		aws.AWSSecretAccessKey != "aws-secret-c" || aws.AWSRegion != "us-west-2" || aws.HostedZoneID != "Z123ABC" {
		t.Fatalf("aws provider mismatch: %+v", aws)
	}
	tmpl := cat.Providers["tmpl"]
	if tmpl == nil || tmpl.Backend != "generic" ||
		tmpl.URLTemplate != "https://dns.example/upd?h=%h&i=%i" || tmpl.OKResponse != "good" ||
		tmpl.CheckIPURL != "https://checkip.example/" || tmpl.CheckIPAllowlist != "1.1.1.1,8.8.8.8" {
		t.Fatalf("tmpl provider mismatch: %+v", tmpl)
	}

	// Every secret must be redacted in String() (logging hygiene; plan §8.1).
	for _, p := range []*DDNSProvider{cf, aws, dd} {
		s := p.String()
		for _, secret := range []string{"cf-secret-b", "aws-secret-c", "tok-secret-a"} {
			if strings.Contains(s, secret) {
				t.Fatalf("provider %q String() leaked a secret: %s", p.Name, s)
			}
		}
	}
}

func TestP3HTTPProviderHierarchicalCompiles(t *testing.T) {
	// The brace form must compile identically to flat-set.
	const cfgText = `system {
  services {
    dynamic-dns {
      provider cf {
        backend cloudflare;
        api-token cf-secret-b;
        zone example.net;
      }
    }
  }
}`
	tree, perr := NewParser(cfgText).Parse()
	if len(perr) != 0 {
		t.Fatalf("Parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cf := cfg.System.Services.DynamicDNS.Providers["cf"]
	if cf == nil || cf.Backend != "cloudflare" || cf.APIToken != "cf-secret-b" || cf.Zone != "example.net" {
		t.Fatalf("hierarchical cf provider mismatch: %+v", cf)
	}
}

func TestP3IncompleteHTTPProviderWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider cf backend cloudflare", // no api-token, no zone
		"set system services dynamic-dns provider aws backend route53",   // no keys/zone-id
		"set system services dynamic-dns provider g backend generic",     // no url-template
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")
	for _, want := range []string{"no api-token", "no zone", "aws-access-key", "no hosted-zone-id", "no url-template"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a warning containing %q; got:\n%s", want, joined)
		}
	}
}

// TestP3CheckIPURLMalformedWarns is the #2773 fail-on-revert gate: a malformed
// checkip-url must be flagged at commit (was dead code — validateCheckIPURL had
// no callers, so a typo committed silently and then masqueraded forever as a
// transient observation failure that suppressed publishing). Goes GREEN with the
// validateSurfaceADDNSWarnings wiring and RED if that wiring is removed. The
// valid-URL providers in the same config must NOT warn (no false positives).
func TestP3CheckIPURLMalformedWarns(t *testing.T) {
	tree := buildTree(t, []string{
		// Malformed checkip-urls that http.NewRequest would otherwise accept and
		// then fail to fetch forever.
		"set system services dynamic-dns provider bad-scheme backend dyndns2",
		"set system services dynamic-dns provider bad-scheme server dyn.example",
		"set system services dynamic-dns provider bad-scheme checkip-url ftp://checkip.example/",
		"set system services dynamic-dns provider no-host backend dyndns2",
		"set system services dynamic-dns provider no-host server dyn.example",
		"set system services dynamic-dns provider no-host checkip-url http://",
		"set system services dynamic-dns provider junk backend dyndns2",
		"set system services dynamic-dns provider junk server dyn.example",
		`set system services dynamic-dns provider junk checkip-url "not a url"`,
		// A valid checkip-url must NOT warn.
		"set system services dynamic-dns provider good backend dyndns2",
		"set system services dynamic-dns provider good server dyn.example",
		"set system services dynamic-dns provider good checkip-url https://checkip.example/",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")

	for _, badName := range []string{"bad-scheme", "no-host", "junk"} {
		want := "provider \"" + badName + "\" checkip-url"
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a checkip-url warning for provider %q; got:\n%s", badName, joined)
		}
	}
	if strings.Contains(joined, "provider \"good\" checkip-url") {
		t.Fatalf("valid checkip-url should not warn; got:\n%s", joined)
	}
}

// TestP3CheckIPAllowlistMalformedWarns is the #2839 fail-on-revert gate: a
// malformed checkip-allowlist token (operator typo, e.g. "8.8.8.8x") was
// SILENTLY DROPPED by ddns.ParseAllowlist, so the bogus-IP safety gate silently
// shrank and the checkip parser admitted the very IP the operator meant to
// suppress. The commit-time warn pass must now name the offending token. Goes
// RED if ddnsAllowlistMalformedTokens / its wiring is removed (back to silent
// drop). The valid-token provider in the same config must NOT warn.
func TestP3CheckIPAllowlistMalformedWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider bad backend dyndns2",
		"set system services dynamic-dns provider bad server dyn.example",
		"set system services dynamic-dns provider bad checkip-url https://checkip.example/",
		// A typoed v4 token + a bare word; the valid 1.1.1.1 is retained.
		"set system services dynamic-dns provider bad checkip-allowlist 1.1.1.1,8.8.8.8x",
		// A provider whose allowlist is entirely valid must NOT warn.
		"set system services dynamic-dns provider good backend dyndns2",
		"set system services dynamic-dns provider good server dyn.example",
		"set system services dynamic-dns provider good checkip-url https://checkip.example/",
		"set system services dynamic-dns provider good checkip-allowlist 1.1.1.1,2606:4700::1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")

	// The offending token must be NAMED for provider "bad".
	for _, want := range []string{
		"provider \"bad\" checkip-allowlist",
		"8.8.8.8x",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a checkip-allowlist warning containing %q; got:\n%s", want, joined)
		}
	}
	// The valid v4 token in the same "bad" allowlist must not be flagged.
	if strings.Contains(joined, "entry \"1.1.1.1\"") {
		t.Fatalf("valid allowlist token 1.1.1.1 must not warn; got:\n%s", joined)
	}
	// Provider "good" (all valid) must not warn.
	if strings.Contains(joined, "provider \"good\" checkip-allowlist") {
		t.Fatalf("valid checkip-allowlist should not warn; got:\n%s", joined)
	}
}

// TestP3CheckIPURLUppercaseSchemeAccepted is the #2842 fail-on-revert gate: a
// checkip-url with an uppercase/mixed-case scheme is valid per RFC 3986 §3.1
// (the scheme is case-INSENSITIVE) and must NOT warn. Goes RED if the mirror
// ddnsCheckIPURLValid reverts to a case-sensitive HasPrefix on the raw string.
func TestP3CheckIPURLUppercaseSchemeAccepted(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider up-http backend dyndns2",
		"set system services dynamic-dns provider up-http server dyn.example",
		"set system services dynamic-dns provider up-http checkip-url HTTP://checkip.example/",
		"set system services dynamic-dns provider mixed-https backend dyndns2",
		"set system services dynamic-dns provider mixed-https server dyn.example",
		"set system services dynamic-dns provider mixed-https checkip-url Https://h/",
		// A non-http scheme and a host-less URL must STILL warn (no over-accept).
		"set system services dynamic-dns provider bad-scheme backend dyndns2",
		"set system services dynamic-dns provider bad-scheme server dyn.example",
		"set system services dynamic-dns provider bad-scheme checkip-url ftp://checkip.example/",
		"set system services dynamic-dns provider no-host backend dyndns2",
		"set system services dynamic-dns provider no-host server dyn.example",
		"set system services dynamic-dns provider no-host checkip-url http://",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	joined := strings.Join(validateSurfaceADDNSWarnings(cfg), "\n")

	for _, okName := range []string{"up-http", "mixed-https"} {
		if strings.Contains(joined, "provider \""+okName+"\" checkip-url") {
			t.Fatalf("uppercase-scheme checkip-url should not warn for %q; got:\n%s", okName, joined)
		}
	}
	for _, badName := range []string{"bad-scheme", "no-host"} {
		if !strings.Contains(joined, "provider \""+badName+"\" checkip-url") {
			t.Fatalf("expected a checkip-url warning for provider %q; got:\n%s", badName, joined)
		}
	}
}
