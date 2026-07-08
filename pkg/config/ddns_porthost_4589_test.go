package config

import (
	"strings"
	"testing"
)

// #4589 A10-b2 F-01: ddnsGenericURLTemplateValid (the #2841 commit-time
// mirror of pkg/ddns.validateGenericURLTemplate) only checked
// `authority != ""`, so `http://:8080/upd` — non-empty authority, EMPTY
// host — warned-clean AND constructed-clean, deferring the failure to the
// first publish. Require a non-empty host after dropping the :port (and
// unwrapping a bracketed IPv6 literal). Kept in lockstep with
// pkg/ddns.ddnsTemplateHost.
//
// RED-on-revert: without the host extraction the port-only provider does
// not warn.
func TestP3GenericURLTemplatePortOnlyHostWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider port-only backend generic",
		`set system services dynamic-dns provider port-only url-template "http://:8080/upd?ip=%i"`,
		// A bracketed IPv6 literal host is VALID and must not warn.
		"set system services dynamic-dns provider v6 backend generic",
		`set system services dynamic-dns provider v6 url-template "http://[2001:db8::1]:8080/upd?ip=%i"`,
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	joined := strings.Join(validateSurfaceADDNSWarnings(cfg), "\n")
	if !strings.Contains(joined, `provider "port-only" url-template`) {
		t.Fatalf("expected a url-template warning for the port-only host; got:\n%s", joined)
	}
	if strings.Contains(joined, `provider "v6" url-template`) {
		t.Fatalf("a bracketed IPv6 host must not warn; got:\n%s", joined)
	}
}
