package daemon

// #4902 render-side belts (defense-in-depth): even if a crafted `system`
// string slips past the strict commit-check (the tolerant load / peer-sync
// path only warns, #1960), the renderers must not emit it verbatim into a
// root-owned service config. These tests drive an injection/breakage value
// through each renderer and assert it is skipped/filtered.
//
// Fail-on-revert: drop the config.Validate* guard from a renderer (or run
// against origin/master) and the corresponding assertion fires.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRenderChronySources_SkipsInjected_4902(t *testing.T) {
	got := renderChronySources([]string{
		"10.0.0.1",                          // valid IP
		"pool.example.net",                  // valid hostname
		"pool.example.net local stratum 10", // embedded space -> skip
		"evil.example\nmakestep 1 -1",       // newline -> skip
	}, nil)
	// Valid servers still render.
	if !strings.Contains(got, "server 10.0.0.1 iburst\n") {
		t.Errorf("valid IP server dropped; got:\n%s", got)
	}
	if !strings.Contains(got, "pool pool.example.net iburst\n") {
		t.Errorf("valid hostname server dropped; got:\n%s", got)
	}
	// No injected token / directive survives.
	if strings.Contains(got, "stratum") || strings.Contains(got, "makestep") {
		t.Errorf("injected NTP token reached chrony sources; got:\n%s", got)
	}
	// Exactly the two valid source lines.
	if n := strings.Count(got, "iburst"); n != 2 {
		t.Errorf("expected 2 rendered source lines, got %d; output:\n%s", n, got)
	}
}

func TestBuildSSHDConfig_FiltersInjectedAlgorithms_4902(t *testing.T) {
	ssh := &config.SSHServiceConfig{
		KeyExchange: []string{"curve25519-sha256", "kex,PermitRootLogin yes"},
		Ciphers:     []string{"aes256-gcm@openssh.com", "bad cipher"},
		MACs:        []string{"hmac-sha2-256\nPermitRootLogin yes"}, // all invalid -> line omitted
	}
	got := buildSSHDConfig(ssh)

	// The one valid KEX token renders; the comma-injection token is filtered.
	if !strings.Contains(got, "KexAlgorithms curve25519-sha256\n") {
		t.Errorf("valid KEX dropped; got:\n%s", got)
	}
	if strings.Contains(got, "PermitRootLogin yes") {
		t.Errorf("injected sshd directive token reached the drop-in; got:\n%s", got)
	}
	if !strings.Contains(got, "Ciphers aes256-gcm@openssh.com\n") {
		t.Errorf("valid cipher dropped; got:\n%s", got)
	}
	// MACs list had only an invalid token, so no MACs line is emitted.
	if strings.Contains(got, "MACs ") {
		t.Errorf("MACs line emitted from an all-invalid list; got:\n%s", got)
	}
}

func TestMergeDNSInput_FiltersInjectedDomains_4902(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DomainName = "example.net evil.corp" // embedded space -> dropped
	cfg.System.DomainSearch = []string{
		"corp.example.net",        // valid
		"a.example\nDomains=evil", // newline -> dropped
		"b.example bad",           // space -> dropped
	}
	in := mergeDNSInput(cfg, nil)

	if in.DomainName != "" {
		t.Errorf("invalid domain-name should be dropped, got %q", in.DomainName)
	}
	if len(in.DomainSearch) != 1 || in.DomainSearch[0] != "corp.example.net" {
		t.Errorf("domain-search = %v, want [corp.example.net]", in.DomainSearch)
	}
}

func TestFilterSSHAlgorithms_4902(t *testing.T) {
	in := []string{"aes256-gcm@openssh.com", "bad,tok", "hmac 1", "chacha20-poly1305@openssh.com"}
	got := filterSSHAlgorithms(in)
	want := []string{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"}
	if len(got) != len(want) {
		t.Fatalf("filterSSHAlgorithms(%v) = %v, want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("filterSSHAlgorithms(%v) = %v, want %v", in, got, want)
		}
	}
}
