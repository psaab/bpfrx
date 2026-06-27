package config

import (
	"strings"
	"testing"
)

// TestAddressBookGlobalNameSlashRejected is the #3061 collision-safety guard.
// A `/` in an address-book entry NAME is hard-rejected at strict commit so the
// synthetic zone-local/<zone>/<name> namespace minted by the zone-local fold
// (resolveZoneLocalAddressBooks) is collision-proof. The lexer permits `/` in
// an identifier (needed for IP-literal VALUES), so without this gate an
// operator could name a global address `zone-local/trust/web-server` and have
// it silently clobbered by the fold.
//
// Remove validateAddressBookEntryNamesStrict (or its dispatch in compiler.go)
// and this test goes RED (CompileConfig accepts the `/` name).
func TestAddressBookGlobalNameSlashRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address zone-local/trust/web-server 10.0.0.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a `/` in a global address-book entry name")
	}
	if !strings.Contains(err.Error(), "must not contain '/'") {
		t.Fatalf("error %q does not explain the `/` restriction", err.Error())
	}
}

// TestAddressBookZoneLocalNameSlashRejected covers the zone-local book NAME.
func TestAddressBookZoneLocalNameSlashRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone trust address-book address a/b 10.0.0.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a `/` in a zone-local address-book entry name")
	}
	if !strings.Contains(err.Error(), "must not contain '/'") {
		t.Fatalf("error %q does not explain the `/` restriction", err.Error())
	}
}

// TestSecurityZoneNameSlashRejected covers the security-zone NAME, the other
// component of the synthetic name.
func TestSecurityZoneNameSlashRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone a/b interfaces eth0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a `/` in a security-zone name")
	}
	if !strings.Contains(err.Error(), "must not contain '/'") {
		t.Fatalf("error %q does not explain the `/` restriction", err.Error())
	}
}

// TestAddressBookNameSlashNormalConfigUnaffected asserts the gate does NOT
// reject an ordinary book — crucially, a `/` in the address VALUE/prefix
// (10.0.1.0/24) is fine; only the NAME token is checked.
func TestAddressBookNameSlashNormalConfigUnaffected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces eth0",
		"set security address-book global address web-server 10.0.1.0/24",
		"set security address-book global address-set servers address web-server",
		"set security zones security-zone trust address-book address local-net 10.0.2.0/24",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an ordinary address book (prefix value contains '/', name does not): %v", err)
	}
}

// TestAddressBookNameSlashLenientDowngrades asserts the tolerant load / peer-
// sync path downgrades the `/`-name rejection to a warning (#1960 no-brick) so
// an already-persisted config an older binary accepted still boots.
func TestAddressBookNameSlashLenientDowngrades(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address weird/name 10.0.0.0/24",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a `/` name: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "must not contain '/'") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a warning for the `/` name; warnings = %v", cfg.Warnings)
	}
}
