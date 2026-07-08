package config

import (
	"strings"
	"testing"
)

// TestAddressBookReservedPrefixNameRejected is the #3061 collision-safety
// guard, narrowed by #4340. A `/` is now permitted in an address-book entry
// name (see TestAddressBookSlashNameCommits), but a name that BEGINS WITH the
// reserved "zone-local/" prefix is still hard-rejected at strict commit so the
// synthetic zone-local/<zone>/<name> namespace minted by the zone-local fold
// (resolveZoneLocalAddressBooks) stays collision-proof: without this gate an
// operator could name a global address `zone-local/trust/web-server` and have
// it silently clobber the synthetic name the fold mints for a zone-local
// `web-server` in zone trust.
//
// Relax validateAddressBookEntryNamesStrict (or its dispatch in compiler.go)
// and this test goes RED (CompileConfig accepts the reserved-prefix name).
func TestAddressBookReservedPrefixNameRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address zone-local/trust/web-server 10.0.0.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a reserved zone-local/ prefix in a global address-book entry name")
	}
	if !strings.Contains(err.Error(), "reserved") || !strings.Contains(err.Error(), "zone-local/") {
		t.Fatalf("error %q does not explain the reserved-prefix restriction", err.Error())
	}
}

// TestAddressBookZoneLocalReservedPrefixRejected covers the zone-local book
// NAME: the reserved-prefix guard applies to zone-local entries too.
func TestAddressBookZoneLocalReservedPrefixRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone trust address-book address zone-local/x/y 10.0.0.0/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a reserved zone-local/ prefix in a zone-local address-book entry name")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error %q does not explain the reserved-prefix restriction", err.Error())
	}
}

// TestSecurityZoneNameSlashRejected covers the security-zone NAME, which keeps
// the full `/` ban (the zone is the unambiguous first segment of the synthetic
// zone-local/<zone>/<name> key, so it must stay `/`-free).
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
		"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces eth0",
		"set security address-book global address web-server 10.0.1.0/24",
		"set security address-book global address-set servers address web-server",
		"set security zones security-zone trust address-book address local-net 10.0.2.0/24",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an ordinary address book (prefix value contains '/', name does not): %v", err)
	}
}

// TestAddressBookReservedPrefixLenientDowngrades asserts the tolerant load /
// peer-sync path downgrades the reserved-prefix rejection to a warning (#1960
// no-brick) so an already-persisted config an older binary accepted still boots.
func TestAddressBookReservedPrefixLenientDowngrades(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address zone-local/weird/name 10.0.0.0/24",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a reserved-prefix name: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "reserved") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a warning for the reserved-prefix name; warnings = %v", cfg.Warnings)
	}
}
