package config

import (
	"strings"
	"testing"
)

// Tests for #5676 (codex-review-182 M10, High): an address book (global or
// zone-local) that defines the SAME name as BOTH a plain `address` AND an
// `address-set`. The two kinds share one operator-visible namespace but are
// stored in separate maps (AddressBook.Addresses / AddressBook.AddressSets), so
// the collision committed silently and every name→prefix resolver
// (pkg/dataplane/userspace expandBookNameRecursive, host-inbound junos_host_deny)
// resolved address-first — the plain address SHADOWED the same-named
// address-set, dropping the set's other members and changing which traffic a
// permit/deny rule covers with no diagnostic.
//
// The fix hard-rejects the collision on the strict commit / commit-check path
// (validateAddressBookNameCollisionStrict, wired in runEarlyStrictAndFolds) and
// downgrades to a warning on the tolerant load / peer-sync path
// (CompileConfigLenient, opts.lenientAddressBookNameCollision), keeping the
// deterministic address-first winner the runtime already used.
//
// FAIL-ON-REVERT: dropping the `if err := validateAddressBookNameCollisionStrict(
// cfg); ... ` dispatch in compiler_earlystrict.go turns every strict-reject case
// GREEN (CompileConfig accepts the collision) and drops the lenient warning — so
// TestAddrSetCollision{Global,ZoneLocal}RejectedAtCommit and
// TestAddrSetCollisionLenientDowngrades go RED.

// TestAddrSetCollisionGlobalRejectedAtCommit — a global address book that names
// the same token as both an `address` and an `address-set` is rejected at strict
// commit, and the diagnostic names both the colliding entry and the book.
func TestAddrSetCollisionGlobalRejectedAtCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address blocklist 10.0.1.0/24",
		"set security address-book global address other 10.9.9.9/32",
		"set security address-book global address-set blocklist address other",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict commit to reject a same-name address + address-set collision in the global book")
	}
	msg := err.Error()
	for _, want := range []string{"blocklist", "address", "address-set", "global"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("collision error %q does not mention %q", msg, want)
		}
	}
}

// TestAddrSetCollisionGlobalRejectedBothOrderings — the reject is independent of
// the order the two entries appear in the config (the collision is a property of
// the two maps, not of set-command line order). Junos-parity: vSRX rejects the
// second same-name definition regardless of which kind was declared first.
func TestAddrSetCollisionGlobalRejectedBothOrderings(t *testing.T) {
	orderings := map[string][]string{
		"address-first": {
			"set security address-book global address dup 10.0.1.0/24",
			"set security address-book global address m 10.2.2.2/32",
			"set security address-book global address-set dup address m",
		},
		"set-first": {
			"set security address-book global address m 10.2.2.2/32",
			"set security address-book global address-set dup address m",
			"set security address-book global address dup 10.0.1.0/24",
		},
	}
	for name, cmds := range orderings {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
				t.Fatalf("expected strict commit to reject the collision (%s ordering)", name)
			}
		})
	}
}

// TestAddrSetCollisionZoneLocalRejectedAtCommit — the gate covers zone-local
// address books too (#3061), and names the offending zone (validated on the
// pristine book BEFORE the zone-local fold).
func TestAddrSetCollisionZoneLocalRejectedAtCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone trust address-book address grp 10.0.5.0/24",
		"set security zones security-zone trust address-book address inner 10.0.6.7/32",
		"set security zones security-zone trust address-book address-set grp address inner",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict commit to reject a same-name collision in a zone-local address book")
	}
	msg := err.Error()
	for _, want := range []string{"grp", "trust", "address-set"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("zone-local collision error %q does not mention %q", msg, want)
		}
	}
}

// TestAddrSetCollisionLenientDowngrades — the tolerant load / peer-sync path
// (#1960 no-brick) must NOT fail-closed on a pre-existing collision: it records
// a warning and boots, keeping the deterministic address-first winner so the
// config forwards exactly as before.
func TestAddrSetCollisionLenientDowngrades(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address blocklist 10.0.1.0/24",
		"set security address-book global address other 10.9.9.9/32",
		"set security address-book global address-set blocklist address other",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a pre-existing collision: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a collision warning; warnings = %v", cfg.Warnings)
	}
	// Both entries survive in their distinct maps — the namespace is tagged at
	// storage, and the runtime resolver picks the documented winner.
	ab := cfg.Security.AddressBook
	if _, ok := ab.Addresses["blocklist"]; !ok {
		t.Fatalf("expected the plain address `blocklist` to survive the lenient load")
	}
	if _, ok := ab.AddressSets["blocklist"]; !ok {
		t.Fatalf("expected the address-set `blocklist` to survive the lenient load")
	}
}

// TestAddrSetCollisionDeterministicWinner is the security-relevant resolution
// assertion: given a collision, resolution is DETERMINISTIC — the plain
// `address` WINS (address-first), matching the runtime name→prefix resolver
// bit-for-bit. So a policy `match source-address blocklist` / `deny` covers
// exactly the plain address's prefix, never an unpredictable mix, and an
// operator/reviewer can reason about which traffic the rule covers. The winner
// is a property of the two KINDS, not of config-set order (both orderings
// resolve identically).
func TestAddrSetCollisionDeterministicWinner(t *testing.T) {
	build := func(t *testing.T, cmds []string) *AddressBook {
		t.Helper()
		cfg, err := CompileConfigLenient(buildTree(t, cmds))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		return cfg.Security.AddressBook
	}

	addressFirst := build(t, []string{
		"set security address-book global address blocklist 10.0.1.0/24",
		"set security address-book global address other 10.9.9.9/32",
		"set security address-book global address-set blocklist address other",
		"set security policies from-zone trust to-zone untrust policy deny-grp match source-address blocklist",
		"set security policies from-zone trust to-zone untrust policy deny-grp match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny-grp match application any",
		"set security policies from-zone trust to-zone untrust policy deny-grp then deny",
	})
	setFirst := build(t, []string{
		"set security address-book global address other 10.9.9.9/32",
		"set security address-book global address-set blocklist address other",
		"set security address-book global address blocklist 10.0.1.0/24",
	})

	for name, ab := range map[string]*AddressBook{"address-first": addressFirst, "set-first": setFirst} {
		kind, collision := resolveAddressBookNameKind(ab, "blocklist")
		if !collision {
			t.Fatalf("[%s] expected resolveAddressBookNameKind to report a collision", name)
		}
		if kind != AddrRefAddress {
			t.Fatalf("[%s] expected the plain address to win the collision (address-first), got kind=%d", name, kind)
		}
	}
}

// TestAddrSetNameKindNamespaceAware — ABSENT a collision, the two kinds are
// distinguishable and each resolves to its own kind; an undefined name is None.
func TestAddrSetNameKindNamespaceAware(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set security address-book global address lone-addr 10.0.1.0/24",
		"set security address-book global address member 10.0.2.0/24",
		"set security address-book global address-set lone-set address member",
	}))
	if err != nil {
		t.Fatalf("non-colliding book must compile clean: %v", err)
	}
	ab := cfg.Security.AddressBook
	cases := []struct {
		name     string
		wantKind AddressBookRefKind
		wantColl bool
	}{
		{"lone-addr", AddrRefAddress, false},
		{"lone-set", AddrRefAddressSet, false},
		{"member", AddrRefAddress, false},
		{"undefined", AddrRefNone, false},
	}
	for _, tc := range cases {
		kind, coll := resolveAddressBookNameKind(ab, tc.name)
		if kind != tc.wantKind || coll != tc.wantColl {
			t.Fatalf("resolveAddressBookNameKind(%q) = (%d, %v), want (%d, %v)",
				tc.name, kind, coll, tc.wantKind, tc.wantColl)
		}
	}
}

// TestAddrSetNoCollisionCompilesUnchanged — configs that do NOT collide must
// keep compiling clean on the strict path: only an address, only a set, an
// address-set whose MEMBER shares a distinct address's name, and a global
// `address foo` alongside a DIFFERENT zone's zone-local `address-set foo`
// (distinct namespaces after the zone-local fold — NOT a collision).
func TestAddrSetNoCollisionCompilesUnchanged(t *testing.T) {
	cases := map[string][]string{
		"only-address": {
			"set security address-book global address foo 10.0.1.0/24",
		},
		"only-set": {
			"set security address-book global address bar 10.0.2.0/24",
			"set security address-book global address-set foo address bar",
		},
		"set-member-shares-address-name": {
			// The classic valid shape: `servers` is a set whose member is the
			// address `web-server`. Different names — never a collision.
			"set security address-book global address web-server 10.0.1.0/24",
			"set security address-book global address-set servers address web-server",
		},
		"global-address-vs-different-zone-set": {
			"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces eth0",
			"set security address-book global address shared 10.0.1.0/24",
			"set security zones security-zone trust address-book address m 10.0.9.0/24",
			"set security zones security-zone trust address-book address-set shared address m",
		},
	}
	for name, cmds := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, cmds)); err != nil {
				t.Fatalf("non-colliding config %q must compile clean on the strict path: %v", name, err)
			}
		})
	}
}
