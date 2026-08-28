package config

import (
	"strings"
	"testing"
)

// #6966: a `system login` stanza packed BEHIND another system statement on the
// same line committed CLEAN with no diagnostic, and the stanza was silently
// dropped:
//
//	system host-name fw login user alice class ops;    ACCEPTED  Login=nil  warnings=0
//	system services ssh login user alice class ops;    ACCEPTED  Login=nil  warnings=0
//	system login user alice class ops;      (control)  REJECTED
//
// Because downstream reads `Config.System.Login == nil` as "no policy
// configured", applyCLILoginClass takes its early return and the shell runs
// with an EMPTY class — allow-everything, secrets rendered in cleartext. The
// operator authored `user alice class ops` and got an unrestricted CLI.
//
// That is worse than the shape #6706 closed, which at least failed a strict
// commit. Both detection arms tested `sys.Keys[1] == "login"`, so `login` at
// index 3 or 4 was invisible to both.
func TestPackedLoginBehindAnotherSystemStatementIsRejected_6966(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"behind a scalar statement", "system host-name fw login user alice class ops;"},
		{"behind a container statement", "system services ssh login user alice class ops;"},
		{"behind two statements", "system host-name fw domain-name example.net login user alice class ops;"},
		// The control that already worked. Kept here so a regression that
		// re-narrows the scan to Keys[1] is distinguishable from one that
		// breaks the gate outright.
		{"login first (control, already rejected)", "system login user alice class ops;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.src).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict CompileConfig ACCEPTED %q; the stanza is dropped "+
					"(Login=%v) and the CLI then runs with an empty class (#6966)",
					tc.src, cfg.System.Login)
			}
			if !strings.Contains(err.Error(), "login") {
				t.Errorf("rejection does not name `login`, so it is not this gate firing: %v", err)
			}
		})
	}
}

// The fail-CLOSED direction, which is the worse mistake here and the reason the
// scan is schema-aware rather than a search for the literal `login`.
//
// A firewall may legitimately be NAMED login. Marking that as packed sets
// LoginDroppedByPacking and DENIES every non-root command — an outage produced
// by a legal config. A naive `slices.Contains(keys, "login")` reds this table.
func TestLoginAsAVALUEIsNotPacking_6966(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"host named login", "system host-name login;"},
		{"host named login-server", "system host-name login-server;"},
		{"domain named login", "system domain-name login;"},
		{"host named login, then another statement", "system host-name login domain-name example.net;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.src).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict CompileConfig REJECTED a legal config %q: %v", tc.src, err)
			}
			if cfg.System.LoginDroppedByPacking {
				t.Errorf("%q set LoginDroppedByPacking; the CLI would deny every non-root "+
					"command for a config that packs no login stanza at all (#6966)", tc.src)
			}
		})
	}
}

// The scanner's own contract, asserted directly so a failure localises to the
// index rather than to a compile outcome three layers away.
//
// The index matters and is not just a boolean: collectLoginPackedFindings
// slices `sys.Keys[i:]` and reads the instance name at offset 2, so an index
// that is right about WHETHER and wrong about WHERE renders the wrong user
// name in the diagnostic.
func TestPackedLoginKeyIndex_6966(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
		want int
	}{
		{"login first", []string{"system", "login", "user", "alice"}, 1},
		{"behind host-name", []string{"system", "host-name", "fw", "login", "user", "alice"}, 3},
		{"behind services ssh", []string{"system", "services", "ssh", "login", "user", "alice"}, 3},
		{"behind two statements", []string{"system", "host-name", "fw", "domain-name", "example.net", "login", "user", "alice"}, 5},
		{"host NAMED login", []string{"system", "host-name", "login"}, -1},
		{"domain NAMED login", []string{"system", "domain-name", "login"}, -1},
		{"host named login then a real statement", []string{"system", "host-name", "login", "domain-name", "example.net"}, -1},
		{"no login at all", []string{"system", "host-name", "fw"}, -1},
		{"bare system", []string{"system"}, -1},
		{"bare packed login", []string{"system", "login"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := packedLoginKeyIndex(tc.keys); got != tc.want {
				t.Errorf("packedLoginKeyIndex(%v) = %d, want %d", tc.keys, got, tc.want)
			}
		})
	}
}
