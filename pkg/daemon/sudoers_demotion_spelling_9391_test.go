package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9391: the CONSEQUENCE cell for the login-user flat-run drop.
//
// #3889 added reconcileSudoers' revocation sweep because "a demoted or deleted
// admin kept passwordless root sudo forever". The sweep is keyed on
// `Class == "super-user"`, so it is only as good as the compiled class — and
// the compiled class was dropped whenever the operator wrote the demotion as
// one `set` line, which is the idiomatic CLI spelling:
//
//	set system login user admin class super-user       (earlier)
//	set system login user admin uid 2001 class read-only
//	  -> compiled class="super-user"     THE DEMOTION IS DROPPED
//
// So #3889's defect was reachable again through the config layer, and every
// cell #3889 wrote passed: they construct config.LoginUser values DIRECTLY and
// never go through the compiler. That is why this cell drives the SPELLING
// end-to-end instead of asserting on a hand-built struct.
func TestDemotionSpellingRevokesTheSudoersGrant9391(t *testing.T) {
	compile := func(t *testing.T, lines ...string) *config.Config {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, l := range lines {
			p, err := config.ParseSetCommand(l)
			if err != nil {
				t.Fatalf("parse %q: %v", l, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("setpath %q: %v", l, err)
			}
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return cfg
	}

	run := func(t *testing.T, cfg *config.Config) bool {
		t.Helper()
		dir := withSudoersTestDir(t)
		// Seed the grant admin already holds as a super-user.
		writeFile(t, filepath.Join(dir, "xpf-admin"), "admin ALL=(ALL) NOPASSWD: ALL\n")
		d := &Daemon{}
		if err := d.reconcileSudoers(cfg); err != nil {
			t.Fatalf("reconcileSudoers: %v", err)
		}
		_, err := os.Stat(filepath.Join(dir, "xpf-admin"))
		return err == nil
	}

	// CONTROL: admin really IS a super-user, so the grant must SURVIVE.
	// Without this arm a reconcile that revoked everything would pass the
	// assertion below while breaking every real administrator.
	if !run(t, compile(t, "set system login user admin class super-user")) {
		t.Fatalf("CONTROL: a genuine super-user lost its sudoers grant — the arm below " +
			"cannot be read, because 'revoked' would no longer mean 'demoted'")
	}

	// ORACLE: the demotion on separate lines revokes the grant.
	if run(t, compile(t,
		"set system login user admin class super-user",
		"set system login user admin uid 2001",
		"set system login user admin class read-only",
	)) {
		t.Fatalf("ORACLE: the separate-lines demotion did NOT revoke the grant; #3889 is " +
			"broken independently of #9391 and the arm below would be measuring that")
	}

	// THE DEFECT: the same demotion written as one line.
	if run(t, compile(t,
		"set system login user admin class super-user",
		"set system login user admin uid 2001 class read-only",
	)) {
		t.Errorf("the ONE-LINE demotion left the xpf-admin NOPASSWD grant in place. The " +
			"operator's own commit says read-only, `show configuration | display set` " +
			"renders their line back, and the account keeps passwordless root — which " +
			"is the #3889 defect reached through the config layer instead of through " +
			"the missing revocation branch")
	}
}
