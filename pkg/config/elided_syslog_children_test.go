package config

import "testing"

// The brace-elided `system syslog` stanza compiled to NO syslog configuration.
//
//	system { syslog { file f1 { any any; } } }   files=1
//	system { syslog file f1 { any any; } }       files=0   silent
//
// strictErr=false and warnings=0 on both the strict commit path and the
// tolerant Store.Load / SyncApply ingress, so nothing told the operator.
//
// A FIREWALL THAT SILENTLY LOGS NOTHING. No local file, no remote host, no
// per-user destination, on a commit that reported success and a `show
// configuration` that renders exactly what was written. Security logging that
// is ABSENT is indistinguishable from security logging that is QUIET -- there
// is no error to notice and no missing feature to trip over, only an empty log
// nobody is watching until they need it.
//
// SCOPE: the hierarchical file spelling. The CLI is unaffected -- `set system
// syslog file f1 any any` goes through SetPath, which builds the nested tree,
// so the compiler never sees the elided shape. Stated because a reader who sees
// only the drop will assume the CLI path and rate this higher than it is.
//
// ALL THREE CHILDREN ARE ASSERTED, not one. `file` alone would have passed
// against a fix that admitted only the leaf a minimal fixture reached -- the
// single-leaf blindness that made `policy-statement -> then` read as a
// non-defect for a day. Each is measured in its OWN arm; see the note in the
// body for why one combined fixture would have been wrong.
func TestElidedSyslogKeepsItsChildren(t *testing.T) {
	// ONE CHILD PER ARM, DELIBERATELY. A single fixture packing all three --
	// `syslog file …; syslog host …; syslog user …` -- is a multi-statement RUN,
	// which #8850 makes the pass DECLINE to fold on purpose rather than fold
	// ambiguously. Measuring that shape would report this fix as broken when it
	// is the decline branch working as designed: a fixture testing a spelling
	// the pass refuses by policy is measuring the policy, not the fix.
	for _, c := range []struct {
		what, braced, elided, consequence string
		count                             func(*Config) int
	}{
		{
			what:        "file",
			braced:      `system { syslog { file f1 { any any; } } }`,
			elided:      `system { syslog file f1 { any any; } }`,
			consequence: "no local log file is written",
			count:       func(c *Config) int { return len(c.System.Syslog.Files) },
		},
		{
			what:        "host",
			braced:      `system { syslog { host 192.0.2.1 { any any; } } }`,
			elided:      `system { syslog host 192.0.2.1 { any any; } }`,
			consequence: "no syslog is forwarded to the collector",
			count:       func(c *Config) int { return len(c.System.Syslog.Hosts) },
		},
		{
			what:        "user",
			braced:      `system { syslog { user u1 { any any; } } }`,
			elided:      `system { syslog user u1 { any any; } }`,
			consequence: "no per-user destination is configured",
			count:       func(c *Config) int { return len(c.System.Syslog.Users) },
		},
	} {
		b := compileText(t, c.braced)
		e := compileText(t, c.elided)
		if b == nil || e == nil {
			t.Fatalf("%s: fixture did not compile", c.what)
		}
		// POSITIVE CONTROL on the reference arm: if the braced spelling stopped
		// delivering this, the assertion below would pass against a config that
		// carries no syslog at all.
		if c.count(b) == 0 {
			t.Fatalf("%s: the BRACED arm delivered nothing, so this cell cannot "+
				"tell a fixed elision from a broken fixture", c.what)
		}
		if got, want := c.count(e), c.count(b); got != want {
			t.Errorf("brace-elided `syslog %s` delivers %d, braced delivers %d -- %s, "+
				"silently, on a commit that reported success",
				c.what, got, want, c.consequence)
		}
	}
}

// The CLI path was never broken and is asserted, so a fix that repairs the
// elided spelling at the cost of the spelling operators actually use cannot
// pass.
func TestSyslogFlatSetStillWorks(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set system syslog file f1 any any",
		"set system syslog host 192.0.2.1 any any",
	} {
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.System.Syslog.Files) != 1 || len(cfg.System.Syslog.Hosts) != 1 {
		t.Errorf("the flat-set path lost a syslog destination: files=%d hosts=%d, "+
			"want 1/1 — the elision fix must not cost the spelling that already worked",
			len(cfg.System.Syslog.Files), len(cfg.System.Syslog.Hosts))
	}
}
