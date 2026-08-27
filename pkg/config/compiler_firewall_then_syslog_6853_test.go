package config

import "testing"

// #6853: `then log` and `then syslog` name DIFFERENT sinks in Junos — the
// firewall filter log buffer (`show firewall log`) and the system log
// respectively — but both spellings compiled to `term.Log` alone, so the two
// were indistinguishable in the model and could never be routed apart.
//
// What this change does and does NOT do, because the difference is the whole
// point of shipping it separately from #6859:
//
//   - It makes the distinction REPRESENTABLE. `then syslog` now sets Syslog in
//     addition to Log.
//   - It changes NO behaviour. `then syslog` already reached the system log,
//     because filter-log events are categorised CategoryFirewall
//     (pkg/logging/ringbuf.go) and the syslog fan-out is gated only by a
//     per-CLIENT category filter, never per-term. Both spellings emitted, and
//     both still do.
//
// Keeping Log set on the syslog arm is therefore load-bearing rather than
// conservative: Log is what makes the dataplane emit a filter-log event at
// all, so clearing it would stop `then syslog` producing anything — a
// regression dressed as a fix.
//
// #6859 owns the other direction (whether `then log` should STOP reaching
// syslog), which is a real behaviour change with a migration cost.
func TestThenSyslogIsDistinctFromThenLog_6853(t *testing.T) {
	// The compiler must handle BOTH AST shapes (#2419), so both are cells.
	// A fix applied to only one spelling is the recurring defect in this
	// package, and each shape reaches a DIFFERENT switch in compileFilterThen.
	t.Run("hierarchical", func(t *testing.T) {
		tree := parseHier(t, `
firewall {
    family inet {
        filter f {
            term only_log    { then { log; } }
            term only_syslog { then { syslog; } }
            term both        { then { log; syslog; } }
        }
    }
}
`)
		assertSyslogTerms6853(t, tree)
	})

	t.Run("flat set (leaf form)", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set firewall family inet filter f term only_log then log",
			"set firewall family inet filter f term only_syslog then syslog",
			"set firewall family inet filter f term both then log",
			"set firewall family inet filter f term both then syslog",
		)
		assertSyslogTerms6853(t, tree)
	})
}

func assertSyslogTerms6853(t *testing.T, tree *ConfigTree) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["f"]
	if filter == nil {
		t.Fatalf("filter f did not compile; FiltersInet = %+v", cfg.Firewall.FiltersInet)
	}
	byName := map[string]*FirewallFilterTerm{}
	for _, term := range filter.Terms {
		if term != nil {
			byName[term.Name] = term
		}
	}
	for _, c := range []struct {
		term       string
		wantLog    bool
		wantSyslog bool
	}{
		{"only_log", true, false},
		// Log stays TRUE on the syslog arm. It is what makes the term emit a
		// filter-log event at all; a fix that cleared it would silently stop
		// `then syslog` producing anything.
		{"only_syslog", true, true},
		{"both", true, true},
	} {
		term := byName[c.term]
		if term == nil {
			t.Errorf("term %q missing; got %v", c.term, keysOf6853(byName))
			continue
		}
		if term.Log != c.wantLog {
			t.Errorf("term %q: Log = %v, want %v", c.term, term.Log, c.wantLog)
		}
		if term.Syslog != c.wantSyslog {
			t.Errorf("term %q: Syslog = %v, want %v — `then log` and `then syslog` must be "+
				"distinguishable, or #6859 can never route them apart",
				c.term, term.Syslog, c.wantSyslog)
		}
	}
}

func keysOf6853(m map[string]*FirewallFilterTerm) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
