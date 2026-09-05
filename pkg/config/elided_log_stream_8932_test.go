package config

import "testing"

// A packed `security log stream` run keeps the first statement and drops the
// rest, and the `category` loss FAILS OPEN.
//
//	stream s1 { host 192.0.2.1; category policy; }   category="policy"
//	stream s1 host 192.0.2.1 category policy;        category=""
//
// `daemon_system.go` sets Categories only when the field is non-empty, and
// `logging/syslog.go` documents Categories == 0 as ALL. So a stream the
// operator scoped to `policy` silently carries EVERY category -- MORE data
// leaving the box than was configured, on a commit that reported success.
//
// That is the fallback shape rather than the missing shape: the consumer has a
// default and the default fires, so nothing is unconfigured and the value is
// WRONG rather than absent. A missing stream would eventually be noticed; a
// stream carrying too much is indistinguishable from one carrying what it
// should until someone reads the volume.
func TestPackedLogStreamKeepsEveryStatement8932(t *testing.T) {
	braced := compileText(t, `security { log { stream s1 { host 192.0.2.1; category policy; } } }`)
	packed := compileText(t, `security { log { stream s1 host 192.0.2.1 category policy; } }`)
	if braced == nil || packed == nil {
		t.Fatal("fixture did not compile (#8932)")
	}
	find := func(c *Config) *SyslogStream {
		for _, s := range c.Security.Log.Streams {
			if s.Name == "s1" {
				return s
			}
		}
		return nil
	}
	b, p := find(braced), find(packed)
	if b == nil {
		t.Fatal("the BRACED arm produced no stream s1, so this cell cannot tell a " +
			"fixed split from a broken fixture (#8932)")
	}
	if b.Category == "" {
		t.Fatalf("the BRACED arm produced category=%q -- the reference arm carries "+
			"no category, so the comparison below would pass against a stream "+
			"that lost it in both spellings (#8932)", b.Category)
	}
	if p == nil {
		t.Fatalf("the packed spelling produced NO stream at all (#8932)")
	}
	if p.Host != b.Host {
		t.Errorf("packed run lost the host: got %q, want %q (#8932)", p.Host, b.Host)
	}
	if p.Category != b.Category {
		t.Errorf("packed run lost the category: got %q, want %q.\n"+
			"  An empty Category FAILS OPEN -- logging/syslog.go treats "+
			"Categories == 0 as ALL -- so a stream scoped to one category "+
			"silently carries every category, and MORE data leaves the box than "+
			"the operator configured (#8932).", p.Category, b.Category)
	}
}
