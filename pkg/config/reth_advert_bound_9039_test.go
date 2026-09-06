package config

import (
	"strings"
	"testing"
)

func rethAdvertTree9039(t *testing.T, ms string) *ConfigTree {
	t.Helper()
	tr := &ConfigTree{}
	for _, c := range []string{
		"set chassis cluster cluster-id 1",
		// Unrelated to this gate, and REQUIRED: without it the chassis-cluster
		// PSK gate rejects every fixture here, and every "must reject" row
		// below would pass for the wrong reason. The reference arm is what
		// surfaced that.
		"set chassis cluster authentication-key dGVzdC1rZXktZm9yLTkwMzktb25seQ==",
		"set chassis cluster reth-advertise-interval " + ms,
	} {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", c, err)
		}
	}
	return tr
}

// #9039: the milliseconds knob had no compiled-Config gate at all, while its
// seconds-valued sibling got one in #8483. Its only bound was a SCHEMA bound,
// and duration_bound_8642.go already states why that is not the same thing:
// compileTreeLenient downgrades a typed-leaf violation to a warning on
// Store.Load / Store.SyncApply, so a schema ceiling stops a commit and does not
// stop a config arriving from disk or from an HA peer.
func TestRethAdvertiseIntervalIsBoundedAtCommit9039(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ms    string
		admit bool
		want  string
	}{
		// REFERENCE ARM: the ordinary value must still commit. Without it,
		// every rejection below is satisfied by a gate that refuses everything.
		{"default 30ms", "30", true, ""},
		{"floor", "10", true, ""},
		{"largest encodable", "40950", true, ""},
		// THE DEFECT: 700000 ms narrows to 368 cs on the wire while the local
		// timer keeps 700 s.
		{"aliases on the wire", "700000", false, "outside 10..40950"},
		{"just past the ceiling", "40960", false, "outside 10..40950"},
		{"below the floor", "5", false, "outside 10..40950"},
		// A value that is in range but not a whole centisecond still tells the
		// peer something other than what was configured.
		{"sub-centisecond precision", "35", false, "not a whole number of centiseconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(rethAdvertTree9039(t, tc.ms))
			if tc.admit {
				if err != nil {
					t.Fatalf("%s ms must commit, got: %v", tc.ms, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s ms was admitted; it is narrowed on the VRRPv3 wire and "+
					"the peer derives its master-down window from the narrowed value", tc.ms)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the reason %q — a rejection whose "+
					"message does not say what is wrong sends the operator hunting",
					err.Error(), tc.want)
			}
		})
	}
}

// NO-BRICK. The gate must be a WARNING on the tolerant ingress, or a box that
// already committed an out-of-range value cannot boot and cannot receive a
// config from its peer. Every sibling gate in this file behaves this way
// (#1960); asserting it here keeps a later edit from quietly making this one
// strict on both paths.
func TestRethAdvertiseIntervalIsLenientOnTheTolerantPath9039(t *testing.T) {
	cfg, err := CompileConfigLenient(rethAdvertTree9039(t, "700000"))
	if err != nil {
		t.Fatalf("the tolerant path must not reject: %v", err)
	}
	if cfg == nil {
		t.Fatal("the tolerant path produced no config")
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "reth-advertise-interval") {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path admitted 700000 ms with NO warning; downgrading "+
			"a rejection to silence is not the no-brick posture, it is the defect. "+
			"warnings=%v", cfg.Warnings)
	}
}
