package config

import (
	"reflect"
	"testing"
)

// #8939 at `system dataplane` and its `shared-umem` sub-container: a packed run
// set only its FIRST option.
//
//	set system dataplane binary /usr/sbin/x claim-host-tunables true control-socket /run/x.sock
//	  -> Binary set; ClaimHostTunables and ControlSocket DROPPED
//
// `control-socket` is the loss worth naming. When it is dropped the daemon falls
// back to a default path, and #9003 records what that default was: a socket in
// /tmp that MkdirAll would adopt with no peer check. An operator who moved the
// socket off /tmp in the same statement as another option DID NOT MOVE IT, and
// nothing said so.
func TestSystemDataplanePackedRun8939(t *testing.T) {
	build := func(t *testing.T, lines ...string) *Config {
		t.Helper()
		tr := &ConfigTree{}
		for _, l := range lines {
			p, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
		}
		c, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return c
	}

	t.Run("dataplane", func(t *testing.T) {
		split := build(t,
			"set system dataplane binary /usr/sbin/x",
			"set system dataplane claim-host-tunables true",
			"set system dataplane control-socket /run/x.sock")
		d := split.System.UserspaceDataplane
		if d == nil || d.Binary == "" || !d.ClaimHostTunables || d.ControlSocket == "" {
			t.Fatalf("the SPLIT control did not set all three: %+v", d)
		}
		packed := build(t,
			"set system dataplane binary /usr/sbin/x claim-host-tunables true control-socket /run/x.sock")
		if !reflect.DeepEqual(packed, split) {
			p := packed.System.UserspaceDataplane
			t.Errorf("packed bin=%q claim=%v sock=%q, split bin=%q claim=%v sock=%q",
				p.Binary, p.ClaimHostTunables, p.ControlSocket,
				d.Binary, d.ClaimHostTunables, d.ControlSocket)
		}

		// NARROWNESS, and it matters here: `claim-host-tunables` is an opt-in
		// gate that lets xpfd touch HOST-scope knobs (#801 B1, default false).
		// A fix that set every option whenever `system dataplane` appeared
		// would satisfy the comparison and turn that gate on for an operator
		// who only set a binary path.
		only := build(t, "set system dataplane binary /usr/sbin/x")
		o := only.System.UserspaceDataplane
		if o == nil || o.Binary == "" {
			t.Fatalf("the single-option spelling lost its own option: %+v", o)
		}
		if o.ClaimHostTunables || o.ControlSocket != "" {
			t.Errorf("`binary` alone also set claim=%v sock=%q — claim-host-tunables is a "+
				"host-scope opt-in and must never be turned on by proximity",
				o.ClaimHostTunables, o.ControlSocket)
		}
	})

	t.Run("shared-umem", func(t *testing.T) {
		split := build(t,
			"set system dataplane shared-umem mode shared",
			"set system dataplane shared-umem artifact-file /a")
		packed := build(t, "set system dataplane shared-umem mode shared artifact-file /a")
		su := split.System.UserspaceDataplane
		if su == nil || su.SharedUMEM == nil || su.SharedUMEM.Mode == "" {
			t.Fatalf("the SPLIT control did not set the shared-umem body: %+v", su)
		}
		if !reflect.DeepEqual(packed, split) {
			t.Errorf("packed %+v\nsplit  %+v",
				packed.System.UserspaceDataplane.SharedUMEM, su.SharedUMEM)
		}
	})
}
