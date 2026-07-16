package config

import (
	"sort"
	"testing"
)

// #5813: the tolerant load / HA config-sync path admits present-but-nil
// InterfaceConfig and InterfaceUnit map values. RangeInterfaces/RangeUnits are
// the shared nil-safe walk every read-only presenter uses; they MUST skip the
// nil slots rather than yield them, so a caller never nil-derefs.
//
// FAIL-ON-REVERT: dropping the `if ifc == nil { continue }` guard in
// RangeInterfaces makes the nil-interface case yield a nil *InterfaceConfig,
// and dropping the `if unit == nil { continue }` guard in RangeUnits makes the
// nil-unit case yield a nil *InterfaceUnit — both assertions below go RED.
func TestRangeInterfacesSkipsNilConfig5813(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0":   {Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"zz-nil-ifc": nil, // present key, nil value (tolerant path)
	}

	var got []string
	RangeInterfaces(cfg, func(name string, ifc *InterfaceConfig) {
		if ifc == nil {
			t.Fatalf("RangeInterfaces yielded a nil InterfaceConfig for %q", name)
		}
		got = append(got, name)
	})
	sort.Strings(got)
	if len(got) != 1 || got[0] != "ge-0/0/0" {
		t.Fatalf("RangeInterfaces yielded %v, want [ge-0/0/0] (nil slot skipped)", got)
	}
}

func TestRangeUnitsSkipsNilUnit5813(t *testing.T) {
	ifc := &InterfaceConfig{
		Units: map[int]*InterfaceUnit{
			0: {Number: 0},
			5: {Number: 5, VlanID: 5},
			7: nil, // present key, nil value (tolerant path)
		},
	}

	var got []int
	RangeUnits(ifc, func(unitNum int, unit *InterfaceUnit) {
		if unit == nil {
			t.Fatalf("RangeUnits yielded a nil InterfaceUnit for unit %d", unitNum)
		}
		got = append(got, unit.Number)
	})
	sort.Ints(got)
	if len(got) != 2 || got[0] != 0 || got[1] != 5 {
		t.Fatalf("RangeUnits yielded numbers %v, want [0 5] (nil unit skipped)", got)
	}
}

// Nil receivers are clean no-ops (a presenter may hold a nil Config or a nil
// InterfaceConfig on the tolerant path).
func TestRangeNilReceiversNoOp5813(t *testing.T) {
	RangeInterfaces(nil, func(string, *InterfaceConfig) {
		t.Fatal("RangeInterfaces(nil) invoked fn")
	})
	RangeInterfaces(&Config{}, func(string, *InterfaceConfig) {
		t.Fatal("RangeInterfaces over an empty config invoked fn")
	})
	RangeUnits(nil, func(int, *InterfaceUnit) {
		t.Fatal("RangeUnits(nil) invoked fn")
	})
	RangeUnits(&InterfaceConfig{}, func(int, *InterfaceUnit) {
		t.Fatal("RangeUnits over a unit-less interface invoked fn")
	})
}
