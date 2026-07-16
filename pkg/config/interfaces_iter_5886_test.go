package config

// #5886: LookupInterface / LookupUnit are the nil-safe key-lookup companions to
// RangeInterfaces / RangeUnits. Read-only presenters that key-check
// `if ifc, ok := cfg.Interfaces.Interfaces[name]; ok` then dereference `ifc`
// panic on a present-but-nil slot (tolerant load / HA sync). Routing the lookup
// through these helpers makes `ok` imply a safe dereference.

import "testing"

func TestLookupInterface_5886(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0"},
		"zz-nil":   nil, // present-but-nil (tolerant path)
	}
	if ifc, ok := LookupInterface(cfg, "ge-0/0/0"); !ok || ifc == nil || ifc.Name != "ge-0/0/0" {
		t.Fatalf("valid interface: got (%v,%v), want the non-nil config", ifc, ok)
	}
	if ifc, ok := LookupInterface(cfg, "zz-nil"); ok || ifc != nil {
		t.Fatalf("present-but-nil slot must read as ABSENT, got (%v,%v)", ifc, ok)
	}
	if ifc, ok := LookupInterface(cfg, "missing"); ok || ifc != nil {
		t.Fatalf("absent key: got (%v,%v), want (nil,false)", ifc, ok)
	}
	if ifc, ok := LookupInterface(nil, "ge-0/0/0"); ok || ifc != nil {
		t.Fatalf("nil cfg: got (%v,%v), want (nil,false)", ifc, ok)
	}
}

func TestLookupUnit_5886(t *testing.T) {
	ifc := &InterfaceConfig{
		Name: "ge-0/0/0",
		Units: map[int]*InterfaceUnit{
			0: {Number: 0},
			7: nil, // present-but-nil unit (tolerant path)
		},
	}
	if u, ok := LookupUnit(ifc, 0); !ok || u == nil || u.Number != 0 {
		t.Fatalf("valid unit: got (%v,%v), want the non-nil unit", u, ok)
	}
	if u, ok := LookupUnit(ifc, 7); ok || u != nil {
		t.Fatalf("present-but-nil unit must read as ABSENT, got (%v,%v)", u, ok)
	}
	if u, ok := LookupUnit(ifc, 99); ok || u != nil {
		t.Fatalf("absent unit: got (%v,%v), want (nil,false)", u, ok)
	}
	if u, ok := LookupUnit(nil, 0); ok || u != nil {
		t.Fatalf("nil ifc: got (%v,%v), want (nil,false)", u, ok)
	}
}
