package config

// Nil-safe interface/unit iterators for read-only presenters (#5813).
//
// The lenient load / HA config-sync path admits PRESENT-BUT-NIL InterfaceConfig
// and InterfaceUnit map values (a key with a nil pointer value — #3494/#5068):
// a peer-synced or tolerantly-loaded config can carry a `cfg.Interfaces.
// Interfaces["ge-0/0/0"] = nil` slot, or an `ifc.Units[7] = nil` slot. Every
// read-only presenter that walks the interface tree — the CLI/gRPC/REST session
// egress-interface map builders, interface displays, completers — must SKIP
// those nil slots, not dereference them: a raw `for _, ifc := range … { for _,
// unit := range ifc.Units { unit.Number … } }` nil-derefs and panics the
// in-process daemon during a routine `show`. Routing every such walk through
// these two helpers keeps the guard in ONE place so this class stops recurring.

// RangeInterfaces calls fn for every (name, *InterfaceConfig) in cfg's interface
// map, SKIPPING any present-but-nil InterfaceConfig value. A nil cfg (or nil
// interface map) is a clean no-op. Map iteration order is unspecified (Go map
// order); callers that need determinism must sort the names themselves.
func RangeInterfaces(cfg *Config, fn func(name string, ifc *InterfaceConfig)) {
	if cfg == nil {
		return
	}
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		fn(name, ifc)
	}
}

// RangeUnits calls fn for every (unit-number, *InterfaceUnit) on ifc, SKIPPING
// any present-but-nil InterfaceUnit value. A nil ifc (or nil unit map) is a
// clean no-op.
func RangeUnits(ifc *InterfaceConfig, fn func(unitNum int, unit *InterfaceUnit)) {
	if ifc == nil {
		return
	}
	for unitNum, unit := range ifc.Units {
		if unit == nil {
			continue
		}
		fn(unitNum, unit)
	}
}

// LookupInterface returns cfg's InterfaceConfig for name and true ONLY when the
// name is present AND its value is non-nil (#5886). It treats a present-but-nil
// slot (tolerant load / HA config-sync, #3494/#5068) as ABSENT — a read-only
// presenter that key-checks `if ifc, ok := cfg.Interfaces.Interfaces[name]; ok`
// then dereferences `ifc` would panic on such a slot; routing the lookup through
// this helper makes `ok` imply a safe dereference. A nil cfg is (nil, false).
func LookupInterface(cfg *Config, name string) (*InterfaceConfig, bool) {
	if cfg == nil {
		return nil, false
	}
	ifc, ok := cfg.Interfaces.Interfaces[name]
	if !ok || ifc == nil {
		return nil, false
	}
	return ifc, true
}

// LookupUnit returns ifc's InterfaceUnit for num and true ONLY when the unit is
// present AND non-nil (#5886) — the unit-level companion to LookupInterface. A
// nil ifc (or nil unit map) is (nil, false).
func LookupUnit(ifc *InterfaceConfig, num int) (*InterfaceUnit, bool) {
	if ifc == nil {
		return nil, false
	}
	unit, ok := ifc.Units[num]
	if !ok || unit == nil {
		return nil, false
	}
	return unit, true
}
