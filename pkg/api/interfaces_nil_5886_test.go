package api

// #5886: the REST interface presenter (writeInterfacesTerse and the unit lookup)
// dereferenced present-but-nil InterfaceConfig / InterfaceUnit map values after
// only a map-key check, so a read-only REST request panicked xpfd on a
// tolerantly-loaded / peer-synced config. It now walks via config.RangeInterfaces
// / LookupInterface / LookupUnit.
//
// FAIL-ON-REVERT: removing the nil-skip / LookupInterface guard makes the walk
// deref the nil value and panic → RED. No panic recovery is used as the
// correctness mechanism; the presenter is called directly and a panic fails the
// test naturally.

import (
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRESTInterfacesTerseNilNoPanic_5886(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			7: nil, // present-but-nil unit
		}},
		"zz-nil-ifc": nil, // present-but-nil interface
	}

	w := httptest.NewRecorder()
	(&Server{}).writeInterfacesTerse(w, cfg, "")

	if w.Code != 200 && w.Code != 0 {
		t.Fatalf("REST interfaces terse status = %d, want 200", w.Code)
	}
}
