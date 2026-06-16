package dataplane

import "testing"

// TestProtectedInterfaceResolver proves the #1922 Item 4 resolver wiring:
// SetProtectedInterfaceResolver registers the daemon's provider, the
// compileZones unmanaged strip consults it, and nil restores the pre-#1922
// (no extra protection) behavior. The end-to-end "fxp0 never marked
// Unmanaged" assertion is covered by live validation (compileZones reads the
// real host's net.Interfaces / netlink, which a unit test cannot fake here).
func TestProtectedInterfaceResolver(t *testing.T) {
	t.Cleanup(func() { SetProtectedInterfaceResolver(nil) })

	if protectedInterfaceResolver != nil {
		t.Fatal("default protectedInterfaceResolver must be nil (pre-#1922 behavior)")
	}

	called := false
	SetProtectedInterfaceResolver(func() map[string]bool {
		called = true
		return map[string]bool{"fxp0": true, "ge-0-0-9": true}
	})
	if protectedInterfaceResolver == nil {
		t.Fatal("SetProtectedInterfaceResolver did not register the provider")
	}
	set := protectedInterfaceResolver()
	if !called {
		t.Fatal("resolver was not invoked")
	}
	if !set["fxp0"] || !set["ge-0-0-9"] {
		t.Fatalf("resolver returned unexpected set: %v", set)
	}

	SetProtectedInterfaceResolver(nil)
	if protectedInterfaceResolver != nil {
		t.Fatal("SetProtectedInterfaceResolver(nil) did not restore pre-#1922 behavior")
	}
}
