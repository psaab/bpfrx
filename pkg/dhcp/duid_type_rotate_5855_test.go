package dhcp

// #5855: a DHCPv6 DUID-type config change (duid-ll <-> duid-llt) restarts the
// client but must ALSO rotate the identity. Before this fix getDUID returned
// the cached DUID first, else the persisted DUID, WITHOUT validating that its
// actual type matched the newly-requested mode — so the restarted client kept
// the OLD type indefinitely. getDUID now validates the type and atomically
// regenerates + persists the requested type on a mismatch; a persist FAILURE
// during rotation retains the previous identity (fail-safe, no unpersisted
// DUID exposed).

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// rotateManager builds a getDUID-only manager with a writable state dir.
func rotateManager(t *testing.T, iface, duidType string) *Manager {
	t.Helper()
	return &Manager{
		duids:     map[string]dhcpv6.DUID{},
		duidTypes: map[string]string{iface: duidType},
		stateDir:  t.TempDir(),
	}
}

// TestGetDUID_WarmCacheRotatesType_5855 (acceptance 1): with a stale-type DUID
// still CACHED, a config rotation makes getDUID return the REQUESTED type — the
// cache type-check rejects the retired identity. Both directions.
//
// FAIL-ON-REVERT: drop the cache type-match check (return m.duids[iface]
// unconditionally) and the rotated call returns the old cached type -> RED.
func TestGetDUID_WarmCacheRotatesType_5855(t *testing.T) {
	iface := firstRealIface(t)
	for _, tc := range []struct{ from, to string }{
		{"duid-ll", "duid-llt"},
		{"duid-llt", "duid-ll"},
	} {
		t.Run(tc.from+"_to_"+tc.to, func(t *testing.T) {
			m := rotateManager(t, iface, tc.from)
			d0, err := m.getDUID(iface)
			if err != nil {
				t.Fatalf("seed getDUID: %v", err)
			}
			if got := actualDUIDType(d0); got != tc.from {
				t.Fatalf("seed DUID type = %q, want %q", got, tc.from)
			}
			// Rotate the config but LEAVE the from-type DUID cached: getDUID must
			// reject the stale cached type itself.
			m.mu.Lock()
			m.duidTypes[iface] = tc.to
			m.mu.Unlock()
			d1, err := m.getDUID(iface)
			if err != nil {
				t.Fatalf("rotate getDUID: %v", err)
			}
			if got := actualDUIDType(d1); got != tc.to {
				t.Fatalf("rotated DUID type = %q, want %q (stale cache leaked)", got, tc.to)
			}
		})
	}
}

// TestGetDUID_ColdCacheRotatesType_5855 (acceptance 2): the OLD type is only
// PERSISTED (no cache); getDUID must reject the mismatched persisted DUID and
// regenerate the requested type. Both directions.
//
// FAIL-ON-REVERT: drop the persisted type-match check (return the loaded DUID
// unconditionally) and the rotated call returns the old persisted type -> RED.
func TestGetDUID_ColdCacheRotatesType_5855(t *testing.T) {
	iface := firstRealIface(t)
	for _, tc := range []struct{ from, to string }{
		{"duid-ll", "duid-llt"},
		{"duid-llt", "duid-ll"},
	} {
		t.Run(tc.from+"_to_"+tc.to, func(t *testing.T) {
			m := rotateManager(t, iface, tc.from)
			if _, err := m.getDUID(iface); err != nil {
				t.Fatalf("seed getDUID: %v", err)
			}
			// Cold cache (persisted only) + a config rotation.
			m.mu.Lock()
			delete(m.duids, iface)
			m.duidTypes[iface] = tc.to
			m.mu.Unlock()
			d1, err := m.getDUID(iface)
			if err != nil {
				t.Fatalf("rotate getDUID: %v", err)
			}
			if got := actualDUIDType(d1); got != tc.to {
				t.Fatalf("rotated DUID type = %q, want %q (stale persisted leaked)", got, tc.to)
			}
			// The regenerated identity must itself be persisted with the new type,
			// so a subsequent cold read is stable.
			if reloaded, err := m.loadDUID(iface); err != nil {
				t.Fatalf("reload rotated DUID: %v", err)
			} else if got := actualDUIDType(reloaded); got != tc.to {
				t.Fatalf("persisted rotated DUID type = %q, want %q", got, tc.to)
			}
		})
	}
}

// TestGetDUID_RotatePersistFailureRetainsPrevious_5855 (acceptance 3): when the
// durable persist of the new-type DUID FAILS, getDUID keeps the PREVIOUS
// persisted identity, returns NO error, and exposes NO unpersisted new DUID.
//
// FAIL-ON-REVERT: remove the rotation fail-safe (the `if loadErr == nil { return
// persisted }` branch) and getDUID surfaces the DUID-LLT persist error instead
// of the retained identity -> RED.
func TestGetDUID_RotatePersistFailureRetainsPrevious_5855(t *testing.T) {
	iface := firstRealIface(t)
	m := rotateManager(t, iface, "duid-ll")
	d0, err := m.getDUID(iface) // persists + caches duid-ll
	if err != nil {
		t.Fatalf("seed getDUID: %v", err)
	}

	// Rotate to duid-llt + mirror Reconcile's cache invalidation.
	m.mu.Lock()
	m.duidTypes[iface] = "duid-llt"
	delete(m.duids, iface)
	m.mu.Unlock()

	// Inject a persist failure for the NEW write; loadDUID still reads the old.
	orig := duidWriteFile
	duidWriteFile = func(string, []byte, os.FileMode) error {
		return errors.New("injected DUID persist failure")
	}
	defer func() { duidWriteFile = orig }()

	d1, err := m.getDUID(iface)
	if err != nil {
		t.Fatalf("a rotation whose persist fails must NOT error (fail-safe retains the previous "+
			"identity): %v", err)
	}
	if got := actualDUIDType(d1); got != "duid-ll" {
		t.Fatalf("after a failed rotation getDUID returned type %q; want the retained duid-ll "+
			"(a partially-rotated, unpersisted DUID-LLT must never be exposed)", got)
	}
	if !bytes.Equal(d1.ToBytes(), d0.ToBytes()) {
		t.Fatal("retained identity differs from the previous DUID — a new unpersisted identity leaked")
	}
	// The on-disk identity is still the old duid-ll (nothing new was persisted).
	if reloaded, err := m.loadDUID(iface); err != nil || actualDUIDType(reloaded) != "duid-ll" {
		t.Fatalf("persisted DUID after failed rotation = type %v err %v; want the untouched duid-ll",
			func() string { return actualDUIDType(reloaded) }(), err)
	}
}

// TestDUIDs_ReportsActiveTypeNotConfigured_5855 (acceptance 4): show/API reports
// the ACTUAL active DUID type, not the configured-but-not-yet-rotated type.
func TestDUIDs_ReportsActiveTypeNotConfigured_5855(t *testing.T) {
	iface := firstRealIface(t)
	m := rotateManager(t, iface, "duid-ll")
	if _, err := m.getDUID(iface); err != nil {
		t.Fatalf("seed getDUID: %v", err)
	}
	// Configure duid-llt but leave the ACTIVE identity as the persisted/cached
	// duid-ll (rotation not yet performed): DUIDs must report the active type.
	m.mu.Lock()
	m.duidTypes[iface] = "duid-llt"
	m.mu.Unlock()

	var found bool
	for _, in := range m.DUIDs() {
		if in.Interface != iface {
			continue
		}
		found = true
		if in.Type != "DUID-LL" {
			t.Fatalf("DUIDs reported Type=%q for a configured-duid-llt / active-duid-ll interface; "+
				"must report the ACTIVE type (DUID-LL), not the newly-configured type", in.Type)
		}
	}
	if !found {
		t.Fatalf("DUIDs did not report interface %q", iface)
	}
}

// TestReconcile_TypeChangeInvalidatesCachedDUID_5855: a DUID-type change through
// Reconcile drops the cached DUID so the restarted client cannot be handed the
// retired identity (defense-in-depth alongside getDUID's own type check).
func TestReconcile_TypeChangeInvalidatesCachedDUID_5855(t *testing.T) {
	iface := firstRealIface(t)
	m := NewManagerForTesting(func(context.Context, string, AddressFamily) {})
	m.stateDir = t.TempDir()

	m.Reconcile([]ClientSpec{{Iface: iface, Family: AFInet6, DUIDType: "duid-ll"}})
	if _, err := m.getDUID(iface); err != nil {
		t.Fatalf("seed getDUID: %v", err)
	}
	m.mu.Lock()
	_, cached := m.duids[iface]
	m.mu.Unlock()
	if !cached {
		t.Fatal("precondition: a DUID should be cached after getDUID")
	}

	m.Reconcile([]ClientSpec{{Iface: iface, Family: AFInet6, DUIDType: "duid-llt"}})
	m.mu.Lock()
	_, still := m.duids[iface]
	m.mu.Unlock()
	if still {
		t.Fatal("Reconcile did not invalidate the cached DUID on a duid-ll->duid-llt type change (#5855)")
	}
}
