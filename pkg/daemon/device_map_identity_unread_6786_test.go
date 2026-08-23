package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/devicemap"
)

// unreadIdentitySeams stubs the mapped-rename orchestration so the single
// present NIC at the pinned PCI has an UNREADABLE identity — the per-NIC
// netlink read failed, so its permanent MAC is unknown. It returns counters
// for the rename and reload seams and the temp link dir, so a test can assert
// ZERO side effects rather than merely a returned error.
func unreadIdentitySeams(t *testing.T) (renameCalls, reloadCalls *int, dir string) {
	t.Helper()
	dir = withTempLinkDir(t)

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{{
			Name:    "enp9s0",
			PCIAddr: "0000:09:00.0",
			// PermMAC deliberately left "" AND IdentityUnread set: this is the
			// exact state a failed netlink.LinkByName produces, and the state
			// that used to be indistinguishable from MAC-less hardware.
			IdentityUnread: true,
		}}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	var rc, lc int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { rc++; return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { lc++; return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	return &rc, &lc, dir
}

// macPinnedMapConfig maps ge-0/0/3 to the NIC at 0000:09:00.0 AND pins its
// permanent MAC — the shape an operator authors precisely so a card swapped
// into that slot is refused rather than silently adopted.
func macPinnedMapConfig() (*config.DeviceMapConfig, *config.Config) {
	dm := &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{
			LogicalName: "ge-0/0/3",
			PCIAddr:     "0000:09:00.0",
			MAC:         "aa:bb:cc:dd:ee:01",
		}},
	}
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: dm}}
	return dm, cfg
}

// linkFileCount counts .link files written into the device-map link dir.
func linkFileCount(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read link dir: %v", err)
	}
	n := 0
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".link" {
			n++
		}
	}
	return n
}

// TestUnreadIdentityProducesZeroRenameSideEffects6786 is the injected
// LinkByName-failure test the issue asked for, and it asserts SIDE EFFECTS
// rather than a return value.
//
// A returned error is not the property that matters here. What matters is that
// nothing was MOVED: no interface renamed, no `.link` file written (a .link is
// DURABLE — udev replays it on every subsequent boot, so a wrong one persists
// the mis-binding long after the transient read failure is gone), and no
// networkctl reload. A fix that logged the refusal but still renamed would
// return an error and still have hijacked the NIC.
//
// Both arms are exercised because they reach "no side effects" through
// DIFFERENT code:
//   - protected non-empty: the #5490 boot re-check runs deviceMapStrandsManagement
//     first, sees a refused binding, and aborts before phase 1. It must also
//     return an error so the retry marker is preserved and boot surfaces it.
//   - protected empty: that pre-check is skipped by contract ("empty protected
//     == nothing to protect"), so the refusal has to be honoured by the rename
//     loop itself — the refused entry must never reach desiredByCurrent.
//
// FAIL-ON-REVERT: discarding the LinkByName error again (or dropping the
// IdentityUnread refusal) binds the entry as BindBoundPCIOnly, phase 2 renames
// enp9s0 to ge-0-0-3 and writes its .link — reddening the rename count and the
// link-file count in both arms.
func TestUnreadIdentityProducesZeroRenameSideEffects6786(t *testing.T) {
	t.Run("protected-set-boot-recheck-aborts", func(t *testing.T) {
		renames, reloads, dir := unreadIdentitySeams(t)
		dm, cfg := macPinnedMapConfig()

		err := enumerateAndRenameMapped(dm, cfg, map[string]bool{"fxp0": true})
		if err == nil {
			t.Error("a mapped entry whose pinned MAC cannot be verified must FAIL the boot rename " +
				"so the retry marker is preserved and boot surfaces it loudly; got nil")
		}
		if *renames != 0 {
			t.Errorf("renames = %d, want 0: a NIC whose permanent MAC could not be read must not be "+
				"renamed into a pinned logical name — that is the silent hijack #1956 forbids", *renames)
		}
		if n := linkFileCount(t, dir); n != 0 {
			t.Errorf(".link files written = %d, want 0: a .link is DURABLE (udev replays it every "+
				"boot), so writing one on an unverified identity persists the mis-binding long "+
				"after the transient read failure clears", n)
		}
		if *reloads != 0 {
			t.Errorf("networkctl reloads = %d, want 0", *reloads)
		}
	})

	t.Run("no-protected-set-rename-loop-honours-refusal", func(t *testing.T) {
		renames, reloads, dir := unreadIdentitySeams(t)
		dm, cfg := macPinnedMapConfig()

		// Empty protected set: the #5490 pre-check is skipped by contract, so
		// this arm proves the rename loop itself honours the refusal.
		_ = enumerateAndRenameMapped(dm, cfg, map[string]bool{})

		if *renames != 0 {
			t.Errorf("renames = %d, want 0: with no protected set the #5490 pre-check is skipped, "+
				"so the refusal must be honoured by the rename loop itself", *renames)
		}
		if n := linkFileCount(t, dir); n != 0 {
			t.Errorf(".link files written = %d, want 0", n)
		}
		if *reloads != 0 {
			t.Errorf("networkctl reloads = %d, want 0", *reloads)
		}
	})
}

// TestReadableIdentityStillRenames6786 is the tightening control for the test
// above: it uses the SAME seams with the ONLY difference being that the
// identity read succeeded and the permanent MAC matches the pin. Without it,
// a "fix" that refuses every mapped entry unconditionally would satisfy every
// zero-side-effect assertion above and look correct — while bricking
// device-map naming entirely.
func TestReadableIdentityStillRenames6786(t *testing.T) {
	dir := withTempLinkDir(t)

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{{
			Name:    "enp9s0",
			PCIAddr: "0000:09:00.0",
			PermMAC: "aa:bb:cc:dd:ee:01", // read OK, matches the pin
		}}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	var renames int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { renames++; return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	dm, cfg := macPinnedMapConfig()
	if err := enumerateAndRenameMapped(dm, cfg, map[string]bool{}); err != nil {
		t.Fatalf("a verified identity must still bind and rename: %v", err)
	}
	if renames == 0 {
		t.Error("renames = 0: a NIC whose permanent MAC was read and MATCHES the pin must still be " +
			"renamed — the #6786 refusal must be scoped to an UNREADABLE identity, not applied to " +
			"every mapped entry")
	}
	if n := linkFileCount(t, dir); n == 0 {
		t.Error(".link files written = 0: a verified binding must still persist its .link")
	}
}

// TestUnreadIdentityRefusesAtCommitPreflight6786 covers the remaining mutation
// site named in the issue: commit. #5490 already fails closed when the WHOLE
// inventory read fails; this is the per-NIC case it does not reach — the
// enumeration succeeds and returns a NIC whose identity is unknown.
//
// Refusing at commit is the cheapest possible place to fail: the operator is
// still connected, nothing on the box has been mutated, and the remedy (retry,
// or repair the identity read) is available to them immediately.
func TestUnreadIdentityRefusesAtCommitPreflight6786(t *testing.T) {
	_, _, _ = unreadIdentitySeams(t)
	_, cfg := macPinnedMapConfig()

	d := &Daemon{}
	if err := d.deviceMapCommitPreflight(cfg, nil); err == nil {
		t.Fatal("committing a device-map whose pinned MAC cannot be verified against the NIC at " +
			"its PCI address must be REJECTED while the operator is still connected, rather than " +
			"accepted and applied unverified at next boot")
	}

	// The refusal must carry the RIGHT REMEDY. This started as a check for the
	// word "identity" and passed while the generic card-swap message was being
	// returned — that message contains "at its pinned identity", so the
	// assertion was satisfied by exactly the wording it was meant to exclude.
	// The discriminating pair is: the unreadable-identity wording must be
	// PRESENT and the card-swap remedy must be ABSENT. Telling an operator
	// whose NIC is merely unreadable to "re-pin the entry" sends them to a fix
	// that changes nothing, and asks them to re-pin against a MAC they cannot
	// currently read (the wrong-remedy trap #6546 named).
	err := d.deviceMapCommitPreflight(cfg, nil)
	got := err.Error()
	if !containsFold(got, "could not be read") || !containsFold(got, "UNKNOWN") {
		t.Errorf("the rejection must say the identity could not be READ and that the permanent MAC "+
			"is UNKNOWN; got %q", got)
	}
	if containsFold(got, "a different card is present") || containsFold(got, "Re-pin the entry") {
		t.Errorf("the rejection must NOT use the topology-change remedy: nothing is known to be "+
			"wrong with the card, and re-pinning against an unreadable MAC fixes nothing; got %q", got)
	}
	if devicemap.BindRefusedIdentityUnknown.String() == devicemap.BindRefusedAmbig.String() {
		t.Error("the unreadable-identity and topology-change statuses must render differently — " +
			"`show chassis device-map` is where an operator reads which one happened")
	}
}

func containsFold(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexFold(haystack, needle) >= 0
}

func indexFold(h, n string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := 0; j < len(n); j++ {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
