// #2514: the address-book content-ID assignment must NOT panic the daemon
// when a folded-hash collision cannot be resolved within the probe window.
// Config-shaped input feeding the commit/apply path must fail closed with a
// returned error so the offending config is rejected and the prior dataplane
// state is retained — never crash a security appliance.
//
// These tests are fail-on-revert: the old code panicked at probe > 256, so if
// the panic is restored, withInjectedAddressBookCollision recovers it and
// fails the test, and the error-not-panic assertions below fail too.
package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// forceAddressBookCollision installs hash + probe-limit seams that drive every
// distinct content bucket onto the same folded primary slot with a probe
// window too small to ever find a free slot, so the (otherwise unreachable)
// collision-exhaustion branch fires deterministically. It returns a restore
// func. recover() is wired so a reintroduced panic surfaces as a test failure
// rather than crashing the test binary.
func forceAddressBookCollision(t *testing.T) (restore func()) {
	t.Helper()
	origHash := addressBookContentHash64
	origLimit := addressBookProbeLimit
	// Constant hash: every bucket maps to the same primary id and the same
	// folded base, so every bucket after the first collides on the same
	// slot. Low 32 bits non-zero so the id != 0 reservation does not move
	// the slot around.
	addressBookContentHash64 = func([]byte) uint64 { return 0x1234 }
	// Probe window of 1: the first colliding bucket takes folded+1, the
	// next colliding bucket finds folded+1 already used and exhausts the
	// single-step window → AddressBookIDCollisionError.
	addressBookProbeLimit = func(int) int { return 1 }
	return func() {
		addressBookContentHash64 = origHash
		addressBookProbeLimit = origLimit
	}
}

// collidingBookCfg builds a config with n address-book entries that all have
// DISTINCT content (so they form n separate content buckets), which under the
// injected constant hash all collide on the same folded slot.
func collidingBookCfg(n int) *config.Config {
	addrs := make(map[string]*config.Address, n)
	for i := 0; i < n; i++ {
		// Distinct /32 per entry → distinct canonical content → distinct
		// bucket. names lexicographically ordered for determinism.
		name := string(rune('a'+i/26)) + string(rune('a'+i%26))
		addrs[name] = &config.Address{
			Name:  name,
			Value: cidrForIndex(i),
		}
	}
	return &config.Config{
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{Addresses: addrs},
		},
	}
}

func cidrForIndex(i int) string {
	// 10.<a>.<b>.<c>/32 — unique per i for the small counts used here.
	a := (i >> 16) & 0xff
	b := (i >> 8) & 0xff
	c := i & 0xff
	return itoa(10) + "." + itoa(a) + "." + itoa(b) + "." + itoa(c) + "/32"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [3]byte
	pos := len(buf)
	for v > 0 {
		pos--
		buf[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[pos:])
}

// TestAddressBookCollisionReturnsErrorNotPanic is the core #2514 assertion:
// the builder returns an AddressBookIDCollisionError instead of panicking when
// the probe window is exhausted. Wrapped in a recover so a reintroduced panic
// fails the test loudly rather than aborting the binary.
func TestAddressBookCollisionReturnsErrorNotPanic(t *testing.T) {
	defer forceAddressBookCollision(t)()

	var (
		err  error
		pan  any
		done bool
	)
	func() {
		defer func() { pan = recover(); done = true }()
		_, _, err = buildAddressBookTable(collidingBookCfg(3))
	}()

	if !done {
		t.Fatal("builder did not complete")
	}
	if pan != nil {
		t.Fatalf("builder PANICKED on content-ID collision (regression of #2514): %v", pan)
	}
	if err == nil {
		t.Fatal("expected AddressBookIDCollisionError, got nil error")
	}
	var collErr *AddressBookIDCollisionError
	if !errors.As(err, &collErr) {
		t.Fatalf("expected *AddressBookIDCollisionError, got %T: %v", err, err)
	}
	if collErr.BucketCount != 3 {
		t.Fatalf("BucketCount = %d, want 3", collErr.BucketCount)
	}
}

// TestAddressBookCollisionPropagatesToSnapshotBuild proves the error threads
// up the snapshot builder (the apply path), so ApplyConfig rejects the config
// and retains the prior dataplane state (fail-closed) rather than panicking.
func TestAddressBookCollisionPropagatesToSnapshotBuild(t *testing.T) {
	defer forceAddressBookCollision(t)()

	cfg := collidingBookCfg(3)
	// A policy referencing a book exercises both the policy builder and
	// the address-book builder error paths inside buildSnapshot.
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   "untrust",
			Policies: []*config.Policy{
				{
					Name: "p1",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"aa"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
					},
					Action: config.PolicyPermit,
				},
			},
		},
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err == nil {
		t.Fatal("expected snapshot build to fail with collision error, got nil")
	}
	if snap != nil {
		t.Fatalf("expected nil snapshot on error, got %+v", snap)
	}
	var collErr *AddressBookIDCollisionError
	if !errors.As(err, &collErr) {
		t.Fatalf("expected wrapped *AddressBookIDCollisionError, got %T: %v", err, err)
	}
}

// TestAddressBookProbeResolvesWithoutErrorNormally guards the happy path: with
// the real seams, a benign multi-book config builds with no error (the probe
// bound scales with bucket count and is never reached for real FNV hashes).
func TestAddressBookProbeResolvesWithoutErrorNormally(t *testing.T) {
	books, _, err := buildAddressBookTable(collidingBookCfg(64))
	if err != nil {
		t.Fatalf("benign 64-book config returned an error: %v", err)
	}
	if len(books) != 64 {
		t.Fatalf("expected 64 unique book rows, got %d", len(books))
	}
	// Every assigned ID must be unique and non-zero.
	seen := make(map[uint32]struct{}, len(books))
	for _, b := range books {
		if b.ID == 0 {
			t.Fatalf("book %q got reserved ID 0", b.Name)
		}
		if _, dup := seen[b.ID]; dup {
			t.Fatalf("duplicate ID %d assigned", b.ID)
		}
		seen[b.ID] = struct{}{}
	}
}
