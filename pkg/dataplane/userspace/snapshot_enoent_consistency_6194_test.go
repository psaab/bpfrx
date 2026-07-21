package userspace

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestBPFSessionReadAbsentMatchesLayer1ErrorSet pins the #6194 consistency
// contract: the Layer-2 transactional-snapshot "key absent" classifier
// (bpfSessionReadAbsent, used by snapshotBPFSessionV4Locked /
// snapshotBPFSessionV6Locked) must accept the SAME key-not-found error set as
// the Layer-1 dataplane.sessionNotFound predicate — ebpf.ErrKeyNotExist OR
// unix.ENOENT (both, via dataplane.IsKeyNotFound).
//
// The snapshot classifies an absent pre-image as existed=false with a nil
// error, so a subsequent mirror-failure rollback DELETES the freshly-installed
// key rather than surfacing the read error and refusing the install. If ENOENT
// is treated as a hard error instead, the install would be refused where
// Layer-1 would have proceeded — the divergence #6194 closes.
//
// bpfShim is a concrete *dataplane.Manager backed by a real cilium map, whose
// GetSession* returns ErrKeyNotExist (never bare ENOENT) on a miss, so the
// ENOENT path is not reachable through a live map. This test therefore pins the
// classification seam directly — no BPF map, no root required.
//
// RED-on-revert: change bpfSessionReadAbsent's body in manager_ha.go from
//
//	return dataplane.IsKeyNotFound(err)
//
// back to the pre-#6194
//
//	return errors.Is(err, ebpf.ErrKeyNotExist)
//
// and the ENOENT (bare + wrapped) and identity assertions below fail with a
// clean assertion error — not a compile break (ebpf stays imported via
// mergeHAStateFromMaps and the restore delete-idempotency checks).
func TestBPFSessionReadAbsentMatchesLayer1ErrorSet(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantAbsent bool
	}{
		{"ebpf.ErrKeyNotExist", ebpf.ErrKeyNotExist, true},
		{"unix.ENOENT", unix.ENOENT, true},
		{"wrapped ebpf.ErrKeyNotExist", fmt.Errorf("lookup v4: %w", ebpf.ErrKeyNotExist), true},
		{"wrapped unix.ENOENT", fmt.Errorf("lookup v4: %w", unix.ENOENT), true},
		// Fail-safe direction: a genuine read error is NOT "absent" — it must be
		// surfaced so the install is refused, never silently treated as a
		// missing pre-image.
		{"unix.EFAULT", unix.EFAULT, false},
		{"generic read error", errors.New("sessions map not found"), false},
		// nil is not a not-found error (the snapshot handles a nil GET as
		// "found" before consulting this predicate).
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bpfSessionReadAbsent(tc.err); got != tc.wantAbsent {
				t.Fatalf("bpfSessionReadAbsent(%v) = %v, want %v", tc.err, got, tc.wantAbsent)
			}
		})
	}

	// The ENOENT-absent path must behave IDENTICALLY to the ErrKeyNotExist-absent
	// path — the whole point of #6194.
	if got, want := bpfSessionReadAbsent(unix.ENOENT), bpfSessionReadAbsent(ebpf.ErrKeyNotExist); got != want {
		t.Fatalf("ENOENT/ErrKeyNotExist divergence: bpfSessionReadAbsent(ENOENT)=%v, bpfSessionReadAbsent(ErrKeyNotExist)=%v", got, want)
	}
}
