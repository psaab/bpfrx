// Package manifest is the single source of truth (SSOT) for the set of
// binaries the in-place-upgrade subsystem manages as a version-locked unit
// (#1982).
//
// The upgrade flow treats these binaries as one atomic, lockstep payload:
// the .deb stages them (debian/rules), the maintainer scripts seed/link/
// clean them (debian/xpf.{preinst,postinst,postrm}), the first-install seed
// copies them (pkg/upgrade/runtime), and the verified cut-over copies, flips,
// verifies, and GCs them (pkg/upgrade). Before #1982 the four-binary list was
// hand-duplicated across eight independent edit sites with no guard, so adding
// a future helper meant editing every site by hand and a one-file miss shipped
// a green build that left an old helper in service, failed rollback cleanup, or
// omitted a binary from first-install seeding.
//
// This package centralizes the list. Go consumers (pkg/upgrade and
// pkg/upgrade/runtime) call Names(); the shell maintainer scripts and
// debian/rules keep a self-contained literal (no build-time mutation of
// tracked files), and the drift canary (manifest_drift_test.go) FAILS the
// suite if any shell site diverges from this manifest. So the manifest stays
// the one place a new managed binary is declared, and the canary enforces it.
package manifest

import "strings"

// Binary describes one managed upgrade binary.
type Binary struct {
	// Name is the staged/sbin basename, e.g. "xpfd". It is also the
	// versions/<ver>/<name> and /usr/local/sbin/<name> basename.
	Name string

	// StagedSrc is the build-output path, relative to the repo root, that
	// debian/rules installs into the dpkg staging dir. For most binaries this
	// equals Name (the Makefile drops them at the repo root); xpf-day0-config
	// is a checked-in script under scripts/image/.
	StagedSrc string

	// LockstepCut classifies the binary. true => cut in version lockstep with
	// the daemon (xpfd, xpf-userspace-dp must match the running version exactly
	// or the dataplane mismatches). false => operator tool (cli,
	// xpf-day0-config) that is copied/linked alongside but is not part of the
	// matched dataplane set. The field documents intent and lets future cut /
	// verify logic distinguish the two classes without re-deriving it from a
	// name allowlist; the current cut copies and links ALL managed binaries.
	LockstepCut bool
}

// Managed is the ordered SSOT list of managed upgrade binaries.
//
// Order matters only for deterministic rendering (ShellBINS, debian/rules);
// the maintainer-script and Go copy/link/cleanup loops are order-free. Keep
// xpfd first — several callers and tests rely on managedBins[0] being the
// daemon, and the cut verifies versions/<ver>/{xpfd,xpf-userspace-dp} exist.
var Managed = []Binary{
	{Name: "xpfd", StagedSrc: "xpfd", LockstepCut: true},
	{Name: "cli", StagedSrc: "cli", LockstepCut: false},
	{Name: "xpf-userspace-dp", StagedSrc: "xpf-userspace-dp", LockstepCut: true},
	{Name: "xpf-day0-config", StagedSrc: "scripts/image/xpf-day0-config", LockstepCut: false},
}

// Names returns the managed-binary basenames in Managed order. Callers that
// want the slice for a copy/link/cleanup loop use this; it allocates a fresh
// slice each call so a caller can never mutate the SSOT.
func Names() []string {
	out := make([]string, len(Managed))
	for i, b := range Managed {
		out[i] = b.Name
	}
	return out
}

// ShellBINS renders the space-separated basename list exactly as the
// maintainer scripts' BINS shell variable carries it, e.g.:
//
//	xpfd cli xpf-userspace-dp xpf-day0-config
//
// The drift canary compares each shell site's BINS literal against this.
func ShellBINS() string {
	return strings.Join(Names(), " ")
}
