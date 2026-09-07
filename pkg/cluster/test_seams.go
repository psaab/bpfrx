// Test-only helpers for pkg/cluster. They live in the PRODUCTION package so
// external packages (pkg/daemon's HA cells) can drive them without
// internal-export tricks — the same arrangement as pkg/dhcp/test_seams.go.
// Not for production callers.
//
// They live in their OWN FILE because sync.go sits at the 2000-LOC modularity
// floor (pkg/refactoraudit): adding this seam there crossed it. A new file is
// the honest answer rather than an entry in docs/refactoring-audit-accepted.txt
// — the guard was right that sync.go should not keep growing, and a test seam
// is the least load-bearing thing in it. Put the next one here too.

package cluster

// SetPeerIPsecSAsForTesting installs the peer's advertised IPsec
// connection-name set without a wire round trip, mirroring
// SetPeerDHCPLeasesForTesting.
//
// #9139: it exists so the TAKEOVER LEGS can be driven. Both halves of that fix
// are wiring — an advertise gate and a per-RG re-initiate call site — and a
// unit test of the filter function alone leaves them unguarded, which is
// exactly how the defect survived: the filter was never the broken part.
func (s *SessionSync) SetPeerIPsecSAsForTesting(names []string) {
	s.peerIPsecSAsMu.Lock()
	defer s.peerIPsecSAsMu.Unlock()
	s.peerIPsecSAs = append([]string(nil), names...)
}
