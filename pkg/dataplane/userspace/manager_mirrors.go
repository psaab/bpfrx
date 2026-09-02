package userspace

// MirrorExclusions returns the port-mirroring entries the LAST APPLIED
// snapshot refused to install for a runtime reason (#7357 §2).
//
// This is a readback of an applied verdict, deliberately, not a fresh
// derivation. `show forwarding-options port-mirroring` asks what IS
// installed; re-resolving interface names against a live table would answer
// what WOULD be installed if the builder ran again now, and an ifindex moves
// across a netdev recreate. Where those disagree the applied answer is the
// true one and the disagreement means a missed rebuild — a bug elsewhere that
// a re-deriving renderer would hide.
//
// Returns a copy: the caller renders it outside the lock, and handing out the
// snapshot's own slice would let a concurrent apply mutate it mid-render.
func (m *Manager) MirrorExclusions() []MirrorExclusion {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil || len(m.lastSnapshot.MirrorExclusions) == 0 {
		return nil
	}
	out := make([]MirrorExclusion, len(m.lastSnapshot.MirrorExclusions))
	copy(out, m.lastSnapshot.MirrorExclusions)
	return out
}
