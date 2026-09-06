package config

// #8997: A NODE-LOCAL POSTURE READER THAT CANNOT SEE THE ELIDED SPELLINGS
// SILENTLY AGREES WITH THE PEER.
//
// `chassis cluster strict-session-auth` is node-local (#7441): config-sync must
// neither clear it nor set it, because an admitted-but-unauthenticated
// session-sync stream can push configuration to a standby. The hook decides by
// comparing the local tree against the incoming one, and `continue`s when they
// AGREE.
//
// The reader underneath walked the raw tree with FindChild, which only ever
// matches a node whose Keys are exactly one segment. So it saw the flag in the
// fully-braced spelling and MISSED it in both elided ones:
//
//	chassis { cluster { strict-session-auth; } }   found
//	chassis { cluster strict-session-auth; }       MISSED  -> Keys ["cluster","strict-session-auth"]
//	chassis cluster strict-session-auth;           MISSED  -> Keys ["chassis","cluster","strict-session-auth"]
//
// A MISS IS NOT A FALSE NEGATIVE HERE, IT IS AN AGREEMENT. Misreading the local
// node as not having the flag makes both sides false, the sides agree, and the
// hook does nothing — so the branch that logs and the branch that fails closed
// are both downstream of a difference that is never detected. The correct
// fail-closed handling in that function is unreachable in exactly the case it
// was written for.
//
// Both directions were broken, which matters because #7441's own rationale says
// preserving in one direction only leaves the other as a lever: a peer could
// also SET the posture on a node that had not chosen it.
//
// WHY THIS LIVES IN pkg/config AND IS EXPORTED. The elision shapes are a
// property of the AST, not of the daemon, and pkg/daemon cannot reach the
// package-private #8992 helpers. Re-deriving the walk in the daemon would make
// a third resolver kept in step with the other two by a comment, which is the
// defect class #8994 is open on.

// FlagSetAtPath reports whether the bare flag leaf named by path — a full path
// from the tree root, e.g. ["chassis","cluster","strict-session-auth"] — is
// present in t, in ANY spelling: fully braced, partly elided, or fully packed
// onto one node's Keys.
//
// It answers the question "would the compiler see this flag", so an INACTIVE
// node reports false: `inactive:` statements are stripped before compilation
// (WithoutInactive), and the firewall behaves as if they were absent. A reader
// that counted them would defend a posture the operator had deactivated.
//
// It is deliberately for BARE FLAGS (arity 0) only. A valued leaf needs to
// distinguish "the leaf is present" from "the value is X", and folding both
// into one boolean is how a reader ends up asserting more than it measured.
func (t *ConfigTree) FlagSetAtPath(path []string) bool {
	if t == nil || len(path) == 0 {
		return false
	}
	return flagSetInNodes8997(t.Children, path)
}

// flagSetInNodes8997 matches path against nodes, allowing each node's Keys to
// consume a RUN of consecutive path segments rather than exactly one.
func flagSetInNodes8997(nodes []*Node, path []string) bool {
	for _, n := range nodes {
		if n == nil || n.Inactive || len(n.Keys) == 0 {
			continue
		}
		// How many leading path segments does this node's Keys consume?
		i := 0
		for i < len(n.Keys) && i < len(path) && n.Keys[i] == path[i] {
			i++
		}
		if i == 0 {
			continue
		}
		if i == len(path) {
			// Every segment matched. Either the Keys end here (the statement
			// is exactly this node) or they carry MORE tokens — a packed run
			// in which our flag is one statement among several. Both mean the
			// flag is present.
			//
			// This cannot match a VALUE by accident: the segments are compared
			// in order from the root, so a node spelling `chassis cluster
			// <other-leaf> strict-session-auth` diverges at <other-leaf> and
			// never reaches here.
			return true
		}
		if i < len(n.Keys) {
			// The node's Keys diverged from the path before the path ran out —
			// a different statement that shares a prefix.
			continue
		}
		// Keys were a proper prefix of path: descend for the remainder.
		if flagSetInNodes8997(n.Children, path[i:]) {
			return true
		}
	}
	return false
}
