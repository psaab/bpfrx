package config

import "sort"

// DHGroupKeyword maps a Diffie-Hellman group number to the canonical swanctl
// proposal keyword, and is the SINGLE source of truth for which groups this
// product accepts.
//
// #8597 (muse-004 K88). ValidateDHGroup accepted any positive integer while
// pkg/ipsec's renderer spelled only an explicit table, falling through to
// `modp<n>` for everything else. Measured: `dh-group 99` committed clean and
// rendered `modp99`; 17 rendered `modp17`, 33 `modp33`, and charon rejects all
// of them. The operator gets an IPsec that never establishes, with diagnostics
// pointing at charon rather than at the one-line value they typed.
//
// 17 and 18 are the sharpest cases and are worth naming, because they are REAL
// IKE groups (RFC 3526 modp6144 and modp8192) that this table does not carry:
// they render as `modp17` / `modp18`, which is not merely unspelled but WRONG.
// They are omitted here rather than guessed at, because adding a keyword this
// map does not already contain is a claim about what strongSwan accepts, and
// this change is not the place to make an unverified one. Rejecting them at
// commit with the accepted set named is strictly better than today's silent
// mis-render: the operator learns immediately instead of debugging charon.
//
// The map lives in pkg/config rather than pkg/ipsec because the VALIDATOR needs
// it and pkg/ipsec imports pkg/config. That direction is the point — it is what
// makes it impossible for the gate and the renderer to disagree about the
// accepted set, which is the actual defect here.
var dhGroupKeywords = map[int]string{
	// RFC 3526 / RFC 2409 MODP groups.
	1:  "modp768",
	2:  "modp1024",
	5:  "modp1536",
	14: "modp2048",
	15: "modp3072",
	16: "modp4096",
	// RFC 5114 MODP groups with prime-order subgroups.
	22: "modp1024s160",
	23: "modp2048s224",
	24: "modp2048s256",
	// RFC 5903 / RFC 6954 / RFC 8031 elliptic-curve groups. These must NOT
	// fall through to a modp spelling: a bit count is not a curve name.
	19: "ecp256",
	20: "ecp384",
	21: "ecp521",
	25: "ecp192",
	26: "ecp224",
	27: "ecp224bp",
	28: "ecp256bp",
	29: "ecp384bp",
	30: "ecp512bp",
	31: "curve25519",
	32: "curve448",
}

// DHGroupKeyword returns the swanctl proposal keyword for a DH group number and
// whether the group is one this product can spell.
func DHGroupKeyword(group int) (string, bool) {
	kw, ok := dhGroupKeywords[group]
	return kw, ok
}

// SupportedDHGroups returns the accepted group numbers in ascending order, for
// diagnostics that name the set.
func SupportedDHGroups() []int {
	out := make([]int, 0, len(dhGroupKeywords))
	for g := range dhGroupKeywords {
		out = append(out, g)
	}
	sort.Ints(out)
	return out
}
