package config

// validateContentFreeSystemLoginWarnings warns when `system login` is authored
// with no user and no class (#6972).
//
// THE DISPOSITION IS UNCHANGED. Such a stanza denies every non-root CLI command
// today, in both spellings, and it keeps doing so. Deny is the correct default:
// an RBAC stanza that resolves to no authorization must not resolve to
// "everything", and the alternative is a fail-OPEN on the authorization surface
// reachable from a half-finished stanza or a `load merge` that lost a body.
//
// What was wrong is that the denial was INVISIBLE. Measured, all four
// content-free spellings commit clean with zero warnings:
//
//	system { login; }         nilLogin=false  dropped=false   0 warnings
//	system login;             nilLogin=true   dropped=true    0 warnings
//	system { login user; }    nilLogin=false  dropped=true    0 warnings
//	system login user;        nilLogin=true   dropped=true    0 warnings
//
// so an operator authors one, sees a clean commit, and discovers at the next
// login that every non-root command is refused. That lockout is the defect,
// not the denial.
//
// WHY THIS IS NOT IMPLEMENTED BY NARROWING THE PACKED MARK. #6706 round 11
// records that narrowing being written, measured, and REVERTED, because it
// makes the two spellings of identical text disagree:
//
//	"system { login; }"  -> non-nil EMPTY LoginConfig, flag irrelevant -> DENIES
//	"system login;"      -> nil Login, flag                            -> DENIES
//	"system login;"      -> nil Login, no flag                         -> PERMITS
//
// A warning is orthogonal to the mark. The mark decides AUTHORIZATION; this
// decides what the operator is TOLD. Folding them is how that fail-open gets
// reintroduced as a side effect of improving a message.
//
// The two halves of the condition are deliberately separate. A stanza EXISTS if
// either spelling produced one — a non-nil LoginConfig, or the packed drop flag
// — and it names NOBODY if it resolved to no users and no classes. After #6966
// a packed login that names anybody is rejected at commit, so a surviving
// packed stanza is content-free by construction; the explicit test is kept
// anyway rather than relying on that, because it is a fact about a different
// gate that could be narrowed later.
func validateContentFreeSystemLoginWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	login := cfg.System.Login
	hasStanza := login != nil || cfg.System.LoginDroppedByPacking
	if !hasStanza {
		return nil
	}
	if login != nil && (len(login.Users) > 0 || len(login.Classes) > 0) {
		return nil
	}
	return []string{
		"system login: the stanza names no user and no class, so it grants nothing — " +
			"every non-root CLI command is DENIED and secrets are withheld. This commits " +
			"cleanly and the denial is not otherwise reported, so it is easy to mistake for " +
			"a working configuration. Add `system login user <name> class <class>` (or a " +
			"`system login class`) if you meant to grant access, or delete the stanza if you " +
			"did not",
	}
}
