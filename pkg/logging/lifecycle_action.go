package logging

// The wire action codes and the "not applicable" sentinel live here with the
// applicability predicate below: what an action IS and when it APPLIES are one
// subject, and separating them is how the exception ended up being re-learned
// by each surface in turn (#7531).
const (
	actionDeny   = 0
	actionPermit = 1
	actionReject = 2
	// actionNotApplicable flags the binary-log action byte on a SESSION_CLOSE,
	// which carries no forwarding decision. Its wire action byte is
	// intentionally 0, which the raw encoding would stamp as "deny" (actionDeny)
	// and mislead binary forensic consumers into reading a normal close as a
	// drop (#4914). The standard and structured text formatters OMIT the action
	// field on a close (#2513); the fixed-shape binary record cannot omit a
	// field, so it carries this explicit "not applicable" sentinel instead of a
	// bogus 0.
	actionNotApplicable = 0xFF
)

// eventCarriesForwardingAction reports whether an event type's wire action byte
// is a real permit/deny/reject decision (#7531).
//
// It is ONE predicate on purpose. The producer writes 0 for both lifecycle
// events and says so at the write site, for each of them, in as many words:
//
//	// [54] action: a session close has no permit/deny/reject action
//	// semantics, so this byte is intentionally 0. … Do NOT rely on the 0
//	// rendering as a value — both close formatters skip it.
//
//	// [54] action: a session open is a permit-and-create event, not a
//	// forwarding decision, so this byte is intentionally 0 (same as the
//	// close path). … Do NOT rely on the 0 rendering as a value.
//
// The Go side then taught the exception to the formatters ONE AT A TIME —
// #2513 for the close text lines, #2593 for the open text lines, #4914 for the
// binary close record — and each new surface inherited the raw
// `actionName(0)` == "deny" until someone noticed it too. trace.go, the REST
// and SSE surfaces, and the binary SESSION_OPEN record are the ones that never
// got their own issue.
//
// Teaching every surface the same exception is what produced a four-issue tail
// for one fact, so this states the fact once and the surfaces read it.
func eventCarriesForwardingAction(eventType uint8) bool {
	switch eventType {
	case eventTypeSessionOpen, eventTypeSessionClose:
		// A create and a teardown are lifecycle transitions. The forwarding
		// decision that ALLOWED the session is carried by the policy
		// attribution (PolicyID / PolicyName), not by this byte.
		return false
	default:
		return true
	}
}

// recordActionName renders an event's action for EventRecord.Action, returning
// the empty string for an event type that carries no forwarding decision
// (#7531).
//
// Empty rather than a placeholder like "n/a": EventRecord.Action feeds the
// event-buffer FILTER (eventbuf.go), which skips an empty filter field and
// compares case-insensitively otherwise. An operator filtering `action deny`
// was matching every normal session open and close — the bug's most concrete
// harm, since it makes a deny filter useless on a busy box. A placeholder
// string would just be a new value to accidentally match.
func recordActionName(eventType, action uint8) string {
	if !eventCarriesForwardingAction(eventType) {
		return ""
	}
	return actionName(action)
}
