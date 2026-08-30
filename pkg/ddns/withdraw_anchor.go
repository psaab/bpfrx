package ddns

import "log/slog"

// applyWithdrawAnchors substitutes THIS FAMILY's last live backend for a family
// that resolved to nop but still owns records, so the backend that published
// also withdraws (#7521).
//
// EXTRACTED SO THE SELECTION IS TESTABLE. It was two inline conditions in
// Reconcile, reachable only through a full reconcile with DHCP leases, policies
// and a state file — and a mutation swapping the anchor, or reading the wrong
// family's index, escaped every test. Burying a one-line selection under that
// much machinery is how the defect survived in the first place.
//
// THE ANCHOR IS PER FAMILY. It used to be `m.updater`, a SINGLE "last live
// backend seen" slot advanced from whichever family happened to be live. So on
// a box running v6 DDNS only, `m.updater` holds the v6 backend — and when v4
// became BACKEND-LESS while still owning records, this substituted it and sent
// v4's WITHDRAWAL to the v6 endpoint. The wrong server is asked to delete a
// record it never published: the delete is refused or lands in the wrong zone,
// and the real A record is orphaned live while the manager believes it withdrew.
//
// The trigger is narrow, and narrower than the source report: the family must
// become backend-LESS — both blocks disappearing, or backend construction
// failing — while a withdrawal is needed. The ordinary disable path resolves to
// a nop with the anchor intact and was never affected.
//
// THE NIL CHECK IS LOAD-BEARING. `isNopUpdater` is a type assertion against
// `nopUpdater`, so it answers FALSE for a nil interface — and `lastLiveUpdater`
// starts as two nils, the post-restart state. `m.updater` was never nil (it is
// seeded), so swapping the anchor without this substituted nil and segfaulted
// the restart path. Declining to substitute is also the RIGHT answer there:
// after a restart with no backend there is no evidence which endpoint published
// the owned records, so the withdrawal waits for a live one rather than guess.
// Guessing is the defect this fixes.
func (m *Manager) applyWithdrawAnchors(resolved [2]DNSUpdater) [2]DNSUpdater {
	out := resolved
	for i, family := range [2]int{4, 6} {
		if !isNopUpdater(out[i]) {
			continue
		}
		anchor := m.lastLiveUpdater[i]
		if anchor == nil || isNopUpdater(anchor) {
			continue
		}
		if !m.familyOwnsRecords(family) {
			continue
		}
		out[i] = anchor
		slog.Debug("ddns: keeping this family's live updater to withdraw owned records",
			"family", family)
	}
	return out
}
