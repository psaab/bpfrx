package daemon

import "log/slog"

// noteExternalHostRenameIfAny records a stale-management-certificate debt when
// the kernel host name has changed WITHOUT xpfd performing the rename (#6863).
//
// # Why a watcher and not a hook
//
// The #6827 mechanism records the debt in `renameHostNotingStaleMgmtCert`,
// which is an in-process fence around xpfd's own `sethostname`. Every other way
// the kernel name can move — `hostnamectl set-hostname`, a direct
// `sethostname(2)` by another process, a provisioning tool rewriting
// /etc/hostname, a manual edit plus a reboot — never calls into xpfd, so there
// is no event to hook and nothing ever sets the flag. Making that flag survive
// longer or drain at more points cannot help.
//
// The boot path does not close it either: `applyHostname` returns early when
// the kernel name already equals the configured one, which is exactly the state
// an external rename leaves behind when it happens to match config.
//
// # Why it cannot double-fire on our own renames
//
// The baseline moves inside `renameHostNotingStaleMgmtCert`, under the same
// single hold of staleCertMu that sets the flag. So a rename xpfd performs
// advances the baseline atomically with the debt it already recorded, and this
// watcher never sees it as external. Without that, one rename would produce two
// debts and two WARNs — the duplicate the #6827 generation fence exists to
// prevent, arriving from outside it.
//
// # Seeding
//
// An empty baseline means "not yet observed". The first call seeds it and
// records NOTHING: a daemon that has just started has no earlier name to have
// been renamed from, and treating boot as a rename would emit a diagnosis on
// every restart of a box whose certificate is perfectly current.
//
// Returns true if a debt was recorded, for the tests. Delivery is the caller's
// job and happens outside the lock, matching applyHostname.
func (d *Daemon) noteExternalHostRenameIfAny() bool {
	current, err := osHostname()
	if err != nil || current == "" {
		// An unreadable kernel name is not evidence of a rename. Say nothing
		// and leave the baseline alone, so a transient read failure cannot
		// manufacture a diagnosis on the next successful read.
		return false
	}

	d.staleCertMu.Lock()
	prior := d.lastSeenHostName
	if prior == "" {
		d.lastSeenHostName = current
		d.staleCertMu.Unlock()
		return false
	}
	if prior == current {
		d.staleCertMu.Unlock()
		return false
	}
	d.lastSeenHostName = current
	d.staleCertPending = true
	d.staleCertGen++
	d.staleCertMu.Unlock()

	slog.Info("kernel host name changed outside xpfd",
		"from", prior, "to", current,
		"note", "re-checking whether the durable management certificate still covers it")
	return true
}

// watchExternalHostRenameOnce is the tick body: observe, and deliver if a debt
// was recorded.
//
// Delivery runs OUTSIDE the lock because deliverStaleMgmtCertDiagnosis takes
// staleCertMu itself, exactly as applyHostname does after a rename.
func (d *Daemon) watchExternalHostRenameOnce() {
	if d.noteExternalHostRenameIfAny() {
		d.deliverStaleMgmtCertDiagnosis()
	}
}
