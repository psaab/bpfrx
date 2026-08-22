package upgrade

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── the boot gate's refusal leaves a durable trace (#6622) ──────────────
//
// scripts/image/xpf-kernel-promote exits 0 on EVERY path, deliberately: a
// non-zero exit trips the unit's OnFailure= and reboots the box over what may
// be a transient packaging window, and the firmware has already cleared
// BootNext so the next plain reboot falls back to known-good on its own.
//
// The cost of that correct decision is that the unit is Type=oneshot with
// RemainAfterExit=yes, so `systemctl status xpf-kernel-promote` reads SUCCESS
// and the unit stays active even when the gate REFUSED and the armed candidate
// is running unverified. Before this, the only signal was a journald line —
// time-limited by journal rotation. An operator who armed a candidate,
// rebooted, and came back later saw a box running the old kernel and a promote
// unit reporting success, with nothing that said the gate declined or why.
//
// #6601 is what made this worth fixing rather than theoretical: it converted
// "maybe run a stale binary" into "refuse", which is the right trade, but it
// also made refusal a REACHABLE outcome rather than a hypothetical one. A state
// that is now reachable needs to be observable.
//
// WHAT THIS DELIBERATELY DOES NOT DO. It does not make the unit fail. That was
// avoided on purpose so a refusal cannot cascade into an OnFailure= chain
// during boot, and nothing here changes it.

// refusalRecordName is the sidecar the boot gate writes when it declines to
// run. It lives beside the journal and the arm record so all three share one
// directory and one lifetime.
const refusalRecordName = "kernel-promote-refusal"

// RefusalRecordPath returns the refusal-record path for a given kernel journal
// path, exactly as ArmRecordPath does for the arm record.
func RefusalRecordPath(journalPath string) string {
	return filepath.Join(filepath.Dir(journalPath), refusalRecordName)
}

// refusalTimeLayout is what the gate's `date -u` writes.
const refusalTimeLayout = "2006-01-02T15:04:05Z"

// PromoteRefusal is the parsed record. It answers the question an operator
// actually has — "the gate did not promote my candidate; why?" — with the facts
// the DECISION was made on rather than a re-read of current state.
type PromoteRefusal struct {
	// Recorded is false when no record exists, which is the ordinary case: the
	// gate writes one only on the paths where it never ran xpfd at all.
	Recorded bool

	// Disposition is "refused" (a loud decline) or "indeterminate" (the journal
	// could not be read, so the gate could not establish whether anything was
	// armed). They are different events and are not folded together: a refusal
	// names a condition the operator can fix, an indeterminate says the gate
	// could not even tell.
	Disposition string

	// At is the gate's timestamp, zero when absent or unparseable. AtRaw keeps
	// the original text so an unparseable value is still shown rather than
	// silently becoming "no time" — a wrong clock is itself a finding.
	At    time.Time
	AtRaw string

	// BootID is /proc/sys/kernel/random/boot_id at the time of the refusal.
	// An early-boot clock can be wrong (no RTC, no NTP yet), so the timestamp
	// alone cannot answer "was this THIS boot?". This can.
	BootID string

	// JournalState is the one bit the gate reads out of the journal: absent,
	// not-armed, armed, or indeterminate.
	JournalState string

	// The systemd discovery snapshot the decision was made on. Not re-read
	// here: the whole point of #6601 r7's snapshot is that what is reported is
	// what was decided on, and a status command re-querying systemd days later
	// would describe a different system.
	Unit         string
	LoadState    string
	MainPID      string
	ControlGroup string
	ExecStart    string

	// Reason is what happened; Cause is the gate's diagnosis; Advice is the
	// branch-specific next step. Kept as three fields because the gate branches
	// its advice, and flattening them would lose which branch it took.
	Reason string
	Cause  string
	Advice string
}

// ReadRefusalRecord parses the record beside journalPath.
//
// An absent record returns a zero PromoteRefusal and a NIL error: "the gate did
// not decline" is the overwhelmingly common state and must not read as a
// failure. Anything else — unreadable, or present but with no recognisable
// fields — is an ERROR, never a silent empty answer, for the same reason
// ReadArmRecord treats a malformed record as an error: "absent" is acted on as
// a positive statement, so it must not be reachable by mis-parsing a file that
// is present.
//
// Unknown keys are ignored so a newer gate can add fields without breaking an
// older reader. The value is split on the FIRST '=' only, because a systemd
// ExecStart rendering contains several.
func ReadRefusalRecord(journalPath string) (PromoteRefusal, error) {
	path := RefusalRecordPath(journalPath)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return PromoteRefusal{}, nil
		}
		return PromoteRefusal{}, fmt.Errorf("read promote-refusal record %s: %w", path, err)
	}
	defer f.Close()

	rec := PromoteRefusal{}
	seen := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Counted per RECOGNISED key, not per '='-bearing line. Counting the
		// latter would let any file that happens to contain one '=' parse as a
		// refusal with every field empty, which renders as a REFUSED banner
		// made entirely of dashes — worse than the error it displaced.
		// Unknown keys are still tolerated, so a newer gate adding fields keeps
		// working with an older reader: it emits the recognised ones too.
		switch key {
		case "disposition":
			rec.Disposition = val
		case "refused_at":
			rec.AtRaw = val
			if t, terr := time.Parse(refusalTimeLayout, val); terr == nil {
				rec.At = t
			}
		case "boot_id":
			rec.BootID = val
		case "journal_state":
			rec.JournalState = val
		case "unit":
			rec.Unit = val
		case "load_state":
			rec.LoadState = val
		case "main_pid":
			rec.MainPID = val
		case "control_group":
			rec.ControlGroup = val
		case "exec_start":
			rec.ExecStart = val
		case "reason":
			rec.Reason = val
		case "cause":
			rec.Cause = val
		case "advice":
			rec.Advice = val
		default:
			continue
		}
		seen++
	}
	if serr := sc.Err(); serr != nil {
		return PromoteRefusal{}, fmt.Errorf("read promote-refusal record %s: %w", path, serr)
	}
	if seen == 0 {
		return PromoteRefusal{}, fmt.Errorf("promote-refusal record %s is present but "+
			"carries no recognised fields; refusing to report it as 'no refusal'", path)
	}
	rec.Recorded = true
	if rec.Disposition == "" {
		rec.Disposition = "refused"
	}
	return rec, nil
}

// clearRefusalRecord removes the record. Called wherever the arm record is
// cleared, so the two share a lifetime: a refusal describes a specific armed
// candidate, and one that outlived its journal would accuse the next boot of a
// decline that happened to a candidate no longer in flight.
func (r *KernelRunner) clearRefusalRecord() error {
	if err := os.Remove(RefusalRecordPath(r.cfg.JournalPath)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove promote-refusal record: %w", err)
	}
	return nil
}

// renderRefusal writes the operator-facing rendering. Split out of
// RenderChannelStatus so the record can be asserted on directly.
//
// It renders on EVERY disposition rather than only "refused": an indeterminate
// is also a boot where the gate did not run, and an operator told nothing there
// is in exactly the position this issue is about.
func renderRefusal(w io.Writer, rec PromoteRefusal) {
	if !rec.Recorded {
		return
	}
	fmt.Fprintln(w, "")
	switch rec.Disposition {
	case "indeterminate":
		fmt.Fprintln(w, "  Promotion gate: did NOT run — the channel state could not be read")
	default:
		fmt.Fprintln(w, "  Promotion gate: REFUSED to promote on a previous boot")
	}
	when := rec.AtRaw
	if when == "" {
		when = "-"
	}
	fmt.Fprintf(w, "    At:            %s\n", when)
	if rec.BootID != "" {
		fmt.Fprintf(w, "    Boot ID:       %s\n", rec.BootID)
	}
	if rec.JournalState != "" {
		fmt.Fprintf(w, "    Journal state: %s\n", rec.JournalState)
	}
	if rec.Reason != "" {
		fmt.Fprintf(w, "    Reason:        %s\n", rec.Reason)
	}
	if rec.Cause != "" {
		fmt.Fprintf(w, "    Cause:         %s\n", rec.Cause)
	}
	// The resolution facts the decision was made on. Printed even when empty
	// so "systemctl answered nothing" is visible as such rather than as a
	// missing line the reader has to notice the absence of.
	fmt.Fprintf(w, "    Unit:          %s\n", dashIfEmpty(rec.Unit))
	fmt.Fprintf(w, "      LoadState:   %s\n", dashIfEmpty(rec.LoadState))
	fmt.Fprintf(w, "      MainPID:     %s\n", dashIfEmpty(rec.MainPID))
	fmt.Fprintf(w, "      ControlGroup:%s\n", " "+dashIfEmpty(rec.ControlGroup))
	fmt.Fprintf(w, "      ExecStart:   %s\n", dashIfEmpty(rec.ExecStart))
	if rec.Advice != "" {
		fmt.Fprintf(w, "    Next step:     %s\n", rec.Advice)
	}
}
