package logging

// junos_facility_mapping_6830_test.go — #6830.
//
// Junos facility names and the names ParseFacility recognizes are different
// vocabularies, and the mismatch resolves silently to local0. That is a
// LABELLING error, not a filtering one: the records arrive, attributed to a
// facility the operator never wrote, and a collector bucketing on facility
// files them in the wrong bucket where nobody looks for them.
//
// The mapping is not a judgement call. Junos publishes it, and the repository
// already implemented one row of it (change-log → local6) — the table was
// consulted once and never finished. These cells pin the whole table against
// the documentation and pin what the box does with it today.

import (
	"sort"
	"testing"
)

// junosDocumentedRemote is Junos's published mapping for messages directed to a
// remote destination, transcribed from the two documented rules:
//
//   - "Table 3: Default Facilities for Messages Directed to a Remote
//     Destination" — the six Junos-SPECIFIC names with a localX stand-in.
//   - "For facilities that are not listed, the default alternative name is the
//     same as the local facility name" — everything else goes out as itself.
//
// It is written out here INDEPENDENTLY of the production map rather than
// derived from it. A test that reads the same map it is checking pins nothing;
// this one fails if a row is edited to something the documentation does not
// say.
var junosDocumentedRemote6830 = map[string]int{
	// Table 3.
	"change-log":           FacilityLocal6,
	"conflict-log":         FacilityLocal5,
	"dfc":                  FacilityLocal1,
	"firewall":             FacilityLocal3,
	"interactive-commands": FacilityLocal7,
	"pfe":                  FacilityLocal4,
	// Not listed → same as the local facility name.
	"authorization": FacilityAuth,
	"daemon":        FacilityDaemon,
	"ftp":           FacilityFTP,
	"kernel":        FacilityKern,
	"user":          FacilityUser,
}

// TestJunosRemoteFacilityMatchesTheDocumentedTable6830 pins every row.
func TestJunosRemoteFacilityMatchesTheDocumentedTable6830(t *testing.T) {
	for name, want := range junosDocumentedRemote6830 {
		got, ok := JunosRemoteFacility(name)
		if !ok {
			t.Errorf("%q is a Junos `[edit system syslog]` facility but is absent from "+
				"the mapping table — the operator who writes it gets local0 and no "+
				"indication of what Junos would have sent", name)
			continue
		}
		if got != want {
			t.Errorf("JunosRemoteFacility(%q) = %d, want %d per the documented table — "+
				"a wrong row here misfiles records just as silently as no row at all",
				name, got, want)
		}
	}
	// The converse: no INVENTED rows. A name in the production map that the
	// documentation does not cover would be exactly the "picked by
	// implementation convenience" the issue warns against.
	for name := range junosRemoteFacility {
		if _, ok := junosDocumentedRemote6830[name]; !ok {
			t.Errorf("the mapping table carries %q, which is not in the documented "+
				"Junos vocabulary — rows must be a lookup, not a judgement", name)
		}
	}
}

// TestWildcardIsNotAMappingRow6830 pins that `any` stays out of the table. It
// names no facility on purpose (FacilityIsWildcard), so a row for it would
// assert an intent the operator did not express.
func TestWildcardIsNotAMappingRow6830(t *testing.T) {
	if _, ok := JunosRemoteFacility("any"); ok {
		t.Fatal("`any` must not be a mapping row — it is the Junos wildcard and names " +
			"no facility (see FacilityIsWildcard)")
	}
	if !FacilityIsWildcard("any") {
		t.Fatal("FacilityIsWildcard no longer recognizes `any`")
	}
}

// TestNothingInTheTableIsMisfiled6830 is what the gap cell BECAME when the
// contract decision was taken and the emit path started using the table.
//
// It used to list the nine names this box emitted as something else and assert
// each was misfiled, deliberately written to go RED the day the mapping was
// applied so the flip could not be silent. The flip has landed. Asserting the
// gap still exists would now pin the defect, so the cell is INVERTED rather
// than deleted: no name in the documented vocabulary may be misfiled.
//
// That is a stronger property than the list it replaces, and it needs no
// maintenance: it quantifies over the table, so a row ADDED without wiring, or
// a wiring regression on any existing row, reds here naming the facility. The
// old list had to be hand-edited every time the table grew.
func TestNothingInTheTableIsMisfiled6830(t *testing.T) {
	checked := 0
	for _, name := range junosFacilityNames6830(t) {
		emitted, junos, misfiled := FacilityMisfiled(name)
		if misfiled {
			t.Errorf("%q is emitted as %d but Junos documents %d. Either ParseFacility "+
				"stopped consulting the table, or a row was added to it without the "+
				"emit path following — the #6830 defect, on this name.",
				name, emitted, junos)
		}
		checked++
	}
	// ANTI-VACUITY. A helper returning no names would report "nothing is
	// misfiled", which is indistinguishable from a healthy result and is
	// exactly how this class of check fails.
	//
	// The floor is DERIVED from the independent transcription rather than
	// written as a literal (#6830 round 2). A hardcoded count is a second place
	// the table's size lives, so removing a row reds this cell for the wrong
	// reason and the obvious repair is to edit the number — which is how an
	// anti-vacuity floor quietly stops tracking the thing it guards.
	if want := len(junosDocumentedRemote6830); checked < want {
		t.Fatalf("only %d facility names were checked; the documented table has %d rows, "+
			"so this assertion is not reaching them", checked, want)
	}
}

// junosFacilityNames6830 lists the table's keys.
//
// It names them explicitly rather than ranging the production map, so the
// population cannot silently shrink with the thing it is measuring, and it
// fails if any listed name has left the table.
func junosFacilityNames6830(t *testing.T) []string {
	t.Helper()
	// #6830 round 2: iterate the independent transcription rather than a
	// third hand-written copy of the same names. Three copies of one list is
	// three places to forget, and the transcription is already the thing every
	// other cell in this file checks against.
	out := make([]string, 0, len(junosDocumentedRemote6830))
	for name := range junosDocumentedRemote6830 {
		if _, ok := JunosRemoteFacility(name); !ok {
			t.Fatalf("%q is in the documented transcription but not in the production "+
				"table; a name Junos documents must not be silently dropped from the "+
				"emit path", name)
		}
		out = append(out, name)
	}
	sort.Strings(out) // deterministic order for a deterministic failure
	return out
}

// TestCorrectlyMappedNamesAreNotReportedMisfiled6830 is the PAIRED control.
// Without it, "FacilityMisfiled reports a gap" is satisfied by a predicate that
// returns true for everything — which would make the operator warning fire on
// every correct config and train them to ignore it.
func TestCorrectlyMappedNamesAreNotReportedMisfiled6830(t *testing.T) {
	for _, name := range []string{"change-log", "daemon", "user"} {
		if _, _, misfiled := FacilityMisfiled(name); misfiled {
			t.Errorf("%q is already emitted as Junos documents, but FacilityMisfiled "+
				"reports a gap — the warning would fire on a correct config", name)
		}
	}
	// A name in neither vocabulary is NOT "misfiled": there is nothing to
	// misfile it against. It is a typo, and conflating the two sends an
	// operator looking for the wrong thing.
	if _, _, misfiled := FacilityMisfiled("nonsense"); misfiled {
		t.Error("a name outside the Junos vocabulary must not be reported misfiled — " +
			"it has no documented target, so the operator action is to fix the spelling")
	}
}

// TestJunosSpellingsResolveToTheirBSDFacility6830 records the sharpest edge of
// the defect, now as the fixed behaviour.
//
// Junos writes `authorization` and `kernel`; this box recognized only the BSD
// spellings `auth` and `kern`, so an operator configuring it as the Junos clone
// it is got local0 for authentication and kernel records — the two buckets a
// security collector is most likely watching.
//
// The cell used to assert those Junos spellings resolve to local0, as a
// tripwire. They now resolve, so it asserts the AGREEMENT instead: the two
// spellings of one facility must produce the same code. Pinning either side to
// a literal would encode which spelling is trusted, and the whole defect was
// that the two disagreed.
func TestJunosSpellingsResolveToTheirBSDFacility6830(t *testing.T) {
	for junosName, bsdName := range map[string]string{
		"authorization": "auth",
		"kernel":        "kern",
		"user":          "user",
		"daemon":        "daemon",
	} {
		junos, bsd := ParseFacility(junosName), ParseFacility(bsdName)
		if bsd == FacilityLocal0 && bsdName != "local0" {
			t.Errorf("ParseFacility(%q) collapsed to local0; the BSD spelling is the one "+
				"this box has always recognized", bsdName)
			continue
		}
		if junos != bsd {
			t.Errorf("ParseFacility(%q) = %d but ParseFacility(%q) = %d — two spellings "+
				"of one facility disagree, which is the #6830 defect itself",
				junosName, junos, bsdName, bsd)
		}
		if want, ok := JunosRemoteFacility(junosName); !ok || want != junos {
			t.Errorf("the table maps %q to %d (present=%v) but the emit path produces %d",
				junosName, want, ok, junos)
		}
	}
}

// TestJunosNamesAreReportedKnown6830 pins the other half of the flip: a
// documented facility must no longer be reported as an unmapped substitution.
//
// Without this, the emit path would file the record correctly while the caller
// still warned that it had substituted local0 — a warning that is false the
// moment the mapping lands, and the fastest way to train an operator to ignore
// the one warning that still means something.
func TestJunosNamesAreReportedKnown6830(t *testing.T) {
	for _, name := range junosFacilityNames6830(t) {
		code, known := ParseFacilityChecked(name)
		if !known {
			t.Errorf("ParseFacilityChecked(%q) reports UNKNOWN, but the emit path now "+
				"maps it to %d. The substitution warning would fire on a config that is "+
				"handled correctly.", name, code)
		}
	}
	// Paired control: a name in neither vocabulary must still be unknown, or
	// the predicate has degraded to "everything is fine".
	if _, known := ParseFacilityChecked("nonsense"); known {
		t.Error("ParseFacilityChecked reports a nonsense name as known; the substitution " +
			"warning can no longer fire on a real typo")
	}
}
