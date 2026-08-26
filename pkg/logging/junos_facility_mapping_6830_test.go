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

import "testing"

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
	"ntp":           FacilityNTP,
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

// TestFacilityMisfiledIdentifiesTodaysGap6830 is the cell that states the
// defect as a fact rather than as prose, and it is deliberately written to fail
// the day the mapping is applied.
//
// Every name below is valid Junos that this box currently emits as something
// else. When #6830's contract decision is taken and the emit path starts using
// the table, THIS TEST GOES RED — and that is its job: the flip must be a
// deliberate edit here, not a silent divergence.
func TestFacilityMisfiledIdentifiesTodaysGap6830(t *testing.T) {
	misfiledToday := []string{
		"authorization", "conflict-log", "dfc", "firewall",
		"ftp", "interactive-commands", "kernel", "ntp", "pfe",
	}
	for _, name := range misfiledToday {
		emitted, junos, misfiled := FacilityMisfiled(name)
		if !misfiled {
			t.Errorf("FacilityMisfiled(%q) reports no gap. If the emit path now applies "+
				"the documented mapping, that is the #6830 contract change landing — "+
				"remove %q from this list in the SAME commit, so the flip is deliberate",
				name, name)
			continue
		}
		if emitted != FacilityLocal0 {
			t.Errorf("%q currently emits %d, expected the local0 default", name, emitted)
		}
		if junos == FacilityLocal0 {
			t.Errorf("%q maps to local0 per the table, so it is not misfiled at all", name)
		}
	}
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

// TestJunosSpellingsAreNotRecognizedByParseFacility6830 records the sharpest
// edge of the defect: the two most obvious facilities in the vocabulary.
//
// Junos writes `authorization` and `kernel`; ParseFacility recognizes the BSD
// spellings `auth` and `kern`. So an operator configuring this box as the Junos
// clone it is gets local0 for authentication and kernel records — the two
// buckets a security collector is most likely to be watching.
func TestJunosSpellingsAreNotRecognizedByParseFacility6830(t *testing.T) {
	for junosName, bsdName := range map[string]string{
		"authorization": "auth",
		"kernel":        "kern",
	} {
		if got := ParseFacility(junosName); got != FacilityLocal0 {
			t.Errorf("ParseFacility(%q) = %d — if this now resolves, the #6830 contract "+
				"change has landed and this cell must be updated with it", junosName, got)
		}
		if ParseFacility(bsdName) == FacilityLocal0 {
			t.Errorf("ParseFacility(%q) collapsed to local0; the BSD spelling is the one "+
				"this box has always recognized", bsdName)
		}
		if want, _ := JunosRemoteFacility(junosName); want != ParseFacility(bsdName) {
			t.Errorf("the table maps %q to %d but the BSD spelling %q parses to %d — the "+
				"two spellings of one facility must agree",
				junosName, want, bsdName, ParseFacility(bsdName))
		}
	}
}
