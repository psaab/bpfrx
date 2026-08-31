package cmdtree

import (
	"strings"
	"testing"
)

// The reverse direction is only well-defined if no two BARE topics share a
// command. Prefix keys are excluded by construction (a command like `show
// class-of-service classifier` keys both `cos-classifier` and
// `cos-classifier:`), and that exclusion is what this asserts is sufficient —
// if a future entry gave two bare topics one command, ShowTextTopicForCommand
// would return whichever won a map iteration, so the remote CLI would send a
// different topic on different runs of the same binary.
func TestShowTextTopicReverseMapIsUnambiguous_8058(t *testing.T) {
	seen := map[string]string{}
	bare := 0
	for topic, command := range showTextTopicCommand {
		if strings.HasSuffix(topic, ":") {
			continue
		}
		bare++
		if prev, dup := seen[command]; dup {
			t.Errorf("command %q is the canonical command for TWO bare topics, %q and %q. "+
				"ShowTextTopicForCommand would return whichever won map iteration, so the "+
				"remote CLI could send a different topic on different runs. If one of them "+
				"is a parameter-packed form, spell it with a trailing ':' so it is excluded "+
				"from this direction.", command, prev, topic)
		}
		seen[command] = topic
	}
	if bare < 100 {
		t.Fatalf("only %d bare topics; the table or this filter is broken and a pass "+
			"would certify nothing", bare)
	}
}

// Every bare topic must survive a round trip through both accessors. This is
// the property the cmd/cli migration relied on: each `c.showCommand("show x")`
// resolves to exactly the topic the call site used to pass literally.
func TestShowTextTopicRoundTrips_8058(t *testing.T) {
	checked := 0
	for topic := range showTextTopicCommand {
		if strings.HasSuffix(topic, ":") {
			continue
		}
		command, ok := CommandForShowTextTopic(topic)
		if !ok {
			t.Errorf("CommandForShowTextTopic(%q) reports unknown for a key of its own table", topic)
			continue
		}
		got, ok := ShowTextTopicForCommand(command)
		if !ok {
			t.Errorf("ShowTextTopicForCommand(%q) reports unknown, but %q maps to it", command, topic)
			continue
		}
		if got != topic {
			t.Errorf("round trip %q -> %q -> %q; the remote CLI would send a different topic "+
				"than the one this table prices", topic, command, got)
		}
		checked++
	}
	if checked < 100 {
		t.Fatalf("only %d topics round-tripped; the filter is broken and a pass certifies nothing", checked)
	}
}

// A prefix form is reachable by topic but deliberately NOT by command, because
// its command is shared with the bare form. A future editor who "fixes" the
// exclusion would reintroduce the ambiguity the test above forbids, so the
// exclusion is pinned rather than left as a comment.
func TestShowTextPrefixTopicsAreExcludedFromCommandLookup_8058(t *testing.T) {
	prefixes := 0
	for topic, command := range showTextTopicCommand {
		if !strings.HasSuffix(topic, ":") {
			continue
		}
		prefixes++
		if got, ok := ShowTextTopicForCommand(command); ok && got == topic {
			t.Errorf("ShowTextTopicForCommand(%q) returned the PREFIX form %q; prefix topics "+
				"carry parameters and must be built by an explicit encoder at the call site",
				command, topic)
		}
	}
	if prefixes == 0 {
		t.Fatal("no prefix-form topics found; the ':' convention changed and this cell is now vacuous")
	}
}

// The table handed to pkg/grpcapi must be a copy. It assigns the result once at
// package init and holds it for the process lifetime; if that were the SSOT
// itself, a mutation on either side would silently re-diverge the two surfaces
// this file exists to keep identical.
func TestShowTextTopicCommandsIsACopy_8058(t *testing.T) {
	first := ShowTextTopicCommands()
	if len(first) == 0 {
		t.Fatal("empty table")
	}
	var probe string
	for topic := range first {
		probe = topic
		break
	}
	first[probe] = "show mutated by a caller"
	first["injected-by-a-caller"] = "show injected"

	second := ShowTextTopicCommands()
	if second[probe] == "show mutated by a caller" {
		t.Errorf("mutating a returned map changed the SSOT entry for %q", probe)
	}
	if _, leaked := second["injected-by-a-caller"]; leaked {
		t.Error("a key added to a returned map appeared in the SSOT")
	}
}
