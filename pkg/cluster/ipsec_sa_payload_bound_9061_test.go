package cluster

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// #9061: decodeIPsecSAPayload split a peer-supplied frame with no element-count
// or name-length bound. The only bound in the chain is the 16 MiB frame ceiling.
func TestIPsecSAPayloadIsBounded9061(t *testing.T) {
	for _, tc := range []struct {
		name      string
		payload   []byte
		malformed bool
		wantNames int
	}{
		// REFERENCE ARM: an ordinary set must decode exactly. Without it, every
		// refusal below is satisfied by a decoder that refuses everything.
		{"ordinary set", []byte("vpn-gw1\nvpn-gw2\nvpn-gw3"), false, 3},
		{"empty payload", nil, false, 0},
		{"blank lines are skipped", []byte("\n\nvpn-gw1\n\n"), false, 1},
		{"at the element bound", bytes.Repeat([]byte("a\n"), maxIPsecSANames), false, maxIPsecSANames},
		// THE DEFECT.
		{"past the element bound", bytes.Repeat([]byte("a\n"), maxIPsecSANames+1), true, 0},
		{"at the name-length bound",
			append(bytes.Repeat([]byte("n"), maxIPsecSANameLen), '\n'), false, 1},
		{"past the name-length bound",
			append(bytes.Repeat([]byte("n"), maxIPsecSANameLen+1), '\n'), true, 0},
		// A single enormous "name" must not stand in for the element bound.
		{"one huge name", bytes.Repeat([]byte("x"), 1<<20), true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, malformed := decodeIPsecSAPayload(tc.payload)
			if malformed != tc.malformed {
				t.Fatalf("malformed = %v, want %v", malformed, tc.malformed)
			}
			if len(got) != tc.wantNames {
				t.Errorf("decoded %d names, want %d", len(got), tc.wantNames)
			}
			if tc.malformed && got != nil {
				t.Errorf("a malformed frame returned %d names; a full set REPLACES, "+
					"so a truncated one makes the standby reinitiate a SUBSET on "+
					"takeover and look like it succeeded", len(got))
			}
		})
	}
}

// The RETAINED size must be proportional to the NAMES, not to the frame.
//
// strings.Split hands back substrings of one backing array, so a single retained
// one-byte name pinned the whole 16 MiB payload — 128 MB retained in the
// measured case, iterated per name by reinitiateIPsecSAs ON TAKEOVER.
//
// Measured rather than asserted by inspection: an aliasing decoder passes every
// count-based check, and aliasing is invisible to them by construction.
func TestIPsecSANamesDoNotRetainTheFrame9061(t *testing.T) {
	const frameLen = 8 << 20 // 8 MiB, well under the 16 MiB ceiling
	payload := make([]byte, 0, frameLen)
	for len(payload) < frameLen-2 {
		payload = append(payload, 'a', '\n')
	}

	names, malformed := decodeIPsecSAPayload(payload)
	if !malformed {
		t.Fatalf("an %d-name frame must be refused by the element bound", len(names))
	}

	// And the accepted case must not alias either. A set at the bound is the
	// largest legitimate one, so it is where aliasing would cost the most.
	small := bytes.Repeat([]byte("a\n"), maxIPsecSANames)
	got, malformed := decodeIPsecSAPayload(small)
	if malformed || len(got) != maxIPsecSANames {
		t.Fatalf("the at-bound set must decode: malformed=%v n=%d", malformed, len(got))
	}
	// Mutate the frame after decoding. An aliased name would change with it.
	for i := range small {
		small[i] = 'Z'
	}
	runtime.GC()
	for i, n := range got {
		if n != "a" {
			t.Fatalf("name %d became %q after the frame was overwritten: the decoded "+
				"names ALIAS the payload, so retaining any one of them pins the "+
				"whole frame", i, n)
		}
	}
}

// The refusal must reach the receiver: a malformed frame must leave the
// previously-installed set intact, because a full set REPLACES.
func TestMalformedIPsecSASetIsRefusedNotInstalled9061(t *testing.T) {
	good, malformed := decodeIPsecSAPayload([]byte("vpn-gw1\nvpn-gw2"))
	if malformed || len(good) != 2 {
		t.Fatalf("fixture: good set did not decode (malformed=%v n=%d)", malformed, len(good))
	}
	bad, malformed := decodeIPsecSAPayload([]byte(strings.Repeat("a\n", maxIPsecSANames+1)))
	if !malformed {
		t.Fatal("the oversized set was accepted")
	}
	if bad != nil {
		t.Errorf("the oversized set yielded %d names; the caller must have nothing "+
			"to install", len(bad))
	}
}

// THE WIRING. The three cells above bind the DECODER; a mutation making the
// receiver install a malformed set anyway killed zero of them, which is the
// whole defect restated one layer up — the bound only matters if the caller
// acts on it.
//
// This drives handleMessage, the arm the peer connection actually reaches, and
// asserts the held set is UNCHANGED. A full set REPLACES, so the recoverable
// outcome is keeping what we have until a good frame arrives; installing a
// truncated one makes the standby reinitiate a SUBSET on takeover and look like
// it succeeded.
func TestMalformedIPsecSAFrameDoesNotReplaceTheHeldSet9061(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var applied [][]string
	ss.OnIPsecSAReceived = func(names []string) {
		applied = append(applied, append([]string(nil), names...))
	}
	const epoch = uint64(2000)
	recv := func(seq uint64, payload []byte) {
		ss.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(payload, epoch, seq))
	}

	// REFERENCE ARM: a good set installs. Without it the assertion below is
	// satisfied by a receiver that installs nothing at all.
	recv(1, encodeIPsecSAPayload([]string{"vpn-a", "vpn-b"}))
	if got := ss.PeerIPsecSAs(); len(got) != 2 {
		t.Fatalf("the good set must install: got %v", got)
	}
	if len(applied) != 1 {
		t.Fatalf("OnIPsecSAReceived fired %d times for one good set", len(applied))
	}

	// An oversized set arrives with a NEWER seq, so nothing but the malformed
	// check can stop it.
	huge := make([]byte, 0, 2*(maxIPsecSANames+1))
	for i := 0; i <= maxIPsecSANames; i++ {
		huge = append(huge, 'a', '\n')
	}
	recv(2, huge)

	if got := ss.PeerIPsecSAs(); len(got) != 2 || got[0] != "vpn-a" || got[1] != "vpn-b" {
		t.Errorf("a malformed full set replaced the held set: %v. The standby now "+
			"reinitiates that set on takeover", got)
	}
	if len(applied) != 1 {
		t.Errorf("OnIPsecSAReceived fired %d times; the malformed frame reached the "+
			"consumer", len(applied))
	}
}
