package upgrade

import "testing"

const sampleProtoVersions = `xpf-version=1.2.3
ha-protocol-version=2
ha-protocol-min-compat=1
session-sync-protocol-version=3
configdb-envelope-version=1
configdb-min-reader-version=1
`

const sampleManifest = `version: 1.2.3
git_commit: abcdef
base_release: 26.04
ha_protocol_version: 2
ha_protocol_min_compat: 1
session_sync_protocol_version: 3
configdb_envelope_version: 1
configdb_min_reader_version: 1
`

func TestParseImageVersions_BothSeparators(t *testing.T) {
	for name, txt := range map[string]string{"equals": sampleProtoVersions, "colon": sampleManifest} {
		iv, err := parseImageVersions(txt)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if iv.HAProtocol != 2 || iv.HAProtocolMinCompat != 1 || iv.SessionSyncProtocol != 3 {
			t.Fatalf("%s: parsed %+v", name, iv)
		}
		for _, k := range requiredKeys {
			if !iv.has(k) {
				t.Fatalf("%s: missing required key %q", name, k)
			}
		}
	}
}

func TestGateMixedBase_PeerInWindow_Survives(t *testing.T) {
	iv, _ := parseImageVersions(sampleProtoVersions) // speaks 2, floor 1, sync 3
	v := GateMixedBaseSwap(iv, 1, 3)                 // peer speaks 1 (in [1,2]), sync 3
	if !v.SessionsSurvive {
		t.Fatalf("peer HA 1 in window [1,2] + sync match must survive: %s", v.Reason)
	}
	// Same-version peer also survives.
	if v2 := GateMixedBaseSwap(iv, 2, 3); !v2.SessionsSurvive {
		t.Fatalf("same-version peer must survive: %s", v2.Reason)
	}
}

func TestGateMixedBase_PeerBelowFloor_DropsClosed(t *testing.T) {
	iv, _ := parseImageVersions(sampleProtoVersions) // floor 1
	if v := GateMixedBaseSwap(iv, 0, 3); v.SessionsSurvive {
		t.Fatal("unknown peer HA (0) must fail closed")
	}
	// Hypothetical: new image floor raised to 2, peer still on 1 -> drop.
	iv.HAProtocolMinCompat = 2
	if v := GateMixedBaseSwap(iv, 1, 3); v.SessionsSurvive {
		t.Fatalf("peer below the new image's compat floor must drop: %s", v.Reason)
	}
}

func TestGateMixedBase_PeerNewerThanImage_DropsClosed(t *testing.T) {
	iv, _ := parseImageVersions(sampleProtoVersions) // speaks 2
	if v := GateMixedBaseSwap(iv, 3, 3); v.SessionsSurvive {
		t.Fatalf("peer newer than the new image must drop (downgrade not gated safe): %s", v.Reason)
	}
}

func TestGateMixedBase_SessionSyncMismatch_DropsClosed(t *testing.T) {
	iv, _ := parseImageVersions(sampleProtoVersions) // sync 3
	if v := GateMixedBaseSwap(iv, 1, 4); v.SessionsSurvive {
		t.Fatalf("session-sync mismatch must drop: %s", v.Reason)
	}
}

func TestGateMixedBase_UnknownPeerSessionSync_DropsClosed(t *testing.T) {
	iv, _ := parseImageVersions(sampleProtoVersions) // sync 3, HA window [1,2]
	// peer HA is fine (1) but peer session-sync is UNKNOWN (0) -> fail closed.
	if v := GateMixedBaseSwap(iv, 1, 0); v.SessionsSurvive {
		t.Fatalf("unknown peer session-sync must fail closed: %s", v.Reason)
	}
}

// TestParseImageVersions_NegativeSessionSync_FailsClosed locks the r4 Codex
// HIGH Go/Python parity fix: a negative (or out-of-uint16-range)
// session-sync-protocol-version must be REJECTED at parse (not stored), so the
// required key is absent and the gate fails closed — matching the Python
// _u16() rejection. A signed strconv.Atoi would have stored -1 and let a peer
// also reporting -1 falsely pass the exact-match.
func TestParseImageVersions_NegativeSessionSync_FailsClosed(t *testing.T) {
	const txt = `ha-protocol-version=2
ha-protocol-min-compat=1
session-sync-protocol-version=-1
`
	iv, err := parseImageVersions(txt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if iv.has("session-sync-protocol-version") {
		t.Fatal("negative session-sync must be rejected at parse (key absent)")
	}
	// Peer also reporting -1 must NOT pass: the gate fails closed on the absent
	// required key regardless of the (rejected) peer value.
	if v := GateMixedBaseSwap(iv, 1, -1); v.SessionsSurvive {
		t.Fatalf("negative session-sync must fail closed: %s", v.Reason)
	}
	// Out-of-uint16-range is likewise rejected.
	iv2, _ := parseImageVersions("ha-protocol-version=2\nha-protocol-min-compat=1\nsession-sync-protocol-version=70000\n")
	if iv2.has("session-sync-protocol-version") {
		t.Fatal("out-of-uint16-range session-sync must be rejected at parse")
	}
}

func TestGateMixedBase_MissingFields_DropsClosed(t *testing.T) {
	iv, _ := parseImageVersions("xpf-version=1.2.3\n") // no protocol fields
	if v := GateMixedBaseSwap(iv, 1, 3); v.SessionsSurvive {
		t.Fatalf("missing required protocol fields must fail closed: %s", v.Reason)
	}
	if v := GateMixedBaseSwap(nil, 1, 3); v.SessionsSurvive {
		t.Fatal("nil image versions must fail closed")
	}
}
