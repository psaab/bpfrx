package upgrade

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// ImageVersions are the compile-time protocol/version constants a baked image's
// xpfd embeds, used by the #1930 INC-3 LANE-2 mixed-base image-replace gate to
// decide — BEFORE swapping the second HA node — whether the new image can run
// alongside the still-running peer's OLD image without dropping sessions.
//
// Two sources produce the same key=value set:
//   - `xpfd protocol-versions` run against the staged binary unpacked from the
//     new image (canonical; the binary IS the protocol).
//   - the bake `.manifest` (the bake recorded the same fields), for a pure file
//     read where running the staged binary is inconvenient (cross-arch).
type ImageVersions struct {
	XPFVersion string
	// HAProtocol is the HA/session-transfer protocol version this image SPEAKS.
	HAProtocol uint16
	// HAProtocolMinCompat is the OLDEST HA protocol version this image can still
	// interoperate with (back-compat floor). An image speaking N that can still
	// talk to N-1 sets MinCompat=N-1.
	HAProtocolMinCompat uint16
	// SessionSyncProtocol is the userspace session-sync frame/control protocol.
	SessionSyncProtocol int
	// ConfigDBEnvelope is the config-DB envelope grammar version.
	ConfigDBEnvelope int
	// ConfigDBMinReader is the minimum envelope-format version a reader must
	// support to load a DB this image writes.
	ConfigDBMinReader int

	// present tracks which fields were actually parsed (missing keys are a
	// fail-closed signal for the gate, not silent zero values).
	present map[string]bool
}

// parseImageVersions reads the `key=value` (protocol-versions) or `key: value`
// (manifest) lines into an ImageVersions. Unknown keys are ignored; the gate
// checks Has() for the fields it requires and fails closed if any is absent.
func parseImageVersions(text string) (*ImageVersions, error) {
	iv := &ImageVersions{present: map[string]bool{}}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var k, v string
		if i := strings.IndexAny(line, "=:"); i >= 0 {
			k = strings.TrimSpace(line[:i])
			v = strings.TrimSpace(line[i+1:])
		} else {
			continue
		}
		// The manifest re-keys with underscores; accept both separators.
		k = strings.ReplaceAll(k, "_", "-")
		switch k {
		case "xpf-version":
			iv.XPFVersion = v
			iv.present[k] = true
		case "ha-protocol-version":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				iv.HAProtocol = uint16(n)
				iv.present[k] = true
			}
		case "ha-protocol-min-compat":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				iv.HAProtocolMinCompat = uint16(n)
				iv.present[k] = true
			}
		case "session-sync-protocol-version":
			if n, err := strconv.Atoi(v); err == nil {
				iv.SessionSyncProtocol = n
				iv.present[k] = true
			}
		case "configdb-envelope-version":
			if n, err := strconv.Atoi(v); err == nil {
				iv.ConfigDBEnvelope = n
				iv.present[k] = true
			}
		case "configdb-min-reader-version":
			if n, err := strconv.Atoi(v); err == nil {
				iv.ConfigDBMinReader = n
				iv.present[k] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan protocol versions: %w", err)
	}
	return iv, nil
}

// has reports whether the named key was parsed.
func (iv *ImageVersions) has(key string) bool { return iv.present[key] }

// requiredKeys are the fields the mixed-base gate must see to make a decision.
// Config-DB versions are informational for the HA gate (the replaced node
// re-bootstraps its DB from text), so they are NOT required here.
var requiredKeys = []string{
	"ha-protocol-version",
	"ha-protocol-min-compat",
	"session-sync-protocol-version",
}

// MixedBaseVerdict is the outcome of the gate.
type MixedBaseVerdict struct {
	// SessionsSurvive is true only when the new image's HA + session-sync
	// protocols are back-compatible with the still-running peer, so the
	// post-swap mixed-base cluster keeps syncing sessions across the failover.
	SessionsSurvive bool
	// Reason is a human-readable explanation (always set).
	Reason string
}

// GateMixedBaseSwap decides whether a LANE-2 image-replace of the SECOND node
// (to `newImg`) can preserve sessions while the FIRST node still runs the old
// image advertising `peerHAProtocol` / `peerSessionSync`. It is fail-closed: any
// missing field, any protocol the peer cannot speak, returns SessionsSurvive
// =false (the operator must replace both nodes and accept a connection drop).
//
// Back-compat rule: sessions survive iff the peer's live HA protocol lies within
// the new image's [MinCompat, HAProtocol] window AND the session-sync protocol
// matches exactly (the userspace frame format is not versioned for skew — a
// mismatch means the replaced node cannot decode the peer's synced sessions).
func GateMixedBaseSwap(newImg *ImageVersions, peerHAProtocol uint16, peerSessionSync int) MixedBaseVerdict {
	if newImg == nil {
		return MixedBaseVerdict{false, "no image version info — fail closed (replace both nodes, sessions drop)"}
	}
	for _, k := range requiredKeys {
		if !newImg.has(k) {
			return MixedBaseVerdict{false, fmt.Sprintf(
				"new image manifest missing %q — fail closed (replace both nodes, sessions drop)", k)}
		}
	}
	if peerHAProtocol == 0 {
		return MixedBaseVerdict{false,
			"peer HA protocol unknown (peer not advertising) — fail closed"}
	}
	// The peer must be able to talk to the new image: the peer's version must be
	// >= the new image's back-compat floor AND <= what the new image speaks (a
	// peer NEWER than the new image is a downgrade we do not gate as safe).
	if peerHAProtocol < newImg.HAProtocolMinCompat || peerHAProtocol > newImg.HAProtocol {
		return MixedBaseVerdict{false, fmt.Sprintf(
			"peer HA protocol %d outside new image window [%d,%d] — not back-compatible; "+
				"replace BOTH nodes (sessions drop)",
			peerHAProtocol, newImg.HAProtocolMinCompat, newImg.HAProtocol)}
	}
	// Session-sync frame format is exact-match (unversioned for skew).
	if peerSessionSync != 0 && peerSessionSync != newImg.SessionSyncProtocol {
		return MixedBaseVerdict{false, fmt.Sprintf(
			"session-sync protocol differs (peer %d, new image %d) — synced sessions "+
				"would not decode across the mixed cluster; replace BOTH nodes (sessions drop)",
			peerSessionSync, newImg.SessionSyncProtocol)}
	}
	return MixedBaseVerdict{true, fmt.Sprintf(
		"new image HA protocol %d (compat floor %d) accepts peer %d; session-sync %d matches — "+
			"mixed-base swap preserves sessions",
		newImg.HAProtocol, newImg.HAProtocolMinCompat, peerHAProtocol, newImg.SessionSyncProtocol)}
}
