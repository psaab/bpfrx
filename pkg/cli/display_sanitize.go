package cli

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// sanitizeTerminalText makes a string safe to print to an operator's terminal
// (#8321 cohort item 8).
//
// Several `show` commands render names and values this daemon does not
// author — a core-dump FILENAME from `/var/crash` or
// `/var/lib/systemd/coredump`, a thermal zone's `type`, a power supply's
// directory name and `status`. Printed raw, a control character in one of those
// is interpreted by the terminal, not displayed: an ANSI escape can move the
// cursor, clear the screen, recolour text, or overwrite lines the CLI already
// wrote — so an attacker who can influence one of those names can forge what
// the operator believes the firewall reported.
//
// The core-dump path is the reachable one. systemd-coredump derives the
// filename from the crashing process's `comm`, so it does not take root to
// influence — only the ability to execute a binary with a chosen name and crash
// it. The sysfs names need root to write and are hardened alongside because the
// shape is identical and the cost is a function call.
//
// `unicode.IsControl` covers C0 (0x00-0x1f), DEL (0x7f) and C1 (0x80-0x9f),
// which is exactly the escape-introducer set. Control runes become spaces
// rather than being deleted, so a name is not silently shortened into a
// different plausible name. Same shape and same replacement as
// `lldp.sanitizeTLVString`, which does this for wire-sourced TLV strings.
//
// The fast path returns the input unchanged for clean text, so ordinary output
// is byte-identical — a cell asserts that, because a sanitizer that quietly
// rewrites normal names is a display bug of its own.
// coreDumpDirs and thermalZoneGlob are the filesystem locations the two
// renderers hardened below read from. They are package vars ONLY so a test can
// point them at a temp tree and drive the REAL renderer: a cell that called
// sanitizeTerminalText or formatMilliCelsius directly would pass against a call
// site that had stopped using them, which is precisely the defect being fixed
// (a correct helper that one caller does not reach).
var (
	coreDumpDirs    = []string{"/var/crash", "/var/lib/systemd/coredump"}
	thermalZoneGlob = "/sys/class/thermal/thermal_zone*/temp"
)

func sanitizeTerminalText(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) < 0 && utf8.ValidString(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// formatMilliCelsius renders a sysfs thermal reading (millidegrees Celsius) as
// a one-decimal temperature (#8321 cohort item 7).
//
// The previous inline form was `fmt.Sprintf("%d.%d", m/1000, (m%1000)/100)`,
// which is correct only for non-negative readings. Go's integer division
// truncates toward zero and `%` keeps the sign of the dividend, so a sub-zero
// reading printed its fractional part with a second minus sign: -12500
// rendered as "-12.-5" and -500 as "0.-5" — the latter losing the sign
// entirely, so half a degree below zero displayed as a positive-looking
// "0.-5 C".
//
// Sub-zero readings are not exotic: thermal zones report ambient and inlet
// sensors, and a cold-start appliance in an unheated cabinet reads below zero
// routinely.
//
// The sign is taken from the whole part where there is one and applied
// explicitly only when the whole part is zero, which is the case that would
// otherwise lose it. The fractional part is negated AFTER the modulo, where it
// is bounded by (-1000, 0], so this cannot overflow even for math.MinInt64 —
// negating the input itself would.
func formatMilliCelsius(millideg int64) string {
	whole := millideg / 1000
	frac := millideg % 1000
	if frac < 0 {
		frac = -frac
	}
	sign := ""
	if millideg < 0 && whole == 0 {
		sign = "-"
	}
	return fmt.Sprintf("%s%d.%d", sign, whole, frac/100)
}
