package cli

import (
	"strings"
	"testing"
)

// TestBuildMonitorTrafficArgvNeutralizesOptionInjection is the #4524
// regression guard. `monitor traffic ... matching <filter>` greedily
// absorbs every token after `matching` up to the next keyword, so an
// operator (or a control-but-not-super-user login class) could type
// `matching -w /tmp/x` or `matching -z /tmp/evil` and — absent a "--"
// end-of-options separator — have tcpdump parse `-w`/`-z` as OPTIONS
// under glibc getopt argv permutation: `-w` writes an arbitrary root-owned
// file, `-z <cmd>` runs a post-rotate command. That escalates a
// capture-only privilege to root file-write / command-exec.
//
// The fix inserts a "--" separator before the filter tokens (mirroring the
// diagcmd ping/traceroute #2084 treatment). After "--", getopt stops
// scanning for options, so every injected `-w`/`-z` token lands as a pcap
// filter OPERAND, not a tcpdump option. This test goes RED on revert: with
// the separator removed the `-w`/`-z` token precedes no "--" (or there is
// no "--" at all), i.e. it is a live option.
func TestBuildMonitorTrafficArgvNeutralizesOptionInjection(t *testing.T) {
	tests := []struct {
		name    string
		matcher []string // tokens after `matching`
		inject  string   // the smuggled option token that must be neutralized
	}{
		{
			name:    "-w file write",
			matcher: []string{"-w", "/tmp/x"},
			inject:  "-w",
		},
		{
			name:    "-z post-rotate command exec",
			matcher: []string{"-z", "/tmp/evil.sh"},
			inject:  "-z",
		},
		{
			name:    "-r read-file option",
			matcher: []string{"-r", "/etc/shadow"},
			inject:  "-r",
		},
		{
			name:    "long postrotate-command option",
			matcher: []string{"--postrotate-command", "/tmp/evil.sh"},
			inject:  "--postrotate-command",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"interface", "ge-0-0-0", "matching"}, tt.matcher...)
			iface, filter, count := parseMonitorTrafficArgs(args)
			argv := buildMonitorTrafficArgv(iface, filter, count)

			sep := indexOf(argv, "--")
			if sep < 0 {
				t.Fatalf("argv %v: missing \"--\" end-of-options separator — injected %q reaches tcpdump as an OPTION", argv, tt.inject)
			}
			inj := indexOf(argv, tt.inject)
			if inj < 0 {
				t.Fatalf("argv %v: injected token %q missing entirely", argv, tt.inject)
			}
			if inj < sep {
				t.Fatalf("argv %v: injected token %q at %d precedes the \"--\" separator at %d — it is parsed as a tcpdump OPTION, not a filter operand", argv, tt.inject, inj, sep)
			}
		})
	}
}

// TestValidateMonitorFilterRejectsOptionTokens is the defense-in-depth
// layer (#4524): an option-looking filter token is rejected outright with
// a clear error, rather than reaching tcpdump (where it is already
// neutralized by "--") and producing an opaque libpcap syntax error.
func TestValidateMonitorFilterRejectsOptionTokens(t *testing.T) {
	reject := []string{
		"-w /tmp/x",
		"-z /tmp/evil.sh",
		"-r /etc/shadow",
		"--postrotate-command /tmp/evil.sh",
		"host 10.0.0.1 -w /tmp/x", // option smuggled after a valid primitive
	}
	for _, f := range reject {
		if err := validateMonitorFilter(f); err == nil {
			t.Errorf("validateMonitorFilter(%q) = nil, want error (option-looking token not rejected)", f)
		}
	}
}

// TestValidateMonitorFilterAcceptsLegitimateFilters ensures the hardening
// does not break real pcap filters. These must all pass validation AND
// survive the argv build as a contiguous filter tail after "--".
func TestValidateMonitorFilterAcceptsLegitimateFilters(t *testing.T) {
	accept := []string{
		"host 10.0.0.1 and port 22",
		"tcp port 80",
		"not arp",
		"udp and not port 53",
		"icmp",
		"host 2001:db8::1",
		"", // no filter at all
	}
	for _, f := range accept {
		if err := validateMonitorFilter(f); err != nil {
			t.Errorf("validateMonitorFilter(%q) = %v, want nil (legitimate filter rejected)", f, err)
		}
	}
}

// TestBuildMonitorTrafficArgvLegitimateFilterAfterSeparator confirms a
// legitimate multi-token filter is passed intact as the pcap expression
// after the "--" separator (`host 10.0.0.1 and port 22`).
func TestBuildMonitorTrafficArgvLegitimateFilterAfterSeparator(t *testing.T) {
	args := []string{"interface", "ge-0-0-0", "matching", "host", "10.0.0.1", "and", "port", "22"}
	iface, filter, count := parseMonitorTrafficArgs(args)
	if err := validateMonitorFilter(filter); err != nil {
		t.Fatalf("legitimate filter %q rejected: %v", filter, err)
	}
	argv := buildMonitorTrafficArgv(iface, filter, count)

	sep := indexOf(argv, "--")
	if sep < 0 {
		t.Fatalf("argv %v: missing \"--\" separator", argv)
	}
	if got := strings.Join(argv[sep+1:], " "); got != "host 10.0.0.1 and port 22" {
		t.Fatalf("filter tail = %q, want %q", got, "host 10.0.0.1 and port 22")
	}
}
