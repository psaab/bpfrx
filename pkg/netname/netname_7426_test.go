package netname

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #7426: one derivation, not two wrong ones.
//
// `deriveKernelName` (pkg/daemon) and `getOriginalKernelName` (pkg/dataplane)
// were both live and wrong in OPPOSITE directions on the same field:
//
//	                   daemon              dataplane
//	altname order      NamePolicy          first match wins
//	PCI `f0`           never emitted       #4795's multifunction fix
//
// An agreement test could only have pinned one to the other, and on the `f0`
// field neither was right — so agreement would have frozen a bug. That is the
// rule this package encodes: BIND an agreement when both copies can be right;
// SINGLE-SOURCE when they are wrong in opposite directions.

// TestFromAltNamesFollowsNamePolicyOrder is the ordering half. It uses the real
// measured altname set from the ARI development host, where all three are
// present at once and udev reports ID_NET_NAME_ONBOARD=eno5np0.
func TestFromAltNamesFollowsNamePolicyOrder(t *testing.T) {
	// Kernel listing order deliberately does NOT match policy order, so a
	// first-match-wins implementation returns the wrong one.
	measured := []string{"enx3cecef6aa8bc", "enp183s0f0np0", "eno5np0"}
	if got := FromAltNames(measured); got != "eno5np0" {
		t.Fatalf("FromAltNames(%v) = %q, want %q — onboard outranks path, and "+
			"first-match-wins would return whichever the kernel listed first",
			measured, got, "eno5np0")
	}

	for _, tc := range []struct {
		name string
		alts []string
		want string
	}{
		{"onboard beats slot and path", []string{"enp1s0", "ens3", "eno1"}, "eno1"},
		{"slot beats path", []string{"enp1s0", "ens3"}, "ens3"},
		{"path when it is the only predictable name", []string{"enp1s0"}, "enp1s0"},
		// eth is the pre-predictable kernel default, not a policy output: it
		// must never outrank a real predictable name.
		{"eth is last resort only", []string{"eth0", "enp1s0"}, "enp1s0"},
		{"eth accepted when alone", []string{"eth0"}, "eth0"},
		// A MAC-based name is deliberately NOT accepted.
		{"mac name is not a predictable name", []string{"enx3cecef6aa8bc"}, ""},
		{"no candidates", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromAltNames(tc.alts); got != tc.want {
				t.Errorf("FromAltNames(%v) = %q, want %q", tc.alts, got, tc.want)
			}
		})
	}
}

// TestFromPCIAddrCarriesMultifunctionF0 is the `f0` half — the field the two
// copies disagreed on, each in the direction the other got right.
func TestFromPCIAddrCarriesMultifunctionF0(t *testing.T) {
	for _, tc := range []struct {
		name          string
		addr          string
		multifunction bool
		want          string
	}{
		// The daemon copy's bug: `fn > 0` never emits f0, so a multifunction
		// NIC's first port derived enp183s0 where systemd says enp183s0f0.
		{"multifunction function 0 carries f0", "0000:b7:00.0", true, "enp183s0f0"},
		// The bug #4795 fixed in the dataplane copy: unconditional f0.
		{"single-function function 0 omits the suffix", "0000:09:00.0", false, "enp9s0"},
		{"nonzero function always carries a suffix", "0000:03:00.1", false, "enp3s0f1"},
		{"non-zero slot", "0000:b7:02.0", false, "enp183s2"},
		{"non-zero domain", "0001:03:00.1", false, "enP1p3s0f1"},
		// #9458: this row is a CHANGE DETECTOR, not a correctness claim, and
		// the comment that stood here made it read as the latter. ".a" is a
		// spelling sysfs CANNOT produce — PCI_FUNC(devfn) is devfn & 0x07, so
		// the field is always 0-7 (see the netname.go rationale and
		// TestPCIFunctionFieldIsThreeBits). systemd therefore assigns no name
		// for this input at all, so "enp183s0f10" is not the right answer in
		// any spec sense; it is merely the answer today's base-16 parse gives.
		// Keep the row so a change to the parse base is DELIBERATE rather than
		// silent — but do not read a red here as a broken guarantee, and do
		// not cite it as evidence that the base-16 parse protects anything.
		{"function spelling sysfs cannot emit — change detector only", "0000:b7:00.a", false, "enp183s0f10"},
		{"malformed", "not-a-pci-address", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromPCIAddr(tc.addr, tc.multifunction); got != tc.want {
				t.Errorf("FromPCIAddr(%q, %v) = %q, want %q",
					tc.addr, tc.multifunction, got, tc.want)
			}
		})
	}
}

func TestFromUdevPropertiesFollowsNamePolicyOrder(t *testing.T) {
	// The real property set measured on the ARI host.
	props := map[string]string{
		"ID_NET_NAME_MAC":     "enx3cecef6aa8bc",
		"ID_NET_NAME_ONBOARD": "eno5np0",
		"ID_NET_NAME_PATH":    "enp183s0f0np0",
	}
	if got := FromUdevProperties(props); got != "eno5np0" {
		t.Errorf("FromUdevProperties = %q, want eno5np0 (onboard outranks path)", got)
	}
	if got := FromUdevProperties(map[string]string{"ID_NET_NAME_PATH": "enp1s0"}); got != "enp1s0" {
		t.Errorf("path-only = %q, want enp1s0", got)
	}
	// MAC is not in the order at all.
	if got := FromUdevProperties(map[string]string{"ID_NET_NAME_MAC": "enx00"}); got != "" {
		t.Errorf("MAC-only = %q, want \"\"", got)
	}
	if got := FromUdevProperties(nil); got != "" {
		t.Errorf("nil = %q, want \"\"", got)
	}
}

// TestResolvePrefersAltNamesOverPCIDerivation pins the chain order: the PCI
// derivation is best-effort and blind to the port suffix, so it must never
// outrank a name the kernel actually holds.
func TestResolvePrefersAltNamesOverPCIDerivation(t *testing.T) {
	got := Resolve([]string{"enp183s0f0np0"}, "0000:b7:00.0")
	if got != "enp183s0f0np0" {
		t.Fatalf("Resolve = %q, want the altname enp183s0f0np0 — the PCI "+
			"derivation cannot reproduce the np0 port suffix, so preferring it "+
			"would produce a name that matches no NIC", got)
	}
	if got := Resolve(nil, ""); got != "" {
		t.Errorf("Resolve with no sources = %q, want \"\"", got)
	}
}

// TestDerivationMatchesRealHardware is the leg only an ARI host can run.
//
// It scans the live PCI topology for a MULTIFUNCTION network device and asserts
// the derivation agrees with udev's own ID_NET_NAME_PATH, which is the ground
// truth. This is the case that was broken: on the development host,
// 0000:b7:00.0 has PCI_HEADER_TYPE 0x80 (multifunction) and a real
// ID_NET_NAME_PATH of enp183s0f0np0, while the daemon's `fn > 0` derivation
// produced enp183s0.
//
// It SKIPS rather than fails on a host with no such device — a slot-0 / VF-only
// box genuinely cannot observe this, which is exactly why the defect survived
// review.
func TestDerivationMatchesRealHardware(t *testing.T) {
	entries, err := os.ReadDir("/sys/bus/pci/devices")
	if err != nil {
		t.Skip("no /sys/bus/pci/devices on this host")
	}
	checked := 0
	for _, e := range entries {
		addr := e.Name()
		netDir := filepath.Join("/sys/bus/pci/devices", addr, "net")
		ifaces, err := os.ReadDir(netDir)
		if err != nil || len(ifaces) == 0 {
			continue
		}
		if !Multifunction(addr) {
			continue
		}
		ifName := ifaces[0].Name()
		// udev's own answer, read from the kernel-exported uevent-adjacent
		// property file when present. Fall back to skipping this device.
		want := udevNamePath(t, ifName)
		if want == "" {
			continue
		}
		got := FromPCIAddr(addr, true)
		// The derivation is blind to the port suffix (np0), so it is a PREFIX
		// of udev's answer rather than equal to it. Asserting equality here
		// would fail for a reason the derivation openly documents.
		if !strings.HasPrefix(want, got) {
			t.Errorf("%s (%s): FromPCIAddr = %q, but udev's ID_NET_NAME_PATH is "+
				"%q — the derivation is not even a prefix of the real name",
				addr, ifName, got, want)
		}
		if !strings.Contains(got, "f") {
			t.Errorf("%s (%s): multifunction device derived %q with NO f<n> "+
				"suffix — this is the under-emission bug (udev says %q)",
				addr, ifName, got, want)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no multifunction PCI network device on this host — this leg " +
			"needs ARI/multifunction hardware; a slot-0 or VF-only box cannot " +
			"observe the defect")
	}
	t.Logf("verified the derivation against udev on %d multifunction NIC(s)", checked)
}

// udevNamePath returns ID_NET_NAME_PATH for ifName from the kernel's exported
// uevent, or "" when unavailable. It does not shell out.
func udevNamePath(t *testing.T, ifName string) string {
	t.Helper()
	for _, path := range []string{
		filepath.Join("/run/udev/data"),
	} {
		if _, err := os.Stat(path); err != nil {
			return ""
		}
	}
	idx, err := os.ReadFile(filepath.Join("/sys/class/net", ifName, "ifindex"))
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join("/run/udev/data", "n"+strings.TrimSpace(string(idx))))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "E:ID_NET_NAME_PATH="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
