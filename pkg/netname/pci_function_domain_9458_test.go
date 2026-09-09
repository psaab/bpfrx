package netname

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// #9458: the PCI FUNCTION FIELD IS THREE BITS, and that is a structural bound
// rather than a sampling result.
//
// Three places on master carried the opposite claim — that an ARI device "can
// carry functions above 9 (up to 255), which a base-10 parse rejects outright"
// — and one of them was a TEST ROW pinning a derivation for the spelling
// "0000:b7:00.a". That made a false rationale load-bearing: anyone changing the
// parse base got a red and read it as a guard doing its job.
//
// The bound: Linux names a PCI device with
//
//	dev_set_name(&dev->dev, "%04x:%02x:%02x.%d", pci_domain_nr(bus),
//	             bus->number, PCI_SLOT(devfn), PCI_FUNC(devfn));
//
// and PCI_FUNC(devfn) is devfn & 0x07 — bits 7:3 are the slot. ARI does not
// widen the field; it reinterprets slot and function together, which systemd
// reconstructs as `func += slot << 3` when ari_enabled is set (#6677, fixed by
// reading the name from the kernel — PR #7420).
//
// So base-16 and base-10 parses of that field agree on every address the kernel
// can produce, and neither is more correct. This file is the guard that keeps
// that statement falsifiable: if a kernel ever presents a function field above
// 7, the parse base becomes observable and the ARI reconstruction question has
// to be reopened. It reds then, and it reds nowhere else.

// maxFunctionField is the predicate, extracted so it can be DRIVEN with inputs
// the host does not have. A guard that can only be fed real data cannot be
// shown to have discriminating power.
//
// It returns the largest function field across names and the name carrying it.
// A name whose function field is not a plain decimal integer in 0-255 is
// reported as an error naming it — the kernel emits decimal, so anything else
// is itself a violation of the bound this file asserts.
func maxFunctionField(names []string) (uint64, string, error) {
	var max uint64
	var at string
	seen := 0
	for _, n := range names {
		dot := strings.LastIndex(n, ".")
		if dot < 0 || dot == len(n)-1 {
			return 0, "", fmt.Errorf("PCI name %q has no function field", n)
		}
		field := n[dot+1:]
		fn, err := strconv.ParseUint(field, 10, 16)
		if err != nil {
			return 0, "", fmt.Errorf("PCI name %q: function field %q is not decimal: %w", n, field, err)
		}
		seen++
		if fn >= max {
			max, at = fn, n
		}
	}
	if seen == 0 {
		return 0, "", fmt.Errorf("no PCI names supplied — nothing was measured")
	}
	return max, at, nil
}

// TestMaxFunctionFieldPredicate exercises the predicate on synthetic input, so
// the sysfs leg below is known to be capable of failing.
func TestMaxFunctionFieldPredicate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      []string
		want    uint64
		wantErr bool
	}{
		{"three-bit domain", []string{"0000:65:00.0", "0000:b7:02.5", "0000:03:00.7"}, 7, false},
		{"a value the bound forbids is REPORTED, not clamped", []string{"0000:03:00.0", "0000:65:00.8"}, 8, false},
		{"decimal 10 is reported as 10", []string{"0000:65:00.10"}, 10, false},
		// The hex spelling the old rationale assumed sysfs emits. It does not,
		// and the predicate must not silently accept it as some other number:
		// accepting ".a" as 10 is precisely how the false claim was reached.
		{"hex spelling is an error, not the value 10", []string{"0000:b7:00.a"}, 0, true},
		{"no function field", []string{"0000:b7:00"}, 0, true},
		// A run that collected nothing must not read as a clean bound.
		{"empty input is an error, not a pass", nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, at, err := maxFunctionField(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("maxFunctionField(%v) = %d (%s), want an error", tc.in, got, at)
				}
				return
			}
			if err != nil {
				t.Fatalf("maxFunctionField(%v) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("maxFunctionField(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestPCIFunctionFieldIsThreeBits measures the live PCI topology.
//
// It publishes its denominator: a "clean bound" over 3 devices and over 175 are
// the same sentence otherwise, and a host with no PCI bus must SKIP rather than
// report a bound it never measured.
func TestPCIFunctionFieldIsThreeBits(t *testing.T) {
	entries, err := os.ReadDir("/sys/bus/pci/devices")
	if err != nil {
		t.Skip("no /sys/bus/pci/devices on this host — the bound cannot be measured here")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		t.Skip("/sys/bus/pci/devices is empty — nothing measured")
	}

	ari := 0
	for _, n := range names {
		b, err := os.ReadFile("/sys/bus/pci/devices/" + n + "/ari_enabled")
		if err == nil && strings.TrimSpace(string(b)) == "1" {
			ari++
		}
	}

	max, at, err := maxFunctionField(names)
	if err != nil {
		t.Fatalf("PCI function field is not the decimal 0-255 field the kernel documents: %v", err)
	}
	if max > 7 {
		t.Fatalf("PCI function field %d at %s exceeds 7, over %d devices (%d ARI-enabled).\n"+
			"The bound PCI_FUNC(devfn) = devfn & 0x07 no longer holds on this kernel. "+
			"That makes FromPCIAddr's base-16 function parse OBSERVABLE for the first "+
			"time (it would read a two-digit decimal field as hex), and it reopens the "+
			"#6677 ARI reconstruction question. Do not relax this assertion — read the "+
			"rationale in netname.go and pkg/netname/README.md, which both cite this "+
			"test as the thing that keeps them honest.", max, at, len(names), ari)
	}
	t.Logf("PCI function field bound holds: max %d at %s over %d devices, %d ARI-enabled",
		max, at, len(names), ari)
	if ari == 0 {
		t.Logf("NOTE: no ARI-enabled device on this host, so the ARI half of the bound " +
			"is asserted structurally (PCI_FUNC masks 3 bits) rather than observed")
	}
}
