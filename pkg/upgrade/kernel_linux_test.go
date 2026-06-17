package upgrade

import "testing"

// TestBootEntryRegex locks the efibootmgr line parse against the two bugs found
// during live #1930 validation: (1) the label is followed by a TAB + loader
// path, NOT line-end, so a greedy (.+) folded the whole path into the key; and
// (2) entries with no loader path (UiApp) must still parse.
func TestBootEntryRegex(t *testing.T) {
	cases := []struct{ line, id, label string }{
		{"Boot0003* xpf-A\tHD(1,GPT,8a827350)/\\EFI\\xpf-A\\shimx64.efi", "0003", "xpf-A"},
		{"Boot0004* xpf-B\tHD(1,GPT,abc)/\\EFI\\xpf-B\\shimx64.efi", "0004", "xpf-B"},
		{"Boot0002* Ubuntu\tHD(1,GPT,xyz)/\\EFI\\ubuntu\\shimx64.efi", "0002", "Ubuntu"},
		{"Boot0000* UiApp", "0000", "UiApp"},                                 // no loader path
		{"Boot0001  inactive-entry\tPciRoot(0x0)", "0001", "inactive-entry"}, // no '*'
	}
	for _, c := range cases {
		m := bootEntryRE.FindStringSubmatch(c.line)
		if len(m) != 3 {
			t.Fatalf("no match for %q", c.line)
		}
		if m[1] != c.id || m[2] != c.label {
			t.Errorf("line %q -> id=%q label=%q, want id=%q label=%q", c.line, m[1], m[2], c.id, c.label)
		}
	}
}

func TestBootCurrentRegex(t *testing.T) {
	m := bootCurrentRE.FindStringSubmatch("BootCurrent: 0001")
	if len(m) != 2 || m[1] != "0001" {
		t.Fatalf("BootCurrent parse failed: %v", m)
	}
}

func TestSlotSelectorRegex(t *testing.T) {
	sel := []byte("set xpf_slot_kernel=\"vmlinuz-7.0.0-22-generic\"\nset xpf_slot_initrd=\"initrd.img-7.0.0-22-generic\"\n")
	m := slotSelectorKernelRE.FindSubmatch(sel)
	if len(m) != 2 || string(m[1]) != "7.0.0-22-generic" {
		t.Fatalf("selector parse failed: %v", m)
	}
}
