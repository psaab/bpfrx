package dataplane

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// #6917 — the generic-attach decision must not read ParentIndex off a device it
// has not proven is a local 802.1Q child.
//
// PAIRED on the SAME failed-parent input, one axis:
//
//	proven vlan, parent in failedNativeXDP     -> SKIP   (the intended behaviour)
//	unproven device, same parent ifindex       -> ATTACH (the aliasing belt)
//
// Without the first row a belt that returned false unconditionally would satisfy
// the second and silently disable the EEXIST avoidance this loop exists for.
// Without the second, an aliased ParentIndex sends a live interface down the
// `continue` path and it gets NO XDP attach at all.
func TestGenericAttachSkipRequiresAProvenVLANParent_6917(t *testing.T) {
	const (
		failedParent = 4310
		childIdx     = 4311
	)
	failed := map[int]bool{failedParent: true}

	newResult := func(child netlink.Link) *CompileResult {
		return &CompileResult{
			linkCache:  map[string]netlink.Link{},
			linkIdxMap: map[int]netlink.Link{childIdx: child},
		}
	}

	t.Run("proven vlan child of a failed parent is skipped", func(t *testing.T) {
		child := &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9.50", Index: childIdx,
				ParentIndex: failedParent, NetNsID: netnsIDLocal},
			VlanId: 50,
		}
		if !newResult(child).skipGenericAttachForVLANChild(childIdx, failed) {
			t.Fatal("a genuine local VLAN child whose parent fell back to generic XDP " +
				"must still be SKIPPED — attaching generic XDP to both can raise EEXIST " +
				"on the parent, which is what this branch exists to avoid")
		}
	})

	// The aliasing rows. Each device carries a ParentIndex that IS in
	// failedNativeXDP, so the ONLY thing standing between it and a silent
	// `continue` is the kind/namespace proof.
	for _, tc := range []struct {
		name string
		link netlink.Link
	}{{
		name: "veth whose ParentIndex is its cross-namespace PEER",
		link: &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9.50", Index: childIdx,
			ParentIndex: failedParent, NetNsID: netnsIDLocal}},
	}, {
		name: "genuine vlan whose real_dev is in another namespace",
		link: &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9.50", Index: childIdx,
			ParentIndex: failedParent, NetNsID: 0}, VlanId: 50},
	}} {
		t.Run("unproven: "+tc.name+" is attached, not skipped", func(t *testing.T) {
			if newResult(tc.link).skipGenericAttachForVLANChild(childIdx, failed) {
				t.Fatalf("skipped the generic attach on an UNPROVEN device (%T).\n"+
					"Its ParentIndex is not a VLAN delegation — netlink folds IFLA_LINK "+
					"into that field for every link kind — so the number matching a "+
					"locally-failed ifindex proves nothing. Skipping leaves the interface "+
					"in pendingXDP with NO program attached: a live forwarding surface "+
					"with no shim (#6917).", tc.link)
			}
		})
	}

	t.Run("unresolvable ifindex does not skip", func(t *testing.T) {
		if (&CompileResult{
			linkCache:  map[string]netlink.Link{},
			linkIdxMap: map[int]netlink.Link{},
		}).skipGenericAttachForVLANChild(999999, failed) {
			t.Fatal("skipped on a link that could not be resolved at all — with no link " +
				"there is no parent to prove, and skipping would hide the surface")
		}
	})
}
