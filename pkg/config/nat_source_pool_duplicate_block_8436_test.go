package config

import "testing"

// #8436: two hierarchical `pool P { ... }` blocks are ONE pool, and both
// blocks' addresses must survive.
//
// The census (TestDuplicateBlockConservationIsPinned8436) already catches a
// revert of this fix — it did, without a bespoke cell, which is the census
// succeeding at what six previous per-container fixes could not do. This exists
// for the other half: naming the CONSEQUENCE, so a reader meets it as "the pool
// translates through a different address set than the operator wrote" rather
// than as a row in a conservation table.
//
// It also fixes the address set by NAME. The census compares a hierarchical
// compile against the flat-set one, so it would be satisfied by two routes that
// are equally wrong; this says which addresses have to be there.
func TestDuplicateSourcePoolBlocksKeepBothAddressSets8436(t *testing.T) {
	const cfgText = `
security {
    nat {
        source {
            pool P {
                address {
                    203.0.113.1;
                }
                port {
                    range low 40000 high 40100;
                }
            }
            pool P {
                address {
                    203.0.113.2;
                }
            }
        }
    }
}
`
	tree, perrs := NewParser(cfgText).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	pool := cfg.Security.NAT.SourcePools["P"]
	if pool == nil {
		t.Fatal("pool P did not compile at all")
	}

	got := map[string]bool{}
	for _, a := range pool.Addresses {
		got[a] = true
	}
	for _, want := range []string{"203.0.113.1", "203.0.113.2"} {
		if !got[want] {
			t.Errorf("pool P lost address %s (has %v).\n"+
				"Two blocks with one name are one pool: constructing a fresh "+
				"NATPool per block makes the LAST block win, so the SNAT "+
				"allocator draws from a different address set than the operator "+
				"authored — silently, because there is no commit gate on this "+
				"container (#8436)", want, pool.Addresses)
		}
	}

	// The scalar half, and it is a distinct failure: a merge that shared the
	// object but let the second block's absent leaves reset it would keep the
	// addresses and still lose the port range. Only the FIRST block sets it.
	if pool.PortLow != 40000 || pool.PortHigh != 40100 {
		t.Errorf("pool P port range = %d-%d, want 40000-40100. The second block "+
			"does not mention `port`, so a merge that reset absent leaves to "+
			"their zero values would discard the first block's range while the "+
			"address assertion above still passed (#8436)",
			pool.PortLow, pool.PortHigh)
	}
}
