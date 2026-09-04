package dataplane

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

// #8249: pin the shim's per-path COMBINED STACK against BPF's 512-byte limit.
//
// THE BUDGET NOBODY WAS WATCHING. Every headroom gate this repo has — #1864's
// verifier floor, #8241's census — measures processed INSTRUCTIONS. BPF has a
// second, independent limit: 512 bytes of stack summed across a call path. On
// master before this change the path from the entry program into the native-GRE
// inner classifier measured:
//
//	entry 400 + dispatcher 0 + classify_native_gre_inner_ipv4 104 = 504 / 512
//
// Eight bytes. Four unrelated attempts to restructure the GRE region were all
// rejected with `combined stack size of N calls is too large` while none of them
// reached an instruction cap — they did not have four different problems, they
// had one, and it took three investigations to see because nothing reported this
// number. #8249 took the entry frame from 400 to 328; this guard is what stops
// it eroding back.
//
// WHAT IT READS. The frame size of a BPF function is the deepest negative
// offset it touches from r10, which is decodable straight out of the shipped
// object: fixed 8-byte instructions, and a stack access is any ST/STX whose DST
// is r10 or any LDX whose SRC is r10. No llvm-objdump, no rebuild, no verifier
// — it travels with the artifact exactly as #4555's facts do.
//
// WHY IT CARRIES POSITIVE CONTROLS, and this is not ceremony. While measuring
// #8249 I ran two probes that reported "no change" with total confidence. Both
// were invalid: a `sed` in my harness had silently replaced the build command
// with `true`, so I was disassembling a stale object and reporting master's
// numbers as the probe's. What caught it was injecting a known 128-byte array
// and asserting the number MOVED — it did not, and the object's md5 was
// identical.
//
// The failure mode is not "someone made a mistake". It is that a broken
// instrument produces a CONFIDENT ZERO, which is indistinguishable from a real
// null result and is the most persuasive wrong answer available. The same shape
// is available to this guard: if llvm changes an encoding, or the symbol table
// is read wrong, every frame decodes as 0, the combined total is 0, the margin
// looks enormous and the test passes while measuring nothing. So the decoder is
// exercised on a synthetic function with a KNOWN frame, and the real object is
// required to yield frames that are non-zero and plural.

const (
	// bpfMaxCombinedStack is the kernel's limit (MAX_BPF_STACK).
	bpfMaxCombinedStack = 512

	// shimEntrySymbol is the XDP entry program — the frame that was 80% of the
	// budget. Its name is unmangled (`#[xdp]` exports it), and the guard fails
	// loudly rather than silently if it is ever renamed.
	shimEntrySymbol = "xdp_userspace_prog"

	// stackMarginFloor is how much of that must stay UNUSED on the deepest
	// path. Set from the #8249 measurement (deepest path 432, i.e. 80 free)
	// with room to spare, and deliberately far above the 8 bytes master had:
	// the point of the guard is that "it still verifies" is not the same
	// property as "there is room to change anything".
	stackMarginFloor = 48
)

// bpfStackDepths decodes the deepest r10-relative access per function symbol.
func bpfStackDepths(t *testing.T) map[string]int {
	t.Helper()
	// The EMBEDDED object — the bytes the daemon actually loads
	// (`userspace_xdp_rust.go`), not a path this test picks. A guard that reads
	// a different artifact from the one that ships can pass while the shipped
	// one is over the limit.
	f, err := elf.NewFile(bytes.NewReader(userspaceXDPBytes))
	if err != nil {
		t.Fatalf("parse embedded shim object: %v", err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("symbols: %v", err)
	}
	out := map[string]int{}
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 {
			continue
		}
		if int(s.Section) >= len(f.Sections) {
			continue
		}
		sec := f.Sections[s.Section]
		data, err := sec.Data()
		if err != nil {
			continue
		}
		if s.Value+s.Size > uint64(len(data)) {
			continue
		}
		out[s.Name] = deepestStackOffset(data[s.Value : s.Value+s.Size])
	}
	return out
}

// deepestStackOffset walks 8-byte BPF instructions and returns the deepest
// negative r10 offset, i.e. the function's stack frame size.
func deepestStackOffset(code []byte) int {
	deepest := 0
	for i := 0; i+8 <= len(code); i += 8 {
		op := code[i]
		regs := code[i+1]
		dst := regs & 0x0f
		src := regs >> 4
		off := int(int16(binary.LittleEndian.Uint16(code[i+2 : i+4])))

		var base byte
		switch op & 0x07 {
		case 0x02, 0x03: // ST, STX — base is DST
			base = dst
		case 0x01: // LDX — base is SRC
			base = src
		default:
			continue
		}
		if base != 10 || off >= 0 {
			continue
		}
		if -off > deepest {
			deepest = -off
		}
	}
	return deepest
}

// POSITIVE CONTROL 1 — the decoder itself.
//
// A decoder that matches nothing reports every frame as 0, which reads as
// "enormous margin, all fine". This feeds it instructions with a KNOWN deepest
// offset and requires that exact number back, so a silent zero fails here
// before it can reassure anyone in the assertions below.
func TestStackDecoderReportsAKnownFrame8249(t *testing.T) {
	mk := func(op, dst, src byte, off int16) []byte {
		b := make([]byte, 8)
		b[0] = op
		b[1] = dst | src<<4
		binary.LittleEndian.PutUint16(b[2:4], uint16(off))
		return b
	}
	var code []byte
	code = append(code, mk(0x7b, 10, 5, -0x40)...) // STX *(u64*)(r10-64) = r5
	code = append(code, mk(0x79, 1, 10, -0xc8)...) // LDX r1 = *(u64*)(r10-200)
	code = append(code, mk(0x79, 1, 2, -0x400)...) // LDX off r2, NOT the stack
	code = append(code, mk(0xbf, 1, 2, 0)...)      // MOV, no stack access

	if got := deepestStackOffset(code); got != 200 {
		t.Fatalf("decoder reported %d, want 200. A decoder that under-reports "+
			"makes every assertion below pass by measuring nothing — the "+
			"confident-zero failure this control exists for (#8249).", got)
	}
	if got := deepestStackOffset(nil); got != 0 {
		t.Errorf("empty input must decode as 0, got %d", got)
	}
}

// POSITIVE CONTROL 2 — the real object.
//
// Control 1 proves the decoder can see a frame in bytes I built. This proves it
// sees frames in the SHIPPED artifact: if the symbol table were read wrong, or
// the sections walked wrong, control 1 still passes while every real frame
// reads 0.
func TestShimObjectYieldsNonZeroFrames8249(t *testing.T) {
	depths := bpfStackDepths(t)
	if len(depths) == 0 {
		t.Fatal("no function symbols decoded from the shim object — the guard " +
			"below would be measuring nothing")
	}
	nonZero := 0
	for _, d := range depths {
		if d > 0 {
			nonZero++
		}
	}
	if nonZero < 2 {
		t.Fatalf("only %d function(s) in the shim object report a non-zero stack "+
			"frame, out of %d symbols. This program demonstrably uses hundreds of "+
			"bytes of stack, so that is a decoder or symbol-table failure reading "+
			"as a clean result (#8249).", nonZero, len(depths))
	}
}

// THE GUARD. The deepest call path must keep real margin under 512.
//
// Modelled as entry + deepest subprogram, which is the shape of the path that
// matters (`xdp_userspace_prog` -> `classify_native_gre_inner_ipv4`) and is an
// upper bound for any two-level path. It deliberately does NOT reconstruct the
// full call graph from relocations: a guard that models more than it can verify
// is how #4555's first four attempts leaked. The kernel verifier remains the
// authority on the exact combined figure; this exists so erosion shows up at
// build time with a number attached, instead of as a later rejection that looks
// like four unrelated problems.
func TestShimStackPathKeepsMarginUnderTheBpfLimit8249(t *testing.T) {
	depths := bpfStackDepths(t)

	entry, ok := depths[shimEntrySymbol]
	if !ok {
		t.Fatalf("the entry program %q was not found among %d decoded symbols. "+
			"Renaming it silently disarms this guard.", shimEntrySymbol, len(depths))
	}
	if entry == 0 {
		t.Fatalf("the entry program decoded a ZERO-byte stack frame, which it " +
			"demonstrably does not have. That is the confident-zero failure, not a " +
			"result (#8249).")
	}

	deepestSub, deepestName := 0, ""
	for name, d := range depths {
		if name == shimEntrySymbol {
			continue
		}
		if d > deepestSub {
			deepestSub, deepestName = d, name
		}
	}

	combined := entry + deepestSub
	margin := bpfMaxCombinedStack - combined
	t.Logf("entry %s = %d B; deepest subprogram %s = %d B; combined %d/%d, margin %d B",
		shimEntrySymbol, entry, deepestName, deepestSub, combined, bpfMaxCombinedStack, margin)

	if combined > bpfMaxCombinedStack {
		t.Fatalf("the shim's deepest stack path is %d bytes, OVER BPF's %d-byte "+
			"combined limit. The object will be rejected at load with `combined "+
			"stack size ... too large`.", combined, bpfMaxCombinedStack)
	}
	if margin < stackMarginFloor {
		t.Errorf("the shim's deepest stack path is %d/%d bytes, leaving only %d "+
			"bytes of margin (floor %d).\n\n"+
			"This is the condition #8249 was opened into and spent three "+
			"investigations misdiagnosing: master sat at 504/512, and every attempt "+
			"to restructure the GRE region was rejected on the STACK while the "+
			"instruction budget looked healthy. It reads as several unrelated "+
			"problems.\n\n"+
			"Entry frame is %s = %d bytes. If it has grown, the lever is OUTLINING "+
			"work out of it — over half that frame is register spill slots, not a "+
			"named object, so the scratch-map advice in CLAUDE.md does not apply "+
			"(measured: moving the metadata store out was worth 72 bytes; writing "+
			"the same fields one at a time through the pointer was worth 8).",
			combined, bpfMaxCombinedStack, margin, stackMarginFloor, shimEntrySymbol, entry)
	}
}
