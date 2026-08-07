package dataplane

// #4555: the shim's SELF-REPORTED facts, read out of the compiled object.
//
// Why this exists. The IPv6 extension-header walk in the AF_XDP shim and
// the one in userspace-dp must agree, and the shim cannot be executed by
// userspace-dp's tests (it is `no_std`, built for `bpfel-unknown-none`).
// The first four attempts at a parity guard all MODELLED the shim from
// its source text, and every one leaked to a more ordinary edit than the
// last:
//
//  1. a substring test on the advance arithmetic accepted an added `+ 8`;
//  2. it also accepted a prepended `if opt[1] == 0 { break; }`, which
//     rejects the ordinary 8-byte HbH/DestOpt;
//  3. pinning arm bodies still ignored a statement placed inside the walk
//     loop but outside the `match`;
//  4. pinning the TEXT `mem::size_of::<FragHdr>()` did not pin its VALUE,
//     so a field added to FragHdr silently changed the advance;
//  5. and the struct-layout resolver that fixed (4) split fields on
//     commas and skipped comments, so a COMMENT above a field hid it.
//
// Each fix was a better model and each model leaked. So the shim now
// EMITS its resolved facts instead: `XPF_SHIM_FACTS` is a `#[used]`
// static whose fields are const-evaluated by rustc from the real types
// and the real classifier (`size_of::<FragHdr>()`, `MAX_EXT_HDRS`, and a
// 256-entry table produced by the same `eh_class` function the walk
// dispatches on). There is nothing left to model: the numbers compared
// against are the numbers the shipped object was built with.
//
// It also travels with the ARTIFACT. The compile-time assertion this
// replaces only ran when the shim crate was compiled, which the Debian
// packaging path never does (`debian/rules` runs `make build`, and the
// daemon embeds the tracked `.o` via `//go:embed`). Facts recorded in
// the manifest are checkable by anyone consuming a prebuilt object.

import (
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	// shimFactsSymbol is the `#[unsafe(no_mangle)] #[used] static` the
	// shim emits into its own `.rodata.XPF_SHIM_FACTS` section.
	shimFactsSymbol = "XPF_SHIM_FACTS"

	// shimFactsMagic is "XPFF" little-endian — a sanity check that the
	// bytes read back are the struct this code expects and not some
	// other symbol that happened to take the name.
	shimFactsMagic = 0x58504646

	// shimFactsVersion is bumped whenever the emitted struct's layout
	// changes, so a stale object is reported as such instead of being
	// silently misparsed.
	shimFactsVersion = 1

	// shimFactsFixedLen is magic+version+max_ext_hdrs+frag_hdr_size.
	shimFactsFixedLen = 16
	// shimEHClassTableLen is one class byte per IPv6 next-header value.
	shimEHClassTableLen = 256
	shimFactsTotalLen   = shimFactsFixedLen + shimEHClassTableLen
)

// Extension-header classes, mirroring EH_CLASS_* in
// userspace-xdp/src/lib.rs. These are the VALUES the shim's `eh_class`
// returns, transported in the emitted table.
const (
	ShimEHClassTerminal uint8 = 0
	ShimEHClassGeneric  uint8 = 1
	ShimEHClassAuth     uint8 = 2
	ShimEHClassFragment uint8 = 3
	ShimEHClassNoNext   uint8 = 4
)

// ShimFacts are the AF_XDP shim's own compile-time values, recovered from
// the object it was compiled into.
type ShimFacts struct {
	// MaxExtHdrs is the shim's `MAX_EXT_HDRS` walk bound.
	MaxExtHdrs uint32 `json:"max_ext_hdrs"`
	// FragHdrSize is `size_of::<FragHdr>()` — the bytes the Fragment arm
	// advances. userspace-dp advances a literal 8.
	FragHdrSize uint32 `json:"frag_hdr_size"`
	// EHClassesHex is the 256-entry class table, one hex byte pair per
	// IPv6 next-header value, in order. A hex string rather than a JSON
	// array because Go marshals []uint8 as base64 (opaque to the Rust
	// reader) and a 256-element number array would be 256 lines of
	// generated diff. Decode with EHClasses.
	EHClassesHex string `json:"eh_classes_hex"`
}

// EHClasses decodes the emitted per-next-header class table.
func (f *ShimFacts) EHClasses() ([]byte, error) {
	b, err := hex.DecodeString(f.EHClassesHex)
	if err != nil {
		return nil, fmt.Errorf("decode %s eh_classes_hex: %w", shimFactsSymbol, err)
	}
	if len(b) != shimEHClassTableLen {
		return nil, fmt.Errorf("%s eh_classes_hex decodes to %d bytes, want %d",
			shimFactsSymbol, len(b), shimEHClassTableLen)
	}
	return b, nil
}

// ReadShimFactsFromObject extracts the emitted facts from a compiled shim
// object. It fails loudly on a missing symbol, a short read, or a magic /
// version mismatch — a caller must never proceed on facts it could not
// actually read, since the whole point is that these numbers are real.
func ReadShimFactsFromObject(path string) (*ShimFacts, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open shim object %q: %w", path, err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("read symbols from %q: %w", path, err)
	}
	for _, s := range syms {
		if s.Name != shimFactsSymbol {
			continue
		}
		if int(s.Section) >= len(f.Sections) {
			return nil, fmt.Errorf("%s: symbol references section %d out of range", shimFactsSymbol, s.Section)
		}
		data, err := f.Sections[s.Section].Data()
		if err != nil {
			return nil, fmt.Errorf("read section for %s: %w", shimFactsSymbol, err)
		}
		end := s.Value + s.Size
		if s.Size < shimFactsTotalLen || end > uint64(len(data)) {
			return nil, fmt.Errorf("%s: want >= %d bytes at offset %d, section holds %d",
				shimFactsSymbol, shimFactsTotalLen, s.Value, len(data))
		}
		return parseShimFacts(data[s.Value:end])
	}
	return nil, fmt.Errorf("%s symbol not found in %q — the shim must emit its facts "+
		"(see userspace-xdp/src/lib.rs); a parity check cannot fall back to modelling the source (#4555)",
		shimFactsSymbol, path)
}

func parseShimFacts(b []byte) (*ShimFacts, error) {
	magic := binary.LittleEndian.Uint32(b[0:4])
	if magic != shimFactsMagic {
		return nil, fmt.Errorf("%s: magic 0x%08x, want 0x%08x", shimFactsSymbol, magic, shimFactsMagic)
	}
	version := binary.LittleEndian.Uint32(b[4:8])
	if version != shimFactsVersion {
		return nil, fmt.Errorf("%s: version %d, want %d — the emitted struct changed shape; "+
			"update pkg/dataplane/userspace_xdp_facts.go together with userspace-xdp/src/lib.rs",
			shimFactsSymbol, version, shimFactsVersion)
	}
	return &ShimFacts{
		MaxExtHdrs:   binary.LittleEndian.Uint32(b[8:12]),
		FragHdrSize:  binary.LittleEndian.Uint32(b[12:16]),
		EHClassesHex: hex.EncodeToString(b[shimFactsFixedLen:shimFactsTotalLen]),
	}, nil
}
