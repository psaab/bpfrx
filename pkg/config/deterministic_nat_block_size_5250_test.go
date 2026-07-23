package config

import "testing"

// TestApplyDeterministicKeysRejectsNonPositiveBlockSize_5250 is the fail-on-revert
// guard for the deterministic CGNAT block-size parse guard (#5250 A3-b1 b1-F1) on
// the flat-set key path. A negative block-size must be ignored (BlockSize stays at
// its default 0), while a positive one is still stored. Removing the `n > 0` guard
// stores -5.
func TestApplyDeterministicKeysRejectsNonPositiveBlockSize_5250(t *testing.T) {
	det := &DeterministicNATConfig{}
	applyDeterministicKeys(det, []string{"block-size", "-5"})
	if det.BlockSize != 0 {
		t.Fatalf("BlockSize = %d, want 0 (a negative block-size must be ignored)", det.BlockSize)
	}
	applyDeterministicKeys(det, []string{"block-size", "0"})
	if det.BlockSize != 0 {
		t.Fatalf("BlockSize = %d, want 0 (a zero block-size must be ignored)", det.BlockSize)
	}
	applyDeterministicKeys(det, []string{"block-size", "2016"})
	if det.BlockSize != 2016 {
		t.Fatalf("BlockSize = %d, want 2016 (a positive block-size must be stored)", det.BlockSize)
	}
}

// TestApplyDeterministicChildrenRejectsNonPositiveBlockSize_5250 covers the same
// guard on the hierarchical `deterministic { block-size N }` child path.
func TestApplyDeterministicChildrenRejectsNonPositiveBlockSize_5250(t *testing.T) {
	det := &DeterministicNATConfig{}
	detNode := &Node{
		Keys: []string{"deterministic"},
		Children: []*Node{
			{Keys: []string{"block-size", "-7"}},
		},
	}
	applyDeterministicChildren(det, detNode)
	if det.BlockSize != 0 {
		t.Fatalf("BlockSize = %d, want 0 (a negative block-size child must be ignored)", det.BlockSize)
	}

	detNode.Children[0] = &Node{Keys: []string{"block-size", "2016"}}
	applyDeterministicChildren(det, detNode)
	if det.BlockSize != 2016 {
		t.Fatalf("BlockSize = %d, want 2016 (a positive block-size child must be stored)", det.BlockSize)
	}
}
