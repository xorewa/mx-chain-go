package dblookupext

import "testing"

// Optional metadata distinguishes an absent record from a present zero-valued record.
func TestQualSP218Z3OrdinaryEpochMetadataOptionalEquality(t *testing.T) {
	var absent *EpochByHash
	zero := &EpochByHash{Epoch: 0}

	if !absent.Equal(nil) || !absent.Equal((*EpochByHash)(nil)) {
		t.Fatal("both forms of absent metadata must compare equal")
	}
	if zero.Equal(nil) || zero.Equal(absent) || absent.Equal(zero) {
		t.Fatal("present zero metadata must remain distinct from absence")
	}
	if zero.Equal(uint32(0)) {
		t.Fatal("the bare scalar is a different representation from the metadata record")
	}
}
