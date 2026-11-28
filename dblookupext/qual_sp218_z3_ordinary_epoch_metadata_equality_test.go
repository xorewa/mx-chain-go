package dblookupext

import "testing"

// Ordinary scalar DTO comparison with independent values and value/pointer inputs.
func TestQualSP218Z3OrdinaryEpochMetadataEquality(t *testing.T) {
	original := &EpochByHash{Epoch: 300}
	same := &EpochByHash{Epoch: 300}
	next := &EpochByHash{Epoch: 301}

	if !original.Equal(same) || !same.Equal(original) {
		t.Fatal("independent DTOs with the same epoch must compare equal")
	}
	if !original.Equal(EpochByHash{Epoch: 300}) {
		t.Fatal("a value carrying the same epoch must compare equal")
	}
	if original.Equal(next) || next.Equal(original) {
		t.Fatal("distinct epoch display values must compare unequal")
	}
	if original.Equal(EpochByHash{Epoch: 301}) {
		t.Fatal("distinct epoch value must compare unequal")
	}
}
