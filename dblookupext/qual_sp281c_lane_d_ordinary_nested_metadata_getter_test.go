package dblookupext

import "testing"

func TestQualLaneDOrdinaryNestedMetadataGetter(t *testing.T) {
	first := &ScResultsHashesAndEpoch{Epoch: 7}
	second := &ScResultsHashesAndEpoch{Epoch: 9}
	metadata := &ResultsHashesByTxHash{ScResultsHashesAndEpoch: []*ScResultsHashesAndEpoch{first, second}}
	if got := metadata.GetScResultsHashesAndEpoch(); len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("nested display DTOs not preserved in order: %v", got)
	}
	var absent *ResultsHashesByTxHash
	if got := absent.GetScResultsHashesAndEpoch(); got != nil {
		t.Errorf("absent nested DTO list = %v, want nil", got)
	}
}
