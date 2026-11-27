package dblookupext

import (
	"bytes"
	"reflect"
	"testing"
)

func TestQualLaneDAbsentMetadataLabels(t *testing.T) {
	var metadata *MiniblockMetadata
	if got := metadata.GetHeaderHash(); got != nil {
		t.Errorf("absent header label = %q, want nil", got)
	}
	if got := metadata.GetMiniblockHash(); got != nil {
		t.Errorf("absent miniblock label = %q, want nil", got)
	}
}

func TestQualLaneDResultsMetadataLabelGetters(t *testing.T) {
	metadata := &ResultsHashesByTxHash{ReceiptsHash: []byte("label")}
	if got := metadata.GetReceiptsHash(); !bytes.Equal(got, []byte("label")) {
		t.Errorf("receipt label = %q, want label", got)
	}
	var absent *ResultsHashesByTxHash
	if got := absent.GetReceiptsHash(); got != nil {
		t.Errorf("absent receipt label = %q, want nil", got)
	}
	nested := &ScResultsHashesAndEpoch{ScResultsHashes: [][]byte{[]byte("first"), []byte("second")}}
	if got := nested.GetScResultsHashes(); !reflect.DeepEqual(got, [][]byte{[]byte("first"), []byte("second")}) {
		t.Errorf("nested labels = %q, want first and second", got)
	}
	var absentNested *ScResultsHashesAndEpoch
	if got := absentNested.GetScResultsHashes(); got != nil {
		t.Errorf("absent nested labels = %q, want nil", got)
	}
}
