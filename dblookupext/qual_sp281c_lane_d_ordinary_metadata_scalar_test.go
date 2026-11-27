package dblookupext

import "testing"

func TestQualLaneDAbsentMetadataScalars(t *testing.T) {
	var metadata *MiniblockMetadata
	if got := metadata.GetRound(); got != 0 {
		t.Errorf("GetRound() = %d, want 0", got)
	}
	if got := metadata.GetHeaderNonce(); got != 0 {
		t.Errorf("GetHeaderNonce() = %d, want 0", got)
	}
	if got := metadata.GetEpoch(); got != 0 {
		t.Errorf("GetEpoch() = %d, want 0", got)
	}
	if got := metadata.GetType(); got != 0 {
		t.Errorf("GetType() = %d, want 0", got)
	}
}

func TestQualLaneDNestedMetadataEpochDisplay(t *testing.T) {
	metadata := &ScResultsHashesAndEpoch{Epoch: 9}
	if got := metadata.GetEpoch(); got != 9 {
		t.Errorf("GetEpoch() = %d, want 9", got)
	}
	var absent *ScResultsHashesAndEpoch
	if got := absent.GetEpoch(); got != 0 {
		t.Errorf("absent GetEpoch() = %d, want 0", got)
	}
}

func TestQualLaneDAbsentMetadataScalarLabels(t *testing.T) {
	var metadata *MiniblockMetadata
	if got := metadata.GetSourceShardID(); got != 0 {
		t.Errorf("absent source label = %d, want 0", got)
	}
	if got := metadata.GetDestinationShardID(); got != 0 {
		t.Errorf("absent destination label = %d, want 0", got)
	}
}
