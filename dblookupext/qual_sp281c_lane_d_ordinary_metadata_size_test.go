package dblookupext

import "testing"

func TestQualLaneDOrdinaryMetadataSize(t *testing.T) {
	nested := &ScResultsHashesAndEpoch{Epoch: 9, ScResultsHashes: [][]byte{[]byte("label")}}
	cases := []struct {
		name  string
		value interface {
			Size() int
			XXX_Size() int
		}
		want int
	}{
		{"empty miniblock metadata", &MiniblockMetadata{}, 0},
		{"scalar miniblock metadata", &MiniblockMetadata{SourceShardID: 2, DestinationShardID: 3, Round: 17, HeaderNonce: 23, Epoch: 7, Type: 1}, 12},
		{"empty nested metadata", &ScResultsHashesAndEpoch{}, 0},
		{"nested labels", nested, 9},
		{"empty results metadata", &ResultsHashesByTxHash{}, 0},
		{"results labels", &ResultsHashesByTxHash{ReceiptsHash: []byte("label"), ScResultsHashesAndEpoch: []*ScResultsHashesAndEpoch{nested}}, 18},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.value.Size(); got != tc.want {
				t.Errorf("Size() = %d, want %d", got, tc.want)
			}
			if got := tc.value.XXX_Size(); got != tc.want {
				t.Errorf("XXX_Size() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestQualLaneDAbsentMetadataSize(t *testing.T) {
	var miniblock *MiniblockMetadata
	var results *ResultsHashesByTxHash
	var nested *ScResultsHashesAndEpoch
	cases := []struct {
		name  string
		value interface {
			Size() int
			XXX_Size() int
		}
	}{
		{"MiniblockMetadata", miniblock},
		{"ResultsHashesByTxHash", results},
		{"ScResultsHashesAndEpoch", nested},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.value.Size(); got != 0 {
				t.Errorf("Size() = %d, want 0", got)
			}
			if got := tc.value.XXX_Size(); got != 0 {
				t.Errorf("XXX_Size() = %d, want 0", got)
			}
		})
	}
}
