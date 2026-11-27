package dblookupext

import (
	"strings"
	"testing"
)

func TestQualLaneDMiniblockMetadataDisplay(t *testing.T) {
	metadata := &MiniblockMetadata{SourceShardID: 2, DestinationShardID: 3, Round: 17, HeaderNonce: 23, Epoch: 7, Type: 1}
	want := "&MiniblockMetadata{SourceShardID:2,DestinationShardID:3,Round:17,HeaderNonce:23,HeaderHash:[],MiniblockHash:[],DeprecatedStatus:[],Epoch:7,NotarizedAtSourceInMetaNonce:0,NotarizedAtDestinationInMetaNonce:0,NotarizedAtSourceInMetaHash:[],NotarizedAtDestinationInMetaHash:[],Type:1,}"
	if got := metadata.String(); got != want {
		t.Fatalf("unexpected metadata display: %q", got)
	}
	got := metadata.GoString()
	for _, want := range []string{"&dblookupext.MiniblockMetadata{", "SourceShardID: 0x2,", "DestinationShardID: 0x3,", "Round: 0x11,", "HeaderNonce: 0x17,", "Epoch: 0x7,", "Type: 1,"} {
		if !strings.Contains(got, want) {
			t.Errorf("display missing %q: %q", want, got)
		}
	}
}

func TestQualLaneDResultsMetadataDisplay(t *testing.T) {
	metadata := &ResultsHashesByTxHash{ReceiptsHash: []byte("label"), ScResultsHashesAndEpoch: []*ScResultsHashesAndEpoch{{Epoch: 9}}}
	want := "&ResultsHashesByTxHash{ReceiptsHash:[108 97 98 101 108],ScResultsHashesAndEpoch:[]*ScResultsHashesAndEpoch{&ScResultsHashesAndEpoch{Epoch:9,ScResultsHashes:[],},},}"
	if got := metadata.String(); got != want {
		t.Fatalf("unexpected metadata display: %q", got)
	}
	got := metadata.GoString()
	for _, want := range []string{"&dblookupext.ResultsHashesByTxHash{", "ReceiptsHash: []byte{0x6c, 0x61, 0x62, 0x65, 0x6c},", "ScResultsHashesAndEpoch: []*dblookupext.ScResultsHashesAndEpoch{", "Epoch: 0x9,"} {
		if !strings.Contains(got, want) {
			t.Errorf("display missing %q: %q", want, got)
		}
	}
}

func TestQualLaneDAbsentMetadataDisplay(t *testing.T) {
	var miniblock *MiniblockMetadata
	var results *ResultsHashesByTxHash
	var nested *ScResultsHashesAndEpoch
	cases := []struct {
		name    string
		display interface {
			String() string
			GoString() string
		}
	}{
		{"MiniblockMetadata", miniblock},
		{"ResultsHashesByTxHash", results},
		{"ScResultsHashesAndEpoch", nested},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.display.String(); got != "nil" {
				t.Errorf("String() = %q, want nil", got)
			}
			if got := tc.display.GoString(); got != "nil" {
				t.Errorf("GoString() = %q, want nil", got)
			}
		})
	}
}
