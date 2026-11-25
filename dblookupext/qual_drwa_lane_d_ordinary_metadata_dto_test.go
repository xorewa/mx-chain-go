package dblookupext

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualLaneDOrdinaryMiniblockMetadataDTO(t *testing.T) {
	t.Parallel()

	input := &MiniblockMetadata{
		SourceShardID:      1,
		DestinationShardID: 2,
		Round:              42,
		HeaderNonce:        11,
		HeaderHash:         []byte("header"),
		MiniblockHash:      []byte("miniblock"),
		Epoch:              3,
	}

	wire, err := input.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, wire)
	require.Len(t, wire, input.Size())

	var result MiniblockMetadata
	require.NoError(t, result.Unmarshal(wire))
	require.Equal(t, input, &result)
	require.EqualValues(t, 1, result.GetSourceShardID())
	require.EqualValues(t, 2, result.GetDestinationShardID())
	require.EqualValues(t, 42, result.GetRound())
	require.EqualValues(t, 11, result.GetHeaderNonce())
	require.Equal(t, []byte("header"), result.GetHeaderHash())
	require.Equal(t, []byte("miniblock"), result.GetMiniblockHash())
	require.EqualValues(t, 3, result.GetEpoch())
	require.EqualValues(t, 0, result.GetType())
}
