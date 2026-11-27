package esdtSupply

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Exercise only the generated presentation and serialization of an ordinary
// scalar DTO; no processing or storage is involved.
func TestQualLaneDOrdinaryProcessedNonceDTO(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nonce     uint64
		wire      []byte
		display   string
		goDisplay string
	}{
		{"default", 0, []byte{}, "&ProcessedBlockNonce{Nonce:0,}", "&esdtSupply.ProcessedBlockNonce{Nonce: 0x0,\n}"},
		{"scalar", 37, []byte{0x08, 0x25}, "&ProcessedBlockNonce{Nonce:37,}", "&esdtSupply.ProcessedBlockNonce{Nonce: 0x25,\n}"},
		{"wide scalar", 4294967296, []byte{0x08, 0x80, 0x80, 0x80, 0x80, 0x10}, "&ProcessedBlockNonce{Nonce:4294967296,}", "&esdtSupply.ProcessedBlockNonce{Nonce: 0x100000000,\n}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dto := &ProcessedBlockNonce{Nonce: tc.nonce}
			require.Equal(t, tc.nonce, dto.GetNonce())
			require.Equal(t, tc.display, dto.String())
			require.Equal(t, tc.goDisplay, dto.GoString())
			require.Equal(t, len(tc.wire), dto.Size())

			wire, err := dto.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.wire, wire)
			buf := make([]byte, dto.Size())
			n, err := dto.MarshalTo(buf)
			require.NoError(t, err)
			require.Equal(t, len(tc.wire), n)
			require.Equal(t, tc.wire, buf)
			var unpacked ProcessedBlockNonce
			require.NoError(t, unpacked.Unmarshal(wire))
			require.Equal(t, tc.nonce, unpacked.GetNonce())
			require.Equal(t, tc.display, unpacked.String())
		})
	}
	t.Run("nil display", func(t *testing.T) {
		var dto *ProcessedBlockNonce
		require.Zero(t, dto.GetNonce())
		require.Zero(t, dto.Size())
		require.Equal(t, "nil", dto.String())
		require.Equal(t, "nil", dto.GoString())
	})
}

func TestQualLaneDProcessedNonceSizeDisplayComplement(t *testing.T) {
	metadata := &ProcessedBlockNonce{Nonce: 9}
	if got := metadata.XXX_Size(); got != 2 {
		t.Errorf("XXX_Size() = %d, want 2", got)
	}
	var absent *ProcessedBlockNonce
	if got := absent.XXX_Size(); got != 0 {
		t.Errorf("absent XXX_Size() = %d, want 0", got)
	}
}
