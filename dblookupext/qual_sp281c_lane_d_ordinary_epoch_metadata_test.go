package dblookupext

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Ordinary scalar metadata serialization and display, without any lookup.
func TestQualLaneDOrdinaryEpochMetadataDTO(t *testing.T) {
	for _, tc := range []struct {
		name    string
		epoch   uint32
		wire    []byte
		display string
	}{
		{name: "default", epoch: 0, wire: []byte{}, display: "&EpochByHash{Epoch:0,}"},
		{name: "scalar", epoch: 37, wire: []byte{0x08, 0x25}, display: "&EpochByHash{Epoch:37,}"},
		{name: "multibyte scalar", epoch: 300, wire: []byte{0x08, 0xac, 0x02}, display: "&EpochByHash{Epoch:300,}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := &EpochByHash{Epoch: tc.epoch}
			require.Equal(t, tc.epoch, value.GetEpoch())
			require.Equal(t, tc.display, value.String())
			require.Equal(t, len(tc.wire), value.Size())

			wire, err := value.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.wire, wire)
			buf := make([]byte, value.Size())
			n, err := value.MarshalTo(buf)
			require.NoError(t, err)
			require.Equal(t, len(wire), n)
			require.Equal(t, wire, buf)

			var decoded EpochByHash
			require.NoError(t, decoded.Unmarshal(wire))
			require.Equal(t, tc.epoch, decoded.GetEpoch())
		})
	}
	t.Run("nil display", func(t *testing.T) {
		var value *EpochByHash
		require.Zero(t, value.GetEpoch())
		require.Zero(t, value.Size())
		require.Equal(t, "nil", value.String())
	})
}

func TestQualLaneDEpochMetadataDisplayComplement(t *testing.T) {
	metadata := &EpochByHash{Epoch: 7}
	if got := metadata.GoString(); got != "&dblookupext.EpochByHash{Epoch: 0x7,\n}" {
		t.Errorf("GoString() = %q", got)
	}
	if got := metadata.XXX_Size(); got != 2 {
		t.Errorf("XXX_Size() = %d, want 2", got)
	}
	var absent *EpochByHash
	if got := absent.GoString(); got != "nil" {
		t.Errorf("absent GoString() = %q, want nil", got)
	}
	if got := absent.XXX_Size(); got != 0 {
		t.Errorf("absent XXX_Size() = %d, want 0", got)
	}
}
