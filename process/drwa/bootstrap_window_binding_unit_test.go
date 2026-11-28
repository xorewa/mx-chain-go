package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
)

// Exercise only the detached window decoder; these are inert data fields,
// not certificates, signatures, provider calls, or admission operations.
func TestBootstrapWindowBindingUnit(t *testing.T) {
	records := &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 4096}
	codec, err := newRegistrationApprovalCodec(records, registrationApprovalBounds{bytes: 4096, fieldBytes: 2048, roleBytes: 64, familyBytes: 64, maxMembers: 8, maxValidity: 100})
	require.NoError(t, err)
	window := qualRecordFrame([]byte("unit-data"), qualA38U64(101), qualA38U64(111))
	for _, binding := range []bootstrapProofBinding{{}, {notBefore: 101, notAfter: 111}} {
		require.NoError(t, codec.bindSignedBootstrapWindow(&binding, window))
		require.Equal(t, uint64(101), binding.notBefore)
		require.Equal(t, uint64(111), binding.notAfter)
	}
	for _, invalid := range [][]byte{nil, qualRecordFrame([]byte("unit-data"), []byte("invalid"), qualA38U64(111))} {
		binding := bootstrapProofBinding{}
		require.Error(t, codec.bindSignedBootstrapWindow(&binding, invalid))
		require.Zero(t, binding.notBefore)
		require.Zero(t, binding.notAfter)
	}
}
