package drwa

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
)

// Candidate bytes only. qualRecordFrame is the independently written literal
// field-1 protobuf fixture, not the production Batch marshaler. Limits, holder
// bytes and family/provenance premises are synthetic, not native admission.
func qualRootLeafCodec(t *testing.T) *rootLeafRecords {
	t.Helper()
	r, err := newRootLeafRecords(&registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 512}, 32)
	require.NoError(t, err)
	return r
}

func TestQualDRWARootLeafCandidateVectors(t *testing.T) {
	r := qualRootLeafCodec(t)
	token, holder := []byte("TOKEN-abcdef"), bytes.Repeat([]byte{0x11}, 32)
	for _, tc := range []struct {
		n   uint64
		raw []byte
	}{
		{0, []byte{0, 0, 0, 0, 0, 0, 0, 0}}, {1, []byte{0, 0, 0, 0, 0, 0, 0, 1}}, {^uint64(0), bytes.Repeat([]byte{0xff}, 8)},
	} {
		family := core.SemiFungible
		if tc.n == 0 {
			family = core.Fungible
		}
		expectedPosition := qualRecordFrame(token, tc.raw, holder)
		key, err := r.positionKey(token, family, tc.n, holder)
		require.NoError(t, err)
		require.Equal(t, expectedPosition, key)
		gotNonce, gotHolder, err := r.decodePositionKey(expectedPosition, token, family)
		require.NoError(t, err)
		require.Equal(t, tc.n, gotNonce)
		require.Equal(t, holder, gotHolder)
		gotHolder[0] ^= 1
		require.Equal(t, qualRecordFrame(token, tc.raw, holder), expectedPosition)
		nonceKey, err := r.nonceKey(token, family, tc.n)
		if tc.n == 0 {
			require.ErrorIs(t, err, errRootLeafRecord)
			continue
		}
		require.NoError(t, err)
		expectedNonce := qualRecordFrame(token, tc.raw)
		require.Equal(t, expectedNonce, nonceKey)
		require.NotEqual(t, key, nonceKey)
		gotNonce, err = r.decodeNonceKey(expectedNonce, token, family)
		require.NoError(t, err)
		require.Equal(t, tc.n, gotNonce)
		_, _, err = r.decodePositionKey(nonceKey, token, family)
		require.Error(t, err)
		_, err = r.decodeNonceKey(key, token, family)
		require.Error(t, err)
	}
	q := new(big.Int).Lsh(big.NewInt(1), 80)
	value, err := r.quantityValue(q)
	require.NoError(t, err)
	require.Equal(t, append([]byte{1}, make([]byte, 10)...), value)
	got, err := r.decodeQuantityValue(value)
	require.NoError(t, err)
	require.Zero(t, got.Cmp(q))
	value[0] ^= 1
	require.Zero(t, got.Cmp(q))
	got.SetInt64(7)
	require.Equal(t, 81, q.BitLen())
	zero, err := r.quantityValue(new(big.Int))
	require.NoError(t, err)
	require.Empty(t, zero)
	_, err = r.decodeQuantityValue(zero)
	require.ErrorIs(t, err, errRootLeafRecord)
}

func TestQualDRWARootLeafCandidateRefusals(t *testing.T) {
	r := qualRootLeafCodec(t)
	token := []byte("TOKEN-abcdef")
	nonce := make([]byte, 8)
	holder := bytes.Repeat([]byte{0x22}, 32)
	for _, bad := range [][]byte{nil, []byte("bad"), bytes.Repeat([]byte{'X'}, 513)} {
		_, err := r.positionKey(bad, core.Fungible, 0, holder)
		require.Error(t, err)
		_, err = r.nonceKey(bad, core.SemiFungible, 1)
		require.Error(t, err)
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		_, err := r.positionKey(token, core.Fungible, 0, bad)
		require.ErrorIs(t, err, errRootLeafRecord)
	}
	for _, raw := range [][]byte{nil, {0x0a}, qualRecordFrame([]byte("bad"), nonce, holder), qualRecordFrame(token, make([]byte, 7), holder), qualRecordFrame(token, make([]byte, 9), holder), qualRecordFrame(token, nonce, make([]byte, 31)), append(qualRecordFrame(token, nonce, holder), 0x28, 0)} {
		_, _, err := r.decodePositionKey(raw, token, core.Fungible)
		require.Error(t, err)
	}
	for _, raw := range [][]byte{nil, {0x0a}, qualRecordFrame([]byte("bad"), nonce), qualRecordFrame(token, make([]byte, 7)), qualRecordFrame(token, make([]byte, 9)), append(qualRecordFrame(token, nonce), 0x28, 0)} {
		_, err := r.decodeNonceKey(raw, token, core.SemiFungible)
		require.Error(t, err)
	}
	for _, q := range []*big.Int{nil, big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 4096)} {
		value, err := r.quantityValue(q)
		require.ErrorIs(t, err, errRootLeafRecord)
		require.Nil(t, value)
	}
	for _, raw := range [][]byte{nil, {0}, {0, 1}, bytes.Repeat([]byte{1}, 513)} {
		value, err := r.decodeQuantityValue(raw)
		require.ErrorIs(t, err, errRootLeafRecord)
		require.Nil(t, value)
	}
	r.codec.maxBytes = 1
	_, err := r.positionKey(token, core.Fungible, 0, holder)
	require.Error(t, err)
	_, err = r.nonceKey(token, core.SemiFungible, 1)
	require.Error(t, err)
	for _, c := range []*registrationRecords{nil, {}, {marshaller: &marshal.GogoProtoMarshalizer{}, maxBytes: 0}} {
		_, err := newRootLeafRecords(c, 32)
		require.ErrorIs(t, err, errRootLeafRecord)
	}
}
