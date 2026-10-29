package common_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// Architecture Part A 2.6: domain separation and exact chain/metachain identity.
func TestSP1CoverageNetworkDomain(t *testing.T) {
	chain := []byte("T")
	genesis := bytes.Repeat([]byte{0x42}, 32)
	hash := &testscommon.HasherStub{SizeCalled: func() int { return 32 }, ComputeCalled: func(s string) []byte {
		require.Equal(t, append(append([]byte("DRWA/NETWORK/v1"), chain...), genesis...), []byte(s))
		sum := sha256.Sum256([]byte(s))
		return sum[:]
	}}
	got, err := common.ComputeDRWANetworkDomain(chain, genesis, hash)
	require.NoError(t, err)
	require.Equal(t, "a582f0c96772befaf89185e27272bf3e76e6329abbeb1cdcee2d71fcedc3574c", hex.EncodeToString(got))
	require.Equal(t, []byte("T"), chain)
	require.Equal(t, bytes.Repeat([]byte{0x42}, 32), genesis)
	_, err = common.ComputeDRWANetworkDomain(chain, genesis, nil)
	require.ErrorIs(t, err, core.ErrNilHasher)
	for _, tc := range []struct {
		name           string
		chain, genesis []byte
		size           int
	}{
		{"empty chain", nil, genesis, 32}, {"absent genesis", chain, nil, 32}, {"wrong hash width", chain, genesis[:31], 32},
		{"zero width", chain, nil, 0}, {"negative width", chain, genesis, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &testscommon.HasherStub{SizeCalled: func() int { return tc.size }, ComputeCalled: func(string) []byte { t.Fatal("invalid input reached hashing"); return nil }}
			out, e := common.ComputeDRWANetworkDomain(tc.chain, tc.genesis, h)
			require.Error(t, e)
			require.Nil(t, out)
		})
	}
	hash.ComputeCalled = func(s string) []byte { sum := sha256.Sum256([]byte(s)); return sum[:] }
	changedChain, err := common.ComputeDRWANetworkDomain([]byte("U"), genesis, hash)
	require.NoError(t, err)
	require.NotEqual(t, got, changedChain)
	other := bytes.Clone(genesis)
	other[0] ^= 1
	changedGenesis, err := common.ComputeDRWANetworkDomain(chain, other, hash)
	require.NoError(t, err)
	require.NotEqual(t, got, changedGenesis)
}
