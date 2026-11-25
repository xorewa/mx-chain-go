package esdtSupply

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/marshal"
	storageStubs "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAOrdinarySupplyGetterDTO(t *testing.T) {
	t.Parallel()

	asBigInt := func(s string) *big.Int {
		value, ok := new(big.Int).SetString(s, 10)
		require.True(t, ok)
		return value
	}
	for _, tc := range []struct {
		name, token           string
		stored, want          *SupplyESDT
		value, burned, minted string
	}{
		{name: "recorded", token: "ordinary-abcdef", stored: &SupplyESDT{Supply: asBigInt("18446744073709551617"), Burned: big.NewInt(5), Minted: asBigInt("18446744073709551622")},
			want:  &SupplyESDT{Supply: asBigInt("18446744073709551617"), Burned: big.NewInt(5), Minted: asBigInt("18446744073709551622")},
			value: "18446744073709551617", burned: "5", minted: "18446744073709551622"},
		{name: "recomputed", token: "ordinary-fedcba", stored: &SupplyESDT{Supply: asBigInt("12345678901234567890"), RecomputedSupply: true},
			want:  &SupplyESDT{Supply: asBigInt("12345678901234567890"), Burned: big.NewInt(0), Minted: big.NewInt(0), RecomputedSupply: true},
			value: "12345678901234567890", burned: "0", minted: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			codec := &marshal.GogoProtoMarshalizer{}
			wire, err := codec.Marshal(tc.stored)
			require.NoError(t, err)
			reads, writes, otherReads := 0, 0, 0
			suppliesStore := &storageStubs.StorerStub{
				GetCalled: func(key []byte) ([]byte, error) {
					reads++
					require.Equal(t, []byte(tc.token), key)
					return bytes.Clone(wire), nil
				},
				PutCalled: func(_, _ []byte) error { writes++; return nil },
			}
			otherStore := &storageStubs.StorerStub{
				GetCalled: func([]byte) ([]byte, error) { otherReads++; return nil, nil },
				PutCalled: func(_, _ []byte) error { writes++; return nil },
			}
			processor, err := NewSuppliesProcessor(codec, suppliesStore, otherStore, otherStore)
			require.NoError(t, err)
			require.False(t, processor.IsInterfaceNil())
			got, err := processor.GetESDTSupply(tc.token)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.want.Supply, got.GetSupply())
			require.Equal(t, tc.want.Burned, got.GetBurned())
			require.Equal(t, tc.want.Minted, got.GetMinted())
			require.Equal(t, tc.want.RecomputedSupply, got.GetRecomputedSupply())
			encoded, err := json.Marshal(got)
			require.NoError(t, err)
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.UseNumber()
			var display map[string]interface{}
			require.NoError(t, decoder.Decode(&display))
			require.Equal(t, map[string]interface{}{"value": json.Number(tc.value), "burned": json.Number(tc.burned), "minted": json.Number(tc.minted), "recomputedSupply": tc.want.RecomputedSupply}, display)
			var readback SupplyESDT
			require.NoError(t, json.Unmarshal(encoded, &readback))
			require.Equal(t, tc.want, &readback)
			require.Equal(t, 1, reads)
			require.Zero(t, writes)
			require.Zero(t, otherReads)
		})
	}
}
