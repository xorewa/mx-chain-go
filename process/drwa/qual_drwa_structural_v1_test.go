package drwa

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/stretchr/testify/require"
)

type qualStructuralOuter struct {
	ID, Kind string
	Encoded  string   `json:"encoded_hex"`
	Fields   []string `json:"fields_hex"`
}

type qualStructuralInner struct {
	Family        string
	Type          core.ESDTType `json:"type_code"`
	PositionKey   string        `json:"position_key_hex"`
	PositionValue string        `json:"position_value_hex"`
	NonceKey      string        `json:"nonce_key_hex"`
	Live          string        `json:"nonce_live_value_hex"`
	Burned        string        `json:"nonce_burned_value_hex"`
}

type qualStructuralData struct {
	Locators struct {
		Address  string `json:"address_hex"`
		Supply   string `json:"supply_key_hex"`
		Position string `json:"position_key_hex"`
	}
	Positive []qualStructuralOuter `json:"outer_positive"`
	Negative []qualStructuralOuter `json:"outer_negative"`
	Inner    []qualStructuralInner `json:"inner_leaf_vectors"`
	BadInner []struct {
		ID    string
		Key   string `json:"raw_key_hex"`
		Value string `json:"raw_value_hex"`
	} `json:"inner_negative"`
	Transitions []struct {
		ID     string
		Before qualStructuralOuter
	} `json:"transition_expectations"`
	NativeNodes map[string]struct {
		Key   string `json:"raw_key_hex"`
		Value string `json:"value_hex"`
		Node  string `json:"encoded_node_hex"`
		Root  string `json:"root_hex"`
	} `json:"experimental_native_single_leaf_nodes"`
}

func qualStructuralV1Data(t *testing.T) qualStructuralData {
	t.Helper()
	var data qualStructuralData
	require.NoError(t, json.Unmarshal([]byte(qualStructuralV1Literals), &data))
	require.Len(t, data.Positive, 37)
	require.Len(t, data.Negative, 37)
	require.Len(t, data.Inner, 7)
	require.Len(t, data.BadInner, 15)
	require.Len(t, data.Transitions, 3)
	require.Len(t, data.NativeNodes, 6)
	return data
}

func TestQualDRWAStructuralV1Outer(t *testing.T) {
	data, r := qualStructuralV1Data(t), qualRootLeafCodec(t)
	token := []byte("TOKEN-abcdef")
	address, supplyKey, positionKey := qualA19Bytes(t, data.Locators.Address),
		qualA19Bytes(t, data.Locators.Supply), qualA19Bytes(t, data.Locators.Position)
	require.Equal(t, core.SystemAccountAddress, address)
	got, err := r.outerKey(supplyStatePrefix, token)
	require.NoError(t, err)
	require.Equal(t, supplyKey, got)
	got, err = r.outerKey(positionTrackingPrefix, token)
	require.NoError(t, err)
	require.Equal(t, positionKey, got)
	decoder, err := NewSupplyPositionRootDecoder(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 512, 32)
	require.NoError(t, err)
	reader := &setupLocalStateReader{records: r}
	for _, vector := range data.Positive {
		if !t.Run(vector.ID, func(t *testing.T) {
			f := make([][]byte, len(vector.Fields))
			for i, field := range vector.Fields {
				f[i] = qualA19Bytes(t, field)
			}
			want := qualA19Bytes(t, vector.Encoded)
			family := core.ESDTType(binary.BigEndian.Uint32(f[2]))
			view := lifecycleReadView{token: token, tokenType: uint32(family)}
			if vector.Kind == "SupplyF9" {
				view.supplyOrigin, view.supplyOriginShard = f[3], binary.BigEndian.Uint32(f[4])
				input := &initializedSupplyState{
					token: token, family: family, origin: view.supplyOrigin, originShard: view.supplyOriginShard,
					accounting: &supplyAccounting{new(big.Int).SetBytes(f[5]), new(big.Int).SetBytes(f[6]), binary.BigEndian.Uint64(f[8])},
					nonceRoot:  f[7],
				}
				actual, e := r.encodeSupplyRecord(input)
				require.NoError(t, e)
				require.Equal(t, want, actual)
				decoded, e := reader.decodeSupply(view, want)
				require.NoError(t, e)
				require.Equal(t, input.family, decoded.family)
				require.Equal(t, input.token, decoded.token)
				require.Equal(t, input.origin, decoded.origin)
				require.Equal(t, input.originShard, decoded.originShard)
				require.Equal(t, input.accounting, decoded.accounting)
				require.True(t, bytes.Equal(input.nonceRoot, decoded.nonceRoot))
				root, e := decoder(address, supplyKey, want)
				if family == core.Fungible {
					require.Error(t, e)
					require.Nil(t, root)
				} else {
					require.NoError(t, e)
					require.Equal(t, f[7], root)
				}
			} else {
				require.Equal(t, "PositionF7", vector.Kind)
				input := &initializedPositionState{token, family, f[4], new(big.Int).SetBytes(f[5]), binary.BigEndian.Uint64(f[6])}
				actual, e := r.encodePositionRecord(input)
				require.NoError(t, e)
				require.Equal(t, want, actual)
				decoded, e := reader.decodePositions(view, want)
				require.NoError(t, e)
				require.Equal(t, input, decoded)
				root, e := decoder(address, positionKey, want)
				require.NoError(t, e)
				require.Equal(t, f[4], root)
				root[0] ^= 1
				again, e := decoder(address, positionKey, want)
				require.NoError(t, e)
				require.Equal(t, f[4], again)
			}
		}) {
			return
		}
	}
	for _, vector := range data.Negative {
		if !t.Run(vector.ID, func(t *testing.T) {
			view := lifecycleReadView{token: token, tokenType: uint32(core.SemiFungible), supplyOrigin: bytes.Repeat([]byte{0x11}, 32), supplyOriginShard: 1}
			raw := qualA19Bytes(t, vector.Encoded)
			key := positionKey
			if vector.Kind == "Supply" {
				if vector.ID == "fungible_supply_child" {
					view.tokenType = uint32(core.Fungible)
				}
				value, e := reader.decodeSupply(view, raw)
				require.ErrorIs(t, e, errSetupLocalState)
				require.Nil(t, value)
				key = supplyKey
			} else {
				require.Equal(t, "Position", vector.Kind)
				value, e := reader.decodePositions(view, raw)
				require.ErrorIs(t, e, errSetupLocalState)
				require.Nil(t, value)
			}
			// The DB decoder has no current CEB. A structurally valid
			// different type is denied by the current-reader comparison above.
			if !strings.HasSuffix(vector.ID, "_wrong_family") {
				root, e := decoder(address, key, raw)
				require.ErrorIs(t, e, errSupplyPositionRecord)
				require.Nil(t, root)
			}
		}) {
			return
		}
	}
	t.Run("invalid_locator_and_bounds", func(t *testing.T) {
		raw := qualA19Bytes(t, data.Positive[1].Encoded)
		wrongAddress := bytes.Clone(address)
		wrongAddress[0] ^= 1
		for _, pair := range [][2][]byte{
			{wrongAddress, positionKey}, {address[:31], positionKey}, {address, supplyKey},
			{address, []byte(positionTrackingPrefix)}, {address, append(bytes.Clone(positionKey), 0)},
			{address, append([]byte(positionTrackingPrefix), 0x0a, 0x8c, 0)},
			{address, bytes.Repeat([]byte{1}, 513)},
		} {
			_, e := decoder(pair[0], pair[1], raw)
			require.ErrorIs(t, e, errSupplyPositionRecord)
		}
		limited, e := NewSupplyPositionRootDecoder(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), len(raw)-1, 32)
		require.NoError(t, e)
		_, e = limited(address, positionKey, raw)
		require.ErrorIs(t, e, errSupplyPositionRecord)
		_, e = NewSupplyPositionRootDecoder(nil, blake2b.NewBlake2b(), 512, 32)
		require.Error(t, e)
		_, e = NewSupplyPositionRootDecoder(&marshal.GogoProtoMarshalizer{}, nil, 512, 32)
		require.Error(t, e)
		_, e = NewSupplyPositionRootDecoder(&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 512, 0)
		require.Error(t, e)
		jsonDecoder, e := NewSupplyPositionRootDecoder(&marshal.JsonMarshalizer{}, blake2b.NewBlake2b(), 512, 32)
		require.NoError(t, e)
		_, e = jsonDecoder(address, positionKey, raw)
		require.ErrorIs(t, e, errSupplyPositionRecord)
		jsonRecords, e := newRootLeafRecords(&registrationRecords{marshaller: &marshal.JsonMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 512}, 32)
		require.NoError(t, e)
		_, e = jsonRecords.outerKey(positionTrackingPrefix, token)
		require.ErrorIs(t, e, errSupplyPositionRecord)
		fields := make([][]byte, len(data.Positive[1].Fields))
		for i, field := range data.Positive[1].Fields {
			fields[i] = qualA19Bytes(t, field)
		}
		jsonRaw, e := jsonRecords.codec.frame(fields...)
		require.NoError(t, e)
		_, e = jsonDecoder(address, positionKey, jsonRaw)
		require.ErrorIs(t, e, errSupplyPositionRecord)
	})
}

func TestQualDRWAStructuralV1Inner(t *testing.T) {
	data, r := qualStructuralV1Data(t), qualRootLeafCodec(t)
	token, holder := []byte("TOKEN-abcdef"), bytes.Repeat([]byte{0x11}, 32)
	for _, vector := range data.Inner {
		if !t.Run(vector.Family, func(t *testing.T) {
			family := vector.Type
			nonce := uint64(1)
			if family == core.Fungible {
				nonce = 0
			}
			key, err := r.positionKey(token, family, nonce, holder)
			require.NoError(t, err)
			require.Equal(t, qualA19Bytes(t, vector.PositionKey), key)
			nativeNonce, gotHolder, err := r.decodePositionKey(key, token, family)
			require.NoError(t, err)
			require.Equal(t, nonce, nativeNonce)
			require.Equal(t, holder, gotHolder)
			scalar, err := r.quantityValue(big.NewInt(5))
			require.NoError(t, err)
			require.Equal(t, qualA19Bytes(t, vector.PositionValue), scalar)
			if family == core.Fungible {
				_, err = r.nonceKey(token, family, 1)
				require.Error(t, err)
				_, err = r.nonceValue(family, nonceSupply{big.NewInt(5), big.NewInt(5)})
				require.Error(t, err)
				return
			}
			key, err = r.nonceKey(token, family, nonce)
			require.NoError(t, err)
			require.Equal(t, qualA19Bytes(t, vector.NonceKey), key)
			nativeNonce, err = r.decodeNonceKey(key, token, family)
			require.NoError(t, err)
			require.Equal(t, nonce, nativeNonce)
			quantity := big.NewInt(5)
			unique := family == core.NonFungibleV2 || family == core.DynamicNFT
			var cap *big.Int
			if unique {
				quantity = big.NewInt(1)
			} else {
				cap = big.NewInt(5)
			}
			created, err := r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTCreate, nil, quantity, cap)
			require.NoError(t, err)
			value, err := r.nonceValue(family, created)
			require.NoError(t, err)
			require.Equal(t, qualA19Bytes(t, vector.Live), value)
			before, err := r.decodeNonceValue(family, qualA19Bytes(t, vector.Live))
			require.NoError(t, err)
			burned, err := r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTBurn, &before, quantity, cap)
			require.NoError(t, err)
			require.Zero(t, burned.live.Sign())
			require.Equal(t, quantity, burned.issued)
			value, err = r.nonceValue(family, burned)
			require.NoError(t, err)
			require.NotEmpty(t, value)
			require.Equal(t, qualA19Bytes(t, vector.Burned), value)
			decoded, err := r.decodeNonceValue(family, qualA19Bytes(t, vector.Burned))
			require.NoError(t, err)
			require.Zero(t, burned.issued.Cmp(decoded.issued))
			require.Zero(t, burned.live.Cmp(decoded.live))
			require.Equal(t, quantity, before.live)
			_, err = r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTCreate, &burned, quantity, cap)
			require.Error(t, err)
			_, err = r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTAddQuantity, &burned, big.NewInt(1), cap)
			require.Error(t, err, "full burn cannot refill cap or authorize AddQuantity on a unique NFT")
			_, err = r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTBurn, &burned, big.NewInt(1), cap)
			require.Error(t, err)
			if !unique {
				partial, e := r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTBurn, &before, big.NewInt(2), cap)
				require.NoError(t, e)
				require.Equal(t, big.NewInt(5), partial.issued)
				require.Equal(t, big.NewInt(3), partial.live)
				_, e = r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTAddQuantity, &partial, big.NewInt(2), cap)
				require.Error(t, e, "new live units would fit but lifetime issuance exceeds the cap")
				successor, e := r.nonceSupplyAfter(family, core.BuiltInFunctionESDTNFTAddQuantity, &partial, big.NewInt(2), nil)
				require.NoError(t, e)
				require.Equal(t, big.NewInt(7), successor.issued)
				require.Equal(t, big.NewInt(5), successor.live)
			}
		}) {
			return
		}
	}
	for _, vector := range data.BadInner {
		if !t.Run(vector.ID, func(t *testing.T) {
			raw, key := qualA19Bytes(t, vector.Value), qualA19Bytes(t, vector.Key)
			var err error
			switch vector.ID {
			case "unique_empty", "unique_status02", "unique_status_0000", "quantity_leaf_in_unique_family":
				_, err = r.decodeNonceValue(core.DynamicNFT, raw)
			case "quantity_issued0_live0", "quantity_leading_zero", "quantity_live_above_issued", "unique_status_in_quantity_family":
				_, err = r.decodeNonceValue(core.DynamicSFT, raw)
			case "position_empty_existing_value", "position_leading_zero":
				_, err = r.decodeQuantityValue(raw)
			case "nonce_zero_nonfungible":
				_, err = r.decodeNonceKey(key, token, core.DynamicNFT)
			case "fungible_nonce_supply_key":
				_, err = r.decodeNonceKey(key, token, core.Fungible)
			case "position_nonce1_for_fungible":
				_, _, err = r.decodePositionKey(key, token, core.Fungible)
			case "position_nonce0_for_nonce_family", "inner_token_mismatch":
				_, _, err = r.decodePositionKey(key, token, core.DynamicMeta)
			default:
				t.Fatalf("unhandled frozen negative %q", vector.ID)
			}
			require.Error(t, err)
		}) {
			return
		}
	}
}

func TestQualDRWAStructuralV1PositionMap(t *testing.T) {
	data, r := qualStructuralV1Data(t), qualRootLeafCodec(t)
	pos := make(map[string]qualStructuralOuter)
	for _, vector := range data.Positive {
		pos[vector.ID] = vector
	}
	key1 := qualA19Bytes(t, data.Inner[2].PositionKey)
	key2 := bytes.Clone(key1)
	copy(key2[len(key2)-32:], bytes.Repeat([]byte{0x22}, 32))
	first := []positionLeafChange{{key1, nil, []byte{5}}}
	move := []positionLeafChange{{key1, []byte{5}, []byte{3}}, {key2, nil, []byte{2}}}
	same := []positionLeafChange{{key1, []byte{3}, []byte{3}}, {key2, []byte{2}, []byte{2}}}
	for _, tc := range []struct {
		from, to   string
		mapChanges []positionLeafChange
		changed    bool
	}{
		{"SemiFungible_position_init", "SemiFungible_position_first_changed", first, true},
		{"SemiFungible_position_first_changed", "SemiFungible_position_balanced_move", move, true},
		{"SemiFungible_position_balanced_move", "SemiFungible_position_net_identical", same, false},
	} {
		if !t.Run(tc.to, func(t *testing.T) {
			before, e := r.decodePositionRecord(qualA19Bytes(t, pos[tc.from].Encoded))
			require.NoError(t, e)
			total, version, changed, e := r.positionMapAfter(before, tc.mapChanges, 2)
			require.NoError(t, e)
			require.Equal(t, tc.changed, changed)
			next := *before
			next.quantity, next.version = total, version
			if changed {
				// The root comes from the independent final-map vector. The
				// operation version calculation performs no native write.
				next.root = qualA19Bytes(t, pos[tc.to].Fields[4])
			}
			raw, e := r.encodePositionRecord(&next)
			require.NoError(t, e)
			require.Equal(t, qualA19Bytes(t, pos[tc.to].Encoded), raw)
			unchanged, e := r.encodePositionRecord(before)
			require.NoError(t, e)
			require.Equal(t, qualA19Bytes(t, pos[tc.from].Encoded), unchanged)
		}) {
			return
		}
	}
	for _, vector := range data.Transitions {
		if !t.Run(vector.ID, func(t *testing.T) {
			raw := qualA19Bytes(t, vector.Before.Encoded)
			switch vector.ID {
			case "position_changed_overflow":
				before, e := r.decodePositionRecord(raw)
				require.NoError(t, e)
				total, _, changed, e := r.positionMapAfter(before,
					[]positionLeafChange{{key1, []byte{3}, []byte{5}}, {key2, []byte{2}, nil}}, 2)
				require.Error(t, e)
				require.Nil(t, total)
				require.False(t, changed)
			case "position_identical_at_max":
				before, e := r.decodePositionRecord(raw)
				require.NoError(t, e)
				total, version, changed, e := r.positionMapAfter(before, same, 2)
				require.NoError(t, e)
				require.False(t, changed)
				before.quantity, before.version = total, version
				actual, e := r.encodePositionRecord(before)
				require.NoError(t, e)
				require.Equal(t, raw, actual)
			case "supply_action_nonce_overflow":
				before, e := r.decodeSupplyRecord(raw)
				require.NoError(t, e)
				actual, e := before.accounting.advance(^uint64(0), false, big.NewInt(5), nil, 32)
				require.ErrorIs(t, e, errSupplyAccounting)
				require.Nil(t, actual)
			default:
				t.Fatalf("unhandled frozen transition %q", vector.ID)
			}
		}) {
			return
		}
	}
	t.Run("bad_final_map", func(t *testing.T) {
		before, err := r.decodePositionRecord(qualA19Bytes(t, pos["SemiFungible_position_first_changed"].Encoded))
		require.NoError(t, err)
		for _, changes := range [][]positionLeafChange{
			{move[1], move[0]},
			{move[0], move[0]},
			{{key1, []byte{}, []byte{5}}},
			{{key1, []byte{5}, []byte{0, 5}}},
			{{key1, []byte{5}, bytes.Repeat([]byte{1}, 33)}},
			{{key1, []byte{5, 1}, nil}},
		} {
			_, _, _, e := r.positionMapAfter(before, changes, 2)
			require.ErrorIs(t, e, errSetupLocalState)
		}
		_, _, _, err = r.positionMapAfter(before, move, 1)
		require.ErrorIs(t, err, errSetupLocalState)
	})
	t.Run("delete_last_position", func(t *testing.T) {
		before, err := r.decodePositionRecord(qualA19Bytes(t, pos["SemiFungible_position_first_changed"].Encoded))
		require.NoError(t, err)
		total, version, changed, err := r.positionMapAfter(before, []positionLeafChange{{key1, []byte{5}, nil}}, 2)
		require.NoError(t, err)
		require.True(t, changed)
		require.Zero(t, total.Sign())
		require.Equal(t, uint64(2), version)
		next := *before
		next.quantity, next.version = total, version
		_, err = r.encodePositionRecord(&next)
		require.ErrorIs(t, err, errSupplyPositionRecord, "the populated predecessor root cannot survive zero tracked units")
		next.root = qualSetupRoot()
		_, err = r.encodePositionRecord(&next)
		require.NoError(t, err)
	})
}

func TestQualDRWAStructuralV1NativeNodes(t *testing.T) {
	data := qualStructuralV1Data(t)
	for _, name := range []string{"unique_live", "unique_burned", "quantity_live5", "quantity_burned5", "position_nonce1_holder11_5", "position_nonce0_holder11_5"} {
		if !t.Run(name, func(t *testing.T) {
			vector, exists := data.NativeNodes[name]
			require.True(t, exists)
			args := qualReaderArgs(false)
			native, err := trie.NewTrie(args.StorageManager, args.Marshaller, args.Hasher,
				args.EnableEpochsHandler, args.MaxTrieLevelInMemory)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, native.Close()) })
			key, value := qualA19Bytes(t, vector.Key), qualA19Bytes(t, vector.Value)
			require.NotEmpty(t, value)
			require.NoError(t, native.UpdateWithVersion(key, value, core.NotSpecified))
			root, err := native.RootHash()
			require.NoError(t, err)
			require.Equal(t, qualA19Bytes(t, vector.Root), root)
			got, version, err := native.Get(key)
			require.NoError(t, err)
			require.Equal(t, uint32(core.NotSpecified), version)
			require.Equal(t, value, got)
			proof, proofValue, err := native.GetProof(key)
			require.NoError(t, err)
			require.Equal(t, value, proofValue)
			require.Equal(t, [][]byte{qualA19Bytes(t, vector.Node)}, proof)
		}) {
			return
		}
	}
}

// Literal fields copied from A19_STRUCTURAL_V1_INDEPENDENT_EXPECTATIONS_20261121.json
// SHA-256 f6d2bb8bc48fa7ac2eab680b678a742491611f53965346e039bc94f841b681e7.
// XV-A19-ROOT-001..004 and XV-A19-STRUCT-KAT-001, experimental profile only.
const qualStructuralV1Literals = `{
  "locators": {
    "address_hex":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "supply_key_hex":"454c524f4e444452574140737570706c79400a0c544f4b454e2d616263646566",
    "position_key_hex":"454c524f4e444452574140706f736974696f6e73400a0c544f4b454e2d616263646566"
  },
  "outer_positive": [
    {"id":"Fungible_supply_init","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000000","1111111111111111111111111111111111111111111111111111111111111111","00000001","","","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000000a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a000a000a000a080000000000000000"},
    {"id":"Fungible_position_init","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000000","01","0000000000000000000000000000000000000000000000000000000000000000","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000000a01010a2000000000000000000000000000000000000000000000000000000000000000000a000a080000000000000000"},
    {"id":"Fungible_supply_created","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000000","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","05","","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000000a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a000a080000000000000001"},
    {"id":"Fungible_supply_full_burn","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000000","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","","","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000000a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a000a000a080000000000000002"},
    {"id":"Fungible_position_first_changed","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000000","01","dc9e2f8d64a4c1f343fcac547042c24d3116157fbae02045c3b1b1dd3d4415fb","05","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000000a01010a20dc9e2f8d64a4c1f343fcac547042c24d3116157fbae02045c3b1b1dd3d4415fb0a01050a080000000000000001"},
    {"id":"NonFungibleV2_supply_init","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000002","1111111111111111111111111111111111111111111111111111111111111111","00000001","","","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000020a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a000a000a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000000"},
    {"id":"NonFungibleV2_position_init","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000002","01","0000000000000000000000000000000000000000000000000000000000000000","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000020a01010a2000000000000000000000000000000000000000000000000000000000000000000a000a080000000000000000"},
    {"id":"NonFungibleV2_supply_created","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000002","1111111111111111111111111111111111111111111111111111111111111111","00000001","01","01","c1bb71020b1a8a33abf56885fb70317e54cf6948beae712eac63f47f002b2626","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000020a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01010a01010a20c1bb71020b1a8a33abf56885fb70317e54cf6948beae712eac63f47f002b26260a080000000000000001"},
    {"id":"NonFungibleV2_supply_full_burn","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000002","1111111111111111111111111111111111111111111111111111111111111111","00000001","01","","75a0171b018ba45b8ca2fc16aa6985babcbbadf7a98af1598476e2c902a1975b","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000020a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01010a000a2075a0171b018ba45b8ca2fc16aa6985babcbbadf7a98af1598476e2c902a1975b0a080000000000000002"},
    {"id":"NonFungibleV2_position_first_changed","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000002","01","2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81","05","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000020a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"SemiFungible_supply_init","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000003","1111111111111111111111111111111111111111111111111111111111111111","00000001","","","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a000a000a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000000"},
    {"id":"SemiFungible_position_init","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000003","01","0000000000000000000000000000000000000000000000000000000000000000","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a2000000000000000000000000000000000000000000000000000000000000000000a000a080000000000000000"},
    {"id":"SemiFungible_supply_created","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000003","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","05","96b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"SemiFungible_supply_full_burn","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000003","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","","4b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af58","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a000a204b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af580a080000000000000002"},
    {"id":"SemiFungible_position_first_changed","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000003","01","2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81","05","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"MetaFungible_supply_init","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000004","1111111111111111111111111111111111111111111111111111111111111111","00000001","","","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000040a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a000a000a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000000"},
    {"id":"MetaFungible_position_init","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000004","01","0000000000000000000000000000000000000000000000000000000000000000","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000040a01010a2000000000000000000000000000000000000000000000000000000000000000000a000a080000000000000000"},
    {"id":"MetaFungible_supply_created","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000004","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","05","96b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000040a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"MetaFungible_supply_full_burn","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000004","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","","4b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af58","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000040a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a000a204b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af580a080000000000000002"},
    {"id":"MetaFungible_position_first_changed","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000004","01","2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81","05","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000040a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"DynamicNFT_supply_init","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000005","1111111111111111111111111111111111111111111111111111111111111111","00000001","","","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000050a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a000a000a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000000"},
    {"id":"DynamicNFT_position_init","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000005","01","0000000000000000000000000000000000000000000000000000000000000000","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000050a01010a2000000000000000000000000000000000000000000000000000000000000000000a000a080000000000000000"},
    {"id":"DynamicNFT_supply_created","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000005","1111111111111111111111111111111111111111111111111111111111111111","00000001","01","01","c1bb71020b1a8a33abf56885fb70317e54cf6948beae712eac63f47f002b2626","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000050a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01010a01010a20c1bb71020b1a8a33abf56885fb70317e54cf6948beae712eac63f47f002b26260a080000000000000001"},
    {"id":"DynamicNFT_supply_full_burn","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000005","1111111111111111111111111111111111111111111111111111111111111111","00000001","01","","75a0171b018ba45b8ca2fc16aa6985babcbbadf7a98af1598476e2c902a1975b","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000050a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01010a000a2075a0171b018ba45b8ca2fc16aa6985babcbbadf7a98af1598476e2c902a1975b0a080000000000000002"},
    {"id":"DynamicNFT_position_first_changed","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000005","01","2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81","05","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000050a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"DynamicSFT_supply_init","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000006","1111111111111111111111111111111111111111111111111111111111111111","00000001","","","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000060a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a000a000a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000000"},
    {"id":"DynamicSFT_position_init","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000006","01","0000000000000000000000000000000000000000000000000000000000000000","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000060a01010a2000000000000000000000000000000000000000000000000000000000000000000a000a080000000000000000"},
    {"id":"DynamicSFT_supply_created","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000006","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","05","96b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000060a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"DynamicSFT_supply_full_burn","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000006","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","","4b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af58","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000060a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a000a204b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af580a080000000000000002"},
    {"id":"DynamicSFT_position_first_changed","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000006","01","2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81","05","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000060a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"DynamicMeta_supply_init","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000007","1111111111111111111111111111111111111111111111111111111111111111","00000001","","","0000000000000000000000000000000000000000000000000000000000000000","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000070a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a000a000a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000000"},
    {"id":"DynamicMeta_position_init","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000007","01","0000000000000000000000000000000000000000000000000000000000000000","","0000000000000000"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000070a01010a2000000000000000000000000000000000000000000000000000000000000000000a000a080000000000000000"},
    {"id":"DynamicMeta_supply_created","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000007","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","05","96b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000070a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"DynamicMeta_supply_full_burn","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000007","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","","4b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af58","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000070a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a000a204b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af580a080000000000000002"},
    {"id":"DynamicMeta_position_first_changed","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000007","01","2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81","05","0000000000000001"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000070a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"SemiFungible_position_balanced_move","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000003","01","242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b","05","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a20242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b0a01050a080000000000000002"},
    {"id":"SemiFungible_position_net_identical","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000003","01","242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b","05","0000000000000002"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a20242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b0a01050a080000000000000002"}
  ],
  "outer_negative": [
    {"id":"old_supply7","kind":"Supply","encoded_hex":"0a0c544f4b454e2d6162636465660a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"old_position5","kind":"Position","encoded_hex":"0a0c544f4b454e2d6162636465660a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"Supply_unknown_V2","kind":"Supply","encoded_hex":"0a04000000020a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"Supply_short_version","kind":"Supply","encoded_hex":"0a01010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"Supply_legacy_type1","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000010a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"Supply_wrong_family","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000020a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"Supply_token_mismatch","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465650a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"Supply_overlong_length","kind":"Supply","encoded_hex":"0a8400000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"Supply_truncated_varint","kind":"Supply","encoded_hex":"0a80"},
    {"id":"Supply_unknown_tag","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a0800000000000000011001"},
    {"id":"Supply_extra_item","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a0800000000000000010a00"},
    {"id":"Supply_missing_item","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04"},
    {"id":"Position_unknown_V2","kind":"Position","encoded_hex":"0a04000000020a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"Position_short_version","kind":"Position","encoded_hex":"0a01010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"Position_legacy_type1","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000010a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"Position_wrong_family","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000020a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"Position_token_mismatch","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465650a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"Position_overlong_length","kind":"Position","encoded_hex":"0a8400000000010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"Position_truncated_varint","kind":"Position","encoded_hex":"0a80"},
    {"id":"Position_unknown_tag","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a0800000000000000011001"},
    {"id":"Position_extra_item","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a0800000000000000010a00"},
    {"id":"Position_missing_item","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a0105"},
    {"id":"supply_issued_leading_zero","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a0200050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"supply_zero_as_00","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01000a000a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000000"},
    {"id":"supply_live_above_issued","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01030a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"supply_origin_short","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a1f111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"supply_shard_short","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a01010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a080000000000000001"},
    {"id":"supply_nonce_short","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a0101"},
    {"id":"nonce_family_empty_root_item","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a000a080000000000000001"},
    {"id":"nonce_family_short_root","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a1f000000000000000000000000000000000000000000000000000000000000000a080000000000000001"},
    {"id":"fungible_supply_child","kind":"Supply","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000000a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2000000000000000000000000000000000000000000000000000000000000000000a080000000000000001"},
    {"id":"position_short_root","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a1f000000000000000000000000000000000000000000000000000000000000000a01050a080000000000000001"},
    {"id":"position_uninitialized_marker","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01000a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"position_marker_extra","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a0201000a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a01050a080000000000000001"},
    {"id":"position_sum_leading_zero","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a0200050a080000000000000001"},
    {"id":"position_empty_root_positive_sum","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a2000000000000000000000000000000000000000000000000000000000000000000a01050a080000000000000001"},
    {"id":"position_populated_root_zero_sum","kind":"Position","encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a202e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f810a000a080000000000000001"}
  ],
  "inner_leaf_vectors": [
    {"family":"Fungible","type_code":0,"position_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000000a201111111111111111111111111111111111111111111111111111111111111111","position_value_hex":"05","nonce_key_hex":null,"nonce_live_value_hex":null,"nonce_burned_value_hex":null},
    {"family":"NonFungibleV2","type_code":2,"position_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111","position_value_hex":"05","nonce_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","nonce_live_value_hex":"01","nonce_burned_value_hex":"00"},
    {"family":"SemiFungible","type_code":3,"position_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111","position_value_hex":"05","nonce_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","nonce_live_value_hex":"0a01050a0105","nonce_burned_value_hex":"0a01050a00"},
    {"family":"MetaFungible","type_code":4,"position_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111","position_value_hex":"05","nonce_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","nonce_live_value_hex":"0a01050a0105","nonce_burned_value_hex":"0a01050a00"},
    {"family":"DynamicNFT","type_code":5,"position_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111","position_value_hex":"05","nonce_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","nonce_live_value_hex":"01","nonce_burned_value_hex":"00"},
    {"family":"DynamicSFT","type_code":6,"position_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111","position_value_hex":"05","nonce_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","nonce_live_value_hex":"0a01050a0105","nonce_burned_value_hex":"0a01050a00"},
    {"family":"DynamicMeta","type_code":7,"position_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111","position_value_hex":"05","nonce_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","nonce_live_value_hex":"0a01050a0105","nonce_burned_value_hex":"0a01050a00"}
  ],
  "inner_negative": [
    {"id":"unique_empty","raw_value_hex":""},
    {"id":"unique_status02","raw_value_hex":"02"},
    {"id":"unique_status_0000","raw_value_hex":"0000"},
    {"id":"quantity_issued0_live0","raw_value_hex":"0a000a00"},
    {"id":"quantity_leading_zero","raw_value_hex":"0a0200050a00"},
    {"id":"quantity_live_above_issued","raw_value_hex":"0a01030a0105"},
    {"id":"quantity_leaf_in_unique_family","raw_value_hex":"0a01050a00"},
    {"id":"unique_status_in_quantity_family","raw_value_hex":"00"},
    {"id":"position_empty_existing_value","raw_value_hex":""},
    {"id":"position_leading_zero","raw_value_hex":"0005"},
    {"id":"nonce_zero_nonfungible","raw_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000000"},
    {"id":"fungible_nonce_supply_key","raw_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000000"},
    {"id":"position_nonce1_for_fungible","raw_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111"},
    {"id":"position_nonce0_for_nonce_family","raw_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000000a201111111111111111111111111111111111111111111111111111111111111111"},
    {"id":"inner_token_mismatch","raw_key_hex":"0a0c544f4b454e2d6162636465650a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111"}
  ],
  "transition_expectations": [
    {"id":"position_changed_overflow","before":{"id":"max_position","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000003","01","242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b","05","ffffffffffffffff"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a20242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b0a01050a08ffffffffffffffff"}},
    {"id":"position_identical_at_max","before":{"id":"max_position","kind":"PositionF7","fields_hex":["00000001","544f4b454e2d616263646566","00000003","01","242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b","05","ffffffffffffffff"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a01010a20242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b0a01050a08ffffffffffffffff"}},
    {"id":"supply_action_nonce_overflow","before":{"id":"max_supply","kind":"SupplyF9","fields_hex":["00000001","544f4b454e2d616263646566","00000003","1111111111111111111111111111111111111111111111111111111111111111","00000001","05","05","96b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04","ffffffffffffffff"],"encoded_hex":"0a04000000010a0c544f4b454e2d6162636465660a04000000030a2011111111111111111111111111111111111111111111111111111111111111110a04000000010a01050a01050a2096b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c040a08ffffffffffffffff"}}
  ],
  "experimental_native_single_leaf_nodes": {
    "unique_live":{"raw_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","value_hex":"01","encoded_node_hex":"0a310100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010101","root_hex":"c1bb71020b1a8a33abf56885fb70317e54cf6948beae712eac63f47f002b2626"},
    "unique_burned":{"raw_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","value_hex":"00","encoded_node_hex":"0a310100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010001","root_hex":"75a0171b018ba45b8ca2fc16aa6985babcbbadf7a98af1598476e2c902a1975b"},
    "quantity_live5":{"raw_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","value_hex":"0a01050a0105","encoded_node_hex":"0a310100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012060a01050a010501","root_hex":"96b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04"},
    "quantity_burned5":{"raw_key_hex":"0a0c544f4b454e2d6162636465660a080000000000000001","value_hex":"0a01050a00","encoded_node_hex":"0a310100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012050a01050a0001","root_hex":"4b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af58"},
    "position_nonce1_holder11_5":{"raw_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111","value_hex":"05","encoded_node_hex":"0a750101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010501","root_hex":"2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81"},
    "position_nonce0_holder11_5":{"raw_key_hex":"0a0c544f4b454e2d6162636465660a0800000000000000000a201111111111111111111111111111111111111111111111111111111111111111","value_hex":"05","encoded_node_hex":"0a750101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000000000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010501","root_hex":"dc9e2f8d64a4c1f343fcac547042c24d3116157fbae02045c3b1b1dd3d4415fb"}
  }
}`
