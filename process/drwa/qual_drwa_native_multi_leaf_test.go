package drwa

import (
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/trie/keyBuilder"
	"github.com/stretchr/testify/require"
)

type qualMultiLeaf struct {
	key, value, node, nibbles, hash                   string
	slot                                              byte
	compressedNode, compressedNibbles, compressedRoot string
}

type qualMultiLeafCase struct {
	name, root, branch, missingKey string
	leaves                         [2]qualMultiLeaf
}

// XV-A19-ROOT-001..004. Literal bytes copied from the independently frozen
// A19_INDEPENDENT_MULTI_LEAF_EXPECTATIONS_20261121.json, SHA-256
// 1a75d14bebfeb09d1cd033237140dcfc7ca9643967c7743ec98c90379d61449c.
// The registered keys differ at the first nibble. Their proof has a root
// branch and one leaf, with no extension.
func TestQualDRWANativeMultiLeafVectors(t *testing.T) {
	cases := []qualMultiLeafCase{
		{
			name:   "position_nonce1_holder11_quantity3_holder22_quantity2",
			root:   "242b9294f730fc6e16975a94449cef9f1843609f81b16d9042106dcd4c2e509b",
			branch: "0a000a20827c1c15e4e0fc686018504cf4b7311600eab6408845d3b8d4689f3ff81065a90a20221cb1d0631097be4349a0683acde79edb6f0e0349fc17ad7cb4ae62d06c78590a000a000a000a000a000a000a000a000a000a000a000a000a000a0002",
			leaves: [2]qualMultiLeaf{
				{
					key:               "0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111",
					value:             "03",
					node:              "0a7401010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010301",
					nibbles:           "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					hash:              "827c1c15e4e0fc686018504cf4b7311600eab6408845d3b8d4689f3ff81065a9",
					compressedNode:    "0a750101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010301",
					compressedNibbles: "0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					compressedRoot:    "5c1d0fbad9ab48c429da46f6b4e010a004332a831b0dbd33780512b03502be67",
					slot:              1,
				},
				{
					key:               "0a0c544f4b454e2d6162636465660a0800000000000000010a202222222222222222222222222222222222222222222222222222222222222222",
					value:             "02",
					node:              "0a7402020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010201",
					nibbles:           "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					hash:              "221cb1d0631097be4349a0683acde79edb6f0e0349fc17ad7cb4ae62d06c7859",
					compressedNode:    "0a750202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010201",
					compressedNibbles: "0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					compressedRoot:    "11f4f1452cbbee683f1816dfa62e847d89c2da70c3d7b90b4d2108ea793edaf1",
					slot:              2,
				},
			},
		},
		{
			name:       "nonce1_issued5_live0_nonce2_issued5_live5",
			missingKey: "0a0c544f4b454e2d6162636465660a080000000000000000",
			root:       "d971616d9149f9e2f1f57738616ea53224f3e3019fc500b35fe87c3c8f1d1999",
			branch:     "0a000a20d17ad81fcbe271db2b7d38b009f0ee27b1c7833c9f3518aa5de4ddc7b5de107e0a20852cc3f5edb2feb98f55e713902d65cbdb6bcba6d1c46557e37a7875f5e8900d0a000a000a000a000a000a000a000a000a000a000a000a000a000a0002",
			leaves: [2]qualMultiLeaf{
				{
					key:               "0a0c544f4b454e2d6162636465660a080000000000000001",
					value:             "0a01050a00",
					node:              "0a3000000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012050a01050a0001",
					nibbles:           "00000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					hash:              "d17ad81fcbe271db2b7d38b009f0ee27b1c7833c9f3518aa5de4ddc7b5de107e",
					compressedNode:    "0a310100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012050a01050a0001",
					compressedNibbles: "0100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					compressedRoot:    "4b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af58",
					slot:              1,
				},
				{
					key:               "0a0c544f4b454e2d6162636465660a080000000000000002",
					value:             "0a01050a0105",
					node:              "0a3000000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012060a01050a010501",
					nibbles:           "00000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					hash:              "852cc3f5edb2feb98f55e713902d65cbdb6bcba6d1c46557e37a7875f5e8900d",
					compressedNode:    "0a310200000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012060a01050a010501",
					compressedNibbles: "0200000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
					compressedRoot:    "ec1cac4b82ce90521b89f23dc2b04d3c3230823731d8f8b4fd9e32a9d426534a",
					slot:              2,
				},
			},
		},
	}
	const emptyRoot = "0000000000000000000000000000000000000000000000000000000000000000"
	for _, tc := range cases {
		if !t.Run(tc.name, func(t *testing.T) {
			for _, order := range []struct {
				name  string
				first int
			}{{"forward", 0}, {"reverse", 1}} {
				if !t.Run(order.name, func(t *testing.T) {
					qualCheckNativeMultiLeaf(t, tc, order.first, emptyRoot)
				}) {
					return
				}
			}
		}) {
			return // Stop on the first disagreement with the frozen bytes.
		}
	}
}

type qualTrieWithQueryProof interface {
	common.Trie
	GetProofForQuery([]byte) ([][]byte, []byte, error)
}

func qualA19Bytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func qualCheckNativeMultiLeaf(t *testing.T, tc qualMultiLeafCase, first int, emptyRoot string) {
	t.Helper()
	args := qualReaderArgs(false)
	native, err := trie.NewTrie(args.StorageManager, args.Marshaller, args.Hasher,
		args.EnableEpochsHandler, args.MaxTrieLevelInMemory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, native.Close()) })

	ordered := [2]qualMultiLeaf{tc.leaves[first], tc.leaves[1-first]}
	for _, leaf := range ordered {
		require.NoError(t, native.Update(qualA19Bytes(t, leaf.key), qualA19Bytes(t, leaf.value)))
	}
	root, err := native.RootHash()
	t.Logf("two-leaf root=%x error=%v", root, err)
	require.NoError(t, err)
	require.Equal(t, qualA19Bytes(t, tc.root), root)
	branch := qualA19Bytes(t, tc.branch)
	for _, leaf := range tc.leaves {
		qualCheckA19Inclusion(t, native, root, leaf, branch)
	}

	// The nonce case keeps the issued5/live0 record throughout. Explicitly
	// deleting nonce2 here exercises raw trie structure only, not a supply effect.
	if tc.missingKey != "" {
		missing := qualA19Bytes(t, tc.missingKey)
		qualCheckA19Missing(t, native, root, missing, [][]byte{branch}, trie.ErrNodeNotFound)
		removed, kept := tc.leaves[1], tc.leaves[0]
		require.NoError(t, native.Delete(qualA19Bytes(t, removed.key)))
		qualCheckA19Compression(t, native, removed, kept)
		return
	}

	// An empty scalar update deletes a position leaf in this raw fixture.
	// Reversing the insertion order also exercises the opposite compression path.
	removed, kept := ordered[0], ordered[1]
	require.NoError(t, native.Update(qualA19Bytes(t, removed.key), nil))
	qualCheckA19Compression(t, native, removed, kept)
	last := qualA19Bytes(t, kept.key)
	require.NoError(t, native.Update(last, nil))
	root, err = native.RootHash()
	t.Logf("after final scalar deletion root=%x error=%v", root, err)
	require.NoError(t, err)
	require.Equal(t, qualA19Bytes(t, emptyRoot), root)
	qualCheckA19Missing(t, native, root, last, nil, trie.ErrNilNode)
}

func qualCheckA19Compression(t *testing.T, native qualTrieWithQueryProof, removed, kept qualMultiLeaf) {
	t.Helper()
	root, err := native.RootHash()
	t.Logf("compressed root=%x error=%v", root, err)
	require.NoError(t, err)
	require.Equal(t, qualA19Bytes(t, kept.compressedRoot), root)
	qualCheckA19Inclusion(t, native, root, kept, nil)
	qualCheckA19Missing(t, native, root, qualA19Bytes(t, removed.key),
		[][]byte{qualA19Bytes(t, kept.compressedNode)}, trie.ErrNodeNotFound)
}

func qualCheckA19Inclusion(t *testing.T, native common.Trie, root []byte, want qualMultiLeaf, branch []byte) {
	t.Helper()
	key := qualA19Bytes(t, want.key)
	value, _, getErr := native.Get(key)
	proof, proofValue, proofErr := native.GetProof(key)
	t.Logf("inclusion key=%x value=%x proof_value=%x proof=%x errors=(%v,%v)", key, value, proofValue, proof, getErr, proofErr)
	require.NoError(t, getErr)
	require.NoError(t, proofErr)
	require.Equal(t, qualA19Bytes(t, want.value), value)
	require.Equal(t, value, proofValue)

	keyPath := keyBuilder.NewKeyBuilder()
	nibbles := want.compressedNibbles
	if branch != nil {
		require.Equal(t, [][]byte{branch, qualA19Bytes(t, want.node)}, proof, "root-to-leaf proof")
		var head trie.CollapsedBn
		require.NoError(t, head.Unmarshal(proof[0][:len(proof[0])-1]))
		require.Len(t, head.EncodedChildren, 17)
		require.Empty(t, head.ChildrenVersion)
		require.Equal(t, qualA19Bytes(t, want.hash), head.EncodedChildren[want.slot])
		keyPath.BuildKey([]byte{want.slot})
		nibbles = want.nibbles
	} else {
		require.Equal(t, [][]byte{qualA19Bytes(t, want.compressedNode)}, proof, "compressed leaf proof")
	}

	encodedLeaf := proof[len(proof)-1]
	var leaf trie.CollapsedLn
	require.NoError(t, leaf.Unmarshal(encodedLeaf[:len(encodedLeaf)-1]))
	require.Equal(t, qualA19Bytes(t, nibbles), leaf.Key)
	require.Equal(t, value, leaf.Value)
	require.Equal(t, uint32(core.NotSpecified), leaf.Version)
	keyPath.BuildKey(leaf.Key)
	actualKey, err := keyPath.GetKey()
	require.NoError(t, err)
	require.Equal(t, key, actualKey, "exact raw key reconstructed from proof")
	ok, err := native.VerifyProof(root, key, proof)
	require.NoError(t, err)
	require.True(t, ok)
}

func qualCheckA19Missing(t *testing.T, native qualTrieWithQueryProof, root, key []byte, wantPrefix [][]byte, wantErr error) {
	t.Helper()
	value, _, getErr := native.Get(key)
	prefix, proofValue, queryErr := native.GetProofForQuery(key)
	legacy, legacyValue, legacyErr := native.GetProof(key)
	ok, verifyErr := native.VerifyProof(root, key, prefix)
	t.Logf("missing key=%x value=%x prefix=%x proof_value=%x legacy=%x legacy_value=%x verify=%t errors=(%v,%v,%v,%v)",
		key, value, prefix, proofValue, legacy, legacyValue, ok, getErr, queryErr, legacyErr, verifyErr)
	require.NoError(t, getErr)
	require.Nil(t, value)
	require.Equal(t, wantPrefix, prefix)
	require.Nil(t, proofValue)
	require.ErrorIs(t, queryErr, wantErr)
	require.EqualError(t, queryErr, wantErr.Error())
	require.Nil(t, legacy)
	require.Nil(t, legacyValue)
	require.ErrorIs(t, legacyErr, wantErr)
	// Raw API observations only. A false result does not authenticate absence.
	require.NoError(t, verifyErr)
	require.False(t, ok)
}
