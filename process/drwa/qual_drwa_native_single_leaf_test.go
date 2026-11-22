package drwa

import (
	"encoding/hex"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/stretchr/testify/require"
)

// XV-A19-ROOT-004 is an experimental in-memory profile, not a storage format.
// Expected hex is copied verbatim from Lane A's independent
// A19_INDEPENDENT_SINGLE_LEAF_EXPECTATIONS_20261121.json (SHA-256
// 67f19392c9e2ed8dbb46c5eaaf9a105eaed669d5860dabbe9a15d072d12cf9d0).
func TestQualDRWANativeSingleLeafVectors(t *testing.T) {
	const issued5Live5 = "0a01050a0105"
	cases := []struct {
		name, key, value, nibbles, node, root, previousValue string
	}{
		{
			name:    "position_single_5",
			key:     "0a0c544f4b454e2d6162636465660a0800000000000000010a201111111111111111111111111111111111111111111111111111111111111111",
			value:   "05",
			nibbles: "0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
			node:    "0a750101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100020a000100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012010501",
			root:    "2e0e03280caa7381ab4990b737bfdd4e0458f4c6571624b5ddfb1c73d8ce5f81",
		},
		{
			name:    "nonce_issued5_live5",
			key:     "0a0c544f4b454e2d6162636465660a080000000000000001",
			value:   issued5Live5,
			nibbles: "0100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
			node:    "0a310100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012060a01050a010501",
			root:    "96b7d0b917aa18eb7ed4878b769e7ad7fc78fbb418c8653d255f73e224953c04",
		},
		{
			name:          "nonce_issued5_live0",
			key:           "0a0c544f4b454e2d6162636465660a080000000000000001",
			value:         "0a01050a00",
			nibbles:       "0100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a0010",
			node:          "0a310100000000000000000000000000000008000a000606050604060306020601060d020e0405040b040f0404050c000a001012050a01050a0001",
			root:          "4b3d3442e9afd3238ad5dc36d04fd7f675c192e286e234d785223500baa7af58",
			previousValue: issued5Live5,
		},
	}
	for _, tc := range cases {
		if !t.Run(tc.name, func(t *testing.T) {
			decode := func(s string) []byte {
				raw, err := hex.DecodeString(s)
				require.NoError(t, err)
				return raw
			}

			args := qualReaderArgs(false)
			require.Equal(t, 32, args.Hasher.Size())
			native, err := trie.NewTrie(args.StorageManager, args.Marshaller, args.Hasher,
				args.EnableEpochsHandler, args.MaxTrieLevelInMemory)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, native.Close()) })

			key, value := decode(tc.key), decode(tc.value)
			if tc.previousValue != "" {
				// Model a value replacement at the same nonce, without a supply writer.
				require.NoError(t, native.Update(key, decode(tc.previousValue)))
			}
			require.NotEmpty(t, value)
			require.NoError(t, native.Update(key, value))

			root, rootErr := native.RootHash()
			got, _, getErr := native.Get(key)
			proof, proofValue, proofErr := native.GetProof(key)
			t.Logf("key=%x value=%x proof_value=%x root=%x proof=%x", key, got, proofValue, root, proof)
			require.NoError(t, rootErr)
			require.NoError(t, getErr)
			require.NoError(t, proofErr)
			require.Equal(t, decode(tc.root), root, "native root")
			require.Equal(t, decode(tc.value), got, "value at the exact raw key")
			require.Equal(t, got, proofValue, "proof value")
			require.Len(t, proof, 1)
			require.Equal(t, decode(tc.node), proof[0], "encoded native proof leaf")

			// The native node-type suffix is outside the protobuf.
			var leaf trie.CollapsedLn
			require.NoError(t, leaf.Unmarshal(proof[0][:len(proof[0])-1]))
			require.Equal(t, decode(tc.nibbles), leaf.Key, "native raw-key nibble path")
			require.Equal(t, got, leaf.Value, "encoded leaf value")
			require.Equal(t, uint32(core.NotSpecified), leaf.Version)
		}) {
			return // Preserve the first mismatch and leave dependent checks unrun.
		}
	}
}
