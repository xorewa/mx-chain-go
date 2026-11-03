package trackableDataTrie_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/dataTrieValue"
	"github.com/multiversx/mx-chain-go/state/trackableDataTrie"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/stretchr/testify/require"
)

// Experimental thresholds/version/key/value, not production configuration.
func TestQualPartialsG11LoadedLeafConsumer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "epochs.toml")
	require.NoError(t, os.WriteFile(p, []byte("[EnableEpochs]\nFixDataTrieLeafValidationEnableEpoch=11\nFixCorrectSmallIntAndGasLimitsEnableEpoch=23\nOutputRollbackOnDestContextEnableEpoch=37\nKeepReturnDataOnAsyncTransferCallbackEnableEpoch=53\n"), 0600))
	cfg, e := common.LoadEpochConfig(p)
	require.NoError(t, e)
	h, e := enablers.NewEnableEpochsHandler(cfg.EnableEpochs, &epochNotifier.EpochNotifierStub{})
	require.NoError(t, e)
	for _, epoch := range []uint32{10, 11, 12, 10} {
		t.Run(fmt.Sprintf("epoch_%d", epoch), func(t *testing.T) {
			h.EpochConfirmed(epoch, 0)
			hasher := blake2b.NewBlake2b()
			codec := &marshal.GogoProtoMarshalizer{}
			tr, e := trie.NewTrie(&storageManager.StorageManagerStub{}, codec, hasher, h, 10)
			require.NoError(t, e)
			key, address := []byte("experimental-key"), []byte("experimental-account")
			b, e := codec.Marshal(&dataTrieValue.TrieLeafData{Key: key, Address: address, Value: []byte("value")})
			require.NoError(t, e)
			require.NoError(t, tr.UpdateWithVersion(hasher.Compute(string(key)), b, core.TrieNodeVersion(99)))
			tdt, e := trackableDataTrie.NewTrackableDataTrie(address, hasher, codec, h, &stateMock.StateAccessesCollectorStub{})
			require.NoError(t, e)
			tdt.SetDataTrie(tr)
			got, _, e := tdt.RetrieveValue(key)
			if epoch >= 11 {
				require.ErrorIs(t, e, state.ErrInvalidDataTrieLeaf, "loaded leaf consumer rejects unknown version")
			} else {
				require.NoError(t, e)
				require.Equal(t, []byte("value"), got, "loaded leaf legacy value")
			}
		})
	}
}
