package core

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common/holders"
	nativeFactory "github.com/multiversx/mx-chain-go/factory"
	dataFactory "github.com/multiversx/mx-chain-go/factory/data"
	stateFactory "github.com/multiversx/mx-chain-go/factory/state"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

func qualDRWACandidateStateComponents(t *testing.T, args dataFactory.DataComponentsFactoryArgs) (nativeFactory.StateComponentsHandler, nativeFactory.DataComponentsHandler) {
	t.Helper()
	dataNativeFactory, err := dataFactory.NewDataComponentsFactory(args)
	require.NoError(t, err)
	dataHandler, err := dataFactory.NewManagedDataComponents(dataNativeFactory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dataHandler.Close()) })
	require.NoError(t, dataHandler.Create())
	require.NoError(t, dataHandler.CheckSubcomponents())
	stateNativeFactory, err := stateFactory.NewStateComponentsFactory(stateFactory.StateComponentsFactoryArgs{
		Config: args.Config, Core: args.Core, StatusCore: args.StatusCore,
		StorageService: dataHandler.StorageService(), ProcessingMode: args.NodeProcessingMode,
		ChainHandler: dataHandler.Blockchain(), ShouldSerializeSnapshots: false,
	})
	require.NoError(t, err)
	handler, err := stateFactory.NewManagedStateComponents(stateNativeFactory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, handler.Close()) })
	require.NoError(t, handler.Create())
	require.NoError(t, handler.CheckSubcomponents())
	return handler, dataHandler
}

// T09-M31: actual native factory composition and ordinary account persistence.
// Synthetic header notifications are supplied before storage subscribers exist.
// The returned root is an operation handle, not an independent root-byte oracle.
// No DRWA authorization, genesis allocation, crash or canonical recovery claimed.
func TestQualDRWACandidateStateFactory(t *testing.T) {
	for _, epoch := range []uint32{0, 3} {
		for _, shard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
			t.Run(fmt.Sprintf("epoch_%d_shard_%d", epoch, shard), func(t *testing.T) {
				args := qualDRWACandidateDataArgs(t, epoch, shard)
				hdr := &block.Header{Epoch: epoch, Round: 440}
				args.Core.EpochStartNotifierWithConfirm().NotifyAll(hdr)
				args.Core.EpochNotifier().CheckEpoch(hdr)
				args.Core.RoundNotifier().CheckRound(hdr)
				address := bytes.Repeat([]byte{0x17}, args.Core.AddressPubKeyConverter().Len())
				key, value := []byte("T09 ordinary account probe"), []byte("native state reopen")
				var root []byte
				for _, reopen := range []bool{false, true} {
					handler, dataHandler := qualDRWACandidateStateComponents(t, args)
					require.NotNil(t, handler.PeerAccounts())
					require.NotNil(t, handler.AccountsAdapterAPI())
					require.NotNil(t, handler.AccountsAdapterProposal())
					require.NotNil(t, handler.AccountsRepository())
					require.NotNil(t, handler.TriesContainer())
					require.NotEmpty(t, handler.TrieStorageManagers())
					require.NotNil(t, handler.MissingTrieNodesNotifier())
					require.NotNil(t, handler.TrieLeavesRetriever())
					accounts := handler.AccountsAdapter()
					require.NotNil(t, accounts)
					if !reopen {
						missing, err := accounts.GetExistingAccount(address)
						require.ErrorIs(t, err, state.ErrAccNotFound)
						require.Nil(t, missing)
						account, err := accounts.LoadAccount(address)
						require.NoError(t, err)
						user, ok := account.(state.UserAccountHandler)
						require.True(t, ok)
						require.NoError(t, user.AddToBalance(big.NewInt(37)))
						require.NoError(t, user.SaveKeyValue(key, value))
						require.NoError(t, accounts.SaveAccount(user))
						root, err = accounts.Commit()
						require.NoError(t, err)
						require.NotEmpty(t, root)
					} else {
						require.NoError(t, accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
					}
					account, err := accounts.GetExistingAccount(address)
					require.NoError(t, err)
					user, ok := account.(state.UserAccountHandler)
					require.True(t, ok)
					require.Zero(t, user.GetBalance().Cmp(big.NewInt(37)))
					got, _, err := user.RetrieveValue(key)
					require.NoError(t, err)
					require.Equal(t, value, got)
					require.NoError(t, handler.Close())
					require.Nil(t, handler.AccountsAdapter())
					require.NoError(t, dataHandler.Close())
				}
			})
		}
	}
}
