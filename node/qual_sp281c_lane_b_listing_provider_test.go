package node_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/keyValStorage"
	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/node"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryListingProviderInterfaceError(t *testing.T) {
	account := createAcc(testscommon.TestPubKeyAlice)
	account.SetDataTrie(&trieMock.TrieStub{})
	key := core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "TOKEN-abcdef"
	mockUser := &stateMock.StateUserAccountHandlerStub{
		DataTrieCalled: func() common.DataTrieHandler { return account.DataTrie() },
		GetAllLeavesCalled: func(ch *common.TrieIteratorChannels, _ context.Context) error {
			ch.LeavesChan <- keyValStorage.NewKeyValStorage([]byte(key), nil)
			close(ch.LeavesChan)
			return nil
		},
	}
	var _ state.UserAccountHandler = mockUser
	_, compatible := interface{}(mockUser).(vmcommon.UserAccountHandler)
	require.False(t, compatible)

	system := createAcc(core.SystemAccountAddress)
	n := getNodeWithAccount(&stateMock.AccountsStub{
		GetAccountWithBlockInfoCalled: func(address []byte, _ common.RootHashHolder) (vmcommon.AccountHandler, common.BlockInfo, error) {
			if bytes.Equal(address, core.SystemAccountAddress) {
				return system, nil, nil
			}
			require.Equal(t, testscommon.TestPubKeyAlice, address)
			return mockUser, nil, nil
		},
	})
	var lookups int
	storage := &testscommon.EsdtStorageHandlerStub{
		GetESDTNFTTokenOnDestinationWithCustomSystemAccountCalled: func(vmcommon.UserAccountHandler, []byte, uint64, vmcommon.UserAccountHandler) (*esdt.ESDigitalToken, bool, error) {
			lookups++
			return nil, false, nil
		},
	}
	require.NoError(t, n.ApplyOptions(node.WithESDTNFTStorageHandler(storage)))
	tokens, block, err := n.GetAllESDTTokens(testscommon.TestAddressAlice, api.AccountQueryOptions{}, context.Background())
	require.ErrorIs(t, err, node.ErrCannotCastUserAccountHandlerToVmCommonUserAccountHandler)
	require.Nil(t, tokens)
	require.Equal(t, api.BlockInfo{}, block)
	require.Zero(t, lookups)
}
