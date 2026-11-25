package node_test

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-core-go/core/keyValStorage"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/node"
	"github.com/multiversx/mx-chain-go/node/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
)

func TestQualSP281COrdinaryIssuedTokenFilter(t *testing.T) {
	fungible, err := getMarshalizer().Marshal(&systemSmartContracts.ESDTDataV2{TokenType: []byte(core.FungibleESDT)})
	require.NoError(t, err)
	nonFungible, err := getMarshalizer().Marshal(&systemSmartContracts.ESDTDataV2{TokenType: []byte(core.NonFungibleESDT)})
	require.NoError(t, err)

	leaves := []core.KeyValueHolder{
		keyValStorage.NewKeyValStorage([]byte("FIRST-abcdef"), fungible),
		keyValStorage.NewKeyValStorage([]byte("unrelated"), nil),
		keyValStorage.NewKeyValStorage([]byte("BAD-abcdef"), []byte{0xff}),
		keyValStorage.NewKeyValStorage([]byte("NFT-abcdef"), nonFungible),
		keyValStorage.NewKeyValStorage([]byte("SECOND-abcdef"), fungible),
	}
	n := qualSP281CQueryNode(t, leaves, nil)
	processComponents := getDefaultProcessComponents()
	processComponents.ShardCoord = &mock.ShardCoordinatorMock{SelfShardId: 0}
	require.NoError(t, n.ApplyOptions(node.WithProcessComponents(processComponents)))

	issued, err := n.GetAllIssuedESDTs("", context.Background())
	require.ErrorIs(t, err, node.ErrMetachainOnlyEndpoint)
	require.Nil(t, issued)

	processComponents.ShardCoord = &mock.ShardCoordinatorMock{SelfShardId: core.MetachainShardId}
	issued, err = n.GetAllIssuedESDTs("", context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"FIRST-abcdef", "BAD-abcdef", "NFT-abcdef", "SECOND-abcdef"}, issued)

	issued, err = n.GetAllIssuedESDTs(core.FungibleESDT, context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"FIRST-abcdef", "SECOND-abcdef"}, issued)
}

func TestQualSP281COrdinaryTokenQueriesDiscardPartialResults(t *testing.T) {
	ctx := context.Background()
	options := api.AccountQueryOptions{}
	terminal := errors.New("synthetic trie iterator failure")
	prefix := core.ProtectedKeyPrefix + core.ESDTKeyIdentifier
	record := &esdt.ESDigitalToken{Value: big.NewInt(7)}
	leaves := []core.KeyValueHolder{
		keyValStorage.NewKeyValStorage([]byte("k"), []byte("v")),
		keyValStorage.NewKeyValStorage([]byte(prefix+"FIRST-abcdef"), nil),
		keyValStorage.NewKeyValStorage([]byte(prefix+"ZERO-abcdef"), nil),
		keyValStorage.NewKeyValStorage([]byte(prefix+"MISS-abcdef"), nil),
	}

	for _, testCase := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "terminal error", err: terminal},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			n := qualSP281CQueryNode(t, leaves[:1], testCase.err)
			values, block, err := n.GetKeyValuePairs(testscommon.TestAddressAlice, options, ctx)
			if testCase.err == nil {
				require.NoError(t, err)
				require.Equal(t, map[string]string{"6b": "76"}, values)
			} else {
				require.ErrorIs(t, err, testCase.err)
				require.Nil(t, values)
				require.Equal(t, api.BlockInfo{}, block)
			}

			n = qualSP281CQueryNode(t, leaves, testCase.err)
			var lookups []string
			storage := &testscommon.EsdtStorageHandlerStub{
				GetESDTNFTTokenOnDestinationWithCustomSystemAccountCalled: func(_ vmcommon.UserAccountHandler, key []byte, nonce uint64, _ vmcommon.UserAccountHandler) (*esdt.ESDigitalToken, bool, error) {
					require.Zero(t, nonce)
					lookups = append(lookups, string(key))
					switch string(key) {
					case prefix + "FIRST-abcdef":
						return record, true, nil
					case prefix + "ZERO-abcdef":
						return &esdt.ESDigitalToken{Value: big.NewInt(0)}, true, nil
					default:
						return nil, false, errors.New("synthetic token storage miss")
					}
				},
			}
			require.NoError(t, n.ApplyOptions(node.WithESDTNFTStorageHandler(storage)))
			tokens, block, err := n.GetAllESDTTokens(testscommon.TestAddressAlice, options, ctx)
			require.Equal(t, []string{prefix + "FIRST-abcdef", prefix + "ZERO-abcdef", prefix + "MISS-abcdef"}, lookups)
			if testCase.err == nil {
				require.NoError(t, err)
				require.Equal(t, map[string]*esdt.ESDigitalToken{"FIRST-abcdef": record}, tokens)
			} else {
				require.ErrorIs(t, err, testCase.err)
				require.Nil(t, tokens)
				require.Equal(t, api.BlockInfo{}, block)
			}
		})
	}
}

func qualSP281CQueryNode(t *testing.T, leaves []core.KeyValueHolder, terminal error) *node.Node {
	t.Helper()
	account := createAcc(testscommon.TestPubKeyAlice)
	account.SetDataTrie(&trieMock.TrieStub{
		RootCalled: func() ([]byte, error) { return nil, nil },
		GetAllLeavesOnChannelCalled: func(channels *common.TrieIteratorChannels, _ context.Context, _ []byte, _ common.KeyBuilder, _ common.TrieLeafParser) error {
			for _, leaf := range leaves {
				channels.LeavesChan <- leaf
			}
			if terminal != nil {
				channels.ErrChan.WriteInChanNonBlocking(terminal)
			}
			close(channels.LeavesChan)
			channels.ErrChan.Close()
			return nil
		},
	})
	n := getNodeWithAccount(&stateMock.AccountsStub{
		GetAccountWithBlockInfoCalled: func(_ []byte, _ common.RootHashHolder) (vmcommon.AccountHandler, common.BlockInfo, error) {
			return account, nil, nil
		},
	})
	coreComponents := getDefaultCoreComponents()
	coreComponents.IntMarsh = getMarshalizer()
	require.NoError(t, n.ApplyOptions(node.WithCoreComponents(coreComponents)))
	return n
}
