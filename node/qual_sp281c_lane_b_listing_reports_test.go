package node_test

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/keyValStorage"
	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/node"
	"github.com/multiversx/mx-chain-go/node/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryListingDecodeServiceError(t *testing.T) {
	codec := getMarshalizer()
	first, err := codec.Marshal(&systemSmartContracts.ESDTDataV2{TokenName: []byte("First"), TokenType: []byte(core.NonFungibleESDT), OwnerAddress: testscommon.TestPubKeyAlice})
	require.NoError(t, err)
	second, err := codec.Marshal(&systemSmartContracts.ESDTDataV2{TokenName: []byte("Second"), TokenType: []byte(core.NonFungibleESDT), OwnerAddress: testscommon.TestPubKeyAlice})
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	n := qualSP281CQueryNode(t, []core.KeyValueHolder{
		keyValStorage.NewKeyValStorage([]byte("FIRST-abcdef"), first),
		keyValStorage.NewKeyValStorage([]byte("SECOND-abcdef"), second),
	}, nil)
	proc := getDefaultProcessComponents()
	proc.ShardCoord = &mock.ShardCoordinatorMock{SelfShardId: core.MetachainShardId}
	components := getDefaultCoreComponents()
	decodeFailure := errors.New("ordinary decoder service error")
	var calls int
	components.IntMarsh = &marshallerMock.MarshalizerStub{
		UnmarshalCalled: func(obj interface{}, buff []byte) error {
			calls++
			if bytes.Equal(buff, first) {
				return decodeFailure
			}
			return codec.Unmarshal(obj, buff)
		},
	}
	require.NoError(t, n.ApplyOptions(node.WithProcessComponents(proc), node.WithCoreComponents(components)))
	tokens, _, err := n.GetNFTTokenIDsRegisteredByAddress(testscommon.TestAddressAlice, api.AccountQueryOptions{}, context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"SECOND-abcdef"}, tokens)
	require.Equal(t, 2, calls)
}

func TestQualSP281COrdinaryListingMetadataFormatError(t *testing.T) {
	key := core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "TOKEN-abcdef"
	creator := testscommon.TestPubKeyAlice
	n := qualSP281CQueryNode(t, []core.KeyValueHolder{keyValStorage.NewKeyValStorage([]byte(key), nil)}, nil)
	storage := &testscommon.EsdtStorageHandlerStub{
		GetESDTNFTTokenOnDestinationWithCustomSystemAccountCalled: func(_ vmcommon.UserAccountHandler, _ []byte, _ uint64, _ vmcommon.UserAccountHandler) (*esdt.ESDigitalToken, bool, error) {
			return &esdt.ESDigitalToken{Type: uint32(core.NonFungible), Value: big.NewInt(1), TokenMetaData: &esdt.MetaData{Nonce: 1, Creator: creator}}, false, nil
		},
	}
	components := getDefaultCoreComponents()
	converter := testscommon.RealWorldBech32PubkeyConverter
	formatFailure := errors.New("ordinary presentation formatter error")
	var calls int
	components.AddrPubKeyConv = &testscommon.PubkeyConverterStub{
		LenCalled:    converter.Len,
		DecodeCalled: converter.Decode,
		EncodeCalled: func(value []byte) (string, error) {
			calls++
			require.Equal(t, creator, value)
			return "", formatFailure
		},
	}
	require.NoError(t, n.ApplyOptions(node.WithCoreComponents(components), node.WithESDTNFTStorageHandler(storage)))
	tokens, block, err := n.GetAllESDTTokens(testscommon.TestAddressAlice, api.AccountQueryOptions{}, context.Background())
	require.ErrorIs(t, err, formatFailure)
	require.Nil(t, tokens)
	require.Equal(t, api.BlockInfo{}, block)
	require.Equal(t, 1, calls)
}
