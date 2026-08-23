//go:build !race

package process

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/genesis/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/sharding/nodesCoordinator"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

func TestPrototypeDRWAReceiverSeedsEmptyConfigPreservesProductionParentFingerprint(t *testing.T) {
	arg := prototypeReceiverGenesisArgument(t)
	creator, err := NewGenesisBlockCreator(arg)
	require.NoError(t, err)
	blocks, err := creator.CreateGenesisBlocks()
	require.NoError(t, err)

	shardIDs := make([]uint32, 0, len(blocks))
	for shardID := range blocks {
		shardIDs = append(shardIDs, shardID)
	}
	sort.Slice(shardIDs, func(first, second int) bool { return shardIDs[first] < shardIDs[second] })
	preimage := make([]byte, 0)
	for _, shardID := range shardIDs {
		headerBytes, marshalErr := arg.Core.InternalMarshalizer().Marshal(blocks[shardID])
		require.NoError(t, marshalErr)
		preimage = binary.BigEndian.AppendUint32(preimage, shardID)
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(blocks[shardID].GetRootHash())))
		preimage = append(preimage, blocks[shardID].GetRootHash()...)
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(headerBytes)))
		preimage = append(preimage, headerBytes...)
	}
	digest := sha256.Sum256(preimage)
	require.Equal(t, "85494394571c02319a44c4442400c1cacb45262a5b8d38335a27b633a1fd1c87", fmt.Sprintf("%x", digest))
	fmt.Printf("DRWA_EMPTY_GENESIS_FINGERPRINT=%x\n", digest)
}

func TestPrototypeDRWAReceiverSeedsFreshGenesisStoresExactRecordAndLeavesControlAbsent(t *testing.T) {
	arg := prototypeReceiverGenesisArgument(t)
	holderAddress := "a00102030405060708090001020304050607080900010203040506070809000a"
	arg.PrototypeDRWACEBEpoch = 7
	arg.PrototypeReceiverSeeds = []config.PrototypeDRWAReceiverSeedConfig{{
		HolderAddress:     holderAddress,
		TokenIdentifier:   "TOKEN-abcdef",
		InitialBalance:    "1000",
		CEBEpoch:          7,
		Admitted:          true,
		ValidThroughRound: 1000,
	}}

	creator, err := NewGenesisBlockCreator(arg)
	require.NoError(t, err)
	_, err = creator.CreateGenesisBlocks()
	require.NoError(t, err)

	holderBytes, err := arg.Core.AddressPubKeyConverter().Decode(holderAddress)
	require.NoError(t, err)
	accountHandler, err := arg.Accounts.GetExistingAccount(holderBytes)
	require.NoError(t, err)
	account, ok := accountHandler.(state.UserAccountHandler)
	require.True(t, ok)
	stored, _, err := account.RetrieveValue(drwaprototype.ReceiverGateStorageKey([]byte("TOKEN-abcdef")))
	require.NoError(t, err)
	record, err := drwaprototype.DecodeReceiverGateRecord(stored)
	require.NoError(t, err)
	require.Equal(t, holderBytes, record.Holder[:])
	require.Equal(t, uint32(7), record.CEBEpoch)
	require.True(t, record.Admitted)
	require.Equal(t, uint64(1000), record.ValidThroughRound)
	regulated, err := drwaprototype.IsPrototypeRegulatedToken(arg.Accounts, []byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.True(t, regulated)

	balanceKey := []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "TOKEN-abcdef")
	encodedBalance, _, err := account.RetrieveValue(balanceKey)
	require.NoError(t, err)
	canonicalBalance := &esdt.ESDigitalToken{}
	require.NoError(t, arg.Core.InternalMarshalizer().Unmarshal(canonicalBalance, encodedBalance))
	require.Equal(t, "1000", canonicalBalance.Value.String())
	require.Equal(t, uint32(core.Fungible), canonicalBalance.Type)

	control, _, err := account.RetrieveValue(drwaprototype.ReceiverGateStorageKey([]byte("OTHER-abcdef")))
	require.NoError(t, err)
	require.Empty(t, control)
	regulated, err = drwaprototype.IsPrototypeRegulatedToken(arg.Accounts, []byte("OTHER-abcdef"))
	require.NoError(t, err)
	require.False(t, regulated)
}

func prototypeReceiverGenesisArgument(t *testing.T) ArgsGenesisBlockCreator {
	scAddressBytes, err := hex.DecodeString("00000000000000000500761b8c4a25d3979359223208b412285f635e71300102")
	require.NoError(t, err)
	stakedAddr, err := hex.DecodeString("b00102030405060708090001020304050607080900010203040506070809000b")
	require.NoError(t, err)
	initialNodesSetup := &mock.InitialNodesHandlerStub{
		InitialNodesInfoCalled: func() (map[uint32][]nodesCoordinator.GenesisNodeInfoHandler, map[uint32][]nodesCoordinator.GenesisNodeInfoHandler) {
			return map[uint32][]nodesCoordinator.GenesisNodeInfoHandler{
				0: {
					&mock.GenesisNodeInfoHandlerMock{AddressBytesValue: scAddressBytes, PubKeyBytesValue: bytes.Repeat([]byte{1}, 96)},
					&mock.GenesisNodeInfoHandlerMock{AddressBytesValue: stakedAddr, PubKeyBytesValue: bytes.Repeat([]byte{2}, 96)},
				},
				1: {
					&mock.GenesisNodeInfoHandlerMock{AddressBytesValue: scAddressBytes, PubKeyBytesValue: bytes.Repeat([]byte{3}, 96)},
				},
			}, make(map[uint32][]nodesCoordinator.GenesisNodeInfoHandler)
		},
		MinNumberOfNodesCalled: func() uint32 { return 1 },
	}
	return createMockArgument(t, "testdata/genesisTest1.json", initialNodesSetup, big.NewInt(22000))
}
