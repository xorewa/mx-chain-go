package process

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	genesisMock "github.com/multiversx/mx-chain-go/genesis/mock"
	processErrors "github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
)

func TestValidateAndCanonicalizePrototypeDRWAReceiverSeeds(t *testing.T) {
	t.Parallel()

	holderOne := prototypeReceiverSeedAddress(1)
	holderTwo := prototypeReceiverSeedAddress(2)
	configured := []config.PrototypeDRWAReceiverSeedConfig{
		prototypeReceiverSeedConfig(holderTwo, "TOKEN-abcdef"),
		prototypeReceiverSeedConfig(holderOne, "ZETA-abcdef"),
		prototypeReceiverSeedConfig(holderOne, "ALPHA-abcdef"),
	}
	configured[0].Admitted = false
	arg := prototypeReceiverSeedArgs(configured)
	original := append([]config.PrototypeDRWAReceiverSeedConfig(nil), configured...)

	canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
	require.NoError(t, err)
	require.Equal(t, original, arg.PrototypeReceiverSeeds)
	require.Len(t, canonical, 3)
	require.Equal(t, holderOne, hex.EncodeToString(canonical[0].holderAddress))
	require.Equal(t, []byte("ALPHA-abcdef"), canonical[0].tokenID)
	require.Equal(t, holderOne, hex.EncodeToString(canonical[1].holderAddress))
	require.Equal(t, []byte("ZETA-abcdef"), canonical[1].tokenID)
	require.Equal(t, holderTwo, hex.EncodeToString(canonical[2].holderAddress))
	require.Equal(t, []byte("TOKEN-abcdef"), canonical[2].tokenID)

	for _, seed := range canonical {
		require.Equal(t, drwaprototype.ReceiverGateStorageKey(seed.tokenID), seed.storageKey)
		record, decodeErr := drwaprototype.DecodeReceiverGateRecord(seed.encodedRecord)
		require.NoError(t, decodeErr)
		require.Equal(t, seed.holderAddress, record.Holder[:])
		require.Equal(t, uint32(7), record.CEBEpoch)
		require.Equal(t, string(seed.tokenID) != "TOKEN-abcdef", record.Admitted)
		require.Equal(t, uint64(1000), record.ValidThroughRound)
	}
}

func TestValidateAndCanonicalizePrototypeDRWAReceiverSeedsRejectsEveryInvalidClass(t *testing.T) {
	t.Parallel()

	valid := prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(1), "TOKEN-abcdef")
	smartContractAddress := make([]byte, 32)
	smartContractAddress[core.NumInitCharactersForScAddress] = 1
	require.True(t, core.IsSmartContractAddress(smartContractAddress))

	tests := map[string]func(arg *ArgsGenesisBlockCreator){
		"holder decode": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].HolderAddress = "not-hex"
		},
		"holder length": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].HolderAddress = hex.EncodeToString(make([]byte, 31))
		},
		"zero holder": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].HolderAddress = hex.EncodeToString(make([]byte, 32))
		},
		"system holder": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].HolderAddress = hex.EncodeToString(vmcommon.SystemAccountAddress)
		},
		"smart contract holder": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].HolderAddress = hex.EncodeToString(smartContractAddress)
		},
		"invalid token": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].TokenIdentifier = "invalid"
		},
		"zero CEB": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].CEBEpoch = 0
		},
		"mismatched CEB": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].CEBEpoch++
		},
		"zero valid-through round": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].ValidThroughRound = 0
		},
		"non-ordinary shard": func(arg *ArgsGenesisBlockCreator) {
			arg.ShardCoordinator = &testscommon.ShardsCoordinatorMock{
				NoShards:     3,
				CurrentShard: 0,
				ComputeIdCalled: func(_ []byte) uint32 {
					return core.MetachainShardId
				},
			}
		},
		"duplicate holder and token": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds = append(arg.PrototypeReceiverSeeds, arg.PrototypeReceiverSeeds[0])
		},
	}

	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			arg := prototypeReceiverSeedArgs([]config.PrototypeDRWAReceiverSeedConfig{valid})
			mutate(&arg)
			_, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
			require.ErrorIs(t, err, ErrInvalidPrototypeDRWAReceiverSeeds)
		})
	}
}

func TestApplyPrototypeDRWAReceiverSeedsFiltersEachShardAndPersistsExactRecord(t *testing.T) {
	t.Parallel()

	configured := []config.PrototypeDRWAReceiverSeedConfig{
		prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(0), "ZERO-abcdef"),
		prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(1), "ONE-abcdef"),
		prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(2), "TWO-abcdef"),
	}

	for shardID := uint32(0); shardID < 3; shardID++ {
		shardID := shardID
		t.Run(hex.EncodeToString([]byte{byte(shardID)}), func(t *testing.T) {
			t.Parallel()

			arg := prototypeReceiverSeedArgs(configured)
			arg.ShardCoordinator.(*testscommon.ShardsCoordinatorMock).CurrentShard = shardID
			canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
			require.NoError(t, err)

			var storedKey []byte
			var storedValue []byte
			var savedAddress []byte
			arg.Accounts = &stateMock.AccountsStub{
				LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					account := &stateMock.UserAccountStub{Address: append([]byte(nil), address...)}
					account.SaveKeyValueCalled = func(key []byte, value []byte) error {
						storedKey = append([]byte(nil), key...)
						storedValue = append([]byte(nil), value...)
						return nil
					}
					return account, nil
				},
				SaveAccountCalled: func(account vmcommon.AccountHandler) error {
					savedAddress = append([]byte(nil), account.AddressBytes()...)
					return nil
				},
			}

			count, err := applyPrototypeDRWAReceiverSeeds(arg, canonical)
			require.NoError(t, err)
			require.Equal(t, 1, count)
			require.Equal(t, byte(shardID), savedAddress[len(savedAddress)-1])
			require.Equal(t, drwaprototype.ReceiverGateStorageKey(canonical[shardID].tokenID), storedKey)
			record, err := drwaprototype.DecodeReceiverGateRecord(storedValue)
			require.NoError(t, err)
			require.Equal(t, savedAddress, record.Holder[:])
		})
	}
}

func TestApplyPrototypeDRWAReceiverSeedsPreservesEveryStorageFailure(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected receiver seed failure")
	validArg := prototypeReceiverSeedArgs([]config.PrototypeDRWAReceiverSeedConfig{
		prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(0), "TOKEN-abcdef"),
	})
	canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(validArg)
	require.NoError(t, err)

	tests := map[string]struct {
		accounts func() *stateMock.AccountsStub
		expected error
	}{
		"load account": {
			accounts: func() *stateMock.AccountsStub {
				return &stateMock.AccountsStub{LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
					return nil, injected
				}}
			},
			expected: injected,
		},
		"wrong account type": {
			accounts: func() *stateMock.AccountsStub {
				return &stateMock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return accounts.NewPeerAccount(address)
				}}
			},
			expected: processErrors.ErrWrongTypeAssertion,
		},
		"save key value": {
			accounts: func() *stateMock.AccountsStub {
				return &stateMock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return &stateMock.UserAccountStub{Address: address, SaveKeyValueCalled: func(_, _ []byte) error {
						return injected
					}}, nil
				}}
			},
			expected: injected,
		},
		"save account": {
			accounts: func() *stateMock.AccountsStub {
				return &stateMock.AccountsStub{
					LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						return &stateMock.UserAccountStub{Address: address}, nil
					},
					SaveAccountCalled: func(_ vmcommon.AccountHandler) error { return injected },
				}
			},
			expected: injected,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			arg := validArg
			arg.Accounts = test.accounts()
			count, err := applyPrototypeDRWAReceiverSeeds(arg, canonical)
			require.Zero(t, count)
			require.ErrorIs(t, err, test.expected)
		})
	}
}

func TestCreateShardGenesisBlockRejectsReceiverSeedsOnHardForkBeforeDependencies(t *testing.T) {
	t.Parallel()

	arg := ArgsGenesisBlockCreator{
		StartEpochNum:          10,
		HardForkConfig:         config.HardforkConfig{AfterHardFork: true, StartEpoch: 10},
		PrototypeReceiverSeeds: []config.PrototypeDRWAReceiverSeedConfig{{HolderAddress: "not-evaluated"}},
	}

	_, _, _, err := CreateShardGenesisBlock(arg, nil, nil, nil)
	require.ErrorIs(t, err, ErrInvalidPrototypeDRWAReceiverSeeds)
}

func prototypeReceiverSeedArgs(seeds []config.PrototypeDRWAReceiverSeedConfig) ArgsGenesisBlockCreator {
	coordinator := &testscommon.ShardsCoordinatorMock{
		NoShards:     3,
		CurrentShard: 0,
		ComputeIdCalled: func(address []byte) uint32 {
			return uint32(address[len(address)-1]) % 3
		},
	}

	return ArgsGenesisBlockCreator{
		Core: &genesisMock.CoreComponentsMock{
			AddrPubKeyConv: testscommon.NewPubkeyConverterMock(32),
		},
		ShardCoordinator:      coordinator,
		PrototypeDRWACEBEpoch: 7,
		PrototypeReceiverSeeds: append(
			[]config.PrototypeDRWAReceiverSeedConfig(nil), seeds...,
		),
	}
}

func prototypeReceiverSeedConfig(holderAddress string, tokenIdentifier string) config.PrototypeDRWAReceiverSeedConfig {
	return config.PrototypeDRWAReceiverSeedConfig{
		HolderAddress:     holderAddress,
		TokenIdentifier:   tokenIdentifier,
		CEBEpoch:          7,
		Admitted:          true,
		ValidThroughRound: 1000,
	}
}

func prototypeReceiverSeedAddress(lastByte byte) string {
	address := make([]byte, 32)
	address[0] = 1
	address[len(address)-1] = lastByte
	return hex.EncodeToString(address)
}
