package process

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	genesisMock "github.com/multiversx/mx-chain-go/genesis/mock"
	processErrors "github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
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
		require.Equal(t, drwaprototype.ReceiverGateStorageKey(seed.tokenID), seed.receiverStorageKey)
		record, decodeErr := drwaprototype.DecodeReceiverGateRecord(seed.encodedReceiverRecord)
		require.NoError(t, decodeErr)
		require.Equal(t, seed.holderAddress, record.Holder[:])
		require.Equal(t, uint32(7), record.CEBEpoch)
		require.Equal(t, string(seed.tokenID) != "TOKEN-abcdef", record.Admitted)
		require.Equal(t, uint64(1000), record.ValidThroughRound)
	}
}

func TestValidateAndCanonicalizePrototypeDRWAReceiverSeedsEncodesCanonicalInitialBalance(t *testing.T) {
	t.Parallel()

	configured := prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(1), "TOKEN-abcdef")
	configured.InitialBalance = "340282366920938463463374607431768211455"
	arg := prototypeReceiverSeedArgs([]config.PrototypeDRWAReceiverSeedConfig{configured})
	arg.Core.(*genesisMock.CoreComponentsMock).IntMarsh = &testscommon.ProtoMarshalizerMock{}

	canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
	require.NoError(t, err)
	require.Len(t, canonical, 1)
	require.Equal(t,
		[]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier+configured.TokenIdentifier),
		canonical[0].balanceStorageKey,
	)

	decoded := &esdt.ESDigitalToken{}
	require.NoError(t, arg.Core.InternalMarshalizer().Unmarshal(decoded, canonical[0].encodedBalance))
	require.Equal(t, configured.InitialBalance, decoded.Value.String())
	require.Equal(t, uint32(core.Fungible), decoded.Type)
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
		"zero initial balance": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].InitialBalance = "0"
		},
		"leading-zero initial balance": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].InitialBalance = "01"
		},
		"signed initial balance": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].InitialBalance = "+1"
		},
		"non-decimal initial balance": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].InitialBalance = "1a"
		},
		"over-32-byte initial balance": func(arg *ArgsGenesisBlockCreator) {
			arg.PrototypeReceiverSeeds[0].InitialBalance = new(big.Int).Lsh(big.NewInt(1), 256).String()
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

func TestApplyPrototypeDRWARegulatedTokenMarkersSortsDeduplicatesAndPreservesFailures(t *testing.T) {
	t.Parallel()

	configured := []config.PrototypeDRWAReceiverSeedConfig{
		prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(0), "ZETA-abcdef"),
		prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(1), "ALPHA-abcdef"),
		prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(2), "ZETA-abcdef"),
	}
	arg := prototypeReceiverSeedArgs(configured)
	canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
	require.NoError(t, err)

	observedKeys := make([]string, 0)
	markerData := &trieMock.DataTrieTrackerStub{
		RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) { return nil, 0, nil },
		SaveKeyValueCalled: func(key []byte, _ []byte) error {
			observedKeys = append(observedKeys, string(key))
			return nil
		},
	}
	markerAccount := &stateMock.UserAccountStub{
		Address: vmcommon.SystemAccountAddress,
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return markerData
		},
	}
	arg.Accounts = &stateMock.AccountsStub{
		GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			require.Equal(t, vmcommon.SystemAccountAddress, address)
			return markerAccount, nil
		},
	}

	count, err := applyPrototypeDRWARegulatedTokenMarkers(arg, canonical)
	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.Equal(t, []string{
		string(mustPrototypeRegulatedTokenKey(t, "ALPHA-abcdef")),
		string(mustPrototypeRegulatedTokenKey(t, "ZETA-abcdef")),
	}, observedKeys)

	injected := errors.New("injected marker failure")
	arg.Accounts = &stateMock.AccountsStub{GetExistingAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
		return nil, injected
	}}
	count, err = applyPrototypeDRWARegulatedTokenMarkers(arg, canonical)
	require.Zero(t, count)
	require.ErrorIs(t, err, injected)
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

func TestApplyPrototypeDRWAReceiverSeedsWritesBalanceBeforeReceiverAndRejectsExisting(t *testing.T) {
	t.Parallel()

	configured := prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(0), "TOKEN-abcdef")
	configured.InitialBalance = "1000"
	arg := prototypeReceiverSeedArgs([]config.PrototypeDRWAReceiverSeedConfig{configured})
	arg.Core.(*genesisMock.CoreComponentsMock).IntMarsh = &testscommon.ProtoMarshalizerMock{}
	canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
	require.NoError(t, err)

	var keys [][]byte
	arg.Accounts = &stateMock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			return &stateMock.UserAccountStub{
				Address: address,
				RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
					require.Equal(t, canonical[0].balanceStorageKey, key)
					return nil, 0, nil
				},
				SaveKeyValueCalled: func(key []byte, _ []byte) error {
					keys = append(keys, append([]byte(nil), key...))
					return nil
				},
			}, nil
		},
	}
	count, err := applyPrototypeDRWAReceiverSeeds(arg, canonical)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, [][]byte{canonical[0].balanceStorageKey, canonical[0].receiverStorageKey}, keys)

	arg.Accounts = &stateMock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		return &stateMock.UserAccountStub{
			Address:             address,
			RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) { return []byte{1}, 0, nil },
		}, nil
	}}
	count, err = applyPrototypeDRWAReceiverSeeds(arg, canonical)
	require.Zero(t, count)
	require.ErrorIs(t, err, ErrInvalidPrototypeDRWAReceiverSeeds)
}

func TestApplyPrototypeDRWAReceiverSeedsAcceptsNilTrieOnlyForEmptyDataRoot(t *testing.T) {
	t.Parallel()

	configured := prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(0), "TOKEN-abcdef")
	configured.InitialBalance = "1000"
	arg := prototypeReceiverSeedArgs([]config.PrototypeDRWAReceiverSeedConfig{configured})
	arg.Core.(*genesisMock.CoreComponentsMock).IntMarsh = &testscommon.ProtoMarshalizerMock{}
	canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
	require.NoError(t, err)

	unrelatedRetrieveFailure := errors.New("injected unrelated retrieve failure")
	tests := map[string]struct {
		rootHash      []byte
		retrieved     []byte
		retrieveError error
		expectedError error
	}{
		"empty root proves absence after exact-key nil-trie result": {
			retrieveError: state.ErrNilTrie,
		},
		"non-empty root preserves nil-trie failure": {
			rootHash:      []byte("persisted-data-root"),
			retrieveError: state.ErrNilTrie,
			expectedError: state.ErrNilTrie,
		},
		"empty root preserves unrelated retrieve failure": {
			retrieveError: unrelatedRetrieveFailure,
			expectedError: unrelatedRetrieveFailure,
		},
		"dirty exact-key collision remains rejected": {
			retrieved:     []byte("existing"),
			expectedError: ErrInvalidPrototypeDRWAReceiverSeeds,
		},
		"persisted exact-key collision remains rejected": {
			rootHash:      []byte("persisted-data-root"),
			retrieved:     []byte("existing"),
			expectedError: ErrInvalidPrototypeDRWAReceiverSeeds,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var savedKeys [][]byte
			localArg := arg
			localArg.Accounts = &stateMock.AccountsStub{
				LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					return &stateMock.UserAccountStub{
						Address: address,
						GetRootHashCalled: func() []byte {
							return append([]byte(nil), test.rootHash...)
						},
						RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
							require.Equal(t, canonical[0].balanceStorageKey, key)
							return append([]byte(nil), test.retrieved...), 0, test.retrieveError
						},
						SaveKeyValueCalled: func(key []byte, _ []byte) error {
							savedKeys = append(savedKeys, append([]byte(nil), key...))
							return nil
						},
					}, nil
				},
			}

			count, applyErr := applyPrototypeDRWAReceiverSeeds(localArg, canonical)
			if test.expectedError != nil {
				require.Zero(t, count)
				require.ErrorIs(t, applyErr, test.expectedError)
				require.Empty(t, savedKeys)
				return
			}

			require.NoError(t, applyErr)
			require.Equal(t, 1, count)
			require.Equal(t, [][]byte{canonical[0].balanceStorageKey, canonical[0].receiverStorageKey}, savedKeys)
		})
	}
}

func TestApplyPrototypeDRWAReceiverSeedsPreservesBalanceAndReceiverWriteFailures(t *testing.T) {
	t.Parallel()

	configured := prototypeReceiverSeedConfig(prototypeReceiverSeedAddress(0), "TOKEN-abcdef")
	configured.InitialBalance = "1000"
	arg := prototypeReceiverSeedArgs([]config.PrototypeDRWAReceiverSeedConfig{configured})
	arg.Core.(*genesisMock.CoreComponentsMock).IntMarsh = &testscommon.ProtoMarshalizerMock{}
	canonical, err := validateAndCanonicalizePrototypeDRWAReceiverSeeds(arg)
	require.NoError(t, err)

	injectedBalanceSave := errors.New("injected initial balance save failure")
	receiverWriteCalled := false
	arg.Accounts = &stateMock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		return &stateMock.UserAccountStub{
			Address: address,
			SaveKeyValueCalled: func(key []byte, _ []byte) error {
				if bytes.Equal(key, canonical[0].balanceStorageKey) {
					return injectedBalanceSave
				}
				receiverWriteCalled = true
				return nil
			},
		}, nil
	}}
	count, err := applyPrototypeDRWAReceiverSeeds(arg, canonical)
	require.Zero(t, count)
	require.ErrorIs(t, err, injectedBalanceSave)
	require.False(t, receiverWriteCalled)

	injectedReceiverSave := errors.New("injected receiver record save failure")
	var observedKeys [][]byte
	arg.Accounts = &stateMock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		return &stateMock.UserAccountStub{
			Address: address,
			SaveKeyValueCalled: func(key []byte, _ []byte) error {
				observedKeys = append(observedKeys, append([]byte(nil), key...))
				if bytes.Equal(key, canonical[0].receiverStorageKey) {
					return injectedReceiverSave
				}
				return nil
			},
		}, nil
	}}
	count, err = applyPrototypeDRWAReceiverSeeds(arg, canonical)
	require.Zero(t, count)
	require.ErrorIs(t, err, injectedReceiverSave)
	require.Equal(t, [][]byte{canonical[0].balanceStorageKey, canonical[0].receiverStorageKey}, observedKeys)
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

func mustPrototypeRegulatedTokenKey(t *testing.T, token string) []byte {
	t.Helper()
	key, err := drwaprototype.PrototypeRegulatedTokenKey([]byte(token))
	require.NoError(t, err)
	return key
}
