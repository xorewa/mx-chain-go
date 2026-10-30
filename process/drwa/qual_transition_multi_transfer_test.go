package drwa

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

type qualTransitionMultiFixture struct {
	store       *qualTransitionReceiverSaveFault
	hook        *hooks.BlockChainHookImpl
	marshal     *marshal.GogoProtoMarshalizer
	coordinator sharding.Coordinator
}

func qualTransitionMulti(t *testing.T, shard uint32) *qualTransitionMultiFixture {
	t.Helper()
	f := &qualTransitionMultiFixture{store: &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}, marshal: &marshal.GogoProtoMarshalizer{}}
	coordinator, err := sharding.NewMultiShardCoordinator(3, shard)
	require.NoError(t, err)
	f.coordinator = coordinator
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.SaveToSystemAccountFlag, builtInFunctions.SendAlwaysFlag, builtInFunctions.FixCorrectSmallIntAndGasLimitsFlag, builtInFunctions.CheckCorrectTokenIDForTransferRoleFlag, builtInFunctions.ConsistentTokensValuesLengthCheckFlag, builtInFunctions.EGLDInESDTMultiTransferFlag, builtInFunctions.ESDTNFTImprovementV1Flag, builtInFunctions.ScToScLogEventFlag, builtInFunctions.CheckFunctionArgumentFlag, builtInFunctions.FixAsyncCallbackCheckFlag)
	settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(f.store, f.marshal, true, core.BuiltInFunctionESDTPause, func() bool { return true })
	require.NoError(t, err)
	storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: f.store, GlobalSettingsHandler: settings, Marshalizer: f.marshal, EnableEpochsHandler: flags, ShardCoordinator: coordinator})
	require.NoError(t, err)
	roles, err := builtInFunctions.NewESDTRolesFunc(f.marshal, true)
	require.NoError(t, err)
	function, err := builtInFunctions.NewESDTNFTMultiTransferFunc(7, f.marshal, settings, f.store, coordinator, vmcommon.BaseOperationCost{}, flags, roles, storage)
	require.NoError(t, err)
	f.hook, _ = qualT42Hook(t, f.store, shard, false, coordinator)
	payable, err := builtInFunctions.NewPayableCheckFunc(f.hook, flags)
	require.NoError(t, err)
	require.NoError(t, function.SetPayableChecker(payable))
	require.NoError(t, f.hook.GetBuiltinFunctionsContainer().Add(core.BuiltInFunctionMultiESDTNFTTransfer, function))
	return f
}

// Native mixed batch only. Regulated authorization/refund composition remains SP2-25/68/42.
func TestQualTransitionR19MultiTransferNative(t *testing.T) {
	for _, mode := range []string{"ordinary", "follow-on", "cross sender", "cross receiver", "late leg", "late id", "metadata", "late save"} {
		t.Run(mode+" should preserve the whole native batch", func(t *testing.T) {
			shard := uint32(1)
			if mode == "cross receiver" {
				shard = 2
			}
			f := qualTransitionMulti(t, shard)
			sender := bytes.Clone(qualContainmentAddress)
			destination := bytes.Repeat([]byte{2}, 32)
			destination[31] = 1
			if mode == "cross sender" || mode == "cross receiver" {
				destination[31] = 2
			}
			if mode == "follow-on" {
				destination = make([]byte, 32)
				destination[8] = 5
				destination[25] = 1
				destination[31] = 1
				require.True(t, vmcommon.IsSmartContractAddress(destination))
			}
			require.Equal(t, uint32(1), f.coordinator.ComputeId(sender))
			wantDestinationShard := uint32(1)
			if mode == "cross sender" || mode == "cross receiver" {
				wantDestinationShard = 2
			}
			require.Equal(t, wantDestinationShard, f.coordinator.ComputeId(destination))
			fungibleID := []byte("TOKEN-abcdef")
			nftID := []byte("NFT-abcdef")
			fungibleKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), fungibleID...)
			nftKey := append(append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), nftID...), 1)
			metadata := &esdt.MetaData{Nonce: 1, Name: []byte("preserved native metadata")}
			systemToken := &esdt.ESDigitalToken{Type: uint32(core.SemiFungible), Value: big.NewInt(12), Reserved: []byte{1}, TokenMetaData: metadata}
			if mode == "metadata" {
				systemToken.TokenMetaData = nil
			}
			priorSystem, err := f.marshal.Marshal(systemToken)
			require.NoError(t, err)
			system, err := f.store.LoadAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			require.NoError(t, system.(state.UserAccountHandler).SaveKeyValue(nftKey, priorSystem))
			require.NoError(t, f.store.SaveAccount(system))
			before := map[string]map[string][]byte{}
			localAddresses := [][]byte{sender, destination}
			if mode == "cross sender" {
				localAddresses = [][]byte{sender}
			}
			if mode == "cross receiver" {
				localAddresses = [][]byte{destination}
			}
			for _, address := range localAddresses {
				quantity := int64(5)
				if bytes.Equal(address, destination) {
					quantity = 1
				}
				account, e := f.store.LoadAccount(address)
				require.NoError(t, e)
				user := account.(state.UserAccountHandler)
				before[string(address)] = map[string][]byte{}
				for key, kind := range map[string]uint32{string(fungibleKey): uint32(core.Fungible), string(nftKey): uint32(core.SemiFungible)} {
					encoded, e := f.marshal.Marshal(&esdt.ESDigitalToken{Type: kind, Value: big.NewInt(quantity)})
					require.NoError(t, e)
					before[string(address)][key] = encoded
					require.NoError(t, user.SaveKeyValue([]byte(key), encoded))
				}
				require.NoError(t, f.store.SaveAccount(user))
			}
			root, err := f.store.Commit()
			require.NoError(t, err)
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: sender, CallValue: big.NewInt(0), GasProvided: 1000, GasLocked: 11, Arguments: [][]byte{destination, {3}, []byte(vmcommon.EGLDIdentifier), {}, {3}, nftID, {1}, {2}, fungibleID, {}, {2}}}, RecipientAddr: sender, Function: core.BuiltInFunctionMultiESDTNFTTransfer}
			if mode == "late leg" {
				input.Arguments[10] = []byte{6}
			}
			if mode == "late id" {
				input.Arguments[8] = []byte("bad")
			}
			if mode == "follow-on" {
				input.Arguments = append(input.Arguments, []byte("follow"), []byte("arg"))
			}
			transferNFT := &esdt.ESDigitalToken{Type: uint32(core.SemiFungible), Value: big.NewInt(2), TokenMetaData: metadata}
			transferBytes, err := f.marshal.Marshal(transferNFT)
			require.NoError(t, err)
			receivedArgs := [][]byte{{3}, []byte(vmcommon.EGLDIdentifier), {0}, {3}, nftID, {1}, transferBytes, fungibleID, {0}, {2}}
			if mode == "cross receiver" {
				input.Arguments = receivedArgs
				input.RecipientAddr = destination
			}
			fault := errors.New("qualification mixed-batch sender save")
			if mode == "late save" {
				f.store.fault = fault
			}
			out, err := f.hook.ProcessBuiltInFunction(input)
			f.store.fault = nil
			denied := mode == "late leg" || mode == "late id" || mode == "metadata" || mode == "late save"
			if denied {
				require.Nil(t, out)
				expected := fault
				switch mode {
				case "late leg":
					expected = builtInFunctions.ErrInsufficientQuantityESDT
				case "late id":
					expected = builtInFunctions.ErrInvalidTokenID
				case "metadata":
					expected = builtInFunctions.ErrNFTDoesNotHaveMetadata
				}
				require.ErrorIs(t, err, expected)
				after, e := f.store.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
				require.Zero(t, f.store.JournalLen())
			} else {
				require.NoError(t, err)
				gas := uint64(979)
				if mode == "cross receiver" {
					gas = 1000
				}
				if mode == "follow-on" {
					gas = 0
				}
				logData := [][]byte{{}, []byte(input.Function)}
				logData = append(logData, input.Arguments...)
				expected := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: gas, Logs: []*vmcommon.LogEntry{{Identifier: []byte(input.Function), Address: sender, Topics: [][]byte{[]byte(vmcommon.EGLDIdentifier), {}, {3}, nftID, {1}, {2}, fungibleID, {}, {2}, destination}, Data: logData}}}
				if mode == "follow-on" {
					expected.OutputAccounts = map[string]*vmcommon.OutputAccount{string(destination): {Address: destination, OutputTransfers: []vmcommon.OutputTransfer{{Index: 1, Value: big.NewInt(0), GasLimit: 979, GasLocked: 11, Data: []byte("follow@617267"), CallType: vm.DirectCall, SenderAddress: sender}}}}
				}
				if mode == "cross sender" {
					encoded := core.BuiltInFunctionMultiESDTNFTTransfer
					for _, arg := range receivedArgs {
						encoded += "@" + hex.EncodeToString(arg)
					}
					expected.OutputAccounts = map[string]*vmcommon.OutputAccount{string(destination): {Address: destination, OutputTransfers: []vmcommon.OutputTransfer{{Index: 1, Value: big.NewInt(0), GasLimit: 0, GasLocked: 11, Data: []byte(encoded), CallType: vm.DirectCall, SenderAddress: sender}}}}
				}
				require.Equal(t, expected, out)
			}
			committed, e := f.store.Commit()
			require.NoError(t, e)
			if denied {
				require.Equal(t, root, committed)
			}
			require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
			for address, values := range before {
				account, e := f.store.GetExistingAccount([]byte(address))
				require.NoError(t, e)
				user := account.(state.UserAccountHandler)
				balance := int64(97)
				if address == string(destination) {
					balance = 3
				}
				if denied {
					balance = 100
					if address == string(destination) {
						balance = 0
					}
				}
				require.Equal(t, big.NewInt(balance), user.GetBalance())
				for key, prior := range values {
					actual, _, e := user.RetrieveValue([]byte(key))
					require.NoError(t, e)
					if denied {
						require.Equal(t, prior, actual)
					} else {
						kind := uint32(core.Fungible)
						if key == string(nftKey) {
							kind = uint32(core.SemiFungible)
						}
						want, e := f.marshal.Marshal(&esdt.ESDigitalToken{Type: kind, Value: big.NewInt(3)})
						require.NoError(t, e)
						require.Equal(t, want, actual)
					}
				}
			}
			actualSystem := qualRegistryValue(t, f.store.qualNativeStore, string(nftKey))
			if denied {
				require.Equal(t, priorSystem, actualSystem)
			} else {
				quantity := int64(12)
				if mode == "cross sender" {
					quantity = 10
				}
				if mode == "cross receiver" {
					quantity = 14
				}
				systemToken.Value = big.NewInt(quantity)
				want, e := f.marshal.Marshal(systemToken)
				require.NoError(t, e)
				require.Equal(t, want, actualSystem)
			}
		})
	}
}

func TestQualTransitionR19CountAdmissionNative(t *testing.T) {
	for _, receiving := range []bool{false, true} {
		for _, countMode := range []string{"valid", "wide", "excess", "zero"} {
			t.Run(fmt.Sprintf("receiving %t %s should reject count before narrowing", receiving, countMode), func(t *testing.T) {
				shard := uint32(1)
				if receiving {
					shard = 2
				}
				f := qualTransitionMulti(t, shard)
				sender := bytes.Clone(qualContainmentAddress)
				destination := bytes.Repeat([]byte{2}, 32)
				require.Equal(t, uint32(1), f.coordinator.ComputeId(sender))
				require.Equal(t, uint32(2), f.coordinator.ComputeId(destination))
				tokenID := []byte("TOKEN-abcdef")
				key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
				address := sender
				quantity := int64(5)
				if receiving {
					address = destination
					quantity = 1
				}
				account, err := f.store.LoadAccount(address)
				require.NoError(t, err)
				prior, err := f.marshal.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(quantity)})
				require.NoError(t, err)
				require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, prior))
				require.NoError(t, f.store.SaveAccount(account))
				root, err := f.store.Commit()
				require.NoError(t, err)
				count := big.NewInt(1)
				switch countMode {
				case "wide":
					count.Add(count, new(big.Int).Lsh(big.NewInt(1), 64))
				case "excess":
					count.SetInt64(3)
				case "zero":
					count.SetInt64(0)
				}
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: sender, CallValue: big.NewInt(0), GasProvided: 1000, Arguments: [][]byte{destination, count.Bytes(), tokenID, {}, {2}}}, RecipientAddr: sender, Function: core.BuiltInFunctionMultiESDTNFTTransfer}
				if receiving {
					input.Arguments = input.Arguments[1:]
					input.RecipientAddr = destination
				}
				out, err := f.hook.ProcessBuiltInFunction(input)
				if countMode != "valid" {
					require.Nil(t, out)
					require.ErrorIs(t, err, builtInFunctions.ErrInvalidArguments)
					message := "invalid number of transfers"
					if countMode == "zero" {
						message = "0 tokens to transfer"
					}
					require.Contains(t, err.Error(), message)
					after, e := f.store.RootHash()
					require.NoError(t, e)
					require.Equal(t, root, after)
					require.Zero(t, f.store.JournalLen())
				} else {
					require.NoError(t, err)
					require.Equal(t, vmcommon.Ok, out.ReturnCode)
					gas := uint64(993)
					if receiving {
						gas = 1000
					}
					require.Equal(t, gas, out.GasRemaining)
				}
				committed, e := f.store.Commit()
				require.NoError(t, e)
				if countMode != "valid" {
					require.Equal(t, root, committed)
				}
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
				account, e = f.store.GetExistingAccount(address)
				require.NoError(t, e)
				actual, _, e := account.(state.UserAccountHandler).RetrieveValue(key)
				require.NoError(t, e)
				if countMode != "valid" {
					require.Equal(t, prior, actual)
				} else {
					want, e := f.marshal.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(3)})
					require.NoError(t, e)
					require.Equal(t, want, actual)
				}
			})
		}
	}
}
