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
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

type qualTransitionMultiFixture struct {
	store       *qualTransitionReceiverSaveFault
	hook        *hooks.BlockChainHookImpl
	marshal     *marshal.GogoProtoMarshalizer
	coordinator sharding.Coordinator
	storage     vmcommon.ESDTNFTStorageHandler
}

func qualTransitionMulti(t *testing.T, shard uint32, extraFlags ...core.EnableEpochFlag) *qualTransitionMultiFixture {
	t.Helper()
	return qualTransitionMultiWithMetadataPolicy(t, shard, true, extraFlags...)
}

func qualTransitionMultiWithMetadataPolicy(t *testing.T, shard uint32, sendAlways bool, extraFlags ...core.EnableEpochFlag) *qualTransitionMultiFixture {
	t.Helper()
	f := &qualTransitionMultiFixture{store: &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}, marshal: &marshal.GogoProtoMarshalizer{}}
	coordinator, err := sharding.NewMultiShardCoordinator(3, shard)
	require.NoError(t, err)
	f.coordinator = coordinator
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.SaveToSystemAccountFlag, builtInFunctions.FixCorrectSmallIntAndGasLimitsFlag, builtInFunctions.CheckCorrectTokenIDForTransferRoleFlag, builtInFunctions.ConsistentTokensValuesLengthCheckFlag, builtInFunctions.EGLDInESDTMultiTransferFlag, builtInFunctions.ESDTNFTImprovementV1Flag, builtInFunctions.ScToScLogEventFlag, builtInFunctions.CheckFunctionArgumentFlag, builtInFunctions.FixAsyncCallbackCheckFlag)
	if sendAlways {
		flags.AddActiveFlags(builtInFunctions.SendAlwaysFlag)
	}
	flags.AddActiveFlags(extraFlags...)
	settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(f.store, f.marshal, true, core.BuiltInFunctionESDTPause, func() bool { return true })
	require.NoError(t, err)
	storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: f.store, GlobalSettingsHandler: settings, Marshalizer: f.marshal, EnableEpochsHandler: flags, ShardCoordinator: coordinator})
	require.NoError(t, err)
	f.storage = storage
	roles, err := builtInFunctions.NewESDTRolesFunc(f.marshal, true)
	require.NoError(t, err)
	function, err := builtInFunctions.NewESDTNFTMultiTransferFunc(7, f.marshal, settings, f.store, coordinator, vmcommon.BaseOperationCost{}, flags, roles, storage)
	require.NoError(t, err)
	f.hook, _ = qualT42Hook(t, f.store, shard, false, coordinator)
	payable, err := builtInFunctions.NewPayableCheckFunc(f.hook, flags)
	require.NoError(t, err)
	require.NoError(t, function.SetPayableChecker(payable))
	require.NoError(t, f.hook.GetBuiltinFunctionsContainer().Add(core.BuiltInFunctionMultiESDTNFTTransfer, function))
	single, err := builtInFunctions.NewESDTNFTTransferFunc(7, f.marshal, settings, f.store, coordinator, vmcommon.BaseOperationCost{}, roles, storage, flags)
	require.NoError(t, err)
	require.NoError(t, single.SetPayableChecker(payable))
	require.NoError(t, f.hook.GetBuiltinFunctionsContainer().Add(core.BuiltInFunctionESDTNFTTransfer, single))
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

func TestQualDRWAP21NativeNonceFamilyCarrierAndDestinationCopy(t *testing.T) {
	// Use the R19 fixture's native flags. The absence of AlwaysSaveTokenMetaData
	// matters here: a full carrier seeds an absent copy but does not replace a
	// populated system-account copy. Dynamic metadata version merging is outside
	// this fixture; the dynamic families still have distinct native storage loci.
	token := []byte("NFT-abcdef")
	tokenKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
	nonceKey := append(bytes.Clone(tokenKey), 1)
	sender := bytes.Clone(qualContainmentAddress)
	receiver := bytes.Repeat([]byte{2}, len(sender))
	// Reuse the R19 metadata name so the wire record exercises the receiver's
	// full-metadata path instead of its compact quantity path.
	name := []byte("preserved native metadata")
	initial := &esdt.MetaData{Nonce: 1, Name: name, Attributes: []byte("initial")}
	updated := &esdt.MetaData{Nonce: 1, Name: name, Attributes: []byte("updated")}
	// List the expected metadata locus independently of the storage helper.
	for _, tc := range []struct {
		family         core.ESDTType
		copyState      string
		systemMetadata bool
		senderBefore   int64
		amount         int64
		receiverBefore int64
		cachedMetadata *esdt.MetaData
		want           *esdt.MetaData
	}{
		{core.NonFungibleV2, "absent copy", false, 1, 1, 0, nil, updated},
		{core.DynamicNFT, "absent copy", false, 1, 1, 0, nil, updated},
		{core.SemiFungible, "absent copy", true, 5, 2, 0, nil, updated},
		{core.SemiFungible, "older copy", true, 5, 2, 1, initial, initial},
		{core.SemiFungible, "zero liquidity copy", true, 5, 2, 0, initial, initial},
		{core.MetaFungible, "absent copy", true, 5, 2, 0, nil, updated},
		{core.MetaFungible, "older copy", true, 5, 2, 1, initial, initial},
		{core.DynamicSFT, "absent copy", true, 5, 2, 0, nil, updated},
		{core.DynamicSFT, "older copy", true, 5, 2, 1, initial, initial},
		{core.DynamicMeta, "absent copy", true, 5, 2, 0, nil, updated},
		{core.DynamicMeta, "older copy", true, 5, 2, 1, initial, initial},
	} {
		t.Run(tc.family.String()+"/"+tc.copyState, func(t *testing.T) {
			source, destination := qualTransitionMulti(t, 1), qualTransitionMulti(t, 2)
			require.Equal(t, uint32(1), source.coordinator.ComputeId(sender))
			require.Equal(t, uint32(2), destination.coordinator.ComputeId(receiver))
			family := uint32(tc.family)
			origin := &esdt.ESDigitalToken{Type: family, Value: big.NewInt(tc.senderBefore), TokenMetaData: updated}
			if tc.systemMetadata {
				source.seedNonce(t, core.SystemAccountAddress, nonceKey, &esdt.ESDigitalToken{
					Type: family, Value: big.NewInt(tc.senderBefore), Reserved: []byte{1}, TokenMetaData: updated,
				})
				origin.TokenMetaData = nil
			}
			source.seedNonce(t, sender, nonceKey, origin)
			if tc.receiverBefore != 0 {
				destination.seedNonce(t, receiver, nonceKey, &esdt.ESDigitalToken{Type: family, Value: big.NewInt(tc.receiverBefore)})
			}
			if tc.cachedMetadata != nil {
				destination.seedNonce(t, core.SystemAccountAddress, nonceKey, &esdt.ESDigitalToken{
					Type: family, Value: big.NewInt(tc.receiverBefore), Reserved: []byte{1}, TokenMetaData: tc.cachedMetadata,
				})
			}
			input, wire := source.sendNonce(t, core.BuiltInFunctionMultiESDTNFTTransfer, sender, receiver, token, tc.amount)
			require.Equal(t, family, wire.Type)
			require.Equal(t, big.NewInt(tc.amount), wire.Value)
			require.Equal(t, updated, wire.TokenMetaData)

			destination.receiveNonce(t, input)
			read := func(f *qualTransitionMultiFixture, address []byte, quantity int64, metadata *esdt.MetaData) {
				t.Helper()
				root, err := f.store.Commit()
				require.NoError(t, err)
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				holder, err := f.store.GetExistingAccount(address)
				require.NoError(t, err)
				user := holder.(vmcommon.UserAccountHandler)
				instance, missing, err := f.storage.GetESDTNFTTokenOnDestination(user, tokenKey, 1)
				require.NoError(t, err)
				require.Equal(t, big.NewInt(quantity), instance.Value)
				system, err := f.storage.GetMetaDataFromSystemAccount(tokenKey, 1)
				require.NoError(t, err)
				if quantity == 0 {
					require.True(t, missing)
					require.Nil(t, instance.TokenMetaData)
					require.Nil(t, system)
					return
				}
				require.False(t, missing)
				require.Equal(t, family, instance.Type)
				require.Equal(t, metadata, instance.TokenMetaData)
				raw, _, err := user.AccountDataHandler().RetrieveValue(nonceKey)
				require.NoError(t, err)
				var local esdt.ESDigitalToken
				require.NoError(t, f.marshal.Unmarshal(&local, raw))
				if tc.systemMetadata {
					require.Nil(t, local.TokenMetaData)
					require.NotNil(t, system)
					require.Equal(t, big.NewInt(quantity), system.Value)
					require.Equal(t, metadata, system.TokenMetaData)
				} else {
					require.Equal(t, metadata, local.TokenMetaData)
					require.Nil(t, system)
				}
			}
			read(source, sender, tc.senderBefore-tc.amount, updated)
			read(destination, receiver, tc.receiverBefore+tc.amount, tc.want)
		})
	}
}

func (f *qualTransitionMultiFixture) seedNonce(t *testing.T, address, nonceKey []byte, token *esdt.ESDigitalToken) {
	t.Helper()
	account, err := f.store.LoadAccount(address)
	require.NoError(t, err)
	raw, err := f.marshal.Marshal(token)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(nonceKey, raw))
	require.NoError(t, f.store.SaveAccount(account))
}

func (f *qualTransitionMultiFixture) sendNonce(t *testing.T, function string, sender, receiver, token []byte, amount int64) (*vmcommon.ContractCallInput, *esdt.ESDigitalToken) {
	t.Helper()
	destInput := f.sendNonceCarrier(t, function, sender, receiver, token, amount)
	args := destInput.Arguments
	if function == core.BuiltInFunctionESDTNFTTransfer {
		require.Equal(t, [][]byte{token, {1}, big.NewInt(amount).Bytes()}, args[:3])
		require.NotEqual(t, []byte{0}, args[3])
	} else {
		require.Equal(t, [][]byte{{1}, token, {1}}, args[:3])
		require.Greater(t, len(args[3]), int(vmcommon.MaxLengthForValueToOptTransfer))
	}
	var wire esdt.ESDigitalToken
	require.NoError(t, f.marshal.Unmarshal(&wire, args[3]))
	return destInput, &wire
}

func (f *qualTransitionMultiFixture) sendNonceCarrier(t *testing.T, function string, sender, receiver, token []byte, amount int64) *vmcommon.ContractCallInput {
	t.Helper()
	quantity := big.NewInt(amount).Bytes()
	args := [][]byte{receiver, {1}, token, {1}, quantity}
	if function == core.BuiltInFunctionESDTNFTTransfer {
		args = [][]byte{token, {1}, quantity, receiver}
	}
	out, err := f.hook.ProcessBuiltInFunction(&vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: sender, CallValue: new(big.Int), GasProvided: 1000, GasLocked: 11,
			Arguments: args,
		},
		RecipientAddr: sender, Function: function,
	})
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Equal(t, uint64(993), out.GasRemaining)
	require.Len(t, out.OutputAccounts, 1)
	account := out.OutputAccounts[string(receiver)]
	require.NotNil(t, account)
	require.Equal(t, receiver, account.Address)
	require.Len(t, account.OutputTransfers, 1)
	carrier := account.OutputTransfers[0]
	require.Equal(t, sender, carrier.SenderAddress)
	require.Equal(t, new(big.Int), carrier.Value)
	require.Equal(t, uint64(0), carrier.GasLimit)
	require.Equal(t, uint64(11), carrier.GasLocked)
	carriedFunction, args, err := parsers.NewCallArgsParser().ParseData(string(carrier.Data))
	require.NoError(t, err)
	require.Equal(t, function, carriedFunction)
	require.Len(t, args, 4)
	return &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{
			CallerAddr: carrier.SenderAddress, CallValue: carrier.Value, GasProvided: carrier.GasLimit,
			GasLocked: carrier.GasLocked, CallType: carrier.CallType, Arguments: args,
		},
		RecipientAddr: account.Address, Function: carriedFunction,
	}
}

func (f *qualTransitionMultiFixture) receiveNonce(t *testing.T, input *vmcommon.ContractCallInput) {
	t.Helper()
	out, err := f.hook.ProcessBuiltInFunction(input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, out.ReturnCode)
	require.Empty(t, out.OutputAccounts)
	require.Zero(t, out.GasRemaining)
}

func TestQualDRWAP21NativeDynamicMetadataVersionMerge(t *testing.T) {
	token := []byte("NFT-abcdef")
	tokenKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
	nonceKey := append(bytes.Clone(tokenKey), 1)
	sender := bytes.Clone(qualContainmentAddress)
	receiver := bytes.Repeat([]byte{2}, len(sender))

	// Use synthetic stored snapshots and the pinned metadata version fixture
	// values. The two native flags exercise merging and persistence separately
	// from activation epochs, DRWA authority and live propagation.
	retained := &esdt.MetaData{
		Nonce: 1, Name: []byte("name"), Creator: receiver, Royalties: 25,
		Hash: receiver, URIs: [][]byte{[]byte("uri1")}, Attributes: []byte("initial"),
	}
	incoming := &esdt.MetaData{
		Nonce: 1, Name: []byte("preserved native metadata"), Creator: sender, Royalties: 11,
		Hash: sender, URIs: [][]byte{[]byte("uri2")}, Attributes: []byte("updated"),
	}
	retainedVersion := &esdt.MetaDataVersion{Name: 2, Creator: 3, Royalties: 2, Hash: 3, URIs: 3, Attributes: 3}
	incomingVersion := &esdt.MetaDataVersion{Name: 3, Creator: 2, Royalties: 3, Hash: 2, URIs: 3, Attributes: 2}
	// The native receiver uses the higher version for each field. The retained
	// version must be strictly higher to override the carrier, so its URI loses
	// the version tie. Spell out the expected result independently of the merge.
	want := &esdt.MetaData{
		Nonce: 1, Name: incoming.Name, Creator: retained.Creator, Royalties: incoming.Royalties,
		Hash: retained.Hash, URIs: incoming.URIs, Attributes: retained.Attributes,
	}
	wantVersion := &esdt.MetaDataVersion{Name: 3, Creator: 3, Royalties: 3, Hash: 3, URIs: 3, Attributes: 3}

	for _, tc := range []struct {
		family         core.ESDTType
		function       string
		systemMetadata bool
		senderBalance  int64
		amount         int64
		receiverBefore int64
	}{
		{core.DynamicNFT, core.BuiltInFunctionMultiESDTNFTTransfer, false, 1, 1, 0},
		{core.DynamicSFT, core.BuiltInFunctionMultiESDTNFTTransfer, true, 5, 2, 1},
		{core.DynamicMeta, core.BuiltInFunctionMultiESDTNFTTransfer, true, 5, 2, 0},
		{core.DynamicNFT, core.BuiltInFunctionESDTNFTTransfer, false, 1, 1, 0},
		{core.DynamicSFT, core.BuiltInFunctionESDTNFTTransfer, true, 5, 2, 1},
		{core.DynamicMeta, core.BuiltInFunctionESDTNFTTransfer, true, 5, 2, 0},
	} {
		t.Run(tc.function+"/"+tc.family.String(), func(t *testing.T) {
			flags := []core.EnableEpochFlag{builtInFunctions.DynamicEsdtFlag, builtInFunctions.AlwaysSaveTokenMetaDataFlag}
			source, destination := qualTransitionMulti(t, 1, flags...), qualTransitionMulti(t, 2, flags...)
			require.Equal(t, uint32(1), source.coordinator.ComputeId(sender))
			require.Equal(t, uint32(2), destination.coordinator.ComputeId(receiver))
			family := uint32(tc.family)
			sourceReserved, err := source.marshal.Marshal(incomingVersion)
			require.NoError(t, err)
			destinationReserved, err := destination.marshal.Marshal(retainedVersion)
			require.NoError(t, err)
			src := &esdt.ESDigitalToken{Type: family, Value: big.NewInt(tc.senderBalance), TokenMetaData: incoming, Reserved: sourceReserved}
			dst := &esdt.ESDigitalToken{Type: family, Value: big.NewInt(tc.receiverBefore), TokenMetaData: retained, Reserved: destinationReserved}
			if tc.systemMetadata {
				source.seedNonce(t, core.SystemAccountAddress, nonceKey, src)
				destination.seedNonce(t, core.SystemAccountAddress, nonceKey, dst)
				source.seedNonce(t, sender, nonceKey, &esdt.ESDigitalToken{Type: family, Value: big.NewInt(tc.senderBalance)})
				if tc.receiverBefore != 0 {
					destination.seedNonce(t, receiver, nonceKey, &esdt.ESDigitalToken{Type: family, Value: big.NewInt(tc.receiverBefore)})
				}
			} else {
				source.seedNonce(t, sender, nonceKey, src)
				// Native metadata administration can retain holder bytes at
				// zero quantity. There is no second live unique NFT here.
				destination.seedNonce(t, receiver, nonceKey, dst)
			}
			for _, f := range []*qualTransitionMultiFixture{source, destination} {
				root, err := f.store.Commit()
				require.NoError(t, err)
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			}

			input, wire := source.sendNonce(t, tc.function, sender, receiver, token, tc.amount)
			require.Equal(t, family, wire.Type)
			require.Equal(t, big.NewInt(tc.amount), wire.Value)
			require.Equal(t, incoming, wire.TokenMetaData)
			require.Equal(t, sourceReserved, wire.Reserved)
			destination.receiveNonce(t, input)

			root, err := destination.store.Commit()
			require.NoError(t, err)
			require.NoError(t, destination.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			holder, err := destination.store.GetExistingAccount(receiver)
			require.NoError(t, err)
			user := holder.(vmcommon.UserAccountHandler)
			instance, missing, err := destination.storage.GetESDTNFTTokenOnDestination(user, tokenKey, 1)
			require.NoError(t, err)
			require.False(t, missing)
			require.Equal(t, family, instance.Type)
			require.Equal(t, big.NewInt(tc.receiverBefore+tc.amount), instance.Value)
			require.Equal(t, want, instance.TokenMetaData)

			var version esdt.MetaDataVersion
			require.NoError(t, destination.marshal.Unmarshal(&version, instance.Reserved))
			require.Equal(t, wantVersion, &version)
			system, err := destination.storage.GetMetaDataFromSystemAccount(tokenKey, 1)
			require.NoError(t, err)
			raw, _, err := user.AccountDataHandler().RetrieveValue(nonceKey)
			require.NoError(t, err)
			var holderToken esdt.ESDigitalToken
			require.NoError(t, destination.marshal.Unmarshal(&holderToken, raw))
			if tc.systemMetadata {
				require.Nil(t, holderToken.TokenMetaData)
				require.Empty(t, holderToken.Reserved)
				require.NotNil(t, system)
				require.Equal(t, instance.Value, system.Value)
				require.Equal(t, want, system.TokenMetaData)
				require.Equal(t, instance.Reserved, system.Reserved)
			} else {
				require.Nil(t, system)
				require.Equal(t, want, holderToken.TokenMetaData)
				require.Equal(t, instance.Reserved, holderToken.Reserved)
			}
		})
	}
}

func TestQualDRWAP21NativeCompactCarrierUsesPersistedMetadata(t *testing.T) {
	token := []byte("NFT-abcdef")
	tokenKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
	nonceKey := append(bytes.Clone(tokenKey), 1)
	sender := bytes.Clone(qualContainmentAddress)
	receiver := bytes.Repeat([]byte{2}, len(sender))
	metadata := &esdt.MetaData{Nonce: 1, Name: []byte("preserved native metadata"), Attributes: []byte("initial")}
	version := &esdt.MetaDataVersion{Name: 3, Attributes: 2}
	for _, carrier := range []struct {
		function string
		compact  [][]byte
	}{
		{core.BuiltInFunctionESDTNFTTransfer, [][]byte{token, {1}, {2}, {0}}},
		{core.BuiltInFunctionMultiESDTNFTTransfer, [][]byte{{1}, token, {1}, {2}}},
	} {
		for _, family := range []core.ESDTType{core.DynamicSFT, core.DynamicMeta} {
			t.Run(carrier.function+"/"+family.String(), func(t *testing.T) {
				// Use a synthetic compact-path configuration on two isolated stores.
				// Quantity 2 selects compact encoding after the source records
				// the first send. A unique NFT's unit transfer stays full.
				flags := []core.EnableEpochFlag{builtInFunctions.DynamicEsdtFlag, builtInFunctions.AlwaysSaveTokenMetaDataFlag}
				source := qualTransitionMultiWithMetadataPolicy(t, 1, false, flags...)
				destination := qualTransitionMultiWithMetadataPolicy(t, 2, false, flags...)
				require.Equal(t, uint32(1), source.coordinator.ComputeId(sender))
				require.Equal(t, uint32(2), destination.coordinator.ComputeId(receiver))
				reserved, err := source.marshal.Marshal(version)
				require.NoError(t, err)
				source.seedNonce(t, sender, nonceKey, &esdt.ESDigitalToken{Type: uint32(family), Value: big.NewInt(5)})
				source.seedNonce(t, core.SystemAccountAddress, nonceKey, &esdt.ESDigitalToken{
					Type: uint32(family), Value: big.NewInt(5), TokenMetaData: metadata, Reserved: reserved,
				})
				cached, err := destination.storage.GetMetaDataFromSystemAccount(tokenKey, 1)
				require.NoError(t, err)
				require.Nil(t, cached)

				read := func(f *qualTransitionMultiFixture, address []byte, quantity, cachedValue int64) *esdt.ESDigitalToken {
					t.Helper()
					root, err := f.store.Commit()
					require.NoError(t, err)
					require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
					holder, err := f.store.GetExistingAccount(address)
					require.NoError(t, err)
					user := holder.(vmcommon.UserAccountHandler)
					loaded, missing, err := f.storage.GetESDTNFTTokenOnDestination(user, tokenKey, 1)
					require.NoError(t, err)
					require.False(t, missing)
					require.Equal(t, uint32(family), loaded.Type)
					require.Equal(t, big.NewInt(quantity), loaded.Value)
					require.Equal(t, metadata, loaded.TokenMetaData)
					require.Equal(t, reserved, loaded.Reserved)
					raw, _, err := user.AccountDataHandler().RetrieveValue(nonceKey)
					require.NoError(t, err)
					var local esdt.ESDigitalToken
					require.NoError(t, f.marshal.Unmarshal(&local, raw))
					require.Equal(t, big.NewInt(quantity), local.Value)
					require.Nil(t, local.TokenMetaData)
					require.Empty(t, local.Reserved)
					system, err := f.storage.GetMetaDataFromSystemAccount(tokenKey, 1)
					require.NoError(t, err)
					require.NotNil(t, system)
					require.Equal(t, uint32(family), system.Type)
					require.Equal(t, big.NewInt(cachedValue), system.Value)
					require.Equal(t, metadata, system.TokenMetaData)
					require.Equal(t, reserved, system.Reserved)
					return system
				}

				first, wire := source.sendNonce(t, carrier.function, sender, receiver, token, 2)
				require.Equal(t, uint32(family), wire.Type)
				require.Equal(t, big.NewInt(2), wire.Value)
				require.Equal(t, metadata, wire.TokenMetaData)
				require.Equal(t, reserved, wire.Reserved)
				destination.receiveNonce(t, first)
				// With SendAlwaysFlag disabled, the native liquidity updater
				// returns before changing system-account Value. The seeded
				// source cache stays at 5 and the new destination cache at 0.
				origin := read(source, sender, 3, 5)
				require.Len(t, origin.Properties, 3)
				require.Equal(t, byte(1), origin.Properties[2])
				read(destination, receiver, 2, 0)

				second := source.sendNonceCarrier(t, carrier.function, sender, receiver, token, 2)
				require.Equal(t, carrier.compact, second.Arguments)
				destination.receiveNonce(t, second)
				read(source, sender, 1, 5)
				read(destination, receiver, 4, 0)
			})
		}
	}
}
