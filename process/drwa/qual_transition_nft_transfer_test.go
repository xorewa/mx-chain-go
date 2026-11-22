package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native hook composition only. Regulated entry/return restrictions: SP2-25/68/42.
func TestQualTransitionR15NFTTransferNative(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		for _, mode := range []string{"ordinary", "frozen return", "limited", "late save"} {
			t.Run(fmt.Sprintf("dynamic %t %s should preserve native transfer effects atomically", dynamic, mode), func(t *testing.T) {
				store := &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}
				marshaller := &marshal.GogoProtoMarshalizer{}
				flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.FixCorrectSmallIntAndGasLimitsFlag)
				if dynamic {
					flags.AddActiveFlags(builtInFunctions.DynamicEsdtFlag)
				}
				settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(store, marshaller, true, core.BuiltInFunctionESDTPause, func() bool { return true })
				require.NoError(t, err)
				coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
				coordinator.CurrentShard = 1
				storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: store, GlobalSettingsHandler: settings, Marshalizer: marshaller, EnableEpochsHandler: flags, ShardCoordinator: coordinator})
				require.NoError(t, err)
				roles, err := builtInFunctions.NewESDTRolesFunc(marshaller, true)
				require.NoError(t, err)
				function, err := builtInFunctions.NewESDTNFTTransferFunc(7, marshaller, settings, store, coordinator, vmcommon.BaseOperationCost{}, roles, storage, flags)
				require.NoError(t, err)
				destination := bytes.Repeat([]byte{2}, 32)
				tokenID := []byte("TOKEN-abcdef")
				key := append(append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...), 1)
				senderToken := &esdt.ESDigitalToken{Type: uint32(core.NonFungible), Value: big.NewInt(5), TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("preserved")}}
				receiverToken := &esdt.ESDigitalToken{Type: uint32(core.NonFungible), Value: big.NewInt(1), TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("preserved")}}
				if mode == "frozen return" {
					receiverToken.Properties = (&builtInFunctions.ESDTUserMetadata{Frozen: true}).ToBytes()
				}
				before := map[string][]byte{}
				for address, token := range map[string]*esdt.ESDigitalToken{string(qualContainmentAddress): senderToken, string(destination): receiverToken} {
					encoded, e := marshaller.Marshal(token)
					require.NoError(t, e)
					before[address] = encoded
					account, e := store.LoadAccount([]byte(address))
					require.NoError(t, e)
					require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, encoded))
					require.NoError(t, store.SaveAccount(account))
				}
				if mode == "limited" {
					system, e := store.LoadAccount(core.SystemAccountAddress)
					require.NoError(t, e)
					require.NoError(t, system.(state.UserAccountHandler).SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...), (&builtInFunctions.ESDTGlobalMetadata{LimitedTransfer: true}).ToBytes()))
					require.NoError(t, store.SaveAccount(system))
				}
				root, err := store.Commit()
				require.NoError(t, err)
				hook, _ := qualT42Hook(t, store, 1, false)
				payable, err := builtInFunctions.NewPayableCheckFunc(hook, flags)
				require.NoError(t, err)
				require.NoError(t, function.SetPayableChecker(payable))
				require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(core.BuiltInFunctionESDTNFTTransfer, function))
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(qualContainmentAddress), CallValue: big.NewInt(0), GasProvided: 1000, Arguments: [][]byte{tokenID, {1}, {2}, destination}, ReturnCallAfterError: mode == "frozen return"}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: core.BuiltInFunctionESDTNFTTransfer}
				if mode == "limited" {
					sender, e := store.GetExistingAccount(qualContainmentAddress)
					require.NoError(t, e)
					out, e := function.ProcessBuiltinFunction(sender.(vmcommon.UserAccountHandler), nil, input)
					require.Nil(t, out)
					require.ErrorIs(t, e, builtInFunctions.ErrActionNotAllowed)
					value, _, e := sender.(state.UserAccountHandler).RetrieveValue(key)
					require.NoError(t, e)
					require.Equal(t, before[string(qualContainmentAddress)], value, "limited denial must precede native debit without hook rollback")
					require.Zero(t, store.JournalLen())
					return
				}
				fault := errors.New("qualification sender save after destination NFT save")
				if mode == "late save" {
					store.fault = fault
				}
				out, err := hook.ProcessBuiltInFunction(input)
				store.fault = nil
				if mode == "late save" {
					require.Nil(t, out)
					require.ErrorIs(t, err, fault)
					after, e := store.RootHash()
					require.NoError(t, e)
					require.Equal(t, root, after)
					require.Zero(t, store.JournalLen())
				} else {
					require.NoError(t, err)
					require.Equal(t, vmcommon.Ok, out.ReturnCode)
					require.Equal(t, uint64(993), out.GasRemaining)
					require.Empty(t, out.OutputAccounts)
					require.Empty(t, out.ReturnData)
					require.Len(t, out.Logs, 1)
					require.Equal(t, []byte(core.BuiltInFunctionESDTNFTTransfer), out.Logs[0].Identifier)
					require.Equal(t, qualContainmentAddress, out.Logs[0].Address)
					require.Equal(t, [][]byte{tokenID, {1}, {2}, destination}, out.Logs[0].Topics)
					require.Equal(t, vmcommon.FormatLogDataForCall("", input.Function, input.Arguments), out.Logs[0].Data)
				}
				committed, e := store.Commit()
				require.NoError(t, e)
				if mode == "late save" {
					require.Equal(t, root, committed)
				}
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
				for address, old := range before {
					account, e := store.GetExistingAccount([]byte(address))
					require.NoError(t, e)
					user := account.(state.UserAccountHandler)
					actual, _, e := user.RetrieveValue(key)
					require.NoError(t, e)
					if mode == "late save" {
						require.Equal(t, old, actual)
					} else {
						want := senderToken
						if bytes.Equal([]byte(address), destination) {
							want = receiverToken
						}
						want.Value = big.NewInt(3)
						// Native merge retains the destination frozen bit even on an error return.
						encoded, e := marshaller.Marshal(want)
						require.NoError(t, e)
						require.Equal(t, encoded, actual)
					}
					if bytes.Equal([]byte(address), qualContainmentAddress) {
						require.Equal(t, big.NewInt(100), user.GetBalance())
					} else {
						require.Zero(t, user.GetBalance().Sign())
					}
				}
			})
		}
	}
}
