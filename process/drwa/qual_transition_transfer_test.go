package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native transfer only; authenticated regulated returns/refunds remain SP2-25/68/42.
func TestQualTransitionR18TransferNative(t *testing.T) {
	for _, mode := range []string{"ordinary", "callback", "follow-on", "nonpayable", "limited", "system", "metachain", "late save"} {
		t.Run(mode+" should compose native balances output and gas", func(t *testing.T) {
			store := &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}
			marshaller := &marshal.GogoProtoMarshalizer{}
			coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
			require.NoError(t, err)
			sender := bytes.Clone(qualContainmentAddress)
			destination := bytes.Repeat([]byte{2}, 32)
			destination[31] = 1
			if mode == "follow-on" || mode == "nonpayable" {
				destination = make([]byte, 32)
				destination[8] = 5
				destination[25] = 1
				destination[31] = 1
				require.True(t, vmcommon.IsSmartContractAddress(destination))
			}
			require.Equal(t, uint32(1), coordinator.ComputeId(sender))
			require.Equal(t, uint32(1), coordinator.ComputeId(destination))
			require.NotEqual(t, sender, destination)
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.CheckCorrectTokenIDForTransferRoleFlag, builtInFunctions.FixAsyncCallbackCheckFlag, builtInFunctions.CheckFunctionArgumentFlag, builtInFunctions.ConsistentTokensValuesLengthCheckFlag)
			settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(store, marshaller, true, core.BuiltInFunctionESDTPause, func() bool { return true })
			require.NoError(t, err)
			roles, err := builtInFunctions.NewESDTRolesFunc(marshaller, true)
			require.NoError(t, err)
			function, err := builtInFunctions.NewESDTTransferFunc(7, marshaller, settings, coordinator, roles, flags)
			require.NoError(t, err)
			tokenID := []byte("TOKEN-abcdef")
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
			before := map[string][]byte{}
			for address, value := range map[string]int64{string(sender): 5, string(destination): 1} {
				token := &esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(value)}
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
				require.NoError(t, system.(state.UserAccountHandler).SaveKeyValue(key, (&builtInFunctions.ESDTGlobalMetadata{LimitedTransfer: true}).ToBytes()))
				require.NoError(t, store.SaveAccount(system))
			}
			root, err := store.Commit()
			require.NoError(t, err)
			hook, _ := qualT42Hook(t, store, 1, false, coordinator)
			payable, err := builtInFunctions.NewPayableCheckFunc(hook, flags)
			require.NoError(t, err)
			require.NoError(t, function.SetPayableChecker(payable))
			require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(core.BuiltInFunctionESDTTransfer, function))
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(sender), CallValue: big.NewInt(0), GasProvided: 1000, GasLocked: 11, Arguments: [][]byte{tokenID, {2}}}, RecipientAddr: bytes.Clone(destination), Function: core.BuiltInFunctionESDTTransfer}
			if mode == "callback" {
				input.CallerAddr = bytes.Repeat([]byte{2}, 32)
				require.Equal(t, uint32(2), coordinator.ComputeId(input.CallerAddr))
				input.CallType = vm.AsynchronousCallBack
			}
			if mode == "follow-on" {
				input.Arguments = append(input.Arguments, []byte("follow"), []byte("arg"))
			}
			if mode == "system" {
				input.RecipientAddr = bytes.Clone(core.SystemAccountAddress)
				require.True(t, vmcommon.IsSystemAccountAddress(input.RecipientAddr))
			}
			if mode == "metachain" {
				input.RecipientAddr = bytes.Clone(core.ESDTSCAddress)
				require.Equal(t, uint32(core.MetachainShardId), coordinator.ComputeId(input.RecipientAddr))
			}
			if mode == "limited" || mode == "system" || mode == "metachain" {
				account, e := store.GetExistingAccount(sender)
				require.NoError(t, e)
				var receiver vmcommon.UserAccountHandler
				if mode == "limited" {
					destinationAccount, loadErr := store.GetExistingAccount(destination)
					require.NoError(t, loadErr)
					receiver = destinationAccount.(vmcommon.UserAccountHandler)
				}
				out, e := function.ProcessBuiltinFunction(account.(vmcommon.UserAccountHandler), receiver, input)
				require.Nil(t, out)
				expected := builtInFunctions.ErrInvalidRcvAddr
				if mode == "limited" {
					expected = builtInFunctions.ErrActionNotAllowed
				}
				require.ErrorIs(t, e, expected)
				actual, _, e := account.(state.UserAccountHandler).RetrieveValue(key)
				require.NoError(t, e)
				require.Equal(t, before[string(sender)], actual, "native admission must precede debit without hook rollback")
				require.Zero(t, store.JournalLen())
				return
			}
			fault := errors.New("qualification fungible sender save")
			if mode == "late save" {
				store.fault = fault
			}
			out, err := hook.ProcessBuiltInFunction(input)
			store.fault = nil
			denied := mode == "late save" || mode == "nonpayable"
			if denied {
				require.Nil(t, out)
				expected := fault
				if mode == "nonpayable" {
					expected = builtInFunctions.ErrAccountNotPayable
				}
				require.ErrorIs(t, err, expected)
				after, e := store.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
				require.Zero(t, store.JournalLen())
			} else {
				require.NoError(t, err)
				wantGas := uint64(993)
				if mode == "callback" {
					wantGas = 1000
				}
				if mode == "follow-on" {
					wantGas = 0
				}
				logData := [][]byte{{}, []byte(input.Function)}
				logData = append(logData, input.Arguments...)
				expected := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: wantGas, Logs: []*vmcommon.LogEntry{{Identifier: []byte(core.BuiltInFunctionESDTTransfer), Address: input.CallerAddr, Topics: [][]byte{tokenID, {}, {2}, destination}, Data: logData}}}
				if mode == "follow-on" {
					expected.OutputAccounts = map[string]*vmcommon.OutputAccount{string(destination): {Address: destination, OutputTransfers: []vmcommon.OutputTransfer{{Index: 1, Value: big.NewInt(0), GasLimit: 993, GasLocked: 11, Data: []byte("follow@617267"), CallType: vm.DirectCall, SenderAddress: sender}}}}
				}
				require.Equal(t, expected, out)
			}
			committed, e := store.Commit()
			require.NoError(t, e)
			if denied {
				require.Equal(t, root, committed)
			}
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
			for address, prior := range before {
				account, e := store.GetExistingAccount([]byte(address))
				require.NoError(t, e)
				user := account.(state.UserAccountHandler)
				actual, _, e := user.RetrieveValue(key)
				require.NoError(t, e)
				if denied {
					require.Equal(t, prior, actual)
				} else {
					value := int64(3)
					if mode == "callback" && address == string(sender) {
						value = 5
					}
					want, e := marshaller.Marshal(&esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(value)})
					require.NoError(t, e)
					require.Equal(t, want, actual)
				}
				if address == string(sender) {
					require.Equal(t, big.NewInt(100), user.GetBalance())
				} else {
					require.Zero(t, user.GetBalance().Sign())
				}
			}
		})
	}
}
