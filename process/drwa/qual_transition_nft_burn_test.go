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
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native burn accounting only; full transfer/classification restrictions remain SP2-25/68/42.
func TestQualTransitionR13NFTBurnNative(t *testing.T) {
	for _, mode := range []string{"partial", "all", "zero", "excess", "role", "exec", "nonce", "liquidity", "late save"} {
		t.Run(mode+" should compose native debit and liquidity atomically", func(t *testing.T) {
			store := &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}
			marshaller := &marshal.GogoProtoMarshalizer{}
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.SaveToSystemAccountFlag, builtInFunctions.SendAlwaysFlag)
			settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(store, marshaller, true, core.BuiltInFunctionESDTPause, func() bool { return true })
			require.NoError(t, err)
			storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: store, GlobalSettingsHandler: settings, Marshalizer: marshaller, EnableEpochsHandler: flags, ShardCoordinator: testscommon.NewMultiShardsCoordinatorMock(3)})
			require.NoError(t, err)
			roles, err := builtInFunctions.NewESDTRolesFunc(marshaller, true)
			require.NoError(t, err)
			function, err := builtInFunctions.NewESDTNFTBurnFunc(7, storage, settings, roles)
			require.NoError(t, err)
			tokenID := []byte("TOKEN-abcdef")
			base := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
			key := append(bytes.Clone(base), 1)
			userToken := &esdt.ESDigitalToken{Type: uint32(core.SemiFungible), Value: big.NewInt(5), Properties: []byte{0, 0}}
			systemToken := &esdt.ESDigitalToken{Type: uint32(core.SemiFungible), Value: big.NewInt(12), Reserved: []byte{1}, TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("preserved")}}
			if mode == "liquidity" {
				systemToken.Value = big.NewInt(1)
			}
			priorUser, err := marshaller.Marshal(userToken)
			require.NoError(t, err)
			priorSystem, err := marshaller.Marshal(systemToken)
			require.NoError(t, err)
			for address, value := range map[string][]byte{string(qualContainmentAddress): priorUser, string(core.SystemAccountAddress): priorSystem} {
				account, loadErr := store.LoadAccount([]byte(address))
				require.NoError(t, loadErr)
				user := account.(state.UserAccountHandler)
				require.NoError(t, user.SaveKeyValue(key, value))
				if bytes.Equal([]byte(address), qualContainmentAddress) {
					require.NoError(t, user.SaveKeyValue(base, priorUser))
					if mode != "role" {
						encoded, marshalErr := marshaller.Marshal(&esdt.ESDTRoles{Roles: [][]byte{[]byte(core.ESDTRoleNFTBurn)}})
						require.NoError(t, marshalErr)
						require.NoError(t, user.SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), tokenID...), encoded))
					}
				}
				require.NoError(t, store.SaveAccount(user))
			}
			root, err := store.Commit()
			require.NoError(t, err)
			hook, _ := qualT42Hook(t, store, 1, false)
			require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(core.BuiltInFunctionESDTNFTBurn, function))
			quantity := big.NewInt(2)
			switch mode {
			case "zero":
				quantity.SetInt64(0)
			case "all":
				quantity.SetInt64(5)
			case "excess":
				quantity.SetInt64(6)
			}
			nonce := []byte{1}
			if mode == "nonce" {
				nonce = nil
			}
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(qualContainmentAddress), CallValue: big.NewInt(0), GasProvided: 1000, Arguments: [][]byte{tokenID, nonce, quantity.Bytes()}}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: core.BuiltInFunctionESDTNFTBurn}
			if mode == "exec" {
				input.CallType = vm.ExecOnDestByCaller
			}
			fault := errors.New("qualification sender save after burn")
			if mode == "late save" {
				store.fault = fault
			}
			out, err := hook.ProcessBuiltInFunction(input)
			store.fault = nil
			success := mode == "partial" || mode == "all" || mode == "zero"
			if success {
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 993, Logs: []*vmcommon.LogEntry{{Identifier: []byte(core.BuiltInFunctionESDTNFTBurn), Address: qualContainmentAddress, Topics: [][]byte{tokenID, {1}, quantity.Bytes()}}}}, out)
			} else {
				require.Nil(t, out)
				expected := builtInFunctions.ErrInvalidNFTQuantity
				switch mode {
				case "role", "exec":
					expected = builtInFunctions.ErrActionNotAllowed
				case "nonce":
					expected = builtInFunctions.ErrNFTDoesNotHaveMetadata
				case "liquidity":
					expected = builtInFunctions.ErrInvalidLiquidityForESDT
				case "late save":
					expected = fault
				}
				require.ErrorIs(t, err, expected)
				after, rootErr := store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, root, after)
				require.Zero(t, store.JournalLen())
			}
			committed, err := store.Commit()
			require.NoError(t, err)
			if !success {
				require.Equal(t, root, committed)
			}
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
			account, err := store.GetExistingAccount(qualContainmentAddress)
			require.NoError(t, err)
			user := account.(state.UserAccountHandler)
			actual, _, err := user.RetrieveValue(key)
			require.NoError(t, err)
			if !success {
				require.Equal(t, priorUser, actual)
			} else if mode == "all" {
				require.Empty(t, actual)
			} else {
				userToken.Value = big.NewInt(5 - quantity.Int64())
				expected, marshalErr := marshaller.Marshal(userToken)
				require.NoError(t, marshalErr)
				require.Equal(t, expected, actual)
			}
			actual = qualRegistryValue(t, store.qualNativeStore, string(key))
			if !success {
				require.Equal(t, priorSystem, actual)
			} else {
				systemToken.Value = big.NewInt(12 - quantity.Int64())
				expected, marshalErr := marshaller.Marshal(systemToken)
				require.NoError(t, marshalErr)
				require.Equal(t, expected, actual)
			}
			require.Equal(t, big.NewInt(100), user.GetBalance())
			baseAfter, _, err := user.RetrieveValue(base)
			require.NoError(t, err)
			require.Equal(t, priorUser, baseAfter)
		})
	}
}
