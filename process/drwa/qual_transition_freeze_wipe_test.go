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

type qualTransitionReceiverSaveFault struct {
	*qualNativeStore
	fault error
}

func (s *qualTransitionReceiverSaveFault) SaveAccount(account vmcommon.AccountHandler) error {
	if err := s.qualNativeStore.SaveAccount(account); err != nil {
		return err
	}
	if bytes.Equal(account.AddressBytes(), qualContainmentAddress) {
		return s.fault
	}
	return nil
}

// Native state/log/liquidity only; forged regulated authority remains SP2-25/68.
func TestQualTransitionR09FreezeWipeNative(t *testing.T) {
	for _, mode := range []string{"freeze", "unfreeze", "wipe"} {
		for _, decrease := range []bool{false, true} {
			for _, failSave := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s liquidity flag %t late save %t should retain native effects atomically", mode, decrease, failSave), func(t *testing.T) {
					store := &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}
					caller, err := store.LoadAccount(core.ESDTSCAddress)
					require.NoError(t, err)
					require.NoError(t, store.SaveAccount(caller))
					marshaller := &marshal.GogoProtoMarshalizer{}
					flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.SaveToSystemAccountFlag, builtInFunctions.SendAlwaysFlag)
					flags.RemoveActiveFlags(builtInFunctions.WipeSingleNFTLiquidityDecreaseFlag)
					if decrease {
						flags.AddActiveFlags(builtInFunctions.WipeSingleNFTLiquidityDecreaseFlag)
					}
					settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(store, marshaller, true, core.BuiltInFunctionESDTPause, func() bool { return true })
					require.NoError(t, err)
					storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: store, GlobalSettingsHandler: settings, Marshalizer: marshaller, EnableEpochsHandler: flags, ShardCoordinator: testscommon.NewMultiShardsCoordinatorMock(3)})
					require.NoError(t, err)
					function, err := builtInFunctions.NewESDTFreezeWipeFunc(storage, flags, marshaller, mode == "freeze", mode == "wipe")
					require.NoError(t, err)
					name := core.BuiltInFunctionESDTFreeze
					if mode == "unfreeze" {
						name = core.BuiltInFunctionESDTUnFreeze
					} else if mode == "wipe" {
						name = core.BuiltInFunctionESDTWipe
					}
					tokenID := []byte("TOKEN-abcdef")
					argument := append(bytes.Clone(tokenID), 1)
					key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), argument...)
					properties := []byte{0, 0}
					if mode != "freeze" {
						properties[0] = 1
					}
					userToken := &esdt.ESDigitalToken{Value: big.NewInt(5), Type: uint32(core.NonFungible), Properties: properties, TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("preserved")}}
					priorUser, err := marshaller.Marshal(userToken)
					require.NoError(t, err)
					systemToken := &esdt.ESDigitalToken{Value: big.NewInt(12), Type: uint32(core.NonFungible), Reserved: []byte{1}, TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("system")}}
					priorSystem, err := marshaller.Marshal(systemToken)
					require.NoError(t, err)
					for address, value := range map[string][]byte{string(qualContainmentAddress): priorUser, string(core.SystemAccountAddress): priorSystem} {
						account, loadErr := store.LoadAccount([]byte(address))
						require.NoError(t, loadErr)
						require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, value))
						require.NoError(t, store.SaveAccount(account))
					}
					root, err := store.Commit()
					require.NoError(t, err)
					hook, _ := qualT42Hook(t, store, 1, false)
					require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(name, function))
					fault := errors.New("qualification receiver save after mutation")
					if failSave {
						store.fault = fault
					}
					input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{argument}}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: name}
					out, err := hook.ProcessBuiltInFunction(input)
					store.fault = nil
					if failSave {
						require.ErrorIs(t, err, fault)
						require.Nil(t, out)
						after, rootErr := store.RootHash()
						require.NoError(t, rootErr)
						require.Equal(t, root, after)
						require.Zero(t, store.JournalLen())
						require.Equal(t, 1, store.reverts)
					} else {
						require.NoError(t, err)
						require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, Logs: []*vmcommon.LogEntry{{Identifier: []byte(name), Address: core.ESDTSCAddress, Topics: [][]byte{tokenID, {1}, {5}, qualContainmentAddress}}}}, out)
					}
					committed, err := store.Commit()
					require.NoError(t, err)
					if failSave {
						require.Equal(t, root, committed)
					}
					require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
					account, err := store.GetExistingAccount(qualContainmentAddress)
					require.NoError(t, err)
					user := account.(state.UserAccountHandler)
					actual, _, err := user.RetrieveValue(key)
					require.NoError(t, err)
					if failSave {
						require.Equal(t, priorUser, actual)
					} else if mode == "wipe" {
						require.Empty(t, actual)
					} else {
						want := byte(0)
						if mode == "freeze" {
							want = 1
						}
						token := &esdt.ESDigitalToken{}
						require.NoError(t, marshaller.Unmarshal(token, actual))
						userToken.Properties = []byte{want, 0}
						require.Equal(t, userToken, token)
					}
					actual = qualRegistryValue(t, store.qualNativeStore, string(key))
					if !failSave && mode == "wipe" && decrease {
						token := &esdt.ESDigitalToken{}
						require.NoError(t, marshaller.Unmarshal(token, actual))
						systemToken.Value = big.NewInt(7)
						require.Equal(t, systemToken, token)
					} else {
						require.Equal(t, priorSystem, actual)
					}
					require.Equal(t, big.NewInt(100), user.GetBalance())
				})
			}
		}
	}
}
