package systemSmartContracts

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	"github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestQualPartialsG25ClassifierConstruction(t *testing.T) {
	args := createDefaultEeiArgs()
	host, err := NewVMContext(args)
	require.NoError(t, err)
	require.NotNil(t, host)
	var typedNil *publicClassifier
	args.DRWAClassifier = typedNil
	host, err = NewVMContext(args)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, host)
	failure := errors.New("synthetic account identity failure")
	args.DRWAClassifier = &publicClassifier{accountsErr: failure}
	host, err = NewVMContext(args)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.ErrorIs(t, err, failure)
	require.Nil(t, host)
}

// The native AddCode output starts with the persisted balance; successive value
// additions accumulate only the delta. The configured ordinary classifier stays
// installed. Values and addresses are synthetic R7 fixtures.
func TestQualPartialsG25PersistedBalanceComposition(t *testing.T) {
	address := bytes.Repeat([]byte{7}, 32)
	account, err := accounts.NewUserAccount(address, &trie.DataTrieTrackerStub{}, &trie.TrieLeafParserStub{})
	require.NoError(t, err)
	require.NoError(t, account.AddToBalance(big.NewInt(1000)))
	args := createDefaultEeiArgs()
	args.DRWAClassifier = &publicClassifier{}
	reads := 0
	args.BlockChainHook = &mock.BlockChainHookStub{GetUserAccountCalled: func(got []byte) (vmcommon.UserAccountHandler, error) {
		require.Equal(t, address, got)
		reads++
		return account, nil
	}}
	host, err := NewVMContext(args)
	require.NoError(t, err)
	host.AddCode(address, []byte("synthetic code"))
	host.AddTxValueToSmartContract(big.NewInt(250), address)
	host.AddTxValueToSmartContract(big.NewInt(7), address)
	require.Equal(t, 1, reads)
	require.Equal(t, big.NewInt(1000), host.outputAccounts[string(address)].Balance)
	require.Equal(t, big.NewInt(257), host.outputAccounts[string(address)].BalanceDelta)
	total := host.GetBalance(address)
	require.Equal(t, big.NewInt(1257), total)
	total.SetInt64(1)
	require.Equal(t, big.NewInt(1257), host.GetBalance(address))
	require.Equal(t, big.NewInt(1000), account.GetBalance())
}

// Bind the new once-only token-type guard to the retained public classifier.
// This exercises native in-process Execute, without a factory or network.
func TestQualPartialsG25TokenUpdateComposition(t *testing.T) {
	classifier := &publicClassifier{}
	contextArgs := createDefaultEeiArgs()
	contextArgs.DRWAClassifier = classifier
	contextArgs.BlockChainHook = &mock.BlockChainHookStub{GetStorageDataCalled: func([]byte, []byte) ([]byte, uint32, error) { return nil, 0, nil }, NumberOfShardsCalled: func() uint32 { return 3 }}
	host, err := NewVMContext(contextArgs)
	require.NoError(t, err)
	host.SetSCAddress(core.ESDTSCAddress)
	args := createMockArgumentsForESDT()
	args.Eei = host
	args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.DynamicESDTFlag, common.FixCorrectSmallIntAndGasLimitsFlag)
	contract, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	input := getDefaultVmInputForFunc("updateTokenID", [][]byte{[]byte("TOKEN-abcdef")})
	input.RecipientAddr = core.ESDTSCAddress
	require.NoError(t, contract.saveToken(input.Arguments[0], &ESDTDataV2{TokenType: []byte(core.NonFungibleESDT), OwnerAddress: input.CallerAddr}))
	host.gasRemaining = 1000000
	require.Equal(t, vmcommon.Ok, contract.Execute(input))
	require.Equal(t, 1, classifier.calls)
	data, err := contract.getExistingToken(input.Arguments[0])
	require.NoError(t, err)
	require.Equal(t, []byte(core.NonFungibleESDTv2), data.TokenType)
	host.returnMessage = ""
	require.Equal(t, vmcommon.UserError, contract.Execute(input))
	require.Contains(t, host.returnMessage, "token was already updated or not non-fungible")
	require.Equal(t, 2, classifier.calls)
	classifier.regulated = true
	host.returnMessage = ""
	require.Equal(t, vmcommon.UserError, contract.Execute(input))
	require.Equal(t, "DRWA public operation denied", host.returnMessage)
	require.Equal(t, 3, classifier.calls)
}

func TestQualPartialsG25DecimalFailureRoutes(t *testing.T) {
	for _, function := range []string{"issue", "registerMetaESDT", "registerAndSetAllRoles", "changeSFTToMetaESDT", "registerDynamic"} {
		for _, width := range []uint{0, 32, 64} {
			t.Run(fmt.Sprintf("%s/width_%d", function, width), func(t *testing.T) {
				args := createMockArgumentsForESDT()
				host := createDefaultEei()
				args.Eei = host
				args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag, common.MetaESDTSetFlag, common.ESDTRegisterAndSetAllRolesFlag, common.DynamicESDTFlag)
				contract, err := NewESDTSmartContract(args)
				require.NoError(t, err)
				decimals := big.NewInt(19)
				if width != 0 {
					decimals.Lsh(big.NewInt(1), width)
					decimals.Add(decimals, big.NewInt(18))
				}
				arguments := [][]byte{[]byte("TokenName"), []byte("TOKEN"), []byte("META"), decimals.Bytes()}
				switch function {
				case "issue":
					arguments[2] = big.NewInt(1).Bytes()
				case "registerMetaESDT":
					arguments = [][]byte{arguments[0], arguments[1], decimals.Bytes()}
				case "changeSFTToMetaESDT":
					arguments = [][]byte{[]byte("TOKEN-abcdef"), decimals.Bytes()}
				}
				input := getDefaultVmInputForFunc(function, arguments)
				input.CallValue = new(big.Int).Set(contract.baseIssuingCost)
				if function == "changeSFTToMetaESDT" {
					input.CallValue = big.NewInt(0)
				}
				host.gasRemaining = 1000000
				input.GasProvided = host.gasRemaining
				require.Equal(t, vmcommon.UserError, contract.Execute(input))
				require.Contains(t, host.returnMessage, vm.ErrInvalidNumberOfDecimals.Error())
				require.Empty(t, host.logs)
			})
		}
	}
}
func TestQualPartialsG25TokenUpdateSaveFailure(t *testing.T) {
	contextArgs := createDefaultEeiArgs()
	contextArgs.DRWAClassifier = &publicClassifier{}
	contextArgs.BlockChainHook = &mock.BlockChainHookStub{GetStorageDataCalled: func([]byte, []byte) ([]byte, uint32, error) { return nil, 0, nil }, NumberOfShardsCalled: func() uint32 { return 3 }}
	host, err := NewVMContext(contextArgs)
	require.NoError(t, err)
	host.SetSCAddress(core.ESDTSCAddress)
	args := createMockArgumentsForESDT()
	args.Eei = host
	args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.DynamicESDTFlag, common.FixCorrectSmallIntAndGasLimitsFlag)
	contract, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	input := getDefaultVmInputForFunc("updateTokenID", [][]byte{[]byte("TOKEN-abcdef")})
	input.RecipientAddr = core.ESDTSCAddress
	require.NoError(t, contract.saveToken(input.Arguments[0], &ESDTDataV2{TokenType: []byte(core.NonFungibleESDT), OwnerAddress: input.CallerAddr}))
	original := contract.marshalizer
	failure := errors.New("synthetic token persistence encoding failure")
	calls := 0
	contract.marshalizer = &marshallerMock.MarshalizerStub{UnmarshalCalled: original.Unmarshal, MarshalCalled: func(interface{}) ([]byte, error) { calls++; return nil, failure }}
	host.gasRemaining = 1000000
	require.Equal(t, vmcommon.UserError, contract.Execute(input))
	require.Equal(t, 1, calls)
	require.Contains(t, host.returnMessage, failure.Error())
	require.Empty(t, host.logs)
	data, err := contract.getExistingToken(input.Arguments[0])
	require.NoError(t, err)
	require.Equal(t, []byte(core.NonFungibleESDT), data.TokenType)
}
