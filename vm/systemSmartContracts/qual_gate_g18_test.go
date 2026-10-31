package systemSmartContracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualGateG18StakeWidthDenialState(t *testing.T) {
	require.False(t, isNumArgsCorrectToStake([][]byte{new(big.Int).Lsh(big.NewInt(1), 63).Bytes()}), "node count must be bounded before arity multiplication")
	args := createMockArgumentsForValidatorSCWithRealAddresses()
	eei := createDefaultEei()
	args.Eei = eei
	contract, err := NewValidatorSmartContract(args)
	require.NoError(t, err)
	input := CreateVmContractCallInput()
	input.Function, input.RecipientAddr = "stake", vm.ValidatorSCAddress
	input.CallerAddr = bytes.Repeat([]byte{7}, 32)
	input.CallValue = big.NewInt(1000)
	input.Arguments = [][]byte{new(big.Int).Lsh(big.NewInt(1), 64).Bytes()}
	before := bytes.Clone(eei.GetStorage(input.CallerAddr))
	require.False(t, isNumArgsCorrectToStake(input.Arguments))
	require.Equal(t, vmcommon.UserError, contract.Execute(input))
	require.Equal(t, "invalid number of arguments to call stake", eei.returnMessage)
	require.Equal(t, before, eei.GetStorage(input.CallerAddr))
	require.Empty(t, eei.logs)
	require.Zero(t, eei.GetBalance(input.CallerAddr).Sign())
	require.Zero(t, eei.GetBalance(vm.ValidatorSCAddress).Sign())
}

func TestQualGateG18WithdrawStateBalanceAndLog(t *testing.T) {
	args := createMockArgumentsForDelegation()
	args.Marshalizer = &marshal.GogoProtoMarshalizer{}
	eei := createDefaultEei()
	eei.blockChainHook = &mock.BlockChainHookStub{CurrentEpochCalled: func() uint32 { return 20 }}
	args.Eei = eei
	contract, err := NewDelegationSystemSC(args)
	require.NoError(t, err)
	user, address := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)
	eei.SetSCAddress(address)
	keys := [][]byte{[]byte("fund1"), []byte("fund2"), []byte("fund3")}
	for i, value := range []int64{100, 50, 30} {
		epoch := uint32(i + 1)
		if i == 2 {
			epoch = 19
		}
		require.NoError(t, contract.saveFund(keys[i], &Fund{Value: big.NewInt(value), Epoch: epoch, Address: user}))
	}
	require.NoError(t, contract.saveDelegatorData(user, &DelegatorData{UnStakedFunds: keys}))
	require.NoError(t, contract.saveDelegationContractConfig(&DelegationConfig{UnBondPeriodInEpochs: 10}))
	require.NoError(t, contract.saveGlobalFundData(&GlobalFundData{TotalUnStaked: big.NewInt(180), TotalActive: big.NewInt(0)}))
	validatorCalls := 0
	eei.systemContracts = &mock.SystemSCContainerStub{GetCalled: func(key []byte) (vm.SystemSmartContract, error) {
		require.Equal(t, vm.ValidatorSCAddress, key)
		return &mock.SystemSCStub{ExecuteCalled: func(input *vmcommon.ContractCallInput) vmcommon.ReturnCode {
			validatorCalls++
			require.Equal(t, "unBondTokens", input.Function)
			eei.output = [][]byte{big.NewInt(30).Bytes()}
			return vmcommon.Ok
		}}, nil
	}}
	input := getDefaultVmInputForFunc("withdraw", nil)
	input.CallerAddr, input.RecipientAddr = user, address
	input.GasProvided = 1000000
	require.Equal(t, vmcommon.Ok, contract.Execute(input))
	require.Equal(t, 1, validatorCalls)
	for i, expected := range []int64{70, 50, 30} {
		fund, readErr := contract.getFund(keys[i])
		require.NoError(t, readErr)
		require.Equal(t, big.NewInt(expected), fund.Value)
	}
	_, delegator, err := contract.getOrCreateDelegatorData(user)
	require.NoError(t, err)
	require.Equal(t, keys, delegator.UnStakedFunds)
	global, err := contract.getGlobalFundData()
	require.NoError(t, err)
	require.Equal(t, big.NewInt(150), global.TotalUnStaked)
	require.Equal(t, big.NewInt(30), eei.GetBalance(user))
	require.Equal(t, big.NewInt(-30), eei.GetBalance(address))
	require.Len(t, eei.logs, 2)
	require.Equal(t, []byte(transferValueOnly), eei.logs[0].Identifier)
	require.Equal(t, address, eei.logs[0].Address)
	require.Equal(t, [][]byte{big.NewInt(0).Bytes(), vm.ValidatorSCAddress}, eei.logs[0].Topics)
	require.Equal(t, []byte("withdraw"), eei.logs[1].Identifier)
	require.Equal(t, user, eei.logs[1].Address)
	require.Len(t, eei.logs[1].Topics, 5)
	require.Equal(t, big.NewInt(30).Bytes(), eei.logs[1].Topics[0])
}
