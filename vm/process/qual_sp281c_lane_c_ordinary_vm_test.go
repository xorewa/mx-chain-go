package process

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type ordinaryVMContext struct {
	*mock.SystemEIStub
	setAddress func([]byte)
	setGas     func(uint64)
}

func (c *ordinaryVMContext) SetSCAddress(address []byte) {
	c.setAddress(address)
}

func (c *ordinaryVMContext) SetGasProvided(gas uint64) {
	c.setGas(gas)
}

func TestQualSP281CLaneCOrdinaryCreateForwarding(t *testing.T) {
	t.Parallel()

	input := &vmcommon.ContractCreateInput{
		VMInput: vmcommon.VMInput{
			CallerAddr:  []byte("synthetic-deployer"),
			Arguments:   [][]byte{[]byte("init argument")},
			CallValue:   big.NewInt(7),
			GasPrice:    3,
			GasProvided: 41,
		},
		ContractCode: []byte("synthetic-code"),
	}
	want := &vmcommon.ContractCreateInput{
		VMInput: vmcommon.VMInput{
			CallerAddr:  []byte("synthetic-deployer"),
			Arguments:   [][]byte{[]byte("init argument")},
			CallValue:   big.NewInt(7),
			GasPrice:    3,
			GasProvided: 41,
		},
		ContractCode: []byte("synthetic-code"),
	}
	var steps []string
	contextOutput := &vmcommon.VMOutput{GasRemaining: 17, ReturnData: [][]byte{[]byte("init result")}}
	contract := &mock.SystemSCStub{ExecuteCalled: func(actual *vmcommon.ContractCallInput) vmcommon.ReturnCode {
		steps = append(steps, "execute")
		require.Equal(t, &vmcommon.ContractCallInput{
			VMInput:       want.VMInput,
			RecipientAddr: want.CallerAddr,
			Function:      core.SCDeployInitFunctionName,
		}, actual)
		return vmcommon.UserError
	}}
	args := createMockArguments()
	args.SystemContracts = &mock.SystemSCContainerStub{GetCalled: func(address []byte) (vm.SystemSmartContract, error) {
		steps = append(steps, "lookup")
		require.Equal(t, want.CallerAddr, address)
		return contract, nil
	}}
	args.SystemEI = &ordinaryVMContext{
		SystemEIStub: &mock.SystemEIStub{
			CleanCacheCalled: func() { steps = append(steps, "reset") },
			AddCodeCalled: func(address, code []byte) {
				steps = append(steps, "code")
				require.Equal(t, want.CallerAddr, address)
				require.Equal(t, want.ContractCode, code)
			},
			CreateVMOutputCalled: func() *vmcommon.VMOutput {
				steps = append(steps, "output")
				return contextOutput
			},
		},
		setAddress: func(address []byte) {
			steps = append(steps, "address")
			require.Equal(t, want.CallerAddr, address)
		},
		setGas: func(uint64) { t.Fatal("create unexpectedly installed call gas in the context") },
	}
	system, err := NewSystemVM(args)
	require.NoError(t, err)

	output, err := system.RunSmartContractCreate(input)
	require.NoError(t, err)
	require.Equal(t, want, input)
	require.Same(t, contextOutput, output)
	require.Equal(t, vmcommon.UserError, output.ReturnCode)
	require.Equal(t, uint64(17), output.GasRemaining)
	require.Equal(t, [][]byte{[]byte("init result")}, output.ReturnData)
	require.Equal(t, []string{"reset", "address", "lookup", "execute", "code", "output"}, steps)
}

func TestQualSP281CLaneCOrdinaryCallForwarding(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		function    string
		refusesInit bool
	}{
		{name: "call", function: "syntheticOrdinaryCall"},
		{name: "direct_init", function: core.SCDeployInitFunctionName, refusesInit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := &vmcommon.ContractCallInput{
				VMInput: vmcommon.VMInput{
					CallerAddr:  []byte("synthetic-caller"),
					Arguments:   [][]byte{[]byte("ordinary argument")},
					CallValue:   big.NewInt(9),
					GasProvided: 53,
				},
				RecipientAddr: []byte("synthetic-system-contract"),
				Function:      tc.function,
			}
			var steps []string
			contextOutput := &vmcommon.VMOutput{GasRemaining: 19, ReturnData: [][]byte{[]byte("call result")}}
			contract := &mock.SystemSCStub{ExecuteCalled: func(actual *vmcommon.ContractCallInput) vmcommon.ReturnCode {
				steps = append(steps, "execute")
				require.Same(t, input, actual)
				return vmcommon.Ok
			}}
			args := createMockArguments()
			args.SystemEI = &ordinaryVMContext{
				SystemEIStub: &mock.SystemEIStub{
					CleanCacheCalled: func() { steps = append(steps, "reset") },
					AddTxValueToSmartContractCalled: func(value *big.Int, address []byte) {
						steps = append(steps, "value")
						require.Equal(t, big.NewInt(9), value)
						require.Equal(t, input.RecipientAddr, address)
					},
					GetContractCalled: func(address []byte) (vm.SystemSmartContract, error) {
						steps = append(steps, "lookup")
						require.Equal(t, input.RecipientAddr, address)
						return contract, nil
					},
					CreateVMOutputCalled: func() *vmcommon.VMOutput {
						steps = append(steps, "output")
						return contextOutput
					},
				},
				setAddress: func(address []byte) {
					steps = append(steps, "address")
					require.Equal(t, input.RecipientAddr, address)
				},
				setGas: func(gas uint64) {
					steps = append(steps, "gas")
					require.Equal(t, uint64(53), gas)
				},
			}
			system, err := NewSystemVM(args)
			require.NoError(t, err)

			output, err := system.RunSmartContractCall(input)
			require.NoError(t, err)
			require.NotNil(t, output)
			if tc.refusesInit {
				require.Equal(t, &vmcommon.VMOutput{
					ReturnCode:    vmcommon.UserError,
					ReturnMessage: "cannot call smart contract init function",
				}, output)
				require.Equal(t, []string{"reset", "address", "value", "gas", "lookup"}, steps)
				return
			}
			require.Same(t, contextOutput, output)
			require.Equal(t, vmcommon.Ok, output.ReturnCode)
			require.Equal(t, uint64(19), output.GasRemaining)
			require.Equal(t, [][]byte{[]byte("call result")}, output.ReturnData)
			require.Equal(t, []string{"reset", "address", "value", "gas", "lookup", "execute", "output"}, steps)
		})
	}
}

func TestQualSP281CLaneCOrdinaryGasSchedule(t *testing.T) {
	t.Parallel()

	system, err := NewSystemVM(createMockArguments())
	require.NoError(t, err)

	system.GasScheduleChange(nil)
	require.Equal(t, uint64(1000), system.asyncCallStepCost)
	require.Equal(t, uint64(3000), system.asyncCallbackGasLock)

	system.GasScheduleChange(map[string]map[string]uint64{
		common.BaseOpsAPICost: {
			common.AsyncCallStepField:        1100,
			common.AsyncCallbackGasLockField: 3100,
		},
	})
	require.Equal(t, uint64(1100), system.asyncCallStepCost)
	require.Equal(t, uint64(3100), system.asyncCallbackGasLock)
}
