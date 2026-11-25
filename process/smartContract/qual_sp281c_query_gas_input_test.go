package smartContract

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CQueryGasInput(t *testing.T) {
	vmErr := errors.New("VM call failed")
	for _, tc := range []struct {
		name     string
		data     string
		vmErr    error
		wantVM   int
		wantFee  int
		wantCost uint64
		wantErr  error
	}{
		{name: "ordinary estimate", data: "inspect@00ff@6162", wantVM: 1, wantFee: 1, wantCost: 11},
		{name: "invalid argument", data: "inspect@zz", wantErr: parsers.ErrTokenizeFailed},
		{name: "VM error", data: "inspect@00ff@6162", vmErr: vmErr, wantVM: 1, wantErr: vmErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &transaction.Transaction{
				SndAddr: []byte("ordinary-caller"),
				RcvAddr: []byte(DummyScAddress),
				Value:   big.NewInt(19),
				Data:    []byte(tc.data),
			}
			var lookups, calls, fees int
			args := createMockArgumentsForSCQuery()
			args.VmContainer = &mock.VMContainerMock{
				GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
					lookups++
					return &mock.VMExecutionHandlerStub{
						RunSmartContractCallCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
							calls++
							require.Equal(t, []byte("ordinary-caller"), input.CallerAddr)
							require.Equal(t, []byte(DummyScAddress), input.RecipientAddr)
							require.Equal(t, "inspect", input.Function)
							require.Equal(t, [][]byte{{0x00, 0xff}, {'a', 'b'}}, input.Arguments)
							require.Equal(t, big.NewInt(19), input.CallValue)
							require.Equal(t, vmData.DirectCall, input.CallType)
							require.Equal(t, uint64(1), input.GasPrice)
							require.Equal(t, uint64(100), input.GasProvided)
							if tc.vmErr != nil {
								return nil, tc.vmErr
							}
							return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 96}, nil
						},
					}, nil
				},
			}
			args.EconomicsFee = &economicsmocks.EconomicsHandlerMock{
				MaxGasLimitPerBlockCalled: func(uint32) uint64 { return math.MaxUint64 },
				ComputeGasLimitCalled: func(input data.TransactionWithFeeHandler) uint64 {
					fees++
					require.Same(t, tx, input)
					return 7
				},
			}
			service, err := NewSCQueryService(args)
			require.NoError(t, err)
			service.gasForQuery = 100

			got, err := service.ComputeScCallGasLimit(tx)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.wantCost, got)
			require.Equal(t, tc.wantVM, lookups)
			require.Equal(t, tc.wantVM, calls)
			require.Equal(t, tc.wantFee, fees)
		})
	}
}
