package smartContract

import (
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualGateG17QueryGasBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		remaining, move, expected uint64
		overflow                  bool
	}{
		{"above", 101, 7, 7, false},
		{"equal", 100, 7, 7, false},
		{"below", 99, 7, 8, false},
		{"empty", 0, 7, 107, false},
		{"overflow", 99, math.MaxUint64, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := createMockArgumentsForSCQuery()
			calls := 0
			args.VmContainer = &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) {
				return &mock.VMExecutionHandlerStub{RunSmartContractCallCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					calls++
					require.Equal(t, uint64(100), input.GasProvided)
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: tc.remaining}, nil
				}}, nil
			}}
			args.EconomicsFee = &economicsmocks.EconomicsHandlerMock{
				MaxGasLimitPerBlockCalled: func(uint32) uint64 { return math.MaxUint64 },
				ComputeGasLimitCalled:     func(data.TransactionWithFeeHandler) uint64 { return tc.move },
			}
			service, err := NewSCQueryService(args)
			require.NoError(t, err)
			service.gasForQuery = 100
			cost, err := service.ComputeScCallGasLimit(&transaction.Transaction{RcvAddr: []byte(DummyScAddress), Data: []byte("increment")})
			if tc.overflow {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expected, cost)
			require.Equal(t, 1, calls)
		})
	}
}
