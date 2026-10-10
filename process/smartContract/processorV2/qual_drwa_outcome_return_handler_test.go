package processorV2

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// T25/Part A 4.7.5 native capability experiment, expected model02 H01-H06.
// Hook/account/finish services are native test doubles. There is no actual
// debit, token credit, incoming-item consumption, regulated refund, journal,
// canonical proof or recovery. Native Ok is deliberately NOT a credit oracle.
func TestQualDRWAOutcomeReturnHandlerHazard(t *testing.T) {
	hookFailure := errors.New("fixture builtin credit error")
	forwardFailure := errors.New("fixture forwarding error")
	for _, c := range []struct {
		name, message             string
		callType                  vmData.CallType
		innerCode, outerCode      vmcommon.ReturnCode
		hookErr, forwardErr       error
		forwardCalls, finishCalls int
		gas                       uint64
		processFail               bool
	}{
		{name: "return_inner_error", message: "denied", innerCode: vmcommon.UserError, outerCode: vmcommon.Ok, forwardCalls: 1, finishCalls: 1, gas: 8},
		{name: "no_return_message_control", innerCode: vmcommon.UserError, outerCode: vmcommon.UserError, processFail: true},
		{name: "callback_control", message: "denied", callType: vmData.AsynchronousCallBack, innerCode: vmcommon.UserError, outerCode: vmcommon.UserError, processFail: true},
		{name: "return_hook_error", message: "denied", hookErr: hookFailure, innerCode: vmcommon.UserError, outerCode: vmcommon.Ok, forwardCalls: 1, finishCalls: 1},
		{name: "forwarding_failure", message: "denied", innerCode: vmcommon.UserError, outerCode: vmcommon.Ok, forwardErr: forwardFailure, forwardCalls: 1},
		{name: "inner_ok_control", message: "denied", innerCode: vmcommon.Ok, outerCode: vmcommon.Ok, forwardCalls: 1, finishCalls: 1, gas: 8},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.ArgsParser = smartContract.NewArgumentParser()
			args.Marshalizer = &marshal.GogoProtoMarshalizer{}
			args.Hasher = sha256.NewSha256()
			args.TxTypeHandler = &testscommon.TxTypeHandlerMock{
				ComputeTransactionTypeCalled: func(data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
					return process.BuiltInFunctionCall, process.BuiltInFunctionCall, false
				},
			}
			hookCalls, forwardCalls, logCalls, feeCalls, gasCalls, cacheCalls := 0, 0, 0, 0, 0, 0
			args.BlockChainHook = &testscommon.BlockChainHookStub{
				ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					hookCalls++
					require.Equal(t, core.BuiltInFunctionESDTTransfer, input.Function)
					require.Equal(t, [][]byte{[]byte("TOKEN-abcdef"), {30}}, input.Arguments)
					require.Equal(t, c.message != "", input.ReturnCallAfterError)
					require.Equal(t, c.callType, input.CallType)
					require.Equal(t, uint64(100), input.GasProvided)
					require.Zero(t, input.GasLocked)
					require.Zero(t, input.CallValue.Sign())
					require.Equal(t, bytes.Repeat([]byte{1}, 32), input.CallerAddr)
					require.Equal(t, bytes.Repeat([]byte{2}, 32), input.RecipientAddr)
					if c.hookErr != nil {
						return nil, c.hookErr
					}
					return &vmcommon.VMOutput{ReturnCode: c.innerCode, ReturnMessage: "inner denial", GasRemaining: 8}, nil
				},
			}
			args.ScrForwarder = &mock.IntermediateTransactionHandlerMock{
				AddIntermediateTransactionsCalled: func(results []data.TransactionHandler, _ []byte) error {
					forwardCalls++
					require.Empty(t, results, "the early-finish branch emits no additional return")
					return c.forwardErr
				},
			}
			args.TxLogsProcessor = &mock.TxLogsProcessorStub{
				SaveLogCalled: func(_ []byte, _ data.TransactionHandler, _ []*vmcommon.LogEntry) error {
					logCalls++
					return nil
				},
			}
			args.TxFeeHandler = &mock.FeeAccumulatorStub{
				ProcessTransactionFeeCalled: func(_, _ *big.Int, _ []byte) { feeCalls++ },
			}
			args.GasHandler = &testscommon.GasHandlerStub{
				SetGasRefundedCalled: func(gas uint64, _ []byte) {
					gasCalls++
					require.Equal(t, c.gas, gas)
				},
			}
			args.VMOutputCacher = &cache.CacherStub{
				PutCalled: func(_ []byte, value interface{}, _ int) bool {
					cacheCalls++
					output, ok := value.(*vmcommon.VMOutput)
					require.True(t, ok)
					require.Equal(t, c.innerCode, output.ReturnCode)
					require.Equal(t, c.gas, output.GasRemaining)
					if c.hookErr != nil {
						require.Equal(t, hookFailure.Error(), output.ReturnMessage)
					}
					return false
				},
			}
			processor, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			input := &smartContractResult.SmartContractResult{
				SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32), Value: big.NewInt(0),
				GasLimit: 100, GasPrice: 7, CallType: c.callType, ReturnMessage: []byte(c.message),
				Data: []byte("ESDTTransfer@544f4b454e2d616263646566@1e"),
			}
			if c.callType == vmData.AsynchronousCallBack {
				input.Data = append(input.Data, []byte("@0102@03@04@00")...)
			}
			failure := NewFailureContext()
			code, err := processor.doExecuteBuiltInFunctionWithoutFailureProcessing(input, nil, nil, failure)
			require.Equal(t, c.outerCode, code)
			if c.forwardErr != nil {
				require.ErrorIs(t, err, c.forwardErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, 1, hookCalls)
			require.Equal(t, c.forwardCalls, forwardCalls)
			require.Equal(t, c.finishCalls, logCalls)
			require.Equal(t, c.finishCalls, feeCalls)
			require.Equal(t, c.finishCalls, gasCalls)
			require.Equal(t, c.finishCalls, cacheCalls)
			require.Equal(t, c.processFail, failure.processFail)
		})
	}
}
