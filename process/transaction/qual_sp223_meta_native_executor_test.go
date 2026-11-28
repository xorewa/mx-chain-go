package transaction_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	txproc "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// qualSP223EnteringSource is a labelled synthetic owner that opens the native
// operation and hands the processor its executor.
type qualSP223EnteringSource struct {
	*testscommon.SCProcessorMock
	executor vm.DRWANativeSCExecutor
}

func (s *qualSP223EnteringSource) WithDRWANativeTransaction(_ data.TransactionHandler, _ any,
	execute func(vm.DRWANativeSCExecutor) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return execute(s.executor)
}

// SP2-23: inside an opened native operation the metachain processor hands the
// transaction and the accounts it loaded to the owner's executor, and to
// nothing else; the executor's result is the transaction's result.
func TestQualSP223MetaHandsAnEnteredOperationToItsExecutor(t *testing.T) {
	outcome := errors.New("synthetic executor outcome")
	for _, name := range []string{"DRWARegisterToken", "DRWARegisterBootstrapIntent"} {
		t.Run(name, func(t *testing.T) {
			tx := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress),
				Value: big.NewInt(0), GasPrice: 1, GasLimit: 1, Data: []byte(name + "@00")}
			require.True(t, txproc.RequiresDRWANativeValidationReceipt(tx))
			sender, receiver := createUserAcc(tx.SndAddr), createUserAcc(tx.RcvAddr)
			require.NoError(t, sender.AddToBalance(big.NewInt(100)))
			calls, ordinary := 0, 0
			source := &qualSP223EnteringSource{SCProcessorMock: &testscommon.SCProcessorMock{
				ExecuteSmartContractTransactionCalled: func(data.TransactionHandler, state.UserAccountHandler, state.UserAccountHandler) (vmcommon.ReturnCode, error) {
					ordinary++
					return vmcommon.Ok, nil
				}}}
			source.executor = func(actual data.TransactionHandler, from, to state.UserAccountHandler) (vmcommon.ReturnCode, error) {
				calls++
				require.Same(t, tx, actual)
				require.Same(t, sender, from)
				require.Same(t, receiver, to)
				return vmcommon.UserError, outcome
			}
			args := createMockNewMetaTxArgs()
			args.Accounts = createAccountStub(tx.SndAddr, tx.RcvAddr, sender, receiver)
			args.ScProcessor = source
			args.TxTypeHandler = &testscommon.TxTypeHandlerMock{
				ComputeTransactionTypeCalled: func(data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
					return process.SCInvoking, process.SCInvoking, false
				}}
			processor, err := txproc.NewMetaTxProcessor(args)
			require.NoError(t, err)
			code, err := processor.ProcessTransactionWithDRWA(tx, nil)
			require.ErrorIs(t, err, outcome)
			require.Equal(t, vmcommon.UserError, code)
			require.Equal(t, 1, calls)
			require.Zero(t, ordinary, "the ordinary executor is not used inside a native operation")
		})
	}
}
