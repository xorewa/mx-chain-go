package processProxy

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

type qualD20RejectingSC struct {
	*testscommon.SCProcessorMock
	seen       data.TransactionHandler
	validation any
	denial     error
	scopeCalls int
}

func (c *qualD20RejectingSC) WithDRWANativeTransaction(tx data.TransactionHandler, validation any, _ func(vm.DRWANativeSCExecutor) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	c.scopeCalls++
	c.seen = tx
	c.validation = validation
	return vmcommon.ExecutionFailed, c.denial
}

func TestQualD20ProxyNativeTransactionScope(t *testing.T) {
	ordinary := &testscommon.SCProcessorMock{}
	proxy := &scProcessorProxy{processor: ordinary}
	tx := &transaction.Transaction{}
	observation := &struct{ fixture string }{"synthetic-not-authority"}
	calls := 0
	callback := func(vm.DRWANativeSCExecutor) (vmcommon.ReturnCode, error) {
		calls++
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	_, err := proxy.WithDRWANativeTransaction(tx, observation, callback)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Zero(t, calls)
	for _, version := range []configuredProcessor{procV1, procV2} {
		sentinel := errors.New("synthetic native operation source unavailable")
		selected := &qualD20RejectingSC{SCProcessorMock: ordinary, denial: sentinel}
		proxy.processorsCache = map[configuredProcessor]process.SmartContractProcessorFacade{version: selected}
		proxy.setActiveProcessor(version)
		code, failure := proxy.WithDRWANativeTransaction(tx, observation, callback)
		require.ErrorIs(t, failure, sentinel)
		require.Equal(t, vmcommon.ExecutionFailed, code)
		require.Same(t, tx, selected.seen)
		require.Same(t, observation, selected.validation)
		require.Equal(t, 1, selected.scopeCalls)
		require.Zero(t, calls)
	}
}

func (c *qualD20RejectingSC) ExecuteSmartContractTransactionWithDRWA(tx data.TransactionHandler, _, _ state.UserAccountHandler, v any) (vmcommon.ReturnCode, error) {
	c.seen = tx
	c.validation = v
	return vmcommon.ExecutionFailed, c.denial
}
func TestQualD20ProxyNativeHandoff(t *testing.T) {
	legacy := 0
	ordinary := &testscommon.SCProcessorMock{ExecuteSmartContractTransactionCalled: func(data.TransactionHandler, state.UserAccountHandler, state.UserAccountHandler) (vmcommon.ReturnCode, error) {
		legacy++
		return vmcommon.Ok, nil
	}}
	proxy := &scProcessorProxy{processor: ordinary}
	tx := &transaction.Transaction{}
	validation := &struct{ fixture string }{"synthetic-validation-not-authority"}
	_, err := proxy.ExecuteSmartContractTransactionWithDRWA(tx, nil, nil, validation)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Zero(t, legacy)
	for _, version := range []configuredProcessor{procV1, procV2} {
		sentinel := errors.New("synthetic source refusal")
		selected := &qualD20RejectingSC{SCProcessorMock: ordinary, denial: sentinel}
		proxy.processorsCache = map[configuredProcessor]process.SmartContractProcessorFacade{version: selected}
		proxy.setActiveProcessor(version)
		_, err = proxy.ExecuteSmartContractTransactionWithDRWA(tx, nil, nil, validation)
		require.ErrorIs(t, err, sentinel)
		require.Same(t, tx, selected.seen)
		require.Same(t, validation, selected.validation)
	}
	require.Zero(t, legacy)
}
