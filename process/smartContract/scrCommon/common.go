package scrCommon

import (
	"math/big"
	"sync/atomic"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// TestSmartContractProcessor is a SmartContractProcessor used in integration tests
type TestSmartContractProcessor interface {
	process.SmartContractProcessorFacade
	GetCompositeTestError() error
	GetGasRemaining() uint64
	GetAllSCRs() []data.TransactionHandler
	CleanGasRefunded()
}

// ExecutableChecker is an interface for checking if a builtin function is executable
type ExecutableChecker interface {
	CheckIsExecutable(senderAddr []byte, value *big.Int, receiverAddr []byte, gasProvidedForCall uint64, arguments [][]byte) error
}

// ArgsNewSmartContractProcessor defines the arguments needed for new smart contract processor
type ArgsNewSmartContractProcessor struct {
	DRWAAccountDeletionGuard vm.DRWAAccountDeletionGuard
	VmContainer              process.VirtualMachinesContainer
	ArgsParser               process.ArgumentsParser
	Hasher                   hashing.Hasher
	Marshalizer              marshal.Marshalizer
	AccountsDB               state.AccountsAdapter
	BlockChainHook           process.BlockChainHookHandler
	BuiltInFunctions         vmcommon.BuiltInFunctionContainer
	PubkeyConv               core.PubkeyConverter
	ShardCoordinator         sharding.Coordinator
	ScrForwarder             process.IntermediateTransactionHandler
	TxFeeHandler             process.TransactionFeeHandler
	EconomicsFee             process.FeeHandler
	TxTypeHandler            process.TxTypeHandler
	GasHandler               process.GasHandler
	GasSchedule              core.GasScheduleNotifier
	TxLogsProcessor          process.TransactionLogProcessor
	BadTxForwarder           process.IntermediateTransactionHandler
	EnableRoundsHandler      common.EnableRoundsHandler
	EnableEpochsHandler      common.EnableEpochsHandler
	EnableEpochs             config.EnableEpochs
	VMOutputCacher           storage.Cacher
	WasmVMChangeLocker       common.Locker
	IsGenesisProcessing      bool
}

// FindVMByScAddress is exported for use in all version of scr processors
func FindVMByScAddress(container process.VirtualMachinesContainer, scAddress []byte) (vmcommon.VMExecutionHandler, []byte, error) {
	vmType, err := vmcommon.ParseVMTypeFromContractAddress(scAddress)
	if err != nil {
		return nil, nil, err
	}

	vm, err := container.Get(vmType)
	if err != nil {
		return nil, nil, err
	}

	return vm, vmType, nil
}

// DRWANativeCall carries the explicitly selected physical VM and its private
// operation-local token. There is no public accepting constructor. The native
// VM-change read lock is retained by WithDRWANativeCall through all SC effects.
type DRWANativeCall struct {
	physical vm.DRWANativeCallExecutor
	handoff  vm.DRWANativeCallHandoff
	prepared atomic.Bool
	executed atomic.Bool
	failed   atomic.Bool
}

func (c *DRWANativeCall) Begin(tx data.TransactionHandler, accounts state.AccountsAdapter, sender, destination state.UserAccountHandler) error {
	if c == nil || c.physical == nil || check.IfNil(c.handoff) {
		return vm.ErrDRWAExecution
	}
	if !c.executed.CompareAndSwap(false, true) {
		c.failed.Store(true)
		return vm.ErrDRWAExecution
	}
	return c.physical.ValidateDRWANativeTransaction(c.handoff, tx, accounts, sender, destination)
}

// Bind is called by the selected SC owner immediately after native preparation,
// before dispatch. No fee/gas calculation or caller-provided authority is added.
func (c *DRWANativeCall) Bind(input *vmcommon.ContractCallInput) error {
	if c == nil || c.physical == nil || check.IfNil(c.handoff) || !c.executed.Load() || c.failed.Load() {
		return vm.ErrDRWAExecution
	}
	if !c.prepared.CompareAndSwap(false, true) {
		c.failed.Store(true)
		return vm.ErrDRWAExecution
	}
	binder, ok := c.physical.(vm.DRWANativePreparedCall)
	if !ok {
		c.failed.Store(true)
		return vm.ErrDRWAExecution
	}
	if err := binder.BindDRWANativeCall(c.handoff, input); err != nil {
		c.failed.Store(true)
		return err
	}
	return nil
}

func (c *DRWANativeCall) Run(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	if c == nil || c.physical == nil || check.IfNil(c.handoff) || !c.executed.Load() || !c.prepared.Load() || c.failed.Load() {
		return nil, vm.ErrDRWAExecution
	}
	return c.physical.RunSmartContractCallWithDRWA(input, c.handoff)
}

func WithDRWANativeCall(container process.VirtualMachinesContainer, locker common.Locker,
	accounts state.AccountsAdapter, tx data.TransactionHandler, validation any,
	execute func(*DRWANativeCall) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	if check.IfNil(container) || check.IfNil(accounts) || check.IfNil(tx) || locker == nil || execute == nil {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	locker.RLock()
	locked := true
	defer func() {
		if locked {
			locker.RUnlock()
		}
	}()
	physical, _, err := FindVMByScAddress(container, tx.GetRcvAddr())
	if err != nil {
		return vmcommon.ExecutionFailed, err
	}
	owner, ok := physical.(vm.DRWANativeCallExecutor)
	if !ok {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	if !owner.DRWANativeCallConfigured() {
		// Ordinary native execution reselects/locks its VM exactly as before.
		// Do not recursively hold a read lock across a pending VM replacement.
		locker.RUnlock()
		locked = false
		return execute(nil)
	}
	return owner.WithDRWANativeCall(tx, validation, accounts, func(handoff vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
		if check.IfNil(handoff) {
			return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
		}
		call := &DRWANativeCall{physical: owner, handoff: handoff}
		code, err := execute(call)
		if call.failed.Load() {
			return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
		}
		return code, err
	})
}

// CreateExecutableCheckersMap creates a map of executable checker builtin functions
func CreateExecutableCheckersMap(builtinFunctions vmcommon.BuiltInFunctionContainer) map[string]ExecutableChecker {
	executableCheckers := make(map[string]ExecutableChecker)

	for key := range builtinFunctions.Keys() {
		builtinFunc, err := builtinFunctions.Get(key)
		if err != nil {
			continue
		}
		executableCheckerFunc, ok := builtinFunc.(ExecutableChecker)
		if !ok {
			continue
		}
		executableCheckers[key] = executableCheckerFunc
	}

	return executableCheckers
}
