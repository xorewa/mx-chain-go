package process

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
)

type systemVM struct {
	systemEI             vm.ContextHandler
	vmType               []byte
	systemContracts      vm.SystemSCContainer
	asyncCallbackGasLock uint64
	asyncCallStepCost    uint64
	mutGasLock           sync.RWMutex
	criticalSection      sync.Mutex
}

// ArgsNewSystemVM defines the needed arguments to create a new system vm
type ArgsNewSystemVM struct {
	SystemEI        vm.ContextHandler
	SystemContracts vm.SystemSCContainer
	VmType          []byte
	GasSchedule     core.GasScheduleNotifier
}

// NewSystemVM instantiates the system VM which is capable of running in protocol smart contracts
func NewSystemVM(args ArgsNewSystemVM) (*systemVM, error) {
	if check.IfNil(args.SystemEI) {
		return nil, vm.ErrNilSystemEnvironmentInterface
	}
	if check.IfNil(args.SystemContracts) {
		return nil, vm.ErrNilSystemContractsContainer
	}
	if len(args.VmType) == 0 { // no need for nil check, len() for nil returns 0
		return nil, vm.ErrNilVMType
	}
	if check.IfNil(args.GasSchedule) {
		return nil, vm.ErrNilGasSchedule
	}

	apiCosts := args.GasSchedule.LatestGasSchedule()[common.BaseOpsAPICost]
	if apiCosts == nil {
		return nil, vm.ErrNilGasSchedule
	}

	s := &systemVM{
		systemEI:             args.SystemEI,
		systemContracts:      args.SystemContracts,
		vmType:               make([]byte, len(args.VmType)),
		asyncCallStepCost:    apiCosts[common.AsyncCallStepField],
		asyncCallbackGasLock: apiCosts[common.AsyncCallbackGasLockField],
	}
	copy(s.vmType, args.VmType)

	if s.asyncCallStepCost == 0 || s.asyncCallbackGasLock == 0 {
		return nil, vm.ErrNilGasSchedule
	}

	args.GasSchedule.RegisterNotifyHandler(s)

	return s, nil
}

// RunSmartContractCreate creates and saves a new smart contract to the trie
func (s *systemVM) RunSmartContractCreate(input *vmcommon.ContractCreateInput) (*vmcommon.VMOutput, error) {
	s.criticalSection.Lock()
	defer s.criticalSection.Unlock()

	if input == nil {
		return nil, vm.ErrInputArgsIsNil
	}
	if input.CallerAddr == nil {
		return nil, vm.ErrInputCallerAddrIsNil
	}
	if context, ok := s.systemEI.(vm.DRWASystemCallContext); ok {
		return context.ExecuteDRWASystemCall(nil, func() (*vmcommon.VMOutput, error) {
			return s.runSmartContractCreate(input)
		})
	}
	return s.runSmartContractCreate(input)
}

func (s *systemVM) runSmartContractCreate(input *vmcommon.ContractCreateInput) (*vmcommon.VMOutput, error) {

	s.systemEI.CleanCache()
	s.systemEI.SetSCAddress(input.CallerAddr)

	contract, err := s.systemContracts.Get(input.CallerAddr)
	if err != nil {
		return nil, vm.ErrUnknownSystemSmartContract
	}

	deployInput := &vmcommon.ContractCallInput{
		VMInput:       input.VMInput,
		RecipientAddr: input.CallerAddr,
		Function:      core.SCDeployInitFunctionName,
	}

	returnCode := contract.Execute(deployInput)

	s.systemEI.AddCode(input.CallerAddr, input.ContractCode)

	vmOutput := s.systemEI.CreateVMOutput()
	vmOutput.ReturnCode = returnCode

	return vmOutput, nil
}

// RunSmartContractCall executes a smart contract according to the input
func (s *systemVM) RunSmartContractCall(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	s.criticalSection.Lock()
	defer s.criticalSection.Unlock()
	if context, ok := s.systemEI.(vm.DRWASystemCallContext); ok {
		return context.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
			return s.runSmartContractCall(input)
		})
	}
	// Unconfigured contexts retain native dispatch, including unknown names.
	// Protected operations require their qualified operation-local consumer;
	// a function name or context presence is never an authentication permit.
	return s.runSmartContractCall(input)
}

func (s *systemVM) runSmartContractCall(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {

	s.systemEI.CleanCache()
	s.systemEI.SetSCAddress(input.RecipientAddr)
	s.systemEI.AddTxValueToSmartContract(input.CallValue, input.RecipientAddr)
	s.systemEI.SetGasProvided(input.GasProvided)

	contract, err := s.systemEI.GetContract(input.RecipientAddr)
	if err != nil {
		return nil, vm.ErrUnknownSystemSmartContract
	}

	if input.Function == core.SCDeployInitFunctionName {
		return &vmcommon.VMOutput{
			ReturnCode:    vmcommon.UserError,
			ReturnMessage: "cannot call smart contract init function",
		}, nil
	}

	returnCode := contract.Execute(input)
	var vmOutput *vmcommon.VMOutput
	if returnCode == vmcommon.Ok {
		vmOutput = s.systemEI.CreateVMOutput()
	} else {
		vmOutput = &vmcommon.VMOutput{
			GasRemaining:  0,
			GasRefund:     big.NewInt(0),
			ReturnMessage: s.systemEI.GetReturnMessage(),
		}
	}

	vmOutput.ReturnCode = returnCode

	return vmOutput, nil
}

// ReplaceDRWAClassifier serializes a healthy candidate handoff with the native
// VM's existing execution boundary. It does not rebuild contracts or subscribe
// gas handlers, and never waits when called reentrantly from native execution.
func (s *systemVM) ReplaceDRWAClassifier(next vm.DRWATokenClassifier) error {
	if !s.criticalSection.TryLock() {
		return vm.ErrDRWAExecution
	}
	defer s.criticalSection.Unlock()
	context, exists := s.systemEI.(interface {
		ReplaceDRWAClassifier(vm.DRWATokenClassifier) error
	})
	if !exists {
		return vm.ErrDRWAExecution
	}
	return context.ReplaceDRWAClassifier(next)
}

// DRWAExecutionError forwards the context's retained failure without creating
// another lifecycle latch. Older native contexts retain their unchanged path.
func (s *systemVM) DRWAExecutionError() error {
	if context, ok := s.systemEI.(interface{ DRWAExecutionError() error }); ok {
		return context.DRWAExecutionError()
	}
	return nil
}

// GetVersion returns an empty string, because the system VM is not versioned
func (s *systemVM) GetVersion() string {
	return ""
}

// GasScheduleChange sets the new gas schedule where it is needed
func (s *systemVM) GasScheduleChange(gasSchedule map[string]map[string]uint64) {
	s.mutGasLock.Lock()
	defer s.mutGasLock.Unlock()

	apiCosts := gasSchedule[common.BaseOpsAPICost]
	if apiCosts == nil {
		return
	}

	s.asyncCallStepCost = apiCosts[common.AsyncCallStepField]
	s.asyncCallbackGasLock = apiCosts[common.AsyncCallbackGasLockField]
}

// Close does nothing, only to implement interface
func (s *systemVM) Close() error {
	return nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *systemVM) IsInterfaceNil() bool {
	return s == nil
}

// WithDRWAAccountDeletion retains this physical VM/current context without
// invoking another prelude, dispatch, Execute or value/gas/output path.
func (s *systemVM) WithDRWAAccountDeletion(accounts state.AccountsAdapter, addresses [][]byte, execute func() error) error {
	if execute == nil || !s.criticalSection.TryLock() {
		return vm.ErrDRWAExecution
	}
	defer s.criticalSection.Unlock()
	guard, ok := s.systemEI.(vm.DRWAAccountDeletionGuard)
	if !ok {
		return vm.ErrDRWAExecution
	}
	return guard.WithDRWAAccountDeletion(accounts, addresses, execute)
}

// drwaNativeCall is never installed in the VM/context or exposed in VMInput.
// The native source owns exclusivity and the original all-effect lease; this
// object only carries that lease to one call on this exact physical VM.
type drwaNativeCall struct {
	mut          sync.Mutex
	vm           *systemVM
	lease        vm.DRWANativeCallLease
	prepared     *vmcommon.ContractCallInput
	active, used bool
	validated    bool
	failure      error
	misused      atomic.Bool
}

func (c *drwaNativeCall) IsInterfaceNil() bool { return c == nil }

// Configuration is only a native-route observation. It is neither a usable
// source nor permission; configured-but-unavailable owners still fail closed.
func (s *systemVM) DRWANativeCallConfigured() bool {
	if s == nil {
		return false
	}
	context, ok := s.systemEI.(interface{ DRWANativeCallConfigured() bool })
	return ok && context.DRWANativeCallConfigured()
}

func (s *systemVM) ValidateDRWANativeTransaction(handoff vm.DRWANativeCallHandoff,
	tx data.TransactionHandler, accounts state.AccountsAdapter, sender, destination state.UserAccountHandler) error {
	call, ok := handoff.(*drwaNativeCall)
	if !ok || call == nil {
		return vm.ErrDRWAExecution
	}
	if !call.mut.TryLock() {
		call.misused.Store(true)
		return vm.ErrDRWAExecution
	}
	defer call.mut.Unlock()
	if call.failure != nil {
		return call.failure
	}
	if call.misused.Load() {
		call.failure = vm.ErrDRWAExecution
		return call.failure
	}
	if s == nil || call.vm != s || !call.active || call.used || call.validated || check.IfNil(call.lease) || check.IfNil(tx) || check.IfNil(accounts) {
		call.failure = vm.ErrDRWAExecution
		return call.failure
	}
	if err := call.lease.VerifyTransaction(tx, accounts, sender, destination); err != nil {
		call.failure = fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
		return call.failure
	}
	call.validated = true
	return nil
}

func (s *systemVM) WithDRWANativeCall(tx data.TransactionHandler, validation any, accounts state.AccountsAdapter,
	execute func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	if s == nil || check.IfNil(tx) || check.IfNil(accounts) || execute == nil {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	source, ok := s.systemEI.(vm.DRWANativeCallContext)
	if !ok {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	var callback sync.Mutex
	var misuse atomic.Bool
	accepting := true
	entered := false
	var childError error
	code, err := source.WithDRWANativeCall(tx, validation, accounts, s, func(lease vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) {
		if !callback.TryLock() {
			misuse.Store(true)
			return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
		}
		defer callback.Unlock()
		if !accepting || entered || check.IfNil(lease) {
			misuse.Store(true)
			childError = vm.ErrDRWAExecution
			return vmcommon.ExecutionFailed, childError
		}
		entered = true
		call := &drwaNativeCall{vm: s, lease: lease, active: true}
		defer func() {
			call.mut.Lock()
			call.active = false
			call.mut.Unlock()
		}()
		result, failure := execute(call)
		call.mut.Lock()
		if call.misused.Load() {
			failure = vm.ErrDRWAExecution
		} else if call.failure != nil {
			failure = call.failure
		} else if failure == nil && result == vmcommon.Ok && !call.used {
			failure = vm.ErrDRWAExecution
		}
		call.mut.Unlock()
		childError = failure
		return result, failure
	})
	callback.Lock()
	defer callback.Unlock()
	accepting = false
	if misuse.Load() || (!entered && err == nil && code == vmcommon.Ok) {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	if childError != nil {
		return vmcommon.ExecutionFailed, childError
	}
	return code, err
}

func (s *systemVM) RunSmartContractCallWithDRWA(input *vmcommon.ContractCallInput,
	handoff vm.DRWANativeCallHandoff) (*vmcommon.VMOutput, error) {
	call, ok := handoff.(*drwaNativeCall)
	if !ok || call == nil {
		return nil, vm.ErrDRWAExecution
	}
	if !call.mut.TryLock() {
		call.misused.Store(true)
		return nil, vm.ErrDRWAExecution
	}
	defer call.mut.Unlock()
	if call.failure != nil {
		return nil, call.failure
	}
	if call.misused.Load() {
		call.failure = vm.ErrDRWAExecution
		return nil, call.failure
	}
	if s == nil || input == nil || call.vm != s || !call.active || call.used || !call.validated || call.prepared == nil || !reflect.DeepEqual(call.prepared, input) || check.IfNil(call.lease) {
		if call.active {
			call.failure = vm.ErrDRWAExecution
		}
		return nil, vm.ErrDRWAExecution
	}
	// A failed use cannot be retried with different bytes under this handoff.
	call.used = true
	if !s.criticalSection.TryLock() {
		call.failure = vm.ErrDRWAExecution
		return nil, vm.ErrDRWAExecution
	}
	defer s.criticalSection.Unlock()
	if err := call.lease.VerifyCall(input); err != nil {
		call.failure = fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
		return nil, call.failure
	}
	// Reuse the complete native prelude, dispatch and output path exactly once.
	// The outer native source already holds the candidate/all-effect lease.
	// Preserve the same before-prelude classifier/error boundary as ordinary
	// RunSmartContractCall. A native origin lease is not a public-token permit.
	var output *vmcommon.VMOutput
	var err error
	if context, ok := s.systemEI.(vm.DRWASystemCallContext); ok {
		output, err = context.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) { return s.runSmartContractCall(input) })
	} else {
		output, err = s.runSmartContractCall(input)
	}
	if call.misused.Load() {
		call.failure = vm.ErrDRWAExecution
		return nil, call.failure
	}
	if failure := call.lease.VerifyCall(input); failure != nil {
		call.failure = fmt.Errorf("%w: %w", vm.ErrDRWAExecution, failure)
		return nil, call.failure
	}
	call.failure = err
	return output, err
}

// BindDRWANativeCall is reached only by the selected SC preparation path.
// The same physical VM's live private token may bind the computed call once.
func (s *systemVM) BindDRWANativeCall(handoff vm.DRWANativeCallHandoff, input *vmcommon.ContractCallInput) error {
	call, ok := handoff.(*drwaNativeCall)
	if !ok || call == nil {
		return vm.ErrDRWAExecution
	}
	if !call.mut.TryLock() {
		call.misused.Store(true)
		return vm.ErrDRWAExecution
	}
	defer call.mut.Unlock()
	if call.failure != nil {
		return call.failure
	}
	if s == nil || input == nil || call.vm != s || !call.active || call.used || !call.validated || call.prepared != nil || call.misused.Load() || check.IfNil(call.lease) {
		call.failure = vm.ErrDRWAExecution
		return call.failure
	}
	binder, ok := call.lease.(vm.DRWANativePreparedCallLease)
	if !ok {
		call.failure = vm.ErrDRWAExecution
		return call.failure
	}
	frozen := freezeDRWACall(input)
	if err := binder.BindCall(freezeDRWACall(frozen)); err != nil {
		call.failure = fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
		return call.failure
	}
	call.prepared = frozen
	return nil
}

// Snapshot every mutable field of the pinned vm-common input. This is only an
// in-memory copy, not a wire codec or authentication of caller-selected data.
func freezeDRWACall(input *vmcommon.ContractCallInput) *vmcommon.ContractCallInput {
	out := *input
	out.CallerAddr = bytes.Clone(input.CallerAddr)
	out.OriginalCallerAddr = bytes.Clone(input.OriginalCallerAddr)
	out.RelayerAddr = bytes.Clone(input.RelayerAddr)
	out.RecipientAddr = bytes.Clone(input.RecipientAddr)
	out.OriginalTxHash = bytes.Clone(input.OriginalTxHash)
	out.CurrentTxHash = bytes.Clone(input.CurrentTxHash)
	out.PrevTxHash = bytes.Clone(input.PrevTxHash)
	out.TxGuardian = bytes.Clone(input.TxGuardian)
	if input.CallValue != nil {
		out.CallValue = new(big.Int).Set(input.CallValue)
	}
	if input.Arguments != nil {
		out.Arguments = make([][]byte, len(input.Arguments))
		for i, arg := range input.Arguments {
			out.Arguments[i] = bytes.Clone(arg)
		}
	}
	if input.AsyncArguments != nil {
		a := *input.AsyncArguments
		a.CallID = bytes.Clone(a.CallID)
		a.CallerCallID = bytes.Clone(a.CallerCallID)
		a.CallbackAsyncInitiatorCallID = bytes.Clone(a.CallbackAsyncInitiatorCallID)
		out.AsyncArguments = &a
	}
	if input.ESDTTransfers != nil {
		out.ESDTTransfers = make([]*vmcommon.ESDTTransfer, len(input.ESDTTransfers))
		for i, transfer := range input.ESDTTransfers {
			if transfer == nil {
				continue
			}
			v := *transfer
			v.ESDTTokenName = bytes.Clone(transfer.ESDTTokenName)
			if transfer.ESDTValue != nil {
				v.ESDTValue = new(big.Int).Set(transfer.ESDTValue)
			}
			out.ESDTTransfers[i] = &v
		}
	}
	return &out
}
