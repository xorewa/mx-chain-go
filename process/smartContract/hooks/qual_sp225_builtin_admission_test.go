package hooks_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// SP2-25, Part A 5.1, F.5 D17: the hook asks the admission after the native
// function lookup and before any account is loaded, only while DRWA is
// enforced for the header in execution. Inert stubs.

type qualSP225HookAdmission struct {
	events *[]string
	err    error
}

func (a *qualSP225HookAdmission) AdmitBuiltIn(function vmcommon.BuiltinFunction, input *vmcommon.ContractCallInput) error {
	*a.events = append(*a.events, "admit:"+input.Function)
	if function == nil {
		return errors.New("the admission did not receive the looked-up function")
	}
	return a.err
}
func (a *qualSP225HookAdmission) IsInterfaceNil() bool { return a == nil }

func qualSP225Hook(t *testing.T, admission hooks.DRWABuiltInAdmission, enforcedAt func(uint32, uint64) bool, events *[]string) *hooks.BlockChainHookImpl {
	t.Helper()
	args := createMockBlockChainHookArgs()
	container := vmcommonBuiltins.NewBuiltInFunctionContainer()
	require.NoError(t, container.Add("qualProbe", &mock.BuiltInFunctionStub{
		ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
			*events = append(*events, "native")
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnMessage: "native result"}, nil
		},
	}))
	args.BuiltInFunctions = container
	args.Accounts = &stateMock.AccountsStub{
		GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			*events = append(*events, "load")
			return stateMock.NewAccountWrapMock(address), nil
		},
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			*events = append(*events, "load")
			return stateMock.NewAccountWrapMock(address), nil
		},
		JournalLenCalled:       func() int { *events = append(*events, "journal"); return 0 },
		SaveAccountCalled:      func(vmcommon.AccountHandler) error { *events = append(*events, "save"); return nil },
		RevertToSnapshotCalled: func(int) error { *events = append(*events, "revert"); return nil },
	}
	args.DRWABuiltInAdmission, args.DRWABuiltInEnforcedAt = admission, enforcedAt
	hook, err := hooks.NewBlockChainHookImpl(args)
	require.NoError(t, err)
	return hook
}

func TestQualSP225HookAdmitsBuiltInBeforeFirstEffect(t *testing.T) {
	enforcedFrom := func(epoch uint32, round uint64) bool { return epoch >= 12 && round >= 440 }
	call := func() *vmcommon.ContractCallInput {
		return createContractCallInput("qualProbe", []byte("sender"), []byte("destination"))
	}

	var native []string
	plain := qualSP225Hook(t, nil, nil, &native)
	expected, err := plain.ProcessBuiltInFunction(call())
	require.NoError(t, err)
	require.NotContains(t, native, "admit:qualProbe")

	for _, tc := range []struct {
		name         string
		epoch        uint32
		round        uint64
		admissionErr error
		asked        bool
	}{
		{"before_enforcement_epoch", 11, 440, errors.New("must not be asked"), false},
		{"before_enforcement_round", 12, 439, errors.New("must not be asked"), false},
		{"enforced_ordinary", 12, 440, nil, true},
		{"enforced_regulated", 12, 440, errors.New("inert regulated refusal"), true},
		{"enforced_unresolved", 13, 500, fmt.Errorf("%w: inert unresolved", vm.ErrDRWAExecution), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			hook := qualSP225Hook(t, &qualSP225HookAdmission{events: &events, err: tc.admissionErr}, enforcedFrom, &events)
			require.NoError(t, hook.SetCurrentHeader(&block.Header{Epoch: tc.epoch, Round: tc.round}))
			output, err := hook.ProcessBuiltInFunction(call())
			if !tc.asked {
				require.NoError(t, err)
				require.Equal(t, expected, output)
				require.Equal(t, native, events, "before enforcement the hook is the native hook")
				return
			}
			require.Equal(t, "admit:qualProbe", events[0], "classification precedes every native step")
			if tc.admissionErr != nil {
				require.Same(t, tc.admissionErr, err)
				require.Nil(t, output)
				require.Equal(t, []string{"admit:qualProbe"}, events, "no account load, journal, effect, save or revert")
				return
			}
			require.NoError(t, err)
			require.Equal(t, expected, output)
			require.Equal(t, native, events[1:], "an admitted call is the native call")
		})
	}

	t.Run("unknown_function_keeps_the_native_error", func(t *testing.T) {
		var events, plainEvents []string
		hook := qualSP225Hook(t, &qualSP225HookAdmission{events: &events}, enforcedFrom, &events)
		require.NoError(t, hook.SetCurrentHeader(&block.Header{Epoch: 12, Round: 440}))
		_, err := hook.ProcessBuiltInFunction(createContractCallInput("unknownFunction", []byte("sender"), []byte("destination")))
		_, nativeErr := qualSP225Hook(t, nil, nil, &plainEvents).ProcessBuiltInFunction(createContractCallInput("unknownFunction", []byte("sender"), []byte("destination")))
		require.Error(t, nativeErr)
		require.Equal(t, nativeErr, err)
		require.Empty(t, events)
	})
}

func TestQualSP225HookAdmissionConstruction(t *testing.T) {
	var events []string
	always := func(uint32, uint64) bool { return true }
	for name, tc := range map[string]struct {
		admission  hooks.DRWABuiltInAdmission
		enforcedAt func(uint32, uint64) bool
	}{
		"typed_nil_admission":         {(*qualSP225HookAdmission)(nil), always},
		"admission_without_predicate": {&qualSP225HookAdmission{events: &events}, nil},
		"predicate_without_admission": {nil, always},
	} {
		t.Run(name, func(t *testing.T) {
			args := createMockBlockChainHookArgs()
			args.DRWABuiltInAdmission, args.DRWABuiltInEnforcedAt = tc.admission, tc.enforcedAt
			hook, err := hooks.NewBlockChainHookImpl(args)
			require.ErrorIs(t, err, hooks.ErrInvalidDRWABuiltInAdmission)
			require.Nil(t, hook)
		})
	}
}

// The native NFT metadata save after a failed incoming transfer does not pass
// the built-in dispatch. Under enforcement it either cannot write (native
// flags) or is refused.
func TestQualSP225HookMetaDataSaveIsClassifiedOrInert(t *testing.T) {
	enforcedFrom := func(epoch uint32, round uint64) bool { return epoch >= 12 }
	for _, tc := range []struct {
		name            string
		flags           []core.EnableEpochFlag
		admission       bool
		epoch           uint32
		refused, called bool
	}{
		{"native_hook", []core.EnableEpochFlag{common.SaveToSystemAccountFlag}, false, 12, false, true},
		{"before_enforcement", []core.EnableEpochFlag{common.SaveToSystemAccountFlag}, true, 11, false, true},
		{"enforced_and_inert_send_always", []core.EnableEpochFlag{common.SaveToSystemAccountFlag, common.SendAlwaysFlag}, true, 12, false, true},
		{"enforced_and_inert_before_save_flag", nil, true, 12, false, true},
		{"enforced_and_writing_is_refused", []core.EnableEpochFlag{common.SaveToSystemAccountFlag}, true, 12, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			args := createMockBlockChainHookArgs()
			args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(tc.flags...)
			called := false
			args.NFTStorageHandler = &testscommon.SimpleNFTStorageHandlerStub{
				SaveNFTMetaDataToSystemAccountCalled: func(data.TransactionHandler) error { called = true; return nil },
			}
			if tc.admission {
				args.DRWABuiltInAdmission, args.DRWABuiltInEnforcedAt = &qualSP225HookAdmission{events: &events}, enforcedFrom
			}
			hook, err := hooks.NewBlockChainHookImpl(args)
			require.NoError(t, err)
			require.NoError(t, hook.SetCurrentHeader(&block.Header{Epoch: tc.epoch}))
			err = hook.SaveNFTMetaDataToSystemAccount(&transaction.Transaction{})
			if tc.refused {
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.called, called)
			require.Empty(t, events)
		})
	}
}
