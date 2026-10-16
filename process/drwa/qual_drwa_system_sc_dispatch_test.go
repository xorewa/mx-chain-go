package drwa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	processFactory "github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	vmFactory "github.com/multiversx/mx-chain-go/vm/factory"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmProcess "github.com/multiversx/mx-chain-go/vm/process"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// These cases use the existing real native proof/registry owner, actual ESDT
// contract and actual System VM. Header fixtures do not establish canonical
// admission. This is the native boundary experiment, not outer block recovery.
type qualSystemSCDispatch struct {
	context   vm.ContextHandler
	contract  vm.SystemSmartContract
	runtime   vmcommon.VMExecutionHandler
	container vm.SystemSCContainer
	reads     int
}

func qualSystemSCNative(t *testing.T, accounts state.AccountsAdapter, classifier vm.DRWATokenClassifier, validatorAccounts ...state.AccountsAdapter) *qualSystemSCDispatch {
	t.Helper()
	require.LessOrEqual(t, len(validatorAccounts), 1)
	validators := accounts
	if len(validatorAccounts) == 1 {
		validators = validatorAccounts[0]
	}
	f := &qualSystemSCDispatch{}
	cfg := qualCandidateEpochs(t, qualDRWACandidateFixtures["enableEpochs.toml"].body)
	flags := qualCandidateFlags(t, cfg, cfg.EnableEpochs.SupernovaEnableEpoch)
	require.False(t, flags.IsFlagEnabled(common.GlobalMintBurnFlag), "E05 candidate prerequisite")
	hook := &mock.BlockChainHookStub{
		GetUserAccountCalled: func(address []byte) (vmcommon.UserAccountHandler, error) {
			f.reads++
			a, err := accounts.GetExistingAccount(address)
			if err != nil {
				return nil, err
			}
			return a.(vmcommon.UserAccountHandler), nil
		},
		GetStorageDataCalled: func(address, key []byte) ([]byte, uint32, error) {
			f.reads++
			a, err := accounts.GetExistingAccount(address)
			if err != nil {
				return nil, 0, err
			}
			return a.(state.UserAccountHandler).RetrieveValue(key)
		},
		NumberOfShardsCalled: func() uint32 { return 3 },
		CurrentNonceCalled:   func() uint64 { return 1 },
	}
	ctx, err := systemSmartContracts.NewVMContext(systemSmartContracts.VMContextArgs{
		BlockChainHook: hook, CryptoHook: hooks.NewVMCryptoHook(), InputParser: parsers.NewCallArgsParser(),
		UserAccountsDB: accounts, ValidatorAccountsDB: validators, ChanceComputer: &mock.RaterMock{},
		EnableEpochsHandler: flags, DRWAClassifier: classifier,
	})
	require.NoError(t, err)
	contract, err := systemSmartContracts.NewESDTSmartContract(systemSmartContracts.ArgsNewESDTSmartContract{
		Eei: ctx, GasCost: vm.GasCost{MetaChainSystemSCsCost: vm.MetaChainSystemSCsCost{ESDTIssue: 10}},
		ESDTSCConfig: config.ESDTSystemSCConfig{BaseIssuingCost: "1000"}, ESDTSCAddress: core.ESDTSCAddress,
		Marshalizer: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(),
		AddressPubKeyConverter: testscommon.NewPubkeyConverterMock(32), EndOfEpochSCAddress: vm.EndOfEpochAddress,
		EnableEpochsHandler: flags,
	})
	require.NoError(t, err)
	container := vmFactory.NewSystemSCContainer()
	require.NoError(t, container.Add(core.ESDTSCAddress, contract))
	require.NoError(t, ctx.SetSystemSCContainer(container))
	gas := testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{
		common.BaseOpsAPICost: {common.AsyncCallStepField: 1000, common.AsyncCallbackGasLockField: 3000},
	})
	runtime, err := vmProcess.NewSystemVM(vmProcess.ArgsNewSystemVM{
		SystemEI: ctx, SystemContracts: container, VmType: processFactory.SystemVirtualMachine, GasSchedule: gas,
	})
	require.NoError(t, err)
	f.context, f.contract, f.runtime = ctx, contract, runtime
	f.container = container
	return f
}

func qualSystemSCInput(method, token string) *vmcommon.ContractCallInput {
	input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{
		CallerAddr: bytes.Repeat([]byte{1}, 32), CallValue: big.NewInt(0), GasProvided: 1000000,
		Arguments: [][]byte{[]byte(token), bytes.Repeat([]byte{2}, 32), []byte(core.ESDTRoleNFTCreate)},
	}, RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: method}
	switch method {
	case "updateTokenID", "changeToDynamic", "changeToMultiShardCreate":
		input.Arguments = input.Arguments[:1]
	case "changeSFTToMetaESDT":
		input.Arguments = [][]byte{[]byte(token), {}}
	}
	return input
}

func qualSystemSCOrdinaryCandidate(t *testing.T, participating ...state.AccountsAdapter) (*registrationCandidate, *qualRegistrationCandidateStore) {
	return qualSystemSCFamilyCandidate(t, core.FungibleESDT, "TOKEN-abcdef", participating...)
}

func qualSystemSCConversionFamily(method string) string {
	switch method {
	case "updateTokenID", "changeToMultiShardCreate":
		return core.NonFungibleESDT
	case "changeSFTToMetaESDT", "changeToDynamic":
		return core.SemiFungibleESDT
	default:
		return ""
	}
}

func qualSystemSCFamilyCandidate(t *testing.T, family, identifier string, participating ...state.AccountsAdapter) (*registrationCandidate, *qualRegistrationCandidateStore) {
	t.Helper()
	f := qualRegistryTransportWithSetup(t, false, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1}, false,
		func(accounts state.AccountsAdapter) {
			token := &systemSmartContracts.ESDTDataV2{OwnerAddress: bytes.Repeat([]byte{1}, 32),
				TokenName: []byte("TokenName"), TickerName: []byte("TOKEN"), TokenType: []byte(family),
				Mintable: true, Burnable: true, CanPause: true, CanFreeze: true, CanWipe: true,
				Upgradable: true, CanChangeOwner: true, CanAddSpecialRoles: true,
				MintedValue: big.NewInt(0), BurntValue: big.NewInt(0)}
			if family == core.NonFungibleESDT {
				token.SpecialRoles = []*systemSmartContracts.ESDTRoles{{Address: bytes.Repeat([]byte{2}, 32),
					Roles: [][]byte{[]byte(core.ESDTRoleNFTCreate)}}}
			}
			body, err := (&marshal.GogoProtoMarshalizer{}).Marshal(token)
			require.NoError(t, err)
			a, err := accounts.LoadAccount(core.ESDTSCAddress)
			require.NoError(t, err)
			require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte(identifier), body))
			require.NoError(t, accounts.SaveAccount(a))
		})
	transport, err := newRegistryTransport(f.reader, 2, f.limit)
	require.NoError(t, err)
	projection, err := transport.reconstruct(f.anchor, f.count, f.members)
	require.NoError(t, err)
	store := &qualRegistrationCandidateStore{qualNativeStore: &qualNativeStore{AccountsAdapter: f.source}}
	candidate, err := reconstructRegistrationCandidate(store, qualRegistrationCoordinator(), 2, projection, participating...)
	require.NoError(t, err)
	return candidate, store
}

func TestQualDRWASystemSCDispatchDenials(t *testing.T) {
	// Independent list from DS01-M1/M6, DS02-M1-4/M8, DS03-M1 and
	// DS04-M1/M2; these model bytes precede their respective behavior changes.
	// do not obtain expectations or enumerate routes through the gate itself.
	for _, method := range []string{"setBurnRoleGlobally", "unsetBurnRoleGlobally", "setSpecialRole", "unSetSpecialRole",
		"transferOwnership", "controlChanges", "transferNFTCreateRole", "stopNFTCreate", "sendAllTransferRoleAddresses",
		"freeze", "unFreeze", "wipe", "pause", "unPause", "freezeSingleNFT", "unFreezeSingleNFT", "wipeSingleNFT", "mint", core.BuiltInFunctionESDTBurn,
		"updateTokenID", "changeSFTToMetaESDT", "changeToDynamic", "changeToMultiShardCreate"} {
		for _, path := range []string{"native_vm", "direct_dispatch", "nested"} {
			t.Run(method+"/"+path, func(t *testing.T) {
				r, store, _ := qualRegistrationCandidate(t, false, true)
				if family := qualSystemSCConversionFamily(method); family != "" {
					r, store = qualSystemSCFamilyCandidate(t, family, "AAA-abcdef")
				}
				f := qualSystemSCNative(t, store, r)
				input := qualSystemSCInput(method, "AAA-abcdef")
				root, err := store.RootHash()
				require.NoError(t, err)
				reads := store.reads
				var output *vmcommon.VMOutput
				switch path {
				case "native_vm":
					output, err = f.runtime.RunSmartContractCall(input)
				case "direct_dispatch":
					f.context.SetSCAddress(core.ESDTSCAddress)
					require.Equal(t, vmcommon.UserError, f.contract.Execute(input))
					output = f.context.CreateVMOutput()
					output.ReturnCode = vmcommon.UserError
				case "nested":
					data := method
					for _, arg := range input.Arguments {
						data += "@" + hex.EncodeToString(arg)
					}
					output, err = f.context.ExecuteOnDestContext(core.ESDTSCAddress, input.CallerAddr, input.CallValue, []byte(data))
				}
				require.NoError(t, err)
				if qualSystemSCConversionFamily(method) != "" {
					raw, encodeErr := json.Marshal(output)
					require.NoError(t, encodeErr)
					t.Log("native_conversion_output", string(raw))
				}
				require.Equal(t, vmcommon.UserError, output.ReturnCode)
				require.Equal(t, "DRWA public operation denied", output.ReturnMessage)
				require.Empty(t, output.OutputAccounts)
				require.Empty(t, output.Logs)
				require.Empty(t, output.ReturnData)
				require.Zero(t, output.GasRemaining)
				require.Zero(t, output.GasRefund.Sign())
				require.Zero(t, f.reads, "no native account lookup, storage or VM-value effect before denial")
				require.Equal(t, reads, store.reads, "classifier must read memory only")
				after, err := store.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, after)
				require.Zero(t, store.JournalLen())
			})
		}
	}
}

func TestQualDRWASystemSCDispatchLifecycle(t *testing.T) {
	for _, phase := range []string{"same_candidate", "failed_registration", "abort", "commit", "rollback_failure", "wrong_store", "typed_nil"} {
		t.Run(phase, func(t *testing.T) {
			r, store, _ := qualRegistrationCandidate(t, false, false)
			var classifier vm.DRWATokenClassifier = r
			accounts := store
			var expected error
			switch phase {
			case "same_candidate":
				require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
			case "failed_registration", "rollback_failure":
				original := errors.New("native creator failure")
				if phase == "rollback_failure" {
					store.revertErr = errors.New("native rollback failure")
					expected = store.revertErr
				}
				require.ErrorIs(t, r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
					return nil, nil, original
				}), original)
			case "abort":
				require.NoError(t, r.abort())
				expected = ErrExecutionClosed
			case "commit":
				_, _, err := r.commit()
				require.NoError(t, err)
				expected = ErrExecutionClosed
			case "wrong_store":
				_, accounts, _ = qualRegistrationCandidate(t, false, false)
				// An unowned store is now refused at construction, before a VM
				// can receive it, including non-classified native call paths.
				ctx, err := systemSmartContracts.NewVMContext(qualSystemSCBindingArgs(t, accounts, accounts, classifier))
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.ErrorIs(t, err, errInvalidMetaContext)
				require.Nil(t, ctx)
				return
			case "typed_nil":
				classifier = (*registrationCandidate)(nil)
				// Constructor must refuse a typed-nil dependency, never treat it
				// as the intentionally absent pre-enforcement dependency.
				_, err := systemSmartContracts.NewVMContext(systemSmartContracts.VMContextArgs{DRWAClassifier: classifier})
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				return
			}
			f := qualSystemSCNative(t, accounts, classifier)
			output, err := f.runtime.RunSmartContractCall(qualSystemSCInput("pause", "TOKEN-abcdef"))
			if expected != nil {
				require.ErrorIs(t, err, expected)
				require.ErrorIs(t, err, vm.ErrDRWAExecution)
				require.Nil(t, output)
				f.context.CleanCache()
				// Even unrelated work cannot continue through a poisoned host.
				output, err = f.runtime.RunSmartContractCall(qualSystemSCInput("getTokenProperties", "ordinary"))
				require.ErrorIs(t, err, expected)
				require.Nil(t, output)
				output, err = f.runtime.RunSmartContractCreate(&vmcommon.ContractCreateInput{
					VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0)},
				})
				require.ErrorIs(t, err, expected)
				require.Nil(t, output)
				require.Zero(t, f.reads)
				return
			}
			require.NoError(t, err)
			if phase == "same_candidate" {
				require.Equal(t, "DRWA public operation denied", output.ReturnMessage)
				require.Zero(t, f.reads)
			} else {
				require.NotEqual(t, "DRWA public operation denied", output.ReturnMessage)
				require.Positive(t, f.reads)
			}
		})
	}
}

func TestQualDRWASystemSCDispatchOrdinary(t *testing.T) {
	for _, method := range []string{"setBurnRoleGlobally", "unsetBurnRoleGlobally", "setSpecialRole", "unSetSpecialRole", "transferOwnership", "controlChanges",
		"transferNFTCreateRole", "stopNFTCreate", "sendAllTransferRoleAddresses", "freeze", "unFreeze", "wipe", "pause", "unPause",
		"freezeSingleNFT", "unFreezeSingleNFT", "wipeSingleNFT", "mint", core.BuiltInFunctionESDTBurn,
		"updateTokenID", "changeSFTToMetaESDT", "changeToDynamic", "changeToMultiShardCreate"} {
		for _, shape := range []string{"native_input", "no_arguments", "nonzero_value", "no_gas"} {
			t.Run(method+"/"+shape, func(t *testing.T) {
				r, store := qualSystemSCOrdinaryCandidate(t)
				if family := qualSystemSCConversionFamily(method); family != "" {
					r, store = qualSystemSCFamilyCandidate(t, family, "TOKEN-abcdef")
				}
				before, err := store.RootHash()
				require.NoError(t, err)
				var outputs []*vmcommon.VMOutput
				var readCounts []int
				for _, classifier := range []vm.DRWATokenClassifier{nil, r} {
					f := qualSystemSCNative(t, store, classifier)
					input := qualSystemSCInput(method, "TOKEN-abcdef")
					switch method {
					case "setBurnRoleGlobally", "unsetBurnRoleGlobally", "pause", "unPause", "sendAllTransferRoleAddresses", "stopNFTCreate":
						input.Arguments = input.Arguments[:1]
					case "transferOwnership", "freeze", "unFreeze", "wipe":
						input.Arguments = input.Arguments[:2]
					case "controlChanges":
						input.Arguments = [][]byte{[]byte("TOKEN-abcdef"), []byte("canPause"), []byte("true")}
					case "setSpecialRole", "unSetSpecialRole":
						input.Arguments[2] = []byte(core.ESDTRoleLocalMint)
					}
					switch shape {
					case "no_arguments":
						input.Arguments = nil
					case "nonzero_value":
						input.CallValue.SetInt64(1)
					case "no_gas":
						input.GasProvided = 0
					}
					output, err := f.runtime.RunSmartContractCall(input)
					require.NoError(t, err)
					outputs = append(outputs, output)
					readCounts = append(readCounts, f.reads)
				}
				require.Equal(t, outputs[0], outputs[1], "full native VM output, including gas/refund/storage/results/logs")
				require.Equal(t, readCounts[0], readCounts[1], "ordinary path adds no account/trie read")
				if shape == "native_input" && (method == "transferOwnership" || method == "pause" || method == "controlChanges" || method == "setSpecialRole" || qualSystemSCConversionFamily(method) != "") {
					require.Equal(t, vmcommon.Ok, outputs[0].ReturnCode, "ordinary valid native operation must remain reachable")
					require.NotEmpty(t, outputs[0].OutputAccounts)
				}
				after, err := store.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
				require.Zero(t, store.JournalLen())
			})
		}
	}
}

func TestQualDRWASystemSCDispatchReadDependency(t *testing.T) {
	r, store, _ := qualRegistrationCandidate(t, false, false)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := r.WithTokenClassification(store, []byte("TOKEN-abcdef"), func(regulated bool) (*vmcommon.VMOutput, error) {
			if regulated {
				return nil, fmt.Errorf("ordinary fixture classified regulated")
			}
			close(entered)
			<-release
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
		})
		finished <- err
	}()
	<-entered
	called := false
	require.ErrorIs(t, r.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		called = true
		return nil, nil, nil
	}), ErrExecutionBusy)
	require.False(t, called)
	_, _, err := r.commit()
	require.ErrorIs(t, err, ErrExecutionBusy)
	close(release)
	require.NoError(t, <-finished)
	require.NoError(t, r.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
}

func TestQualDRWASystemSCDispatchIgnoredNestedFailure(t *testing.T) {
	r, store, _ := qualRegistrationCandidate(t, false, false)
	f := qualSystemSCNative(t, store, r)
	address := bytes.Repeat([]byte{3}, 32)
	called := false
	require.NoError(t, f.container.Add(address, &mock.SystemSCStub{ExecuteCalled: func(*vmcommon.ContractCallInput) vmcommon.ReturnCode {
		called = true
		// Enter while healthy, then fail inside this native operation. A
		// preclosed owner is now rejected before the hostile callback starts.
		require.NoError(t, r.abort())
		// A hostile native caller ignores the nested context error and even
		// constructs tentative success output. The real outer VM must refuse
		// to release it. The classifier and nested VM context are genuine.
		_, err := f.context.ExecuteOnDestContext(core.ESDTSCAddress, address, big.NewInt(0), []byte("pause@544f4b454e2d616263646566"))
		require.ErrorIs(t, err, ErrExecutionClosed)
		f.context.SetStorage([]byte("tentative"), []byte("unpublished"))
		f.context.Finish([]byte("unpublished"))
		return vmcommon.Ok
	}}))
	input := qualSystemSCInput("nested", "TOKEN-abcdef")
	input.RecipientAddr = address
	output, err := f.runtime.RunSmartContractCall(input)
	require.True(t, called)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.ErrorIs(t, err, ErrExecutionClosed)
	require.Nil(t, output)
	require.Zero(t, store.JournalLen())
}
