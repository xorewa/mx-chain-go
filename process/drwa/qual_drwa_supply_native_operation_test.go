package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Actual native factory/roles/AccountsDB, synthetic policy and classification.
// These cases do not supply D/W03/B/E authority, finality, funding or profile
// admission. The reused native fixture's limits/addresses are experimental.
func qualSupplyOperationFixture(t *testing.T, name string) *routeOperationTestFixture {
	t.Helper()
	f := routeOperationFixture(t)
	a, err := f.store.GetExistingAccount(f.source)
	require.NoError(t, err)
	u := a.(vmcommon.UserAccountHandler)
	roles, err := f.args.Marshalizer.Marshal(&esdt.ESDTRoles{Roles: [][]byte{[]byte(core.ESDTRoleLocalMint), []byte(core.ESDTRoleLocalBurn)}})
	require.NoError(t, err)
	require.NoError(t, u.AccountDataHandler().SaveKeyValue([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier+"ORDINARY-abcdef"), roles))
	require.NoError(t, f.store.SaveAccount(u))
	_, err = f.store.AccountsAdapter.Commit()
	require.NoError(t, err)
	f.input.Function = name
	f.input.RecipientAddr = bytes.Clone(f.source)
	return f
}

func TestQualDRWASupplyNativeOperationEffectsAndAbort(t *testing.T) {
	for _, name := range []string{core.BuiltInFunctionESDTLocalMint, core.BuiltInFunctionESDTLocalBurn} {
		t.Run(name, func(t *testing.T) {
			f := qualSupplyOperationFixture(t, name)
			op, err := newSupplyNativeOperation(f.args, name)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			checks := 0
			policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) { return true, nil }, check: func(fn string, effect vmcommon.DRWASupplyEffect, input *vmcommon.ContractCallInput) error {
				checks++
				require.Equal(t, name, fn)
				require.Equal(t, []byte("ORDINARY-abcdef"), effect.TokenIdentifier)
				require.Equal(t, f.source, effect.RoleAddress)
				require.Equal(t, big.NewInt(10), effect.Quantity)
				require.Equal(t, big.NewInt(100), f.balance(t, f.source))
				require.Zero(t, f.store.JournalLen())
				reentrant, nestedError := op.execute(input, nil, nil)
				require.Nil(t, reentrant)
				require.ErrorIs(t, nestedError, ErrExecutionBusy)
				return nil
			}}
			err = owner.Execute(func() (*vmcommon.VMOutput, error) { return op.execute(f.input, policy, f.resolve) })
			require.NoError(t, err)
			require.Equal(t, 1, checks)
			want := int64(110)
			if name == core.BuiltInFunctionESDTLocalBurn {
				want = 90
			}
			require.Equal(t, big.NewInt(want), f.balance(t, f.source))
			out, err := op.execute(f.input, policy, f.resolve)
			require.Nil(t, out)
			require.ErrorIs(t, err, ErrExecutionClosed)
			require.NoError(t, owner.Abort())
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
		})
	}
}

func TestQualDRWASupplyNativeOperationRefusalAndResolverBinding(t *testing.T) {
	for _, mode := range []string{"policy refusal", "ordinary classification", "classification error", "resolver mutation", "missing role"} {
		t.Run(mode, func(t *testing.T) {
			f := qualSupplyOperationFixture(t, core.BuiltInFunctionESDTLocalMint)
			if mode == "missing role" {
				a, err := f.store.GetExistingAccount(f.source)
				require.NoError(t, err)
				require.NoError(t, a.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier+"ORDINARY-abcdef"), nil))
				require.NoError(t, f.store.SaveAccount(a))
				_, err = f.store.AccountsAdapter.Commit()
				require.NoError(t, err)
			}
			op, err := newSupplyNativeOperation(f.args, f.input.Function)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			checks, resolutions := 0, 0
			sentinel := errors.New("exact supply approval refused")
			policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) {
				if mode == "ordinary classification" {
					return false, nil
				}
				if mode == "classification error" {
					return false, sentinel
				}
				return true, nil
			}, check: func(string, vmcommon.DRWASupplyEffect, *vmcommon.ContractCallInput) error { checks++; return sentinel }}
			resolver := func(a vmcommon.AccountsAdapter, input *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
				resolutions++
				if mode == "resolver mutation" {
					copy(input.CallerAddr, f.other)
					copy(input.RecipientAddr, f.other)
				}
				return f.resolve(a, input)
			}
			var output *vmcommon.VMOutput
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = op.execute(f.input, policy, resolver)
				return output, e
			})
			require.Error(t, err)
			require.Nil(t, output)
			if mode == "policy refusal" {
				require.ErrorIs(t, err, sentinel)
				require.Equal(t, 1, checks)
			} else {
				require.Zero(t, checks)
			}
			if mode == "ordinary classification" || mode == "classification error" {
				require.Zero(t, resolutions)
			}
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Zero(t, f.store.JournalLen())
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
			require.Equal(t, f.source, f.input.CallerAddr)
			require.Equal(t, f.source, f.input.RecipientAddr)
		})
	}
}

type qualSupplyOperationFaultAccounts struct {
	vmcommon.AccountsAdapter
	readFault     func([]byte) error
	dataReadFault func([]byte) error
	saveFault     error
	loads         int
}

func (a *qualSupplyOperationFaultAccounts) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	a.loads++
	return a.AccountsAdapter.LoadAccount(address)
}
func (a *qualSupplyOperationFaultAccounts) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if a.readFault != nil {
		if err := a.readFault(address); err != nil {
			return nil, err
		}
	}
	account, err := a.AccountsAdapter.GetExistingAccount(address)
	if err != nil || a.dataReadFault == nil {
		return account, err
	}
	user, found := account.(vmcommon.UserAccountHandler)
	if !found {
		return account, nil
	}
	return &qualSupplyOperationDataFaultUser{user, a.dataReadFault}, nil
}
func (a *qualSupplyOperationFaultAccounts) SaveAccount(account vmcommon.AccountHandler) error {
	if a.saveFault != nil {
		return a.saveFault
	}
	if user, found := account.(*qualSupplyOperationDataFaultUser); found {
		account = user.UserAccountHandler
	}
	return a.AccountsAdapter.SaveAccount(account)
}

type qualSupplyOperationDataFaultUser struct {
	vmcommon.UserAccountHandler
	fault func([]byte) error
}

func (u *qualSupplyOperationDataFaultUser) AccountDataHandler() vmcommon.AccountDataHandler {
	return &qualSupplyOperationDataFault{u.UserAccountHandler.AccountDataHandler(), u.fault}
}

type qualSupplyOperationDataFault struct {
	vmcommon.AccountDataHandler
	fault func([]byte) error
}

func (d *qualSupplyOperationDataFault) RetrieveValue(key []byte) ([]byte, uint32, error) {
	value, depth, err := d.AccountDataHandler.RetrieveValue(key)
	if err != nil {
		return value, depth, err
	}
	return value, depth, d.fault(key)
}

func TestQualDRWASupplyNativeOperationReadAndSaveFailures(t *testing.T) {
	for _, mode := range []string{"origin read before policy", "discarded native read", "discarded missing account", "final save"} {
		t.Run(mode, func(t *testing.T) {
			f := qualSupplyOperationFixture(t, core.BuiltInFunctionESDTLocalMint)
			faults := &qualSupplyOperationFaultAccounts{AccountsAdapter: f.store}
			f.args.Accounts = faults
			op, err := newSupplyNativeOperation(f.args, f.input.Function)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			sentinel := errors.New("native supply IO refusal")
			var order []string
			if mode == "origin read before policy" {
				faults.readFault = func(address []byte) error {
					if bytes.Equal(address, f.source) {
						order = append(order, "origin read")
						return sentinel
					}
					return nil
				}
			}
			if mode == "discarded native read" {
				faults.readFault = func(address []byte) error {
					if bytes.Equal(address, vmcommon.SystemAccountAddress) {
						order = append(order, "native read")
						return sentinel
					}
					return nil
				}
			}
			if mode == "final save" {
				faults.saveFault = sentinel
			}
			checks := 0
			var missingError error
			policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) { return true, nil }, check: func(string, vmcommon.DRWASupplyEffect, *vmcommon.ContractCallInput) error {
				checks++
				order = append(order, "check")
				if mode == "discarded missing account" {
					_, missingError = op.accounts.LoadAccount(bytes.Repeat([]byte{9}, 32))
					require.Error(t, missingError)
				}
				return nil
			}}
			var output *vmcommon.VMOutput
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = op.execute(f.input, policy, f.resolve)
				return output, e
			})
			require.Error(t, err)
			require.Nil(t, output)
			if mode == "discarded missing account" {
				require.Same(t, missingError, err)
			} else {
				require.ErrorIs(t, err, sentinel)
			}
			if mode == "origin read before policy" {
				require.Zero(t, checks)
				require.Equal(t, []string{"origin read"}, order)
			} else {
				require.Equal(t, 1, checks)
				if mode == "discarded native read" {
					require.Equal(t, []string{"check", "native read"}, order)
				}
			}
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
			require.Zero(t, faults.loads) // The actual creating loader was never used.
		})
	}
}

func TestQualDRWASupplyNativeOperationRejectsOtherPrimitives(t *testing.T) {
	f := qualSupplyOperationFixture(t, core.BuiltInFunctionESDTLocalMint)
	for _, name := range []string{core.BuiltInFunctionESDTBurn, core.BuiltInFunctionESDTTransfer, "unrecognized"} {
		op, err := newSupplyNativeOperation(f.args, name)
		require.ErrorIs(t, err, errRouteNativeGuard)
		require.Nil(t, op)
	}
}

func TestQualDRWASupplyNativeOperationUnavailableFactory(t *testing.T) {
	f := qualSupplyOperationFixture(t, core.BuiltInFunctionESDTLocalMint)
	root, err := f.store.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal := f.store.JournalLen()
	for _, mode := range []string{"accounts", "marshaller", "coordinator", "native factory limit"} {
		args := f.args
		want := error(errRouteNativeGuard)
		switch mode {
		case "accounts":
			args.Accounts = nil
		case "marshaller":
			args.Marshalizer = nil
			want = nativeBuiltins.ErrNilMarshalizer
		case "coordinator":
			args.ShardCoordinator = nil
			want = nativeBuiltins.ErrNilShardCoordinator
		case "native factory limit":
			args.MaxNumOfAddressesForTransferRole = 0
			want = nativeBuiltins.ErrInvalidMaxNumAddresses
		}
		op, e := newSupplyNativeOperation(args, f.input.Function)
		require.ErrorIs(t, e, want, mode)
		require.Nil(t, op)
	}
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, f.store.JournalLen())
}

// Only dependency availability is synthetic. Every factory, primitive and
// account operation remains the pinned native implementation. The changing
// nil report is hostile input, not a native-store availability guarantee.
type qualSupplyConstructorAvailability struct {
	vmcommon.AccountsAdapter
	nilAt, nilChecks, loads, reads, saves int
}

func (a *qualSupplyConstructorAvailability) IsInterfaceNil() bool {
	a.nilChecks++
	return a.nilAt != 0 && a.nilChecks >= a.nilAt
}
func (a *qualSupplyConstructorAvailability) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	a.loads++
	return a.AccountsAdapter.LoadAccount(address)
}
func (a *qualSupplyConstructorAvailability) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	a.reads++
	return a.AccountsAdapter.GetExistingAccount(address)
}
func (a *qualSupplyConstructorAvailability) SaveAccount(account vmcommon.AccountHandler) error {
	a.saves++
	return a.AccountsAdapter.SaveAccount(account)
}

func TestQualDRWASupplyNativeOperationConstructorAvailability(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nilAt int
		want  error
	}{
		{"stable native control", 0, nil},
		{"dependency disappears before guard", 2, state.ErrNilAccountsAdapter},
		{"dependency disappears before factory", 3, nativeBuiltins.ErrNilAccountsAdapter},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := qualSupplyOperationFixture(t, core.BuiltInFunctionESDTLocalMint)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal, commits := f.store.JournalLen(), f.store.commits
			accounts := &qualSupplyConstructorAvailability{AccountsAdapter: f.store, nilAt: tc.nilAt}
			f.args.Accounts = accounts
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			var op *supplyNativeOperation
			var output *vmcommon.VMOutput
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				op, e = newSupplyNativeOperation(f.args, f.input.Function)
				if e != nil {
					return nil, e
				}
				output = &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
				return output, nil
			})
			if tc.want != nil {
				require.Same(t, tc.want, err)
				require.Nil(t, op)
				require.Nil(t, output)
				require.Equal(t, tc.nilAt, accounts.nilChecks)
			} else {
				require.NoError(t, err)
				require.NotNil(t, op)
				require.NotNil(t, output)
				require.Greater(t, accounts.nilChecks, 3)
				require.NoError(t, owner.Abort())
			}
			require.Zero(t, accounts.loads)
			require.Zero(t, accounts.reads)
			require.Zero(t, accounts.saves)
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Equal(t, commits, f.store.commits)
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
		})
	}
}

func TestQualDRWASupplyNativeOperationInputAndOwnerRefusals(t *testing.T) {
	for _, mode := range []string{"nil input", "wrong primitive", "nil policy", "nil resolver", "resolver refusal", "nil sender", "nil receiver", "unwrapped", "foreign owner", "wrong account", "distinct same-account instances"} {
		t.Run(mode, func(t *testing.T) {
			f := qualSupplyOperationFixture(t, core.BuiltInFunctionESDTLocalMint)
			op, err := newSupplyNativeOperation(f.args, f.input.Function)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := f.store.JournalLen()
			classifications, resolutions, checks := 0, 0, 0
			policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) {
				classifications++
				return true, nil
			}, check: func(string, vmcommon.DRWASupplyEffect, *vmcommon.ContractCallInput) error {
				checks++
				return nil
			}}
			sentinel := errors.New("owning native resolver refused")
			resolver := routeNativeResolver(func(a vmcommon.AccountsAdapter, input *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
				resolutions++
				if mode == "resolver refusal" {
					return nil, nil, sentinel
				}
				sender, receiver, e := f.resolve(a, input)
				if e != nil {
					return nil, nil, e
				}
				switch mode {
				case "nil sender":
					sender = nil
				case "nil receiver":
					receiver = nil
				case "unwrapped":
					sender = sender.(*routeNativeUser).UserAccountHandler
				case "foreign owner":
					_, foreign, e := newRouteNativeGuard(f.store)
					require.NoError(t, e)
					account, e := foreign.GetExistingAccount(f.source)
					require.NoError(t, e)
					sender = account.(vmcommon.UserAccountHandler)
				case "wrong account":
					account, e := a.GetExistingAccount(f.other)
					require.NoError(t, e)
					sender = account.(vmcommon.UserAccountHandler)
				case "distinct same-account instances":
					account, e := a.GetExistingAccount(f.source)
					require.NoError(t, e)
					receiver = account.(vmcommon.UserAccountHandler)
					require.NotSame(t, sender, receiver)
				}
				return sender, receiver, nil
			})
			input := f.input
			want := error(errRouteNativeGuard)
			switch mode {
			case "nil input":
				input = nil
				want = process.ErrNilVmInput
			case "wrong primitive":
				input.Function = core.BuiltInFunctionESDTLocalBurn
			case "nil policy":
				policy = nil
			case "nil resolver":
				resolver = nil
			case "resolver refusal":
				want = sentinel
			}
			var output *vmcommon.VMOutput
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = op.execute(input, policy, resolver)
				return output, e
			})
			require.ErrorIs(t, err, want)
			require.Nil(t, output)
			require.Zero(t, checks)
			if mode == "nil input" || mode == "wrong primitive" || mode == "nil policy" || mode == "nil resolver" {
				require.Zero(t, classifications)
				require.Zero(t, resolutions)
			} else {
				require.Equal(t, 1, classifications)
				require.Equal(t, 1, resolutions)
			}
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
		})
	}
}

func TestQualDRWASupplyNativeOperationDiscardedPolicyReadError(t *testing.T) {
	for _, stage := range []string{"classification", "approval"} {
		t.Run(stage, func(t *testing.T) {
			f := qualSupplyOperationFixture(t, core.BuiltInFunctionESDTLocalMint)
			op, err := newSupplyNativeOperation(f.args, f.input.Function)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := f.store.JournalLen()
			var discarded error
			classifications, resolutions, checks := 0, 0, 0
			readMissing := func() {
				_, discarded = op.accounts.GetExistingAccount(bytes.Repeat([]byte{9}, 32))
				require.Error(t, discarded)
			}
			policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) {
				classifications++
				if stage == "classification" {
					readMissing()
				}
				return true, nil // The native read failure must survive this discard.
			}, check: func(string, vmcommon.DRWASupplyEffect, *vmcommon.ContractCallInput) error {
				checks++
				require.Equal(t, big.NewInt(100), f.balance(t, f.source))
				require.Equal(t, journal, f.store.JournalLen())
				readMissing()
				return nil // Approval cannot erase the original account read failure.
			}}
			resolver := func(a vmcommon.AccountsAdapter, input *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
				resolutions++
				return f.resolve(a, input)
			}
			var output *vmcommon.VMOutput
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = op.execute(f.input, policy, resolver)
				return output, e
			})
			require.Error(t, discarded)
			require.Same(t, discarded, err)
			require.Nil(t, output)
			require.Equal(t, 1, classifications)
			if stage == "classification" {
				require.Zero(t, resolutions)
				require.Zero(t, checks)
			} else {
				require.Equal(t, 1, resolutions)
				require.Equal(t, 1, checks)
			}
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
		})
	}
}

func TestQualDRWASupplyNativeOperationDiscardedCreateNonceRead(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "native control", true: "ignored nonce error"}[refuse], func(t *testing.T) {
			f := routeOperationFixture(t)
			f.args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
				nativeBuiltins.SaveToSystemAccountFlag, nativeBuiltins.SendAlwaysFlag, nativeBuiltins.ESDTNFTImprovementV1Flag,
				nativeBuiltins.EGLDInESDTMultiTransferFlag, nativeBuiltins.CheckTransferFlag, nativeBuiltins.CheckCorrectTokenIDForTransferRoleFlag,
				nativeBuiltins.DynamicEsdtFlag, nativeBuiltins.ValueLengthCheckFlag)
			factory, err := nativeBuiltins.NewBuiltInFunctionsCreator(f.args)
			require.NoError(t, err)
			require.NoError(t, factory.CreateBuiltInFunctionContainer())
			global := factory.ESDTGlobalSettingsHandler().(vmcommon.GlobalMetadataHandler)
			storage := factory.NFTStorageHandler().(vmcommon.ESDTNFTStorageHandler)
			token := []byte("COLLECT-abcdef")
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
			require.NoError(t, global.SetTokenType(key, uint32(core.NonFungibleV2)))
			account, err := f.store.GetExistingAccount(f.source)
			require.NoError(t, err)
			user := account.(vmcommon.UserAccountHandler)
			roles, err := f.args.Marshalizer.Marshal(&esdt.ESDTRoles{Roles: [][]byte{[]byte(core.ESDTRoleNFTCreate)}})
			require.NoError(t, err)
			require.NoError(t, user.AccountDataHandler().SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), token...), roles))
			nonceKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier), token...)
			require.NoError(t, user.AccountDataHandler().SaveKeyValue(nonceKey, []byte{3}))
			require.NoError(t, f.store.SaveAccount(user))
			_, err = f.store.AccountsAdapter.Commit()
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := f.store.JournalLen()
			reads, checks := 0, 0
			sentinel := errors.New("native creator nonce read refused")
			faults := &qualSupplyOperationFaultAccounts{AccountsAdapter: f.store, dataReadFault: func(k []byte) error {
				if bytes.Equal(k, nonceKey) {
					reads++
					if refuse {
						return sentinel
					}
				}
				return nil
			}}
			f.args.Accounts = faults
			f.input.Function, f.input.RecipientAddr, f.input.GasProvided = core.BuiltInFunctionESDTNFTCreate, bytes.Clone(f.source), 1000000
			f.input.Arguments = [][]byte{bytes.Clone(token), {1}, []byte("synthetic-native-name"), nil, []byte("hash"), []byte("attributes"), []byte("uri")}
			op, err := newSupplyNativeOperation(f.args, f.input.Function)
			require.NoError(t, err)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			policy := &qualSupplyOperationPolicy{classify: func(string, []byte) (bool, error) { return true, nil }, check: func(fn string, effect vmcommon.DRWASupplyEffect, input *vmcommon.ContractCallInput) error {
				checks++
				require.Equal(t, core.BuiltInFunctionESDTNFTCreate, fn)
				require.Equal(t, uint32(core.NonFungibleV2), effect.TokenType)
				require.Equal(t, token, effect.TokenIdentifier)
				require.Equal(t, uint64(3), effect.PreviousNonce)
				require.Equal(t, uint64(4), effect.Nonce)
				require.Equal(t, big.NewInt(1), effect.Quantity)
				require.Equal(t, journal, f.store.JournalLen())
				return nil
			}}
			var output *vmcommon.VMOutput
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = op.execute(f.input, policy, f.resolve)
				return output, e
			})
			require.Equal(t, 1, reads)
			if refuse {
				require.Same(t, sentinel, err)
				require.Nil(t, output)
				require.Zero(t, checks)
			} else {
				require.NoError(t, err)
				require.NotNil(t, output)
				require.Equal(t, vmcommon.Ok, output.ReturnCode)
				require.Equal(t, [][]byte{{4}}, output.ReturnData)
				require.Equal(t, 1, checks)
				a, e := f.store.GetExistingAccount(f.source)
				require.NoError(t, e)
				value, isNew, e := storage.GetESDTNFTTokenOnDestination(a.(vmcommon.UserAccountHandler), key, 4)
				require.NoError(t, e)
				require.False(t, isNew)
				require.Zero(t, big.NewInt(1).Cmp(value.Value))
				require.NoError(t, owner.Abort())
			}
			a, e := f.store.GetExistingAccount(f.source)
			require.NoError(t, e)
			latest, _, e := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(nonceKey)
			require.NoError(t, e)
			require.Equal(t, []byte{3}, latest)
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
		})
	}
}
