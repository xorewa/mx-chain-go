package drwa

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/guardianMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// These doubles isolate the dependency adapter, not DRWA policy or admission.
// All quantities, costs, addresses and enabled flags below are EXPERIMENTAL.
type routeOperationTestPayable struct{}

func (*routeOperationTestPayable) IsPayable([]byte, []byte) (bool, error) { return true, nil }
func (p *routeOperationTestPayable) IsInterfaceNil() bool                 { return p == nil }

type routeOperationTestGate struct {
	check func(string, []byte, *vmcommon.ParsedESDTTransfers, *vmcommon.ContractCallInput) error
}

func (*routeOperationTestGate) Classify(string, [][]byte) (bool, error) { return true, nil }
func (g *routeOperationTestGate) CheckTransfer(n string, s []byte, p *vmcommon.ParsedESDTTransfers, i *vmcommon.ContractCallInput) error {
	if g.check != nil {
		return g.check(n, s, p, i)
	}
	return nil
}
func (g *routeOperationTestGate) IsInterfaceNil() bool { return g == nil }

type routeOperationTestFixture struct {
	store                      *qualNativeStore
	args                       nativeBuiltins.ArgsCreateBuiltInFunctionContainer
	input                      *vmcommon.ContractCallInput
	source, destination, other []byte
}

func routeOperationFixture(t *testing.T) *routeOperationTestFixture {
	t.Helper()
	f := &routeOperationTestFixture{store: qualRegistrationStore(t, 0), source: bytes.Clone(qualContainmentAddress), destination: bytes.Repeat([]byte{2}, 32), other: bytes.Repeat([]byte{3}, 32)}
	f.destination[31], f.other[31] = 1, 1
	coord, err := sharding.NewMultiShardCoordinator(3, 1)
	require.NoError(t, err)
	f.args = routeBuiltinArgs(f.store, coord, f.source)
	for i, address := range [][]byte{f.source, f.destination, f.other} {
		require.Equal(t, uint32(1), coord.ComputeId(address))
		a, e := f.store.LoadAccount(address)
		require.NoError(t, e)
		u := a.(vmcommon.UserAccountHandler)
		value := int64(100)
		if i == 1 {
			value = 20
		}
		raw, e := f.args.Marshalizer.Marshal(&esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(value)})
		require.NoError(t, e)
		require.NoError(t, u.AccountDataHandler().SaveKeyValue(routeOperationTokenKey(), raw))
		require.NoError(t, f.store.SaveAccount(u))
	}
	_, err = f.store.AccountsAdapter.Commit()
	require.NoError(t, err)
	f.input = &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(f.source), CallValue: big.NewInt(0), GasProvided: 20000, Arguments: [][]byte{[]byte("ORDINARY-abcdef"), {10}}}, RecipientAddr: bytes.Clone(f.destination), Function: core.BuiltInFunctionESDTTransfer}
	return f
}

func routeBuiltinArgs(accounts vmcommon.AccountsAdapter, coord vmcommon.Coordinator, address []byte) nativeBuiltins.ArgsCreateBuiltInFunctionContainer {
	gas := make(map[string]map[string]uint64)
	for name, value := range map[string]interface{}{"BaseOperationCost": vmcommon.BaseOperationCost{}, "BuiltInCost": vmcommon.BuiltInCost{}} {
		gas[name] = make(map[string]uint64)
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			gas[name][typ.Field(i).Name] = 7
		}
	}
	return nativeBuiltins.ArgsCreateBuiltInFunctionContainer{
		Accounts: accounts, Marshalizer: &marshal.GogoProtoMarshalizer{}, ShardCoordinator: coord,
		MapDNSAddresses: map[string]struct{}{}, MapDNSV2Addresses: map[string]struct{}{}, GasMap: gas,
		EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(nativeBuiltins.SaveToSystemAccountFlag, nativeBuiltins.SendAlwaysFlag,
			nativeBuiltins.ESDTNFTImprovementV1Flag, nativeBuiltins.EGLDInESDTMultiTransferFlag, nativeBuiltins.CheckTransferFlag, nativeBuiltins.CheckCorrectTokenIDForTransferRoleFlag),
		GuardedAccountHandler: &guardianMocks.GuardedAccountHandlerStub{}, MaxNumOfAddressesForTransferRole: 100, ConfigAddress: bytes.Clone(address),
	}
}

func routeOperationTokenKey() []byte {
	return []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "ORDINARY-abcdef")
}
func (f *routeOperationTestFixture) balance(t *testing.T, address []byte) *big.Int {
	t.Helper()
	a, e := f.store.GetExistingAccount(address)
	require.NoError(t, e)
	raw, _, e := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(routeOperationTokenKey())
	require.NoError(t, e)
	value := &esdt.ESDigitalToken{}
	require.NoError(t, f.args.Marshalizer.Unmarshal(value, raw))
	return value.Value
}
func (f *routeOperationTestFixture) operation(t *testing.T) *routeNativeOperation {
	t.Helper()
	op, e := newRouteNativeOperation(f.args, f.input.Function, func(vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error) {
		return &routeOperationTestPayable{}, nil
	})
	require.NoError(t, e)
	return op
}
func (f *routeOperationTestFixture) resolve(accounts vmcommon.AccountsAdapter, input *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
	load := func(address []byte) (vmcommon.UserAccountHandler, error) {
		if f.args.ShardCoordinator.ComputeId(address) != f.args.ShardCoordinator.SelfId() {
			return nil, nil
		}
		a, e := accounts.LoadAccount(address)
		if e != nil {
			return nil, e
		}
		return a.(vmcommon.UserAccountHandler), nil
	}
	s, e := load(input.CallerAddr)
	if e != nil {
		return nil, nil, e
	}
	if bytes.Equal(input.CallerAddr, input.RecipientAddr) {
		return s, s, nil
	}
	r, e := load(input.RecipientAddr)
	return s, r, e
}

func TestRouteNativeOperationRejectsResolverAddressMutation(t *testing.T) {
	for _, field := range []string{"caller", "recipient"} {
		t.Run(field, func(t *testing.T) {
			f := routeOperationFixture(t)
			op := f.operation(t)
			owner, e := NewRollbackContainment(f.store)
			require.NoError(t, e)
			root, e := f.store.RootHash()
			require.NoError(t, e)
			var output *vmcommon.VMOutput
			e = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var err error
				output, _, err = op.execute(f.input, &routeOperationTestGate{}, func(a vmcommon.AccountsAdapter, i *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
					if field == "caller" {
						copy(i.CallerAddr, f.other)
					} else {
						copy(i.RecipientAddr, f.other)
					}
					return f.resolve(a, i)
				})
				return output, err
			})
			require.ErrorIs(t, e, errRouteNativeGuard)
			require.Nil(t, output)
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
			require.Equal(t, big.NewInt(20), f.balance(t, f.destination))
			require.Equal(t, big.NewInt(100), f.balance(t, f.other))
			require.Equal(t, f.source, f.input.CallerAddr)
			require.Equal(t, f.destination, f.input.RecipientAddr)
		})
	}
}

func TestRouteNativeOperationNativeFT(t *testing.T) {
	f := routeOperationFixture(t)
	op := f.operation(t)
	owner, e := NewRollbackContainment(f.store)
	require.NoError(t, e)
	checks := 0
	e = owner.Execute(func() (*vmcommon.VMOutput, error) {
		out, parsed, err := op.execute(f.input, &routeOperationTestGate{check: func(name string, source []byte, p *vmcommon.ParsedESDTTransfers, _ *vmcommon.ContractCallInput) error {
			checks++
			require.Equal(t, f.input.Function, name)
			require.Equal(t, f.source, source)
			require.Equal(t, f.destination, p.RcvAddr)
			require.Len(t, p.ESDTTransfers, 1)
			require.Equal(t, big.NewInt(10), p.ESDTTransfers[0].ESDTValue)
			return nil
		}}, f.resolve)
		require.NotNil(t, parsed)
		return out, err
	})
	require.NoError(t, e)
	require.Equal(t, 1, checks)
	require.Equal(t, big.NewInt(90), f.balance(t, f.source))
	require.Equal(t, big.NewInt(30), f.balance(t, f.destination))
	require.NoError(t, owner.Abort())
	require.Equal(t, big.NewInt(100), f.balance(t, f.source))
	require.Equal(t, big.NewInt(20), f.balance(t, f.destination))
}

type routeOperationFaultAccounts struct {
	vmcommon.AccountsAdapter
	fault func([]byte) error
}

func (a *routeOperationFaultAccounts) LoadAccount(address []byte) (vmcommon.AccountHandler, error) {
	if a.fault != nil {
		if err := a.fault(address); err != nil {
			return nil, err
		}
	}
	return a.AccountsAdapter.LoadAccount(address)
}

func TestRouteNativeOperationRetainsDiscardedNativeError(t *testing.T) {
	f := routeOperationFixture(t)
	original := errors.New("experimental native system read failure")
	f.args.Accounts = &routeOperationFaultAccounts{AccountsAdapter: f.store, fault: func(address []byte) error {
		if bytes.Equal(address, vmcommon.SystemAccountAddress) {
			return original
		}
		return nil
	}}
	op := f.operation(t)
	owner, e := NewRollbackContainment(f.store)
	require.NoError(t, e)
	root, e := f.store.RootHash()
	require.NoError(t, e)
	var output *vmcommon.VMOutput
	e = owner.Execute(func() (*vmcommon.VMOutput, error) {
		var err error
		output, _, err = op.execute(f.input, &routeOperationTestGate{}, f.resolve)
		return output, err
	})
	// The real native IsLimitedTransfer/IsPaused helpers return bool and discard
	// this non-DB error. It must still reach the enclosing owner unchanged.
	require.Same(t, original, e)
	require.Nil(t, output)
	require.Same(t, original, op.guard.first)
	after, e := f.store.RootHash()
	require.NoError(t, e)
	require.Equal(t, root, after)
	require.Zero(t, f.store.JournalLen())
	require.Equal(t, big.NewInt(100), f.balance(t, f.source))
	require.Equal(t, big.NewInt(20), f.balance(t, f.destination))
}

func TestRouteNativeOperationPolicyReadFailureAndMutation(t *testing.T) {
	for _, mode := range []string{"first-error", "balance", "data", "save", "commit", "revert", "deny"} {
		t.Run(mode, func(t *testing.T) {
			f := routeOperationFixture(t)
			first, second := errors.New("experimental first IO"), errors.New("experimental later IO")
			armed := false
			reads := 0
			faults := &routeOperationFaultAccounts{AccountsAdapter: f.store, fault: func(address []byte) error {
				if armed && bytes.Equal(address, vmcommon.SystemAccountAddress) {
					reads++
					if reads == 1 {
						return first
					}
					return second
				}
				return nil
			}}
			f.args.Accounts = faults
			op := f.operation(t)
			owner, e := NewRollbackContainment(f.store)
			require.NoError(t, e)
			want := errRouteNativeGuard
			if mode == "first-error" {
				want = first
			}
			if mode == "deny" {
				want = second
			}
			var output *vmcommon.VMOutput
			e = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var err error
				output, _, err = op.execute(f.input, &routeOperationTestGate{check: func(_ string, _ []byte, _ *vmcommon.ParsedESDTTransfers, _ *vmcommon.ContractCallInput) error {
					switch mode {
					case "first-error":
						armed = true
						_, err := op.accounts.LoadAccount(vmcommon.SystemAccountAddress)
						require.Same(t, first, err)
						_, err = op.accounts.LoadAccount(vmcommon.SystemAccountAddress)
						require.Same(t, second, err)
					case "commit":
						_, _ = op.accounts.Commit()
					case "revert":
						_ = op.accounts.RevertToSnapshot(0)
					case "deny":
						return second
					default:
						a, err := op.accounts.LoadAccount(f.source)
						require.NoError(t, err)
						u := a.(vmcommon.UserAccountHandler)
						switch mode {
						case "balance":
							_ = u.AddToBalance(big.NewInt(1))
						case "data":
							_ = u.AccountDataHandler().SaveKeyValue([]byte("experimental/write"), []byte{1})
						case "save":
							_ = op.accounts.SaveAccount(a)
						}
					}
					return nil // Deliberately discard dependency failures, never policy authority.
				}}, f.resolve)
				return output, err
			})
			require.Same(t, want, e)
			require.Nil(t, output)
			require.False(t, op.guard.admitted)
			require.Equal(t, big.NewInt(100), f.balance(t, f.source))
			require.Equal(t, big.NewInt(20), f.balance(t, f.destination))
			qualAssertContainmentBalance(t, f.store, 100)
			if mode == "first-error" {
				require.Equal(t, 2, reads)
			}
		})
	}
}

func TestRouteNativeOperationRejectsForeignBindings(t *testing.T) {
	for _, mode := range []string{"raw", "foreign", "wrong-address", "nil-local", "non-nil-remote", "same-address-distinct"} {
		t.Run(mode, func(t *testing.T) {
			f := routeOperationFixture(t)
			if mode == "non-nil-remote" {
				f.input.RecipientAddr[31] = 2
			}
			if mode == "same-address-distinct" {
				f.input.RecipientAddr = bytes.Clone(f.source)
			}
			op := f.operation(t)
			out, _, err := op.execute(f.input, &routeOperationTestGate{}, func(a vmcommon.AccountsAdapter, i *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
				s, r, e := f.resolve(a, i)
				if e != nil {
					return nil, nil, e
				}
				switch mode {
				case "raw":
					raw, e := f.store.LoadAccount(f.source)
					require.NoError(t, e)
					s = raw.(vmcommon.UserAccountHandler)
				case "foreign":
					_, foreign, e := newRouteNativeGuard(f.store)
					require.NoError(t, e)
					raw, e := foreign.LoadAccount(f.source)
					require.NoError(t, e)
					s = raw.(vmcommon.UserAccountHandler)
				case "wrong-address":
					raw, e := a.LoadAccount(f.other)
					require.NoError(t, e)
					s = raw.(vmcommon.UserAccountHandler)
				case "nil-local":
					s = nil
				case "non-nil-remote":
					raw, e := a.LoadAccount(f.destination)
					require.NoError(t, e)
					r = raw.(vmcommon.UserAccountHandler)
				case "same-address-distinct":
					raw, e := a.LoadAccount(f.source)
					require.NoError(t, e)
					r = raw.(vmcommon.UserAccountHandler)
				}
				return s, r, nil
			})
			require.ErrorIs(t, err, errRouteNativeGuard)
			require.Nil(t, out)
			require.False(t, op.guard.admitted)
			require.Zero(t, f.store.JournalLen())
		})
	}
}

func TestRouteNativeOperationRejectsRemoteRecipientAtOwnAddress(t *testing.T) {
	// EXPERIMENTAL G10 fixture: seed and commit the remote recipient before the
	// operation, so account creation cannot supply an unrelated rejection.
	f := routeOperationTransferFixture(t, core.BuiltInFunctionESDTTransfer, "source")
	require.NotEqual(t, f.args.ShardCoordinator.SelfId(), f.args.ShardCoordinator.ComputeId(f.input.RecipientAddr))
	root, err := f.store.RootHash()
	require.NoError(t, err)
	require.Zero(t, f.store.JournalLen())
	op := f.operation(t)
	resolves, checks := 0, 0
	output, _, err := op.execute(f.input, &routeOperationTestGate{check: func(string, []byte, *vmcommon.ParsedESDTTransfers, *vmcommon.ContractCallInput) error {
		checks++
		return nil
	}}, func(accounts vmcommon.AccountsAdapter, input *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
		resolves++
		sender, receiver, e := f.resolve(accounts, input)
		require.NoError(t, e)
		require.Nil(t, receiver)
		account, e := accounts.LoadAccount(input.RecipientAddr)
		require.NoError(t, e)
		receiver = account.(vmcommon.UserAccountHandler)
		guarded, found := receiver.(*routeNativeUser)
		require.True(t, found)
		require.Same(t, op.guard, guarded.guard)
		require.Equal(t, input.RecipientAddr, receiver.AddressBytes())
		return sender, receiver, nil
	})
	require.ErrorIs(t, err, errRouteNativeGuard)
	require.Nil(t, output)
	require.Equal(t, 1, resolves)
	require.Zero(t, checks)
	require.False(t, op.guard.admitted)
	require.Zero(t, f.store.JournalLen())
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, big.NewInt(100), f.balance(t, f.source))
	require.Equal(t, big.NewInt(20), f.balance(t, f.destination))
}

func TestRouteNativeOperationSaveFailureRollsBackNativeWrites(t *testing.T) {
	f := routeOperationFixture(t)
	op := f.operation(t)
	owner, e := NewRollbackContainment(f.store)
	require.NoError(t, e)
	root, e := f.store.RootHash()
	require.NoError(t, e)
	original := errors.New("experimental save error after real native write")
	f.store.saveErr = original
	var output *vmcommon.VMOutput
	e = owner.Execute(func() (*vmcommon.VMOutput, error) {
		var err error
		output, _, err = op.execute(f.input, &routeOperationTestGate{}, f.resolve)
		return output, err
	})
	require.Same(t, original, e)
	require.Nil(t, output)
	require.Equal(t, 1, f.store.reverts)
	after, e := f.store.RootHash()
	require.NoError(t, e)
	require.Equal(t, root, after)
	require.Zero(t, f.store.JournalLen())
	require.Equal(t, big.NewInt(100), f.balance(t, f.source))
	require.Equal(t, big.NewInt(20), f.balance(t, f.destination))
}

func TestRouteNativeOperationSingleUseAndBusy(t *testing.T) {
	f := routeOperationFixture(t)
	op := f.operation(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, _, err := op.execute(f.input, &routeOperationTestGate{check: func(_ string, _ []byte, _ *vmcommon.ParsedESDTTransfers, _ *vmcommon.ContractCallInput) error {
			_, _, nested := op.execute(f.input, &routeOperationTestGate{}, f.resolve)
			if nested != ErrExecutionBusy {
				return errors.New("reentry was not rejected")
			}
			close(entered)
			<-release
			return nil
		}}, f.resolve)
		finished <- err
	}()
	<-entered
	out, parsed, e := op.execute(f.input, &routeOperationTestGate{}, f.resolve)
	require.Same(t, ErrExecutionBusy, e)
	require.Nil(t, out)
	require.Nil(t, parsed)
	close(release)
	require.NoError(t, <-finished)
	out, parsed, e = op.execute(f.input, &routeOperationTestGate{}, f.resolve)
	require.Same(t, ErrExecutionClosed, e)
	require.Nil(t, out)
	require.Nil(t, parsed)
	require.Equal(t, big.NewInt(90), f.balance(t, f.source))
	require.Equal(t, big.NewInt(30), f.balance(t, f.destination))
	require.ErrorIs(t, op.accounts.SaveAccount(nil), errRouteNativeGuard)
}

func routeOperationTransferFixture(t *testing.T, function, side string) *routeOperationTestFixture {
	t.Helper()
	f := routeOperationFixture(t)
	self := uint32(1)
	if side != "same" {
		f.destination[31] = 2
	}
	if side == "receiver" {
		self = 2
	}
	coordinator, e := sharding.NewMultiShardCoordinator(3, self)
	require.NoError(t, e)
	f.args.ShardCoordinator = coordinator
	for i, address := range [][]byte{f.source, f.destination, vmcommon.SystemAccountAddress} {
		a, e := f.store.LoadAccount(address)
		require.NoError(t, e)
		u := a.(vmcommon.UserAccountHandler)
		value := int64(100)
		if i == 1 {
			value = 20
		}
		if i == 2 {
			value = 120
		}
		if i < 2 {
			require.NoError(t, u.AddToBalance(new(big.Int).Sub(big.NewInt(value), u.GetBalance())))
		}
		for _, token := range []struct {
			id    string
			nonce uint64
			typ   uint32
		}{{"ORDINARY-abcdef", 0, uint32(core.Fungible)}, {"NONFUNG-abcdef", 1, uint32(core.SemiFungible)}} {
			if i == 2 && token.nonce == 0 {
				continue
			}
			var metadata *esdt.MetaData
			if token.nonce != 0 {
				metadata = &esdt.MetaData{Nonce: 1, Name: []byte("experimental metadata"), URIs: [][]byte{[]byte("experimental uri")}}
			}
			raw, e := f.args.Marshalizer.Marshal(&esdt.ESDigitalToken{Type: token.typ, Value: big.NewInt(value), TokenMetaData: metadata})
			require.NoError(t, e)
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier+token.id), new(big.Int).SetUint64(token.nonce).Bytes()...)
			require.NoError(t, u.AccountDataHandler().SaveKeyValue(key, raw))
		}
		require.NoError(t, f.store.SaveAccount(u))
	}
	_, e = f.store.AccountsAdapter.Commit()
	require.NoError(t, e)
	f.input.Function = function
	f.input.RecipientAddr = bytes.Clone(f.destination)
	payload, e := f.args.Marshalizer.Marshal(&esdt.ESDigitalToken{Type: uint32(core.SemiFungible), Value: big.NewInt(10), TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("experimental metadata"), URIs: [][]byte{[]byte("experimental uri")}}})
	require.NoError(t, e)
	switch function {
	case core.BuiltInFunctionESDTNFTTransfer:
		f.input.Arguments = [][]byte{[]byte("NONFUNG-abcdef"), {1}, {10}, payload}
		if side != "receiver" {
			f.input.RecipientAddr = bytes.Clone(f.source)
			f.input.Arguments[3] = bytes.Clone(f.destination)
		}
	case core.BuiltInFunctionMultiESDTNFTTransfer:
		f.input.Arguments = [][]byte{{3}, []byte("ORDINARY-abcdef"), {}, {10}, []byte("NONFUNG-abcdef"), {1}, payload, []byte(vmcommon.EGLDIdentifier), {}, {5}}
		if side != "receiver" {
			f.input.RecipientAddr = bytes.Clone(f.source)
			f.input.Arguments = [][]byte{bytes.Clone(f.destination), {3}, []byte("ORDINARY-abcdef"), {}, {10}, []byte("NONFUNG-abcdef"), {1}, {10}, []byte(vmcommon.EGLDIdentifier), {}, {5}}
		}
	}
	return f
}

func (f *routeOperationTestFixture) sftBalance(t *testing.T, address []byte) *big.Int {
	t.Helper()
	a, e := f.store.GetExistingAccount(address)
	require.NoError(t, e)
	key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier+"NONFUNG-abcdef"), 1)
	raw, _, e := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(key)
	require.NoError(t, e)
	value := &esdt.ESDigitalToken{}
	require.NoError(t, f.args.Marshalizer.Unmarshal(value, raw))
	return value.Value
}

func TestRouteNativeOperationTransferGraph(t *testing.T) {
	for _, function := range []string{core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTNFTTransfer, core.BuiltInFunctionMultiESDTNFTTransfer} {
		t.Run(function, func(t *testing.T) {
			for _, side := range []string{"same", "source", "receiver"} {
				t.Run(side, func(t *testing.T) {
					for _, mode := range []string{"healthy", "policy-denial", "post-write-save-failure"} {
						t.Run(mode, func(t *testing.T) {
							f := routeOperationTransferFixture(t, function, side)
							root, e := f.store.RootHash()
							require.NoError(t, e)
							op := f.operation(t)
							owner, e := NewRollbackContainment(f.store)
							require.NoError(t, e)
							original := errors.New("experimental " + mode)
							if mode == "post-write-save-failure" {
								f.store.saveErr = original
							}
							checks := 0
							var output *vmcommon.VMOutput
							e = owner.Execute(func() (*vmcommon.VMOutput, error) {
								var err error
								output, _, err = op.execute(f.input, &routeOperationTestGate{check: func(n string, s []byte, p *vmcommon.ParsedESDTTransfers, _ *vmcommon.ContractCallInput) error {
									checks++
									require.Equal(t, function, n)
									require.Equal(t, f.source, s)
									require.Equal(t, f.destination, p.RcvAddr)
									if function == core.BuiltInFunctionMultiESDTNFTTransfer {
										require.Len(t, p.ESDTTransfers, 3)
										require.Equal(t, []byte("ORDINARY-abcdef"), p.ESDTTransfers[0].ESDTTokenName)
										require.Equal(t, []byte("NONFUNG-abcdef"), p.ESDTTransfers[1].ESDTTokenName)
										require.Equal(t, []byte(vmcommon.EGLDIdentifier), p.ESDTTransfers[2].ESDTTokenName)
										require.Equal(t, big.NewInt(5), p.ESDTTransfers[2].ESDTValue)
									} else {
										require.Len(t, p.ESDTTransfers, 1)
									}
									if mode == "policy-denial" {
										return original
									}
									return nil
								}}, f.resolve)
								return output, err
							})
							require.Equal(t, 1, checks)
							if mode != "healthy" {
								require.Same(t, original, e)
								require.Nil(t, output)
								after, e := f.store.RootHash()
								require.NoError(t, e)
								require.Equal(t, root, after)
								require.Zero(t, f.store.JournalLen())
							} else {
								require.NoError(t, e)
								require.NotNil(t, output)
							}
							for _, leg := range []struct {
								address       []byte
								before, delta int64
							}{{f.source, 100, -10}, {f.destination, 20, 10}} {
								expected := leg.before
								local := f.args.ShardCoordinator.ComputeId(leg.address) == f.args.ShardCoordinator.SelfId()
								if mode == "healthy" && local {
									expected += leg.delta
								}
								if function != core.BuiltInFunctionESDTNFTTransfer {
									require.Equal(t, big.NewInt(expected), f.balance(t, leg.address))
								}
								if function != core.BuiltInFunctionESDTTransfer {
									require.Equal(t, big.NewInt(expected), f.sftBalance(t, leg.address))
								}
								account, e := f.store.GetExistingAccount(leg.address)
								require.NoError(t, e)
								base := leg.before
								if function == core.BuiltInFunctionMultiESDTNFTTransfer && mode == "healthy" && local {
									base += leg.delta / 2
								}
								require.Equal(t, big.NewInt(base), account.(vmcommon.UserAccountHandler).GetBalance())
							}
							if mode == "healthy" {
								require.NoError(t, owner.Abort())
								after, e := f.store.RootHash()
								require.NoError(t, e)
								require.Equal(t, root, after)
							}
						})
					}
				})
			}
		})
	}
}

func TestRouteNativeOperationConstructorFailures(t *testing.T) {
	for _, mode := range []string{"unsupported", "nil-accounts", "native-invalid-args", "nil-payable-factory", "nil-payable", "payable-error", "constructor-write", "constructor-commit", "constructor-revert"} {
		t.Run(mode, func(t *testing.T) {
			f := routeOperationFixture(t)
			name := f.input.Function
			original := errors.New("experimental constructor error")
			var captured vmcommon.AccountsAdapter
			payable := func(a vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error) {
				captured = a
				switch mode {
				case "nil-payable":
					return nil, nil
				case "payable-error":
					return nil, original
				case "constructor-write":
					u, e := a.LoadAccount(f.source)
					require.NoError(t, e)
					_ = u.(vmcommon.UserAccountHandler).AddToBalance(big.NewInt(1))
				case "constructor-commit":
					_, _ = a.Commit()
				case "constructor-revert":
					_ = a.RevertToSnapshot(0)
				}
				return &routeOperationTestPayable{}, nil
			}
			switch mode {
			case "unsupported":
				name = core.BuiltInFunctionESDTBurn
			case "nil-accounts":
				f.args.Accounts = nil
			case "native-invalid-args":
				f.args.Marshalizer = nil
			case "nil-payable-factory":
				payable = nil
			}
			op, e := newRouteNativeOperation(f.args, name, payable)
			require.Error(t, e)
			require.Nil(t, op)
			if mode == "payable-error" {
				require.Same(t, original, e)
			}
			if captured != nil {
				a := captured.(*routeNativeAccounts)
				require.True(t, a.guard.closed)
				require.ErrorIs(t, a.SaveAccount(nil), errRouteNativeGuard)
			}
			require.Zero(t, f.store.JournalLen())
			qualAssertContainmentBalance(t, f.store, 100)
		})
	}
}

func TestRouteNativeOperationPanicClosesViews(t *testing.T) {
	f := routeOperationFixture(t)
	op := f.operation(t)
	owner, e := NewRollbackContainment(f.store)
	require.NoError(t, e)
	require.PanicsWithValue(t, "experimental callback panic", func() {
		_ = owner.Execute(func() (*vmcommon.VMOutput, error) {
			out, _, err := op.execute(f.input, &routeOperationTestGate{check: func(_ string, _ []byte, _ *vmcommon.ParsedESDTTransfers, _ *vmcommon.ContractCallInput) error {
				panic("experimental callback panic")
			}}, f.resolve)
			return out, err
		})
	})
	require.True(t, op.guard.closed)
	require.False(t, op.guard.admitted)
	_, _, e = op.execute(f.input, &routeOperationTestGate{}, f.resolve)
	require.Same(t, ErrExecutionClosed, e)
	_, outputs, e := owner.Commit()
	require.Same(t, ErrExecutionInterrupted, e)
	require.Nil(t, outputs)
	require.NoError(t, owner.Recover())
	qualAssertContainmentBalance(t, f.store, 100)
}

func TestRouteNativeOwnerCommitOnce(t *testing.T) {
	s := qualContainmentStore(t)
	c, e := newNativeRollbackContainment(s)
	require.NoError(t, e)
	output := &vmcommon.VMOutput{GasRemaining: 123} // EXPERIMENTAL observation only.
	require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) { return output, qualContainmentBalance(s, 90) }))
	pending, e := s.RootHash()
	require.NoError(t, e)
	_, out, e := c.Commit()
	require.Same(t, errNativePersistenceOwned, e)
	require.Nil(t, out)
	require.Same(t, errNativePersistenceOwned, c.Abort())
	require.Same(t, errNativePersistenceOwned, c.Recover())
	require.Zero(t, s.commits)
	require.Zero(t, s.reverts)
	require.Zero(t, s.recreates)
	require.NoError(t, c.nativeBeforeCommit())
	require.Same(t, ErrExecutionBusy, c.Execute(func() (*vmcommon.VMOutput, error) { t.Fatal("effect after precommit"); return nil, nil }))
	actual, e := s.Commit()
	require.NoError(t, e)
	require.Equal(t, pending, actual)
	require.Equal(t, 1, s.commits)
	roots, outputs, e := c.nativeCommitReceipt()
	require.NoError(t, e)
	require.Equal(t, [][]byte{actual}, roots)
	require.Len(t, outputs, 1)
	require.Same(t, output, outputs[0])
	require.NoError(t, c.nativeCommittedFor(s))
	require.Equal(t, 1, s.commits)
	roots, outputs, e = c.nativeCommitReceipt()
	require.Same(t, ErrExecutionClosed, e)
	require.Nil(t, roots)
	require.Nil(t, outputs)
	require.Same(t, ErrExecutionClosed, c.nativeResetReceipt())
	require.Same(t, ErrExecutionClosed, c.Execute(func() (*vmcommon.VMOutput, error) { t.Fatal("effect after commit"); return nil, nil }))
}

func TestRouteNativeOwnerRejectsEarlyAndWrongReceipts(t *testing.T) {
	for _, mode := range []string{"early", "uncommitted", "wrong-root"} {
		t.Run(mode, func(t *testing.T) {
			s := qualContainmentStore(t)
			c, e := newNativeRollbackContainment(s)
			require.NoError(t, e)
			require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) {
				return &vmcommon.VMOutput{GasRemaining: 123}, qualContainmentBalance(s, 90)
			}))
			if mode != "early" {
				require.NoError(t, c.nativeBeforeCommit())
			}
			if mode == "wrong-root" {
				require.NoError(t, s.RevertToSnapshot(0))
			}
			roots, outputs, e := c.nativeCommitReceipt()
			require.Error(t, e)
			require.Nil(t, roots)
			require.Nil(t, outputs)
			require.NotNil(t, c.failure)
			require.Zero(t, s.commits)
			require.Error(t, c.Execute(func() (*vmcommon.VMOutput, error) { t.Fatal("effect after rejected receipt"); return nil, nil }))
			require.NoError(t, s.RevertToSnapshot(0))
			require.NoError(t, c.nativeResetReceipt())
			require.NoError(t, c.nativeResetFor(s))
			qualAssertContainmentBalance(t, s, 100)
			require.Error(t, c.nativeCommittedFor(s))
			require.Same(t, ErrExecutionClosed, c.nativeResetReceipt())
		})
	}
}

func TestRouteNativeOwnerPartialCommitNeedsActualReset(t *testing.T) {
	a, b := qualContainmentStore(t), qualContainmentStore(t)
	ra, e := a.RootHash()
	require.NoError(t, e)
	rb, e := b.RootHash()
	require.NoError(t, e)
	c, e := newNativeRollbackContainment(a, b)
	require.NoError(t, e)
	require.NoError(t, c.Execute(func() (*vmcommon.VMOutput, error) {
		if err := qualContainmentBalance(a, 90); err != nil {
			return nil, err
		}
		return &vmcommon.VMOutput{GasRemaining: 123}, qualContainmentBalance(b, 80)
	}))
	require.NoError(t, c.nativeBeforeCommit())
	_, e = a.Commit()
	require.NoError(t, e)
	original := errors.New("experimental second native store commit failure")
	b.commitErr = original
	_, e = b.Commit()
	require.Same(t, original, e)
	require.Same(t, original, c.nativeCommitFailed(e))
	roots, outputs, e := c.nativeCommitReceipt()
	require.Same(t, original, e)
	require.Nil(t, roots)
	require.Nil(t, outputs)
	require.Error(t, c.nativeResetReceipt())
	require.ErrorIs(t, c.failure, original)
	// The actual caller restores BOTH native stores, including the one persisted
	// before the later error. The attachment itself must not recreate either.
	require.Zero(t, a.recreates)
	require.Zero(t, b.recreates)
	require.NoError(t, a.RecreateTrie(holders.NewDefaultRootHashesHolder(ra)))
	require.NoError(t, b.RecreateTrie(holders.NewDefaultRootHashesHolder(rb)))
	require.NoError(t, c.nativeResetReceipt())
	require.Equal(t, 1, a.commits)
	require.Equal(t, 1, b.commits)
	require.Equal(t, 1, a.recreates)
	require.Equal(t, 1, b.recreates)
	qualAssertContainmentBalance(t, a, 100)
	qualAssertContainmentBalance(t, b, 100)
	require.Same(t, ErrExecutionClosed, c.Execute(func() (*vmcommon.VMOutput, error) { t.Fatal("reused recovered owner"); return nil, nil }))
}

func TestRouteNativeOwnerRegistryDelta(t *testing.T) {
	for _, mode := range []string{"commit", "abort", "commit-failure"} {
		t.Run(mode, func(t *testing.T) {
			parent, db, adapter, f, tr := qualRegistryLifecycle(t, false)
			// Transport has real native proofs/encoding, but supplies no canonical
			// inter-candidate ancestry/finality credit (same limit as the old fixture).
			store := &qualNativeStore{AccountsAdapter: adapter}
			owner, e := newNativeRollbackContainment(store)
			require.NoError(t, e)
			v, e := parent.prepareDelta(tr, &parent.anchor, f.anchor, f.count, []registryMemberWitness{f.members[2]})
			require.NoError(t, e)
			require.NoError(t, v.stageWithOwner(store, owner))
			regulated, e := v.classify(f.anchor.candidateHash, []byte("CCC-abcdef"))
			require.NoError(t, e)
			require.True(t, regulated)
			require.Len(t, parent.members, 2)
			require.Error(t, v.publishNativeDelta())
			require.Len(t, parent.members, 2)
			require.Zero(t, store.commits)
			require.Same(t, errNativePersistenceOwned, v.abort())
			require.Same(t, errNativePersistenceOwned, v.recover())
			_, _, e = v.commit()
			require.Same(t, errNativePersistenceOwned, e)
			require.Zero(t, store.commits)
			if mode == "commit" {
				require.NoError(t, owner.nativeBeforeCommit())
				_, e = store.Commit()
				require.NoError(t, e)
				require.Len(t, parent.members, 2)
				_, _, e = owner.nativeCommitReceipt()
				require.NoError(t, e)
				require.NoError(t, v.publishNativeDelta())
				require.Len(t, parent.members, 3)
				require.True(t, sameRegistryAnchor(&parent.anchor, f.anchor))
				require.Error(t, v.publishNativeDelta())
				require.Equal(t, 1, store.commits)
			} else {
				if mode == "commit-failure" {
					require.NoError(t, owner.nativeBeforeCommit())
					original := errors.New("experimental native delta commit failure")
					store.commitErr = original
					_, e = store.Commit()
					require.Same(t, original, e)
					require.Same(t, original, owner.nativeCommitFailed(e))
				}
				require.Error(t, v.discardNativeDelta())
				require.NotNil(t, parent.active)
				require.NoError(t, db.RevertToSnapshot(0))
				require.NoError(t, owner.nativeResetReceipt())
				require.NoError(t, v.discardNativeDelta())
				require.Len(t, parent.members, 2)
				require.Nil(t, parent.active)
				require.Error(t, v.publishNativeDelta())
			}
			_, e = v.classify(f.anchor.candidateHash, []byte("CCC-abcdef"))
			require.Error(t, e)
		})
	}
}

func TestRouteNativeOwnerInitialProjectionAndStoreIdentity(t *testing.T) {
	_, view, db, adapter := qualRegistryMaterialization(t, false)
	store := &qualNativeStore{AccountsAdapter: adapter}
	owner, e := newNativeRollbackContainment(store)
	require.NoError(t, e)
	other := qualContainmentStore(t)
	require.Error(t, owner.nativeOwns(other))
	isolated, e := NewRollbackContainment(store)
	require.NoError(t, e)
	_, e = newRegistryMaterializationWithOwner(store, &view.anchor, isolated)
	require.Error(t, e)
	_, e = newRegistryMaterializationWithOwner(other, &view.anchor, owner)
	require.Error(t, e)
	m, e := newRegistryMaterializationWithOwner(store, &view.anchor, owner)
	require.NoError(t, e)
	require.NoError(t, m.prepare(context.Background(), view))
	_, e = m.publishNativeProjection()
	require.Error(t, e)
	require.Zero(t, store.commits)
	require.NoError(t, owner.nativeBeforeCommit())
	_, e = store.Commit()
	require.NoError(t, e)
	_, _, e = owner.nativeCommitReceipt()
	require.NoError(t, e)
	projection, e := m.publishNativeProjection()
	require.NoError(t, e)
	require.Len(t, projection.members, 2)
	require.Equal(t, 1, store.commits)
	_, e = m.publishNativeProjection()
	require.Error(t, e)
	require.Nil(t, m.members)
	_, e = db.RootHash()
	require.NoError(t, e)
}

func TestRouteNativeOwnerPostCommitError(t *testing.T) {
	base := qualContainmentStore(t)
	root, err := base.RootHash()
	require.NoError(t, err)
	original := errors.New("experimental error after native commit cleared journal")
	fault := &qualRegistryLifecycleFault{qualRegistryMaterializationFault: &qualRegistryMaterializationFault{AccountsAdapter: base.AccountsAdapter}, commitError: original}
	store := &qualNativeStore{AccountsAdapter: fault}
	owner, err := newNativeRollbackContainment(store)
	require.NoError(t, err)
	require.NoError(t, owner.Execute(func() (*vmcommon.VMOutput, error) {
		return &vmcommon.VMOutput{GasRemaining: 123}, qualContainmentBalance(store, 90)
	}))
	require.NoError(t, owner.nativeBeforeCommit())
	_, err = store.Commit()
	require.Same(t, original, err)
	require.Zero(t, store.JournalLen())
	qualAssertContainmentBalance(t, store, 90)
	require.Same(t, original, owner.nativeCommitFailed(err))
	roots, outputs, err := owner.nativeCommitReceipt()
	require.Same(t, original, err)
	require.Nil(t, roots)
	require.Nil(t, outputs)
	require.Error(t, owner.nativeResetReceipt())
	require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.NoError(t, owner.nativeResetReceipt())
	qualAssertContainmentBalance(t, store, 100)
}

func TestRouteNativeOwnerFreezesBeforeCommit(t *testing.T) {
	store := qualContainmentStore(t)
	owner, err := newNativeRollbackContainment(store)
	require.NoError(t, err)
	require.NoError(t, owner.nativeBeforeCommit())
	called := false
	err = owner.Execute(func() (*vmcommon.VMOutput, error) { called = true; return nil, nil })
	require.Same(t, ErrExecutionBusy, err)
	require.False(t, called)
}

type routeOwnerRootFault struct {
	*qualNativeStore
	err error
}

func (s *routeOwnerRootFault) RootHash() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.qualNativeStore.RootHash()
}

func TestRouteNativeOwnerRootReadFailure(t *testing.T) {
	store := &routeOwnerRootFault{qualNativeStore: qualContainmentStore(t)}
	owner, err := newNativeRollbackContainment(store)
	require.NoError(t, err)
	require.NoError(t, owner.Execute(func() (*vmcommon.VMOutput, error) {
		return &vmcommon.VMOutput{GasRemaining: 123}, qualContainmentBalance(store.qualNativeStore, 90)
	}))
	first, later := errors.New("experimental precommit root read"), errors.New("experimental recovery root read")
	store.err = first
	require.Same(t, first, owner.nativeBeforeCommit())
	roots, outputs, err := owner.nativeCommitReceipt()
	require.Same(t, first, err)
	require.Nil(t, roots)
	require.Nil(t, outputs)
	// The actual native reset clears the dirty journal before probing its root read.
	require.NoError(t, store.RevertToSnapshot(0))
	store.err = later
	require.Error(t, owner.nativeResetReceipt())
	require.ErrorIs(t, owner.failure, first)
	require.ErrorIs(t, owner.failure, later)
	store.err = nil
	require.NoError(t, store.RevertToSnapshot(0))
	require.NoError(t, owner.nativeResetReceipt())
	qualAssertContainmentBalance(t, store.qualNativeStore, 100)
}

func TestRouteNativeOwnerRejectsConcurrentFinalization(t *testing.T) {
	store := qualContainmentStore(t)
	owner, err := newNativeRollbackContainment(store)
	require.NoError(t, err)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	go func() {
		finished <- owner.Execute(func() (*vmcommon.VMOutput, error) {
			close(entered)
			<-release
			return &vmcommon.VMOutput{GasRemaining: 123}, qualContainmentBalance(store, 90)
		})
	}()
	<-entered
	require.Same(t, ErrExecutionBusy, owner.nativeBeforeCommit())
	require.Same(t, ErrExecutionBusy, owner.nativeResetReceipt())
	require.Same(t, ErrExecutionBusy, owner.nativeOwns(store))
	roots, outputs, err := owner.nativeCommitReceipt()
	require.Same(t, ErrExecutionBusy, err)
	require.Nil(t, roots)
	require.Nil(t, outputs)
	require.Same(t, ErrExecutionBusy, owner.nativeCommitFailed(errors.New("experimental concurrent commit error")))
	close(release)
	require.NoError(t, <-finished)
	require.Nil(t, owner.failure)
	require.NoError(t, store.RevertToSnapshot(0))
	require.NoError(t, owner.nativeResetReceipt())
	require.Zero(t, store.commits)
}

type routeOperationClassifyGate struct {
	*routeOperationTestGate
	classify func(string, [][]byte) (bool, error)
}

func (g *routeOperationClassifyGate) Classify(n string, ids [][]byte) (bool, error) {
	return g.classify(n, ids)
}

func TestRouteNativeOperationClassificationDenial(t *testing.T) {
	for _, mode := range []string{"ordinary", "classification-error", "original-read-error"} {
		t.Run(mode, func(t *testing.T) {
			f := routeOperationFixture(t)
			original, later := errors.New("experimental classifier read error"), errors.New("experimental classifier error")
			f.args.Accounts = &routeOperationFaultAccounts{AccountsAdapter: f.store, fault: func(address []byte) error {
				if bytes.Equal(address, vmcommon.SystemAccountAddress) {
					return original
				}
				return nil
			}}
			op := f.operation(t)
			resolved, checked := 0, 0
			gate := &routeOperationClassifyGate{routeOperationTestGate: &routeOperationTestGate{check: func(string, []byte, *vmcommon.ParsedESDTTransfers, *vmcommon.ContractCallInput) error {
				checked++
				return nil
			}}, classify: func(n string, ids [][]byte) (bool, error) {
				require.Equal(t, f.input.Function, n)
				require.Equal(t, [][]byte{[]byte("ORDINARY-abcdef")}, ids)
				if mode == "ordinary" {
					return false, nil
				}
				if mode == "original-read-error" {
					_, _ = op.accounts.LoadAccount(vmcommon.SystemAccountAddress)
				}
				return true, later
			}}
			out, parsed, err := op.execute(f.input, gate, func(a vmcommon.AccountsAdapter, i *vmcommon.ContractCallInput) (vmcommon.UserAccountHandler, vmcommon.UserAccountHandler, error) {
				resolved++
				return f.resolve(a, i)
			})
			want := errRouteNativeGuard
			if mode == "classification-error" {
				want = later
			}
			if mode == "original-read-error" {
				want = original
			}
			require.Same(t, want, err)
			require.Nil(t, out)
			require.Nil(t, parsed)
			require.Zero(t, resolved)
			require.Zero(t, checked)
			require.False(t, op.guard.admitted)
			require.Zero(t, f.store.JournalLen())
		})
	}
}

func TestRouteNativeOperationCompactMetadataPreparation(t *testing.T) {
	for _, mode := range []string{"healthy", "native-read-error"} {
		t.Run(mode, func(t *testing.T) {
			f := routeOperationTransferFixture(t, core.BuiltInFunctionESDTNFTTransfer, "receiver")
			f.input.Arguments[3] = []byte{0} // Native compact metadata sentinel, not a new codec.
			f.args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(nativeBuiltins.SaveToSystemAccountFlag, nativeBuiltins.SendAlwaysFlag, nativeBuiltins.ESDTNFTImprovementV1Flag, nativeBuiltins.EGLDInESDTMultiTransferFlag, nativeBuiltins.CheckTransferFlag, nativeBuiltins.CheckCorrectTokenIDForTransferRoleFlag, nativeBuiltins.DynamicEsdtFlag)
			original := errors.New("experimental native compact metadata read")
			if mode == "native-read-error" {
				f.args.Accounts = &routeOperationFaultAccounts{AccountsAdapter: f.store, fault: func(address []byte) error {
					if bytes.Equal(address, vmcommon.SystemAccountAddress) {
						return original
					}
					return nil
				}}
			}
			op := f.operation(t)
			owner, err := NewRollbackContainment(f.store)
			require.NoError(t, err)
			checks := 0
			var output *vmcommon.VMOutput
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, _, e = op.execute(f.input, &routeOperationTestGate{check: func(_ string, _ []byte, p *vmcommon.ParsedESDTTransfers, _ *vmcommon.ContractCallInput) error {
					checks++
					require.Len(t, p.ESDTTransfers, 1)
					require.Equal(t, uint32(core.SemiFungible), p.ESDTTransfers[0].ESDTTokenType)
					require.Equal(t, big.NewInt(10), p.ESDTTransfers[0].ESDTValue)
					return nil
				}}, f.resolve)
				return output, e
			})
			if mode == "native-read-error" {
				require.Same(t, original, err)
				require.Nil(t, output)
				require.Zero(t, checks)
				require.False(t, op.guard.admitted)
				require.Equal(t, big.NewInt(20), f.sftBalance(t, f.destination))
				require.Zero(t, f.store.JournalLen())
			} else {
				require.NoError(t, err)
				require.NotNil(t, output)
				require.Equal(t, 1, checks)
				require.Equal(t, big.NewInt(30), f.sftBalance(t, f.destination))
				require.NoError(t, owner.Abort())
			}
		})
	}
}

func TestRouteNativeGuardAdapterRootViewIsDetached(t *testing.T) {
	store := qualContainmentStore(t)
	root, err := store.RootHash()
	require.NoError(t, err)
	original := bytes.Clone(root)
	require.NotEmpty(t, original)
	_, accounts, err := newRouteNativeGuard(store)
	require.NoError(t, err)
	view, err := accounts.RootHash()
	require.NoError(t, err)
	require.NotEmpty(t, view)
	view[0] ^= 0xff
	after, err := store.RootHash()
	require.NoError(t, err)
	require.Equal(t, original, after)
}

func TestRouteNativeOperationConstructorRetainsRootReadError(t *testing.T) {
	f := routeOperationFixture(t)
	original := errors.New("experimental constructor native root read")
	f.args.Accounts = &routeOwnerRootFault{qualNativeStore: f.store, err: original}
	operation, err := newRouteNativeOperation(f.args, f.input.Function, func(accounts vmcommon.AccountsAdapter) (vmcommon.PayableHandler, error) {
		_, _ = accounts.RootHash() // Deliberately discard the original read error.
		return &routeOperationTestPayable{}, nil
	})
	require.Same(t, original, err)
	require.Nil(t, operation)
}
