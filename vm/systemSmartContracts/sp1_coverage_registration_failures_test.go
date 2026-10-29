package systemSmartContracts

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type sp1CreationFault struct {
	kind    string
	at      int
	calls   map[string]int
	hit     bool
	failure error
}

func (f *sp1CreationFault) deny(kind string) bool {
	f.calls[kind]++
	if kind == f.kind && f.calls[kind] == f.at {
		f.hit = true
		return true
	}
	return false
}

type sp1CreationStore struct {
	state.AccountsAdapter
	f *sp1CreationFault
}

func (s *sp1CreationStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if !bytes.Equal(address, core.ESDTSCAddress) {
		return s.AccountsAdapter.GetExistingAccount(address)
	}
	if s.f.deny("account") {
		return nil, s.f.failure
	}
	if s.f.deny("invalid-user") {
		return nil, nil
	}
	a, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &sp1CreationAccount{UserAccountHandler: a.(state.UserAccountHandler), f: s.f}, nil
}
func (s *sp1CreationStore) SaveAccount(a vmcommon.AccountHandler) error {
	if wrapped, ok := a.(*sp1CreationAccount); ok {
		a = wrapped.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(a)
}

type sp1CreationAccount struct {
	state.UserAccountHandler
	f *sp1CreationFault
}

func (a *sp1CreationAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if a.f.deny("read") {
		return nil, 0, a.f.failure
	}
	return a.UserAccountHandler.RetrieveValue(key)
}
func (a *sp1CreationAccount) SaveKeyValue(key, value []byte) error {
	if a.f.deny("write") {
		return a.f.failure
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

type sp1CreationMarshal struct {
	marshal.Marshalizer
	f *sp1CreationFault
}

func (m *sp1CreationMarshal) Marshal(v interface{}) ([]byte, error) {
	if m.f.deny("marshal") {
		return nil, m.f.failure
	}
	return m.Marshalizer.Marshal(v)
}
func (m *sp1CreationMarshal) Unmarshal(v interface{}, data []byte) error {
	if m.f.deny("unmarshal") {
		return m.f.failure
	}
	return m.Marshalizer.Unmarshal(v, data)
}
func TestSP1CoverageNativeRegistrationDependencyFailures(t *testing.T) {
	// The healthy native operation establishes which dependency boundaries are
	// reached. Each failure then starts from a new committed native fixture.
	control := &sp1CreationFault{calls: make(map[string]int)}
	e, _, s, r, _, request := qualNativeRegistration(t)
	e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.ESDTMetadataContinuousCleanupFlag, common.ESDTNFTCreateOnMultiShardFlag)
	s.AccountsAdapter = &sp1CreationStore{AccountsAdapter: s.AccountsAdapter, f: control}
	e.marshalizer = &sp1CreationMarshal{Marshalizer: e.marshalizer, f: control}
	require.NoError(t, e.registerDRWAToken(r, request))
	for _, kind := range []string{"account", "invalid-user", "read", "write", "marshal", "unmarshal"} {
		for at := 1; at <= control.calls[kind]; at++ {
			t.Run(fmt.Sprintf("%s/%d", kind, at), func(t *testing.T) {
				e, ctx, s, r, _, request := qualNativeRegistration(t)
				e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.ESDTMetadataContinuousCleanupFlag, common.ESDTNFTCreateOnMultiShardFlag)
				f := &sp1CreationFault{kind: kind, at: at, calls: make(map[string]int), failure: errors.New("native creation dependency unavailable")}
				s.AccountsAdapter = &sp1CreationStore{AccountsAdapter: s.AccountsAdapter, f: f}
				e.marshalizer = &sp1CreationMarshal{Marshalizer: e.marshalizer, f: f}
				root, err := s.RootHash()
				require.NoError(t, err)
				journal := s.JournalLen()
				require.Error(t, e.registerDRWAToken(r, request))
				require.True(t, f.hit)
				after, err := s.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, after)
				require.Equal(t, journal, s.JournalLen())
				require.Empty(t, ctx.storageUpdate)
				require.Empty(t, ctx.output)
				require.Empty(t, ctx.outputAccounts)
				require.Empty(t, ctx.logs)
				require.Same(t, ctx, e.eei)
			})
		}
	}
}

func TestSP1CoverageStrictRegistrationStorage(t *testing.T) {
	_, ctx, s, _, _, _ := qualNativeRegistration(t)
	f := &sp1CreationFault{kind: "account", at: 1, calls: make(map[string]int), failure: errors.New("native account unavailable")}
	strict := &drwaRegistrationEI{SystemEI: ctx, context: ctx, accounts: &sp1CreationStore{AccountsAdapter: s, f: f}}
	key := []byte("pending-native-key")
	ctx.SetStorage(key, []byte("pending-value"))
	require.Equal(t, []byte("pending-value"), strict.GetStorage(key))
	require.Empty(t, f.calls)
	require.NoError(t, strict.readErr)
	ctx.CleanStorageUpdates()
	require.Nil(t, strict.GetStorage(key))
	require.ErrorIs(t, strict.readErr, f.failure)
	f.kind = "invalid-user"
	f.calls = make(map[string]int)
	strict.readErr = nil
	require.Nil(t, strict.GetStorage(key))
	require.ErrorIs(t, strict.readErr, errInvalidDRWARegistration)
}

type sp1EndpointOwner struct {
	called   bool
	id, body []byte
}

func (o *sp1EndpointOwner) IsInterfaceNil() bool { return o == nil }
func (o *sp1EndpointOwner) RegisterTokenForAuthenticatedCreation(id, body, issuer, manager, family, profile, name, ticker []byte, decimals uint32,
	create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error {
	o.called = true
	o.id = bytes.Clone(id)
	o.body = bytes.Clone(body)
	_, _, err := create(nil, issuer, manager, family, name, ticker, decimals, nil)
	return err
}
func TestSP1CoverageEndpointCreationFailure(t *testing.T) {
	_, ctx, _, _, _, _ := qualNativeRegistration(t)
	owner := &sp1EndpointOwner{}
	endpoint := &drwaEndpointCreation{owner: owner, context: ctx, id: []byte("intent"), body: []byte("immutable-body"), value: big.NewInt(17)}
	sentinel := errors.New("native creator denied")
	err := endpoint.RegisterTokenForCommittedCreation(nil, nil, nil, nil, nil, nil, 0, nil,
		func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error) {
			return nil, nil, sentinel
		})
	require.ErrorIs(t, err, sentinel)
	require.True(t, owner.called)
	require.Equal(t, endpoint.id, owner.id)
	require.Equal(t, endpoint.body, owner.body)
	require.Empty(t, ctx.outputAccounts)
	require.Empty(t, ctx.output)
	require.Empty(t, ctx.storageUpdate)
}
