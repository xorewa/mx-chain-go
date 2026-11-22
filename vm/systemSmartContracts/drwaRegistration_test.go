package systemSmartContracts

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

type creationFault struct {
	kind    string
	at      int
	calls   map[string]int
	hit     bool
	failure error
}

func (f *creationFault) deny(kind string) bool {
	f.calls[kind]++
	if kind == f.kind && f.calls[kind] == f.at {
		f.hit = true
		return true
	}
	return false
}

type creationStore struct {
	state.AccountsAdapter
	f *creationFault
}

func (s *creationStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
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
	return &creationAccount{UserAccountHandler: a.(state.UserAccountHandler), f: s.f}, nil
}

func (s *creationStore) SaveAccount(a vmcommon.AccountHandler) error {
	if wrapped, ok := a.(*creationAccount); ok {
		a = wrapped.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(a)
}

type creationAccount struct {
	state.UserAccountHandler
	f *creationFault
}

func (a *creationAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if a.f.deny("read") {
		return nil, 0, a.f.failure
	}
	return a.UserAccountHandler.RetrieveValue(key)
}

func (a *creationAccount) SaveKeyValue(key, value []byte) error {
	if a.f.deny("write") {
		return a.f.failure
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

type creationMarshal struct {
	marshal.Marshalizer
	f *creationFault
}

func (m *creationMarshal) Marshal(v interface{}) ([]byte, error) {
	if m.f.deny("marshal") {
		return nil, m.f.failure
	}
	return m.Marshalizer.Marshal(v)
}

func (m *creationMarshal) Unmarshal(v interface{}, data []byte) error {
	if m.f.deny("unmarshal") {
		return m.f.failure
	}
	return m.Marshalizer.Unmarshal(v, data)
}

func TestESDT_RegisterDRWATokenLocked(t *testing.T) {
	// The healthy native operation establishes which dependency boundaries are
	// reached. Each failure then starts from a new committed native fixture.
	control := &creationFault{calls: make(map[string]int)}
	e, _, s, r, _, request := qualNativeRegistration(t)
	e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.ESDTMetadataContinuousCleanupFlag, common.ESDTNFTCreateOnMultiShardFlag)
	s.AccountsAdapter = &creationStore{AccountsAdapter: s.AccountsAdapter, f: control}
	e.marshalizer = &creationMarshal{Marshalizer: e.marshalizer, f: control}
	require.NoError(t, e.registerDRWAToken(r, request))
	for _, kind := range []string{"account", "invalid-user", "read", "write", "marshal", "unmarshal"} {
		for at := 1; at <= control.calls[kind]; at++ {
			t.Run(strings.ReplaceAll(fmt.Sprintf("%s/%d", kind, at), "/", " ")+" should preserve the expected result", func(t *testing.T) {
				e, ctx, s, r, _, request := qualNativeRegistration(t)
				e.enableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.ESDTMetadataContinuousCleanupFlag, common.ESDTNFTCreateOnMultiShardFlag)
				f := &creationFault{kind: kind, at: at, calls: make(map[string]int), failure: errors.New("native creation dependency unavailable")}
				s.AccountsAdapter = &creationStore{AccountsAdapter: s.AccountsAdapter, f: f}
				e.marshalizer = &creationMarshal{Marshalizer: e.marshalizer, f: f}
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

func TestDRWARegistrationEI_GetStorage(t *testing.T) {
	_, ctx, s, _, _, _ := qualNativeRegistration(t)
	f := &creationFault{kind: "account", at: 1, calls: make(map[string]int), failure: errors.New("native account unavailable")}
	strict := &drwaRegistrationEI{SystemEI: ctx, context: ctx, accounts: &creationStore{AccountsAdapter: s, f: f}}
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
