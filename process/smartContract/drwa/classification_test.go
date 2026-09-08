package drwa

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"

	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestDRWAClassificationMarkerDeterministicFixture(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	key, err := DRWARegulatedTokenKey(tokenID)
	require.NoError(t, err)
	require.Equal(t, "ELRONDdrwa/prototype-regulated/TOKEN-abcdef", string(key))
	require.Equal(t, "445257412d50524f544f545950452d524547554c4154454401", hex.EncodeToString([]byte(drwaRegulatedMarkerValue)))

	fixture := append(append([]byte(nil), key...), []byte(drwaRegulatedMarkerValue)...)
	digest := sha256.Sum256(fixture)
	require.Equal(t, "d001c4504add3257288c61e0a76ef0b864934f58f0f955384e528911751cd5d2", hex.EncodeToString(digest[:]))
}

func TestDRWARegulatedTokenKeyIsProtectedBoundedAndFresh(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	key, err := DRWARegulatedTokenKey(tokenID)
	require.NoError(t, err)
	require.False(t, vmcommon.IsAllowedToSaveUnderKey(key))
	require.Equal(t, core.ProtectedKeyPrefix+drwaRegulatedKeySuffix+string(tokenID), string(key))

	tokenID[0] ^= 0xff
	require.Equal(t, byte('T'), key[len(core.ProtectedKeyPrefix)+len(drwaRegulatedKeySuffix)])
	key[0] ^= 0xff
	fresh, err := DRWARegulatedTokenKey([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.Equal(t, byte(core.ProtectedKeyPrefix[0]), fresh[0])

	_, err = DRWARegulatedTokenKey([]byte("ABCDEFGHIJ-abcdef"))
	require.NoError(t, err)
	_, err = DRWARegulatedTokenKey(nil)
	require.ErrorIs(t, err, ErrInvalidDRWARegulatedTokenID)
	_, err = DRWARegulatedTokenKey([]byte("invalid"))
	require.ErrorIs(t, err, ErrInvalidDRWARegulatedTokenID)
	_, err = DRWARegulatedTokenKey(make([]byte, drwaTokenIDLimit+1))
	require.ErrorIs(t, err, ErrInvalidDRWARegulatedTokenID)
}

func TestDRWAClassificationAbsentMarkedAndMalformed(t *testing.T) {
	t.Parallel()

	accounts, stored, _, loadedAddresses := newDRWAClassificationMemoryAccounts()
	tokenID := []byte("TOKEN-abcdef")
	regulated, err := IsDRWARegulatedToken(accounts, tokenID)
	require.NoError(t, err)
	require.False(t, regulated)
	require.Equal(t, [][]byte{vmcommon.SystemAccountAddress}, *loadedAddresses)

	key, err := DRWARegulatedTokenKey(tokenID)
	require.NoError(t, err)
	stored[string(key)] = []byte(drwaRegulatedMarkerValue)
	regulated, err = IsDRWARegulatedToken(accounts, tokenID)
	require.NoError(t, err)
	require.True(t, regulated)

	stored[string(key)] = []byte("not-the-marker")
	regulated, err = IsDRWARegulatedToken(accounts, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidDRWAClassificationMarker)
}

func TestDRWAClassificationFailsClosedOnAccountFailures(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	var nilAccounts *vmcommonMock.AccountsStub
	regulated, err := IsDRWARegulatedToken(nilAccounts, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrNilDRWAClassificationAccounts)

	injectedLoad := errors.New("injected account load failure")
	loadFailure := &vmcommonMock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			require.Equal(t, vmcommon.SystemAccountAddress, address)
			return nil, injectedLoad
		},
	}
	regulated, err = IsDRWARegulatedToken(loadFailure, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, injectedLoad)

	wrongType := &vmcommonMock.AccountsStub{
		GetExistingAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &drwaNonUserAccount{}, nil
		},
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &drwaNonUserAccount{}, nil
		},
	}
	regulated, err = IsDRWARegulatedToken(wrongType, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidDRWAClassificationAccount)

	wrongAddress := &vmcommonMock.AccountsStub{
		GetExistingAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &vmcommonMock.UserAccountStub{
				Address: []byte("not-the-system-account"),
				AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
					return &trieMock.DataTrieTrackerStub{}
				},
			}, nil
		},
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &vmcommonMock.UserAccountStub{
				Address: []byte("not-the-system-account"),
				AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
					return &trieMock.DataTrieTrackerStub{}
				},
			}, nil
		},
	}
	regulated, err = IsDRWARegulatedToken(wrongAddress, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidDRWAClassificationAccount)

	nilDataHandler := &vmcommonMock.AccountsStub{
		GetExistingAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &vmcommonMock.UserAccountStub{Address: vmcommon.SystemAccountAddress}, nil
		},
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &vmcommonMock.UserAccountStub{Address: vmcommon.SystemAccountAddress}, nil
		},
	}
	regulated, err = IsDRWARegulatedToken(nilDataHandler, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidDRWAClassificationAccount)
}

func TestDRWAClassificationPropagatesStorageFailures(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	injectedRetrieve := errors.New("injected marker retrieve failure")
	retrieveFailure := newDRWAClassificationAccountsWithHandler(&trieMock.DataTrieTrackerStub{
		RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
			return nil, 0, injectedRetrieve
		},
	}, nil)
	regulated, err := IsDRWARegulatedToken(retrieveFailure, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, injectedRetrieve)
}

type drwaNonUserAccount struct{}

func (account *drwaNonUserAccount) AddressBytes() []byte   { return vmcommon.SystemAccountAddress }
func (account *drwaNonUserAccount) IncreaseNonce(_ uint64) {}
func (account *drwaNonUserAccount) GetNonce() uint64       { return 0 }
func (account *drwaNonUserAccount) IsInterfaceNil() bool   { return account == nil }

func newDRWAClassificationMemoryAccounts() (*vmcommonMock.AccountsStub, map[string][]byte, *[]vmcommon.AccountHandler, *[][]byte) {
	stored := make(map[string][]byte)
	savedAccounts := make([]vmcommon.AccountHandler, 0)
	loadedAddresses := make([][]byte, 0)
	handler := &trieMock.DataTrieTrackerStub{
		RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
			return append([]byte(nil), stored[string(key)]...), 0, nil
		},
		SaveKeyValueCalled: func(key []byte, value []byte) error {
			stored[string(append([]byte(nil), key...))] = append([]byte(nil), value...)
			return nil
		},
	}
	account := &vmcommonMock.UserAccountStub{
		Address: vmcommon.SystemAccountAddress,
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return handler
		},
	}
	accounts := &vmcommonMock.AccountsStub{
		GetExistingAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return account, nil
		},
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			loadedAddresses = append(loadedAddresses, append([]byte(nil), address...))
			return account, nil
		},
		SaveAccountCalled: func(saved vmcommon.AccountHandler) error {
			savedAccounts = append(savedAccounts, saved)
			return nil
		},
	}

	return accounts, stored, &savedAccounts, &loadedAddresses
}

func newDRWAClassificationAccountsWithHandler(handler vmcommon.AccountDataHandler, saveAccount func(vmcommon.AccountHandler) error) *vmcommonMock.AccountsStub {
	account := &vmcommonMock.UserAccountStub{
		Address: vmcommon.SystemAccountAddress,
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return handler
		},
	}

	return &vmcommonMock.AccountsStub{
		GetExistingAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return account, nil
		},
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return account, nil
		},
		SaveAccountCalled: saveAccount,
	}
}
