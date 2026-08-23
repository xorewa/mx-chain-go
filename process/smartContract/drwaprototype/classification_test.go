package drwaprototype

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

func TestPrototypeClassificationMarkerDeterministicFixture(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	key, err := PrototypeRegulatedTokenKey(tokenID)
	require.NoError(t, err)
	require.Equal(t, "ELRONDdrwa/prototype-regulated/TOKEN-abcdef", string(key))
	require.Equal(t, "445257412d50524f544f545950452d524547554c4154454401", hex.EncodeToString([]byte(prototypeRegulatedMarkerValue)))

	fixture := append(append([]byte(nil), key...), []byte(prototypeRegulatedMarkerValue)...)
	digest := sha256.Sum256(fixture)
	require.Equal(t, "d001c4504add3257288c61e0a76ef0b864934f58f0f955384e528911751cd5d2", hex.EncodeToString(digest[:]))
}

func TestPrototypeRegulatedTokenKeyIsProtectedBoundedAndFresh(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	key, err := PrototypeRegulatedTokenKey(tokenID)
	require.NoError(t, err)
	require.False(t, vmcommon.IsAllowedToSaveUnderKey(key))
	require.Equal(t, core.ProtectedKeyPrefix+prototypeRegulatedKeySuffix+string(tokenID), string(key))

	tokenID[0] ^= 0xff
	require.Equal(t, byte('T'), key[len(core.ProtectedKeyPrefix)+len(prototypeRegulatedKeySuffix)])
	key[0] ^= 0xff
	fresh, err := PrototypeRegulatedTokenKey([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.Equal(t, byte(core.ProtectedKeyPrefix[0]), fresh[0])

	maximumTokenID := make([]byte, prototypeTokenIDLimit)
	maximumTokenID[0] = 1
	_, err = PrototypeRegulatedTokenKey(maximumTokenID)
	require.NoError(t, err)
	_, err = PrototypeRegulatedTokenKey(nil)
	require.ErrorIs(t, err, ErrInvalidPrototypeRegulatedTokenID)
	_, err = PrototypeRegulatedTokenKey(make([]byte, prototypeTokenIDLimit+1))
	require.ErrorIs(t, err, ErrInvalidPrototypeRegulatedTokenID)
}

func TestPrototypeClassificationAbsentMarkedAndMalformed(t *testing.T) {
	t.Parallel()

	accounts, stored, _, loadedAddresses := newPrototypeClassificationMemoryAccounts()
	tokenID := []byte("TOKEN-abcdef")
	regulated, err := IsPrototypeRegulatedToken(accounts, tokenID)
	require.NoError(t, err)
	require.False(t, regulated)
	require.Equal(t, [][]byte{vmcommon.SystemAccountAddress}, *loadedAddresses)

	require.NoError(t, MarkPrototypeRegulatedToken(accounts, tokenID))
	regulated, err = IsPrototypeRegulatedToken(accounts, tokenID)
	require.NoError(t, err)
	require.True(t, regulated)

	key, err := PrototypeRegulatedTokenKey(tokenID)
	require.NoError(t, err)
	stored[string(key)] = []byte("not-the-marker")
	regulated, err = IsPrototypeRegulatedToken(accounts, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidPrototypeClassificationMarker)
}

func TestMarkPrototypeRegulatedTokenSavesSystemAccountAndRejectsEveryDuplicate(t *testing.T) {
	t.Parallel()

	accounts, stored, savedAccounts, _ := newPrototypeClassificationMemoryAccounts()
	tokenID := []byte("TOKEN-abcdef")
	require.NoError(t, MarkPrototypeRegulatedToken(accounts, tokenID))
	require.Len(t, *savedAccounts, 1)
	require.Equal(t, vmcommon.SystemAccountAddress, (*savedAccounts)[0].AddressBytes())

	key, err := PrototypeRegulatedTokenKey(tokenID)
	require.NoError(t, err)
	require.Equal(t, []byte(prototypeRegulatedMarkerValue), stored[string(key)])
	require.ErrorIs(t, MarkPrototypeRegulatedToken(accounts, tokenID), ErrPrototypeClassificationAlreadyExists)
	require.Len(t, *savedAccounts, 1)

	otherTokenID := []byte("OTHER-abcdef")
	otherKey, err := PrototypeRegulatedTokenKey(otherTokenID)
	require.NoError(t, err)
	stored[string(otherKey)] = []byte("malformed-existing-state")
	require.ErrorIs(t, MarkPrototypeRegulatedToken(accounts, otherTokenID), ErrPrototypeClassificationAlreadyExists)
	require.Len(t, *savedAccounts, 1)
}

func TestPrototypeClassificationFailsClosedOnAccountFailures(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	var nilAccounts *vmcommonMock.AccountsStub
	regulated, err := IsPrototypeRegulatedToken(nilAccounts, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrNilPrototypeClassificationAccounts)
	require.ErrorIs(t, MarkPrototypeRegulatedToken(nilAccounts, tokenID), ErrNilPrototypeClassificationAccounts)

	injectedLoad := errors.New("injected account load failure")
	loadFailure := &vmcommonMock.AccountsStub{
		LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			require.Equal(t, vmcommon.SystemAccountAddress, address)
			return nil, injectedLoad
		},
	}
	regulated, err = IsPrototypeRegulatedToken(loadFailure, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, injectedLoad)

	wrongType := &vmcommonMock.AccountsStub{
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &prototypeNonUserAccount{}, nil
		},
	}
	regulated, err = IsPrototypeRegulatedToken(wrongType, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidPrototypeClassificationAccount)

	wrongAddress := &vmcommonMock.AccountsStub{
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &vmcommonMock.UserAccountStub{
				Address: []byte("not-the-system-account"),
				AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
					return &trieMock.DataTrieTrackerStub{}
				},
			}, nil
		},
	}
	regulated, err = IsPrototypeRegulatedToken(wrongAddress, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidPrototypeClassificationAccount)

	nilDataHandler := &vmcommonMock.AccountsStub{
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return &vmcommonMock.UserAccountStub{}, nil
		},
	}
	regulated, err = IsPrototypeRegulatedToken(nilDataHandler, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, ErrInvalidPrototypeClassificationAccount)
}

func TestPrototypeClassificationPropagatesStorageFailures(t *testing.T) {
	t.Parallel()

	tokenID := []byte("TOKEN-abcdef")
	injectedRetrieve := errors.New("injected marker retrieve failure")
	retrieveFailure := newPrototypeClassificationAccountsWithHandler(&trieMock.DataTrieTrackerStub{
		RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
			return nil, 0, injectedRetrieve
		},
	}, nil)
	regulated, err := IsPrototypeRegulatedToken(retrieveFailure, tokenID)
	require.False(t, regulated)
	require.ErrorIs(t, err, injectedRetrieve)
	require.ErrorIs(t, MarkPrototypeRegulatedToken(retrieveFailure, tokenID), injectedRetrieve)

	injectedKeySave := errors.New("injected marker key save failure")
	accountSaveCalled := false
	keySaveFailure := newPrototypeClassificationAccountsWithHandler(&trieMock.DataTrieTrackerStub{
		SaveKeyValueCalled: func(_ []byte, _ []byte) error {
			return injectedKeySave
		},
	}, func(_ vmcommon.AccountHandler) error {
		accountSaveCalled = true
		return nil
	})
	require.ErrorIs(t, MarkPrototypeRegulatedToken(keySaveFailure, tokenID), injectedKeySave)
	require.False(t, accountSaveCalled)

	injectedAccountSave := errors.New("injected system account save failure")
	accountSaveFailure := newPrototypeClassificationAccountsWithHandler(&trieMock.DataTrieTrackerStub{}, func(_ vmcommon.AccountHandler) error {
		return injectedAccountSave
	})
	require.ErrorIs(t, MarkPrototypeRegulatedToken(accountSaveFailure, tokenID), injectedAccountSave)
}

type prototypeNonUserAccount struct{}

func (account *prototypeNonUserAccount) AddressBytes() []byte   { return vmcommon.SystemAccountAddress }
func (account *prototypeNonUserAccount) IncreaseNonce(_ uint64) {}
func (account *prototypeNonUserAccount) GetNonce() uint64       { return 0 }
func (account *prototypeNonUserAccount) IsInterfaceNil() bool   { return account == nil }

func newPrototypeClassificationMemoryAccounts() (*vmcommonMock.AccountsStub, map[string][]byte, *[]vmcommon.AccountHandler, *[][]byte) {
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

func newPrototypeClassificationAccountsWithHandler(handler vmcommon.AccountDataHandler, saveAccount func(vmcommon.AccountHandler) error) *vmcommonMock.AccountsStub {
	account := &vmcommonMock.UserAccountStub{
		Address: vmcommon.SystemAccountAddress,
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return handler
		},
	}

	return &vmcommonMock.AccountsStub{
		LoadAccountCalled: func(_ []byte) (vmcommon.AccountHandler, error) {
			return account, nil
		},
		SaveAccountCalled: saveAccount,
	}
}
