package drwaprototype

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// This protected marker is only an S1-S5 test classifier. Its key and value are not production
// registry representations and must be removed or disabled when the permanent classifier lands.

const (
	prototypeRegulatedKeySuffix   = "drwa/prototype-regulated/"
	prototypeRegulatedMarkerValue = "DRWA-PROTOTYPE-REGULATED\x01"
)

var (
	// ErrInvalidPrototypeRegulatedTokenID signals an empty or over-limit prototype token ID.
	ErrInvalidPrototypeRegulatedTokenID = errors.New("invalid non-normative DRWA prototype regulated token ID")
	// ErrNilPrototypeClassificationAccounts signals that the prototype classifier has no accounts adapter.
	ErrNilPrototypeClassificationAccounts = errors.New("nil non-normative DRWA prototype classification accounts adapter")
	// ErrInvalidPrototypeClassificationAccount signals that the system address did not resolve to a usable user account.
	ErrInvalidPrototypeClassificationAccount = errors.New("invalid non-normative DRWA prototype classification system account")
	// ErrInvalidPrototypeClassificationMarker signals non-empty state other than the exact prototype marker.
	ErrInvalidPrototypeClassificationMarker = errors.New("invalid non-normative DRWA prototype classification marker")
	// ErrPrototypeClassificationAlreadyExists signals that the marker key already has non-empty state.
	ErrPrototypeClassificationAlreadyExists = errors.New("non-normative DRWA prototype classification marker already exists")
)

// PrototypeRegulatedTokenKey returns a fresh protected key for one bounded prototype token ID.
func PrototypeRegulatedTokenKey(tokenID []byte) ([]byte, error) {
	if len(tokenID) == 0 || len(tokenID) > prototypeTokenIDLimit {
		return nil, ErrInvalidPrototypeRegulatedTokenID
	}

	key := make([]byte, 0, len(core.ProtectedKeyPrefix)+len(prototypeRegulatedKeySuffix)+len(tokenID))
	key = append(key, core.ProtectedKeyPrefix...)
	key = append(key, prototypeRegulatedKeySuffix...)
	key = append(key, tokenID...)

	return key, nil
}

// IsPrototypeRegulatedToken classifies one token from protected system-account state.
// Absence is ordinary; every observation or decoding failure is returned as an error.
func IsPrototypeRegulatedToken(accounts vmcommon.AccountsAdapter, tokenID []byte) (bool, error) {
	key, err := PrototypeRegulatedTokenKey(tokenID)
	if err != nil {
		return false, err
	}

	_, dataHandler, err := loadPrototypeClassificationSystemAccount(accounts)
	if err != nil {
		return false, err
	}
	stored, _, err := dataHandler.RetrieveValue(key)
	if err != nil {
		return false, fmt.Errorf("retrieve prototype classification marker: %w", err)
	}
	if len(stored) == 0 {
		return false, nil
	}
	if !bytes.Equal(stored, []byte(prototypeRegulatedMarkerValue)) {
		return false, ErrInvalidPrototypeClassificationMarker
	}

	return true, nil
}

// MarkPrototypeRegulatedToken creates one protected system-account marker for a controlled S1-S5
// harness. This helper is not registered as a built-in and provides no delete operation.
func MarkPrototypeRegulatedToken(accounts vmcommon.AccountsAdapter, tokenID []byte) error {
	key, err := PrototypeRegulatedTokenKey(tokenID)
	if err != nil {
		return err
	}

	systemAccount, dataHandler, err := loadPrototypeClassificationSystemAccount(accounts)
	if err != nil {
		return err
	}
	existing, _, err := dataHandler.RetrieveValue(key)
	if err != nil {
		return fmt.Errorf("retrieve prototype classification marker: %w", err)
	}
	if len(existing) != 0 {
		return ErrPrototypeClassificationAlreadyExists
	}
	err = dataHandler.SaveKeyValue(key, []byte(prototypeRegulatedMarkerValue))
	if err != nil {
		return fmt.Errorf("save prototype classification marker: %w", err)
	}
	err = accounts.SaveAccount(systemAccount)
	if err != nil {
		return fmt.Errorf("save prototype classification system account: %w", err)
	}

	return nil
}

func loadPrototypeClassificationSystemAccount(accounts vmcommon.AccountsAdapter) (vmcommon.UserAccountHandler, vmcommon.AccountDataHandler, error) {
	if check.IfNil(accounts) {
		return nil, nil, ErrNilPrototypeClassificationAccounts
	}
	account, err := accounts.LoadAccount(vmcommon.SystemAccountAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("load prototype classification system account: %w", err)
	}
	userAccount, ok := account.(vmcommon.UserAccountHandler)
	if !ok || check.IfNil(userAccount) || !bytes.Equal(userAccount.AddressBytes(), vmcommon.SystemAccountAddress) {
		return nil, nil, ErrInvalidPrototypeClassificationAccount
	}
	dataHandler := userAccount.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return nil, nil, ErrInvalidPrototypeClassificationAccount
	}

	return userAccount, dataHandler, nil
}
