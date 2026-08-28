package drwa

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/state"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// This protected marker is only an S1-S5 test classifier. Its key and value are not production
// registry representations and must be removed or disabled when the permanent classifier lands.

const (
	drwaRegulatedKeySuffix   = "drwa/prototype-regulated/"
	drwaRegulatedMarkerValue = "DRWA-PROTOTYPE-REGULATED\x01"
)

var (
	// ErrInvalidDRWARegulatedTokenID signals a malformed or over-limit DRWA token ID.
	ErrInvalidDRWARegulatedTokenID = errors.New("invalid non-normative DRWA prototype regulated token ID")
	// ErrNilDRWAClassificationAccounts signals that the DRWA classifier has no accounts adapter.
	ErrNilDRWAClassificationAccounts = errors.New("nil non-normative DRWA prototype classification accounts adapter")
	// ErrInvalidDRWAClassificationAccount signals that the system address did not resolve to a usable user account.
	ErrInvalidDRWAClassificationAccount = errors.New("invalid non-normative DRWA prototype classification system account")
	// ErrInvalidDRWAClassificationMarker signals non-empty state other than the exact DRWA marker.
	ErrInvalidDRWAClassificationMarker = errors.New("invalid non-normative DRWA prototype classification marker")
	// ErrDRWAClassificationAlreadyExists signals that the marker key already has non-empty state.
	ErrDRWAClassificationAlreadyExists = errors.New("non-normative DRWA prototype classification marker already exists")
)

// DRWARegulatedTokenKey returns a fresh protected key for one bounded DRWA token ID.
func DRWARegulatedTokenKey(tokenID []byte) ([]byte, error) {
	if len(tokenID) == 0 || len(tokenID) > drwaTokenIDLimit || !vmcommon.ValidateToken(tokenID) {
		return nil, ErrInvalidDRWARegulatedTokenID
	}

	key := make([]byte, 0, len(core.ProtectedKeyPrefix)+len(drwaRegulatedKeySuffix)+len(tokenID))
	key = append(key, core.ProtectedKeyPrefix...)
	key = append(key, drwaRegulatedKeySuffix...)
	key = append(key, tokenID...)

	return key, nil
}

// IsDRWARegulatedToken classifies one token from protected system-account state.
// Absence is ordinary; every observation or decoding failure is returned as an error.
func IsDRWARegulatedToken(accounts vmcommon.AccountsAdapter, tokenID []byte) (bool, error) {
	key, err := DRWARegulatedTokenKey(tokenID)
	if err != nil {
		return false, err
	}

	_, dataHandler, err := loadDRWAClassificationSystemAccount(accounts)
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
	if !bytes.Equal(stored, []byte(drwaRegulatedMarkerValue)) {
		return false, ErrInvalidDRWAClassificationMarker
	}

	return true, nil
}

// MarkDRWARegulatedToken creates one protected system-account marker for a controlled S1-S5
// harness. This helper is not registered as a built-in and provides no delete operation.
func MarkDRWARegulatedToken(accounts vmcommon.AccountsAdapter, tokenID []byte) error {
	key, err := DRWARegulatedTokenKey(tokenID)
	if err != nil {
		return err
	}

	if check.IfNil(accounts) {
		return ErrNilDRWAClassificationAccounts
	}

	account, err := accounts.GetExistingAccount(vmcommon.SystemAccountAddress)
	isNewAccount := errors.Is(err, state.ErrAccNotFound)
	if err != nil && !isNewAccount {
		return fmt.Errorf("get existing prototype classification system account: %w", err)
	}
	if isNewAccount {
		account, err = accounts.LoadAccount(vmcommon.SystemAccountAddress)
		if err != nil {
			return fmt.Errorf("load prototype classification system account: %w", err)
		}
	}

	systemAccount, dataHandler, err := validateDRWAClassificationSystemAccount(account)
	if err != nil {
		return err
	}
	if !isNewAccount {
		existing, _, retrieveErr := dataHandler.RetrieveValue(key)
		if retrieveErr != nil {
			return fmt.Errorf("retrieve prototype classification marker: %w", retrieveErr)
		}
		if len(existing) != 0 {
			return ErrDRWAClassificationAlreadyExists
		}
	}
	err = dataHandler.SaveKeyValue(key, []byte(drwaRegulatedMarkerValue))
	if err != nil {
		return fmt.Errorf("save prototype classification marker: %w", err)
	}
	err = accounts.SaveAccount(systemAccount)
	if err != nil {
		return fmt.Errorf("save prototype classification system account: %w", err)
	}

	return nil
}

func loadDRWAClassificationSystemAccount(accounts vmcommon.AccountsAdapter) (vmcommon.UserAccountHandler, vmcommon.AccountDataHandler, error) {
	if check.IfNil(accounts) {
		return nil, nil, ErrNilDRWAClassificationAccounts
	}
	account, err := accounts.LoadAccount(vmcommon.SystemAccountAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("load prototype classification system account: %w", err)
	}

	return validateDRWAClassificationSystemAccount(account)
}

func validateDRWAClassificationSystemAccount(account vmcommon.AccountHandler) (vmcommon.UserAccountHandler, vmcommon.AccountDataHandler, error) {
	userAccount, ok := account.(vmcommon.UserAccountHandler)
	if !ok || check.IfNil(userAccount) || !bytes.Equal(userAccount.AddressBytes(), vmcommon.SystemAccountAddress) {
		return nil, nil, ErrInvalidDRWAClassificationAccount
	}
	dataHandler := userAccount.AccountDataHandler()
	if check.IfNil(dataHandler) {
		return nil, nil, ErrInvalidDRWAClassificationAccount
	}

	return userAccount, dataHandler, nil
}
