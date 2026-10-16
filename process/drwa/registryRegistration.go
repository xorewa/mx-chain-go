package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var ErrInvalidRegistryRegistration = errors.New("invalid DRWA registry registration")

// RegistryRegistration owns the atomic metachain token/membership/count core
// (Part A L2211-2216). It is not an admitted DRWARegisterToken endpoint. Its
// native creator must include every token, intent, manager/profile and lifecycle
// mutation in the supplied store; authenticated admission and enforcement-epoch
// checks precede entry. T14 and the endpoint owner supply those constructions.
// No caller may use this component to register an existing ordinary identifier.
//
// Only this component writes the experimental global registry member domain.
// It reuses the existing eight-byte count and one-byte marker; allocation remains
// due under Part B L346. Exclusive native-store ownership and root retention
// follow RollbackContainment. There is no ordinary-path importer or raw-key API.
type RegistryRegistration struct {
	state    *protectedState
	boundary *RollbackContainment
	maxEver  uint64
}

// NewRegistryRegistration starts one metachain candidate at a committed native
// root. The returned native containment owner is the only commit/output-release
// boundary; callers must not commit stores or publish creator outputs directly.
// accounts is the user/registry store and remains first in native receipts.
// participating contains the other native stores touched by the operation (for
// example the metachain peer store), under the same exclusive ownership and
// authoritative-root retention obligations. It adds no independent journal.
// maxEver is the caller's actual configured bound; no numeric default is chosen.
func NewRegistryRegistration(accounts state.AccountsAdapter, coordinator sharding.Coordinator,
	maxEver uint64, participating ...state.AccountsAdapter) (*RegistryRegistration, *RollbackContainment, error) {
	if check.IfNil(coordinator) || coordinator.SelfId() != core.MetachainShardId {
		return nil, nil, ErrInvalidRegistryRegistration
	}
	s, err := newProtectedState(accounts)
	if err != nil {
		return nil, nil, err
	}
	boundary, err := NewRollbackContainment(append([]state.AccountsAdapter{accounts}, participating...)...)
	if err != nil {
		return nil, nil, err
	}
	return &RegistryRegistration{state: s, boundary: boundary, maxEver: maxEver}, boundary, nil
}

func registrationCount(account state.UserAccountHandler) (uint64, error) {
	value, _, err := account.RetrieveValue([]byte(registryCountKey))
	if err != nil {
		return 0, err
	}
	if len(value) != 8 {
		return 0, ErrInvalidRegistryRegistration
	}
	return binary.BigEndian.Uint64(value), nil
}

// RegisterToken executes a DRWA-owned native creation operation inside the SAME
// native journal as count and membership. Capacity is checked before creation.
// The creator must generate a fresh identifier, save its native token record and
// all associated registration state through accounts, and return only its pending
// native output. It must never commit or forward an output. A creator error rolls
// back the entire operation; rollback failure poisons the candidate under P-05.
// The owning production creator is the separate DRWA-only System-SC construction.
func (r *RegistryRegistration) RegisterToken(create func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	if create == nil {
		return ErrInvalidOperation
	}
	return r.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		account, err := r.state.systemAccount()
		if err != nil {
			return nil, err
		}
		count, err := registrationCount(account)
		if err != nil {
			return nil, err
		}
		if count >= r.maxEver {
			return nil, ErrInvalidRegistryRegistration
		}
		tokenID, output, err := create(r.state.accounts)
		if err != nil {
			return nil, err
		}
		if !vmcommon.ValidateToken(tokenID) || output == nil || output.ReturnCode != vmcommon.Ok {
			return nil, ErrInvalidRegistryRegistration
		}
		// Reload after native creation/associated registration saves: a stale
		// account object must not overwrite the creator's system-account changes.
		account, err = r.state.systemAccount()
		if err != nil {
			return nil, err
		}
		current, err := registrationCount(account)
		if err != nil {
			return nil, err
		}
		if current != count {
			return nil, ErrInvalidRegistryRegistration
		}
		key := append([]byte(registryMemberKeyPrefix), bytes.Clone(tokenID)...)
		value, _, err := account.RetrieveValue(key)
		if err != nil {
			return nil, err
		}
		if len(value) != 0 {
			return nil, ErrInvalidRegistryRegistration
		}
		if err = account.SaveKeyValue(key, []byte{1}); err != nil {
			return nil, err
		}
		encoded := make([]byte, 8)
		binary.BigEndian.PutUint64(encoded, count+1)
		if err = account.SaveKeyValue([]byte(registryCountKey), encoded); err != nil {
			return nil, err
		}
		if err = r.state.accounts.SaveAccount(account); err != nil {
			return nil, err
		}
		return output, nil
	})
}

// IsInterfaceNil follows the native interface nil convention for construction.
func (r *RegistryRegistration) IsInterfaceNil() bool { return r == nil }
