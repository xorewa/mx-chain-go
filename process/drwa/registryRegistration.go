package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

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
	shards   uint32
	effects  RegistrationEffects
	funding  *CarrierFunding
}

// RegistryDeltaCarrierClass is the pricing class of the registry delta: one
// leg for each execution shard, whose outcome is that shard's acknowledgment.
const RegistryDeltaCarrierClass = "RegistryDelta"

// SetCarrierFunding installs the funding owner of the registry delta. It is a
// construction step. With it, a registration is admitted only when the gas it
// has left after native creation covers, under the active schedule, its own
// source work and, for every execution shard, the delta, the acknowledgment
// and the metachain's processing of that acknowledgment; the price is
// retained with the member, and the registration returns only what is left.
// A registration that cannot pay is refused inside its own journal operation,
// before the member or the count is written, and nothing of it remains.
func (r *RegistryRegistration) SetCarrierFunding(funding *CarrierFunding) error {
	if funding == nil || r.funding != nil || funding.codec.state.accounts != r.state.accounts {
		return ErrInvalidRegistryRegistration
	}
	r.funding = funding
	return nil
}

// registryDeltaEffect is the identity of one member's delta: the token
// identifier and its ordinal, as the delta and its acknowledgment carry them.
func registryDeltaEffect(tokenID []byte, ordinal uint64) []byte {
	return binary.BigEndian.AppendUint64(bytes.Clone(tokenID), ordinal)
}

// WithheldEffect is one result the token creator produced for a registration.
type WithheldEffect struct {
	Destination []byte
	Transfer    vmcommon.OutputTransfer
}

// RegistrationEffects is what the registration needs from the metachain half
// of the acknowledged registration (SP2-34/SP2-38; owner decision of
// 27 November 2026, option 1: acknowledgment from every shard before any
// other effect of a registration). Once it is installed, a registration
// releases nothing but the registry delta; every result the creator produced
// is handed over here instead, in the order it would have been created.
type RegistrationEffects interface {
	// AcknowledgmentGas is the gas each delta carries. The delta uses none
	// of it; the native processor of the shard gives it to the callback, the
	// acknowledgment, which it would otherwise drop, so it cannot be zero.
	// The metachain half takes the amount from the gas schedule and takes
	// it, once for each execution shard, out of the gas the registration
	// returns as remaining: the native processor refuses a transaction whose
	// results carry more gas than it was given (gasConsumedChecks).
	AcknowledgmentGas() uint64
	// Withhold is called inside the registration's native journal step, after
	// the member and the count are saved and before the output is returned.
	// The implementation keeps the effects, with any value they carry, in
	// accounts, under that journal, and may release them, in this order, only
	// when every execution shard has acknowledged member ordinal
	// (ParseRegistryAcknowledgment, read by the callBack entry of the
	// metachain ESDT system contract). The same condition gates every later
	// result the metachain produces for the token. An error rolls back the
	// whole registration.
	Withhold(accounts state.AccountsAdapter, tokenID []byte, ordinal uint64, effects []WithheldEffect) error
	IsInterfaceNil() bool
}

// SetRegistrationEffects installs the owner of the withheld effects. It is a
// construction step. Until one is installed the registration releases the
// creator's results behind the delta and no shard acknowledges; the
// registration ingress must not open in that state.
func (r *RegistryRegistration) SetRegistrationEffects(effects RegistrationEffects) error {
	if check.IfNil(effects) || r.effects != nil {
		return ErrInvalidRegistryRegistration
	}
	r.effects = effects
	return nil
}

// withhold removes every transfer from the creator's output and hands them to
// the effects owner, ordered as their results would have been created
// (transfer index). A creator cannot supply a delta of its own.
func (r *RegistryRegistration) withhold(output *vmcommon.VMOutput, tokenID []byte, ordinal uint64) error {
	var effects []WithheldEffect
	for _, account := range output.OutputAccounts {
		if account == nil {
			return ErrInvalidRegistryRegistration
		}
		for _, transfer := range account.OutputTransfers {
			if bytes.HasPrefix(transfer.Data, []byte(RegistryDeltaFunctionName+"@")) {
				return ErrInvalidRegistryRegistration
			}
			effects = append(effects, WithheldEffect{Destination: bytes.Clone(account.Address), Transfer: transfer})
		}
	}
	if len(effects) == 0 {
		return nil
	}
	sort.SliceStable(effects, func(i, j int) bool { return effects[i].Transfer.Index < effects[j].Transfer.Index })
	for i := 1; i < len(effects); i++ {
		if effects[i].Transfer.Index == effects[i-1].Transfer.Index {
			return ErrInvalidRegistryRegistration
		}
	}
	for _, account := range output.OutputAccounts {
		account.OutputTransfers = nil
	}
	return r.effects.Withhold(r.state.accounts, bytes.Clone(tokenID), ordinal, effects)
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
	return &RegistryRegistration{state: s, boundary: boundary, maxEver: maxEver, shards: coordinator.NumberOfShards()}, boundary, nil
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
	return r.registerToken(create, nil)
}

// registrationGuard surrounds the WHOLE token/intent/registry/count operation
// inside T04. In particular, a late time invalidation cannot escape rollback
// after intent consumption or registry publication. No independent journal.
type registrationGuard func([]state.AccountsAdapter, func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error)

func (r *RegistryRegistration) registerToken(create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error), guard registrationGuard) error {
	operation, err := r.prepareRegistration(create, guard)
	if err != nil {
		return err
	}
	return r.boundary.Execute(operation)
}

// prepareRegistration shares the existing closed native creator/member/count
// mutation with the original operation owner. It starts no journal or commit.
func (r *RegistryRegistration) prepareRegistration(create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error), guard registrationGuard) (func() (*vmcommon.VMOutput, error), error) {
	if create == nil {
		return nil, ErrInvalidOperation
	}
	operation := func() (*vmcommon.VMOutput, error) {
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
		// Funding precedes the member and the count: an underfunded
		// registration is refused here and its creation rolls back with it.
		funded := uint64(0)
		if r.funding != nil && r.shards != 0 {
			reservation, fundErr := r.funding.Accept(RegistryDeltaCarrierClass, registryDeltaEffect(tokenID, count), r.shards, output.GasRemaining)
			if fundErr != nil {
				return nil, fundErr
			}
			if reservation.LegGas == 0 {
				return nil, ErrInvalidRegistryRegistration
			}
			funded, output.GasRemaining = reservation.LegGas, reservation.Remaining
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
		entry := registryEntryKey(count)
		occupied, _, err := account.RetrieveValue(entry)
		if err != nil {
			return nil, err
		}
		if len(occupied) != 0 {
			return nil, ErrInvalidRegistryRegistration
		}
		if err = account.SaveKeyValue(entry, bytes.Clone(tokenID)); err != nil {
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
		// The member reaches every execution shard as the first result of this
		// registration. With the metachain half installed it is the only one:
		// the creator's own results wait for every shard's acknowledgment.
		gas := funded
		if r.effects != nil && r.shards != 0 {
			// Without a funding owner the metachain half names the gas itself.
			if gas == 0 {
				gas = r.effects.AcknowledgmentGas()
			}
			if gas == 0 {
				return nil, ErrInvalidRegistryRegistration
			}
			if err = r.withhold(output, tokenID, count); err != nil {
				return nil, err
			}
		}
		if err = emitRegistryDelta(output, tokenID, count, r.shards, gas); err != nil {
			return nil, err
		}
		return output, nil
	}
	return func() (*vmcommon.VMOutput, error) {
		if guard != nil {
			return guard(r.boundary.stores, operation)
		}
		return operation()
	}, nil
}

// registryEntryPrefix is the ordinal index of the global registry: entry n holds
// the n-th registered identifier. It is written only here, in the same native
// journal step as the member marker and the count, so that the owning node can
// enumerate exactly count members at startup without walking unrelated leaves
// of the system account (Part A 5.1 rule 5). Experimental layout, as the count.
const registryEntryPrefix = core.ProtectedKeyPrefix + "DRWA@registry@entry@"

func registryEntryKey(ordinal uint64) []byte {
	key := make([]byte, len(registryEntryPrefix)+8)
	copy(key, registryEntryPrefix)
	binary.BigEndian.PutUint64(key[len(registryEntryPrefix):], ordinal)
	return key
}

// IsInterfaceNil follows the native interface nil convention for construction.
func (r *RegistryRegistration) IsInterfaceNil() bool { return r == nil }
