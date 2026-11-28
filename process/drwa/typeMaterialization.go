package drwa

import (
	"bytes"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// ErrInvalidTypeMaterialization refuses a type materialization that is not
// the exact protected exception: a registered regulated token of a supported
// family, on a configuration where the baseline materializes a type.
var ErrInvalidTypeMaterialization = errors.New("invalid DRWA type materialization")

// ErrTokenTypeNotMaterialized refuses an effect that depends on a regulated
// token's type on a shard whose global item does not hold exactly that type
// (Part A 4.1 step 3: "Expected token type ... must be unambiguous at every
// execution locus before its earliest dependent effect").
var ErrTokenTypeNotMaterialized = errors.New("DRWA token type is not materialized on this shard")

// TypeMaterializationRequest names one registered token whose type is to be
// materialized on every execution shard.
type TypeMaterializationRequest struct {
	TokenID, Family, Origin []byte
	Binding                 string
	Epoch                   uint64
}

// TypeMaterialization is the exact protected materialization exception of
// Part A AR-27 ("Public updateTokenID denies after registration both before
// and after activation"; "Only the exact protected materialization exception
// is admitted"). A regulated token registered while the baseline sent no type
// (DynamicESDTFlag not yet active) holds, on every shard, the false
// global item without a type. Once the baseline materializes types, Open
// carries the token's own family type to every shard by the protected admin
// leg, from exactly that typeless false item to the typed one. It converts
// nothing: the family is the one the registration fixed.
//
// A token registered with the flag active gets its type with its readiness
// (BurnForAllReadiness) and has nothing to materialize: its shards hold the
// typed item, so the legs of a second materialization find another state than
// they expect and are refused there.
type TypeMaterialization struct {
	effects *AdminEffects
	flags   common.EnableEpochsHandler
}

// NewTypeMaterialization creates the owner over the node's admin-effect owner.
func NewTypeMaterialization(effects *AdminEffects, flags common.EnableEpochsHandler) (*TypeMaterialization, error) {
	if effects == nil || check.IfNil(flags) {
		return nil, ErrInvalidTypeMaterialization
	}
	return &TypeMaterialization{effects: effects, flags: flags}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (m *TypeMaterialization) IsInterfaceNil() bool { return m == nil }

// Open opens the type effect of one token for every configured execution
// shard, paid from available gas units of the operation in execution, and
// returns its effect identifier and the gas left. It runs inside its caller's
// native journal operation; the caller is the protected metachain operation.
func (m *TypeMaterialization) Open(output *vmcommon.VMOutput, request TypeMaterializationRequest, available uint64) ([]byte, uint64, error) {
	typeByte, supported := burnReadinessTypeByte[string(request.Family)]
	shards := m.effects.args.Shards
	// A node with no execution shard has no leg to open: the effects owner refuses it.
	if !supported || !vmcommon.ValidateToken(request.TokenID) || !m.flags.IsFlagEnabled(common.DynamicESDTFlag) {
		return nil, 0, ErrInvalidTypeMaterialization
	}
	carrier, err := m.effects.carrier()
	if err != nil {
		return nil, 0, err
	}
	itemKey := append([]byte(adminTokenKeyPrefix), request.TokenID...)
	// The typeless false item every shard holds, and the typed one.
	states := [][]byte{{0, 0}, {0, typeByte}}
	for i, item := range states {
		if states[i], err = carrier.digest("STATE", core.SystemAccountAddress, itemKey, item); err != nil {
			return nil, 0, ErrInvalidTypeMaterialization
		}
	}
	typeless, typed := states[0], states[1]
	legs := make([]AdminEffectLeg, shards)
	for shard := range legs {
		legs[shard] = AdminEffectLeg{Shard: uint32(shard), Target: bytes.Clone(core.SystemAccountAddress),
			Predecessor: typeless, Result: typed}
	}
	return m.effects.Open(output, AdminEffectRequest{Operation: "DRWAApplyTokenAdmin", Origin: request.Origin,
		TokenID: request.TokenID, TokenType: request.Family, Binding: request.Binding, Epoch: request.Epoch,
		Payload: []byte(core.ESDTSetTokenType + "@" + hexEncode(request.TokenID) + "@" + hexEncode(request.Family)),
		Legs:    legs}, available)
}
