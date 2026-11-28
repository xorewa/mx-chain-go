package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// EXPERIMENTAL storage of the E10 readiness record of one registered token
// (Part A E.20.3; Part B freezes the production form).
const (
	burnReadinessPrefix = core.ProtectedKeyPrefix + "DRWA@burnReadiness@"
	burnReadinessTag    = "DRWA/BURN_READINESS/candidate1"
)

// ErrBurnForAllNotReady refuses a transition of a regulated token while the
// metachain holds a burn-for-all role for it, or while not every configured
// execution shard has acknowledged, as canonically final, the exact false
// global-burn state (Part A E.20.3: "Keep activation denied. A successful
// unset call, dispatch receipt, observer report or timeout does not fill the
// missing readiness requirement.").
var ErrBurnForAllNotReady = errors.New("DRWA burn-for-all absence is not acknowledged by every shard")

// ErrInvalidBurnForAllReadiness refuses a malformed, repeated or unpriced
// readiness request, and every read of a record that is not exactly what
// this owner writes.
var ErrInvalidBurnForAllReadiness = errors.New("invalid DRWA burn-for-all readiness")

// burnReadinessTypeByte is the type byte the native global item of a token
// holds for each supported family (vm-common builtInFunctions,
// ESDTTypeForGlobalSettingsHandler, which is not exported). The table is
// pinned to the native built-in by test.
var burnReadinessTypeByte = map[string]byte{
	core.FungibleESDT: 1, core.NonFungibleESDTv2: 3, core.MetaESDT: 4, core.SemiFungibleESDT: 5,
	core.DynamicNFTESDT: 6, core.DynamicSFTESDT: 7, core.DynamicMetaESDT: 8,
}

// MetaBurnRoleReader answers from the metachain's own token record whether a
// token holds the burn-for-all special role. The production reader is the
// ESDT system contract's record reader. A read failure is an error, never
// absence.
type MetaBurnRoleReader interface {
	HasBurnForAllRole(tokenID []byte) (bool, error)
	IsInterfaceNil() bool
}

// BurnForAllReadinessRequest names one registered token whose false
// global-burn state is to be established on every execution shard. Origin is
// the origin execution identity of the registration; Binding and Epoch are
// the binding the shards hold for the token at that point.
type BurnForAllReadinessRequest struct {
	TokenID, Family, Origin []byte
	Binding                 string
	Epoch                   uint64
}

// ArgsBurnForAllReadiness holds the native dependencies of the readiness
// owner. Limits is the chain-global retained budget of SP2-29. No value has a
// default.
type ArgsBurnForAllReadiness struct {
	Accounts    state.AccountsAdapter
	Marshaller  marshal.Marshalizer
	Hasher      hashing.Hasher
	Domain      func() []byte
	Effects     *AdminEffects
	Funding     *CarrierFunding
	Roles       MetaBurnRoleReader
	Block       ConvergenceBlockSource
	Flags       common.EnableEpochsHandler
	Limits      RegistrationResourceLimits
	RecordBytes int
	Shards      uint32
}

// BurnForAllReadiness is the metachain owner of E10's shard half (Part A E.20,
// L6388-6393, IA-10). The protected creation path removes the metachain role
// inside the registration; the native set, unset and type fan-out it produced
// is refused on every shard for a regulated token (BuiltInAdmission). This
// owner establishes the shard state through the protected admin legs:
//
//   - Open opens, for every configured execution shard, the effect that sets
//     the token type (only where the native creation sends one: with
//     DynamicESDTFlag) and the effect that unsets burn-for-all, whose expected
//     result is the positively present global item with the false flag and the
//     family's type. It retains which effects those are.
//   - Verify is nil only when the metachain record has no burn-for-all role
//     and each of those effects closed on its complete acknowledgement set.
//     Each acknowledgement is canonical-final evidence of the shard's own
//     applied-leg item for that exact expected state (AdminEffects).
//
// Every method runs inside its caller's native journal operation.
type BurnForAllReadiness struct {
	args  ArgsBurnForAllReadiness
	codec *registrationRecords
}

// NewBurnForAllReadiness creates the owner. It reads no state.
func NewBurnForAllReadiness(args ArgsBurnForAllReadiness) (*BurnForAllReadiness, error) {
	if args.Domain == nil || args.Effects == nil || args.Funding == nil || check.IfNil(args.Roles) || check.IfNil(args.Block) ||
		check.IfNil(args.Flags) || args.Limits.Records == 0 || args.Limits.RetainedBytes == 0 ||
		args.Limits.NewRecordsPerEpoch == 0 || args.Shards > maxCarrierLegs {
		return nil, ErrInvalidBurnForAllReadiness
	}
	codec, err := newRegistrationRecords(args.Accounts, args.Marshaller, args.Hasher, args.RecordBytes)
	if err != nil {
		return nil, err
	}
	if args.Effects.codec.state.accounts != args.Accounts || args.Funding.codec.state.accounts != args.Accounts {
		return nil, ErrInvalidBurnForAllReadiness
	}
	return &BurnForAllReadiness{args: args, codec: codec}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (r *BurnForAllReadiness) IsInterfaceNil() bool { return r == nil }

func (r *BurnForAllReadiness) key(tokenID []byte) []byte {
	return append([]byte(burnReadinessPrefix), tokenID...)
}

// record is the retained readiness record: the token, its family, the shard
// count it was opened for and the effects that carry its state.
type burnReadinessRecord struct {
	family []byte
	shards uint32
	// typeEffect is empty when the creation sent no type.
	typeEffect, unsetEffect []byte
}

func (r *BurnForAllReadiness) load(tokenID []byte) (*burnReadinessRecord, error) {
	if !vmcommon.ValidateToken(tokenID) {
		return nil, ErrInvalidBurnForAllReadiness
	}
	account, err := r.codec.state.systemAccount()
	if err != nil {
		return nil, err
	}
	raw, _, err := account.RetrieveValue(r.key(tokenID))
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	f, err := r.codec.unframe(raw, 6)
	size := r.codec.hasher.Size()
	if err != nil || len(f[3]) != 4 || len(f[5]) != size || len(f[4]) != 0 && len(f[4]) != size {
		return nil, ErrInvalidBurnForAllReadiness
	}
	record := &burnReadinessRecord{family: f[2], shards: binary.BigEndian.Uint32(f[3]), typeEffect: f[4], unsetEffect: f[5]}
	canonical, err := r.encode(tokenID, record)
	if _, supported := burnReadinessTypeByte[string(record.family)]; err != nil || !supported || !bytes.Equal(canonical, raw) {
		return nil, ErrInvalidBurnForAllReadiness
	}
	return record, nil
}

func (r *BurnForAllReadiness) encode(tokenID []byte, record *burnReadinessRecord) ([]byte, error) {
	return r.codec.frame([]byte(burnReadinessTag), tokenID, record.family, binary.BigEndian.AppendUint32(nil, record.shards),
		record.typeEffect, record.unsetEffect)
}

// Effects returns the identifiers of the effects that carry the token's shard
// state, in the order they were opened: the type effect, when there is one,
// and the unset effect. They are what the acknowledgement and redrive
// operations name. A token without a readiness record has none.
func (r *BurnForAllReadiness) Effects(tokenID []byte) ([][]byte, error) {
	record, err := r.load(tokenID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrBurnForAllNotReady
	}
	var ids [][]byte
	if len(record.typeEffect) != 0 {
		ids = append(ids, bytes.Clone(record.typeEffect))
	}
	return append(ids, bytes.Clone(record.unsetEffect)), nil
}

// Open establishes, for one registered token, the expected shard state and
// the legs that carry it to every configured execution shard, paid from
// available gas units of the registration in execution; it returns what is
// left of them. A token is opened once.
//
// The expected state of each shard is the native global item of the token,
// positively present: flags zero, and the type byte the native creation
// would have sent (the family's type with DynamicESDTFlag, none without). A
// shard whose item is anything else before the leg, an earlier enable effect
// included, refuses the leg and is not acknowledged.
func (r *BurnForAllReadiness) Open(output *vmcommon.VMOutput, request BurnForAllReadinessRequest, available uint64) (uint64, error) {
	typeByte, supported := burnReadinessTypeByte[string(request.Family)]
	if !supported || !vmcommon.ValidateToken(request.TokenID) || r.args.Shards == 0 {
		return 0, ErrInvalidBurnForAllReadiness
	}
	existing, err := r.load(request.TokenID)
	if err != nil {
		return 0, err
	}
	if existing != nil {
		return 0, ErrInvalidBurnForAllReadiness
	}
	carrier, err := r.args.Effects.carrier()
	if err != nil {
		return 0, err
	}
	itemKey := append([]byte(adminTokenKeyPrefix), request.TokenID...)
	stateOf := func(item []byte) ([]byte, error) {
		return carrier.digest("STATE", core.SystemAccountAddress, itemKey, item)
	}
	absent, err := stateOf(nil)
	if err != nil {
		return 0, ErrInvalidBurnForAllReadiness
	}
	typed := r.args.Flags.IsFlagEnabled(common.DynamicESDTFlag)
	if !typed {
		typeByte = 0
	}
	final, err := stateOf([]byte{0, typeByte})
	if err != nil {
		return 0, ErrInvalidBurnForAllReadiness
	}
	effect := func(payload string, predecessor []byte) AdminEffectRequest {
		legs := make([]AdminEffectLeg, r.args.Shards)
		for shard := range legs {
			legs[shard] = AdminEffectLeg{Shard: uint32(shard), Target: bytes.Clone(core.SystemAccountAddress),
				Predecessor: predecessor, Result: final}
		}
		return AdminEffectRequest{Operation: "DRWAApplyTokenAdmin", Origin: request.Origin, TokenID: request.TokenID,
			TokenType: request.Family, Binding: request.Binding, Epoch: request.Epoch, Payload: []byte(payload), Legs: legs}
	}
	token := hexEncode(request.TokenID)
	var requests []AdminEffectRequest
	unsetFrom := absent
	if typed {
		requests = append(requests, effect(core.ESDTSetTokenType+"@"+token+"@"+hexEncode(request.Family), absent))
		unsetFrom = final
	}
	requests = append(requests, effect(vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll+"@"+token, unsetFrom))

	// The whole price is checked before the first write: a registration that
	// cannot pay for every leg of every effect opens none.
	price, err := r.args.Funding.args.Prices.CarrierPrice(AdminEffectCarrierClass)
	if err != nil {
		return 0, err
	}
	total := uint64(0)
	for range requests {
		_, one, _, reserveErr := carrierReserve(^uint64(0), price.Source, r.args.Shards, price)
		if reserveErr != nil {
			return 0, reserveErr
		}
		if total, err = core.SafeAddUint64(total, one); err != nil {
			return 0, ErrInvalidBurnForAllReadiness
		}
	}
	if available < total {
		return 0, ErrCarrierUnderfunded
	}
	record := &burnReadinessRecord{family: request.Family, shards: r.args.Shards}
	remaining := available
	for i := range requests {
		id, left, openErr := r.args.Effects.Open(output, requests[i], remaining)
		if openErr != nil {
			return 0, openErr
		}
		remaining = left
		if typed && i == 0 {
			record.typeEffect = id
		} else {
			record.unsetEffect = id
		}
	}
	encoded, err := r.encode(request.TokenID, record)
	if err != nil {
		return 0, ErrInvalidBurnForAllReadiness
	}
	_, _, epoch, err := r.args.Block.ExecutingBlock()
	if err != nil {
		return 0, err
	}
	account, err := r.codec.state.systemAccount()
	if err != nil {
		return 0, err
	}
	budget := &scopedAdmissionRecords{codec: r.codec, limits: scopedAdmissionLimits{recordBytes: r.codec.maxBytes,
		records: r.args.Limits.Records, retainedBytes: r.args.Limits.RetainedBytes,
		newRecordsPerEpoch: r.args.Limits.NewRecordsPerEpoch}}
	if err = budget.retain(account, epoch, scopedAdmissionWrite{r.key(request.TokenID), encoded}); err != nil {
		return 0, err
	}
	return remaining, nil
}

// Verify is the readiness predicate of E10 for one token. It is nil only
// when all of these hold in the state of the block in execution:
//
//   - the metachain token record holds no burn-for-all role;
//   - the token has a readiness record, opened for the configured number of
//     execution shards;
//   - every effect it names is closed (its OpenEffect is gone) and its
//     funding record is terminal: one outcome for each of its legs, which are
//     the shards the record was opened for.
//
// It writes nothing. A read failure is an error, never readiness.
func (r *BurnForAllReadiness) Verify(tokenID []byte) error {
	record, err := r.load(tokenID)
	if err != nil {
		return err
	}
	if record == nil || record.shards != r.args.Shards || r.args.Shards == 0 {
		return ErrBurnForAllNotReady
	}
	granted, err := r.args.Roles.HasBurnForAllRole(bytes.Clone(tokenID))
	if err != nil {
		return err
	}
	if granted {
		return ErrBurnForAllNotReady
	}
	for _, id := range [][]byte{record.typeEffect, record.unsetEffect} {
		if len(id) == 0 {
			continue
		}
		open, readErr := r.args.Effects.Read(id)
		if readErr != nil {
			return readErr
		}
		funded, readErr := r.args.Funding.Read(AdminEffectCarrierClass, id)
		if readErr != nil {
			return readErr
		}
		if open != nil || funded == nil || funded.Phase != CarrierTerminal {
			return ErrBurnForAllNotReady
		}
	}
	return nil
}

// BurnBoundConvergenceHost is the convergence host of a metachain node with
// E10 bound into it: no phase of a regulated token completes unless Verify
// holds for that token. Activation is the completion of the bootstrap
// readiness phase, so it stays refused until the complete acknowledgement set
// of the false global-burn state exists; the phases of requalification,
// recovery and retirement complete under the same predicate (Part A L11044).
// Everything else is the host's own behaviour.
type BurnBoundConvergenceHost struct {
	*ConvergenceHost
	readiness *BurnForAllReadiness
}

// NewBurnBoundConvergenceHost binds the readiness owner into a host.
func NewBurnBoundConvergenceHost(host *ConvergenceHost, readiness *BurnForAllReadiness) (*BurnBoundConvergenceHost, error) {
	if host == nil || readiness == nil || host.args.Accounts != readiness.args.Accounts {
		return nil, ErrInvalidBurnForAllReadiness
	}
	return &BurnBoundConvergenceHost{ConvergenceHost: host, readiness: readiness}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (h *BurnBoundConvergenceHost) IsInterfaceNil() bool { return h == nil || h.ConvergenceHost == nil }

// Complete requires the E10 readiness of the phase's token before the host
// writes the parent receipt of the phase.
func (h *BurnBoundConvergenceHost) Complete(binding, commitment []byte) (*vmcommon.VMOutput, error) {
	b, err := h.ConvergenceHost.decode(binding)
	if err != nil {
		return nil, err
	}
	if err = h.readiness.Verify(b.Token); err != nil {
		return nil, err
	}
	return h.ConvergenceHost.Complete(binding, commitment)
}
