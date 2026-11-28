package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
)

// EXPERIMENTAL storage of the typed OpenEffect of an admin effect and of its
// retained legs (Part A 4.7.1; Part B L1219: physical schema open).
const (
	openEffectPrefix    = core.ProtectedKeyPrefix + "DRWA@openEffect@"
	openEffectLegPrefix = core.ProtectedKeyPrefix + "DRWA@openEffectLeg@"
	openEffectTag       = "DRWA/OPEN_EFFECT/candidate1"
)

// AdminEffectCarrierClass is the pricing class of a protected admin effect:
// one leg for each required acknowledgement target.
const AdminEffectCarrierClass = "AdminEffect"

// adminEffectKind and adminEffectPending are the OpenEffect kind and source
// state of Part A 4.7.1 for a token-admin effect.
const (
	adminEffectKind    = "TOKEN_ADMIN"
	adminEffectPending = "PENDING_APPLY"
)

// ErrAdminEffectNotOpen refuses an acknowledgement or a redrive of an effect
// that has no OpenEffect: one never opened, or one already closed. Nothing is
// written (Part A L3279-3280: "a late/unknown ack cannot close or mutate an
// absent/different effect").
var ErrAdminEffectNotOpen = errors.New("no open DRWA admin effect")

// AdminEffectLeg is one required acknowledgement target of an effect: the
// execution shard, the account or system key the inner effect changes there,
// and that target's state before and after.
type AdminEffectLeg struct {
	Shard               uint32
	Target              []byte
	Predecessor, Result []byte
}

// AdminEffectRequest is what the protected metachain operation asks to be
// carried: one inner baseline effect, under one binding, to its ordered
// targets. Origin is the origin execution identity of that operation.
type AdminEffectRequest struct {
	Operation            string
	Origin               []byte
	TokenID, TokenType   []byte
	Binding              string
	Epoch                uint64
	ActionID, PlanDigest []byte
	// PlanStep is nil when the effect belongs to no ordered plan.
	PlanStep *uint64
	Payload  []byte
	Legs     []AdminEffectLeg
}

// OpenAdminEffect is the retained OpenEffect of one admin effect.
type OpenAdminEffect struct {
	EffectID, TokenID, TokenType, Origin []byte
	Epoch                                uint64
	ContextHash, Commitment              []byte
	Legs                                 uint32
	// Acknowledged has bit n set when leg n's canonical acknowledgement was
	// applied. It is the only field that changes.
	Acknowledged []byte
}

// HasAcknowledged tells whether leg's bit is set.
func (o *OpenAdminEffect) HasAcknowledged(leg uint32) bool {
	return o != nil && leg < o.Legs && o.Acknowledged[leg/8]&(1<<(leg%8)) != 0
}

// AdminEffectProgress is what one acknowledgement did.
type AdminEffectProgress struct {
	// Applied is false for the acknowledgement of a leg whose bit is set:
	// nothing was written and nothing was charged.
	Applied bool
	// Closed is true when this acknowledgement completed the set and the
	// OpenEffect was removed in the same step.
	Closed bool
	// Remaining is what is left of the gas the operation provided.
	Remaining uint64
}

// AdminEffectEvidenceReader reads, from presented evidence, the value the
// system account of an execution shard holds under key in an execution
// result that is canonically final for the metachain block in execution
// (SP2-22's result reading). The production reader is the convergence host.
type AdminEffectEvidenceReader interface {
	ReadFinalItem(shard uint32, key, evidence []byte) (origin, value []byte, err error)
	IsInterfaceNil() bool
}

// ArgsAdminEffects holds the native dependencies of the origin owner. Limits
// is the chain-global retained budget of SP2-29. Shards is the configured
// number of execution shards: a leg names one of them, so with none every
// effect is refused. No value has a default.
type ArgsAdminEffects struct {
	Accounts    state.AccountsAdapter
	Marshaller  marshal.Marshalizer
	Hasher      hashing.Hasher
	Domain      func() []byte
	Funding     *CarrierFunding
	Block       ConvergenceBlockSource
	Evidence    AdminEffectEvidenceReader
	Limits      RegistrationResourceLimits
	RecordBytes int
	Shards      uint32
}

// AdminEffects is the metachain origin of protected admin effects (Part A
// 4.5.2, 4.7.1; section 13 item 6):
//
//   - Open creates the typed OpenEffect and retains every leg's canonical
//     envelope, funded under the active schedule, before it adds any leg to
//     the native output of the operation in execution.
//   - Acknowledge sets one leg's bit from evidence that the destination's
//     applied-leg item is canonically final, and removes the OpenEffect in the
//     step that sets the last bit.
//   - Redrive adds the same retained envelope of a leg without a bit to the
//     output again. It authorises nothing new and changes no OpenEffect.
//
// Every method runs inside its caller's native journal operation and neither
// commits nor reverts. The caller is the protected metachain operation; no
// method authenticates who asks.
type AdminEffects struct {
	args  ArgsAdminEffects
	codec *registrationRecords
}

// NewAdminEffects creates the owner. It reads no state.
func NewAdminEffects(args ArgsAdminEffects) (*AdminEffects, error) {
	if args.Domain == nil || args.Funding == nil || check.IfNil(args.Block) || check.IfNil(args.Evidence) ||
		args.Limits.Records == 0 || args.Limits.RetainedBytes == 0 || args.Limits.NewRecordsPerEpoch == 0 ||
		args.Shards > maxCarrierLegs {
		return nil, ErrInvalidAdminEffect
	}
	codec, err := newRegistrationRecords(args.Accounts, args.Marshaller, args.Hasher, args.RecordBytes)
	if err != nil {
		return nil, err
	}
	if args.Funding.codec.state.accounts != args.Accounts {
		return nil, ErrInvalidAdminEffect
	}
	return &AdminEffects{args: args, codec: codec}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (a *AdminEffects) IsInterfaceNil() bool { return a == nil }

func (a *AdminEffects) carrier() (*adminCarrier, error) {
	domain := a.args.Domain()
	if len(domain) == 0 || len(domain) > a.codec.maxBytes {
		return nil, ErrInvalidAdminEffect
	}
	return &adminCarrier{codec: a.codec, domain: domain}, nil
}

func (a *AdminEffects) budget() *scopedAdmissionRecords {
	return &scopedAdmissionRecords{codec: a.codec, limits: scopedAdmissionLimits{recordBytes: a.codec.maxBytes,
		records: a.args.Limits.Records, retainedBytes: a.args.Limits.RetainedBytes,
		newRecordsPerEpoch: a.args.Limits.NewRecordsPerEpoch}}
}

func (a *AdminEffects) hash(tag string, domain []byte, fields ...[]byte) ([]byte, error) {
	preimage, err := a.codec.frame(append([][]byte{[]byte(tag), domain}, fields...)...)
	if err != nil {
		return nil, ErrInvalidAdminEffect
	}
	return a.codec.hasher.Compute(string(preimage)), nil
}

func (a *AdminEffects) legKey(effectID []byte, leg uint32) []byte {
	return append([]byte(openEffectLegPrefix), a.codec.hasher.Compute(string(binary.BigEndian.AppendUint32(bytes.Clone(effectID), leg)))...)
}

// encode writes the record of an effect: its immutable identity, the
// commitment over that identity, and the acknowledgement bitmap.
func (a *AdminEffects) encode(o *OpenAdminEffect, policy []byte) ([]byte, error) {
	return a.codec.frame([]byte(openEffectTag), o.EffectID, []byte(adminEffectKind), o.TokenID, o.TokenType, o.Origin,
		bytes.Clone(core.ESDTSCAddress), binary.BigEndian.AppendUint64(nil, o.Epoch), o.ContextHash, policy,
		o.Commitment, binary.BigEndian.AppendUint32(nil, o.Legs), o.Acknowledged, []byte(adminEffectPending))
}

// load returns the record of effectID exactly as encode writes it, with its
// terminal policy; nil when the effect has no OpenEffect.
func (a *AdminEffects) load(effectID []byte) (state.UserAccountHandler, *OpenAdminEffect, []byte, error) {
	if len(effectID) != a.codec.hasher.Size() {
		return nil, nil, nil, ErrInvalidAdminEffect
	}
	account, err := a.codec.state.systemAccount()
	if err != nil {
		return nil, nil, nil, err
	}
	raw, _, err := account.RetrieveValue(append([]byte(openEffectPrefix), effectID...))
	if err != nil || len(raw) == 0 {
		return account, nil, nil, err
	}
	f, err := a.codec.unframe(raw, 14)
	if err != nil || len(f[7]) != 8 || len(f[11]) != 4 {
		return nil, nil, nil, ErrInvalidAdminEffect
	}
	o := &OpenAdminEffect{EffectID: f[1], TokenID: f[3], TokenType: f[4], Origin: f[5], Epoch: binary.BigEndian.Uint64(f[7]),
		ContextHash: f[8], Commitment: f[10], Legs: binary.BigEndian.Uint32(f[11]), Acknowledged: f[12]}
	if !bytes.Equal(o.EffectID, effectID) || o.Legs == 0 || o.Legs > maxCarrierLegs ||
		len(o.Acknowledged) != common.GetBitmapSize(int(o.Legs)) {
		return nil, nil, nil, ErrInvalidAdminEffect
	}
	set := uint32(0)
	for bit := uint32(0); bit < uint32(len(o.Acknowledged))*8; bit++ {
		if o.Acknowledged[bit/8]&(1<<(bit%8)) == 0 {
			continue
		}
		if bit >= o.Legs {
			return nil, nil, nil, ErrInvalidAdminEffect
		}
		set++
	}
	// A complete set never remains: the effect is removed with its last bit.
	canonical, err := a.encode(o, f[9])
	if err != nil || set == o.Legs || !bytes.Equal(canonical, raw) {
		return nil, nil, nil, ErrInvalidAdminEffect
	}
	return account, o, f[9], nil
}

// Read returns the OpenEffect of effectID, or nil when there is none.
func (a *AdminEffects) Read(effectID []byte) (*OpenAdminEffect, error) {
	_, o, _, err := a.load(effectID)
	return o, err
}

// Leg returns the retained canonical envelope of one leg of an open effect.
func (a *AdminEffects) Leg(effectID []byte, leg uint32) ([]byte, error) {
	account, o, _, err := a.load(effectID)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, ErrAdminEffectNotOpen
	}
	return a.leg(account, o, leg)
}

func (a *AdminEffects) leg(account state.UserAccountHandler, o *OpenAdminEffect, leg uint32) ([]byte, error) {
	if leg >= o.Legs {
		return nil, ErrInvalidAdminEffect
	}
	envelope, _, err := account.RetrieveValue(a.legKey(o.EffectID, leg))
	if err != nil {
		return nil, err
	}
	if len(envelope) == 0 {
		return nil, ErrInvalidAdminEffect
	}
	return bytes.Clone(envelope), nil
}

// adminLegIndex returns the transfer index that follows every transfer already
// in the output, when the output can take count more.
func adminLegIndex(output *vmcommon.VMOutput, count uint32) (uint32, error) {
	if output == nil {
		return 0, ErrInvalidAdminEffect
	}
	index := uint32(0)
	for _, account := range output.OutputAccounts {
		if account == nil {
			return 0, ErrInvalidAdminEffect
		}
		for _, transfer := range account.OutputTransfers {
			if transfer.Index == ^uint32(0) {
				return 0, ErrInvalidAdminEffect
			}
			if transfer.Index >= index {
				index = transfer.Index + 1
			}
		}
	}
	if index > ^uint32(0)-count {
		return 0, ErrInvalidAdminEffect
	}
	return index, nil
}

// emitAdminLeg adds one leg to the output as a native asynchronous call of the
// metachain ESDT system contract to the shard's system account address, the
// carrier of the registry delta (emitRegistryDelta).
func emitAdminLeg(output *vmcommon.VMOutput, index, shard uint32, envelope, effectID, legID []byte, gas uint64) {
	address := registryDeltaSystemAddress(shard)
	if output.OutputAccounts == nil {
		output.OutputAccounts = make(map[string]*vmcommon.OutputAccount, 1)
	}
	account, exists := output.OutputAccounts[string(address)]
	if !exists {
		account = &vmcommon.OutputAccount{Address: address, BalanceDelta: big.NewInt(0)}
		output.OutputAccounts[string(address)] = account
	}
	account.OutputTransfers = append(account.OutputTransfers, vmcommon.OutputTransfer{
		Index: index, Value: big.NewInt(0), GasLimit: gas,
		Data:      []byte(AdminEffectFunctionName + "@" + hexEncode(envelope)),
		AsyncData: []byte("@" + hexEncode(legID) + "@" + hexEncode(effectID)),
		CallType:  vmData.AsynchronousCall, SenderAddress: bytes.Clone(core.ESDTSCAddress),
	})
}

// Open admits one admin effect, paid from available gas units of the
// operation in execution, and returns its effect identifier and what is left
// of that gas. The order is fixed: the effect is priced and funded, its
// OpenEffect and every leg's envelope are retained, and only then are the
// legs added to output. An effect is opened once: the same origin, inner
// effect, binding and action again is refused, also after it closed.
//
// The targets are the terminal policy: they must be in canonical order,
// strictly ascending by shard and then by target, with no repeat.
func (a *AdminEffects) Open(output *vmcommon.VMOutput, request AdminEffectRequest, available uint64) ([]byte, uint64, error) {
	carrier, err := a.carrier()
	if err != nil {
		return nil, 0, err
	}
	if len(request.Legs) == 0 || len(request.Legs) > maxCarrierLegs || len(request.Origin) != a.codec.hasher.Size() {
		return nil, 0, ErrInvalidAdminEffect
	}
	index, err := adminLegIndex(output, uint32(len(request.Legs)))
	if err != nil {
		return nil, 0, err
	}
	function, _, err := parsers.NewCallArgsParser().ParseData(string(request.Payload))
	if err != nil {
		return nil, 0, ErrInvalidAdminEffect
	}
	if _, admitted := adminEffectLoci[function]; !admitted {
		return nil, 0, ErrInvalidAdminEffect
	}
	normalized, err := carrier.normalized(request.Payload, []byte(function))
	if err != nil {
		return nil, 0, ErrInvalidAdminEffect
	}
	epoch := binary.BigEndian.AppendUint64(nil, request.Epoch)
	effectID, err := a.hash("DRWA/EFFECT/ADMINOP/v1", carrier.domain, request.Origin, normalized, epoch, request.ActionID)
	if err != nil {
		return nil, 0, err
	}
	targets := make([][]byte, len(request.Legs))
	for i, leg := range request.Legs {
		if leg.Shard >= a.args.Shards || i > 0 && (leg.Shard < request.Legs[i-1].Shard ||
			leg.Shard == request.Legs[i-1].Shard && bytes.Compare(leg.Target, request.Legs[i-1].Target) <= 0) {
			return nil, 0, ErrInvalidAdminEffect
		}
		if targets[i], err = a.codec.frame(binary.BigEndian.AppendUint32(nil, leg.Shard), leg.Target, leg.Result); err != nil {
			return nil, 0, ErrInvalidAdminEffect
		}
	}
	policy, err := a.codec.frame(append([][]byte{[]byte("ACK_SET")}, targets...)...)
	if err != nil {
		return nil, 0, ErrInvalidAdminEffect
	}
	var step []byte
	if request.PlanStep != nil {
		step = binary.BigEndian.AppendUint64(nil, *request.PlanStep)
	}
	contextHash, err := a.hash("DRWA/ADMIN_CONTEXT/v1", carrier.domain, effectID, []byte(request.Operation), epoch,
		request.ActionID, request.PlanDigest, a.codec.hasher.Compute(string(policy)), normalized)
	if err != nil {
		return nil, 0, err
	}
	commitment, err := a.hash("DRWA/OPEN_EFFECT_IDENTITY/v1", carrier.domain, effectID, []byte(adminEffectKind),
		request.TokenID, request.Origin, epoch, contextHash, policy)
	if err != nil {
		return nil, 0, err
	}
	// Everything is built and checked before the first write: the price the
	// envelopes carry is the one the funding owner is about to retain. A price
	// without destination work makes no envelope (encode refuses it).
	price, err := a.args.Funding.args.Prices.CarrierPrice(AdminEffectCarrierClass)
	if err != nil {
		return nil, 0, err
	}
	identity := a.args.Funding.priceIdentity(AdminEffectCarrierClass, price)
	legs := uint32(len(request.Legs))
	o := &OpenAdminEffect{EffectID: effectID, TokenID: request.TokenID, TokenType: request.TokenType, Origin: request.Origin,
		Epoch: request.Epoch, ContextHash: contextHash, Commitment: commitment, Legs: legs,
		Acknowledged: make([]byte, common.GetBitmapSize(len(request.Legs)))}
	record, err := a.encode(o, policy)
	if err != nil {
		return nil, 0, ErrInvalidAdminEffect
	}
	writes := []scopedAdmissionWrite{{append([]byte(openEffectPrefix), effectID...), record}}
	envelopes, legIDs := make([][]byte, legs), make([][]byte, legs)
	for i, leg := range request.Legs {
		if legIDs[i], err = carrier.digest("LEG", effectID, binary.BigEndian.AppendUint32(nil, uint32(i))); err != nil {
			return nil, 0, ErrInvalidAdminEffect
		}
		envelopes[i], err = carrier.encode(adminEffectEnvelope{effectID: effectID, legID: legIDs[i],
			operation: []byte(request.Operation), origin: request.Origin, openCommitment: commitment,
			tokenID: request.TokenID, tokenType: request.TokenType, binding: []byte(request.Binding), cebEpoch: request.Epoch,
			actionID: request.ActionID, planDigest: request.PlanDigest, planStep: step,
			normalizedDigest: normalized, discriminator: []byte(function), payload: request.Payload,
			targetShard: leg.Shard, targetKey: leg.Target, predecessor: leg.Predecessor, result: leg.Result,
			gasVersion: identity, workLimit: price.Destination})
		if err != nil {
			return nil, 0, errors.Join(ErrInvalidAdminEffect, err)
		}
		writes = append(writes, scopedAdmissionWrite{a.legKey(effectID, uint32(i)), envelopes[i]})
	}
	_, existing, _, err := a.load(effectID)
	if err != nil {
		return nil, 0, err
	}
	if existing != nil {
		return nil, 0, ErrInvalidAdminEffect
	}
	_, _, blockEpoch, err := a.args.Block.ExecutingBlock()
	if err != nil {
		return nil, 0, err
	}
	reservation, err := a.args.Funding.Accept(AdminEffectCarrierClass, effectID, legs, available)
	if err != nil {
		return nil, 0, err
	}
	if reservation.Price != price || !bytes.Equal(reservation.Identity, identity) {
		return nil, 0, ErrInvalidAdminEffect
	}
	// Reload: the funding owner saved the same account.
	account, err := a.codec.state.systemAccount()
	if err != nil {
		return nil, 0, err
	}
	if err = a.budget().retain(account, blockEpoch, writes...); err != nil {
		return nil, 0, err
	}
	// The OpenEffect exists: emission follows it.
	for i, leg := range request.Legs {
		emitAdminLeg(output, index+uint32(i), leg.Shard, envelopes[i], effectID, legIDs[i], reservation.LegGas)
	}
	return bytes.Clone(effectID), reservation.Remaining, nil
}

// Acknowledge is the metachain entry point for the acknowledgement evidence of
// one leg (owner decision of 28 November 2026, OWNER_DECISIONS.md entry 10,
// point 9.2, option A). The acknowledgement is the applied-leg item the
// destination shard wrote with the baseline mutation: evidence must prove
// that the shard's system account holds, under that leg's item key, the exact
// retained envelope, in an execution result canonically final for the block
// in execution. Then the leg's bit, and only that bit, is set, and the
// retained completion work is taken from provided, the gas of the operation
// that presents the evidence. The acknowledgement that completes the set
// removes the OpenEffect and its legs in the same step.
//
// An exact repeat for a leg whose bit is set is authenticated and then
// changes and charges nothing. Evidence of anything else, an effect without
// an OpenEffect, or too little gas is refused and nothing is written.
func (a *AdminEffects) Acknowledge(effectID []byte, leg uint32, evidence []byte, provided uint64) (AdminEffectProgress, error) {
	carrier, err := a.carrier()
	if err != nil {
		return AdminEffectProgress{}, err
	}
	account, o, policy, err := a.load(effectID)
	if err != nil {
		return AdminEffectProgress{}, err
	}
	if o == nil {
		return AdminEffectProgress{}, ErrAdminEffectNotOpen
	}
	envelope, err := a.leg(account, o, leg)
	if err != nil {
		return AdminEffectProgress{}, err
	}
	e, err := carrier.decode(envelope)
	if err != nil || !bytes.Equal(e.effectID, o.EffectID) || !bytes.Equal(e.openCommitment, o.Commitment) {
		return AdminEffectProgress{}, ErrInvalidAdminEffect
	}
	key, err := carrier.appliedKey(e.effectID, e.legID)
	if err != nil {
		return AdminEffectProgress{}, ErrInvalidAdminEffect
	}
	_, applied, err := a.args.Evidence.ReadFinalItem(e.targetShard, key, evidence)
	if err != nil {
		return AdminEffectProgress{}, err
	}
	if !bytes.Equal(applied, envelope) {
		return AdminEffectProgress{}, ErrInvalidAdminEffect
	}
	if o.HasAcknowledged(leg) {
		return AdminEffectProgress{Remaining: provided}, nil
	}
	outcome, err := a.args.Funding.Outcome(AdminEffectCarrierClass, effectID, leg, provided)
	if err != nil {
		return AdminEffectProgress{}, err
	}
	if !outcome.Applied {
		return AdminEffectProgress{}, ErrInvalidAdminEffect
	}
	o.Acknowledged[leg/8] |= 1 << (leg % 8)
	closed := true
	for other := uint32(0); other < o.Legs; other++ {
		closed = closed && o.HasAcknowledged(other)
	}
	if closed != outcome.Terminal {
		return AdminEffectProgress{}, ErrInvalidAdminEffect
	}
	// Reload: the funding owner saved the same account.
	if account, err = a.codec.state.systemAccount(); err != nil {
		return AdminEffectProgress{}, err
	}
	effectKey := append([]byte(openEffectPrefix), effectID...)
	if closed {
		if err = account.SaveKeyValue(effectKey, nil); err != nil {
			return AdminEffectProgress{}, err
		}
		for other := uint32(0); other < o.Legs; other++ {
			if err = account.SaveKeyValue(a.legKey(effectID, other), nil); err != nil {
				return AdminEffectProgress{}, err
			}
		}
	} else {
		record, encodeErr := a.encode(o, policy)
		if encodeErr != nil {
			return AdminEffectProgress{}, ErrInvalidAdminEffect
		}
		if err = account.SaveKeyValue(effectKey, record); err != nil {
			return AdminEffectProgress{}, err
		}
	}
	if err = a.codec.state.accounts.SaveAccount(account); err != nil {
		return AdminEffectProgress{}, err
	}
	return AdminEffectProgress{Applied: true, Closed: closed, Remaining: outcome.Remaining}, nil
}

// Redrive adds to output the same retained envelope of one leg that has no
// acknowledgement, funded at the retained entries from available gas units of
// the operation in execution, and returns what is left of them. The envelope
// is byte for byte the one Open emitted: the destination applies nothing
// twice, and the redrive is no second authorisation. The OpenEffect is not
// changed. Which native operation may redrive, and who pays for it, is its
// caller's contract (Part A AR-13).
func (a *AdminEffects) Redrive(output *vmcommon.VMOutput, effectID []byte, leg uint32, available uint64) (uint64, error) {
	carrier, err := a.carrier()
	if err != nil {
		return 0, err
	}
	account, o, _, err := a.load(effectID)
	if err != nil {
		return 0, err
	}
	if o == nil {
		return 0, ErrAdminEffectNotOpen
	}
	if leg >= o.Legs || o.HasAcknowledged(leg) {
		return 0, ErrInvalidAdminEffect
	}
	index, err := adminLegIndex(output, 1)
	if err != nil {
		return 0, err
	}
	envelope, err := a.leg(account, o, leg)
	if err != nil {
		return 0, err
	}
	e, err := carrier.decode(envelope)
	if err != nil || !bytes.Equal(e.effectID, o.EffectID) || !bytes.Equal(e.openCommitment, o.Commitment) {
		return 0, ErrInvalidAdminEffect
	}
	// The retained leg carries the retained price: checked before the funding
	// owner counts the redrive.
	funded, err := a.args.Funding.Read(AdminEffectCarrierClass, effectID)
	if err != nil {
		return 0, err
	}
	if funded == nil || !bytes.Equal(funded.Identity, e.gasVersion) || funded.Price.Destination != e.workLimit {
		return 0, ErrInvalidAdminEffect
	}
	reservation, err := a.args.Funding.Redrive(AdminEffectCarrierClass, effectID, leg, available)
	if err != nil {
		return 0, err
	}
	emitAdminLeg(output, index, e.targetShard, envelope, e.effectID, e.legID, reservation.LegGas)
	return reservation.Remaining, nil
}
