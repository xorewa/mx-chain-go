package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
)

// AdminEffectFunctionName is the protected built-in call by which the
// metachain delivers one leg of a protected admin effect to its execution
// shard (Part A 4.5.2, "Cross-shard provenance for protected admin effects").
// Its single argument is the canonical DRWAAdminEffectEnvelope. EXPERIMENTAL
// name and wire form: the approved documents allocate neither (Part B L1217).
const AdminEffectFunctionName = "DRWAAdminEffect"

// ErrInvalidAdminEffect refuses a leg that is not the canonical envelope of a
// protected metachain admin operation for this shard, in its exact binding.
var ErrInvalidAdminEffect = errors.New("invalid DRWA admin effect")

// adminEffectLocus names the native state one inner baseline effect changes.
type adminEffectLocus uint8

const (
	// adminLocusAccountRoles: the target account's role item of the token and
	// its latest-nonce item (ESDTSetRole writes both for the multi-shard
	// create role).
	adminLocusAccountRoles adminEffectLocus = iota + 1
	// adminLocusSystemToken: the token's global item in the system account.
	adminLocusSystemToken
	// adminLocusSystemTransferRole: the token's transfer-role address item in
	// the system account.
	adminLocusSystemTransferRole
)

// adminEffectLoci is the closed set of inner baseline effects a leg may
// carry: the built-in calls the upstream ESDT system contract sends to a
// shard for a role, a setting or the token type. Pause, freeze and wipe are
// absent (Part A L3185: "No wrapper can be used to enable freeze/wipe/pause as
// a DRWA control path"), and so is setting burn-for-all, which a regulated
// token never has. Which of these a programme may use, and when, is its
// binding's rule (AdminEffectBindingSource).
var adminEffectLoci = map[string]adminEffectLocus{
	core.BuiltInFunctionSetESDTRole:                       adminLocusAccountRoles,
	core.BuiltInFunctionUnSetESDTRole:                     adminLocusAccountRoles,
	core.BuiltInFunctionESDTSetLimitedTransfer:            adminLocusSystemToken,
	core.BuiltInFunctionESDTUnSetLimitedTransfer:          adminLocusSystemToken,
	vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll:       adminLocusSystemToken,
	core.ESDTSetTokenType:                                 adminLocusSystemToken,
	vmcommon.BuiltInFunctionESDTTransferRoleAddAddress:    adminLocusSystemTransferRole,
	vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress: adminLocusSystemTransferRole,
}

// The native keys of the three loci (vm-common builtInFunctions: roleKeyPrefix,
// noncePrefix, baseESDTKeyPrefix, transferAddressesKeyPrefix).
const (
	adminRolesKeyPrefix        = core.ProtectedKeyPrefix + core.ESDTRoleIdentifier + core.ESDTKeyIdentifier
	adminNonceKeyPrefix        = core.ProtectedKeyPrefix + core.ESDTNFTLatestNonceIdentifier
	adminTokenKeyPrefix        = core.ProtectedKeyPrefix + core.ESDTKeyIdentifier
	adminTransferRoleKeyPrefix = core.ProtectedKeyPrefix + "transfer" + core.ESDTKeyIdentifier
)

// AdminEffect is the decoded envelope of one leg, as the binding source
// receives it. Every slice is a copy.
type AdminEffect struct {
	EffectID, LegID, Origin, OpenCommitment []byte
	Operation, Binding                      string
	TokenID, TokenType                      []byte
	Epoch                                   uint64
	ActionID, PlanDigest                    []byte
	// PlanStep is nil when the leg belongs to no ordered plan.
	PlanStep            *uint64
	Function            string
	Arguments           [][]byte
	TargetShard         uint32
	Target              []byte
	Predecessor, Result []byte
}

// AdminEffectBindingSource is the destination's knowledge of its own locally
// installed binding (Part A L3238-3239, predicates 5 and 6): it answers
// whether the binding the envelope names, of the kind it names, is exactly
// the current, prepared or terminal binding this shard holds for the token,
// and whether that binding allows this inner effect on this target at this
// plan step. It is read-only. There is no default: until the row that owns
// the local binding installs one, every leg is refused and stays pending at
// its origin.
type AdminEffectBindingSource interface {
	VerifyAdminEffect(effect AdminEffect) error
	IsInterfaceNil() bool
}

// ArgsAdminEffectFunction holds the native dependencies of the destination.
// Domain returns the network domain of the deployment; ShardOf is the shard
// coordinator's address rule. No value has a default.
type ArgsAdminEffectFunction struct {
	Accounts    state.AccountsAdapter
	Marshaller  marshal.Marshalizer
	Hasher      hashing.Hasher
	Classifier  TokenClassifier
	BuiltIns    vmcommon.BuiltInFunctionContainer
	Shard       uint32
	ShardOf     func(address []byte) uint32
	Domain      func() []byte
	RecordBytes int
}

// AdminEffectFunction is the destination of protected admin legs on one
// execution shard. It belongs in that shard's processing built-in container
// only. The native inner built-ins stay refused for a regulated token on
// every public path (BuiltInAdmission); they run for one only from here.
type AdminEffectFunction struct {
	args    ArgsAdminEffectFunction
	codec   *registrationRecords
	mut     sync.RWMutex
	binding AdminEffectBindingSource
}

// NewAdminEffectFunction creates the destination. It reads no state.
func NewAdminEffectFunction(args ArgsAdminEffectFunction) (*AdminEffectFunction, error) {
	if check.IfNil(args.Classifier) || check.IfNil(args.BuiltIns) || args.ShardOf == nil || args.Domain == nil ||
		args.Shard == core.MetachainShardId || args.Shard > maxCarrierLegs {
		return nil, ErrInvalidAdminEffect
	}
	codec, err := newRegistrationRecords(args.Accounts, args.Marshaller, args.Hasher, args.RecordBytes)
	if err != nil {
		return nil, err
	}
	return &AdminEffectFunction{args: args, codec: codec}, nil
}

// SetBindingSource installs the owner of this shard's local bindings, once,
// at node construction.
func (f *AdminEffectFunction) SetBindingSource(source AdminEffectBindingSource) error {
	if check.IfNil(source) {
		return ErrInvalidAdminEffect
	}
	f.mut.Lock()
	defer f.mut.Unlock()
	if f.binding != nil {
		return ErrInvalidAdminEffect
	}
	f.binding = source
	return nil
}

// SetNewGasConfig does nothing: the work of a leg is the retained destination
// entry its envelope carries, not an entry of the active schedule.
func (f *AdminEffectFunction) SetNewGasConfig(*vmcommon.GasCost) {}

// IsActive always returns true
func (f *AdminEffectFunction) IsActive() bool { return true }

// IsInterfaceNil returns true if there is no value under the interface
func (f *AdminEffectFunction) IsInterfaceNil() bool { return f == nil }

// verifiedAdminEffectContext is the protocol-only VerifiedDRWAAdminEffectContext
// of Part A L3242-3246. Only ProcessBuiltinFunction creates one, and only for
// the native call the processor is executing: an asynchronous call whose
// sender is the metachain ESDT system contract and whose destination is this
// shard's system account address. No byte of a transaction, of a contract's
// result or of the envelope can set it; the inner built-in runs only as a
// method of this value.
type verifiedAdminEffectContext struct {
	function *AdminEffectFunction
	carrier  *adminCarrier
	input    *vmcommon.ContractCallInput
}

// ProcessBuiltinFunction applies one leg. It authenticates the call as a
// protected metachain result, then the envelope against this shard's own
// state, and then either applies the exact inner baseline effect once or,
// for a leg this shard already applied, changes nothing. Its outcome is what
// the native processor returns to the metachain: the effect and leg
// identifiers, with the gas the retained destination work did not use. Any
// refusal is an error outcome; the native processor reverts everything the
// call wrote, and the origin's OpenEffect stays open.
func (f *AdminEffectFunction) ProcessBuiltinFunction(_, _ vmcommon.UserAccountHandler,
	input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	if input == nil || input.CallValue == nil || input.CallValue.Sign() != 0 ||
		input.CallType != vmData.AsynchronousCall || len(input.Arguments) != 1 ||
		!bytes.Equal(input.CallerAddr, core.ESDTSCAddress) ||
		!bytes.Equal(input.RecipientAddr, registryDeltaSystemAddress(f.args.Shard)) {
		return nil, ErrInvalidAdminEffect
	}
	domain := f.args.Domain()
	if len(domain) == 0 || len(domain) > f.codec.maxBytes {
		return nil, ErrInvalidAdminEffect
	}
	context := &verifiedAdminEffectContext{function: f, input: input}
	context.carrier = &adminCarrier{codec: f.codec, host: context, domain: domain}
	// The result hash is the proof the sequence binds; without one it refuses.
	apply, err := context.carrier.prepareApply(input.Arguments[0], input.CurrentTxHash)
	if err != nil {
		return nil, errors.Join(ErrInvalidAdminEffect, err)
	}
	output, err := apply()
	if err != nil {
		return nil, errors.Join(ErrInvalidAdminEffect, err)
	}
	return output, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (c *verifiedAdminEffectContext) IsInterfaceNil() bool { return c == nil }

// VerifyCanonical is predicates 1 to 3: the envelope is the argument of the
// protected result in execution, and that result is addressed to this shard.
func (c *verifiedAdminEffectContext) VerifyCanonical(envelope, proof []byte) error {
	if !bytes.Equal(proof, c.input.CurrentTxHash) || !bytes.Equal(envelope, c.input.Arguments[0]) {
		return errAdminCarrier
	}
	e, err := c.carrier.decode(envelope)
	if err != nil {
		return err
	}
	if e.targetShard != c.function.args.Shard {
		return errAdminCarrier
	}
	return nil
}

func (c *verifiedAdminEffectContext) call(e adminEffectEnvelope) (adminEffectLocus, [][]byte, error) {
	function, arguments, err := parsers.NewCallArgsParser().ParseData(string(e.payload))
	if err != nil {
		return 0, nil, errAdminCarrier
	}
	locus, admitted := adminEffectLoci[function]
	if !admitted || len(arguments) == 0 || !bytes.Equal(arguments[0], e.tokenID) {
		return 0, nil, errAdminCarrier
	}
	return locus, arguments, nil
}

// ValidateLocal is predicates 5 to 7 and the destination's own dependencies:
// the token is regulated in this shard's registry, the inner effect is one of
// the closed set and names the envelope's token, the target is the locus of
// that effect on this shard, the carrier brought the retained destination
// work, and the local binding is exactly the one the envelope names.
func (c *verifiedAdminEffectContext) ValidateLocal(e adminEffectEnvelope) error {
	f := c.function
	if string(e.operation) == "DRWAMetadataMutation" {
		return errAdminCarrier
	}
	regulated, err := f.args.Classifier.ClassifyToken(e.tokenID)
	if err != nil {
		return err
	}
	if !regulated {
		return errAdminCarrier
	}
	locus, arguments, err := c.call(e)
	if err != nil {
		return err
	}
	if locus == adminLocusAccountRoles {
		if len(e.targetKey) != len(core.SystemAccountAddress) || vmcommon.IsSystemAccountAddress(e.targetKey) ||
			core.IsSmartContractAddress(e.targetKey) || f.args.ShardOf(bytes.Clone(e.targetKey)) != f.args.Shard {
			return errAdminCarrier
		}
	} else if !bytes.Equal(e.targetKey, core.SystemAccountAddress) {
		return errAdminCarrier
	}
	if _, err = CarrierDestinationGas(c.input.GasProvided, e.workLimit, e.workLimit); err != nil {
		return err
	}
	f.mut.RLock()
	source := f.binding
	f.mut.RUnlock()
	if source == nil {
		return errAdminCarrier
	}
	effect := AdminEffect{EffectID: e.effectID, LegID: e.legID, Origin: e.origin, OpenCommitment: e.openCommitment,
		Operation: string(e.operation), Binding: string(e.binding), TokenID: e.tokenID, TokenType: e.tokenType,
		Epoch: e.cebEpoch, ActionID: e.actionID, PlanDigest: e.planDigest, Function: string(e.discriminator),
		Arguments: arguments, TargetShard: e.targetShard, Target: e.targetKey, Predecessor: e.predecessor, Result: e.result}
	if len(e.planStep) == 8 {
		step := uint64(0)
		for _, b := range e.planStep {
			step = step<<8 | uint64(b)
		}
		effect.PlanStep = &step
	}
	return source.VerifyAdminEffect(effect)
}

func (c *verifiedAdminEffectContext) target(e adminEffectEnvelope) (vmcommon.UserAccountHandler, error) {
	loaded, err := c.function.args.Accounts.LoadAccount(bytes.Clone(e.targetKey))
	if err != nil {
		return nil, err
	}
	account, ok := loaded.(vmcommon.UserAccountHandler)
	if !ok || check.IfNil(account) {
		return nil, errAdminCarrier
	}
	return account, nil
}

// StateHash is the hash of the exact native items the inner effect of this
// envelope reads and writes, under the target they belong to. EXPERIMENTAL
// form: the approved documents fix no state-hash grammar.
func (c *verifiedAdminEffectContext) StateHash(e adminEffectEnvelope) ([]byte, error) {
	locus, _, err := c.call(e)
	if err != nil {
		return nil, err
	}
	account, err := c.target(e)
	if err != nil {
		return nil, err
	}
	var keys [][]byte
	switch locus {
	case adminLocusAccountRoles:
		keys = [][]byte{append([]byte(adminRolesKeyPrefix), e.tokenID...), append([]byte(adminNonceKeyPrefix), e.tokenID...)}
	case adminLocusSystemToken:
		keys = [][]byte{append([]byte(adminTokenKeyPrefix), e.tokenID...)}
	default:
		keys = [][]byte{append([]byte(adminTransferRoleKeyPrefix), e.tokenID...)}
	}
	fields := [][]byte{e.targetKey}
	for _, key := range keys {
		value, readErr := shardRegistryValue(account, key)
		if readErr != nil {
			return nil, readErr
		}
		if len(value) > c.function.codec.maxBytes {
			return nil, errAdminCarrier
		}
		fields = append(fields, key, value)
	}
	return c.carrier.digest("STATE", fields...)
}

// ApplyNative runs the one native built-in the envelope carries, with the
// native sender of such a call, the metachain ESDT system contract, which is
// the authenticated sender of the leg itself. An inner effect that would send
// anything onward is not the exact baseline effect and is refused.
func (c *verifiedAdminEffectContext) ApplyNative(e adminEffectEnvelope) (*vmcommon.VMOutput, error) {
	locus, arguments, err := c.call(e)
	if err != nil {
		return nil, err
	}
	builtIn, err := c.function.args.BuiltIns.Get(string(e.discriminator))
	if err != nil {
		return nil, err
	}
	inner := &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0),
			Arguments: arguments, GasProvided: e.workLimit, CurrentTxHash: bytes.Clone(c.input.CurrentTxHash),
			OriginalTxHash: bytes.Clone(c.input.OriginalTxHash), PrevTxHash: bytes.Clone(c.input.PrevTxHash)},
		Function: string(e.discriminator), RecipientAddr: bytes.Clone(c.input.RecipientAddr),
	}
	var output *vmcommon.VMOutput
	if locus == adminLocusAccountRoles {
		inner.RecipientAddr = bytes.Clone(e.targetKey)
		account, loadErr := c.target(e)
		if loadErr != nil {
			return nil, loadErr
		}
		if output, err = builtIn.ProcessBuiltinFunction(nil, account, inner); err != nil {
			return nil, err
		}
		if err = c.function.args.Accounts.SaveAccount(account); err != nil {
			return nil, err
		}
	} else if output, err = builtIn.ProcessBuiltinFunction(nil, nil, inner); err != nil {
		return nil, err
	}
	if output == nil || len(output.OutputAccounts) != 0 || len(output.DeletedAccounts) != 0 || len(output.TouchedAccounts) != 0 {
		return nil, errAdminCarrier
	}
	return output, nil
}

// Ack completes the native outcome of the leg. The acknowledgement itself is
// the applied-leg item the sequence wrote in this shard's system account in
// the same journal step (adminCarrier.appliedKey); the metachain reads it as
// canonically final. The outcome returns the identifiers and, of the gas the
// carrier brought, everything but the retained destination work.
func (c *verifiedAdminEffectContext) Ack(e adminEffectEnvelope, _ []byte, output *vmcommon.VMOutput) (*vmcommon.VMOutput, error) {
	remaining, err := CarrierDestinationGas(c.input.GasProvided, e.workLimit, e.workLimit)
	if err != nil {
		return nil, err
	}
	if output == nil {
		output = &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	}
	output.GasRemaining = remaining
	output.ReturnData = [][]byte{bytes.Clone(e.effectID), bytes.Clone(e.legID)}
	return output, nil
}
