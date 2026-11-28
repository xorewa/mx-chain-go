package drwa

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/state"
)

// LifecycleSealCarrierClass is the pricing class of a replicated lifecycle
// state (entries LifecycleSealSource, ...Destination, ...Success, ...Refund,
// ...Completion of the carrier section). EXPERIMENTAL as the section is.
const LifecycleSealCarrierClass = "LifecycleSeal"

// ArgsLifecycleSealOrigin holds the native dependencies of the metachain
// owner. Shards is the configured number of execution shards.
type ArgsLifecycleSealOrigin struct {
	Accounts    state.AccountsAdapter
	Marshaller  marshal.Marshalizer
	Hasher      hashing.Hasher
	Funding     *CarrierFunding
	Shards      uint32
	RecordBytes int
}

// LifecycleSealOrigin is the metachain owner of the setup seal's replication.
// It is the owner of the SETUP_LIFECYCLE convergence family: it authenticates
// a phase binding against the metachain's own lifecycle record and current
// CEB pointer. And it emits a lifecycle state to the execution shards, funded
// before anything is emitted, only for the phase that record holds. It writes
// no lifecycle record: the transitions are setupLifecycle's.
type LifecycleSealOrigin struct {
	args  ArgsLifecycleSealOrigin
	codec *registrationRecords
}

// NewLifecycleSealOrigin creates the owner. It reads no state.
func NewLifecycleSealOrigin(args ArgsLifecycleSealOrigin) (*LifecycleSealOrigin, error) {
	if check.IfNil(args.Accounts) || check.IfNil(args.Funding) || args.Shards > maxCarrierLegs {
		return nil, ErrLifecycleSeal
	}
	codec, err := newRegistrationRecords(args.Accounts, args.Marshaller, args.Hasher, args.RecordBytes)
	if err != nil {
		return nil, err
	}
	// One store: the funding record and the lifecycle record of one journal.
	if args.Funding.codec.state.accounts != args.Accounts {
		return nil, ErrLifecycleSeal
	}
	return &LifecycleSealOrigin{args: args, codec: codec}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (o *LifecycleSealOrigin) IsInterfaceNil() bool { return o == nil }

// current returns the metachain's lifecycle record of token and the hash of
// its current CEB, which must be of the record's epoch.
func (o *LifecycleSealOrigin) current(token []byte) (epoch uint64, phase string, cebHash []byte, err error) {
	if !vmcommon.ValidateToken(token) || len(token) > o.codec.maxBytes {
		return 0, "", nil, ErrLifecycleSeal
	}
	account, err := o.codec.state.systemAccount()
	if err != nil {
		return 0, "", nil, err
	}
	epoch, phase, _, err = lifecycleSealRead(o.codec, account, token)
	if err != nil {
		return 0, "", nil, err
	}
	// Without a record the epoch is zero and the phase empty: no pointer is of
	// that epoch, and no phase of the table is empty.
	cebHash, err = lifecycleSealCEB(o.codec, account, token, epoch)
	if err != nil {
		return 0, "", nil, err
	}
	return epoch, phase, cebHash, nil
}

// setupPhaseStates names, for each phase of the setup family, the lifecycle
// state the metachain holds while that phase is collected, and the state
// before it.
var setupPhaseStates = map[string][2]string{
	"SETUP_READY_ACK":   {"SETUP", ""},
	"SETUP_SEALED":      {"SETUP_SEALED", "SETUP"},
	"DRWAQuiescenceAck": {"SETUP_SEALED", "SETUP_SEALED"},
}

// SetupPhaseCoordinates returns the coordinates of a setup-family phase
// binding that this owner derives from the metachain's own state: the
// instance (action), the CEB hash (digest), the target state hash, the
// lineage and the predecessor. EXPERIMENTAL layout: the approved documents
// fix the seven coordinates (Part A L5433-5436) and no byte value for them.
// The dependency hash is not derived here; its owner is the local dependency
// commitment (SP2-26) that the transition's authorizing host checks.
func (o *LifecycleSealOrigin) SetupPhaseCoordinates(token []byte, phase string) (action, digest, target, lineage, predecessor []byte, epoch uint64, err error) {
	states, known := setupPhaseStates[phase]
	if !known {
		return nil, nil, nil, nil, nil, 0, ErrLifecycleSeal
	}
	epoch, held, cebHash, err := o.current(token)
	if err != nil {
		return nil, nil, nil, nil, nil, 0, err
	}
	if held != states[0] {
		return nil, nil, nil, nil, nil, 0, ErrLifecycleSeal
	}
	action, digest, target, lineage, predecessor, err = setupPhaseCoordinates(o.codec, token, epoch, cebHash, states)
	return action, digest, target, lineage, predecessor, epoch, err
}

// setupPhaseCoordinates derives the coordinates of one setup-family phase
// (states: its entry of setupPhaseStates) of a token's CEB epoch from the
// token, the epoch and the CEB hash alone. The
// metachain derives them from its own state to admit a binding; a shard
// derives them from its own state to check the binding a seal arrives under.
func setupPhaseCoordinates(codec *registrationRecords, token []byte, epoch uint64, cebHash []byte, states [2]string) (action, digest, target, lineage, predecessor []byte, err error) {
	epochBytes := binary.BigEndian.AppendUint64(nil, epoch)
	instance, err := codec.frame([]byte(ConvergenceFamilySetup), token, epochBytes, cebHash)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	lineage, err = codec.frame(token, epochBytes, cebHash)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	record, err := lifecycleSealRecord(codec, token, epoch, states[0])
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	predecessor = bytes.Clone(cebHash)
	if states[1] != "" {
		before, e := lifecycleSealRecord(codec, token, epoch, states[1])
		if e != nil {
			return nil, nil, nil, nil, nil, e
		}
		predecessor = codec.hasher.Compute(string(before))
	}
	return codec.hasher.Compute(string(instance)), bytes.Clone(cebHash), codec.hasher.Compute(string(record)), lineage, predecessor, nil
}

// VerifyTransition is the ConvergenceFamilyOwner of SETUP_LIFECYCLE. A phase
// is admitted only while the metachain's own record is the state that phase
// belongs to, for the record's CEB epoch and current CEB, with every
// configured execution shard required: readiness while SETUP, the seal and
// the quiescence while SETUP_SEALED. So no seal phase exists before the
// metachain sealed, none of an earlier epoch is admitted again, and none
// survives a later state.
func (o *LifecycleSealOrigin) VerifyTransition(binding ConvergenceBinding) error {
	if string(binding.Family) != ConvergenceFamilySetup {
		return ErrLifecycleSeal
	}
	action, digest, target, lineage, predecessor, epoch, err := o.SetupPhaseCoordinates(binding.Token, string(binding.Phase))
	if err != nil {
		return err
	}
	if binding.Version != epoch || !completeShardSet(binding.Shards, o.args.Shards) ||
		!bytes.Equal(binding.Action, action) || !bytes.Equal(binding.Digest, digest) ||
		!bytes.Equal(binding.Target, target) || !bytes.Equal(binding.Lineage, lineage) ||
		!bytes.Equal(binding.Predecessor, predecessor) {
		return ErrLifecycleSeal
	}
	return nil
}

func lifecycleSealEffect(codec *registrationRecords, token []byte, epoch uint64, phase string) ([]byte, error) {
	record, err := lifecycleSealRecord(codec, token, epoch, phase)
	if err != nil {
		return nil, err
	}
	return codec.hasher.Compute(string(record)), nil
}

// emitLifecycleSeal adds one native asynchronous call of the seal function
// for shard to output, after every transfer already in it.
func emitLifecycleSeal(output *vmcommon.VMOutput, effect, token []byte, epoch uint64, phase string, binding []byte, shard uint32, gas uint64) error {
	index := uint32(0)
	for _, account := range output.OutputAccounts {
		if account == nil {
			return ErrLifecycleSeal
		}
		for _, transfer := range account.OutputTransfers {
			if transfer.Index >= index {
				if transfer.Index == ^uint32(0) {
					return ErrLifecycleSeal
				}
				index = transfer.Index + 1
			}
		}
	}
	data := LifecycleSealFunctionName + "@" + hexEncode(token) + "@" + hexEncode(binary.BigEndian.AppendUint64(nil, epoch)) +
		"@" + hexEncode([]byte(phase))
	if len(binding) != 0 {
		data += "@" + hexEncode(binding)
	}
	address := registryDeltaSystemAddress(shard)
	if output.OutputAccounts == nil {
		output.OutputAccounts = make(map[string]*vmcommon.OutputAccount, 1)
	}
	account, exists := output.OutputAccounts[string(address)]
	if !exists {
		account = &vmcommon.OutputAccount{Address: address, BalanceDelta: big.NewInt(0)}
		output.OutputAccounts[string(address)] = account
	}
	delivery := append(bytes.Clone(effect), uint8(shard))
	account.OutputTransfers = append(account.OutputTransfers, vmcommon.OutputTransfer{
		Index: index, Value: big.NewInt(0), GasLimit: gas, Data: []byte(data),
		AsyncData: []byte("@" + hexEncode(delivery) + "@" + hexEncode(effect)),
		CallType:  vmData.AsynchronousCall, SenderAddress: bytes.Clone(core.ESDTSCAddress),
	})
	return nil
}

// admit checks that phase is a state of the table, that it is exactly the
// metachain's own record of this epoch, and, for a seal, that binding is the
// phase binding this family owner admits: the terminal seal's binding is of
// another family and is refused there.
func (o *LifecycleSealOrigin) admit(output *vmcommon.VMOutput, token []byte, epoch uint64, phase string, binding []byte) ([]byte, error) {
	step, known := lifecycleSealSteps[phase]
	if output == nil || !known || (step.family == "") != (len(binding) == 0) {
		return nil, ErrLifecycleSeal
	}
	have, held, _, err := o.current(token)
	if err != nil {
		return nil, err
	}
	if have != epoch || held != phase {
		return nil, ErrLifecycleSeal
	}
	if step.family != "" {
		b, e := decodeConvergenceBinding(o.codec, binding)
		if e != nil {
			return nil, e
		}
		if string(b.Phase) != phase {
			return nil, ErrLifecycleSeal
		}
		if e = o.VerifyTransition(*b); e != nil {
			return nil, e
		}
	}
	return lifecycleSealEffect(o.codec, token, epoch, phase)
}

// Replicate adds to output, for every execution shard, the call that carries
// the metachain's lifecycle state of token: the setup seal with its phase
// binding, or OPEN. The whole fan-out is funded from available gas units of
// the operation in execution before a call is added, and what is left of
// them is returned. A state is replicated once; a shard that did not answer
// is served by Redrive.
func (o *LifecycleSealOrigin) Replicate(output *vmcommon.VMOutput, token []byte, epoch uint64, phase string, binding []byte, available uint64) (uint64, error) {
	effect, err := o.admit(output, token, epoch, phase, binding)
	if err != nil {
		return 0, err
	}
	reservation, err := o.args.Funding.Accept(LifecycleSealCarrierClass, effect, o.args.Shards, available)
	if err != nil {
		return 0, err
	}
	// A call without gas is applied and never answered (emitRegistryDelta).
	if reservation.LegGas == 0 {
		return 0, ErrLifecycleSeal
	}
	for shard := uint32(0); shard < o.args.Shards; shard++ {
		if err = emitLifecycleSeal(output, effect, token, epoch, phase, binding, shard, reservation.LegGas); err != nil {
			return 0, err
		}
	}
	return reservation.Remaining, nil
}

// Redrive adds the same call again for one execution shard whose outcome has
// not arrived, funded at the retained entries. The shard applies nothing
// twice. A shard the effect has no leg for is refused by the funding owner.
func (o *LifecycleSealOrigin) Redrive(output *vmcommon.VMOutput, token []byte, epoch uint64, phase string, binding []byte, shard uint32, available uint64) (uint64, error) {
	effect, err := o.admit(output, token, epoch, phase, binding)
	if err != nil {
		return 0, err
	}
	// The retained price is the one Replicate accepted, which gives a call gas.
	reservation, err := o.args.Funding.Redrive(LifecycleSealCarrierClass, effect, shard, available)
	if err != nil {
		return 0, err
	}
	if err = emitLifecycleSeal(output, effect, token, epoch, phase, binding, shard, reservation.LegGas); err != nil {
		return 0, err
	}
	return reservation.Remaining, nil
}

// LifecycleSealOutcome is the native callback of one shard's seal call.
type LifecycleSealOutcome struct {
	Shard   uint32
	TokenID []byte
	Epoch   uint64
	Phase   string
}

// Outcome is the metachain's funded application of the native callback of a
// seal call: the leg of that shard gets its one outcome, paid at the retained
// completion entry from the gas the callback carries. It is no
// acknowledgement and sets no bit of a phase: the seal is acknowledged only
// by the shard's item read as canonically final (ConvergenceHost.VerifyAck).
// This authenticates the form of the call only, as
// ParseRegistryAcknowledgment does.
func (o *LifecycleSealOrigin) Outcome(input *vmcommon.ContractCallInput) (*LifecycleSealOutcome, CarrierOutcomeResult, error) {
	if input == nil || input.CallType != vmData.AsynchronousCallBack ||
		input.Function != RegistryAcknowledgmentFunctionName || !bytes.Equal(input.RecipientAddr, core.ESDTSCAddress) ||
		input.CallValue == nil || input.CallValue.Sign() != 0 ||
		len(input.CallerAddr) != len(core.SystemAccountAddress) || len(input.Arguments) != 4 ||
		!bytes.Equal(input.Arguments[0], []byte{byte(vmcommon.Ok)}) || len(input.Arguments[2]) != 8 ||
		!vmcommon.ValidateToken(input.Arguments[1]) {
		return nil, CarrierOutcomeResult{}, ErrLifecycleSeal
	}
	shard := uint32(input.CallerAddr[len(input.CallerAddr)-1])
	phase := string(input.Arguments[3])
	if _, known := lifecycleSealSteps[phase]; !known || shard >= o.args.Shards ||
		!bytes.Equal(input.CallerAddr, registryDeltaSystemAddress(shard)) {
		return nil, CarrierOutcomeResult{}, ErrLifecycleSeal
	}
	epoch := binary.BigEndian.Uint64(input.Arguments[2])
	effect, err := lifecycleSealEffect(o.codec, input.Arguments[1], epoch, phase)
	if err != nil {
		return nil, CarrierOutcomeResult{}, err
	}
	result, err := o.args.Funding.Outcome(LifecycleSealCarrierClass, effect, shard, input.GasProvided)
	if err != nil {
		return nil, CarrierOutcomeResult{}, err
	}
	return &LifecycleSealOutcome{Shard: shard, TokenID: bytes.Clone(input.Arguments[1]), Epoch: epoch, Phase: phase}, result, nil
}
