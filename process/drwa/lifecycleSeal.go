package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/state"
)

// LifecycleSealFunctionName is the protected built-in call that carries a
// replicated lifecycle seal from the metachain to an execution shard. It is
// state replication (Part A L5486-5488: "State replication copies an
// already-authoritative DRWA object and is acknowledged by DRWAStateAck; it
// does not grant an ESDT role/config mutation"), not an admin effect, and it
// uses the native transport the registry delta uses.
const LifecycleSealFunctionName = "DRWALifecycleSeal"

// ErrLifecycleSeal refuses a seal, or an operation the seal closes.
var ErrLifecycleSeal = errors.New("invalid DRWA lifecycle seal")

// lifecycleSealAckPrefix holds, per token and seal phase, the CEB epoch and
// the hash of the one phase binding this shard acknowledged.
const lifecycleSealAckPrefix = core.ProtectedKeyPrefix + "DRWA@lifecycleSealAck@"

// lifecycleSealStep is one forward step of the replicated lifecycle record.
// later lists the phases of the same CEB epoch that already include the step.
// A step with a family is a seal: it is acknowledged under that family's
// phase of the same name.
type lifecycleSealStep struct {
	prior  string
	later  []string
	family string
}

// lifecycleSealSteps is the closed successor table (Part A L2110-2120). There
// is no step to SETUP, to WIND_DOWN or to REQUALIFYING: those belong to the
// governed transitions of their own rows, and nothing here goes back.
var lifecycleSealSteps = map[string]lifecycleSealStep{
	"SETUP_SEALED":     {prior: "SETUP", later: []string{"OPEN"}, family: ConvergenceFamilySetup},
	"OPEN":             {prior: "SETUP_SEALED"},
	"WIND_DOWN_SEALED": {prior: "WIND_DOWN", family: ConvergenceFamilyRetirement},
}

func lifecycleSealKey(codec *registrationRecords, token []byte) ([]byte, error) {
	identity, err := codec.frame(token)
	if err != nil {
		return nil, err
	}
	return append([]byte(lifecycleRecordPrefix), identity...), nil
}

// lifecycleSealRecord is the lifecycle record of activationRecords and
// setupLifecycle: token, CEB epoch, phase.
func lifecycleSealRecord(codec *registrationRecords, token []byte, epoch uint64, phase string) ([]byte, error) {
	return codec.frame(token, binary.BigEndian.AppendUint64(nil, epoch), []byte(phase))
}

// lifecycleSealRead returns the record this store holds for token, or a nil
// raw value when it holds none. A record that does not decode is an error.
func lifecycleSealRead(codec *registrationRecords, account state.UserAccountHandler, token []byte) (epoch uint64, phase string, raw []byte, err error) {
	key, err := lifecycleSealKey(codec, token)
	if err != nil {
		return 0, "", nil, err
	}
	raw, _, err = account.RetrieveValue(key)
	if err != nil {
		return 0, "", nil, err
	}
	if len(raw) == 0 {
		return 0, "", nil, nil
	}
	fields, err := codec.unframe(raw, 3)
	if err != nil || !bytes.Equal(fields[0], token) || len(fields[1]) != 8 || len(fields[2]) == 0 {
		return 0, "", nil, ErrLifecycleSeal
	}
	return binary.BigEndian.Uint64(fields[1]), string(fields[2]), raw, nil
}

// lifecycleSealCEB returns the hash of the current CEB this store holds for
// token, which must be of the given epoch.
func lifecycleSealCEB(codec *registrationRecords, account state.UserAccountHandler, token []byte, epoch uint64) ([]byte, error) {
	identity, err := codec.frame(token)
	if err != nil {
		return nil, err
	}
	pointer, _, err := account.RetrieveValue(append([]byte(currentLocalPointerPrefix), identity...))
	if err != nil {
		return nil, err
	}
	if len(pointer) == 0 {
		return nil, ErrLifecycleSeal
	}
	fields, err := codec.unframe(pointer, 2)
	if err != nil || len(fields[0]) != 8 || binary.BigEndian.Uint64(fields[0]) != epoch ||
		len(fields[1]) != codec.hasher.Size() {
		return nil, ErrLifecycleSeal
	}
	return fields[1], nil
}

// completeShardSet tells whether shards is every configured execution shard,
// in order.
func completeShardSet(shards []uint32, configured uint32) bool {
	if uint64(len(shards)) != uint64(configured) {
		return false
	}
	for i, shard := range shards {
		if shard != uint32(i) {
			return false
		}
	}
	return true
}

// ArgsLifecycleSeal holds the native dependencies of one execution shard's
// seal owner. Shards is the configured number of execution shards.
type ArgsLifecycleSeal struct {
	Accounts    state.AccountsAdapter
	Marshaller  marshal.Marshalizer
	Hasher      hashing.Hasher
	Shard       uint32
	Shards      uint32
	RecordBytes int
}

// LifecycleSeal is the execution-shard owner of the replicated lifecycle
// seal (Part A L2489-2503, L6308-6310). It advances the shard's own lifecycle
// record forward only, acknowledges a seal in the same journal, and refuses a
// protected admin leg the shard's own phase closes. It reads no other shard
// and nothing of the metachain: a lagging shard decides by its own record,
// which is never more permissive than the metachain's.
type LifecycleSeal struct {
	args  ArgsLifecycleSeal
	codec *registrationRecords
	ack   *ConvergenceAckWriter
}

// NewLifecycleSeal creates the owner. It reads no state.
func NewLifecycleSeal(args ArgsLifecycleSeal) (*LifecycleSeal, error) {
	if check.IfNil(args.Accounts) || args.Shards == 0 || args.Shards > maxCarrierLegs || args.Shard >= args.Shards {
		return nil, ErrLifecycleSeal
	}
	codec, err := newRegistrationRecords(args.Accounts, args.Marshaller, args.Hasher, args.RecordBytes)
	if err != nil {
		return nil, err
	}
	// The writer of this execution shard: the checks above are its own.
	return &LifecycleSeal{args: args, codec: codec, ack: &ConvergenceAckWriter{records: codec, shard: args.Shard}}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (s *LifecycleSeal) IsInterfaceNil() bool { return s == nil }

// Phase returns the CEB epoch and the phase of this shard's own lifecycle
// record of token. held is false when the shard has no record.
func (s *LifecycleSeal) Phase(token []byte) (epoch uint64, phase string, held bool, err error) {
	account, err := s.codec.state.systemAccount()
	if err != nil {
		return 0, "", false, err
	}
	epoch, phase, raw, err := lifecycleSealRead(s.codec, account, token)
	return epoch, phase, raw != nil, err
}

// VerifyAdminEffect is the seal check of a protected admin leg (matrix of
// Part A L5150, L5154): a leg under the current CEB is a setup-only mutation
// and is admitted only while this shard's record is SETUP of that epoch; a
// leg under a prepared CEB only in REQUALIFYING; a terminal leg only in
// WIND_DOWN, never after the terminal seal. A token this shard has no
// lifecycle record of has no seal: its legs are the binding source's alone.
// The check only refuses; admission stays with the binding source.
func (s *LifecycleSeal) VerifyAdminEffect(effect AdminEffect) error {
	epoch, phase, held, err := s.Phase(effect.TokenID)
	if err != nil {
		return err
	}
	if !held {
		return nil
	}
	admitted := false
	switch effect.Binding {
	case "CURRENT_CEB":
		admitted = phase == "SETUP" && epoch == effect.Epoch
	case "PREPARED_CEB":
		admitted = phase == "REQUALIFYING"
	case "TERMINAL":
		admitted = phase == "WIND_DOWN"
	}
	if !admitted {
		return ErrLifecycleSeal
	}
	return nil
}

// verifyBinding checks the phase binding a seal is acknowledged under against
// what this shard is about to hold: the family and phase of the step, the
// token, the CEB epoch, the hash of the exact successor record and the
// complete configured shard set. For the setup seal it also derives the
// instance, the CEB hash, the lineage and the predecessor from the shard's
// own current CEB pointer, so that only the dependency hash, whose owner is
// the local dependency commitment (SP2-26), is not checked here. The terminal
// seal's other coordinates are its family owner's (SP2-61).
func (s *LifecycleSeal) verifyBinding(account state.UserAccountHandler, step lifecycleSealStep, token []byte, epoch uint64, phase string, successor, binding []byte) error {
	b, err := decodeConvergenceBinding(s.codec, binding)
	if err != nil {
		return err
	}
	if string(b.Family) != step.family || string(b.Phase) != phase || !bytes.Equal(b.Token, token) ||
		b.Version != epoch || !bytes.Equal(b.Target, s.codec.hasher.Compute(string(successor))) ||
		!completeShardSet(b.Shards, s.args.Shards) {
		return ErrLifecycleSeal
	}
	if step.family != ConvergenceFamilySetup {
		return nil
	}
	cebHash, err := lifecycleSealCEB(s.codec, account, token, epoch)
	if err != nil {
		return err
	}
	action, digest, _, lineage, predecessor, err := setupPhaseCoordinates(s.codec, token, epoch, cebHash, setupPhaseStates[phase])
	if err != nil {
		return err
	}
	if !bytes.Equal(b.Action, action) || !bytes.Equal(b.Digest, digest) || !bytes.Equal(b.Lineage, lineage) ||
		!bytes.Equal(b.Predecessor, predecessor) {
		return ErrLifecycleSeal
	}
	return nil
}

// Apply advances this shard's lifecycle record of token to phase, inside the
// journal of the native call in execution. The record must be of the same CEB
// epoch and exactly the step's predecessor; a shard that already holds the
// phase, or a later one of the same epoch, changes nothing. Every other case
// is refused: no record, another epoch, OPEN before the seal, a phase outside
// the table. A seal is acknowledged under its binding in the same journal,
// and only under the one binding first applied. applied tells whether the
// record changed.
func (s *LifecycleSeal) Apply(token []byte, epoch uint64, phase string, binding []byte) (applied bool, err error) {
	step, known := lifecycleSealSteps[phase]
	if !known || epoch == 0 || !vmcommon.ValidateToken(token) || len(token) > s.codec.maxBytes ||
		(step.family == "") != (len(binding) == 0) {
		return false, ErrLifecycleSeal
	}
	account, err := s.codec.state.systemAccount()
	if err != nil {
		return false, err
	}
	member, _, err := account.RetrieveValue(shardMemberKey(token))
	if err != nil {
		return false, err
	}
	have, held, raw, err := lifecycleSealRead(s.codec, account, token)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(member, []byte{1}) || raw == nil || have != epoch {
		return false, ErrLifecycleSeal
	}
	repeat := held == phase
	for _, later := range step.later {
		repeat = repeat || held == later
	}
	if held != step.prior && !repeat {
		return false, ErrLifecycleSeal
	}
	successor, err := lifecycleSealRecord(s.codec, token, epoch, phase)
	if err != nil {
		return false, err
	}
	if step.family != "" {
		if err = s.verifyBinding(account, step, token, epoch, phase, successor, binding); err != nil {
			return false, err
		}
		identity, e := s.codec.frame(token, []byte(phase))
		if e != nil {
			return false, e
		}
		ackKey := append([]byte(lifecycleSealAckPrefix), identity...)
		acknowledged, e := s.codec.frame(binary.BigEndian.AppendUint64(nil, epoch), s.codec.hasher.Compute(string(binding)))
		if e != nil {
			return false, e
		}
		old, _, e := account.RetrieveValue(ackKey)
		if e != nil {
			return false, e
		}
		// A repeat is the same seal: the binding first applied. A first
		// application of an epoch replaces what an earlier epoch left.
		if repeat && !bytes.Equal(old, acknowledged) {
			return false, ErrLifecycleSeal
		}
		if !repeat {
			if e = account.SaveKeyValue(ackKey, acknowledged); e != nil {
				return false, e
			}
		}
	}
	if !repeat {
		key, e := lifecycleSealKey(s.codec, token)
		if e != nil {
			return false, e
		}
		if e = account.SaveKeyValue(key, successor); e != nil {
			return false, e
		}
		if e = s.args.Accounts.SaveAccount(account); e != nil {
			return false, e
		}
	}
	if step.family != "" {
		if err = s.ack.Acknowledge(binding); err != nil {
			return false, err
		}
	}
	return !repeat, nil
}

// Function returns the protected built-in call of this shard's seal owner.
// It belongs in the shard's processing built-in container only.
func (s *LifecycleSeal) Function() vmcommon.BuiltinFunction {
	return &lifecycleSealFunction{seal: s}
}

type lifecycleSealFunction struct {
	seal *LifecycleSeal
}

// SetNewGasConfig does nothing: the call uses no schedule entry.
func (f *lifecycleSealFunction) SetNewGasConfig(*vmcommon.GasCost) {}

// IsActive always returns true
func (f *lifecycleSealFunction) IsActive() bool { return true }

// IsInterfaceNil returns true if there is no value under the interface
func (f *lifecycleSealFunction) IsInterfaceNil() bool { return f == nil }

// ProcessBuiltinFunction applies one replicated lifecycle state. Only the
// metachain ESDT system contract can be its caller, only by an asynchronous
// call, and only this shard's system account address its destination. Its
// arguments are the token, the eight-byte CEB epoch, the phase and, for a
// seal, the phase binding. Its outcome is what the native processor returns
// to the metachain as the callback of that call, with all the gas the call
// was given, which it does not use. A refused call has an error outcome; the
// native processor reverts everything it wrote.
func (f *lifecycleSealFunction) ProcessBuiltinFunction(_, _ vmcommon.UserAccountHandler,
	input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
	s := f.seal
	if input == nil || input.CallValue == nil || input.CallValue.Sign() != 0 ||
		input.CallType != vmData.AsynchronousCall || len(input.Arguments) < 3 || len(input.Arguments) > 4 ||
		len(input.Arguments[1]) != 8 ||
		!bytes.Equal(input.CallerAddr, core.ESDTSCAddress) ||
		!bytes.Equal(input.RecipientAddr, registryDeltaSystemAddress(s.args.Shard)) {
		return nil, ErrLifecycleSeal
	}
	var binding []byte
	if len(input.Arguments) == 4 {
		binding = input.Arguments[3]
		if len(binding) == 0 {
			return nil, ErrLifecycleSeal
		}
	}
	_, err := s.Apply(input.Arguments[0], binary.BigEndian.Uint64(input.Arguments[1]), string(input.Arguments[2]), binding)
	if err != nil {
		return nil, errors.Join(ErrLifecycleSeal, err)
	}
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: input.GasProvided,
		ReturnData: [][]byte{bytes.Clone(input.Arguments[0]), bytes.Clone(input.Arguments[1]), bytes.Clone(input.Arguments[2])}}, nil
}
