package drwa

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-37, execution-shard side. Each shard is SP2-32's test shard: a real
// account store with the real registry, the native built-in container and the
// destination of protected admin legs. The shard's lifecycle record is put
// into the store as the activation replication (SP2-38) will write it; every
// expected record, key and acknowledgement item is framed independently here.

func sp237Record(token string, epoch uint64, phase string) []byte {
	return qualRecordFrame([]byte(token), binary.BigEndian.AppendUint64(nil, epoch), []byte(phase))
}

func sp237Key(token string) []byte {
	return append([]byte(lifecycleRecordPrefix), qualRecordFrame([]byte(token))...)
}

// sp237Install adds the seal owner to a shard as the node factory does.
func sp237Install(t *testing.T, s *sp232Shard) *LifecycleSeal {
	t.Helper()
	seal, err := NewLifecycleSeal(ArgsLifecycleSeal{Accounts: s.store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: s.f.reader.accounts.args.Hasher, Shard: s.id, Shards: 3, RecordBytes: 4096})
	require.NoError(t, err)
	require.False(t, seal.IsInterfaceNil())
	function := seal.Function()
	require.False(t, function.IsInterfaceNil())
	require.True(t, function.IsActive())
	function.SetNewGasConfig(nil)
	require.NoError(t, s.builtIns.Add(LifecycleSealFunctionName, function))
	require.NoError(t, s.function.SetSealGate(seal))
	return seal
}

// sp237CEB is the hash of the token's current CEB of an epoch in these tests.
func sp237CEB(epoch uint64) []byte {
	return bytes.Repeat([]byte{byte(0xc0 + epoch)}, 32)
}

func sp237Pointer(token string) []byte {
	return append([]byte(currentLocalPointerPrefix), qualRecordFrame([]byte(token))...)
}

// sp237Put writes the shard's lifecycle record and its current CEB pointer of
// the same epoch.
func sp237Put(t *testing.T, s *sp232Shard, token string, epoch uint64, phase string) {
	t.Helper()
	qualRecordPut(t, s.store, sp237Key(token), sp237Record(token, epoch, phase))
	qualRecordPut(t, s.store, sp237Pointer(token), qualRecordFrame(binary.BigEndian.AppendUint64(nil, epoch), sp237CEB(epoch)))
	s.commit()
}

func (s *sp232Shard) sp237Held(token string) []byte {
	return s.value(core.SystemAccountAddress, sp237Key(token))
}

// sp237Coordinates are the coordinates of a binding other than its family,
// phase, token, epoch, target and shard set.
type sp237Coordinates struct {
	action, digest, lineage, predecessor []byte
	// dependencies is the dependency hash; nil stands for the usual one.
	dependencies []byte
	// target, when set, replaces the hash of the named state.
	target []byte
}

// sp237SetupCoordinates is the independent derivation for the setup seal of
// a token's CEB epoch.
func sp237SetupCoordinates(s *sp232Shard, token string, epoch uint64, ceb []byte) sp237Coordinates {
	hasher := s.f.reader.accounts.args.Hasher
	e := binary.BigEndian.AppendUint64(nil, epoch)
	return sp237Coordinates{
		action:      hasher.Compute(string(qualRecordFrame([]byte("SETUP_LIFECYCLE"), []byte(token), e, ceb))),
		digest:      ceb,
		lineage:     qualRecordFrame([]byte(token), e, ceb),
		predecessor: hasher.Compute(string(sp237Record(token, epoch, "SETUP"))),
	}
}

// sp237BindingOf frames a phase binding independently: the twelve fields of
// the convergence binding, with the target the hash of the state it names.
func sp237BindingOf(s *sp232Shard, c sp237Coordinates, family, phase, token string, epoch uint64, state string, shards ...uint32) []byte {
	hasher := s.f.reader.accounts.args.Hasher
	ids := make([][]byte, len(shards))
	for i, shard := range shards {
		ids[i] = binary.BigEndian.AppendUint32(nil, shard)
	}
	set := qualRecordFrame(ids...)
	dependencies := c.dependencies
	if dependencies == nil {
		dependencies = bytes.Repeat([]byte{3}, 32)
	}
	target := c.target
	if target == nil {
		target = hasher.Compute(string(sp237Record(token, epoch, state)))
	}
	return qualRecordFrame([]byte(family), c.action, c.digest, []byte(phase), []byte(token),
		binary.BigEndian.AppendUint64(nil, epoch), target,
		dependencies, hasher.Compute(string(set)), set, c.lineage, c.predecessor)
}

func sp237Binding(s *sp232Shard, family, phase, token string, epoch uint64, state string, shards ...uint32) []byte {
	return sp237BindingOf(s, sp237SetupCoordinates(s, token, epoch, sp237CEB(epoch)), family, phase, token, epoch, state, shards...)
}

func sp237SetupBinding(s *sp232Shard, epoch uint64) []byte {
	return sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, epoch, "SETUP_SEALED", 0, 1, 2)
}

func sp237Call(shard uint32, arguments ...[]byte) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0),
		CallType: vmData.AsynchronousCall, GasProvided: 77, Arguments: arguments, CurrentTxHash: []byte("seal result hash")},
		RecipientAddr: registryDeltaSystemAddress(shard), Function: LifecycleSealFunctionName}
}

func sp237Seal(shard uint32, token string, epoch uint64, phase string, binding []byte) *vmcommon.ContractCallInput {
	arguments := [][]byte{[]byte(token), binary.BigEndian.AppendUint64(nil, epoch), []byte(phase)}
	if binding != nil {
		arguments = append(arguments, binding)
	}
	return sp237Call(shard, arguments...)
}

// sp237Refused requires an error of the seal and no state: the root after
// the processor's revert is the root before.
func (s *sp232Shard) sp237Refused(label string, input *vmcommon.ContractCallInput) {
	s.t.Helper()
	before, journal := s.root(), s.store.JournalLen()
	output, err := s.call(input)
	require.ErrorIs(s.t, err, ErrLifecycleSeal, label)
	require.Nil(s.t, output, label)
	require.Equal(s.t, before, s.root(), label)
	require.Equal(s.t, journal, s.store.JournalLen(), label)
}

func (s *sp232Shard) sp237Applied(label string, input *vmcommon.ContractCallInput) {
	s.t.Helper()
	output, err := s.call(input)
	require.NoError(s.t, err, label)
	require.Equal(s.t, vmcommon.Ok, output.ReturnCode, label)
	require.Equal(s.t, input.GasProvided, output.GasRemaining, "the call uses none of the gas it was given")
	require.Equal(s.t, input.Arguments[:3], output.ReturnData, label)
}

// sp237AckItem is the independent expectation of SP2-23's shard item.
func sp237AckItem(s *sp232Shard, binding []byte) (key, value []byte) {
	hasher := s.f.reader.accounts.args.Hasher
	return append([]byte(convergenceAckPrefix), hasher.Compute(string(binding))...),
		hasher.Compute(string(qualRecordFrame(binding, binary.BigEndian.AppendUint32(nil, s.id))))
}

func TestQualSP237ShardSealIsForwardOnly(t *testing.T) {
	s := sp232ShardNew(t, 1)
	seal := sp237Install(t, s)
	binding := sp237SetupBinding(s, 2)
	ackKey, ackValue := sp237AckItem(s, binding)

	// No record: the shard has nothing to seal.
	_, _, held, err := seal.Phase([]byte(sp232Token))
	require.NoError(t, err)
	require.False(t, held)
	s.sp237Refused("no record", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding))
	s.sp237Refused("no record, open", sp237Seal(1, sp232Token, 2, "OPEN", nil))

	sp237Put(t, s, sp232Token, 2, "SETUP")
	epoch, phase, held, err := seal.Phase([]byte(sp232Token))
	require.NoError(t, err)
	require.True(t, held)
	require.Equal(t, uint64(2), epoch)
	require.Equal(t, "SETUP", phase)

	// OPEN before the seal, a seal of another epoch, a phase outside the table.
	s.sp237Refused("open before the seal", sp237Seal(1, sp232Token, 2, "OPEN", nil))
	s.sp237Refused("earlier epoch", sp237Seal(1, sp232Token, 1, "SETUP_SEALED", sp237SetupBinding(s, 1)))
	s.sp237Refused("later epoch", sp237Seal(1, sp232Token, 3, "SETUP_SEALED", sp237SetupBinding(s, 3)))
	for _, other := range []string{"SETUP", "REQUALIFYING", "WIND_DOWN", "RETIRED", "WIND_DOWN_SEALED", ""} {
		s.sp237Refused("phase "+other, sp237Seal(1, sp232Token, 2, other, nil))
		s.sp237Refused("phase with binding "+other, sp237Seal(1, sp232Token, 2, other, binding))
	}
	require.Equal(t, sp237Record(sp232Token, 2, "SETUP"), s.sp237Held(sp232Token))

	// The seal: the record and the acknowledgement item, in one journal.
	s.sp237Applied("seal", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding))
	require.Equal(t, sp237Record(sp232Token, 2, "SETUP_SEALED"), s.sp237Held(sp232Token))
	require.Equal(t, ackValue, s.value(core.SystemAccountAddress, ackKey))
	sealed := s.commit()

	// Delivered twice: nothing changes.
	s.sp237Applied("seal again", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding))
	require.Equal(t, sealed, s.commit())

	// Nothing leads back, and the same seal under another binding is refused.
	// The one coordinate the shard does not derive is the dependency hash: a
	// second binding that differs only there is not the seal it applied.
	coordinates := sp237SetupCoordinates(s, sp232Token, 2, sp237CEB(2))
	coordinates.dependencies = bytes.Repeat([]byte{5}, 32)
	other := sp237BindingOf(s, coordinates, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2)
	otherKey, _ := sp237AckItem(s, other)
	s.sp237Refused("another binding for the applied seal", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", other))
	for _, back := range []string{"SETUP", "REQUALIFYING", "WIND_DOWN"} {
		s.sp237Refused("back to "+back, sp237Seal(1, sp232Token, 2, back, nil))
	}
	require.Equal(t, sealed, s.root())
	require.Empty(t, s.value(core.SystemAccountAddress, otherKey), "one seal, one acknowledgement item")

	// Restart: the same decisions from the reopened store.
	s.restart()
	s.sp237Refused("another binding after restart", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", other))
	s.sp237Applied("seal after restart", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding))
	require.Equal(t, sealed, s.commit())

	// OPEN, once, and only of the record's epoch.
	s.sp237Refused("OPEN of a later epoch", sp237Seal(1, sp232Token, 3, "OPEN", nil))
	s.sp237Refused("OPEN of an earlier epoch", sp237Seal(1, sp232Token, 1, "OPEN", nil))
	s.sp237Refused("open with a binding", sp237Seal(1, sp232Token, 2, "OPEN", binding))
	s.sp237Applied("open", sp237Seal(1, sp232Token, 2, "OPEN", nil))
	require.Equal(t, sp237Record(sp232Token, 2, "OPEN"), s.sp237Held(sp232Token))
	open := s.commit()
	s.sp237Applied("open again", sp237Seal(1, sp232Token, 2, "OPEN", nil))
	// The seal delivered late, after OPEN: the shard stays OPEN.
	s.sp237Applied("seal after open", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding))
	s.sp237Refused("another binding after open", sp237Seal(1, sp232Token, 2, "SETUP_SEALED", other))
	require.Equal(t, open, s.commit())
	require.Equal(t, sp237Record(sp232Token, 2, "OPEN"), s.sp237Held(sp232Token))
}

func TestQualSP237ShardSealRefusesAlteredContent(t *testing.T) {
	s := sp232ShardNew(t, 0)
	sp237Install(t, s)
	sp237Put(t, s, sp232Token, 2, "SETUP")
	good := sp237SetupBinding(s, 2)

	altered := map[string][]byte{
		"family":             sp237Binding(s, ConvergenceFamilyCEB, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"retirement family":  sp237Binding(s, ConvergenceFamilyRetirement, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"readiness phase":    sp237Binding(s, ConvergenceFamilySetup, "SETUP_READY_ACK", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"quiescence phase":   sp237Binding(s, ConvergenceFamilySetup, "DRWAQuiescenceAck", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"another token":      sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", "OTHER-0a1b2c", 2, "SETUP_SEALED", 0, 1, 2),
		"another epoch":      sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 3, "SETUP_SEALED", 0, 1, 2),
		"target of SETUP":    sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP", 0, 1, 2),
		"target of OPEN":     sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "OPEN", 0, 1, 2),
		"a shard missing":    sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1),
		"this shard missing": sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 1, 2),
		"a shard too many":   sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2, 3),
		"another instance": sp237BindingOf(s, func() sp237Coordinates {
			c := sp237SetupCoordinates(s, sp232Token, 2, sp237CEB(2))
			c.action = bytes.Repeat([]byte{1}, 32)
			return c
		}(), ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"another CEB": sp237BindingOf(s, sp237SetupCoordinates(s, sp232Token, 2, sp237CEB(1)),
			ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"another digest": sp237BindingOf(s, func() sp237Coordinates {
			c := sp237SetupCoordinates(s, sp232Token, 2, sp237CEB(2))
			c.digest = sp237CEB(1)
			return c
		}(), ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"another lineage": sp237BindingOf(s, func() sp237Coordinates {
			c := sp237SetupCoordinates(s, sp232Token, 2, sp237CEB(2))
			c.lineage = []byte("lineage")
			return c
		}(), ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"another predecessor": sp237BindingOf(s, func() sp237Coordinates {
			c := sp237SetupCoordinates(s, sp232Token, 2, sp237CEB(2))
			c.predecessor = sp237CEB(2)
			return c
		}(), ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2),
		"not a binding":        []byte("not a binding"),
		"truncated":            good[:len(good)-3],
		"with a trailing byte": append(bytes.Clone(good), 0),
	}
	for label, binding := range altered {
		s.sp237Refused(label, sp237Seal(0, sp232Token, 2, "SETUP_SEALED", binding))
	}
	s.sp237Refused("without a binding", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", nil))
	s.sp237Refused("empty binding", sp237Call(0, []byte(sp232Token), binary.BigEndian.AppendUint64(nil, 2), []byte("SETUP_SEALED"), nil))
	s.sp237Refused("epoch zero", sp237Seal(0, sp232Token, 0, "SETUP_SEALED", sp237SetupBinding(s, 0)))
	// Even where a record of epoch zero stood in the store.
	sp237Put(t, s, sp232Token, 0, "SETUP")
	s.sp237Refused("epoch zero with a record of it", sp237Seal(0, sp232Token, 0, "SETUP_SEALED", sp237SetupBinding(s, 0)))
	sp237Put(t, s, sp232Token, 2, "SETUP")
	s.sp237Refused("another token's record", sp237Seal(0, "OTHER-0a1b2c", 2, "SETUP_SEALED",
		sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", "OTHER-0a1b2c", 2, "SETUP_SEALED", 0, 1, 2)))
	s.sp237Refused("invalid token", sp237Seal(0, "x", 2, "SETUP_SEALED", good))

	// The form of the call: sender, kind, value, destination, arguments.
	form := func(change func(*vmcommon.ContractCallInput)) *vmcommon.ContractCallInput {
		input := sp237Seal(0, sp232Token, 2, "SETUP_SEALED", good)
		change(input)
		return input
	}
	s.sp237Refused("another sender", form(func(i *vmcommon.ContractCallInput) { i.CallerAddr = s.holder }))
	s.sp237Refused("the shard's own system address as sender", form(func(i *vmcommon.ContractCallInput) { i.CallerAddr = registryDeltaSystemAddress(0) }))
	s.sp237Refused("a direct call", form(func(i *vmcommon.ContractCallInput) { i.CallType = vmData.DirectCall }))
	s.sp237Refused("a callback", form(func(i *vmcommon.ContractCallInput) { i.CallType = vmData.AsynchronousCallBack }))
	s.sp237Refused("with value", form(func(i *vmcommon.ContractCallInput) { i.CallValue = big.NewInt(1) }))
	s.sp237Refused("without a value", form(func(i *vmcommon.ContractCallInput) { i.CallValue = nil }))
	s.sp237Refused("another shard's address", form(func(i *vmcommon.ContractCallInput) { i.RecipientAddr = registryDeltaSystemAddress(1) }))
	s.sp237Refused("two arguments", form(func(i *vmcommon.ContractCallInput) { i.Arguments = i.Arguments[:2] }))
	s.sp237Refused("five arguments", form(func(i *vmcommon.ContractCallInput) { i.Arguments = append(i.Arguments, []byte{1}) }))
	s.sp237Refused("short epoch", form(func(i *vmcommon.ContractCallInput) { i.Arguments[1] = []byte{2} }))
	_, err := seal237Function(s).ProcessBuiltinFunction(nil, nil, nil)
	require.ErrorIs(t, err, ErrLifecycleSeal)

	// A token that is not a member of this shard's registry, with a record.
	sp237Put(t, s, "OTHER-0a1b2c", 2, "SETUP")
	s.sp237Refused("not a member", sp237Seal(0, "OTHER-0a1b2c", 2, "SETUP_SEALED",
		sp237Binding(s, ConvergenceFamilySetup, "SETUP_SEALED", "OTHER-0a1b2c", 2, "SETUP_SEALED", 0, 1, 2)))
	// A record that does not decode.
	qualRecordPut(t, s.store, sp237Key(sp232Token), []byte("not a record"))
	s.commit()
	s.sp237Refused("record that does not decode", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", good))
	qualRecordPut(t, s.store, sp237Key(sp232Token), sp237Record("OTHER-0a1b2c", 2, "SETUP"))
	s.commit()
	s.sp237Refused("record of another token", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", good))

	// After all of it the good seal still applies, and nothing else was written.
	sp237Put(t, s, sp232Token, 2, "SETUP")
	s.sp237Applied("the exact seal", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", good))
	for label, binding := range altered {
		key, _ := sp237AckItem(s, binding)
		require.Empty(t, s.value(core.SystemAccountAddress, key), label)
	}
}

func seal237Function(s *sp232Shard) vmcommon.BuiltinFunction {
	function, err := s.builtIns.Get(LifecycleSealFunctionName)
	require.NoError(s.t, err)
	return function
}

func TestQualSP237ShardSealRollbackLeavesNothing(t *testing.T) {
	s := sp232ShardNew(t, 2)
	sp237Install(t, s)
	sp237Put(t, s, sp232Token, 2, "SETUP")
	binding := sp237SetupBinding(s, 2)
	ackKey, _ := sp237AckItem(s, binding)
	before := s.root()

	// The block that carried the seal is rolled back.
	snapshot := s.store.JournalLen()
	s.sp237Applied("seal", sp237Seal(2, sp232Token, 2, "SETUP_SEALED", binding))
	require.NotEqual(t, before, s.root())
	require.NoError(t, s.store.RevertToSnapshot(snapshot))
	require.Equal(t, before, s.root())
	require.Equal(t, sp237Record(sp232Token, 2, "SETUP"), s.sp237Held(sp232Token))
	require.Empty(t, s.value(core.SystemAccountAddress, ackKey), "a rolled-back block leaves no acknowledgement")

	// The same for a block that carried OPEN.
	s.sp237Applied("seal", sp237Seal(2, sp232Token, 2, "SETUP_SEALED", binding))
	sealed := s.commit()
	snapshot = s.store.JournalLen()
	s.sp237Applied("open", sp237Seal(2, sp232Token, 2, "OPEN", nil))
	require.NoError(t, s.store.RevertToSnapshot(snapshot))
	require.Equal(t, sealed, s.root())
	require.Equal(t, sp237Record(sp232Token, 2, "SETUP_SEALED"), s.sp237Held(sp232Token))
}

func TestQualSP237TerminalSealClosesClosure(t *testing.T) {
	s := sp232ShardNew(t, 1)
	seal := sp237Install(t, s)
	sp237Put(t, s, sp232Token, 5, "WIND_DOWN")
	terminal := AdminEffect{TokenID: []byte(sp232Token), Binding: "TERMINAL", Epoch: 5}
	require.NoError(t, seal.VerifyAdminEffect(terminal), "a closure leg before the terminal seal")

	binding := sp237Binding(s, ConvergenceFamilyRetirement, "WIND_DOWN_SEALED", sp232Token, 5, "WIND_DOWN_SEALED", 0, 1, 2)
	s.sp237Refused("setup family for the terminal seal", sp237Seal(1, sp232Token, 5, "WIND_DOWN_SEALED",
		sp237Binding(s, ConvergenceFamilySetup, "WIND_DOWN_SEALED", sp232Token, 5, "WIND_DOWN_SEALED", 0, 1, 2)))
	s.sp237Refused("setup seal in wind-down", sp237Seal(1, sp232Token, 5, "SETUP_SEALED", sp237SetupBinding(s, 5)))
	s.sp237Refused("open in wind-down", sp237Seal(1, sp232Token, 5, "OPEN", nil))
	// The terminal seal's binding names this token and this epoch.
	sp237Put(t, s, "OTHER-0a1b2c", 5, "WIND_DOWN")
	s.sp237Refused("the terminal binding of another token", sp237Seal(1, sp232Token, 5, "WIND_DOWN_SEALED",
		sp237BindingOf(s, sp237Coordinates{action: bytes.Repeat([]byte{1}, 32), digest: bytes.Repeat([]byte{2}, 32), lineage: []byte("l"),
			predecessor: bytes.Repeat([]byte{4}, 32), target: s.f.reader.accounts.args.Hasher.Compute(string(sp237Record(sp232Token, 5, "WIND_DOWN_SEALED")))},
			ConvergenceFamilyRetirement, "WIND_DOWN_SEALED", "OTHER-0a1b2c", 5, "WIND_DOWN_SEALED", 0, 1, 2)))
	s.sp237Refused("the terminal binding of another epoch", sp237Seal(1, sp232Token, 5, "WIND_DOWN_SEALED",
		sp237BindingOf(s, sp237Coordinates{action: bytes.Repeat([]byte{1}, 32), digest: bytes.Repeat([]byte{2}, 32), lineage: []byte("l"),
			predecessor: bytes.Repeat([]byte{4}, 32), target: s.f.reader.accounts.args.Hasher.Compute(string(sp237Record(sp232Token, 5, "WIND_DOWN_SEALED")))},
			ConvergenceFamilyRetirement, "WIND_DOWN_SEALED", sp232Token, 6, "WIND_DOWN_SEALED", 0, 1, 2)))
	s.sp237Applied("terminal seal", sp237Seal(1, sp232Token, 5, "WIND_DOWN_SEALED", binding))
	require.Equal(t, sp237Record(sp232Token, 5, "WIND_DOWN_SEALED"), s.sp237Held(sp232Token))
	key, value := sp237AckItem(s, binding)
	require.Equal(t, value, s.value(core.SystemAccountAddress, key))
	sealed := s.commit()
	s.sp237Applied("terminal seal again", sp237Seal(1, sp232Token, 5, "WIND_DOWN_SEALED", binding))
	require.Equal(t, sealed, s.commit())

	// After the seal every closure leg is refused, of every binding kind.
	for _, kind := range []string{"TERMINAL", "CURRENT_CEB", "PREPARED_CEB", "", "OTHER"} {
		terminal.Binding = kind
		require.ErrorIs(t, seal.VerifyAdminEffect(terminal), ErrLifecycleSeal, kind)
	}
	s.sp237Refused("setup seal after the terminal seal", sp237Seal(1, sp232Token, 5, "SETUP_SEALED", sp237SetupBinding(s, 5)))
	s.sp237Refused("open after the terminal seal", sp237Seal(1, sp232Token, 5, "OPEN", nil))
	require.Equal(t, sealed, s.root())
}

func TestQualSP237SealGateTable(t *testing.T) {
	s := sp232ShardNew(t, 0)
	seal := sp237Install(t, s)
	effect := func(kind string, epoch uint64) AdminEffect {
		return AdminEffect{TokenID: []byte(sp232Token), Binding: kind, Epoch: epoch}
	}
	// No record: the seal has no rule; admission is the binding source's.
	for _, kind := range []string{"CURRENT_CEB", "PREPARED_CEB", "TERMINAL"} {
		require.NoError(t, seal.VerifyAdminEffect(effect(kind, 2)), kind)
	}
	admitted := map[string]string{"SETUP": "CURRENT_CEB", "REQUALIFYING": "PREPARED_CEB", "WIND_DOWN": "TERMINAL"}
	for _, phase := range []string{"SETUP", "SETUP_SEALED", "OPEN", "REQUALIFYING", "WIND_DOWN", "WIND_DOWN_SEALED", "RETIRED", "UNKNOWN"} {
		sp237Put(t, s, sp232Token, 2, phase)
		for _, kind := range []string{"CURRENT_CEB", "PREPARED_CEB", "TERMINAL", "", "OTHER"} {
			err := seal.VerifyAdminEffect(effect(kind, 2))
			if want, any := admitted[phase]; any && want == kind {
				require.NoError(t, err, phase+"/"+kind)
			} else {
				require.ErrorIs(t, err, ErrLifecycleSeal, phase+"/"+kind)
			}
		}
	}
	// A setup leg of another CEB epoch than the shard's record.
	sp237Put(t, s, sp232Token, 2, "SETUP")
	require.ErrorIs(t, seal.VerifyAdminEffect(effect("CURRENT_CEB", 1)), ErrLifecycleSeal)
	require.ErrorIs(t, seal.VerifyAdminEffect(effect("CURRENT_CEB", 3)), ErrLifecycleSeal)
	// A record that does not decode refuses.
	qualRecordPut(t, s.store, sp237Key(sp232Token), []byte("not a record"))
	require.ErrorIs(t, seal.VerifyAdminEffect(effect("CURRENT_CEB", 2)), ErrLifecycleSeal)
	_, _, _, err := seal.Phase([]byte(sp232Token))
	require.ErrorIs(t, err, ErrLifecycleSeal)
}

// A real role leg, opened by the real origin and delivered to the real
// destination of each shard, in every setup state of that shard.
func TestQualSP237SetupOnlyLegOnSealedAndLaggingShards(t *testing.T) {
	for _, c := range []struct {
		name    string
		phases  [3]string
		epoch   uint64
		applied [3]bool
	}{
		{"no record on any shard", [3]string{"", "", ""}, 2, [3]bool{true, true, true}},
		{"every shard in setup", [3]string{"SETUP", "SETUP", "SETUP"}, 2, [3]bool{true, true, true}},
		{"two sealed, one lagging in setup", [3]string{"SETUP_SEALED", "SETUP_SEALED", "SETUP"}, 2, [3]bool{false, false, true}},
		{"every shard sealed", [3]string{"SETUP_SEALED", "SETUP_SEALED", "SETUP_SEALED"}, 2, [3]bool{false, false, false}},
		{"two open, one lagging sealed", [3]string{"OPEN", "OPEN", "SETUP_SEALED"}, 2, [3]bool{false, false, false}},
		{"every shard open", [3]string{"OPEN", "OPEN", "OPEN"}, 2, [3]bool{false, false, false}},
		{"setup of another epoch", [3]string{"SETUP", "SETUP", "SETUP"}, 3, [3]bool{false, false, false}},
		{"requalifying", [3]string{"REQUALIFYING", "REQUALIFYING", "REQUALIFYING"}, 2, [3]bool{false, false, false}},
		{"wind-down and its seal", [3]string{"WIND_DOWN", "WIND_DOWN_SEALED", "WIND_DOWN_SEALED"}, 2, [3]bool{false, false, false}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := sp232New(t)
			for id, s := range w.shards {
				sp237Install(t, s)
				if c.phases[id] != "" {
					sp237Put(t, s, sp232Token, c.epoch, c.phases[id])
				}
			}
			_, legs := w.open(w.limited())
			require.Len(t, legs, 3)
			key := append([]byte(adminTokenKeyPrefix), sp232Token...)
			for id, s := range w.shards {
				calls := s.binding.calls
				input := sp232Input(t, registryDeltaSystemAddress(s.id), legs[id], "leg result hash")
				if !c.applied[id] {
					s.refused(c.name, input)
					require.Equal(t, calls, s.binding.calls, "the seal refuses before the binding source is asked")
					require.Empty(t, s.value(core.SystemAccountAddress, key))
					continue
				}
				output, err := s.call(input)
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, output.ReturnCode)
				require.Equal(t, sp232TokenItem(true), s.value(core.SystemAccountAddress, key))
			}
		})
	}
}

func TestQualSP237ShardSealConstruction(t *testing.T) {
	s := sp232ShardNew(t, 0)
	args := ArgsLifecycleSeal{Accounts: s.store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: s.f.reader.accounts.args.Hasher, Shard: 0, Shards: 3, RecordBytes: 4096}
	for label, change := range map[string]func(*ArgsLifecycleSeal){
		"no store":           func(a *ArgsLifecycleSeal) { a.Accounts = nil },
		"no marshaller":      func(a *ArgsLifecycleSeal) { a.Marshaller = nil },
		"no hasher":          func(a *ArgsLifecycleSeal) { a.Hasher = nil },
		"no shards":          func(a *ArgsLifecycleSeal) { a.Shards = 0 },
		"too many shards":    func(a *ArgsLifecycleSeal) { a.Shards, a.Shard = maxCarrierLegs+1, 1 },
		"shard outside":      func(a *ArgsLifecycleSeal) { a.Shard = 3 },
		"the metachain":      func(a *ArgsLifecycleSeal) { a.Shard = core.MetachainShardId },
		"no record capacity": func(a *ArgsLifecycleSeal) { a.RecordBytes = 0 },
	} {
		changed := args
		change(&changed)
		seal, err := NewLifecycleSeal(changed)
		require.Error(t, err, label)
		require.Nil(t, seal, label)
	}
	require.True(t, (*LifecycleSeal)(nil).IsInterfaceNil())
	require.True(t, (*lifecycleSealFunction)(nil).IsInterfaceNil())

	// The seal check is installed once, and is no nil value.
	seal := sp237Install(t, s)
	require.ErrorIs(t, s.function.SetSealGate(seal), ErrInvalidAdminEffect)
	require.ErrorIs(t, s.function.SetSealGate(nil), ErrInvalidAdminEffect)
	other := sp232ShardNew(t, 1)
	require.ErrorIs(t, other.function.SetSealGate((*LifecycleSeal)(nil)), ErrInvalidAdminEffect)
}

// The route inventory: the seal call carries no public identifier, as the
// registry delta carries none, so the classification gate hands it to the
// function, which authenticates its sender and the token's membership itself.
// The seal's name as the inner effect of an admin leg is outside the closed
// set of SP2-32.
func TestQualSP237SealCallInTheRouteInventory(t *testing.T) {
	s := sp232ShardNew(t, 0)
	sp237Install(t, s)
	admission := &BuiltInAdmission{classifier: s.registry}
	for _, name := range []string{LifecycleSealFunctionName, RegistryDeltaFunctionName} {
		function, err := s.builtIns.Get(name)
		require.NoError(t, err)
		input := sp237Seal(0, sp232Token, 2, "OPEN", nil)
		input.Function = name
		identifiers, err := builtInIdentifiers(function, input)
		require.NoError(t, err, name)
		require.Empty(t, identifiers, name)
		require.NoError(t, admission.AdmitBuiltIn(function, input), name)
	}
	_, known := adminEffectLoci[LifecycleSealFunctionName]
	require.False(t, known)
}
