package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

var errSP223Fault = errors.New("injected native read or write failure")

// sp223Faults fails the n-th system-account access of the store: the load
// itself, or the first read or the first write made through that handle.
type sp223Faults struct {
	*qualNativeStore
	at, calls int
	kind      string
}

type sp223FaultAccount struct {
	state.UserAccountHandler
	kind string
}

func (a *sp223FaultAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if a.kind == "read" {
		return nil, 0, errSP223Fault
	}
	return a.UserAccountHandler.RetrieveValue(key)
}

func (a *sp223FaultAccount) SaveKeyValue(key, value []byte) error {
	if a.kind == "write" {
		return errSP223Fault
	}
	return a.UserAccountHandler.SaveKeyValue(key, value)
}

func (s *sp223Faults) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	s.calls++
	if s.calls-1 != s.at {
		return s.qualNativeStore.GetExistingAccount(address)
	}
	if s.kind == "load" {
		return nil, errSP223Fault
	}
	a, err := s.qualNativeStore.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &sp223FaultAccount{a.(state.UserAccountHandler), s.kind}, nil
}

// A failed native read or write at any step of creation, completion, parent
// verification or the shard's acknowledgement is an error of that request,
// never a match, a free instance or a finished phase.
func TestQualSP223NativeFailuresDenyTheRequest(t *testing.T) {
	for _, kind := range []string{"load", "read", "write"} {
		for at := 0; at < 6; at++ {
			w := sp223New(t, sp223Ample())
			tr := w.transition(ConvergenceFamilyContinuation, "cancellation-fence", 120, true)
			binding := w.binding(tr)
			faults := &sp223Faults{qualNativeStore: w.store, at: 1 << 30, kind: kind}
			codec, err := newRegistrationRecords(faults, &marshal.GogoProtoMarshalizer{}, w.hasher, 4096)
			require.NoError(t, err)
			host, err := NewConvergenceHost(ArgsConvergenceHost{Accounts: faults, Records: codec, Reader: w.reader, Block: w.block,
				Limits: w.limits, EvidenceBytes: 1 << 20, Owners: map[string]ConvergenceFamilyOwner{ConvergenceFamilyContinuation: w.owner}})
			require.NoError(t, err)
			commitment := bytes.Repeat([]byte{7}, 32)

			steps := map[string]func() error{
				"admission": func() error { return host.Admission(binding, 500) },
				"complete":  func() error { _, e := host.Complete(binding, commitment); return e },
				"parent":    func() error { return host.VerifyParent(binding, commitment) },
				"shard": func() error {
					writer, e := NewConvergenceAckWriter(codec, 1)
					require.NoError(t, e)
					return writer.Acknowledge(binding)
				},
			}
			for name, step := range steps {
				snapshot := w.store.JournalLen()
				faults.calls, faults.at = 0, 1<<30
				reference := step()
				used := faults.calls
				require.NoError(t, w.store.RevertToSnapshot(snapshot))
				if name == "parent" {
					require.Error(t, reference, "no parent receipt exists")
				} else {
					require.NoError(t, reference, name)
				}
				if at >= used {
					continue
				}
				faults.calls, faults.at = 0, at
				err = step()
				require.NoError(t, w.store.RevertToSnapshot(snapshot))
				if kind == "write" && name == "parent" {
					continue // a pure read
				}
				if kind == "load" || name != "parent" {
					require.Error(t, err, "%s %s at %d", kind, name, at)
				}
			}
		}
	}
}

// Malformed inputs at the host boundary, each refused without state.
func TestQualSP223HostRefusesMalformedInput(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyRoot, "ROOT_TARGET_READY_ACK", 130, true)
	binding := w.binding(tr)
	root := w.root()
	args := w.host.args
	for name, change := range map[string]func(*ArgsConvergenceHost){
		"no accounts":       func(a *ArgsConvergenceHost) { a.Accounts = nil },
		"no records":        func(a *ArgsConvergenceHost) { a.Records = nil },
		"foreign records":   func(a *ArgsConvergenceHost) { a.Accounts = qualRegistrationStore(t, 0) },
		"no reader":         func(a *ArgsConvergenceHost) { a.Reader = nil },
		"no block source":   func(a *ArgsConvergenceHost) { a.Block = nil },
		"no record limit":   func(a *ArgsConvergenceHost) { a.Limits.Records = 0 },
		"no byte limit":     func(a *ArgsConvergenceHost) { a.Limits.RetainedBytes = 0 },
		"no rate limit":     func(a *ArgsConvergenceHost) { a.Limits.NewRecordsPerEpoch = 0 },
		"no evidence limit": func(a *ArgsConvergenceHost) { a.EvidenceBytes = 0 },
		"a nil owner":       func(a *ArgsConvergenceHost) { a.Owners = map[string]ConvergenceFamilyOwner{ConvergenceFamilyRoot: nil} },
	} {
		changed := args
		change(&changed)
		_, err := NewConvergenceHost(changed)
		require.Error(t, err, name)
	}
	require.Error(t, w.host.SetFamilyOwner(ConvergenceFamilyRoot, w.owner), "an owner is installed once")
	require.Error(t, w.host.SetFamilyOwner("PLANE", w.owner))
	require.Error(t, w.host.SetFamilyOwner(ConvergenceFamilySetup, nil))
	bare, err := NewConvergenceHost(ArgsConvergenceHost{Accounts: w.store, Records: args.Records, Reader: w.reader, Block: w.block,
		Limits: w.limits, EvidenceBytes: 1 << 20})
	require.NoError(t, err)
	require.Error(t, bare.VerifyTransition(binding))
	require.NoError(t, bare.SetFamilyOwner(ConvergenceFamilyRoot, w.owner))
	require.NoError(t, bare.VerifyTransition(binding))
	require.False(t, bare.IsInterfaceNil())

	eleven := qualRecordFrame(bytes.Split(bytes.Repeat([]byte("x,"), 11), []byte(","))[:11]...)
	short := qualRecordFrame([]byte(ConvergenceFamilyRoot), tr.action, tr.digest, []byte("ROOT_TARGET_READY_ACK"), tr.token,
		[]byte{7}, tr.target, tr.dependencies, tr.requiredSet, qualRecordFrame([]byte{0, 0, 0, 0}), []byte("l"), tr.digest)
	badSet := qualRecordFrame([]byte(ConvergenceFamilyRoot), tr.action, tr.digest, []byte("ROOT_TARGET_READY_ACK"), tr.token,
		[]byte{0, 0, 0, 0, 0, 0, 0, 7}, tr.target, tr.dependencies, tr.requiredSet, []byte("not a list"), []byte("l"), tr.digest)
	shortID := qualRecordFrame([]byte(ConvergenceFamilyRoot), tr.action, tr.digest, []byte("ROOT_TARGET_READY_ACK"), tr.token,
		[]byte{0, 0, 0, 0, 0, 0, 0, 7}, tr.target, tr.dependencies, tr.requiredSet, qualRecordFrame([]byte{0, 0, 1}), []byte("l"), tr.digest)
	legacy := w.binding(w.transition(ConvergenceFamilyCEB, "CURRENT_ACK", 131, true))
	withLineage := append(bytes.Clone(legacy), qualRecordFrame([]byte("l"), tr.digest)...)
	for name, malformed := range map[string][]byte{"empty": nil, "not framed": []byte("binding"), "eleven fields": eleven,
		"short version": short, "set not a list": badSet, "short shard id": shortID, "legacy pair with a lineage": withLineage} {
		require.Error(t, w.host.VerifyTransition(malformed), name)
		require.Error(t, w.host.Admission(malformed, 100), name)
		_, err = w.host.VerifyAck(malformed, []byte("ack"), []byte("evidence"))
		require.Error(t, err, name)
		_, err = w.host.Complete(malformed, tr.digest)
		require.Error(t, err, name)
		require.Error(t, w.host.VerifyParent(malformed, tr.digest), name)
	}
	require.NoError(t, w.host.VerifyTransition(legacy))
	require.Error(t, w.host.Admission(binding, 0), "a phase that retains nothing is not a phase")
	_, err = w.host.Complete(binding, []byte("short"))
	require.Error(t, err)
	require.Error(t, w.host.VerifyParent(binding, []byte("short")))
	for name, ack := range map[string][]byte{
		"not framed":            []byte("ack"),
		"another binding":       qualRecordFrame(legacy, []byte{0, 0, 0, 1}, tr.digest),
		"short shard":           qualRecordFrame(binding, []byte{0, 1}, tr.digest),
		"short local execution": qualRecordFrame(binding, []byte{0, 0, 0, 1}, []byte("s")),
		"metachain":             qualRecordFrame(binding, []byte{0xff, 0xff, 0xff, 0xff}, tr.digest),
	} {
		_, err = w.host.VerifyAck(binding, ack, []byte("evidence"))
		require.Error(t, err, name)
	}
	require.Equal(t, root, w.root())
	require.Zero(t, w.store.JournalLen())
}

// The same path through the node's own constructor: the canonical reader is
// built from native dependencies over the host's in-memory proof cache, which
// holds only the nodes of the evidence in hand.
func TestQualSP223NativeConstructorAndProofCache(t *testing.T) {
	w := sp223New(t, sp223Ample())
	exclusions, err := common.NewRoundExclusionHandler(nil)
	require.NoError(t, err)
	args := ArgsNativeConvergenceHost{Accounts: w.store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: w.hasher,
		EnableEpochsHandler: w.reader.accounts.args.EnableEpochsHandler, MaxTrieLevelInMemory: 5,
		Validator: w.reader.validator, Proofs: w.reader.proofs, Integrity: w.reader.integrity, Exclusions: exclusions,
		Block: w.block, Limits: w.limits, RecordBytes: 4096, EvidenceBytes: 1 << 20,
		Owners: map[string]ConvergenceFamilyOwner{ConvergenceFamilyRoot: w.owner}}
	host, err := NewNativeConvergenceHost(args)
	require.NoError(t, err)
	for name, change := range map[string]func(*ArgsNativeConvergenceHost){
		"no record bytes":  func(a *ArgsNativeConvergenceHost) { a.RecordBytes = 0 },
		"no epochs":        func(a *ArgsNativeConvergenceHost) { a.EnableEpochsHandler = nil },
		"no validator":     func(a *ArgsNativeConvergenceHost) { a.Validator = nil },
		"no block source":  func(a *ArgsNativeConvergenceHost) { a.Block = nil },
		"no evidence size": func(a *ArgsNativeConvergenceHost) { a.EvidenceBytes = 0 },
	} {
		changed := args
		change(&changed)
		_, e := NewNativeConvergenceHost(changed)
		require.Error(t, e, name)
	}
	boundary, err := NewRollbackContainment(w.store)
	require.NoError(t, err)
	records, err := newConvergenceRecords(w.store, boundary, &marshal.GogoProtoMarshalizer{}, w.hasher, 4096, 16, host)
	require.NoError(t, err)
	tr := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_CLEAR_ACK", 140, true)
	require.NoError(t, records.create(tr))
	binding := w.binding(tr)
	acks := sp223Acks(t, 11, binding)
	for _, ack := range acks {
		w.enter(ack)
		require.NoError(t, records.acknowledge(tr, ack.shard, ack.origin, ack.evidence(t, binding)))
		require.NotEmpty(t, host.cache.nodes)
	}
	require.NoError(t, records.complete(tr))

	// A warm cache completes nothing: evidence stripped of its data proof is
	// refused although the previous read cached those very nodes.
	other := w.transition(ConvergenceFamilyRoot, "ROOT_FENCE_ACK", 141, true)
	require.NoError(t, records.create(other))
	ack := sp223Acknowledge(t, 0, 11, w.binding(other))
	w.enter(ack)
	require.NoError(t, records.acknowledge(other, 0, ack.origin, ack.evidence(t, w.binding(other))))
	second := w.transition(ConvergenceFamilyRoot, "ROOT_CURRENT_ACK", 142, true)
	require.NoError(t, records.create(second))
	both := sp223Acknowledge(t, 0, 11, w.binding(second))
	w.enter(both)
	stripped := both.witness(t, w.binding(second))
	full := sp223Evidence(t, stripped)
	stripped.Account.DataProof = stripped.Account.DataProof[:1]
	require.NoError(t, records.acknowledge(second, 0, both.origin, full))
	third := w.transition(ConvergenceFamilyRoot, "ROOT_TARGET_READY_ACK", 143, true)
	require.NoError(t, records.create(third))
	require.Error(t, records.acknowledge(second, 1, both.origin, sp223Evidence(t, stripped)))

	cache := host.cache
	require.False(t, cache.IsInterfaceNil())
	require.Equal(t, "DRWAConvergenceProofCache", cache.GetIdentifier())
	require.NotNil(t, cache.GetStateStatsHandler())
	_, err = cache.GetFromCurrentEpoch([]byte("absent"))
	require.ErrorIs(t, err, ErrInvalidAccountWitness)
	require.NoError(t, cache.Put([]byte("k"), []byte("v")))
	value, err := cache.Get([]byte("k"))
	require.NoError(t, err)
	require.Equal(t, []byte("v"), value)
	_ = core.MetachainShardId
}

// sp223Marshaller fails the n-th encoding.
type sp223Marshaller struct {
	marshal.GogoProtoMarshalizer
	at, calls int
}

func (m *sp223Marshaller) Marshal(value interface{}) ([]byte, error) {
	m.calls++
	if m.calls-1 == m.at {
		return nil, errSP223Fault
	}
	return m.GogoProtoMarshalizer.Marshal(value)
}

// A failed encoding at any step is an error of that request.
func TestQualSP223EncodingFailuresDenyTheRequest(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyContinuation, "cancellation-fence", 150, true)
	binding := w.binding(tr)
	ack := sp223Acknowledge(t, 1, 11, binding)
	w.enter(ack)
	witness := ack.witness(t, binding)
	evidence := sp223Evidence(t, witness)
	mar := &sp223Marshaller{at: 1 << 30}
	codec, err := newRegistrationRecords(w.store, mar, w.hasher, 4096)
	require.NoError(t, err)
	host, err := NewConvergenceHost(ArgsConvergenceHost{Accounts: w.store, Records: codec, Reader: w.reader, Block: w.block,
		Limits: w.limits, EvidenceBytes: 1 << 20, Owners: map[string]ConvergenceFamilyOwner{ConvergenceFamilyContinuation: w.owner}})
	require.NoError(t, err)
	commitment := bytes.Repeat([]byte{7}, 32)
	payload := qualRecordFrame(binding, []byte{0, 0, 0, 1}, ack.origin)
	wide := &registrationRecords{marshaller: mar, maxBytes: 1 << 20}
	steps := map[string]func() error{
		"transition": func() error { return host.VerifyTransition(binding) },
		"admission":  func() error { return host.Admission(binding, 500) },
		"ack":        func() error { _, e := host.VerifyAck(binding, payload, evidence); return e },
		"complete":   func() error { _, e := host.Complete(binding, commitment); return e },
		"shard": func() error {
			writer, e := NewConvergenceAckWriter(codec, 1)
			require.NoError(t, e)
			return writer.Acknowledge(binding)
		},
		"evidence": func() error { _, e := encodeConvergenceEvidence(wide, witness); return e },
	}
	for name, step := range steps {
		snapshot := w.store.JournalLen()
		mar.calls, mar.at = 0, 1<<30
		require.NoError(t, step(), name)
		used := mar.calls
		require.NoError(t, w.store.RevertToSnapshot(snapshot))
		require.NotZero(t, used, name)
		for at := 0; at < used; at++ {
			mar.calls, mar.at = 0, at
			require.Error(t, step(), "%s at encoding %d", name, at)
			require.NoError(t, w.store.RevertToSnapshot(snapshot))
		}
	}
	mar.at = 1 << 30

	// The block source refuses a header it cannot encode or whose bytes are not the committed hash.
	n := newSP222Node(t, core.MetachainShardId, true)
	h := n.next(false)
	require.NoError(t, n.begin(h))
	failing := &sp223Marshaller{at: 0}
	n.imp.args.Marshaller = failing
	_, _, _, err = n.imp.ExecutingBlock()
	require.ErrorIs(t, err, errSP223Fault)
	n.imp.args.Marshaller = n.mar
	n.imp.executing = bytes.Repeat([]byte{1}, 32)
	_, _, _, err = n.imp.ExecutingBlock()
	require.ErrorIs(t, err, ErrFinalityImport)
}

// The budget reservation used for the progress record: same rules as every
// retained record.
func TestQualSP223BudgetReservation(t *testing.T) {
	w := sp223New(t, sp223Ample())
	budget := w.host.budget()
	account, err := w.host.args.Records.state.systemAccount()
	require.NoError(t, err)
	require.Error(t, budget.reserve(account, 10, 0))
	require.Error(t, budget.reserve(account, 9, 100), "an epoch before the committed rate epoch")
	before := w.value(sp223BudgetKey)
	require.NoError(t, budget.reserve(account, 11, 100))
	after := w.value(sp223BudgetKey)
	require.Equal(t, uint64(2), binaryU64(after, 0))
	require.Equal(t, binaryU64(before, 8)+100, binaryU64(after, 8))
	require.Equal(t, uint64(11), binaryU64(after, 16))
	require.Equal(t, uint64(1), binaryU64(after, 24))
	require.NoError(t, account.SaveKeyValue([]byte(sp223BudgetKey), nil))
	require.Error(t, budget.reserve(account, 11, 100), "a missing budget is never zero usage")
	failing := &sp223FaultAccount{UserAccountHandler: account, kind: "write"}
	require.NoError(t, account.SaveKeyValue([]byte(sp223BudgetKey), after))
	require.ErrorIs(t, budget.reserve(failing, 11, 100), errSP223Fault)
}

func binaryU64(b []byte, offset int) uint64 {
	var v uint64
	for _, x := range b[offset : offset+8] {
		v = v<<8 | uint64(x)
	}
	return v
}

// The parent receipt is written once, only inside a block in execution, and
// evidence larger than the configured bound is not framed.
func TestQualSP223ParentReceiptIsWrittenOnceInsideABlock(t *testing.T) {
	w := sp223New(t, sp223Ample())
	tr := w.transition(ConvergenceFamilyRebindFence, "FENCE_CLEAR_ACK", 160, true)
	binding := w.binding(tr)
	commitment := bytes.Repeat([]byte{7}, 32)
	hash := w.block.hash
	w.block.hash = nil
	_, err := w.host.Complete(binding, commitment)
	require.ErrorIs(t, err, ErrFinalityImport)
	require.ErrorIs(t, w.host.Admission(binding, 500), ErrFinalityImport)
	w.block.hash = hash
	output, err := w.host.Complete(binding, commitment)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, []byte(ConvergenceCompleteObservation), output.Logs[0].Identifier)
	require.Equal(t, commitment, output.Logs[0].Topics[1])
	_, err = w.host.Complete(binding, commitment)
	require.Error(t, err, "a parent receipt is never rewritten")
	_, err = w.host.Complete(binding, bytes.Repeat([]byte{8}, 32))
	require.Error(t, err)
	require.NoError(t, w.host.VerifyParent(binding, commitment))
	require.Error(t, w.host.VerifyParent(binding, bytes.Repeat([]byte{8}, 32)))

	ack := sp223Acknowledge(t, 0, 11, binding)
	small := &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, maxBytes: 64}
	_, err = encodeConvergenceEvidence(small, ack.witness(t, binding))
	require.Error(t, err)
	witness := ack.witness(t, binding)
	witness.MetaHeaders = nil
	_, err = encodeConvergenceEvidence(small, witness)
	require.Error(t, err)
}
