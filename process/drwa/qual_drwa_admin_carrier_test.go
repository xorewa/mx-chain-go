package drwa

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// L46 DEVELOPMENT: real native trie/journal/parser with a SYNTHETIC trusted host.
// This is no proof of actual protected result origin, transport or canonicality.
type qualAdminHost struct {
	store                                           state.AccountsAdapter
	expected                                        []byte
	key                                             []byte
	verifyErr, localErr, stateErr, applyErr, ackErr error
	wrongResult, corruptArguments                   bool
	nativeFailedOutput, ackFailedOutput             bool
	nativeNilOutput, ackNilOutput                   bool
	localFailAt, stateFailAt                        int32
	localCalls, stateCalls                          int32
	verifyCalls, applyCalls, ackCalls               int32
	verifyHook                                      func()
}

func (h *qualAdminHost) IsInterfaceNil() bool { return h == nil }
func (h *qualAdminHost) VerifyCanonical(envelope, proof []byte) error {
	atomic.AddInt32(&h.verifyCalls, 1)
	if h.verifyHook != nil {
		h.verifyHook()
	}
	if h.verifyErr != nil {
		return h.verifyErr
	}
	if !bytes.Equal(envelope, h.expected) || !bytes.Equal(proof, blake2b.NewBlake2b().Compute(string(h.expected))) {
		return errAdminCarrier
	}
	if h.corruptArguments {
		envelope[0] ^= 1
		proof[0] ^= 1
	}
	return nil
}
func (h *qualAdminHost) ValidateLocal(e adminEffectEnvelope) error {
	if atomic.AddInt32(&h.localCalls, 1) == h.localFailAt {
		return errAdminCarrier
	}
	if h.localErr != nil {
		return h.localErr
	}
	if e.targetShard != 1 || !bytes.Equal(e.targetKey, h.key) || string(e.binding) != "CURRENT_CEB" || e.cebEpoch != 2 ||
		string(e.gasVersion) != "independent-gas-fixture" || e.workLimit < 7 {
		return errAdminCarrier
	}
	if h.corruptArguments {
		e.effectID[0] ^= 1
		e.gasVersion[0] ^= 1
		e.result[0] ^= 1
	}
	return nil
}
func (h *qualAdminHost) account() (state.UserAccountHandler, error) {
	a, err := h.store.GetExistingAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, err
	}
	return a.(state.UserAccountHandler), nil
}
func (h *qualAdminHost) StateHash(e adminEffectEnvelope) ([]byte, error) {
	if atomic.AddInt32(&h.stateCalls, 1) == h.stateFailAt {
		return nil, errAdminCarrier
	}
	if h.stateErr != nil {
		return nil, h.stateErr
	}
	a, err := h.account()
	if err != nil {
		return nil, err
	}
	v, _, err := a.RetrieveValue(e.targetKey)
	if err != nil {
		return nil, err
	}
	return blake2b.NewBlake2b().Compute(string(v)), nil
}
func (h *qualAdminHost) ApplyNative(e adminEffectEnvelope) (*vmcommon.VMOutput, error) {
	atomic.AddInt32(&h.applyCalls, 1)
	a, err := h.account()
	if err != nil {
		return nil, err
	}
	v := []byte("result")
	if h.wrongResult {
		v = []byte("wrong result")
	}
	if err = a.SaveKeyValue(e.targetKey, v); err != nil {
		return nil, err
	}
	if err = h.store.SaveAccount(a); err != nil {
		return nil, err
	}
	if h.applyErr != nil {
		return nil, h.applyErr
	}
	if h.nativeNilOutput {
		return nil, nil
	}
	code := vmcommon.Ok
	if h.nativeFailedOutput {
		code = vmcommon.UserError
	}
	return &vmcommon.VMOutput{ReturnCode: code, ReturnData: [][]byte{[]byte("native-output")}}, nil
}
func (h *qualAdminHost) Ack(_ adminEffectEnvelope, ack []byte, out *vmcommon.VMOutput) (*vmcommon.VMOutput, error) {
	atomic.AddInt32(&h.ackCalls, 1)
	if h.ackErr != nil {
		return nil, h.ackErr
	}
	if h.ackNilOutput {
		return nil, nil
	}
	if out == nil {
		out = &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	}
	out.ReturnData = append(out.ReturnData, bytes.Clone(ack))
	if h.ackFailedOutput {
		out.ReturnCode = vmcommon.UserError
	}
	return out, nil
}

type qualAdminFixture struct {
	store          *qualNativeStore
	boundary       *RollbackContainment
	carrier        *adminCarrier
	host           *qualAdminHost
	e              adminEffectEnvelope
	encoded, proof []byte
}

type qualAdminNthSave struct {
	state.AccountsAdapter
	calls, failAt int
	fault         error
}

// Fault only the selected data-trie key. Hand the original native account back
// to AccountsDB, whose marshaller and data-trie writer require its native type.
// Otherwise the earlier native target save masks an identity-key fault.
type qualAdminKeyFault struct{ *qualScopedAccountFault }

func (s *qualAdminKeyFault) SaveAccount(account vmcommon.AccountHandler) error {
	if wrapped, ok := account.(*qualScopedKeyFault); ok {
		account = wrapped.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(account)
}

func (s *qualAdminNthSave) SaveAccount(account vmcommon.AccountHandler) error {
	s.calls++
	if s.calls == s.failAt {
		return s.fault
	}
	return s.AccountsAdapter.SaveAccount(account)
}

func qualAdminDigest(purpose string, fields ...[]byte) []byte {
	return blake2b.NewBlake2b().Compute(string(qualRecordFrame(append([][]byte{[]byte("DRWA/ADMIN/" + purpose + "/candidate1"), []byte("fixture-domain")}, fields...)...)))
}

// Independent hand-framed protobuf vectors; production codec creates no expected body.
func qualAdminEncode(e adminEffectEnvelope) []byte {
	return qualRecordFrame([]byte("DRWA/ADMIN_ENVELOPE/candidate1"), []byte("fixture-domain"),
		e.effectID, e.legID, e.operation, e.origin, e.openCommitment, e.tokenID, e.tokenType, e.binding,
		binary.BigEndian.AppendUint64(nil, e.cebEpoch), e.actionID, e.planDigest, e.planStep, e.normalizedDigest, e.discriminator, e.payload,
		binary.BigEndian.AppendUint32(nil, e.targetShard), e.targetKey, e.predecessor, e.result, e.gasVersion, binary.BigEndian.AppendUint64(nil, e.workLimit))
}
func qualAdminNew(t *testing.T) *qualAdminFixture {
	t.Helper()
	f := &qualAdminFixture{store: qualRegistrationStore(t, 0)}
	key := []byte(core.ProtectedKeyPrefix + "DRWA@qualAdminTarget")
	qualRecordPut(t, f.store, key, []byte("predecessor"))
	_, err := f.store.Commit()
	require.NoError(t, err)
	f.boundary, err = NewRollbackContainment(f.store)
	require.NoError(t, err)
	digest := func(s string) []byte { return blake2b.NewBlake2b().Compute(s) }
	f.e = adminEffectEnvelope{effectID: digest("effect"), legID: digest("leg"), operation: []byte("DRWAApplyTokenAdmin"), origin: digest("origin"), openCommitment: digest("immutable-policy"),
		tokenID: []byte("TOKEN-abcdef"), tokenType: []byte(core.NonFungibleESDTv2), binding: []byte("CURRENT_CEB"), cebEpoch: 2,
		discriminator: []byte(core.BuiltInFunctionSetESDTRole), targetShard: 1, targetKey: key, predecessor: digest("predecessor"), result: digest("result"), gasVersion: []byte("independent-gas-fixture"), workLimit: 7}
	f.e.payload = []byte(core.BuiltInFunctionSetESDTRole + "@" + hex.EncodeToString(f.e.tokenID) + "@" + hex.EncodeToString([]byte(core.ESDTRoleNFTCreate)))
	f.e.normalizedDigest = qualAdminDigest("NORMALIZED", f.e.discriminator, f.e.tokenID, []byte(core.ESDTRoleNFTCreate))
	f.host = &qualAdminHost{store: f.store, key: key}
	f.carrier, err = newAdminCarrier(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, f.host)
	require.NoError(t, err)
	f.rebind()
	return f
}
func (f *qualAdminFixture) rebind() {
	f.encoded = qualAdminEncode(f.e)
	f.host.expected = bytes.Clone(f.encoded)
	f.proof = blake2b.NewBlake2b().Compute(string(f.encoded))
}
func (f *qualAdminFixture) appliedKey() []byte {
	return append([]byte(adminAppliedPrefix), qualAdminDigest("APPLIED_ID", f.e.effectID, f.e.legID)...)
}

func TestQualDRWAAdminCarrierNativeControl(t *testing.T) {
	f := qualAdminNew(t)
	require.NoError(t, f.carrier.apply(f.encoded, f.proof))
	require.NoError(t, f.carrier.apply(f.encoded, f.proof))
	require.Equal(t, int32(1), atomic.LoadInt32(&f.host.applyCalls))
	roots, outputs, err := f.boundary.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 2)
	wantAck := qualRecordFrame([]byte("DRWA/ADMIN_ACK/candidate1"), f.encoded)
	require.Equal(t, [][]byte{[]byte("native-output"), wantAck}, outputs[0].ReturnData)
	require.Equal(t, [][]byte{wantAck}, outputs[1].ReturnData)
	require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	require.Equal(t, []byte("result"), qualRegistryValue(t, f.store, string(f.e.targetKey)))
	require.Equal(t, f.encoded, qualRegistryValue(t, f.store, string(f.appliedKey())))
	f.boundary, err = NewRollbackContainment(f.store)
	require.NoError(t, err)
	f.carrier.boundary = f.boundary
	require.NoError(t, f.carrier.apply(f.encoded, f.proof))
	require.Equal(t, int32(1), atomic.LoadInt32(&f.host.applyCalls))
}
func TestQualDRWAAdminCarrierIndependentCodec(t *testing.T) {
	f := qualAdminNew(t)
	got, err := f.carrier.encode(f.e)
	require.NoError(t, err)
	require.Equal(t, f.encoded, got)
	e, err := f.carrier.decode(f.encoded)
	require.NoError(t, err)
	// Native repeated bytes decode zero-length fields as empty slices.
	// The independent fixture expects that exact native representation.
	want := f.e.copy()
	want.actionID, want.planDigest, want.planStep = []byte{}, []byte{}, []byte{}
	require.Equal(t, want, e)
	// Only argument hexadecimal is normalized; the native function stays exact.
	parts := strings.Split(string(f.e.payload), "@")
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.ToUpper(parts[i])
	}
	f.e.payload = []byte(strings.Join(parts, "@"))
	f.rebind()
	require.NoError(t, f.carrier.apply(f.encoded, f.proof))
}
func TestQualDRWAAdminCarrierHostAndBindingGuards(t *testing.T) {
	for _, fault := range []string{"origin", "local-dependency", "state-read", "target", "shard", "binding", "ceb", "gas", "work", "proof", "oversized-proof", "normalized", "discriminator", "malformed-frame", "noncanonical-frame"} {
		t.Run(fault, func(t *testing.T) {
			f := qualAdminNew(t)
			original := errors.New("independent host rejection")
			root, err := f.store.RootHash()
			require.NoError(t, err)
			switch fault {
			case "origin":
				f.host.verifyErr = original
			case "local-dependency":
				f.host.localErr = original
			case "state-read":
				f.host.stateErr = original
			case "target":
				f.e.targetKey = []byte("another target")
				f.rebind()
			case "shard":
				f.e.targetShard = 2
				f.rebind()
			case "binding":
				f.e.binding = []byte("PREPARED_CEB")
				f.rebind()
			case "ceb":
				f.e.cebEpoch = 3
				f.rebind()
			case "gas":
				f.e.gasVersion = []byte("other schedule")
				f.rebind()
			case "work":
				f.e.workLimit = 6
				f.rebind()
			case "proof":
				f.proof[0] ^= 1
			case "oversized-proof":
				f.proof = make([]byte, 4097)
			case "normalized":
				f.e.normalizedDigest[0] ^= 1
				f.rebind()
			case "discriminator":
				f.e.discriminator = []byte("another function")
				f.rebind()
			case "malformed-frame":
				f.encoded = []byte{0x0a, 0xff}
			case "noncanonical-frame":
				f.encoded = append(f.encoded, 0x10, 0x01)
			}
			require.Error(t, f.carrier.apply(f.encoded, f.proof))
			require.Zero(t, atomic.LoadInt32(&f.host.applyCalls))
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			if fault == "oversized-proof" {
				require.Zero(t, atomic.LoadInt32(&f.host.verifyCalls))
			}
		})
	}
}
func TestQualDRWAAdminCarrierDurableIdentityAndABA(t *testing.T) {
	for _, fault := range []string{"aba", "equal-state-other-leg", "different-body", "missing-provenance-on-duplicate", "missing-binding-on-duplicate", "corrupt-applied"} {
		t.Run(fault, func(t *testing.T) {
			f := qualAdminNew(t)
			if fault != "equal-state-other-leg" {
				require.NoError(t, f.carrier.apply(f.encoded, f.proof))
			}
			switch fault {
			case "aba":
				qualRecordPut(t, f.store, f.e.targetKey, []byte("predecessor"))
			case "equal-state-other-leg":
				qualRecordPut(t, f.store, f.e.targetKey, []byte("result"))
			case "different-body":
				f.e.openCommitment = bytes.Repeat([]byte{9}, 32)
				f.rebind()
			case "missing-provenance-on-duplicate":
				f.host.verifyErr = errAdminCarrier
			case "missing-binding-on-duplicate":
				f.host.localErr = errAdminCarrier
			case "corrupt-applied":
				qualRecordPut(t, f.store, f.appliedKey(), []byte("corrupt"))
			}
			before := atomic.LoadInt32(&f.host.applyCalls)
			require.Error(t, f.carrier.apply(f.encoded, f.proof))
			require.Equal(t, before, atomic.LoadInt32(&f.host.applyCalls))
		})
	}
}
func TestQualDRWAAdminCarrierCoJournalFaults(t *testing.T) {
	for _, fault := range []string{"native-effect", "native-return-code", "native-nil-output", "wrong-result", "post-effect-state-read", "post-effect-binding", "ack", "ack-return-code", "ack-nil-output", "save-account", "applied-key", "target-key", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			f := qualAdminNew(t)
			original := errors.New("native fault")
			rollback := errors.New("rollback fault")
			root, err := f.store.RootHash()
			require.NoError(t, err)
			switch fault {
			case "native-effect":
				f.host.applyErr = original
			case "native-return-code":
				f.host.nativeFailedOutput = true
			case "native-nil-output":
				f.host.nativeNilOutput = true
			case "wrong-result":
				f.host.wrongResult = true
			case "post-effect-state-read":
				f.host.stateFailAt = 2
			case "post-effect-binding":
				f.host.localFailAt = 2
			case "ack":
				f.host.ackErr = original
			case "ack-return-code":
				f.host.ackFailedOutput = true
			case "ack-nil-output":
				f.host.ackNilOutput = true
			case "save-account":
				// Select the identity account save AFTER the native target save;
				// an all-save fault would be masked by the native effect's save.
				wrapped := &qualAdminNthSave{AccountsAdapter: f.store, failAt: 2, fault: original}
				f.host.store = wrapped
				f.boundary, err = NewRollbackContainment(wrapped)
				require.NoError(t, err)
				f.carrier, err = newAdminCarrier(wrapped, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, f.host)
				require.NoError(t, err)
			case "rollback":
				f.host.ackErr = original
				f.store.revertErr = rollback
			case "applied-key", "target-key":
				key := f.appliedKey()
				if fault == "target-key" {
					key = f.e.targetKey
				}
				wrapped := &qualAdminKeyFault{&qualScopedAccountFault{f.store, key, original}}
				f.host.store = wrapped
				f.boundary, err = NewRollbackContainment(wrapped)
				require.NoError(t, err)
				f.carrier, err = newAdminCarrier(wrapped, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, f.host)
				require.NoError(t, err)
			}
			err = f.carrier.apply(f.encoded, f.proof)
			require.Error(t, err)
			if fault == "applied-key" || fault == "target-key" || fault == "save-account" {
				require.ErrorIs(t, err, original, "the selected native write, rather than an earlier wrapper failure, must reject")
			}
			if fault == "native-return-code" || fault == "native-nil-output" {
				require.Zero(t, atomic.LoadInt32(&f.host.ackCalls), "unsuccessful native execution must never invoke the success ACK producer")
			}
			if fault == "rollback" {
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, rollback)
				_, out, e := f.boundary.Commit()
				require.Error(t, e)
				require.Empty(t, out)
				require.NoError(t, f.boundary.Recover())
			}
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Empty(t, qualRegistryValue(t, f.store, string(f.appliedKey())))
			require.Equal(t, []byte("predecessor"), qualRegistryValue(t, f.store, string(f.e.targetKey)))
		})
	}
}

func TestQualDRWAAdminCarrierStructuralDenials(t *testing.T) {
	for _, fault := range []string{"domain", "effect-id", "leg-id", "origin-id", "open-commitment", "token", "type", "binding-kind", "operation-class", "metachain-target", "zero-work", "no-gas-profile", "empty-target", "plan-without-step", "step-without-plan", "action-width", "requalification-without-action", "requalification-wrong-binding", "oversized-body"} {
		t.Run(fault, func(t *testing.T) {
			f := qualAdminNew(t)
			switch fault {
			case "domain":
				f.encoded = bytes.Replace(f.encoded, []byte("fixture-domain"), []byte("foreign-domain"), 1)
			case "effect-id":
				f.e.effectID = []byte("short")
			case "leg-id":
				f.e.legID = nil
			case "origin-id":
				f.e.origin = nil
			case "open-commitment":
				f.e.openCommitment = nil
			case "token":
				f.e.tokenID = []byte("invalid")
			case "type":
				f.e.tokenType = []byte("unknown family")
			case "binding-kind":
				f.e.binding = []byte("unknown binding")
			case "operation-class":
				f.e.operation = []byte("transferOwnership")
			case "metachain-target":
				f.e.targetShard = core.MetachainShardId
			case "zero-work":
				f.e.workLimit = 0
			case "no-gas-profile":
				f.e.gasVersion = nil
			case "empty-target":
				f.e.targetKey = nil
			case "plan-without-step":
				f.e.planDigest = bytes.Repeat([]byte{1}, 32)
			case "step-without-plan":
				f.e.planStep = make([]byte, 8)
			case "action-width":
				f.e.actionID = []byte("short")
			case "requalification-without-action":
				f.e.operation = []byte("DRWAApplyRequalificationAdmin")
				f.e.binding = []byte("PREPARED_CEB")
				f.e.planDigest = bytes.Repeat([]byte{1}, 32)
				f.e.planStep = make([]byte, 8)
			case "requalification-wrong-binding":
				f.e.operation = []byte("DRWAApplyRequalificationAdmin")
				f.e.actionID = bytes.Repeat([]byte{1}, 32)
				f.e.planDigest = bytes.Repeat([]byte{2}, 32)
				f.e.planStep = make([]byte, 8)
			case "oversized-body":
				f.e.targetKey = make([]byte, 4097)
			}
			if fault != "domain" {
				f.rebind()
			}
			require.Error(t, f.carrier.apply(f.encoded, f.proof))
			require.Zero(t, atomic.LoadInt32(&f.host.verifyCalls), "reject malformed/unbounded carrier before trusted adapter work")
		})
	}
}
func TestQualDRWAAdminCarrierAdapterBufferIsolation(t *testing.T) {
	f := qualAdminNew(t)
	f.host.corruptArguments = true
	require.NoError(t, f.carrier.apply(f.encoded, f.proof))
	require.Equal(t, f.encoded, qualRegistryValue(t, f.store, string(f.appliedKey())))
}

func TestQualDRWAAdminCarrierSelectiveFaultAdapterControl(t *testing.T) {
	f := qualAdminNew(t)
	wrapped := &qualAdminKeyFault{&qualScopedAccountFault{f.store, []byte("unrelated-key"), errors.New("unselected fault")}}
	f.host.store = wrapped
	boundary, err := NewRollbackContainment(wrapped)
	require.NoError(t, err)
	f.carrier, err = newAdminCarrier(wrapped, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, f.host)
	require.NoError(t, err)
	require.NoError(t, f.carrier.apply(f.encoded, f.proof))
	_, outputs, err := boundary.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	require.Equal(t, []byte("result"), qualRegistryValue(t, f.store, string(f.e.targetKey)))
	require.Equal(t, f.encoded, qualRegistryValue(t, f.store, string(f.appliedKey())))
}
func TestQualDRWAAdminCarrierDependenciesAndSerialization(t *testing.T) {
	f := qualAdminNew(t)
	_, err := newAdminCarrier(f.store, nil, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, f.host)
	require.Error(t, err)
	_, err = newAdminCarrier(f.store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, nil)
	require.Error(t, err)
	_, err = newAdminCarrier(qualRegistrationStore(t, 0), f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, f.host)
	require.Error(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	f.host.verifyHook = func() { close(entered); <-release }
	result := make(chan error, 1)
	go func() { result <- f.carrier.apply(f.encoded, f.proof) }()
	<-entered
	require.ErrorIs(t, f.carrier.apply(f.encoded, f.proof), ErrExecutionBusy)
	close(release)
	require.NoError(t, <-result)
}
