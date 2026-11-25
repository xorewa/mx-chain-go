package drwa

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	statemock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFRecordPendingCodec(t *testing.T) {
	var vectors struct {
		qualGASVectors
		Malformed map[string]string
	}
	require.NoError(t, json.Unmarshal([]byte(qualPendingFinalIndependentVectors), &vectors))
	initial := vectors.Records["initial"]
	want := qualGASVectorBytes(t, initial.Hex)
	digest := qualGASVectorBytes(t, vectors.Digests["initial"].Hex)
	nextDigest := qualGASVectorBytes(t, vectors.Digests["successor"].Hex)
	candidate := pendingFinalCandidate{
		key: qualGASVectorBytes(t, initial.Fields[0]), body: qualGASVectorBytes(t, initial.Fields[3]),
		origin: qualGASVectorBytes(t, initial.Fields[4]),
	}
	codec := &registrationRecords{
		marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 4096,
	}
	records := &pendingFinalRecords{codec: codec}
	encoded, err := records.encode(candidate)
	require.NoError(t, err)
	require.Equal(t, want, encoded)
	require.Equal(t, digest, codec.hasher.Compute(string(encoded)))
	require.NoError(t, records.decode(want, candidate.key))
	require.ErrorIs(t, records.decode(want, []byte("different record")), errPendingFinal)
	for name, malformed := range vectors.Malformed {
		t.Run(name, func(t *testing.T) {
			require.Error(t, records.decode(qualGASVectorBytes(t, malformed), candidate.key))
		})
	}

	key, err := records.key("final", candidate.key)
	require.NoError(t, err)
	require.Equal(t, qualGASVectorBytes(t, vectors.Keys["final"]), key)
	_, err = records.key("final", make([]byte, codec.maxBytes+1))
	require.ErrorIs(t, err, errInvalidRegistrationRecord)

	list, err := records.decodeOriginItems(qualRecordFrame(digest, nextDigest))
	require.NoError(t, err)
	require.Equal(t, [][]byte{digest, nextDigest}, list)
	for name, raw := range map[string][]byte{
		"duplicate": qualRecordFrame(digest, digest),
		"short":     qualRecordFrame(digest[:len(digest)-1]),
		"empty":     nil,
		"oversized": make([]byte, codec.maxBytes+1),
		"truncated": {0x0a},
	} {
		t.Run("manifest/"+name, func(t *testing.T) {
			items, err := records.decodeOriginItems(raw)
			require.Error(t, err)
			require.Nil(t, items)
		})
	}

	operation, err := records.prepareStage(candidate)
	require.NoError(t, err)
	require.NotNil(t, operation)

	proof := []byte("inert proof bytes")
	prepared, err := records.preparePromotion(candidate, proof)
	require.NoError(t, err)
	candidate.key[0] ^= 1
	candidate.origin[0] ^= 1
	proof[0] ^= 1
	require.Equal(t, want, prepared.encoded)
	require.Equal(t, qualGASVectorBytes(t, initial.Fields[0]), prepared.candidate.key)
	require.Equal(t, qualGASVectorBytes(t, initial.Fields[4]), prepared.candidate.origin)
	require.Equal(t, []byte("inert proof bytes"), prepared.evidence)

	require.ErrorIs(t, records.stage(pendingFinalCandidate{}), errPendingFinal)
	require.ErrorIs(t, records.promote(prepared.candidate, nil), errPendingFinal)
	require.ErrorIs(t, records.promote(prepared.candidate, make([]byte, codec.maxBytes+1)), errPendingFinal)
	require.ErrorIs(t, records.promoteResult(nil, nil, 1, codec.maxBytes), errPendingFinal)
}

func TestQualSP281CLaneFRecordPendingRead(t *testing.T) {
	readerFailure := errors.New("inert protected record read failure")
	lookupFailure := errors.New("inert system account lookup failure")
	logicalKey := []byte("record")
	storedKey := append([]byte(core.ProtectedKeyPrefix+"DRWA@head@final@"), qualRecordFrame(logicalKey)...)
	raw := qualRecordFrame(logicalKey, make([]byte, 8), nil, []byte("body"), []byte("origin"))
	marshaller, hasher := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	tests := []struct {
		name        string
		value       []byte
		lookupError error
		readError   error
		wantError   error
	}{
		{name: "retained", value: raw},
		{name: "absent"},
		{name: "different logical key", value: qualRecordFrame([]byte("other"), make([]byte, 8), nil, []byte("body"), []byte("origin")), wantError: errPendingFinal},
		{name: "oversized", value: make([]byte, 129), wantError: errPendingFinal},
		{name: "lookup failure", lookupError: lookupFailure, wantError: lookupFailure},
		{name: "read failure", readError: readerFailure, wantError: readerFailure},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			account := &statemock.UserAccountStub{Address: core.SystemAccountAddress,
				RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
					require.Equal(t, storedKey, key)
					return tc.value, 0, tc.readError
				},
			}
			accounts := &statemock.AccountsStub{GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
				require.Equal(t, core.SystemAccountAddress, address)
				return account, tc.lookupError
			}}
			r := &pendingFinalRecords{codec: &registrationRecords{
				state: &protectedState{accounts: accounts}, marshaller: marshaller, hasher: hasher, maxBytes: 128,
			}}
			actual, commitment, err := r.final(logicalKey)
			if tc.wantError != nil {
				require.ErrorIs(t, err, tc.wantError)
				require.Nil(t, actual)
				require.Nil(t, commitment)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.value, actual)
			if len(actual) == 0 {
				require.Nil(t, commitment)
				return
			}
			require.Equal(t, hasher.Compute(string(raw)), commitment)
			actual[0] ^= 1
			require.Equal(t, byte(0x0a), raw[0])
		})
	}
}

func TestQualSP281CLaneFRecordReadConsistency(t *testing.T) {
	c := pendingFinalCandidate{key: []byte("record"), origin: []byte("origin"), body: []byte("body")}
	hasher := blake2b.NewBlake2b()
	raw := qualRecordFrame(c.key, make([]byte, 8), nil, c.body, c.origin)
	digest := hasher.Compute(string(raw))
	prefix := core.ProtectedKeyPrefix + "DRWA@head@"
	pending := prefix + "pending@" + string(qualRecordFrame(c.key))
	item := prefix + "item@" + string(qualRecordFrame(c.origin, c.key))
	origin := prefix + "origin@" + string(qualRecordFrame(c.origin))
	values := map[string][]byte{pending: raw, item: digest, origin: qualRecordFrame(digest)}
	account := &statemock.UserAccountStub{Address: core.SystemAccountAddress,
		RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
			return values[string(key)], 0, nil
		},
	}
	accounts := &statemock.AccountsStub{GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		require.Equal(t, core.SystemAccountAddress, address)
		return account, nil
	}}
	codec := &registrationRecords{
		state: &protectedState{accounts: accounts}, marshaller: &marshal.GogoProtoMarshalizer{},
		hasher: hasher, maxBytes: 128,
	}
	r := &pendingFinalRecords{codec: codec}
	require.NoError(t, r.check(c, raw, false))
	require.ErrorIs(t, r.check(c, raw, true), errPendingFinal)
	_, _, err := r.final(nil)
	require.ErrorIs(t, err, errPendingFinal)
	_, _, err = r.final(make([]byte, codec.maxBytes+1))
	require.ErrorIs(t, err, errInvalidRegistrationRecord)

	verify := func() error { return nil }
	refusal := errors.New("inert callback refusal")
	require.NoError(t, r.verifyStates([]pendingFinalCandidate{c}, verify))
	require.ErrorIs(t, r.verifyStates([]pendingFinalCandidate{c}, func() error {
		return refusal
	}), refusal)
	s := &scopedAdmissionRecords{codec: codec, limits: scopedAdmissionLimits{recordBytes: 128}}
	require.NoError(t, s.verifyState([][]byte{[]byte(pending)}, verify))
	require.ErrorIs(t, s.verifyState([][]byte{[]byte(pending)}, func() error {
		return refusal
	}), refusal)

	// Change the stub's returned value only. These reads never open a journal.
	require.ErrorIs(t, r.verifyStates([]pendingFinalCandidate{c}, func() error {
		delete(values, item)
		return nil
	}), errPendingFinal)
	require.ErrorIs(t, r.check(c, raw, false), errPendingFinal)
	require.ErrorIs(t, s.verifyState([][]byte{[]byte(pending)}, func() error {
		delete(values, pending)
		return nil
	}), errScopedAdmission)
}

func TestQualSP281CLaneFRecordOriginManifestRead(t *testing.T) {
	digest := bytes.Repeat([]byte{1}, 32)
	origin := []byte("origin")
	key := append([]byte(core.ProtectedKeyPrefix+"DRWA@head@origin@"), qualRecordFrame(origin)...)
	raw := qualRecordFrame(digest)
	readFailure := errors.New("inert manifest read failure")
	for _, tc := range []struct {
		name string
		raw  []byte
		err  error
	}{
		{name: "ordered manifest", raw: raw},
		{name: "absent"},
		{name: "unavailable", err: readFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := &statemock.UserAccountStub{Address: core.SystemAccountAddress,
				RetrieveValueCalled: func(actual []byte) ([]byte, uint32, error) {
					require.Equal(t, key, actual)
					return tc.raw, 0, tc.err
				},
			}
			accounts := &statemock.AccountsStub{GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
				require.Equal(t, core.SystemAccountAddress, address)
				return account, nil
			}}
			records := &pendingFinalRecords{codec: &registrationRecords{
				state: &protectedState{accounts: accounts}, marshaller: &marshal.GogoProtoMarshalizer{},
				hasher: blake2b.NewBlake2b(), maxBytes: 128,
			}}
			actual, err := records.originItems(origin)
			require.ErrorIs(t, err, tc.err)
			if tc.raw == nil {
				require.Nil(t, actual)
			} else {
				require.Equal(t, [][]byte{digest}, actual)
			}
			_, err = records.originItems(make([]byte, 129))
			require.ErrorIs(t, err, errInvalidRegistrationRecord)
		})
	}
}

func TestQualSP281CLaneFRecordScopedDecision(t *testing.T) {
	codec := &registrationRecords{
		marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 512,
	}
	s := &scopedAdmissionRecords{codec: codec, domain: []byte("fixture-domain"), limits: scopedAdmissionLimits{recordBytes: 512}}
	d := scopedAdmissionDecision{
		owner: bytes.Repeat([]byte{1}, len(core.SystemAccountAddress)), program: []byte("programme"),
		issuer: bytes.Repeat([]byte{2}, len(core.SystemAccountAddress)), version: []byte("version"),
		commitment: []byte("intent"), authority: bytes.Repeat([]byte{3}, codec.hasher.Size()), validUntil: 257,
	}
	expectedScope := qualRecordFrame([]byte("fixture-domain"), d.owner, d.program)
	scope, body, err := s.decisionBody(d)
	require.NoError(t, err)
	require.Equal(t, expectedScope, scope)
	require.Equal(t, qualRecordFrame(expectedScope, d.issuer, d.version, d.commitment, d.authority, []byte{0, 0, 0, 0, 0, 0, 1, 1}), body)
	id, err := s.decisionID(scope, d)
	require.NoError(t, err)
	require.Equal(t, qualScopedHash("DECISION", expectedScope, d.issuer, d.version), id)

	changed := d
	changed.commitment = []byte("other intent")
	_, changedBody, err := s.decisionBody(changed)
	require.NoError(t, err)
	require.NotEqual(t, body, changedBody)
	changedID, err := s.decisionID(scope, changed)
	require.NoError(t, err)
	require.Equal(t, id, changedID)
	changed.version = []byte("other version")
	newID, err := s.decisionID(scope, changed)
	require.NoError(t, err)
	require.NotEqual(t, id, newID)

	t.Run("bootstrap decoder", func(t *testing.T) {
		approval, err := newRegistrationApprovalCodec(codec, registrationApprovalBounds{
			bytes: 512, fieldBytes: 256, roleBytes: 64, familyBytes: 64, maxMembers: 8, maxValidity: 100,
		})
		require.NoError(t, err)
		intent := bootstrapIntentBody{
			networkDomain: []byte("fixture-domain"), issuer: d.issuer, programID: d.program,
			issuerProgramAdmissionDecision: qualRecordFrame(expectedScope, d.issuer, d.version, d.commitment, d.authority, []byte{0, 0, 0, 0, 0, 0, 1, 1}),
		}
		decision, actualScope, err := approval.decodeBootstrapAdmissionDecision(s, intent, d.owner)
		require.NoError(t, err)
		require.Equal(t, d, decision)
		require.Equal(t, expectedScope, actualScope)
		intent.programID = []byte("other programme")
		_, actualScope, err = approval.decodeBootstrapAdmissionDecision(s, intent, d.owner)
		require.ErrorIs(t, err, errScopedAdmission)
		require.Nil(t, actualScope)
	})

	malformed := d
	malformed.issuer = nil
	_, _, err = s.decisionBody(malformed)
	require.ErrorIs(t, err, errScopedAdmission)
	require.ErrorIs(t, s.install(nil, nil, nil, nil, nil, nil), errScopedAdmission)
	require.ErrorIs(t, s.admit(nil, d, nil), errScopedAdmission)
	require.ErrorIs(t, s.withdraw(nil, d, nil), errScopedAdmission)
	require.ErrorIs(t, s.checkDecisionAt(nil, d, nil), errScopedAdmission)
	release, err := scopedAdmissionLease(nil)
	require.ErrorIs(t, err, errScopedAdmission)
	require.Nil(t, release)
	require.ErrorIs(t, s.installInitialPurposePair(nil, nil, nil, nil, nil, nil, nil, nil, nil), errScopedAdmission)
	var unbound *scopedAdmissionRecords
	require.ErrorIs(t, unbound.installInitialPurposePairOwned(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil), errScopedAdmission)
}

func TestQualSP281CLaneFRecordScopedRead(t *testing.T) {
	readFailure := errors.New("inert scoped record read failure")
	codec := &registrationRecords{
		marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 256,
	}
	s := &scopedAdmissionRecords{codec: codec, domain: []byte("fixture-domain"),
		limits: scopedAdmissionLimits{recordBytes: 256, records: 4, retainedBytes: 256, newRecordsPerEpoch: 2}}
	scope := qualRecordFrame([]byte("fixture-domain"), bytes.Repeat([]byte{1}, len(core.SystemAccountAddress)), []byte("programme"))
	version := []byte("version body")
	id := qualScopedHash("VERSION", scope, nil, version)
	pointerKey := append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@current@"), qualScopedHash("SCOPE", scope)...)
	versionKey := append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@version@"), id...)
	pointer := qualRecordFrame(scope, id)
	versionRecord := qualRecordFrame(scope, nil, version)

	for _, tc := range []struct {
		name    string
		pointer []byte
		version []byte
		errorAt []byte
		want    error
	}{
		{name: "current", pointer: pointer, version: versionRecord},
		{name: "pointer absent", want: errScopedAdmission},
		{name: "version absent", pointer: pointer, want: errScopedAdmission},
		{name: "pointer read error", errorAt: pointerKey, want: readFailure},
		{name: "version read error", pointer: pointer, errorAt: versionKey, want: readFailure},
		{name: "version mismatch", pointer: pointer, version: qualRecordFrame(scope, nil, []byte("other body")), want: errScopedAdmission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := &statemock.UserAccountStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
				switch {
				case bytes.Equal(key, tc.errorAt):
					return nil, 0, readFailure
				case bytes.Equal(key, pointerKey):
					return tc.pointer, 0, nil
				default:
					require.Equal(t, versionKey, key)
					return tc.version, 0, nil
				}
			}}
			actual, err := s.current(account, scope)
			require.ErrorIs(t, err, tc.want)
			if tc.want == nil {
				require.Equal(t, id, actual)
			} else {
				require.Nil(t, actual)
			}
		})
	}

	budgetKey := []byte(core.ProtectedKeyPrefix + "DRWA@scopedAdmission@budget")
	budget := make([]byte, 32)
	binary.BigEndian.PutUint64(budget, 1)
	binary.BigEndian.PutUint64(budget[8:], uint64(len(budgetKey)+len(budget)))
	binary.BigEndian.PutUint64(budget[16:], 3)
	binary.BigEndian.PutUint64(budget[24:], 1)
	account := &statemock.UserAccountStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
		require.Equal(t, budgetKey, key)
		return budget, 0, nil
	}}
	accepted, err := s.retainedBudget(account, 3)
	require.NoError(t, err)
	require.Equal(t, budget, accepted)
	_, err = s.retainedBudget(account, 2)
	require.ErrorIs(t, err, errScopedAdmission)
	budget = budget[:31]
	_, err = s.retainedBudget(account, 3)
	require.ErrorIs(t, err, errScopedAdmission)
	account.RetrieveValueCalled = func([]byte) ([]byte, uint32, error) { return nil, 0, readFailure }
	_, err = s.retainedBudget(account, 3)
	require.ErrorIs(t, err, readFailure)
	require.ErrorIs(t, s.retainRecords(account, 3, false,
		scopedAdmissionWrite{key: []byte(core.ProtectedKeyPrefix + "DRWA@scopedAdmission@initial@fixture")}), errScopedAdmission)
}

func TestQualSP281CLaneFRecordConstruction(t *testing.T) {
	accounts := &statemock.AccountsStub{}
	owner := &RollbackContainment{stores: []state.AccountsAdapter{accounts}}
	unowned := &RollbackContainment{}
	marshaller, hasher := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	host := &qualPendingFinalHost{}
	_, err := newPendingFinalRecords(accounts, nil, marshaller, hasher, 256, host)
	require.ErrorIs(t, err, errPendingFinal)
	_, err = newPendingFinalRecords(accounts, unowned, marshaller, hasher, 256, host)
	require.ErrorIs(t, err, errPendingFinal)
	_, err = newPendingFinalRecords(accounts, owner, nil, hasher, 256, host)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	pending, err := newPendingFinalRecords(accounts, owner, marshaller, hasher, 256, host)
	require.NoError(t, err)
	require.Same(t, accounts, pending.codec.state.accounts)

	timeSource := qualClockSource(qualHeaderTimeOwner(t), accounts)
	mandates := &qualScopedMandates{}
	limits := scopedAdmissionLimits{recordBytes: 256, records: 4, retainedBytes: 256, newRecordsPerEpoch: 2}
	domain := []byte("fixture-domain")
	_, err = newScopedAdmissionRecords(accounts, owner, marshaller, hasher, domain, limits, mandates, nil)
	require.ErrorIs(t, err, errScopedAdmission)
	_, err = newScopedAdmissionRecords(accounts, unowned, marshaller, hasher, domain, limits, mandates, timeSource)
	require.ErrorIs(t, err, errScopedAdmission)
	_, err = newScopedAdmissionRecords(accounts, owner, nil, hasher, domain, limits, mandates, timeSource)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	_, err = newScopedAdmissionRecords(accounts, owner, marshaller, hasher, make([]byte, limits.recordBytes+1), limits, mandates, timeSource)
	require.ErrorIs(t, err, errScopedAdmission)
	scoped, err := newScopedAdmissionRecords(accounts, owner, marshaller, hasher, domain, limits, mandates, timeSource)
	require.NoError(t, err)
	domain[0] ^= 1
	require.Equal(t, []byte("fixture-domain"), scoped.domain)
}
