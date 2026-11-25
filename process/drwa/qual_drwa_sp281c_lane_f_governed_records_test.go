package drwa

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	statestub "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func qualFRecordReader(t *testing.T, read func([]byte) ([]byte, uint32, error)) *statestub.AccountsStub {
	t.Helper()
	account := &statestub.UserAccountStub{
		Address: bytes.Clone(core.SystemAccountAddress), RetrieveValueCalled: read,
		SaveKeyValueCalled: func([]byte, []byte) error {
			t.Fatal("read-only fixture must not save a key")
			return nil
		},
	}
	return &statestub.AccountsStub{
		GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			require.Equal(t, core.SystemAccountAddress, address)
			return account, nil
		},
		SaveAccountCalled: func(vmcommon.AccountHandler) error {
			t.Fatal("read-only fixture must not save an account")
			return nil
		},
	}
}

func TestQualSP281CFGovernedRecordConstruction(t *testing.T) {
	accounts := &statestub.AccountsStub{}
	clock := qualHeaderTimeOwner(t)
	source := qualClockSource(clock, accounts)
	boundary := &RollbackContainment{stores: []state.AccountsAdapter{accounts}}
	host := &qualGovernedActionHost{}
	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	domain := []byte("n")
	g, err := newGovernedActionRecords(accounts, boundary, m, h, 4096, domain, 2, 1, 1, host, source)
	require.NoError(t, err)
	domain[0] = 'x'
	require.Equal(t, []byte("n"), g.domain)

	_, err = newGovernedActionRecords(accounts, nil, m, h, 4096, domain, 2, 1, 1, host, source)
	require.ErrorIs(t, err, errGovernedActionRecord)
	_, err = newGovernedActionRecords(accounts, boundary, m, h, 4096, domain, 2, math.MaxUint64, 1, host, source)
	require.ErrorIs(t, err, errGovernedActionRecord)
	_, err = newGovernedActionRecords(accounts, boundary, m, h, 4096, domain, 3, 1, 1, host, source)
	require.ErrorIs(t, err, errGovernedActionRecord)
	_, err = newGovernedActionRecords(accounts, &RollbackContainment{}, m, h, 4096, domain, 2, 1, 1, host, source)
	require.ErrorIs(t, err, errGovernedActionRecord)
	_, err = newGovernedActionRecords(accounts, boundary, nil, h, 4096, domain, 2, 1, 1, host, source)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)

	at, release, err := g.lease(qualGovernedContext(t, clock, core.MetachainShardId, 105))
	require.NoError(t, err)
	require.Equal(t, HeaderMilliseconds(105), at)
	release()
	_, missingRelease, err := g.lease(nil)
	require.Error(t, err)
	require.Nil(t, missingRelease)
}

func TestQualSP281CFGovernedRecordProjectionLease(t *testing.T) {
	clock := qualHeaderTimeOwner(t)
	window, err := newGovernedActionWindow(qualGovernedContext(t, clock, core.MetachainShardId, 100), 5, 20, 105, 120)
	require.NoError(t, err)
	refusal := errors.New("fixture second acquire refused")
	acquires := 0
	context, err := clock.BeginBound(&block.MetaBlockV3{Epoch: 10, TimestampMs: 105}, func() (func(), error) {
		acquires++
		if acquires == 2 {
			return nil, refusal
		}
		return func() {}, nil
	}, func() error { return nil })
	require.NoError(t, err)
	expiry, err := window.projectionExpiry(context, 7)
	require.ErrorIs(t, err, refusal)
	require.Zero(t, expiry)
	require.Equal(t, 2, acquires)
}

func TestQualSP281CFGovernedRecordEnvelope(t *testing.T) {
	v := qualGASVectorsLoad(t)
	value := func(name string) []byte { return qualGASVectorBytes(t, v.Records[name].Hex) }
	g := &governedActionRecords{codec: qualB9Codec(t, nil).source, domain: []byte("n")}
	p := governedActionProposal{
		subject: []byte("program-subject"), class: []byte("synthetic-class"), token: []byte("TOKEN-abcdef"),
		payload: []byte("synthetic-complete-class-body"), bindings: []byte("synthetic-frozen-current-dependencies"),
		earliest: 105, until: 120,
	}
	raw, err := g.envelope(p, 100)
	require.NoError(t, err)
	require.Equal(t, value("envelope"), raw)
	digest, id := g.identity(raw, p)
	require.Equal(t, qualGASVectorBytes(t, v.Digests["payload"].Hex), digest)
	require.Equal(t, qualGASVectorBytes(t, v.Digests["id"].Hex), id)

	init, err := g.prepareInitialization(p.subject, p.class, p.token)
	require.NoError(t, err)
	require.Equal(t, qualRecordFrame([]byte("n"), []byte("program-subject"), []byte("synthetic-class")), init.identity)
	p.subject[0], p.class[0], p.token[0] = 'X', 'X', 'X'
	require.Equal(t, []byte("program-subject"), init.subject)
	require.Equal(t, []byte("synthetic-class"), init.class)
	require.Equal(t, []byte("TOKEN-abcdef"), init.token)
	p.payload = nil
	_, err = g.envelope(p, 100)
	require.ErrorIs(t, err, errGovernedActionRecord)
	_, err = g.prepareInitialization(nil, init.class, init.token)
	require.ErrorIs(t, err, errGovernedActionRecord)
	_, err = g.prepareInitialization(init.subject, init.class, []byte("bad-token"))
	require.ErrorIs(t, err, errGovernedActionRecord)
	g.codec.maxBytes = 24
	_, err = g.prepareInitialization(init.subject, init.class, init.token)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
}

func TestQualSP281CFGovernedRecordRead(t *testing.T) {
	v := qualGASVectorsLoad(t)
	id := qualGASVectorBytes(t, v.Digests["id"].Hex)
	actionKey := qualGASVectorBytes(t, v.Keys["action"])
	nonceKey := qualGASVectorBytes(t, v.Keys["nonce"])
	activeKey := qualGASVectorBytes(t, v.Keys["active"])
	value := func(name string) []byte { return qualGASVectorBytes(t, v.Records[name].Hex) }
	nonce := qualGASVectorBytes(t, v.Fixed["nonce1"])
	action, active := value("proposed"), value("active_ordinary")
	var readError error
	accounts := qualFRecordReader(t, func(key []byte) ([]byte, uint32, error) {
		switch string(key) {
		case string(actionKey):
			return action, 0, nil
		case string(nonceKey):
			return nonce, 0, readError
		case string(activeKey):
			return active, 0, readError
		default:
			t.Fatalf("unexpected record key %x", key)
			return nil, 0, nil
		}
	})
	codec := qualB9Codec(t, nil).source
	codec.state = &protectedState{accounts: accounts}
	g := &governedActionRecords{codec: codec, domain: []byte("n"), total: 2, ordinary: 1, protected: 1}
	statuses := []struct{ fixture, status string }{
		{"proposed", "PROPOSED"}, {"executable", "EXECUTABLE"}, {"local_started", "IN_PROGRESS"},
		{"armed", "IN_PROGRESS"}, {"expired", "EXPIRED"}, {"stale", "CANCELLED"},
	}
	for _, tt := range statuses {
		t.Run(tt.fixture, func(t *testing.T) {
			action = value(tt.fixture)
			r, key, raw, err := g.load(id)
			require.NoError(t, err)
			require.Equal(t, tt.status, r.status)
			require.Equal(t, actionKey, key)
			require.Equal(t, action, raw)
			encoded, err := g.encode(r)
			require.NoError(t, err)
			require.Equal(t, action, encoded)
			raw[0] = 0
			require.Equal(t, value(tt.fixture), action)
		})
	}
	parts := qualA38Split(value("proposed"))
	parts[3] = []byte{1}
	action = qualRecordFrame(parts...)
	protected, _, _, err := g.load(id)
	require.NoError(t, err)
	require.True(t, protected.protected)
	encoded, err := g.encode(protected)
	require.NoError(t, err)
	require.Equal(t, action, encoded)

	action = value("proposed")
	r, _, _, err := g.load(id)
	require.NoError(t, err)
	members, key, raw, err := g.active(r)
	require.NoError(t, err)
	require.Equal(t, []governedActionMember{{id: id}}, members)
	require.Equal(t, activeKey, key)
	require.Equal(t, active, raw)

	counter, err := g.counterSnapshot(r)
	require.NoError(t, err)
	require.Equal(t, governedActionWrite{nonceKey, nonce}, counter)
	require.NoError(t, g.unchanged(counter))
	nonce = qualGASVectorBytes(t, v.Fixed["nonce0"])
	require.ErrorIs(t, g.unchanged(counter), errGovernedActionRecord)
	_, _, _, err = g.load(id)
	require.ErrorIs(t, err, errGovernedActionRecord)
	nonce = nil
	_, _, _, err = g.load(id)
	require.ErrorIs(t, err, errGovernedActionRecord)
	nonce = qualGASVectorBytes(t, v.Fixed["nonce1"])

	readError = errors.New("fixture read refused")
	_, err = g.counterSnapshot(r)
	require.ErrorIs(t, err, readError)
	require.ErrorIs(t, g.unchanged(counter), readError)
	_, _, _, err = g.active(r)
	require.ErrorIs(t, err, readError)
	_, _, _, err = g.load(id)
	require.ErrorIs(t, err, readError)
	readError = nil
	for _, name := range []string{"active_empty", "active_protected"} {
		active = value(name)
		_, _, _, err = g.active(r)
		require.ErrorIs(t, err, errGovernedActionRecord)
	}
	active = nil
	_, _, _, err = g.active(r)
	require.ErrorIs(t, err, errGovernedActionRecord)
	r.proposal.token = nil
	members, key, raw, err = g.active(r)
	require.NoError(t, err)
	require.Empty(t, members)
	require.Nil(t, key)
	require.Nil(t, raw)

	for _, field := range []struct {
		name  string
		index int
		data  []byte
	}{
		{"wrong domain envelope", 0, qualRecordFrame([]byte("other-domain"))},
		{"detached digest", 1, bytes.Repeat([]byte{0}, 32)},
		{"unknown status", 2, []byte("UNKNOWN")},
		{"invalid category", 3, []byte{2}},
	} {
		t.Run(field.name, func(t *testing.T) {
			parts := qualA38Split(value("proposed"))
			parts[field.index] = field.data
			action = qualRecordFrame(parts...)
			_, _, _, err := g.load(id)
			require.ErrorIs(t, err, errGovernedActionRecord)
		})
	}
	action = bytes.Repeat([]byte{0}, codec.maxBytes+1)
	_, _, _, err = g.load(id)
	require.ErrorIs(t, err, errGovernedActionRecord)
	_, _, _, err = g.load(id[:1])
	require.ErrorIs(t, err, errGovernedActionRecord)
	codec.maxBytes = 1
	_, err = g.counterSnapshot(r)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	_, _, _, err = g.load(id)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	r.proposal.token = []byte("TOKEN-abcdef")
	_, _, _, err = g.active(r)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	codec.maxBytes = 4096

	unavailable := errors.New("fixture account unavailable")
	accounts.GetExistingAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return nil, unavailable }
	_, _, _, err = g.load(id)
	require.ErrorIs(t, err, unavailable)
}

func TestQualSP281CFGovernedRecordActiveIndex(t *testing.T) {
	v := qualGASVectorsLoad(t)
	g := &governedActionRecords{codec: qualB9Codec(t, nil).source, domain: []byte("n"), total: 2, ordinary: 1, protected: 1}
	id := qualGASVectorBytes(t, v.Digests["id"].Hex)
	second := bytes.Repeat([]byte{0xff}, len(id))
	for _, tt := range []struct {
		name    string
		members []governedActionMember
	}{
		{"empty", nil},
		{"ordinary", []governedActionMember{{id: id}}},
		{"protected", []governedActionMember{{id: id, protected: true}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			expected := qualGASVectorBytes(t, v.Records["active_"+tt.name].Hex)
			actual, err := g.aggregate(tt.members)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
			decoded, err := g.members(expected)
			require.NoError(t, err)
			require.Equal(t, len(tt.members), len(decoded))
			for i := range decoded {
				require.Equal(t, tt.members[i], decoded[i])
			}
		})
	}
	for _, tt := range []struct {
		name    string
		members []governedActionMember
	}{
		{"duplicate", []governedActionMember{{id: id}, {id: id, protected: true}}},
		{"descending", []governedActionMember{{id: second}, {id: id, protected: true}}},
		{"ordinary limit", []governedActionMember{{id: id}, {id: second}}},
		{"protected limit", []governedActionMember{{id: id, protected: true}, {id: second, protected: true}}},
		{"total limit", []governedActionMember{{id: id}, {id: second}, {id: second}}},
		{"ID width", []governedActionMember{{id: id[:1]}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := g.aggregate(tt.members)
			require.ErrorIs(t, err, errGovernedActionRecord)
		})
	}
	raw := qualGASVectorBytes(t, v.Records["active_ordinary"].Hex)
	for _, tt := range []struct {
		name        string
		index       int
		replacement []byte
		err         error
	}{
		{"count outside limit", 0, qualA38U64(3), errGovernedActionRecord},
		{"entry count mismatch", 0, qualA38U64(2), errInvalidRegistrationRecord},
		{"zero count with entry", 0, qualA38U64(0), errGovernedActionRecord},
		{"changed digest", 2, bytes.Repeat([]byte{0}, 32), errGovernedActionRecord},
		{"invalid nested category", 3, qualRecordFrame(qualRecordFrame(id, []byte{2})), errGovernedActionRecord},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fields := qualA38Split(raw)
			fields[tt.index] = tt.replacement
			_, err := g.members(qualRecordFrame(fields...))
			require.ErrorIs(t, err, tt.err)
		})
	}
	_, err := g.members(nil)
	require.ErrorIs(t, err, errGovernedActionRecord)
	g.codec.maxBytes = 35
	_, err = g.aggregate([]governedActionMember{{id: id}})
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	g.codec.maxBytes = 60
	_, err = g.aggregate([]governedActionMember{{id: id}, {id: second, protected: true}})
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
}

func TestQualSP281CFAuthorityBodyBounds(t *testing.T) {
	c := qualB9Codec(t, nil)
	raw := qualB9Bytes(t, "A_body")
	body, err := c.decode(raw)
	require.NoError(t, err)
	require.Equal(t, qualB9Bytes(t, "A_hash"), body.hash)

	tight, err := newAuthorityBodyCodec(c.source, authorityBodyBounds{len(raw), 256, 64, 10})
	require.NoError(t, err)
	_, err = tight.decode(raw)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	wrongWidth := *c.source
	wrongWidth.hasher = &testscommon.HasherStub{
		SizeCalled:    func() int { return 32 },
		ComputeCalled: func(string) []byte { return []byte{1} },
	}
	_, err = qualB9Codec(t, &wrongWidth).decode(raw)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)

	g6 := qualB9Bytes(t, "G6")
	for _, index := range []int{3, 4} {
		fields := qualA38Split(g6)
		fields[index] = nil
		_, err := c.decodeInitial(qualRecordFrame(fields...), []byte("admission\x00opaque"), []byte("independenté"))
		require.ErrorIs(t, err, errInvalidRegistrationRecord)
	}
}

func TestQualSP281CFAuthorityPurposeRecordData(t *testing.T) {
	c := qualB9Codec(t, nil)
	domain := []byte("fixture-domain")
	admission := []byte("admission\x00opaque")
	independent := []byte("independenté")
	appointment, err := c.decodeInitial(qualB9Bytes(t, "G6"), admission, independent)
	require.NoError(t, err)
	scope := qualRecordFrame(domain, bytes.Repeat([]byte{1}, 32), []byte("program"))
	s := &scopedAdmissionRecords{codec: c.source, domain: domain}
	records := map[string][]byte{}
	expected := make([]scopedAdmissionWrite, 0, 4)
	for _, tt := range []struct{ purpose, fixture string }{
		{"REGISTER_TOKEN_ADMISSION", "A_body"},
		{"REGISTER_TOKEN", "C_body"},
	} {
		raw := qualB9Bytes(t, tt.fixture)
		version := qualScopedHash("VERSION", scope, nil, raw)
		versionKey := append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@version@"), version...)
		current := qualScopedHash("SCOPE", scope, []byte(tt.purpose))
		currentKey := append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@current@"), current...)
		records[string(versionKey)] = qualRecordFrame(scope, nil, raw)
		records[string(currentKey)] = qualRecordFrame(scope, version)
		expected = append(expected, scopedAdmissionWrite{versionKey, records[string(versionKey)]},
			scopedAdmissionWrite{currentKey, records[string(currentKey)]})
	}
	writes, err := s.initialPurposeWrites(appointment)
	require.NoError(t, err)
	require.Equal(t, expected, writes)
	require.NotEqual(t, writes[1].key, writes[3].key)
	_, err = s.authorityPurposeKey(scope, "OTHER")
	require.ErrorIs(t, err, errScopedAdmission)
	c.source.maxBytes = len(scope) + len(qualB9Bytes(t, "A_body"))
	_, err = s.initialPurposeWrites(appointment)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	c.source.maxBytes = 4096

	accounts := qualFRecordReader(t, func(key []byte) ([]byte, uint32, error) {
		return records[string(key)], 0, nil
	})
	c.source.state = &protectedState{accounts: accounts}
	clock := qualHeaderTimeOwner(t)
	s.timeSource = qualClockSource(clock, accounts)
	context := qualGovernedContext(t, clock, core.MetachainShardId, 105)
	body, current, err := s.readAuthorityPurposeHead(context, appointment.owner, appointment.programme, "REGISTER_TOKEN_ADMISSION", admission, c)
	require.NoError(t, err)
	require.Equal(t, qualB9Bytes(t, "A_hash"), body.hash)
	require.Equal(t, qualScopedHash("VERSION", scope, nil, qualB9Bytes(t, "A_body")), current)
	other, err := s.inspectAuthorityPurposeHead(context, appointment.owner, appointment.programme, "REGISTER_TOKEN", independent, c)
	require.NoError(t, err)
	require.Equal(t, qualB9Bytes(t, "C_hash"), other.hash)

	_, err = s.inspectAuthorityPurposeHead(context, appointment.owner, appointment.programme, "REGISTER_TOKEN", admission, c)
	require.ErrorIs(t, err, errScopedAdmission)
	_, err = s.inspectAuthorityPurposeHead(context, nil, appointment.programme, "REGISTER_TOKEN", independent, c)
	require.ErrorIs(t, err, errScopedAdmission)
	_, err = s.inspectAuthorityPurposeHead(context, appointment.owner, appointment.programme, "OTHER", independent, c)
	require.ErrorIs(t, err, errScopedAdmission)
	_, err = s.inspectAuthorityPurposeHead(context, appointment.owner, appointment.programme, "REGISTER_TOKEN", nil, c)
	require.ErrorIs(t, err, errScopedAdmission)

	key := string(expected[0].key)
	for _, tt := range []struct {
		name string
		raw  []byte
	}{
		{"missing version", nil},
		{"wrong outer scope", qualRecordFrame([]byte("other"), nil, qualB9Bytes(t, "A_body"))},
		{"wrong outer digest", qualRecordFrame(scope, nil, qualB9Bytes(t, "C_body"))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			records[key] = tt.raw
			_, err := s.inspectAuthorityPurposeHead(context, appointment.owner, appointment.programme, "REGISTER_TOKEN_ADMISSION", admission, c)
			require.ErrorIs(t, err, errScopedAdmission)
		})
	}
	currentKey := string(expected[1].key)
	records[currentKey] = nil
	_, err = s.inspectAuthorityPurposeHead(context, appointment.owner, appointment.programme, "REGISTER_TOKEN_ADMISSION", admission, c)
	require.ErrorIs(t, err, errScopedAdmission)
}

func TestQualSP281CFAuthorityPurposeFrameRefusal(t *testing.T) {
	c := qualB9Codec(t, nil)
	domain := []byte("fixture-domain")
	appointment, err := c.decodeInitial(qualB9Bytes(t, "G6"), []byte("admission\x00opaque"), []byte("independenté"))
	require.NoError(t, err)
	scope := qualRecordFrame(domain, bytes.Repeat([]byte{1}, 32), []byte("program"))
	raw := qualB9Bytes(t, "A_body")
	version := qualScopedHash("VERSION", scope, nil, raw)
	for _, tt := range []struct {
		name string
		wire []byte
	}{
		{"VERSION frame", qualRecordFrame(scope, nil, raw)},
		{"pointer frame", qualRecordFrame(scope, version)},
		{"purpose key preimage", qualRecordFrame([]byte("DRWA/SCOPED_ADMISSION/SCOPE/candidate1"), domain, scope, []byte("REGISTER_TOKEN_ADMISSION"))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			refusal := errors.New("fixture marshal refused")
			local := *c.source
			local.marshaller = &marshallerMock.MarshalizerStub{
				MarshalCalled: func(value interface{}) ([]byte, error) {
					wire, err := c.source.marshaller.Marshal(value)
					if err == nil && bytes.Equal(wire, tt.wire) {
						return nil, refusal
					}
					return wire, err
				},
			}
			s := &scopedAdmissionRecords{codec: &local, domain: domain}
			writes, err := s.initialPurposeWrites(appointment)
			require.ErrorIs(t, err, refusal)
			require.Nil(t, writes)
		})
	}
}

func TestQualSP281CFAuthorityPurposePredecessorData(t *testing.T) {
	c := qualB9Codec(t, nil)
	domain := []byte("fixture-domain")
	owner := bytes.Repeat([]byte{1}, 32)
	programme := []byte("program")
	role := []byte("independenté")
	scope := qualRecordFrame(domain, owner, programme)
	const purpose = "REGISTER_TOKEN"
	currentKey := string(append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@current@"), qualScopedHash("SCOPE", scope, []byte(purpose))...))
	versionKey := func(id []byte) string {
		return string(append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@version@"), id...))
	}
	original := qualB9Bytes(t, "C_body")
	previous := qualScopedHash("VERSION", scope, nil, original)
	next := qualA38Split(original)
	next[2], next[7], next[8] = qualA38U64(9), qualA38U64(1), qualB9Bytes(t, "C_hash")
	nextRaw := qualRecordFrame(next...)

	records := map[string][]byte{}
	setHead := func(predecessor, raw []byte) []byte {
		id := qualScopedHash("VERSION", scope, predecessor, raw)
		records[versionKey(id)] = qualRecordFrame(scope, predecessor, raw)
		records[currentKey] = qualRecordFrame(scope, id)
		return id
	}
	accounts := qualFRecordReader(t, func(key []byte) ([]byte, uint32, error) {
		return records[string(key)], 0, nil
	})
	c.source.state = &protectedState{accounts: accounts}
	clock := qualHeaderTimeOwner(t)
	s := &scopedAdmissionRecords{codec: c.source, domain: domain, timeSource: qualClockSource(clock, accounts)}
	context := qualGovernedContext(t, clock, core.MetachainShardId, 105)
	records[versionKey(previous)] = qualRecordFrame(scope, nil, original)
	id := setHead(previous, nextRaw)
	body, ref, err := s.readAuthorityPurposeHead(context, owner, programme, purpose, role, c)
	require.NoError(t, err)
	require.Equal(t, id, ref)
	require.Equal(t, nextRaw, body.raw)
	require.Equal(t, qualA38U64(9), body.version)

	for _, tt := range []struct {
		name             string
		predecessor, raw []byte
	}{
		{"missing predecessor", bytes.Repeat([]byte{0}, 32), nextRaw},
		{"outer root with body predecessor", nil, nextRaw},
		{"outer predecessor with root body", previous, original},
		{"historical unknown body", nil, []byte("unknown body")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setHead(tt.predecessor, tt.raw)
			_, _, err := s.readAuthorityPurposeHead(context, owner, programme, purpose, role, c)
			require.Error(t, err)
		})
	}
	setHead(previous, nextRaw)
	records[versionKey(previous)] = qualRecordFrame(scope, nil, qualB9Bytes(t, "A_body"))
	_, _, err = s.readAuthorityPurposeHead(context, owner, programme, purpose, role, c)
	require.ErrorIs(t, err, errScopedAdmission)
	historical := []byte("unknown previous body")
	historicalID := qualScopedHash("VERSION", scope, nil, historical)
	records[versionKey(historicalID)] = qualRecordFrame(scope, nil, historical)
	setHead(historicalID, nextRaw)
	_, _, err = s.readAuthorityPurposeHead(context, owner, programme, purpose, role, c)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	shard := qualGovernedContext(t, clock, 1, 105)
	_, _, err = s.readAuthorityPurposeHead(shard, owner, programme, purpose, role, c)
	require.ErrorIs(t, err, errScopedAdmission)
	clock.End(shard)
	_, _, err = s.readAuthorityPurposeHead(context, owner, programme, purpose, role, c)
	require.ErrorIs(t, err, ErrInactiveHeaderTime)
}
