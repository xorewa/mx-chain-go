package drwa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
)

// Public test inputs from Go standard Ed25519 through the existing test helper.
// No native signer/encoder or authority source produces these expectations.
// This input capture earns no native authentication or behavioural credit.
func TestQualB9G6IndependentPublicInputs(t *testing.T) {
	groups := make(map[string][]string)
	for i, name := range []string{"A", "C", "PA"} {
		keys, _ := qualA38Keys(byte(i))
		require.Len(t, keys, 5)
		for _, key := range keys {
			groups[name] = append(groups[name], hex.EncodeToString(key))
		}
	}
	raw, err := json.Marshal(groups)
	require.NoError(t, err)
	fmt.Printf("B9_PUBLIC_INPUTS=%s\n", raw)
}

// Independent Python framing/hash literals; see retained chronology correction.
var qualB9Vectors = map[string]string{
	"A_body":  "0a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0a208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940a20ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10a20ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0a206e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf10a3d0a1061646d697373696f6e006f70617175650a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a00",
	"A_hash":  "b5754ab9a4f27599a70b544c66da6dc8dfe06b7c68ee97c4121ec8c94abb3f47",
	"C_body":  "0a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2042424242424242424242424242424242424242424242424242424242424242420a0800000000000000010a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370a20204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c210a2066cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf76330a2020828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f70a20d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da0a3a0a0d696e646570656e64656e74c3a90a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a00",
	"C_hash":  "d49b7f1cf237c75abff4bc6270c666d9688d32d550ba07c9be1a6b0b6dd144e0",
	"PA_body": "0a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2043434343434343434343434343434343434343434343434343434343434343430a0800000000000000020a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a20884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b0a20a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f00a2074f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa90a2058936604abda112bc94933569c82f8d0cc0ddf92a3f8329f2f448f7f484a594c0a20bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a60a4d0a2050726f6772616d2041646d696e697374726174696f6e20417574686f726974790a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a00",
	"PA_hash": "bb7781ae5698dfa9a1cc4603d4a19c875355536e6853d7373bbafbe69143e0eb",
	"G6":      "0a2d445257412f494e495449414c5f50524f4752414d4d455f4150504f494e544d454e542f63616e646964617465310a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0add020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0a208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940a20ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10a20ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0a206e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf10a3d0a1061646d697373696f6e006f70617175650a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000ada020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2042424242424242424242424242424242424242424242424242424242424242420a0800000000000000010a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370a20204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c210a2066cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf76330a2020828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f70a20d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da0a3a0a0d696e646570656e64656e74c3a90a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000a20abababababababababababababababababababababababababababababababab",
}

func qualB9Bytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(qualB9Vectors[name])
	require.NoError(t, err)
	return raw
}
func qualB9Codec(t *testing.T, records *registrationRecords) *authorityBodyCodec {
	t.Helper()
	if records == nil {
		records = &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 4096}
	}
	c, err := newAuthorityBodyCodec(records, authorityBodyBounds{4096, 2048, 64, 10})
	require.NoError(t, err)
	return c
}
func qualB9Valid(t *testing.T, c *authorityBodyCodec) {
	t.Helper()
	for index, name := range []string{"A", "C", "PA"} {
		b, err := c.decode(qualB9Bytes(t, name+"_body"))
		require.NoError(t, err)
		require.Equal(t, qualB9Bytes(t, name+"_hash"), b.hash)
		expectedMembers, _ := qualA38Keys(byte(index))
		expectedRoles := [][]byte{[]byte("admission\x00opaque"), []byte("independent\xc3\xa9"), []byte("Program Administration Authority")}
		require.Equal(t, expectedMembers, b.members)
		require.Equal(t, expectedRoles[index], b.role)
		require.Equal(t, bytes.Repeat([]byte{byte(65 + index)}, 32), b.id)
		require.Equal(t, qualA38U64(uint64(index)), b.version)
		require.Equal(t, uint64(3), b.threshold)
		require.Equal(t, bytes.Repeat([]byte{1}, 32), b.owner)
		require.Equal(t, []byte("program"), b.programme)
		require.Empty(t, b.predecessorVersion)
		require.Empty(t, b.predecessorHash)

	}
}
func TestQualB9BodyAndIntentBinding(t *testing.T) {
	c := qualB9Codec(t, nil)
	qualB9Valid(t, c)
	a, err := c.decode(qualB9Bytes(t, "A_body"))
	require.NoError(t, err)
	require.Equal(t, qualA38U64(0), a.version)
	require.Equal(t, uint64(3), a.threshold)
	pa, err := c.decode(qualB9Bytes(t, "PA_body"))
	require.NoError(t, err)
	original := bootstrapIntentBody{proposedProgramAuthoritySetBodies: [][]byte{a.raw, pa.raw}, proposedProgramAuthoritySetHashes: [][]byte{a.hash, pa.hash}}
	got, err := c.selectIntentPA(original, pa.owner, pa.programme)
	require.NoError(t, err)
	require.Equal(t, pa.members, got.members)
	require.Equal(t, pa.version, got.version)
	for _, name := range []string{"hash", "duplicate_pa", "unknown_schema", "missing_pa", "wrong_scope"} {
		t.Run(name, func(t *testing.T) {
			x := original
			x.proposedProgramAuthoritySetBodies = append([][]byte(nil), original.proposedProgramAuthoritySetBodies...)
			x.proposedProgramAuthoritySetHashes = append([][]byte(nil), original.proposedProgramAuthoritySetHashes...)
			owner := pa.owner
			switch name {
			case "hash":
				x.proposedProgramAuthoritySetHashes[1] = bytes.Repeat([]byte{1}, 32)
			case "duplicate_pa":
				x.proposedProgramAuthoritySetBodies = append(x.proposedProgramAuthoritySetBodies, pa.raw)
				x.proposedProgramAuthoritySetHashes = append(x.proposedProgramAuthoritySetHashes, pa.hash)
			case "unknown_schema":
				x.proposedProgramAuthoritySetBodies[0] = []byte("opaque historical body")
			case "missing_pa":
				x.proposedProgramAuthoritySetBodies = x.proposedProgramAuthoritySetBodies[:1]
				x.proposedProgramAuthoritySetHashes = x.proposedProgramAuthoritySetHashes[:1]
			case "wrong_scope":
				owner = bytes.Repeat([]byte{9}, 32)
			}
			_, err := c.selectIntentPA(x, owner, pa.programme)
			require.Error(t, err)
			_, err = c.selectIntentPA(original, pa.owner, pa.programme)
			require.NoError(t, err, "restored independently valid intent neighbour")
		})
	}
	for _, name := range []string{"count8", "count10", "tag", "scheme", "version_missing", "version9", "threshold_width", "threshold2", "threshold6", "members4", "duplicate_key", "bad_key", "scope_count", "role_missing", "owner_width", "program_missing", "pred_half", "pred_width", "nonshort", "extra_unknown", "oversize"} {
		t.Run(name, func(t *testing.T) {
			qualB9Valid(t, c)
			raw := qualB9Bytes(t, "A_body")
			f := qualA38Split(raw)
			switch name {
			case "count8":
				f = f[:8]
			case "count10":
				f = append(f, nil)
			case "tag":
				f[0] = []byte("unsupported-body-schema")
			case "scheme":
				f[3] = []byte("BLS")
			case "version_missing":
				f[2] = nil
			case "version9":
				f[2] = append(f[2], 0)
			case "threshold_width":
				f[4] = f[4][1:]
			case "threshold2":
				f[4] = qualA38U64(2)
			case "threshold6":
				f[4] = qualA38U64(6)
			case "members4", "duplicate_key", "bad_key":
				m := qualA38Split(f[5])
				if name == "members4" {
					m = m[:4]
				}
				if name == "duplicate_key" {
					m[1] = m[0]
				}
				if name == "bad_key" {
					m[0] = []byte{1}
				}
				f[5] = qualRecordFrame(m...)
			case "scope_count", "role_missing", "owner_width", "program_missing":
				scope := qualA38Split(f[6])
				switch name {
				case "scope_count":
					scope = scope[:2]
				case "role_missing":
					scope[0] = nil
				case "owner_width":
					scope[1] = scope[1][1:]
				case "program_missing":
					scope[2] = nil
				}
				f[6] = qualRecordFrame(scope...)
			case "pred_half":
				f[7] = qualA38U64(1)
			case "pred_width":
				f[7] = qualA38U64(1)
				f[8] = []byte{1}
			}
			raw = qualRecordFrame(f...)
			switch name {
			case "nonshort":
				raw = append([]byte{10, raw[1] | 128, 0}, raw[2:]...)
			case "extra_unknown":
				raw = append(raw, 0x18, 0)
			case "oversize":
				raw = bytes.Repeat([]byte{0}, 4097)
			}
			_, err := c.decode(raw)
			require.Error(t, err)
			qualB9Valid(t, c)
		})
	}
	// Missing/relational bounds and nil providers cannot select defaults.
	for _, name := range []string{"nil", "marshal", "hash", "bytes", "field", "role", "members"} {
		t.Run("bound/"+name, func(t *testing.T) {
			records := *c.codec
			b := c.bounds
			input := &records
			switch name {
			case "nil":
				input = nil
			case "marshal":
				records.marshaller = nil
			case "hash":
				records.hasher = nil
			case "bytes":
				b.bytes = 0
			case "field":
				b.fieldBytes = 31
			case "role":
				b.roleBytes = 0
			case "members":
				b.maxMembers = 4
			}
			_, err := newAuthorityBodyCodec(input, b)
			require.Error(t, err)
			qualB9Valid(t, c)
		})
	}
}

func TestQualG6InitialAppointmentData(t *testing.T) {
	c := qualB9Codec(t, nil)
	a, err := c.decode(qualB9Bytes(t, "A_body"))
	require.NoError(t, err)
	i, err := c.decode(qualB9Bytes(t, "C_body"))
	require.NoError(t, err)
	raw := qualB9Bytes(t, "G6")
	valid := func() {
		g, e := c.decodeInitial(raw, a.role, i.role)
		require.NoError(t, e)
		require.Equal(t, qualB9Bytes(t, "A_hash"), g.admission.hash)
		require.Equal(t, qualB9Bytes(t, "C_hash"), g.independent.hash)
	}
	valid()
	for _, name := range []string{"count5", "count7", "tag", "owner", "program", "commitment", "swap", "same_id", "overlap", "threshold4", "successor", "wrong_role"} {
		t.Run(name, func(t *testing.T) {
			valid()
			f := qualA38Split(raw)
			arole := a.role
			switch name {
			case "count5":
				f = f[:5]
			case "count7":
				f = append(f, nil)
			case "tag":
				f[0] = []byte("wrong")
			case "owner":
				f[1][0] ^= 1
			case "program":
				f[2] = []byte("foreign")
			case "commitment":
				f[5] = f[5][:31]
			case "swap":
				f[3], f[4] = f[4], f[3]
			case "wrong_role":
				arole = []byte("portal-role-is-not-authority")
			default:
				body := qualA38Split(f[4])
				switch name {
				case "same_id":
					body[1] = a.id
				case "overlap":
					m := qualA38Split(body[5])
					m[0] = a.members[0]
					body[5] = qualRecordFrame(m...)
				case "threshold4":
					body[4] = qualA38U64(4)
				case "successor":
					body[7] = a.version
					body[8] = a.hash
				}
				f[4] = qualRecordFrame(body...)
			}
			_, e := c.decodeInitial(qualRecordFrame(f...), arole, i.role)
			require.Error(t, e)
			valid()
		})
	}
}

func TestQualPurposeHeadsSeparatedNativeRead(t *testing.T) {
	f := qualScopedNew(t)
	c := qualB9Codec(t, f.records.codec)
	// All native state/appointment/controls here are SYNTHETIC fixture assumptions.
	// Direct fixture writes are not a native installer or lawful appointment.
	a, e := c.decode(qualB9Bytes(t, "A_body"))
	require.NoError(t, e)
	i, e := c.decode(qualB9Bytes(t, "C_body"))
	require.NoError(t, e)
	put := func(purpose string, body, previous []byte) ([]byte, []byte) {
		id := qualScopedHash("VERSION", f.scope, previous, body)
		key := f.records.key("current", qualScopedHash("SCOPE", f.scope, []byte(purpose)))
		qualRecordPut(t, f.store, f.records.key("version", id), qualRecordFrame(f.scope, previous, body))
		qualRecordPut(t, f.store, key, qualRecordFrame(f.scope, id))
		return id, key
	}
	read := func(purpose string, role []byte) (*authorityBody, error) {
		return f.records.inspectAuthorityPurposeHead(f.context, f.d.owner, f.d.program, purpose, role, c)
	}
	// Old shared head is explicitly NOT a fallback for missing P head.
	f.enroll(t)
	_, e = read("REGISTER_TOKEN_ADMISSION", a.role)
	require.Error(t, e)
	aid, akey := put("REGISTER_TOKEN_ADMISSION", a.raw, nil)
	cid, ckey := put("REGISTER_TOKEN", i.raw, nil)
	before, _ := f.store.RootHash()
	av, e := read("REGISTER_TOKEN_ADMISSION", a.role)
	require.NoError(t, e)
	require.Equal(t, qualB9Bytes(t, "A_hash"), av.hash)
	cv, e := read("REGISTER_TOKEN", i.role)
	require.NoError(t, e)
	require.Equal(t, qualB9Bytes(t, "C_hash"), cv.hash)
	after, _ := f.store.RootHash()
	require.Equal(t, before, after, "inspection writes nothing")
	require.NotEqual(t, akey, ckey)
	require.NotEqual(t, aid, cid)
	next := qualA38Split(i.raw)
	next[2] = qualA38U64(9)
	next[7] = i.version
	next[8] = i.hash
	nextRaw := qualRecordFrame(next...)
	nextBody, e := c.decode(nextRaw)
	require.NoError(t, e)
	_, _ = put("REGISTER_TOKEN", nextRaw, cid)
	cv, e = read("REGISTER_TOKEN", i.role)
	require.NoError(t, e)
	require.Equal(t, nextBody.hash, cv.hash)
	av, e = read("REGISTER_TOKEN_ADMISSION", a.role)
	require.NoError(t, e)
	require.Equal(t, a.hash, av.hash, "C-only head change preserves A head")
	restoreHead := func() { _, _ = put("REGISTER_TOKEN", i.raw, nil); _, _ = put("REGISTER_TOKEN", nextRaw, cid) }
	for _, name := range []string{"unknown_purpose", "wrong_role", "missing_body", "bad_outer_hash", "wrong_predecessor", "historical_schema", "previous_envelope_width", "previous_root_shape", "missing_previous", "same_version_conflicting_body"} {
		t.Run(name, func(t *testing.T) {
			restoreHead()
			defer restoreHead()
			purpose, role := "REGISTER_TOKEN", i.role
			switch name {
			case "unknown_purpose":
				purpose = ""
			case "wrong_role":
				role = a.role
			case "missing_body":
				qualRecordPut(t, f.store, ckey, qualRecordFrame(f.scope, bytes.Repeat([]byte{99}, 32)))
			case "bad_outer_hash":
				bad := qualScopedHash("VERSION", f.scope, nil, i.raw)
				qualRecordPut(t, f.store, f.records.key("version", bad), qualRecordFrame(f.scope, nil, a.raw))
				qualRecordPut(t, f.store, ckey, qualRecordFrame(f.scope, bad))
			case "same_version_conflicting_body":
				x := qualA38Split(nextRaw)
				x[2] = i.version
				_, _ = put("REGISTER_TOKEN", qualRecordFrame(x...), cid)
			case "wrong_predecessor":
				x := qualA38Split(nextRaw)
				x[8] = bytes.Repeat([]byte{99}, 32)
				_, _ = put("REGISTER_TOKEN", qualRecordFrame(x...), cid)
			case "historical_schema":
				_, _ = put("REGISTER_TOKEN", []byte("opaque historical body"), nil)
			case "missing_previous":
				_, _ = put("REGISTER_TOKEN", nextRaw, bytes.Repeat([]byte{99}, 32))
			case "previous_envelope_width", "previous_root_shape":
				outerPred := []byte{1}
				if name == "previous_root_shape" {
					outerPred = bytes.Repeat([]byte{99}, 32)
				}
				altered := qualScopedHash("VERSION", f.scope, outerPred, i.raw)
				qualRecordPut(t, f.store, f.records.key("version", altered), qualRecordFrame(f.scope, outerPred, i.raw))
				_, _ = put("REGISTER_TOKEN", nextRaw, altered)

			}
			_, err := read(purpose, role)
			require.Error(t, err)
			restoreHead()
			_, err = read("REGISTER_TOKEN", i.role)
			require.NoError(t, err, "restored P neighbour")
		})
	}
	var missing *scopedAdmissionRecords
	_, e = missing.inspectAuthorityPurposeHead(f.context, f.d.owner, f.d.program, "REGISTER_TOKEN", i.role, c)
	require.Error(t, e)
	_, e = f.records.inspectAuthorityPurposeHead(f.context, f.d.owner, f.d.program, "REGISTER_TOKEN", i.role, qualB9Codec(t, nil))
	require.Error(t, e, "foreign codec cannot select another source")
	_, e = f.records.inspectAuthorityPurposeHead(nil, f.d.owner, f.d.program, "REGISTER_TOKEN", i.role, c)
	require.Error(t, e)
	// Ended/foreign ownership is not replaced by a constructor or caller flag.
	f.clock.End(f.context)
	_, e = read("REGISTER_TOKEN", i.role)
	require.Error(t, e)
}

// The selected maxMembers bounds each roster, not the number of proposed sets.
// This is body-selection data only; repeated non-PA data confers no role powers.
func TestQualB9IntentListUsesByteBounds(t *testing.T) {
	c := qualB9Codec(t, nil)
	_, e := c.decode(qualB9Bytes(t, "A_body"))
	require.NoError(t, e)
	pa, e := c.decode(qualB9Bytes(t, "PA_body"))
	require.NoError(t, e)
	intent := bootstrapIntentBody{}
	for n := 0; n < 10; n++ {
		intent.proposedProgramAuthoritySetBodies = append(intent.proposedProgramAuthoritySetBodies, qualB9Bytes(t, "A_body"))
		intent.proposedProgramAuthoritySetHashes = append(intent.proposedProgramAuthoritySetHashes, qualB9Bytes(t, "A_hash"))
	}
	intent.proposedProgramAuthoritySetBodies = append(intent.proposedProgramAuthoritySetBodies, qualB9Bytes(t, "PA_body"))
	intent.proposedProgramAuthoritySetHashes = append(intent.proposedProgramAuthoritySetHashes, qualB9Bytes(t, "PA_hash"))
	require.Greater(t, len(intent.proposedProgramAuthoritySetBodies), c.bounds.maxMembers)
	_, e = c.codec.authorityList(intent.proposedProgramAuthoritySetBodies)
	require.NoError(t, e, "existing intent list fits byte bound")
	_, e = c.selectIntentPA(intent, pa.owner, pa.programme)
	require.NoError(t, e, "roster bound cannot allocate an unrelated set-count limit")
}

func TestQualInitialMaterializationPurposeWrites(t *testing.T) {
	f := qualScopedNew(t)
	bodies, e := newAuthorityBodyCodec(f.records.codec, authorityBodyBounds{4096, 2048, 64, 10})
	require.NoError(t, e)
	a, e := bodies.decodeInitial(qualB9Bytes(t, "G6"), []byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
	require.NoError(t, e)
	writes, e := f.records.initialPurposeWrites(a)
	require.NoError(t, e)
	require.Len(t, writes, 4)
	for i, name := range []string{"A_body", "C_body"} {
		body := qualB9Bytes(t, name)
		id := qualScopedHash("VERSION", f.scope, nil, body)
		purpose := "REGISTER_TOKEN_ADMISSION"
		if i == 1 {
			purpose = "REGISTER_TOKEN"
		}
		key := append([]byte("ELRONDDRWA@scopedAdmission@current@"), qualScopedHash("SCOPE", f.scope, []byte(purpose))...)
		require.Equal(t, append([]byte("ELRONDDRWA@scopedAdmission@version@"), id...), writes[2*i].key)
		require.Equal(t, qualRecordFrame(f.scope, nil, body), writes[2*i].value)
		require.Equal(t, key, writes[2*i+1].key)
		require.Equal(t, qualRecordFrame(f.scope, id), writes[2*i+1].value)
	}
	require.NotEqual(t, writes[1].key, writes[3].key)
}
