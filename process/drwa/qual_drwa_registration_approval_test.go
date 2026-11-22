package drwa

import (
	"bytes"
	stded "crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
	independentHash "golang.org/x/crypto/blake2b"
)

// A38 non-authoritative construction fixtures. Exact bytes/hashes were derived
// before production edits by independent Python field-1 framing + hashlib.
// Public test seeds and Go standard Ed25519 sign that independently based hash;
// no production encoder, decoder or signature verifier generates expectations.
// Opaque version bodies below are NOT an admitted AuthoritySetVersion schema.
// Negative cases/controls were authored after production construction; only the
// fourteen literal vectors have the retained pre-production derivation chronology.
var qualA38Vectors = map[string]string{
	"profile":                "0a18445257412f4352454154494f4e5f50524f46494c452f76320a08746573742d6e65740a2033333333333333333333333333333333333333333333333333333333333333330a0c46756e6769626c65455344540a01000a01010a01000a01000a01000a01000a01000a01000a01000a0100",
	"creation":               "0a1b445257412f544f4b454e5f4352454154494f4e5f424f44592f76310a0c46756e6769626c65455344540a20e5419973520661fb0fad1bda4babefcde5ec1edd6b8c537abf3cb4dc67bae0500a09546f6b656e4e616d650a05544f4b454e0a0400000006",
	"intent_body":            "0a08746573742d6e65740a2011111111111111111111111111111111111111111111111111111111111111110a01700a01310a0c46756e6769626c65455344540a20e5419973520661fb0fad1bda4babefcde5ec1edd6b8c537abf3cb4dc67bae0500a204371944b7552d27e3ddc894b848e39f5336cb34d2d9c527056819d1559f9dece0a206a2400720afa718586175cba4ce03a9ed982abdffa4df70eede739a3fc1b29c80a204988d524ae410761db2fae828f3e122f65c3bd1746d946b1f68b54fecd6b53380a06736368656d610a086465636973696f6e0a190a17666978747572652d70612d76657273696f6e2d626f64790a220a20756600ee4a0c8c4538df7c3d1dc927e15611859b6bb9119069bea4c97f626ff70a0f6275726e2d616e642d7265746972650a0d492d666978747572652d7265660a080000000000000064",
	"intent_hash":            "e4bc3b2ab430560688d0b972acb90df7b416c81faba0ca00e523ee303f14e220",
	"intent_id":              "001b3a96747c2ca47c539be6c06a2d78981e13418c7e36a7e23d5ee041cd17a4",
	"scope":                  "0a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a0170",
	"map_bytes":              "0a27445257412f52454749535445525f544f4b454e5f524f4c455f4d41502f63616e646964617465310a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a01700a7a0a1852454749535445525f544f4b454e5f41444d495353494f4e0a1061646d697373696f6e006f70617175650a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a20d3d69c5e4921c9839df9d8954ee63c40f1a1eb378db5758118fb8a08ff95e4880a6d0a0e52454749535445525f544f4b454e0a0d696e646570656e64656e74c3a90a2043434343434343434343434343434343434343434343434343434343434343430a0800000000000000090a201516b1cfcf31f0a8740f4351ee44d8165873f8a8b3ae3d0005f4a850c130f9fb",
	"map_hash":               "45635a84a5bcb4df5cf5e68000bfb0f5b34fe87c5bfdba66ae344cb61af97407",
	"admission_dependency":   "0a1061646d697373696f6e006f70617175650a2f0a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a01700a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a20d3d69c5e4921c9839df9d8954ee63c40f1a1eb378db5758118fb8a08ff95e4880a2045635a84a5bcb4df5cf5e68000bfb0f5b34fe87c5bfdba66ae344cb61af97407",
	"pa_dependency":          "0a2050726f6772616d2041646d696e697374726174696f6e20417574686f726974790a2f0a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a01700a2050505050505050505050505050505050505050505050505050505050505050500a0800000000000000070a20756600ee4a0c8c4538df7c3d1dc927e15611859b6bb9119069bea4c97f626ff70a20e4bc3b2ab430560688d0b972acb90df7b416c81faba0ca00e523ee303f14e220",
	"independent_dependency": "0a0d696e646570656e64656e74c3a90a2f0a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a01700a2043434343434343434343434343434343434343434343434343434343434343430a0800000000000000090a201516b1cfcf31f0a8740f4351ee44d8165873f8a8b3ae3d0005f4a850c130f9fb0a2045635a84a5bcb4df5cf5e68000bfb0f5b34fe87c5bfdba66ae344cb61af97407",
	"message":                "0a27445257412f52454749535445525f544f4b454e5f415050524f56414c2f63616e646964617465320a08746573742d6e65740a0e52454749535445525f544f4b454e0a2022222222222222222222222222222222222222222222222222222222222222220a01700a2011111111111111111111111111111111111111111111111111111111111111110a20001b3a96747c2ca47c539be6c06a2d78981e13418c7e36a7e23d5ee041cd17a40a20e4bc3b2ab430560688d0b972acb90df7b416c81faba0ca00e523ee303f14e2200a20390ced52044b7f718c0c936daf0ece544254a94240a0e4d6d17bfe5ed9f5dae20ab3010a1061646d697373696f6e006f70617175650a2f0a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a01700a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a20d3d69c5e4921c9839df9d8954ee63c40f1a1eb378db5758118fb8a08ff95e4880a2045635a84a5bcb4df5cf5e68000bfb0f5b34fe87c5bfdba66ae344cb61af974070ac3010a2050726f6772616d2041646d696e697374726174696f6e20417574686f726974790a2f0a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a01700a2050505050505050505050505050505050505050505050505050505050505050500a0800000000000000070a20756600ee4a0c8c4538df7c3d1dc927e15611859b6bb9119069bea4c97f626ff70a20e4bc3b2ab430560688d0b972acb90df7b416c81faba0ca00e523ee303f14e2200ab0010a0d696e646570656e64656e74c3a90a2f0a08746573742d6e65740a2022222222222222222222222222222222222222222222222222222222222222220a01700a2043434343434343434343434343434343434343434343434343434343434343430a0800000000000000090a201516b1cfcf31f0a8740f4351ee44d8165873f8a8b3ae3d0005f4a850c130f9fb0a2045635a84a5bcb4df5cf5e68000bfb0f5b34fe87c5bfdba66ae344cb61af974070a08000000000000000a0a08000000000000005a",
	"message_hash":           "4ffa91ce58531f428d274e55fa1af510f758d4c4454557e0adbcf1bfb5f47690",
	"creation_hash":          "390ced52044b7f718c0c936daf0ece544254a94240a0e4d6d17bfe5ed9f5dae2",
}

func qualA38Bytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(qualA38Vectors[name])
	require.NoError(t, err)
	return raw
}
func qualA38Hash(raw []byte) []byte { h := independentHash.Sum256(raw); return h[:] }
func qualA38U64(v uint64) []byte    { return binary.BigEndian.AppendUint64(nil, v) }
func qualA38Keys(kind byte) ([][]byte, []stded.PrivateKey) {
	var pubs [][]byte
	var privs []stded.PrivateKey
	for i := byte(0); i < 5; i++ {
		key := stded.NewKeyFromSeed(bytes.Repeat([]byte{kind*16 + i + 1}, stded.SeedSize))
		privs = append(privs, key)
		pubs = append(pubs, bytes.Clone(key.Public().(stded.PublicKey)))
	}
	return pubs, privs
}
func qualA38Fixture(t *testing.T) (*registrationApprovalCodec, *registrationApprovalContext, []stded.PrivateKey) {
	t.Helper()
	records := &registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 4096}
	c, err := newRegistrationApprovalCodec(records, registrationApprovalBounds{bytes: 4096, fieldBytes: 2048, roleBytes: 64, familyBytes: 64, maxMembers: 8, maxValidity: 100})
	require.NoError(t, err)
	a, _ := qualA38Keys(0)
	p, _ := qualA38Keys(1)
	i, keys := qualA38Keys(2)
	ctx := &registrationApprovalContext{network: []byte("test-net"), scopeOwner: bytes.Repeat([]byte{34}, 32), programme: []byte("p"), issuer: bytes.Repeat([]byte{17}, 32), intentID: qualA38Bytes(t, "intent_id"), intentHash: qualA38Bytes(t, "intent_hash"), intentBody: qualA38Bytes(t, "intent_body"), manager: bytes.Repeat([]byte{51}, 32), profile: qualA38Bytes(t, "profile"), at: 50}
	authority := func(role, id, body []byte, version uint64, members [][]byte) registrationApprovalAuthority {
		return registrationApprovalAuthority{role: role, scope: qualA38Bytes(t, "scope"), setID: id, version: qualA38U64(version), body: body, bodyHash: qualA38Hash(body), threshold: 3, members: members}
	}
	ctx.admission = authority([]byte("admission\x00opaque"), bytes.Repeat([]byte{'A'}, 32), []byte("fixture-admission-version-body"), 0, a)
	ctx.pa = authority([]byte("Program Administration Authority"), bytes.Repeat([]byte{'P'}, 32), []byte("fixture-pa-version-body"), 7, p)
	ctx.independent = authority([]byte("independent\xc3\xa9"), bytes.Repeat([]byte{'C'}, 32), []byte("fixture-independent-version-body"), 9, i)
	return c, ctx, keys
}

// Test-only independent grammar, never production frame/encode methods.
func qualA38Message(t *testing.T, ctx *registrationApprovalContext, nb, na uint64) []byte {
	t.Helper()
	row := func(purpose string, a registrationApprovalAuthority) []byte {
		return qualRecordFrame([]byte(purpose), a.role, a.setID, a.version, a.bodyHash)
	}
	mapBytes := qualRecordFrame([]byte("DRWA/REGISTER_TOKEN_ROLE_MAP/candidate1"), ctx.network, ctx.scopeOwner, ctx.programme, row("REGISTER_TOKEN_ADMISSION", ctx.admission), row("REGISTER_TOKEN", ctx.independent))
	mh := qualA38Hash(mapBytes)
	dep := func(a registrationApprovalAuthority, binding []byte) []byte {
		return qualRecordFrame(a.role, a.scope, a.setID, a.version, a.bodyHash, binding)
	}
	return qualRecordFrame([]byte("DRWA/REGISTER_TOKEN_APPROVAL/candidate2"), ctx.network, []byte("REGISTER_TOKEN"), ctx.scopeOwner, ctx.programme, ctx.issuer, ctx.intentID, ctx.intentHash, qualA38Bytes(t, "creation_hash"), dep(ctx.admission, mh), dep(ctx.pa, ctx.intentHash), dep(ctx.independent, mh), qualA38U64(nb), qualA38U64(na))
}
func qualA38Envelope(message []byte, keys []stded.PrivateKey, indices ...uint64) []byte {
	var positions, signatures [][]byte
	for _, i := range indices {
		positions = append(positions, qualA38U64(i))
		signer := i
		if signer >= uint64(len(keys)) {
			signer = 0
		} // intentionally nonmember-index negative
		signatures = append(signatures, stded.Sign(keys[signer], qualA38Hash(message)))
	}
	return qualRecordFrame(message, qualRecordFrame(positions...), qualRecordFrame(signatures...))
}
func qualA38Split(raw []byte) [][]byte {
	var fields [][]byte
	for len(raw) > 0 {
		if raw[0] != 10 {
			panic("test fixture framing")
		}
		n, k := binary.Uvarint(raw[1:])
		if k <= 0 || n > uint64(len(raw)-1-k) {
			panic("test fixture length")
		}
		fields = append(fields, bytes.Clone(raw[1+k:1+k+int(n)]))
		raw = raw[1+k+int(n):]
	}
	return fields
}

// Neighbours prove that a negative's surrounding inputs are independently valid.
// Restoring the same codec/context must accept again. A shared sentinel cannot
// identify a private branch; redundant checks remain explicitly indistinguishable.
func qualA38Neighbours(t *testing.T, c *registrationApprovalCodec, ctx *registrationApprovalContext, keys []stded.PrivateKey) func() {
	t.Helper()
	cloneSet := func(a registrationApprovalAuthority) registrationApprovalAuthority {
		a.role = bytes.Clone(a.role)
		a.scope = bytes.Clone(a.scope)
		a.setID = bytes.Clone(a.setID)
		a.version = bytes.Clone(a.version)
		a.body = bytes.Clone(a.body)
		a.bodyHash = bytes.Clone(a.bodyHash)
		members := make([][]byte, len(a.members))
		for i, k := range a.members {
			members[i] = bytes.Clone(k)
		}
		a.members = members
		return a
	}
	saved := *ctx
	saved.network = bytes.Clone(ctx.network)
	saved.scopeOwner = bytes.Clone(ctx.scopeOwner)
	saved.programme = bytes.Clone(ctx.programme)
	saved.issuer = bytes.Clone(ctx.issuer)
	saved.intentID = bytes.Clone(ctx.intentID)
	saved.intentHash = bytes.Clone(ctx.intentHash)
	saved.intentBody = bytes.Clone(ctx.intentBody)
	saved.manager = bytes.Clone(ctx.manager)
	saved.profile = bytes.Clone(ctx.profile)
	saved.admission = cloneSet(ctx.admission)
	saved.pa = cloneSet(ctx.pa)
	saved.independent = cloneSet(ctx.independent)
	bounds, codec := c.bounds, *c.codec
	positive := func() {
		require.NoError(t, c.verifyIndependent(qualA38Envelope(qualA38Message(t, ctx, 10, 90), keys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx), "valid/restored neighbour")
	}
	positive()
	return func() { *ctx = saved; c.bounds = bounds; *c.codec = codec; positive() }
}

func TestQualA38IndependentGrammarAndNativeSignature(t *testing.T) {
	c, ctx, keys := qualA38Fixture(t)
	body, err := c.codec.decodeBody(ctx.intentBody)
	require.NoError(t, err)
	creation, err := c.decodeCreation(qualA38Bytes(t, "creation"), body, ctx.manager, ctx.profile)
	require.NoError(t, err)
	require.Equal(t, qualA38Bytes(t, "creation_hash"), creation.digest)
	require.Equal(t, uint32(6), creation.decimals)
	require.Equal(t, []byte("TokenName"), creation.name)
	require.Equal(t, []byte("TOKEN"), creation.ticker)
	_, _, err = c.context(ctx)
	require.NoError(t, err)
	mb, mh, err := c.roleMap(ctx)
	require.NoError(t, err)
	require.Equal(t, qualA38Bytes(t, "map_bytes"), mb)
	require.Equal(t, qualA38Bytes(t, "map_hash"), mh)
	message := qualA38Message(t, ctx, 10, 90)
	require.Equal(t, qualA38Bytes(t, "message"), message)
	require.Equal(t, qualA38Bytes(t, "message_hash"), qualA38Hash(message))
	require.NoError(t, c.verifyIndependent(qualA38Envelope(message, keys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx))
	// More than threshold still verifies EVERY signature.
	require.NoError(t, c.verifyIndependent(qualA38Envelope(message, keys, 0, 1, 2, 3, 4), qualA38Bytes(t, "creation"), ctx))
}

func TestQualA38AuthoritativeBodyHashIsNotRedefined(t *testing.T) {
	c, ctx, keys := qualA38Fixture(t)
	// This is a fresh synthetic intent fixture, not an intent rewrite. The
	// native authority-body hash preimage/schema is not allocated by A38.
	ctx.admission.bodyHash = bytes.Repeat([]byte{0xa1}, 32)
	ctx.pa.bodyHash = bytes.Repeat([]byte{0xb1}, 32)
	ctx.independent.bodyHash = bytes.Repeat([]byte{0xc1}, 32)
	fields := qualA38Split(ctx.intentBody)
	fields[12] = qualRecordFrame(ctx.pa.bodyHash)
	ctx.intentBody = qualRecordFrame(fields...)
	ctx.intentHash = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), ctx.intentBody))
	ctx.intentID = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), ctx.network,
		ctx.issuer, ctx.programme, []byte("1"), ctx.intentHash))
	message := qualA38Message(t, ctx, 10, 90)
	require.NoError(t, c.verifyIndependent(qualA38Envelope(message, keys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx))
}

func TestQualA38CreationBodyHostileGrammar(t *testing.T) {
	for _, name := range []string{"empty", "truncated", "extra", "unknown", "nonshort", "tag", "family", "profile_hash_width", "name", "ticker", "decimals_width", "profile_body", "oversized"} {
		t.Run(name, func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, keys)()
			body, err := c.codec.decodeBody(ctx.intentBody)
			require.NoError(t, err)
			raw := qualA38Bytes(t, "creation")
			f := qualA38Split(raw)
			switch name {
			case "empty":
				raw = nil
			case "truncated":
				raw = raw[:len(raw)-1]
			case "extra":
				raw = qualRecordFrame(append(f, []byte("extra"))...)
			case "unknown":
				raw = append(raw, 0x18, 0)
			case "nonshort":
				raw = append([]byte{10, raw[1] | 128, 0}, raw[2:]...)
			case "tag":
				f[0] = []byte("wrong")
				raw = qualRecordFrame(f...)
			case "family":
				f[1] = []byte("other")
				raw = qualRecordFrame(f...)
			case "profile_hash_width":
				f[2] = f[2][:31]
				raw = qualRecordFrame(f...)
			case "name":
				f[3] = nil
				raw = qualRecordFrame(f...)
			case "ticker":
				f[4] = nil
				raw = qualRecordFrame(f...)
			case "decimals_width":
				f[5] = f[5][1:]
				raw = qualRecordFrame(f...)
			case "profile_body":
				ctx.profile[len(ctx.profile)-1] ^= 1
			case "oversized":
				raw = bytes.Repeat([]byte{0}, 4097)
			}
			_, err = c.decodeCreation(raw, body, ctx.manager, ctx.profile)
			require.Error(t, err)
		})
	}
}

func TestQualA38MessageAndDependencySubstitution(t *testing.T) {
	names := []string{"tag", "purpose", "network", "scope_owner", "programme", "issuer", "intent_id", "intent_hash", "body_digest", "nb_width", "na_width", "extra", "pa_as_map_hash", "a_as_intent_hash", "old_independent_version", "old_admission_version", "wrong_pa_version", "role_nul_truncation", "role_case_fold", "hash_width", "missing_version", "short_version", "empty_role", "reordered_deps", "scope_substitution", "wrong_map_hash"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, keys)()
			m := qualA38Split(qualA38Bytes(t, "message"))
			indices := map[string]int{"tag": 0, "purpose": 2, "network": 1, "scope_owner": 3, "programme": 4, "issuer": 5, "intent_id": 6, "intent_hash": 7, "body_digest": 8}
			if i, ok := indices[name]; ok {
				m[i] = bytes.Clone(m[i])
				m[i][0] ^= 1
			} else {
				switch name {
				case "nb_width":
					m[12] = m[12][1:]
				case "na_width":
					m[13] = append(m[13], 0)
				case "extra":
					m = append(m, []byte("extra"))
				case "reordered_deps":
					m[9], m[11] = m[11], m[9]
				default:
					coordinate := 11
					if name == "pa_as_map_hash" || name == "wrong_pa_version" {
						coordinate = 10
					}
					if name == "a_as_intent_hash" || name == "old_admission_version" {
						coordinate = 9
					}
					d := qualA38Split(m[coordinate])
					switch name {
					case "pa_as_map_hash":
						d[5] = qualA38Bytes(t, "map_hash")
					case "a_as_intent_hash":
						d[5] = ctx.intentHash
					case "old_independent_version":
						d[3] = qualA38U64(8)
					case "old_admission_version":
						d[3] = qualA38U64(1)
					case "wrong_pa_version":
						d[3] = qualA38U64(8)
					case "role_nul_truncation":
						coordinate = 9
						d = qualA38Split(m[9])
						d[0] = []byte("admission")
					case "role_case_fold":
						d[0] = bytes.ToUpper(d[0])
					case "hash_width":
						d[4] = d[4][:31]
					case "missing_version":
						d[3] = nil
					case "short_version":
						d[3] = []byte{0}
					case "empty_role":
						d[0] = nil
					case "scope_substitution":
						d[1] = qualRecordFrame([]byte("other"), ctx.scopeOwner, ctx.programme)
					case "wrong_map_hash":
						d[5][0] ^= 1
					}
					m[coordinate] = qualRecordFrame(d...)
				}
			}
			// Even a valid independent signature on the wrong statement cannot authorize it.
			require.Error(t, c.verifyIndependent(qualA38Envelope(qualRecordFrame(m...), keys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx))
		})
	}
}

func TestQualA38CurrentSourcesAndRotation(t *testing.T) {
	c, ctx, keys := qualA38Fixture(t)
	original := qualA38Envelope(qualA38Bytes(t, "message"), keys, 0, 2, 4)
	oldIntent := bytes.Clone(ctx.intentBody)
	nextMembers, nextKeys := qualA38Keys(3)
	ctx.independent.members = nextMembers
	ctx.independent.version = qualA38U64(10)
	ctx.independent.body = []byte("fixture-independent-version-body-2")
	ctx.independent.bodyHash = qualA38Hash(ctx.independent.body)
	require.Error(t, c.verifyIndependent(original, qualA38Bytes(t, "creation"), ctx))
	nextMessage := qualA38Message(t, ctx, 10, 90)
	require.NotEqual(t, qualA38Bytes(t, "message"), nextMessage)
	require.NoError(t, c.verifyIndependent(qualA38Envelope(nextMessage, nextKeys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx))
	require.Equal(t, oldIntent, ctx.intentBody)
	require.Error(t, c.verifyIndependent(qualA38Envelope(nextMessage, keys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx))
	require.NoError(t, c.verifyIndependent(qualA38Envelope(nextMessage, nextKeys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx), "restore successor proof in same context")
	for _, name := range []string{"missing_context", "missing_independent_input", "missing_admission_input", "new_scoped_pa", "missing_pa_body", "missing_profile", "missing_version_bytes"} {
		t.Run(name, func(t *testing.T) {
			c, x, k := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, x, k)()
			switch name {
			case "missing_context":
				x = nil
			case "missing_independent_input":
				x.independent = registrationApprovalAuthority{}
			case "missing_admission_input":
				x.admission = registrationApprovalAuthority{}
			case "new_scoped_pa":
				x.pa.body = []byte("new-scoped-PA-not-in-intent")
				x.pa.bodyHash = qualA38Hash(x.pa.body)
			case "missing_pa_body":
				x.pa.body = nil
			case "missing_profile":
				x.profile = nil
			case "missing_version_bytes":
				x.admission.version = nil
			}
			require.Error(t, c.verifyIndependent(qualA38Envelope(qualA38Bytes(t, "message"), k, 0, 2, 4), qualA38Bytes(t, "creation"), x))
		})
	}
}

func TestQualA38IndependentRosterOnlyAndEverySignature(t *testing.T) {
	for _, name := range []string{"admission_keys", "pa_keys", "below_threshold", "unsorted", "duplicate", "nonmember", "mismatched_lists", "bad_signature", "extra_bad_signature", "short_signature", "key_overlap", "same_set_id", "duplicate_key", "bad_native_key", "four_members", "weak_threshold", "excess_threshold", "role_bound", "wrong_pa_role"} {
		t.Run(name, func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, keys)()
			msg := qualA38Bytes(t, "message")
			idx := []uint64{0, 2, 4}
			switch name {
			case "admission_keys":
				_, keys = qualA38Keys(0)
			case "pa_keys":
				_, keys = qualA38Keys(1)
			case "below_threshold":
				idx = []uint64{0, 2}
			case "unsorted":
				idx = []uint64{2, 0, 4}
			case "duplicate":
				idx = []uint64{0, 0, 4}
			case "nonmember":
				idx = []uint64{0, 2, 8}
			case "extra_bad_signature":
				idx = []uint64{0, 1, 2, 3}
			case "key_overlap":
				ctx.admission.members[0] = bytes.Clone(ctx.independent.members[0])
			case "same_set_id":
				ctx.admission.setID = bytes.Clone(ctx.independent.setID)
			case "duplicate_key":
				ctx.independent.members[1] = bytes.Clone(ctx.independent.members[0])
			case "bad_native_key":
				ctx.independent.members[0] = []byte{1}
			case "four_members":
				ctx.independent.members = ctx.independent.members[:4]
			case "weak_threshold":
				ctx.independent.threshold = 2
			case "excess_threshold":
				ctx.independent.threshold = 6
			case "role_bound":
				c.bounds.roleBytes = 2
			case "wrong_pa_role":
				ctx.pa.role = []byte("Supply Authority")
			}
			raw := qualA38Envelope(msg, keys, idx...)
			f := qualA38Split(raw)
			sigs := qualA38Split(f[2])
			switch name {
			case "mismatched_lists":
				sigs = sigs[:2]
			case "bad_signature":
				sigs[0][0] ^= 1
			case "extra_bad_signature":
				sigs[3][0] ^= 1
			case "short_signature":
				sigs[0] = []byte{1}
			}
			f[2] = qualRecordFrame(sigs...)
			raw = qualRecordFrame(f...)
			require.Error(t, c.verifyIndependent(raw, qualA38Bytes(t, "creation"), ctx))
		})
	}
}

func TestQualA38InclusiveTimeAndExplicitBounds(t *testing.T) {
	for _, tc := range []struct {
		name       string
		at, nb, na uint64
		want       bool
	}{{"before", 9, 10, 90, false}, {"not_before", 10, 10, 90, true}, {"not_after", 90, 10, 90, true}, {"after", 91, 10, 90, false}, {"expiry", 100, 90, 100, true}, {"past_expiry", 50, 10, 101, false}, {"inverted", 50, 90, 10, false}} {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx, k := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, k)()
			ctx.at = HeaderMilliseconds(tc.at)
			err := c.verifyIndependent(qualA38Envelope(qualA38Message(t, ctx, tc.nb, tc.na), k, 0, 2, 4), qualA38Bytes(t, "creation"), ctx)
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	c, ctx, k := qualA38Fixture(t)
	restore := qualA38Neighbours(t, c, ctx, k)
	c.bounds.maxValidity = 79
	require.Error(t, c.verifyIndependent(qualA38Envelope(qualA38Bytes(t, "message"), k, 0, 2, 4), qualA38Bytes(t, "creation"), ctx))
	restore()
	for _, name := range []string{"bytes", "field", "role", "family", "members", "validity"} {
		t.Run("missing_bound/"+name, func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, keys)()
			b := c.bounds
			switch name {
			case "bytes":
				b.bytes = 0
			case "field":
				b.fieldBytes = 0
			case "role":
				b.roleBytes = 0
			case "family":
				b.familyBytes = 0
			case "members":
				b.maxMembers = 0
			case "validity":
				b.maxValidity = 0
			}
			_, err := newRegistrationApprovalCodec(c.codec, b)
			require.Error(t, err)
		})
	}
}

type qualA38MarshalSpy struct {
	marshal.Marshalizer
	reads int
}

func (s *qualA38MarshalSpy) Unmarshal(obj interface{}, raw []byte) error {
	s.reads++
	return s.Marshalizer.Unmarshal(obj, raw)
}
func TestQualA38PreflightBeforeNativeAllocation(t *testing.T) {
	for _, name := range []string{"outer_extra", "outer_unknown", "outer_nonshort", "outer_truncated", "outer_oversized", "list_count", "list_field", "creation_extra"} {
		t.Run(name, func(t *testing.T) {
			c, ctx, k := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, k)()
			spy := &qualA38MarshalSpy{Marshalizer: c.codec.marshaller}
			c.codec.marshaller = spy
			raw := qualA38Envelope(qualA38Bytes(t, "message"), k, 0, 2, 4)
			var err error
			switch name {
			case "list_count":
				fields := make([][]byte, 9)
				for i := range fields {
					fields[i] = []byte{1}
				}
				_, err = c.list(qualRecordFrame(fields...), 8)
			case "list_field":
				_, err = c.list(qualRecordFrame(bytes.Repeat([]byte{1}, 9)), 8)
			case "creation_extra":
				body := bootstrapIntentBody{}
				f := qualA38Split(qualA38Bytes(t, "creation"))
				_, err = c.decodeCreation(qualRecordFrame(append(f, []byte("extra"))...), body, ctx.manager, ctx.profile)
			default:
				switch name {
				case "outer_extra":
					raw = append(raw, 10, 0)
				case "outer_unknown":
					raw = append(raw, 0x18, 0)
				case "outer_nonshort":
					raw = append([]byte{10, 0x80, 0}, raw[1:]...)
				case "outer_truncated":
					raw = raw[:len(raw)-1]
				case "outer_oversized":
					raw = bytes.Repeat([]byte{0}, 4097)
				}
				err = c.verifyIndependent(raw, qualA38Bytes(t, "creation"), ctx)
			}
			require.Error(t, err)
			require.Zero(t, spy.reads, "reject bounds/canonicality before native allocation")
		})
	}
}

// Each statement mutation is signed independently with the correct C keys.
// Thus wrong-statement refusals cannot be attributed to an unsigned message.
func TestQualA38RepairGrammarNeighbours(t *testing.T) {
	names := []string{"creation_five", "message_thirteen", "dependency_five", "dependency_seven", "envelope_two", "hash_plus_one", "version_nine", "approval_v1", "index_seven", "M_nonshort", "dependency_nonshort", "positions_nonshort", "signatures_nonshort", "pa_message_role"}
	for _, dep := range []string{"A", "PA", "C"} {
		names = append(names, "set_id_"+dep, "body_hash_"+dep)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, keys)()
			m := qualA38Split(qualA38Bytes(t, "message"))
			creation := qualA38Bytes(t, "creation")
			nonshort := func(raw []byte) []byte { // expand only the first length's final varint byte
				_, n := binary.Uvarint(raw[1:])
				out := bytes.Clone(raw[:1+n])
				out[len(out)-1] |= 0x80
				out = append(out, 0)
				return append(out, raw[1+n:]...)
			}
			switch name {
			case "creation_five":
				f := qualA38Split(creation)
				creation = qualRecordFrame(f[:5]...)
			case "message_thirteen":
				m = m[:13]
			case "approval_v1":
				m[0] = []byte("DRWA/REGISTER_TOKEN_APPROVAL/v1")
			case "dependency_five", "dependency_seven", "hash_plus_one", "version_nine", "dependency_nonshort", "pa_message_role":
				coordinate := 11
				if name == "pa_message_role" {
					coordinate = 10
				}
				d := qualA38Split(m[coordinate])
				switch name {
				case "dependency_five":
					d = d[:5]
				case "dependency_seven":
					d = append(d, []byte("extra"))
				case "hash_plus_one":
					d[4] = append(d[4], 0)
				case "version_nine":
					d[3] = append(d[3], 0)
				case "pa_message_role":
					d[0] = []byte("another-role")
				}
				m[coordinate] = qualRecordFrame(d...)
				if name == "dependency_nonshort" {
					m[coordinate] = nonshort(m[coordinate])
				}
			default:
				for i, dep := range []string{"A", "PA", "C"} {
					if name == "set_id_"+dep || name == "body_hash_"+dep {
						d := qualA38Split(m[9+i])
						j := 2
						if name == "body_hash_"+dep {
							j = 4
						}
						d[j][0] ^= 1
						m[9+i] = qualRecordFrame(d...)
					}
				}
			}
			message := qualRecordFrame(m...)
			if name == "M_nonshort" {
				message = nonshort(message)
			}
			raw := qualA38Envelope(message, keys, 0, 2, 4)
			f := qualA38Split(raw)
			switch name {
			case "envelope_two":
				f = f[:2]
			case "index_seven":
				positions := qualA38Split(f[1])
				positions[0] = positions[0][1:]
				f[1] = qualRecordFrame(positions...)
			case "positions_nonshort":
				f[1] = nonshort(f[1])
			case "signatures_nonshort":
				f[2] = nonshort(f[2])
			}
			require.Error(t, c.verifyIndependent(qualRecordFrame(f...), creation, ctx))
		})
	}
}

func TestQualA38RepairContextAndPairwiseNeighbours(t *testing.T) {
	names := []string{"network_missing", "scope_owner_missing", "issuer_missing", "programme_missing", "intent_id_missing", "intent_hash_missing", "intent_body_missing", "manager_missing", "intent_network_disagrees", "intent_programme_disagrees", "intent_issuer_disagrees", "duplicate_pa_pair", "admission_invalid_native_key", "pa_invalid_native_key"}
	for _, pair := range []string{"A_PA", "PA_C", "A_C"} {
		names = append(names, "overlap_"+pair, "equal_set_id_"+pair)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, keys)()
			switch name {
			case "network_missing":
				ctx.network = nil
			case "scope_owner_missing":
				ctx.scopeOwner = nil
			case "issuer_missing":
				ctx.issuer = nil
			case "programme_missing":
				ctx.programme = nil
			case "intent_id_missing":
				ctx.intentID = nil
			case "intent_hash_missing":
				ctx.intentHash = nil
			case "intent_body_missing":
				ctx.intentBody = nil
			case "manager_missing":
				ctx.manager = nil
			case "admission_invalid_native_key":
				ctx.admission.members[0] = []byte{1}
			case "pa_invalid_native_key":
				ctx.pa.members[0] = []byte{1}
			case "duplicate_pa_pair":
				f := qualA38Split(ctx.intentBody)
				f[11] = qualRecordFrame(ctx.pa.body, ctx.pa.body)
				f[12] = qualRecordFrame(ctx.pa.bodyHash, ctx.pa.bodyHash)
				ctx.intentBody = qualRecordFrame(f...)
				ctx.intentHash = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), ctx.intentBody))
				ctx.intentID = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), ctx.network, ctx.issuer, ctx.programme, []byte("1"), ctx.intentHash))
			case "intent_network_disagrees", "intent_programme_disagrees", "intent_issuer_disagrees":
				f := qualA38Split(ctx.intentBody)
				i := 0
				if name == "intent_programme_disagrees" {
					i = 2
				}
				if name == "intent_issuer_disagrees" {
					i = 1
				}
				f[i][0] ^= 1
				ctx.intentBody = qualRecordFrame(f...)
				// Keep hash/id valid for this fresh alternative intent, isolating the context disagreement.
				ctx.intentHash = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), ctx.intentBody))
				ctx.intentID = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), f[0], f[1], f[2], []byte("1"), ctx.intentHash))
			default:
				left, right := &ctx.admission, &ctx.pa
				if name == "overlap_PA_C" || name == "equal_set_id_PA_C" {
					left, right = &ctx.pa, &ctx.independent
				}
				if name == "overlap_A_C" || name == "equal_set_id_A_C" {
					left, right = &ctx.admission, &ctx.independent
				}
				if bytes.HasPrefix([]byte(name), []byte("overlap_")) {
					left.members[0] = bytes.Clone(right.members[0])
				} else {
					left.setID = bytes.Clone(right.setID)
				}
			}
			// Sign current context identities, including intentionally bad pairs, so the
			// independent envelope remains cryptographically valid before policy checks.
			message := qualA38Message(t, ctx, 10, 90)
			if bytes.HasSuffix([]byte(name), []byte("_missing")) {
				message = qualA38Bytes(t, "message")
			} // hold envelope valid while removing only the context input
			require.Error(t, c.verifyIndependent(qualA38Envelope(message, keys, 0, 2, 4), qualA38Bytes(t, "creation"), ctx))
		})
	}
}

func TestQualA38RepairConstructorAndValidityNeighbours(t *testing.T) {
	for _, name := range []string{"nil_records", "nil_marshaller", "nil_hasher", "bytes_exceed_records", "field_below_hash", "field_exceed_bytes", "role_exceed_field", "family_exceed_field", "members_below_five", "members_exceed_byte_capacity"} {
		t.Run(name, func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			defer qualA38Neighbours(t, c, ctx, keys)()
			records := *c.codec
			b := c.bounds
			input := &records
			switch name {
			case "nil_records":
				input = nil
			case "nil_marshaller":
				records.marshaller = nil
			case "nil_hasher":
				records.hasher = nil
			case "bytes_exceed_records":
				b.bytes = records.maxBytes + 1
			case "field_below_hash":
				b.fieldBytes = records.hasher.Size() - 1
			case "field_exceed_bytes":
				b.fieldBytes = b.bytes + 1
			case "role_exceed_field":
				b.roleBytes = b.fieldBytes + 1
			case "family_exceed_field":
				b.familyBytes = b.fieldBytes + 1
			case "members_below_five":
				b.maxMembers = 4
			case "members_exceed_byte_capacity":
				b.maxMembers = b.bytes/2 + 1
			}
			_, err := newRegistrationApprovalCodec(input, b)
			require.Error(t, err)
			// The actual constructor's valid counterpart, not a discarded error.
			_, err = newRegistrationApprovalCodec(c.codec, c.bounds)
			require.NoError(t, err)
		})
	}
	c, ctx, keys := qualA38Fixture(t)
	defer qualA38Neighbours(t, c, ctx, keys)()
	c.bounds.maxValidity = 80
	raw := qualA38Envelope(qualA38Message(t, ctx, 10, 90), keys, 0, 2, 4)
	require.NoError(t, c.verifyIndependent(raw, qualA38Bytes(t, "creation"), ctx), "exact duration limit inclusive")
	c.bounds.maxValidity = 79
	require.Error(t, c.verifyIndependent(raw, qualA38Bytes(t, "creation"), ctx))
	c.bounds.maxValidity = 80
	require.NoError(t, c.verifyIndependent(raw, qualA38Bytes(t, "creation"), ctx))
}

func TestQualA38RepairCodecThresholdNeighbours(t *testing.T) {
	// Independently calculated ceil(3*n/5), not minimumProgrammeAuthorityThreshold.
	for _, tc := range []struct{ n, floor int }{{5, 3}, {6, 4}, {7, 5}, {8, 5}, {9, 6}, {10, 6}} {
		t.Run(strconv.Itoa(tc.n), func(t *testing.T) {
			c, ctx, keys := qualA38Fixture(t)
			c.bounds.maxMembers = 10 // explicit fixture capacity only
			for i := 5; i < tc.n; i++ {
				k := stded.NewKeyFromSeed(bytes.Repeat([]byte{byte(33 + i)}, stded.SeedSize))
				keys = append(keys, k)
				ctx.independent.members = append(ctx.independent.members, bytes.Clone(k.Public().(stded.PublicKey)))
			}
			indices := make([]uint64, tc.n)
			for i := range indices {
				indices[i] = uint64(i)
			}
			message := qualA38Message(t, ctx, 10, 90)
			for _, threshold := range []int{tc.floor, tc.n} {
				ctx.independent.threshold = uint64(threshold)
				require.NoError(t, c.verifyIndependent(qualA38Envelope(message, keys, indices[:threshold]...), qualA38Bytes(t, "creation"), ctx))
				require.Error(t, c.verifyIndependent(qualA38Envelope(message, keys, indices[:threshold-1]...), qualA38Bytes(t, "creation"), ctx))
				require.NoError(t, c.verifyIndependent(qualA38Envelope(message, keys, indices[:threshold]...), qualA38Bytes(t, "creation"), ctx))
			}
			ctx.independent.threshold = uint64(tc.floor - 1)
			require.Error(t, c.verifyIndependent(qualA38Envelope(message, keys, indices...), qualA38Bytes(t, "creation"), ctx))
			ctx.independent.threshold = uint64(tc.floor)
			require.NoError(t, c.verifyIndependent(qualA38Envelope(message, keys, indices[:tc.floor]...), qualA38Bytes(t, "creation"), ctx))
		})
	}
}

// Selected E14 expectations: independent test-side F, Blake2b and standard
// Ed25519 over existing public synthetic G6 literals, never SUT-produced bytes.
func qualInitialMessage(t *testing.T, independent bool, nb, na uint64) []byte {
	t.Helper()
	g := qualA38Split(qualB9Bytes(t, "G6"))
	a := qualA38Split(g[3])
	c := qualA38Split(g[4])
	body := a
	purpose := "INSTALL_INITIAL_ADMISSION"
	hash := qualB9Bytes(t, "A_hash")
	if independent {
		body = c
		purpose = "INSTALL_INITIAL_REGISTER_TOKEN"
		hash = qualB9Bytes(t, "C_hash")
	}
	role := qualA38Split(body[6])[0]
	return qualRecordFrame([]byte("DRWA/INITIAL_PROGRAMME_AUTHORITY_INSTALL/candidate1"), []byte("fixture-domain"), []byte(purpose), g[1], g[2], qualB9Bytes(t, "A_hash"), qualB9Bytes(t, "C_hash"), g[5], role, body[1], body[2], hash, qualA38U64(nb), qualA38U64(na))
}
func qualInitialEnvelope(t *testing.T, independent bool, nb, na uint64) []byte {
	t.Helper()
	group := byte(0)
	if independent {
		group = 1
	}
	_, keys := qualA38Keys(group)
	return qualA38Envelope(qualInitialMessage(t, independent, nb, na), keys, 0, 2, 4)
}
func TestQualInitialMaterializationPossession(t *testing.T) {
	bodies := qualB9Codec(t, nil)
	a, e := bodies.decodeInitial(qualB9Bytes(t, "G6"), []byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
	require.NoError(t, e)
	codec, e := newRegistrationApprovalCodec(bodies.source, registrationApprovalBounds{4096, 2048, 64, 64, 10, 100})
	require.NoError(t, e)
	for _, independent := range []bool{false, true} {
		verify := func(raw []byte, at HeaderMilliseconds) error {
			return codec.verifyInitialPossession(raw, []byte("fixture-domain"), a, independent, at)
		}
		raw := qualInitialEnvelope(t, independent, 90, 110)
		require.NoError(t, verify(raw, 100))
		require.NoError(t, verify(raw, 90))
		require.NoError(t, verify(raw, 110))
		group := byte(0)
		if independent {
			group = 1
		}
		_, keys := qualA38Keys(group)
		for coordinate := 0; coordinate < 14; coordinate++ {
			fields := qualA38Split(qualInitialMessage(t, independent, 90, 110))
			fields[coordinate] = append(bytes.Clone(fields[coordinate]), 0)
			require.Error(t, verify(qualA38Envelope(qualRecordFrame(fields...), keys, 0, 2, 4), 100), "one E14 coordinate %d", coordinate)
			require.NoError(t, verify(raw, 100), "restored positive")
		}
		for _, indices := range [][]uint64{{0, 2}, {0, 0, 4}, {4, 2, 0}, {0, 2, 5}} {
			require.Error(t, verify(qualA38Envelope(qualInitialMessage(t, independent, 90, 110), keys, indices...), 100))
		}
		require.Error(t, verify(qualInitialEnvelope(t, !independent, 90, 110), 100), "other role cannot substitute")
		require.Error(t, verify(raw, 89))
		require.Error(t, verify(raw, 111))
		require.Error(t, verify(qualInitialEnvelope(t, independent, 0, 101), 100))
		parts := qualA38Split(raw)
		sig := qualA38Split(parts[2])
		sig[2][0] ^= 1
		parts[2] = qualRecordFrame(sig...)
		require.Error(t, verify(qualRecordFrame(parts...), 100))
		require.Error(t, verify(append(bytes.Clone(raw), 0), 100))
		require.Error(t, verify(raw[:len(raw)-1], 100))
		// Exact width/canonicality/cardinality neighbours with independent signatures.
		parts = qualA38Split(raw)
		parts[1] = qualRecordFrame([]byte{0}, qualA38U64(2), qualA38U64(4))
		require.Error(t, verify(qualRecordFrame(parts...), 100))
		parts = qualA38Split(raw)
		parts[2] = qualRecordFrame(qualA38Split(parts[2])[:2]...)
		require.Error(t, verify(qualRecordFrame(parts...), 100))
		require.NoError(t, verify(raw, 100))
	}
}

func TestQualInitialMaterializationSignatureBounds(t *testing.T) {
	bodies := qualB9Codec(t, nil)
	a, e := bodies.decodeInitial(qualB9Bytes(t, "G6"), []byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
	require.NoError(t, e)
	c, e := newRegistrationApprovalCodec(bodies.source, registrationApprovalBounds{4096, 2048, 64, 64, 10, 100})
	require.NoError(t, e)
	_, keys := qualA38Keys(0)
	message := qualInitialMessage(t, false, 90, 110)
	verify := func(raw []byte) error { return c.verifyInitialPossession(raw, []byte("fixture-domain"), a, false, 100) }
	valid := qualInitialEnvelope(t, false, 90, 110)
	require.NoError(t, verify(valid))
	for _, indices := range [][]uint64{{0, 2}, {0, 0, 4}, {4, 2, 0}, {0, 2, 5}} {
		require.Error(t, verify(qualA38Envelope(message, keys, indices...)))
		require.NoError(t, verify(valid))
	}
	for _, fault := range []string{"missing_field", "extra_field", "index_width", "signature_width", "invalid_extra_signature", "wrong_group", "bad_time", "future", "expired", "long_lifetime", "over_budget", "noncanonical"} {
		raw := bytes.Clone(valid)
		m := message
		switch fault {
		case "missing_field":
			m = qualRecordFrame(qualA38Split(message)[:13]...)
			raw = qualA38Envelope(m, keys, 0, 2, 4)
		case "extra_field":
			m = qualRecordFrame(append(qualA38Split(message), nil)...)
			raw = qualA38Envelope(m, keys, 0, 2, 4)
		case "index_width":
			f := qualA38Split(raw)
			f[1] = qualRecordFrame([]byte{0}, qualA38U64(2), qualA38U64(4))
			raw = qualRecordFrame(f...)
		case "signature_width":
			f := qualA38Split(raw)
			signatures := qualA38Split(f[2])
			signatures[0] = signatures[0][:63]
			f[2] = qualRecordFrame(signatures...)
			raw = qualRecordFrame(f...)
		case "invalid_extra_signature":
			raw = qualA38Envelope(message, keys, 0, 1, 2, 3)
			f := qualA38Split(raw)
			signatures := qualA38Split(f[2])
			signatures[3][0] ^= 1
			f[2] = qualRecordFrame(signatures...)
			raw = qualRecordFrame(f...)
		case "wrong_group":
			_, wrong := qualA38Keys(1)
			raw = qualA38Envelope(message, wrong, 0, 2, 4)
		case "bad_time":
			raw = qualInitialEnvelope(t, false, 110, 90)
		case "future":
			raw = qualInitialEnvelope(t, false, 101, 110)
		case "expired":
			raw = qualInitialEnvelope(t, false, 90, 99)
		case "long_lifetime":
			raw = qualInitialEnvelope(t, false, 0, 101)
		case "over_budget":
			raw = make([]byte, 4097)
		case "noncanonical":
			raw = append(raw, 0)
		}
		require.Error(t, verify(raw), fault)
		require.NoError(t, verify(valid), "restored "+fault)
	}
}
