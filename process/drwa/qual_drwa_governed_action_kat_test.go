package drwa

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// Public independent Python field1/hashlib fixtures, generated BEFORE Go tests.
// No product codec/hasher generates expected bytes; no external runtime file is
// loaded. Hosts remain synthetic; these are not valid business/canonical proofs.
// Vector source qualification/models/T39_GAS_record_vectors_04.json SHA256 e5bd9cfaebf6772e8ecad96224c517eb85207d43c976f800c33c2def5870ebaa.
const qualGASIndependentVectors = `{"scope":"four experimental layouts/23 positions,12 variants,explicit nonce; no authority/canonicality/profile adoption","records":{"envelope":{"hex":"0a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573","field_hex":["6e","70726f6772616d2d7375626a656374","73796e7468657469632d636c617373","544f4b454e2d616263646566","0000000000000000","0000000000000064","0000000000000069","0000000000000078","73796e7468657469632d636f6d706c6574652d636c6173732d626f6479","73796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573"],"count":10},"proposed":{"hex":"0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a0850524f504f5345440a01000a0800000000000000000a0800000000000000000a00","field_hex":["0a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573","33ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b","50524f504f534544","00","0000000000000000","0000000000000000",""],"count":7},"executable":{"hex":"0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a0a45584543555441424c450a01000a0800000000000000000a0800000000000000000a00","field_hex":["0a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573","33ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b","45584543555441424c45","00","0000000000000000","0000000000000000",""],"count":7},"local_started":{"hex":"0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a0b494e5f50524f47524553530a01000a0800000000000000690a0800000000000000000a00","field_hex":["0a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573","33ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b","494e5f50524f4752455353","00","0000000000000069","0000000000000000",""],"count":7},"armed":{"hex":"0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a0b494e5f50524f47524553530a01000a0800000000000000690a0800000000000000700a00","field_hex":["0a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573","33ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b","494e5f50524f4752455353","00","0000000000000069","0000000000000070",""],"count":7},"expired":{"hex":"0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a07455850495245440a01000a0800000000000000000a0800000000000000000a0745585049524544","field_hex":["0a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573","33ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b","45585049524544","00","0000000000000000","0000000000000000","45585049524544"],"count":7},"stale":{"hex":"0aa1010a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e636965730a2033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b0a0943414e43454c4c45440a01000a0800000000000000000a0800000000000000000a0d5354414c455f42494e44494e47","field_hex":["0a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573","33ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b","43414e43454c4c4544","00","0000000000000000","0000000000000000","5354414c455f42494e44494e47"],"count":7},"member_ordinary":{"hex":"0a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0100","field_hex":["14e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb","00"],"count":2},"active_ordinary":{"hex":"0a0800000000000000010a0800000000000000010a201c02d8798578fd88f278aa8fe9ea0c413ff67a59e69ea58b6ed71de61095b9ad0a270a250a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0100","field_hex":["0000000000000001","0000000000000001","1c02d8798578fd88f278aa8fe9ea0c413ff67a59e69ea58b6ed71de61095b9ad","0a250a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0100"],"count":4},"member_protected":{"hex":"0a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0101","field_hex":["14e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb","01"],"count":2},"active_protected":{"hex":"0a0800000000000000010a0800000000000000000a20b547b52774401bccf9c107379fbb919846ef7010b9af66b629f679f18e8e73a40a270a250a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0101","field_hex":["0000000000000001","0000000000000000","b547b52774401bccf9c107379fbb919846ef7010b9af66b629f679f18e8e73a4","0a250a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0101"],"count":4},"active_empty":{"hex":"0a0800000000000000000a0800000000000000000a200e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a80a00","field_hex":["0000000000000000","0000000000000000","0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",""],"count":4}},"digests":{"payload":{"hex":"33ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b","preimage_hex":"445257412f4741532f5041594c4f41442f76310a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c6173730a0c544f4b454e2d6162636465660a0800000000000000000a0800000000000000640a0800000000000000690a0800000000000000780a1d73796e7468657469632d636f6d706c6574652d636c6173732d626f64790a2573796e7468657469632d66726f7a656e2d63757272656e742d646570656e64656e63696573"},"id":{"hex":"14e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb","preimage_hex":"445257412f4741532f76316e70726f6772616d2d7375626a65637473796e7468657469632d636c617373000000000000000033ede78526dcfa905092a2961a06738fe3e372613c320c2a963b0f433aaba33b"},"active_ordinary":{"hex":"1c02d8798578fd88f278aa8fe9ea0c413ff67a59e69ea58b6ed71de61095b9ad","preimage_hex":"0a250a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0100"},"active_protected":{"hex":"b547b52774401bccf9c107379fbb919846ef7010b9af66b629f679f18e8e73a4","preimage_hex":"0a250a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb0a0101"},"active_empty":{"hex":"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8","preimage_hex":""}},"keys":{"nonce":"454c524f4e444452574140676f7665726e6564416374696f6e406e6f6e6365400a016e0a0f70726f6772616d2d7375626a6563740a0f73796e7468657469632d636c617373","action":"454c524f4e444452574140676f7665726e6564416374696f6e40616374696f6e400a016e0a2014e8270b9aa56b9b31a1b6c11fef8a2ed8038bf6e300a5814f9bc68c0b11a8bb","active":"454c524f4e444452574140676f7665726e6564416374696f6e40616374697665400a016e0a0c544f4b454e2d616263646566"},"fixed":{"nonce0":"0000000000000000","nonce1":"0000000000000001"}}`

type qualGASVector struct {
	Hex    string   `json:"hex"`
	Fields []string `json:"field_hex"`
	Count  int      `json:"count"`
}
type qualGASDigestVector struct {
	Hex      string `json:"hex"`
	Preimage string `json:"preimage_hex"`
}
type qualGASVectors struct {
	Records map[string]qualGASVector       `json:"records"`
	Digests map[string]qualGASDigestVector `json:"digests"`
	Keys    map[string]string              `json:"keys"`
	Fixed   map[string]string              `json:"fixed"`
}

func qualGASVectorsLoad(t *testing.T) qualGASVectors {
	t.Helper()
	var v qualGASVectors
	require.NoError(t, json.Unmarshal([]byte(qualGASIndependentVectors), &v))
	require.Len(t, v.Records, 12)
	require.Len(t, v.Digests, 5)
	require.Len(t, v.Keys, 3)
	return v
}
func qualGASVectorBytes(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	require.NoError(t, err)
	return b
}

func TestQualDRWAGASIndependentWireVectors(t *testing.T) {
	v := qualGASVectorsLoad(t)
	f := qualGovernedActionNew(t)
	expectedEnvelope := qualGASVectorBytes(t, v.Records["envelope"].Hex)
	expectedDigest := qualGASVectorBytes(t, v.Digests["payload"].Hex)
	expectedID := qualGASVectorBytes(t, v.Digests["id"].Hex)
	envelope, err := f.g.envelope(f.p, 100)
	require.NoError(t, err)
	require.Equal(t, expectedEnvelope, envelope)
	digest, id := f.g.identity(envelope, f.p)
	require.Equal(t, expectedDigest, digest)
	require.Equal(t, expectedID, id)
	// Every expected preimage is prepared with Python, never the Go hash helper.
	for name, vector := range v.Digests {
		t.Run("digest/"+name, func(t *testing.T) {
			require.Equal(t, qualGASVectorBytes(t, vector.Hex), f.g.codec.hasher.Compute(string(qualGASVectorBytes(t, vector.Preimage))))
		})
	}
	for name, vector := range v.Records {
		t.Run("framing/"+name, func(t *testing.T) {
			fields := make([][]byte, 0, len(vector.Fields))
			for _, s := range vector.Fields {
				fields = append(fields, qualGASVectorBytes(t, s))
			}
			require.Len(t, fields, vector.Count)
			actual, err := f.g.codec.frame(fields...)
			require.NoError(t, err)
			require.Equal(t, qualGASVectorBytes(t, vector.Hex), actual)
			decoded, err := f.g.codec.unframe(actual, vector.Count)
			require.NoError(t, err)
			require.Equal(t, fields, decoded)
		})
	}
	for kind, fields := range map[string][][]byte{"nonce": {[]byte("n"), f.p.subject, f.p.class}, "action": {[]byte("n"), expectedID}, "active": {[]byte("n"), f.p.token}} {
		t.Run("key/"+kind, func(t *testing.T) {
			key, err := f.g.key(kind, fields...)
			require.NoError(t, err)
			require.Equal(t, qualGASVectorBytes(t, v.Keys[kind]), key)
		})
	}
	for _, name := range []string{"empty", "ordinary", "protected"} {
		t.Run("aggregate/"+name, func(t *testing.T) {
			var m []governedActionMember
			if name != "empty" {
				m = append(m, governedActionMember{id: expectedID, protected: name == "protected"})
			}
			encoded, err := f.g.aggregate(m)
			require.NoError(t, err)
			require.Equal(t, qualGASVectorBytes(t, v.Records["active_"+name].Hex), encoded)
			decoded, err := f.g.members(encoded)
			require.NoError(t, err)
			require.Len(t, decoded, len(m))
			for i := range m {
				require.Equal(t, m[i], decoded[i])
			}
		})
	}
}

func TestQualDRWAGASIndependentPersistedTransitions(t *testing.T) {
	v := qualGASVectorsLoad(t)
	for _, name := range []string{"proposed", "executable", "local_started", "armed", "expired", "stale"} {
		t.Run(name, func(t *testing.T) {
			f := qualGovernedActionNew(t)
			f.initialize(t)
			require.Equal(t, qualGASVectorBytes(t, v.Fixed["nonce0"]), qualRegistryValue(t, f.s, string(f.counter())))
			require.Equal(t, qualGASVectorBytes(t, v.Records["active_empty"].Hex), qualRegistryValue(t, f.s, string(f.activeKey())))
			id := f.propose(t)
			require.Equal(t, qualGASVectorBytes(t, v.Digests["id"].Hex), id)
			require.Equal(t, qualGASVectorBytes(t, v.Fixed["nonce1"]), qualRegistryValue(t, f.s, string(f.counter())))
			f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 105)
			switch name {
			case "executable", "local_started", "armed":
				require.NoError(t, f.g.authorize(f.x, id, []byte("synthetic-full-authorize")))
				if name != "executable" {
					f.h.arm = name == "armed"
					require.NoError(t, f.g.start(f.x, id, []byte("synthetic-current-start")))
				}
			case "expired":
				f.x = qualGovernedContext(t, f.c, core.MetachainShardId, 120)
				require.NoError(t, f.g.cleanup(f.x, id, "EXPIRED", []byte("synthetic-no-irreversible-proof")))
			case "stale":
				require.NoError(t, f.g.cleanup(f.x, id, "STALE_BINDING", []byte("synthetic-no-irreversible-proof")))
			}
			record, _, stored, err := f.g.load(id)
			require.NoError(t, err)
			require.Equal(t, qualGASVectorBytes(t, v.Records[name].Hex), stored)
			require.Equal(t, qualGASVectorBytes(t, v.Records["envelope"].Hex), record.envelope)
			require.Equal(t, qualGASVectorBytes(t, v.Digests["payload"].Hex), record.digest)
			want := v.Records["active_ordinary"].Hex
			if name == "expired" || name == "stale" {
				want = v.Records["active_empty"].Hex
			}
			require.Equal(t, qualGASVectorBytes(t, want), qualRegistryValue(t, f.s, string(f.activeKey())))
		})
	}
}

func TestQualDRWAGASIndependentDomainSeparation(t *testing.T) {
	v := qualGASVectorsLoad(t)
	f := qualGovernedActionNew(t)
	// Fixture-only alternate constructor identity, not an admitted network domain.
	f.g.domain = []byte("different-domain")
	envelope, err := f.g.envelope(f.p, 100)
	require.NoError(t, err)
	digest, id := f.g.identity(envelope, f.p)
	require.NotEqual(t, qualGASVectorBytes(t, v.Digests["payload"].Hex), digest)
	require.NotEqual(t, qualGASVectorBytes(t, v.Digests["id"].Hex), id)
	for kind, fields := range map[string][][]byte{"nonce": {f.g.domain, f.p.subject, f.p.class}, "action": {f.g.domain, id}, "active": {f.g.domain, f.p.token}} {
		key, err := f.g.key(kind, fields...)
		require.NoError(t, err)
		require.NotEqual(t, qualGASVectorBytes(t, v.Keys[kind]), key)
	}
}
