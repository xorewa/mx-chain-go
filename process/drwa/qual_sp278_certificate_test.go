package drwa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519/singlesig"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/stretchr/testify/require"
)

// SP2-78: the certificate contract. Every case runs the real verifier with the
// native hook as time source (the object the production time-source function
// returns) over a real account store. All forms are EXPERIMENTAL.

type qualSP278Bench struct {
	t      *testing.T
	store  *qualNativeStore
	codec  *registrationRecords
	hook   *hooks.BlockChainHookImpl
	set    scopedAuthoritySet
	keys   []crypto.PrivateKey
	limits certificateLimits
	end    func()
}

func qualSP278New(t *testing.T) *qualSP278Bench {
	t.Helper()
	b := &qualSP278Bench{t: t, store: qualRegistrationStore(t, 0), limits: certificateLimits{members: 5, bytes: 4096, lifetime: 60}}
	var err error
	b.codec, err = newRegistrationRecords(b.store, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	b.hook, _ = qualT42Hook(t, b.store, core.MetachainShardId, true)
	generator := signing.NewKeyGenerator(ed25519.NewEd25519())
	var members [][]byte
	for i := 0; i < 5; i++ {
		private, public := generator.GeneratePair()
		raw, keyErr := public.ToByteArray()
		require.NoError(t, keyErr)
		b.keys, members = append(b.keys, private), append(members, raw)
	}
	b.set = scopedAuthoritySet{id: []byte("sp2-78 test set"), hash: blake2b.NewBlake2b().Compute(string(qualRecordFrame(members...))),
		version: 2, threshold: 3, members: members, predecessor: []byte("predecessor set hash"), predecessorVersion: 1}
	return b
}

func (b *qualSP278Bench) body() certificateBody {
	return certificateBody{network: []byte("network domain"), operation: []byte("DRWA/FIXTURE_OPERATION/experimental1"), version: 1,
		purpose: []byte("FIXTURE_PURPOSE"), scope: []byte("programme scope"), subjects: [][]byte{[]byte("subject one"), []byte("subject two")},
		kind: []byte("fixture operation kind"), payload: []byte("payload digest"), setID: b.set.id, setHash: b.set.hash, setVersion: b.set.version,
		predecessor: b.set.predecessor, predecessorVersion: b.set.predecessorVersion, notBefore: 100, until: 150, nonce: []byte{0, 0, 0, 0, 0, 0, 0, 7}}
}

func (b *qualSP278Bench) sign(raw []byte, signers ...uint64) ([]uint64, [][]byte) {
	b.t.Helper()
	digest := blake2b.NewBlake2b().Compute(string(raw))
	var signatures [][]byte
	for _, i := range signers {
		signature, err := (&singlesig.Ed25519Signer{}).Sign(b.keys[i], digest)
		require.NoError(b.t, err)
		signatures = append(signatures, signature)
	}
	return signers, signatures
}

// at installs a header with the given time as the block processor does.
func (b *qualSP278Bench) at(time uint64) {
	b.t.Helper()
	if b.end != nil {
		b.end()
	}
	var err error
	_, b.end, err = qualSP224Begin(b.t, b.hook, qualT42Header(core.MetachainShardId, time))
	require.NoError(b.t, err)
}

func (b *qualSP278Bench) unchanged(run func() error) error {
	b.t.Helper()
	root, journal := qualSP224State(b.t, b.store)
	err := run()
	after, afterJournal := qualSP224State(b.t, b.store)
	require.Equal(b.t, root, after, "a certificate check changes no state")
	require.Equal(b.t, journal, afterJournal)
	return err
}

func TestQualSP278CertificateBindsEveryField(t *testing.T) {
	b := qualSP278New(t)
	signed := b.body()
	raw, err := encodeCertificateBody(b.codec, signed)
	require.NoError(t, err)
	indices, signatures := b.sign(raw, 0, 2, 4)
	b.at(120)
	verify := func(expected certificateBody, presented []byte) error {
		return b.unchanged(func() error {
			return verifyCertificate(b.codec, b.hook, expected, presented, b.set, indices, signatures, b.limits)
		})
	}
	require.NoError(t, verify(signed, raw), "positive: the consumer expects exactly what was signed")
	decoded, err := decodeCertificateBody(b.codec, raw)
	require.NoError(t, err)
	require.Equal(t, signed, decoded)

	// The consumer expects something else in exactly one bound field: the same
	// natively valid certificate is refused for it.
	for name, change := range map[string]func(*certificateBody){
		"network domain":        func(c *certificateBody) { c.network = []byte("another network") },
		"operation domain":      func(c *certificateBody) { c.operation = []byte("DRWA/OTHER_OPERATION/experimental1") },
		"certificate version":   func(c *certificateBody) { c.version = 2 },
		"purpose":               func(c *certificateBody) { c.purpose = []byte("OTHER_PURPOSE") },
		"scope":                 func(c *certificateBody) { c.scope = []byte("another programme") },
		"first subject":         func(c *certificateBody) { c.subjects = [][]byte{[]byte("subject ONE"), []byte("subject two")} },
		"second subject":        func(c *certificateBody) { c.subjects = [][]byte{[]byte("subject one"), []byte("subject 2")} },
		"subject order":         func(c *certificateBody) { c.subjects = [][]byte{[]byte("subject two"), []byte("subject one")} },
		"fewer subjects":        func(c *certificateBody) { c.subjects = [][]byte{[]byte("subject one")} },
		"more subjects":         func(c *certificateBody) { c.subjects = append(c.subjects, []byte("subject three")) },
		"operation kind":        func(c *certificateBody) { c.kind = []byte("another kind") },
		"payload digest":        func(c *certificateBody) { c.payload = []byte("another digest") },
		"nonce":                 func(c *certificateBody) { c.nonce = []byte{0, 0, 0, 0, 0, 0, 0, 8} },
		"no nonce":              func(c *certificateBody) { c.nonce = nil },
		"authority set id":      func(c *certificateBody) { c.setID = []byte("another set") },
		"authority set hash":    func(c *certificateBody) { c.setHash = []byte("another hash") },
		"authority set version": func(c *certificateBody) { c.setVersion = 3 },
		"predecessor hash":      func(c *certificateBody) { c.predecessor = []byte("another predecessor") },
		"predecessor version":   func(c *certificateBody) { c.predecessorVersion = 5 },
	} {
		expected := b.body()
		change(&expected)
		require.ErrorIs(t, verify(expected, raw), errCertificate, name)
	}

	// The resolved set is not the one the body names.
	for name, change := range map[string]func(*scopedAuthoritySet){
		"id":                  func(s *scopedAuthoritySet) { s.id = []byte("another set") },
		"hash":                func(s *scopedAuthoritySet) { s.hash = []byte("another hash") },
		"version":             func(s *scopedAuthoritySet) { s.version++ },
		"predecessor":         func(s *scopedAuthoritySet) { s.predecessor = nil; s.predecessorVersion = 0 },
		"predecessor version": func(s *scopedAuthoritySet) { s.predecessorVersion++ },
	} {
		set := b.set
		change(&set)
		err = b.unchanged(func() error {
			return verifyCertificate(b.codec, b.hook, signed, raw, set, indices, signatures, b.limits)
		})
		require.ErrorIs(t, err, errCertificate, "set "+name)
	}

	// Signatures: below the threshold, by another member, in another order, over
	// another body.
	for name, signers := range map[string][]uint64{"two of five": {0, 2}, "none": {}} {
		i, s := b.sign(raw, signers...)
		err = b.unchanged(func() error { return verifyCertificate(b.codec, b.hook, signed, raw, b.set, i, s, b.limits) })
		require.ErrorIs(t, err, errInvalidAuthoritySignatures, name)
	}
	err = b.unchanged(func() error {
		return verifyCertificate(b.codec, b.hook, signed, raw, b.set, []uint64{0, 1, 4}, signatures, b.limits)
	})
	require.ErrorIs(t, err, errInvalidAuthoritySignatures, "a signature presented for another member")
	err = b.unchanged(func() error {
		return verifyCertificate(b.codec, b.hook, signed, raw, b.set, []uint64{2, 0, 4}, [][]byte{signatures[1], signatures[0], signatures[2]}, b.limits)
	})
	require.ErrorIs(t, err, errInvalidAuthoritySignatures, "unordered signers")
	other := b.body()
	other.payload = []byte("another digest")
	otherRaw, err := encodeCertificateBody(b.codec, other)
	require.NoError(t, err)
	require.ErrorIs(t, verify(other, otherRaw), errInvalidAuthoritySignatures, "signatures of another body")

	// Limits have no default.
	for name, limits := range map[string]certificateLimits{
		"no member bound": {0, 4096, 60}, "no byte bound": {5, 0, 60}, "no lifetime": {5, 4096, 0},
		"body over the byte bound": {5, uint64(len(raw) - 1), 60}, "roster over the member bound": {4, 4096, 60},
	} {
		err = b.unchanged(func() error {
			return verifyCertificate(b.codec, b.hook, signed, raw, b.set, indices, signatures, limits)
		})
		require.Error(t, err, name)
	}
	require.ErrorIs(t, verifyCertificate(nil, b.hook, signed, raw, b.set, indices, signatures, b.limits), errCertificate)
	require.ErrorIs(t, verifyCertificate(b.codec, nil, signed, raw, b.set, indices, signatures, b.limits), errCertificate)
}

func TestQualSP278CertificateOneCanonicalEncoding(t *testing.T) {
	b := qualSP278New(t)
	signed := b.body()
	raw, err := encodeCertificateBody(b.codec, signed)
	require.NoError(t, err)
	// The product bytes are the documented field order in the native framing,
	// written here with the test's own framing.
	u64 := qualSP227Number
	expected := qualRecordFrame([]byte("DRWA/CERTIFICATE_BODY/experimental1"), signed.network, signed.operation, u64(1), signed.purpose, signed.scope,
		qualRecordFrame(signed.subjects...), signed.kind, signed.payload, signed.setID, u64(2), signed.setHash, u64(1), signed.predecessor,
		u64(100), u64(150), signed.nonce)
	require.Equal(t, expected, raw)
	digest, err := certificateDigest(b.codec, raw)
	require.NoError(t, err)
	require.Equal(t, blake2b.NewBlake2b().Compute(string(expected)), digest)
	indices, signatures := b.sign(raw, 0, 1, 2)
	b.at(100)
	require.NoError(t, verifyCertificate(b.codec, b.hook, signed, raw, b.set, indices, signatures, b.limits))

	// Other encodings of the same content. Each is signed over its own bytes, so
	// only the encoding rule can refuse it.
	nonMinimal := append([]byte{0x0a, 0x80 | byte(len(certificateBodyTag)), 0x00}, raw[2:]...)
	subjectsAsOne := qualRecordFrame([]byte("DRWA/CERTIFICATE_BODY/experimental1"), signed.network, signed.operation, u64(1), signed.purpose, signed.scope,
		append(qualRecordFrame(signed.subjects...), 0x0a, 0x00), signed.kind, signed.payload, signed.setID, u64(2), signed.setHash, u64(1), signed.predecessor,
		u64(100), u64(150), signed.nonce)
	shortNumber := qualRecordFrame([]byte("DRWA/CERTIFICATE_BODY/experimental1"), signed.network, signed.operation, []byte{1}, signed.purpose, signed.scope,
		qualRecordFrame(signed.subjects...), signed.kind, signed.payload, signed.setID, u64(2), signed.setHash, u64(1), signed.predecessor,
		u64(100), u64(150), signed.nonce)
	for name, other := range map[string][]byte{
		"trailing byte":           append(bytes.Clone(raw), 0),
		"trailing empty field":    append(bytes.Clone(raw), 0x0a, 0x00),
		"missing last field":      raw[:len(raw)-len(signed.nonce)-2],
		"non-minimal length":      nonMinimal,
		"foreign field tag":       append([]byte{0x12}, raw[1:]...),
		"another body tag":        append(qualRecordFrame([]byte("DRWA/CERTIFICATE_BODY/experimental2")), raw[2+len(certificateBodyTag):]...),
		"empty subject appended":  subjectsAsOne,
		"one-byte version number": shortNumber,
		"empty":                   nil,
	} {
		i, s := b.sign(other, 0, 1, 2)
		err = b.unchanged(func() error { return verifyCertificate(b.codec, b.hook, signed, other, b.set, i, s, b.limits) })
		require.ErrorIs(t, err, errCertificate, name)
		_, err = decodeCertificateBody(b.codec, other)
		require.ErrorIs(t, err, errCertificate, name)
	}

	// The encoder refuses a body with a missing bound field.
	for name, change := range map[string]func(*certificateBody){
		"no network": func(c *certificateBody) { c.network = nil }, "no operation": func(c *certificateBody) { c.operation = nil },
		"version zero": func(c *certificateBody) { c.version = 0 }, "no purpose": func(c *certificateBody) { c.purpose = nil },
		"no scope": func(c *certificateBody) { c.scope = nil }, "no subject": func(c *certificateBody) { c.subjects = nil },
		"empty subject": func(c *certificateBody) { c.subjects = [][]byte{nil} }, "no kind": func(c *certificateBody) { c.kind = nil },
		"no payload": func(c *certificateBody) { c.payload = nil }, "no set id": func(c *certificateBody) { c.setID = nil },
		"no set hash": func(c *certificateBody) { c.setHash = nil }, "set version zero": func(c *certificateBody) { c.setVersion = 0 },
		"predecessor without version": func(c *certificateBody) { c.predecessorVersion = 0 },
		"version without predecessor": func(c *certificateBody) { c.predecessor = nil },
		"over the codec bound":        func(c *certificateBody) { c.scope = make([]byte, 5000) },
		"subjects over the bound":     func(c *certificateBody) { c.subjects = [][]byte{make([]byte, 5000)} },
	} {
		c := b.body()
		change(&c)
		_, err = encodeCertificateBody(b.codec, c)
		require.ErrorIs(t, err, errCertificate, name)
	}
	_, err = encodeCertificateBody(nil, signed)
	require.ErrorIs(t, err, errCertificate)
	_, err = decodeCertificateBody(nil, raw)
	require.ErrorIs(t, err, errCertificate)
	_, err = certificateDigest(nil, raw)
	require.ErrorIs(t, err, errCertificate)
	_, err = certificateDigest(b.codec, nil)
	require.ErrorIs(t, err, errCertificate)
}

func TestQualSP278CertificateValidityThroughTheNativeTimeSource(t *testing.T) {
	b := qualSP278New(t)
	signed := b.body() // 100..150, class lifetime 60
	raw, err := encodeCertificateBody(b.codec, signed)
	require.NoError(t, err)
	indices, signatures := b.sign(raw, 1, 2, 3)
	verify := func() error {
		return b.unchanged(func() error {
			return verifyCertificate(b.codec, b.hook, signed, raw, b.set, indices, signatures, b.limits)
		})
	}
	// No evaluation begun: no time, no verdict.
	require.ErrorIs(t, verify(), ErrInactiveHeaderTime)
	for time, admitted := range map[uint64]bool{99: false, 100: true, 101: true, 149: true, 150: true, 151: false} {
		b.at(time)
		if admitted {
			require.NoError(t, verify(), "time %d", time)
		} else {
			require.ErrorIs(t, verify(), errCertificate, "time %d", time)
		}
	}
	// A header with time zero gives no coordinate (SP2-24 D-1).
	b.end()
	_, b.end, err = qualSP224Begin(t, b.hook, qualT42Header(core.MetachainShardId, 0))
	require.ErrorIs(t, err, ErrUnavailableHeaderTime)
	require.ErrorIs(t, verify(), ErrUnavailableHeaderTime)
	// A header installed by the plain setter is no time source.
	b.end()
	require.NoError(t, b.hook.SetCurrentHeader(qualT42Header(core.MetachainShardId, 120)))
	require.ErrorIs(t, verify(), ErrInactiveHeaderTime)
	// The evaluation ended.
	b.at(120)
	require.NoError(t, verify())
	b.end()
	require.ErrorIs(t, verify(), ErrInactiveHeaderTime)

	// Windows the class lifetime does not allow, each signed for itself.
	b.at(120)
	for name, window := range map[string][2]HeaderMilliseconds{
		"one over the lifetime": {100, 161}, "inverted": {130, 110}, "far future expiry": {100, ^HeaderMilliseconds(0)},
	} {
		c := b.body()
		c.notBefore, c.until = window[0], window[1]
		other, encodeErr := encodeCertificateBody(b.codec, c)
		require.NoError(t, encodeErr)
		i, s := b.sign(other, 1, 2, 3)
		err = b.unchanged(func() error { return verifyCertificate(b.codec, b.hook, c, other, b.set, i, s, b.limits) })
		require.ErrorIs(t, err, errCertificate, name)
	}
	exact := b.body()
	exact.notBefore, exact.until = 100, 160
	other, err := encodeCertificateBody(b.codec, exact)
	require.NoError(t, err)
	i, s := b.sign(other, 1, 2, 3)
	require.NoError(t, verifyCertificate(b.codec, b.hook, exact, other, b.set, i, s, b.limits), "exactly the lifetime")

	// Restart: a new hook and codec over the reopened store decide the same.
	reopened := qualSP224Reopen(t, b.store)
	b.store = reopened
	b.codec, err = newRegistrationRecords(reopened, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	b.end()
	b.hook, _ = qualT42Hook(t, reopened, core.MetachainShardId, true)
	b.end = nil
	require.ErrorIs(t, verify(), ErrInactiveHeaderTime, "no context survives the restart")
	for time, admitted := range map[uint64]bool{99: false, 100: true, 150: true, 151: false} {
		b.at(time)
		require.Equal(t, admitted, verify() == nil, "after the restart, time %d", time)
	}
}

// One certificate never satisfies two purposes or two subjects: presented to a
// consumer that expects another purpose, subject, kind or request, it is
// refused although its signatures are valid.
func TestQualSP278OneCertificateOnePurposeOneSubject(t *testing.T) {
	b := qualSP278New(t)
	b.at(120)
	signed := b.body()
	raw, err := encodeCertificateBody(b.codec, signed)
	require.NoError(t, err)
	indices, signatures := b.sign(raw, 0, 1, 2)
	require.NoError(t, verifyCertificate(b.codec, b.hook, signed, raw, b.set, indices, signatures, b.limits))
	second := b.body()
	second.purpose = []byte("SECOND_PURPOSE")
	require.ErrorIs(t, verifyCertificate(b.codec, b.hook, second, raw, b.set, indices, signatures, b.limits), errCertificate)
	second = b.body()
	second.subjects = [][]byte{[]byte("another subject"), []byte("subject two")}
	require.ErrorIs(t, verifyCertificate(b.codec, b.hook, second, raw, b.set, indices, signatures, b.limits), errCertificate)

	// The scoped authority check: a certificate of one role, kind, request
	// subject, action, owner, body, phase or use is refused for any other.
	all := qualSP227Rosters(t)
	f := qualSP227ConstitutionNew(t, all, qualSP227Programmes(all)[0])
	f.r.use, f.r.phase = scopedEmergencyAdd, scopedDirect
	f.bindRequest()
	wants := []scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)}
	proofs := f.sign(t, wants)
	require.NoError(t, f.verify(proofs), "control")
	for name, change := range map[string]func(){
		"another use":          func() { f.r.use = scopedEmergencyRelease },
		"another subject":      func() { f.r.subject = []byte("another subject") },
		"another action":       func() { f.r.action = []byte("another action") },
		"another owner":        func() { f.r.owner = []byte("another owner") },
		"another body":         func() { f.r.digest = []byte("another body commitment") },
		"another scope":        func() { f.r.scope = []byte("another programme") },
		"another network":      func() { f.r.domain = []byte("another network domain") },
		"another target shard": func() { f.r.targetShard = 2 },
	} {
		saved := f.r.clone()
		change()
		f.bindRequest()
		require.Error(t, f.verify(proofs), name)
		f.r = saved
		f.bindRequest()
	}
	require.NoError(t, f.verify(proofs), "control after the changes")
	release := proofs[0]
	release.requirement.kind = "release"
	f.r.use = scopedEmergencyRelease
	f.bindRequest()
	require.Error(t, f.verify([]scopedAuthorityProof{release}), "the add certificate presented as a release certificate")
}

type qualSP278Fixtures struct {
	Experimental bool `json:"experimental"`
	Set          struct {
		ID, Hash  string
		Version   uint64
		Threshold uint64
		Members   []string
		Signers   []uint64
	} `json:"authority_set"`
	Scoped struct {
		Use, Phase, Source, Locus uint32
		Target                    uint32 `json:"target_shard"`
		Role, Kind                string
		Network, Scope, Subject   string
		Action, Owner             string
		Commitment                string `json:"body_commitment"`
		NotBefore                 uint64 `json:"not_before"`
		Until                     uint64
		ExpectedBody              string `json:"expected_body"`
		ExpectedDigest            string `json:"expected_digest"`
		Signatures                []string
	} `json:"scoped_authority"`
	Transfer struct {
		Network, Scope, Token string
		TokenNonce            uint64 `json:"token_nonce"`
		Source, Destination   string
		Quantity              uint64
		CEBEpoch              uint64 `json:"ceb_epoch"`
		AuthorizationNonce    uint64 `json:"authorization_nonce"`
		TravelRule            string `json:"travel_rule"`
		Evidence              string
		NotBefore             uint64 `json:"not_before"`
		Until                 uint64
		ExpectedEffect        string `json:"expected_effect_digest"`
		ExpectedPayload       string `json:"expected_payload_digest"`
		ExpectedBody          string `json:"expected_body"`
		ExpectedDigest        string `json:"expected_digest"`
		Signatures            []string
	} `json:"transfer_authorization"`
	Supply struct {
		Token       string
		CEBEpoch    uint64 `json:"ceb_epoch"`
		CEBHash     string `json:"ceb_hash"`
		Action      string
		Closure     uint64
		OriginShard uint32 `json:"origin_shard"`
		Family      uint32
		Origin      string
		Cumulative  uint64 `json:"cumulative_issued"`
		Live        uint64 `json:"live_supply"`
		NextNonce   uint64 `json:"next_supply_nonce"`
		Record      string `json:"expected_supply_record"`
		Binding     string `json:"expected_binding"`
		Key         string `json:"expected_key"`
		Value       string `json:"expected_value"`
	} `json:"supply_evidence"`
}

func qualSP278Hex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	require.NoError(t, err)
	return raw
}

func qualSP278Load(t *testing.T) (*qualSP278Fixtures, scopedAuthoritySet, [][]byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/sp2_78_experimental_fixtures.json")
	require.NoError(t, err)
	fixtures := &qualSP278Fixtures{}
	require.NoError(t, json.Unmarshal(raw, fixtures))
	require.True(t, fixtures.Experimental)
	set := scopedAuthoritySet{id: qualSP278Hex(t, fixtures.Set.ID), hash: qualSP278Hex(t, fixtures.Set.Hash), version: fixtures.Set.Version, threshold: fixtures.Set.Threshold}
	for _, member := range fixtures.Set.Members {
		set.members = append(set.members, qualSP278Hex(t, member))
	}
	return fixtures, set, nil
}

func qualSP278Signatures(t *testing.T, values []string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, value := range values {
		out = append(out, qualSP278Hex(t, value))
	}
	return out
}

// The expected bytes, digests and signatures of the fixture file were produced
// by testdata/sp2_78_experimental_fixtures.py, which shares no code with the
// product. The product must reproduce them and accept the signatures.
func TestQualSP278IndependentlyExpectedCertificateFixtures(t *testing.T) {
	fixtures, set, _ := qualSP278Load(t)
	b := qualSP278New(t)
	h := func(value string) []byte { return qualSP278Hex(t, value) }

	t.Run("scoped_authority", func(t *testing.T) {
		x := fixtures.Scoped
		require.EqualValues(t, x.Use, scopedEmergencyAdd, "the fixture's use number is the product's")
		require.EqualValues(t, x.Phase, scopedDirect)
		require.EqualValues(t, x.Source, scopedCurrent)
		require.Equal(t, x.Role, scopedEA)
		require.Equal(t, core.MetachainShardId, x.Locus)
		r := scopedAuthorityRequest{use: scopedAuthorityUse(x.Use), phase: scopedAuthorityPhase(x.Phase), locus: x.Locus, targetShard: x.Target,
			domain: h(x.Network), scope: h(x.Scope), subject: h(x.Subject), action: h(x.Action), owner: h(x.Owner), digest: h(x.Commitment)}
		proof := scopedAuthorityProof{requirement: scopedAuthorityRequirement{x.Role, x.Kind, int(x.Source)}, id: set.id, hash: set.hash, version: set.version,
			notBefore: HeaderMilliseconds(x.NotBefore), until: HeaderMilliseconds(x.Until), indices: fixtures.Set.Signers, signatures: qualSP278Signatures(t, x.Signatures)}
		raw, err := scopedAuthorityCertificate(b.codec, r, proof, set)
		require.NoError(t, err)
		require.Equal(t, h(x.ExpectedBody), raw)
		digest, err := certificateDigest(b.codec, raw)
		require.NoError(t, err)
		require.Equal(t, h(x.ExpectedDigest), digest)

		// The whole check accepts the fixture's signatures for this request.
		all := qualSP227Rosters(t)
		f := qualSP227ConstitutionNew(t, all, qualSP227Programmes(all)[0])
		f.r = r
		f.s.v.current[scopedEA], f.s.v.bound[scopedEA] = set, set
		f.bindRequest()
		f.s.v.time = qualGovernedContext(t, f.clock, core.MetachainShardId, x.NotBefore)
		require.NoError(t, f.verify([]scopedAuthorityProof{proof}))
		proof.signatures[0][0] ^= 1
		require.ErrorIs(t, f.verify([]scopedAuthorityProof{proof}), errInvalidAuthoritySignatures)
		_, err = scopedAuthorityCertificate(nil, r, proof, set)
		require.ErrorIs(t, err, errInvalidAuthoritySignatures)
	})

	t.Run("transfer_authorization", func(t *testing.T) {
		x := fixtures.Transfer
		a := transferAuthorization{network: h(x.Network), scope: h(x.Scope), token: h(x.Token), tokenNonce: x.TokenNonce, source: h(x.Source),
			destination: h(x.Destination), quantity: new(big.Int).SetUint64(x.Quantity), cebEpoch: x.CEBEpoch, authorizationNonce: x.AuthorizationNonce,
			travelRule: h(x.TravelRule), evidence: h(x.Evidence)}
		effect, err := transferAuthorizationEffectDigest(b.codec, a)
		require.NoError(t, err)
		require.Equal(t, h(x.ExpectedEffect), effect)
		raw, err := transferAuthorizationCertificate(b.codec, a, set, HeaderMilliseconds(x.NotBefore), HeaderMilliseconds(x.Until))
		require.NoError(t, err)
		require.Equal(t, h(x.ExpectedBody), raw)
		decoded, err := decodeCertificateBody(b.codec, raw)
		require.NoError(t, err)
		require.Equal(t, h(x.ExpectedPayload), decoded.payload)
		digest, err := certificateDigest(b.codec, raw)
		require.NoError(t, err)
		require.Equal(t, h(x.ExpectedDigest), digest)
		b.at(x.NotBefore)
		require.NoError(t, b.unchanged(func() error {
			return verifyTransferAuthorization(b.codec, b.hook, a, raw, set, fixtures.Set.Signers, qualSP278Signatures(t, x.Signatures), b.limits)
		}))
	})
}
