package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon"
	statestub "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-78, carry O-T7: the transfer-authorization certificate of an
// authorization-mediated token, the early certificate contract of SP2-50.

func qualSP278Transfer() transferAuthorization {
	return transferAuthorization{network: []byte("network domain"), scope: []byte("programme scope"), token: []byte(qualSP278Token), tokenNonce: 7,
		source: bytes.Repeat([]byte{0x11}, 32), destination: bytes.Repeat([]byte{0x22}, 32), quantity: big.NewInt(1500), cebEpoch: 3,
		authorizationNonce: 9, travelRule: []byte("TRAVEL_RULE_SATISFIED"), evidence: blake2b.NewBlake2b().Compute("evidence")}
}

func TestQualSP278TransferAuthorizationExactEffectOnly(t *testing.T) {
	b := qualSP278New(t)
	b.limits.lifetime = 60
	authorized := qualSP278Transfer()
	raw, err := transferAuthorizationCertificate(b.codec, authorized, b.set, 1000, 1060)
	require.NoError(t, err)
	indices, signatures := b.sign(raw, 0, 1, 2)
	verify := func(actual transferAuthorization) error {
		return b.unchanged(func() error {
			return verifyTransferAuthorization(b.codec, b.hook, actual, raw, b.set, indices, signatures, b.limits)
		})
	}
	require.ErrorIs(t, verify(authorized), ErrInactiveHeaderTime, "no evaluated header, no verdict")
	b.at(1030)
	require.NoError(t, verify(authorized))

	relayer := bytes.Repeat([]byte{0x99}, 32)
	for name, change := range map[string]func(*transferAuthorization){
		"another quantity":                func(a *transferAuthorization) { a.quantity = big.NewInt(1501) },
		"a smaller quantity":              func(a *transferAuthorization) { a.quantity = big.NewInt(1) },
		"another destination":             func(a *transferAuthorization) { a.destination = bytes.Repeat([]byte{0x23}, 32) },
		"the relayer as source":           func(a *transferAuthorization) { a.source = relayer },
		"source and destination swapped":  func(a *transferAuthorization) { a.source, a.destination = a.destination, a.source },
		"another token":                   func(a *transferAuthorization) { a.token = []byte("OTHR-0a1b2c") },
		"another token nonce":             func(a *transferAuthorization) { a.tokenNonce = 8 },
		"another CEB epoch":               func(a *transferAuthorization) { a.cebEpoch = 4 },
		"the nonce already consumed":      func(a *transferAuthorization) { a.authorizationNonce = 10 },
		"a lower nonce":                   func(a *transferAuthorization) { a.authorizationNonce = 8 },
		"another Travel-Rule disposition": func(a *transferAuthorization) { a.travelRule = []byte("TRAVEL_RULE_NOT_REQUIRED") },
		"no Travel-Rule disposition":      func(a *transferAuthorization) { a.travelRule = nil },
		"another evidence commitment":     func(a *transferAuthorization) { a.evidence = blake2b.NewBlake2b().Compute("other") },
		"another programme":               func(a *transferAuthorization) { a.scope = []byte("another programme") },
		"another network":                 func(a *transferAuthorization) { a.network = []byte("another network") },
	} {
		actual := qualSP278Transfer()
		change(&actual)
		require.ErrorIs(t, verify(actual), errCertificate, name)
	}
	// An effect that is no transfer is refused before any comparison.
	for name, change := range map[string]func(*transferAuthorization){
		"no network": func(a *transferAuthorization) { a.network = nil }, "no scope": func(a *transferAuthorization) { a.scope = nil },
		"invalid token": func(a *transferAuthorization) { a.token = []byte("not a token") }, "short source": func(a *transferAuthorization) { a.source = []byte("short") },
		"short destination": func(a *transferAuthorization) { a.destination = []byte("short") }, "no quantity": func(a *transferAuthorization) { a.quantity = nil },
		"zero quantity": func(a *transferAuthorization) { a.quantity = big.NewInt(0) }, "negative quantity": func(a *transferAuthorization) { a.quantity = big.NewInt(-5) },
		"CEB epoch zero": func(a *transferAuthorization) { a.cebEpoch = 0 }, "no evidence commitment": func(a *transferAuthorization) { a.evidence = nil },
		"quantity over the codec bound":    func(a *transferAuthorization) { a.quantity = new(big.Int).Lsh(big.NewInt(1), 40000) },
		"disposition over the codec bound": func(a *transferAuthorization) { a.travelRule = make([]byte, 5000) },
	} {
		actual := qualSP278Transfer()
		change(&actual)
		require.ErrorIs(t, verify(actual), errCertificate, name)
		_, err = transferAuthorizationCertificate(b.codec, actual, b.set, 1000, 1060)
		require.ErrorIs(t, err, errCertificate, name)
	}
	_, err = transferAuthorizationEffectDigest(nil, authorized)
	require.ErrorIs(t, err, errCertificate)

	// A certificate of another purpose or operation with the same subjects and
	// payload is no transfer authorization.
	body, err := decodeCertificateBody(b.codec, raw)
	require.NoError(t, err)
	for name, change := range map[string]func(*certificateBody){
		"wrong purpose":   func(c *certificateBody) { c.purpose = []byte("ADMINISTRATIVE_TRANSFER") },
		"wrong operation": func(c *certificateBody) { c.operation = []byte(scopedAuthorityCertificateOperation) },
		"wrong kind":      func(c *certificateBody) { c.kind = []byte("ESDTTransfer") },
		"wrong version":   func(c *certificateBody) { c.version = 2 },
	} {
		other := body
		change(&other)
		otherRaw, encodeErr := encodeCertificateBody(b.codec, other)
		require.NoError(t, encodeErr)
		i, s := b.sign(otherRaw, 0, 1, 2)
		err = b.unchanged(func() error {
			return verifyTransferAuthorization(b.codec, b.hook, authorized, otherRaw, b.set, i, s, b.limits)
		})
		require.ErrorIs(t, err, errCertificate, name)
	}
	// Another authority set, although its members sign.
	rotated := b.set
	rotated.version++
	require.ErrorIs(t, b.unchanged(func() error {
		return verifyTransferAuthorization(b.codec, b.hook, authorized, raw, rotated, indices, signatures, b.limits)
	}), errCertificate)

	// Validity at the evaluated header time: inclusive at both ends.
	for time, admitted := range map[uint64]bool{999: false, 1000: true, 1060: true, 1061: false} {
		b.at(time)
		require.Equal(t, admitted, verify(authorized) == nil, "time %d", time)
	}
	// The effect digest excludes everything but the intent.
	first, err := transferAuthorizationEffectDigest(b.codec, authorized)
	require.NoError(t, err)
	other := qualSP278Transfer()
	other.authorizationNonce, other.travelRule, other.evidence, other.scope = 77, nil, []byte("x"), []byte("another")
	second, err := transferAuthorizationEffectDigest(b.codec, other)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

// Faults of the stores and hashers under the new code: every error is
// returned, nothing is written.
func TestQualSP278StoreAndHasherFaults(t *testing.T) {
	failure := errors.New("injected store failure")
	short := &testscommon.HasherStub{SizeCalled: func() int { return 32 }, ComputeCalled: func(string) []byte { return []byte("short") }}
	b := qualSP278New(t)
	stubbed := *b.codec
	stubbed.hasher = short
	_, err := certificateDigest(&stubbed, []byte("body"))
	require.ErrorIs(t, err, errCertificate)
	_, err = transferAuthorizationEffectDigest(&stubbed, qualSP278Transfer())
	require.ErrorIs(t, err, errCertificate)
	raw, err := encodeCertificateBody(b.codec, b.body())
	require.NoError(t, err)
	indices, signatures := b.sign(raw, 0, 1, 2)
	b.at(120)
	require.ErrorIs(t, verifyCertificate(&stubbed, b.hook, b.body(), raw, b.set, indices, signatures, b.limits), errCertificate)
	calls := 0
	second := *b.codec
	second.hasher = &testscommon.HasherStub{SizeCalled: func() int { return 32 }, ComputeCalled: func(value string) []byte {
		calls++
		if calls > 1 {
			return []byte("short")
		}
		return blake2b.NewBlake2b().Compute(value)
	}}
	_, err = transferAuthorizationCertificate(&second, qualSP278Transfer(), b.set, 1, 2)
	require.ErrorIs(t, err, errCertificate, "the payload digest")
	// A subjects field that is not a frame.
	broken := qualRecordFrame([]byte(certificateBodyTag), []byte("n"), []byte("o"), qualSP227Number(1), []byte("p"), []byte("s"), []byte("not a frame"),
		[]byte("k"), []byte("d"), []byte("i"), qualSP227Number(1), []byte("h"), qualSP227Number(0), nil, qualSP227Number(1), qualSP227Number(2), nil)
	_, err = decodeCertificateBody(b.codec, broken)
	require.ErrorIs(t, err, errCertificate)

	// The scoped authority body under a codec that holds its operation kind but
	// not the whole body.
	all := qualSP227Rosters(t)
	f := qualSP227ConstitutionNew(t, all, qualSP227Programmes(all)[0])
	f.r.use, f.r.phase = scopedEmergencyAdd, scopedDirect
	f.bindRequest()
	proofs := f.sign(t, []scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)})
	require.NoError(t, f.verify(proofs))
	f.codec, err = newRegistrationRecords(qualRegistrationStore(t, 0), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 200)
	require.NoError(t, err)
	require.ErrorIs(t, f.verify(proofs), errInvalidAuthoritySignatures)

	// The origin writer over failing accounts.
	codec := func(accounts *statestub.AccountsStub, maxBytes int) (*registrationRecords, *rootLeafRecords) {
		records, recordsErr := newRegistrationRecords(accounts, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), maxBytes)
		require.NoError(t, recordsErr)
		wide, wideErr := newRegistrationRecords(accounts, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
		require.NoError(t, wideErr)
		leaves, leavesErr := newRootLeafRecords(wide, 32)
		require.NoError(t, leavesErr)
		return records, leaves
	}
	binding := qualSP278Binding(1)
	origin := qualSP278OriginNew(t, 1)
	supply := origin.supply(t, qualSP278Token, 1, 1000, 990)
	supplyKey, err := origin.leaves.outerKey(supplyStatePrefix, []byte(qualSP278Token))
	require.NoError(t, err)
	for name, c := range map[string]struct {
		read    func(key []byte) ([]byte, uint32, error)
		save    error
		account error
		store   error
		bytes   int
	}{
		"no system account":      {account: failure, bytes: 4096},
		"SupplyState read fails": {read: func([]byte) ([]byte, uint32, error) { return nil, 0, failure }, bytes: 4096},
		"item read fails": {read: func(key []byte) ([]byte, uint32, error) {
			if bytes.Equal(key, supplyKey) {
				return supply, 0, nil
			}
			return nil, 0, failure
		}, bytes: 4096},
		"item write fails": {read: func(key []byte) ([]byte, uint32, error) {
			if bytes.Equal(key, supplyKey) {
				return supply, 0, nil
			}
			return nil, 0, nil
		}, save: failure, bytes: 4096},
		"account save fails": {read: func(key []byte) ([]byte, uint32, error) {
			if bytes.Equal(key, supplyKey) {
				return supply, 0, nil
			}
			return nil, 0, nil
		}, store: failure, bytes: 4096},
	} {
		saved := 0
		account := &statestub.UserAccountStub{Address: bytes.Clone(core.SystemAccountAddress), RetrieveValueCalled: c.read,
			SaveKeyValueCalled: func([]byte, []byte) error { saved++; return c.save }}
		accounts := &statestub.AccountsStub{
			GetExistingAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
				if c.account != nil {
					return nil, c.account
				}
				return account, nil
			},
			SaveAccountCalled: func(vmcommon.AccountHandler) error { return c.store },
		}
		records, leaves := codec(accounts, c.bytes)
		writer, writerErr := NewSupplyEvidenceWriter(records, leaves, 1)
		require.NoError(t, writerErr)
		require.ErrorIs(t, writer.Attest(binding), failure, name)
		if c.save == nil && c.store == nil {
			require.Zero(t, saved, name)
		}
	}
	// An item that does not fit the record bound is refused, not truncated.
	_, _, err = supplyEvidenceItem(&registrationRecords{marshaller: &marshal.GogoProtoMarshalizer{}, hasher: blake2b.NewBlake2b(), maxBytes: 40},
		[]byte("binding"), big.NewInt(1), blake2b.NewBlake2b().Compute("x"))
	require.ErrorIs(t, err, errSupplyEvidence)
}

// A shard whose item value is not the canonical form gives no value, although
// the evidence of the item is canonical.
func TestQualSP278SupplyEvidenceRefusesANonCanonicalItem(t *testing.T) {
	for name, value := range map[string]func(codec *registrationRecords, identity []byte) []byte{
		"not a frame": func(*registrationRecords, []byte) []byte { return []byte("cumulative issued: 1") },
		"cumulative with a leading zero": func(codec *registrationRecords, identity []byte) []byte {
			return qualRecordFrame(identity, []byte{0, 1}, codec.hasher.Compute("record"))
		},
		"another binding's identity": func(codec *registrationRecords, identity []byte) []byte {
			return qualRecordFrame(codec.hasher.Compute("other"), []byte{1}, codec.hasher.Compute("record"))
		},
		"short record hash": func(codec *registrationRecords, identity []byte) []byte {
			return qualRecordFrame(identity, []byte{1}, []byte("short"))
		},
		"a fourth field": func(codec *registrationRecords, identity []byte) []byte {
			return qualRecordFrame(identity, []byte{1}, codec.hasher.Compute("record"), []byte("more"))
		},
	} {
		origin := qualSP278OriginNew(t, 1)
		binding := qualSP278Binding(1)
		encoded, err := binding.encode(origin.codec)
		require.NoError(t, err)
		identity := origin.codec.hasher.Compute(string(encoded))
		qualSP278Put(t, origin.f.s, append([]byte(supplyEvidencePrefix), identity...), value(origin.codec, identity))
		origin.settle(t, 11)
		meta := qualSP278MetaNew(t)
		meta.enter(origin)
		evidence := origin.evidence(t, binding)
		meta.refused(name, func() (*big.Int, error) { return meta.verifier.CumulativeIssued(binding, evidence) })
	}
	// Evidence whose proof lists are not frames.
	meta := qualSP278MetaNew(t)
	malformed := qualRecordFrame([]byte("S"), []byte("H"), []byte("proof"), []byte("not a list"), nil, nil, nil)
	meta.refused("malformed list", func() (*big.Int, error) { return meta.verifier.CumulativeIssued(qualSP278Binding(1), malformed) })
}

// The production constructor of a metachain node: native dependencies only,
// its own proof cache, the same decisions.
func TestQualSP278NativeSupplyEvidenceVerifier(t *testing.T) {
	origin := qualSP278OriginNew(t, 1)
	origin.supply(t, qualSP278Token, 1, 4242, 4000)
	binding := qualSP278Binding(1)
	require.NoError(t, origin.writer.Attest(binding))
	origin.settle(t, 11)
	meta := qualSP278MetaNew(t)
	meta.enter(origin)
	reader := meta.verifier.args.Reader
	exclusions, err := common.NewRoundExclusionHandler(nil)
	require.NoError(t, err)
	args := ArgsNativeSupplyEvidenceVerifier{Accounts: meta.store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: origin.codec.hasher,
		EnableEpochsHandler: reader.accounts.args.EnableEpochsHandler, MaxTrieLevelInMemory: 5,
		Validator: reader.validator, Proofs: reader.proofs, Integrity: reader.integrity, Exclusions: exclusions,
		Block: meta.block, RecordBytes: 4096, EvidenceBytes: 1 << 20}
	native, err := NewNativeSupplyEvidenceVerifier(args)
	require.NoError(t, err)
	evidence := origin.evidence(t, binding)
	value, err := native.CumulativeIssued(binding, evidence)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(4242), value)
	require.NotEmpty(t, native.cache.nodes, "the read used the verifier's own proof cache")
	later := binding
	later.Closure++
	_, err = native.CumulativeIssued(later, evidence)
	require.Error(t, err)
	_, err = native.ValidateCap(binding, big.NewInt(4241), evidence)
	require.ErrorIs(t, err, errSupplyEvidence)
	for name, change := range map[string]func(*ArgsNativeSupplyEvidenceVerifier){
		"no record bytes": func(a *ArgsNativeSupplyEvidenceVerifier) { a.RecordBytes = 0 }, "no epochs": func(a *ArgsNativeSupplyEvidenceVerifier) { a.EnableEpochsHandler = nil },
		"no validator": func(a *ArgsNativeSupplyEvidenceVerifier) { a.Validator = nil }, "no block source": func(a *ArgsNativeSupplyEvidenceVerifier) { a.Block = nil },
		"no evidence size": func(a *ArgsNativeSupplyEvidenceVerifier) { a.EvidenceBytes = 0 },
	} {
		changed := args
		change(&changed)
		_, err = NewNativeSupplyEvidenceVerifier(changed)
		require.Error(t, err, name+": refused, not defaulted")
	}
}
