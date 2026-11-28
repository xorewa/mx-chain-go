package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// SP2-78 certificate contract (Part A L1146-1164, L1234-1244, AR-05 L1692; F.2
// L11048). EXPERIMENTAL form: the tag below is a qualification form, not a
// released or frozen encoding. One canonical body binds everything the clause
// lists: network domain, operation-specific domain, certificate version,
// purpose, scope, subjects, operation kind, payload digest, the signing
// authority set with its version, hash and predecessor, validity and nonce.
// The signature is over the hash of exactly these bytes; nothing else is signed.
const certificateBodyTag = "DRWA/CERTIFICATE_BODY/experimental1"

var errCertificate = errors.New("invalid DRWA certificate")

// certificateBody is the decoded canonical body. A consumer builds the body it
// expects from its own authenticated state; a presented certificate is
// accepted only when its bytes are exactly the encoding of that expectation.
type certificateBody struct {
	network, operation []byte
	version            uint64
	purpose, scope     []byte
	subjects           [][]byte
	kind, payload      []byte
	setID, setHash     []byte
	setVersion         uint64
	predecessor        []byte
	predecessorVersion uint64
	notBefore, until   HeaderMilliseconds
	nonce              []byte
}

// certificateLimits come from the owning admitted profile (Part A L1241-1244:
// the E.12/O-11 schedule). No value has a default: a zero bound refuses.
type certificateLimits struct {
	members, bytes uint64
	lifetime       HeaderMilliseconds
}

func certificateNumber(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

// encodeCertificateBody returns the one canonical encoding: the tag and
// sixteen fields in the native Batch wire form, in this order.
func encodeCertificateBody(codec *registrationRecords, b certificateBody) ([]byte, error) {
	if codec == nil || check.IfNil(codec.hasher) || len(b.network) == 0 || len(b.operation) == 0 || b.version == 0 ||
		len(b.purpose) == 0 || len(b.scope) == 0 || len(b.subjects) == 0 || len(b.kind) == 0 ||
		len(b.payload) == 0 || len(b.setID) == 0 || len(b.setHash) == 0 || b.setVersion == 0 ||
		(len(b.predecessor) == 0) != (b.predecessorVersion == 0) {
		return nil, errCertificate
	}
	for _, subject := range b.subjects {
		if len(subject) == 0 {
			return nil, errCertificate
		}
	}
	subjects, err := codec.frameBatch(true, b.subjects...)
	if err != nil {
		return nil, errCertificate
	}
	raw, err := codec.frameBatch(true, []byte(certificateBodyTag), b.network, b.operation, certificateNumber(b.version),
		b.purpose, b.scope, subjects, b.kind, b.payload, b.setID, certificateNumber(b.setVersion), b.setHash,
		certificateNumber(b.predecessorVersion), b.predecessor,
		certificateNumber(uint64(b.notBefore)), certificateNumber(uint64(b.until)), b.nonce)
	if err != nil {
		return nil, errCertificate
	}
	return raw, nil
}

// decodeCertificateBody accepts only the canonical encoding of a body: the
// decoded fields are encoded again and must give the presented bytes.
func decodeCertificateBody(codec *registrationRecords, raw []byte) (certificateBody, error) {
	var b certificateBody
	if codec == nil {
		return b, errCertificate
	}
	f, err := codec.unframeBatch(true, raw, 17)
	if err != nil || !bytes.Equal(f[0], []byte(certificateBodyTag)) {
		return b, errCertificate
	}
	for _, i := range []int{3, 10, 12, 14, 15} {
		if len(f[i]) != 8 {
			return b, errCertificate
		}
	}
	subjects, err := registrationBoundedFields(codec, f[6], 1, codec.maxBytes/2, codec.maxBytes)
	if err != nil {
		return b, errCertificate
	}
	b = certificateBody{network: f[1], operation: f[2], version: binary.BigEndian.Uint64(f[3]), purpose: f[4], scope: f[5],
		subjects: subjects, kind: f[7], payload: f[8], setID: f[9], setVersion: binary.BigEndian.Uint64(f[10]), setHash: f[11],
		predecessorVersion: binary.BigEndian.Uint64(f[12]), predecessor: f[13],
		notBefore: HeaderMilliseconds(binary.BigEndian.Uint64(f[14])), until: HeaderMilliseconds(binary.BigEndian.Uint64(f[15])), nonce: f[16]}
	again, err := encodeCertificateBody(codec, b)
	if err != nil || !bytes.Equal(again, raw) {
		return certificateBody{}, errCertificate
	}
	return b, nil
}

// certificateDigest is the signed digest of a canonical body.
func certificateDigest(codec *registrationRecords, raw []byte) ([]byte, error) {
	if codec == nil || check.IfNil(codec.hasher) || len(raw) == 0 || len(raw) > codec.maxBytes {
		return nil, errCertificate
	}
	digest := codec.hasher.Compute(string(raw))
	if len(digest) != codec.hasher.Size() {
		return nil, errCertificate
	}
	return digest, nil
}

// certificateWindow applies the detached-certificate rule of AR-05: inclusive
// at both ends, never inverted, never longer than the class lifetime.
func certificateWindow(at, notBefore, until, lifetime HeaderMilliseconds) error {
	if lifetime == 0 || until < notBefore || until-notBefore > lifetime || at < notBefore || at > until {
		return errCertificate
	}
	return nil
}

// verifyCertificate is the one function a certificate consumer calls. expected
// is the body the consumer derived from its own authenticated state; its
// window fields are ignored and taken from the presented certificate, which is
// then required to be byte-for-byte the canonical encoding of the expectation.
// A certificate for another network, operation, version, purpose, scope,
// subject, kind, payload, authority set or nonce therefore never verifies, and
// neither does another encoding of the same content. The evaluated header time
// comes from the consumer's own source, inside its time boundary. set is the
// authority set the consumer resolved for expected.setID; its keys are never
// taken from the certificate. It reads no state and writes none.
func verifyCertificate(codec *registrationRecords, source HeaderTimeSource, expected certificateBody, raw []byte,
	set scopedAuthoritySet, indices []uint64, signatures [][]byte, limits certificateLimits) error {
	if codec == nil || check.IfNil(source) || limits.members == 0 || limits.bytes == 0 || limits.lifetime == 0 ||
		uint64(len(raw)) > limits.bytes {
		return errCertificate
	}
	context, err := source.EvaluatedHeaderTimeContext()
	if err != nil {
		return err
	}
	_, err = withHeaderTime(source, context, func() (*vmcommon.VMOutput, error) {
		presented, decodeErr := decodeCertificateBody(codec, raw)
		if decodeErr != nil {
			return nil, decodeErr
		}
		expected.notBefore, expected.until = presented.notBefore, presented.until
		canonical, encodeErr := encodeCertificateBody(codec, expected)
		if encodeErr != nil || !bytes.Equal(canonical, raw) {
			return nil, errCertificate
		}
		if !bytes.Equal(set.id, expected.setID) || !bytes.Equal(set.hash, expected.setHash) || set.version != expected.setVersion ||
			!bytes.Equal(set.predecessor, expected.predecessor) || set.predecessorVersion != expected.predecessorVersion {
			return nil, errCertificate
		}
		at, _, release, leaseErr := context.Lease()
		if leaseErr != nil {
			return nil, leaseErr
		}
		defer release()
		if windowErr := certificateWindow(at, presented.notBefore, presented.until, limits.lifetime); windowErr != nil {
			return nil, windowErr
		}
		digest, digestErr := certificateDigest(codec, raw)
		if digestErr != nil {
			return nil, digestErr
		}
		return nil, verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", set.threshold, set.members, indices, signatures,
			digest, limits.members, limits.bytes)
	})
	return err
}
