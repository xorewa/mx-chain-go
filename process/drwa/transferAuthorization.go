package drwa

import (
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// SP2-78: the transfer-authorization certificate of an authorization-mediated
// token (Part A L3343-3384), on the certificate contract. EXPERIMENTAL form; no
// built-in, nonce state or ingress is installed here. The consuming row
// (SP2-50, DRWAAuthorizedTransfer) calls verifyTransferAuthorization with the
// effect it normalized from the holder-signed transaction, the token's current
// CEB epoch, the holder's current next_authorization_nonce and the transfer
// authority set of the local current CEB, and then consumes that nonce itself.
const (
	transferAuthorizationOperation  = "DRWA/AUTHORIZED_TRANSFER/experimental1"
	transferAuthorizationPurpose    = "AUTHORIZED_TRANSFER"
	transferAuthorizationKind       = "DRWAAuthorizedTransfer"
	transferAuthorizationEffectTag  = "DRWA/AUTH_TRANSFER/EFFECT/experimental1"
	transferAuthorizationPayloadTag = "DRWA/AUTH_TRANSFER/PAYLOAD/experimental1"
	transferAuthorizationVersion    = 1
)

// transferAuthorization is the exact effect a certificate authorizes. source
// is the holder who signed the transaction that carries the transfer: under
// relayed execution it is the sender of the holder-signed inner transaction,
// never the relayer. travelRule is the transaction-specific disposition, empty
// when none is required; evidence is the evidence commitment.
type transferAuthorization struct {
	network, scope, token []byte
	tokenNonce            uint64
	source, destination   []byte
	quantity              *big.Int
	cebEpoch              uint64
	authorizationNonce    uint64
	travelRule, evidence  []byte
}

func (a transferAuthorization) valid() bool {
	return len(a.network) != 0 && len(a.scope) != 0 && vmcommon.ValidateToken(a.token) &&
		len(a.source) == len(core.SystemAccountAddress) && len(a.destination) == len(core.SystemAccountAddress) &&
		a.quantity != nil && a.quantity.Sign() > 0 && a.cebEpoch != 0 && len(a.evidence) != 0
}

// transferAuthorizationEffectDigest is authorized_effect_digest: the canonical
// token, nonce, source, destination, quantity and CEB intent. It contains no
// transaction hash and no signature.
func transferAuthorizationEffectDigest(codec *registrationRecords, a transferAuthorization) ([]byte, error) {
	if codec == nil || !a.valid() {
		return nil, errCertificate
	}
	raw, err := codec.frameBatch(true, []byte(transferAuthorizationEffectTag), a.token, certificateNumber(a.tokenNonce),
		a.source, a.destination, a.quantity.Bytes(), certificateNumber(a.cebEpoch))
	if err != nil {
		return nil, errCertificate
	}
	return certificateDigest(codec, raw)
}

// transferAuthorizationBody is the certificate body of one effect and one
// authority set, without a window. Subjects are the token, its nonce, the
// source holder and the destination holder; the payload digest commits the
// effect digest, the quantity, the CEB epoch, the authorization nonce, the
// Travel-Rule disposition and the evidence commitment; the nonce field is the
// authorization nonce.
func transferAuthorizationBody(codec *registrationRecords, a transferAuthorization, set scopedAuthoritySet) (certificateBody, error) {
	effect, err := transferAuthorizationEffectDigest(codec, a)
	if err != nil {
		return certificateBody{}, err
	}
	payload, err := codec.frameBatch(true, []byte(transferAuthorizationPayloadTag), effect, a.quantity.Bytes(),
		certificateNumber(a.cebEpoch), certificateNumber(a.authorizationNonce), a.travelRule, a.evidence)
	if err != nil {
		return certificateBody{}, errCertificate
	}
	digest, err := certificateDigest(codec, payload)
	if err != nil {
		return certificateBody{}, err
	}
	return certificateBody{network: a.network, operation: []byte(transferAuthorizationOperation),
		version: transferAuthorizationVersion, purpose: []byte(transferAuthorizationPurpose), scope: a.scope,
		subjects: [][]byte{a.token, certificateNumber(a.tokenNonce), a.source, a.destination},
		kind:     []byte(transferAuthorizationKind), payload: digest, setID: set.id, setHash: set.hash, setVersion: set.version,
		predecessor: set.predecessor, predecessorVersion: set.predecessorVersion,
		nonce: certificateNumber(a.authorizationNonce)}, nil
}

// transferAuthorizationCertificate returns the canonical certificate bytes an
// authority signs for one effect and one window.
func transferAuthorizationCertificate(codec *registrationRecords, a transferAuthorization, set scopedAuthoritySet,
	notBefore, until HeaderMilliseconds) ([]byte, error) {
	body, err := transferAuthorizationBody(codec, a, set)
	if err != nil {
		return nil, err
	}
	body.notBefore, body.until = notBefore, until
	return encodeCertificateBody(codec, body)
}

// verifyTransferAuthorization accepts a presented certificate only for exactly
// the actual effect: any other token, nonce, holder, destination, quantity, CEB
// epoch, authorization nonce, disposition, evidence commitment, programme
// scope, network, purpose or authority set gives other canonical bytes and is
// refused, as is a certificate outside its validity at the evaluated header
// time or longer than the class lifetime. It changes no state.
func verifyTransferAuthorization(codec *registrationRecords, source HeaderTimeSource, actual transferAuthorization, raw []byte,
	set scopedAuthoritySet, indices []uint64, signatures [][]byte, limits certificateLimits) error {
	body, err := transferAuthorizationBody(codec, actual, set)
	if err != nil {
		return err
	}
	return verifyCertificate(codec, source, body, raw, set, indices, signatures, limits)
}
