package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Experimental construction encodings only (Part B L344-346). No ordinary
// caller, release format, profile identifier or production bound is installed.
const registrationIntentPrefix = core.ProtectedKeyPrefix + "DRWA@registration@intent@"
const registrationAssociationPrefix = core.ProtectedKeyPrefix + "DRWA@registration@token@"
const registrationActivationPrefix = core.ProtectedKeyPrefix + "DRWA@registration@activation@"

var errInvalidRegistrationRecord = errors.New("invalid DRWA registration record")

// bootstrapIntentBody preserves the COMPLETE immutable Step 1 body (Part A
// L2133-2158). Nested admission/profile/authority bytes are exact commitments,
// not evidence of their authority or validity. T14 and the owning admission
// producer must validate their admitted schemas and lawful current provenance.
// This storage component cannot establish canonical finality or authentication.
type bootstrapIntentBody struct {
	networkDomain, issuer, programID, intentNonce []byte
	requestedTokenFamily, creationProfile         []byte
	nameCommitment, tickerCommitment              []byte
	propertyCommitment, publicSchemaProfile       []byte
	issuerProgramAdmissionDecision                []byte
	proposedProgramAuthoritySetBodies             [][]byte
	proposedProgramAuthoritySetHashes             [][]byte
	closurePlan, networkProfile                   []byte
	expiry                                        HeaderMilliseconds
}

type bootstrapIntentRecord struct {
	body    bootstrapIntentBody
	encoded []byte
	digest  []byte
	status  string
	tokenID []byte
}

// registrationRecords reads/writes the existing native system-account trie.
// It owns no journal, account, cache, commit, authority or output publication.
// Every write MUST occur inside its owning T04 operation. The future protected
// OPEN-intent producer must enforce aggregate D07 admission/retention bounds;
// maxBytes bounds one record and is not aggregate capacity admission.
//
// Native Gogo framing and the actual supplied native hasher are reused. These
// candidate preimages, keys and widths are NOT allocated release formats.
type registrationRecords struct {
	state      *protectedState
	marshaller marshal.Marshalizer
	hasher     hashing.Hasher
	maxBytes   int
}

func newRegistrationRecords(accounts state.AccountsAdapter, marshaller marshal.Marshalizer,
	hasher hashing.Hasher, maxBytes int) (*registrationRecords, error) {
	if check.IfNil(marshaller) || check.IfNil(hasher) || hasher.Size() <= 0 || maxBytes <= 0 {
		return nil, errInvalidRegistrationRecord
	}
	s, err := newProtectedState(accounts)
	if err != nil {
		return nil, err
	}
	return &registrationRecords{state: s, marshaller: marshaller, hasher: hasher, maxBytes: maxBytes}, nil
}

// frame bounds every input before invoking a native allocator/decoder. Gogo's
// Data field adds at least two bytes per item, including an empty item. The
// exact native Size check then accounts for the actual varint overhead.
func (s *registrationRecords) frame(fields ...[]byte) ([]byte, error) {
	remaining := s.maxBytes
	for _, field := range fields {
		if remaining < 2 || len(field) > remaining-2 {
			return nil, errInvalidRegistrationRecord
		}
		remaining -= len(field) + 2
	}
	value := batch.New(fields...)
	if value.Size() > s.maxBytes {
		return nil, errInvalidRegistrationRecord
	}
	return s.marshaller.Marshal(value)
}

func (s *registrationRecords) unframe(encoded []byte, count int) ([][]byte, error) {
	if len(encoded) == 0 || len(encoded) > s.maxBytes {
		return nil, errInvalidRegistrationRecord
	}
	value := &batch.Batch{}
	if err := s.marshaller.Unmarshal(value, encoded); err != nil {
		return nil, err
	}
	if len(value.Data) != count {
		return nil, errInvalidRegistrationRecord
	}
	canonical, err := s.frame(value.Data...)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, errInvalidRegistrationRecord
	}
	return value.Data, nil
}

func (s *registrationRecords) authorityList(values [][]byte) ([]byte, error) {
	if len(values) == 0 || len(values) > s.maxBytes/2 {
		return nil, errInvalidRegistrationRecord
	}
	for _, value := range values {
		if len(value) == 0 {
			return nil, errInvalidRegistrationRecord
		}
	}
	return s.frame(values...)
}

func (s *registrationRecords) encodeBody(body bootstrapIntentBody) ([]byte, error) {
	if len(body.requestedTokenFamily) > s.maxBytes || len(body.issuer) != len(core.SystemAccountAddress) ||
		!bytes.Equal(body.closurePlan, []byte("burn-and-retire")) && !bytes.Equal(body.closurePlan, []byte("preserve-and-close")) ||
		len(body.proposedProgramAuthoritySetBodies) != len(body.proposedProgramAuthoritySetHashes) {
		return nil, errInvalidRegistrationRecord
	}
	switch string(body.requestedTokenFamily) {
	case core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT:
	default:
		return nil, errInvalidRegistrationRecord
	}
	bodies, err := s.authorityList(body.proposedProgramAuthoritySetBodies)
	if err != nil {
		return nil, err
	}
	for _, digest := range body.proposedProgramAuthoritySetHashes {
		if len(digest) != s.hasher.Size() {
			return nil, errInvalidRegistrationRecord
		}
	}
	hashes, err := s.authorityList(body.proposedProgramAuthoritySetHashes)
	if err != nil {
		return nil, err
	}
	expiry := make([]byte, 8)
	binary.BigEndian.PutUint64(expiry, uint64(body.expiry))
	fields := [][]byte{body.networkDomain, body.issuer, body.programID, body.intentNonce,
		body.requestedTokenFamily, body.creationProfile, body.nameCommitment, body.tickerCommitment,
		body.propertyCommitment, body.publicSchemaProfile, body.issuerProgramAdmissionDecision,
		bodies, hashes, body.closurePlan, body.networkProfile, expiry}
	for _, field := range fields {
		if len(field) == 0 {
			return nil, errInvalidRegistrationRecord
		}
	}
	return s.frame(fields...)
}

func (s *registrationRecords) decodeBody(encoded []byte) (bootstrapIntentBody, error) {
	f, err := s.unframe(encoded, 16)
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	// Bound nested list cardinality by its already bounded encoded byte length.
	readList := func(value []byte) ([][]byte, error) {
		v := &batch.Batch{}
		if len(value) == 0 || len(value) > s.maxBytes {
			return nil, errInvalidRegistrationRecord
		}
		if err := s.marshaller.Unmarshal(v, value); err != nil {
			return nil, err
		}
		return s.unframe(value, len(v.Data))
	}
	bodies, err := readList(f[11])
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	hashes, err := readList(f[12])
	if err != nil {
		return bootstrapIntentBody{}, err
	}
	if len(f[15]) != 8 {
		return bootstrapIntentBody{}, errInvalidRegistrationRecord
	}
	body := bootstrapIntentBody{networkDomain: f[0], issuer: f[1], programID: f[2], intentNonce: f[3],
		requestedTokenFamily: f[4], creationProfile: f[5], nameCommitment: f[6], tickerCommitment: f[7],
		propertyCommitment: f[8], publicSchemaProfile: f[9], issuerProgramAdmissionDecision: f[10],
		proposedProgramAuthoritySetBodies: bodies, proposedProgramAuthoritySetHashes: hashes,
		closurePlan: f[13], networkProfile: f[14], expiry: HeaderMilliseconds(binary.BigEndian.Uint64(f[15]))}
	canonical, err := s.encodeBody(body)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return bootstrapIntentBody{}, errInvalidRegistrationRecord
	}
	return body, nil
}

func (s *registrationRecords) identity(body bootstrapIntentBody) (encoded, digest, id []byte, err error) {
	encoded, err = s.encodeBody(body)
	if err != nil {
		return nil, nil, nil, err
	}
	payload, err := s.frame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), encoded)
	if err != nil {
		return nil, nil, nil, err
	}
	digest = s.hasher.Compute(string(payload))
	preimage, err := s.frame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), body.networkDomain, body.issuer,
		body.programID, body.intentNonce, digest)
	if err != nil {
		return nil, nil, nil, err
	}
	return encoded, digest, s.hasher.Compute(string(preimage)), nil
}

func (s *registrationRecords) intent(id []byte) (*bootstrapIntentRecord, error) {
	if len(id) != s.hasher.Size() {
		return nil, errInvalidRegistrationRecord
	}
	account, err := s.state.systemAccount()
	if err != nil {
		return nil, err
	}
	encoded, _, err := account.RetrieveValue(append([]byte(registrationIntentPrefix), id...))
	if err != nil {
		return nil, err
	}
	f, err := s.unframe(encoded, 3)
	if err != nil {
		return nil, err
	}
	body, err := s.decodeBody(f[0])
	if err != nil {
		return nil, err
	}
	_, digest, computed, err := s.identity(body)
	if err != nil || !bytes.Equal(computed, id) {
		return nil, errInvalidRegistrationRecord
	}
	status := string(f[1])
	if status != "OPEN" && status != "CONSUMED" && status != "CANCELLED" ||
		status == "CONSUMED" && !vmcommon.ValidateToken(f[2]) || status != "CONSUMED" && len(f[2]) != 0 {
		return nil, errInvalidRegistrationRecord
	}
	return &bootstrapIntentRecord{body: body, encoded: f[0], digest: digest, status: status, tokenID: f[2]}, nil
}

// consume performs the record part of Part A L2236-2247. The caller first
// reads/validates the authoritative OPEN intent; this method reloads it after
// native token creation and compares the EXACT immutable body and digest.
// Native token creation, this write and registry/count must share T04's journal.
// No caller may publish output or commit after an error. This is not ingress.
func (s *registrationRecords) consume(id []byte, expected *bootstrapIntentRecord,
	tokenID, manager []byte) error {
	if expected == nil || expected.status != "OPEN" || !vmcommon.ValidateToken(tokenID) ||
		len(manager) != len(core.SystemAccountAddress) {
		return errInvalidRegistrationRecord
	}
	current, err := s.intent(id)
	if err != nil {
		return err
	}
	if current.status != "OPEN" || !bytes.Equal(current.encoded, expected.encoded) ||
		!bytes.Equal(current.digest, expected.digest) {
		return errInvalidRegistrationRecord
	}
	account, err := s.state.systemAccount()
	if err != nil {
		return err
	}
	key := append([]byte(registrationAssociationPrefix), tokenID...)
	old, _, err := account.RetrieveValue(key)
	if err != nil {
		return err
	}
	if len(old) != 0 {
		return errInvalidRegistrationRecord
	}
	activationKey := append([]byte(registrationActivationPrefix), tokenID...)
	priorActivation, _, err := account.RetrieveValue(activationKey)
	if err != nil {
		return err
	}
	if len(priorActivation) != 0 {
		return errInvalidRegistrationRecord
	}
	activation, err := s.frame(tokenID, id, []byte("BootstrapDeny"))
	if err != nil {
		return err
	}
	association, err := s.frame(tokenID, id, current.digest, current.encoded, manager)
	if err != nil {
		return err
	}
	consumed, err := s.frame(current.encoded, []byte("CONSUMED"), tokenID)
	if err != nil {
		return err
	}
	if err = account.SaveKeyValue(activationKey, activation); err != nil {
		return err
	}
	if err = account.SaveKeyValue(key, association); err != nil {
		return err
	}
	if err = account.SaveKeyValue(append([]byte(registrationIntentPrefix), id...), consumed); err != nil {
		return err
	}
	return s.state.accounts.SaveAccount(account)
}

// registeredToken resolves the immutable association rather than trusting a
// caller-supplied intent (Part B L387). Lifecycle/authority/expiry validation
// remains the owning consumer's obligation. Activation is a separate mutable
// record; this function grants no activation or cancellation permission.
func (s *registrationRecords) registeredToken(tokenID []byte) (*bootstrapIntentRecord, []byte, error) {
	if !vmcommon.ValidateToken(tokenID) {
		return nil, nil, errInvalidRegistrationRecord
	}
	account, err := s.state.systemAccount()
	if err != nil {
		return nil, nil, err
	}
	encoded, _, err := account.RetrieveValue(append([]byte(registrationAssociationPrefix), tokenID...))
	if err != nil {
		return nil, nil, err
	}
	f, err := s.unframe(encoded, 5)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(f[0], tokenID) || len(f[4]) != len(core.SystemAccountAddress) {
		return nil, nil, errInvalidRegistrationRecord
	}
	intent, err := s.intent(f[1])
	if err != nil {
		return nil, nil, err
	}
	if intent.status != "CONSUMED" || !bytes.Equal(intent.tokenID, tokenID) ||
		!bytes.Equal(intent.digest, f[2]) || !bytes.Equal(intent.encoded, f[3]) {
		return nil, nil, errInvalidRegistrationRecord
	}
	return intent, bytes.Clone(f[4]), nil
}

// registerTokenForIntent co-journals native creation, the complete retained
// body/consumption/association/BootstrapDeny write set, and the existing sole
// registry/count writer. It is unwired construction, not DRWARegisterToken:
// T14 must authenticate current intent/admission and exact creation commitments,
// native issuer/approvals/epoch/support/expiry before this production caller.
// No ordinary route imports it, and no boolean substitutes for those predicates.
func (r *RegistryRegistration) registerTokenForIntent(records *registrationRecords,
	id, digest, manager []byte, create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	if records == nil || records.state.accounts != r.state.accounts || create == nil {
		return errInvalidRegistrationRecord
	}
	// Native creation may use or mutate its own argument buffers. Retain our
	// exact operation identities before invoking it; no mutable caller alias
	// may select the later intent key or stored permanent manager.
	id = bytes.Clone(id)
	manager = bytes.Clone(manager)
	return r.RegisterToken(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		expected, err := records.intent(id)
		if err != nil {
			return nil, nil, err
		}
		if expected.status != "OPEN" || !bytes.Equal(expected.digest, digest) {
			return nil, nil, errInvalidRegistrationRecord
		}
		tokenID, output, err := create(accounts)
		if err != nil {
			return nil, nil, err
		}
		if err = records.consume(id, expected, tokenID, manager); err != nil {
			return nil, nil, err
		}
		return tokenID, output, nil
	})
}
